import hashlib
import json
import struct

import pytest

from ares_studio.cli import main
from ares_studio.core import MAX_FILE_BYTES, _entropy, analyze
from ares_studio.disassembly import disassemble
from ares_studio.ollama import LocalAIError, _endpoint, explain
from ares_studio.reporting import make_markdown, write_report


def sample_pe():
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0)
    struct.pack_into("<H", data, 0x98, 0x20B)
    struct.pack_into("<I", data, 0x98 + 16, 0x1000)
    struct.pack_into("<Q", data, 0x98 + 24, 0x140000000)
    sec = 0x98 + 0xF0
    data[sec : sec + 5] = b".text"
    struct.pack_into("<IIII", data, sec + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, sec + 36, 0x60000020)
    data[0x200:0x208] = b"\x55\x48\x89\xe5\x90\x90\x5d\xc3"
    data[0x220:0x239] = b"https://example.com/test\x00"
    return bytes(data)


def test_pe_headers(tmp_path):
    item = tmp_path / "hello.exe"
    item.write_bytes(sample_pe())
    a = analyze(item)
    assert a.file_type == "PE"
    assert a.architecture == "x86-64"
    assert a.entry_point == 0x140001000
    assert a.entry_offset == 0x200
    assert a.sections[0].name == ".text"
    assert a.sections[0].executable
    assert a.sha256 == hashlib.sha256(item.read_bytes()).hexdigest()
    assert "URL-like" in " ".join(a.indicators)


def test_elf_minimal(tmp_path):
    data = bytearray(128)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", data, 18, 62)
    struct.pack_into("<Q", data, 24, 0x400080)
    p = tmp_path / "sample.elf"
    p.write_bytes(data)
    a = analyze(p)
    assert a.file_type == "ELF"
    assert a.architecture == "x86-64"
    assert a.entry_point == 0x400080
    assert a.entry_offset is None


def test_unknown_and_truncated(tmp_path):
    raw = tmp_path / "raw.bin"
    raw.write_bytes(b"Hello world via ARES!" * 20)
    a = analyze(raw)
    assert a.file_type == "Raw / unknown"
    assert a.strings
    raw.write_bytes(b"MZ")
    assert "Truncated" in " ".join(analyze(raw).warnings)


def test_empty_rejected(tmp_path):
    p = tmp_path / "empty"
    p.write_bytes(b"")
    with pytest.raises(ValueError, match="empty"):
        analyze(p)


def test_size_limit(tmp_path):
    p = tmp_path / "too-large"
    with p.open("wb") as handle:
        handle.truncate(MAX_FILE_BYTES + 1)
    with pytest.raises(ValueError, match="limit"):
        analyze(p)


def test_entropy():
    assert _entropy(b"\x00" * 32) == 0.0
    assert round(_entropy(bytes(range(256))), 3) == 8.0


def test_reports(tmp_path):
    p = tmp_path / "sample.exe"
    p.write_bytes(sample_pe())
    a = analyze(p)
    assert a.sha256 in make_markdown(a)
    out = tmp_path / "analysis.json"
    write_report(out, a, "Local AI only")
    doc = json.loads(out.read_text())
    assert doc["analysis"]["sha256"] == a.sha256
    assert doc["schema"] == "ares.report/v1"
    write_report(tmp_path / "analysis.md", a)
    assert (tmp_path / "analysis.md").read_text().startswith("# ARES")


def test_cli(tmp_path, capsys):
    p = tmp_path / "code"
    p.write_bytes(sample_pe())
    assert main([str(p)]) == 0
    assert '"file_type": "PE"' in capsys.readouterr().out
    assert main([str(tmp_path / "absent")]) == 2


@pytest.mark.parametrize("url", ["http://127.0.0.1:11434", "http://localhost:11434", "http://[::1]:11434"])
def test_accepted_loopback(url):
    assert _endpoint(url).endswith("/api/generate")


@pytest.mark.parametrize("url", ["https://127.0.0.1:11434", "http://evil.com:11434", "http://10.0.0.1:11434",
                                 "http://127.0.0.1:11434/path", "http://localhost", "http://me:pw@localhost:11434"])
def test_rejected_nonlocal(url):
    with pytest.raises(LocalAIError):
        _endpoint(url)


def test_missing_entry_point(tmp_path):
    p = tmp_path / "raw"
    p.write_bytes(b"raw binary only")
    with pytest.raises(ValueError, match="Entry"):
        disassemble(analyze(p))


def test_bad_model(tmp_path):
    p = tmp_path / "raw"
    p.write_bytes(b"any binary")
    with pytest.raises(LocalAIError, match="model"):
        explain(analyze(p), "white space")


def test_elf_program_header_file_mapping(tmp_path):
    data = bytearray(0x500)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", data, 18, 62)
    struct.pack_into("<Q", data, 24, 0x400150)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<H", data, 54, 56)
    struct.pack_into("<H", data, 56, 1)
    struct.pack_into("<I", data, 64, 1)  # PT_LOAD
    struct.pack_into("<Q", data, 64 + 8, 0x100)  # p_offset
    struct.pack_into("<Q", data, 64 + 16, 0x400100)  # p_vaddr
    struct.pack_into("<Q", data, 64 + 32, 0x300)  # p_filesz
    p = tmp_path / "entry.elf"
    p.write_bytes(data)
    assert analyze(p).entry_offset == 0x150


def test_macho_minimal(tmp_path):
    data = bytearray(80)
    data[:4] = b"\xcf\xfa\xed\xfe"  # 64-bit little-endian
    struct.pack_into("<I", data, 4, 0x0100000C)  # ARM64
    struct.pack_into("<I", data, 16, 1)
    struct.pack_into("<I", data, 32, 0x80000028)  # LC_MAIN
    struct.pack_into("<I", data, 36, 24)
    struct.pack_into("<Q", data, 40, 48)
    p = tmp_path / "entry.macho"
    p.write_bytes(data)
    a = analyze(p)
    assert a.file_type == "Mach-O"
    assert a.bitness == 64
    assert a.architecture == "ARM64"
    assert a.entry_offset == 48


def test_invalid_pe_does_not_crash(tmp_path):
    p = tmp_path / "broken.exe"
    data = bytearray(64)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0xFFFF0000)
    p.write_bytes(data)
    a = analyze(p)
    assert a.warnings
    assert a.file_type == "Unknown"


def test_ghidra_path_validation(tmp_path):
    from ares_studio.ghidra import GhidraError, locate_headless

    with pytest.raises(GhidraError, match="not found"):
        locate_headless(tmp_path)


def test_endpoint_query_rejected():
    with pytest.raises(LocalAIError):
        _endpoint("http://127.0.0.1:11434?api_key=dont-send")
