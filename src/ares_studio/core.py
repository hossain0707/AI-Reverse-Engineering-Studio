"""Bounded, static binary analysis. Never loads or executes a subject as code."""

from __future__ import annotations

import hashlib
import math
import re
import struct
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_SCAN_BYTES = 16 * 1024 * 1024
MAX_STRINGS = 1200
MAX_SECTIONS = 96
STRING_PATTERN = re.compile(rb"[\x20-\x7e]{5,}")
URL_PATTERN = re.compile(r"(?i)\b(?:https?://|ftp://)[^\s\x00\"'<>]{4,160}")

PE_MACHINES = {0x14C: "x86", 0x8664: "x86-64", 0xAA64: "ARM64", 0x1C0: "ARM"}
ELF_MACHINES = {3: "x86", 40: "ARM", 62: "x86-64", 183: "ARM64", 243: "RISC-V"}
MACH_MACHINES = {7: "x86", 0x01000007: "x86-64", 12: "ARM", 0x0100000C: "ARM64"}


@dataclass
class Section:
    name: str
    offset: int
    size: int
    virtual_address: int = 0
    executable: bool = False


@dataclass
class Analysis:
    name: str
    path: str
    size: int
    sha256: str
    file_type: str
    architecture: str
    bitness: int | None
    endianness: str
    entry_point: int | None
    entry_offset: int | None
    entropy: float
    sections: list[Section] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    scan_bytes: int = 0

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _u16(data: bytes, offset: int, endian: str = "<") -> int:
    if offset < 0 or offset + 2 > len(data):
        raise ValueError("Truncated binary header")
    return struct.unpack_from(endian + "H", data, offset)[0]


def _u32(data: bytes, offset: int, endian: str = "<") -> int:
    if offset < 0 or offset + 4 > len(data):
        raise ValueError("Truncated binary header")
    return struct.unpack_from(endian + "I", data, offset)[0]


def _u64(data: bytes, offset: int, endian: str = "<") -> int:
    if offset < 0 or offset + 8 > len(data):
        raise ValueError("Truncated binary header")
    return struct.unpack_from(endian + "Q", data, offset)[0]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for val in data:
        counts[val] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _pe(data: bytes, result: Analysis) -> None:
    if len(data) < 0x40:
        raise ValueError("Truncated DOS header")
    nt = _u32(data, 0x3C)
    if nt + 24 > len(data) or data[nt : nt + 4] != b"PE\0\0":
        raise ValueError("Invalid PE header")
    machine = _u16(data, nt + 4)
    count = min(_u16(data, nt + 6), MAX_SECTIONS)
    opt_size = _u16(data, nt + 20)
    opt = nt + 24
    if opt + opt_size > len(data) or opt_size < 32:
        raise ValueError("Truncated PE optional header")
    magic = _u16(data, opt)
    if magic not in (0x10B, 0x20B):
        raise ValueError("Unsupported PE optional header")
    result.file_type = "PE"
    result.architecture = PE_MACHINES.get(machine, f"Machine 0x{machine:04X}")
    result.bitness = 64 if magic == 0x20B else 32
    image_base = _u64(data, opt + 24) if result.bitness == 64 else _u32(data, opt + 28)
    entry_rva = _u32(data, opt + 16)
    result.entry_point = image_base + entry_rva
    sect = opt + opt_size
    for i in range(count):
        p = sect + i * 40
        if p + 40 > len(data):
            result.warnings.append("Section table is truncated")
            break
        name = data[p : p + 8].split(b"\0")[0].decode("ascii", "replace")
        virtual_size = _u32(data, p + 8)
        rva = _u32(data, p + 12)
        raw_size = _u32(data, p + 16)
        raw_offset = _u32(data, p + 20)
        flags = _u32(data, p + 36)
        result.sections.append(Section(name or f"section_{i}", raw_offset, raw_size,
                                       image_base + rva, bool(flags & 0x20000000)))
        if rva <= entry_rva < rva + max(virtual_size, raw_size):
            mapped = raw_offset + entry_rva - rva
            if mapped < result.size and entry_rva - rva < raw_size:
                result.entry_offset = mapped


def _elf(data: bytes, result: Analysis) -> None:
    if len(data) < 0x34:
        raise ValueError("Truncated ELF header")
    clazz, encoding = data[4], data[5]
    if clazz not in (1, 2) or encoding not in (1, 2):
        raise ValueError("Invalid ELF class/byte order")
    bits, end = (32 if clazz == 1 else 64), ("<" if encoding == 1 else ">")
    result.file_type, result.bitness = "ELF", bits
    result.endianness = "little" if end == "<" else "big"
    result.architecture = ELF_MACHINES.get(_u16(data, 18, end), "Unknown")
    entry = _u32(data, 24, end) if bits == 32 else _u64(data, 24, end)
    result.entry_point = entry
    phoff = _u32(data, 28, end) if bits == 32 else _u64(data, 32, end)
    shoff = _u32(data, 32, end) if bits == 32 else _u64(data, 40, end)
    phentsize = _u16(data, 42 if bits == 32 else 54, end)
    phnum = min(_u16(data, 44 if bits == 32 else 56, end), MAX_SECTIONS)
    shentsize = _u16(data, 46 if bits == 32 else 58, end)
    shnum = min(_u16(data, 48 if bits == 32 else 60, end), MAX_SECTIONS)
    shstrndx = _u16(data, 50 if bits == 32 else 62, end)
    # Program headers are used for accurate virtual-address mapping.
    if phentsize >= (32 if bits == 32 else 56):
        for i in range(phnum):
            p = phoff + i * phentsize
            if p + phentsize > len(data):
                break
            typ = _u32(data, p, end)
            if typ != 1:
                continue
            if bits == 32:
                off, vaddr, filesz = _u32(data, p + 4, end), _u32(data, p + 8, end), _u32(data, p + 16, end)
            else:
                off, vaddr, filesz = _u64(data, p + 8, end), _u64(data, p + 16, end), _u64(data, p + 32, end)
            if vaddr <= entry < vaddr + filesz and off + entry - vaddr < result.size:
                result.entry_offset = off + entry - vaddr
    if not shentsize or shentsize < (40 if bits == 32 else 64):
        return
    name_table = b""
    if shstrndx < shnum:
        sp = shoff + shstrndx * shentsize
        if sp + shentsize <= len(data):
            nameoff = _u32(data, sp + (16 if bits == 32 else 24), end)
            namesize = _u32(data, sp + (20 if bits == 32 else 32), end) if bits == 32 else _u64(data, sp + 32, end)
            if nameoff + namesize <= len(data) and namesize <= 1024 * 1024:
                name_table = data[nameoff : nameoff + namesize]
    for i in range(shnum):
        p = shoff + i * shentsize
        if p + shentsize > len(data):
            result.warnings.append("Section table is truncated")
            break
        noff = _u32(data, p, end)
        flags = _u32(data, p + 8, end) if bits == 32 else _u64(data, p + 8, end)
        addr = _u32(data, p + 12, end) if bits == 32 else _u64(data, p + 16, end)
        off = _u32(data, p + 16, end) if bits == 32 else _u64(data, p + 24, end)
        size = _u32(data, p + 20, end) if bits == 32 else _u64(data, p + 32, end)
        endname = name_table.find(b"\0", noff) if noff < len(name_table) else -1
        name = name_table[noff:endname].decode("ascii", "replace") if endname >= 0 else f"section_{i}"
        result.sections.append(Section(name, off, size, addr, bool(flags & 4)))


def _macho(data: bytes, result: Analysis) -> None:
    magic = data[:4]
    if magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf"):
        result.file_type = "Mach-O (universal)"
        result.architecture = "Multiple architectures; extract a slice for disassembly"
        return
    configs = {
        b"\xfe\xed\xfa\xce": (32, ">"), b"\xce\xfa\xed\xfe": (32, "<"),
        b"\xfe\xed\xfa\xcf": (64, ">"), b"\xcf\xfa\xed\xfe": (64, "<"),
    }
    bits, end = configs[magic]
    if len(data) < (32 if bits == 64 else 28):
        raise ValueError("Truncated Mach-O header")
    result.file_type, result.bitness = "Mach-O", bits
    result.endianness = "little" if end == "<" else "big"
    cpu = _u32(data, 4, end)
    result.architecture = MACH_MACHINES.get(cpu, f"CPU 0x{cpu:X}")
    ncmds = min(_u32(data, 16, end), MAX_SECTIONS)
    cmd = 32 if bits == 64 else 28
    for _ in range(ncmds):
        if cmd + 8 > len(data):
            result.warnings.append("Load command table is truncated")
            break
        kind, size = _u32(data, cmd, end), _u32(data, cmd + 4, end)
        if size < 8 or cmd + size > len(data):
            result.warnings.append("Invalid Mach-O load command")
            break
        if kind == 0x80000028 and cmd + 24 <= len(data):
            # LC_MAIN's entryoff is a file offset.
            result.entry_offset = _u64(data, cmd + 8, end)
        if kind in (1, 0x19):
            expected = 72 if bits == 64 else 56
            if size >= expected:
                name = data[cmd + 8 : cmd + 24].split(b"\0")[0].decode("ascii", "replace")
                if bits == 64:
                    addr, fsize = _u64(data, cmd + 24, end), _u64(data, cmd + 48, end)
                    fileoff = _u64(data, cmd + 40, end)
                    initprot = _u32(data, cmd + 60, end)
                else:
                    addr, fsize = _u32(data, cmd + 24, end), _u32(data, cmd + 36, end)
                    fileoff = _u32(data, cmd + 32, end)
                    initprot = _u32(data, cmd + 44, end)
                result.sections.append(Section(name, fileoff, fsize, addr, bool(initprot & 4)))
        cmd += size
    if result.entry_offset is not None:
        section = next((s for s in result.sections if s.offset <= result.entry_offset < s.offset + s.size), None)
        if section:
            result.entry_point = section.virtual_address + result.entry_offset - section.offset


def analyze(path: str | Path) -> Analysis:
    target = Path(path).expanduser().resolve(strict=True)
    if not target.is_file():
        raise ValueError("Select a regular file")
    size = target.stat().st_size
    if size == 0:
        raise ValueError("Cannot analyze an empty file")
    if size > MAX_FILE_BYTES:
        raise ValueError(f"File exceeds the {MAX_FILE_BYTES // (1024*1024)} MiB safety limit")
    stat_before = target.stat()
    h = hashlib.sha256()
    collected = bytearray()
    with target.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            h.update(chunk)
            if len(collected) < MAX_SCAN_BYTES:
                collected.extend(chunk[: MAX_SCAN_BYTES - len(collected)])
    data = bytes(collected)
    result = Analysis(target.name, str(target), size, h.hexdigest(), "Unknown", "Unknown",
                      None, "little", None, None, _entropy(data), scan_bytes=len(data))
    try:
        if data.startswith(b"MZ"):
            _pe(data, result)
        elif data.startswith(b"\x7fELF"):
            _elf(data, result)
        elif data[:4] in (
            b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
            b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
            b"\xca\xfe\xba\xbf",
        ):
            _macho(data, result)
        else:
            result.file_type = "Raw / unknown"
    except (ValueError, struct.error) as exc:
        result.warnings.append(f"Header parser: {exc}")
    raw_strings = STRING_PATTERN.findall(data)
    # Retain distinct values, stable in original byte order.
    seen: set[str] = set()
    for item in raw_strings:
        s = item[:500].decode("ascii", "replace")
        if s not in seen:
            seen.add(s)
            result.strings.append(s)
            if len(result.strings) >= MAX_STRINGS:
                break
    if result.entropy >= 7.3:
        result.indicators.append("High sampled entropy; may reflect compression, encryption, or packed data")
    if any(URL_PATTERN.search(x) for x in result.strings):
        result.indicators.append("URL-like strings present; inspect their context")
    if any(any(word in x.lower() for word in ("debugger", "isdebuggerpresent", "ptrace"))
           for x in result.strings):
        result.indicators.append("Debugging-related symbols or text present")
    if len(data) < size:
        result.warnings.append(f"Strings and entropy sample the first {len(data):,} bytes only")
    stat_after = target.stat()
    if (stat_after.st_size, stat_after.st_mtime_ns) != (stat_before.st_size, stat_before.st_mtime_ns):
        result.warnings.append("File changed during inspection; checksum and metadata may be inconsistent")
    if result.file_type == "Raw / unknown":
        result.warnings.append("Unrecognized header: architecture-aware disassembly unavailable")
    return result
