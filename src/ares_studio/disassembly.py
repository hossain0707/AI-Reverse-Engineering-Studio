"""Opt-in lightweight disassembly of a bounded entry-point window (Capstone)."""

from __future__ import annotations

from pathlib import Path

from .core import Analysis

MAX_INSTRUCTIONS = 180
WINDOW_BYTES = 4096


def disassemble(analysis: Analysis, count: int = 120) -> list[dict[str, str]]:
    if analysis.entry_offset is None or analysis.entry_point is None:
        raise ValueError("Entry point has no verified file mapping")
    if count < 1 or count > MAX_INSTRUCTIONS:
        raise ValueError(f"Instruction count must be 1..{MAX_INSTRUCTIONS}")
    if analysis.entry_offset < 0 or analysis.entry_offset >= analysis.size:
        raise ValueError("Entry offset is outside the binary")
    try:
        import capstone as cs
    except ImportError as exc:
        raise RuntimeError("Install the optional disassembly dependency: pip install '.[disassembly]'") from exc
    arch = analysis.architecture
    if arch in ("x86", "x86-64"):
        architecture, mode = cs.CS_ARCH_X86, cs.CS_MODE_64 if arch == "x86-64" else cs.CS_MODE_32
    elif arch in ("ARM", "ARM64"):
        architecture, mode = (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM) if arch == "ARM64" else (cs.CS_ARCH_ARM, cs.CS_MODE_ARM)
    elif arch == "RISC-V":
        architecture, mode = cs.CS_ARCH_RISCV, cs.CS_MODE_RISCV64 if analysis.bitness == 64 else cs.CS_MODE_RISCV32
    else:
        raise ValueError(f"No disassembler configured for {arch}")
    mode |= cs.CS_MODE_BIG_ENDIAN if analysis.endianness == "big" else cs.CS_MODE_LITTLE_ENDIAN
    with Path(analysis.path).open("rb") as handle:
        handle.seek(analysis.entry_offset)
        buf = handle.read(WINDOW_BYTES)
    engine = cs.Cs(architecture, mode)
    return [{"address": f"0x{insn.address:X}", "bytes": insn.bytes.hex(" "),
             "instruction": f"{insn.mnemonic} {insn.op_str}".strip()}
            for insn in engine.disasm(buf, analysis.entry_point, count=count)]
