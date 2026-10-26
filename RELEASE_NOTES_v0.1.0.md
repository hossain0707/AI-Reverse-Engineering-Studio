# ARES Studio v0.1.0 — Engineering Preview

ARES Studio is a local-first, cross-platform application for authorized static binary analysis and AI-assisted reverse engineering. This inaugural engineering preview packages the desktop application for Windows, macOS and Linux.

## Included features

- PE, ELF, and Mach-O metadata inspection, file hashes, section details, bounded strings, and entry-point mapping.
- Optional Capstone instruction disassembly.
- Optional, explicitly initiated Ghidra headless function discovery and decompilation.
- Optional Ollama explanations using a local loopback HTTP service.
- Read-only baseline analysis without executing the selected binary.
- JSON and Markdown reporting, plus a command-line interface.

## Download guidance

| Platform | Artifact |
| --- | --- |
| Windows 10/11 x64 | `ARES-Studio-Setup-0.1.0.exe` or `ARES-Studio-Windows-Portable.zip` |
| macOS Intel | `ARES-Studio-macos-x64.dmg` |
| macOS Apple Silicon | `ARES-Studio-macos-arm64.dmg` |
| Debian/Ubuntu x64 | `ares-studio_0.1.0_amd64.deb` |
| Other Linux x64 | `ARES-Studio-Linux-Portable.tar.gz` |

`SHA256SUMS.txt` accompanies the assets so installers can be checked for transfer integrity.

## Safety and release maturity

**This is an engineering preview, not hardened production security software.** CI packaging completed on native GitHub runners, but successful packaging does not establish native installation, usability, decompiler compatibility, or security acceptance on real user systems.

- Installers are not independently signed, and macOS disk images are not notarized. Standard OS protection warnings may appear. Do not bypass security protections for files you cannot verify.
- The built-in inspector does not execute analyzed binaries. Optional Ghidra tooling is **not** isolated by ARES; handle suspicious files in an appropriately isolated VM.
- Local AI responses may be inaccurate and should never be treated as verified findings.
- No first-party telemetry or automatic sample uploads are implemented.
- Use ARES Studio only for binaries you are authorized to analyze.

## Verification and source

Release assets were produced by the successful [native build workflow](https://github.com/hossain0707/AI-Reverse-Engineering-Studio/actions/runs/40253690685) from commit `3e67f07b06e92f07ae491b17879b1ae46c4788d5`. Further security testing, macOS notarization, Windows signing, and native smoke tests remain on the roadmap.

[README](https://github.com/hossain0707/AI-Reverse-Engineering-Studio#readme) · [Security policy](https://github.com/hossain0707/AI-Reverse-Engineering-Studio/blob/main/SECURITY.md)

**Author:** Md Najmul Hossain · **License:** MIT
