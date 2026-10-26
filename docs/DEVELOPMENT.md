# Development and release guide

## Set up

```bash
python -m venv .venv
# macOS/Linux: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e '.[dev]'
python -m pytest -q
python -m ruff check .
python -m ares_studio
```

## Packaging

Run this command on each target OS. PyInstaller is **not** a cross-compiler.

```bash
pyinstaller --noconfirm --clean --onedir --windowed \
  --name ARES-Studio --paths src \
  --add-data "src/ares_studio/resources:ares_studio/resources" launcher.py
```

The GitHub workflow builds on native Windows/macOS/Linux runners. After a passing build:

- Windows: portable ZIP and NSIS `.exe` installer.
- macOS: drag-to-Applications `.dmg` (Intel and Apple Silicon builds).
- Linux: `.deb` for Ubuntu/Debian x86-64 and portable `.tar.gz`.

Installers are **not digitally signed**. macOS Gatekeeper and Windows SmartScreen may display warnings. Signing/notarization and multi-architecture production certification remain future release requirements.

Tag a release as `v0.1.0` to build release assets into a **draft** GitHub Release; review the artifacts and manually publish. Tags should match the current version in `pyproject.toml` and Windows/Debian packaging files.

## Verification checklist

- Unit tests and Ruff lint on Ubuntu CI.
- Build on all three GitHub Actions OS runners.
- Open sample executables on real OS machines and confirm PE/ELF/Mach-O import.
- Verify navigation, file drag/drop, report export, and no freezing on analysis.
- Test actual Ghidra installation and installed Ollama model independently on each OS.
- Run QA with an unprivileged user and no Ollama/Ghidra installed.
- Security review and sign/notarize installers before claiming verified production readiness.

## Publishing from a local Git checkout

GitHub repository creation requires a GitHub session with repository-creation privileges. The optional maintainer scripts enforce ownership by `hossain0707` and use the GitHub CLI (no token is stored in the repository):

```bash
# Install/authenticate gh once, then from the repository root:
./scripts/publish-github.sh AI-Reverse-Engineering-Studio public
# or Windows PowerShell:
# .\scripts\publish-github.ps1 -RepoName AI-Reverse-Engineering-Studio -Visibility public
```

The scripts intentionally refuse to publish under a different account. They assume an existing local `main` Git commit. Use `private` as the second argument (or `-Visibility private`) if you do not intend to make the code public.
