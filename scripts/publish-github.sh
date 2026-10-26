#!/usr/bin/env bash
# Optional maintainer helper; requires GitHub CLI and interactive authentication.
set -euo pipefail
cd "$(dirname "$0")/.."
repo="${1:-AI-Reverse-Engineering-Studio}"
visibility="${2:-public}"
if [[ "$visibility" != "public" && "$visibility" != "private" ]]; then
  echo 'Visibility must be public or private' >&2
  exit 2
fi
if ! command -v gh >/dev/null 2>&1; then
  echo 'Install GitHub CLI: https://cli.github.com/' >&2
  exit 1
fi
gh auth status >/dev/null
owner="$(gh api user --jq .login)"
if [[ "$owner" != "hossain0707" ]]; then
  echo "Expected hossain0707, but authenticated as $owner. Refusing to publish." >&2
  exit 1
fi
gh repo create "$owner/$repo" "--$visibility" --description \
  'Local-first cross-platform AI Reverse Engineering Studio with Ghidra and Ollama integration' \
  --source . --remote origin --push
echo "Created: https://github.com/$owner/$repo"
