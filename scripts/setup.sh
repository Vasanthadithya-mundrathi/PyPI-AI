#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "Setting up PyPi-AI in $ROOT_DIR"
uv sync --all-groups
uv run pypi-ai doctor

cat <<'MSG'

Setup complete.

Try:
  uv run pypi-ai
  uv run pypi-ai scan examples/safe_packages/benign --review-mode --show-evidence
  uv run pypi-ai scan-venv .venv --review-mode --format json
MSG
