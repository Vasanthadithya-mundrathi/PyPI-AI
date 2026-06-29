#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

uv run pypi-ai scan examples/safe_packages/benign \
  --review-mode \
  --show-evidence \
  --show-citations \
  --format all \
  --output reports/benign-demo

uv run pypi-ai scan examples/safe_packages/env_network \
  --review-mode \
  --debug \
  --trace-rules \
  --show-evidence \
  --show-citations \
  --explain-risk \
  --format all \
  --output reports/env-network-demo

uv run pypi-ai scan examples/safe_packages/obfuscated \
  --review-mode \
  --debug \
  --trace-rules \
  --show-evidence \
  --show-citations \
  --explain-risk \
  --format all \
  --output reports/obfuscated-demo

echo "Demo reports written under reports/"
