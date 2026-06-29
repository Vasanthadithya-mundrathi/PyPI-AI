# PyPi-AI

PyPi-AI is an evidence-grounded static scanner for suspicious Python packages.
It inspects package folders, wheels, source distributions, and virtual environments
without executing untrusted package code. Ollama local is the primary/default AI
provider; Ollama Cloud prefers `glm-5.2:cloud` when the account has access, with
`minimax-m3:cloud` documented as the tested fallback on this machine. Gemini is
kept as an optional API-key backed provider.

## Developers

- VASANTH ADITHYA - 160123749049 - vasanthfeb13@gmail.com
- SAI GEETHIKA - 160123749302 - yedlasaigeethika37@gmail.com

## Quick Start

```bash
./scripts/setup.sh
uv run pypi-ai
uv run pypi-ai scan examples/safe_packages/benign --review-mode --show-evidence
uv run pypi-ai scan-venv .venv --review-mode --format json
uv run pypi-ai install requests --venv .venv --dry-run
uv run pypi-ai scan examples/safe_packages/benign --check-osv
uv run pypi-ai database check requests
uv run pypi-ai config init
uv run pypi-ai model test --provider ollama-cloud
uv run pypi-ai theme preview
```

## Safety

PyPi-AI never installs, imports, or executes scanned package code. Findings are
based on static metadata, AST, and pattern analysis.

## Real Integrations

- Ollama local uses the real `http://localhost:11434/api/generate` API.
- Ollama Cloud uses the signed-in `ollama run <cloud-model>` CLI path.
- Gemini uses `GEMINI_API_KEY` when provided.
- If a provider is unavailable, explanations fall back to deterministic
  evidence-only text and mark the fallback reason.
- `--check-osv` queries the free OSV.dev vulnerability database and caches
  package advisories in local SQLite for faster repeat checks.

`pypi-ai install <package>` is the only install workflow. It creates `.venv` if
needed, downloads wheel files first, scans the downloaded wheels, blocks risky
packages, and then installs from the verified local wheel cache.
