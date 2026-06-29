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
pypi-ai
pypi-ai scan examples/safe_packages/benign --teacher-mode --show-evidence
pypi-ai scan-venv .venv --teacher-mode --format json
pypi-ai install requests --venv .venv
pypi-ai model test --provider ollama-cloud
pypi-ai theme preview
```

## Safety

PyPi-AI never installs, imports, or executes scanned package code. Findings are
based on static metadata, AST, and pattern analysis.

`pypi-ai install <package>` is the only install workflow. It creates `.venv` if
needed, downloads wheel files first, scans the downloaded wheels, blocks risky
packages, and then installs from the verified local wheel cache.
