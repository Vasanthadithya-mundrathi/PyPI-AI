# PyPi-AI Tool Screenshots

These screenshots were generated from real local PyPi-AI commands and the local
browser dashboard. The `.txt` files beside the terminal screenshots contain the
raw command output used to generate each image.

| Screenshot | Command Or Source | PNG |
|---|---|---|
| Welcome/About screen | `uv run pypi-ai --color` | `01-welcome.png` |
| Scan evidence and citations | `uv run pypi-ai scan examples/safe_packages/env_network --review-mode --debug --trace-rules --show-evidence --explain-risk --show-citations --no-ai` | `02-scan-evidence.png` |
| Theme preview | `uv run pypi-ai theme preview` | `03-theme-preview.png` |
| Verified install dry run | `uv run pypi-ai install requests --venv .venv --dry-run` | `04-install-dry-run.png` |
| Version and doctor check | `uv run pypi-ai --version && uv run pypi-ai doctor` | `05-doctor-version.png` |
| HTML report preview | `docs/final/reports/env-network-review.html` | `06-html-report.png` |
| Local dashboard | `dashboard/index.html` | `../dashboard-local.png` |

Generated report artifacts:

- `docs/final/reports/env-network-review.json`
- `docs/final/reports/env-network-review.html`
- `docs/final/reports/env-network-review.pdf`
