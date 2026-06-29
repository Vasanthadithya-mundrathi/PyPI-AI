# Review Three Demo Commands

```bash
uv run pypi-ai scan-venv .venv --review-mode --format json
uv run pypi-ai scan examples/safe_packages/obfuscated --review-mode --format all --output reports/obfuscated-demo
uv run pypi-ai benchmark run
uv run pytest -q
```
