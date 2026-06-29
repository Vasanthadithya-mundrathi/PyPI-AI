# Review Three Demo Commands

```bash
uv run pypi-ai scan-venv .venv --teacher-mode --format json
uv run pypi-ai scan examples/safe_packages/obfuscated --teacher-mode --format all --output reports/obfuscated-demo
uv run pypi-ai benchmark run
uv run pytest -q
```
