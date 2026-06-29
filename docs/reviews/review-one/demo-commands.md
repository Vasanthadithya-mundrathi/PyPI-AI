# Review One Demo Commands

```bash
uv run pypi-ai
uv run pypi-ai rules list
uv run pypi-ai scan examples/safe_packages/benign --review-mode --show-evidence --format json
uv run pypi-ai scan examples/safe_packages/obfuscated --review-mode --debug --trace-rules --format json
uv run pytest -q
```
