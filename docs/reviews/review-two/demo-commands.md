# Review Two Demo Commands

```bash
uv run pypi-ai scan examples/safe_packages/env_network --teacher-mode --debug --trace-rules --show-evidence --explain-risk --format json
uv run pypi-ai model test --provider ollama-local
uv run pypi-ai install requests --venv .venv --dry-run
uv run pytest -q
```
