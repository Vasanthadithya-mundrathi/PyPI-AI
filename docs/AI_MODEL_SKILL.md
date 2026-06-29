# PyPi-AI AI Model Skill

The runtime provider prompt uses [skills/pypi-ai-model/SKILL.md](../skills/pypi-ai-model/SKILL.md).

This file is included for faculty review so the AI behavior is easy to explain:

- Ollama local is the default provider.
- Gemini and Ollama Cloud are optional provider modes.
- Every AI sentence must cite a valid evidence ID.
- Unsupported claims are omitted.
- If a model fails to produce grounded output, PyPi-AI falls back to deterministic
  local explanations.
