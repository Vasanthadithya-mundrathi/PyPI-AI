from __future__ import annotations

from pathlib import Path

from pypi_ai.ai import load_ai_model_skill


def test_ai_model_skill_file_exists_and_enforces_evidence_grounding() -> None:
    skill_path = Path("skills/pypi-ai-model/SKILL.md")

    assert skill_path.exists()
    content = skill_path.read_text(encoding="utf-8")
    assert "name: pypi-ai-model" in content
    assert "Never claim behavior without a valid evidence ID" in content
    assert "Gemini" in content
    assert "Ollama" in content


def test_runtime_loads_ai_model_skill_for_provider_prompts() -> None:
    content = load_ai_model_skill()

    assert "Evidence-grounded" in content
    assert "unsupported claim" in content
