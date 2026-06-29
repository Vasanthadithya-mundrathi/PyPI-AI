from __future__ import annotations

from pypi_ai.ai import (
    EvidenceVerifier,
    build_provider_prompt,
    explain_from_evidence,
    provider_health,
)
from pypi_ai.models import Finding, Severity


def test_evidence_verifier_rejects_unsupported_claims() -> None:
    finding = Finding(
        finding_id="F001",
        rule_id="PY001_ENV_ACCESS",
        severity=Severity.MEDIUM,
        category="credential-access",
        file_path="pkg/mod.py",
        line_start=2,
        line_end=2,
        snippet="token = os.environ.get('TOKEN')",
        message="Environment variable access was detected.",
        confidence=0.85,
        tags=["credentials"],
        citations=["CHASE"],
    )

    verifier = EvidenceVerifier([finding])

    assert verifier.verify_sentence("The package reads environment variables. [F001]")
    assert not verifier.verify_sentence("The package deletes files from disk.")


def test_explain_from_evidence_only_uses_finding_ids() -> None:
    finding = Finding(
        finding_id="F001",
        rule_id="PY005_DYNAMIC_EXEC",
        severity=Severity.HIGH,
        category="dynamic-execution",
        file_path="pkg/mod.py",
        line_start=1,
        line_end=1,
        snippet="eval(payload)",
        message="Dynamic execution was detected.",
        confidence=0.9,
        tags=["dynamic-execution"],
        citations=["PYTHON_EVAL"],
    )

    explanation = explain_from_evidence([finding])

    assert explanation.sentences
    assert all("F001" in sentence for sentence in explanation.sentences)


def test_provider_prompt_loads_skill_and_evidence() -> None:
    finding = Finding(
        finding_id="F002",
        rule_id="PY002_SUBPROCESS",
        severity=Severity.HIGH,
        category="command-execution",
        file_path="setup.py",
        line_start=3,
        line_end=3,
        snippet="subprocess.call(['echo', 'x'])",
        message="Subprocess or shell command execution was detected.",
        confidence=0.9,
        tags=["process"],
        citations=["CHASE"],
    )

    prompt = build_provider_prompt([finding])

    assert "pypi-ai-model" in prompt
    assert "F002" in prompt
    assert "subprocess.call" in prompt


def test_provider_health_messages() -> None:
    assert "Ollama local" in provider_health("ollama-local")
    assert "Gemini" in provider_health("gemini")
    assert "Ollama Cloud" in provider_health("ollama-cloud")
    assert "deterministic" in provider_health("none")
    assert "unknown provider" in provider_health("other")
