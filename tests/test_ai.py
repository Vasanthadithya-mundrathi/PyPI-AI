from __future__ import annotations

from pypi_ai.ai import (
    DEFAULT_OLLAMA_CLOUD_MODEL,
    FALLBACK_OLLAMA_CLOUD_MODEL,
    EvidenceVerifier,
    ProviderRequest,
    build_provider_prompt,
    explain_from_evidence,
    provider_health,
    resolve_model,
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
    assert DEFAULT_OLLAMA_CLOUD_MODEL in provider_health("ollama-cloud")
    assert FALLBACK_OLLAMA_CLOUD_MODEL in provider_health("ollama-cloud")
    assert "deterministic" in provider_health("none")
    assert "unknown provider" in provider_health("other")


def test_resolve_model_defaults_to_fast_defensible_models() -> None:
    assert resolve_model("ollama-cloud", None) == "glm-5.2:cloud"
    assert resolve_model("ollama-local", None) == "llama3.2:latest"
    assert resolve_model("gemini", None) == "gemini-2.5-flash"
    assert resolve_model("ollama-cloud", "minimax-m3:cloud") == "minimax-m3:cloud"


def test_explain_from_evidence_calls_provider_transport_and_verifies_output() -> None:
    finding = Finding(
        finding_id="F001",
        rule_id="PY002_SUBPROCESS",
        severity=Severity.HIGH,
        category="command-execution",
        file_path="pkg/mod.py",
        line_start=5,
        line_end=5,
        snippet="sp.run(['id'])",
        message="Subprocess or shell command execution was detected.",
        confidence=0.9,
        tags=["process"],
        citations=["CHASE"],
    )
    seen: list[ProviderRequest] = []

    def fake_transport(request: ProviderRequest) -> str:
        seen.append(request)
        return "Subprocess execution is risky because it launches commands. [F001]\nUnsupported."

    explanation = explain_from_evidence(
        [finding],
        provider="ollama-local",
        model="demo-model",
        transport=fake_transport,
        timeout_seconds=1,
    )

    assert seen
    assert seen[0].provider == "ollama-local"
    assert seen[0].model == "demo-model"
    assert "F001" in seen[0].prompt
    assert explanation.used_fallback is False
    assert explanation.sentences == [
        "Subprocess execution is risky because it launches commands. [F001]"
    ]


def test_explain_from_evidence_falls_back_when_provider_fails() -> None:
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
        citations=["CHASE"],
    )

    def failing_transport(request: ProviderRequest) -> str:
        _ = request
        raise TimeoutError("model timed out")

    explanation = explain_from_evidence(
        [finding],
        provider="ollama-local",
        transport=failing_transport,
        timeout_seconds=1,
    )

    assert explanation.used_fallback is True
    assert explanation.fallback_reason == "model timed out"
    assert explanation.sentences
    assert all("[F001]" in sentence for sentence in explanation.sentences)
