from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pypi_ai.models import Finding

DEFAULT_OLLAMA_LOCAL_MODEL = "llama3.2:latest"
DEFAULT_OLLAMA_CLOUD_MODEL = "glm-5.2:cloud"
FALLBACK_OLLAMA_CLOUD_MODEL = "minimax-m3:cloud"
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"


@dataclass(frozen=True)
class Explanation:
    provider: str
    sentences: list[str]
    evidence_ids: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "sentences": list(self.sentences),
            "evidence_ids": list(self.evidence_ids),
        }


class EvidenceVerifier:
    def __init__(self, findings: list[Finding]) -> None:
        self.finding_ids = {finding.finding_id for finding in findings}

    def verify_sentence(self, sentence: str) -> bool:
        return any(f"[{finding_id}]" in sentence for finding_id in self.finding_ids)

    def filter_sentences(self, sentences: list[str]) -> list[str]:
        return [sentence for sentence in sentences if self.verify_sentence(sentence)]


def resolve_model(provider: str, model: str | None) -> str:
    if model:
        return model
    if provider == "ollama-cloud":
        return DEFAULT_OLLAMA_CLOUD_MODEL
    if provider == "ollama-local":
        return DEFAULT_OLLAMA_LOCAL_MODEL
    if provider == "gemini":
        return DEFAULT_GEMINI_MODEL
    return "deterministic"


def explain_from_evidence(
    findings: list[Finding],
    provider: str = "deterministic",
    model: str | None = None,
) -> Explanation:
    resolved_model = resolve_model(provider, model)
    sentences = [
        (
            f"{finding.message} Category: {finding.category}; severity: "
            f"{finding.severity.value}; file: {finding.file_path}:{finding.line_start}. "
            f"[{finding.finding_id}]"
        )
        for finding in findings[:8]
    ]
    verifier = EvidenceVerifier(findings)
    return Explanation(
        provider=f"{provider}:{resolved_model}",
        sentences=verifier.filter_sentences(sentences),
        evidence_ids=[finding.finding_id for finding in findings],
    )


def load_ai_model_skill() -> str:
    root = Path(__file__).resolve().parents[2]
    skill_path = root / "skills" / "pypi-ai-model" / "SKILL.md"
    if skill_path.exists():
        return skill_path.read_text(encoding="utf-8")
    return (
        "Evidence-grounded PyPi-AI model skill. Never produce an unsupported claim; "
        "every sentence must cite a valid evidence ID."
    )


def build_provider_prompt(findings: list[Finding]) -> str:
    evidence_lines = [
        f"{finding.finding_id}: {finding.rule_id} {finding.file_path}:{finding.line_start} "
        f"{finding.message} Snippet: {finding.snippet!r}"
        for finding in findings
    ]
    return f"{load_ai_model_skill()}\n\nEvidence:\n" + "\n".join(evidence_lines)


def provider_health(provider: str, model: str | None = None) -> str:
    resolved_model = resolve_model(provider, model)
    if provider == "none":
        return "deterministic evidence-only mode is available"
    if provider == "gemini":
        return f"Gemini provider uses {resolved_model} through GEMINI_API_KEY when available"
    if provider == "ollama-local":
        return f"Ollama local provider uses {resolved_model} and expects http://localhost:11434"
    if provider == "ollama-cloud":
        return (
            f"Ollama Cloud provider uses {resolved_model} and expects "
            "OLLAMA_API_KEY or a signed-in Ollama client. "
            f"Fallback cloud model: {FALLBACK_OLLAMA_CLOUD_MODEL}"
        )
    return f"unknown provider: {provider}"
