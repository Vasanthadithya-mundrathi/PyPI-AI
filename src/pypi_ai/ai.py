from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pypi_ai.models import Finding


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


def explain_from_evidence(findings: list[Finding], provider: str = "deterministic") -> Explanation:
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
        provider=provider,
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


def provider_health(provider: str) -> str:
    if provider == "none":
        return "deterministic evidence-only mode is available"
    if provider == "gemini":
        return "Gemini provider configured through GEMINI_API_KEY when available"
    if provider == "ollama-local":
        return "Ollama local provider expects http://localhost:11434"
    if provider == "ollama-cloud":
        return "Ollama Cloud provider expects OLLAMA_API_KEY or signed-in Ollama client"
    return f"unknown provider: {provider}"
