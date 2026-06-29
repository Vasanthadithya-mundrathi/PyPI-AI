from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urljoin
from urllib.request import Request, urlopen

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
    used_fallback: bool = False
    fallback_reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "sentences": list(self.sentences),
            "evidence_ids": list(self.evidence_ids),
            "used_fallback": self.used_fallback,
            "fallback_reason": self.fallback_reason,
        }


@dataclass(frozen=True)
class ProviderRequest:
    provider: str
    model: str
    prompt: str
    timeout_seconds: float


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
    *,
    transport: Any | None = None,
    timeout_seconds: float = 20.0,
) -> Explanation:
    resolved_model = resolve_model(provider, model)
    if provider in {"none", "deterministic"}:
        return _deterministic_explanation(findings, provider, resolved_model)
    request = ProviderRequest(
        provider=provider,
        model=resolved_model,
        prompt=build_provider_prompt(findings),
        timeout_seconds=timeout_seconds,
    )
    selected_transport = transport or call_provider
    verifier = EvidenceVerifier(findings)
    try:
        raw_text = str(selected_transport(request))
        verified = verifier.filter_sentences(_split_sentences(raw_text))
        if verified:
            return Explanation(
                provider=f"{provider}:{resolved_model}",
                sentences=verified,
                evidence_ids=[finding.finding_id for finding in findings],
            )
        return _deterministic_explanation(
            findings,
            provider,
            resolved_model,
            fallback_reason="provider returned no evidence-grounded sentences",
        )
    except Exception as exc:
        return _deterministic_explanation(
            findings,
            provider,
            resolved_model,
            fallback_reason=str(exc),
        )


def _deterministic_explanation(
    findings: list[Finding],
    provider: str,
    resolved_model: str,
    *,
    fallback_reason: str | None = None,
) -> Explanation:
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
        used_fallback=fallback_reason is not None,
        fallback_reason=fallback_reason,
    )


def call_provider(request: ProviderRequest) -> str:
    if request.provider == "ollama-local":
        return _call_ollama_local(request)
    if request.provider == "ollama-cloud":
        return _call_ollama_cloud_cli(request)
    if request.provider == "gemini":
        return _call_gemini(request)
    raise ValueError(f"unknown provider: {request.provider}")


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


def _call_ollama_local(request: ProviderRequest) -> str:
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    endpoint = urljoin(host.rstrip("/") + "/", "api/generate")
    body = json.dumps(
        {
            "model": request.model,
            "prompt": request.prompt,
            "stream": False,
            "options": {"temperature": 0},
        }
    ).encode("utf-8")
    http_request = Request(
        endpoint,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "PyPi-AI/0.1"},
        method="POST",
    )
    with urlopen(http_request, timeout=request.timeout_seconds) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Ollama returned a non-object response")
    return str(payload.get("response", ""))


def _call_ollama_cloud_cli(request: ProviderRequest) -> str:
    completed = subprocess.run(
        ["ollama", "run", request.model, request.prompt],
        check=False,
        capture_output=True,
        text=True,
        timeout=request.timeout_seconds,
    )
    if completed.returncode != 0:
        error = completed.stderr.strip() or completed.stdout.strip() or "ollama cloud failed"
        raise RuntimeError(error)
    return completed.stdout.strip()


def _call_gemini(request: ProviderRequest) -> str:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not set")
    endpoint = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{quote(request.model, safe='')}:generateContent?key={quote(api_key, safe='')}"
    )
    body = json.dumps(
        {
            "contents": [{"parts": [{"text": request.prompt}]}],
            "generationConfig": {"temperature": 0},
        }
    ).encode("utf-8")
    http_request = Request(
        endpoint,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "PyPi-AI/0.1"},
        method="POST",
    )
    with urlopen(http_request, timeout=request.timeout_seconds) as response:
        payload = json.loads(response.read().decode("utf-8"))
    return _gemini_text(payload)


def _gemini_text(payload: object) -> str:
    if not isinstance(payload, dict):
        return ""
    candidates = payload.get("candidates", [])
    if not isinstance(candidates, list):
        return ""
    parts: list[str] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        content = candidate.get("content", {})
        if not isinstance(content, dict):
            continue
        for part in content.get("parts", []):
            if isinstance(part, dict):
                text = part.get("text")
                if isinstance(text, str):
                    parts.append(text)
    return "\n".join(parts)


def _split_sentences(text: str) -> list[str]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) > 1:
        return lines
    return [
        sentence.strip()
        for sentence in re.split(r"(?<=[.!?])\s+", text.strip())
        if sentence.strip()
    ]


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
