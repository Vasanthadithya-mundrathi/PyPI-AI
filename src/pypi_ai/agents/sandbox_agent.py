from __future__ import annotations

from pathlib import Path

from pypi_ai.sandbox.policy import DockerSandboxPolicy
from pypi_ai.sandbox.runner import run_sandbox_probe


def run_behavior_probe(
    artifact: Path,
    *,
    enabled: bool,
    timeout_seconds: int,
    image: str,
) -> dict[str, object]:
    if not enabled:
        return {"status": "skipped", "reason": "sandbox disabled"}
    policy = DockerSandboxPolicy(timeout_seconds=timeout_seconds, image=image)
    try:
        return run_sandbox_probe(artifact, policy).to_dict()
    except (FileNotFoundError, RuntimeError, TimeoutError) as exc:
        return {"status": "failed", "reason": str(exc)}
