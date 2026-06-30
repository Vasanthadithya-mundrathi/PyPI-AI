from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

from pypi_ai.sandbox.policy import DockerSandboxPolicy


def docker_available() -> bool:
    return shutil.which("docker") is not None


def run_docker_probe(artifact: Path, policy: DockerSandboxPolicy) -> dict[str, Any]:
    if not docker_available():
        raise FileNotFoundError("Docker CLI not found")
    command = [
        "docker",
        "run",
        *policy.docker_args(),
        "-v",
        f"{artifact.resolve().parent}:/input:ro",
        policy.image,
        "/input/" + artifact.name,
    ]
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=policy.timeout_seconds,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no output"
        raise RuntimeError(f"Docker sandbox failed: {detail}")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Docker sandbox returned non-JSON telemetry") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("Docker sandbox returned invalid telemetry")
    return cast(dict[str, Any], payload)
