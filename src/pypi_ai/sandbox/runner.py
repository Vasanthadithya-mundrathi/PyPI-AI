from __future__ import annotations

from pathlib import Path

from pypi_ai.sandbox.docker_client import run_docker_probe
from pypi_ai.sandbox.policy import DockerSandboxPolicy
from pypi_ai.sandbox.telemetry import SandboxReport, SandboxTelemetry


def run_sandbox_probe(artifact: Path, policy: DockerSandboxPolicy) -> SandboxReport:
    payload = run_docker_probe(artifact, policy)
    telemetry = SandboxTelemetry(
        process_events=_event_list(payload.get("process_events")),
        file_events=_event_list(payload.get("file_events")),
        network_events=_event_list(payload.get("network_events")),
        import_events=_event_list(payload.get("import_events")),
    )
    return SandboxReport(status=str(payload.get("status", "complete")), telemetry=telemetry)


def _event_list(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]
