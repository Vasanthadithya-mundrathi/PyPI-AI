from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class SandboxTelemetry:
    process_events: list[dict[str, Any]] = field(default_factory=list)
    file_events: list[dict[str, Any]] = field(default_factory=list)
    network_events: list[dict[str, Any]] = field(default_factory=list)
    import_events: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "process_events": list(self.process_events),
            "file_events": list(self.file_events),
            "network_events": list(self.network_events),
            "import_events": list(self.import_events),
        }


@dataclass(frozen=True)
class SandboxReport:
    status: str
    telemetry: SandboxTelemetry
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {"status": self.status, "telemetry": self.telemetry.to_dict()}
        if self.reason:
            payload["reason"] = self.reason
        return payload
