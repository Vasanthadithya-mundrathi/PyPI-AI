from __future__ import annotations

from pypi_ai.models import ScanResult


def recommend_actions(result: ScanResult, sandbox_status: str) -> dict[str, object]:
    level = result.risk.level.value
    if level in {"critical", "high"}:
        action = "block"
        commands = ["Do not install automatically.", "Create a fresh virtualenv before review."]
    elif level == "medium" or sandbox_status in {"failed", "timeout"}:
        action = "manual-review"
        commands = ["Install only in an isolated environment after manual review."]
    else:
        action = "allow-with-monitoring"
        commands = ["Install in a project virtualenv, not system Python."]
    return {
        "recommended_action": action,
        "risk_level": level,
        "commands": commands,
    }
