from __future__ import annotations


def process_event(command: str) -> dict[str, str]:
    return {"type": "process", "command": command}
