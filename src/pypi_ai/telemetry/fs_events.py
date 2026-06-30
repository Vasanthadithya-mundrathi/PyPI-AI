from __future__ import annotations


def fs_event(path: str, operation: str) -> dict[str, str]:
    return {"type": "file", "path": path, "operation": operation}
