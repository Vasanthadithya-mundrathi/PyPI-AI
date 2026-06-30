from __future__ import annotations


def import_event(module: str) -> dict[str, str]:
    return {"type": "import", "module": module}
