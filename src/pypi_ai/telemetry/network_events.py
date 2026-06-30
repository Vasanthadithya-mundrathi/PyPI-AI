from __future__ import annotations


def network_event(host: str, port: int) -> dict[str, object]:
    return {"type": "network", "host": host, "port": port}
