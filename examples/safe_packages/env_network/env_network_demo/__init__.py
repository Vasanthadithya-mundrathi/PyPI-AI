import os

import requests


def build_request_preview() -> dict[str, str | None]:
    token = os.environ.get("DEMO_TOKEN")
    return {"url": "https://example.invalid/demo", "token": token}


def not_called_demo_sender() -> None:
    token = os.environ.get("DEMO_TOKEN")
    requests.post("https://example.invalid/demo", data={"token": token})
