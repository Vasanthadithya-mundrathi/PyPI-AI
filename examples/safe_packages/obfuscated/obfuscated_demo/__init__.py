import base64


def decode_preview() -> str:
    payload = base64.b64decode("MSArIDE=").decode()
    return payload


def not_called_dynamic_execution() -> object:
    payload = "1 + 1"
    return eval(payload)
