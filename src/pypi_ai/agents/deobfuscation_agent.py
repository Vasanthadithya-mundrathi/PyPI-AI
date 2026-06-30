from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DecodedString:
    file_path: str
    encoding: str
    value: str

    def to_dict(self) -> dict[str, str]:
        return {"file_path": self.file_path, "encoding": self.encoding, "value": self.value}


BASE64_RE = re.compile(r"['\"]([A-Za-z0-9+/]{16,}={0,2})['\"]")
HEX_RE = re.compile(r"['\"]((?:\\x[0-9a-fA-F]{2}){4,})['\"]")


def decode_obfuscated_strings(root: Path, *, limit: int = 25) -> list[DecodedString]:
    if not root.is_dir():
        return []
    decoded: list[DecodedString] = []
    for file_path in sorted(root.rglob("*.py")):
        if len(decoded) >= limit:
            break
        text = file_path.read_text(encoding="utf-8", errors="ignore")
        for item in _decode_text(text, file_path.relative_to(root).as_posix()):
            decoded.append(item)
            if len(decoded) >= limit:
                break
    return decoded


def _decode_text(text: str, file_path: str) -> list[DecodedString]:
    decoded: list[DecodedString] = []
    for match in BASE64_RE.finditer(text):
        try:
            value = base64.b64decode(match.group(1), validate=True).decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            continue
        if _looks_useful(value):
            decoded.append(DecodedString(file_path, "base64", value[:200]))
    for match in HEX_RE.finditer(text):
        try:
            value = bytes.fromhex(match.group(1).replace("\\x", "")).decode("utf-8", "ignore")
        except ValueError:
            continue
        if _looks_useful(value):
            decoded.append(DecodedString(file_path, "hex", value[:200]))
    return decoded


def _looks_useful(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in ("http", "socket", "token", "eval", "exec"))
