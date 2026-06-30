from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote
from urllib.request import urlopen


def resolve_artifact(target: str, download_root: Path, timeout_seconds: float) -> tuple[Path, str]:
    """Normalize a local path or PyPI package specifier into a scan artifact."""
    target_path = Path(target)
    if target_path.exists():
        return target_path, "local"
    return download_pypi_wheel(target, download_root, timeout_seconds), "pypi"


def download_pypi_wheel(package: str, download_root: Path, timeout_seconds: float) -> Path:
    download_root.mkdir(parents=True, exist_ok=True)
    name, pinned_version = _parse_package_specifier(package)
    metadata = _fetch_json(f"https://pypi.org/pypi/{quote(name)}/json", timeout_seconds)
    wheel = _select_wheel(metadata, pinned_version)
    destination = download_root / str(wheel["filename"])
    with urlopen(str(wheel["url"]), timeout=timeout_seconds) as response:
        destination.write_bytes(response.read())
    if destination.stat().st_size == 0:
        raise RuntimeError(f"Downloaded empty wheel for {package}")
    return destination


def _parse_package_specifier(package: str) -> tuple[str, str | None]:
    match = re.fullmatch(r"([A-Za-z0-9_.-]+)(?:==([A-Za-z0-9_.!+-]+))?", package.strip())
    if match is None:
        raise RuntimeError(f"Unsupported package specifier for safe wheel intake: {package}")
    return match.group(1), match.group(2)


def _fetch_json(url: str, timeout_seconds: float) -> dict[str, Any]:
    with urlopen(url, timeout=timeout_seconds) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"Expected JSON object from {url}")
    return cast(dict[str, Any], payload)


def _select_wheel(metadata: dict[str, Any], pinned_version: str | None) -> dict[str, object]:
    info = metadata.get("info")
    releases = metadata.get("releases")
    if not isinstance(info, dict) or not isinstance(releases, dict):
        raise RuntimeError("PyPI metadata did not include release information.")
    version = pinned_version or info.get("version")
    if not isinstance(version, str):
        raise RuntimeError("PyPI metadata did not include a usable version.")
    files = releases.get(version)
    if not isinstance(files, list):
        raise RuntimeError(f"No release files found for version {version}")
    wheels = [
        file_info
        for file_info in files
        if isinstance(file_info, dict)
        and file_info.get("packagetype") == "bdist_wheel"
        and file_info.get("yanked") is not True
        and isinstance(file_info.get("filename"), str)
        and isinstance(file_info.get("url"), str)
    ]
    if not wheels:
        raise RuntimeError(f"No non-yanked wheel found for version {version}")
    return cast(dict[str, object], min(wheels, key=lambda item: int(item.get("size", 0))))
