from __future__ import annotations

import tomllib
from email.parser import Parser
from pathlib import Path

from pypi_ai.models import PackageMetadata


def parse_metadata_file(path: Path) -> tuple[str | None, str | None]:
    if not path.exists():
        return None, None
    parsed = Parser().parsestr(path.read_text(encoding="utf-8", errors="replace"))
    return parsed.get("Name"), parsed.get("Version")


def discover_package_metadata(root: Path) -> PackageMetadata:
    for pattern in ("*.dist-info/METADATA", "PKG-INFO"):
        for metadata_file in root.rglob(pattern):
            name, version = parse_metadata_file(metadata_file)
            if name or version:
                return PackageMetadata(name=name, version=version, root=root)
    pyproject_name, pyproject_version = parse_pyproject(root / "pyproject.toml")
    if pyproject_name or pyproject_version:
        return PackageMetadata(name=pyproject_name, version=pyproject_version, root=root)
    return PackageMetadata(name=root.name if root.exists() else None, version=None, root=root)


def parse_pyproject(path: Path) -> tuple[str | None, str | None]:
    if not path.exists():
        return None, None
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError:
        return None, None
    project = payload.get("project", {})
    if not isinstance(project, dict):
        return None, None
    name = project.get("name")
    version = project.get("version")
    return (
        name if isinstance(name, str) else None,
        version if isinstance(version, str) else None,
    )
