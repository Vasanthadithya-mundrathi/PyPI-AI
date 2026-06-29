from __future__ import annotations

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
    return PackageMetadata(name=root.name if root.exists() else None, version=None, root=root)
