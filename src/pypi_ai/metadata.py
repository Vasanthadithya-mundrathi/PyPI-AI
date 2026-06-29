from __future__ import annotations

import tomllib
from email.parser import Parser
from pathlib import Path
from typing import Any

from pypi_ai.models import PackageMetadata


def parse_metadata_file(path: Path) -> tuple[str | None, str | None]:
    metadata = parse_package_metadata_file(path, path.parent)
    return metadata.name, metadata.version


def parse_package_metadata_file(path: Path, root: Path) -> PackageMetadata:
    if not path.exists():
        return PackageMetadata(name=None, version=None, root=root)
    parsed = Parser().parsestr(path.read_text(encoding="utf-8", errors="replace"))
    urls: dict[str, str] = {}
    home_page = parsed.get("Home-page")
    if home_page:
        urls["Homepage"] = home_page
    for project_url in parsed.get_all("Project-URL", []):
        label, separator, value = project_url.partition(",")
        if separator:
            urls[label.strip()] = value.strip()
    authors = _compact([parsed.get("Author"), parsed.get("Author-email")])
    maintainers = _compact([parsed.get("Maintainer"), parsed.get("Maintainer-email")])
    return PackageMetadata(
        name=parsed.get("Name"),
        version=parsed.get("Version"),
        root=root,
        authors=authors,
        maintainers=maintainers,
        dependencies=[str(item) for item in parsed.get_all("Requires-Dist", [])],
        urls=urls,
    )


def discover_package_metadata(root: Path) -> PackageMetadata:
    for pattern in ("*.dist-info/METADATA", "PKG-INFO"):
        for metadata_file in root.rglob(pattern):
            metadata = parse_package_metadata_file(metadata_file, root)
            if metadata.name or metadata.version:
                return metadata
    pyproject_metadata = parse_pyproject_metadata(root / "pyproject.toml", root)
    if pyproject_metadata.name or pyproject_metadata.version:
        return pyproject_metadata
    return PackageMetadata(name=root.name if root.exists() else None, version=None, root=root)


def parse_pyproject(path: Path) -> tuple[str | None, str | None]:
    metadata = parse_pyproject_metadata(path, path.parent)
    return metadata.name, metadata.version


def parse_pyproject_metadata(path: Path, root: Path) -> PackageMetadata:
    if not path.exists():
        return PackageMetadata(name=None, version=None, root=root)
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError:
        return PackageMetadata(name=None, version=None, root=root)
    project = payload.get("project", {})
    if not isinstance(project, dict):
        return PackageMetadata(name=None, version=None, root=root)
    name = project.get("name")
    version = project.get("version")
    urls = project.get("urls", {})
    dependencies = project.get("dependencies", [])
    return PackageMetadata(
        name=name if isinstance(name, str) else None,
        version=version if isinstance(version, str) else None,
        root=root,
        authors=_people(project.get("authors", [])),
        maintainers=_people(project.get("maintainers", [])),
        dependencies=[item for item in dependencies if isinstance(item, str)]
        if isinstance(dependencies, list)
        else [],
        urls={str(key): str(value) for key, value in urls.items()}
        if isinstance(urls, dict)
        else {},
    )


def _people(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    people: list[str] = []
    for item in value:
        if isinstance(item, str):
            people.append(item)
        elif isinstance(item, dict):
            name = item.get("name")
            email = item.get("email")
            people.extend(
                [
                    part
                    for part in (
                        name if isinstance(name, str) else None,
                        email if isinstance(email, str) else None,
                    )
                    if part
                ]
            )
    return people


def _compact(values: list[Any]) -> list[str]:
    return [str(value) for value in values if value]
