from __future__ import annotations

import json
import random
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast
from urllib.parse import quote
from urllib.request import urlopen

from pypi_ai.models import ScanResult, Severity
from pypi_ai.scanner import scan_path

TOP_PYPI_PACKAGES_URL = (
    "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
)
LIVE_SAMPLE_EXCLUDED_PACKAGES = {
    "pip",
    "setuptools",
    "wheel",
    "build",
    "twine",
    "virtualenv",
}


class JsonFetcher(Protocol):
    def __call__(self, url: str) -> dict[str, Any]: ...


class WheelDownloader(Protocol):
    def __call__(
        self, package: PlannedPackage, package_dir: Path, timeout_seconds: float
    ) -> Path: ...


class Scanner(Protocol):
    def __call__(self, target: Path) -> ScanResult: ...


@dataclass(frozen=True)
class PlannedPackage:
    name: str
    version: str
    wheel_filename: str
    wheel_size_bytes: int
    wheel_url: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "wheel_filename": self.wheel_filename,
            "wheel_size_bytes": self.wheel_size_bytes,
            "wheel_url": self.wheel_url,
        }


@dataclass(frozen=True)
class ChasePlan:
    source_url: str
    strategy: str
    sample_size: int
    candidate_pool: int
    max_wheel_mb: float
    seed: int | None
    packages: list[PlannedPackage]
    safety_notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_url": self.source_url,
            "strategy": self.strategy,
            "sample_size": self.sample_size,
            "candidate_pool": self.candidate_pool,
            "max_wheel_mb": self.max_wheel_mb,
            "seed": self.seed,
            "packages": [package.to_dict() for package in self.packages],
            "safety_notes": list(self.safety_notes),
        }


@dataclass(frozen=True)
class ChasePackageResult:
    package: str
    version: str
    status: str
    wheel_path: str | None
    risk_level: str | None
    risk_score: int | None
    finding_count: int
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "version": self.version,
            "status": self.status,
            "wheel_path": self.wheel_path,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "finding_count": self.finding_count,
            "error": self.error,
        }


@dataclass(frozen=True)
class ChaseRunResult:
    plan: ChasePlan
    results: list[ChasePackageResult]

    def to_dict(self) -> dict[str, Any]:
        scanned = [result for result in self.results if result.status == "scanned"]
        failed = [result for result in self.results if result.status != "scanned"]
        return {
            "plan": self.plan.to_dict(),
            "summary": {
                "planned_packages": len(self.plan.packages),
                "scanned_packages": len(scanned),
                "failed_packages": len(failed),
                "total_findings": sum(result.finding_count for result in scanned),
                "max_risk_level": _max_risk(result.risk_level for result in scanned),
            },
            "results": [result.to_dict() for result in self.results],
        }


def build_live_chase_plan(
    *,
    sample_size: int = 5,
    candidate_pool: int = 250,
    max_wheel_mb: float = 5.0,
    seed: int | None = None,
    source_url: str = TOP_PYPI_PACKAGES_URL,
    fetch_json: JsonFetcher | None = None,
) -> ChasePlan:
    """Build a scan plan from live PyPI package popularity data."""
    if fetch_json is None:
        fetch_json = _fetch_json
    if sample_size < 1:
        raise ValueError("sample_size must be at least 1")
    if candidate_pool < sample_size:
        raise ValueError("candidate_pool must be greater than or equal to sample_size")
    if max_wheel_mb <= 0:
        raise ValueError("max_wheel_mb must be greater than 0")

    names = [
        name
        for name in _top_package_names(fetch_json(source_url))
        if name.lower() not in LIVE_SAMPLE_EXCLUDED_PACKAGES
    ][:candidate_pool]
    if len(names) < sample_size:
        raise RuntimeError("Not enough live package names were returned to build a plan.")

    shuffled = list(names)
    random.Random(seed).shuffle(shuffled)
    max_bytes = int(max_wheel_mb * 1024 * 1024)
    selected: list[PlannedPackage] = []
    for name in shuffled:
        metadata_url = f"https://pypi.org/pypi/{quote(name)}/json"
        metadata = fetch_json(metadata_url)
        package = _planned_package_from_metadata(metadata, max_bytes=max_bytes)
        if package is None:
            continue
        selected.append(package)
        if len(selected) == sample_size:
            break

    if len(selected) < sample_size:
        raise RuntimeError(
            "Could not find enough packages with non-yanked wheels under the configured size."
        )

    return ChasePlan(
        source_url=source_url,
        strategy="agentic-plan-then-execute-real-pypi-wheel-scan",
        sample_size=sample_size,
        candidate_pool=candidate_pool,
        max_wheel_mb=max_wheel_mb,
        seed=seed,
        packages=selected,
        safety_notes=[
            "Package names are selected from a live PyPI popularity dataset at runtime.",
            "Only wheel archives are downloaded; source distributions are skipped.",
            "Downloaded wheels are scanned statically and are not installed, imported, "
            "or executed.",
            "The executor continues across package failures and records errors in the report.",
        ],
    )


def execute_chase_plan(
    plan: ChasePlan,
    *,
    download_dir: Path,
    timeout_seconds: float = 120.0,
    downloader: WheelDownloader | None = None,
    scanner: Scanner = scan_path,
) -> ChaseRunResult:
    if downloader is None:
        downloader = _download_planned_wheel
    download_dir.mkdir(parents=True, exist_ok=True)
    results: list[ChasePackageResult] = []
    for package in plan.packages:
        package_dir = download_dir / _safe_directory_name(f"{package.name}-{package.version}")
        package_dir.mkdir(parents=True, exist_ok=True)
        try:
            wheel_path = downloader(package, package_dir, timeout_seconds)
            scan_result = scanner(wheel_path)
            results.append(
                ChasePackageResult(
                    package=package.name,
                    version=package.version,
                    status="scanned",
                    wheel_path=str(wheel_path),
                    risk_level=scan_result.risk.level.value,
                    risk_score=scan_result.risk.score,
                    finding_count=len(scan_result.findings),
                )
            )
        except (RuntimeError, ValueError) as exc:
            results.append(
                ChasePackageResult(
                    package=package.name,
                    version=package.version,
                    status="failed",
                    wheel_path=None,
                    risk_level=None,
                    risk_score=None,
                    finding_count=0,
                    error=str(exc),
                )
            )
    return ChaseRunResult(plan=plan, results=results)


def _fetch_json(url: str) -> dict[str, Any]:
    with urlopen(url, timeout=20) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"Expected JSON object from {url}")
    return cast(dict[str, Any], payload)


def _top_package_names(payload: dict[str, Any]) -> list[str]:
    rows = payload.get("rows")
    if not isinstance(rows, list):
        raise RuntimeError("Top PyPI package payload did not contain rows.")
    names: list[str] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        project = row.get("project")
        if not isinstance(project, str) or not project:
            continue
        normalized = project.strip()
        if normalized and normalized.lower() not in seen:
            names.append(normalized)
            seen.add(normalized.lower())
    return names


def _planned_package_from_metadata(
    payload: dict[str, Any],
    *,
    max_bytes: int,
) -> PlannedPackage | None:
    info = payload.get("info")
    releases = payload.get("releases")
    if not isinstance(info, dict) or not isinstance(releases, dict):
        return None
    name = info.get("name")
    version = info.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        return None
    release_files = releases.get(version)
    if not isinstance(release_files, list):
        return None
    wheels = [
        file_info
        for file_info in release_files
        if isinstance(file_info, dict)
        and file_info.get("packagetype") == "bdist_wheel"
        and file_info.get("yanked") is not True
        and isinstance(file_info.get("filename"), str)
        and isinstance(file_info.get("url"), str)
        and isinstance(file_info.get("size"), int)
        and cast(int, file_info["size"]) <= max_bytes
    ]
    if not wheels:
        return None
    wheel = min(wheels, key=lambda file_info: cast(int, file_info["size"]))
    return PlannedPackage(
        name=name,
        version=version,
        wheel_filename=cast(str, wheel["filename"]),
        wheel_size_bytes=cast(int, wheel["size"]),
        wheel_url=cast(str, wheel["url"]),
    )


def _download_planned_wheel(
    package: PlannedPackage, package_dir: Path, timeout_seconds: float
) -> Path:
    destination = package_dir / package.wheel_filename
    with urlopen(package.wheel_url, timeout=timeout_seconds) as response:
        destination.write_bytes(response.read())
    if destination.stat().st_size == 0:
        raise RuntimeError(f"Downloaded empty wheel for {package.name}")
    return destination


def _safe_directory_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-") or "package"


def _max_risk(levels: Iterable[str | None]) -> str:
    order = {
        Severity.INFO.value: 0,
        Severity.LOW.value: 1,
        Severity.MEDIUM.value: 2,
        Severity.HIGH.value: 3,
        Severity.CRITICAL.value: 4,
    }
    max_level = Severity.INFO.value
    for level in levels:
        if isinstance(level, str) and order.get(level, -1) > order[max_level]:
            max_level = level
    return max_level
