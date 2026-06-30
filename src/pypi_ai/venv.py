from __future__ import annotations

from pathlib import Path

from pypi_ai.analyzer import analyze_python_file
from pypi_ai.constants import CITATIONS, DEVELOPERS, PROJECT_NAME, VERSION
from pypi_ai.metadata import parse_metadata_file
from pypi_ai.models import Finding, PackageMetadata, ScanPlan, ScanResult, ScanSummary
from pypi_ai.risk import calculate_risk
from pypi_ai.scanner import LIMITATIONS

NON_RUNTIME_PARTS = {
    "__pycache__",
    ".git",
    ".venv",
    "venv",
    "test",
    "tests",
    "testing",
    "benchmark",
    "benchmarks",
    "docs",
    "doc",
}


def find_site_packages(venv_path: Path | str) -> Path:
    root = Path(venv_path)
    candidates = sorted(root.glob("lib/python*/site-packages")) + sorted(
        root.glob("Lib/site-packages")
    )
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    raise FileNotFoundError(f"No site-packages directory found in {root}")


def scan_venv(
    venv_path: Path | str,
    *,
    dry_run: bool = False,
    trace_rules: bool = False,
) -> ScanResult:
    root = Path(venv_path)
    site_packages = find_site_packages(root)
    distributions = _discover_distributions(site_packages)
    files = _discover_package_files(site_packages, distributions)
    plan = ScanPlan(
        target=str(root),
        input_type="venv",
        files_discovered=sum(len(paths) for paths in files.values()),
        safety_notes=[
            "Installed packages are scanned from disk without importing them.",
            "Distribution metadata is read from .dist-info directories.",
        ],
    )
    if dry_run:
        return _venv_result(root, [], 0, 0, plan, [])

    findings: list[Finding] = []
    trace: list[str] = []
    for package_root, metadata in distributions.items():
        package_files = files.get(package_root, [])
        for file_path in package_files:
            before = len(findings)
            findings.extend(
                analyze_python_file(file_path, package_root, metadata, len(findings) + 1)
            )
            if trace_rules:
                matched = len(findings) - before
                trace.append(f"{metadata.name or package_root.name}/{file_path.name}: {matched}")
    return _venv_result(
        root, findings, sum(len(paths) for paths in files.values()), len(distributions), plan, trace
    )


def _discover_distributions(site_packages: Path) -> dict[Path, PackageMetadata]:
    distributions: dict[Path, PackageMetadata] = {}
    for dist_info in sorted(site_packages.glob("*.dist-info")):
        name, version = parse_metadata_file(dist_info / "METADATA")
        if not name:
            continue
        package_root = site_packages / name.replace("-", "_")
        if not package_root.exists():
            package_root = site_packages / name
        if package_root.exists():
            distributions[package_root] = PackageMetadata(
                name=name, version=version, root=package_root
            )
    return distributions


def _discover_package_files(
    site_packages: Path,
    distributions: dict[Path, PackageMetadata],
) -> dict[Path, list[Path]]:
    package_files: dict[Path, list[Path]] = {}
    for package_root in distributions:
        if package_root.is_file() and package_root.suffix == ".py":
            package_files[package_root] = [package_root]
        elif package_root.is_dir():
            package_files[package_root] = [
                path
                for path in sorted(package_root.rglob("*.py"))
                if not _is_non_runtime_file(package_root, path)
            ]
    return package_files


def _is_non_runtime_file(package_root: Path, file_path: Path) -> bool:
    try:
        relative_parts = file_path.relative_to(package_root).parts
    except ValueError:
        relative_parts = file_path.parts
    return bool(NON_RUNTIME_PARTS.intersection(relative_parts[:-1]))


def _venv_result(
    target: Path,
    findings: list[Finding],
    files_scanned: int,
    packages_scanned: int,
    plan: ScanPlan,
    trace: list[str],
) -> ScanResult:
    return ScanResult(
        project={
            "name": PROJECT_NAME,
            "version": VERSION,
            "developers": DEVELOPERS,
            "safety": "Static-only scanner; never executes untrusted package code.",
        },
        summary=ScanSummary(
            target=str(target),
            input_type="venv",
            files_scanned=files_scanned,
            packages_scanned=packages_scanned,
            total_findings=len(findings),
        ),
        risk=calculate_risk(findings),
        findings=findings,
        scan_plan=plan,
        rule_trace=trace,
        citations=CITATIONS,
        limitations=LIMITATIONS,
    )
