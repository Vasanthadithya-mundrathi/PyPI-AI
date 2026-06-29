from __future__ import annotations

import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path

from pypi_ai.analyzer import analyze_python_file
from pypi_ai.constants import CITATIONS, DEVELOPERS, PROJECT_NAME, VERSION
from pypi_ai.metadata import discover_package_metadata
from pypi_ai.models import Finding, ScanPlan, ScanResult, ScanSummary
from pypi_ai.risk import calculate_risk

LIMITATIONS = [
    "Static analysis can miss behavior generated at runtime.",
    "The scanner never executes package code, so it cannot observe live network "
    "or process behavior.",
    "AI explanations are summaries of evidence and are not independent proof.",
]


def scan_path(
    target: Path | str,
    *,
    dry_run: bool = False,
    trace_rules: bool = False,
) -> ScanResult:
    target_path = Path(target)
    working_root: Path | None = None
    cleanup_dir: Path | None = None
    input_type = _detect_input_type(target_path)
    try:
        if input_type == "folder":
            working_root = target_path
        elif input_type == "wheel":
            cleanup_dir = Path(tempfile.mkdtemp(prefix="pypi-ai-wheel-"))
            _extract_wheel(target_path, cleanup_dir)
            working_root = cleanup_dir
        elif input_type == "sdist":
            cleanup_dir = Path(tempfile.mkdtemp(prefix="pypi-ai-sdist-"))
            _extract_sdist(target_path, cleanup_dir)
            working_root = cleanup_dir
        else:
            raise ValueError(f"Unsupported scan target: {target_path}")

        files = _python_files(working_root)
        plan = ScanPlan(
            target=str(target_path),
            input_type=input_type,
            files_discovered=len(files),
            safety_notes=[
                "No package code is installed, imported, or executed.",
                "Archives are extracted into temporary scanner-owned directories.",
            ],
        )
        if dry_run:
            return _build_result(target_path, input_type, [], 0, 0, plan, [])

        metadata = discover_package_metadata(working_root)
        findings: list[Finding] = []
        rule_trace_entries: list[str] = []
        for file_path in files:
            before = len(findings)
            findings.extend(
                analyze_python_file(file_path, working_root, metadata, len(findings) + 1)
            )
            if trace_rules:
                matched = len(findings) - before
                rule_trace_entries.append(
                    f"{file_path.relative_to(working_root)}: {matched} findings"
                )
        return _build_result(
            target_path,
            input_type,
            findings,
            len(files),
            1 if files else 0,
            plan,
            rule_trace_entries,
        )
    finally:
        if cleanup_dir is not None:
            shutil.rmtree(cleanup_dir, ignore_errors=True)


def _build_result(
    target: Path,
    input_type: str,
    findings: list[Finding],
    files_scanned: int,
    packages_scanned: int,
    plan: ScanPlan | None,
    rule_trace: list[str],
) -> ScanResult:
    summary = ScanSummary(
        target=str(target),
        input_type=input_type,
        files_scanned=files_scanned,
        packages_scanned=packages_scanned,
        total_findings=len(findings),
    )
    project = {
        "name": PROJECT_NAME,
        "version": VERSION,
        "developers": DEVELOPERS,
        "safety": "Static-only scanner; never executes untrusted package code.",
    }
    return ScanResult(
        project=project,
        summary=summary,
        risk=calculate_risk(findings),
        findings=findings,
        scan_plan=plan,
        rule_trace=rule_trace,
        citations=CITATIONS,
        limitations=LIMITATIONS,
    )


def _detect_input_type(target: Path) -> str:
    if target.is_dir():
        return "folder"
    name = target.name.lower()
    if name.endswith(".whl"):
        return "wheel"
    if name.endswith((".tar.gz", ".tgz")):
        return "sdist"
    return "unknown"


def _python_files(root: Path) -> list[Path]:
    ignored_parts = {"__pycache__", ".git", ".venv", "venv"}
    return sorted(
        path
        for path in root.rglob("*.py")
        if path.is_file() and not ignored_parts.intersection(path.parts)
    )


def _extract_wheel(path: Path, destination: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            target = destination / member.filename
            if not _is_safe_member(destination, target):
                raise ValueError(f"Unsafe wheel member path: {member.filename}")
            archive.extract(member, destination)


def _extract_sdist(path: Path, destination: Path) -> None:
    with tarfile.open(path) as archive:
        members = archive.getmembers()
        if len(members) > 5000:
            raise ValueError("Archive has too many files to scan safely.")
        for member in members:
            target = destination / member.name
            if not _is_safe_member(destination, target):
                raise ValueError(f"Unsafe tar member path: {member.name}")
            if member.size > 10_000_000:
                raise ValueError(f"Archive member too large: {member.name}")
        archive.extractall(destination, filter="data")


def _is_safe_member(destination: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(destination.resolve())
    except ValueError:
        return False
    return True
