from __future__ import annotations

import shutil
import tarfile
import tempfile
import zipfile
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlparse

from rapidfuzz import fuzz

from pypi_ai.analyzer import analyze_python_file
from pypi_ai.constants import CITATIONS, DEVELOPERS, PROJECT_NAME, VERSION
from pypi_ai.intelligence import Advisory, AdvisoryLookup
from pypi_ai.metadata import discover_package_metadata
from pypi_ai.models import Finding, PackageMetadata, ScanPlan, ScanResult, ScanSummary
from pypi_ai.risk import calculate_risk
from pypi_ai.rules import RULES, Rule

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
    ignored_rules: Iterable[str] = (),
    advisory_lookup: AdvisoryLookup | None = None,
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
        findings.extend(_metadata_findings(metadata, len(findings) + 1))
        findings.extend(_advisory_findings(metadata, advisory_lookup, len(findings) + 1))
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
        findings = _filter_ignored_rules(findings, ignored_rules)
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


POPULAR_PACKAGE_NAMES = {
    "boto3",
    "colorama",
    "cryptography",
    "django",
    "fastapi",
    "flask",
    "numpy",
    "pandas",
    "pillow",
    "pip",
    "pytest",
    "python-dateutil",
    "requests",
    "setuptools",
    "six",
    "torch",
    "urllib3",
}

SUSPICIOUS_URL_HOSTS = {
    "bit.ly",
    "cutt.ly",
    "discord.gg",
    "gist.githubusercontent.com",
    "ngrok.io",
    "pastebin.com",
    "raw.githubusercontent.com",
    "shorturl.at",
    "t.me",
    "tinyurl.com",
}


def _metadata_findings(metadata: PackageMetadata, start_index: int) -> list[Finding]:
    findings: list[Finding] = []
    next_index = start_index
    if _looks_typosquatted(metadata.name):
        findings.append(
            _metadata_finding(
                RULES["PY009_TYPOSQUAT_RISK"],
                next_index,
                metadata,
                metadata.name or "<unknown>",
            )
        )
        next_index += 1
    suspicious_url = _suspicious_url(metadata.urls)
    if suspicious_url:
        findings.append(
            _metadata_finding(
                RULES["PY010_SUSPICIOUS_HOMEPAGE"],
                next_index,
                metadata,
                suspicious_url,
            )
        )
        next_index += 1
    if _author_maintainer_mismatch(metadata):
        findings.append(
            _metadata_finding(
                RULES["PY011_AUTHOR_MAINTAINER_MISMATCH"],
                next_index,
                metadata,
                f"authors={metadata.authors}; maintainers={metadata.maintainers}",
            )
        )
        next_index += 1
    dependency_signal = _dependency_confusion_signal(metadata.dependencies)
    if dependency_signal:
        findings.append(
            _metadata_finding(
                RULES["PY012_DEPENDENCY_CONFUSION_SIGNAL"],
                next_index,
                metadata,
                dependency_signal,
            )
        )
    return findings


def _advisory_findings(
    metadata: PackageMetadata,
    advisory_lookup: AdvisoryLookup | None,
    start_index: int,
) -> list[Finding]:
    if advisory_lookup is None or not metadata.name:
        return []
    try:
        advisories = advisory_lookup(metadata.name, metadata.version)
    except Exception:
        return []
    findings: list[Finding] = []
    for offset, advisory in enumerate(advisories[:10]):
        findings.append(
            _advisory_finding(
                RULES["PY015_OSV_ADVISORY"],
                start_index + offset,
                metadata,
                advisory,
            )
        )
    return findings


def _metadata_finding(
    rule: Rule,
    index: int,
    metadata: PackageMetadata,
    snippet: str,
) -> Finding:
    return Finding(
        finding_id=f"F{index:03d}",
        rule_id=rule.rule_id,
        severity=rule.severity,
        category=rule.category,
        file_path="package metadata",
        line_start=1,
        line_end=1,
        snippet=snippet,
        message=rule.message,
        confidence=0.75,
        tags=list(rule.tags),
        citations=list(rule.citations),
        package_name=metadata.name,
        package_version=metadata.version,
    )


def _advisory_finding(
    rule: Rule,
    index: int,
    metadata: PackageMetadata,
    advisory: Advisory,
) -> Finding:
    return Finding(
        finding_id=f"F{index:03d}",
        rule_id=rule.rule_id,
        severity=rule.severity,
        category=rule.category,
        file_path="OSV.dev advisory database",
        line_start=1,
        line_end=1,
        snippet=f"{advisory.advisory_id}: {advisory.summary}",
        message=rule.message,
        confidence=0.95,
        tags=list(rule.tags),
        citations=list(rule.citations),
        package_name=metadata.name,
        package_version=metadata.version,
    )


def _looks_typosquatted(name: str | None) -> bool:
    if not name:
        return False
    normalized = _normalize_package_name(name)
    for popular in POPULAR_PACKAGE_NAMES:
        normalized_popular = _normalize_package_name(popular)
        if normalized == normalized_popular:
            continue
        if abs(len(normalized) - len(normalized_popular)) > 3:
            continue
        if fuzz.ratio(normalized, normalized_popular) >= 86:
            return True
    return False


def _suspicious_url(urls: dict[str, str]) -> str | None:
    for label, value in urls.items():
        parsed = urlparse(value)
        host = (parsed.hostname or "").lower()
        if parsed.scheme == "http":
            return f"{label}: {value}"
        if host in SUSPICIOUS_URL_HOSTS:
            return f"{label}: {value}"
    return None


def _author_maintainer_mismatch(metadata: PackageMetadata) -> bool:
    if not metadata.authors or not metadata.maintainers:
        return False
    authors = {_normalize_identity(item) for item in metadata.authors}
    maintainers = {_normalize_identity(item) for item in metadata.maintainers}
    return bool(authors and maintainers and authors.isdisjoint(maintainers))


def _dependency_confusion_signal(dependencies: list[str]) -> str | None:
    for dependency in dependencies:
        lower = dependency.lower()
        if any(marker in lower for marker in ("internal", "private", "corp", "company")):
            return dependency
        if " @ http://" in lower or " @ https://" in lower:
            host = urlparse(lower.split(" @ ", 1)[1]).hostname or ""
            if host not in {"pypi.org", "files.pythonhosted.org"}:
                return dependency
    return None


def _filter_ignored_rules(findings: list[Finding], ignored_rules: Iterable[str]) -> list[Finding]:
    ignored = set(ignored_rules)
    if not ignored:
        return findings
    return [finding for finding in findings if finding.rule_id not in ignored]


def _normalize_package_name(value: str) -> str:
    return value.lower().replace("-", "").replace("_", "").replace(".", "")


def _normalize_identity(value: str) -> str:
    return value.lower().strip()


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
