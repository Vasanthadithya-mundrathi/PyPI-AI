from __future__ import annotations

import tempfile
from pathlib import Path

from pypi_ai.agents.deobfuscation_agent import decode_obfuscated_strings
from pypi_ai.agents.dependency_agent import collect_dependency_intelligence
from pypi_ai.agents.evidence_auditor import audit_evidence
from pypi_ai.agents.intake_agent import resolve_artifact
from pypi_ai.agents.remediation_agent import recommend_actions
from pypi_ai.agents.sandbox_agent import run_behavior_probe
from pypi_ai.agents.static_agent import run_static_scan, run_static_venv_scan
from pypi_ai.models import ScanResult

STAGE_BUDGETS = {
    "intake_metadata_seconds": 20,
    "static_deobfuscation_seconds": 60,
    "dependency_intelligence_seconds": 30,
    "sandbox_behavior_seconds": 120,
    "reasoning_audit_seconds": 45,
    "report_generation_seconds": 25,
}


def run_agent_scan(
    target: str,
    *,
    max_package_time: int = 300,
    sandbox: bool = True,
    sandbox_image: str = "pypi-ai-sandbox:latest",
    check_osv: bool = False,
    download_dir: Path | None = None,
) -> dict[str, object]:
    work_dir = download_dir or Path(tempfile.mkdtemp(prefix="pypi-ai-agent-"))
    plan = _plan(target, max_package_time=max_package_time, sandbox=sandbox)
    try:
        artifact, intake_type = resolve_artifact(
            target, work_dir, STAGE_BUDGETS["intake_metadata_seconds"]
        )
        static_result = run_static_scan(artifact)
        decoded = decode_obfuscated_strings(artifact)
        sandbox_report = run_behavior_probe(
            artifact,
            enabled=sandbox,
            timeout_seconds=min(STAGE_BUDGETS["sandbox_behavior_seconds"], max_package_time),
            image=sandbox_image,
        )
        dependencies = collect_dependency_intelligence(static_result, check_osv=check_osv)
        cited_ids = [finding.finding_id for finding in static_result.findings]
        audit = audit_evidence(static_result, cited_ids)
        remediation = recommend_actions(static_result, str(sandbox_report.get("status", "skipped")))
        status = (
            "complete" if sandbox_report.get("status") not in {"failed", "timeout"} else "partial"
        )
        return _report(
            plan,
            status=status,
            artifact=str(artifact),
            intake_type=intake_type,
            static_result=static_result,
            decoded=[item.to_dict() for item in decoded],
            sandbox_report=sandbox_report,
            dependencies=dependencies,
            audit=audit,
            remediation=remediation,
        )
    except (RuntimeError, ValueError) as exc:
        return {
            "status": (
                "PARTIAL_ANALYSIS_TIMEOUT" if "timed out" in str(exc).lower() else "inconclusive"
            ),
            "plan": plan,
            "error": str(exc),
            "recommended_action": "do not auto-install until manually reviewed",
        }


def run_agent_venv_scan(
    venv_path: Path,
    *,
    max_package_time: int = 300,
) -> dict[str, object]:
    plan = _plan(str(venv_path), max_package_time=max_package_time, sandbox=False)
    static_result = run_static_venv_scan(venv_path)
    audit = audit_evidence(
        static_result, [finding.finding_id for finding in static_result.findings]
    )
    return _report(
        plan,
        status="complete",
        artifact=str(venv_path),
        intake_type="venv",
        static_result=static_result,
        decoded=[],
        sandbox_report={"status": "skipped", "reason": "virtualenv scan is static-only"},
        dependencies=collect_dependency_intelligence(static_result, check_osv=False),
        audit=audit,
        remediation=recommend_actions(static_result, "skipped"),
    )


def run_agent_batch(
    requirements_file: Path,
    *,
    max_package_time: int = 300,
    sandbox: bool = True,
    sandbox_image: str = "pypi-ai-sandbox:latest",
) -> dict[str, object]:
    packages = _requirements(requirements_file)
    results = [
        run_agent_scan(
            package,
            max_package_time=max_package_time,
            sandbox=sandbox,
            sandbox_image=sandbox_image,
        )
        for package in packages
    ]
    return {
        "status": "complete",
        "input": str(requirements_file),
        "package_count": len(packages),
        "results": results,
    }


def _plan(target: str, *, max_package_time: int, sandbox: bool) -> dict[str, object]:
    return {
        "target": target,
        "architecture": "CHASE-inspired Plan-and-Execute supervisor with worker agents",
        "max_package_time_seconds": max_package_time,
        "stage_budgets": STAGE_BUDGETS,
        "agents": [
            "package-intake",
            "static",
            "deobfuscation",
            "sandbox" if sandbox else "sandbox-skipped",
            "dependency",
            "remediation",
            "evidence-auditor",
        ],
        "safety": (
            "Untrusted package code is never executed on the host. Docker sandbox behavior "
            "analysis is disposable, resource-limited, and evidence-only."
        ),
    }


def _report(
    plan: dict[str, object],
    *,
    status: str,
    artifact: str,
    intake_type: str,
    static_result: ScanResult,
    decoded: list[dict[str, str]],
    sandbox_report: dict[str, object],
    dependencies: dict[str, object],
    audit: dict[str, object],
    remediation: dict[str, object],
) -> dict[str, object]:
    return {
        "status": status,
        "plan": plan,
        "artifact": artifact,
        "intake_type": intake_type,
        "static_result": static_result.to_dict(),
        "deobfuscation": {"decoded_strings": decoded},
        "sandbox": sandbox_report,
        "dependency_intelligence": dependencies,
        "evidence_audit": audit,
        "remediation": remediation,
    }


def _requirements(path: Path) -> list[str]:
    packages: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-")):
            continue
        packages.append(stripped)
    return packages
