from __future__ import annotations

from pypi_ai.models import Finding, Severity
from pypi_ai.risk import calculate_risk


def finding(index: int, rule_id: str, severity: Severity, category: str) -> Finding:
    return Finding(
        finding_id=f"F{index:03d}",
        rule_id=rule_id,
        severity=severity,
        category=category,
        file_path="pkg/module.py",
        line_start=index,
        line_end=index,
        snippet="socket.socket()",
        message="Detected.",
        confidence=0.8,
        tags=[],
        citations=[],
    )


def test_repeated_medium_findings_do_not_escalate_to_critical() -> None:
    findings = [
        finding(index, "PY003_NETWORK_CLIENT", Severity.MEDIUM, "network") for index in range(1, 20)
    ]

    risk = calculate_risk(findings)

    assert risk.score <= 59
    assert risk.level == Severity.MEDIUM
    assert risk.breakdown["network"] == 30


def test_high_severity_evidence_can_still_raise_high_risk() -> None:
    findings = [
        finding(1, "PY005_DYNAMIC_EXEC", Severity.HIGH, "dynamic-execution"),
        finding(2, "PY002_SUBPROCESS", Severity.HIGH, "command-execution"),
        finding(3, "PY013_SECRET_PATTERN_IN_CODE", Severity.HIGH, "credential-access"),
    ]

    risk = calculate_risk(findings)

    assert risk.level == Severity.HIGH
    assert risk.score >= 60


def test_single_high_finding_does_not_force_critical() -> None:
    findings = [
        finding(1, "PY005_DYNAMIC_EXEC", Severity.HIGH, "dynamic-execution"),
        *[
            finding(index, "PY004_OBFUSCATION", Severity.MEDIUM, "obfuscation")
            for index in range(2, 10)
        ],
    ]

    risk = calculate_risk(findings)

    assert risk.score <= 84
    assert risk.level == Severity.HIGH
