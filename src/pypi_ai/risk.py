from __future__ import annotations

from pypi_ai.models import Finding, RiskScore, Severity
from pypi_ai.rules import RULES


def calculate_risk(findings: list[Finding]) -> RiskScore:
    breakdown: dict[str, int] = {}
    severity_order = {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }
    category_caps = {
        "package-metadata": 10,
        "evasion": 10,
        "network": 30,
        "credential-access": 25,
    }
    max_severity = Severity.INFO
    high_or_critical_count = 0
    for finding in findings:
        rule = RULES.get(finding.rule_id)
        weight = rule.weight if rule is not None else 5
        category_score = breakdown.get(finding.category, 0) + weight
        breakdown[finding.category] = min(category_score, category_caps.get(finding.category, 60))
        if severity_order[finding.severity] > severity_order[max_severity]:
            max_severity = finding.severity
        if severity_order[finding.severity] >= severity_order[Severity.HIGH]:
            high_or_critical_count += 1
    score = sum(breakdown.values())
    bounded = min(score, 100)
    if severity_order[max_severity] <= severity_order[Severity.LOW]:
        bounded = min(bounded, 29)
    elif severity_order[max_severity] <= severity_order[Severity.MEDIUM]:
        bounded = min(bounded, 59)
    elif high_or_critical_count < 2:
        bounded = min(bounded, 84)
    if bounded >= 85:
        level = Severity.CRITICAL
    elif bounded >= 60:
        level = Severity.HIGH
    elif bounded >= 30:
        level = Severity.MEDIUM
    elif bounded > 0:
        level = Severity.LOW
    else:
        level = Severity.INFO
    return RiskScore(score=bounded, level=level, breakdown=breakdown)
