from __future__ import annotations

from pypi_ai.models import Finding, RiskScore, Severity
from pypi_ai.rules import RULES


def calculate_risk(findings: list[Finding]) -> RiskScore:
    breakdown: dict[str, int] = {}
    score = 0
    for finding in findings:
        rule = RULES.get(finding.rule_id)
        weight = rule.weight if rule is not None else 5
        breakdown[finding.category] = breakdown.get(finding.category, 0) + weight
        score += weight
    bounded = min(score, 100)
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
