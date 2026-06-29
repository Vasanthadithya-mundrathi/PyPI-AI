from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Finding:
    finding_id: str
    rule_id: str
    severity: Severity
    category: str
    file_path: str
    line_start: int
    line_end: int
    snippet: str
    message: str
    confidence: float
    tags: list[str]
    citations: list[str]
    package_name: str | None = None
    package_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass(frozen=True)
class ScanPlan:
    target: str
    input_type: str
    files_discovered: int
    safety_notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RiskScore:
    score: int
    level: Severity
    breakdown: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level.value,
            "breakdown": self.breakdown,
        }


@dataclass(frozen=True)
class ScanSummary:
    target: str
    input_type: str
    files_scanned: int
    packages_scanned: int
    total_findings: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ScanResult:
    project: dict[str, Any]
    summary: ScanSummary
    risk: RiskScore
    findings: list[Finding]
    scan_plan: ScanPlan | None = None
    rule_trace: list[str] = field(default_factory=list)
    citations: dict[str, str] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "summary": self.summary.to_dict(),
            "risk": self.risk.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
            "scan_plan": self.scan_plan.to_dict() if self.scan_plan else None,
            "rule_trace": list(self.rule_trace),
            "citations": dict(self.citations),
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class PackageMetadata:
    name: str | None
    version: str | None
    root: Path
    authors: list[str] = field(default_factory=list)
    maintainers: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    urls: dict[str, str] = field(default_factory=dict)
