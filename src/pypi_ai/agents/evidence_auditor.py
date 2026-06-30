from __future__ import annotations

from pypi_ai.models import ScanResult


def audit_evidence(result: ScanResult, cited_evidence_ids: list[str]) -> dict[str, object]:
    valid_ids = {finding.finding_id for finding in result.findings}
    unsupported = sorted(set(cited_evidence_ids) - valid_ids)
    return {
        "valid_evidence_ids": sorted(valid_ids),
        "unsupported_claim_ids": unsupported,
        "accepted": not unsupported,
    }
