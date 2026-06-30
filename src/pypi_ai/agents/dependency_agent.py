from __future__ import annotations

from pypi_ai.intelligence import DEFAULT_CACHE_PATH, lookup_osv_advisories
from pypi_ai.models import ScanResult


def collect_dependency_intelligence(result: ScanResult, *, check_osv: bool) -> dict[str, object]:
    package_names = sorted(
        {
            finding.package_name
            for finding in result.findings
            if finding.package_name is not None and finding.package_name != "<unknown>"
        }
    )
    advisories: list[dict[str, object]] = []
    if check_osv:
        for name in package_names[:5]:
            for advisory in lookup_osv_advisories(name, None, cache_path=DEFAULT_CACHE_PATH):
                advisories.append(
                    {
                        "package": name,
                        "id": advisory.advisory_id,
                        "summary": advisory.summary,
                        "aliases": advisory.aliases,
                    }
                )
    return {"packages_seen_in_evidence": package_names, "osv_advisories": advisories}
