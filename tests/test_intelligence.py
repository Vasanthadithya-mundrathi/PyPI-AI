from __future__ import annotations

import json

from pypi_ai.intelligence import Advisory, OSVClient, SQLiteAdvisoryCache


def test_osv_client_queries_pypi_package_and_parses_advisories() -> None:
    calls: list[tuple[str, bytes, float]] = []

    def fake_transport(url: str, payload: bytes, timeout: float) -> bytes:
        calls.append((url, payload, timeout))
        return json.dumps(
            {
                "vulns": [
                    {
                        "id": "MAL-2026-0001",
                        "summary": "Malicious package report",
                        "details": "Package exfiltrates credentials.",
                        "aliases": ["CVE-2026-0001"],
                    }
                ]
            }
        ).encode()

    client = OSVClient(transport=fake_transport)

    advisories = client.query("demo-package", "1.0.0")

    assert calls
    assert calls[0][0].endswith("/v1/query")
    assert json.loads(calls[0][1]) == {
        "package": {"name": "demo-package", "ecosystem": "PyPI"},
        "version": "1.0.0",
    }
    assert advisories == [
        Advisory(
            advisory_id="MAL-2026-0001",
            summary="Malicious package report",
            details="Package exfiltrates credentials.",
            aliases=["CVE-2026-0001"],
        )
    ]


def test_sqlite_advisory_cache_round_trips_advisories(tmp_path) -> None:
    cache = SQLiteAdvisoryCache(tmp_path / "advisories.sqlite3")
    advisory = Advisory(
        advisory_id="GHSA-demo",
        summary="Known vulnerability",
        details="Details",
        aliases=[],
    )

    cache.store("pkg", "2.0.0", [advisory])

    assert cache.get("pkg", "2.0.0") == [advisory]
    assert cache.get("pkg", None) is None
