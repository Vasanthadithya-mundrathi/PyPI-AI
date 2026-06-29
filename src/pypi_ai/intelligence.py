from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from urllib.request import Request, urlopen

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
DEFAULT_CACHE_PATH = Path(".pypi-ai-cache") / "advisories.sqlite3"

HTTPTransport = Callable[[str, bytes, float], bytes]
AdvisoryLookup = Callable[[str, str | None], list["Advisory"]]


@dataclass(frozen=True)
class Advisory:
    advisory_id: str
    summary: str
    details: str
    aliases: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "advisory_id": self.advisory_id,
            "summary": self.summary,
            "details": self.details,
            "aliases": list(self.aliases),
        }


class OSVClient:
    def __init__(
        self,
        *,
        endpoint: str = OSV_QUERY_URL,
        timeout_seconds: float = 5.0,
        transport: HTTPTransport | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.timeout_seconds = timeout_seconds
        self.transport = transport or _http_post

    def query(self, package_name: str, version: str | None = None) -> list[Advisory]:
        payload: dict[str, object] = {
            "package": {"name": package_name, "ecosystem": "PyPI"},
        }
        if version:
            payload["version"] = version
        response = self.transport(
            self.endpoint,
            json.dumps(payload).encode("utf-8"),
            self.timeout_seconds,
        )
        raw = json.loads(response.decode("utf-8"))
        vulns = raw.get("vulns", [])
        if not isinstance(vulns, list):
            return []
        advisories: list[Advisory] = []
        for item in vulns:
            if isinstance(item, dict):
                advisories.append(_advisory_from_payload(item))
        return advisories


class SQLiteAdvisoryCache:
    def __init__(self, path: Path = DEFAULT_CACHE_PATH) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def get(self, package_name: str, version: str | None) -> list[Advisory] | None:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                "select advisories_json from advisories where package_name = ? and version = ?",
                (package_name, version or ""),
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(str(row[0]))
        if not isinstance(payload, list):
            return []
        return [_advisory_from_cache(item) for item in payload if isinstance(item, dict)]

    def store(self, package_name: str, version: str | None, advisories: list[Advisory]) -> None:
        payload = json.dumps([advisory.to_dict() for advisory in advisories], sort_keys=True)
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """
                insert into advisories(package_name, version, advisories_json)
                values (?, ?, ?)
                on conflict(package_name, version)
                do update set advisories_json = excluded.advisories_json
                """,
                (package_name, version or "", payload),
            )

    def _init_db(self) -> None:
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """
                create table if not exists advisories (
                    package_name text not null,
                    version text not null,
                    advisories_json text not null,
                    primary key(package_name, version)
                )
                """
            )


class CachedAdvisoryLookup:
    def __init__(
        self,
        *,
        client: OSVClient | None = None,
        cache: SQLiteAdvisoryCache | None = None,
    ) -> None:
        self.client = client or OSVClient()
        self.cache = cache or SQLiteAdvisoryCache()

    def __call__(self, package_name: str, version: str | None) -> list[Advisory]:
        cached = self.cache.get(package_name, version)
        if cached is not None:
            return cached
        advisories = self.client.query(package_name, version)
        self.cache.store(package_name, version, advisories)
        return advisories


def lookup_osv_advisories(
    package_name: str,
    version: str | None,
    *,
    cache_path: Path = DEFAULT_CACHE_PATH,
    timeout_seconds: float = 5.0,
) -> list[Advisory]:
    lookup = CachedAdvisoryLookup(
        client=OSVClient(timeout_seconds=timeout_seconds),
        cache=SQLiteAdvisoryCache(cache_path),
    )
    return lookup(package_name, version)


def _http_post(url: str, payload: bytes, timeout: float) -> bytes:
    request = Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "PyPi-AI/0.1"},
        method="POST",
    )
    with urlopen(request, timeout=timeout) as response:
        return cast(bytes, response.read())


def _advisory_from_payload(payload: dict[str, object]) -> Advisory:
    aliases = payload.get("aliases", [])
    return Advisory(
        advisory_id=str(payload.get("id", "UNKNOWN")),
        summary=str(payload.get("summary", "")),
        details=str(payload.get("details", "")),
        aliases=[str(alias) for alias in aliases] if isinstance(aliases, list) else [],
    )


def _advisory_from_cache(payload: dict[str, object]) -> Advisory:
    aliases = payload.get("aliases", [])
    return Advisory(
        advisory_id=str(payload.get("advisory_id", "UNKNOWN")),
        summary=str(payload.get("summary", "")),
        details=str(payload.get("details", "")),
        aliases=[str(alias) for alias in aliases] if isinstance(aliases, list) else [],
    )
