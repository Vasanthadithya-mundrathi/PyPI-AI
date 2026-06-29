from __future__ import annotations

import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_PATH = Path(".pypi-ai.toml")


@dataclass(frozen=True)
class PyPiAIConfig:
    risk_threshold: str = "medium"
    default_provider: str = "ollama-local"
    default_report_format: str = "json"
    show_citations: bool = False
    check_osv: bool = False
    advisory_cache_path: str = ".pypi-ai-cache/advisories.sqlite3"
    ignored_rules: list[str] = field(default_factory=list)
    allowed_domains: list[str] = field(
        default_factory=lambda: ["pypi.org", "files.pythonhosted.org"]
    )
    theme: str = "default"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


DEFAULT_CONFIG = PyPiAIConfig()


def load_config(path: Path | None = None) -> PyPiAIConfig:
    config_path = path or DEFAULT_CONFIG_PATH
    if not config_path.exists():
        return DEFAULT_CONFIG
    try:
        payload = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"Invalid config TOML: {config_path}") from exc
    return PyPiAIConfig(
        risk_threshold=_str_value(payload, "risk_threshold", DEFAULT_CONFIG.risk_threshold),
        default_provider=_str_value(payload, "default_provider", DEFAULT_CONFIG.default_provider),
        default_report_format=_str_value(
            payload, "default_report_format", DEFAULT_CONFIG.default_report_format
        ),
        show_citations=_bool_value(payload, "show_citations", DEFAULT_CONFIG.show_citations),
        check_osv=_bool_value(payload, "check_osv", DEFAULT_CONFIG.check_osv),
        advisory_cache_path=_str_value(
            payload, "advisory_cache_path", DEFAULT_CONFIG.advisory_cache_path
        ),
        ignored_rules=_str_list(payload, "ignored_rules", DEFAULT_CONFIG.ignored_rules),
        allowed_domains=_str_list(payload, "allowed_domains", DEFAULT_CONFIG.allowed_domains),
        theme=_str_value(payload, "theme", DEFAULT_CONFIG.theme),
    )


def write_default_config(path: Path = DEFAULT_CONFIG_PATH, *, force: bool = False) -> Path:
    if path.exists() and not force:
        raise FileExistsError(f"Config already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(default_config_toml(), encoding="utf-8")
    return path


def default_config_toml() -> str:
    return (
        'risk_threshold = "medium"\n'
        'default_provider = "ollama-local"\n'
        'default_report_format = "html"\n'
        "show_citations = true\n"
        "check_osv = false\n"
        'advisory_cache_path = ".pypi-ai-cache/advisories.sqlite3"\n'
        "ignored_rules = []\n"
        'allowed_domains = ["pypi.org", "files.pythonhosted.org"]\n'
        'theme = "default"\n'
    )


def _str_value(payload: dict[str, Any], key: str, default: str) -> str:
    value = payload.get(key, default)
    return value if isinstance(value, str) else default


def _bool_value(payload: dict[str, Any], key: str, default: bool) -> bool:
    value = payload.get(key, default)
    return value if isinstance(value, bool) else default


def _str_list(payload: dict[str, Any], key: str, default: list[str]) -> list[str]:
    value = payload.get(key, default)
    if not isinstance(value, list):
        return list(default)
    return [item for item in value if isinstance(item, str)]
