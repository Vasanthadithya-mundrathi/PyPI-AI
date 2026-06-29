from __future__ import annotations

from dataclasses import dataclass

from pypi_ai.models import Severity


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    category: str
    severity: Severity
    message: str
    tags: list[str]
    citations: list[str]
    weight: int


RULES: dict[str, Rule] = {
    "PY001_ENV_ACCESS": Rule(
        "PY001_ENV_ACCESS",
        "Environment variable access",
        "credential-access",
        Severity.MEDIUM,
        "Environment variable access was detected.",
        ["credentials", "environment"],
        ["CHASE"],
        15,
    ),
    "PY002_SUBPROCESS": Rule(
        "PY002_SUBPROCESS",
        "Subprocess execution",
        "command-execution",
        Severity.HIGH,
        "Subprocess or shell command execution was detected.",
        ["process", "execution"],
        ["CHASE"],
        25,
    ),
    "PY003_NETWORK_CLIENT": Rule(
        "PY003_NETWORK_CLIENT",
        "Network client behavior",
        "network",
        Severity.MEDIUM,
        "Network client behavior was detected.",
        ["network", "exfiltration-risk"],
        ["CHASE"],
        15,
    ),
    "PY004_OBFUSCATION": Rule(
        "PY004_OBFUSCATION",
        "Encoding or obfuscation indicator",
        "obfuscation",
        Severity.MEDIUM,
        "Encoding or obfuscation indicator was detected.",
        ["obfuscation", "encoding"],
        ["CHASE"],
        15,
    ),
    "PY005_DYNAMIC_EXEC": Rule(
        "PY005_DYNAMIC_EXEC",
        "Dynamic code execution",
        "dynamic-execution",
        Severity.HIGH,
        "Dynamic execution was detected.",
        ["dynamic-execution"],
        ["CHASE"],
        30,
    ),
    "PY006_UNSAFE_DESERIALIZATION": Rule(
        "PY006_UNSAFE_DESERIALIZATION",
        "Unsafe deserialization API",
        "unsafe-deserialization",
        Severity.MEDIUM,
        "Unsafe deserialization API usage was detected.",
        ["deserialization"],
        ["CHASE"],
        15,
    ),
    "PY007_NATIVE_CODE": Rule(
        "PY007_NATIVE_CODE",
        "Native code interface",
        "native-code",
        Severity.MEDIUM,
        "Native code interface usage was detected.",
        ["native-code"],
        ["CHASE"],
        15,
    ),
    "PY008_INSTALL_TIME": Rule(
        "PY008_INSTALL_TIME",
        "Install-time execution surface",
        "install-time-execution",
        Severity.HIGH,
        "Install-time execution surface was detected.",
        ["setup", "install-time"],
        ["CHASE", "PYPA_SDIST"],
        25,
    ),
    "PY009_TYPOSQUAT_RISK": Rule(
        "PY009_TYPOSQUAT_RISK",
        "Typosquatting risk",
        "package-identity",
        Severity.MEDIUM,
        "Package name is visually or textually close to a popular package name.",
        ["metadata", "typosquatting"],
        ["CHASE", "MALWARE_EXAMPLES"],
        20,
    ),
    "PY010_SUSPICIOUS_HOMEPAGE": Rule(
        "PY010_SUSPICIOUS_HOMEPAGE",
        "Suspicious homepage or project URL",
        "package-metadata",
        Severity.LOW,
        "Suspicious homepage or project URL was detected.",
        ["metadata", "homepage"],
        ["MALWARE_EXAMPLES"],
        10,
    ),
    "PY011_AUTHOR_MAINTAINER_MISMATCH": Rule(
        "PY011_AUTHOR_MAINTAINER_MISMATCH",
        "Author and maintainer mismatch",
        "package-metadata",
        Severity.LOW,
        "Author and maintainer identity mismatch was detected.",
        ["metadata", "identity"],
        ["PYPA_SDIST"],
        10,
    ),
    "PY012_DEPENDENCY_CONFUSION_SIGNAL": Rule(
        "PY012_DEPENDENCY_CONFUSION_SIGNAL",
        "Dependency confusion signal",
        "dependencies",
        Severity.MEDIUM,
        "Dependency declaration contains a direct URL or private/internal naming signal.",
        ["metadata", "dependency-confusion"],
        ["PYPA_WHEEL", "MALWARE_EXAMPLES"],
        20,
    ),
    "PY013_SECRET_PATTERN_IN_CODE": Rule(
        "PY013_SECRET_PATTERN_IN_CODE",
        "Secret pattern in source code",
        "credential-access",
        Severity.HIGH,
        "A likely secret, token, or credential pattern was detected in source code.",
        ["credentials", "secret"],
        ["CHASE"],
        30,
    ),
    "PY014_IMPORT_ALIAS_RISK": Rule(
        "PY014_IMPORT_ALIAS_RISK",
        "Suspicious import alias",
        "evasion",
        Severity.LOW,
        "Suspicious import alias can hide command, network, or dynamic behavior.",
        ["alias", "evasion"],
        ["CHASE"],
        10,
    ),
    "PY015_OSV_ADVISORY": Rule(
        "PY015_OSV_ADVISORY",
        "Public vulnerability or malicious-package advisory",
        "public-intelligence",
        Severity.HIGH,
        "A public OSV advisory was found for this package release.",
        ["osv", "database", "advisory"],
        ["OSV"],
        30,
    ),
}


def list_rules() -> list[Rule]:
    return list(RULES.values())
