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
}


def list_rules() -> list[Rule]:
    return list(RULES.values())
