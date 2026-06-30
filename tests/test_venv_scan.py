from __future__ import annotations

from typer.testing import CliRunner

from pypi_ai.cli import app
from pypi_ai.venv import find_site_packages, scan_venv

runner = CliRunner()


def make_fake_venv(tmp_path):
    venv = tmp_path / ".venv"
    site_packages = venv / "lib" / "python3.11" / "site-packages"
    package = site_packages / "samplepkg"
    dist_info = site_packages / "samplepkg-1.2.3.dist-info"
    package.mkdir(parents=True)
    dist_info.mkdir(parents=True)
    (package / "__init__.py").write_text(
        "import subprocess\nsubprocess.call(['echo', 'x'])\n", encoding="utf-8"
    )
    (dist_info / "METADATA").write_text("Name: samplepkg\nVersion: 1.2.3\n", encoding="utf-8")
    return venv, site_packages


def test_find_site_packages_discovers_venv_site_packages(tmp_path) -> None:
    venv, site_packages = make_fake_venv(tmp_path)

    assert find_site_packages(venv) == site_packages


def test_scan_venv_scans_installed_package_without_importing(tmp_path) -> None:
    venv, _ = make_fake_venv(tmp_path)

    result = scan_venv(venv)

    assert result.summary.packages_scanned == 1
    assert result.findings[0].package_name == "samplepkg"
    assert result.findings[0].package_version == "1.2.3"
    assert any(f.rule_id == "PY002_SUBPROCESS" for f in result.findings)


def test_scan_venv_skips_packaged_tests(tmp_path) -> None:
    venv = tmp_path / ".venv"
    site_packages = venv / "lib" / "python3.11" / "site-packages"
    package = site_packages / "cleanpkg"
    tests = package / "tests"
    dist_info = site_packages / "cleanpkg-1.0.0.dist-info"
    tests.mkdir(parents=True)
    dist_info.mkdir(parents=True)
    (package / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tests / "test_cli.py").write_text(
        "import subprocess\nsubprocess.run(['python', '--version'])\n",
        encoding="utf-8",
    )
    (dist_info / "METADATA").write_text("Name: cleanpkg\nVersion: 1.0.0\n", encoding="utf-8")

    result = scan_venv(venv)

    assert result.summary.files_scanned == 1
    assert result.findings == []


def test_scan_venv_cli_command(tmp_path) -> None:
    venv, _ = make_fake_venv(tmp_path)

    result = runner.invoke(app, ["scan-venv", str(venv), "--format", "json"])

    assert result.exit_code == 0
    assert "samplepkg" in result.output
    assert "PY002_SUBPROCESS" in result.output
