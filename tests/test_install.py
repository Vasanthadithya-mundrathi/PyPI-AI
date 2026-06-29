from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from pypi_ai.cli import app
from pypi_ai.installer import InstallDecision, install_verified_package
from pypi_ai.models import Finding, RiskScore, ScanResult, ScanSummary, Severity

runner = CliRunner()


class FakeRunner:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str]) -> None:
        self.commands.append(command)


def clean_result(target: Path) -> ScanResult:
    return ScanResult(
        project={"name": "PyPi-AI", "version": "0.1.0", "developers": [], "safety": "static"},
        summary=ScanSummary(
            target=str(target),
            input_type="wheel",
            files_scanned=1,
            packages_scanned=1,
            total_findings=0,
        ),
        risk=RiskScore(score=0, level=Severity.INFO, breakdown={}),
        findings=[],
    )


def risky_result(target: Path) -> ScanResult:
    finding = Finding(
        finding_id="F001",
        rule_id="PY005_DYNAMIC_EXEC",
        severity=Severity.HIGH,
        category="dynamic-execution",
        file_path="pkg/__init__.py",
        line_start=1,
        line_end=1,
        snippet="eval(payload)",
        message="Dynamic execution was detected.",
        confidence=0.9,
        tags=["dynamic-execution"],
        citations=["CHASE"],
    )
    return ScanResult(
        project={"name": "PyPi-AI", "version": "0.1.0", "developers": [], "safety": "static"},
        summary=ScanSummary(
            target=str(target),
            input_type="wheel",
            files_scanned=1,
            packages_scanned=1,
            total_findings=1,
        ),
        risk=RiskScore(score=60, level=Severity.HIGH, breakdown={"dynamic-execution": 60}),
        findings=[finding],
    )


def test_install_verified_package_creates_venv_downloads_scans_then_installs(tmp_path) -> None:
    runner_calls = FakeRunner()

    def downloader(package: str, download_dir: Path, python_executable: Path) -> list[Path]:
        assert package == "safe"
        assert python_executable.name == "python"
        download_dir.mkdir(parents=True)
        wheel = download_dir / "safe-1.0-py3-none-any.whl"
        wheel.write_text("wheel-bytes", encoding="utf-8")
        return [wheel]

    decision = install_verified_package(
        "safe",
        venv_path=tmp_path / ".venv",
        runner=runner_calls,
        downloader=downloader,
        scanner=clean_result,
    )

    assert decision == InstallDecision.INSTALLED
    assert any("venv" in command for command in runner_calls.commands[0])
    assert any("pip" in command for command in runner_calls.commands[-1])
    assert "--no-index" in runner_calls.commands[-1]


def test_install_verified_package_blocks_high_risk_wheel(tmp_path) -> None:
    runner_calls = FakeRunner()

    def downloader(package: str, download_dir: Path, python_executable: Path) -> list[Path]:
        _ = package, python_executable
        download_dir.mkdir(parents=True)
        wheel = download_dir / "risky-1.0-py3-none-any.whl"
        wheel.write_text("wheel-bytes", encoding="utf-8")
        return [wheel]

    decision = install_verified_package(
        "risky",
        venv_path=tmp_path / ".venv",
        fail_on=Severity.MEDIUM,
        runner=runner_calls,
        downloader=downloader,
        scanner=risky_result,
    )

    assert decision == InstallDecision.BLOCKED
    assert not any("install" in command for command in runner_calls.commands)


def test_install_cli_dry_run_is_visible(tmp_path) -> None:
    result = runner.invoke(
        app, ["install", "requests", "--venv", str(tmp_path / ".venv"), "--dry-run"]
    )

    assert result.exit_code == 0
    assert "Verified install plan" in result.output
    assert "requests" in result.output
    assert "Ollama local" in result.output
