from __future__ import annotations

import subprocess
import sys
import tempfile
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path

from pypi_ai.models import ScanResult, Severity
from pypi_ai.scanner import scan_path

CommandRunner = Callable[[list[str]], None]
Downloader = Callable[[str, Path, Path], list[Path]]
Scanner = Callable[[Path], ScanResult]


class InstallDecision(StrEnum):
    DRY_RUN = "dry-run"
    INSTALLED = "installed"
    BLOCKED = "blocked"


def install_verified_package(
    package: str,
    *,
    venv_path: Path,
    fail_on: Severity = Severity.MEDIUM,
    dry_run: bool = False,
    runner: CommandRunner | None = None,
    downloader: Downloader | None = None,
    scanner: Scanner = scan_path,
) -> InstallDecision:
    command_runner = runner or _run_command
    if dry_run:
        return InstallDecision.DRY_RUN

    python_executable = _ensure_venv(venv_path, command_runner)
    with tempfile.TemporaryDirectory(prefix="pypi-ai-install-") as tmp:
        download_dir = Path(tmp) / "wheels"
        wheels = (downloader or _download_wheels)(package, download_dir, python_executable)
        scan_results = [scanner(wheel) for wheel in wheels]
        if _has_blocking_risk(scan_results, fail_on):
            return InstallDecision.BLOCKED
        _install_from_downloads(package, download_dir, python_executable, command_runner)
    return InstallDecision.INSTALLED


def _ensure_venv(venv_path: Path, runner: CommandRunner) -> Path:
    python_executable = _venv_python(venv_path)
    if not python_executable.exists():
        runner([sys.executable, "-m", "venv", str(venv_path)])
    return python_executable


def _download_wheels(package: str, download_dir: Path, python_executable: Path) -> list[Path]:
    _ = python_executable
    download_dir.mkdir(parents=True, exist_ok=True)
    _run_command(
        [
            sys.executable,
            "-m",
            "pip",
            "download",
            "--only-binary=:all:",
            "--dest",
            str(download_dir),
            package,
        ]
    )
    wheels = sorted(download_dir.glob("*.whl"))
    if not wheels:
        raise RuntimeError("No wheel files were downloaded. Install blocked for safety.")
    return wheels


def _install_from_downloads(
    package: str,
    download_dir: Path,
    python_executable: Path,
    runner: CommandRunner,
) -> None:
    runner(
        [
            str(python_executable),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--find-links",
            str(download_dir),
            "--only-binary=:all:",
            package,
        ]
    )


def _has_blocking_risk(results: list[ScanResult], fail_on: Severity) -> bool:
    order = {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }
    threshold = order[fail_on]
    return any(order[result.risk.level] >= threshold for result in results)


def _venv_python(venv_path: Path) -> Path:
    unix_python = venv_path / "bin" / "python"
    if unix_python.exists() or not sys.platform.startswith("win"):
        return unix_python
    return venv_path / "Scripts" / "python.exe"


def _run_command(command: list[str]) -> None:
    subprocess.run(command, check=True)
