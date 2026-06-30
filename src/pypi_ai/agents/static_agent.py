from __future__ import annotations

from pathlib import Path

from pypi_ai.models import ScanResult
from pypi_ai.scanner import scan_path
from pypi_ai.venv import scan_venv


def run_static_scan(artifact: Path) -> ScanResult:
    return scan_path(artifact)


def run_static_venv_scan(venv_path: Path) -> ScanResult:
    return scan_venv(venv_path)
