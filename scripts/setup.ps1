$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $RootDir

Write-Host "Setting up PyPi-AI in $RootDir"
uv sync --all-groups
uv run pypi-ai doctor

Write-Host ""
Write-Host "Setup complete."
Write-Host "Try:"
Write-Host "  uv run pypi-ai"
Write-Host "  uv run pypi-ai scan examples/safe_packages/benign --teacher-mode --show-evidence"
Write-Host "  uv run pypi-ai scan-venv .venv --teacher-mode --format json"
