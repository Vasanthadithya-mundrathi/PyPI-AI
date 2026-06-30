from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from pypi_ai.agentic import (
    TOP_PYPI_PACKAGES_URL,
    ChasePlan,
    PlannedPackage,
    build_live_chase_plan,
    execute_chase_plan,
)
from pypi_ai.agents.deobfuscation_agent import decode_obfuscated_strings
from pypi_ai.agents.dependency_agent import collect_dependency_intelligence
from pypi_ai.agents.intake_agent import download_pypi_wheel, resolve_artifact
from pypi_ai.agents.remediation_agent import recommend_actions
from pypi_ai.agents.sandbox_agent import run_behavior_probe
from pypi_ai.agents.supervisor import run_agent_batch, run_agent_scan
from pypi_ai.cli import app
from pypi_ai.intelligence import Advisory
from pypi_ai.models import Finding, RiskScore, ScanResult, ScanSummary, Severity
from pypi_ai.sandbox import docker_client
from pypi_ai.sandbox.policy import DockerSandboxPolicy
from pypi_ai.sandbox.runner import run_sandbox_probe
from pypi_ai.sandbox.telemetry import SandboxReport, SandboxTelemetry
from pypi_ai.telemetry.fs_events import fs_event
from pypi_ai.telemetry.import_events import import_event
from pypi_ai.telemetry.network_events import network_event
from pypi_ai.telemetry.process_events import process_event

runner = CliRunner()


def clean_result(target: Path) -> ScanResult:
    return ScanResult(
        project={"name": "PyPi-AI", "version": "0.1.0", "developers": [], "safety": "static"},
        summary=ScanSummary(
            target=str(target),
            input_type="wheel" if target.suffix == ".whl" else "folder",
            files_scanned=1,
            packages_scanned=1,
            total_findings=0,
        ),
        risk=RiskScore(score=0, level=Severity.INFO, breakdown={}),
        findings=[],
    )


def fake_fetch(url: str) -> dict[str, object]:
    if url == TOP_PYPI_PACKAGES_URL:
        return {
            "rows": [
                {"project": "alpha"},
                {"project": "bravo"},
                {"project": "charlie"},
                {"project": "delta"},
            ]
        }
    name = url.rsplit("/", 2)[-2]
    return {
        "info": {"name": name, "version": "1.2.3"},
        "releases": {
            "1.2.3": [
                {
                    "filename": f"{name}-1.2.3-py3-none-any.whl",
                    "url": f"https://files.pythonhosted.org/{name}.whl",
                    "packagetype": "bdist_wheel",
                    "size": 2048,
                    "yanked": False,
                }
            ]
        },
    }


def test_build_live_chase_plan_selects_realistic_runtime_candidates() -> None:
    plan = build_live_chase_plan(sample_size=2, candidate_pool=4, seed=7, fetch_json=fake_fetch)

    assert plan.strategy == "agentic-plan-then-execute-real-pypi-wheel-scan"
    assert len(plan.packages) == 2
    assert {package.version for package in plan.packages} == {"1.2.3"}
    assert "not installed" in " ".join(plan.safety_notes)


def test_build_live_chase_plan_validates_bounds() -> None:
    with pytest.raises(ValueError, match="sample_size"):
        build_live_chase_plan(sample_size=0, fetch_json=fake_fetch)
    with pytest.raises(ValueError, match="candidate_pool"):
        build_live_chase_plan(sample_size=3, candidate_pool=2, fetch_json=fake_fetch)
    with pytest.raises(ValueError, match="max_wheel_mb"):
        build_live_chase_plan(max_wheel_mb=0, fetch_json=fake_fetch)


def test_execute_chase_plan_downloads_and_scans_planned_wheels(tmp_path) -> None:
    planned = PlannedPackage(
        name="alpha",
        version="1.2.3",
        wheel_filename="alpha-1.2.3-py3-none-any.whl",
        wheel_size_bytes=10,
        wheel_url="https://files.pythonhosted.org/alpha.whl",
    )
    plan = ChasePlan(
        source_url=TOP_PYPI_PACKAGES_URL,
        strategy="test",
        sample_size=1,
        candidate_pool=1,
        max_wheel_mb=5,
        seed=None,
        packages=[planned],
        safety_notes=[],
    )

    def fake_downloader(package: PlannedPackage, package_dir: Path, timeout_seconds: float) -> Path:
        assert timeout_seconds == 120.0
        wheel = package_dir / package.wheel_filename
        wheel.write_text("wheel", encoding="utf-8")
        return wheel

    result = execute_chase_plan(
        plan, download_dir=tmp_path, downloader=fake_downloader, scanner=clean_result
    )

    assert result.to_dict()["summary"]["scanned_packages"] == 1
    assert result.results[0].status == "scanned"
    assert result.results[0].risk_level == "info"


def test_execute_chase_plan_records_download_failures(tmp_path) -> None:
    plan = ChasePlan(
        source_url=TOP_PYPI_PACKAGES_URL,
        strategy="test",
        sample_size=1,
        candidate_pool=1,
        max_wheel_mb=5,
        seed=None,
        packages=[PlannedPackage("broken", "1.0", "broken-1.0.whl", 10, "https://example.invalid")],
        safety_notes=[],
    )

    def failing_downloader(
        package: PlannedPackage, package_dir: Path, timeout_seconds: float
    ) -> Path:
        _ = package, package_dir, timeout_seconds
        raise RuntimeError("download failed")

    result = execute_chase_plan(plan, download_dir=tmp_path, downloader=failing_downloader)

    assert result.to_dict()["summary"]["failed_packages"] == 1
    assert result.results[0].status == "failed"
    assert result.results[0].error == "download failed"


def test_deobfuscation_agent_decodes_safe_strings(tmp_path) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "module.py").write_text(
        "payload='aHR0cHM6Ly9leGFtcGxlLmludmFsaWQvdG9rZW4='\n", encoding="utf-8"
    )

    decoded = decode_obfuscated_strings(package)

    assert decoded
    assert decoded[0].encoding == "base64"
    assert "https://example.invalid/token" in decoded[0].value


def test_intake_agent_resolves_local_and_downloaded_artifacts(tmp_path, monkeypatch) -> None:
    local = tmp_path / "pkg"
    local.mkdir()
    assert resolve_artifact(str(local), tmp_path / "downloads", 1)[1] == "local"

    class FakeResponse:
        def __init__(self, payload: bytes) -> None:
            self.payload = payload

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, *args: object) -> None:
            _ = args

        def read(self) -> bytes:
            return self.payload

    def fake_urlopen(url: str, timeout: float) -> FakeResponse:
        _ = timeout
        if url.endswith("/json"):
            return FakeResponse(
                json.dumps(
                    {
                        "info": {"version": "1.0"},
                        "releases": {
                            "1.0": [
                                {
                                    "filename": "demo-1.0-py3-none-any.whl",
                                    "url": "https://files.pythonhosted.org/demo.whl",
                                    "packagetype": "bdist_wheel",
                                    "size": 5,
                                    "yanked": False,
                                }
                            ]
                        },
                    }
                ).encode()
            )
        return FakeResponse(b"wheel")

    monkeypatch.setattr("pypi_ai.agents.intake_agent.urlopen", fake_urlopen)
    wheel = download_pypi_wheel("demo", tmp_path / "downloads", 1)

    assert wheel.name == "demo-1.0-py3-none-any.whl"


def test_intake_agent_reports_download_failure(tmp_path, monkeypatch) -> None:
    class FakeResponse:
        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, *args: object) -> None:
            _ = args

        def read(self) -> bytes:
            return b'{"info":{"version":"1.0"},"releases":{"1.0":[]}}'

    monkeypatch.setattr("pypi_ai.agents.intake_agent.urlopen", lambda url, timeout: FakeResponse())

    with pytest.raises(RuntimeError, match="No non-yanked wheel"):
        download_pypi_wheel("missing-demo", tmp_path / "downloads", 1)


def test_sandbox_policy_and_runner_convert_docker_payload(monkeypatch, tmp_path) -> None:
    policy = DockerSandboxPolicy(image="sandbox:test", timeout_seconds=5)
    assert "--network" in policy.docker_args()
    assert "--read-only" in policy.docker_args()
    assert "--cap-drop" in policy.docker_args()

    def fake_probe(artifact: Path, policy: DockerSandboxPolicy) -> dict[str, object]:
        _ = artifact, policy
        return {"status": "complete", "network_events": [{"host": "example.invalid"}]}

    monkeypatch.setattr("pypi_ai.sandbox.runner.run_docker_probe", fake_probe)
    report = run_sandbox_probe(tmp_path / "pkg.whl", policy)

    assert report.status == "complete"
    assert report.telemetry.network_events == [{"host": "example.invalid"}]


def test_docker_client_success_and_unavailable_paths(monkeypatch, tmp_path) -> None:
    artifact = tmp_path / "pkg.whl"
    artifact.write_text("wheel", encoding="utf-8")
    monkeypatch.setattr("pypi_ai.sandbox.docker_client.shutil.which", lambda name: None)

    assert docker_client.docker_available() is False
    with pytest.raises(FileNotFoundError):
        docker_client.run_docker_probe(artifact, DockerSandboxPolicy())

    monkeypatch.setattr("pypi_ai.sandbox.docker_client.shutil.which", lambda name: "/bin/docker")

    def fake_run(command, check, capture_output, text, timeout):  # type: ignore[no-untyped-def]
        _ = check, capture_output, text, timeout
        assert command[:2] == ["docker", "run"]
        return SimpleNamespace(
            returncode=0,
            stdout='{"status":"complete","process_events":[{"command":"pip"}]}',
            stderr="",
        )

    monkeypatch.setattr("pypi_ai.sandbox.docker_client.subprocess.run", fake_run)
    payload = docker_client.run_docker_probe(artifact, DockerSandboxPolicy())

    assert payload["status"] == "complete"
    assert payload["process_events"] == [{"command": "pip"}]


def test_telemetry_helpers_and_report_dict() -> None:
    telemetry = SandboxTelemetry(
        process_events=[process_event("pip install")],
        file_events=[fs_event("/tmp/x", "open")],
        network_events=[network_event("example.invalid", 443)],
        import_events=[import_event("demo")],
    )
    report = SandboxReport(status="complete", telemetry=telemetry, reason="ok")

    payload = report.to_dict()

    assert payload["reason"] == "ok"
    assert telemetry.to_dict()["process_events"][0]["command"] == "pip install"
    assert telemetry.to_dict()["network_events"][0]["port"] == 443


def test_sandbox_agent_can_skip_or_capture_failure(monkeypatch, tmp_path) -> None:
    skipped = run_behavior_probe(
        tmp_path / "pkg.whl", enabled=False, timeout_seconds=5, image="sandbox:test"
    )
    assert skipped["status"] == "skipped"

    def failing_probe(artifact: Path, policy: DockerSandboxPolicy) -> object:
        _ = artifact, policy
        raise RuntimeError("docker missing")

    monkeypatch.setattr("pypi_ai.agents.sandbox_agent.run_sandbox_probe", failing_probe)
    failed = run_behavior_probe(
        tmp_path / "pkg.whl", enabled=True, timeout_seconds=5, image="sandbox:test"
    )

    assert failed["status"] == "failed"
    assert "docker missing" in str(failed["reason"])


def test_dependency_and_remediation_agents_cover_advisories(monkeypatch, tmp_path) -> None:
    finding = Finding(
        finding_id="F001",
        rule_id="PY015_OSV_ADVISORY",
        severity=Severity.HIGH,
        category="dependency-intelligence",
        file_path="OSV.dev",
        line_start=1,
        line_end=1,
        snippet="advisory",
        message="Known vulnerability.",
        confidence=0.95,
        tags=["dependency"],
        citations=["OSV"],
        package_name="demo",
        package_version="1.0",
    )
    result = ScanResult(
        project={"name": "PyPi-AI"},
        summary=ScanSummary(str(tmp_path), "wheel", 1, 1, 1),
        risk=RiskScore(score=80, level=Severity.HIGH, breakdown={"dependency": 80}),
        findings=[finding],
    )

    monkeypatch.setattr(
        "pypi_ai.agents.dependency_agent.lookup_osv_advisories",
        lambda name, version, cache_path: [
            Advisory("GHSA-1", "demo advisory", "details", ["CVE-1"])
        ],
    )

    intelligence = collect_dependency_intelligence(result, check_osv=True)
    remediation = recommend_actions(result, "complete")

    assert intelligence["osv_advisories"][0]["id"] == "GHSA-1"
    assert remediation["recommended_action"] == "block"


def test_supervisor_agent_scan_local_folder_and_batch(tmp_path) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "module.py").write_text("VALUE = 1\n", encoding="utf-8")

    payload = run_agent_scan(str(package), sandbox=False)

    assert payload["status"] == "complete"
    assert payload["intake_type"] == "local"
    assert payload["evidence_audit"] == {
        "valid_evidence_ids": [],
        "unsupported_claim_ids": [],
        "accepted": True,
    }

    requirements = tmp_path / "requirements.txt"
    requirements.write_text(f"{package}\n# ignored\n", encoding="utf-8")
    batch = run_agent_batch(requirements, sandbox=False)

    assert batch["package_count"] == 1
    assert batch["results"][0]["status"] == "complete"


def test_agent_cli_scan_and_output_file(tmp_path) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    output = tmp_path / "agent-report.json"

    result = runner.invoke(
        app, ["agent", "scan", str(package), "--no-sandbox", "--output", str(output)]
    )

    assert result.exit_code == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["status"] == "complete"
    assert payload["plan"]["architecture"].startswith("CHASE-inspired")


def test_agent_cli_sample_live_dry_run(monkeypatch) -> None:
    def fake_plan(**kwargs):  # type: ignore[no-untyped-def]
        return build_live_chase_plan(fetch_json=fake_fetch, **kwargs)

    monkeypatch.setattr("pypi_ai.cli.build_live_chase_plan", fake_plan)

    result = runner.invoke(app, ["agent", "sample-live", "--sample-size", "1", "--dry-run"])

    assert result.exit_code == 0
    assert "agentic-plan-then-execute-real-pypi-wheel-scan" in result.output
