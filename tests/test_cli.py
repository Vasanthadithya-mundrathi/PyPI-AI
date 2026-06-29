from __future__ import annotations

from typer.testing import CliRunner

from pypi_ai.ai import Explanation
from pypi_ai.cli import app

runner = CliRunner()


def test_root_command_shows_about_welcome() -> None:
    result = runner.invoke(app, [])

    assert result.exit_code == 0
    assert "██████╗" in result.output
    assert "PyPi-AI" in result.output
    assert "VASANTH ADITHYA - 160123749049" in result.output
    assert "SAI GEETHIKA - 160123749302" in result.output
    assert "yedlasaigeethika37@gmail.com" in result.output
    assert "never executes untrusted package code" in result.output
    assert "pypi-ai scan" in result.output


def test_about_command_shows_full_project_information() -> None:
    result = runner.invoke(app, ["about"])

    assert result.exit_code == 0
    assert "AI + Cybersecurity" in result.output
    assert "CHASE" in result.output
    assert "Gemini" in result.output
    assert "Ollama local" in result.output
    assert "default" in result.output
    assert "Ollama Cloud" in result.output
    assert "glm-5.2:cloud" in result.output


def test_quiet_suppresses_scan_banner(tmp_path) -> None:
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    (package_dir / "safe.py").write_text("VALUE = 1\n", encoding="utf-8")

    result = runner.invoke(app, ["--quiet", "scan", str(package_dir), "--format", "json"])

    assert result.exit_code == 0
    assert "Welcome" not in result.output
    assert "██████╗" not in result.output
    assert '"findings"' in result.output


def test_teacher_mode_debug_options_are_visible(tmp_path) -> None:
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    (package_dir / "danger.py").write_text(
        "import os\nTOKEN = os.environ.get('TOKEN')\n", encoding="utf-8"
    )

    result = runner.invoke(
        app,
        [
            "scan",
            str(package_dir),
            "--teacher-mode",
            "--debug",
            "--trace-rules",
            "--show-evidence",
            "--explain-risk",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert "Scan plan" in result.output
    assert "Rule trace" in result.output
    assert "Evidence" in result.output
    assert "Risk breakdown" in result.output
    assert "PY001_ENV_ACCESS" in result.output


def test_utility_commands_are_visible(tmp_path) -> None:
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    (package_dir / "module.py").write_text("eval('1')\n", encoding="utf-8")
    report_path = tmp_path / "scan.json"
    scan_result = runner.invoke(
        app,
        [
            "scan",
            str(package_dir),
            "--format",
            "json",
            "--output",
            str(report_path.with_suffix("")),
        ],
    )
    assert scan_result.exit_code == 0

    assert runner.invoke(app, ["rules", "list"]).exit_code == 0
    assert "PY005_DYNAMIC_EXEC" in runner.invoke(app, ["rules", "list"]).output
    assert runner.invoke(app, ["examples", "list"]).exit_code == 0
    assert "termcolour" in runner.invoke(app, ["examples", "list"]).output
    assert runner.invoke(app, ["model", "test"]).exit_code == 0
    assert "Ollama local" in runner.invoke(app, ["model", "test"]).output
    cloud_model = runner.invoke(app, ["model", "test", "--provider", "ollama-cloud"])
    assert cloud_model.exit_code == 0
    assert "glm-5.2:cloud" in cloud_model.output
    assert runner.invoke(app, ["doctor"]).exit_code == 0
    assert runner.invoke(app, ["theme", "preview"]).exit_code == 0
    assert "Theme preview" in runner.invoke(app, ["theme", "preview"]).output
    assert runner.invoke(app, ["evidence", "show", str(report_path)]).exit_code == 0
    assert runner.invoke(app, ["explain", str(report_path)]).exit_code == 0
    render_base = tmp_path / "rendered"
    render_result = runner.invoke(
        app,
        [
            "report",
            "render",
            str(report_path),
            "--output",
            str(render_base),
            "--format",
            "html",
        ],
    )
    assert render_result.exit_code == 0
    assert render_base.with_suffix(".html").exists()


def test_scan_fail_on_exits_nonzero_for_threshold(tmp_path) -> None:
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    (package_dir / "module.py").write_text("eval('1')\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(package_dir), "--fail-on", "medium"])

    assert result.exit_code == 2


def test_scan_missing_target_has_clean_error(tmp_path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path / "missing")])

    assert result.exit_code != 0
    assert "Unsupported scan target" in result.output
    assert "Traceback" not in result.output


def test_scan_venv_missing_target_has_clean_error(tmp_path) -> None:
    result = runner.invoke(app, ["scan-venv", str(tmp_path / ".venv")])

    assert result.exit_code != 0
    assert "No site-packages directory found" in result.output
    assert "Traceback" not in result.output


def test_scan_invalid_report_format_has_clean_error(tmp_path) -> None:
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    (package_dir / "module.py").write_text("VALUE = 1\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(package_dir), "--format", "xml"])

    assert result.exit_code != 0
    assert "Unsupported report format" in result.output
    assert "Traceback" not in result.output


def test_config_init_show_and_scan_ignored_rules(tmp_path) -> None:
    config_path = tmp_path / ".pypi-ai.toml"

    init_result = runner.invoke(app, ["config", "init", "--path", str(config_path)])

    assert init_result.exit_code == 0
    assert config_path.exists()
    assert "default_provider" in config_path.read_text(encoding="utf-8")

    config_path.write_text(
        'risk_threshold = "medium"\n'
        'default_provider = "none"\n'
        'default_report_format = "json"\n'
        "show_citations = true\n"
        'ignored_rules = ["PY003_NETWORK_CLIENT"]\n'
        'allowed_domains = ["pypi.org", "files.pythonhosted.org"]\n'
        'theme = "default"\n',
        encoding="utf-8",
    )

    show_result = runner.invoke(app, ["config", "show", "--path", str(config_path)])
    assert show_result.exit_code == 0
    assert "PY003_NETWORK_CLIENT" in show_result.output

    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    (package_dir / "module.py").write_text(
        "import requests\nrequests.post('https://example.invalid')\n", encoding="utf-8"
    )

    scan_result = runner.invoke(
        app,
        ["scan", str(package_dir), "--config", str(config_path), "--format", "json"],
    )

    assert scan_result.exit_code == 0
    assert "PY003_NETWORK_CLIENT" not in scan_result.output
    assert '"findings": []' in scan_result.output


def test_scan_ai_timeout_option_is_passed_to_provider(tmp_path, monkeypatch) -> None:
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    (package_dir / "module.py").write_text("eval('1')\n", encoding="utf-8")
    captured: list[float] = []

    def fake_explain_from_evidence(
        findings,
        provider="deterministic",
        model=None,
        *,
        transport=None,
        timeout_seconds=20.0,
    ):
        _ = findings, provider, model, transport
        captured.append(timeout_seconds)
        return Explanation(provider="fake", sentences=[], evidence_ids=[])

    monkeypatch.setattr("pypi_ai.cli.explain_from_evidence", fake_explain_from_evidence)

    result = runner.invoke(
        app,
        [
            "scan",
            str(package_dir),
            "--ai-timeout",
            "0.25",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert captured == [0.25]
