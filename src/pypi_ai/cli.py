from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from pypi_ai.ai import DEFAULT_OLLAMA_CLOUD_MODEL, explain_from_evidence, provider_health
from pypi_ai.config import DEFAULT_CONFIG_PATH, load_config, write_default_config
from pypi_ai.constants import (
    ASCII_ART,
    CITATIONS,
    DEVELOPERS,
    DOMAIN,
    MALICIOUS_PACKAGE_NAME_EXAMPLES,
    PROJECT_NAME,
    TAGLINE,
    VERSION,
)
from pypi_ai.installer import InstallDecision, install_verified_package
from pypi_ai.intelligence import DEFAULT_CACHE_PATH, Advisory, AdvisoryLookup, lookup_osv_advisories
from pypi_ai.models import ScanResult, Severity
from pypi_ai.reports import render_report, scan_result_from_dict
from pypi_ai.rules import list_rules
from pypi_ai.scanner import scan_path
from pypi_ai.venv import scan_venv as scan_virtualenv

app = typer.Typer(
    name="pypi-ai",
    invoke_without_command=True,
    no_args_is_help=False,
    help="Evidence-grounded static scanner for suspicious Python packages.",
)
report_app = typer.Typer(help="Render saved scan reports.")
evidence_app = typer.Typer(help="Inspect evidence from a JSON report.")
rules_app = typer.Typer(help="List detector rules.")
examples_app = typer.Typer(help="List safe and public-reference examples.")
benchmark_app = typer.Typer(help="Run local benchmark fixtures.")
model_app = typer.Typer(help="Check AI model provider configuration.")
theme_app = typer.Typer(help="Preview terminal colors and severity styles.")
config_app = typer.Typer(help="Create and inspect PyPi-AI configuration.")
database_app = typer.Typer(help="Check free public package-intelligence databases.")

app.add_typer(report_app, name="report")
app.add_typer(evidence_app, name="evidence")
app.add_typer(rules_app, name="rules")
app.add_typer(examples_app, name="examples")
app.add_typer(benchmark_app, name="benchmark")
app.add_typer(model_app, name="model")
app.add_typer(theme_app, name="theme")
app.add_typer(config_app, name="config")
app.add_typer(database_app, name="database")

console = Console()


@app.callback()
def main(
    ctx: typer.Context,
    quiet: Annotated[
        bool, typer.Option("--quiet", help="Suppress nonessential banner output.")
    ] = False,
) -> None:
    ctx.obj = {"quiet": quiet}
    if ctx.invoked_subcommand is None:
        print_about(compact=False)


@app.command()
def about() -> None:
    """Show project, developer, safety, research, and usage information."""
    print_about(compact=False)


@app.command()
def scan(
    ctx: typer.Context,
    target: Annotated[Path, typer.Argument(help="Package folder, .whl, or .tar.gz to scan.")],
    debug: Annotated[
        bool, typer.Option("--debug", help="Show detailed scanner decisions.")
    ] = False,
    verbose: Annotated[bool, typer.Option("--verbose", help="Show file-by-file progress.")] = False,
    trace_rules: Annotated[
        bool, typer.Option("--trace-rules", help="Show rule trace output.")
    ] = False,
    show_evidence: Annotated[
        bool, typer.Option("--show-evidence", help="Print evidence table.")
    ] = False,
    show_citations: Annotated[
        bool, typer.Option("--show-citations", help="Include citations.")
    ] = False,
    explain_risk: Annotated[
        bool, typer.Option("--explain-risk", help="Show risk breakdown.")
    ] = False,
    teacher_mode: Annotated[
        bool, typer.Option("--teacher-mode", help="Enable explanation-friendly output.")
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show scan plan without scanning.")
    ] = False,
    config_path: Annotated[
        Path | None,
        typer.Option("--config", help="Read defaults and ignored rules from .pypi-ai.toml."),
    ] = None,
    check_osv: Annotated[
        bool,
        typer.Option("--check-osv", help="Query OSV.dev and local SQLite advisory cache."),
    ] = False,
    advisory_cache: Annotated[
        Path | None,
        typer.Option("--advisory-cache", help="SQLite advisory cache path."),
    ] = None,
    no_ai: Annotated[bool, typer.Option("--no-ai", help="Disable AI explanations.")] = False,
    provider: Annotated[
        str | None,
        typer.Option("--provider", help="AI provider: ollama-local, gemini, ollama-cloud, none."),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option("--model", help="Provider model name, such as glm-5.2:cloud."),
    ] = None,
    ai_timeout: Annotated[
        float,
        typer.Option("--ai-timeout", help="Seconds to wait before falling back from AI."),
    ] = 3.0,
    report_format: Annotated[
        str | None,
        typer.Option("--format", help="Output format: json, html, pdf, all."),
    ] = None,
    output: Annotated[
        Path | None, typer.Option("--output", help="Output report base path.")
    ] = None,
    fail_on: Annotated[
        str | None,
        typer.Option("--fail-on", help="Exit non-zero at severity: medium, high, critical."),
    ] = None,
) -> None:
    """Scan a package folder, wheel, or source distribution."""
    quiet = bool(ctx.obj and ctx.obj.get("quiet"))
    try:
        config = load_config(config_path)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    provider_value = provider or config.default_provider
    report_format_value = report_format or config.default_report_format
    show_citations_value = show_citations or config.show_citations
    fail_on_value = fail_on or (config.risk_threshold if config_path is not None else None)
    advisory_lookup: AdvisoryLookup | None = None
    if check_osv or config.check_osv:
        cache_path = advisory_cache or Path(config.advisory_cache_path)

        def configured_advisory_lookup(name: str, version: str | None) -> list[Advisory]:
            return lookup_osv_advisories(name, version, cache_path=cache_path)

        advisory_lookup = configured_advisory_lookup
    try:
        result = scan_path(
            target,
            dry_run=dry_run,
            trace_rules=trace_rules,
            ignored_rules=config.ignored_rules,
            advisory_lookup=advisory_lookup,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if teacher_mode or debug:
        _print_scan_plan(result)
    if verbose:
        console.print(f"[white]Scanned files:[/white] {result.summary.files_scanned}")
    if trace_rules:
        _print_rule_trace(result.rule_trace)
    if explain_risk:
        _print_risk(result)
    if show_evidence or teacher_mode:
        _print_evidence(result)
    if show_citations_value:
        _print_citations()
    if not no_ai and provider_value != "none" and not quiet:
        explanation = explain_from_evidence(
            result.findings,
            provider=provider_value,
            model=model,
            timeout_seconds=ai_timeout,
        )
        console.print(
            Panel(
                "\n".join(explanation.sentences) or "No findings to explain.",
                title="AI Explanation",
            )
        )
    _emit_or_write_report(result, report_format_value, output, show_citations_value)
    _handle_fail_on(result.risk.level.value, fail_on_value)


@app.command("scan-venv")
def scan_venv_command(
    ctx: typer.Context,
    venv_path: Annotated[Path, typer.Argument(help="Virtual environment folder to scan.")],
    debug: Annotated[
        bool, typer.Option("--debug", help="Show detailed scanner decisions.")
    ] = False,
    trace_rules: Annotated[
        bool, typer.Option("--trace-rules", help="Show rule trace output.")
    ] = False,
    show_evidence: Annotated[
        bool, typer.Option("--show-evidence", help="Print evidence table.")
    ] = False,
    teacher_mode: Annotated[
        bool, typer.Option("--teacher-mode", help="Enable explanation-friendly output.")
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show scan plan without scanning.")
    ] = False,
    report_format: Annotated[
        str, typer.Option("--format", help="Output format: json, html, pdf, all.")
    ] = "json",
    output: Annotated[
        Path | None, typer.Option("--output", help="Output report base path.")
    ] = None,
) -> None:
    """Scan installed packages inside a .venv without importing them."""
    _ = ctx
    try:
        result = scan_virtualenv(venv_path, dry_run=dry_run, trace_rules=trace_rules)
    except FileNotFoundError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if teacher_mode or debug:
        _print_scan_plan(result)
    if trace_rules:
        _print_rule_trace(result.rule_trace)
    if show_evidence or teacher_mode:
        _print_evidence(result)
    _emit_or_write_report(result, report_format, output, show_citations=False)


@app.command("scan-installed")
def scan_installed_command(
    python: Annotated[
        Path, typer.Option("--python", help="Python executable inside a virtualenv.")
    ],
    report_format: Annotated[
        str, typer.Option("--format", help="Output format: json, html, pdf, all.")
    ] = "json",
) -> None:
    """Scan installed packages by deriving the virtualenv from a Python executable path."""
    venv_root = python.parent.parent
    result = scan_virtualenv(venv_root)
    _emit_or_write_report(result, report_format, None, show_citations=False)


@app.command()
def install(
    package: Annotated[str, typer.Argument(help="Package specifier to verify and install.")],
    venv_path: Annotated[Path, typer.Option("--venv", help="Virtual environment path.")] = Path(
        ".venv"
    ),
    fail_on: Annotated[
        str,
        typer.Option("--fail-on", help="Block install at severity: low, medium, high, critical."),
    ] = "medium",
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show verified install plan only.")
    ] = False,
) -> None:
    """Download wheels, scan them, then install into .venv only if verification passes."""
    console.print(
        Panel(
            "\n".join(
                [
                    f"Package: {package}",
                    f"Virtual environment: {venv_path}",
                    "Verification: download wheels first, scan statically, "
                    "then install if allowed.",
                    "Default AI provider for explanations: Ollama local.",
                    "Safety: source distributions are not installed by this command.",
                ]
            ),
            title="Verified install plan",
        )
    )
    if dry_run:
        return
    severity = _parse_severity(fail_on)
    decision = install_verified_package(package, venv_path=venv_path, fail_on=severity)
    if decision == InstallDecision.BLOCKED:
        console.print(
            "[bold red]Install blocked because downloaded wheel evidence met "
            "the risk threshold.[/bold red]"
        )
        raise typer.Exit(code=2)
    console.print("[bold green]Package installed after static verification.[/bold green]")


@report_app.command("render")
def report_render(
    input_json: Annotated[Path, typer.Argument(help="Existing JSON report.")],
    output: Annotated[Path, typer.Option("--output", help="Output base path.")] = Path(
        "reports/rendered"
    ),
    report_format: Annotated[
        str, typer.Option("--format", help="Output format: html, pdf, all.")
    ] = "html",
) -> None:
    """Render an existing JSON report into HTML/PDF."""
    payload = json.loads(input_json.read_text(encoding="utf-8"))
    result = scan_result_from_dict(payload)
    paths = render_report(
        result,
        output_base=output,
        formats=[item.strip() for item in report_format.split(",")],
        show_citations=True,
    )
    console.print("Reports written:")
    for path in paths:
        console.print(str(path))


@evidence_app.command("show")
def evidence_show(
    input_json: Annotated[Path, typer.Argument(help="JSON report to inspect.")],
) -> None:
    """Show evidence table from a JSON report."""
    payload = json.loads(input_json.read_text(encoding="utf-8"))
    table = Table(title="Evidence")
    for column in ("ID", "Rule", "Severity", "Location", "Message"):
        table.add_column(column)
    for finding in payload.get("findings", []):
        table.add_row(
            finding["finding_id"],
            finding["rule_id"],
            finding["severity"],
            f"{finding['file_path']}:{finding['line_start']}",
            finding["message"],
        )
    console.print(table)


@rules_app.command("list")
def rules_list() -> None:
    """List detector rules."""
    table = Table(title="PyPi-AI Rules")
    for column in ("Rule", "Severity", "Category", "Title"):
        table.add_column(column)
    for rule in list_rules():
        table.add_row(rule.rule_id, rule.severity.value, rule.category, rule.title)
    console.print(table)


@examples_app.command("list")
def examples_list() -> None:
    """List safe fixtures and public malicious package-name examples."""
    console.print(
        Panel("Safe demo packages live under examples/safe_packages.", title="Safe Examples")
    )
    table = Table(title="Public package-name examples - do not download for tests")
    table.add_column("Name")
    for name in MALICIOUS_PACKAGE_NAME_EXAMPLES:
        table.add_row(name)
    console.print(table)


@benchmark_app.command("run")
def benchmark_run() -> None:
    """Run a lightweight local benchmark over bundled safe fixtures."""
    examples_root = Path("examples/safe_packages")
    if not examples_root.exists():
        raise typer.BadParameter("examples/safe_packages is missing")
    table = Table(title="Benchmark")
    table.add_column("Fixture")
    table.add_column("Findings")
    table.add_column("Risk")
    for fixture in sorted(path for path in examples_root.iterdir() if path.is_dir()):
        result = scan_path(fixture)
        table.add_row(fixture.name, str(result.summary.total_findings), result.risk.level.value)
    console.print(table)


@model_app.command("test")
def model_test(
    provider: Annotated[
        str, typer.Option("--provider", help="Provider to check.")
    ] = "ollama-local",
    model: Annotated[str | None, typer.Option("--model", help="Model name to check.")] = None,
) -> None:
    """Check AI model provider configuration."""
    console.print(provider_health(provider, model))


@theme_app.command("preview")
def theme_preview() -> None:
    """Preview PyPi-AI terminal colors for teacher demos."""
    table = Table(title="Theme preview")
    table.add_column("Element")
    table.add_column("Style")
    table.add_column("Example")
    rows = [
        ("logo", "bold white", "[bold white]PyPi-AI[/bold white]"),
        ("option", "cyan", "[cyan]--teacher-mode[/cyan]"),
        ("success", "green", "[green]Package verified[/green]"),
        ("warning", "yellow", "[yellow]Medium risk evidence[/yellow]"),
        ("error", "red", "[red]Install blocked[/red]"),
        ("critical", "bold red", "[bold red]Critical finding[/bold red]"),
    ]
    for element, style, example in rows:
        table.add_row(element, style, example)
    console.print(table)


@config_app.command("init")
def config_init(
    path: Annotated[Path, typer.Option("--path", help="Config file path.")] = DEFAULT_CONFIG_PATH,
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing config.")] = False,
) -> None:
    """Create a default .pypi-ai.toml file."""
    try:
        written = write_default_config(path, force=force)
    except FileExistsError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"Config written: {written}")


@config_app.command("show")
def config_show(
    path: Annotated[Path, typer.Option("--path", help="Config file path.")] = DEFAULT_CONFIG_PATH,
) -> None:
    """Show the resolved PyPi-AI config."""
    try:
        config = load_config(path)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print_json(json.dumps(config.to_dict()))


@database_app.command("check")
def database_check(
    package: Annotated[str, typer.Argument(help="PyPI package name to check in OSV.dev.")],
    version: Annotated[str | None, typer.Option("--version", help="Optional version.")] = None,
    cache_path: Annotated[
        Path, typer.Option("--cache", help="SQLite advisory cache path.")
    ] = DEFAULT_CACHE_PATH,
) -> None:
    """Check OSV.dev for package advisories using a local SQLite cache."""
    advisories = lookup_osv_advisories(package, version, cache_path=cache_path)
    table = Table(title=f"OSV advisories for {package}")
    table.add_column("ID")
    table.add_column("Summary")
    table.add_column("Aliases")
    for advisory in advisories:
        table.add_row(advisory.advisory_id, advisory.summary, ", ".join(advisory.aliases))
    if not advisories:
        table.add_row("-", "No advisories returned by OSV.dev", "-")
    console.print(table)
    console.print(f"Cache: {cache_path}")


@app.command()
def explain(input_json: Annotated[Path, typer.Argument(help="JSON report to explain.")]) -> None:
    """Generate deterministic evidence-grounded explanation from a JSON report."""
    payload = json.loads(input_json.read_text(encoding="utf-8"))
    for finding in payload.get("findings", []):
        console.print(f"{finding['message']} [{finding['finding_id']}]")


@app.command()
def doctor() -> None:
    """Check local setup."""
    console.print(f"{PROJECT_NAME} {VERSION}")
    console.print(f"Python: {sys.version.split()[0]}")
    console.print("Static scanner: available")
    console.print(provider_health("none"))


def print_about(*, compact: bool) -> None:
    _ = compact
    body = (
        f"{ASCII_ART}\n"
        f"[bold white]{PROJECT_NAME}[/bold white]\n{TAGLINE}\n\n"
        f"Domain: {DOMAIN}\n"
        "Safety: scans statically and never executes untrusted package code.\n"
        "Targets: folder, .whl, .tar.gz, .venv, installed packages.\n"
        "AI modes: Ollama local default, deterministic only, Gemini, Ollama Cloud.\n"
        f"Preferred cloud model: {DEFAULT_OLLAMA_CLOUD_MODEL}.\n"
        "Research anchor: CHASE and evidence-grounded LLM explanations.\n\n"
        "Developers:\n"
        f"- {DEVELOPERS[0]['name']} - {DEVELOPERS[0]['roll']} - {DEVELOPERS[0]['email']}\n"
        f"- {DEVELOPERS[1]['name']} - {DEVELOPERS[1]['roll']} - {DEVELOPERS[1]['email']}\n\n"
        "Teacher demo commands:\n"
        "pypi-ai scan examples/safe_packages/benign --teacher-mode --show-evidence\n"
        "pypi-ai scan examples/safe_packages/obfuscated --debug --trace-rules --explain-risk\n"
        "pypi-ai scan-venv .venv --teacher-mode --format json\n"
    )
    console.print(Panel(body, title="Welcome"))


def _print_scan_plan(result) -> None:  # type: ignore[no-untyped-def]
    if not result.scan_plan:
        return
    console.print(Panel(json.dumps(result.scan_plan.to_dict(), indent=2), title="Scan plan"))


def _print_rule_trace(trace: list[str]) -> None:
    console.print(Panel("\n".join(trace) or "No rule trace entries.", title="Rule trace"))


def _print_risk(result) -> None:  # type: ignore[no-untyped-def]
    console.print(Panel(json.dumps(result.risk.to_dict(), indent=2), title="Risk breakdown"))


def _print_evidence(result) -> None:  # type: ignore[no-untyped-def]
    table = Table(title="Evidence")
    for column in ("ID", "Rule", "Severity", "Location", "Snippet"):
        table.add_column(column)
    for finding in result.findings:
        table.add_row(
            finding.finding_id,
            finding.rule_id,
            finding.severity.value,
            f"{finding.file_path}:{finding.line_start}",
            finding.snippet,
        )
    console.print(table)


def _print_citations() -> None:
    table = Table(title="Citations")
    table.add_column("ID")
    table.add_column("Source")
    for key, value in CITATIONS.items():
        table.add_row(key, value)
    console.print(table)


def _emit_or_write_report(
    result: ScanResult,
    report_format: str,
    output: Path | None,
    show_citations: bool,
) -> None:
    formats = [item.strip() for item in report_format.split(",")]
    supported = {"json", "html", "pdf", "all"}
    unsupported = [item for item in formats if item not in supported]
    if unsupported:
        raise typer.BadParameter(f"Unsupported report format: {', '.join(unsupported)}")
    if output is not None or any(item in {"html", "pdf", "all"} for item in formats):
        output_base = output or Path("reports") / "scan"
        try:
            paths = render_report(
                result, output_base=output_base, formats=formats, show_citations=show_citations
            )
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
        console.print("Reports written:")
        for path in paths:
            console.print(str(path))
        return
    console.print_json(json.dumps(result.to_dict()))


def _handle_fail_on(level: str, fail_on: str | None) -> None:
    if fail_on is None:
        return
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    if order.get(level, 0) >= order.get(fail_on, 99):
        raise typer.Exit(code=2)


def _parse_severity(value: str) -> Severity:
    try:
        return Severity(value)
    except ValueError as exc:
        raise typer.BadParameter("Use one of: info, low, medium, high, critical") from exc
