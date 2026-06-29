from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, cast

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from pypi_ai.ai import explain_from_evidence
from pypi_ai.models import Finding, RiskScore, ScanResult, ScanSummary, Severity


def render_report(
    result: ScanResult,
    *,
    output_base: Path,
    formats: list[str],
    show_citations: bool = False,
) -> list[Path]:
    output_base.parent.mkdir(parents=True, exist_ok=True)
    expanded = ["json", "html", "pdf"] if "all" in formats else formats
    written: list[Path] = []
    for report_format in expanded:
        if report_format == "json":
            path = output_base.with_suffix(".json")
            path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
            written.append(path)
        elif report_format == "html":
            path = output_base.with_suffix(".html")
            path.write_text(_html_report(result, show_citations=show_citations), encoding="utf-8")
            written.append(path)
        elif report_format == "pdf":
            path = output_base.with_suffix(".pdf")
            _pdf_report(result, path, show_citations=show_citations)
            written.append(path)
        else:
            raise ValueError(f"Unsupported report format: {report_format}")
    return written


def scan_result_from_dict(payload: dict[str, object]) -> ScanResult:
    summary_payload = _dict_payload(payload["summary"])
    risk_payload = _dict_payload(payload["risk"])
    findings_payload = payload.get("findings", [])
    if not isinstance(findings_payload, list):
        raise ValueError("findings must be a list")
    findings = [
        Finding(
            finding_id=str(_dict_payload(item)["finding_id"]),
            rule_id=str(_dict_payload(item)["rule_id"]),
            severity=Severity(str(_dict_payload(item)["severity"])),
            category=str(_dict_payload(item)["category"]),
            file_path=str(_dict_payload(item)["file_path"]),
            line_start=int(_dict_payload(item)["line_start"]),
            line_end=int(_dict_payload(item)["line_end"]),
            snippet=str(_dict_payload(item)["snippet"]),
            message=str(_dict_payload(item)["message"]),
            confidence=float(_dict_payload(item)["confidence"]),
            tags=[str(tag) for tag in _list_payload(_dict_payload(item)["tags"])],
            citations=[str(cite) for cite in _list_payload(_dict_payload(item)["citations"])],
            package_name=_optional_str(_dict_payload(item).get("package_name")),
            package_version=_optional_str(_dict_payload(item).get("package_version")),
        )
        for item in findings_payload
    ]
    return ScanResult(
        project=_dict_payload(payload["project"]),
        summary=ScanSummary(
            target=str(summary_payload["target"]),
            input_type=str(summary_payload["input_type"]),
            files_scanned=int(summary_payload["files_scanned"]),
            packages_scanned=int(summary_payload["packages_scanned"]),
            total_findings=int(summary_payload["total_findings"]),
        ),
        risk=RiskScore(
            score=int(risk_payload["score"]),
            level=Severity(str(risk_payload["level"])),
            breakdown={
                str(key): int(value)
                for key, value in _dict_payload(risk_payload["breakdown"]).items()
            },
        ),
        findings=findings,
        citations={
            str(key): str(value)
            for key, value in _dict_payload(payload.get("citations", {})).items()
        },
        limitations=[str(item) for item in _list_payload(payload.get("limitations", []))],
    )


def _dict_payload(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Expected object payload")
    return cast(dict[str, Any], value)


def _list_payload(value: object) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError("Expected list payload")
    return value


def _optional_str(value: object) -> str | None:
    return None if value is None else str(value)


def _html_report(result: ScanResult, *, show_citations: bool) -> str:
    explanation = explain_from_evidence(result.findings)
    developer_rows = "".join(
        "<li>"
        f"{html.escape(dev['name'])} - {html.escape(dev['roll'])} - "
        f"{html.escape(dev['email'])}</li>"
        for dev in result.project["developers"]
    )
    finding_rows = "".join(
        "<tr>"
        f"<td>{html.escape(finding.finding_id)}</td>"
        f"<td>{html.escape(finding.rule_id)}</td>"
        f"<td>{html.escape(finding.severity.value)}</td>"
        f"<td>{html.escape(finding.file_path)}:{finding.line_start}</td>"
        f"<td><code>{html.escape(finding.snippet)}</code></td>"
        "</tr>"
        for finding in result.findings
    )
    citations = ""
    if show_citations:
        citation_rows = "".join(
            f"<li><strong>{html.escape(key)}</strong>: {html.escape(value)}</li>"
            for key, value in result.citations.items()
        )
        citations = f"<h2>Citations</h2><ul>{citation_rows}</ul>"
    explanation_rows = "".join(
        f"<li>{html.escape(sentence)}</li>" for sentence in explanation.sentences
    )
    limitation_rows = "".join(f"<li>{html.escape(item)}</li>" for item in result.limitations)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{html.escape(result.project["name"])} Security Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; color: #111; background: #fff; margin: 32px; }}
    h1, h2 {{ color: #000; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #333; padding: 8px; vertical-align: top; }}
    th {{ background: #f1f1f1; }}
    code {{ white-space: pre-wrap; }}
  </style>
</head>
<body>
  <h1>{html.escape(result.project["name"])} Evidence Report</h1>
  <p>{html.escape(result.project["safety"])}</p>
  <h2>Developers</h2><ul>{developer_rows}</ul>
  <h2>Summary</h2>
  <p>Target: {html.escape(result.summary.target)}<br>
  Risk: {result.risk.score}/100 ({html.escape(result.risk.level.value)})<br>
  Findings: {result.summary.total_findings}</p>
  <h2>Evidence</h2>
  <table><thead><tr><th>ID</th><th>Rule</th><th>Severity</th><th>Location</th><th>Snippet</th></tr></thead>
  <tbody>{finding_rows}</tbody></table>
  <h2>Evidence-Grounded Explanation</h2><ul>{explanation_rows}</ul>
  <h2>Limitations</h2><ul>{limitation_rows}</ul>
  {citations}
</body>
</html>
"""


def _pdf_report(result: ScanResult, path: Path, *, show_citations: bool) -> None:
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(path), pagesize=letter)
    story: list[object] = [
        Paragraph(f"{result.project['name']} Evidence Report", styles["Title"]),
        Paragraph(result.project["safety"], styles["BodyText"]),
        Spacer(1, 12),
        Paragraph("Developers", styles["Heading2"]),
    ]
    for developer in result.project["developers"]:
        story.append(
            Paragraph(
                f"{developer['name']} - {developer['roll']} - {developer['email']}",
                styles["BodyText"],
            )
        )
    story.extend(
        [
            Spacer(1, 12),
            Paragraph("Summary", styles["Heading2"]),
            Paragraph(
                f"Target: {result.summary.target}<br/>Risk: {result.risk.score}/100 "
                f"({result.risk.level.value})<br/>Findings: {result.summary.total_findings}",
                styles["BodyText"],
            ),
            Spacer(1, 12),
            Paragraph("Evidence", styles["Heading2"]),
        ]
    )
    data = [["ID", "Rule", "Severity", "Location"]]
    data.extend(
        [
            finding.finding_id,
            finding.rule_id,
            finding.severity.value,
            f"{finding.file_path}:{finding.line_start}",
        ]
        for finding in result.findings[:20]
    )
    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, "black")]))
    story.append(table)
    if show_citations:
        story.append(Spacer(1, 12))
        story.append(Paragraph("Citations", styles["Heading2"]))
        for key, value in result.citations.items():
            story.append(Paragraph(f"{key}: {value}", styles["BodyText"]))
    doc.build(story)
