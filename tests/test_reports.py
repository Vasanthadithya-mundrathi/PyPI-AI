from __future__ import annotations

import json

from pypi_ai.reports import render_report
from pypi_ai.scanner import scan_path


def test_render_json_html_and_pdf_reports(tmp_path) -> None:
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    (package_dir / "danger.py").write_text(
        "import base64\nbase64.b64decode('ZXY=')\n", encoding="utf-8"
    )
    result = scan_path(package_dir)
    output_base = tmp_path / "reports" / "demo"

    written = render_report(
        result, output_base=output_base, formats=["json", "html", "pdf"], show_citations=True
    )

    assert {path.suffix for path in written} == {".json", ".html", ".pdf"}
    json_payload = json.loads((tmp_path / "reports" / "demo.json").read_text(encoding="utf-8"))
    html_payload = (tmp_path / "reports" / "demo.html").read_text(encoding="utf-8")
    pdf_size = (tmp_path / "reports" / "demo.pdf").stat().st_size

    assert json_payload["project"]["name"] == "PyPi-AI"
    assert "Citations" in html_payload
    assert "VASANTH ADITHYA" in html_payload
    assert pdf_size > 1000
