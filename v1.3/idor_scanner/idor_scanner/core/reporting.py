"""Report exports: HTML, JSON, and PDF.

HTML is rendered with Jinja2. JSON is a direct dump of the scan result. PDF is
produced by rendering the HTML in headless Chromium via Playwright - reusing a
dependency the project already needs, so no extra system packages (wkhtmltopdf,
weasyprint) are required.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .models import ScanResult, Severity

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )


def _context(result: ScanResult) -> dict:
    findings = sorted(result.findings, key=lambda f: _SEV_ORDER.get(f.severity.value, 9))
    return {
        "target": result.target,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "status": result.status.value,
        "start_time": result.start_time,
        "end_time": result.end_time,
        "stats": {
            "endpoints": result.endpoints, "parameters": result.parameters,
            "objects": result.objects, "findings": len(result.findings),
        },
        "risk": result.risk_rating,
        "sev_counts": result.severity_counts(),
        "findings": findings,
        "matrix": result.matrix,
        "matrix_summary": dict(Counter(c.result for c in result.matrix)),
    }


def render_html(result: ScanResult) -> str:
    return _env().get_template("report.html.j2").render(**_context(result))


def export_html(result: ScanResult, out_dir: str) -> str:
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    path = Path(out_dir) / "idor_report.html"
    path.write_text(render_html(result), encoding="utf-8")
    return str(path)


def export_json(result: ScanResult, out_dir: str) -> str:
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    path = Path(out_dir) / "idor_report.json"
    path.write_text(json.dumps(result.to_dict(), indent=2, default=str), encoding="utf-8")
    return str(path)


def export_pdf(result: ScanResult, out_dir: str) -> str:
    """Render the HTML report to PDF via Playwright/Chromium.

    Raises RuntimeError with a friendly message if the browser isn't installed.
    """
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    html_path = export_html(result, out_dir)
    pdf_path = Path(out_dir) / "idor_report.pdf"
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("Playwright is not installed; run 'pip install playwright'.") from exc
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            page = browser.new_page()
            page.goto(Path(html_path).as_uri())
            page.pdf(path=str(pdf_path), format="A4",
                     print_background=True, margin={"top": "12mm", "bottom": "12mm"})
            browser.close()
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "Could not generate PDF. Run 'playwright install chromium' once, "
            f"then retry. Underlying error: {exc}"
        ) from exc
    return str(pdf_path)
