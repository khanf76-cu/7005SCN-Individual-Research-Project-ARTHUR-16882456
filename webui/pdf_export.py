"""PDF report generation using fpdf2 (pure Python, no system
dependencies like a headless browser or wkhtmltopdf), so it runs
anywhere the rest of the artefact runs.
"""
from __future__ import annotations

from pathlib import Path

from fpdf import FPDF

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


class ReportPDF(FPDF):
    def header(self) -> None:
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(0, 180, 180)
        self.cell(0, 10, "ARTHUR - Multi-Agent Assessment Report", new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)
        self.set_font("Helvetica", "", 9)
        self.ln(1)

    def footer(self) -> None:
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")


def _safe(text) -> str:
    if text is None:
        return ""
    return str(text).encode("latin-1", errors="replace").decode("latin-1")


def build_pdf_report(result_dict: dict, out_path: Path) -> Path:
    pdf = ReportPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, f"Target: {_safe(result_dict.get('target_origin'))}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 6, f"Run ID: {_safe(result_dict.get('run_id'))}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, f"Total duration: {result_dict.get('duration_s', 0):.1f}s", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    correlate = result_dict.get("correlate") or {}

    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(0, 140, 140)
    pdf.cell(0, 8, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(0, 5, _safe(correlate.get("executive_summary", "No summary available.")))
    pdf.ln(2)

    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 6, f"Overall risk rating: {_safe(correlate.get('overall_risk_rating', 'unknown')).upper()}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    findings = correlate.get("findings", [])
    findings_sorted = sorted(
        findings, key=lambda f: SEVERITY_ORDER.get((f.get("severity") or "unknown").lower(), 5)
    )

    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(0, 140, 140)
    pdf.cell(0, 8, f"Findings ({len(findings_sorted)})", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(1)

    for f in findings_sorted:
        severity = (f.get("severity") or "unknown").upper()
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 6, f"[{severity}] {_safe(f.get('title'))}", new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, f"Endpoint: {_safe(f.get('endpoint'))}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(
            0,
            5,
            f"Confidence: {_safe(f.get('confidence'))}  |  Category: {_safe(f.get('category'))}  "
            f"|  Source: {', '.join(f.get('source_agents', []) or [])}",
            new_x="LMARGIN",
            new_y="NEXT",
        )
        if f.get("related_cves"):
            pdf.cell(0, 5, f"Related CVEs: {', '.join(f.get('related_cves', []))}", new_x="LMARGIN", new_y="NEXT")
        pdf.multi_cell(0, 5, f"Evidence: {_safe(f.get('evidence'))}")
        pdf.ln(2)

    if correlate.get("deduplication_notes"):
        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 7, "Deduplication Notes", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 5, _safe(correlate.get("deduplication_notes")))

    errors = result_dict.get("errors") or {}
    if errors:
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(180, 0, 0)
        pdf.cell(0, 7, "Agent Errors", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 9)
        for stage, err in errors.items():
            pdf.multi_cell(0, 5, f"{stage}: {_safe(err)}")

    pdf.output(str(out_path))
    return out_path
