"""PDF report (fpdf2): verdict, AI summary, issues with explanation and fix, and files reviewed."""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from fpdf import FPDF, XPos, YPos

RGB = Tuple[int, int, int]
VERDICT_COLORS: Dict[str, RGB] = {"FAIL": (220, 38, 38), "WARN": (217, 119, 6), "PASS": (22, 163, 74)}
SEVERITY_COLORS: Dict[str, RGB] = {"CRITICAL": (185, 28, 28), "HIGH": (234, 88, 12), "MEDIUM": (202, 138, 4),
                                   "LOW": (14, 116, 144), "INFO": (100, 116, 139)}
INK: RGB = (18, 24, 38)
MUTED: RGB = (110, 118, 135)
RULE: RGB = (227, 230, 239)
MAX_FINDINGS = 40


def clean(text: Any, limit: int = 0) -> str:
    """Core PDF fonts are Latin-1 only; replace anything else."""
    value = str(text if text is not None else "")
    for a, b in (("—", "-"), ("–", "-"), ("‘", "'"), ("’", "'"), ("“", '"'),
                 ("”", '"'), ("…", "..."), ("\t", "    ")):
        value = value.replace(a, b)
    value = value.encode("latin-1", "replace").decode("latin-1")
    if limit and len(value) > limit:
        value = value[: limit - 3] + "..."
    return value


class ReportPDF(FPDF):
    project_name = ""

    def header(self) -> None:
        if self.page_no() == 1:
            return
        self.set_font("helvetica", "", 8)
        self.set_text_color(*MUTED)
        self.cell(0, 6, clean(f"AI code review - {self.project_name}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("helvetica", "", 8)
        self.set_text_color(*MUTED)
        self.cell(0, 6, f"Page {self.page_no()}/{{nb}}", align="C")

    def heading(self, text: str) -> None:
        self.ln(4)
        self.set_font("helvetica", "B", 12)
        self.set_text_color(*INK)
        self.cell(0, 8, clean(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(*RULE)
        self.line(self.l_margin, self.get_y(), self.l_margin + self.epw, self.get_y())
        self.ln(2)

    def pill(self, text: str, color: RGB, width: float = 22) -> None:
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.set_font("helvetica", "B", 7)
        self.cell(width, 5, clean(text), align="C", fill=True)
        self.set_text_color(*INK)

    def ensure_space(self, height: float) -> None:
        if self.get_y() + height > self.h - self.b_margin:
            self.add_page()


def _summary(pdf: ReportPDF, project_name: str, r: Dict[str, Any]) -> None:
    verdict = r.get("verdict", "PASS")
    color = VERDICT_COLORS.get(verdict, MUTED)
    stats = r.get("stats") or {}
    pdf.set_font("helvetica", "B", 20)
    pdf.set_text_color(*INK)
    pdf.cell(0, 10, "AI code review", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("helvetica", "", 10)
    pdf.set_text_color(*MUTED)
    scope = f"changes since {r['base_ref']}" if r.get("base_ref") else "whole project"
    pdf.multi_cell(0, 5, clean(f"{project_name} | {scope} | {r.get('finished_at', '')} | "
                               f"{r.get('model', '')}\n{r.get('target', '')}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)
    top = pdf.get_y()
    pdf.set_fill_color(*color)
    pdf.rect(pdf.l_margin, top, 3, 20, style="F")
    pdf.set_xy(pdf.l_margin + 6, top + 1)
    pdf.set_font("helvetica", "B", 18)
    pdf.set_text_color(*color)
    pdf.cell(0, 10, clean(r.get("verdict_label", verdict)), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_x(pdf.l_margin + 6)
    pdf.set_font("helvetica", "", 10)
    pdf.set_text_color(*INK)
    pdf.multi_cell(pdf.epw - 6, 5, clean(r.get("verdict_reason", ""), 300), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_y(max(pdf.get_y(), top + 22))
    pdf.set_font("helvetica", "", 9)
    pdf.set_text_color(*MUTED)
    pdf.cell(0, 5, clean(f"{stats.get('files_reviewed', 0)} files reviewed, +{stats.get('lines_added', 0)} / "
                         f"-{stats.get('lines_removed', 0)} lines, {stats.get('issues', 0)} issues"
                         f"{', ' + str(stats['ignored']) + ' ignored' if stats.get('ignored') else ''}"),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    counts = stats.get("by_severity") or {}
    pdf.ln(1)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        pdf.pill(sev, SEVERITY_COLORS[sev], 20)
        pdf.set_font("helvetica", "B", 9)
        pdf.cell(14, 5, f" {counts.get(sev, 0)}")
    pdf.ln(7)
    if r.get("summary"):
        pdf.heading("Summary")
        pdf.set_font("helvetica", "", 10)
        pdf.set_text_color(*INK)
        pdf.multi_cell(0, 5, clean(r["summary"], 2000), new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _code_block(pdf: ReportPDF, code: str, max_lines: int = 16) -> None:
    lines = (code or "").splitlines()
    shown = lines[:max_lines]
    if len(lines) > max_lines:
        shown.append(f"... {len(lines) - max_lines} more lines")
    pdf.set_font("courier", "", 8)
    pdf.set_fill_color(246, 247, 251)
    pdf.set_text_color(*INK)
    for line in shown:
        pdf.ensure_space(4)
        pdf.cell(0, 3.8, clean(line, 120), fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)


def _findings(pdf: ReportPDF, findings: List[Dict[str, Any]]) -> None:
    active = [f for f in findings if not f.get("suppressed")]
    pdf.heading(f"Issues ({min(len(active), MAX_FINDINGS)} of {len(active)})")
    if not active:
        pdf.set_font("helvetica", "", 10)
        pdf.set_text_color(*MUTED)
        pdf.cell(0, 6, "No issues found in the changed code.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        return
    for f in active[:MAX_FINDINGS]:
        pdf.ensure_space(28)
        sev = str(f.get("severity", "LOW"))
        pdf.pill(sev, SEVERITY_COLORS.get(sev, MUTED), 18)
        pdf.set_font("helvetica", "B", 9)
        lines = f"{f.get('line')}" + (f"-{f['end_line']}" if f.get("end_line") and f["end_line"] != f.get("line") else "")
        pdf.cell(0, 5, clean(f"  {f.get('file_path', '')}:{lines}  [{f.get('category', '')}]", 110),
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("helvetica", "B", 10)
        pdf.set_text_color(*INK)
        pdf.multi_cell(0, 5, clean(f.get("title", ""), 300), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        if f.get("explanation"):
            pdf.set_font("helvetica", "", 9)
            pdf.multi_cell(0, 4.5, clean(f["explanation"], 800), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        if f.get("fix"):
            pdf.set_font("helvetica", "B", 8)
            pdf.set_text_color(*MUTED)
            pdf.cell(0, 5, "Suggested fix", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            _code_block(pdf, f["fix"])
        pdf.set_draw_color(*RULE)
        pdf.line(pdf.l_margin, pdf.get_y() + 1, pdf.l_margin + pdf.epw, pdf.get_y() + 1)
        pdf.ln(3)


def _files(pdf: ReportPDF, files: List[Dict[str, Any]]) -> None:
    pdf.heading("Files")
    pdf.set_font("helvetica", "", 9)
    for f in files:
        pdf.ensure_space(5)
        pdf.set_text_color(*INK)
        pdf.cell(110, 5, clean(f.get("path", ""), 80))
        pdf.set_text_color(*MUTED)
        status = f.get("status", "")
        detail = f"{f.get('issues', 0)} issues" if status == "reviewed" else f.get("message", "")
        pdf.cell(0, 5, clean(f"{status}: {detail}", 70), new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def generate_pdf_report(project_name: str, results: Dict[str, Any], output_path: str) -> str:
    pdf = ReportPDF(format="A4")
    pdf.project_name = project_name
    pdf.set_margins(14, 14, 14)
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.alias_nb_pages()
    pdf.add_page()
    _summary(pdf, project_name, results)
    _findings(pdf, results.get("findings") or [])
    _files(pdf, results.get("files") or [])
    pdf.output(output_path)
    return output_path
