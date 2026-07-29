"""JSON, Markdown, HTML, CSV, and PDF report rendering."""

from __future__ import annotations

import csv
import html
import json
from enum import StrEnum
from io import StringIO
from pathlib import Path
from textwrap import wrap

from sentinel.models import Finding, ScanReport


class ReportFormat(StrEnum):
    """Supported report formats."""

    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    CSV = "csv"
    PDF = "pdf"


_EXTENSIONS = {
    ReportFormat.JSON: ".json",
    ReportFormat.MARKDOWN: ".md",
    ReportFormat.HTML: ".html",
    ReportFormat.CSV: ".csv",
    ReportFormat.PDF: ".pdf",
}


class ReportWriter:
    """Write report artifacts and return their final paths."""

    def write(self, report: ScanReport, output: Path, report_format: ReportFormat) -> Path:
        """Render a report, adding the appropriate suffix when needed."""
        output.parent.mkdir(parents=True, exist_ok=True)
        final_path = output if output.suffix else output.with_suffix(_EXTENSIONS[report_format])
        if report_format is ReportFormat.JSON:
            final_path.write_text(
                json.dumps(report.as_dict(), indent=2, default=str), encoding="utf-8"
            )
        elif report_format is ReportFormat.MARKDOWN:
            final_path.write_text(self.to_markdown(report), encoding="utf-8")
        elif report_format is ReportFormat.HTML:
            final_path.write_text(self.to_html(report), encoding="utf-8")
        elif report_format is ReportFormat.CSV:
            final_path.write_text(self.to_csv(report), encoding="utf-8", newline="")
        elif report_format is ReportFormat.PDF:
            self.to_pdf(report, final_path)
        else:  # pragma: no cover - StrEnum is exhaustive, retained for defensive use.
            raise ValueError(f"Unsupported report format: {report_format}")
        return final_path

    @staticmethod
    def findings(report: ScanReport) -> list[Finding]:
        """Flatten report findings while retaining each finding's origin module."""
        return [finding for module in report.modules for finding in module.findings]

    def to_markdown(self, report: ScanReport) -> str:
        """Render a concise, portable Markdown report."""
        statistics = report.statistics
        summary_row = (
            f"| {statistics.get('modules_run', 0)} | {statistics.get('findings', 0)} | "
            f"{statistics.get('errors', 0)} | {statistics.get('high', 0)} | "
            f"{statistics.get('medium', 0)} | {statistics.get('low', 0)} |"
        )
        lines = [
            "# Sentinel assessment report",
            "",
            f"- **Target:** `{report.target}`",
            f"- **Started:** {report.started_at}",
            f"- **Finished:** {report.finished_at}",
            f"- **Authorized acknowledgement:** {report.authorized}",
            "",
            "> " + report.notice,
            "",
            "## Summary",
            "",
            "| Modules | Findings | Errors | High | Medium | Low |",
            "| ---: | ---: | ---: | ---: | ---: | ---: |",
            summary_row,
            "",
            "## Findings",
            "",
        ]
        findings = self.findings(report)
        if not findings:
            lines.append("No reportable observations were produced.")
        for index, finding in enumerate(findings, start=1):
            lines.extend(
                [
                    f"### {index}. [{finding.severity.upper()}] {finding.title}",
                    "",
                    finding.description,
                    "",
                    f"- **Module:** {finding.module}",
                    f"- **Evidence:** {finding.evidence}",
                    f"- **Recommendation:** {finding.recommendation}",
                    f"- **CVSS:** {finding.cvss or 'Not scored'}",
                    "",
                ]
            )
        lines.extend(["## Module data", ""])
        for module in report.modules:
            lines.extend(
                [
                    f"### {module.module}",
                    "",
                    "```json",
                    json.dumps(module.data, indent=2, default=str),
                    "```",
                    "",
                ]
            )
            if module.errors:
                lines.extend(["Errors:", *[f"- {error}" for error in module.errors], ""])
        return "\n".join(lines)

    def to_html(self, report: ScanReport) -> str:
        """Render a self-contained escaped HTML report."""
        styles = (
            "body{font:16px system-ui,sans-serif;max-width:1100px;margin:2rem auto;"
            "padding:0 1rem;color:#17202a}"
            "table{border-collapse:collapse;width:100%}"
            "th,td{border:1px solid #d5d8dc;padding:.55rem;text-align:left;vertical-align:top}"
            "th{background:#17202a;color:white}"
            "pre{white-space:pre-wrap;background:#f4f6f7;padding:1rem}"
            ".notice{background:#fff3cd;padding:1rem}"
        )
        finding_rows = (
            "".join(
                "<tr>"
                f"<td>{html.escape(finding.severity)}</td>"
                f"<td>{html.escape(finding.title)}</td>"
                f"<td>{html.escape(finding.module)}</td>"
                f"<td>{html.escape(finding.evidence)}</td>"
                f"<td>{html.escape(finding.recommendation)}</td>"
                "</tr>"
                for finding in self.findings(report)
            )
            or "<tr><td colspan='5'>No reportable observations were produced.</td></tr>"
        )
        module_blocks = "".join(
            f"<details><summary>{html.escape(module.module)}</summary>"
            f"<pre>{html.escape(json.dumps(module.data, indent=2, default=str))}</pre>"
            f"<pre>{html.escape(chr(10).join(module.errors))}</pre></details>"
            for module in report.modules
        )
        return f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Sentinel report</title><style>{styles}</style></head>
<body>
<h1>Sentinel assessment report</h1>
<p><strong>Target:</strong> {html.escape(report.target)}<br>
<strong>Started:</strong> {html.escape(report.started_at)}<br>
<strong>Finished:</strong> {html.escape(report.finished_at)}</p>
<p class="notice">{html.escape(report.notice)}</p>
<h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>Title</th><th>Module</th><th>Evidence</th>
<th>Recommendation</th></tr></thead><tbody>{finding_rows}</tbody></table>
<h2>Module data</h2>{module_blocks}</body></html>"""

    def to_csv(self, report: ScanReport) -> str:
        """Render one row per finding for spreadsheet workflows."""
        output = StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "severity",
                "title",
                "description",
                "evidence",
                "recommendation",
                "module",
                "cvss",
                "url",
            ],
        )
        writer.writeheader()
        for finding in self.findings(report):
            writer.writerow(
                {
                    "severity": finding.severity,
                    "title": finding.title,
                    "description": finding.description,
                    "evidence": finding.evidence,
                    "recommendation": finding.recommendation,
                    "module": finding.module,
                    "cvss": finding.cvss,
                    "url": finding.url,
                }
            )
        return output.getvalue()

    def to_pdf(self, report: ScanReport, output: Path) -> None:
        """Render a compact PDF using ReportLab when the optional runtime is installed."""
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen.canvas import Canvas

        canvas = Canvas(str(output), pagesize=A4)
        width, height = A4
        x, y = 48, height - 48

        def line(value: str, bold: bool = False) -> None:
            nonlocal y
            if y < 60:
                canvas.showPage()
                y = height - 48
            canvas.setFont("Helvetica-Bold" if bold else "Helvetica", 10 if bold else 9)
            canvas.drawString(x, y, value[:150])
            y -= 15

        line("Sentinel assessment report", bold=True)
        line(f"Target: {report.target}")
        line(f"Started: {report.started_at}")
        line(report.notice)
        line("Findings", bold=True)
        findings = self.findings(report)
        if not findings:
            line("No reportable observations were produced.")
        for finding in findings:
            line(f"[{finding.severity.upper()}] {finding.title}", bold=True)
            for item in wrap(finding.description, width=105):
                line(item)
            for item in wrap(f"Evidence: {finding.evidence}", width=105):
                line(item)
            for item in wrap(f"Recommendation: {finding.recommendation}", width=105):
                line(item)
        canvas.save()
