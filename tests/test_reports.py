from __future__ import annotations

import json

from sentinel.models import Finding, ModuleResult, ScanReport, Severity
from sentinel.reports import ReportWriter


def _report() -> ScanReport:
    report = ScanReport.create("https://example.com/", True, "0.1.0")
    report.modules = [
        ModuleResult(
            module="headers",
            findings=[
                Finding(
                    title="Missing header",
                    severity=Severity.LOW,
                    description="Example",
                    evidence="No header",
                    recommendation="Set it",
                    module="headers",
                )
            ],
        )
    ]
    report.statistics = {
        "modules_run": 1,
        "findings": 1,
        "errors": 0,
        "high": 0,
        "medium": 0,
        "low": 1,
        "info": 0,
    }
    return report


def test_renders_json_markdown_html_and_csv_reports() -> None:
    writer = ReportWriter()
    report = _report()

    assert json.loads(json.dumps(report.as_dict()))["target"] == report.target
    assert "Sentinel assessment report" in writer.to_markdown(report)
    assert "<html" in writer.to_html(report)
    assert "Missing header" in writer.to_csv(report)
