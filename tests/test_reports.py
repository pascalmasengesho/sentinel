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


def test_report_can_be_restored_for_offline_rerendering() -> None:
    report = _report()

    restored = ScanReport.from_dict(json.loads(json.dumps(report.as_dict())))

    assert restored.as_dict() == report.as_dict()


def test_html_report_includes_enterprise_dashboard_and_investigation_guidance() -> None:
    rendered = ReportWriter().to_html(_report())

    assert 'data-theme="dark"' in rendered
    assert "Executive summary" in rendered
    assert "Risk overview" in rendered
    assert "Research priorities" in rendered
    assert "Critical severity" in rendered
    assert "URLs discovered" in rendered
    assert "Investigation Assistant" in rendered
    assert "Copy evidence" in rendered
    assert "data-sortable-findings" in rendered
    assert "data-finding-search" in rendered
    assert "No confirmed reportable vulnerability has been identified" in rendered
    assert '<script id="scan-data" type="application/json">' in rendered


def test_html_report_shows_optional_presentation_only_configuration_snapshot() -> None:
    report = _report()
    rendered = ReportWriter(config_snapshot={"concurrency": 2, "verify_tls": True}).to_html(report)

    assert "Assessment configuration" in rendered
    assert "Concurrency" in rendered
    assert "Verify Tls" in rendered
    assert "config_snapshot" not in report.as_dict()


def test_html_report_escapes_scan_values_and_supports_safe_branding() -> None:
    report = _report()
    report.modules[0].findings[0].title = '<script>alert("xss")</script>'
    report.modules[0].findings[0].evidence = "<unsafe-evidence>"

    rendered = ReportWriter(
        brand_name="Acme Security",
        logo_url="https://example.test/logo.svg",
    ).to_html(report)

    assert "Acme Security" in rendered
    assert 'src="https://example.test/logo.svg"' in rendered
    assert "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;" in rendered
    assert "&lt;unsafe-evidence&gt;" in rendered
    assert "javascript:" not in ReportWriter(logo_url="javascript:alert(1)").to_html(report)
