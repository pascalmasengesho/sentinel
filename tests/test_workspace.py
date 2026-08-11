from __future__ import annotations

from sentinel.models import Finding, ModuleResult, ScanReport, Severity
from sentinel.workspace import WorkspaceStore


def _report(
    title: str = "Missing Content-Security-Policy header", technology: str = "React"
) -> ScanReport:
    report = ScanReport.create("https://example.com/", True, "0.1.0")
    report.modules = [
        ModuleResult(
            module="dns",
            data={"records": {"A": ["192.0.2.1"], "MX": ["mail.example.com."]}},
        ),
        ModuleResult(
            module="recon",
            data={"passive_subdomains": ["api.example.com"], "cdn": ["cloudflare"], "waf": []},
        ),
        ModuleResult(
            module="technology",
            data={"technologies": [technology], "technology_hints": {"frameworks": [technology]}},
        ),
        ModuleResult(
            module="http",
            data={"cookie_names": ["session"], "url": "https://example.com/"},
        ),
        ModuleResult(
            module="ports",
            data={"open_ports": [{"port": 443, "service": "https"}]},
        ),
        ModuleResult(
            module="javascript",
            data={
                "script_sources": ["https://example.com/app.js"],
                "endpoint_candidates": ["/api/v1/users"],
            },
        ),
        ModuleResult(
            module="api_discovery",
            data={"public_endpoint_candidates": ["https://example.com/graphql"]},
        ),
        ModuleResult(
            module="sitemap",
            data={"urls": ["https://example.com/docs"], "url_count": 1},
        ),
        ModuleResult(
            module="headers",
            data={"observed_headers": {"content-security-policy": "default-src 'self'"}},
            findings=[
                Finding(
                    title=title,
                    severity=Severity.LOW,
                    description="A test observation.",
                    evidence="Synthetic evidence.",
                    recommendation="Review the configuration.",
                    module="headers",
                    url="https://example.com/",
                )
            ],
        ),
    ]
    report.statistics = {
        "modules_run": len(report.modules),
        "findings": 1,
        "errors": 0,
        "high": 0,
        "medium": 0,
        "low": 1,
        "info": 0,
    }
    return report


def test_workspace_stores_history_notes_and_a_local_graph(tmp_path) -> None:
    store = WorkspaceStore(tmp_path / "research.db")
    scan_id = store.save_scan(_report(), {"concurrency": 2})
    note_id = store.add_note(
        target="https://example.com/",
        content="Review the API response manually within scope.",
        tags=["api", "follow-up"],
        scan_id=scan_id,
        favorite=True,
    )

    history = store.list_scans(target="https://example.com/")
    notes = store.search_notes("follow-up")
    graph = store.graph_for_scan(scan_id).as_dict()

    assert history[0].scan_id == scan_id
    assert history[0].findings_count == 1
    assert notes[0].note_id == note_id
    assert notes[0].favorite
    assert notes[0].tags == ("api", "follow-up")
    assert graph["statistics"] == {"nodes": 16, "edges": 15}
    assert {node["kind"] for node in graph["nodes"]} >= {
        "api_endpoint",
        "cookie",
        "dns_record",
        "graphql_endpoint",
        "observation",
        "subdomain",
        "technology",
    }


def test_workspace_comparison_reports_observed_changes_without_claiming_impact(tmp_path) -> None:
    store = WorkspaceStore(tmp_path / "research.db")
    previous_scan_id = store.save_scan(_report(), {"concurrency": 2})
    current_scan_id = store.save_scan(
        _report(title="Wildcard CORS origin policy", technology="Vue.js"), {"concurrency": 2}
    )

    comparison = store.compare_scans(previous_scan_id, current_scan_id)

    assert comparison.target == "https://example.com/"
    assert comparison.new_findings[0]["title"] == "Wildcard CORS origin policy"
    assert comparison.resolved_findings[0]["title"] == "Missing Content-Security-Policy header"
    assert "technology" in comparison.changed_modules
    assert "Validate scope and impact manually" in comparison.as_dict()["notice"]


def test_workspace_rejects_comparison_for_different_targets(tmp_path) -> None:
    store = WorkspaceStore(tmp_path / "research.db")
    first_scan_id = store.save_scan(_report(), {})
    other = _report()
    other.target = "https://other.example/"
    second_scan_id = store.save_scan(other, {})

    try:
        store.compare_scans(first_scan_id, second_scan_id)
    except ValueError as exc:
        assert "same exact target" in str(exc)
    else:  # pragma: no cover - regression protection for a required safety check.
        raise AssertionError("Expected different-target comparison to fail")
