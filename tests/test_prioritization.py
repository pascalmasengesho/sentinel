from __future__ import annotations

from sentinel.models import ModuleResult
from sentinel.prioritization import build_research_priorities


def test_builds_manual_research_priorities_without_creating_vulnerability_findings() -> None:
    result = build_research_priorities(
        [
            ModuleResult(
                module="surface",
                data={
                    "authentication_points": ["https://example.com/login"],
                    "forms": [{"has_password": True}],
                    "graphql_candidates": ["https://example.com/graphql"],
                    "websocket_candidates": ["wss://example.com/realtime"],
                },
            ),
            ModuleResult(module="http", data={"cookie_names": ["session"]}),
            ModuleResult(module="javascript", data={"endpoint_candidates": ["/api/v1/profile"]}),
            ModuleResult(
                module="api_discovery",
                data={"public_endpoint_candidates": ["https://example.com/api"]},
            ),
            ModuleResult(module="recon", data={"passive_subdomains": ["api.example.com"]}),
        ]
    )

    priorities = result.data["priorities"]

    assert result.module == "research_priorities"
    assert result.findings == []
    assert result.data["priority_count"] == 4
    assert isinstance(priorities, list)
    assert {priority["title"] for priority in priorities} == {
        "Authentication surface review",
        "Public API and real-time surface review",
        "Browser session and client-side endpoint review",
        "Passive asset inventory review",
    }
    assert "do not assert that a vulnerability exists" in result.data["notice"]
