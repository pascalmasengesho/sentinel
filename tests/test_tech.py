"""Tests for passive technology hints."""

from __future__ import annotations

from sentinel.config import ScanConfig
from sentinel.http_client import HttpResponse
from sentinel.modules.base import ScanContext
from sentinel.modules.tech import TechnologyModule
from sentinel.target import normalize_target


class DummyHttp:
    """Technology detection only uses the shared root response."""


async def test_technology_module_groups_passive_framework_and_edge_hints() -> None:
    context = ScanContext(
        target=normalize_target("example.com"),
        config=ScanConfig(),
        http=DummyHttp(),  # type: ignore[arg-type]
        http_response=HttpResponse(
            url="https://example.com/",
            status_code=200,
            headers={
                "server": "nginx",
                "cf-ray": "example",
                "x-powered-by": "PHP/8.3",
            },
            text='<script src="/react.production.min.js"></script>wp-content/',
            http_version="HTTP/2",
            redirect_chain=[],
        ),
    )

    result = await TechnologyModule().run(context)

    hints = result.data["technology_hints"]
    assert {"React", "WordPress"}.issubset(result.data["technologies"])
    assert hints["cdn_or_edge"] == ["Cloudflare"]
    assert hints["waf_hints"] == ["Cloudflare"]
    assert hints["programming_language_hints"] == ["X-Powered-By: PHP/8.3"]
