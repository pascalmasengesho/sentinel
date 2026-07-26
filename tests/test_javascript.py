from __future__ import annotations

from sentinel.config import ScanConfig
from sentinel.http_client import HttpResponse
from sentinel.modules.base import ScanContext
from sentinel.modules.javascript import JavaScriptModule
from sentinel.target import normalize_target


class FakeHttp:
    async def get(self, url: str) -> HttpResponse:
        return HttpResponse(
            url=url,
            status_code=200,
            headers={},
            text='const token = "not-a-real-value-but-long"; fetch("/api/v1/profile")',
            http_version="HTTP/2",
            redirect_chain=[],
        )


async def test_javascript_redacts_secret_values_and_keeps_same_origin() -> None:
    context = ScanContext(
        target=normalize_target("example.com"),
        config=ScanConfig(),
        http=FakeHttp(),  # type: ignore[arg-type]
        http_response=HttpResponse(
            url="https://example.com/",
            status_code=200,
            headers={},
            text='<script src="/app.js"></script><script src="https://cdn.example.net/lib.js"></script>',
            http_version="HTTP/2",
            redirect_chain=[],
        ),
    )

    result = await JavaScriptModule().run(context)

    assert result.data["script_sources"] == ["https://example.com/app.js"]
    assert "/api/v1/profile" in result.data["endpoint_candidates"]
    assert "not-a-real-value" not in result.findings[0].evidence
