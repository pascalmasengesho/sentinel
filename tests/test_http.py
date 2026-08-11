from __future__ import annotations

from sentinel.config import ScanConfig
from sentinel.http_client import HttpResponse
from sentinel.modules.base import ScanContext
from sentinel.modules.http import HttpModule
from sentinel.target import normalize_target


class DummyHttp:
    """Return captured public response metadata without performing requests in tests."""

    async def get(self, url: str) -> HttpResponse:
        return HttpResponse(
            url=url,
            status_code=200,
            headers={"set-cookie": "session=<redacted>"},
            text="",
            http_version="HTTP/2",
            redirect_chain=[],
            set_cookie_headers=["session=<redacted>; Path=/"],
        )

    async def options(self, url: str) -> HttpResponse:
        return HttpResponse(
            url=url,
            status_code=204,
            headers={"allow": "GET, OPTIONS, PUT"},
            text="",
            http_version="HTTP/2",
            redirect_chain=[],
        )


async def test_reports_cookie_hardening_and_advertised_method_observations() -> None:
    context = ScanContext(
        target=normalize_target("example.com"),
        config=ScanConfig(),
        http=DummyHttp(),  # type: ignore[arg-type]
    )

    result = await HttpModule().run(context)

    assert result.data["cookie_names"] == ["session"]
    assert result.data["cookies"] == [
        {
            "name": "session",
            "secure": False,
            "httponly": False,
            "samesite": "",
            "path": "/",
            "domain": "",
        }
    ]
    titles = {finding.title for finding in result.findings}
    assert "Potentially state-changing HTTP methods advertised" in titles
    assert "Cookie missing Secure attribute" in titles
    assert "Session-like cookie missing HttpOnly attribute" in titles
    assert "Cookie has no explicit SameSite attribute" in titles
