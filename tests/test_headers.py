from __future__ import annotations

from sentinel.config import ScanConfig
from sentinel.http_client import HttpResponse
from sentinel.modules.base import ScanContext
from sentinel.modules.headers import HeaderModule
from sentinel.target import normalize_target


class DummyHttp:
    pass


async def test_reports_missing_security_headers() -> None:
    context = ScanContext(
        target=normalize_target("example.com"),
        config=ScanConfig(),
        http=DummyHttp(),  # type: ignore[arg-type]
        http_response=HttpResponse(
            url="https://example.com/",
            status_code=200,
            headers={"access-control-allow-origin": "*"},
            text="",
            http_version="HTTP/2",
            redirect_chain=[],
        ),
    )

    result = await HeaderModule().run(context)

    assert len(result.findings) == 7
    assert any(finding.title == "Wildcard CORS origin policy" for finding in result.findings)


async def test_reports_weak_csp_and_short_hsts_without_active_testing() -> None:
    context = ScanContext(
        target=normalize_target("example.com"),
        config=ScanConfig(),
        http=DummyHttp(),  # type: ignore[arg-type]
        http_response=HttpResponse(
            url="https://example.com/",
            status_code=200,
            headers={
                "content-security-policy": "default-src *; script-src 'unsafe-inline'",
                "strict-transport-security": "max-age=300",
                "x-frame-options": "DENY",
                "referrer-policy": "strict-origin",
                "permissions-policy": "geolocation=()",
                "x-content-type-options": "nosniff",
            },
            text="",
            http_version="HTTP/2",
            redirect_chain=[],
        ),
    )

    result = await HeaderModule().run(context)

    titles = {finding.title for finding in result.findings}
    assert "Content-Security-Policy permits unsafe script behavior" in titles
    assert "Content-Security-Policy has a wildcard script source" in titles
    assert "HSTS policy has a short max-age" in titles
