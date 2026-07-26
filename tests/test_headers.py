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
