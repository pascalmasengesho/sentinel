from __future__ import annotations

from sentinel.config import ScanConfig
from sentinel.http_client import HttpResponse
from sentinel.modules.base import ScanContext
from sentinel.modules.robots import RobotsModule
from sentinel.target import normalize_target


class _FakeHttp:
    def __init__(self, status_code: int = 200) -> None:
        self.status_code = status_code

    async def get(self, url: str) -> HttpResponse:
        return HttpResponse(
            url=url,
            status_code=self.status_code,
            headers={},
            text=(
                "User-agent: *\n"
                "Disallow: /admin\n"
                "Disallow: /private/\n"
                "Sitemap: https://example.com/sitemap.xml\n"
            ),
            http_version="HTTP/2",
            redirect_chain=[],
        )


def _context(status_code: int = 200) -> ScanContext:
    return ScanContext(
        target=normalize_target("https://example.com"),
        config=ScanConfig(),
        http=_FakeHttp(status_code),  # type: ignore[arg-type]
    )


async def test_robots_module_collects_disallowed_paths_and_sitemaps() -> None:
    context = _context()

    result = await RobotsModule().run(context)

    assert result.data["disallowed_paths"] == ["/admin", "/private/"]
    assert result.data["sitemaps"] == ["https://example.com/sitemap.xml"]
    assert context.robots_disallowed == ["/admin", "/private/"]
    assert context.robots_sitemaps == ["https://example.com/sitemap.xml"]


async def test_robots_module_records_non_200_without_parsing() -> None:
    result = await RobotsModule().run(_context(status_code=404))

    assert result.data["status_code"] == 404
    assert result.data.get("disallowed_paths") is None
