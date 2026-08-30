from __future__ import annotations

from sentinel.config import ScanConfig
from sentinel.http_client import HttpResponse
from sentinel.modules.base import ScanContext
from sentinel.modules.sitemap import SitemapModule
from sentinel.target import normalize_target


class _FakeHttp:
    def __init__(self, responses: dict[str, str]) -> None:
        self.responses = responses

    async def get(self, url: str) -> HttpResponse:
        text = self.responses.get(url, "")
        return HttpResponse(
            url=url,
            status_code=200 if text else 404,
            headers={},
            text=text,
            http_version="HTTP/2",
            redirect_chain=[],
        )


def _context(responses: dict[str, str]) -> ScanContext:
    return ScanContext(
        target=normalize_target("https://example.com"),
        config=ScanConfig(),
        http=_FakeHttp(responses),  # type: ignore[arg-type]
    )


def test_sitemap_parser_handles_urlsets_and_indexes() -> None:
    urls, nested = SitemapModule._parse(
        """<?xml version="1.0"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <url><loc>https://example.com/a</loc></url>
        </urlset>"""
    )

    assert urls == []
    assert nested == ["https://example.com/a"]

    nested, urls = SitemapModule._parse(
        """<?xml version="1.0"?>
        <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <sitemap><loc>https://example.com/sitemap-1.xml</loc></sitemap>
        </sitemapindex>"""
    )

    assert nested == ["https://example.com/sitemap-1.xml"]
    assert urls == []


async def test_sitemap_module_collects_only_same_host_urls() -> None:
    context = _context(
        {
            "https://example.com/sitemap.xml": (
                '<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                "<url><loc>https://example.com/page</loc></url>"
                "<url><loc>https://other.example/page</loc></url>"
                "</urlset>"
            )
        }
    )

    result = await SitemapModule().run(context)

    assert result.data["urls"] == ["https://example.com/page"]
    assert result.data["url_count"] == 1
