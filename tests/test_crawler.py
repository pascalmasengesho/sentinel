from __future__ import annotations

import pytest

from sentinel.config import ScanConfig
from sentinel.http_client import HttpResponse
from sentinel.modules.base import ScanContext
from sentinel.modules.crawler import CrawlerModule
from sentinel.target import normalize_target


class _FakeHttp:
    def __init__(self, responses: dict[str, HttpResponse]) -> None:
        self.responses = responses
        self.requests: list[str] = []

    async def get(self, url: str) -> HttpResponse:
        self.requests.append(url)
        return self.responses[url]


def _response(url: str, text: str, status_code: int = 200) -> HttpResponse:
    return HttpResponse(
        url=url,
        status_code=status_code,
        headers={"content-type": "text/html"},
        text=text,
        http_version="HTTP/1.1",
        redirect_chain=[],
    )


@pytest.mark.asyncio
async def test_crawler_follows_only_bounded_same_host_query_free_links() -> None:
    target = normalize_target("https://example.com")
    root = _response(
        target.url,
        """<a href='/about'>About</a><a href='/private'>Private</a>
        <a href='/search?q=term'>Search</a><a href='https://other.example/docs'>Other</a>""",
    )
    about = _response("https://example.com/about", "<a href='/team'>Team</a>")
    team = _response("https://example.com/team", "")
    http = _FakeHttp({about.url: about, team.url: team})
    context = ScanContext(
        target=target,
        config=ScanConfig(enable_safe_crawl=True, max_crawl_pages=3, max_crawl_depth=2),
        http=http,  # type: ignore[arg-type]
        http_response=root,
        robots_disallowed=["/private"],
    )

    result = await CrawlerModule().run(context)

    assert [page["url"] for page in result.data["pages"]] == [
        "https://example.com/",
        "https://example.com/about",
        "https://example.com/team",
    ]
    assert http.requests == ["https://example.com/about", "https://example.com/team"]
    assert result.data["robots_skipped_urls"] == ["https://example.com/private"]


@pytest.mark.asyncio
async def test_crawler_is_disabled_without_explicit_opt_in() -> None:
    target = normalize_target("https://example.com")
    http = _FakeHttp({})
    context = ScanContext(target=target, config=ScanConfig(), http=http)  # type: ignore[arg-type]

    result = await CrawlerModule().run(context)

    assert result.data["enabled"] is False
    assert http.requests == []
