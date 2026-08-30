from __future__ import annotations

import httpx
import pytest

from sentinel.config import ScanConfig
from sentinel.http_client import RequestBlockedError, SafeHttpClient
from sentinel.scope import ScopeManifest
from sentinel.target import normalize_target


class _FakeTransportClient:
    def __init__(self, responses: list[httpx.Response]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    async def request(self, method: str, url: str) -> httpx.Response:
        self.calls.append(url)
        return self.responses.pop(0)

    async def aclose(self) -> None:
        pass


def _client(scope: ScopeManifest | None = None) -> SafeHttpClient:
    return SafeHttpClient(
        target=normalize_target("https://example.com"),
        config=ScanConfig(rate_limit_per_second=10.0),
        scope=scope,
    )


def test_validate_url_blocks_foreign_hosts_and_scope_exclusions(monkeypatch) -> None:
    monkeypatch.setattr("sentinel.http_client.is_safe_public_host", lambda *a, **k: True)
    scope = ScopeManifest(
        name="Example",
        allowed_hosts=("example.com",),
        excluded_paths=("/admin",),
        rate_limit_per_second=1.0,
    )
    client = _client(scope)

    with pytest.raises(RequestBlockedError, match="out-of-scope"):
        client._validate_url("https://api.example.com/")
    with pytest.raises(RequestBlockedError, match="scope manifest"):
        client._validate_url("https://example.com/admin/users")


def test_validate_url_blocks_private_addresses(monkeypatch) -> None:
    monkeypatch.setattr("sentinel.http_client.is_safe_public_host", lambda *a, **k: False)
    client = _client()

    with pytest.raises(RequestBlockedError, match="private"):
        client._validate_url("https://example.com/")


async def test_request_follows_same_host_redirects(monkeypatch) -> None:
    monkeypatch.setattr("sentinel.http_client.is_safe_public_host", lambda *a, **k: True)
    client = _client()
    transport = _FakeTransportClient(
        [
            httpx.Response(
                302,
                headers={"location": "/final"},
                request=httpx.Request("GET", "https://example.com/start"),
            ),
            httpx.Response(
                200,
                headers={"content-type": "text/html"},
                request=httpx.Request("GET", "https://example.com/final"),
            ),
        ]
    )
    monkeypatch.setattr(client, "_client", transport)

    response = await client.get("https://example.com/start")

    assert response.status_code == 200
    assert response.url == "https://example.com/final"
    assert response.redirect_chain == ["https://example.com/start"]
    assert transport.calls == ["https://example.com/start", "https://example.com/final"]


async def test_request_raises_after_the_redirect_limit(monkeypatch) -> None:
    monkeypatch.setattr("sentinel.http_client.is_safe_public_host", lambda *a, **k: True)
    client = SafeHttpClient(
        target=normalize_target("https://example.com"),
        config=ScanConfig(rate_limit_per_second=10.0, max_redirects=1),
    )
    transport = _FakeTransportClient(
        [
            httpx.Response(
                302,
                headers={"location": "/one"},
                request=httpx.Request("GET", "https://example.com/start"),
            ),
            httpx.Response(
                302,
                headers={"location": "/two"},
                request=httpx.Request("GET", "https://example.com/one"),
            ),
        ]
    )
    monkeypatch.setattr(client, "_client", transport)

    with pytest.raises(httpx.TooManyRedirects):
        await client.get("https://example.com/start")
