from __future__ import annotations

import httpx
import pytest

from sentinel.asset_probe import AssetObservation, AssetProbeEngine
from sentinel.asset_state import AssetStateStore
from sentinel.config import ScanConfig
from sentinel.scope import ScopeManifest


def _scope() -> ScopeManifest:
    return ScopeManifest(
        name="Example program",
        allowed_hosts=("*.example.com",),
        targets=("https://one.example.com", "https://two.example.com"),
        rate_limit_per_second=10.0,
    )


@pytest.mark.asyncio
async def test_asset_probe_is_concurrent_scope_limited_and_header_only() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "one.example.com":
            return httpx.Response(
                200,
                headers={"content-length": "42", "server": "nginx", "cf-ray": "sample"},
                request=request,
            )
        return httpx.Response(503, headers={"content-length": "0"}, request=request)

    observations, failures = await AssetProbeEngine(
        _scope(),
        ScanConfig(concurrency=2, rate_limit_per_second=10.0),
        httpx.MockTransport(handler),
    ).probe()

    assert failures == []
    assert [(item.target, item.status_code, item.content_length) for item in observations] == [
        ("https://one.example.com/", 200, 42),
        ("https://two.example.com/", 503, 0),
    ]
    assert observations[0].technologies == ("server: nginx", "edge: Cloudflare")


def test_asset_state_returns_only_new_status_or_size_deltas(tmp_path) -> None:
    store = AssetStateStore(tmp_path / "assets.db")
    first = AssetObservation("https://app.example.com/", 200, 100, ("server: nginx",))
    same = AssetObservation("https://app.example.com/", 200, 100, ("server: nginx",))
    changed = AssetObservation("https://app.example.com/", 403, 120, ("server: nginx",))

    initial = store.record("Example", [first])
    no_change = store.record("Example", [same])
    delta = store.record("Example", [changed])

    assert initial[0].changes == ("new",)
    assert no_change == []
    assert delta[0].changes == ("status changed", "content length changed")
    assert delta[0].previous_status_code == 200
    assert delta[0].previous_content_length == 100
