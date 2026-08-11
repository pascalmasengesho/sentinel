from __future__ import annotations

from sentinel.config import ScanConfig
from sentinel.http_client import HttpResponse
from sentinel.modules.base import ScanContext
from sentinel.modules.surface import SurfaceModule
from sentinel.target import normalize_target


class DummyHttp:
    pass


async def test_maps_public_surface_without_submitting_forms_or_opening_sockets() -> None:
    context = ScanContext(
        target=normalize_target("example.com"),
        config=ScanConfig(),
        http=DummyHttp(),  # type: ignore[arg-type]
        http_response=HttpResponse(
            url="https://example.com/",
            status_code=200,
            headers={},
            text="""
                <a href="/login">Sign in</a>
                <form action="https://accounts.example.net/sign-in" method="get">
                  <input type="email"><input type="password">
                </form>
                <script>const socket = "wss://example.com/realtime";</script>
                <a href="/graphql">GraphQL</a>
            """,
            http_version="HTTP/2",
            redirect_chain=[],
        ),
    )

    result = await SurfaceModule().run(context)

    assert result.data["authentication_points"] == [
        "https://accounts.example.net/sign-in",
        "https://example.com/login",
    ]
    assert result.data["websocket_candidates"] == ["wss://example.com/realtime"]
    assert result.data["graphql_candidates"] == ["https://example.com/graphql"]
    assert result.data["forms"] == [
        {
            "action": "https://accounts.example.net/sign-in",
            "method": "GET",
            "same_origin": False,
            "has_password": True,
            "input_types": ["email", "password"],
        }
    ]
    titles = {finding.title for finding in result.findings}
    assert "Password form uses the GET method" in titles
    assert "Cross-origin form action observed" in titles
    assert "does not submit forms" in result.data["note"]
