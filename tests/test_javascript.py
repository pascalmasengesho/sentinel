from __future__ import annotations

from sentinel.config import ScanConfig
from sentinel.http_client import HttpResponse
from sentinel.modules.base import ScanContext
from sentinel.modules.javascript import JavaScriptModule
from sentinel.target import normalize_target


class FakeHttp:
    async def get(self, url: str) -> HttpResponse:
        if url.endswith("jquery.min.js"):
            text = "/*! jQuery v3.7.1 */"
        else:
            text = """
            const route = '/api/v2/internal/users?debug=true&test_env=staging';
            const bucket = 'https://assets-private.s3.us-east-1.amazonaws.com/build.js';
            const headers = {'X-Internal-Client': 'browser', 'X-Requested-With': 'XMLHttpRequest'};
            request.setRequestHeader('X-Service-Version', '2');
            const database = 'postgres://user:secret@db.example.test:5432/app';
            """
        return HttpResponse(
            url=url,
            status_code=200,
            headers={},
            text=text,
            http_version="HTTP/2",
            redirect_chain=[],
        )


async def test_javascript_maps_high_signal_structures_with_source_provenance() -> None:
    context = ScanContext(
        target=normalize_target("example.com"),
        config=ScanConfig(),
        http=FakeHttp(),  # type: ignore[arg-type]
        http_response=HttpResponse(
            url="https://example.com/",
            status_code=200,
            headers={},
            text=(
                '<script src="/app.js"></script><script src="/jquery.min.js"></script>'
                '<script src="https://cdn.example.net/lib.js"></script>'
            ),
            http_version="HTTP/2",
            redirect_chain=[],
        ),
    )

    result = await JavaScriptModule().run(context)

    assert result.findings == []
    assert result.data["script_sources"] == ["https://example.com/app.js"]
    assert result.data["vendor_frameworks_skipped"] == ["https://example.com/jquery.min.js"]
    assert result.data["routing_candidates"] == [
        {
            "script": "https://example.com/app.js",
            "path": "/api/v2/internal/users",
            "category": "internal route candidate",
        }
    ]
    assert result.data["query_parameter_candidates"] == [
        {
            "script": "https://example.com/app.js",
            "path": "/api/v2/internal/users",
            "parameter": "debug",
            "value_hint": "true",
        },
        {
            "script": "https://example.com/app.js",
            "path": "/api/v2/internal/users",
            "parameter": "test_env",
            "value_hint": "staging",
        },
    ]
    assert result.data["cloud_asset_candidates"] == [
        {
            "script": "https://example.com/app.js",
            "kind": "S3 bucket reference",
            "bucket": "assets-private",
        }
    ]
    assert result.data["custom_header_candidates"] == [
        {"script": "https://example.com/app.js", "header": "x-internal-client"},
        {"script": "https://example.com/app.js", "header": "x-service-version"},
    ]
    assert result.data["redacted_connection_string_markers"][0]["value"] == "<redacted>"
    assert "user:secret" not in str(result.data)
