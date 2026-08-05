"""Tests for opt-in public artifact collection."""

from __future__ import annotations

from sentinel.config import ScanConfig
from sentinel.http_client import HttpResponse
from sentinel.modules.artifacts import PublicArtifactModule
from sentinel.modules.base import ScanContext
from sentinel.target import normalize_target


class FakeHttp:
    """Return small, public artifacts without network access."""

    async def get(self, url: str) -> HttpResponse:
        if url.endswith("favicon.ico"):
            return HttpResponse(
                url=url,
                status_code=200,
                headers={"content-type": "image/x-icon"},
                text="",
                content=b"favicon-bytes",
                http_version="HTTP/2",
                redirect_chain=[],
            )
        return HttpResponse(
            url=url,
            status_code=200,
            headers={"content-type": "text/plain"},
            text="Contact: mailto:security@example.com\nPolicy: https://example.com/policy\n",
            http_version="HTTP/2",
            redirect_chain=[],
        )


async def test_collects_favicon_hash_and_published_security_metadata() -> None:
    context = ScanContext(
        target=normalize_target("example.com"),
        config=ScanConfig(enable_public_artifact_checks=True),
        http=FakeHttp(),  # type: ignore[arg-type]
    )

    result = await PublicArtifactModule().run(context)

    artifacts = result.data["public_artifacts"]
    assert artifacts["favicon"]["sha256"] == (
        "b8efe6a7938823a19b28b06ada2f4901b79a7f254861a5cf3d79543b5c95be13"
    )
    assert artifacts["favicon"]["bytes"] == 13
    assert artifacts["well_known_security_txt"]["fields"]["contact"] == [
        "mailto:security@example.com"
    ]
