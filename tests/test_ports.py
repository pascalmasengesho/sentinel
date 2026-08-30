from __future__ import annotations

from sentinel.config import ScanConfig
from sentinel.http_client import HttpResponse
from sentinel.modules.base import ScanContext
from sentinel.modules.ports import PortModule
from sentinel.target import normalize_target


def _context(config: ScanConfig) -> ScanContext:
    return ScanContext(
        target=normalize_target("example.com"),
        config=config,
        http=object(),  # type: ignore[arg-type]
        http_response=HttpResponse(
            url="https://example.com/",
            status_code=200,
            headers={},
            text="",
            http_version="HTTP/2",
            redirect_chain=[],
        ),
    )


async def test_port_module_is_skipped_when_disabled() -> None:
    result = await PortModule().run(_context(ScanConfig(enable_port_scan=False)))

    assert result.data == {"enabled": False}
