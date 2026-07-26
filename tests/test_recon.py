from __future__ import annotations

from sentinel.config import ScanConfig
from sentinel.modules.base import ScanContext
from sentinel.modules.recon import ReconModule
from sentinel.target import normalize_target


class DummyHttp:
    pass


async def test_recon_skips_whois_for_ip_literal() -> None:
    context = ScanContext(
        target=normalize_target("127.0.0.1", allow_private=True),
        config=ScanConfig(allow_private=True),
        http=DummyHttp(),  # type: ignore[arg-type]
    )

    result = await ReconModule().run(context)

    assert result.data["whois"]["skipped"]
    assert not result.errors
