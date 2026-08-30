from __future__ import annotations

import dns.resolver

from sentinel.config import ScanConfig
from sentinel.modules.base import ScanContext
from sentinel.modules.takeover import TakeoverModule
from sentinel.target import normalize_target


class _FakeItem:
    def __init__(self, text: str) -> None:
        self.text = text
        self.target = text

    def to_text(self) -> str:
        return self.text


class _FakeAnswer:
    def __init__(self, texts: list[str]) -> None:
        self.texts = texts

    def __iter__(self):
        return iter(_FakeItem(text) for text in self.texts)


class _FakeResolver:
    lifetime = 1.0

    def __init__(
        self,
        records: dict[tuple[str, str], list[str]],
        failures: dict[tuple[str, str], Exception] | None = None,
    ) -> None:
        self.records = records
        self.failures = failures or {}

    async def resolve(self, name: str, rdtype: str, raise_on_no_answer: bool = False):
        key = (name, rdtype)
        if key in self.failures:
            raise self.failures[key]
        return _FakeAnswer(self.records.get(key, []))


def _context(enabled: bool = True, subdomains: list[str] | None = None) -> ScanContext:
    context = ScanContext(
        target=normalize_target("example.com"),
        config=ScanConfig(enable_takeover_check=enabled),
        http=object(),  # type: ignore[arg-type]
    )
    if subdomains is not None:
        context.data["passive_subdomains"] = subdomains
    return context


async def test_takeover_module_is_disabled_without_opt_in() -> None:
    result = await TakeoverModule().run(_context(enabled=False))

    assert result.data["enabled"] is False


async def test_takeover_module_skips_when_no_subdomains_are_available() -> None:
    result = await TakeoverModule().run(_context(subdomains=[]))

    assert result.data["checked"] == 0
    assert result.data["candidates"] == []


async def test_takeover_module_flags_nxdomain_and_dangling_cname(monkeypatch) -> None:
    resolver = _FakeResolver(
        records={
            ("sub.example.com", "A"): [],
            ("sub.example.com", "CNAME"): ["target.example.com."],
            ("dangling.example.com", "A"): [],
            ("dangling.example.com", "CNAME"): ["gone.s3.amazonaws.com."],
        },
        failures={
            ("missing.example.com", "A"): dns.resolver.NXDOMAIN(),
            ("gone.s3.amazonaws.com", "A"): dns.resolver.NXDOMAIN(),
        },
    )
    monkeypatch.setattr("dns.asyncresolver.Resolver", lambda: resolver)

    result = await TakeoverModule().run(
        _context(subdomains=["dangling.example.com", "missing.example.com", "sub.example.com"])
    )

    kinds = {candidate["kind"] for candidate in result.data["candidates"]}
    assert "nxdomain" in kinds
    assert "dangling_cname" in kinds
    assert result.data["candidates"][0]["subdomain"] == "dangling.example.com"
    assert all(finding.severity == "info" for finding in result.findings)


async def test_takeover_module_ignores_healthy_resolving_subdomains(monkeypatch) -> None:
    monkeypatch.setattr(
        "dns.asyncresolver.Resolver",
        lambda: _FakeResolver({("live.example.com", "A"): ["192.0.2.10"]}),
    )

    result = await TakeoverModule().run(_context(subdomains=["live.example.com"]))

    assert result.data["candidates"] == []
    assert result.findings == []
