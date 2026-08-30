from __future__ import annotations

from sentinel.config import ScanConfig
from sentinel.modules.base import ScanContext
from sentinel.modules.email import EmailSecurityModule
from sentinel.target import normalize_target


class _FakeItem:
    def __init__(self, text: str) -> None:
        self.text = text

    def to_text(self) -> str:
        return self.text


class _FakeAnswer:
    def __init__(self, texts: list[str]) -> None:
        self.texts = texts

    def __iter__(self):
        return iter(_FakeItem(text) for text in self.texts)


class _FakeResolver:
    lifetime = 1.0

    def __init__(self, records: dict[tuple[str, str], list[str]]) -> None:
        self.records = records

    async def resolve(self, name: str, rdtype: str, raise_on_no_answer: bool = False):
        return _FakeAnswer(self.records.get((name, rdtype), []))


def _context(enable: bool = True) -> ScanContext:
    return ScanContext(
        target=normalize_target("www.example.com"),
        config=ScanConfig(enable_email_security=enable),
        http=object(),  # type: ignore[arg-type]
    )


async def test_email_security_module_can_be_disabled() -> None:
    result = await EmailSecurityModule().run(_context(enable=False))

    assert result.data["enabled"] is False


def test_email_security_domain_candidates_include_parent_domains() -> None:
    assert EmailSecurityModule._domain_candidates("www.example.com") == [
        "www.example.com",
        "example.com",
    ]
    assert EmailSecurityModule._domain_candidates("example.com") == ["example.com"]


async def test_email_security_reports_missing_spf_and_dmarc(monkeypatch) -> None:
    monkeypatch.setattr(
        "dns.asyncresolver.Resolver",
        lambda: _FakeResolver({}),
    )

    result = await EmailSecurityModule().run(_context())

    titles = {finding.title for finding in result.findings}
    assert "Domain has no published SPF policy" in titles
    assert "Domain has no published DMARC policy" in titles


async def test_email_security_flags_spf_all_and_dmarc_monitoring(monkeypatch) -> None:
    monkeypatch.setattr(
        "dns.asyncresolver.Resolver",
        lambda: _FakeResolver(
            {
                ("example.com", "TXT"): ["v=spf1 +all"],
                ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none"],
            }
        ),
    )

    result = await EmailSecurityModule().run(_context())

    titles = {finding.title for finding in result.findings}
    assert "SPF policy permits any host to send mail" in titles
    assert "DMARC policy is in monitor-only mode" in titles
    assert result.data["dmarc_policy"] == "none"


async def test_email_security_findings_are_empty_for_healthy_policy(monkeypatch) -> None:
    monkeypatch.setattr(
        "dns.asyncresolver.Resolver",
        lambda: _FakeResolver(
            {
                ("example.com", "TXT"): ["v=spf1 include:_spf.example.com -all"],
                ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
            }
        ),
    )

    result = await EmailSecurityModule().run(_context())

    assert result.findings == []
    assert result.data["spf_records"] == ["v=spf1 include:_spf.example.com -all"]
