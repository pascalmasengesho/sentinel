"""Bounded DNS collection and wildcard-DNS detection."""

from __future__ import annotations

import secrets

import dns.asyncresolver
import dns.flags
import dns.resolver

from sentinel.models import ModuleResult
from sentinel.modules.base import ScanContext, ScanModule


class DnsModule(ScanModule):
    """Resolve common record types without performing zone transfer attempts."""

    name = "dns"
    _record_types = ("A", "AAAA", "MX", "TXT", "NS", "CNAME")

    async def run(self, context: ScanContext) -> ModuleResult:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = context.config.timeout_seconds
        records: dict[str, list[str]] = {}
        errors: list[str] = []
        dnssec_validated = False
        for record_type in self._record_types:
            try:
                answer = await resolver.resolve(
                    context.target.host, record_type, raise_on_no_answer=False
                )
                records[record_type] = [item.to_text() for item in answer]
                if answer.response is not None:
                    dnssec_validated = dnssec_validated or bool(
                        answer.response.flags & dns.flags.AD
                    )
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                records[record_type] = []
            except Exception as exc:
                errors.append(f"{record_type}: {type(exc).__name__}: {exc}")

        wildcard = await self._detect_wildcard(resolver, context.target.host)
        return ModuleResult(
            module=self.name,
            data={
                "records": records,
                "wildcard_dns": wildcard,
                "dnssec_ad_flag": dnssec_validated,
                "note": (
                    "The AD flag is resolver-provided and is not an independent "
                    "DNSSEC validation."
                ),
            },
            errors=errors,
        )

    async def _detect_wildcard(self, resolver: dns.asyncresolver.Resolver, host: str) -> bool:
        random_label = secrets.token_hex(10)
        candidate = f"{random_label}.{host}"
        for record_type in ("A", "AAAA"):
            try:
                answer = await resolver.resolve(candidate, record_type, raise_on_no_answer=False)
                if list(answer):
                    return True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except Exception:
                continue
        return False
