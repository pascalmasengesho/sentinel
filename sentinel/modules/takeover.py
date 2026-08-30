"""Passive subdomain-takeover triage from certificate-transparency observations.

This module only performs DNS lookups against names already collected by the
opt-in passive-subdomain module. It never connects to third-party services,
never provisions resources, and never attempts to claim a service. Candidates
require manual, in-scope verification before they mean anything.
"""

from __future__ import annotations

import dns.asyncresolver
import dns.resolver

from sentinel.models import Finding, ModuleResult, Severity
from sentinel.modules.base import ScanContext, ScanModule

_SERVICE_LINKED_SUFFIXES = (
    ".amazonaws.com",
    ".cloudfront.net",
    ".github.io",
    ".github.com",
    ".herokudns.com",
    ".herokuapp.com",
    ".azurewebsites.net",
    ".cloudapp.azure.com",
    ".trafficmanager.net",
    ".azurefd.net",
    ".bitbucket.io",
    ".surge.sh",
    ".fastly.net",
    ".fastlylb.net",
    ".ghost.io",
    ".myshopify.com",
    ".zendesk.com",
    ".helpscoutdocs.com",
    ".pantheon.io",
    ".wordpress.com",
)


class TakeoverModule(ScanModule):
    """Flag DNS patterns that commonly indicate a dormant takeover candidate."""

    name = "takeover"
    _MAX_SUBDOMAINS = 100

    async def run(self, context: ScanContext) -> ModuleResult:
        if not context.config.enable_takeover_check:
            return ModuleResult(
                module=self.name,
                data={
                    "enabled": False,
                    "reason": "Use --takeover-check with --passive-subdomains to enable.",
                },
            )
        raw_subdomains = context.data.get("passive_subdomains", [])
        subdomains = (
            sorted(
                {
                    str(item).strip().lower().rstrip(".")
                    for item in raw_subdomains
                    if str(item).strip()
                }
            )
            if isinstance(raw_subdomains, list)
            else []
        )
        if not subdomains:
            return ModuleResult(
                module=self.name,
                data={
                    "enabled": True,
                    "checked": 0,
                    "candidates": [],
                    "note": "No passive subdomains were available to triage.",
                },
            )
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = context.config.timeout_seconds
        candidates: list[dict[str, str]] = []
        errors: list[str] = []
        for subdomain in subdomains[: self._MAX_SUBDOMAINS]:
            candidate = await self._check_subdomain(resolver, subdomain)
            if candidate:
                candidates.append(candidate)
        findings = [
            Finding(
                title="Potential subdomain takeover candidate",
                severity=Severity.INFO,
                description=(
                    "The observed DNS pattern is commonly associated with dormant subdomain "
                    "takeover risk. Sentinel did not claim or connect to any service; this "
                    "requires manual verification within the program's scope."
                ),
                evidence=(f"{candidate['subdomain']}: {candidate['kind']} — {candidate['reason']}"),
                recommendation=(
                    "Confirm the subdomain is in scope, verify ownership requirements for the "
                    "referenced service, and never provision third-party resources without "
                    "program permission."
                ),
                module=self.name,
                url=f"https://{candidate['subdomain']}",
            )
            for candidate in candidates
        ]
        return ModuleResult(
            module=self.name,
            data={
                "enabled": True,
                "checked": min(len(subdomains), self._MAX_SUBDOMAINS),
                "candidates": candidates,
                "note": (
                    "DNS-only triage. Candidate presence does not prove takeover is possible; "
                    "it only prioritizes manual review."
                ),
            },
            findings=findings,
            errors=errors,
        )

    async def _check_subdomain(
        self, resolver: dns.asyncresolver.Resolver, subdomain: str
    ) -> dict[str, str] | None:
        """Return a takeover candidate dict, or None when DNS looks healthy."""
        try:
            answer = await resolver.resolve(subdomain, "A", raise_on_no_answer=False)
            if list(answer):
                return None
        except dns.resolver.NXDOMAIN:
            return {
                "subdomain": subdomain,
                "kind": "nxdomain",
                "cname": "",
                "reason": (
                    "The subdomain no longer resolves; check whether a service reference "
                    "was abandoned."
                ),
            }
        except dns.resolver.NoAnswer:
            pass
        except Exception as exc:
            return {
                "subdomain": subdomain,
                "kind": "dns_error",
                "cname": "",
                "reason": f"{type(exc).__name__}: {exc}",
            }

        cnames: list[str] = []
        try:
            cname_answer = await resolver.resolve(subdomain, "CNAME", raise_on_no_answer=False)
            cnames = [str(item.target).rstrip(".").lower() for item in cname_answer]
        except dns.resolver.NXDOMAIN:
            return {
                "subdomain": subdomain,
                "kind": "nxdomain",
                "cname": "",
                "reason": (
                    "The subdomain no longer resolves; check whether a service reference "
                    "was abandoned."
                ),
            }
        except dns.resolver.NoAnswer:
            pass
        except Exception as exc:
            return {
                "subdomain": subdomain,
                "kind": "dns_error",
                "cname": "",
                "reason": f"{type(exc).__name__}: {exc}",
            }

        if not cnames:
            return {
                "subdomain": subdomain,
                "kind": "no_record",
                "cname": "",
                "reason": "The subdomain has no A or CNAME records; verify manually.",
            }

        target = cnames[-1]
        if not await self._resolves(resolver, target):
            return {
                "subdomain": subdomain,
                "kind": "dangling_cname",
                "cname": target,
                "reason": (
                    f"The CNAME target '{target}' does not resolve; the reference appears "
                    "abandoned."
                ),
            }
        if self._is_service_linked(target):
            return {
                "subdomain": subdomain,
                "kind": "service_cname",
                "cname": target,
                "reason": (
                    f"CNAME points to third-party service '{target}' without an A record; "
                    "verify ownership manually."
                ),
            }
        return None

    @staticmethod
    def _is_service_linked(cname: str) -> bool:
        return any(
            cname == suffix.lstrip(".") or cname.endswith(suffix)
            for suffix in _SERVICE_LINKED_SUFFIXES
        )

    @staticmethod
    async def _resolves(resolver: dns.asyncresolver.Resolver, hostname: str) -> bool:
        try:
            answer = await resolver.resolve(hostname, "A", raise_on_no_answer=False)
            return bool(list(answer))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False
        except Exception:
            # Transient resolver failures should not look like a dangling CNAME.
            return True
