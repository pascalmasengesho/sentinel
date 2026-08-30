"""Passive subdomain, WHOIS, CDN, WAF, and hosting hints."""

from __future__ import annotations

import asyncio
import ipaddress
import json
from typing import Any
from urllib.parse import quote

import httpx

from sentinel.models import ModuleResult
from sentinel.modules.base import ScanContext, ScanModule

_CDN_MARKERS = {
    "cloudflare": ("cf-ray", "cloudflare"),
    "fastly": ("x-served-by", "fastly"),
    "akamai": ("akamai", "akamaighost"),
    "amazon cloudfront": ("cloudfront",),
}
_WAF_MARKERS = {
    "cloudflare": ("cf-ray", "__cf_bm"),
    "aws waf": ("awswaf",),
    "sucuri": ("x-sucuri",),
    "imperva": ("incap_ses", "visid_incap"),
}


class ReconModule(ScanModule):
    """Collect only passive metadata and response/header-derived platform hints."""

    name = "recon"

    async def run(self, context: ScanContext) -> ModuleResult:
        data: dict[str, Any] = {
            "passive_subdomains": [],
            "whois": {},
            "cdn": [],
            "waf": [],
            "hosting_hints": [],
        }
        errors: list[str] = []
        if context.config.enable_passive_subdomains:
            try:
                data["passive_subdomains"] = await self._crtsh(
                    context.target.host, context.config.timeout_seconds, context.config.user_agent
                )
                context.data["passive_subdomains"] = data["passive_subdomains"]
            except Exception as exc:
                errors.append(f"crt.sh: {type(exc).__name__}: {exc}")
        if self._is_ip_literal(context.target.host):
            data["whois"] = {"skipped": "WHOIS collection applies to DNS names, not IP literals."}
        elif not context.config.enable_whois:
            data["whois"] = {"skipped": "WHOIS lookup is opt-in; enable it with --whois."}
        else:
            try:
                data["whois"] = await asyncio.to_thread(self._whois, context.target.host)
            except Exception as exc:
                errors.append(f"WHOIS: {type(exc).__name__}: {exc}")

        if context.http_response:
            blob = "\n".join(
                f"{key}: {value}" for key, value in context.http_response.headers.items()
            ).lower()
            data["cdn"] = self._match_markers(blob, _CDN_MARKERS)
            data["waf"] = self._match_markers(blob, _WAF_MARKERS)
            server = context.http_response.headers.get("server", "")
            if server:
                data["hosting_hints"].append(f"Server header: {server}")
        return ModuleResult(module=self.name, data=data, errors=errors)

    @staticmethod
    async def _crtsh(host: str, timeout_seconds: float, user_agent: str) -> list[str]:
        """Query crt.sh, a public certificate-transparency index, with a small result cap."""
        url = f"https://crt.sh/?q={quote('%.' + host)}&output=json"
        async with httpx.AsyncClient(
            timeout=timeout_seconds, headers={"User-Agent": user_agent}
        ) as client:
            response = await client.get(url)
            response.raise_for_status()
        entries = json.loads(response.text)
        values = {
            candidate.strip().lower()
            for entry in entries[:500]
            for candidate in str(entry.get("name_value", "")).splitlines()
            if candidate.strip().lower().endswith(host.lower()) and "*" not in candidate
        }
        return sorted(values)[:100]

    @staticmethod
    def _whois(host: str) -> dict[str, str]:
        """Return a deliberately small, report-safe subset of public WHOIS metadata."""
        import whois  # Imported lazily so the rest of Sentinel works without it.

        record = whois.whois(host)
        result: dict[str, str] = {}
        for key in ("registrar", "creation_date", "expiration_date", "name_servers"):
            value = getattr(record, key, None)
            if value:
                result[key] = str(value)
        return result

    @staticmethod
    def _match_markers(blob: str, marker_sets: dict[str, tuple[str, ...]]) -> list[str]:
        return [
            name
            for name, markers in marker_sets.items()
            if any(marker in blob for marker in markers)
        ]

    @staticmethod
    def _is_ip_literal(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return False
        return True
