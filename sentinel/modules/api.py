"""Public API endpoint discovery from published links and optional small probes."""

from __future__ import annotations

import re
from urllib.parse import urljoin

from sentinel.models import ModuleResult
from sentinel.modules.base import ScanContext, ScanModule, response_or_error
from sentinel.target import same_host

_API_PATH_PATTERN = re.compile(
    r"(?:/api(?:/|$)|/v\d+(?:/|$)|/graphql(?:/|$)|openapi|swagger)", re.I
)
_PUBLIC_DOC_PATHS = ("/openapi.json", "/swagger.json", "/api-docs", "/graphql")


class ApiDiscoveryModule(ScanModule):
    """Find public API references; probing conventional paths requires explicit opt-in."""

    name = "api_discovery"

    async def run(self, context: ScanContext) -> ModuleResult:
        response, skipped = response_or_error(context, self.name)
        if skipped:
            return skipped
        assert response is not None
        candidates = {url for url in context.sitemap_urls if _API_PATH_PATTERN.search(url)}
        candidates.update(
            urljoin(response.url, path)
            for path in re.findall(r"(?:href|src)=[\"']([^\"']+)[\"']", response.text, flags=re.I)
            if _API_PATH_PATTERN.search(path)
        )
        candidates = {url for url in candidates if same_host(url, context.target)}
        discovered: list[dict[str, str | int]] = []
        if context.config.enable_public_api_probe:
            for path in _PUBLIC_DOC_PATHS:
                url = urljoin(context.target.origin + "/", path.lstrip("/"))
                try:
                    probe = await context.http.get(url)
                except Exception:
                    continue
                if probe.status_code in {200, 401, 403}:
                    candidates.add(probe.url)
                    discovered.append({"url": probe.url, "status_code": probe.status_code})
        return ModuleResult(
            module=self.name,
            data={
                "public_endpoint_candidates": sorted(candidates),
                "probed_public_docs": discovered,
                "active_public_doc_probe_enabled": context.config.enable_public_api_probe,
            },
        )
