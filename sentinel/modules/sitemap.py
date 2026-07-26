"""Public sitemap collection with strict same-host and URL-count limits."""

from __future__ import annotations

from urllib.parse import urljoin
from xml.etree import ElementTree

from sentinel.models import ModuleResult
from sentinel.modules.base import ScanContext, ScanModule
from sentinel.target import same_host


class SitemapModule(ScanModule):
    """Enumerate URLs published in public sitemap documents only."""

    name = "sitemap"

    async def run(self, context: ScanContext) -> ModuleResult:
        candidates = [*context.robots_sitemaps, urljoin(context.target.origin + "/", "sitemap.xml")]
        seen_sitemaps: set[str] = set()
        urls: set[str] = set()
        errors: list[str] = []
        while candidates and len(urls) < context.config.max_sitemap_urls:
            sitemap_url = candidates.pop(0)
            if sitemap_url in seen_sitemaps or not same_host(sitemap_url, context.target):
                continue
            seen_sitemaps.add(sitemap_url)
            try:
                response = await context.http.get(sitemap_url)
                if response.status_code != 200:
                    continue
                nested, discovered = self._parse(response.text)
                candidates.extend(url for url in nested if same_host(url, context.target))
                urls.update(url for url in discovered if same_host(url, context.target))
            except Exception as exc:
                errors.append(f"{sitemap_url}: {type(exc).__name__}: {exc}")
        context.sitemap_urls = sorted(urls)[: context.config.max_sitemap_urls]
        return ModuleResult(
            module=self.name,
            data={
                "sitemaps_checked": sorted(seen_sitemaps),
                "url_count": len(context.sitemap_urls),
                "urls": context.sitemap_urls,
            },
            errors=errors,
        )

    @staticmethod
    def _parse(xml_text: str) -> tuple[list[str], list[str]]:
        root = ElementTree.fromstring(xml_text)
        local_name = root.tag.rsplit("}", 1)[-1]
        locations = [
            item.text.strip()
            for item in root.iter()
            if item.tag.rsplit("}", 1)[-1] == "loc" and item.text and item.text.strip()
        ]
        if local_name == "sitemapindex":
            return locations, []
        return [], locations
