"""A bounded, same-origin HTML link crawler for authorized assessments."""

from __future__ import annotations

from collections import deque
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

from sentinel.models import ModuleResult
from sentinel.modules.base import ScanContext, ScanModule, response_or_error
from sentinel.target import same_host


class _LinkParser(HTMLParser):
    """Collect navigational links only; forms and subresources are intentionally ignored."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.script_sources: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_name = tag.lower()
        if tag_name == "script":
            source = dict(attrs).get("src")
            if source:
                self.script_sources.append(source)
            return
        if tag_name not in {"a", "area"}:
            return
        href = dict(attrs).get("href")
        if href:
            self.links.append(href)


class CrawlerModule(ScanModule):
    """Follow a small number of public same-host HTML links using GET only.

    The crawler starts from the already-fetched root response, honors every parsed
    ``robots.txt`` Disallow path conservatively, does not send queries, and never
    discovers or submits form actions.
    """

    name = "crawler"

    async def run(self, context: ScanContext) -> ModuleResult:
        if not context.config.enable_safe_crawl:
            return ModuleResult(
                module=self.name,
                data={
                    "enabled": False,
                    "reason": "Use --crawl to enable bounded same-origin GET crawling.",
                },
            )
        root, skipped = response_or_error(context, self.name)
        if skipped:
            return skipped
        assert root is not None

        queue = deque((url, 1) for url in self._links(root.url, root.text, context))
        visited = {self._canonical(root.url)}
        pages = [self._page_data(root.url, root.status_code, 0)]
        script_sources = self._script_sources(root.url, root.text, context)
        blocked_by_robots: list[str] = []
        errors: list[str] = []
        while queue and len(pages) < context.config.max_crawl_pages:
            candidate, depth = queue.popleft()
            canonical = self._canonical(candidate)
            if canonical in visited:
                continue
            visited.add(canonical)
            if self._blocked_by_robots(candidate, context.robots_disallowed):
                blocked_by_robots.append(candidate)
                continue
            try:
                response = await context.http.get(candidate)
            except Exception as exc:
                errors.append(f"{candidate}: {type(exc).__name__}: {exc}")
                continue
            pages.append(self._page_data(response.url, response.status_code, depth))
            script_sources.extend(self._script_sources(response.url, response.text, context))
            if depth >= context.config.max_crawl_depth or response.status_code != 200:
                continue
            for link in self._links(response.url, response.text, context):
                if self._canonical(link) not in visited:
                    queue.append((link, depth + 1))
        collected_scripts = sorted(set(script_sources))[: context.config.max_js_files]
        context.data["crawl_script_sources"] = collected_scripts
        return ModuleResult(
            module=self.name,
            data={
                "enabled": True,
                "method": "GET only; same host; no query strings; no form submission",
                "pages": pages,
                "pages_requested": len(pages),
                "max_pages": context.config.max_crawl_pages,
                "max_depth": context.config.max_crawl_depth,
                "script_sources": collected_scripts,
                "robots_skipped_urls": sorted(set(blocked_by_robots))[:100],
                "queue_limit_reached": bool(queue) and len(pages) >= context.config.max_crawl_pages,
            },
            errors=errors,
        )

    @staticmethod
    def _links(base_url: str, html: str, context: ScanContext) -> list[str]:
        parser = _LinkParser()
        parser.feed(html)
        urls: list[str] = []
        for raw_link in parser.links:
            resolved = urljoin(base_url, raw_link)
            parsed = urlsplit(resolved)
            if (
                parsed.scheme not in {"http", "https"}
                or parsed.query
                or not same_host(resolved, context.target)
                or (context.scope is not None and not context.scope.allows_url(resolved))
            ):
                continue
            urls.append(CrawlerModule._canonical(resolved))
        return list(dict.fromkeys(urls))

    @staticmethod
    def _script_sources(base_url: str, html: str, context: ScanContext) -> list[str]:
        parser = _LinkParser()
        parser.feed(html)
        sources: list[str] = []
        for raw_source in parser.script_sources:
            candidate = CrawlerModule._canonical(urljoin(base_url, raw_source))
            parsed = urlsplit(candidate)
            if (
                parsed.scheme in {"http", "https"}
                and same_host(candidate, context.target)
                and (context.scope is None or context.scope.allows_url(candidate))
            ):
                sources.append(candidate)
        return sources

    @staticmethod
    def _canonical(url: str) -> str:
        parsed = urlsplit(url)
        return urlunsplit(
            (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", "")
        )

    @staticmethod
    def _blocked_by_robots(url: str, rules: list[str]) -> bool:
        """Apply conservative, standards-compliant robots.txt prefix matching.

        ``Disallow: /admin`` blocks every path that starts with ``/admin``,
        including ``/administrator``. Rules containing ``*`` or ``$`` are
        ignored because Sentinel does not implement the full robots grammar.
        """
        path = urlsplit(url).path or "/"
        for rule in rules:
            prefix = rule.strip()
            if not prefix or "*" in prefix or "$" in prefix:
                continue
            if path.startswith(prefix):
                return True
        return False

    @staticmethod
    def _page_data(url: str, status_code: int, depth: int) -> dict[str, str | int]:
        return {"url": url, "status_code": status_code, "depth": depth}
