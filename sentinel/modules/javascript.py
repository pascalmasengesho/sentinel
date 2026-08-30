"""High-signal static triage of public proprietary JavaScript bundles."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit

from sentinel.models import ModuleResult
from sentinel.modules.base import ScanContext, ScanModule, response_or_error
from sentinel.target import same_host


class _ScriptParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.sources: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "script":
            return
        attributes = dict(attrs)
        source = attributes.get("src")
        if source:
            self.sources.append(source)


_ROUTE_LITERAL_PATTERN = re.compile(
    r"""(?P<quote>[\"'`])
        (?P<path>/(?:api(?:/v\d+)?|v\d+|graphql|internal|admin|private|debug|test|auth|oauth|account|accounts|billing|settings|users|projects|organizations)
        [A-Za-z0-9._~!$&'()*+,;=:@%{}\-/]*)
        (?:\?(?P<query>[^\"'`\\\s#]{0,240}))?
        (?P=quote)""",
    re.IGNORECASE | re.VERBOSE,
)
_S3_BUCKET_PATTERN = re.compile(
    r"""(?:s3://(?P<scheme_bucket>[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])(?:/|$)
        |https?://(?P<host_bucket>[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])
        \.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com)""",
    re.IGNORECASE | re.VERBOSE,
)
_CUSTOM_HEADER_PATTERN = re.compile(
    r"""(?:(?:[\"'])(?P<object_header>x-[a-z][a-z0-9-]{1,80})(?:[\"'])\s*:
        |(?:setRequestHeader|headers\.set)\s*\(\s*(?:[\"'])(?P<call_header>x-[a-z][a-z0-9-]{1,80})(?:[\"']))""",
    re.IGNORECASE | re.VERBOSE,
)
_DATABASE_DSN_PATTERN = re.compile(
    r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s\"'`<>]{1,240}", re.IGNORECASE
)
_VENDOR_BASENAME_PATTERN = re.compile(
    r"(?:^|[._-])(?:jquery|bootstrap|react-dom|react\.production|angular(?:\.min)?|vue\.global|lodash|moment|polyfill)(?:[._-]|$)",
    re.IGNORECASE,
)
_VENDOR_BANNER_PATTERN = re.compile(
    r"(?:jQuery v\d|Bootstrap v\d|ReactDOM(?:\.production)?\.min|lodash v\d|Moment\.js)",
    re.IGNORECASE,
)
_INTERNAL_ROUTE_MARKERS = re.compile(
    r"/(?:internal|admin|private|debug|test)(?:/|$)", re.IGNORECASE
)
_INTERESTING_QUERY_PARAMETERS = {
    "debug",
    "env",
    "environment",
    "feature",
    "mode",
    "preview",
    "test",
    "test_env",
    "trace",
    "verbose",
}
_INTERNAL_HEADER_MARKERS = (
    "api",
    "client",
    "debug",
    "environment",
    "feature",
    "gateway",
    "internal",
    "service",
    "tenant",
    "version",
)
_STANDARD_X_HEADERS = {
    "x-csrf-token",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-requested-with",
}


class JavaScriptModule(ScanModule):
    """Map routes and infrastructure references without extracting token values.

    The module deliberately avoids generic secret regexes. It maps structural
    references with provenance, redacts connection-string content, and ignores
    common third-party framework files to keep triage signal high.
    """

    name = "javascript"

    async def run(self, context: ScanContext) -> ModuleResult:
        response, skipped = response_or_error(context, self.name)
        if skipped:
            return skipped
        assert response is not None
        parser = _ScriptParser()
        parser.feed(response.text)
        sources = [urljoin(response.url, source) for source in parser.sources]
        crawled_sources = context.data.get("crawl_script_sources", [])
        if isinstance(crawled_sources, list):
            sources.extend(str(source) for source in crawled_sources)
        sources = list(
            dict.fromkeys(source for source in sources if same_host(source, context.target))
        )
        routes: list[dict[str, str]] = []
        query_parameters: list[dict[str, str]] = []
        cloud_assets: list[dict[str, str]] = []
        headers: list[dict[str, str]] = []
        connection_markers: list[dict[str, str | int]] = []
        checked: list[str] = []
        skipped_vendor: list[str] = []
        errors: list[str] = []
        downloaded = 0
        for source in sources:
            if self._is_vendor_basename(source):
                skipped_vendor.append(source)
                continue
            if downloaded >= context.config.max_js_files:
                break
            try:
                script = await context.http.get(source)
            except Exception as exc:
                errors.append(f"{source}: {type(exc).__name__}: {exc}")
                continue
            downloaded += 1
            if script.status_code != 200:
                continue
            if self._is_vendor_banner(script.text):
                skipped_vendor.append(script.url)
                continue
            checked.append(script.url)
            script_routes, script_queries = self._routes(script.url, script.text)
            routes.extend(script_routes)
            query_parameters.extend(script_queries)
            cloud_assets.extend(self._cloud_assets(script.url, script.text))
            headers.extend(self._custom_headers(script.url, script.text))
            connection_markers.extend(self._connection_markers(script.url, script.text))
        return ModuleResult(
            module=self.name,
            data={
                "script_sources": sorted(set(checked)),
                "vendor_frameworks_skipped": sorted(set(skipped_vendor)),
                "routing_candidates": _deduplicate(routes)[:200],
                "query_parameter_candidates": _deduplicate(query_parameters)[:200],
                "cloud_asset_candidates": _deduplicate(cloud_assets)[:100],
                "custom_header_candidates": _deduplicate(headers)[:100],
                "redacted_connection_string_markers": _deduplicate(connection_markers)[:50],
                "endpoint_candidates": sorted({item["path"] for item in routes})[:200],
                "note": (
                    "Static structural mapping only. Sentinel does not extract API-token values, "
                    "attempt credentials, access cloud buckets, or send custom headers."
                ),
            },
            errors=errors,
        )

    @staticmethod
    def _is_vendor_basename(url: str) -> bool:
        basename = urlsplit(url).path.rsplit("/", 1)[-1]
        return bool(_VENDOR_BASENAME_PATTERN.search(basename))

    @staticmethod
    def _is_vendor_banner(script: str) -> bool:
        return bool(_VENDOR_BANNER_PATTERN.search(script[:2_000]))

    @staticmethod
    def _routes(script_url: str, script: str) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
        routes: list[dict[str, str]] = []
        parameters: list[dict[str, str]] = []
        for match in _ROUTE_LITERAL_PATTERN.finditer(script):
            path = match.group("path")
            category = (
                "internal route candidate" if _INTERNAL_ROUTE_MARKERS.search(path) else "route"
            )
            routes.append({"script": script_url, "path": path, "category": category})
            query = match.group("query")
            if not query:
                continue
            for name, value in parse_qsl(query, keep_blank_values=True):
                normalized_name = name.strip().lower()
                if normalized_name not in _INTERESTING_QUERY_PARAMETERS:
                    continue
                parameters.append(
                    {
                        "script": script_url,
                        "path": path,
                        "parameter": normalized_name,
                        "value_hint": value[:80] if value else "<empty>",
                    }
                )
        return routes, parameters

    @staticmethod
    def _cloud_assets(script_url: str, script: str) -> list[dict[str, str]]:
        return [
            {
                "script": script_url,
                "kind": "S3 bucket reference",
                "bucket": match.group("scheme_bucket") or match.group("host_bucket"),
            }
            for match in _S3_BUCKET_PATTERN.finditer(script)
        ]

    @staticmethod
    def _custom_headers(script_url: str, script: str) -> list[dict[str, str]]:
        results: list[dict[str, str]] = []
        for match in _CUSTOM_HEADER_PATTERN.finditer(script):
            header = (match.group("object_header") or match.group("call_header")).lower()
            if header in _STANDARD_X_HEADERS or not any(
                marker in header for marker in _INTERNAL_HEADER_MARKERS
            ):
                continue
            results.append({"script": script_url, "header": header})
        return results

    @staticmethod
    def _connection_markers(script_url: str, script: str) -> list[dict[str, str | int]]:
        return [
            {
                "script": script_url,
                "kind": "database connection-string pattern",
                "offset": match.start(),
                "value": "<redacted>",
            }
            for match in _DATABASE_DSN_PATTERN.finditer(script)
        ]


def _deduplicate[Value](items: list[dict[str, Value]]) -> list[dict[str, Value]]:
    """Return stable mapping records, deduplicated across bundles without losing provenance."""
    unique: dict[tuple[tuple[str, str], ...], dict[str, Value]] = {}
    for item in items:
        key = tuple(sorted((str(name), str(value)) for name, value in item.items()))
        unique[key] = item
    return [unique[key] for key in sorted(unique)]
