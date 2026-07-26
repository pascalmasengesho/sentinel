"""Same-origin JavaScript collection and passive endpoint/secret-pattern review."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin

from sentinel.models import Finding, ModuleResult, Severity
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


_URL_PATTERN = re.compile(r"https?://[^\s\"'`<>]+|/(?:api|v\d+|graphql)[\w./?=&-]*", re.I)
_SECRET_PATTERNS = {
    "AWS access-key pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Generic API-key assignment": re.compile(
        r"(?:api[_-]?key|secret|token)\s*[:=]\s*[\"'][^\"']{12,}[\"']", re.I
    ),
    "Private-key marker": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}


class JavaScriptModule(ScanModule):
    """Collect public same-origin scripts and redact all secret-like values in output."""

    name = "javascript"

    async def run(self, context: ScanContext) -> ModuleResult:
        response, skipped = response_or_error(context, self.name)
        if skipped:
            return skipped
        assert response is not None
        parser = _ScriptParser()
        parser.feed(response.text)
        sources = [urljoin(response.url, source) for source in parser.sources]
        sources = list(
            dict.fromkeys(source for source in sources if same_host(source, context.target))
        )
        sources = sources[: context.config.max_js_files]
        endpoints: set[str] = set()
        findings: list[Finding] = []
        checked: list[str] = []
        errors: list[str] = []
        for source in sources:
            try:
                script = await context.http.get(source)
                if script.status_code != 200:
                    continue
                checked.append(script.url)
                endpoints.update(_URL_PATTERN.findall(script.text))
                for name, pattern in _SECRET_PATTERNS.items():
                    for match in pattern.finditer(script.text):
                        findings.append(
                            Finding(
                                title=f"Possible hard-coded secret: {name}",
                                severity=Severity.MEDIUM,
                                description=(
                                    "A secret-like pattern appears in a publicly served "
                                    "JavaScript file."
                                ),
                                evidence=(
                                    "Pattern match at character offset "
                                    f"{match.start()}; value redacted."
                                ),
                                recommendation=(
                                    "Verify the value is not live, revoke it if necessary, "
                                    "and move secrets server-side."
                                ),
                                module=self.name,
                                url=script.url,
                            )
                        )
            except Exception as exc:
                errors.append(f"{source}: {type(exc).__name__}: {exc}")
        return ModuleResult(
            module=self.name,
            data={"script_sources": checked, "endpoint_candidates": sorted(endpoints)[:100]},
            findings=findings,
            errors=errors,
        )
