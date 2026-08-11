"""Passive root-page attack-surface mapping without form submission or authentication."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from sentinel.models import Finding, ModuleResult, Severity
from sentinel.modules.base import ScanContext, ScanModule, response_or_error
from sentinel.target import same_host

_AUTH_PATH_PATTERN = re.compile(r"(?:login|log-in|sign-in|signin|sso|auth|account)", re.I)
_GRAPHQL_PATTERN = re.compile(
    r"https?://[^\s\"'<>]+/graphql[^\s\"'<>]*|/graphql(?:/[\w./?=&-]*)?", re.I
)
_WEBSOCKET_PATTERN = re.compile(r"wss?://[^\s\"'<>]+", re.I)


class _SurfaceParser(HTMLParser):
    """Collect form and authentication metadata while excluding field values."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, object]] = []
        self._active_form: dict[str, object] | None = None
        self.auth_links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag.lower() == "form":
            self._active_form = {
                "action": attributes.get("action", ""),
                "method": str(attributes.get("method") or "get").lower(),
                "input_types": [],
                "has_password": False,
            }
            return
        if tag.lower() == "input" and self._active_form is not None:
            input_type = str(attributes.get("type") or "text").lower()
            input_types = self._active_form["input_types"]
            assert isinstance(input_types, list)
            input_types.append(input_type)
            if input_type == "password":
                self._active_form["has_password"] = True
            return
        if tag.lower() == "a":
            href = attributes.get("href", "")
            if href and _AUTH_PATH_PATTERN.search(href):
                self.auth_links.append(href)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._active_form is not None:
            self.forms.append(self._active_form)
            self._active_form = None


class SurfaceModule(ScanModule):
    """Map public forms, auth entry points, GraphQL, and WebSocket candidates passively."""

    name = "surface"

    async def run(self, context: ScanContext) -> ModuleResult:
        response, skipped = response_or_error(context, self.name)
        if skipped:
            return skipped
        assert response is not None
        parser = _SurfaceParser()
        parser.feed(response.text)
        forms = self._forms(response.url, parser.forms, context)
        auth_points = sorted(
            {
                urljoin(response.url, href)
                for href in parser.auth_links
                if href and urlsplit(urljoin(response.url, href)).scheme in {"http", "https"}
            }
        )
        auth_points.extend(str(form["action"]) for form in forms if bool(form["has_password"]))
        websocket_candidates = sorted(set(_WEBSOCKET_PATTERN.findall(response.text)))[:50]
        graphql_candidates = sorted(
            {
                urljoin(response.url, candidate)
                for candidate in _GRAPHQL_PATTERN.findall(response.text)
            }
        )[:50]
        findings = self._form_findings(response.url, forms)
        return ModuleResult(
            module=self.name,
            data={
                "forms": forms,
                "authentication_points": sorted(set(auth_points))[:50],
                "websocket_candidates": websocket_candidates,
                "graphql_candidates": graphql_candidates,
                "note": (
                    "Collected from the root response only. Sentinel does not submit forms, "
                    "authenticate, connect to WebSockets, or probe GraphQL candidates."
                ),
            },
            findings=findings,
        )

    @staticmethod
    def _forms(
        base_url: str, raw_forms: list[dict[str, object]], context: ScanContext
    ) -> list[dict[str, str | bool | list[str]]]:
        forms: list[dict[str, str | bool | list[str]]] = []
        for raw_form in raw_forms[:50]:
            raw_action = str(raw_form.get("action", ""))
            action = urljoin(base_url, raw_action) if raw_action else base_url
            parsed = urlsplit(action)
            input_types = raw_form.get("input_types", [])
            forms.append(
                {
                    "action": action,
                    "method": str(raw_form.get("method", "get")).upper(),
                    "same_origin": (
                        parsed.scheme in {"http", "https"} and same_host(action, context.target)
                    ),
                    "has_password": bool(raw_form.get("has_password", False)),
                    "input_types": (
                        [str(item) for item in input_types] if isinstance(input_types, list) else []
                    ),
                }
            )
        return forms

    @staticmethod
    def _form_findings(
        root_url: str, forms: list[dict[str, str | bool | list[str]]]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for form in forms:
            action = str(form["action"])
            method = str(form["method"])
            has_password = bool(form["has_password"])
            same_origin = bool(form["same_origin"])
            evidence = f"Form action: {action}; method: {method}; password field: {has_password}"
            if has_password and urlsplit(action).scheme == "http":
                findings.append(
                    Finding(
                        title="Password form posts to an HTTP endpoint",
                        severity=Severity.MEDIUM,
                        description=(
                            "A public form containing a password field references an HTTP action. "
                            "Sentinel did not submit the form."
                        ),
                        evidence=evidence,
                        recommendation=(
                            "Use HTTPS for the form action and enforce HTTPS redirects before "
                            "collecting credentials."
                        ),
                        module=SurfaceModule.name,
                        url=root_url,
                    )
                )
            if has_password and method == "GET":
                findings.append(
                    Finding(
                        title="Password form uses the GET method",
                        severity=Severity.MEDIUM,
                        description=(
                            "A public form containing a password field uses GET, which can expose "
                            "submitted data in URLs or logs. Sentinel did not submit the form."
                        ),
                        evidence=evidence,
                        recommendation=(
                            "Use POST for credential-bearing forms and avoid placing secrets "
                            "in URLs."
                        ),
                        module=SurfaceModule.name,
                        url=root_url,
                    )
                )
            if urlsplit(action).scheme in {"http", "https"} and not same_origin:
                findings.append(
                    Finding(
                        title="Cross-origin form action observed",
                        severity=Severity.INFO,
                        description=(
                            "A public form submits to another origin. This may be intentional, but "
                            "the data-sharing and trust boundary need manual review."
                        ),
                        evidence=evidence,
                        recommendation=(
                            "Document the third-party destination and ensure only intended "
                            "form data is shared with it."
                        ),
                        module=SurfaceModule.name,
                        url=root_url,
                    )
                )
        return findings
