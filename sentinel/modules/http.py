"""Root HTTP response collection and low-impact protocol observations."""

from __future__ import annotations

from urllib.parse import urlsplit

from sentinel.http_client import HttpResponse
from sentinel.models import Finding, ModuleResult, Severity
from sentinel.modules.base import ScanContext, ScanModule


class HttpModule(ScanModule):
    """Fetch the selected URL and inspect response metadata and advertised methods."""

    name = "http"
    _RISKY_ADVERTISED_METHODS = {"CONNECT", "DELETE", "PATCH", "PUT", "TRACE"}

    async def run(self, context: ScanContext) -> ModuleResult:
        response = await context.http.get(context.target.url)
        context.http_response = response
        options_allow = ""
        options_error = ""
        try:
            options = await context.http.options(response.url)
            options_allow = options.headers.get("allow", "")
        except Exception as exc:
            options_error = f"OPTIONS unavailable: {type(exc).__name__}: {exc}"

        cookies = self._cookies(response)
        cookie_names = [cookie["name"] for cookie in cookies]
        data = {
            "url": response.url,
            "status_code": response.status_code,
            "http_version": response.http_version,
            "redirect_chain": response.redirect_chain,
            "server": response.headers.get("server", ""),
            "content_type": response.headers.get("content-type", ""),
            "content_encoding": response.headers.get("content-encoding", ""),
            "cache_control": response.headers.get("cache-control", ""),
            "advertised_methods": options_allow,
            "cookie_names": cookie_names,
            "cookies": cookies,
        }
        findings: list[Finding] = []
        if response.url.startswith("http://"):
            findings.append(
                Finding(
                    title="HTTP endpoint used without transport encryption",
                    severity=Severity.LOW,
                    description="The final root response was served over HTTP rather than HTTPS.",
                    evidence=response.url,
                    recommendation=(
                        "Use HTTPS and redirect HTTP traffic to the canonical HTTPS " "endpoint."
                    ),
                    module=self.name,
                    url=response.url,
                )
            )
        advertised = {
            method.strip().upper() for method in options_allow.split(",") if method.strip()
        }
        risky_methods = sorted(advertised & self._RISKY_ADVERTISED_METHODS)
        if risky_methods:
            findings.append(
                Finding(
                    title="Potentially state-changing HTTP methods advertised",
                    severity=Severity.LOW,
                    description=(
                        "The root endpoint advertises methods that may require careful "
                        "access-control review. Sentinel did not send any of these methods."
                    ),
                    evidence=f"Allow: {options_allow}",
                    recommendation=(
                        "Confirm each advertised method is necessary and enforces authentication, "
                        "authorization, CSRF protections, and safe error handling."
                    ),
                    module=self.name,
                    url=response.url,
                )
            )
        findings.extend(self._cookie_findings(response.url, cookies))
        errors = [options_error] if options_error else []
        return ModuleResult(module=self.name, data=data, findings=findings, errors=errors)

    @staticmethod
    def _cookies(response: HttpResponse) -> list[dict[str, str | bool]]:
        """Parse cookie attribute metadata without retaining cookie values."""
        raw_headers = response.set_cookie_headers or [response.headers.get("set-cookie", "")]
        cookies: list[dict[str, str | bool]] = []
        for raw_header in raw_headers:
            parts = [part.strip() for part in raw_header.split(";") if part.strip()]
            if not parts or "=" not in parts[0]:
                continue
            name = parts[0].split("=", 1)[0].strip()
            if not name:
                continue
            attributes: dict[str, str] = {}
            for part in parts[1:]:
                key, _, value = part.partition("=")
                attributes[key.lower().strip()] = value.strip()
            cookies.append(
                {
                    "name": name,
                    "secure": "secure" in attributes,
                    "httponly": "httponly" in attributes,
                    "samesite": attributes.get("samesite", ""),
                    "path": attributes.get("path", ""),
                    "domain": attributes.get("domain", ""),
                }
            )
        return cookies

    @staticmethod
    def _cookie_findings(url: str, cookies: list[dict[str, str | bool]]) -> list[Finding]:
        """Create hardening observations from passive cookie attributes only."""
        findings: list[Finding] = []
        is_https = urlsplit(url).scheme == "https"
        for cookie in cookies:
            name = str(cookie["name"])
            evidence = f"Set-Cookie: {name}=<redacted>"
            if is_https and not bool(cookie["secure"]):
                findings.append(
                    Finding(
                        title="Cookie missing Secure attribute",
                        severity=Severity.LOW,
                        description=(
                            "A cookie set on an HTTPS response does not declare the Secure "
                            "attribute."
                        ),
                        evidence=evidence,
                        recommendation="Set Secure on cookies that should never be sent over HTTP.",
                        module=HttpModule.name,
                        url=url,
                    )
                )
            if _looks_session_related(name) and not bool(cookie["httponly"]):
                findings.append(
                    Finding(
                        title="Session-like cookie missing HttpOnly attribute",
                        severity=Severity.LOW,
                        description=(
                            "A cookie with a session-like name is readable by browser scripts "
                            "because it lacks HttpOnly. Its sensitivity requires manual "
                            "confirmation."
                        ),
                        evidence=evidence,
                        recommendation=(
                            "Use HttpOnly for server-managed session cookies unless client-side "
                            "script access is an explicit, reviewed requirement."
                        ),
                        module=HttpModule.name,
                        url=url,
                    )
                )
            if not str(cookie["samesite"]):
                findings.append(
                    Finding(
                        title="Cookie has no explicit SameSite attribute",
                        severity=Severity.INFO,
                        description=(
                            "The cookie relies on browser default SameSite behavior, which can "
                            "vary by context and browser version."
                        ),
                        evidence=evidence,
                        recommendation=(
                            "Set an explicit SameSite value after confirming the application's "
                            "cross-site flows and CSRF requirements."
                        ),
                        module=HttpModule.name,
                        url=url,
                    )
                )
        return findings


def _looks_session_related(name: str) -> bool:
    """Return whether a cookie name deserves manual session-hardening review."""
    lowered = name.lower()
    return any(marker in lowered for marker in ("auth", "session", "sid", "token", "jwt"))
