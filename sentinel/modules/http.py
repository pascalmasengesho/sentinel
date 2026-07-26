"""Root HTTP response collection and low-impact protocol observations."""

from __future__ import annotations

from sentinel.models import Finding, ModuleResult, Severity
from sentinel.modules.base import ScanContext, ScanModule


class HttpModule(ScanModule):
    """Fetch the selected URL and inspect response metadata and advertised methods."""

    name = "http"

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

        cookie_names = []
        for raw_cookie in response.headers.get("set-cookie", "").split(","):
            name = raw_cookie.split("=", 1)[0].strip()
            if name:
                cookie_names.append(name)
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
        errors = [options_error] if options_error else []
        return ModuleResult(module=self.name, data=data, findings=findings, errors=errors)
