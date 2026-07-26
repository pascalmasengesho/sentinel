"""Security response-header and cookie-attribute analysis."""

from __future__ import annotations

from sentinel.models import Finding, ModuleResult, Severity
from sentinel.modules.base import ScanContext, ScanModule, response_or_error


class HeaderModule(ScanModule):
    """Identify absent or broadly permissive browser security controls."""

    name = "headers"
    _required_headers = {
        "content-security-policy": (
            "Content-Security-Policy",
            "Define a restrictive Content Security Policy.",
        ),
        "strict-transport-security": (
            "Strict-Transport-Security",
            "Enable HSTS after confirming all subdomains are ready for HTTPS.",
        ),
        "x-frame-options": (
            "X-Frame-Options",
            "Set DENY or SAMEORIGIN, or use CSP frame-ancestors.",
        ),
        "referrer-policy": (
            "Referrer-Policy",
            "Set a deliberate referrer policy, such as strict-origin-when-cross-origin.",
        ),
        "permissions-policy": (
            "Permissions-Policy",
            "Restrict browser capabilities that the application does not require.",
        ),
        "x-content-type-options": (
            "X-Content-Type-Options",
            "Set X-Content-Type-Options: nosniff.",
        ),
    }

    async def run(self, context: ScanContext) -> ModuleResult:
        response, skipped = response_or_error(context, self.name)
        if skipped:
            return skipped
        assert response is not None
        findings: list[Finding] = []
        for lower_name, (display_name, recommendation) in self._required_headers.items():
            if lower_name not in response.headers:
                findings.append(
                    Finding(
                        title=f"Missing {display_name} header",
                        severity=Severity.LOW,
                        description=f"The response does not include {display_name}.",
                        evidence=f"GET {response.url} returned no {display_name} header.",
                        recommendation=recommendation,
                        module=self.name,
                        url=response.url,
                    )
                )

        acao = response.headers.get("access-control-allow-origin", "")
        acac = response.headers.get("access-control-allow-credentials", "").lower()
        if acao == "*" and acac == "true":
            findings.append(
                Finding(
                    title="Inconsistent permissive CORS headers",
                    severity=Severity.MEDIUM,
                    description="The response permits any origin and also advertises credentials.",
                    evidence=(
                        "Access-Control-Allow-Origin: *; " "Access-Control-Allow-Credentials: true"
                    ),
                    recommendation=(
                        "Use an explicit allowlist of trusted origins and validate it "
                        "server-side."
                    ),
                    module=self.name,
                    url=response.url,
                )
            )
        elif acao == "*":
            findings.append(
                Finding(
                    title="Wildcard CORS origin policy",
                    severity=Severity.LOW,
                    description="The response allows browser reads from any origin.",
                    evidence="Access-Control-Allow-Origin: *",
                    recommendation=(
                        "Confirm this is intentional; restrict origins for non-public " "responses."
                    ),
                    module=self.name,
                    url=response.url,
                )
            )
        return ModuleResult(
            module=self.name,
            data={
                "observed_headers": {
                    key: response.headers.get(key, "")
                    for key in set(self._required_headers) | {"access-control-allow-origin"}
                }
            },
            findings=findings,
        )
