"""Security response-header and cookie-attribute analysis."""

from __future__ import annotations

import re

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
        findings.extend(self._policy_findings(response.url, response.headers))
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

    @staticmethod
    def _policy_findings(url: str, headers: dict[str, str]) -> list[Finding]:
        """Assess observed policy quality without injecting requests or browser payloads."""
        findings: list[Finding] = []
        csp = headers.get("content-security-policy", "")
        normalized_csp = csp.lower()
        if "'unsafe-eval'" in normalized_csp or "'unsafe-inline'" in normalized_csp:
            findings.append(
                Finding(
                    title="Content-Security-Policy permits unsafe script behavior",
                    severity=Severity.LOW,
                    description=(
                        "The observed Content-Security-Policy includes unsafe-inline or "
                        "unsafe-eval. This can weaken browser-side defense in depth."
                    ),
                    evidence=f"Content-Security-Policy: {csp}",
                    recommendation=(
                        "Replace unsafe script allowances with nonces, hashes, and "
                        "externalized scripts where application behavior permits."
                    ),
                    module=HeaderModule.name,
                    url=url,
                )
            )
        if re.search(r"(?:default-src|script-src)\s+[^;]*\*", normalized_csp):
            findings.append(
                Finding(
                    title="Content-Security-Policy has a wildcard script source",
                    severity=Severity.LOW,
                    description=(
                        "The observed policy permits a wildcard source for default-src or "
                        "script-src, which reduces origin restriction."
                    ),
                    evidence=f"Content-Security-Policy: {csp}",
                    recommendation=(
                        "Use a reviewed allowlist of required script origins and avoid broad "
                        "wildcards where possible."
                    ),
                    module=HeaderModule.name,
                    url=url,
                )
            )
        hsts = headers.get("strict-transport-security", "")
        match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
        if match and int(match.group(1)) < 15_552_000:
            findings.append(
                Finding(
                    title="HSTS policy has a short max-age",
                    severity=Severity.INFO,
                    description=(
                        "The observed HSTS max-age is shorter than 180 days. Short durations "
                        "reduce long-term downgrade resistance after an initial HTTPS visit."
                    ),
                    evidence=f"Strict-Transport-Security: {hsts}",
                    recommendation=(
                        "Increase max-age gradually after validating HTTPS support across the "
                        "intended scope."
                    ),
                    module=HeaderModule.name,
                    url=url,
                )
            )
        elif match and "includesubdomains" not in hsts.lower():
            findings.append(
                Finding(
                    title="HSTS policy does not include subdomains",
                    severity=Severity.INFO,
                    description=(
                        "The observed HSTS policy protects the exact host only; subdomains "
                        "remain subject to downgrade until each one publishes its own policy."
                    ),
                    evidence=f"Strict-Transport-Security: {hsts}",
                    recommendation=(
                        "Add includeSubDomains after confirming every subdomain supports HTTPS."
                    ),
                    module=HeaderModule.name,
                    url=url,
                )
            )
        referrer_policy = headers.get("referrer-policy", "")
        if "unsafe-url" in referrer_policy.lower():
            findings.append(
                Finding(
                    title="Referrer-Policy allows full URLs to be sent cross-origin",
                    severity=Severity.LOW,
                    description=(
                        "The observed referrer policy includes unsafe-url, which sends the full "
                        "URL, including path and query, to cross-origin destinations."
                    ),
                    evidence=f"Referrer-Policy: {referrer_policy}",
                    recommendation=(
                        "Use a stricter policy such as strict-origin-when-cross-origin and "
                        "avoid placing sensitive data in URL query strings."
                    ),
                    module=HeaderModule.name,
                    url=url,
                )
            )
        return findings
