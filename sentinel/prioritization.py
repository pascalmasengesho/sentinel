"""Deterministic, non-exploitative prioritization of existing Sentinel observations."""

from __future__ import annotations

from typing import Any

from sentinel.models import ModuleResult


def build_research_priorities(modules: list[ModuleResult]) -> ModuleResult:
    """Correlate completed module data into safe manual-investigation queues."""
    module_data = {module.module: module.data for module in modules}
    priorities: list[dict[str, str | list[str]]] = []
    surface = module_data.get("surface", {})
    http = module_data.get("http", {})
    api = module_data.get("api_discovery", {})
    javascript = module_data.get("javascript", {})
    recon = module_data.get("recon", {})
    artifacts = module_data.get("public_artifacts", {})
    crawler = module_data.get("crawler", {})
    takeover = module_data.get("takeover", {})
    email_security = module_data.get("email_security", {})

    forms = _mapping_list(surface.get("forms"))
    auth_points = _strings(surface.get("authentication_points"))
    if auth_points or any(bool(form.get("has_password")) for form in forms):
        priorities.append(
            _priority(
                title="Authentication surface review",
                tier="High-value manual review",
                confidence="Observed public entry points",
                evidence=[
                    f"Authentication points: {len(auth_points)}",
                    f"Password forms: {sum(bool(form.get('has_password')) for form in forms)}",
                ],
                next_step=(
                    "Confirm the entry points are in scope, then manually review session handling, "
                    "CSRF protections, and account-recovery flows without bypassing authentication."
                ),
            )
        )

    api_endpoints = _strings(api.get("public_endpoint_candidates"))
    graphql = _strings(surface.get("graphql_candidates"))
    websocket = _strings(surface.get("websocket_candidates"))
    if api_endpoints or graphql or websocket:
        priorities.append(
            _priority(
                title="Public API and real-time surface review",
                tier="Needs manual investigation",
                confidence="Published or page-referenced endpoints",
                evidence=[
                    f"API candidates: {len(api_endpoints)}",
                    f"GraphQL candidates: {len(graphql)}",
                    f"WebSocket candidates: {len(websocket)}",
                ],
                next_step=(
                    "Verify documented endpoints at the permitted rate and review authorization "
                    "boundaries using only program-approved test accounts or public behavior."
                ),
            )
        )

    js_endpoints = _strings(javascript.get("endpoint_candidates"))
    cookie_names = _strings(http.get("cookie_names"))
    if js_endpoints and cookie_names:
        priorities.append(
            _priority(
                title="Browser session and client-side endpoint review",
                tier="Contextual manual review",
                confidence="Observed scripts and response cookies",
                evidence=[
                    f"JavaScript endpoint candidates: {len(js_endpoints)}",
                    f"Cookies observed: {len(cookie_names)}",
                ],
                next_step=(
                    "Document the browser-visible endpoints and cookie attributes, then evaluate "
                    "realistic impact only within the program's scope and rules."
                ),
            )
        )

    subdomains = _strings(recon.get("passive_subdomains"))
    if subdomains:
        priorities.append(
            _priority(
                title="Passive asset inventory review",
                tier="Discovery follow-up",
                confidence="Certificate-transparency observations",
                evidence=[f"Passive subdomains: {len(subdomains)}"],
                next_step=(
                    "Validate each asset against the program scope before any further authorized "
                    "assessment. Passive discovery alone does not establish ownership or risk."
                ),
            )
        )

    if artifacts.get("public_artifacts"):
        priorities.append(
            _priority(
                title="Published security metadata review",
                tier="Security-contact and policy review",
                confidence="Public artifacts observed",
                evidence=["favicon/security.txt metadata was collected with explicit opt-in"],
                next_step=(
                    "Use published security contact and policy information to align disclosure and "
                    "verification work with the owner's documented process."
                ),
            )
        )

    takeover_candidates = _mapping_list(takeover.get("candidates"))
    if takeover_candidates:
        priorities.append(
            _priority(
                title="Subdomain takeover candidate review",
                tier="High-value manual review",
                confidence="DNS-only triage of certificate-transparency subdomains",
                evidence=[f"Takeover candidates: {len(takeover_candidates)}"],
                next_step=(
                    "Validate each candidate's service reference manually, confirm it is in "
                    "scope, and never claim third-party resources without written program "
                    "permission."
                ),
            )
        )

    if email_security.get("enabled"):
        spf = _strings(email_security.get("spf_records"))
        dmarc = str(email_security.get("dmarc_record", ""))
        weak_email_policy = (
            not spf or not dmarc or "p=none" in dmarc.lower() or "+all" in " ".join(spf).lower()
        )
        if weak_email_policy:
            priorities.append(
                _priority(
                    title="Email authentication policy review",
                    tier="Contextual manual review",
                    confidence="Published SPF/DMARC DNS records",
                    evidence=[
                        f"SPF records: {len(spf)}",
                        f"DMARC published: {bool(dmarc)}",
                    ],
                    next_step=(
                        "Compare the published email policy with the program's scope; missing "
                        "or weak SPF/DMARC can support a spoofing report when mail handling is "
                        "in scope."
                    ),
                )
            )

    crawled_pages = _mapping_list(crawler.get("pages"))
    if len(crawled_pages) > 1:
        priorities.append(
            _priority(
                title="Public route inventory review",
                tier="Discovery follow-up",
                confidence="Bounded same-origin GET crawl",
                evidence=[
                    f"Public routes requested: {len(crawled_pages)}",
                    f"Robots paths skipped: {len(_strings(crawler.get('robots_skipped_urls')))}",
                ],
                next_step=(
                    "Confirm each collected route remains in scope, then use the route inventory "
                    "to guide manual documentation and non-destructive review."
                ),
            )
        )

    return ModuleResult(
        module="research_priorities",
        data={
            "priorities": priorities,
            "priority_count": len(priorities),
            "method": "Deterministic correlation of completed, non-destructive module outputs.",
            "notice": (
                "Priorities identify where manual, authorized investigation may be useful. They do "
                "not assert that a vulnerability exists or recommend exploitation."
            ),
        },
    )


def _priority(
    title: str, tier: str, confidence: str, evidence: list[str], next_step: str
) -> dict[str, str | list[str]]:
    return {
        "title": title,
        "tier": tier,
        "confidence": confidence,
        "evidence": evidence,
        "safe_next_step": next_step,
    }


def _strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _mapping_list(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]
