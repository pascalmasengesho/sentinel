"""Lightweight technology fingerprinting based only on visible page data."""

from __future__ import annotations

import re

from sentinel.models import ModuleResult
from sentinel.modules.base import ScanContext, ScanModule, response_or_error

_HTML_MARKERS: dict[str, dict[str, tuple[str, ...]]] = {
    "cms": {
        "WordPress": (r"wp-content/", r"wp-includes/"),
        "Drupal": (r"drupal-settings-json", r"/sites/default/files/"),
        "Joomla": (r"/media/system/js/", r"joomla!"),
    },
    "frameworks": {
        "React": (r"__next_data__", r"react(?:\.production)?\.min\.js"),
        "Vue.js": (r"__vue__", r"vue(?:\.global)?(?:\.prod)?\.js"),
        "Angular": (r"ng-version=", r"angular(?:\.min)?\.js"),
        "Svelte": (r"__svelte", r"svelte(?:\.min)?\.js"),
    },
    "libraries": {"jQuery": (r"jquery(?:-[\d.]+)?(?:\.min)?\.js",)},
    "analytics": {
        "Google Analytics": (r"googletagmanager\.com", r"google-analytics\.com"),
        "Matomo": (r"matomo\.js", r"piwik\.js"),
    },
}

_HEADER_HINTS: dict[str, dict[str, tuple[str, ...]]] = {
    "cdn_or_edge": {
        "Cloudflare": ("cf-ray", "cf-cache-status"),
        "CloudFront": ("x-amz-cf-id", "x-amz-cf-pop"),
        "Akamai": ("x-akamai", "akamai-grn"),
        "Fastly": ("x-served-by", "x-cache-hits"),
        "Vercel": ("x-vercel-id",),
        "Netlify": ("x-nf-request-id",),
    },
    "waf_hints": {
        "Cloudflare": ("cf-ray",),
        "Sucuri": ("x-sucuri-id", "x-sucuri-cache"),
        "Imperva": ("x-iinfo",),
    },
    "reverse_proxy_or_container_hints": {
        "Envoy": ("x-envoy",),
        "Traefik": ("x-traefik",),
        "Kubernetes ingress": ("x-kubernetes",),
    },
}


class TechnologyModule(ScanModule):
    """Identify probable frameworks and libraries without active probing."""

    name = "technology"

    async def run(self, context: ScanContext) -> ModuleResult:
        response, skipped = response_or_error(context, self.name)
        if skipped:
            return skipped
        assert response is not None
        body = response.text.lower()
        categories = {
            category: [
                technology
                for technology, patterns in markers.items()
                if any(re.search(pattern, body, flags=re.IGNORECASE) for pattern in patterns)
            ]
            for category, markers in _HTML_MARKERS.items()
        }
        generator = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', response.text, re.I
        )
        if generator:
            categories.setdefault("cms", []).append(f"Generator: {generator.group(1)}")
        powered_by = response.headers.get("x-powered-by", "")
        if powered_by:
            categories["programming_language_hints"] = [f"X-Powered-By: {powered_by}"]
        header_hints = {
            category: [
                vendor
                for vendor, headers in vendors.items()
                if any(
                    header in response.headers
                    or header.rstrip("-") in response.headers.get("server", "").lower()
                    for header in headers
                )
            ]
            for category, vendors in _HEADER_HINTS.items()
        }
        server = response.headers.get("server", "")
        if server:
            header_hints["web_server_hints"] = [server]
            if any(marker in server.lower() for marker in ("nginx", "apache", "caddy", "iis")):
                header_hints["reverse_proxy_or_container_hints"].append(server)
        detected = [item for items in categories.values() for item in items]
        return ModuleResult(
            module=self.name,
            data={
                "technologies": detected,
                "technology_hints": {**categories, **header_hints},
                "web_server": server,
                "reverse_proxy_or_cdn": response.headers.get("via", ""),
            },
        )
