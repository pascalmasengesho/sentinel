"""Lightweight technology fingerprinting based only on visible page data."""

from __future__ import annotations

import re

from sentinel.models import ModuleResult
from sentinel.modules.base import ScanContext, ScanModule, response_or_error

_HTML_MARKERS: dict[str, dict[str, tuple[str, ...]]] = {
    "cms": {
        "WordPress": (r"wp-content/", r"wp-includes/"),
        "Drupal": (r"drupal-settings-json", r"/sites/default/files/", r"/sites/all/"),
        "Joomla": (r"/media/system/js/", r"joomla!"),
        "TYPO3": (r"typo3temp/", r"typo3conf/"),
        "Shopify": (r"cdn\.shopify\.com", r"Shopify\.theme"),
        "Wix": (r"static\.wixstatic\.com", r"wix\.com"),
        "Squarespace": (r"static1\.squarespace\.com", r"squarespace"),
        "Webflow": (r"webflow\.js", r"data-wf-page"),
        "Ghost": (r"ghost\.io", r"content/images/"),
    },
    "frameworks": {
        "React": (r"react(?:\.production|\.development)?\.min\.js", r"react-dom"),
        "Next.js": (r"__next_data__", r"/_next/"),
        "Vue.js": (r"__vue__", r"vue(?:\.global)?(?:\.prod)?\.js"),
        "Nuxt.js": (r"__nuxt__", r"/_nuxt/"),
        "Angular": (r"ng-version=", r"angular(?:\.min)?\.js"),
        "Svelte": (r"__svelte", r"svelte(?:\.min)?\.js"),
        "SvelteKit": (r"__sveltekit", r"/_app/immutable/"),
        "Gatsby": (r"___gatsby", r"gatsby"),
        "Remix": (r"__remixContext", r"remix"),
        "Django": (r"csrfmiddlewaretoken",),
        "Ruby on Rails": (r"authenticity_token", r"data-turbolinks"),
        "Laravel": (r'name="csrf-token"', r"laravel"),
        "ASP.NET": (r"__viewstate", r"__eventvalidation"),
        "Alpine.js": (r"x-data", r"alpine(?:\.min)?\.js"),
        "htmx": (r"hx-get", r"htmx\.org"),
        "Livewire": (r"wire:", r"livewire"),
    },
    "libraries": {
        "jQuery": (r"jquery(?:-[\d.]+)?(?:\.min)?\.js",),
        "Bootstrap": (r"bootstrap(?:\.min)?\.(?:js|css)",),
        "Font Awesome": (r"font-awesome", r"fontawesome"),
        "Google Fonts": (r"fonts\.googleapis\.com",),
        "Lodash": (r"lodash(?:\.min)?\.js",),
        "Moment.js": (r"moment(?:\.min)?\.js",),
    },
    "analytics": {
        "Google Analytics": (r"googletagmanager\.com", r"google-analytics\.com"),
        "Google Tag Manager": (r"googletagmanager\.com/gtm",),
        "Matomo": (r"matomo\.js", r"piwik\.js"),
        "Plausible": (r"plausible\.io",),
        "Fathom": (r"fathom\.analytics",),
        "Hotjar": (r"hotjar\.com",),
        "Segment": (r"segment\.com/analytics",),
        "Mixpanel": (r"mixpanel",),
    },
}

_HEADER_HINTS: dict[str, dict[str, tuple[str, ...]]] = {
    "cdn_or_edge": {
        "Cloudflare": ("cf-ray", "cf-cache-status"),
        "CloudFront": ("x-amz-cf-id", "x-amz-cf-pop"),
        "Akamai": ("x-akamai", "akamai-grn"),
        "Fastly": ("x-served-by", "x-cache-hits"),
        "Vercel": ("x-vercel-id", "x-vercel-cache"),
        "Netlify": ("x-nf-request-id",),
        "GitHub Pages": ("x-github-request-id",),
    },
    "waf_hints": {
        "Cloudflare": ("cf-ray",),
        "Sucuri": ("x-sucuri-id", "x-sucuri-cache"),
        "Imperva": ("x-iinfo",),
        "AWS WAF": ("x-amzn-waf-",),
        "Akamai WAF": ("x-akamai-sig",),
    },
    "reverse_proxy_or_container_hints": {
        "Envoy": ("x-envoy",),
        "Traefik": ("x-traefik",),
        "Kubernetes ingress": ("x-kubernetes",),
    },
    "hosting_hints": {
        "Heroku": ("x-heroku", "via:vegur"),
        "Pantheon": ("x-pantheon-styx-hostname",),
        "WP Engine": ("x-wpe-",),
        "Kinsta": ("x-kinsta-cache",),
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
        server_lower = response.headers.get("server", "").lower()
        header_hints = {
            category: [
                vendor
                for vendor, markers in vendors.items()
                if any(
                    self._header_hint_matches(marker, response.headers, server_lower)
                    for marker in markers
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

    @staticmethod
    def _header_hint_matches(marker: str, headers: dict[str, str], server_lower: str) -> bool:
        """Match an exact header name, a header prefix, a Via value, or a Server hint."""
        if marker in headers:
            return True
        if marker.endswith("-"):
            return any(name.startswith(marker) for name in headers)
        if marker.startswith("via:"):
            return marker[4:] in headers.get("via", "").lower()
        return bool(server_lower and marker.rstrip("-") in server_lower)
