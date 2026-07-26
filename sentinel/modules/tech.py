"""Lightweight technology fingerprinting based only on visible page data."""

from __future__ import annotations

import re

from sentinel.models import ModuleResult
from sentinel.modules.base import ScanContext, ScanModule, response_or_error

_HTML_MARKERS = {
    "WordPress": (r"wp-content/", r"wp-includes/"),
    "Drupal": (r"drupal-settings-json", r"/sites/default/files/"),
    "React": (r"__next_data__", r"react(?:\.production)?\.min\.js"),
    "Vue.js": (r"__vue__", r"vue(?:\.global)?(?:\.prod)?\.js"),
    "Angular": (r"ng-version=", r"angular(?:\.min)?\.js"),
    "jQuery": (r"jquery(?:-[\d.]+)?(?:\.min)?\.js",),
    "Google Analytics": (r"googletagmanager\.com", r"google-analytics\.com"),
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
        detected = [
            technology
            for technology, patterns in _HTML_MARKERS.items()
            if any(re.search(pattern, body, flags=re.IGNORECASE) for pattern in patterns)
        ]
        generator = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', response.text, re.I
        )
        if generator:
            detected.append(f"Generator: {generator.group(1)}")
        powered_by = response.headers.get("x-powered-by", "")
        if powered_by:
            detected.append(f"X-Powered-By: {powered_by}")
        return ModuleResult(
            module=self.name,
            data={
                "technologies": detected,
                "web_server": response.headers.get("server", ""),
                "reverse_proxy_or_cdn": response.headers.get("via", ""),
            },
        )
