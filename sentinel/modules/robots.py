"""robots.txt collection and non-invasive path/sitemap extraction."""

from __future__ import annotations

from urllib.parse import urljoin

from sentinel.models import ModuleResult
from sentinel.modules.base import ScanContext, ScanModule


class RobotsModule(ScanModule):
    """Read a public robots.txt file without requesting any listed paths."""

    name = "robots"

    async def run(self, context: ScanContext) -> ModuleResult:
        url = urljoin(context.target.origin + "/", "robots.txt")
        response = await context.http.get(url)
        if response.status_code != 200:
            return ModuleResult(
                module=self.name, data={"url": response.url, "status_code": response.status_code}
            )
        disallowed: list[str] = []
        sitemaps: list[str] = []
        for raw_line in response.text.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if ":" not in line:
                continue
            key, value = (item.strip() for item in line.split(":", 1))
            if key.lower() == "disallow" and value:
                disallowed.append(value)
            if key.lower() == "sitemap" and value:
                sitemaps.append(urljoin(response.url, value))
        context.robots_text = response.text
        context.robots_disallowed = disallowed
        context.robots_sitemaps = sitemaps
        return ModuleResult(
            module=self.name,
            data={
                "url": response.url,
                "status_code": response.status_code,
                "disallowed_paths": disallowed,
                "sitemaps": sitemaps,
            },
        )
