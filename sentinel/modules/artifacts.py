"""Opt-in collection of public security metadata and favicon fingerprints."""

from __future__ import annotations

import hashlib
from urllib.parse import urljoin

from sentinel.models import ModuleResult
from sentinel.modules.base import ScanContext, ScanModule

_PUBLIC_PATHS = (
    ("favicon", "/favicon.ico"),
    ("well_known_security_txt", "/.well-known/security.txt"),
    ("security_txt", "/security.txt"),
)
_SECURITY_TXT_FIELDS = {"acknowledgments", "contact", "encryption", "expires", "policy"}


class PublicArtifactModule(ScanModule):
    """Collect small, public metadata files only when explicitly enabled."""

    name = "public_artifacts"

    async def run(self, context: ScanContext) -> ModuleResult:
        """Read conventional public artifacts without requesting discovered private paths."""
        artifacts: dict[str, object] = {}
        errors: list[str] = []
        for name, path in _PUBLIC_PATHS:
            url = urljoin(context.target.origin + "/", path.lstrip("/"))
            try:
                response = await context.http.get(url)
            except Exception as exc:
                errors.append(f"{name}: {type(exc).__name__}: {exc}")
                continue
            entry: dict[str, object] = {"url": response.url, "status_code": response.status_code}
            if name == "favicon" and response.status_code == 200:
                entry.update(
                    {
                        "sha256": hashlib.sha256(response.content).hexdigest(),
                        "bytes": len(response.content),
                        "content_type": response.headers.get("content-type", ""),
                    }
                )
            if "security_txt" in name and response.status_code == 200:
                entry["fields"] = self._parse_security_txt(response.text)
            artifacts[name] = entry
        return ModuleResult(module=self.name, data={"public_artifacts": artifacts}, errors=errors)

    @staticmethod
    def _parse_security_txt(text: str) -> dict[str, list[str]]:
        """Extract published security.txt metadata without interpreting its trustworthiness."""
        fields: dict[str, list[str]] = {}
        for raw_line in text.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if ":" not in line:
                continue
            key, value = (item.strip() for item in line.split(":", 1))
            key = key.lower()
            if key in _SECURITY_TXT_FIELDS and value:
                fields.setdefault(key, []).append(value)
        return fields
