"""Base types and shared helpers for scan modules."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from sentinel.config import ScanConfig
from sentinel.http_client import HttpResponse, SafeHttpClient
from sentinel.models import ModuleResult
from sentinel.target import Target


@dataclass(slots=True)
class ScanContext:
    """Mutable state intentionally shared between modules in one scan."""

    target: Target
    config: ScanConfig
    http: SafeHttpClient
    http_response: HttpResponse | None = None
    robots_text: str = ""
    robots_sitemaps: list[str] = field(default_factory=list)
    sitemap_urls: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)


class ScanModule(ABC):
    """Abstract interface implemented by all Sentinel modules."""

    name: str

    async def execute(self, context: ScanContext) -> ModuleResult:
        """Run the module and convert unexpected errors into reportable output."""
        started = time.perf_counter()
        try:
            result = await self.run(context)
        except Exception as exc:  # modules must not abort an entire assessment
            result = ModuleResult(module=self.name, errors=[f"{type(exc).__name__}: {exc}"])
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        return result

    @abstractmethod
    async def run(self, context: ScanContext) -> ModuleResult:
        """Perform the module's bounded, non-destructive check."""


def response_or_error(
    context: ScanContext, module: str
) -> tuple[HttpResponse | None, ModuleResult | None]:
    """Return the shared root response, or a consistent skipped-module result."""
    if context.http_response is None:
        return None, ModuleResult(
            module=module, errors=["Root HTTP request was unavailable; module skipped."]
        )
    return context.http_response, None
