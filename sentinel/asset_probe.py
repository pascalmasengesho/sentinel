"""Rate-limited concurrent probes for explicitly authorized asset inventories."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx

from sentinel.config import ScanConfig
from sentinel.http_client import RateLimiter
from sentinel.scope import ScopeManifest, ScopeValidationError
from sentinel.target import Target, is_safe_public_host


@dataclass(frozen=True, slots=True)
class AssetObservation:
    """One minimal, header-derived observation for an explicit asset target."""

    target: str
    status_code: int
    content_length: int | None
    technologies: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AssetProbeFailure:
    """A non-fatal target-specific failure retained outside the baseline."""

    target: str
    error: str


class AssetProbeEngine:
    """Probe explicit scope targets concurrently with one shared rate limit.

    Probes use one direct GET per target, do not follow redirects, do not read
    response bodies, and collect only headers/status metadata. This makes the
    monitor appropriate for low-impact availability and change observation.
    """

    def __init__(
        self,
        scope: ScopeManifest,
        config: ScanConfig,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.scope = scope
        self.config = scope.constrained_config(config)
        self.transport = transport

    async def probe(self) -> tuple[list[AssetObservation], list[AssetProbeFailure]]:
        """Probe all explicit manifest targets without failing the remaining batch."""
        targets = self.scope.normalized_targets(allow_private=self.config.allow_private)
        if not targets:
            raise ScopeValidationError("Asset monitoring requires at least one manifest target.")
        limiter = RateLimiter(self.config.rate_limit_per_second)
        semaphore = asyncio.Semaphore(self.config.concurrency)
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.timeout_seconds),
            verify=self.config.verify_tls,
            follow_redirects=False,
            headers={
                "User-Agent": self.config.user_agent,
                "Accept": "*/*;q=0.1",
            },
            transport=self.transport,
        ) as client:
            results = await asyncio.gather(
                *(self._probe_one(client, target, limiter, semaphore) for target in targets)
            )
        observations = sorted(
            (result for result in results if isinstance(result, AssetObservation)),
            key=lambda item: item.target,
        )
        failures = sorted(
            (result for result in results if isinstance(result, AssetProbeFailure)),
            key=lambda item: item.target,
        )
        return observations, failures

    async def _probe_one(
        self,
        client: httpx.AsyncClient,
        target: Target,
        limiter: RateLimiter,
        semaphore: asyncio.Semaphore,
    ) -> AssetObservation | AssetProbeFailure:
        async with semaphore:
            if not self.scope.allows_url(target.url):
                return AssetProbeFailure(target.url, "Blocked by scope.")
            if not is_safe_public_host(target.host, self.config.allow_private):
                return AssetProbeFailure(target.url, "Blocked private or reserved target.")
            await limiter.wait()
            try:
                async with client.stream("GET", target.url) as response:
                    return AssetObservation(
                        target=target.url,
                        status_code=response.status_code,
                        content_length=_content_length(response.headers.get("content-length")),
                        technologies=_technology_hints(response.headers),
                    )
            except (httpx.RequestError, httpx.TimeoutException) as exc:
                return AssetProbeFailure(target.url, f"{type(exc).__name__}: {exc}")


def _content_length(value: str | None) -> int | None:
    """Parse a trustworthy non-negative Content-Length header when present."""
    if value is None:
        return None
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def _technology_hints(headers: Any) -> tuple[str, ...]:
    """Return a small deterministic, header-only technology summary."""
    values: list[str] = []
    for name in ("server", "x-powered-by", "x-aspnet-version"):
        value = headers.get(name, "").strip()
        if value:
            values.append(f"{name}: {value}")
    if headers.get("cf-ray"):
        values.append("edge: Cloudflare")
    if "cloudfront" in headers.get("via", "").lower():
        values.append("edge: CloudFront")
    return tuple(dict.fromkeys(values))
