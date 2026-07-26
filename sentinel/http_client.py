"""A scope-aware, rate-limited asynchronous HTTP client."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from sentinel.config import ScanConfig
from sentinel.target import Target, is_safe_public_host, same_host


class RequestBlockedError(ValueError):
    """Raised when a request would leave the chosen target scope or safety policy."""


@dataclass(slots=True)
class HttpResponse:
    """Small response representation retained for inter-module use and reporting."""

    url: str
    status_code: int
    headers: dict[str, str]
    text: str
    http_version: str
    redirect_chain: list[str]


class RateLimiter:
    """Serialize starts of requests to stay within the selected per-host rate."""

    def __init__(self, rate_per_second: float) -> None:
        self._interval = 1 / rate_per_second
        self._next_start = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        """Wait until starting another request is permitted."""
        async with self._lock:
            now = time.monotonic()
            delay = max(0.0, self._next_start - now)
            self._next_start = max(now, self._next_start) + self._interval
        if delay:
            await asyncio.sleep(delay)


class SafeHttpClient:
    """HTTP client that permits only same-host, public HTTP(S) requests by default."""

    def __init__(self, target: Target, config: ScanConfig) -> None:
        self.target = target
        self.config = config
        self._limiter = RateLimiter(config.rate_limit_per_second)
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(config.timeout_seconds),
            verify=config.verify_tls,
            follow_redirects=False,
            headers={
                "User-Agent": config.user_agent,
                "Accept": "text/html,application/json,*/*;q=0.5",
            },
        )

    async def __aenter__(self) -> SafeHttpClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self._client.aclose()

    async def get(self, url: str) -> HttpResponse:
        """Issue a safe, rate-limited GET request and follow safe same-host redirects."""
        return await self.request("GET", url)

    async def options(self, url: str) -> HttpResponse:
        """Issue an OPTIONS request to inspect advertised public HTTP methods."""
        return await self.request("OPTIONS", url)

    async def request(self, method: str, url: str) -> HttpResponse:
        """Request a URL after scope validation with bounded retry and redirects."""
        current_url = url
        redirects: list[str] = []
        for _ in range(self.config.max_redirects + 1):
            self._validate_url(current_url)
            response = await self._request_with_retry(method, current_url)
            if response.status_code not in {301, 302, 303, 307, 308}:
                return HttpResponse(
                    url=str(response.url),
                    status_code=response.status_code,
                    headers={key.lower(): value for key, value in response.headers.items()},
                    text=response.text[: self.config.max_response_bytes],
                    http_version=response.http_version,
                    redirect_chain=redirects,
                )
            location = response.headers.get("location")
            if not location:
                return HttpResponse(
                    url=str(response.url),
                    status_code=response.status_code,
                    headers={key.lower(): value for key, value in response.headers.items()},
                    text=response.text[: self.config.max_response_bytes],
                    http_version=response.http_version,
                    redirect_chain=redirects,
                )
            redirects.append(str(response.url))
            current_url = urljoin(str(response.url), location)
        raise httpx.TooManyRedirects("Redirect limit exceeded", request=None)

    async def _request_with_retry(self, method: str, url: str) -> httpx.Response:
        for attempt in range(3):
            await self._limiter.wait()
            try:
                response = await self._client.request(method, url)
            except (httpx.RequestError, httpx.TimeoutException):
                if attempt == 2:
                    raise
                await asyncio.sleep(0.25 * (2**attempt))
                continue
            if response.status_code not in {429, 502, 503, 504} or attempt == 2:
                return response
            await asyncio.sleep(0.25 * (2**attempt))
        raise AssertionError("retry loop should return or raise")

    def _validate_url(self, url: str) -> None:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise RequestBlockedError(f"Blocked non-HTTP(S) URL: {url}")
        if not same_host(url, self.target):
            raise RequestBlockedError(f"Blocked out-of-scope host: {parsed.hostname}")
        if not is_safe_public_host(parsed.hostname, self.config.allow_private):
            raise RequestBlockedError(f"Blocked private or reserved address: {parsed.hostname}")
