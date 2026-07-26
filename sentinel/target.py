"""Target normalization, scope controls, and private-address safeguards."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


class TargetValidationError(ValueError):
    """Raised when a supplied target is malformed or disallowed by safeguards."""


@dataclass(frozen=True, slots=True)
class Target:
    """Normalized target details used by all modules."""

    raw: str
    url: str
    scheme: str
    host: str
    port: int | None
    path: str

    @property
    def origin(self) -> str:
        """Return the target origin without a path."""
        default_port = (self.scheme == "https" and self.port in (None, 443)) or (
            self.scheme == "http" and self.port in (None, 80)
        )
        host_port = self.host if default_port else f"{self.host}:{self.port}"
        return f"{self.scheme}://{host_port}"


def normalize_target(raw: str, allow_private: bool = False) -> Target:
    """Validate and normalize a domain or HTTP(S) URL.

    Private, loopback, link-local, multicast, and reserved IP literals are blocked
    unless the user explicitly selects ``allow_private`` for a local lab.
    """
    candidate = raw.strip()
    if not candidate:
        raise TargetValidationError("A target is required.")
    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise TargetValidationError("Only http and https targets are supported.")
    if not parsed.hostname or parsed.username or parsed.password:
        raise TargetValidationError("Supply a hostname or IP address without credentials.")
    if parsed.query or parsed.fragment:
        raise TargetValidationError("Targets cannot include query strings or fragments.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise TargetValidationError("The target port is invalid.") from exc

    host = parsed.hostname.rstrip(".").lower()
    if " " in host:
        raise TargetValidationError("The target hostname is invalid.")
    if not allow_private and _is_ip_literal(host) and not _is_public_ip(host):
        raise TargetValidationError(
            "Private or reserved IP targets require --allow-private (local lab use only)."
        )

    normalized_path = parsed.path or "/"
    netloc = host if port is None else f"{host}:{port}"
    url = urlunsplit((parsed.scheme.lower(), netloc, normalized_path, "", ""))
    return Target(
        raw=raw, url=url, scheme=parsed.scheme.lower(), host=host, port=port, path=normalized_path
    )


def is_safe_public_host(host: str, allow_private: bool = False) -> bool:
    """Return whether a host is safe to request under Sentinel's default policy."""
    if allow_private:
        return True
    if _is_ip_literal(host):
        return _is_public_ip(host)
    try:
        addresses = {
            str(entry[4][0]) for entry in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        }
    except socket.gaierror:
        # DNS modules will report a resolution error. Do not turn a transient lookup
        # failure into a misleading private-address decision.
        return True
    return bool(addresses) and any(_is_public_ip(address) for address in addresses)


def same_host(url: str, target: Target) -> bool:
    """Return whether a URL is still inside the exact host selected by the user."""
    host = urlsplit(url).hostname
    return host is not None and host.lower().rstrip(".") == target.host


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _is_public_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return ip.is_global
