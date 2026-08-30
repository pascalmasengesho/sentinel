"""Program-scope manifests that prevent Sentinel from leaving authorized targets."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import unquote, urlsplit

import yaml

from sentinel.config import ScanConfig
from sentinel.target import Target, normalize_target


class ScopeValidationError(ValueError):
    """Raised when a scope manifest is invalid or a target is not permitted."""


@dataclass(frozen=True, slots=True)
class ScopeManifest:
    """A local, explicit allow-list for one authorized assessment program.

    Host patterns are exact names or a leading ``*.`` wildcard. A wildcard matches
    subdomains only; ``*.example.com`` deliberately does not match ``example.com``.
    """

    name: str
    allowed_hosts: tuple[str, ...]
    targets: tuple[str, ...] = ()
    excluded_hosts: tuple[str, ...] = ()
    excluded_paths: tuple[str, ...] = ()
    rate_limit_per_second: float = 1.0

    def assert_target_allowed(self, target: Target) -> None:
        """Reject a normalized target outside this manifest's explicit scope."""
        if not self.allows_url(target.url):
            raise ScopeValidationError(
                f"Target '{target.url}' is outside the selected scope manifest '{self.name}'."
            )

    def allows_url(self, url: str) -> bool:
        """Return whether an HTTP(S) URL matches allowed hosts and exclusions."""
        parsed = urlsplit(url)
        host = (parsed.hostname or "").rstrip(".").lower()
        if parsed.scheme.lower() not in {"http", "https"} or not host:
            return False
        if not any(_host_matches(host, pattern) for pattern in self.allowed_hosts):
            return False
        if any(_host_matches(host, pattern) for pattern in self.excluded_hosts):
            return False
        path = unquote(parsed.path or "/")
        return not any(_path_matches(path, prefix) for prefix in self.excluded_paths)

    def constrained_config(self, config: ScanConfig) -> ScanConfig:
        """Return an independent config whose request rate cannot exceed the scope cap."""
        constrained = replace(
            config,
            ports=list(config.ports),
            rate_limit_per_second=min(config.rate_limit_per_second, self.rate_limit_per_second),
        )
        constrained.validate()
        return constrained

    def normalized_targets(self, allow_private: bool = False) -> list[Target]:
        """Normalize batch targets and reject any manifest entry outside the allow-list."""
        normalized: list[Target] = []
        seen: set[str] = set()
        for raw_target in self.targets:
            target = normalize_target(raw_target, allow_private=allow_private)
            self.assert_target_allowed(target)
            if target.url not in seen:
                normalized.append(target)
                seen.add(target.url)
        return normalized

    def report_data(self, target: Target) -> dict[str, object]:
        """Return report-safe scope metadata without exposing unrelated notes or secrets."""
        return {
            "name": self.name,
            "selected_target": target.url,
            "allowed_host_patterns": list(self.allowed_hosts),
            "excluded_host_patterns": list(self.excluded_hosts),
            "excluded_path_prefixes": list(self.excluded_paths),
            "rate_limit_per_second": self.rate_limit_per_second,
            "note": (
                "Sentinel enforced this local scope manifest for every HTTP request. "
                "The --authorized acknowledgement remains required."
            ),
        }


def load_scope_manifest(path: Path) -> ScopeManifest:
    """Load a strict YAML scope manifest from a local file."""
    if not path.is_file():
        raise FileNotFoundError(f"Scope manifest not found: {path}")
    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(loaded, dict):
        raise ScopeValidationError("Scope manifest must contain a YAML mapping.")
    allowed_keys = {
        "name",
        "allowed_hosts",
        "targets",
        "excluded_hosts",
        "excluded_paths",
        "rate_limit_per_second",
    }
    unknown = set(loaded) - allowed_keys
    if unknown:
        raise ScopeValidationError(f"Unknown scope keys: {', '.join(sorted(unknown))}")
    name = loaded.get("name", "")
    if not isinstance(name, str) or not name.strip():
        raise ScopeValidationError("Scope manifest requires a non-empty 'name'.")
    allowed_hosts = _host_patterns(loaded.get("allowed_hosts"), "allowed_hosts", required=True)
    excluded_hosts = _host_patterns(loaded.get("excluded_hosts", []), "excluded_hosts")
    excluded_paths = _path_prefixes(loaded.get("excluded_paths", []))
    targets = _targets(loaded.get("targets", []))
    rate_limit = loaded.get("rate_limit_per_second", 1.0)
    if not isinstance(rate_limit, (int, float)) or isinstance(rate_limit, bool):
        raise ScopeValidationError("rate_limit_per_second must be a number.")
    if not 0.1 <= float(rate_limit) <= 10.0:
        raise ScopeValidationError("rate_limit_per_second must be between 0.1 and 10.")
    return ScopeManifest(
        name=name.strip(),
        allowed_hosts=tuple(allowed_hosts),
        targets=tuple(targets),
        excluded_hosts=tuple(excluded_hosts),
        excluded_paths=tuple(excluded_paths),
        rate_limit_per_second=float(rate_limit),
    )


def _host_patterns(value: object, field_name: str, required: bool = False) -> list[str]:
    if not isinstance(value, list) or (required and not value):
        requirement = "a non-empty list" if required else "a list"
        raise ScopeValidationError(f"{field_name} must be {requirement} of host patterns.")
    patterns: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ScopeValidationError(f"{field_name} entries must be strings.")
        pattern = item.strip().rstrip(".").lower()
        suffix = pattern[2:] if pattern.startswith("*.") else pattern
        if (
            not suffix
            or "://" in pattern
            or "/" in pattern
            or "@" in pattern
            or " " in pattern
            or "*" in suffix
        ):
            raise ScopeValidationError(f"Invalid host pattern: {item!r}")
        patterns.append(pattern)
    return list(dict.fromkeys(patterns))


def _path_prefixes(value: object) -> list[str]:
    if not isinstance(value, list):
        raise ScopeValidationError("excluded_paths must be a list of absolute path prefixes.")
    prefixes: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.startswith("/") or "://" in item:
            raise ScopeValidationError("excluded_paths entries must begin with '/'.")
        prefixes.append(item.rstrip("/") or "/")
    return list(dict.fromkeys(prefixes))


def _targets(value: object) -> list[str]:
    if not isinstance(value, list):
        raise ScopeValidationError("targets must be a list of domains or HTTP(S) URLs.")
    if not all(isinstance(item, str) and item.strip() for item in value):
        raise ScopeValidationError("targets entries must be non-empty strings.")
    return list(dict.fromkeys(item.strip() for item in value if isinstance(item, str)))


def _host_matches(host: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        return host.endswith("." + pattern[2:])
    return host == pattern


def _path_matches(path: str, prefix: str) -> bool:
    return prefix == "/" or path == prefix or path.startswith(prefix + "/")
