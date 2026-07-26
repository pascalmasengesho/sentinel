"""Configuration loading and conservative defaults for Sentinel."""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml

DEFAULT_PORTS = [80, 443, 8080, 8443, 8000, 3000, 5000, 22]


@dataclass(slots=True)
class ScanConfig:
    """Runtime settings. Active discovery is disabled unless explicitly enabled."""

    timeout_seconds: float = 8.0
    concurrency: int = 4
    rate_limit_per_second: float = 1.0
    verify_tls: bool = True
    max_redirects: int = 3
    max_response_bytes: int = 1_000_000
    user_agent: str = "Sentinel/0.1 (authorized security assessment)"
    ports: list[int] = field(default_factory=lambda: list(DEFAULT_PORTS))
    enable_port_scan: bool = True
    enable_banner_grab: bool = False
    enable_passive_subdomains: bool = False
    enable_public_api_probe: bool = False
    enable_content_discovery: bool = False
    wordlist_path: str | None = None
    max_directory_requests: int = 50
    max_sitemap_urls: int = 100
    max_js_files: int = 10
    allow_private: bool = False
    plugin_directory: str | None = None

    def validate(self) -> None:
        """Validate configuration bounds before any requests are made."""
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        if not 1 <= self.concurrency <= 20:
            raise ValueError("concurrency must be between 1 and 20")
        if not 0.1 <= self.rate_limit_per_second <= 10:
            raise ValueError("rate_limit_per_second must be between 0.1 and 10")
        if len(self.ports) > 100:
            raise ValueError("at most 100 ports may be selected")
        if any(port < 1 or port > 65535 for port in self.ports):
            raise ValueError("ports must be integers between 1 and 65535")
        if not 1 <= self.max_directory_requests <= 500:
            raise ValueError("max_directory_requests must be between 1 and 500")


def load_config(path: Path | None = None, profile: str | None = None) -> ScanConfig:
    """Load YAML settings and optionally overlay a named profile."""
    if path is None:
        return ScanConfig()
    if not path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {path}")
    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(loaded, dict):
        raise ValueError("Configuration must be a YAML mapping.")
    profiles = loaded.pop("profiles", {})
    if profile:
        if not isinstance(profiles, dict) or profile not in profiles:
            raise ValueError(f"Profile '{profile}' was not found in {path}.")
        profile_data = profiles[profile]
        if not isinstance(profile_data, dict):
            raise ValueError(f"Profile '{profile}' must be a YAML mapping.")
        loaded = {**loaded, **profile_data}
    return _config_from_mapping(loaded)


def apply_overrides(config: ScanConfig, overrides: dict[str, Any]) -> ScanConfig:
    """Apply CLI values that are not ``None`` to an existing configuration."""
    allowed = {item.name for item in fields(ScanConfig)}
    for key, value in overrides.items():
        if key in allowed and value is not None:
            setattr(config, key, value)
    config.validate()
    return config


def _config_from_mapping(data: dict[str, Any]) -> ScanConfig:
    allowed = {item.name for item in fields(ScanConfig)}
    unknown = set(data) - allowed
    if unknown:
        raise ValueError(f"Unknown configuration keys: {', '.join(sorted(unknown))}")
    config = ScanConfig(**data)
    config.validate()
    return config
