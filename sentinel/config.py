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
    user_agent: str = "Sentinel/0.3 (authorized security assessment)"
    ports: list[int] = field(default_factory=lambda: list(DEFAULT_PORTS))
    enable_port_scan: bool = True
    enable_banner_grab: bool = False
    enable_passive_subdomains: bool = False
    enable_whois: bool = False
    enable_email_security: bool = True
    enable_takeover_check: bool = False
    enable_public_api_probe: bool = False
    enable_public_artifact_checks: bool = False
    enable_content_discovery: bool = False
    wordlist_path: str | None = None
    max_directory_requests: int = 50
    max_sitemap_urls: int = 100
    max_js_files: int = 10
    enable_safe_crawl: bool = False
    max_crawl_pages: int = 20
    max_crawl_depth: int = 2
    allow_private: bool = False
    plugin_directory: str | None = None
    enable_subfinder: bool = False
    enable_amass: bool = False
    enable_nmap: bool = False
    enable_nuclei: bool = False
    enable_ffuf: bool = False
    external_timeout_seconds: float = 300.0
    subfinder_args: str = "-silent"
    amass_args: str = "-passive"
    nmap_args: str = "-sV -Pn -T3"
    nuclei_args: str = "-silent"
    nuclei_severity: str = "low,medium,high,critical"
    nuclei_tags: str = "exposure,misconfig"
    nuclei_templates: str | None = None
    ffuf_args: str = "-noninteractive"
    ffuf_wordlist_path: str | None = None
    ffuf_match_codes: str = "200,204,301,302,307,308,401,403"

    def validate(self) -> None:
        """Validate configuration types and bounds before any requests are made."""
        self._require_number("timeout_seconds", self.timeout_seconds, minimum=0.1)
        self._require_integer("concurrency", self.concurrency, minimum=1, maximum=20)
        self._require_number(
            "rate_limit_per_second", self.rate_limit_per_second, minimum=0.1, maximum=10.0
        )
        self._require_integer("max_redirects", self.max_redirects, minimum=1, maximum=10)
        self._require_integer(
            "max_response_bytes", self.max_response_bytes, minimum=1_000, maximum=10_000_000
        )
        if not isinstance(self.user_agent, str) or not self.user_agent.strip():
            raise ValueError("user_agent must be a non-empty string")
        if not isinstance(self.ports, list) or not all(
            isinstance(port, int) and not isinstance(port, bool) for port in self.ports
        ):
            raise ValueError("ports must be a list of integers")
        if len(self.ports) > 100:
            raise ValueError("at most 100 ports may be selected")
        if any(port < 1 or port > 65535 for port in self.ports):
            raise ValueError("ports must be integers between 1 and 65535")
        for name, value in self._boolean_fields().items():
            if not isinstance(value, bool):
                raise ValueError(f"{name} must be a boolean")
        self._require_integer(
            "max_directory_requests", self.max_directory_requests, minimum=1, maximum=500
        )
        self._require_integer("max_sitemap_urls", self.max_sitemap_urls, minimum=1, maximum=10_000)
        self._require_integer("max_js_files", self.max_js_files, minimum=1, maximum=100)
        self._require_integer("max_crawl_pages", self.max_crawl_pages, minimum=1, maximum=100)
        self._require_integer("max_crawl_depth", self.max_crawl_depth, minimum=1, maximum=4)
        self._require_number(
            "external_timeout_seconds", self.external_timeout_seconds, minimum=1.0, maximum=3600.0
        )
        if self.wordlist_path is not None and not isinstance(self.wordlist_path, str):
            raise ValueError("wordlist_path must be a string or null")
        if self.plugin_directory is not None and not isinstance(self.plugin_directory, str):
            raise ValueError("plugin_directory must be a string or null")
        for string_name, string_value in self._string_fields().items():
            if not isinstance(string_value, str):
                raise ValueError(f"{string_name} must be a string")

    def _boolean_fields(self) -> dict[str, bool]:
        """Return boolean configuration fields for strict type validation."""
        return {
            "verify_tls": self.verify_tls,
            "enable_port_scan": self.enable_port_scan,
            "enable_banner_grab": self.enable_banner_grab,
            "enable_passive_subdomains": self.enable_passive_subdomains,
            "enable_whois": self.enable_whois,
            "enable_email_security": self.enable_email_security,
            "enable_takeover_check": self.enable_takeover_check,
            "enable_public_api_probe": self.enable_public_api_probe,
            "enable_public_artifact_checks": self.enable_public_artifact_checks,
            "enable_content_discovery": self.enable_content_discovery,
            "enable_safe_crawl": self.enable_safe_crawl,
            "allow_private": self.allow_private,
            "enable_subfinder": self.enable_subfinder,
            "enable_amass": self.enable_amass,
            "enable_nmap": self.enable_nmap,
            "enable_nuclei": self.enable_nuclei,
            "enable_ffuf": self.enable_ffuf,
        }

    def _string_fields(self) -> dict[str, str]:
        """Return string configuration fields for strict type validation."""
        return {
            "subfinder_args": self.subfinder_args,
            "amass_args": self.amass_args,
            "nmap_args": self.nmap_args,
            "nuclei_args": self.nuclei_args,
            "nuclei_severity": self.nuclei_severity,
            "nuclei_tags": self.nuclei_tags,
            "ffuf_args": self.ffuf_args,
            "ffuf_match_codes": self.ffuf_match_codes,
        }

    @staticmethod
    def _require_number(
        name: str, value: object, minimum: float, maximum: float | None = None
    ) -> None:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{name} must be a number")
        number = float(value)
        if number < minimum or (maximum is not None and number > maximum):
            upper = f" and {maximum}" if maximum is not None else ""
            raise ValueError(f"{name} must be between {minimum}{upper}")

    @staticmethod
    def _require_integer(
        name: str, value: object, minimum: int, maximum: int | None = None
    ) -> None:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name} must be an integer")
        if value < minimum or (maximum is not None and value > maximum):
            upper = f" and {maximum}" if maximum is not None else ""
            raise ValueError(f"{name} must be between {minimum}{upper}")


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
    if not isinstance(profiles, dict):
        raise ValueError("'profiles' must be a YAML mapping of named profiles.")
    if profile:
        if profile not in profiles:
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
