from __future__ import annotations

import pytest

from sentinel.config import ScanConfig
from sentinel.http_client import RequestBlockedError, SafeHttpClient
from sentinel.scope import ScopeManifest, ScopeValidationError, load_scope_manifest
from sentinel.target import normalize_target


def _scope() -> ScopeManifest:
    return ScopeManifest(
        name="Example program",
        allowed_hosts=("example.com", "*.example.com"),
        targets=("https://app.example.com",),
        excluded_hosts=("status.example.com",),
        excluded_paths=("/admin", "/internal"),
        rate_limit_per_second=0.5,
    )


def test_scope_allows_wildcard_subdomains_and_blocks_exclusions() -> None:
    scope = _scope()

    assert scope.allows_url("https://app.example.com/docs")
    assert scope.allows_url("https://example.com/")
    assert not scope.allows_url("https://status.example.com/")
    assert not scope.allows_url("https://app.example.com/admin/users")
    assert not scope.allows_url("https://third-party.example/")


def test_scope_rejects_a_target_outside_the_allow_list() -> None:
    with pytest.raises(ScopeValidationError, match="outside"):
        _scope().assert_target_allowed(normalize_target("https://other.example"))


def test_scope_caps_the_configured_request_rate() -> None:
    config = ScanConfig(rate_limit_per_second=2.0)

    assert _scope().constrained_config(config).rate_limit_per_second == 0.5
    assert config.rate_limit_per_second == 2.0


def test_scope_manifest_requires_a_nonempty_allow_list(tmp_path) -> None:
    manifest = tmp_path / "scope.yaml"
    manifest.write_text("name: Empty\nallowed_hosts: []\n", encoding="utf-8")

    with pytest.raises(ScopeValidationError, match="allowed_hosts"):
        load_scope_manifest(manifest)


def test_scope_manifest_normalizes_and_validates_batch_targets(tmp_path) -> None:
    manifest = tmp_path / "scope.yaml"
    manifest.write_text(
        """name: Example
allowed_hosts: [example.com, '*.example.com']
targets: [app.example.com, https://api.example.com]
rate_limit_per_second: 0.5
""",
        encoding="utf-8",
    )

    scope = load_scope_manifest(manifest)

    assert [target.url for target in scope.normalized_targets()] == [
        "https://app.example.com/",
        "https://api.example.com/",
    ]


def test_http_client_enforces_scope_path_exclusions_before_request() -> None:
    target = normalize_target("https://app.example.com")
    client = SafeHttpClient(target, ScanConfig(), scope=_scope())

    with pytest.raises(RequestBlockedError, match="scope manifest"):
        client._validate_url("https://app.example.com/admin/users")
