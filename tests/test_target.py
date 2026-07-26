from __future__ import annotations

import pytest

from sentinel.target import TargetValidationError, normalize_target, same_host


def test_normalizes_bare_domain() -> None:
    target = normalize_target("Example.COM/docs")

    assert target.url == "https://example.com/docs"
    assert target.origin == "https://example.com"


def test_rejects_private_ip_without_explicit_lab_flag() -> None:
    with pytest.raises(TargetValidationError, match="Private or reserved"):
        normalize_target("http://127.0.0.1")


def test_allows_private_ip_for_explicit_lab_scan() -> None:
    assert normalize_target("http://127.0.0.1:8080", allow_private=True).port == 8080


def test_exact_host_scope_does_not_accept_subdomain() -> None:
    target = normalize_target("example.com")

    assert same_host("https://example.com/path", target)
    assert not same_host("https://api.example.com/path", target)
