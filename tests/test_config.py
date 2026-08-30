from __future__ import annotations

import pytest

from sentinel.config import ScanConfig, apply_overrides


def test_applies_safe_cli_override() -> None:
    config = apply_overrides(ScanConfig(), {"rate_limit_per_second": 0.5})

    assert config.rate_limit_per_second == 0.5


def test_rejects_unsafe_rate_override() -> None:
    with pytest.raises(ValueError, match="rate_limit"):
        apply_overrides(ScanConfig(), {"rate_limit_per_second": 99})


def test_public_artifact_checks_are_opt_in() -> None:
    config = apply_overrides(ScanConfig(), {"enable_public_artifact_checks": True})

    assert config.enable_public_artifact_checks


def test_rejects_an_unbounded_safe_crawl_page_limit() -> None:
    with pytest.raises(ValueError, match="max_crawl_pages"):
        apply_overrides(ScanConfig(), {"max_crawl_pages": 101})


def test_rejects_malformed_yaml_types_with_clean_value_errors(tmp_path) -> None:
    from sentinel.config import load_config

    manifest = tmp_path / "config.yaml"
    manifest.write_text("ports: '80,443'\ntimeout_seconds: '8'\n", encoding="utf-8")

    with pytest.raises(ValueError, match="timeout_seconds"):
        load_config(manifest)

    manifest.write_text("ports: '80,443'\n", encoding="utf-8")

    with pytest.raises(ValueError, match="ports"):
        load_config(manifest)


def test_rejects_non_mapping_profiles(tmp_path) -> None:
    from sentinel.config import load_config

    manifest = tmp_path / "config.yaml"
    manifest.write_text("profiles: passive\n", encoding="utf-8")

    with pytest.raises(ValueError, match="profiles"):
        load_config(manifest)


def test_validates_js_and_sitemap_bounds() -> None:
    with pytest.raises(ValueError, match="max_js_files"):
        apply_overrides(ScanConfig(), {"max_js_files": 0})
    with pytest.raises(ValueError, match="max_sitemap_urls"):
        apply_overrides(ScanConfig(), {"max_sitemap_urls": 10_001})
