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
