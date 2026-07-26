from __future__ import annotations

import pytest

from sentinel.config import ScanConfig
from sentinel.scanner import Scanner


def test_scanner_requires_explicit_authorization() -> None:
    with pytest.raises(PermissionError, match="--authorized"):
        Scanner("example.com", ScanConfig(), authorized=False)
