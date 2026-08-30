"""Sequential, manifest-driven scans for authorized target sets."""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.config import ScanConfig
from sentinel.models import ScanReport
from sentinel.scanner import Scanner
from sentinel.scope import ScopeManifest, ScopeValidationError
from sentinel.target import Target


@dataclass(frozen=True, slots=True)
class BatchScanResult:
    """One completed report paired with its normalized manifest target."""

    target: Target
    report: ScanReport


class BatchScanner:
    """Scan explicit manifest targets one at a time under the manifest rate cap.

    Sequential execution is intentional: it gives program rate limits precedence
    over throughput and prevents separate per-host worker pools from amplifying
    traffic across an authorized program.
    """

    def __init__(self, scope: ScopeManifest, config: ScanConfig, authorized: bool) -> None:
        if not authorized:
            raise PermissionError(
                "Sentinel requires --authorized before it makes network requests."
            )
        self.scope = scope
        self.config = scope.constrained_config(config)
        self.authorized = authorized

    async def scan(self) -> list[BatchScanResult]:
        """Run every explicit, in-scope manifest target in deterministic order."""
        targets = self.scope.normalized_targets(allow_private=self.config.allow_private)
        if not targets:
            raise ScopeValidationError(
                "Batch scans require at least one target in the scope manifest."
            )
        results: list[BatchScanResult] = []
        for target in targets:
            report = await Scanner(
                target.url, self.config, authorized=self.authorized, scope=self.scope
            ).scan()
            results.append(BatchScanResult(target=target, report=report))
        return results
