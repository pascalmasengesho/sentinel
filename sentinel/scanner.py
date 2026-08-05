"""Orchestration of Sentinel's staged, non-destructive checks."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from sentinel import __version__
from sentinel.config import ScanConfig
from sentinel.http_client import SafeHttpClient
from sentinel.models import ModuleResult, ScanReport
from sentinel.modules import (
    ApiDiscoveryModule,
    DnsModule,
    HeaderModule,
    HttpModule,
    JavaScriptModule,
    PortModule,
    PublicArtifactModule,
    ReconModule,
    RobotsModule,
    SitemapModule,
    TechnologyModule,
    TlsModule,
    WordlistModule,
)
from sentinel.modules.base import ScanContext, ScanModule
from sentinel.plugins import load_plugins
from sentinel.target import Target, normalize_target


class Scanner:
    """Run ordered module stages and return a complete, renderable report."""

    def __init__(self, target: str, config: ScanConfig, authorized: bool) -> None:
        if not authorized:
            raise PermissionError(
                "Sentinel requires --authorized before it makes network requests."
            )
        config.validate()
        self.target: Target = normalize_target(target, allow_private=config.allow_private)
        self.config = config
        self.authorized = authorized

    async def scan(self) -> ScanReport:
        """Run the selected modules while preserving useful partial results on failure."""
        report = ScanReport.create(self.target.url, self.authorized, __version__)
        async with SafeHttpClient(self.target, self.config) as http:
            context = ScanContext(target=self.target, config=self.config, http=http)
            first_stage: list[ScanModule] = [DnsModule(), HttpModule(), TlsModule(), PortModule()]
            report.modules.extend(await self._run_stage(first_stage, context))

            # These read the root response/robots output, so preserving this order
            # avoids duplicate traffic and lets each module report a clean skip.
            second_stage: list[ScanModule] = [
                ReconModule(),
                HeaderModule(),
                TechnologyModule(),
                RobotsModule(),
                JavaScriptModule(),
            ]
            report.modules.extend(await self._run_stage(second_stage, context))
            report.modules.extend(await self._run_stage([SitemapModule()], context))
            final_stage: list[ScanModule] = [ApiDiscoveryModule(), WordlistModule()]
            if self.config.enable_public_artifact_checks:
                final_stage.append(PublicArtifactModule())
            report.modules.extend(await self._run_stage(final_stage, context))

            plugins, plugin_errors = load_plugins(self.config.plugin_directory)
            if plugin_errors:
                report.modules.append(ModuleResult(module="plugins", errors=plugin_errors))
            if plugins:
                report.modules.extend(await self._run_stage(plugins, context))

        report.finished_at = datetime.now(UTC).isoformat()
        report.statistics = self._statistics(report)
        return report

    @staticmethod
    async def _run_stage(modules: list[ScanModule], context: ScanContext) -> list[ModuleResult]:
        return list(await asyncio.gather(*(module.execute(context) for module in modules)))

    @staticmethod
    def _statistics(report: ScanReport) -> dict[str, int]:
        findings = [finding for module in report.modules for finding in module.findings]
        errors = [error for module in report.modules for error in module.errors]
        return {
            "modules_run": len(report.modules),
            "findings": len(findings),
            "errors": len(errors),
            "high": sum(finding.severity == "high" for finding in findings),
            "medium": sum(finding.severity == "medium" for finding in findings),
            "low": sum(finding.severity == "low" for finding in findings),
            "info": sum(finding.severity == "info" for finding in findings),
        }
