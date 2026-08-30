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
    CrawlerModule,
    DnsModule,
    EmailSecurityModule,
    HeaderModule,
    HttpModule,
    JavaScriptModule,
    PortModule,
    PublicArtifactModule,
    ReconModule,
    RobotsModule,
    SitemapModule,
    SurfaceModule,
    TakeoverModule,
    TechnologyModule,
    TlsModule,
    WordlistModule,
)
from sentinel.modules.base import ScanContext, ScanModule
from sentinel.plugins import load_plugins
from sentinel.prioritization import build_research_priorities
from sentinel.scope import ScopeManifest
from sentinel.target import Target, normalize_target


class Scanner:
    """Run ordered module stages and return a complete, renderable report."""

    def __init__(
        self,
        target: str,
        config: ScanConfig,
        authorized: bool,
        scope: ScopeManifest | None = None,
    ) -> None:
        if not authorized:
            raise PermissionError(
                "Sentinel requires --authorized before it makes network requests."
            )
        config.validate()
        self.target: Target = normalize_target(target, allow_private=config.allow_private)
        if scope:
            scope.assert_target_allowed(self.target)
        self.config = config
        self.authorized = authorized
        self.scope = scope

    async def scan(self) -> ScanReport:
        """Run the selected modules while preserving useful partial results on failure."""
        report = ScanReport.create(self.target.url, self.authorized, __version__)
        if self.scope:
            report.modules.append(
                ModuleResult(module="scope", data=self.scope.report_data(self.target))
            )
        async with SafeHttpClient(self.target, self.config, scope=self.scope) as http:
            context = ScanContext(
                target=self.target, config=self.config, http=http, scope=self.scope
            )
            first_stage: list[ScanModule] = [
                DnsModule(),
                EmailSecurityModule(),
                HttpModule(),
                TlsModule(),
                PortModule(),
            ]
            report.modules.extend(await self._run_stage(first_stage, context))

            # These read the root response/robots output, so preserving this order
            # avoids duplicate traffic and lets each module report a clean skip.
            second_stage: list[ScanModule] = [
                ReconModule(),
                HeaderModule(),
                TechnologyModule(),
                SurfaceModule(),
                RobotsModule(),
            ]
            report.modules.extend(await self._run_stage(second_stage, context))
            report.modules.extend(await self._run_stage([TakeoverModule()], context))
            report.modules.extend(await self._run_stage([SitemapModule()], context))
            report.modules.extend(await self._run_stage([CrawlerModule()], context))
            final_stage: list[ScanModule] = [
                JavaScriptModule(),
                ApiDiscoveryModule(),
                WordlistModule(),
            ]
            if self.config.enable_public_artifact_checks:
                final_stage.append(PublicArtifactModule())
            report.modules.extend(await self._run_stage(final_stage, context))

            plugins, plugin_errors = load_plugins(self.config.plugin_directory)
            if plugin_errors:
                report.modules.append(ModuleResult(module="plugins", errors=plugin_errors))
            if plugins:
                report.modules.extend(await self._run_stage(plugins, context))

            report.modules.append(build_research_priorities(report.modules))

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
