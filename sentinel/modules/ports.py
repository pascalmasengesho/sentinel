"""Small, configurable TCP-connect scan for authorized targets."""

from __future__ import annotations

import asyncio
from contextlib import suppress

from sentinel.models import ModuleResult
from sentinel.modules.base import ScanContext, ScanModule

_COMMON_SERVICES = {
    22: "ssh",
    80: "http",
    443: "https",
    3000: "http-alt",
    5000: "http-alt",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
}


class PortModule(ScanModule):
    """Perform bounded TCP connection attempts; no UDP or exploit probes are used."""

    name = "ports"

    async def run(self, context: ScanContext) -> ModuleResult:
        if not context.config.enable_port_scan:
            return ModuleResult(module=self.name, data={"enabled": False})
        semaphore = asyncio.Semaphore(context.config.concurrency)
        tasks = [self._probe(context, port, semaphore) for port in context.config.ports]
        outcomes = await asyncio.gather(*tasks)
        open_ports = [outcome for outcome in outcomes if outcome is not None]
        return ModuleResult(
            module=self.name,
            data={"enabled": True, "ports_checked": context.config.ports, "open_ports": open_ports},
        )

    async def _probe(
        self, context: ScanContext, port: int, semaphore: asyncio.Semaphore
    ) -> dict[str, str | int] | None:
        async with semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(context.target.host, port),
                    timeout=context.config.timeout_seconds,
                )
            except (TimeoutError, OSError):
                return None
            banner = ""
            if context.config.enable_banner_grab:
                with suppress(TimeoutError, OSError):
                    banner_bytes = await asyncio.wait_for(reader.read(256), timeout=1)
                    banner = banner_bytes.decode("utf-8", errors="replace").strip()
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()
            result: dict[str, str | int] = {
                "port": port,
                "service": _COMMON_SERVICES.get(port, "unknown"),
            }
            if banner:
                result["banner"] = banner
            return result
