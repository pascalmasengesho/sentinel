"""Opt-in adapters for trusted, locally installed reconnaissance tools.

Every adapter is disabled by default and only runs when the corresponding
``enable_*`` configuration flag is selected. The tools are invoked as local
subprocesses with bounded timeouts; their raw output is parsed into the normal
Sentinel report model. Results remain observations and never override the
scope or rate decisions already enforced by Sentinel.

Security note: these binaries run arbitrary local code. Install and trust them
the same way you would trust a plugin, and never point Sentinel at a target
without explicit authorization.
"""

from __future__ import annotations

import asyncio
import json
import re
import shlex
import shutil
import xml.etree.ElementTree as ElementTree
from typing import Any
from urllib.parse import urljoin

from sentinel.models import Finding, ModuleResult, Severity
from sentinel.modules.base import ScanContext, ScanModule

_SUBDOMAIN_CAP = 500
_NUCLEI_FINDING_CAP = 200
_FFUF_LINE_PATTERN = re.compile(r"\[Status:\s*(?P<status>\d+)[^\]]*\]\s+(?P<path>\S+)")


async def run_external_tool(
    binary: str, args: list[str], timeout_seconds: float
) -> tuple[int | None, str, str]:
    """Run a local tool with a bounded timeout and return (code, stdout, stderr)."""
    executable = shutil.which(binary)
    if executable is None:
        return None, "", f"{binary} was not found on PATH."
    try:
        process = await asyncio.create_subprocess_exec(
            executable,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        return None, "", f"{binary} could not be executed: {exc}"
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
    except TimeoutError:
        process.kill()
        await process.communicate()
        return None, "", f"{binary} timed out after {timeout_seconds:.0f} seconds."
    return (
        process.returncode,
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
    )


def _disabled(module: str, flag: str) -> ModuleResult:
    return ModuleResult(
        module=module,
        data={"enabled": False, "reason": f"Enable it with {flag} to invoke this local tool."},
    )


def _split_args(raw: str) -> list[str]:
    return shlex.split(raw.strip()) if raw.strip() else []


class SubfinderModule(ScanModule):
    """Passive subdomain discovery through the local ``subfinder`` binary."""

    name = "subfinder"

    async def run(self, context: ScanContext) -> ModuleResult:
        if not context.config.enable_subfinder:
            return _disabled(self.name, "--subfinder")
        code, stdout, stderr = await run_external_tool(
            "subfinder",
            [*_split_args(context.config.subfinder_args), "-d", context.target.host],
            context.config.external_timeout_seconds,
        )
        subdomains = self._parse_subdomain_lines(stdout, context.target.host)
        errors = [stderr.strip()] if code != 0 and stderr.strip() else []
        if code is None:
            errors = [stderr.strip()]
        return ModuleResult(
            module=self.name,
            data={
                "enabled": True,
                "binary": "subfinder",
                "subdomains": subdomains,
                "count": len(subdomains),
                "note": "Passive subdomain collection by a trusted local tool.",
            },
            errors=errors,
        )

    @staticmethod
    def _parse_subdomain_lines(stdout: str, host: str) -> list[str]:
        host_suffix = host.lower().rstrip(".")
        values = {
            line.strip().lower().rstrip(".")
            for line in stdout.splitlines()
            if line.strip().lower().rstrip(".").endswith(host_suffix)
            and " " not in line.strip()
            and ":" not in line.strip()
        }
        return sorted(values)[:_SUBDOMAIN_CAP]


class AmassModule(ScanModule):
    """Passive subdomain discovery through the local ``amass`` binary."""

    name = "amass"

    async def run(self, context: ScanContext) -> ModuleResult:
        if not context.config.enable_amass:
            return _disabled(self.name, "--amass")
        code, stdout, stderr = await run_external_tool(
            "amass",
            [*_split_args(context.config.amass_args), "-d", context.target.host],
            context.config.external_timeout_seconds,
        )
        subdomains = self._parse_subdomain_lines(stdout, context.target.host)
        errors = [stderr.strip()] if code != 0 and stderr.strip() else []
        if code is None:
            errors = [stderr.strip()]
        return ModuleResult(
            module=self.name,
            data={
                "enabled": True,
                "binary": "amass",
                "subdomains": subdomains,
                "count": len(subdomains),
                "note": "Passive subdomain collection by a trusted local tool.",
            },
            errors=errors,
        )

    @staticmethod
    def _parse_subdomain_lines(stdout: str, host: str) -> list[str]:
        host_suffix = host.lower().rstrip(".")
        values = {
            line.strip().lower().rstrip(".")
            for line in stdout.splitlines()
            if line.strip().lower().rstrip(".").endswith(host_suffix)
            and " " not in line.strip()
            and ":" not in line.strip()
        }
        return sorted(values)[:_SUBDOMAIN_CAP]


class NmapModule(ScanModule):
    """Service/version discovery through the local ``nmap`` binary."""

    name = "nmap"

    async def run(self, context: ScanContext) -> ModuleResult:
        if not context.config.enable_nmap:
            return _disabled(self.name, "--nmap")
        ports = ",".join(str(port) for port in context.config.ports)
        code, stdout, stderr = await run_external_tool(
            "nmap",
            [*_split_args(context.config.nmap_args), "-oX", "-", "-p", ports, context.target.host],
            context.config.external_timeout_seconds,
        )
        hosts = self._parse_nmap_xml(stdout)
        errors = [stderr.strip()] if code != 0 and stderr.strip() else []
        if code is None:
            errors = [stderr.strip()]
        open_ports = [
            {"host": host["address"], "port": port}
            for host in hosts
            for port in host["ports"]
            if port["state"] == "open"
        ]
        return ModuleResult(
            module=self.name,
            data={
                "enabled": True,
                "binary": "nmap",
                "hosts": hosts,
                "open_ports": open_ports,
                "note": (
                    "nmap service observations are unverified and limited to the exact "
                    "authorized host."
                ),
            },
            errors=errors,
        )

    @staticmethod
    def _parse_nmap_xml(xml_text: str) -> list[dict[str, Any]]:
        try:
            root = ElementTree.fromstring(xml_text)
        except ElementTree.ParseError:
            return []
        hosts: list[dict[str, Any]] = []
        for host in root.findall(".//host"):
            address_element = host.find("address")
            address = address_element.get("addr", "") if address_element is not None else ""
            if not address:
                continue
            ports = []
            for port in host.findall(".//ports/port"):
                state = port.find("state")
                service = port.find("service")
                ports.append(
                    {
                        "port": port.get("portid", ""),
                        "protocol": port.get("protocol", ""),
                        "state": state.get("state", "") if state is not None else "",
                        "service": service.get("name", "") if service is not None else "",
                        "product": service.get("product", "") if service is not None else "",
                        "version": service.get("version", "") if service is not None else "",
                    }
                )
            hosts.append({"address": address, "ports": ports})
        return hosts


class NucleiModule(ScanModule):
    """Template-based scanning through the local ``nuclei`` binary.

    Only the configured severity/tag set is passed to nuclei. The default tag
    set (exposure, misconfig) avoids credential and exploit categories; users
    can broaden it through the YAML configuration.
    """

    name = "nuclei"

    async def run(self, context: ScanContext) -> ModuleResult:
        if not context.config.enable_nuclei:
            return _disabled(self.name, "--nuclei")
        args = [
            *_split_args(context.config.nuclei_args),
            "-u",
            context.target.url,
            "-jsonl",
            "-severity",
            context.config.nuclei_severity,
            "-tags",
            context.config.nuclei_tags,
            "-rl",
            str(max(1, int(context.config.rate_limit_per_second))),
            "-c",
            str(context.config.concurrency),
        ]
        if context.config.nuclei_templates:
            args.extend(["-t", context.config.nuclei_templates])
        code, stdout, stderr = await run_external_tool(
            "nuclei", args, context.config.external_timeout_seconds
        )
        results = self._parse_nuclei_jsonl(stdout)
        errors = [stderr.strip()] if code != 0 and stderr.strip() else []
        if code is None:
            errors = [stderr.strip()]
        findings = [self._finding(result) for result in results[:_NUCLEI_FINDING_CAP]]
        return ModuleResult(
            module=self.name,
            data={
                "enabled": True,
                "binary": "nuclei",
                "results": results,
                "result_count": len(results),
                "note": (
                    "nuclei results are template observations, not confirmed "
                    "vulnerabilities. Validate every match manually in scope."
                ),
            },
            findings=findings,
            errors=errors,
        )

    @staticmethod
    def _parse_nuclei_jsonl(stdout: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                results.append(parsed)
        return results

    @classmethod
    def _finding(cls, result: dict[str, Any]) -> Finding:
        info = result.get("info", {}) if isinstance(result.get("info"), dict) else {}
        template_id = str(result.get("template-id", "unknown-template"))
        name = str(info.get("name") or template_id)
        severity = cls._nuclei_severity(str(info.get("severity", "info")))
        matched = str(result.get("matched-at", ""))
        return Finding(
            title=f"[nuclei] {name}",
            severity=severity,
            description=str(info.get("description") or f"Template observation {template_id}."),
            evidence=f"Template: {template_id}; matched-at: {matched or 'unknown'}",
            recommendation="Reproduce manually within the program's scope before reporting.",
            module="nuclei",
            url=matched,
        )

    @staticmethod
    def _nuclei_severity(level: str) -> Severity:
        normalized = level.strip().lower()
        if normalized == "critical":
            return Severity.HIGH
        if normalized in {"high", "medium", "low", "info"}:
            return Severity(normalized)
        return Severity.INFO


class FfufModule(ScanModule):
    """Content discovery through the local ``ffuf`` binary.

    Ffuf is pointed only at ``<origin>/FUZZ`` with the configured match codes,
    concurrency, and shared rate limit.
    """

    name = "ffuf"

    async def run(self, context: ScanContext) -> ModuleResult:
        if not context.config.enable_ffuf:
            return _disabled(self.name, "--ffuf")
        wordlist = context.config.ffuf_wordlist_path or context.config.wordlist_path
        if not wordlist:
            return ModuleResult(
                module=self.name,
                errors=["ffuf requires --wordlist or a configured ffuf_wordlist_path."],
            )
        fuzz_url = context.target.origin + "/FUZZ"
        args = [
            *_split_args(context.config.ffuf_args),
            "-u",
            fuzz_url,
            "-w",
            wordlist,
            "-mc",
            context.config.ffuf_match_codes,
            "-t",
            str(context.config.concurrency),
            "-rate",
            str(max(1, int(context.config.rate_limit_per_second))),
        ]
        code, stdout, stderr = await run_external_tool(
            "ffuf", args, context.config.external_timeout_seconds
        )
        discovered = self._parse_ffuf_output(stdout, context.target.origin)
        errors = [stderr.strip()] if code != 0 and stderr.strip() else []
        if code is None:
            errors = [stderr.strip()]
        return ModuleResult(
            module=self.name,
            data={
                "enabled": True,
                "binary": "ffuf",
                "fuzz_url": fuzz_url,
                "wordlist": wordlist,
                "discovered_paths": discovered,
                "count": len(discovered),
                "note": "ffuf results are unverified path observations from the exact host.",
            },
            errors=errors,
        )

    @staticmethod
    def _parse_ffuf_output(stdout: str, origin: str) -> list[dict[str, str]]:
        discovered: list[dict[str, str]] = []
        seen: set[str] = set()
        for line in stdout.splitlines():
            match = _FFUF_LINE_PATTERN.search(line)
            if not match:
                continue
            path = match.group("path")
            if path in seen:
                continue
            seen.add(path)
            discovered.append(
                {
                    "path": path,
                    "url": urljoin(origin + "/", path.lstrip("/")),
                    "status_code": match.group("status"),
                }
            )
        return discovered
