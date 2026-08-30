from __future__ import annotations

from sentinel.config import ScanConfig
from sentinel.models import Severity
from sentinel.modules.base import ScanContext
from sentinel.modules.external_tools import (
    FfufModule,
    NmapModule,
    NucleiModule,
    SubfinderModule,
)
from sentinel.target import normalize_target


def _context(**config_overrides: object) -> ScanContext:
    config = ScanConfig(**config_overrides)
    return ScanContext(
        target=normalize_target("https://example.com"),
        config=config,
        http=object(),  # type: ignore[arg-type]
    )


async def test_external_modules_are_disabled_by_default() -> None:
    from sentinel.modules.external_tools import AmassModule

    for module in (SubfinderModule(), AmassModule(), NmapModule(), NucleiModule(), FfufModule()):
        result = await module.run(_context())
        assert result.data["enabled"] is False


async def test_missing_binary_is_reported_as_an_error(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: None)

    result = await SubfinderModule().run(_context(enable_subfinder=True))

    assert result.data["enabled"] is True
    assert any("not found on PATH" in error for error in result.errors)


async def test_ffuf_requires_a_wordlist() -> None:
    result = await FfufModule().run(_context(enable_ffuf=True))

    assert any("requires --wordlist" in error for error in result.errors)


def test_subfinder_output_parser_filters_and_deduplicates() -> None:
    output = "\n".join(
        [
            "app.example.com",
            "api.example.com",
            "app.example.com",
            "https://other.example.net",
            "",
            "192.0.2.10",
        ]
    )

    assert SubfinderModule._parse_subdomain_lines(output, "example.com") == [
        "api.example.com",
        "app.example.com",
    ]


def test_nmap_xml_parser_extracts_hosts_and_ports() -> None:
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <address addr="192.0.2.10" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="443">
            <state state="open"/>
            <service name="https" product="nginx" version="1.24.0"/>
          </port>
          <port protocol="tcp" portid="22">
            <state state="closed"/>
          </port>
        </ports>
      </host>
    </nmaprun>"""

    hosts = NmapModule._parse_nmap_xml(xml)

    assert hosts == [
        {
            "address": "192.0.2.10",
            "ports": [
                {
                    "port": "443",
                    "protocol": "tcp",
                    "state": "open",
                    "service": "https",
                    "product": "nginx",
                    "version": "1.24.0",
                },
                {
                    "port": "22",
                    "protocol": "tcp",
                    "state": "closed",
                    "service": "",
                    "product": "",
                    "version": "",
                },
            ],
        }
    ]


def test_nuclei_jsonl_parser_and_severity_mapping() -> None:
    output = "\n".join(
        [
            "",
            '{"template-id":"exposed-panel","info":{"name":"Exposed Panel",'
            '"severity":"medium","description":"A panel is exposed."},'
            '"matched-at":"https://example.com/admin"}',
            "not-json",
        ]
    )

    results = NucleiModule._parse_nuclei_jsonl(output)

    assert len(results) == 1
    finding = NucleiModule._finding(results[0])
    assert finding.title == "[nuclei] Exposed Panel"
    assert finding.severity == Severity.MEDIUM
    assert finding.url == "https://example.com/admin"
    assert NucleiModule._nuclei_severity("critical") == Severity.HIGH
    assert NucleiModule._nuclei_severity("unknown") == Severity.INFO


def test_ffuf_output_parser_extracts_status_and_path() -> None:
    output = "\n".join(
        [
            ":: Progress: [10/100] :: Job [1/1] :: 0 req/sec ::",
            "[Status: 200, Size: 123, Words: 5, Lines: 3, Duration: 50ms] /admin",
            "[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 20ms] /login",
        ]
    )

    discovered = FfufModule._parse_ffuf_output(output, "https://example.com")

    assert discovered == [
        {"path": "/admin", "url": "https://example.com/admin", "status_code": "200"},
        {"path": "/login", "url": "https://example.com/login", "status_code": "301"},
    ]
