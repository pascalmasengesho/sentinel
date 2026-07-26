"""Typer command-line interface for Sentinel."""

from __future__ import annotations

import asyncio
from dataclasses import asdict
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from sentinel.config import ScanConfig, apply_overrides, load_config
from sentinel.reports import ReportFormat, ReportWriter
from sentinel.scanner import Scanner

app = typer.Typer(
    add_completion=False,
    help="Sentinel: safe, rate-limited reconnaissance for authorized security assessments.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    target: Annotated[
        str, typer.Argument(help="A domain, subdomain, or HTTP(S) URL in your authorized scope.")
    ],
    authorized: Annotated[
        bool,
        typer.Option(
            "--authorized",
            help="Required acknowledgement that you are authorized to assess this target.",
        ),
    ] = False,
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Output file (suffix is optional).")
    ] = Path("reports/sentinel-report"),
    report_format: Annotated[
        ReportFormat, typer.Option("--format", "-f", case_sensitive=False)
    ] = ReportFormat.JSON,
    config_path: Annotated[
        Path | None, typer.Option("--config", help="YAML configuration file.")
    ] = None,
    profile: Annotated[
        str | None, typer.Option("--profile", help="Named profile in the YAML configuration.")
    ] = None,
    timeout: Annotated[
        float | None, typer.Option("--timeout", min=0.1, help="Request timeout in seconds.")
    ] = None,
    concurrency: Annotated[int | None, typer.Option("--concurrency", min=1, max=20)] = None,
    rate: Annotated[
        float | None,
        typer.Option("--rate", min=0.1, max=10.0, help="Maximum request starts per second."),
    ] = None,
    ports: Annotated[
        str | None, typer.Option("--ports", help="Comma-separated TCP ports, e.g. 80,443,8080.")
    ] = None,
    no_port_scan: Annotated[
        bool, typer.Option("--no-port-scan", help="Disable bounded TCP-connect scanning.")
    ] = False,
    banners: Annotated[
        bool,
        typer.Option("--banners", help="Read a small banner only if the service sends one first."),
    ] = False,
    passive_subdomains: Annotated[
        bool,
        typer.Option("--passive-subdomains", help="Query crt.sh, a third-party public CT index."),
    ] = False,
    api_probe: Annotated[
        bool, typer.Option("--api-probe", help="Check four conventional public API-doc paths.")
    ] = False,
    content_discovery: Annotated[
        bool,
        typer.Option("--content-discovery", help="Enable wordlist paths at the configured rate."),
    ] = False,
    wordlist: Annotated[
        Path | None, typer.Option("--wordlist", help="Wordlist required for --content-discovery.")
    ] = None,
    allow_private: Annotated[
        bool, typer.Option("--allow-private", help="Permit private/IP lab targets only.")
    ] = False,
    plugins_dir: Annotated[
        Path | None, typer.Option("--plugins-dir", help="Trusted local plugin directory.")
    ] = None,
) -> None:
    """Run non-destructive checks against an explicitly authorized target."""
    if not authorized:
        raise typer.BadParameter("--authorized is required before Sentinel makes network requests.")
    try:
        config = load_config(config_path, profile)
        parsed_ports = [int(item.strip()) for item in ports.split(",")] if ports else None
        config = apply_overrides(
            config,
            {
                "timeout_seconds": timeout,
                "concurrency": concurrency,
                "rate_limit_per_second": rate,
                "ports": parsed_ports,
                "enable_port_scan": False if no_port_scan else None,
                "enable_banner_grab": True if banners else None,
                "enable_passive_subdomains": True if passive_subdomains else None,
                "enable_public_api_probe": True if api_probe else None,
                "enable_content_discovery": True if content_discovery else None,
                "wordlist_path": str(wordlist) if wordlist else None,
                "allow_private": True if allow_private else None,
                "plugin_directory": str(plugins_dir) if plugins_dir else None,
            },
        )
        if content_discovery and not wordlist:
            raise ValueError("--content-discovery requires --wordlist.")
        scanner = Scanner(target, config, authorized=True)
    except (ValueError, OSError, PermissionError) as exc:
        console.print(f"[bold red]Configuration error:[/] {exc}")
        raise typer.Exit(code=2) from exc

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console
    ) as progress:
        progress.add_task("Running safe, rate-limited assessment checks…", total=None)
        report = asyncio.run(scanner.scan())
    path = ReportWriter().write(report, output, report_format)
    _print_summary(report.statistics, path)


@app.command("config")
def show_config() -> None:
    """Print the default configuration keys and conservative values."""
    for key, value in asdict(ScanConfig()).items():
        console.print(f"{key}: {value}")


def _print_summary(statistics: dict[str, int], path: Path) -> None:
    table = Table(title="Sentinel complete")
    table.add_column("Modules", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Errors", justify="right")
    table.add_column("Report")
    table.add_row(
        str(statistics.get("modules_run", 0)),
        str(statistics.get("findings", 0)),
        str(statistics.get("errors", 0)),
        str(path),
    )
    console.print(table)
