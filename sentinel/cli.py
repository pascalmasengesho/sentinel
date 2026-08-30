"""Typer command-line interface for Sentinel."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from dataclasses import asdict
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from sentinel.asset_probe import AssetProbeEngine
from sentinel.asset_state import AssetDelta, AssetStateStore
from sentinel.batch import BatchScanner
from sentinel.config import ScanConfig, apply_overrides, load_config
from sentinel.models import ScanReport
from sentinel.reports import ReportFormat, ReportWriter
from sentinel.scanner import Scanner
from sentinel.scope import ScopeValidationError, load_scope_manifest
from sentinel.workspace import WorkspaceStore

app = typer.Typer(
    add_completion=False,
    help="Sentinel: safe, rate-limited reconnaissance for authorized security assessments.",
    invoke_without_command=True,
    no_args_is_help=True,
)
console = Console()
workspace_app = typer.Typer(
    help="Inspect local, authorized-assessment research workspaces.",
    no_args_is_help=True,
)
report_app = typer.Typer(
    help="Render existing Sentinel JSON reports without rescanning a target.",
    no_args_is_help=True,
)
app.add_typer(workspace_app, name="workspace")
app.add_typer(report_app, name="report")


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", help="Show the installed Sentinel version and exit."),
    ] = False,
) -> None:
    """Sentinel: safe, rate-limited reconnaissance for authorized assessments."""
    if version:
        from sentinel import __version__

        console.print(__version__)
        raise typer.Exit()


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
    scope_file: Annotated[
        Path | None,
        typer.Option("--scope", help="Optional YAML scope manifest that Sentinel enforces."),
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
    whois: Annotated[
        bool,
        typer.Option(
            "--whois", help="Query public WHOIS servers for the target's registration metadata."
        ),
    ] = False,
    email_security: Annotated[
        bool,
        typer.Option(
            "--email-security/--no-email-security",
            help="Check published SPF/DMARC policies through passive DNS (enabled by default).",
        ),
    ] = True,
    takeover_check: Annotated[
        bool,
        typer.Option(
            "--takeover-check",
            help="Triage CT-discovered subdomains for takeover candidates (passive DNS only).",
        ),
    ] = False,
    api_probe: Annotated[
        bool, typer.Option("--api-probe", help="Check four conventional public API-doc paths.")
    ] = False,
    public_artifacts: Annotated[
        bool,
        typer.Option(
            "--public-artifacts",
            help="Read public favicon and security.txt files at the configured rate.",
        ),
    ] = False,
    crawl: Annotated[
        bool,
        typer.Option("--crawl", help="Enable bounded same-origin GET crawling."),
    ] = False,
    crawl_pages: Annotated[
        int | None, typer.Option("--crawl-pages", min=1, max=100, help="Maximum pages to crawl.")
    ] = None,
    crawl_depth: Annotated[
        int | None, typer.Option("--crawl-depth", min=1, max=4, help="Maximum crawl link depth.")
    ] = None,
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
    brand_name: Annotated[
        str, typer.Option("--brand-name", help="Brand name shown in HTML reports.")
    ] = "Sentinel",
    logo_url: Annotated[
        str,
        typer.Option(
            "--logo-url",
            help=(
                "Optional HTTP(S) logo URL shown in HTML reports; it is not fetched during "
                "scanning."
            ),
        ),
    ] = "",
    workspace: Annotated[
        Path | None,
        typer.Option(
            "--workspace",
            help="Optional local SQLite workspace used to retain this completed scan.",
        ),
    ] = None,
) -> None:
    """Run non-destructive checks against an explicitly authorized target."""
    if not authorized:
        raise typer.BadParameter("--authorized is required before Sentinel makes network requests.")
    try:
        scope = load_scope_manifest(scope_file) if scope_file else None
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
                "enable_whois": True if whois else None,
                "enable_email_security": email_security,
                "enable_takeover_check": True if takeover_check else None,
                "enable_public_api_probe": True if api_probe else None,
                "enable_public_artifact_checks": True if public_artifacts else None,
                "enable_safe_crawl": True if crawl else None,
                "max_crawl_pages": crawl_pages,
                "max_crawl_depth": crawl_depth,
                "enable_content_discovery": True if content_discovery else None,
                "wordlist_path": str(wordlist) if wordlist else None,
                "allow_private": True if allow_private else None,
                "plugin_directory": str(plugins_dir) if plugins_dir else None,
            },
        )
        if content_discovery and not wordlist:
            raise ValueError("--content-discovery requires --wordlist.")
        if (crawl_pages is not None or crawl_depth is not None) and not crawl:
            raise ValueError("--crawl-pages and --crawl-depth require --crawl.")
        if takeover_check and not passive_subdomains:
            raise ValueError("--takeover-check requires --passive-subdomains.")
        if scope:
            config = scope.constrained_config(config)
        scanner = Scanner(target, config, authorized=True, scope=scope)
    except (ScopeValidationError, TypeError, ValueError, OSError, PermissionError) as exc:
        console.print(f"[bold red]Configuration error:[/] {exc}")
        raise typer.Exit(code=2) from exc

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        disable=not _progress_is_enabled(console.is_interactive, console.legacy_windows),
    ) as progress:
        progress.add_task("Running safe, rate-limited assessment checks…", total=None)
        report = asyncio.run(scanner.scan())
    path = ReportWriter(
        brand_name=brand_name,
        logo_url=logo_url,
        config_snapshot=asdict(config),
    ).write(report, output, report_format)
    _print_summary(report.statistics, path)
    if workspace:
        try:
            scan_id = WorkspaceStore(workspace).save_scan(report, asdict(config))
        except (OSError, ValueError, sqlite3.Error) as exc:
            console.print(
                f"[yellow]Workspace warning:[/] Scan report was written, but not stored: {exc}"
            )
        else:
            console.print(f"[dim]Stored scan {scan_id} in local workspace {workspace}.[/]")


@app.command("batch")
def batch_scan(
    scope_file: Annotated[
        Path, typer.Argument(help="YAML scope manifest containing explicit targets.")
    ],
    authorized: Annotated[
        bool,
        typer.Option("--authorized", help="Required acknowledgement for every manifest target."),
    ] = False,
    output_dir: Annotated[
        Path, typer.Option("--output-dir", "-o", help="Directory for one report per target.")
    ] = Path("reports/batch"),
    report_format: Annotated[
        ReportFormat, typer.Option("--format", "-f", case_sensitive=False)
    ] = ReportFormat.JSON,
    config_path: Annotated[
        Path | None, typer.Option("--config", help="YAML scanner configuration file.")
    ] = None,
    profile: Annotated[
        str | None, typer.Option("--profile", help="Named profile in the YAML configuration.")
    ] = None,
    crawl: Annotated[
        bool, typer.Option("--crawl", help="Enable bounded same-origin GET crawling per target.")
    ] = False,
    workspace: Annotated[
        Path | None,
        typer.Option("--workspace", help="Optional SQLite workspace for completed scans."),
    ] = None,
    brand_name: Annotated[
        str, typer.Option("--brand-name", help="Brand name shown in HTML reports.")
    ] = "Sentinel",
    logo_url: Annotated[
        str, typer.Option("--logo-url", help="Optional HTTP(S) logo URL for HTML reports.")
    ] = "",
) -> None:
    """Scan explicit manifest targets sequentially under its rate limit."""
    if not authorized:
        raise typer.BadParameter("--authorized is required before Sentinel makes network requests.")
    try:
        scope = load_scope_manifest(scope_file)
        config = load_config(config_path, profile)
        config = apply_overrides(config, {"enable_safe_crawl": True if crawl else None})
        results = asyncio.run(BatchScanner(scope, config, authorized=True).scan())
    except (ScopeValidationError, TypeError, ValueError, OSError, PermissionError) as exc:
        console.print(f"[bold red]Batch configuration error:[/] {exc}")
        raise typer.Exit(code=2) from exc

    writer = ReportWriter(
        brand_name=brand_name,
        logo_url=logo_url,
        config_snapshot=asdict(scope.constrained_config(config)),
    )
    store = WorkspaceStore(workspace) if workspace else None
    for index, result in enumerate(results, start=1):
        path = writer.write(
            result.report,
            output_dir / _batch_report_stem(index, result.target.host),
            report_format,
        )
        _print_summary(result.report.statistics, path)
        if store:
            try:
                scan_id = store.save_scan(result.report, asdict(scope.constrained_config(config)))
            except (OSError, ValueError, sqlite3.Error) as exc:
                console.print(
                    f"[yellow]Workspace warning for {result.target.host}:[/] report was written, "
                    f"but not stored: {exc}"
                )
            else:
                console.print(f"[dim]Stored scan {scan_id} in local workspace {workspace}.[/]")


@app.command("monitor")
def monitor_assets(
    scope_file: Annotated[
        Path, typer.Argument(help="YAML scope manifest containing explicit targets.")
    ],
    authorized: Annotated[
        bool,
        typer.Option("--authorized", help="Required acknowledgement for every manifest target."),
    ] = False,
    state_path: Annotated[
        Path,
        typer.Option("--state", help="Local SQLite baseline database for asset observations."),
    ] = Path(".sentinel/assets.db"),
    config_path: Annotated[
        Path | None, typer.Option("--config", help="YAML scanner configuration file.")
    ] = None,
    profile: Annotated[
        str | None, typer.Option("--profile", help="Named profile in the YAML configuration.")
    ] = None,
    concurrency: Annotated[
        int | None, typer.Option("--concurrency", min=1, max=20, help="Concurrent probes.")
    ] = None,
    rate: Annotated[
        float | None,
        typer.Option("--rate", min=0.1, max=10.0, help="Shared maximum request starts per second."),
    ] = None,
) -> None:
    """Report only new/status/size changes for explicit authorized assets."""
    if not authorized:
        raise typer.BadParameter("--authorized is required before Sentinel makes network requests.")
    try:
        scope = load_scope_manifest(scope_file)
        config = apply_overrides(
            load_config(config_path, profile),
            {"concurrency": concurrency, "rate_limit_per_second": rate},
        )
        observations, failures = asyncio.run(AssetProbeEngine(scope, config).probe())
        deltas = AssetStateStore(state_path).record(scope.name, observations)
    except (
        ScopeValidationError,
        TypeError,
        ValueError,
        OSError,
        PermissionError,
        sqlite3.Error,
    ) as exc:
        console.print(f"[bold red]Monitor configuration error:[/] {exc}")
        raise typer.Exit(code=2) from exc

    console.print(_asset_delta_markdown(deltas))
    if failures:
        console.print(f"[yellow]Probe failures ({len(failures)}):[/]")
        for failure in failures:
            console.print(f"- {failure.target}: {failure.error}")


@app.command("config")
def show_config() -> None:
    """Print the default configuration keys and conservative values."""
    for key, value in asdict(ScanConfig()).items():
        console.print(f"{key}: {value}")


@report_app.command("render")
def report_render(
    source: Annotated[Path, typer.Argument(help="Existing Sentinel JSON report.")],
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Rendered report file; suffix is optional.")
    ] = Path("reports/sentinel-report"),
    report_format: Annotated[
        ReportFormat, typer.Option("--format", "-f", case_sensitive=False)
    ] = ReportFormat.HTML,
    brand_name: Annotated[
        str, typer.Option("--brand-name", help="Brand name shown in HTML reports.")
    ] = "Sentinel",
    logo_url: Annotated[
        str, typer.Option("--logo-url", help="Optional HTTP(S) logo URL for HTML reports.")
    ] = "",
) -> None:
    """Render an existing JSON report offline; no scanner module is executed."""
    try:
        loaded = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise ValueError("A Sentinel JSON report must contain an object at the top level.")
        report = ScanReport.from_dict(loaded)
        if not report.target:
            raise ValueError("The Sentinel JSON report does not contain a target.")
        path = ReportWriter(brand_name=brand_name, logo_url=logo_url).write(
            report, output, report_format
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        console.print(f"[bold red]Report error:[/] {exc}")
        raise typer.Exit(code=2) from exc
    console.print(f"[green]Rendered report:[/] {path}")


@workspace_app.command("history")
def workspace_history(
    workspace: Annotated[Path, typer.Argument(help="SQLite workspace path.")],
    target: Annotated[
        str | None, typer.Option("--target", help="Show an exact target only.")
    ] = None,
    limit: Annotated[int, typer.Option("--limit", min=1, max=500)] = 20,
) -> None:
    """List saved scans without sending any network requests."""
    try:
        scans = WorkspaceStore(workspace).list_scans(target=target, limit=limit)
    except (OSError, ValueError, sqlite3.Error) as exc:
        console.print(f"[bold red]Workspace error:[/] {exc}")
        raise typer.Exit(code=2) from exc
    table = Table(title="Sentinel local scan history")
    table.add_column("ID", justify="right")
    table.add_column("Target")
    table.add_column("Stored")
    table.add_column("Findings", justify="right")
    table.add_column("Errors", justify="right")
    for scan in scans:
        table.add_row(
            str(scan.scan_id),
            scan.target,
            scan.stored_at,
            str(scan.findings_count),
            str(scan.errors_count),
        )
    if not scans:
        console.print("[dim]No scans are stored in this workspace.[/]")
        return
    console.print(table)


@workspace_app.command("compare")
def workspace_compare(
    workspace: Annotated[Path, typer.Argument(help="SQLite workspace path.")],
    previous_scan_id: Annotated[int, typer.Argument(help="Older local scan ID.")],
    current_scan_id: Annotated[int, typer.Argument(help="Newer local scan ID.")],
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Optional JSON comparison output.")
    ] = None,
) -> None:
    """Compare two exact-target scans without classifying changes as vulnerabilities."""
    try:
        comparison = WorkspaceStore(workspace).compare_scans(previous_scan_id, current_scan_id)
    except (OSError, ValueError, sqlite3.Error) as exc:
        console.print(f"[bold red]Workspace error:[/] {exc}")
        raise typer.Exit(code=2) from exc
    payload = comparison.as_dict()
    rendered = json.dumps(payload, indent=2)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        console.print(f"[green]Wrote comparison:[/] {output}")
    else:
        console.print_json(rendered)


@workspace_app.command("graph")
def workspace_graph(
    workspace: Annotated[Path, typer.Argument(help="SQLite workspace path.")],
    scan_id: Annotated[int, typer.Argument(help="Local scan ID to model.")],
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Knowledge-graph JSON output.")
    ] = Path("knowledge-graph.json"),
) -> None:
    """Export a visualization-neutral graph from one saved scan without new traffic."""
    try:
        graph = WorkspaceStore(workspace).graph_for_scan(scan_id)
    except (OSError, ValueError, sqlite3.Error) as exc:
        console.print(f"[bold red]Workspace error:[/] {exc}")
        raise typer.Exit(code=2) from exc
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(graph.as_dict(), indent=2), encoding="utf-8")
    statistics = graph.as_dict()["statistics"]
    assert isinstance(statistics, dict)
    console.print(
        f"[green]Wrote graph:[/] {output} "
        f"({statistics['nodes']} nodes, {statistics['edges']} relationships)"
    )


@workspace_app.command("note")
def workspace_note(
    workspace: Annotated[Path, typer.Argument(help="SQLite workspace path.")],
    target: Annotated[
        str, typer.Option("--target", help="Target or workspace label for the note.")
    ],
    text: Annotated[str, typer.Option("--text", help="Local investigation note text.")],
    tags: Annotated[str, typer.Option("--tags", help="Optional comma-separated local tags.")] = "",
    scan_id: Annotated[
        int | None, typer.Option("--scan-id", help="Optional related local scan ID.")
    ] = None,
    favorite: Annotated[
        bool, typer.Option("--favorite", help="Mark the note as a favorite.")
    ] = False,
) -> None:
    """Store a local manual-investigation note without transmitting it."""
    try:
        note_id = WorkspaceStore(workspace).add_note(
            target=target,
            content=text,
            tags=tags.split(","),
            scan_id=scan_id,
            favorite=favorite,
        )
    except (OSError, ValueError, sqlite3.Error) as exc:
        console.print(f"[bold red]Workspace error:[/] {exc}")
        raise typer.Exit(code=2) from exc
    console.print(f"[green]Stored local note {note_id}.[/]")


@workspace_app.command("notes")
def workspace_notes(
    workspace: Annotated[Path, typer.Argument(help="SQLite workspace path.")],
    query: Annotated[str, typer.Argument(help="Text or tag to search locally.")],
    limit: Annotated[int, typer.Option("--limit", min=1, max=500)] = 50,
) -> None:
    """Search local notes, targets, and tags without using external services."""
    try:
        notes = WorkspaceStore(workspace).search_notes(query, limit=limit)
    except (OSError, ValueError, sqlite3.Error) as exc:
        console.print(f"[bold red]Workspace error:[/] {exc}")
        raise typer.Exit(code=2) from exc
    if not notes:
        console.print("[dim]No local notes match that query.[/]")
        return
    table = Table(title="Sentinel local notes")
    table.add_column("ID", justify="right")
    table.add_column("Target")
    table.add_column("Tags")
    table.add_column("Note")
    for note in notes:
        table.add_row(
            str(note.note_id),
            note.target,
            ", ".join(note.tags) or "—",
            note.content,
        )
    console.print(table)


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


def _batch_report_stem(index: int, host: str) -> str:
    """Create a portable deterministic report name without trusting host punctuation."""
    safe_host = "".join(
        character if character.isalnum() or character in {"-", "."} else "-" for character in host
    )
    return f"{index:03d}-{safe_host}-sentinel-report"


def _asset_delta_markdown(deltas: list[AssetDelta]) -> str:
    """Render the monitor result as an intentionally compact Markdown delta table."""
    if not deltas:
        return "No new or changed endpoints were observed against the local baseline."
    lines = [
        "| Endpoint | Change | Status | Content length | Header-derived stack |",
        "| --- | --- | --- | --- | --- |",
    ]
    for delta in deltas:
        status = f"{_display(delta.previous_status_code)} → {delta.status_code}"
        length = f"{_display(delta.previous_content_length)} → {_display(delta.content_length)}"
        lines.append(
            "| "
            f"{_markdown_cell(delta.target)} | {_markdown_cell(', '.join(delta.changes))} | "
            f"{status} | {length} | {_markdown_cell(', '.join(delta.technologies) or '—')} |"
        )
    return "\n".join(lines)


def _display(value: object) -> str:
    return "—" if value is None else str(value)


def _markdown_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _progress_is_enabled(is_interactive: bool, legacy_windows: bool) -> bool:
    """Avoid Unicode spinner output in non-interactive or legacy Windows consoles."""
    return is_interactive and not legacy_windows
