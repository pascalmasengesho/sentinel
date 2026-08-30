"""CLI behavior that does not require a network target."""

from typer.testing import CliRunner

from sentinel.cli import _progress_is_enabled, app


def test_progress_requires_an_interactive_modern_terminal() -> None:
    assert _progress_is_enabled(is_interactive=True, legacy_windows=False)
    assert not _progress_is_enabled(is_interactive=False, legacy_windows=False)
    assert not _progress_is_enabled(is_interactive=True, legacy_windows=True)


def test_cli_exposes_manifest_driven_batch_help_without_network_access() -> None:
    result = CliRunner().invoke(app, ["batch", "--help"])

    assert result.exit_code == 0
    assert "scope_file" in result.output
    assert "--crawl" in result.output


def test_cli_scan_help_exposes_bug_bounty_helpers_without_network_access() -> None:
    result = CliRunner().invoke(app, ["scan", "--help"])

    assert result.exit_code == 0
    assert "--whois" in result.output
    assert "--takeover-check" in result.output
    assert "--email-security" in result.output
