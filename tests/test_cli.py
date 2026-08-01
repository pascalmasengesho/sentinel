"""CLI behavior that does not require a network target."""

from sentinel.cli import _progress_is_enabled


def test_progress_requires_an_interactive_modern_terminal() -> None:
    assert _progress_is_enabled(is_interactive=True, legacy_windows=False)
    assert not _progress_is_enabled(is_interactive=False, legacy_windows=False)
    assert not _progress_is_enabled(is_interactive=True, legacy_windows=True)
