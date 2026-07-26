"""Minimal local plugin loader for trusted, user-authored assessment modules."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Protocol, cast

from sentinel.modules.base import ScanModule


class PluginRegistration(Protocol):
    """Protocol implemented by a trusted plugin's ``register`` function."""

    def __call__(self) -> ScanModule | list[ScanModule]:
        """Return one or more scanner modules."""


def load_plugins(directory: str | None) -> tuple[list[ScanModule], list[str]]:
    """Load trusted local Python plugins from a directory.

    Plugins run as local Python code and therefore must be reviewed before being
    placed in this directory. A plugin must export ``register()`` returning a
    ``ScanModule`` or a list of them.
    """
    if not directory:
        return [], []
    path = Path(directory)
    if not path.is_dir():
        return [], [f"Plugin directory not found: {path}"]
    modules: list[ScanModule] = []
    errors: list[str] = []
    for plugin_path in sorted(path.glob("*.py")):
        if plugin_path.name.startswith("_"):
            continue
        try:
            spec = importlib.util.spec_from_file_location(
                f"sentinel_plugin_{plugin_path.stem}", plugin_path
            )
            if spec is None or spec.loader is None:
                raise ImportError("Could not load plugin specification")
            plugin = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(plugin)
            registration = cast(PluginRegistration, plugin.register)
            registered = registration()
            candidates = registered if isinstance(registered, list) else [registered]
            for module in candidates:
                if not isinstance(module, ScanModule):
                    raise TypeError("register() must return ScanModule instances")
            modules.extend(candidates)
        except Exception as exc:
            errors.append(f"{plugin_path.name}: {type(exc).__name__}: {exc}")
    return modules, errors
