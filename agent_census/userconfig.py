"""Persisted CLI defaults under ``~/.config/agent-census/config.json``.

A handful of options (the log format, identity strategy, robots source) are
sticky: the value you last passed is remembered and reused on later runs that
omit it, so you needn't retype your log format every time. JSON, not TOML, so it
can be both read and written with only the standard library.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

# CLI dest names that persist between runs. log_format / log_format_preset are
# alternatives: setting one clears the other (see cli._apply_persisted_settings).
PERSISTED = ("log_format", "log_format_preset", "identity", "robots_file", "robots_url")


def config_path() -> Path:
    """Location of the settings file (``$XDG_CONFIG_HOME`` aware)."""
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "agent-census" / "config.json"


def load() -> dict[str, str]:
    """Return the saved settings, or an empty dict if none / unreadable."""
    try:
        data = json.loads(config_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in data.items() if k in PERSISTED and isinstance(v, str)}


def save(settings: dict[str, str]) -> None:
    """Write the settings back, ignoring write failures (a convenience, not state)."""
    path = config_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass
