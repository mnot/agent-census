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
# cf_api_token is a secret, so the file is written 0600 (see save()).
PERSISTED = (
    "log_format",
    "log_format_preset",
    "identity",
    "robots_file",
    "robots_url",
    "cf_api_token",
    "mm_asn_db",
    "mm_country_db",
    "mm_db_dir",
)


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
    if not isinstance(data, dict):
        # Valid JSON but not an object (a list, string, number, ...): json.loads
        # succeeds, so the guard above doesn't catch it. Fall back to defaults
        # rather than crash on .items() -- a hand-edited config shouldn't abort
        # every run.
        return {}
    return {k: v for k, v in data.items() if k in PERSISTED and isinstance(v, str)}


def save(settings: dict[str, str]) -> None:
    """Write the settings back, ignoring write failures (a convenience, not state)."""
    path = config_path()
    payload = json.dumps(settings, indent=2) + "\n"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # The file may hold an API token, so create it owner-only from the start:
        # a plain write-then-chmod leaves a window where a new file sits at the
        # umask default (typically world-readable) before the chmod lands. O_CREAT
        # with mode 0o600 closes that window; the trailing chmod also tightens a
        # pre-existing file that a prior version left at looser permissions.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
        os.chmod(path, 0o600)
    except OSError:
        pass
