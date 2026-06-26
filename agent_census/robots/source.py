"""Where robots.txt comes from: a local file (default) or an opt-in live fetch.

For log analysis the correct source is a *local* copy that matches the log's time
period — a live fetch reflects today's rules, which may have changed. The fetch
path is therefore opt-in and records when it ran so the report can warn about
time skew.
"""

from __future__ import annotations

import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .. import USER_AGENT
from ..errors import ConfigError

_FETCH_TIMEOUT = 10


@dataclass(frozen=True, slots=True)
class RobotsDoc:
    """A robots.txt document plus where and when it came from."""

    text: str
    provenance: str
    fetched_at: datetime | None = None

    def note(self) -> str:
        """A one-line provenance note for the report header."""
        if self.fetched_at is not None:
            stamp = self.fetched_at.strftime("%Y-%m-%d")
            return (
                f"fetched live ({self.provenance}) on {stamp} — "
                "live rules may differ from the log's time period"
            )
        return f"loaded from {self.provenance}"


def from_file(path: Path) -> RobotsDoc:
    """Read robots.txt from a local file."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ConfigError(f"could not read robots file {path}: {exc}") from exc
    # File name only -- the report's provenance note shouldn't leak the full path.
    return RobotsDoc(text=text, provenance=path.name)


def from_network(url: str) -> RobotsDoc:
    """Fetch robots.txt over the network (opt-in)."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=_FETCH_TIMEOUT) as response:  # noqa: S310
            raw = response.read()
    except (OSError, ValueError) as exc:
        raise ConfigError(f"could not fetch robots.txt from {url}: {exc}") from exc
    text = raw.decode("utf-8", errors="replace")
    return RobotsDoc(text=text, provenance=url, fetched_at=datetime.now())


def url_for_host(host: str) -> str:
    """Build a robots.txt URL from a bare host or a base URL."""
    host = host.strip()
    if host.startswith(("http://", "https://")):
        base = host.rstrip("/")
        return f"{base}/robots.txt" if not base.endswith("/robots.txt") else base
    return f"https://{host}/robots.txt"
