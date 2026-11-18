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
# Cap the fetched body so a malicious or misconfigured origin can't exhaust memory
# with an enormous (or endless) robots.txt. 512 KiB is Google's documented parse
# limit for robots.txt, so nothing legitimate is lost.
_MAX_ROBOTS_BYTES = 512 * 1024


@dataclass(frozen=True, slots=True)
class RobotsDoc:
    """A robots.txt document plus where and when it came from."""

    text: str
    provenance: str
    fetched_at: datetime | None = None
    # Oddities of the fetch that make the text suspect (a redirect, a non-text
    # content type, truncation); shown in the note and on stderr.
    caveats: tuple[str, ...] = ()

    def note(self) -> str:
        """A one-line provenance note for the report header."""
        if self.fetched_at is not None:
            stamp = self.fetched_at.strftime("%Y-%m-%d")
            note = (
                f"fetched live ({self.provenance}) on {stamp} — "
                "live rules may differ from the log's time period"
            )
        else:
            note = f"loaded from {self.provenance}"
        return note + "".join(f"; {caveat}" for caveat in self.caveats)


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
            raw = response.read(_MAX_ROBOTS_BYTES + 1)
            final_url = response.geturl()
            content_type = response.headers.get_content_type()
    except (OSError, ValueError) as exc:
        raise ConfigError(f"could not fetch robots.txt from {url}: {exc}") from exc
    caveats: list[str] = []
    if final_url != url:
        caveats.append(f"redirected to {final_url}")
    if content_type not in ("text/plain", "application/octet-stream"):
        caveats.append(f"served as {content_type}, not text/plain")
    if len(raw) > _MAX_ROBOTS_BYTES:
        raw = raw[:_MAX_ROBOTS_BYTES]
        caveats.append(f"truncated at {_MAX_ROBOTS_BYTES // 1024} KiB")
    text = raw.decode("utf-8", errors="replace")
    return RobotsDoc(text=text, provenance=url, fetched_at=datetime.now(), caveats=tuple(caveats))


def url_for_host(host: str) -> str:
    """Build a robots.txt URL from a bare host or a base URL."""
    host = host.strip()
    if host.startswith(("http://", "https://")):
        base = host.rstrip("/")
        return f"{base}/robots.txt" if not base.endswith("/robots.txt") else base
    return f"https://{host}/robots.txt"
