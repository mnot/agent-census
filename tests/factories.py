"""Helpers for building LogEntry fixtures in tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from agent_census.model import LogEntry

BASE = datetime(2023, 10, 10, 12, 0, 0, tzinfo=timezone.utc)


def entry(
    path: str,
    *,
    ip: str = "192.0.2.1",
    status: int | None = 200,
    user_agent: str | None = "Mozilla/5.0 (browser) AppleWebKit/600",
    method: str = "GET",
    bytes_sent: int | None = 100,
    referer: str | None = None,
    offset: float = 0.0,
    query: str | None = None,
) -> LogEntry:
    """Build a LogEntry with sensible defaults; ``offset`` is seconds past BASE."""
    return LogEntry(
        raw_line=f"{method} {path}",
        line_no=1,
        remote_host=ip,
        timestamp=BASE + timedelta(seconds=offset),
        method=method,
        path=path,
        query=query,
        status=status,
        bytes_sent=bytes_sent,
        referer=referer,
        user_agent=user_agent,
    )
