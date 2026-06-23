"""Tests for client identity strategies."""

from __future__ import annotations

from agent_census.identity import get_strategy
from agent_census.model import LogEntry

from .factories import entry


def _forwarded(ip: str, xff: tuple[str, ...]) -> LogEntry:
    return LogEntry(raw_line="", line_no=1, remote_host=ip, forwarded_for=xff)


def test_ip_strategy_merges_user_agents() -> None:
    strat = get_strategy("ip")
    a = strat.key(entry("/", ip="10.0.0.1", user_agent="A"))
    b = strat.key(entry("/", ip="10.0.0.1", user_agent="B"))
    assert a == b


def test_ip_ua_strategy_separates_user_agents() -> None:
    strat = get_strategy("ip_ua")
    a = strat.key(entry("/", ip="10.0.0.1", user_agent="A"))
    b = strat.key(entry("/", ip="10.0.0.1", user_agent="B"))
    assert a != b


def test_subnet_strategy_merges_within_24() -> None:
    strat = get_strategy("ip_ua_subnet")
    a = strat.key(entry("/", ip="10.0.0.5", user_agent="A"))
    b = strat.key(entry("/", ip="10.0.0.200", user_agent="A"))
    assert a == b
    assert a.subnet == "10.0.0.0/24"


def test_forwarded_strategy_uses_leftmost_xff() -> None:
    strat = get_strategy("forwarded")
    key = strat.key(_forwarded("10.0.0.1", ("203.0.113.7", "70.41.3.18")))
    assert key.ip == "203.0.113.7"


def test_forwarded_strategy_falls_back_to_remote_host() -> None:
    strat = get_strategy("forwarded")
    key = strat.key(_forwarded("10.0.0.1", ()))
    assert key.ip == "10.0.0.1"
