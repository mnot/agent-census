"""Pluggable access-log parsers.

Every parser normalizes its server's log lines into :class:`~agent_census.model.LogEntry`
values, so nothing downstream depends on the server. Built-in parsers register
themselves on import; importing this package populates the registry.
"""

from __future__ import annotations

from . import apache  # noqa: F401  (import for registration side effect)
from .base import LogParser, ParseOutcome
from .registry import available, register, resolve

__all__ = ["LogParser", "ParseOutcome", "available", "register", "resolve"]
