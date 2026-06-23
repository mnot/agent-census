"""The contract every log parser meets."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass

from ..model import LogEntry


@dataclass(frozen=True, slots=True)
class ParseOutcome:
    """The result of parsing one line: either an entry or a skip reason.

    Exactly one of ``entry`` / ``skip_reason`` is set. Parsers never raise on a
    single bad line — a malformed line becomes a skip, which the pipeline tallies
    (a high skip rate is itself diagnostic).
    """

    entry: LogEntry | None = None
    skip_reason: str | None = None
    line_no: int = 0
    raw_line: str = ""

    @property
    def ok(self) -> bool:
        return self.entry is not None


class LogParser(ABC):
    """Turns raw log lines into normalized :class:`LogEntry` values."""

    name: str = ""

    @abstractmethod
    def parse_lines(self, lines: Iterator[str]) -> Iterator[ParseOutcome]:
        """Stream one :class:`ParseOutcome` per input line."""
