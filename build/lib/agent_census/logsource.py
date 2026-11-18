"""Where log lines come from: reading, peeking, ordering, and time-windowing.

Decoupled from the analysis orchestration in :mod:`pipeline`. The pipeline asks
this module for a stream of lines; this module decides which files to read, in
what order, and where to start. Two cheap peeks per file (the head for a first
timestamp, the tail for a last) are enough to sort rotated logs into time order
and to skip whole files that fall outside a ``--since`` window without reading
them.
"""

from __future__ import annotations

import gzip
import itertools
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from .parsing.base import LogParser

# A single logical line is read in pieces no larger than this. Real access-log
# lines are at most a few kilobytes; the cap only ever bites on pathological
# input -- notably a gzip decompression bomb, a small .gz that expands to one
# enormous newline-free run. readline(limit) stops at a newline or after `limit`
# characters, whichever comes first, so such a run is chopped into bounded pieces
# (each an unparseable line the parser skips) instead of being buffered whole
# into a multi-gigabyte string. Normal lines shorter than the cap are unaffected.
_MAX_LINE_CHARS = 1 << 20  # 1 MiB


def _open_log(path: Path) -> TextIO:
    """Open a plain or gzip-compressed log for text reading."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("rt", encoding="utf-8", errors="replace")


def _bounded_lines(handle: TextIO) -> Iterator[str]:
    """Yield lines from ``handle``, each capped at ``_MAX_LINE_CHARS``.

    Decompression happens incrementally as ``readline`` refills, so peak memory
    stays bounded even for a ``.gz`` whose decompressed form has no newlines.
    """
    while True:
        line = handle.readline(_MAX_LINE_CHARS)
        if not line:
            break
        yield line


def read_lines(path: Path) -> Iterator[str]:
    """Yield lines from a plain or gzip-compressed log file (each bounded in size)."""
    with _open_log(path) as handle:
        yield from _bounded_lines(handle)


def read_many(paths: Sequence[Path]) -> Iterator[str]:
    """Yield lines from several log files in order, as one stream."""
    for path in paths:
        yield from read_lines(path)


def _first_timestamp(path: Path, parser: LogParser, *, scan: int = 256) -> float | None:
    """Epoch seconds of the first timestamped line near the head of ``path``.

    Reads at most ``scan`` lines -- enough to clear a few unparseable or
    timestamp-less header lines -- so placing a file in order is cheap even for a
    large gzip. ``None`` when nothing in that window carried a timestamp.
    """
    with _open_log(path) as handle:
        for outcome in parser.parse_lines(itertools.islice(_bounded_lines(handle), scan)):
            entry = outcome.entry
            if entry is not None and entry.timestamp is not None:
                return entry.timestamp.timestamp()
    return None


def _last_ts_in_block(raw_lines: list[bytes], parser: LogParser) -> float | None:
    """Scan decoded lines back-to-front, returning the first timestamp found."""
    for raw in reversed(raw_lines):
        if not raw.strip():
            continue
        text = raw.decode("utf-8", errors="replace")
        for outcome in parser.parse_lines(iter((text,))):
            if outcome.entry is not None and outcome.entry.timestamp is not None:
                return outcome.entry.timestamp.timestamp()
    return None


def _last_timestamp(
    path: Path, parser: LogParser, *, tail_bytes: int = 1 << 16, max_bytes: int = 1 << 20
) -> float | None:
    """Epoch seconds of the last timestamped line in ``path``, by reading its tail.

    Seeks to the end and grows the read window until a parseable timestamp turns
    up (or the cap is hit). Gzip streams have no cheap random access, so a ``.gz``
    file returns ``None`` here -- its upper bound is inferred from the next file
    instead (see :func:`order_logs`).
    """
    if path.suffix == ".gz":
        return None
    size = path.stat().st_size
    if size == 0:
        return None
    read = min(tail_bytes, size)
    with path.open("rb") as handle:
        while True:
            handle.seek(size - read)
            chunk = handle.read(read)
            lines = chunk.split(b"\n")
            # Drop the (likely partial) first line unless we've read the whole file.
            block = lines if read >= size else lines[1:]
            ts = _last_ts_in_block(block, parser)
            if ts is not None:
                return ts
            if read >= size or read >= max_bytes:
                return None
            read = min(read * 4, size, max_bytes)


@dataclass(frozen=True)
class _LogSpan:
    path: Path
    first: float | None  # epoch seconds, or None if no timestamp near the head
    last: float | None  # epoch seconds, or None (gzip / unknown)


def order_logs(
    paths: Sequence[Path],
    parser: LogParser,
    *,
    since_seconds: float | None = None,
    from_latest: bool = False,
    now: float | None = None,
) -> tuple[list[Path], float | None]:
    """Sort logs into chronological order and drop those fully outside the window.

    Files are ordered by their first timestamp (peeked from the head), so rotated
    logs handed over in any order -- or in a shell glob's lexicographic order,
    which sorts ``access.log.10`` before ``access.log.2`` -- still stream in time
    order. Files with no detectable timestamp can't be placed or windowed: they
    keep their original order, lead the list, and are never skipped.

    Returns ``(ordered_paths, window_start)``. ``window_start`` is the epoch cutoff
    (``None`` when no ``since_seconds`` was given); callers must still filter each
    line against it, since a file is only skipped when its *whole* span is proven
    older. The window is anchored at ``now`` (wall clock) by default, or at the
    newest timestamp in the logs when ``from_latest`` -- the latter for archived
    logs whose newest entry is itself in the past.

    Skipping is a best-effort optimisation that never changes the result: a file
    we can prove ends before the window is not read; every file we do read is
    still filtered line-by-line. A plain file's upper bound is its own last
    timestamp (read from the tail); a gzip's is the *next* file's first timestamp,
    which is exact for non-overlapping rotated logs and conservative otherwise.
    """
    # The head peek (first timestamp) is all sorting needs, and it's the only
    # peek on the common no-window path.
    firsts = [(p, _first_timestamp(p, parser)) for p in paths]
    untimed = [p for p, first in firsts if first is None]
    timed = sorted(((p, first) for p, first in firsts if first is not None), key=lambda pf: pf[1])

    if since_seconds is None:
        return untimed + [p for p, _ in timed], None

    # Windowing needs each file's last timestamp too -- an extra tail read per
    # plain file (a gzip yields None, bounded from the next file below). Deferred
    # to here so it's never paid when no --since was given.
    spans = [_LogSpan(p, first, _last_timestamp(p, parser)) for p, first in timed]

    if from_latest and spans:
        anchor = max((s.last if s.last is not None else s.first or 0.0) for s in spans)
    else:
        anchor = now if now is not None else time.time()
    window_start = anchor - since_seconds

    kept: list[Path] = []
    for i, span in enumerate(spans):
        # Upper bound of this file's coverage. For a plain file it's the exact
        # last timestamp read from the tail. For a gzip (no cheap tail) we fall
        # back to the next sorted file's first timestamp: under non-overlapping
        # rotation this file ends no later than the next begins, so that bound is
        # sound -- it just only proves "fully old" when the *next* file is itself
        # before the window. A gzip with no successor (the newest file) has no
        # bound and is always kept (then trimmed line by line).
        upper = span.last
        if upper is None:
            upper = spans[i + 1].first if i + 1 < len(spans) else None
        if upper is not None and upper < window_start:
            continue  # entirely before the window
        kept.append(span.path)
    return untimed + kept, window_start
