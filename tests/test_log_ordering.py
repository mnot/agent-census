"""Multi-file ordering and the --since time window."""

from __future__ import annotations

import gzip
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agent_census import identity, pipeline
from agent_census.cli import _duration
from agent_census.parsing import resolve
from agent_census.parsing.apache import PRESETS

FMT = PRESETS["combined"]


def _parser():
    return resolve("apache", {"format": FMT})


def _line(when: datetime, ip: str) -> str:
    stamp = when.strftime("%d/%b/%Y:%H:%M:%S %z")
    return f'{ip} - - [{stamp}] "GET / HTTP/1.1" 200 100 "-" "curl/8"'


def _day(n: int) -> datetime:
    # Jan 2024, one entry per day, at noon UTC.
    return datetime(2024, 1, n, 12, 0, 0, tzinfo=timezone.utc)


def _write(path: Path, days: list[int], ip: str = "1.1.1.1") -> Path:
    body = "\n".join(_line(_day(d), ip) for d in days) + "\n"
    if path.suffix == ".gz":
        path.write_bytes(gzip.compress(body.encode()))
    else:
        path.write_text(body, encoding="utf-8")
    return path


# --- duration parsing -------------------------------------------------------


@pytest.mark.parametrize(
    "text,seconds",
    [("1w", 604800), ("36h", 129600), ("90m", 5400), ("45s", 45), ("2d", 172800), ("3600", 3600)],
)
def test_duration_units(text: str, seconds: float) -> None:
    assert _duration(text) == seconds


@pytest.mark.parametrize("bad", ["", "1y", "-5h", "0", "abc", "10x"])
def test_duration_rejects_garbage(bad: str) -> None:
    with pytest.raises(Exception):
        _duration(bad)


# --- ordering ---------------------------------------------------------------


def test_files_sorted_by_first_timestamp(tmp_path: Path) -> None:
    # Hand them over newest-first (the order `access.log access.log.1` implies);
    # order_logs must put them back into time order.
    newest = _write(tmp_path / "access.log", [10, 11, 12])
    middle = _write(tmp_path / "access.log.1", [5, 6, 7])
    oldest = _write(tmp_path / "access.log.2", [1, 2, 3])

    ordered, window = pipeline.order_logs([newest, middle, oldest], _parser())
    assert ordered == [oldest, middle, newest]
    assert window is None


def test_lexicographic_glob_order_is_fixed(tmp_path: Path) -> None:
    # A shell glob sorts access.log.10 before access.log.2 -- wrong by time.
    f2 = _write(tmp_path / "access.log.2", [2])
    f10 = _write(tmp_path / "access.log.10", [10])
    ordered, _ = pipeline.order_logs([f10, f2], _parser())
    assert ordered == [f2, f10]


def test_untimed_files_lead_and_are_never_skipped(tmp_path: Path) -> None:
    timed = _write(tmp_path / "access.log", [10])
    # A file whose lines don't match the format has no peekable timestamp.
    untimed = tmp_path / "garbage.log"
    untimed.write_text("not a log line at all\nstill not one\n", encoding="utf-8")

    ordered, _ = pipeline.order_logs([timed, untimed], _parser(), since_seconds=3600)
    assert ordered[0] == untimed  # leads, and survives the window
    assert untimed in ordered


# --- windowing & file-skipping ---------------------------------------------


def _now_after(day: int) -> float:
    return _day(day).timestamp() + 3600  # an hour past noon on that day


def test_since_skips_fully_old_file_and_trims_straddler(tmp_path: Path) -> None:
    old = _write(tmp_path / "old.log", [1, 2])  # entirely before the window
    recent = _write(tmp_path / "recent.log", [9, 10, 11])  # 9 is before, 10/11 inside

    parser = _parser()
    # "now" just after day 11; a 36h window starts midday on day 10.
    now = _now_after(11)
    ordered, window = pipeline.order_logs([recent, old], parser, since_seconds=36 * 3600, now=now)
    assert old not in ordered  # skipped without reading
    assert ordered == [recent]
    assert window is not None and window < _day(10).timestamp() + 1

    result = pipeline.analyze(
        [recent, old], parser, identity.get_strategy("ip_ua"), since_seconds=36 * 3600, now=now
    )
    # Day 9 from recent.log is read but trimmed; days 10 and 11 survive.
    assert result.skips.parsed == 2
    assert result.skips.out_of_window == 1
    assert result.skips.total_lines == 3  # old.log's 2 lines were never read
    assert result.skipped_files == ("old.log",)  # named in the report, not silent


def test_gz_old_file_skipped_when_next_file_is_also_old(tmp_path: Path) -> None:
    # A gzip has no cheap tail read, so its upper bound is the next file's first
    # timestamp -- which only proves "fully old" when that next file also starts
    # before the window. Sorted: old.gz (1-2), mid.gz (5-6), recent.log (20-21).
    old = _write(tmp_path / "old.log.gz", [1, 2])
    mid = _write(tmp_path / "mid.log.gz", [5, 6])
    recent = _write(tmp_path / "recent.log", [20, 21])

    now = _now_after(21)
    # ~32h window -> starts midday day 20; both gz files are entirely before it.
    ordered, _ = pipeline.order_logs(
        [recent, old, mid], _parser(), since_seconds=32 * 3600, now=now
    )
    # old.gz is dropped (its successor mid.gz also starts before the window);
    # mid.gz can't be proven old by recent.log (day 20, inside), so it is read.
    assert ordered == [mid, recent]
    assert old not in ordered


def test_gz_newest_file_is_kept_despite_unreadable_tail(tmp_path: Path) -> None:
    # The newest file is a gzip with no successor to bound it, so it survives the
    # file-level skip and is trimmed line by line instead.
    only = _write(tmp_path / "access.log.gz", [10, 11])
    now = _now_after(11)
    ordered, _ = pipeline.order_logs([only], _parser(), since_seconds=1, now=now)
    assert ordered == [only]


def test_plain_file_fully_before_window_is_skipped(tmp_path: Path) -> None:
    # A plain file's exact tail timestamp lets it be skipped on its own.
    only = _write(tmp_path / "access.log", [10, 11])
    now = _now_after(11)  # an hour past the last entry; a 1s window catches nothing
    ordered, _ = pipeline.order_logs([only], _parser(), since_seconds=1, now=now)
    assert ordered == []  # nothing in window, proven by the tail read


def test_from_latest_anchors_to_newest_log_timestamp(tmp_path: Path) -> None:
    # Logs are "old" relative to wall clock, but --from-latest anchors on the data.
    old = _write(tmp_path / "old.log", [1])
    recent = _write(tmp_path / "recent.log", [10, 11])

    parser = _parser()
    result = pipeline.analyze(
        [old, recent],
        parser,
        identity.get_strategy("ip_ua"),
        since_seconds=12 * 3600,  # back from day 11 noon -> day 11 00:00
        from_latest=True,
    )
    # Day 1 and day 10 fall outside [day 11 00:00, day 11 noon]; only day 11 survives.
    assert result.skips.parsed == 1
    assert result.skips.out_of_window == 1  # day 10, read from recent.log then trimmed
    assert result.skips.total_lines == 2  # old.log skipped entirely


def test_no_since_reads_everything_in_time_order(tmp_path: Path) -> None:
    a = _write(tmp_path / "b.log", [5, 6])
    b = _write(tmp_path / "a.log", [1, 2])
    result = pipeline.analyze([a, b], _parser(), identity.get_strategy("ip_ua"))
    assert result.skips.parsed == 4 and result.skips.out_of_window == 0
