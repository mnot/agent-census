"""Load the bundled data lists.

Each list is a UTF-8 text file with one entry per line; blank lines and lines
starting with ``#`` are ignored. Results are cached so repeated lookups during a
run are free.
"""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files


@lru_cache(maxsize=None)
def load_list(name: str) -> tuple[str, ...]:
    """Return the non-comment, non-blank lines of data file ``name``."""
    text = (files("agent_census.data") / name).read_text(encoding="utf-8")
    out: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            out.append(stripped)
    return tuple(out)


@lru_cache(maxsize=None)
def load_tokens(name: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Load a ``<token> <domain>...`` data file as (token, domains) pairs."""
    pairs: list[tuple[str, tuple[str, ...]]] = []
    for line in load_list(name):
        parts = line.split()
        pairs.append((parts[0], tuple(parts[1:])))
    return tuple(pairs)
