"""Name-keyed registry of parser factories.

A factory takes an opaque ``opts`` dict so each parser declares its own required
options (Apache needs ``opts["format"]``; a future nginx parser would need its
own ``log_format`` string). The CLI maps flags into that dict. This registry is
the single seam for adding server support — external packages can call
:func:`register` to plug in their own.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping

from ..errors import ConfigError
from .base import LogParser

ParserFactory = Callable[[Mapping[str, str]], LogParser]

_FACTORIES: dict[str, ParserFactory] = {}


def register(name: str, factory: ParserFactory) -> None:
    """Register a parser factory under ``name`` (last registration wins)."""
    _FACTORIES[name] = factory


def available() -> list[str]:
    """Return the registered parser names, sorted."""
    return sorted(_FACTORIES)


def resolve(name: str, opts: Mapping[str, str]) -> LogParser:
    """Build the named parser from ``opts``, or raise :class:`ConfigError`."""
    try:
        factory = _FACTORIES[name]
    except KeyError:
        known = ", ".join(available()) or "(none registered)"
        raise ConfigError(f"unknown server {name!r}; known parsers: {known}") from None
    return factory(opts)
