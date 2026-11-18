"""Typed exceptions raised by agent-census.

These are for *configuration and usage* errors that should abort the run with a
clear message. A malformed individual log line is not an error — the parser
records it as a skipped line and keeps going.
"""

from __future__ import annotations


class AgentCensusError(Exception):
    """Base class for all errors raised by this package."""


class FormatSpecError(AgentCensusError):
    """The supplied log-format directive string could not be understood."""


class ConfigError(AgentCensusError):
    """Invalid combination of command-line options or runtime configuration."""
