"""robots.txt acquisition, parsing, and per-client compliance scoring."""

from __future__ import annotations

from .compliance import evaluate, report_from_signals
from .parser import RobotsRules
from .source import RobotsDoc, from_file, from_network

__all__ = [
    "RobotsDoc",
    "RobotsRules",
    "from_file",
    "from_network",
    "evaluate",
    "report_from_signals",
]
