"""Markdown and HTML rendering of analysis results and inspection traces."""

from __future__ import annotations

from ._inspect_html import render_inspect_html
from .calibrate import render_calibration
from .geo import CountryFlags, country_flags
from .html import render_report_html
from .inspect import render_inspect, select_profiles
from .markdown import render_report

__all__ = [
    "render_report",
    "render_inspect",
    "render_report_html",
    "render_inspect_html",
    "render_calibration",
    "select_profiles",
    "country_flags",
    "CountryFlags",
]
