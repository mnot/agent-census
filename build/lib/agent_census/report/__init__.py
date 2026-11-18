"""Markdown and HTML rendering of analysis results and inspection traces."""

from __future__ import annotations

from .calibrate import render_calibration
from .geo import CountryFlags, country_flags
from .html import render_report_html
from .inspect import render_inspect, select_profiles
from .inspect_data import write_inspect_bundle
from .markdown import render_report

__all__ = [
    "render_report",
    "render_inspect",
    "render_report_html",
    "render_calibration",
    "select_profiles",
    "write_inspect_bundle",
    "country_flags",
    "CountryFlags",
]
