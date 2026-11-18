"""Hosted tools fetching a page while a person uses them (read-aloud, translation, ...)."""

from __future__ import annotations

from ..model import Kind
from .known_bot import KnownBotClassifier


class WebToolClassifier(KnownBotClassifier):
    label = Kind.WEB_TOOL
    name = "web_tool"
    category = "web_tool"
    descriptor = "hosted web tool"
