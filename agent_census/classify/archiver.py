"""Web-archiving / preservation crawlers (Internet Archive / Wayback Machine)."""

from __future__ import annotations

from ..model import Kind
from .known_bot import KnownBotClassifier


class ArchiverClassifier(KnownBotClassifier):
    label = Kind.ARCHIVER
    name = "archiver"
    category = "archiver"
    descriptor = "web archiver"
