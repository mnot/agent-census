"""Declared search-engine and social-preview crawlers (Googlebot, Bingbot, ...)."""

from __future__ import annotations

from ..model import Kind
from .known_bot import KnownBotClassifier


class GoodBotClassifier(KnownBotClassifier):
    label = Kind.GOOD_BOT
    name = "good_bot"
    data_file = "good_bots.txt"
    descriptor = "search/preview crawler"
