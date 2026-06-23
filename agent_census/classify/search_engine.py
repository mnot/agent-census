"""Search-engine crawlers (Googlebot, Bingbot, Yandex, Baidu, ...)."""

from __future__ import annotations

from ..model import Kind
from .known_bot import KnownBotClassifier


class SearchEngineClassifier(KnownBotClassifier):
    label = Kind.SEARCH_ENGINE
    name = "search_engine"
    data_file = "search_engines.txt"
    descriptor = "search-engine crawler"
