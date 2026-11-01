"""Ad-platform fetchers (AdsBot-Google, AdIdxBot, Mediapartners-Google, ...)."""

from __future__ import annotations

from ..model import Kind
from .known_bot import KnownBotClassifier


class AdsClassifier(KnownBotClassifier):
    label = Kind.ADS
    name = "ads"
    category = "ads"
    descriptor = "ad-platform fetcher"
