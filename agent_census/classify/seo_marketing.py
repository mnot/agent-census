"""SEO / marketing / brand-monitoring crawlers (Ahrefs, Semrush, DotBot, ...)."""

from __future__ import annotations

from ..model import Kind
from .known_bot import KnownBotClassifier


class SeoMarketingClassifier(KnownBotClassifier):
    label = Kind.SEO_MARKETING
    name = "seo_marketing"
    category = "seo_marketing"
    descriptor = "SEO / marketing crawler"
