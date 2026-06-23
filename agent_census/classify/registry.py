"""The ordered set of active classifiers.

To add or remove a classifier, edit this list — each entry is self-contained and
independent of the others. Order does not affect the outcome (the combiner
aggregates by label), but it sets the order signals appear in inspect output.
"""

from __future__ import annotations

from .ai_crawler import AiCrawlerClassifier
from .archiver import ArchiverClassifier
from .base import Classifier
from .browser import BrowserClassifier
from .crawler import CrawlerClassifier
from .feed_reader import FeedReaderClassifier
from .monitor import MonitorClassifier
from .scraper import ScraperClassifier
from .search_engine import SearchEngineClassifier
from .seo_marketing import SeoMarketingClassifier
from .social_preview import SocialPreviewClassifier
from .spam_bot import SpamBotClassifier
from .vuln_scanner import VulnScannerClassifier

_CLASSIFIERS: tuple[Classifier, ...] = (
    SearchEngineClassifier(),
    SocialPreviewClassifier(),
    ArchiverClassifier(),
    AiCrawlerClassifier(),
    SeoMarketingClassifier(),
    VulnScannerClassifier(),
    BrowserClassifier(),
    CrawlerClassifier(),
    ScraperClassifier(),
    MonitorClassifier(),
    FeedReaderClassifier(),
    SpamBotClassifier(),
)


def all_classifiers() -> tuple[Classifier, ...]:
    """Return every active classifier instance."""
    return _CLASSIFIERS
