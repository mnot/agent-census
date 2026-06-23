"""The ordered set of active classifiers.

To add or remove a classifier, edit this list — each entry is self-contained and
independent of the others. Order does not affect the outcome (the combiner
aggregates by label), but it sets the order signals appear in inspect output.
"""

from __future__ import annotations

from .ai_crawler import AiCrawlerClassifier
from .base import Classifier
from .browser import BrowserClassifier
from .crawler import CrawlerClassifier
from .feed_reader import FeedReaderClassifier
from .good_bot import GoodBotClassifier
from .monitor import MonitorClassifier
from .scraper import ScraperClassifier
from .spam_bot import SpamBotClassifier
from .vuln_scanner import VulnScannerClassifier

_CLASSIFIERS: tuple[Classifier, ...] = (
    GoodBotClassifier(),
    AiCrawlerClassifier(),
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
