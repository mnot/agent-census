"""Declared AI / LLM data-gathering crawlers (GPTBot, ClaudeBot, Google-Extended, ...)."""

from __future__ import annotations

from ..model import Kind
from .known_bot import KnownBotClassifier


class AiCrawlerClassifier(KnownBotClassifier):
    label = Kind.AI_CRAWLER
    name = "ai_crawler"
    category = "ai_crawler"
    descriptor = "AI / LLM crawler"
