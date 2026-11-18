"""AI assistants fetching a page at a person's request (ChatGPT-User, Claude-User, ...)."""

from __future__ import annotations

from ..model import Kind
from .known_bot import KnownBotClassifier


class AiUserClassifier(KnownBotClassifier):
    label = Kind.AI_USER
    name = "ai_user"
    category = "ai_user"
    descriptor = "AI assistant fetcher"
