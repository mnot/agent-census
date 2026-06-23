"""Social-preview / link-unfurl fetchers (facebookexternalhit, Twitterbot, ...)."""

from __future__ import annotations

from ..model import Kind
from .known_bot import KnownBotClassifier


class SocialPreviewClassifier(KnownBotClassifier):
    label = Kind.SOCIAL_PREVIEW
    name = "social_preview"
    data_file = "social_preview.txt"
    descriptor = "social-preview / link-unfurl bot"
