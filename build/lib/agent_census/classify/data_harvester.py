"""Data harvesters: crawl content into a private corpus or dataset.

Commercial crawlers that ingest pages into a proprietary database for their own
product -- plagiarism/similarity indexes (Turnitin), data brokers and dataset
builders (Panscient) -- as opposed to public search, preservation, AI/LLM
training, or SEO. Recognised by a known UA token, like the other declared kinds.
"""

from __future__ import annotations

from ..model import Kind
from .known_bot import KnownBotClassifier


class DataHarvesterClassifier(KnownBotClassifier):
    label = Kind.DATA_HARVESTER
    name = "data_harvester"
    category = "data_harvester"
    descriptor = "data harvester"
