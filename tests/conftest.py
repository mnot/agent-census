"""Shared test fixtures."""

from __future__ import annotations

import os
from collections.abc import Iterator
from types import SimpleNamespace

import pytest

from agent_census import dataload, egress, hosting, iprange, uas

# Loaders memoised off the agent data, cleared when a synthetic agent is injected.
_AGENT_CACHES = (
    dataload.load_asn_agents,
    dataload.load_asn_range_feeds,
    uas._asn_index,  # pylint: disable=protected-access
    hosting._asn_feed_indexes,  # pylint: disable=protected-access
    hosting.asn_for_ip,
)


@pytest.fixture(autouse=True)
def _reset_range_state(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    """Keep the process-global range-fetch flag and its caches from leaking.

    ``--fetch-ranges`` is on by default, so running the CLI flips a module-global
    flag; reset it (and the memoised network sets) after every test so one test's
    network opt-in can't bleed into the next and trigger real fetches. Also point
    the cache and config dirs at throwaway tmp dirs so disk caches (range lists,
    DNS lookups) and persisted CLI settings never touch the developer's real
    ``~/.cache`` / ``~/.config`` and stay isolated per test. Set the env directly
    (not via ``monkeypatch``) so this fixture's teardown runs before any test-level
    ``monkeypatch`` undoes patched ``lru_cache`` objects below.
    """
    saved = {k: os.environ.get(k) for k in ("XDG_CACHE_HOME", "XDG_CONFIG_HOME")}
    os.environ["XDG_CACHE_HOME"] = str(tmp_path_factory.mktemp("cache"))
    os.environ["XDG_CONFIG_HOME"] = str(tmp_path_factory.mktemp("config"))
    yield
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    iprange._remote["enabled"] = False  # pylint: disable=protected-access
    iprange._warned.clear()  # pylint: disable=protected-access
    hosting._provider_indexes.cache_clear()  # pylint: disable=protected-access
    hosting._asn_providers.cache_clear()  # pylint: disable=protected-access
    hosting._asn_feed_indexes.cache_clear()  # pylint: disable=protected-access
    hosting.datacenter_provider.cache_clear()
    hosting.asn_for_ip.cache_clear()
    hosting.is_datacenter_ip.cache_clear()
    hosting.datacenter_subnet.cache_clear()
    hosting.subnet_of.cache_clear()
    egress._networks.cache_clear()  # pylint: disable=protected-access
    egress._asn_networks.cache_clear()  # pylint: disable=protected-access
    egress.lookup.cache_clear()


@pytest.fixture
def synthetic_asn_crawler(monkeypatch: pytest.MonkeyPatch) -> Iterator[SimpleNamespace]:
    """Inject a synthetic ``asn_primary`` AI crawler that publishes a prefix feed.

    The AS-by-feed recovery path (recognising an AS-identified crawler by matching
    its IP against the AS's announced prefixes, when the log carries no AS number)
    needs *some* ``asn_primary`` agent with a ``ranges_url``. The curated data may
    have none, so these tests stand up their own rather than pinning to whichever
    crawler happens to publish one. Returns its ``asn`` / ``label`` / ``url``.
    """
    crawler = SimpleNamespace(
        asn=64500,
        label="Testbank",
        url="https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS64500",
    )
    agent = {
        "name": crawler.label,
        "asn_primary": True,
        "asns": [crawler.asn],
        "ranges_url": crawler.url,
        "format": "ripestat",
    }
    real_agents = dataload._agents  # pylint: disable=protected-access
    monkeypatch.setattr(
        dataload,
        "_agents",
        lambda category: (*real_agents(category), agent) if category == "ai_crawler" else real_agents(category),
    )
    for cache in _AGENT_CACHES:
        cache.cache_clear()
    yield crawler
    for cache in _AGENT_CACHES:  # don't let the synthetic agent leak into later tests
        cache.cache_clear()
