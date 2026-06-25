"""Shared test fixtures."""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from agent_census import egress, hosting, iprange


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
    egress.lookup.cache_clear()
