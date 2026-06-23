"""Shared test fixtures."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from agent_census import egress, hosting, iprange


@pytest.fixture(autouse=True)
def _reset_range_state() -> Iterator[None]:
    """Keep the process-global range-fetch flag and its caches from leaking.

    ``--fetch-ranges`` is on by default, so running the CLI flips a module-global
    flag; reset it (and the memoised network sets) after every test so one test's
    network opt-in can't bleed into the next and trigger real fetches.
    """
    yield
    iprange._remote["enabled"] = False  # pylint: disable=protected-access
    hosting._index.cache_clear()  # pylint: disable=protected-access
    hosting.is_datacenter_ip.cache_clear()
    hosting.datacenter_subnet.cache_clear()
    egress._networks.cache_clear()  # pylint: disable=protected-access
    egress.lookup.cache_clear()
