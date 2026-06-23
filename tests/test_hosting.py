"""Tests for datacenter / cloud range detection."""

from __future__ import annotations

import pytest

from agent_census import hosting, iprange
from agent_census.hosting import is_datacenter_ip


def test_inline_ranges_match_offline_when_present() -> None:
    # If any ranges are bundled inline, an address inside one is recognised as
    # datacenter with no network fetch. Detection is feed-based by default, so
    # there may be no inline ranges -- nothing to assert then.
    from agent_census.dataload import load_range_sources
    from agent_census.iprange import parse_networks

    inline = [cidr for source in load_range_sources("datacenter_ranges") for cidr in source.ranges]
    if not inline:
        pytest.skip("no inline datacenter ranges bundled (detection is feed-based)")
    first = parse_networks((inline[0],))[0]
    assert is_datacenter_ip(str(first.network_address))


def test_non_hosting_ip_does_not_match() -> None:
    assert not is_datacenter_ip("8.8.8.8")  # Google DNS, not in the list


def test_garbage_ip_is_false() -> None:
    assert not is_datacenter_ip("not-an-ip")
    assert not is_datacenter_ip("")


def test_remote_ranges_are_used_only_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    # An IP only present in a fetched list is invisible until --fetch-ranges.
    from agent_census.iprange import network_intervals

    monkeypatch.setattr(
        hosting, "fetch_range_intervals", lambda url, fmt: network_intervals(("203.0.113.0/24",))
    )
    try:
        assert not is_datacenter_ip("203.0.113.7")  # default run is offline
        iprange.enable_remote()
        hosting._provider_indexes.cache_clear()  # pylint: disable=protected-access
        hosting.datacenter_provider.cache_clear()
        is_datacenter_ip.cache_clear()
        assert is_datacenter_ip("203.0.113.7")  # now merged from the fetched list
    finally:  # reset module/cache state so other tests stay offline
        iprange._remote["enabled"] = False  # pylint: disable=protected-access
        hosting._provider_indexes.cache_clear()  # pylint: disable=protected-access
        hosting.datacenter_provider.cache_clear()
        is_datacenter_ip.cache_clear()


def test_datacenter_provider_names_the_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    # A hit is attributed to a named provider; a miss is None. (conftest resets the
    # remote flag and caches in teardown.)
    from agent_census.dataload import load_range_sources
    from agent_census.iprange import network_intervals

    monkeypatch.setattr(
        hosting, "fetch_range_intervals", lambda url, fmt: network_intervals(("203.0.113.0/24",))
    )
    iprange.enable_remote()
    sources = [s for s in load_range_sources("datacenter_ranges") if s.ranges_url]
    expected = sources[0].name  # first source with a feed wins the overlap
    assert hosting.datacenter_provider("203.0.113.7") == expected
    assert hosting.datacenter_provider("8.8.8.8") is None
