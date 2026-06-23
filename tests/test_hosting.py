"""Tests for datacenter / cloud range detection."""

from __future__ import annotations

import pytest

from agent_census import hosting, iprange
from agent_census.hosting import is_datacenter_ip


def test_known_hosting_ranges_match() -> None:
    assert is_datacenter_ip("170.64.183.82")  # DigitalOcean
    assert is_datacenter_ip("91.217.194.17")  # SberCloud


def test_non_hosting_ip_does_not_match() -> None:
    assert not is_datacenter_ip("8.8.8.8")  # Google DNS, not in the list


def test_garbage_ip_is_false() -> None:
    assert not is_datacenter_ip("not-an-ip")
    assert not is_datacenter_ip("")


def test_remote_ranges_are_used_only_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    # An IP only present in a fetched list is invisible until --fetch-ranges.
    monkeypatch.setattr(hosting, "fetch_ranges_text", lambda url: "203.0.113.0/24")
    try:
        assert not is_datacenter_ip("203.0.113.7")  # default run is offline
        iprange.enable_remote()
        hosting._index.cache_clear()  # pylint: disable=protected-access
        is_datacenter_ip.cache_clear()
        assert is_datacenter_ip("203.0.113.7")  # now merged from the fetched list
    finally:  # reset module/cache state so other tests stay offline
        iprange._remote["enabled"] = False  # pylint: disable=protected-access
        hosting._index.cache_clear()  # pylint: disable=protected-access
        is_datacenter_ip.cache_clear()
