"""Tests for datacenter / cloud range detection."""

from __future__ import annotations

from agent_census.hosting import is_datacenter_ip


def test_known_hosting_ranges_match() -> None:
    assert is_datacenter_ip("170.64.183.82")  # DigitalOcean
    assert is_datacenter_ip("91.217.194.17")  # SberCloud


def test_non_hosting_ip_does_not_match() -> None:
    assert not is_datacenter_ip("8.8.8.8")  # Google DNS, not in the list


def test_garbage_ip_is_false() -> None:
    assert not is_datacenter_ip("not-an-ip")
    assert not is_datacenter_ip("")
