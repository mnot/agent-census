"""Tests for shared-egress (e.g. iCloud Private Relay) detection and folding."""

from __future__ import annotations

import pytest

from agent_census import egress, identity, iprange, pipeline
from agent_census.dataload import EgressNetwork
from agent_census.parsing import resolve
from agent_census.parsing.apache import PRESETS

_RELAY = EgressNetwork(name="iCloud Private Relay", tag="icloud-private-relay")


def test_known_egress_networks_are_registered() -> None:
    from agent_census.dataload import load_egress_networks

    tags = {network.tag for network in load_egress_networks()}
    assert {"icloud-private-relay", "tor-exit", "vpn", "corporate-proxy"} <= tags
    # Several networks share a cross-tab column ("group") while keeping their tag.
    groups = {network.group for network in load_egress_networks()}
    assert {"Privacy proxies", "VPNs", "Corporate proxies"} <= groups


def test_lookup_uses_remote_ranges_only_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        egress, "fetch_range_intervals", lambda url, fmt, name=None: iprange.network_intervals(("203.0.113.0/24",))
    )
    try:
        assert egress.lookup("203.0.113.9") is None  # offline by default
        iprange.enable_remote()
        egress._networks.cache_clear()  # pylint: disable=protected-access
        egress.lookup.cache_clear()
        found = egress.lookup("203.0.113.9")
        assert found is not None and found.name == "iCloud Private Relay"
    finally:
        iprange._remote["enabled"] = False  # pylint: disable=protected-access
        egress._networks.cache_clear()  # pylint: disable=protected-access
        egress.lookup.cache_clear()


def test_vpn_recognised_by_asn_folds_as_egress(
    tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Strong Technology (AS54203) publishes no range list, so it's matched by the
    # logged AS number: three exit IPs with one UA collapse into one tagged entry.
    monkeypatch.setattr(egress, "lookup", lambda ip: None)  # no range match
    fmt = '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i" "%{MM_ASN}e"'
    ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
    lines = [
        f'5.5.5.{i} - - [10/Oct/2023:12:0{i}:00 +0000] "GET /p{i} HTTP/1.1" 200 100 "-" "{ua}" "54203"'
        for i in range(3)
    ]
    log = tmp_path / "vpn.log"  # type: ignore[attr-defined]
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    parser = resolve("apache", {"format": fmt})
    result = pipeline.analyze(log, parser, identity.get_strategy("ip_ua"))

    # The client keeps its own identity (Strong Technology), is tagged 'vpn', and is
    # summed into the shared "VPNs" cross-tab column.
    vpns = [p for p in result.profiles if p.client_id.ip == "Strong Technology"]
    assert len(vpns) == 1
    assert vpns[0].features.request_count == 3
    assert set(vpns[0].member_ips) == {"5.5.5.0", "5.5.5.1", "5.5.5.2"}
    assert "vpn" in vpns[0].classification.tags
    assert vpns[0].network == "VPNs"


def test_relay_traffic_folds_into_one_entry(
    tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Same Safari UA across three relay egress IPs + one ordinary client.
    safari = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.0 Safari/605.1.15"
    )
    lines = [
        f'172.224.0.{i} - - [10/Oct/2023:12:0{i}:00 +0000] "GET /p{i} HTTP/1.1" 200 900 "-" "{safari}"'
        for i in range(3)
    ]
    lines.append('9.9.9.9 - - [10/Oct/2023:12:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "curl/8"')
    log = tmp_path / "relay.log"  # type: ignore[attr-defined]
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    monkeypatch.setattr(
        egress, "lookup", lambda ip: _RELAY if ip.startswith("172.224.") else None
    )
    parser = resolve("apache", {"format": PRESETS["combined"]})
    result = pipeline.analyze(log, parser, identity.get_strategy("ip_ua"))

    relay = [p for p in result.profiles if p.client_id.ip == "iCloud Private Relay"]
    assert len(relay) == 1  # three egress IPs collapsed to one entry
    profile = relay[0]
    assert profile.features.request_count == 3
    assert set(profile.member_ips) == {"172.224.0.0", "172.224.0.1", "172.224.0.2"}
    assert "icloud-private-relay" in profile.classification.tags
    # the ordinary client is untouched and still its own entry
    assert any(p.client_id.ip == "9.9.9.9" for p in result.profiles)
