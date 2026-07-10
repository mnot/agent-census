"""Tests for shared-egress (e.g. iCloud Private Relay) detection and folding."""

from __future__ import annotations

import pytest

from agent_census import egress, identity, iprange, pipeline
from agent_census.dataload import EgressNetwork
from agent_census.model import Kind
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


def _relay_browser_lines() -> list[str]:
    """Browser-shaped relay traffic spanning days: each visit is a page co-loaded
    with its CSS (so it classifies as a browser and qualifies for the reference
    pool), and one visit makes a conditional 304 (a real cache)."""
    safari = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.0 Safari/605.1.15"
    )

    def visit(day: int, ip: str, status: int = 200) -> list[str]:
        when_page = f"[1{day}/Oct/2023:12:00:00 +0000]"
        when_asset = f"[1{day}/Oct/2023:12:00:01 +0000]"
        return [
            f'{ip} - - {when_page} "GET /p{day} HTTP/1.1" {status} 900 "-" "{safari}"',
            # CSS carries the page as Referer, so it's a genuine (referer-linked) co-load
            # -- the browser signal, independent of cadence.
            f'{ip} - - {when_asset} "GET /a{day}.css HTTP/1.1" 200 100 '
            f'"http://h/p{day}" "{safari}"',
        ]

    # Three visits on the 11th/12th/13th -> a >24h span; the last returns a 304.
    return visit(1, "172.224.0.0") + visit(2, "172.224.0.1") + visit(3, "172.224.0.2", status=304)


def test_relay_fold_is_an_aggregate_not_a_single_client(
    tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The folded relay row is many independent users in one entry. Its union span is
    # days and it co-loads assets, so as a *single* client it would earn long-session
    # and seed the reference-browser pool. Marked is_aggregate, it does neither: the
    # site-relative magnitudes are suppressed and it never contaminates calibration.
    log = tmp_path / "relay_browser.log"  # type: ignore[attr-defined]
    log.write_text("\n".join(_relay_browser_lines()) + "\n", encoding="utf-8")
    monkeypatch.setattr(
        egress, "lookup", lambda ip: _RELAY if ip.startswith("172.224.") else None
    )
    parser = resolve("apache", {"format": PRESETS["combined"]})
    result = pipeline.analyze(log, parser, identity.get_strategy("ip_ua"))

    relay = next(p for p in result.profiles if p.client_id.ip == "iCloud Private Relay")
    assert relay.is_aggregate
    assert relay.classification.primary is Kind.BROWSER  # duration metric is in scope
    assert relay.features.duration_seconds > 86_400  # would clear the long-session floor
    assert "long-session" not in relay.classification.tags
    # And it was kept out of the reference pool it would otherwise have seeded.
    assert result.reference_calibration is not None
    assert result.reference_calibration.pool_sizes["browsers"] == 0
