"""Tests for the kind x network cross-tab builder."""

from __future__ import annotations

from agent_census.model import Kind
from agent_census.pipeline import OTHER_HOSTING, RESIDENTIAL_NETWORK, KindRollup
from agent_census.report.aggregate import network_matrix


def _rollup(requests: int) -> KindRollup:
    return KindRollup(clients=1, requests=requests)


def test_collapses_smallest_datacenter_providers_into_other() -> None:
    # Eight providers (DC0 busiest ... DC7 quietest) plus a residential bucket;
    # only the top six datacenters keep their own column.
    rollups: dict[str, dict[Kind, KindRollup]] = {}
    categories: dict[str, str] = {}
    for i in range(8):
        rollups[f"DC{i}"] = {Kind.SCRAPER: _rollup(100 - i)}
        categories[f"DC{i}"] = "datacenter"
    rollups[RESIDENTIAL_NETWORK] = {Kind.BROWSER: _rollup(500)}
    categories[RESIDENTIAL_NETWORK] = "residential"

    matrix = network_matrix(rollups, categories, max_datacenter=6)

    assert matrix is not None
    assert "DC0" in matrix.networks
    assert "DC6" not in matrix.networks and "DC7" not in matrix.networks  # folded
    assert OTHER_HOSTING in matrix.networks
    # Folded cell is the sum of the two dropped providers' requests.
    assert matrix.cell(OTHER_HOSTING, Kind.SCRAPER) == (100 - 6) + (100 - 7)
    # Catch-all columns are pinned to the right; named networks read first.
    assert matrix.networks[-1] == OTHER_HOSTING
    assert matrix.networks[-2] == RESIDENTIAL_NETWORK
    # Totals are exact.
    assert matrix.row_totals[Kind.BROWSER] == 500
    assert matrix.total == sum(100 - i for i in range(8)) + 500
    # Rows follow the report's kind ordering and skip kinds with no traffic.
    assert matrix.kinds == (Kind.BROWSER, Kind.SCRAPER)


def test_egress_networks_are_never_collapsed() -> None:
    rollups = {
        "iCloud Private Relay": {Kind.BROWSER: _rollup(10)},
        RESIDENTIAL_NETWORK: {Kind.BROWSER: _rollup(20)},
    }
    categories = {"iCloud Private Relay": "egress", RESIDENTIAL_NETWORK: "residential"}

    matrix = network_matrix(rollups, categories, max_datacenter=0)

    assert matrix is not None
    assert "iCloud Private Relay" in matrix.networks  # egress stays even at cap 0
    assert OTHER_HOSTING not in matrix.networks


def test_none_when_only_residential() -> None:
    # A single residential column carries no cross-tab information.
    rollups = {RESIDENTIAL_NETWORK: {Kind.BROWSER: _rollup(10)}}
    categories = {RESIDENTIAL_NETWORK: "residential"}
    assert network_matrix(rollups, categories) is None
