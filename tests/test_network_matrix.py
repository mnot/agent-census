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
    # Hosting reads first (named providers, then the Other-hosting catch-all);
    # the residential bucket is pinned far right.
    assert matrix.networks[-1] == RESIDENTIAL_NETWORK
    assert matrix.networks[-2] == OTHER_HOSTING
    assert matrix.is_hosting(OTHER_HOSTING) and not matrix.is_hosting(RESIDENTIAL_NETWORK)
    # Totals are exact.
    assert matrix.row_totals[Kind.BROWSER] == 500
    assert matrix.total == sum(100 - i for i in range(8)) + 500
    # Rows follow the report's kind ordering and skip kinds with no traffic.
    assert matrix.kinds == (Kind.BROWSER, Kind.SCRAPER)


def test_promotes_substantial_datacenter_beyond_top_n() -> None:
    # Top six always shown; a seventh that's big enough earns its own column, an
    # eighth that's negligible folds into Other.
    rollups: dict[str, dict[Kind, KindRollup]] = {}
    categories: dict[str, str] = {}
    for i in range(6):
        rollups[f"DC{i}"] = {Kind.SCRAPER: _rollup(1000)}
        categories[f"DC{i}"] = "datacenter"
    rollups["Promoted"] = {Kind.SCRAPER: _rollup(800)}  # clears the per-kind floor + guard
    categories["Promoted"] = "datacenter"
    rollups["TinyFold"] = {Kind.SCRAPER: _rollup(50)}  # below the 100-request guard
    categories["TinyFold"] = "datacenter"

    matrix = network_matrix(rollups, categories, max_datacenter=6)

    assert matrix is not None
    assert "Promoted" in matrix.networks  # its own column
    assert "TinyFold" not in matrix.networks  # folded
    assert matrix.cell(OTHER_HOSTING, Kind.SCRAPER) == 50


def test_top_n_always_shown_exempt_from_guard() -> None:
    # Seven datacentres, all below the 100-request guard. The top six are shown
    # regardless; the seventh, beyond the baseline, folds.
    rollups: dict[str, dict[Kind, KindRollup]] = {}
    categories: dict[str, str] = {}
    for i in range(7):
        rollups[f"DC{i}"] = {Kind.SCRAPER: _rollup(20 - i)}  # all tiny, below the guard
        categories[f"DC{i}"] = "datacenter"

    matrix = network_matrix(rollups, categories, max_datacenter=6)

    assert matrix is not None
    for i in range(6):
        assert f"DC{i}" in matrix.networks  # top six shown despite < 100 requests each
    assert "DC6" not in matrix.networks  # seventh folds
    assert OTHER_HOSTING in matrix.networks


def test_guard_blocks_tiny_provider_that_dominates_a_small_kind() -> None:
    # Niche owns 91% of the (tiny) browser kind but only 20 requests overall: the
    # per-kind floor alone would promote it, but the absolute guard folds it.
    rollups: dict[str, dict[Kind, KindRollup]] = {}
    categories: dict[str, str] = {}
    for i in range(6):
        rollups[f"DC{i}"] = {Kind.SCRAPER: _rollup(1000)}
        categories[f"DC{i}"] = "datacenter"
    rollups["Niche"] = {Kind.BROWSER: _rollup(20)}
    categories["Niche"] = "datacenter"

    matrix = network_matrix(rollups, categories, max_datacenter=6)
    assert matrix is not None
    assert "Niche" not in matrix.networks  # 20 < 100-request guard
    assert matrix.cell(OTHER_HOSTING, Kind.BROWSER) == 20

    # Drop the guard and the per-kind win alone promotes it.
    noguard = network_matrix(
        rollups, categories, max_datacenter=6, guard_requests=0, guard_share=0.0
    )
    assert noguard is not None
    assert "Niche" in noguard.networks


def test_per_kind_floor_promotes_provider_concentrated_in_one_kind() -> None:
    # A provider that's a sliver of overall traffic but a big share of one small
    # kind -- and clears the absolute guard -- earns its own column; a same-size
    # provider that clears the guard but no kind's 10% folds.
    rollups: dict[str, dict[Kind, KindRollup]] = {}
    categories: dict[str, str] = {}
    for i in range(6):
        rollups[f"DC{i}"] = {Kind.SCRAPER: _rollup(5000)}
        categories[f"DC{i}"] = "datacenter"
    rollups["Niche"] = {Kind.BROWSER: _rollup(300)}  # 100% of a tiny kind, > guard
    categories["Niche"] = "datacenter"
    rollups["Spread"] = {Kind.SCRAPER: _rollup(120)}  # clears guard, but <10% of any kind
    categories["Spread"] = "datacenter"

    matrix = network_matrix(rollups, categories, max_datacenter=6)

    assert matrix is not None
    assert "Niche" in matrix.networks  # promoted on its browser share
    assert "Spread" not in matrix.networks  # negligible within every kind


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


def test_other_hosting_sits_left_of_egress_and_residential() -> None:
    rollups = {
        "DC0": {Kind.SCRAPER: _rollup(100)},
        "DC1": {Kind.SCRAPER: _rollup(90)},
        "iCloud Private Relay": {Kind.BROWSER: _rollup(50)},
        RESIDENTIAL_NETWORK: {Kind.BROWSER: _rollup(200)},
    }
    categories = {
        "DC0": "datacenter",
        "DC1": "datacenter",
        "iCloud Private Relay": "egress",
        RESIDENTIAL_NETWORK: "residential",
    }
    matrix = network_matrix(rollups, categories, max_datacenter=1)  # DC1 folds

    cols = list(matrix.networks)  # type: ignore[union-attr]
    assert cols.index(OTHER_HOSTING) < cols.index("iCloud Private Relay")  # hosting first
    assert cols.index("iCloud Private Relay") < cols.index(RESIDENTIAL_NETWORK)
    assert cols == ["DC0", OTHER_HOSTING, "iCloud Private Relay", RESIDENTIAL_NETWORK]


def test_none_when_only_residential() -> None:
    # A single residential column carries no cross-tab information.
    rollups = {RESIDENTIAL_NETWORK: {Kind.BROWSER: _rollup(10)}}
    categories = {RESIDENTIAL_NETWORK: "residential"}
    assert network_matrix(rollups, categories) is None
