"""Tests for the shared IP-range fetch/parse helpers."""

from __future__ import annotations

from agent_census.iprange import RangeIndex, extract_cidrs, ip_in, parse_networks


def test_parse_prefixes_gcp_schema() -> None:
    text = '{"prefixes": [{"ipv4Prefix": "8.8.8.0/24"}, {"ipv6Prefix": "2001:db8::/32"}]}'
    assert extract_cidrs(text, "prefixes") == ("8.8.8.0/24", "2001:db8::/32")


def test_parse_aws_schema() -> None:
    text = (
        '{"prefixes": [{"ip_prefix": "52.0.0.0/8"}], '
        '"ipv6_prefixes": [{"ipv6_prefix": "2600:1f00::/24"}]}'
    )
    assert extract_cidrs(text, "aws") == ("52.0.0.0/8", "2600:1f00::/24")


def test_parse_azure_schema() -> None:
    text = '{"values": [{"properties": {"addressPrefixes": ["20.0.0.0/8", "40.0.0.0/8"]}}]}'
    assert extract_cidrs(text, "azure") == ("20.0.0.0/8", "40.0.0.0/8")


def test_parse_text_list() -> None:
    text = "173.245.48.0/20\n# a comment\n\n103.21.244.0/22\n"
    assert extract_cidrs(text, "text") == ("173.245.48.0/20", "103.21.244.0/22")


def test_parse_csv_first_column() -> None:
    text = "1.2.3.0/24,US,California,SF\n5.6.7.0/24,AU,NSW,Sydney\nheader,without,prefix\n"
    assert extract_cidrs(text, "csv") == ("1.2.3.0/24", "5.6.7.0/24")


def test_parse_subnets_vultr_schema() -> None:
    text = '{"subnets": [{"ip_prefix": "45.32.0.0/21"}, {"ip_prefix": "43.224.32.0/22"}]}'
    assert extract_cidrs(text, "subnets") == ("45.32.0.0/21", "43.224.32.0/22")


def test_parse_oracle_schema() -> None:
    text = (
        '{"regions": [{"region": "iad", "cidrs": ['
        '{"cidr": "40.233.0.0/19", "tags": ["OCI"]}, {"cidr": "139.177.96.0/21"}]}]}'
    )
    assert extract_cidrs(text, "oracle") == ("40.233.0.0/19", "139.177.96.0/21")


def test_unknown_format_falls_back_to_prefixes() -> None:
    text = '{"prefixes": [{"ipv4Prefix": "9.9.9.0/24"}]}'
    assert extract_cidrs(text, "bogus") == ("9.9.9.0/24",)


def test_range_index_membership() -> None:
    idx = RangeIndex.from_networks(parse_networks(("10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32")))
    assert idx.contains("10.1.2.3")
    assert idx.contains("192.168.5.5")
    assert idx.contains("2001:db8::1")
    assert not idx.contains("11.0.0.1")
    assert not idx.contains("8.8.8.8")
    assert not idx.contains("not-an-ip")


def test_range_index_empty_is_false() -> None:
    assert not RangeIndex([], []).contains("1.2.3.4")


def test_fetch_range_intervals_caches_the_parse(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import agent_census.iprange as ir

    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    calls = {"n": 0}

    def fake_get(_url: str) -> str:
        calls["n"] += 1
        return "203.0.113.0/24\n198.51.100.0/24\n"

    monkeypatch.setattr(ir, "_http_get", fake_get)
    url = "https://example.invalid/list.txt"
    v4, v6 = ir.fetch_range_intervals(url, "text")
    assert len(v4) == 2 and not v6
    again, _ = ir.fetch_range_intervals(url, "text")
    assert again == v4
    assert calls["n"] == 1  # second call served from the parsed-intervals cache


def test_ip_in_respects_version_and_membership() -> None:
    nets = parse_networks(("1.2.3.0/24",))
    assert ip_in("1.2.3.4", nets) is not None
    assert ip_in("9.9.9.9", nets) is None
    assert ip_in("not-an-ip", nets) is None
