"""Tests for the shared IP-range fetch/parse helpers."""

from __future__ import annotations

from agent_census.iprange import extract_cidrs, ip_in, parse_networks


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


def test_ip_in_respects_version_and_membership() -> None:
    nets = parse_networks(("1.2.3.0/24",))
    assert ip_in("1.2.3.4", nets) is not None
    assert ip_in("9.9.9.9", nets) is None
    assert ip_in("not-an-ip", nets) is None
