"""Offline tests for the audit helpers (no network: parsing, matching, rendering)."""

from __future__ import annotations

import pytest

from agent_census import userconfig
from agent_census.audit import (
    AsnReport,
    _asn_bullet,
    _assessment,
    _bot_note,
    _concerns,
    _names_match,
    _org_tokens,
    _parse_asns,
    _resolve_token,
    _render_concerns,
    _render_suggestion,
    _sib_label,
)


def test_parse_asns_accepts_as_prefix_and_separators() -> None:
    assert _parse_asns("AS123, 456  789\nas1011") == [123, 456, 789, 1011]
    assert _parse_asns("garbage, , AS") == []


def test_parse_asns_rejects_out_of_range_and_absurd_tokens() -> None:
    # Above the 32-bit ASN ceiling is dropped, not accepted.
    assert _parse_asns("4294967296") == []
    # A multi-thousand-digit token must not crash int() (4300-digit limit).
    assert _parse_asns("9" * 100_000) == []


def test_org_tokens_drops_generic_words() -> None:
    assert _org_tokens("Hetzner Online GmbH") == {"hetzner"}  # 'online'/'gmbh' generic
    assert _org_tokens("Amazon.com, Inc.") == {"amazon", "com"}
    assert _org_tokens("Google Cloud") == {"google"}  # 'cloud' is generic


def test_org_tokens_folds_dotted_acronyms() -> None:
    # "F.N.S." would otherwise tokenise to nothing (single letters dropped, rest generic).
    assert "fns" in _org_tokens("F.N.S. HOLDINGS LIMITED")
    assert _names_match("FNS", "F.N.S. Holdings Limited")
    assert _names_match("F.N.S.", "SECFIREWALLAS F.N.S. HOLDINGS LIMITED")
    # A lone single letter is not an acronym, and adjacency is required.
    assert "a" not in _org_tokens("A Small Orange")


def test_names_match_is_token_overlap() -> None:
    assert _names_match("Amazon AWS", "Amazon Web Services")
    assert _names_match("Hetzner", "Hetzner Online GmbH")
    assert _names_match("OVH", "OVH SAS")
    assert not _names_match("Hetzner", "ORG-HOA1-RIPE")  # RIR handle, no brand token
    assert not _names_match("Hetzner", None)


def test_names_match_accepts_prefix_and_joined_forms() -> None:
    assert _names_match("OVH", "OVHcloud")  # suffixed
    assert _names_match("DigitalOcean", "Digital Ocean")  # joined vs spaced
    assert _names_match("Cherry Servers", "cherryservers SG-Singapore")
    assert not _names_match("Vultr", "The Constant Company, LLC")  # genuinely different name


def _report(**kw: object) -> AsnReport:
    base: dict[str, object] = {"asn": 123, "radar_known": True}
    base.update(kw)
    return AsnReport(**base)  # type: ignore[arg-type]


def test_bot_note_bands() -> None:
    assert _bot_note(_report(bot_pct=99.0)).endswith("datacentre-like")
    assert _bot_note(_report(bot_pct=60.0)).endswith("mixed")
    assert _bot_note(_report(bot_pct=20.0)).endswith("mostly human")
    assert _bot_note(_report(bot_pct=None)) == "bot %: unknown"
    assert "low confidence" in _bot_note(_report(bot_pct=90.0, bot_low_confidence=True))


def test_asn_bullet_markdown_and_sibling_suggestion() -> None:
    report = _report(
        radar_org="Hetzner Online GmbH",
        bot_pct=93.0,
        pdb_checked=True,
        pdb_name="Hetzner",
        pdb_type="NSP",
    )
    # Siblings are pre-filtered to datacentre-like ones by the caller; each carries
    # its own automated-traffic share.
    bullet = _asn_bullet(report, [(215859, "HETZNER-CLOUD4-AS", 96.0)])
    # One fact per sub-bullet, indented under the ASN heading.
    assert bullet.startswith("- **AS123**\n")
    assert "\n  - Radar: Hetzner Online GmbH" in bullet
    assert "\n  - 93% automated -- datacentre-like" in bullet
    assert "\n  - PeeringDB: Hetzner [NSP]" in bullet
    assert (
        "\n  - datacentre siblings, not listed: AS215859 HETZNER-CLOUD4-AS (96% automated)"
        in bullet
    )


def test_unknown_asn_bullet() -> None:
    assert _asn_bullet(_report(radar_known=False), []) == (
        "- **AS123**\n  - Radar: unknown ASN (dead / unrouted?)"
    )


def test_sib_label_shows_automation() -> None:
    assert _sib_label(215859, "HETZNER-CLOUD4-AS", 96.0) == "AS215859 HETZNER-CLOUD4-AS (96% automated)"
    assert _sib_label(123, "", 90.0) == "AS123 (90% automated)"  # no name -> no stray space


def test_bullet_shows_ripe_holder() -> None:
    bullet = _asn_bullet(_report(radar_org="X", bot_pct=90.0, ripe_holder="AS-VULTR - Vultr"), [])
    assert "\n  - RIPE: AS-VULTR - Vultr" in bullet


def test_assessment_bands() -> None:
    assert "datacentre" in _assessment(_report(bot_pct=99.0))
    assert _assessment(_report(bot_pct=60.0)).startswith("mixed")
    assert "eyeball ISP" in _assessment(_report(bot_pct=10.0))
    assert "can't assess" in _assessment(_report(radar_known=False))
    assert "no traffic data" in _assessment(_report(bot_pct=None))


def test_assessment_appends_peeringdb_type_hint() -> None:
    # PeeringDB's self-declared type rides along as a hint, without changing the lead.
    dc = _assessment(_report(bot_pct=99.0, pdb_type="Content"))
    assert dc.startswith("datacentre") and dc.endswith("PeeringDB calls it Content")
    # Even with no Radar traffic data, PeeringDB can still say something useful.
    assert _assessment(_report(bot_pct=None, pdb_type="Enterprise")) == (
        "no Radar traffic data; PeeringDB calls it Enterprise"
    )


def test_asn_bullet_includes_assessment_subbullet() -> None:
    bullet = _asn_bullet(
        _report(radar_org="X", bot_pct=99.0), [], assessment="datacentre / hosting"
    )
    assert "\n  - assessment: datacentre / hosting" in bullet


def test_resolve_token_persists_explicit_and_reads_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CF_API_TOKEN", raising=False)
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    assert _resolve_token(None) is None  # nothing saved yet
    assert _resolve_token("cfat_secret") == "cfat_secret"  # explicit token is persisted
    assert userconfig.load()["cf_api_token"] == "cfat_secret"
    assert _resolve_token(None) == "cfat_secret"  # read back from config


def test_resolve_token_env_beats_saved(monkeypatch: pytest.MonkeyPatch) -> None:
    _resolve_token("cfat_saved")
    monkeypatch.setenv("CF_API_TOKEN", "cfat_env")
    assert _resolve_token(None) == "cfat_env"  # env wins over the saved token


def test_concerns_categorises_by_type() -> None:
    # A clean, datacentre-like, correctly-named entry raises nothing.
    assert _concerns(_report(radar_org="Hetzner Online GmbH", bot_pct=95.0), "Hetzner") == []
    # Wrong name and low traffic are *separate* concerns, both raised at once.
    headings = {h for h, _key, _msg in _concerns(_report(radar_org="Some ISP", bot_pct=10.0), "Hetzner")}
    assert "Wrong name" in headings and "Traffic mix" in headings
    # The traffic-mix sort key is the bot %, so the section can be ordered least-automated first.
    (mix,) = [t for t in _concerns(_report(radar_org="Hetzner", bot_pct=10.0), "Hetzner")
              if t[0] == "Traffic mix"]
    assert mix[1] == 10.0
    # An unknown ASN is its own category and short-circuits the rest.
    dead = _concerns(_report(radar_known=False), "Hetzner")
    assert [h for h, _key, _msg in dead] == ["Unknown / dead ASNs"]


def test_concerns_ripe_holder_corroborates_label() -> None:
    # Radar's friendly name is the new parent (Akamai), but the registry handle still
    # carries our brand (Linode) -> not a wrong-name concern.
    quiet = _concerns(
        _report(radar_org="Akamai Connected Cloud", bot_pct=95.0,
                ripe_holder="AKAMAI-LINODE-AP - Akamai Connected Cloud"),
        "Linode",
    )
    assert all(h != "Wrong name" for h, _key, _msg in quiet)
    # When neither Radar nor RIPE backs the label, it's flagged and RIPE is quoted.
    (_h, _k, msg), = [t for t in _concerns(
        _report(radar_org="Some ISP", bot_pct=95.0, ripe_holder="SOME-ISP - Some ISP"), "Hetzner"
    ) if t[0] == "Wrong name"]
    assert "RIPE has 'SOME-ISP - Some ISP'" in msg
    # When Radar doesn't know an ASN, fall back to RIPE and PeeringDB both.
    (_h, _k, msg) = _concerns(
        _report(radar_known=False, ripe_holder="ACME-AS - Acme", pdb_name="Acme", pdb_type="NSP"),
        "Acme",
    )[0]
    assert "the RIPE registry has 'ACME-AS - Acme'" in msg
    assert "PeeringDB has 'Acme' [NSP]" in msg
    # Nothing anywhere -> name every source that was consulted and drew a blank.
    (_h2, _k2, msg2) = _concerns(_report(radar_known=False, pdb_checked=True), "Acme")[0]
    assert msg2.endswith("unknown to Radar, RIPE and PeeringDB -- dead or unrouted?")
    # With PeeringDB skipped (--no-peeringdb), don't claim it was checked.
    (_h3, _k3, msg3) = _concerns(_report(radar_known=False), "Acme")[0]
    assert msg3.endswith("unknown to Radar and RIPE -- dead or unrouted?")


def test_render_suggestion_inline_vs_sublist() -> None:
    # One sibling stays on the provider line.
    assert _render_suggestion("Hetzner", [(215859, "HC", 96.0)]) == (
        "- Hetzner: AS215859 HC (96% automated)"
    )
    # Several become a sub-list, one per line.
    assert _render_suggestion("Google Cloud", [(1, "A", 90.0), (2, "B", 88.0)]) == (
        "- Google Cloud:\n  - AS1 A (90% automated)\n  - AS2 B (88% automated)"
    )


def test_render_concerns_groups_and_falls_back() -> None:
    rendered = "\n".join(
        _render_concerns(
            {"Wrong name": [(0.0, "AS1: x")]},
            [_render_suggestion("Prov", [(2, "SIB", 91.0)])],
            ["AS3: dup"],
        )
    )
    assert "## Wrong name" in rendered
    assert "## Suggested additions (datacentre siblings)" in rendered and "AS2 SIB" in rendered
    assert "## Duplicate ASNs" in rendered
    assert "Nothing flagged" in "\n".join(_render_concerns({}, [], []))


def test_concerns_traffic_mix_can_be_suppressed_for_egress() -> None:
    report = _report(radar_org="StrongVPN", bot_pct=8.0, ripe_holder="StrongVPN")
    # Datacentre: low automation is suspect and flagged.
    assert any(h == "Traffic mix" for h, _k, _m in _concerns(report, "StrongVPN"))
    # Egress: low automation is normal, so no traffic concern (name still checked).
    assert all(h != "Traffic mix" for h, _k, _m in _concerns(report, "StrongVPN", flag_traffic_mix=False))


def test_traffic_mix_line_carries_peeringdb_hint() -> None:
    (_h, _k, msg), = [
        t for t in _concerns(_report(radar_org="X", bot_pct=10.0, pdb_type="Cable/DSL/ISP"), "X")
        if t[0] == "Traffic mix"
    ]
    assert msg.endswith("according to Radar; PeeringDB calls it Cable/DSL/ISP")


def test_render_concerns_emits_extra_sections() -> None:
    rendered = "\n".join(
        _render_concerns(
            {}, [], [], extras=(("Automation per network (informational)", ["AS1: 8% automated"]),)
        )
    )
    assert "## Automation per network (informational)" in rendered
    assert "AS1: 8% automated" in rendered
    assert "Nothing flagged" not in rendered  # an extra section counts as content


def test_render_concerns_sorts_traffic_mix_least_automated_first() -> None:
    rendered = "\n".join(
        _render_concerns({"Traffic mix": [(40.0, "AS40: forty"), (5.0, "AS5: five")]}, [], [])
    )
    assert rendered.index("AS5: five") < rendered.index("AS40: forty")
