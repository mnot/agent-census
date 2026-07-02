"""Country-flag annotations for the report.

A flag is shown next to a client only when knowing its origin country *adds* signal:
the client is automation we have NOT already pinned to a specific operator. So a
verified Googlebot (global, identified) gets none, while an unknown scraper does.

Flags are decided per *actor* (the render-time grouping of clients differing only by
IP/ASN), not per raw client, so a multi-IP actor reports where its traffic actually
comes from rather than wherever its busiest single IP happens to sit:

* The collapsed/summary flag is the country holding a **traffic-weighted majority**
  (>= :data:`_MAJORITY` of the actor's resolved, non-suppressed requests). Below that
  cut a neutral :data:`MULTI_ORIGIN` globe marks a genuinely spread actor.
* Each member profile contributes one country weighted by its request count. A member
  that is itself a fold of many IPs with no per-IP counts (an egress/subnet cluster)
  falls back to a per-IP-count majority among its addresses.
* IPs flagged anycast / anonymous-proxy / satellite by the database are dropped from
  the share (their country is meaningless); those traits exist only in richer tiers,
  so on a free Country database nothing is suppressed.

The maps are computed at report time from a user-supplied MaxMind database, bounded to
the highest-traffic eligible actors per kind so they inform without cluttering. HTML
renders per-member and per-IP flags on expansion; Markdown shows only the actor flag.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field

from ..maxmind import CountryResolver
from ..model import ClientId, ClientProfile, Kind
from .aggregate import ActorGroup, by_kind, group_actors

# A rendered flag: the emoji glyph and the hover text (country name, or a marker label).
CountryFlag = tuple[str, str]
MULTI_ORIGIN: CountryFlag = ("\U0001f310", "multiple origins")  # 🌐, below the majority cut

_FLAG_TOP = 25  # per kind, by request volume, among eligible actors
_MAJORITY = 0.70  # share of an actor's resolved traffic a country needs for its own flag
# Kinds we're fairly confident are a single human; a country flag there is noise.
_EXCLUDED_KINDS = frozenset({Kind.BROWSER, Kind.FEED_READER, Kind.APP})
# Tags meaning we've identified the *agent* by IP range / rDNS / signature / AS -- a
# known global operator, for which a country is meaningless. (Not about datacentre
# vs residential.)
_IDENTIFIED_AGENT_TAGS = frozenset(
    {"dns-verified", "ip-verified", "wba-verified", "asn-associated", "asn-attributed"}
)


@dataclass
class CountryFlags:
    """Resolved flags at the three levels the renderers display them.

    ``actors`` keys the collapsed/summary/lone row by its lead's id; ``members`` keys
    each expanded member row by its id; ``ips`` keys each clustered-IP row by address.
    """

    actors: dict[ClientId, CountryFlag] = field(default_factory=dict)
    members: dict[ClientId, CountryFlag] = field(default_factory=dict)
    ips: dict[str, CountryFlag] = field(default_factory=dict)

    def for_actor(self, client_id: ClientId) -> CountryFlag | None:
        return self.actors.get(client_id)

    def for_member(self, client_id: ClientId) -> CountryFlag | None:
        return self.members.get(client_id)

    def for_ip(self, ip: str) -> CountryFlag | None:
        return self.ips.get(ip)


def _eligible(profile: ClientProfile) -> bool:
    return profile.classification.primary not in _EXCLUDED_KINDS and not (
        profile.classification.tags & _IDENTIFIED_AGENT_TAGS
    )


def _flag_emoji(iso_code: str) -> str:
    """A two-letter ISO code as its regional-indicator flag emoji; '' if not 2 letters."""
    code = iso_code.upper()
    if len(code) != 2 or not code.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in code)


def _resolve(resolver: CountryResolver, ip: str) -> CountryFlag | None:
    """The flag for a single IP, or ``None`` if unresolved, suppressed, or not a real IP."""
    hit = resolver.lookup(ip)
    if hit.suppressed or not hit.iso_code:
        return None
    emoji = _flag_emoji(hit.iso_code)
    return (emoji, hit.name or hit.iso_code) if emoji else None


def _member_country(
    profile: ClientProfile, resolver: CountryResolver, flags: CountryFlags
) -> CountryFlag | None:
    """One country for a member profile, recording its per-member (and per-IP) flags.

    A single-IP member resolves directly. A member that folded many IPs keeps no
    per-IP traffic, so it falls back to a per-IP-count majority (a strict majority of
    its resolved, non-suppressed addresses); each of those IPs is also flagged for the
    HTML clustered-IP rows.
    """
    if not profile.member_ips:
        flag = _resolve(resolver, profile.client_id.ip)
        if flag:
            flags.members[profile.client_id] = flag
        return flag

    counts: Counter[str] = Counter()
    by_glyph: dict[str, CountryFlag] = {}
    for ip in profile.member_ips:
        flag = _resolve(resolver, ip)
        if flag:
            flags.ips[ip] = flag
            counts[flag[0]] += 1
            by_glyph[flag[0]] = flag
    total = sum(counts.values())
    if not total:
        return None
    glyph, top = counts.most_common(1)[0]
    if top * 2 > total:  # strict majority of the resolved addresses
        flags.members[profile.client_id] = by_glyph[glyph]
        return by_glyph[glyph]
    return None


def _flag_actor(actor: ActorGroup, resolver: CountryResolver, flags: CountryFlags) -> None:
    """Decide and record an actor's summary flag from its members' traffic-weighted countries."""
    weighted: Counter[str] = Counter()
    by_glyph: dict[str, CountryFlag] = {}
    for member in actor.members:
        flag = _member_country(member, resolver, flags)
        if flag:
            weighted[flag[0]] += member.features.request_count
            by_glyph[flag[0]] = flag
    total = sum(weighted.values())
    if not total:
        return
    glyph, top = weighted.most_common(1)[0]
    flags.actors[actor.lead.client_id] = (
        by_glyph[glyph] if top >= _MAJORITY * total else MULTI_ORIGIN
    )


def country_flags(profiles: Sequence[ClientProfile], resolver: CountryResolver) -> CountryFlags:
    """Resolve flags for the flag-eligible actors, grouped exactly as the report displays them.

    Eligible = a non-human kind we have NOT identified as a specific agent; capped to the
    top :data:`_FLAG_TOP` actors by request volume within each kind.
    """
    flags = CountryFlags()
    for kind, group in by_kind(tuple(profiles)).items():
        if kind in _EXCLUDED_KINDS:
            continue
        actors = [a for a in group_actors(group) if _eligible(a.lead)]
        actors.sort(key=lambda a: a.requests, reverse=True)
        for actor in actors[:_FLAG_TOP]:
            _flag_actor(actor, resolver, flags)
    return flags
