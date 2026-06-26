"""Country-flag annotations for the report.

A flag is shown next to a client only when knowing its origin country *adds* signal:
the client is automation we have NOT already pinned to a specific operator. So a
verified Googlebot (global, identified) gets none, while an unknown scraper does. The
flags are computed at report time from a user-supplied MaxMind country database, bounded
to the highest-traffic eligible clients per kind so they inform without cluttering.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

from ..maxmind import CountryResolver
from ..model import ClientId, ClientProfile, Kind

# client -> (flag emoji, country name); the name is the HTML hover text.
CountryFlags = dict[ClientId, tuple[str, str]]

_FLAG_TOP = 25  # per kind, by request volume, among eligible clients
# Kinds we're fairly confident are a single human; a country flag there is noise.
_EXCLUDED_KINDS = frozenset({Kind.BROWSER, Kind.FEED_READER, Kind.APP})
# Tags meaning we've identified the *agent* by IP range / rDNS / AS -- a known global
# operator, for which a country is meaningless. (Not about datacentre vs residential.)
_IDENTIFIED_AGENT_TAGS = frozenset({"verified", "asn-associated", "asn-attributed"})


def _eligible(profile: ClientProfile) -> bool:
    return profile.classification.primary not in _EXCLUDED_KINDS and not (
        profile.classification.tags & _IDENTIFIED_AGENT_TAGS
    )


def _representative_ip(profile: ClientProfile) -> str:
    """A real IP to geolocate: a folded entry's first member, else the identity IP."""
    return profile.member_ips[0] if profile.member_ips else profile.client_id.ip


def _flag_emoji(iso_code: str) -> str:
    """A two-letter ISO code as its regional-indicator flag emoji; '' if not 2 letters."""
    code = iso_code.upper()
    if len(code) != 2 or not code.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in code)


def country_flags(profiles: Sequence[ClientProfile], resolver: CountryResolver) -> CountryFlags:
    """Map flag-eligible clients to ``(emoji, country name)``.

    Eligible = a non-human kind that we have NOT identified as a specific agent; capped
    to the top :data:`_FLAG_TOP` by request volume within each kind, and only kept when a
    country actually resolves for the client's representative IP.
    """
    by_kind: dict[Kind, list[ClientProfile]] = defaultdict(list)
    for profile in profiles:
        if _eligible(profile):
            by_kind[profile.classification.primary].append(profile)

    flags: CountryFlags = {}
    for kind_profiles in by_kind.values():
        top = sorted(kind_profiles, key=lambda p: p.features.request_count, reverse=True)
        for profile in top[:_FLAG_TOP]:
            code, name = resolver.lookup(_representative_ip(profile))
            if code:
                emoji = _flag_emoji(code)
                if emoji:
                    flags[profile.client_id] = (emoji, name or code)
    return flags
