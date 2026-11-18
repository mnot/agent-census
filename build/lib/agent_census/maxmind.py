"""MaxMind database lookups: origin AS (for logs without one) and origin country.

Servers that run ``mod_maxminddb`` log the origin AS directly (e.g. ``%{MM_ASN}e``);
those that don't leave :class:`~agent_census.model.ClientFeatures` without it, which
blanks out ASN-based datacentre / egress / crawler recognition. Pointing
``--mm-asn-db`` at a MaxMind-format database fills that gap from the client IP, and
-- since the database can be fresher than an old log -- takes precedence over a
logged AS when it has an answer. ``--mm-country-db`` adds the origin country, used to
flag high-traffic, unidentified non-human clients in the report.

Rather than a path per database, ``--mm-db-dir`` can point at a directory (e.g. a
``geoipupdate`` target); :func:`discover_mm_dir` then routes each ``.mmdb`` by its
metadata type, so an explicit ``--mm-asn-db`` / ``--mm-country-db`` is only needed for
an oddly-named or out-of-tree file (and overrides the directory for its role).

The reader (``maxminddb``) is bundled. The databases are not: MaxMind's licence
forbids redistributing GeoLite2, the files are several MB, and they go stale, so the
user supplies the path. Only the standard ASN / country fields are read, so any
matching ``.mmdb`` (GeoLite2, IPinfo, DB-IP) works.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import maxminddb

from .errors import ConfigError


@dataclass
class AsnResolver:
    """Resolves an IP to its ``(asn, org)`` from a MaxMind-format database."""

    reader: maxminddb.Reader
    build_epoch: int | None = None  # the DB's build time, for the staleness warning

    def lookup(self, ip: str) -> tuple[int | None, str | None]:
        """The ``(asn, org)`` for ``ip``; ``(None, None)`` if absent or not a real IP."""
        try:
            record = self.reader.get(ip)
        except ValueError:  # not a valid address (e.g. a folded synthetic key)
            return None, None
        if not isinstance(record, dict):
            return None, None
        asn = record.get("autonomous_system_number")
        org = record.get("autonomous_system_organization")
        return (
            asn if isinstance(asn, int) else None,
            org if isinstance(org, str) and org else None,
        )

    def close(self) -> None:
        self.reader.close()


@dataclass(frozen=True)
class CountryHit:
    """A country lookup result: the ISO code, the English name, and a location-meaningless flag.

    ``suppressed`` is set when the IP's traits mark it anycast, an anonymising
    proxy, or a satellite provider -- cases where a single origin country is
    meaningless. Those traits live only in the City / Enterprise / Anonymous-IP
    tiers; a free Country database carries no ``traits`` block, so ``suppressed``
    is simply always ``False`` there.
    """

    iso_code: str | None = None
    name: str | None = None
    suppressed: bool = False


_SUPPRESS_TRAITS = ("is_anycast", "is_anonymous_proxy", "is_satellite_provider")


@dataclass
class CountryResolver:
    """Resolves an IP to its :class:`CountryHit` from a MaxMind database."""

    reader: maxminddb.Reader
    build_epoch: int | None = None  # the DB's build time, for the staleness warning

    def lookup(self, ip: str) -> CountryHit:
        """The :class:`CountryHit` for ``ip``; an empty hit if absent or not a real IP."""
        try:
            record = self.reader.get(ip)
        except ValueError:  # not a valid address (e.g. a folded synthetic key)
            return CountryHit()
        if not isinstance(record, dict):
            return CountryHit()
        country = record.get("country")
        if not isinstance(country, dict):
            return CountryHit()
        code = country.get("iso_code")
        names = country.get("names")
        name = names.get("en") if isinstance(names, dict) else None
        traits = record.get("traits")
        suppressed = isinstance(traits, dict) and any(traits.get(t) for t in _SUPPRESS_TRAITS)
        return CountryHit(
            iso_code=code if isinstance(code, str) and code else None,
            name=name if isinstance(name, str) and name else None,
            suppressed=bool(suppressed),
        )

    def close(self) -> None:
        self.reader.close()


def _open(path: Path) -> tuple[maxminddb.Reader, int | None]:
    """Open a MaxMind database and read its build time, raising ``ConfigError`` on failure."""
    try:
        reader = maxminddb.open_database(str(path))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"could not open MaxMind database {path}: {exc}") from exc
    try:
        build_epoch = reader.metadata().build_epoch
    except (AttributeError, ValueError):  # minimal/exotic reader -- skip the skew check
        build_epoch = None
    return reader, build_epoch


def open_asn_db(path: Path) -> AsnResolver:
    """Open a MaxMind ASN database, raising :class:`ConfigError` on any problem."""
    return AsnResolver(*_open(path))


def open_country_db(path: Path) -> CountryResolver:
    """Open a MaxMind country (or city) database, raising :class:`ConfigError` on any problem."""
    return CountryResolver(*_open(path))


# A database's ``database_type`` metadata, matched case-insensitively as a substring,
# tells us what each ``.mmdb`` in a directory carries -- regardless of its filename, so
# the free GeoLite2-*, the commercial GeoIP2-*, and third-party (IPinfo, DB-IP) names
# all route correctly. Listed best-first: a dedicated database wins over a richer one
# that merely happens to include the same field (ISP/Enterprise carry an AS; City and
# Enterprise carry a country block).
_ASN_TYPES = ("ASN", "ISP", "Enterprise")
_COUNTRY_TYPES = ("Country", "City", "Enterprise")


@dataclass(frozen=True)
class DiscoveredDbs:
    """The best ASN and country ``.mmdb`` found in a directory (either may be ``None``)."""

    asn: Path | None = None
    country: Path | None = None


def _db_type(path: Path) -> str | None:
    """A database's ``database_type`` metadata string, or ``None`` if it won't open."""
    try:
        reader = maxminddb.open_database(str(path))
    except (OSError, ValueError):
        return None
    try:
        return str(reader.metadata().database_type)
    except (AttributeError, ValueError):
        return None
    finally:
        reader.close()


def discover_mm_dir(
    directory: Path, *, type_of: Callable[[Path], str | None] = _db_type
) -> DiscoveredDbs:
    """Find the best ASN and country ``.mmdb`` in ``directory`` by each file's metadata type.

    Filenames are not trusted: every ``*.mmdb`` is opened and routed by its
    ``database_type`` (see :data:`_ASN_TYPES` / :data:`_COUNTRY_TYPES`), so any vendor's
    naming works. When several files can fill a role the more specific one wins; ties
    break on filename for determinism. Raises :class:`ConfigError` if ``directory`` is
    not a directory.
    """
    if not directory.is_dir():
        raise ConfigError(f"not a directory: {directory}")

    def _best(candidates: tuple[str, ...], db_type: str) -> int | None:
        low = db_type.lower()
        for rank, key in enumerate(candidates):
            if key.lower() in low:
                return rank
        return None

    asn_rank: int | None = None
    asn_path: Path | None = None
    country_rank: int | None = None
    country_path: Path | None = None
    for path in sorted(directory.glob("*.mmdb")):
        db_type = type_of(path)
        if not db_type:
            continue
        rank = _best(_ASN_TYPES, db_type)
        if rank is not None and (asn_rank is None or rank < asn_rank):
            asn_rank, asn_path = rank, path
        rank = _best(_COUNTRY_TYPES, db_type)
        if rank is not None and (country_rank is None or rank < country_rank):
            country_rank, country_path = rank, path
    return DiscoveredDbs(asn=asn_path, country=country_path)
