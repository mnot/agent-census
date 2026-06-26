"""MaxMind database lookups: origin AS (for logs without one) and origin country.

Servers that run ``mod_maxminddb`` log the origin AS directly (e.g. ``%{MM_ASN}e``);
those that don't leave :class:`~agent_census.model.ClientFeatures` without it, which
blanks out ASN-based datacentre / egress / crawler recognition. Pointing
``--mm-asn-db`` at a MaxMind-format database fills that gap from the client IP, and
-- since the database can be fresher than an old log -- takes precedence over a
logged AS when it has an answer. ``--mm-country-db`` adds the origin country, used to
flag high-traffic, unidentified non-human clients in the report.

The reader (``maxminddb``) is bundled. The databases are not: MaxMind's licence
forbids redistributing GeoLite2, the files are several MB, and they go stale, so the
user supplies the path. Only the standard ASN / country fields are read, so any
matching ``.mmdb`` (GeoLite2, IPinfo, DB-IP) works.
"""

from __future__ import annotations

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


@dataclass
class CountryResolver:
    """Resolves an IP to its ``(iso_code, country_name)`` from a MaxMind database."""

    reader: maxminddb.Reader
    build_epoch: int | None = None  # the DB's build time, for the staleness warning

    def lookup(self, ip: str) -> tuple[str | None, str | None]:
        """The ``(ISO code, name)`` for ``ip``; ``(None, None)`` if absent or not a real IP."""
        try:
            record = self.reader.get(ip)
        except ValueError:  # not a valid address (e.g. a folded synthetic key)
            return None, None
        if not isinstance(record, dict):
            return None, None
        country = record.get("country")
        if not isinstance(country, dict):
            return None, None
        code = country.get("iso_code")
        names = country.get("names")
        name = names.get("en") if isinstance(names, dict) else None
        return (
            code if isinstance(code, str) and code else None,
            name if isinstance(name, str) and name else None,
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
