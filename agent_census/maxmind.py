"""MaxMind ASN lookups, for logs that don't carry an AS number.

Servers that run ``mod_maxminddb`` log the origin AS directly (e.g. ``%{MM_ASN}e``);
those that don't leave :class:`~agent_census.model.ClientFeatures` without it, which
blanks out ASN-based datacentre / egress / crawler recognition. Pointing
``--mm-asn-db`` at a MaxMind-format database fills that gap from the client IP, and
-- since the database can be fresher than an old log -- takes precedence over a
logged AS when it has an answer.

The reader (``maxminddb``) is bundled. The database itself is not: MaxMind's licence
forbids redistributing GeoLite2, the file is several MB, and it goes stale, so the
user supplies the path. Only the two standard ASN fields are read, so any ASN-bearing
``.mmdb`` (GeoLite2-ASN, IPinfo, DB-IP) works. The flag is namespaced ``-asn-`` to
leave room for City/Country databases later; this module is their natural home too.
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


def open_asn_db(path: Path) -> AsnResolver:
    """Open a MaxMind ASN database, raising :class:`ConfigError` on any problem."""
    try:
        reader = maxminddb.open_database(str(path))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"could not open MaxMind database {path}: {exc}") from exc
    try:
        build_epoch = reader.metadata().build_epoch
    except (AttributeError, ValueError):  # minimal/exotic reader -- skip the skew check
        build_epoch = None
    return AsnResolver(reader, build_epoch)
