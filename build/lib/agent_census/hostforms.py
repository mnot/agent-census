"""Host-form helpers: extracting and normalising the ``www`` / apex forms of a host.

Shared by feature extraction and the pipeline's redirect-shadow gate so the two
agree on what "the same site" and "the www form" mean. (``report.inspect_data`` has
its own parallel copies predating this module; they could later consolidate here.)
"""

from __future__ import annotations

from urllib.parse import urlsplit


def referer_host(referer: str | None) -> str | None:
    """The lowercased host of a Referer, or ``None`` for an absent/blank one."""
    if not referer or referer == "-":
        return None
    return (urlsplit(referer).hostname or "").lower() or None


def bare_host(value: str | None) -> str | None:
    """The lowercased hostname of a ``host[:port]`` (or ``[ipv6]:port``) value, port
    and brackets stripped -- for comparing a served host to a Referer host. ``None``
    when blank."""
    if not value:
        return None
    return (urlsplit("//" + value).hostname or "").lower() or None


def site_key(host: str | None) -> str | None:
    """A same-site comparison key: a single leading ``www.`` dropped so ``www`` and
    the apex read as one site. Only ``www.`` -- other subdomains are genuinely
    different hosts, and different registrable domains stay distinct."""
    if host and host.startswith("www."):
        return host[4:] or host
    return host
