"""The ``agent-census wba-check`` subcommand: validate a host's Web Bot Auth setup.

Fetches an operator's published key directory
(``/.well-known/http-message-signatures-directory``, per
draft-meunier-http-message-signatures-directory) and checks the handful of things
:mod:`agent_census.wba`'s own verifier relies on: that it's reachable over HTTPS,
serves valid JSON with a ``keys`` array, and that each key is a well-formed
Ed25519 JWK whose declared ``kid`` (if any) actually matches its RFC 7638
thumbprint -- the value a ``keyid`` in a Web Bot Auth signature must name, and
the value the verifier's key store keys on (see ``WbaVerifier._fetch_directory``,
which stores under the recomputed thumbprint, never the claimed ``kid``).

This is not a conformance test suite for the draft -- just enough to catch the
mistakes that would keep signed requests from this host from verifying, and to
hand back ready-to-paste ``agent_urls`` / ``keyids`` for a new ``[[operator]]``
entry in ``data/agents/web_bot_auth.toml``. Standard library only, one fetch.
"""

from __future__ import annotations

import http.client
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from . import USER_AGENT
from .wba import WELL_KNOWN_DIRECTORY, jwk_thumbprint, public_key_from_jwk

_TIMEOUT = 10
_MAX_BYTES = 4 * 1024 * 1024  # cap the directory body so a hostile host can't OOM us
_EXPECTED_CONTENT_TYPE = "application/http-message-signatures-directory+json"
# Only these two are ever fetched. urlsplit accepts any scheme (file, ftp, data,
# ...) without complaint, and urlopen will happily follow one -- so this is a
# hard allowlist, checked before any request is made, not just a warning.
_ALLOWED_SCHEMES = frozenset({"http", "https"})

Level = str  # "ok" | "warn" | "error"
_MARK = {"ok": "[ok]   ", "warn": "[warn] ", "error": "[error]"}


@dataclass
class Check:
    level: Level
    message: str


def _origin(raw: str) -> tuple[str | None, list[Check]]:
    """Normalise ``raw`` (a bare host or a URL) to a scheme://host origin, or
    ``None`` with an explanatory check if it doesn't parse, carries a scheme this
    tool refuses to fetch, or doesn't resolve to a host at all."""
    text = raw.strip()
    if "://" not in text:
        text = f"https://{text}"
    try:
        parts = urllib.parse.urlsplit(text)
        host, port = parts.hostname, parts.port
    except ValueError as exc:  # e.g. a malformed IPv6 literal or a non-numeric port
        return None, [Check("error", f"{raw!r} doesn't look like a host or URL: {exc}")]
    # urlsplit doesn't validate netloc content -- "https://not a host!!" splits
    # cleanly with that whole string as the netloc -- so reject whitespace/control
    # characters here rather than let them surface later as a raw socket error.
    if not host or any(not ch.isprintable() or ch.isspace() for ch in host):
        return None, [Check("error", f"{raw!r} doesn't look like a host or URL")]
    if parts.scheme not in _ALLOWED_SCHEMES:
        return None, [
            Check("error", f"scheme {parts.scheme!r} isn't http or https -- refusing to fetch it")
        ]
    checks: list[Check] = []
    if parts.username is not None or parts.password is not None:
        checks.append(
            Check(
                "warn",
                "credentials in the URL are ignored -- the directory is fetched without them",
            )
        )
    if parts.scheme != "https":
        checks.append(
            Check(
                "error",
                f"scheme is {parts.scheme!r}, not https -- a Signature-Agent and its "
                "directory must be served over https",
            )
        )
    netloc = host if port is None else f"{host}:{port}"
    return f"{parts.scheme}://{netloc}", checks


def _fetch(url: str) -> tuple[int | None, str | None, bytes | None, str | None]:
    """GET ``url`` -> ``(status, content_type, body, error)``; body is set only on a
    200 read cleanly, so exactly one of body/error carries the outcome.

    Deliberately not ``wba.py``'s ``_http_get`` or ``robots/source.py``'s
    ``from_network`` -- both discard the status code and headers, collapsing a
    404 and a timeout into the same ``None``. A diagnostic needs to tell those
    apart (and surface the Content-Type), so this keeps its own thin GET.
    """
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": f"{_EXPECTED_CONTENT_TYPE}, application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:  # noqa: S310
            return (
                response.status,
                response.headers.get("Content-Type"),
                response.read(_MAX_BYTES),
                None,
            )
    except urllib.error.HTTPError as exc:
        content_type = exc.headers.get("Content-Type") if exc.headers else None
        return exc.code, content_type, None, f"HTTP {exc.code}"
    except (
        urllib.error.URLError,
        OSError,
        ValueError,
        http.client.HTTPException,
        UnicodeError,
    ) as exc:
        return (
            None,
            None,
            None,
            str(exc.reason) if isinstance(exc, urllib.error.URLError) else str(exc),
        )


def _check_key(index: int, jwk: object) -> tuple[list[Check], str | None]:
    """Checks for one directory entry -> ``(checks, thumbprint)``, thumbprint
    ``None`` if the key isn't a usable Ed25519 one (agent-census verifies no other
    algorithm, so such a key -- however valid per the draft -- won't be checked)."""
    if not isinstance(jwk, dict):
        return [Check("error", f"key[{index}]: not a JSON object")], None
    kty, crv = jwk.get("kty"), jwk.get("crv")
    if kty != "OKP" or crv != "Ed25519":
        return [
            Check(
                "warn",
                f"key[{index}]: kty={kty!r} crv={crv!r} -- not an Ed25519 OKP key; "
                "agent-census only verifies Ed25519, so this key won't be usable",
            )
        ], None
    thumbprint = jwk_thumbprint(jwk)
    # jwk_thumbprint only checks that 'x' is present, not that it decodes to a
    # real 32-byte Ed25519 point -- public_key_from_jwk is what verify_claim()
    # actually calls, so a key that fails there is unusable even though a
    # (meaningless) thumbprint could still be computed over it.
    if thumbprint is None or public_key_from_jwk(jwk) is None:
        return [
            Check(
                "error",
                f"key[{index}]: malformed -- 'x' is not a valid base64url-encoded "
                "Ed25519 public key",
            )
        ], None
    kid = jwk.get("kid")
    if kid is not None and kid != thumbprint:
        return [
            Check(
                "error",
                f"key[{index}]: declared kid {kid!r} does not match its RFC 7638 thumbprint "
                f"{thumbprint!r} -- verifiers key on the recomputed thumbprint, not the "
                f"declared kid, so a signature must name keyid={thumbprint!r} to be found",
            )
        ], thumbprint
    return [Check("ok", f"key[{index}]: valid Ed25519 key, thumbprint {thumbprint}")], thumbprint


def check_host(host: str) -> tuple[list[Check], str, list[str]]:
    """Run every check for ``host`` -> ``(checks, origin, usable keyids)``.

    ``origin`` is ``""`` when ``host`` didn't even parse as a host or URL -- the
    one case where there's nothing to fetch.
    """
    origin, checks = _origin(host)
    if origin is None:
        return checks, "", []
    url = origin + WELL_KNOWN_DIRECTORY
    status, content_type, body, error = _fetch(url)
    if body is None:
        checks.append(Check("error", f"GET {url}: {error or f'HTTP {status}'}"))
        return checks, origin, []
    checks.append(Check("ok", f"GET {url}: HTTP {status}"))
    if content_type is None or _EXPECTED_CONTENT_TYPE not in content_type:
        checks.append(
            Check(
                "warn",
                f"Content-Type is {content_type!r}, not {_EXPECTED_CONTENT_TYPE!r} as the "
                "directory draft requires (some clients accept it anyway)",
            )
        )
    else:
        checks.append(Check("ok", f"Content-Type: {content_type}"))
    try:
        data: Any = json.loads(body)
    except ValueError as exc:
        checks.append(Check("error", f"body is not valid JSON: {exc}"))
        return checks, origin, []
    keys = data.get("keys") if isinstance(data, dict) else None
    if not isinstance(keys, list):
        checks.append(Check("error", "body has no top-level 'keys' array"))
        return checks, origin, []
    if not keys:
        checks.append(
            Check("error", "'keys' array is empty -- nothing for a signature to verify against")
        )
        return checks, origin, []
    seen: dict[str, int] = {}
    thumbprints: list[str] = []
    for index, jwk in enumerate(keys):
        key_checks, thumbprint = _check_key(index, jwk)
        checks += key_checks
        if thumbprint is None:
            continue
        if thumbprint in seen:
            checks.append(
                Check(
                    "warn",
                    f"key[{index}]: same thumbprint as key[{seen[thumbprint]}] -- duplicate key",
                )
            )
        else:
            seen[thumbprint] = index
            thumbprints.append(thumbprint)
    return checks, origin, thumbprints


def _render(checks: list[Check], origin: str, keyids: list[str]) -> str:
    target = f"{origin}{WELL_KNOWN_DIRECTORY}" if origin else "(no target)"
    lines = [f"Web Bot Auth check: {target}", ""]
    lines += [f"{_MARK[c.level]} {c.message}" for c in checks]
    if keyids:
        lines += [
            "",
            "# paste into data/agents/web_bot_auth.toml (fill in the operator name):",
            "[[operator]]",
            'name = "TODO"',
            f'agent_urls = ["{origin}"]',
            "keyids = [",
            *(f'    "{keyid}",' for keyid in keyids),
            "]",
        ]
    return "\n".join(lines) + "\n"


def run(host: str) -> int:
    """Entry point for the ``agent-census wba-check`` subcommand."""
    checks, origin, keyids = check_host(host)
    sys.stdout.write(_render(checks, origin, keyids))
    return 1 if any(c.level == "error" for c in checks) else 0
