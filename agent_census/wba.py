"""Web Bot Auth: parse the signature headers a client logs, no crypto yet.

Web Bot Auth (``draft-meunier-web-bot-auth-architecture``) lets a bot sign its
requests with an Ed25519 key the operator publishes in a JWK directory. A signed
request carries three headers we ask operators to log:

* ``Signature-Input`` -- an RFC 8941 dictionary: per-label covered components plus
  the signature parameters (``keyid``, ``created``, ``expires``, ``nonce``,
  ``alg``, ``tag``). The member tagged ``tag="web-bot-auth"`` is ours.
* ``Signature`` -- the same dictionary keyed by label, each value the raw signature
  bytes (an RFC 8941 byte-sequence).
* ``Signature-Agent`` -- a pointer to the operator's directory / identity.

This module is the *parsing* tier (phase 1): it turns those logged header strings
into a :class:`WbaClaim` -- the representative request's fields, stashed during
streaming so the per-request signature can be verified after grouping. It does no
network and no cryptography; :mod:`agent_census` adds those on top of what we
extract here.

The structured fields are parsed with ``http-sf``, the RFC 8941 reference
implementation: it returns each ``Signature-Input`` member as an inner list of
covered components plus a parameters mapping, and its (deterministic) serializer
reconstructs the ``@signature-params`` base line canonically -- so when the base is
rebuilt for verification, we round-trip through the same library the signer's
canonicalisation is measured against, rather than a bespoke re-serialiser.

A header that doesn't parse yields ``None`` (not a claim) or an empty mapping,
never an exception that would abort a run.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

import http_sf
from http_sf import Token

from .dataload import load_wba_operators
from .model import WbaResult, WbaStatus

# The signature parameter (and value) that marks the label as a Web Bot Auth one;
# a Signature-Input may carry other application labels alongside ours.
WEB_BOT_AUTH_TAG = "web-bot-auth"

# Request headers we ask operators to log (see the issue's Apache LogFormat). The
# parser reads them out of ``LogEntry.extra`` by these exact names.
SIGNATURE_INPUT_HEADER = "Signature-Input"
SIGNATURE_HEADER = "Signature"
SIGNATURE_AGENT_HEADER = "Signature-Agent"


@dataclass(frozen=True, slots=True)
class SigParams:
    """One Signature-Input member: its covered components and signature parameters.

    ``components`` are the covered component identifiers in order, lowercased and
    unquoted (``"@authority"``, ``"signature-agent"``, ...). The ``@signature-params``
    base line is reconstructed for verification (phase 2) from the full
    ``Signature-Input`` header and the selected label, re-serialised through
    ``http-sf`` -- so it isn't stored here.
    """

    components: tuple[str, ...]
    keyid: str | None = None
    alg: str | None = None
    created: int | None = None
    expires: int | None = None
    nonce: str | None = None
    tag: str | None = None


@dataclass(frozen=True, slots=True)
class WbaClaim:
    """A representative Web Bot Auth request, captured for later verification.

    Stashed on a client's accumulator the first time a signed request is seen, so
    the per-request signature survives the streaming pass that discards entries.
    Holds the raw header strings (the signature base is rebuilt from logged values
    verbatim), the derived components needed for that base, the request time (for
    freshness), and the parsed parameters of the selected ``web-bot-auth`` label.
    """

    signature_input: str  # raw Signature-Input header value
    signature: str  # raw Signature header value
    signature_agent: str | None  # raw Signature-Agent header value, if logged
    label: str  # the dictionary label whose tag is web-bot-auth
    params: SigParams  # that label's parsed components + parameters
    agent_url: str | None  # operator/directory URL parsed from Signature-Agent
    authority: str | None  # @authority derived component (Host, lowercased)
    method: str | None  # @method derived component (upper-case)
    path: str  # @path derived component
    scheme: str  # @scheme derived component (always https for a logged request)
    timestamp: float | None  # request time, for created/expires freshness


# --- RFC 8941 structured-field parsing (via the http-sf reference impl) ----------


def _param_str(params: dict[str, object], key: str) -> str | None:
    """A string-valued signature parameter (a Token is taken as its text)."""
    value = params.get(key)
    if isinstance(value, str):
        return value
    if isinstance(value, Token):
        return str(value)
    return None


def _param_int(params: dict[str, object], key: str) -> int | None:
    value = params.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def parse_signature_input(value: str) -> dict[str, SigParams]:
    """Parse a ``Signature-Input`` header into ``{label: SigParams}``.

    Returns an empty mapping for anything that doesn't parse as the expected
    dictionary -- a malformed header is "no claim", never an error that aborts a
    run. Only inner-list members (a signature's covered components) are kept; a
    plain-item member, if any, isn't a signature.
    """
    try:
        parsed = cast(dict[str, Any], http_sf.parse(value.encode("utf-8"), tltype="dictionary"))
    except http_sf.StructuredFieldError:
        return {}
    out: dict[str, SigParams] = {}
    for label, member in parsed.items():
        # A dictionary value is ``(bare_value, params)``; for a signature the
        # bare value is the inner list of covered components.
        if not (isinstance(member, tuple) and isinstance(member[0], list)):
            continue
        inner, params = member
        components = tuple(str(item[0]).lower() for item in inner)
        out[label] = SigParams(
            components=components,
            keyid=_param_str(params, "keyid"),
            alg=_param_str(params, "alg"),
            created=_param_int(params, "created"),
            expires=_param_int(params, "expires"),
            nonce=_param_str(params, "nonce"),
            tag=_param_str(params, "tag"),
        )
    return out


def parse_signature(value: str) -> dict[str, bytes]:
    """Parse a ``Signature`` header into ``{label: signature-bytes}`` (decoded)."""
    try:
        parsed = cast(dict[str, Any], http_sf.parse(value.encode("utf-8"), tltype="dictionary"))
    except http_sf.StructuredFieldError:
        return {}
    out: dict[str, bytes] = {}
    for label, member in parsed.items():
        # Each value is a byte sequence -> ``(bytes, params)``.
        if isinstance(member, tuple) and isinstance(member[0], bytes):
            out[label] = member[0]
    return out


def parse_signature_agent(value: str | None) -> str | None:
    """Extract the operator/directory URL from a ``Signature-Agent`` header.

    Three forms are seen in the wild (thibmeu, on the issue):

    * ``"https://example.com"`` -- a bare structured-field string. Valid through
      directory draft -03 and what current deployments send; the common case.
    * ``label="https://example.com"`` -- a dictionary member, the -04 syntax.
    * ``https://example.com`` -- unescaped, invalid (not a quoted string). Accepted
      leniently here as a best-effort URL so attribution still works, since it is
      seen even though the spec forbids it.

    Returns the URL, or ``None`` if the header is absent/empty or carries no URL.
    The signature *base* never uses this parsed form (it uses the logged header
    value); this is only for naming the operator and locating its directory.
    """
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    data = text.encode("utf-8")
    # Bare structured-field string item: "https://..." (the -03 form).
    try:
        item = cast(Any, http_sf.parse(data, tltype="item"))
        if isinstance(item, tuple) and isinstance(item[0], str):
            return item[0]
    except http_sf.StructuredFieldError:
        pass
    # Dictionary member: label="https://..." (the -04 form).
    try:
        parsed = cast(dict[str, Any], http_sf.parse(data, tltype="dictionary"))
        for member in parsed.values():
            if isinstance(member, tuple) and isinstance(member[0], str):
                return member[0]
    except http_sf.StructuredFieldError:
        pass
    # Lenient fallback: an unescaped bare URL (invalid form #1, but seen).
    if text.startswith(("http://", "https://")):
        return text.split(",", 1)[0].strip().strip('"')
    return None


def _norm_url(url: str) -> str:
    """Canonical form for comparing directory URLs: lowercased, no trailing slash."""
    return url.strip().rstrip("/").lower()


def resolve_operator(agent_url: str | None, keyid: str | None) -> str | None:
    """Name the operator behind a signature from the offline list, or ``None``.

    A ``keyid`` (JWK thumbprint) is content-addressed, so it is the surer match and
    is tried first; the ``Signature-Agent`` directory URL is the fallback. Purely
    the "who" -- says nothing about whether the signature verifies.
    """
    operators = load_wba_operators()
    if keyid is not None:
        for op in operators:
            if keyid in op.keyids:
                return op.name
    if agent_url is not None:
        norm = _norm_url(agent_url)
        for op in operators:
            if any(_norm_url(u) == norm for u in op.agent_urls):
                return op.name
    return None


def detect_result(claim: WbaClaim) -> WbaResult:
    """The phase-1 verdict for a signed request: present and attributed, unverified.

    No cryptography yet -- the signature is recorded as :attr:`WbaStatus.PRESENT`
    with its operator (if known), keyid, and freshness window, so adoption is
    visible before the verification tier (phase 2) turns this into ``verified`` /
    ``forged`` / ``expired`` / ``unverifiable``.
    """
    operator = resolve_operator(claim.agent_url, claim.params.keyid)
    who = f" by {operator}" if operator else ""
    return WbaResult(
        status=WbaStatus.PRESENT,
        operator=operator,
        keyid=claim.params.keyid,
        created=claim.params.created,
        expires=claim.params.expires,
        evidence=(f"presented a Web Bot Auth signature{who} (keyid {claim.params.keyid})",),
    )


def select_web_bot_auth(parsed: dict[str, SigParams]) -> tuple[str, SigParams] | None:
    """Pick the ``(label, params)`` whose ``tag`` is ``web-bot-auth``.

    A Signature-Input may carry several application labels; ours is the one tagged
    ``web-bot-auth``. Returns ``None`` when none is -- the request is signed, but
    not for us.
    """
    for label, params in parsed.items():
        if params.tag == WEB_BOT_AUTH_TAG:
            return label, params
    return None


def build_claim(
    extra: dict[str, str],
    *,
    host: str | None,
    method: str | None,
    path: str,
    timestamp: float | None,
) -> WbaClaim | None:
    """Build a :class:`WbaClaim` from one request's logged fields, or ``None``.

    Returns ``None`` unless the request carries a ``Signature-Input`` with a
    ``web-bot-auth`` label and a matching ``Signature`` value -- i.e. it is a
    Web Bot Auth request we could go on to verify. Derived components
    (``@authority``/``@method``/``@path``/``@scheme``) are computed the way RFC
    9421 specifies so the base can be rebuilt later.
    """
    sig_input = extra.get(SIGNATURE_INPUT_HEADER)
    sig = extra.get(SIGNATURE_HEADER)
    if not sig_input or not sig:
        return None
    selected = select_web_bot_auth(parse_signature_input(sig_input))
    if selected is None:
        return None
    label, params = selected
    if label not in parse_signature(sig):
        return None  # signed for web-bot-auth but the Signature lacks that label
    agent_raw = extra.get(SIGNATURE_AGENT_HEADER)
    return WbaClaim(
        signature_input=sig_input,
        signature=sig,
        signature_agent=agent_raw,
        label=label,
        params=params,
        agent_url=parse_signature_agent(agent_raw),
        authority=host.lower() if host else None,
        method=method.upper() if method else None,
        path=path,
        scheme="https",
        timestamp=timestamp,
    )
