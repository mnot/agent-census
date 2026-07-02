"""Web Bot Auth: parse and cryptographically verify a client's signed requests.

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

Verification (:func:`verify_claim`) rebuilds the RFC 9421 signature base from the
logged values -- field components verbatim (OWS-trimmed), derived components
(``@authority``/``@method``/``@path``/``@scheme``) as the spec defines, and the
terminal ``@signature-params`` re-serialised from the logged ``Signature-Input`` --
then checks the Ed25519 signature against the operator's key. Only a signature
that *fails* against an authentic key is forgery; a base we can't rebuild (a
covered field we didn't log, a signed body) is ``UNVERIFIABLE``, never forgery.
The key itself (fetching it, thumbprint-checking it, caching it) is handled by the
caller; this module verifies a claim against a key it is given.
"""

from __future__ import annotations

import base64
import hashlib
import json
import urllib.parse
import urllib.request
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

import http_sf
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from http_sf import Token

from . import USER_AGENT
from .dataload import load_wba_operators
from .iprange import cache_dir, remote_enabled
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


def _domain_of(agent_url: str | None) -> str | None:
    """The host of a Signature-Agent URL, lowercased -- the display fallback for the
    operator when it isn't in the curated list (e.g. ``ahrefs.com``)."""
    if not agent_url:
        return None
    try:
        host = urllib.parse.urlsplit(agent_url).hostname
    except ValueError:
        return None
    return host.lower() if host else None


def display_operator(result: WbaResult) -> str | None:
    """The "who" to show: the curated operator name, else the signer's domain."""
    return result.operator or result.signer_domain


def detect_result(claim: WbaClaim) -> WbaResult:
    """The phase-1 verdict for a signed request: present and attributed, unverified.

    No cryptography yet -- the signature is recorded as :attr:`WbaStatus.PRESENT`
    with its operator (if known), keyid, and freshness window, so adoption is
    visible before the verification tier (phase 2) turns this into ``verified`` /
    ``forged`` / ``expired`` / ``unverifiable``.
    """
    operator = resolve_operator(claim.agent_url, claim.params.keyid)
    domain = _domain_of(claim.agent_url)
    who = f" by {operator or domain}" if (operator or domain) else ""
    return WbaResult(
        status=WbaStatus.PRESENT,
        operator=operator,
        signer_domain=domain,
        keyid=claim.params.keyid,
        created=claim.params.created,
        expires=claim.params.expires,
        evidence=(f"presented a Web Bot Auth signature{who} (keyid {claim.params.keyid})",),
    )


def extract_nonce(signature_input: str) -> str | None:
    """The ``nonce`` of the web-bot-auth label in a ``Signature-Input`` header.

    A cheap targeted parse used while streaming to track nonces across the whole
    log (replay detection), without stashing every signed request. ``None`` if the
    header doesn't parse or carries no web-bot-auth nonce.
    """
    selected = select_web_bot_auth(parse_signature_input(signature_input))
    return selected[1].nonce if selected is not None else None


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


# --- verification (RFC 9421 base rebuild + Ed25519) ------------------------------


def _b64url_decode(text: str) -> bytes:
    """Decode unpadded base64url (JWK ``x``, a keyid thumbprint)."""
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def jwk_thumbprint(jwk: dict[str, Any]) -> str | None:
    """The RFC 7638 thumbprint of an Ed25519 JWK (its content-addressed ``keyid``).

    Built over exactly the required members (``crv``, ``kty``, ``x``) in lexical
    order with no whitespace, SHA-256, base64url without padding. Returns ``None``
    for a JWK that isn't a well-formed Ed25519 (OKP) public key.
    """
    try:
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or "x" not in jwk:
            return None
        canonical = json.dumps(
            {"crv": "Ed25519", "kty": "OKP", "x": jwk["x"]},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError):
        return None
    return base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode("ascii")


def public_key_from_jwk(jwk: dict[str, Any]) -> Ed25519PublicKey | None:
    """An ``Ed25519PublicKey`` from a JWK's ``x`` member, or ``None`` if malformed."""
    x_b64 = jwk.get("x")  # the JWK's public-key member, base64url
    if not isinstance(x_b64, str):
        return None
    try:
        return Ed25519PublicKey.from_public_bytes(_b64url_decode(x_b64))
    except (ValueError, TypeError):
        return None


# Derived components we can supply from a logged request; the value rules are
# RFC 9421 §2.2 (@authority lowercased, @method upper-case, @path, @scheme).
def _derived_value(claim: WbaClaim, component: str) -> str | None:
    if component == "@authority":
        return claim.authority
    if component == "@method":
        return claim.method
    if component == "@path":
        return claim.path
    if component == "@scheme":
        return claim.scheme
    return None


def _signature_params_value(signature_input: str, label: str) -> str | None:
    """Re-serialise the chosen label's member as the ``@signature-params`` value.

    Reuses ``http-sf``'s deterministic serializer over the parsed member, so the
    terminal base line matches a conformant signer's canonicalisation (verified
    against real signatures). ``None`` if the header no longer parses.
    """
    try:
        parsed = cast(
            dict[str, Any], http_sf.parse(signature_input.encode("utf-8"), tltype="dictionary")
        )
    except http_sf.StructuredFieldError:
        return None
    if label not in parsed:
        return None
    serialised = http_sf.ser({label: parsed[label]})  # a one-member dictionary
    return serialised[len(label) + 1 :]  # drop the "label=" prefix


# A covered component value is None when we can't supply it: either a signed body
# (content-digest) or a covered field the log didn't carry. Either way -> the base
# can't be rebuilt, so the verdict is UNVERIFIABLE (never forgery), with a hint.
def build_signature_base(claim: WbaClaim) -> tuple[str | None, str]:
    """Rebuild the RFC 9421 signature base for a claim, or explain why we can't.

    Returns ``(base, "")`` on success, or ``(None, reason)`` when a covered
    component can't be supplied from the log -- a signed request body
    (``content-digest``) or a covered header that wasn't logged. The reason names
    the missing component so a user can add it to their LogFormat.
    """
    lines: list[str] = []
    for component in claim.params.components:
        if component == "content-digest":
            return None, "the request body was signed (content-digest); the log can't carry it"
        if component.startswith("@"):
            value = _derived_value(claim, component)
        elif component == "signature-agent":
            value = claim.signature_agent.strip() if claim.signature_agent else None
        else:
            value = None  # a covered header we didn't log
        if value is None:
            return None, f"covered component {component!r} was not available from the log"
        lines.append(f'"{component}": {value}')
    params_value = _signature_params_value(claim.signature_input, claim.label)
    if params_value is None:
        return None, "could not re-serialise the signature parameters"
    lines.append(f'"@signature-params": {params_value}')
    return "\n".join(lines), ""


def verify_claim(claim: WbaClaim, public_key: Ed25519PublicKey) -> tuple[WbaStatus, str]:
    """Verify a claim's signature against ``public_key`` -> ``(status, reason)``.

    ``public_key`` must already be the authentic operator key (thumbprint-checked
    against the ``keyid`` by the caller). The outcomes:

    * ``VERIFIED`` -- the Ed25519 signature checks out and the request is within the
      signature's freshness window.
    * ``EXPIRED`` -- it checks out, but the request post-dates ``expires`` (a valid
      signature, replayed or simply old; still the operator's key).
    * ``FORGED`` -- the signature fails against this authentic key. The only forgery
      verdict.
    * ``UNVERIFIABLE`` -- the base couldn't be rebuilt (signed body / unlogged
      covered field) or the signature bytes are missing. Never forgery.
    """
    base, problem = build_signature_base(claim)
    if base is None:
        return WbaStatus.UNVERIFIABLE, problem
    signature = parse_signature(claim.signature).get(claim.label)
    if signature is None:
        return WbaStatus.UNVERIFIABLE, "no signature bytes for the web-bot-auth label"
    try:
        public_key.verify(signature, base.encode("utf-8"))
    except InvalidSignature:
        return WbaStatus.FORGED, "Ed25519 signature does not verify against the operator's key"
    expires = claim.params.expires
    if expires is not None and claim.timestamp is not None and claim.timestamp > expires:
        return WbaStatus.EXPIRED, "valid signature, but the request post-dates its `expires`"
    return WbaStatus.VERIFIED, "valid Ed25519 signature, within its freshness window"


# --- key directory + the verifier the pipeline drives ---------------------------

# The operator's JWK directory, relative to the Signature-Agent origin. Public so
# `wba_check` (which probes a host's directory directly, not via a logged
# Signature-Agent) can build the same URL without duplicating the path.
WELL_KNOWN_DIRECTORY = "/.well-known/http-message-signatures-directory"
_FETCH_TIMEOUT = 10
# The directory URL comes from the attacker-controlled ``Signature-Agent`` header,
# and ``urlsplit`` accepts any scheme (``file``, ``ftp``, ``data``, ...) while
# ``urlopen`` will happily follow one -- so a crafted ``Signature-Agent`` would
# otherwise be an SSRF / local-file-read primitive. Only http(s) is ever fetched;
# a rejected scheme fails closed to UNVERIFIABLE (never forgery), like any other
# unobtainable key. Mirrors ``wba_check._ALLOWED_SCHEMES``.
_ALLOWED_SCHEMES = frozenset({"http", "https"})


def _key_store_path() -> Path:
    return cache_dir() / "wba-keys.json"


def _directory_url(agent_url: str) -> str:
    """The JWK directory URL for a Signature-Agent value (append the well-known path)."""
    url = agent_url.rstrip("/")
    return url if url.endswith(WELL_KNOWN_DIRECTORY) else url + WELL_KNOWN_DIRECTORY


def _http_get(url: str) -> str | None:
    # Refuse any non-http(s) scheme before a request is made: the URL derives from
    # the untrusted Signature-Agent header, so file://, ftp://, etc. must not reach
    # urlopen. A refused fetch returns None, which the caller treats as "key not
    # obtained" -- UNVERIFIABLE, never a false verify.
    try:
        scheme = urllib.parse.urlsplit(url).scheme.lower()
    except ValueError:
        return None
    if scheme not in _ALLOWED_SCHEMES:
        return None
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=_FETCH_TIMEOUT) as response:  # noqa: S310
            return str(response.read().decode("utf-8", "replace"))
    except (OSError, ValueError):
        return None


class WbaVerifier:
    """Verifies Web Bot Auth claims, resolving operator keys with a permanent cache.

    The key cache is the opposite of the range / robots caches. A ``keyid`` is a
    JWK thumbprint -- content-addressed and immutable -- so a key, once seen, is
    stored under its own hash forever: it can't go stale, and a hostile directory
    can't poison an entry (the thumbprint must match the ``keyid`` the signature
    names). The store therefore accrues coverage across runs, which is what keeps a
    months-old log verifiable after the operator has rotated: the key is gone from
    the live directory, but still in our store from when it was published.

    Fetching the directory is gated on ``allow_fetch`` *and* the shared remote
    switch; offline, only already-cached keys are used (a missing one is
    ``UNVERIFIABLE``, never forgery).
    """

    def __init__(self, *, allow_fetch: bool = True) -> None:
        self._allow_fetch = allow_fetch
        self._keys: dict[str, dict[str, Any]] = {}  # keyid (thumbprint) -> minimal JWK
        self._fetched: set[str] = set()  # directory URLs tried this run (once each)
        self._dirty = False
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(_key_store_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if isinstance(data, dict):
            for keyid, jwk in data.items():
                if isinstance(jwk, dict):
                    self._keys[keyid] = jwk

    def save(self) -> None:
        """Persist newly-learned keys (atomically). A no-op when nothing changed."""
        if not self._dirty:
            return
        path = _key_store_path()
        tmp = path.with_suffix(".json.tmp")
        try:
            tmp.write_text(json.dumps(self._keys), encoding="utf-8")
            tmp.replace(path)  # atomic: a crash leaves the old store intact
        except OSError:
            pass

    def _fetch_directory(self, agent_url: str) -> None:
        url = _directory_url(agent_url)
        if url in self._fetched:
            return
        self._fetched.add(url)
        text = _http_get(url)
        if text is None:
            return
        try:
            data = json.loads(text)
        except ValueError:
            return
        keys = data.get("keys") if isinstance(data, dict) else None
        if not isinstance(keys, list):
            return
        for jwk in keys:
            if not isinstance(jwk, dict):
                continue
            # Store under the recomputed thumbprint, not the directory's claimed
            # `kid`: content-addressing is the integrity check, so a lying `kid`
            # can't displace or impersonate another key.
            thumbprint = jwk_thumbprint(jwk)
            if thumbprint is not None and thumbprint not in self._keys:
                self._keys[thumbprint] = {"kty": "OKP", "crv": "Ed25519", "x": jwk.get("x")}
                self._dirty = True

    def _resolve_key(self, keyid: str, agent_url: str | None) -> dict[str, Any] | None:
        if keyid in self._keys:
            return self._keys[keyid]
        if self._allow_fetch and remote_enabled() and agent_url:
            self._fetch_directory(agent_url)
        return self._keys.get(keyid)

    def verify(self, claim: WbaClaim) -> WbaResult:
        """Resolve the operator's key and verify ``claim`` -> a full :class:`WbaResult`."""
        operator = resolve_operator(claim.agent_url, claim.params.keyid)
        domain = _domain_of(claim.agent_url)
        keyid = claim.params.keyid

        def result(status: WbaStatus, reason: str) -> WbaResult:
            who = f" by {operator or domain}" if (operator or domain) else ""
            return WbaResult(
                status=status,
                operator=operator,
                signer_domain=domain,
                keyid=keyid,
                created=claim.params.created,
                expires=claim.params.expires,
                reason=reason,
                evidence=(f"Web Bot Auth signature{who}: {reason}",),
            )

        if keyid is None:
            return result(WbaStatus.UNVERIFIABLE, "signature names no keyid")
        jwk = self._resolve_key(keyid, claim.agent_url)
        if jwk is None:
            return result(
                WbaStatus.UNVERIFIABLE,
                "could not obtain the operator's key (rotated since, or directory unreachable)",
            )
        public_key = public_key_from_jwk(jwk)
        if public_key is None:
            return result(WbaStatus.UNVERIFIABLE, "the operator's stored key is not usable")
        status, reason = verify_claim(claim, public_key)
        return result(status, reason)

    def verify_sample(self, claims: list[WbaClaim]) -> WbaResult:
        """Verify a client's sampled signed requests; the first is the headline.

        The representative (first) claim drives the verdict, exactly as before. The
        rest of the sparse sample are verified only to detect a *mixed* identity --
        one whose signatures don't all agree -- which sets ``mixed`` on the result
        without changing the headline status (so the impersonation precedence is
        unaffected; mixing is surfaced as its own flag).
        """
        head = self.verify(claims[0])
        mixed = any(self.verify(other).status is not head.status for other in claims[1:])
        return replace(head, mixed=True) if mixed else head


# Ceiling on distinct Web Bot Auth nonces tracked for replay detection, so a log
# with an unbounded number of signed requests can't exhaust memory. Generous --
# signed traffic is rare today; past it we stop learning new nonces (a documented
# limit, not a crash). Tightening / Bloom-filtering this is a future refinement.
_WBA_NONCE_CAP = 1_000_000


class WbaNonceTracker:
    """Tracks Web Bot Auth signature nonces across a whole log for replay detection
    -- something an edge server checking one request at a time can't do.

    A nonce seen again from a *different* origin is a captured signature replayed
    elsewhere (``replay_ips`` names both origins); seen again from the *same*
    origin is just a signer reusing nonces, a milder note (``reused_nonces``).
    """

    def __init__(self, cap: int = _WBA_NONCE_CAP) -> None:
        self._cap = cap
        self._origin: dict[str, str] = {}
        self.replay_ips: set[str] = set()
        self.replayed_nonces: set[str] = set()
        self.reused_nonces: set[str] = set()

    def track(self, nonce: str, ip: str) -> None:
        first = self._origin.get(nonce)
        if first is None:
            if len(self._origin) < self._cap:
                self._origin[nonce] = ip
        elif first != ip:  # the same signature presented from a different origin
            self.replayed_nonces.add(nonce)
            self.replay_ips.add(first)
            self.replay_ips.add(ip)
        else:  # one origin reusing a nonce -- a signer quirk, not a replay
            self.reused_nonces.add(nonce)
