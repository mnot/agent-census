"""Core data types shared across the pipeline.

These are the contracts that decouple the stages: parsers emit ``LogEntry``
values, feature extraction turns a client's entries into ``ClientFeatures``,
classifiers turn features into ``Signal`` votes, and the combiner produces a
``Classification``. Nothing downstream of the parser knows which server the log
came from.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Kind(str, Enum):
    """The primary kind a client can be classified as.

    Inherits from ``str`` so values render readably and sort/serialize without
    fuss. ``UNKNOWN`` is the honest fallback the combiner uses when no signal is
    strong enough — it is never argued for by a classifier. ``AUTOMATION`` is a
    narrower fallback for a would-be-unknown client that still shows a positive
    machine tell (a headless engine, a cache-lacking re-fetch pattern, a generic
    HTTP-library UA, or a hosting / datacenter origin): clearly not a person, purpose
    unidentified. A single-request client is not its own kind -- "made one request"
    is a volume fact carried by the ``singleton`` *tag*, on whatever kind it lands.
    """

    BROWSER = "browser"
    APP = "app"
    CRAWLER = "crawler"
    VULN_SCANNER = "vuln_scanner"
    SEARCH_ENGINE = "search_engine"
    SOCIAL_PREVIEW = "social_preview"
    ARCHIVER = "archiver"
    AI_CRAWLER = "ai_crawler"
    SEO_MARKETING = "seo_marketing"
    DATA_HARVESTER = "data_harvester"
    FEED_READER = "feed_reader"
    MONITOR = "monitor"
    SCRAPER = "scraper"
    SPAM_BOT = "spam_bot"
    IMPERSONATOR = "impersonator"
    SPOOFED_BROWSER = "spoofed_browser"
    AUTOMATION = "automation"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class LogEntry:
    """One parsed access-log line, normalized across server formats.

    ``None`` means a field was absent (``-`` in the log); an empty string means
    the field was present but empty. That distinction matters: e.g. ``%b`` of
    ``-`` is normalized to ``0`` (no response body) rather than ``None``.

    Entries are retained in bulk for the whole log, so the type stays lean: it
    keeps the parsed fields, not the original line. ``raw_request`` is populated
    only when the request line could not be split (malformed/garbage), where it
    is the sole evidence of what was sent.
    """

    line_no: int

    # client / network
    remote_host: str
    remote_logname: str | None = None
    remote_user: str | None = None
    forwarded_for: tuple[str, ...] = ()

    # timing
    timestamp: datetime | None = None
    response_usec: int | None = None  # %D, or %T normalized to microseconds

    # request line (%r split)
    method: str | None = None
    path: str = ""
    query: str | None = None
    protocol: str | None = None
    raw_request: str = ""  # set only for an unparseable request line

    # response
    status: int | None = None
    bytes_sent: int | None = None

    # commonly-logged headers
    referer: str | None = None
    user_agent: str | None = None
    host_header: str | None = None

    # anything else the format captured (%{Foo}i/%{Foo}o/cookies/notes)
    extra: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ClientId:
    """A stable identity for a group of log lines treated as one client.

    The components that were actually used depend on the chosen identity
    strategy; unused ones are ``None``. The dataclass is frozen so it can serve
    as a dict key while grouping.
    """

    ip: str
    user_agent: str | None = None
    subnet: str | None = None

    @property
    def display(self) -> str:
        """A short human-readable label for reports and inspect output."""
        ua = self.user_agent if self.user_agent is not None else "-"
        if self.subnet is not None:
            return f"{self.subnet} | {ua}"
        return f"{self.ip} | {ua}"


@dataclass(frozen=True, slots=True)
class ClientFeatures:  # pylint: disable=too-many-instance-attributes
    """Pure descriptive metrics for one client — no judgments.

    Classifiers consume only this struct (plus their own static data lists), so
    the wall between "measure" and "decide" stays clean and each classifier is a
    pure, independently-testable function. Every field carries a neutral default
    so tests can build partial fixtures that exercise one behavior at a time.
    It is deliberately a wide bag of metrics; the attribute-count check is off.
    """

    # volume / bandwidth / span
    request_count: int = 0
    total_bytes: int = 0
    mean_bytes: float = 0.0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    duration_seconds: float = 0.0

    # status mix
    status_counts: dict[int, int] = field(default_factory=dict)
    ratio_2xx: float = 0.0
    ratio_3xx: float = 0.0
    ratio_4xx: float = 0.0
    ratio_5xx: float = 0.0
    ratio_404: float = 0.0
    distinct_404_paths: int = 0

    # vulnerability-probe signal
    vuln_path_hits: int = 0
    vuln_path_ratio: float = 0.0
    sample_vuln_paths: tuple[str, ...] = ()
    submit_path_hits: int = 0  # requests to comment/login/xmlrpc submission endpoints
    traversal_hits: int = 0
    evasion_hits: int = 0  # double / overlong encoding -- deliberate WAF evasion

    # timing / rate (None when too few requests to measure intervals)
    inter_arrival_mean: float | None = None
    inter_arrival_median: float | None = None
    inter_arrival_p95: float | None = None
    inter_arrival_min: float | None = None
    peak_requests_per_minute: int = 0
    rate_regularity: float | None = None  # coefficient of variation of intervals
    # Per-request volume folded into equal slices of [first_seen, last_seen], the
    # source histogram for the report's request-pattern sparkline. Empty when
    # there is no shape to plot (no timestamps, or the whole span fits one minute).
    request_buckets: tuple[int, ...] = ()

    # crawl shape
    distinct_paths: int = 0
    coverage: float = 0.0  # distinct_paths / request_count
    breadth_ratio: float = 0.0  # fraction of consecutive hops that change subtree
    referer_following_ratio: float = 0.0  # referer is a path this client fetched earlier
    self_referer_ratio: float = 0.0  # referer == the requested path (fabricated; browsers never do)
    referer_count: int = 0  # requests that carried a Referer (0 -> can't judge navigation)

    # asset co-loading (the browser fingerprint)
    asset_coload_ratio: float = 0.0  # HTML responses followed by sub-resource fetches
    static_ratio: float = 0.0  # static-asset requests / total
    page_count: int = 0  # HTML page responses (0 -> can't judge sub-resource loading)

    # method mix
    method_counts: dict[str, int] = field(default_factory=dict)
    get_ratio: float = 0.0
    head_ratio: float = 0.0
    post_ratio: float = 0.0
    exotic_method_count: int = 0  # PUT/DELETE/PROPFIND/CONNECT/...

    # feed polling: requests for an RSS/Atom resource (by URL or response media type)
    feed_requests: int = 0
    feed_ratio: float = 0.0

    # politeness (behavioral; robots-rule compliance lives in ComplianceReport)
    fetched_robots_txt: bool = False

    # user-agent hints (raw, not verdicts)
    user_agent: str | None = None
    ua_looks_like_browser: bool = False
    ua_declares_bot: bool = False
    ua_empty: bool = True
    ua_count_for_ip: int = 1

    # Autonomous-system identity from the log (MaxMind %{MM_ASORG}e / %{MM_ASN}e),
    # when present. Not inferred -- absent if the log doesn't carry it.
    as_org: str | None = None
    as_number: str | None = None

    @property
    def holds_no_cache(self) -> bool:
        """True when re-fetch volume proves the client keeps no browser cache.

        A real browser revalidates what it re-requests (earning 304s) or serves
        assets from cache without hitting the server. A client that re-fetches the
        same URLs -- or simply makes many requests -- yet never receives a single
        304 holds no cache: not browser behaviour. One-sided on purpose: a 304 can
        only arise from a re-request, so distinct-once fetching at low volume is
        spared (it could legitimately be uncacheable content).
        """
        revisits = self.request_count - self.distinct_paths
        no_304 = self.status_counts.get(304, 0) == 0
        return no_304 and self.distinct_paths > 0 and (revisits >= 20 or self.request_count >= 500)


@dataclass(frozen=True, slots=True)
class Signal:
    """One classifier's vote for a kind, with the reasons behind it.

    ``confidence`` is an ordinal strength in [0, 1], not a probability — the
    combiner aggregates per label rather than multiplying votes. ``evidence``
    strings are shown verbatim in inspect mode.
    """

    kind: Kind
    confidence: float
    evidence: tuple[str, ...]
    classifier: str
    # Set only by a known-agent match: the operator's declared name (or, for an
    # ASN-primary agent, its label). Lets the report show the agent's own
    # identity rather than a bare IP/network, without re-deriving it from the UA.
    agent_name: str | None = None
    # True when evidence[0] only justifies *why this classifier fired at all* --
    # a declared identity, a networking-stack token -- restating the kind itself
    # rather than telling us something specific about this client. A report
    # caption (format.top_evidence) skips it in favour of whatever more specific
    # evidence follows, and shows nothing rather than a boilerplate restatement
    # of the kind when nothing does.
    boilerplate_lead: bool = False


@dataclass(frozen=True, slots=True)
class Classification:
    """The final verdict for a client: one primary kind plus secondary tags."""

    primary: Kind
    confidence: float
    tags: frozenset[str] = frozenset()
    evidence: tuple[str, ...] = ()
    all_signals: tuple[Signal, ...] = ()
    # Per-tag evidence for inspect mode: the concrete measurement that earned each
    # tag, paired ``(tag, why)``. Like ``all_signals`` this is detail only inspect
    # reads, so it is populated only when signals are kept (``keep_signals``); the
    # bulk ``analyze`` path leaves it empty to avoid holding a string per client.
    tag_evidence: tuple[tuple[str, str], ...] = ()
    # The winning signal's known-agent identity, carried through from Signal (see
    # its docstring) -- None unless a known-agent classifier won.
    agent_name: str | None = None
    # Whether evidence[0] is a boilerplate restatement of the kind rather than a
    # client-specific fact -- carried through from Signal.boilerplate_lead (see
    # its docstring), unconditional on keep_signals like evidence and agent_name.
    boilerplate_lead: bool = False


class RobotsVerdict(str, Enum):
    """Whether a client appears to respect robots.txt."""

    RESPECTS = "respects"  # fetched robots.txt and requested no disallowed paths
    IGNORES = "ignores"  # requested paths its applicable group disallows
    UNKNOWN = "unknown"  # no rules to test, or never touched a restricted area


@dataclass(frozen=True, slots=True)
class ComplianceReport:
    """How a client measured up against robots.txt."""

    verdict: RobotsVerdict
    matched_group: str | None  # the User-agent group that applied (or None / "*")
    disallowed_hits: int
    sample_disallowed: tuple[str, ...]
    fetched_robots_first: bool
    crawl_delay: float | None
    crawl_delay_respected: bool | None
    evidence: tuple[str, ...] = ()


class VerificationStatus(str, Enum):
    """Result of reverse/forward DNS verification of a declared crawler."""

    VERIFIED = "verified"  # rDNS + forward confirm an expected crawler domain
    ASN_ASSOCIATED = "asn_associated"  # origin AS matches the declared crawler's network
    IMPERSONATOR = "impersonator"  # claims a crawler UA but DNS / AS disagrees
    UNVERIFIED = "unverified"  # lookup inconclusive / network failure
    NOT_APPLICABLE = "not_applicable"  # UA does not declare a verifiable crawler


class ChannelVerdict(str, Enum):
    """Outcome of one identity-verification channel (reverse DNS, or IP range),
    independent of the other and of the merged :class:`VerificationStatus`.

    Each channel is its own tri-state-plus-absent: a genuine confirmation, an
    inconclusive check (a timeout, unfetchable ranges), a definitive failure
    (surfaced as ``<channel>-violation``, the evidence for an ``impersonator``
    verdict), or nothing declared/attempted for this channel at all.
    """

    VERIFIED = "verified"
    UNVERIFIED = "unverified"  # checked, inconclusive
    VIOLATION = "violation"  # checked, definitively failed
    NOT_CHECKED = "not_checked"  # nothing declared for this channel, or skipped


@dataclass(frozen=True, slots=True)
class BotVerification:
    """Outcome of an opt-in DNS check on a client's declared-crawler claim."""

    status: VerificationStatus
    resolved_host: str | None = None
    expected_domains: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    # The agent declared rdns/range info, so a network check was actually run (as
    # opposed to the asns-only or no-verifiable-info paths). Lets the report mark a
    # declared crawler that *could* be network-verified but wasn't -- failed or
    # inconclusive -- distinct from one with nothing to check against.
    network_checked: bool = False
    # The two identity channels, independent of each other and of `status` above
    # (which remains the merged verdict driving the impersonation decision and
    # the pipeline's identity fold/display). Surfaced as their own `dns-*` /
    # `ip-*` tags so a reader can see which channel, specifically, confirmed or
    # violated -- rather than one merged "verified"/"unverified" for both.
    dns: ChannelVerdict = ChannelVerdict.NOT_CHECKED
    dns_evidence: str | None = None
    ip: ChannelVerdict = ChannelVerdict.NOT_CHECKED
    ip_evidence: str | None = None


class WbaStatus(str, Enum):
    """Outcome of a Web Bot Auth signature check, a cryptographic identity tier.

    Parallel to (and outranking) the network :class:`VerificationStatus`: a valid
    signature is proof the operator's key signed the request, not an inference from
    where the IP sits. ``PRESENT`` is the phase-1 detect-only state (a signature is
    there, not yet cryptographically checked). ``FORGED`` -- a signature that fails
    against the operator's *authentic* fetched key -- is the only state that means
    impersonation; every "couldn't obtain the key / rebuild the base" path is
    ``UNVERIFIABLE``, never forgery.
    """

    PRESENT = "present"  # a web-bot-auth signature is present; not yet verified
    VERIFIED = "verified"  # signature valid against the operator's key, and fresh
    EXPIRED = "expired"  # signature valid, but its `expires` is before the request
    FORGED = "forged"  # signature fails against the operator's authentic key
    UNVERIFIABLE = "unverifiable"  # key unobtainable / base unbuildable / body signed
    NOT_APPLICABLE = "not_applicable"  # no web-bot-auth signature on the request


@dataclass(frozen=True, slots=True)
class WbaResult:
    """Outcome of a Web Bot Auth check on a client's representative signed request.

    Carried alongside :class:`BotVerification` (the network tier) rather than
    folded into it, so the cryptographic and network channels each keep their own
    opinion; the combiner weighs both, with a definitive WBA verdict outranking the
    network one. ``operator`` is the human name resolved from the offline list (the
    "who"), orthogonal to whether the signature is valid.
    """

    status: WbaStatus
    # The curated operator name (from the offline list), or None when the signer
    # isn't one we recognise. Kept registered-only on purpose: the impersonation
    # operator-vs-claim check compares this, and a domain we merely fell back to
    # could be the same operator under another name -- not grounds to cry forgery.
    operator: str | None = None
    # The Signature-Agent host, a display fallback for the "who" when ``operator``
    # is unknown (e.g. ``ahrefs.com``). Never used for the impersonation decision.
    signer_domain: str | None = None
    keyid: str | None = None  # the JWK thumbprint the signature names
    created: int | None = None  # signature `created` (unix seconds), if present
    expires: int | None = None  # signature `expires` (unix seconds), if present
    reason: str | None = None  # why UNVERIFIABLE / FORGED, for the report
    evidence: tuple[str, ...] = ()
    # A sparse sample of this client's signed requests disagreed: some verified,
    # some didn't (the headline status is the representative request's). Surfaced as
    # ``wba-mixed`` -- one identity presenting both valid and non-valid signatures.
    mixed: bool = False
    # A nonce in this client's signature(s) also appeared from a *different* origin:
    # a captured signature replayed (``wba-replay``). The whole-log view is what lets
    # us see this; an edge server checking one request can't.
    replayed: bool = False
    # A nonce reused across this client's own requests (same origin) -- a signer
    # reusing nonces rather than a replay. A benign-ish note (``wba-nonce-reuse``).
    nonce_reused: bool = False


@dataclass(frozen=True, slots=True)
class ClientProfile:
    """Everything known about one client, assembled by the pipeline.

    Binds the identity, the raw entries (kept for inspect-mode traces), the
    measured features, optional robots/verification results, and the final
    classification. Reports and inspect mode consume this.
    """

    client_id: ClientId
    entries: tuple[LogEntry, ...]
    features: ClientFeatures
    classification: Classification
    compliance: ComplianceReport | None = None
    verification: BotVerification | None = None
    # Web Bot Auth signature verdict, when the client presented a signed request.
    # The cryptographic-identity channel, parallel to ``verification`` (network).
    wba: WbaResult | None = None
    # For a merged verified-bot entry: the individual IPs collapsed into it.
    member_ips: tuple[str, ...] = ()
    # Origin-network bucket this client was attributed to (hosting provider /
    # egress network / residential), matching the cross-tab columns.
    network: str | None = None
    # True when this row is a display aggregate of many independent clients (a
    # privacy-relay / VPN egress fold, keyed by network+UA past throwaway IPs),
    # not a single identified client. Per-client behavioural signals -- request
    # cadence and the site-relative magnitudes -- are meaningless on it (the
    # interleaved arrivals and union span are artifacts of folding), so they are
    # suppressed, and it is never sampled into the reference-browser pool.
    is_aggregate: bool = False
