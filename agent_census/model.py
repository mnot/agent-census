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
    traversal_hits: int = 0
    evasion_hits: int = 0  # double / overlong encoding -- deliberate WAF evasion

    # timing / rate (None when too few requests to measure intervals)
    inter_arrival_mean: float | None = None
    inter_arrival_median: float | None = None
    inter_arrival_p95: float | None = None
    inter_arrival_min: float | None = None
    peak_requests_per_minute: int = 0
    rate_regularity: float | None = None  # coefficient of variation of intervals

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


@dataclass(frozen=True, slots=True)
class Classification:
    """The final verdict for a client: one primary kind plus secondary tags."""

    primary: Kind
    confidence: float
    tags: frozenset[str] = frozenset()
    evidence: tuple[str, ...] = ()
    all_signals: tuple[Signal, ...] = ()


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


@dataclass(frozen=True, slots=True)
class BotVerification:
    """Outcome of an opt-in DNS check on a client's declared-crawler claim."""

    status: VerificationStatus
    resolved_host: str | None = None
    expected_domains: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()


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
    # For a merged verified-bot entry: the individual IPs collapsed into it.
    member_ips: tuple[str, ...] = ()
    # Origin-network bucket this client was attributed to (hosting provider /
    # egress network / residential), matching the cross-tab columns.
    network: str | None = None
