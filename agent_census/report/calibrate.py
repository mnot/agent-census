"""Render a calibration digest of an analysis run.

This is deliberately *not* the human report. It surfaces the marginal,
uncertain, and unrecognised traffic -- the decision boundaries where the data
files (ASN lists, crawler verification) and the UA/behaviour heuristics are most
likely incomplete or wrong -- so an operator (or an assistant tuning the
classifier) can review it and improve accuracy. Output is aggregated Markdown,
capped per section and self-contained, small enough to paste into a chat.

The digest assumes the run kept every client (``max_per_kind=0``); otherwise the
long tail it cares about -- singletons, unknowns, unrecognised ASNs -- would be
truncated before it ever got here.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from ..model import ClientProfile, Kind
from ..pipeline import AnalysisResult
from ..uas import browser_version
from .format import elide_ua, kind_label, truncate

DEFAULT_TOP = 30

# Version-age bands the browser classifier folds into the UA-shape tag.
_AGE_TAGS = (
    "current-browser-ua",
    "stale-browser-ua",
    "ancient-browser-ua",
    "impossible-browser-ua",
)
# One mutually-exclusive UA-shape tag per client (most specific first).
_SHAPE_TAGS = _AGE_TAGS + ("browser-ua", "generic-ua", "bot-ua", "no-user-agent")
# Tags (plus the impersonator kind) worth a false-positive review: each asserts
# something is forged or hostile, so a wrong one mislabels a real client.
_SPOOF_TAGS = (
    "impossible-browser-ua",
    "ancient-browser-ua",
    "forged-referer",
    "probe-paths",
    "traversal",
    "encoding-evasion",
    "exotic-method",
    "404-storm",
    "ua-rotating",
)
# A signal at or above this confidence counts as a real contender for the
# conflicting-signals section.
_CONFLICT_FLOOR = 0.4


def _net_cat(result: AnalysisResult, profile: ClientProfile) -> str:
    return result.network_categories.get(profile.network or "", "residential")


def _shape(tags: frozenset[str]) -> str:
    for tag in _SHAPE_TAGS:
        if tag in tags:
            return tag
    return "—"


def _ua(profile: ClientProfile) -> str:
    shown = elide_ua(profile.features.user_agent, is_browser=profile.features.ua_looks_like_browser)
    return shown or "—"


def _pct(part: int, whole: int) -> str:
    return f"{100 * part / whole:.1f}%" if whole else "0%"


def _trunc_note(shown: int, total: int, unit: str) -> list[str]:
    if total > shown:
        return [f"_… {total - shown} more {unit} not shown (top {shown} by volume)._"]
    return []


@dataclass
class _Cluster:
    """A volume-weighted bucket of clients sharing some key, with sample UAs."""

    requests: int = 0
    clients: int = 0
    kinds: Counter[Kind] = None  # type: ignore[assignment]
    sample_uas: Counter[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.kinds = Counter()
        self.sample_uas = Counter()

    def add(self, profile: ClientProfile) -> None:
        self.requests += profile.features.request_count
        self.clients += 1
        self.kinds[profile.classification.primary] += 1
        self.sample_uas[_ua(profile)] += 1

    def top_kinds(self, limit: int = 3) -> str:
        return ", ".join(f"{kind_label(k)} ×{n}" for k, n in self.kinds.most_common(limit))

    def top_uas(self, limit: int = 3) -> list[str]:
        return [f"`{truncate(ua, 100)}` ×{n}" for ua, n in self.sample_uas.most_common(limit)]


def _unrecognized_asns(result: AnalysisResult, top: int) -> list[str]:
    by_asn: dict[str, _Cluster] = defaultdict(_Cluster)
    org: dict[str, str] = {}
    for profile in result.profiles:
        asn = profile.features.as_number
        if not asn or _net_cat(result, profile) != "residential":
            continue
        by_asn[asn].add(profile)
        org.setdefault(asn, profile.features.as_org or "—")
    if not by_asn:
        return [
            "## Unrecognised ASNs",
            "",
            "_No residual ASNs — the log carried no AS data, or every ASN is "
            "already classified._",
        ]
    ranked = sorted(by_asn.items(), key=lambda kv: kv[1].requests, reverse=True)
    lines = [
        "## Unrecognised ASNs",
        "",
        "Clients that carried an AS number but matched no datacenter / egress / "
        "crawler list, so they fell to residential. High-volume, non-browser ones "
        "are candidates for the ASN lists.",
        "",
        "| ASN | Org | Requests | Clients | Top kinds |",
        "| --- | --- | ---: | ---: | --- |",
    ]
    for asn, cluster in ranked[:top]:
        org_name = truncate(org[asn], 40).replace("|", "/")
        lines.append(
            f"| {asn} | {org_name} | {cluster.requests:,} | {cluster.clients:,} "
            f"| {cluster.top_kinds()} |"
        )
    lines.append("")
    lines += _trunc_note(min(top, len(ranked)), len(ranked), "ASNs")
    return lines


def _declared_unverified(result: AnalysisResult, top: int) -> list[str]:
    known: dict[str, _Cluster] = defaultdict(_Cluster)
    unknown: dict[str, _Cluster] = defaultdict(_Cluster)
    for profile in result.profiles:
        tags = profile.classification.tags
        verified = "verified" in tags or "asn-associated" in tags
        if "declares-known-bot" in tags and not verified:
            known[_ua(profile)].add(profile)
        elif "bot-ua" in tags:
            unknown[_ua(profile)].add(profile)
    lines = [
        "## Declared but unverified crawlers",
        "",
        "Self-identified bots we could not confirm. The first group names a "
        "crawler we recognise but couldn't verify (add/repair its ranges or "
        "rDNS); the second declares a bot we don't recognise at all.",
    ]
    lines += _ua_group("Recognised, unverified", known, top)
    lines += _ua_group("Unrecognised declared bots", unknown, top)
    return lines


def _ua_group(title: str, clusters: dict[str, _Cluster], top: int) -> list[str]:
    if not clusters:
        return ["", f"### {title}", "", "_None._"]
    ranked = sorted(clusters.values(), key=lambda c: c.requests, reverse=True)
    keyed = sorted(clusters.items(), key=lambda kv: kv[1].requests, reverse=True)
    lines = ["", f"### {title}", ""]
    for ua, cluster in keyed[:top]:
        lines.append(
            f"- **{cluster.requests:,} req** · {cluster.clients:,} clients · "
            f"{cluster.top_kinds()}"
        )
        lines.append(f"  `{truncate(ua, 120)}`")
    lines += _trunc_note(min(top, len(ranked)), len(ranked), "user-agents")
    return lines


def _spoof_flags(result: AnalysisResult, top: int) -> list[str]:
    by_tag: dict[str, list[ClientProfile]] = defaultdict(list)
    for profile in result.profiles:
        tags = profile.classification.tags
        for tag in _SPOOF_TAGS:
            if tag in tags:
                by_tag[tag].append(profile)
        if profile.classification.primary is Kind.IMPERSONATOR:
            by_tag["impersonator"].append(profile)
    lines = [
        "## Anomaly / spoof flags",
        "",
        "Every client carrying a tag that asserts forgery or hostility. Scan for "
        "false positives — a real client wrongly flagged here is a heuristic bug.",
    ]
    if not by_tag:
        return lines + ["", "_No anomaly flags fired._"]
    for tag in sorted(by_tag, key=lambda t: -len(by_tag[t])):
        hits = sorted(by_tag[tag], key=lambda p: p.features.request_count, reverse=True)
        lines += ["", f"### {tag} ({len(hits)})", ""]
        for profile in hits[:top]:
            lines.append(
                f"- **{profile.features.request_count:,} req** · "
                f"{_net_cat(result, profile)} · {kind_label(profile.classification.primary)}"
            )
            lines.append(f"  `{truncate(_ua(profile), 120)}`")
        lines += _trunc_note(min(top, len(hits)), len(hits), "clients")
    return lines


def _browser_quality(result: AnalysisResult, top: int) -> list[str]:
    browsers = [
        p
        for p in result.profiles
        if p.features.ua_looks_like_browser
        or p.classification.primary is Kind.BROWSER
        or any(t in p.classification.tags for t in _AGE_TAGS)
    ]
    lines = ["## Browser identification quality", ""]
    if not browsers:
        return lines + ["_No browser-shaped clients._"]
    bands: Counter[str] = Counter()
    band_req: Counter[str] = Counter()
    for profile in browsers:
        band = _shape(profile.classification.tags)
        bands[band] += 1
        band_req[band] += profile.features.request_count
    lines += [
        "Version-age band over browser-shaped clients. `browser-ua` means no age "
        "verdict -- either the version couldn't be read *or* it sits between current "
        "and stale; the regex-gap list below is the truly-unreadable subset.",
        "",
        "| Band | Clients | Requests |",
        "| --- | ---: | ---: |",
    ]
    for band in (*_AGE_TAGS, "browser-ua", "—"):
        if bands[band]:
            lines.append(f"| {band} | {bands[band]:,} | {band_req[band]:,} |")
    lines.append("")
    lines += _browser_subgroups(result, browsers, top)
    return lines


def _browser_subgroups(
    result: AnalysisResult, browsers: list[ClientProfile], top: int
) -> list[str]:
    from_dc = [p for p in browsers if _net_cat(result, p) == "datacenter"]
    unparsed: dict[str, _Cluster] = defaultdict(_Cluster)
    headless = []
    for profile in browsers:
        # A genuine regex gap: looks like a browser, but no version can be read at
        # all. (A readable version with a middling age also lacks a band, but it is
        # not a gap, so don't list it here.)
        if (
            profile.features.ua_looks_like_browser
            and browser_version(profile.features.user_agent) is None
        ):
            unparsed[_ua(profile)].add(profile)
        feats = profile.features
        if feats.page_count > 0 and feats.asset_coload_ratio < 0.1:
            headless.append(profile)
    lines: list[str] = []
    lines += _ua_group("Unparsed browser UAs (regex gaps)", unparsed, top)
    lines += _profile_list("Browser UA from a datacenter network", from_dc, result, top, spoof=True)
    lines += _profile_list(
        "Browser UA but loaded no assets (headless tell)", headless, result, top, spoof=False
    )
    return lines


def _profile_list(
    title: str,
    profiles: list[ClientProfile],
    result: AnalysisResult,
    top: int,
    *,
    spoof: bool,
) -> list[str]:
    if not profiles:
        return ["", f"### {title}", "", "_None._"]
    ranked = sorted(profiles, key=lambda p: p.features.request_count, reverse=True)
    note = " (suspicious)" if spoof else ""
    lines = ["", f"### {title}{note}", ""]
    for profile in ranked[:top]:
        lines.append(
            f"- **{profile.features.request_count:,} req** · "
            f"{kind_label(profile.classification.primary)} · "
            f"{_net_cat(result, profile)}"
        )
        lines.append(f"  `{truncate(_ua(profile), 120)}`")
    lines += _trunc_note(min(top, len(ranked)), len(ranked), "clients")
    return lines


def _singletons(result: AnalysisResult, top: int) -> list[str]:
    singles = [p for p in result.profiles if p.features.request_count == 1]
    total_clients = len(result.profiles)
    total_requests = sum(p.features.request_count for p in result.profiles)
    lines = ["## Singletons", ""]
    if not singles:
        return lines + ["_No one-request clients._"]
    by_kind: Counter[Kind] = Counter(p.classification.primary for p in singles)
    by_shape: Counter[str] = Counter(_shape(p.classification.tags) for p in singles)
    by_net: Counter[str] = Counter(_net_cat(result, p) for p in singles)
    by_ua: Counter[str] = Counter(_ua(p) for p in singles)
    lines += [
        f"{len(singles):,} clients made exactly one request "
        f"({_pct(len(singles), total_clients)} of clients, "
        f"{_pct(len(singles), total_requests)} of requests). A UA recurring across "
        "many singletons points at identity fragmentation or one-shot bots.",
        "",
        "| By kind | n | By UA shape | n | By network | n |",
        "| --- | ---: | --- | ---: | --- | ---: |",
    ]
    kinds = by_kind.most_common()
    shapes = by_shape.most_common()
    nets = by_net.most_common()
    for i in range(max(len(kinds), len(shapes), len(nets))):
        kcol = f"{kind_label(kinds[i][0])} | {kinds[i][1]:,}" if i < len(kinds) else " | "
        scol = f"{shapes[i][0]} | {shapes[i][1]:,}" if i < len(shapes) else " | "
        ncol = f"{nets[i][0]} | {nets[i][1]:,}" if i < len(nets) else " | "
        lines.append(f"| {kcol} | {scol} | {ncol} |")
    lines += ["", "**Most common singleton UAs**", ""]
    for ua, count in by_ua.most_common(top):
        lines.append(f"- ×{count:,} `{truncate(ua, 110)}`")
    lines += _trunc_note(min(top, len(by_ua)), len(by_ua), "distinct UAs")
    return lines


def _unknowns(result: AnalysisResult, top: int) -> list[str]:
    by_key: dict[tuple[str, str], _Cluster] = defaultdict(_Cluster)
    for profile in result.profiles:
        if profile.classification.primary is not Kind.UNKNOWN:
            continue
        key = (_shape(profile.classification.tags), _net_cat(result, profile))
        by_key[key].add(profile)
    lines = ["## Unknown clusters", ""]
    if not by_key:
        return lines + ["_Nothing fell to UNKNOWN._"]
    ranked = sorted(by_key.items(), key=lambda kv: kv[1].requests, reverse=True)
    lines += [
        "Clients the combiner couldn't classify, grouped by UA shape × network. A "
        "large coherent cluster is a gap worth a new classifier or data entry.",
        "",
    ]
    for (shape, net), cluster in ranked[:top]:
        lines.append(
            f"- **{shape} · {net}** — {cluster.requests:,} req, {cluster.clients:,} clients"
        )
        for sample in cluster.top_uas(3):
            lines.append(f"  - {sample}")
    lines += _trunc_note(min(top, len(ranked)), len(ranked), "clusters")
    return lines


def _conflicts(result: AnalysisResult, top: int) -> list[str]:
    flagged: list[tuple[ClientProfile, list[tuple[Kind, float]]]] = []
    for profile in result.profiles:
        best: dict[Kind, float] = {}
        for signal in profile.classification.all_signals:
            best[signal.kind] = max(best.get(signal.kind, 0.0), signal.confidence)
        contenders = sorted(
            ((k, c) for k, c in best.items() if c >= _CONFLICT_FLOOR),
            key=lambda kc: kc[1],
            reverse=True,
        )
        if len(contenders) >= 2:
            flagged.append((profile, contenders))
    lines = ["## Conflicting signals", ""]
    if not flagged:
        return lines + ["_No client drew two strong, competing signals._"]
    flagged.sort(key=lambda pc: pc[0].features.request_count, reverse=True)
    lines += [
        "Clients where two or more classifiers fired strongly for different kinds "
        "— a taxonomy or priority issue if the chosen primary is wrong.",
        "",
    ]
    for profile, contenders in flagged[:top]:
        votes = ", ".join(f"{kind_label(k)} {c:.2f}" for k, c in contenders)
        lines.append(
            f"- **{profile.features.request_count:,} req** → {votes} "
            f"(chose {kind_label(profile.classification.primary)})"
        )
        lines.append(f"  `{truncate(_ua(profile), 110)}`")
    lines += _trunc_note(min(top, len(flagged)), len(flagged), "clients")
    return lines


def render_calibration(result: AnalysisResult, *, source: str, top: int = DEFAULT_TOP) -> str:
    """Render the full calibration digest as Markdown."""
    blocks = [
        [f"# Calibration digest — {source}", ""],
        _unrecognized_asns(result, top),
        _declared_unverified(result, top),
        _spoof_flags(result, top),
        _browser_quality(result, top),
        _singletons(result, top),
        _unknowns(result, top),
        _conflicts(result, top),
    ]
    return "\n\n".join("\n".join(block).strip("\n") for block in blocks).rstrip() + "\n"
