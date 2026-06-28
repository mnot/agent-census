"""Command-line interface: ``analyze`` and ``inspect`` subcommands."""

from __future__ import annotations

import argparse
import dataclasses
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, identity, iprange, pipeline, userconfig
from .audit import run as run_audit
from .classify import DEFAULT_UNKNOWN_THRESHOLD
from .errors import AgentCensusError
from .identity import ClientKeyStrategy
from .maxmind import (
    AsnResolver,
    CountryResolver,
    discover_mm_dir,
    open_asn_db,
    open_country_db,
)
from .netverify import BotVerifier
from .parsing import available, resolve
from .parsing.apache import PRESETS
from .parsing.base import LogParser
from .pipeline import AnalysisResult, collect_entries
from .report import (
    CountryFlags,
    country_flags,
    render_calibration,
    render_inspect,
    render_inspect_html,
    render_report,
    render_report_html,
    select_profiles,
)
from .robots import from_file, from_network
from .robots.parser import RobotsRules
from .robots.source import RobotsDoc, url_for_host

_ANALYZE_EXAMPLES = """\
examples:
  # simplest case: a log in the default Apache "combined" format
  agent-census analyze access.log

  # several rotated logs, pooled into one analysis (shell glob is fine)
  agent-census analyze access.log access.log.1 access.log.2.gz

  # a custom Apache LogFormat, pasted verbatim from your config (quote it!)
  agent-census analyze access.log \\
      --log-format '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"'

  # write the HTML report (the default) to a file, with robots.txt compliance
  agent-census analyze access.log* -o census.html \\
      --robots-file /srv/http/site/robots.txt

  # Markdown instead of HTML, to stdout
  agent-census analyze access.log --md

  # skip the network lookups crawler verification does
  agent-census analyze access.log --no-verify-bots

Options may appear before, after, or between the log files.
"""

_CALIBRATE_EXAMPLES = """\
examples:
  # digest of the traffic worth reviewing to improve accuracy
  agent-census calibrate access.log* -o calibration.md

  # widen each section to 50 rows before truncating
  agent-census calibrate access.log --top 50

The output is meant to be read (or pasted to an assistant) to spot ASNs, crawlers,
and UA/heuristic gaps that need tuning -- not as an end-user report.
"""

_INSPECT_EXAMPLES = """\
examples:
  # every client classified as a vulnerability scanner, with full reasoning
  agent-census inspect access.log --kind vuln_scanner

  # one client by IP (or any substring of its display label), full trace
  agent-census inspect access.log --client 203.0.113.66 --full
"""


def _percent(value: str) -> float:
    """An argparse type for a 0-100 percentage, rejecting out-of-range input upfront."""
    pct = float(value)
    if not 0.0 <= pct <= 100.0:
        raise argparse.ArgumentTypeError(f"must be between 0 and 100, got {pct:g}")
    return pct


def _add_shared(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "logfiles",
        type=Path,
        nargs="+",
        metavar="LOGFILE",
        help="one or more access logs (plain or .gz); multiple files are pooled",
    )

    # Sticky options (log format, identity, robots source) default to None so an
    # unset one falls back to ~/.config; see _apply_persisted_settings.
    fmt_group = parser.add_argument_group("input format")
    fmt = fmt_group.add_mutually_exclusive_group()
    fmt.add_argument(
        "--log-format",
        metavar="STR",
        help="verbatim Apache LogFormat/CustomLog directive string (default: combined)",
    )
    fmt.add_argument(
        "--log-format-preset",
        choices=sorted(set(PRESETS) | (set(available()) - {"apache"})),
        help="a named format instead of --log-format: an Apache preset "
        "(common / combined / vhost_combined) or 'cloudflare' (Logpush JSON)",
    )
    fmt_group.add_argument(
        "--identity",
        default=None,
        choices=identity.available(),
        help="how to group requests into clients (default: ip_ua)",
    )
    fmt_group.add_argument(
        "--vhost",
        metavar="SUBSTRING",
        action="append",
        help="analyse only lines served for a virtual host matching SUBSTRING "
        "(matched against the logged %%v, else the Host header); scopes a multi-site "
        "log to one site. Repeatable: a line is kept if it matches any --vhost",
    )

    robots_group = parser.add_argument_group("robots.txt (optional)")
    robots_group.add_argument(
        "--robots-file", type=Path, metavar="PATH", help="local robots.txt to check against"
    )
    robots_group.add_argument(
        "--robots-url", metavar="URL", help="robots.txt URL to fetch over the network"
    )
    robots_group.add_argument(
        "--host",
        metavar="HOST",
        help="site host; its robots.txt is fetched over the network",
    )
    robots_group.add_argument(
        "--verify-bots",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="DNS / IP-range verification of declared crawlers "
        "(default: on; --no-verify-bots skips its network lookups)",
    )
    robots_group.add_argument(
        "--fetch-ranges",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="fetch providers' published IP ranges for datacenter / egress "
        "detection (default: on, cached weekly; --no-fetch-ranges stays offline "
        "on the bundled inline ranges)",
    )

    asn_group = parser.add_argument_group("MaxMind lookups (optional)")
    asn_group.add_argument(
        "--mm-asn-db",
        type=Path,
        metavar="PATH",
        help="MaxMind-format ASN database (.mmdb) used to resolve each client's "
        "origin AS from its IP. Wins over an AS the log already carries (the "
        "database can be fresher). Remembered between runs.",
    )
    asn_group.add_argument(
        "--mm-country-db",
        type=Path,
        metavar="PATH",
        help="MaxMind-format country (or city) database (.mmdb) used to flag the "
        "origin country of high-traffic, unidentified non-human clients in the "
        "report. Remembered between runs.",
    )
    asn_group.add_argument(
        "--mm-db-dir",
        type=Path,
        metavar="DIR",
        help="directory of MaxMind .mmdb files (e.g. a geoipupdate target); the ASN "
        "and country databases are found by their metadata, whatever they're named. "
        "An explicit --mm-asn-db / --mm-country-db overrides it for that role. "
        "Remembered between runs.",
    )

    out_group = parser.add_argument_group("output")
    out_group.add_argument(
        "--md",
        action="store_true",
        help="emit Markdown instead of the default self-contained HTML page",
    )
    out_group.add_argument(
        "-o", "--output", type=Path, metavar="PATH", help="write output here instead of stdout"
    )
    out_group.add_argument(
        "--unknown-threshold",
        type=float,
        metavar="FLOAT",
        default=DEFAULT_UNKNOWN_THRESHOLD,
        help="minimum confidence to assign a kind (default: %(default)s)",
    )
    out_group.add_argument(
        "--quiescent-hours",
        type=float,
        metavar="H",
        default=24.0,
        help="free a client's state after H hours of inactivity to cap memory "
        "(default: %(default)s; 0 disables)",
    )
    out_group.add_argument(
        "--max-per-kind",
        type=int,
        metavar="N",
        default=pipeline.DEFAULT_MAX_PER_KIND,
        help="keep at most N detailed client profiles per kind to cap memory; "
        "summary stats stay exact regardless (default: %(default)s; 0 = unlimited, "
        "needed to inspect a rare low-volume client)",
    )


_TOP_DESCRIPTION = """\
agent-census: characterize the clients hitting a web site.

Reads one or more Apache access logs, identifies each distinct client, and works
out what it is from its request patterns -- URLs, status codes, and timing. It
also checks robots.txt compliance and verifies declared crawlers by DNS / IP
range (on by default; --no-verify-bots to skip the network lookups).

Client kinds:
  browser       app            feed_reader      social_preview  search_engine
  archiver      ai_crawler     seo_marketing    data_harvester  monitor
  crawler       scraper        spoofed_browser  spam_bot        vuln_scanner
  impersonator  automation     unknown

Output is a self-contained HTML page (default), or Markdown with --md.
"""

_TOP_EPILOG = """\
quick start:
  agent-census analyze /var/log/apache2/access.log -o census.html
  agent-census analyze access.log --md
  agent-census analyze access.log --robots-file ./robots.txt
  agent-census inspect access.log --kind vuln_scanner
  agent-census calibrate access.log -o calibration.md

Run 'agent-census analyze -h', 'inspect -h', or 'calibrate -h' for every option,
the supported log-format directives, and more examples.
"""


def _build_parser() -> tuple[argparse.ArgumentParser, dict[str, argparse.ArgumentParser]]:
    parser = argparse.ArgumentParser(
        prog="agent-census",
        description=_TOP_DESCRIPTION,
        epilog=_TOP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    analyze = sub.add_parser(
        "analyze",
        aliases=["analyse"],
        help="produce a census of all clients, grouped by kind",
        description="Produce a census of all clients hitting the site, grouped by kind.",
        epilog=_ANALYZE_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_shared(analyze)
    analyze_out = analyze.add_argument_group("report detail")
    analyze_out.add_argument(
        "--top", type=int, default=5, metavar="N", help="clients shown per kind (default: 5)"
    )
    analyze_out.add_argument(
        "--min-requests",
        type=int,
        default=1,
        metavar="N",
        help="ignore clients below N requests (default: 1)",
    )
    analyze_out.add_argument(
        "--breakout-min-pct",
        type=_percent,
        default=10.0,
        metavar="PCT",
        help="HTML report: smallest folded datacentre offered in the network "
        "table's break-out selector, as a %% of any single kind's traffic "
        "(default: 10)",
    )

    calibrate = sub.add_parser(
        "calibrate",
        help="emit a Markdown digest of uncertain / unrecognised traffic for tuning",
        description="Emit a calibration digest: the marginal, uncertain, and "
        "unrecognised traffic to review when improving classification accuracy "
        "(unrecognised ASNs, unverified crawlers, spoof flags, browser-ID quality, "
        "singletons, unknowns, conflicting signals). Markdown only; keeps every "
        "client in memory, so it is heavier than analyze.",
        epilog=_CALIBRATE_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_shared(calibrate)
    calibrate.add_argument(
        "--top",
        type=int,
        default=30,
        metavar="N",
        help="rows shown per section before truncating (default: 30)",
    )

    inspect = sub.add_parser(
        "inspect",
        help="dump the trace and classification rationale for client(s)",
        description="Dump the full trace and classification rationale for selected client(s).",
        epilog=_INSPECT_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_shared(inspect)

    audit = sub.add_parser(
        "audit",
        help="check the datacentre ASN list against Cloudflare Radar + PeeringDB",
        description="Validate the (provider, ASN) associations in the bundled "
        "datacenter_ranges list -- flag mismatches and dead ASNs, suggest sibling "
        "ASNs -- or, with --asn, assess candidate ASNs (e.g. from `calibrate`). "
        "Needs a Cloudflare Radar API token (--token or $CF_API_TOKEN); uses an "
        "automated-vs-human traffic split as a datacentre signal.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    audit.add_argument(
        "--asn",
        metavar="N,N,…",
        help="assess these candidate ASNs instead of the bundled file "
        "('AS123' or '123', comma/space separated)",
    )
    audit.add_argument(
        "--token",
        help="Cloudflare Radar API token; saved to config for next time. Else "
        "$CF_API_TOKEN / $CLOUDFLARE_API_TOKEN, else the saved token",
    )
    audit.add_argument(
        "--no-peeringdb", action="store_true", help="skip the PeeringDB network-type lookup"
    )
    audit.add_argument(
        "--refresh", action="store_true", help="ignore the cached API responses and re-fetch"
    )
    audit.add_argument(
        "--verbose",
        action="store_true",
        help="also list every entry with its details, not just the concerns",
    )

    sub_parsers = {
        "analyze": analyze,
        "analyse": analyze,  # British / Australian spelling alias
        "calibrate": calibrate,
        "inspect": inspect,
        "audit": audit,
    }
    inspect_sel = inspect.add_argument_group("selection")
    inspect_sel.add_argument(
        "--client", metavar="ID", help="match clients by IP or display substring"
    )
    inspect_sel.add_argument("--kind", metavar="KIND", help="inspect all clients of this kind")
    inspect_sel.add_argument(
        "--network",
        metavar="NET",
        help="inspect clients in this origin network (substring, e.g. aws / relay / "
        "residential; combine with --kind to drill into one cross-tab cell)",
    )
    inspect_sel.add_argument(
        "--limit", type=int, default=20, metavar="N", help="trace rows per client (default: 20)"
    )
    inspect_sel.add_argument("--full", action="store_true", help="show every request in the trace")
    return parser, sub_parsers


def _resolve_format(args: argparse.Namespace) -> str:
    if args.log_format:
        return str(args.log_format)
    if args.log_format_preset:
        return PRESETS[args.log_format_preset]
    print("note: no --log-format given; assuming the Apache 'combined' format", file=sys.stderr)
    return PRESETS["combined"]


def _build_log_parser(args: argparse.Namespace) -> LogParser:
    """Pick the parser. A preset naming a non-Apache parser (e.g. cloudflare)
    selects it directly; otherwise it's Apache with a format string."""
    preset = args.log_format_preset
    if preset and preset not in PRESETS:
        return resolve(preset, {})
    return resolve("apache", {"format": _resolve_format(args)})


def _load_robots(args: argparse.Namespace) -> RobotsDoc | None:
    if args.robots_file:
        return from_file(args.robots_file)
    target = args.robots_url or args.host  # naming a remote source opts into fetching it
    if target:
        return from_network(url_for_host(target))
    return None


@dataclass
class _RunContext:
    parser: LogParser
    strategy: ClientKeyStrategy
    result: AnalysisResult
    robots_note: str | None
    elapsed: float
    country_flags: CountryFlags


def _apply_persisted_settings(args: argparse.Namespace) -> None:
    """Fill sticky options from ``~/.config`` when unset; persist any passed now.

    Sticky options: the log format (``--log-format`` / ``--log-format-preset``,
    one supersedes the other), ``--identity``, and the robots source
    (``--robots-file`` / ``--robots-url``). Naming any robots source this run
    (including ``--host``) suppresses a restored one so it can't override.
    """
    cfg = userconfig.load()
    updated = False

    if args.log_format is not None:
        cfg["log_format"], updated = args.log_format, True
        cfg.pop("log_format_preset", None)
    elif args.log_format_preset is not None:
        cfg["log_format_preset"], updated = args.log_format_preset, True
        cfg.pop("log_format", None)
    elif "log_format" in cfg:
        args.log_format = cfg["log_format"]
    elif "log_format_preset" in cfg:
        args.log_format_preset = cfg["log_format_preset"]

    if args.identity is not None:
        cfg["identity"], updated = args.identity, True
    elif "identity" in cfg:
        args.identity = cfg["identity"]

    passed_source = args.robots_file or args.robots_url or args.host
    if args.robots_file is not None:
        cfg["robots_file"], updated = str(args.robots_file), True
        cfg.pop("robots_url", None)
    elif args.robots_url is not None:
        cfg["robots_url"], updated = args.robots_url, True
        cfg.pop("robots_file", None)
    if not passed_source:
        if "robots_file" in cfg:
            args.robots_file = Path(cfg["robots_file"])
        elif "robots_url" in cfg:
            args.robots_url = cfg["robots_url"]

    # A MaxMind source is either a directory (discovered) or explicit per-database paths;
    # an explicit path overrides the directory for its role. Passing --mm-db-dir this run
    # drops any restored explicit paths so the directory can take over cleanly, but a
    # path also passed this run still wins.
    passed_dir = args.mm_db_dir is not None
    if passed_dir:
        cfg["mm_db_dir"], updated = str(args.mm_db_dir), True
        if args.mm_asn_db is None:
            cfg.pop("mm_asn_db", None)
        if args.mm_country_db is None:
            cfg.pop("mm_country_db", None)
    elif "mm_db_dir" in cfg:
        args.mm_db_dir = Path(cfg["mm_db_dir"])

    if args.mm_asn_db is not None:
        cfg["mm_asn_db"], updated = str(args.mm_asn_db), True
    elif not passed_dir and "mm_asn_db" in cfg:
        args.mm_asn_db = Path(cfg["mm_asn_db"])

    if args.mm_country_db is not None:
        cfg["mm_country_db"], updated = str(args.mm_country_db), True
    elif not passed_dir and "mm_country_db" in cfg:
        args.mm_country_db = Path(cfg["mm_country_db"])

    if updated:
        userconfig.save(cfg)
    if args.identity is None:
        args.identity = "ip_ua"  # the built-in default when nothing is set or saved


_MAXMIND_SKEW_DAYS = 90  # warn if the DB was built this far outside the log's span


def _as_utc(stamp: datetime) -> datetime:
    """Treat a naive log timestamp (a log format without a zone) as UTC, so it can
    be compared against the tz-aware MaxMind build epoch without a TypeError."""
    return stamp if stamp.tzinfo is not None else stamp.replace(tzinfo=timezone.utc)


def _warn_maxmind_skew(
    resolver: AsnResolver | CountryResolver, result: AnalysisResult, what: str
) -> None:
    """Warn loudly when a MaxMind DB was built well outside the log's time span.

    ``what`` names what the database supplies (e.g. ``"AS attributions"``), so the
    warning points at the database actually responsible.
    """
    if resolver.build_epoch is None:
        return
    seen = [
        _as_utc(t)
        for p in result.profiles
        for t in (p.features.first_seen, p.features.last_seen)
        if t
    ]
    if not seen:
        return
    built = datetime.fromtimestamp(resolver.build_epoch, tz=timezone.utc)
    low, high = min(seen), max(seen)
    if built < low:
        gap, when = (low - built).days, "before"
    elif built > high:
        gap, when = (built - high).days, "after"
    else:
        return
    if gap > _MAXMIND_SKEW_DAYS:
        print(
            f"agent-census: warning: the MaxMind database was built {gap} days {when} the "
            f"log period; its {what} may not match the log's era.",
            file=sys.stderr,
        )


def _maxmind_paths(args: argparse.Namespace) -> tuple[Path | None, Path | None]:
    """Effective (ASN, country) database paths; explicit flags override --mm-db-dir."""
    asn, country = args.mm_asn_db, args.mm_country_db
    if args.mm_db_dir is not None:
        found = discover_mm_dir(args.mm_db_dir)
        asn = asn or found.asn
        country = country or found.country
        if asn is None and country is None:
            print(
                f"agent-census: warning: no ASN or country .mmdb found in {args.mm_db_dir}",
                file=sys.stderr,
            )
    return asn, country


def _run_pipeline(args: argparse.Namespace) -> _RunContext:
    parser = _build_log_parser(args)
    strategy = identity.get_strategy(args.identity)

    robots_doc = _load_robots(args)
    rules = RobotsRules(robots_doc.text) if robots_doc is not None else None
    robots_note = robots_doc.note() if robots_doc is not None else None

    verifier = BotVerifier() if args.verify_bots else None
    if args.fetch_ranges:
        iprange.enable_remote()
    quiescent = args.quiescent_hours * 3600 if args.quiescent_hours > 0 else None
    asn_path, country_path = _maxmind_paths(args)
    asn_resolver = open_asn_db(asn_path) if asn_path else None

    start = time.monotonic()
    try:
        result = pipeline.analyze(
            args.logfiles,
            parser,
            strategy,
            robots=rules,
            verifier=verifier,
            unknown_threshold=args.unknown_threshold,
            keep_signals=args.command in ("inspect", "calibrate"),
            quiescent_seconds=quiescent,
            max_per_kind=args.max_per_kind,
            vhosts=args.vhost,
            asn_resolver=asn_resolver,
        )
    finally:
        if asn_resolver is not None:
            asn_resolver.close()
    if asn_resolver is not None:
        _warn_maxmind_skew(asn_resolver, result, "AS attributions")

    flags = CountryFlags()
    if country_path:
        country_resolver = open_country_db(country_path)
        try:
            flags = country_flags(result.profiles, country_resolver)
        finally:
            country_resolver.close()
        _warn_maxmind_skew(country_resolver, result, "country attributions")

    elapsed = time.monotonic() - start
    return _RunContext(
        parser=parser,
        strategy=strategy,
        result=result,
        robots_note=robots_note,
        elapsed=elapsed,
        country_flags=flags,
    )


def _inspect_text(ctx: _RunContext, args: argparse.Namespace) -> str:
    """Render inspect output, collecting raw entries only for the matched clients."""
    selected = select_profiles(ctx.result, client=args.client, kind=args.kind, network=args.network)
    entries = collect_entries(args.logfiles, ctx.parser, ctx.strategy, selected, vhosts=args.vhost)
    selected = [dataclasses.replace(p, entries=entries.get(p.client_id, ())) for p in selected]
    if args.md:
        return render_inspect(selected, limit=args.limit, full=args.full)
    return render_inspect_html(selected, limit=args.limit, full=args.full)


def _source_label(args: argparse.Namespace) -> str:
    # File names only -- the report shouldn't disclose where the logs live on disk.
    return ", ".join(Path(p).name for p in args.logfiles)


def _emit(text: str, output: Path | None) -> None:
    if output is None:
        sys.stdout.write(text)
    else:
        output.write_text(text, encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    top, subcommands = _build_parser()
    if not raw or raw[0] not in subcommands:
        # No/unknown command (or a bare -h): let the top parser show usage/help.
        # It raises SystemExit for -h (0) and for an unknown command (2).
        top.parse_args(raw)
        top.print_help()
        return 0
    # Per-command parsing so options can be freely intermixed with the log files
    # (argparse's plain parse_args can't do that with an nargs="+" positional).
    args = subcommands[raw[0]].parse_intermixed_args(raw[1:])
    args.command = "analyze" if raw[0] == "analyse" else raw[0]
    try:
        if args.command == "audit":
            return run_audit(
                asn=args.asn,
                token=args.token,
                no_peeringdb=args.no_peeringdb,
                refresh=args.refresh,
                verbose=args.verbose,
            )
        _apply_persisted_settings(args)
        if args.command == "calibrate":
            args.max_per_kind = 0  # the digest needs every client, not the top-N tail
        ctx = _run_pipeline(args)
        if args.command == "analyze":
            result = ctx.result
            if args.min_requests > 1:
                kept = tuple(
                    p for p in result.profiles if p.features.request_count >= args.min_requests
                )
                result = dataclasses.replace(result, profiles=kept)
            source = _source_label(args)
            if args.md:
                text = render_report(
                    result,
                    source=source,
                    top=args.top,
                    robots_note=ctx.robots_note,
                    elapsed=ctx.elapsed,
                    country_flags=ctx.country_flags,
                )
            else:
                text = render_report_html(
                    result,
                    source=source,
                    top=args.top,
                    robots_note=ctx.robots_note,
                    elapsed=ctx.elapsed,
                    country_flags=ctx.country_flags,
                    breakout_min_share=args.breakout_min_pct / 100,
                )
        elif args.command == "calibrate":
            text = render_calibration(ctx.result, source=_source_label(args), top=args.top)
        else:
            text = _inspect_text(ctx, args)
        _emit(text, args.output)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except AgentCensusError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0
