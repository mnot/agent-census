"""Command-line interface: ``analyze`` and ``inspect`` subcommands."""

from __future__ import annotations

import argparse
import dataclasses
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from . import __version__, identity, iprange, pipeline, userconfig
from .classify import DEFAULT_UNKNOWN_THRESHOLD
from .errors import AgentCensusError
from .identity import ClientKeyStrategy
from .netverify import BotVerifier
from .parsing import resolve
from .parsing.apache import PRESETS
from .parsing.base import LogParser
from .pipeline import AnalysisResult, collect_entries
from .report import (
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

  # HTML report with robots.txt compliance (crawler verification is on by default)
  agent-census analyze access.log* --html -o census.html \\
      --robots-file /srv/http/site/robots.txt

  # skip the network lookups crawler verification does
  agent-census analyze access.log --no-verify-bots

Options may appear before, after, or between the log files.
"""

_INSPECT_EXAMPLES = """\
examples:
  # every client classified as a vulnerability scanner, with full reasoning
  agent-census inspect access.log --kind vuln_scanner

  # one client by IP (or any substring of its display label), full trace
  agent-census inspect access.log --client 203.0.113.66 --full
"""


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
        choices=sorted(PRESETS),
        help="a named format instead of --log-format",
    )
    fmt_group.add_argument(
        "--identity",
        default=None,
        choices=identity.available(),
        help="how to group requests into clients (default: ip_ua)",
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

    out_group = parser.add_argument_group("output")
    out_group.add_argument(
        "--html", action="store_true", help="emit a self-contained HTML page instead of Markdown"
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
  browser       feed_reader    social_preview  search_engine  archiver
  ai_crawler    seo_marketing  monitor         crawler        scraper
  spoofed_browser  spam_bot    vuln_scanner    impersonator   singleton
  unknown

Output is Markdown (default) or a self-contained HTML page.
"""

_TOP_EPILOG = """\
quick start:
  agent-census analyze /var/log/apache2/access.log
  agent-census analyze access.log* --html -o census.html
  agent-census analyze access.log --robots-file ./robots.txt
  agent-census inspect access.log --kind vuln_scanner

Run 'agent-census analyze -h' or 'agent-census inspect -h' for every option,
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

    inspect = sub.add_parser(
        "inspect",
        help="dump the trace and classification rationale for client(s)",
        description="Dump the full trace and classification rationale for selected client(s).",
        epilog=_INSPECT_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_shared(inspect)
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
    return parser, {"analyze": analyze, "inspect": inspect}


def _resolve_format(args: argparse.Namespace) -> str:
    if args.log_format:
        return str(args.log_format)
    if args.log_format_preset:
        return PRESETS[args.log_format_preset]
    print("note: no --log-format given; assuming the Apache 'combined' format", file=sys.stderr)
    return PRESETS["combined"]


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

    if updated:
        userconfig.save(cfg)
    if args.identity is None:
        args.identity = "ip_ua"  # the built-in default when nothing is set or saved


def _run_pipeline(args: argparse.Namespace) -> _RunContext:
    parser = resolve("apache", {"format": _resolve_format(args)})
    strategy = identity.get_strategy(args.identity)

    robots_doc = _load_robots(args)
    rules = RobotsRules(robots_doc.text) if robots_doc is not None else None
    robots_note = robots_doc.note() if robots_doc is not None else None

    verifier = BotVerifier() if args.verify_bots else None
    if args.fetch_ranges:
        iprange.enable_remote()
    quiescent = args.quiescent_hours * 3600 if args.quiescent_hours > 0 else None

    start = time.monotonic()
    result = pipeline.analyze(
        args.logfiles,
        parser,
        strategy,
        robots=rules,
        verifier=verifier,
        unknown_threshold=args.unknown_threshold,
        keep_signals=args.command == "inspect",
        quiescent_seconds=quiescent,
        max_per_kind=args.max_per_kind,
    )
    elapsed = time.monotonic() - start
    return _RunContext(
        parser=parser, strategy=strategy, result=result, robots_note=robots_note, elapsed=elapsed
    )


def _inspect_text(ctx: _RunContext, args: argparse.Namespace) -> str:
    """Render inspect output, collecting raw entries only for the matched clients."""
    selected = select_profiles(ctx.result, client=args.client, kind=args.kind, network=args.network)
    entries = collect_entries(args.logfiles, ctx.parser, ctx.strategy, selected)
    selected = [dataclasses.replace(p, entries=entries.get(p.client_id, ())) for p in selected]
    if args.html:
        return render_inspect_html(selected, limit=args.limit, full=args.full)
    return render_inspect(selected, limit=args.limit, full=args.full)


def _source_label(args: argparse.Namespace) -> str:
    return ", ".join(str(p) for p in args.logfiles)


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
    args.command = raw[0]
    try:
        _apply_persisted_settings(args)
        ctx = _run_pipeline(args)
        if args.command == "analyze":
            result = ctx.result
            if args.min_requests > 1:
                kept = tuple(
                    p for p in result.profiles if p.features.request_count >= args.min_requests
                )
                result = dataclasses.replace(result, profiles=kept)
            source = _source_label(args)
            if args.html:
                text = render_report_html(
                    result,
                    source=source,
                    top=args.top,
                    robots_note=ctx.robots_note,
                    elapsed=ctx.elapsed,
                )
            else:
                text = render_report(
                    result,
                    source=source,
                    top=args.top,
                    robots_note=ctx.robots_note,
                    elapsed=ctx.elapsed,
                )
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
