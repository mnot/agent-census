"""Command-line interface: ``analyze`` and ``inspect`` subcommands."""

from __future__ import annotations

import argparse
import dataclasses
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__, identity, pipeline
from .classify import DEFAULT_UNKNOWN_THRESHOLD
from .errors import AgentCensusError
from .netverify import make_verify_fn
from .parsing import resolve
from .parsing.apache import PRESETS
from .pipeline import AnalysisResult, ComplianceFn, VerifyFn
from .report import (
    render_inspect,
    render_inspect_html,
    render_report,
    render_report_html,
    select_profiles,
)
from .robots import from_file, from_network, make_compliance_fn
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

  # HTML report, with robots.txt compliance and DNS-verified crawlers
  agent-census analyze access.log* --html -o census.html \\
      --robots-file /srv/http/site/robots.txt --verify-bots

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

    fmt_group = parser.add_argument_group("input format")
    fmt_group.add_argument("--server", default="apache", help="log server format (default: apache)")
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
        default="ip_ua",
        choices=identity.available(),
        help="how to group requests into clients (default: ip_ua)",
    )

    robots_group = parser.add_argument_group("robots.txt (optional)")
    robots_group.add_argument(
        "--robots-file", type=Path, metavar="PATH", help="local robots.txt to check against"
    )
    robots_group.add_argument(
        "--robots-url", metavar="URL", help="robots.txt URL to fetch (with --fetch-robots)"
    )
    robots_group.add_argument(
        "--host", metavar="HOST", help="site host, used to derive the robots.txt URL"
    )
    robots_group.add_argument(
        "--fetch-robots",
        action="store_true",
        help="opt in to fetching robots.txt over the network (may post-date the log)",
    )
    robots_group.add_argument(
        "--verify-bots",
        action="store_true",
        help="opt in to reverse/forward DNS verification of declared crawlers",
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


_TOP_DESCRIPTION = """\
agent-census: characterize the clients hitting a web site.

Reads one or more Apache access logs, identifies each distinct client, and works
out what it is from its request patterns -- URLs, status codes, and timing. It
also checks robots.txt compliance and can DNS-verify declared crawlers.

Client kinds:
  browser       crawler       good_bot      ai_crawler    scraper
  vuln_scanner  spam_bot      feed_reader   monitor       unknown

Output is Markdown (default) or a self-contained HTML page.
"""

_TOP_EPILOG = """\
quick start:
  agent-census analyze /var/log/apache2/access.log
  agent-census analyze access.log* --html -o census.html
  agent-census analyze access.log --robots-file ./robots.txt --verify-bots
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
    if args.fetch_robots:
        target = args.robots_url or args.host
        if not target:
            raise AgentCensusError("--fetch-robots requires --host or --robots-url")
        return from_network(url_for_host(target))
    if args.robots_url or args.host:
        raise AgentCensusError("to fetch robots.txt over the network, add --fetch-robots")
    return None


def _run_pipeline(args: argparse.Namespace) -> tuple[AnalysisResult, str | None]:
    if args.server != "apache":
        log_format = args.log_format or ""
    else:
        log_format = _resolve_format(args)
    parser = resolve(args.server, {"format": log_format})
    strategy = identity.get_strategy(args.identity)

    robots_doc = _load_robots(args)
    compliance_fn: ComplianceFn | None = None
    robots_note: str | None = None
    if robots_doc is not None:
        compliance_fn = make_compliance_fn(RobotsRules(robots_doc.text))
        robots_note = robots_doc.note()

    verify_fn: VerifyFn | None = make_verify_fn() if args.verify_bots else None

    result = pipeline.analyze(
        args.logfiles,
        parser,
        strategy,
        keep_entries=args.command == "inspect",
        compliance_fn=compliance_fn,
        verify_fn=verify_fn,
        unknown_threshold=args.unknown_threshold,
    )
    return result, robots_note


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
        result, robots_note = _run_pipeline(args)
        if args.command == "analyze":
            if args.min_requests > 1:
                kept = tuple(
                    p for p in result.profiles if p.features.request_count >= args.min_requests
                )
                result = dataclasses.replace(result, profiles=kept)
            source = _source_label(args)
            if args.html:
                text = render_report_html(
                    result, source=source, top=args.top, robots_note=robots_note
                )
            else:
                text = render_report(result, source=source, top=args.top, robots_note=robots_note)
        elif args.html:
            selected = select_profiles(result, client=args.client, kind=args.kind)
            text = render_inspect_html(selected, limit=args.limit, full=args.full)
        else:
            text = render_inspect(
                result, client=args.client, kind=args.kind, limit=args.limit, full=args.full
            )
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
