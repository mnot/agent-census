"""Run-level stderr warnings about inputs and checks that went wrong or thin.

Each function inspects a finished :class:`AnalysisResult` (or the verifier / robots
document behind it) and prints an ``agent-census: warning:`` line when something
would otherwise read as a quiet non-result.
"""

from __future__ import annotations

import sys

from .netverify import BotVerifier
from .pipeline import AnalysisResult
from .robots.parser import RobotsRules
from .robots.source import RobotsDoc
from .wba import WbaVerifier


def warn_robots_doc(doc: RobotsDoc, rules: RobotsRules) -> None:
    """Warn when the robots.txt in hand is unlikely to be one, or is incomplete.

    A document with no ``User-agent`` group at all parses to "everything allowed",
    which would read as every client being compliant.
    """
    problems = list(doc.caveats)
    if doc.text.strip() and rules.group_count == 0:
        problems.append("it contains no User-agent groups, so every path is treated as allowed")
    elif not doc.text.strip():
        problems.append("it is empty, so every path is treated as allowed")
    if problems:
        print(
            f"agent-census: warning: robots.txt ({doc.provenance}): {'; '.join(problems)}.",
            file=sys.stderr,
        )


# Share of unparseable lines above which a run warns: a few malformed lines are
# normal in a busy log, but beyond this the --log-format is the likelier culprit.
_SKIP_WARN_FRACTION = 0.05


def warn_skipped_lines(result: AnalysisResult) -> None:
    """Warn when many lines (or all of them) failed to parse -- the classic symptom of
    a wrong ``--log-format``, which otherwise yields a plausible-looking empty report."""
    skips = result.skips
    if skips.total_lines == 0 or skips.skipped == 0:
        return
    kept = skips.parsed + skips.excluded + skips.out_of_window
    if kept and skips.skipped / skips.total_lines <= _SKIP_WARN_FRACTION:
        return
    top = sorted(skips.reasons.items(), key=lambda item: -item[1])[:3]
    why = "; ".join(f"{count:,} {reason}" for reason, count in top)
    first = ""
    if skips.first_skip is not None:
        line_no, text = skips.first_skip
        first = f" First at line {line_no}: {text!r}."
    print(
        f"agent-census: warning: {skips.skipped:,} of {skips.total_lines:,} log lines "
        f"({skips.skipped / skips.total_lines:.0%}) could not be parsed ({why}).{first} "
        "Check --log-format / --log-format-preset.",
        file=sys.stderr,
    )


_DNS_WARN_FRACTION = 0.10


def warn_dns_failures(verifier: BotVerifier) -> None:
    """Warn when many reverse/forward DNS lookups timed out or errored.

    Each such client is merely ``dns-unverified``, so a dead or throttled resolver
    would otherwise look like a log full of unverifiable crawlers. The commonest
    message per cause is shown: the same error on most lookups (e.g. "Temporary
    failure in name resolution") points at the resolver, whereas a mix is usually
    the remote reverse zones of individual clients failing.
    """
    counts, total, top = verifier.dns_failure_report()
    failed = counts.get("timed out", 0) + counts.get("resolver error", 0)
    if total == 0 or failed / total <= _DNS_WARN_FRACTION:
        return
    detail = ", ".join(
        f"{num:,} {category} (commonest: {top[category][0]} x{top[category][1]:,})"
        for category, num in sorted(counts.items())
    )
    print(
        f"agent-census: warning: {failed:,} of {total:,} DNS lookups during bot verification "
        f"timed out or errored: {detail}. The affected clients are dns-unverified. "
        "If most share one error, check the resolver is reachable and not rate-limiting.",
        file=sys.stderr,
    )


def warn_untimed_lines(result: AnalysisResult, since: float | None) -> None:
    """Warn when parsed lines carry no readable timestamp.

    Such lines slip past ``--since`` and add nothing to timing, so a log whose date
    format the parser can't read otherwise yields a report with no time range and no
    hint why.
    """
    skips = result.skips
    if not skips.untimed or not skips.parsed:
        return
    if since is None and skips.untimed / skips.parsed <= _SKIP_WARN_FRACTION:
        return
    effect = "--since cannot window them and " if since is not None else ""
    print(
        f"agent-census: warning: {skips.untimed:,} of {skips.parsed:,} parsed log lines have no "
        f"readable timestamp; {effect}timing and cadence signals ignore them. "
        "Check the log format's time field.",
        file=sys.stderr,
    )


def warn_wba_unusable(result: AnalysisResult) -> None:
    """Warn when requests carried Web Bot Auth ``Signature-Input`` but no usable claim.

    Such clients get no ``wba`` tag at all, so without this a mis-set LogFormat
    reads as "nobody signs".
    """
    totals: dict[str, int] = {}
    clients = 0
    for profile in result.profiles:
        if profile.features.wba_unusable:
            clients += 1
        for problem, num in profile.features.wba_unusable.items():
            totals[problem] = totals.get(problem, 0) + num
    if totals:
        causes = "; ".join(f"{problem} ({num})" for problem, num in sorted(totals.items()))
        print(
            f"agent-census: warning: {sum(totals.values())} request(s) from {clients} client(s) "
            f"carried Signature-Input but no usable Web Bot Auth signature: {causes}. "
            "Check the log format captures the Signature and Signature-Input headers intact.",
            file=sys.stderr,
        )


def warn_wba_directories(verifier: WbaVerifier) -> None:
    """Warn when no Web Bot Auth key directory could be reached at all.

    A single operator's directory being down, absent or malformed is that operator's
    fault and shows per client in the report (``wba-unverified``). Every directory
    failing at the connection level, across at least two operators, points at this
    machine's network instead.
    """
    attempted, unreachable = verifier.directory_fetch_summary()
    if 2 <= attempted == unreachable:
        print(
            f"agent-census: warning: none of {attempted} Web Bot Auth key directories could be "
            "reached (timeouts or connection errors); check this machine's network. "
            "Signed clients are wba-unverified.",
            file=sys.stderr,
        )
