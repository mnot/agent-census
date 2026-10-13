"""Run-level stderr warnings about inputs and checks that went wrong or thin.

Each function inspects a finished :class:`AnalysisResult` (or the verifier / robots
document behind it) and prints an ``agent-census: warning:`` line when something
would otherwise read as a quiet non-result.
"""

from __future__ import annotations

import sys
import time
from dataclasses import replace

from .model import WbaResult, WbaStatus
from .netverify import BotVerifier
from .pipeline import AnalysisResult
from .report.format import count
from .robots.parser import RobotsRules
from .robots.source import RobotsDoc
from .wba import format_stamp, key_failure_note


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


_WBA_KEY_HINTS = {
    "fetch-failed": "Check the directory is reachable from here, then re-run.",
    "bad-directory": "The directory may be misconfigured (see `agent-census wba-check`).",
    "offline": "Re-run with remote lookups enabled.",
}


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


_KEY_EXAMPLES = 3


def warn_wba_key_skew(result: AnalysisResult, now: float | None = None) -> None:
    """Warn, once per (cause, directory), when operators' keys couldn't be obtained.

    Signed clients are grouped so a log with hundreds of them stays a handful of
    lines; the per-client detail (key, dates, directory) is each client's
    ``wba-unverified`` tag evidence in the report. A ``keyid`` is content-addressed
    and immutable, so a key absent from a directory that read fine was either
    rotated away (plausible only for an older log; the permanent key store then
    helps if verification runs nearer collection) or never published there. The note
    is therefore conditioned on the requests' age
    (:func:`agent_census.wba.key_failure_note`). Other causes (offline, unreachable
    or malformed directory) are named as such rather than lumped in as rotation.
    """
    now = time.time() if now is None else now
    groups: dict[tuple[str, str], list[WbaResult]] = {}
    for profile in result.profiles:
        wba = profile.wba
        if wba is None or wba.status is not WbaStatus.UNVERIFIABLE or wba.key_failure is None:
            continue
        groups.setdefault((wba.key_failure, wba.directory_url or ""), []).append(wba)
    for (failure, directory), results in sorted(groups.items()):
        keys = list(
            dict.fromkeys(f"{r.keyid} ({r.operator or r.signer_domain or '?'})" for r in results)
        )
        shown = ", ".join(keys[:_KEY_EXAMPLES]) + (
            f", +{len(keys) - _KEY_EXAMPLES} more" if len(keys) > _KEY_EXAMPLES else ""
        )
        requests = sorted(r.request_time for r in results if r.request_time is not None)
        facts = [f"{count(len(keys), 'key')}: {shown}"]
        if directory:
            facts.insert(0, f"directory {directory}")
        if requests:
            facts.append(f"requests {format_stamp(requests[0])} to {format_stamp(requests[-1])}")
        notes: dict[str, None] = {}
        for when in requests[:1] + requests[-1:]:
            notes[key_failure_note(replace(results[0], request_time=when), now)] = None
        advice = " ".join(filter(None, [*notes, _WBA_KEY_HINTS.get(failure, "")]))
        print(
            f"agent-census: warning: Web Bot Auth: {count(len(results), 'client')} unverified, "
            f"{results[0].reason} [{'; '.join(facts)}]. {advice}".rstrip(),
            file=sys.stderr,
        )
