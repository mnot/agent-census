"""The ASN verification tier: `asns` corroborates or impeaches a declared crawler."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_census import identity, pipeline
from agent_census.dataload import load_asn_agents, load_tokens
from agent_census.model import BotVerification, ClientFeatures, Kind, VerificationStatus
from agent_census.parsing import resolve
from agent_census.parsing.apache import PRESETS
from agent_census.pipeline import _resolve_asn_verification

_AHREFS = "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)"  # asns = [140577]
_ASN_FMT = '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i" "%{MM_ASN}e"'


def _status(as_number: str | None, prior: BotVerification | None = None) -> str | None:
    v = _resolve_asn_verification(prior, ClientFeatures(user_agent=_AHREFS, as_number=as_number))
    return v.status.value if v is not None else None


def test_asn_tier_corroborates_impeaches_and_abstains() -> None:
    assert _status("140577") == "asn_associated"  # in the agent's asns -> corroborated
    assert _status("99999") == "impersonator"  # logged AS, not in the list -> spoofing
    assert _status(None) is None  # no AS in the log -> can't say (never impersonator)


def test_dns_or_range_verdict_takes_precedence_over_asn() -> None:
    verified = BotVerification(VerificationStatus.VERIFIED)
    impostor = BotVerification(VerificationStatus.IMPERSONATOR)
    # A definitive network verdict wins even when the AS would say otherwise.
    assert _status("99999", verified) == "verified"
    assert _status("140577", impostor) == "impersonator"


def test_non_crawler_ua_is_untouched() -> None:
    feats = ClientFeatures(user_agent="curl/8", as_number="140577")
    assert _resolve_asn_verification(None, feats) is None


def test_only_asn_primary_agents_are_recognised_by_as() -> None:
    # Sberbank (asn_primary) is recognised *by* its AS; Ahrefs/Semrush (plain asns)
    # are not -- their AS is verification, looked up via the token spec instead.
    ai_labels = {label for _asn, label in load_asn_agents("ai_crawler")}
    assert "Sberbank" in ai_labels
    assert all(label != "AhrefsBot" for _asn, label in load_asn_agents("seo_marketing"))
    spec = dict(load_tokens("seo_marketing"))[_AHREFS_TOKEN]
    assert spec.asns == (140577,)


_AHREFS_TOKEN = "AhrefsBot"
DATA = Path(__file__).parent / "data"


def _analyze_one_line(tmp_path: Path, line: str, fmt: str = _ASN_FMT) -> pipeline.AnalysisResult:
    log = tmp_path / "asn.log"
    log.write_text(line + "\n", encoding="utf-8")
    parser = resolve("apache", {"format": fmt})
    # verifier off: AhrefsBot folds without DNS, so the ASN tier is what decides.
    return pipeline.analyze(log, parser, identity.get_strategy("ip_ua"))


def _ahrefs_line(as_number: str | None) -> str:
    asn = "-" if as_number is None else as_number
    return (
        f'66.249.66.1 - - [10/Oct/2023:12:00:00 +0000] "GET /p HTTP/1.1" 200 9 "-" '
        f'"{_AHREFS}" "{asn}"'
    )


def test_declared_crawler_from_its_as_is_associated(tmp_path: Path) -> None:
    result = _analyze_one_line(tmp_path, _ahrefs_line("140577"))
    (profile,) = result.profiles
    assert profile.classification.primary is Kind.SEO_MARKETING
    assert "asn-associated" in profile.classification.tags
    assert "verified" not in profile.classification.tags


def test_declared_crawler_from_wrong_as_is_impersonator(tmp_path: Path) -> None:
    result = _analyze_one_line(tmp_path, _ahrefs_line("99999"))
    (profile,) = result.profiles
    assert profile.classification.primary is Kind.IMPERSONATOR
    assert "asn-associated" not in profile.classification.tags


def test_declared_crawler_without_logged_as_is_not_impersonated(tmp_path: Path) -> None:
    # No AS number to check against -> stays a declared crawler, neither flagged.
    line = (
        '66.249.66.1 - - [10/Oct/2023:12:00:00 +0000] "GET /p HTTP/1.1" 200 9 "-" '
        f'"{_AHREFS}"'
    )
    result = _analyze_one_line(tmp_path, line, fmt=PRESETS["combined"])
    (profile,) = result.profiles
    assert profile.classification.primary is Kind.SEO_MARKETING
    assert "asn-associated" not in profile.classification.tags
    assert profile.classification.primary is not Kind.IMPERSONATOR
