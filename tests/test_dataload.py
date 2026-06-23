"""Tests for data-file parsing (inline comments, CIDR hints)."""

from __future__ import annotations

from agent_census.dataload import load_tokens


def test_inline_comment_stripped_and_cidr_kept() -> None:
    hints = dict(load_tokens("ai_crawlers.txt"))["ClaudeBot"]
    assert "anthropic.com" in hints
    assert "160.79.104.0/21" in hints  # CIDR range kept
    # the trailing "# https://..." comment is not parsed as a hint
    assert not any("http" in hint or hint.startswith("#") for hint in hints)
