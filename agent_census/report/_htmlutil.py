"""Tiny HTML-rendering helpers shared by :mod:`html` and :mod:`_networktab`.

Split out so neither has to import the other: the network cross-tab renderer
needs the kind badge, and :mod:`html` needs both it and the cross-tab -- a
straight import in either direction would cycle.
"""

from __future__ import annotations

import html as _html

from ..model import Kind
from .format import kind_label

# Kind badge fills. White-text badges, so each fill is held at >=4.5:1 against
# white (deepened along OKLCH lightness from its original hue where needed);
# the hue family -- the actual signal -- is preserved.
_KIND_COLORS: dict[Kind, str] = {
    Kind.BROWSER: "#2563eb",
    Kind.APP: "#6062ed",
    Kind.CRAWLER: "#007d9e",
    Kind.SEARCH_ENGINE: "#00862e",
    Kind.ARCHIVER: "#047857",
    Kind.SOCIAL_PREVIEW: "#0079bb",
    Kind.AI_CRAWLER: "#7c3aed",
    Kind.SEO_MARKETING: "#a36600",
    Kind.DATA_HARVESTER: "#a16207",
    Kind.IMPERSONATOR: "#b91c1c",
    Kind.SCRAPER: "#b85900",
    Kind.VULN_SCANNER: "#dc2626",
    Kind.SPOOFED_BROWSER: "#d14000",
    Kind.SPAM_BOT: "#d92476",
    Kind.FEED_READER: "#478200",
    Kind.MONITOR: "#008277",
    Kind.AUTOMATION: "#78716c",
    Kind.UNKNOWN: "#6b7280",
}


def esc(text: str) -> str:
    return _html.escape(text, quote=True)


def kind_badge(kind: Kind) -> str:
    color = _KIND_COLORS.get(kind, "#6b7280")
    return f'<span class="badge" style="background:{color}">{esc(kind_label(kind))}</span>'
