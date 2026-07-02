---
name: agent-census
description: A self-contained, dependency-free HTML report that classifies access-log clients by behaviour — a flat forensic ledger, not a dashboard.
colors:
  # --- Substrate: system colors, in prose only ---
  # Background and text are CSS system colors (Canvas / CanvasText) so the
  # report inherits the OS light/dark theme. They have no fixed hex and are
  # documented in the Colors section, not here.

  # --- Primary: the one UI accent ---
  interaction-blue: "#2563eb"        # disclosure triangles; doubles as the Browser kind hue

  # --- Secondary: the verdict / signal palette (the opinionated layer) ---
  # All carry white text, so each is held at >=4.5:1 against white (deepened
  # along OKLCH lightness from its original hue; the hue -- the signal -- is kept).
  verified-green: "#00862e"          # confirmed identity, search-engine kind
  asn-associated-green: "#008459"    # origin AS corroborates the declared crawler
  caution-amber: "#b45309"           # unverified declared crawler; the page-level warn color (light)
  alert-amber: "#b85900"             # ignores-robots, ua-rotating, 404-storm
  threat-red: "#dc2626"              # probe-paths, traversal, impersonator, forged-referer, vuln-scanner
  deep-red: "#b91c1c"                # encoding-evasion, impersonator kind
  datacenter-violet: "#9333ea"       # origin is hosting, not an eyeball network
  relay-blue: "#0079bc"              # iCloud Private Relay — a positive browser signal
  tor-violet: "#6d28d9"              # Tor exit node
  proxy-violet: "#7c3aed"            # corporate / SASE proxy; also the AI-crawler kind
  egress-teal: "#008277"            # consumer VPN egress; also the Monitor kind

  # --- Tertiary: the categorical "kind" badge wheel (white text, all >=4.5:1) ---
  kind-app: "#6062ed"
  kind-crawler: "#007d9e"
  kind-archiver: "#047857"
  kind-social-preview: "#0079bb"
  kind-seo-marketing: "#a36600"
  kind-data-harvester: "#a16207"
  kind-scraper: "#b85900"
  kind-spoofed-browser: "#d14000"
  kind-spam-bot: "#d92476"
  kind-feed-reader: "#478200"
  kind-automation: "#78716c"

  # --- Neutral ---
  # Secondary text is a color-mix of the system ink/paper so it tracks the OS
  # theme and clears 4.5:1 in both modes; the warn ink is a light-dark() pair.
  muted-ink: "color-mix(in srgb, CanvasText 58%, Canvas)"  # meta, blurbs, AS names, secondary text
  warn-ink: "light-dark(#b45309, #d97706)"  # calibration / robots notices, legible in both modes
  hairline: "#88888844"              # td bottom borders, card border (mode-adaptive gray + alpha)
  hairline-strong: "#88888866"       # th bottom border, input border
  wash: "#88888811"                  # row-hover / column-off background tint
  chip-neutral: "#88888833"          # unsignalled tags, share-bar track
  on-chip: "#ffffff"                 # text on colored kind badges and signal tags
  heat-blue: "96 165 250 (light) / 37 99 235 (dark)"  # cross-tab cell heat; deeper in dark for light text

typography:
  display:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
    fontSize: "1.7rem"
    fontWeight: 700
    lineHeight: 1.3
  headline:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
    fontSize: "1.25rem"
    fontWeight: 700
    lineHeight: 1.4
  body:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.5
  data:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
    fontSize: "0.92rem"
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: "tabular-nums"
  label:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
    fontSize: "0.8rem"
    fontWeight: 600
    letterSpacing: "normal"
  mono:
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace"
    fontSize: "0.85rem"
    fontWeight: 400
rounded:
  focus: "2px"
  bar: "4px"
  control: "6px"
  card: "10px"
  pill: "999px"
spacing:
  cell-y: "0.45rem"
  cell-x: "0.6rem"
  section: "2.25rem"
  page-x: "1.25rem"
  page-top: "2rem"
  page-bottom: "4rem"
components:
  kind-badge:
    backgroundColor: "{colors.interaction-blue}"
    textColor: "#ffffff"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "0.08rem 0.5rem"
  tag-neutral:
    backgroundColor: "{colors.chip-neutral}"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    padding: "0.05rem 0.45rem"
  tag-signal:
    backgroundColor: "{colors.threat-red}"
    textColor: "#ffffff"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    padding: "0.05rem 0.45rem"
  share-bar:
    backgroundColor: "{colors.chip-neutral}"
    rounded: "{rounded.bar}"
    height: "0.7rem"
  filter-input:
    typography: "{typography.body}"
    rounded: "{rounded.control}"
    padding: "0.4rem 0.55rem"
    width: "30rem"
  card:
    rounded: "{rounded.card}"
    padding: "1rem 1.1rem"
---

# Design System: agent-census

## 1. Overview

**Creative North Star: "The Field Ledger"**

agent-census renders one thing: a plain-paper investigator's record where every
observation is logged and every verdict is defensible from the entry sitting next
to it. The page has no chrome to speak of — no app shell, no nav, no hero, no
cards-as-decoration. It is a stack of dense, scannable tables on the bare
substrate of the operating system's own light or dark surface, read top-to-bottom
the way you read a ledger: summary first, then the cross-tab, then page after page
of clients with their evidence in the margin. The aesthetic is *unstyled on
purpose*. What little visual force the page spends, it spends on meaning — a hue
that says "verified", a hairline that separates hosting from off-network, a red
wash that marks where the volume actually is.

The system is built on three deliberate constraints, each a feature. **It is one
file with zero dependencies** — no web fonts, no external CSS or JS, no images;
it opens from `file://` and will render identically in ten years. **It defers to
the operating system** — background and text are CSS system colors (`Canvas` /
`CanvasText`) and borders are a single mode-adaptive gray, so the same markup is
legible in light and dark without a theme toggle or a second palette. **It keeps
claims and findings visibly distinct** — anything a client *asserted* (its IP,
User-Agent, the paths it requested) is set in monospace; the report's own *prose*
and *verdicts* are set in the system sans. You can tell at a glance what the log
said from what agent-census concluded.

What this explicitly rejects: marketing-dashboard slop (no hero-metric tiles, no
gradients, no glassmorphism, no identical icon-and-heading card grids); SOC /
security-vendor theatrics (no alarm-red everywhere, no fake "threat level"
gauges, no dark-cyber cosplay — color marks signal, not drama); and over-chromed
enterprise BI (no 3-D bars, no skeuomorphic gauges, no decorative chartjunk). The
report earns trust by under-reacting, not over-reacting.

**Key Characteristics:**
- Flat. No shadows anywhere; depth is hairlines and tonal washes only.
- System-native: OS light/dark substrate, system font stack, zero assets.
- Dense by intent — tables run wide and long; the operator wants the data.
- Color is a legend, never decoration. Every hue is a documented fact.
- Mono = claim, sans = finding. The two are never visually merged.
- Single, self-contained HTML file; portability is non-negotiable.

## 2. Colors

A near-monochrome ground of system colors and adaptive grays, lit only by a
disciplined categorical-plus-semantic palette where each hue carries a specific,
documented meaning.

### Primary
- **Interaction Blue** (`#2563eb`): the report's single UI accent. Used for the
  disclosure triangle (`▶`) that expands a folded actor's member IPs. It does
  double duty as the **Browser** kind hue, which is intentional — the everyday,
  benign baseline reads in the same calm blue as the one control you click.

### Secondary — The Verdict Palette
The opinionated layer. These hues appear on tags and encode agent-census's
*stance* on a client, not just its category. Every one carries white text, so
each is held at **≥4.5:1 against white**: where a hue was too light it was
deepened along its OKLCH lightness axis, keeping the hue (the actual signal)
intact.
- **Verified Green** (`#00862e`): identity confirmed, one tag per independent
  channel — `dns-verified` (rDNS), `ip-verified` (published IP range), and
  `wba-verified` (a valid Web Bot Auth signature); also the Search-Engine kind.
- **ASN-Associated Green** (`#008459`): origin AS matches the declared crawler —
  confirming it even when the network channel (IP range or rDNS) said otherwise
  (the network/AS channels combine as an OR); coarser than an IP/DNS hit
  (`asn-associated`).
- **Caution Amber** (`#b45309`): a declared crawler that *could* be checked but
  wasn't confirmed — `dns-unverified` / `ip-unverified`, each channel's mirror of
  Verified Green. A *definitive* disagreement (`dns-violation` / `ip-violation`)
  is a stronger red, not this amber — see Threat Red below. The page-level
  `.warn` color (robots.txt mismatches, calibration warnings) is a `light-dark()`
  pair built on it — `#b45309` on light paper, `#d97706` on dark so the notice
  stays legible either way.
- **Alert Amber** (`#b85900`): conduct worth a second look — `ignores-robots`,
  `ua-rotating`, `404-storm`. Also the Scraper kind.
- **Threat Red** (`#dc2626`): hostile intent — `probe-paths`, `traversal`,
  `forged-referer`, `impersonator`, `dns-violation`, `ip-violation`,
  spoofed/impossible browser UAs. Also the Vuln-Scanner kind.
- **Deep Red** (`#b91c1c`): the most deliberate evasion — `encoding-evasion`;
  also the Impersonator kind.
- **Datacenter Violet** (`#9333ea`): origin is hosting, not an eyeball network
  (`datacenter`).
- **Egress hues** — Relay Blue (`#0079bc`, iCloud Private Relay, a *positive*
  browser signal), Tor Violet (`#6d28d9`, Tor exit), Proxy Violet (`#7c3aed`,
  corporate/SASE proxy), Egress Teal (`#008277`, consumer VPN). These mark *how*
  a client reached you, not whether it's bad.

### Tertiary — The Kind Wheel
Eighteen categorical hues for the kind badges, white text, all **≥4.5:1**.
These are **identity-neutral classification, not judgement** — Crawler teal
(`#007d9e`), App indigo (`#6062ed`), AI-Crawler violet (`#7c3aed`), Archiver
green (`#047857`), Social-Preview sky (`#0079bb`), SEO-Marketing gold
(`#a36600`), Data-Harvester ochre (`#a16207`), Spoofed-Browser orange
(`#d14000`), Spam-Bot pink (`#d92476`), Feed-Reader lime (`#478200`), Monitor
teal (`#008277`), Automation warm-gray (`#78716c`), Unknown gray (`#6b7280`).
Several deliberately share a hue with a Secondary verdict (Vuln-Scanner = Threat
Red, Impersonator = Deep Red, Search-Engine = Verified Green, Monitor = Egress
Teal) so the badge and its dangerous tags read as one voice.

### Neutral
- **Canvas / CanvasText** (system): the substrate. Background and all default
  text. Never hardcoded — this is what makes one file work in both OS themes.
- **Muted Ink** (`color-mix(in srgb, CanvasText 58%, Canvas)`): secondary text —
  meta lines, blurbs, AS-org names, the secondary UA line, captions. Mixed from
  the system ink and paper rather than a fixed gray, so it tracks the OS theme
  and clears 4.5:1 in **both** modes (the old fixed `#6b7280` dropped to ~3.4:1
  on a dark canvas). Falls back to plain `CanvasText` if `color-mix` is absent.
- **Hairlines** (`#888` + alpha: `#88888844` cell rules, `#88888866` header
  rules & input border): a single mode-adaptive gray. Because it's gray-with-
  alpha, it darkens on a light page and lightens on a dark one automatically.
- **Washes** (`#88888811` row-hover/column-off, `#88888833` tag track &
  share-bar): the same gray at lower alpha, for tonal separation without ink.
- **Heat Blue** (`--heat`: `96 165 250` light / `37 99 235` dark) and **Heat
  Red** (`#dc2626`), applied at variable alpha to cross-tab cells to shade by
  share. The blue deepens in dark mode so the cell's `CanvasText` (now light)
  stays readable over the strongest fills; red sits where both light- and
  dark-mode text read over it unchanged.

### Named Rules
**The System-Color Substrate Rule.** Background and body text are `Canvas` and
`CanvasText`. Never replace them with a fixed hex — doing so breaks dark mode and
the zero-config promise. Structural grays are `#888` + alpha for the same reason.

**The Meaning-Only Color Rule.** Every non-neutral hue in this system is in the
legend above and stands for a fact. If a color isn't encoding a kind, a verdict,
or an egress type, it does not belong on the page. There is no decorative color.

**The White-On-Hue Rule.** Any chip filled with a palette hue (kind badges,
signal tags) carries `#ffffff` text — always. Unsignalled tags stay on the
neutral `#88888833` track with inherited `CanvasText`.

## 3. Typography

**Display / Body Font:** system UI sans (`-apple-system, BlinkMacSystemFont,
"Segoe UI", Roboto, sans-serif`)
**Mono Font:** platform monospace (`ui-monospace, SFMono-Regular, Menlo,
monospace`)

**Character:** One sans family does all the structural work — headings, prose,
labels, and tabular data — at a tight scale, because a forensic table has many
type roles and exaggerated contrast would only add noise. The monospace face is
not a second "design" font; it is a semantic tool, reserved for verbatim machine
strings the client emitted.

### Hierarchy
- **Display** (700, `1.7rem`): the page `h1` ("Agent Census — site"). One per page.
- **Headline** (700, `1.25rem`, `2.25rem` top margin): the `h2` section headers —
  Summary by kind, the cross-tab, each kind section, inspect cards.
- **Title** (700, ~`1.17rem`): `h3` inside inspect cards ("Why this
  classification", "Features", "Request trace").
- **Body** (400, `15px`/1.5): the base. Default prose, list items, link text.
- **Data** (400, `0.92rem`, `tabular-nums` on numeric columns): every table.
  Tables may run well past prose line-length limits — density is the point.
- **Label** (600, `0.8rem` badges / `0.78rem` tags): kind badges and tags. Slightly
  heavier to hold their colored fill.
- **Mono** (400, `0.85rem`): IPs, AS strings, User-Agents, request paths, copyable
  client ids. The UA line in client cells is clamped to ~3 lines and ellipsised.

### Named Rules
**The Claim-in-Mono Rule.** Anything the *client* asserted — its IP, its
User-Agent, the paths it requested — is set in monospace. The report's own
narration and verdicts are set in the system sans. The typeface boundary *is*
the boundary between "what the log said" and "what agent-census concluded." Never
set a finding in mono or a raw claim in sans.

**The One-Family Rule.** The system sans carries every structural role. Do not
introduce a display face, a second sans, or a "brand" font. Mono is the only
permitted second family, and only for verbatim strings.

## 4. Elevation

This system has **no shadows at all**. It is flat by conviction: a ledger is ink
on paper, and depth that isn't carrying information is just theater. Separation
and grouping are done entirely with **hairline borders** (`#888` + alpha) and
**tonal washes** (the same gray at lower alpha). A table's rows are divided by 1px
rules; its header sits under a 2px rule; the hosting/off-network split in the
cross-tab is a 2px vertical rule (`.netdiv`); a hovered row gets a faint
`#88888811` wash; the inspect "card" is a 1px-bordered, 10px-radius box — a frame,
not a floating surface. Quantitative emphasis (which cell holds the volume) is
carried by **variable-alpha color heat**, not by lift.

### Named Rules
**The Flat-Ledger Rule.** No `box-shadow`, ever — not on cards, not on hover, not
on the sticky filter. If something needs to feel separated, use a hairline or a
tonal wash. If it needs emphasis, use weight or color-heat. Depth is reserved for
nothing, because there is none.

## 5. Components

Every component is monochrome-by-default and earns color only when it has a fact
to report. Nothing here uses a shadow, a gradient, or a custom control where a
native one exists.

### Badges (Kind)
- **Character:** a confident, filled identity stamp.
- **Shape:** full pill (`999px`).
- **Fill:** the client's kind hue (Tertiary wheel) with `#ffffff` text, `0.8rem`,
  weight 600, padding `0.08rem 0.5rem`, `white-space: nowrap`.
- **Behavior:** badges link to their kind section (`#<kind>`); the summary and
  cross-tab tables use them as row anchors.

### Tags (Signal Chips)
- **Character:** terse evidence labels; the page's primary information texture.
- **Shape:** soft rectangle (`6px`), `0.78rem`, padding `0.05rem 0.45rem`,
  `cursor: help`.
- **Two states by meaning:** *signalled* tags take a Secondary verdict hue + white
  text; *unsignalled* tags sit on the neutral `#88888833` track with inherited
  text. A native `title=` tooltip carries the tag's full description.
- **Baseline suppression:** tags that are typical for a kind are hoisted into a
  "Typically:" line under the section header and suppressed on individual rows, so
  each row shows only what makes it *unusual*.

### Share Bar
- **Character:** an inline magnitude cue, not a chart.
- **Style:** a `#88888833` track, `4px` radius, `0.7rem` tall, width set to the
  percentage; a Muted-Ink `%` label beside it. No axis, no gridlines, no fill
  color — magnitude only.

### Cross-Tab Matrix (Signature Component)
- The kind×network table is the report's centerpiece. Numeric cells carry a
  `data-v` raw count and are repainted client-side by a toggle (counts / % of
  kind / % of network). **Cell heat** is Heat Blue at alpha proportional to the
  cell's share of its row or column max; the group's leader is bolded (weight
  500). The **Total column and All-kinds row** use Heat *Red* on a separate axis
  (per-kind and per-network totals), so the eye separates "biggest cell" from
  "biggest total." A 2px `.netdiv` rule splits hosting (left) from off-network
  (right); off-network headers carry a faint `.netoff` wash.

### Filter Input
- **Character:** the one persistent control; stays in reach as you scroll.
- **Style:** full-width (max `30rem`), 1px `#88888866` border, `6px` radius, on
  `Canvas` with `CanvasText`, `position: sticky; top: 0.5rem`.
- **Behavior:** a single search box filters *every* client row across *every* kind
  section at once (matching IP, UA, AS name, and visible tags), force-opens all
  "Show more" disclosures so hidden matches surface, and collapses any section or
  disclosure left with no surviving rows.

### Collapsible Actor Row
- A folded actor (an ASN operator, a verified bot, an egress cluster) is a
  `<tbody>` whose summary row carries an Interaction-Blue `▶` **disclosure
  button** — a real `<button>` with `aria-expanded`, so it is keyboard-operable
  (Enter/Space), while the whole row stays a click target for mouse. Activating
  it rotates the triangle 90° (`transform .12s`, with a `prefers-reduced-motion`
  fallback) and reveals member-IP rows that share the table's Requests/Bandwidth
  columns. The "Show more" set per kind uses a native exclusive accordion
  (`<details name=...>`); opening one closes the others, and the script pins the
  clicked summary so the page doesn't jump.

### Copyable Client Cell
- The client id cell is `cursor: pointer`; clicking copies the IP (for
  `inspect --client`) and flashes a `#16a34a55` green confirmation for ~900ms.
  Uses the async clipboard API with an `execCommand` fallback so it works on
  `file://` pages. Pointer-only by design: the id is already selectable text, so
  keyboard users copy it directly rather than gaining 500 extra tab stops.

### Inspect Card
- **Corner:** `10px`. **Border:** 1px `#88888844`. **Padding:** `1rem 1.1rem`.
  **No shadow.** A bordered frame grouping one client's header, rationale,
  robots.txt finding, features table, and request trace.

### Small Screens
- Wide tables each sit in a horizontal-scroll track (`.tscroll`) so none forces
  the *page* to scroll sideways; a track becomes keyboard-focusable (a labelled
  `role="region"`) only while it actually overflows, so non-scrolling tables add
  no dead tab stops. Below 640px the kind×network cross-tab folds to **Kind | one
  chosen network | Total**, with a Column picker that swaps the visible network —
  the same fold-then-reveal pattern as the desktop break-out control. The
  identity column keeps a `min-width` so it never collapses to a sliver.

## 6. Do's and Don'ts

### Do:
- **Do** keep background and body text on `Canvas` / `CanvasText` and structural
  lines on `#888` + alpha, so the single file stays legible in both OS themes.
- **Do** treat color as a legend: every non-neutral hue must map to a kind, a
  verdict, or an egress type that's documented in the Colors section.
- **Do** set every client-asserted string (IP, UA, path, client id) in monospace
  and every report finding in the system sans — preserve the Claim-in-Mono Rule.
- **Do** give colored chips `#ffffff` text and leave unsignalled tags on the
  neutral `#88888833` track.
- **Do** convey depth and grouping with hairlines and tonal washes; convey
  magnitude with the share bar or variable-alpha heat.
- **Do** keep tables dense — they may exceed prose line-length; that is correct
  here. Use `tabular-nums` on numeric columns.
- **Do** give all motion a `prefers-reduced-motion: reduce` fallback; the only
  motion today is the 120ms triangle rotation (already gated) and the copy flash.

### Don't:
- **Don't** ship **marketing-dashboard slop** — no hero-metric tiles, no
  gradients, no glassmorphism, no identical icon-and-heading card grids.
- **Don't** ship **SOC / security-vendor theatrics** — no alarm-red everywhere,
  no fake "threat level" gauges, no dark-cyber cosplay. Red is reserved for
  documented hostile-conduct signals.
- **Don't** ship **over-chromed enterprise BI** — no 3-D bars, no skeuomorphic
  gauges, no decorative chartjunk. The bars and heat must read honestly.
- **Don't** add a `box-shadow` anywhere — the Flat-Ledger Rule is absolute.
- **Don't** hardcode a background or text hex; never break the System-Color
  Substrate Rule.
- **Don't** introduce a web font, a display face, or a second sans. One system
  sans plus mono, nothing more.
- **Don't** use color as decoration, render a finding in mono, or set a raw claim
  in sans.
- **Don't** add external assets (fonts, images, CSS/JS files). The report is one
  self-contained file and must stay that way.
