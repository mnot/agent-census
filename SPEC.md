# agent-census: Classification & Tagging Specification

This document specifies the two verdicts agent-census produces for every client
it sees in an access log:

1. **Tags** — a set of orthogonal descriptors ("what is true of this client")
2. **Classification** — a single primary *kind* ("what this client fundamentally is")

It describes *how each is derived* and, throughout, *how the two relate* — because
the same underlying measurement often both raises a tag and moves a classifier's
verdict, and several tags exist precisely because a classifier needed the signal.

No numeric thresholds appear here. Every threshold, weight, and confidence level
named below is a tunable value living in a `data/tuning/*.toml` file; the logic
that reads them is fixed, the numbers are calibrated separately. Where a decision
"clears a threshold," "scores enough," or compares against "a floor," the bar is
one of those tunables. (A small number of structural constants are hardcoded in
the feature record itself; these are called out as such.)

Throughout, tuning knobs are cited as a link to the file plus the `[section]`
that holds them — e.g. [`shared.toml`](agent_census/data/tuning/shared.toml)
`[browser_shape]`. Section and key names are the stable anchor; line numbers
drift as the files are recalibrated, so they are not used. The full mapping from
each tag and classifier to its tuning locations is collected in the
[Tuning map](#3-tuning-map) at the end.

## Contents

- **[0. Foundations](#0-foundations)** — [measure/decide wall](#01-the-measuredecide-wall) · [context](#02-context-beyond-the-feature-vector) · [where the numbers live](#03-where-the-numbers-live) · [shared predicates](#04-predicates-shared-between-tags-and-classifiers)
- **[1. Tags](#1-tags)**
  - [1.1 Behavioural fingerprint](#11-behavioural-fingerprint-tags): [Cadence](#cadence) · [Sub-resource co-loading](#sub-resource-co-loading) · [Navigation](#navigation) · [Caching](#caching) · [Headless engine](#headless-engine) · [User-Agent shape](#user-agent-shape)
  - [1.2 Conduct](#12-conduct-tags): [`probe-paths`](#probe-paths) · [`traversal`](#traversal) · [`encoding-evasion`](#encoding-evasion) · [`404-storm`](#404-storm) · [`often-forbidden`](#often-forbidden) · [`exotic-method`](#exotic-method) · [`uses-HEAD`](#uses-head) · [`post-heavy`](#post-heavy) · [`forged-referer`](#forged-referer) · [`impossible-referer`](#impossible-referer)
  - [1.3 Fact](#13-fact-tags): [`singleton`](#singleton) · [`datacenter`](#datacenter) · [`no-user-agent`](#no-user-agent) · [`checked-robots`](#checked-robots) · [`asn-attributed`](#asn-attributed) · [identity channels](#identity-channel-verdicts) · [`asn-associated`](#asn-associated) · [`declares-known-bot`](#declares-known-bot) · [`fetches-feeds`](#fetches-feeds) · [`polls-feeds`](#polls-feeds) · [`declares-app-client`](#declares-app-client) · [`user-triggered`](#user-triggered) · [`ignores-robots`](#ignores-robots) · [`ua-rotating` / `shared-ip`](#ua-rotating-and-shared-ip)
  - [1.4 Web Bot Auth](#14-web-bot-auth-tags) · [1.5 Site-relative magnitude](#15-site-relative-magnitude-tags) · [1.6 Suppression & aggregates](#16-suppression-and-aggregates)
- **[2. Classification](#2-classification)**
  - [2.1 Classifier contract](#21-the-classifier-contract)
  - [2.2 The classifiers](#22-the-classifiers): [Declared-identity](#declared-identity-kinds) · [`browser`](#browser) · [`spoofed_browser`](#spoofed_browser) · [`crawler`](#crawler) · [`scraper`](#scraper) · [`vuln_scanner`](#vuln_scanner) · [`monitor`](#monitor) · [`feed_reader`](#feed_reader) · [`spam_bot`](#spam_bot) · [`app`](#app)
  - [2.3 The combiner](#23-the-combiner) · [2.4 Non-classifier kinds](#24-kinds-that-are-not-their-own-classifier)
- **[3. Tuning map](#3-tuning-map)** — [tags](#31-tags) · [classifiers & combiner](#32-classifiers-and-combiner)

---

## 0. Foundations

### 0.1 The measure/decide wall

A client is first reduced to a `ClientFeatures` record: a wide, opinion-free bag
of measurements aggregated from all of that client's log lines — request count,
status-code mix, timing regularity, path coverage, sub-resource co-loading,
method mix, User-Agent shape, origin AS, and so on. `ClientFeatures` contains
**no judgements**, only counts and ratios.

Both verdicts are pure functions of that record (plus a few static data lists and
a small amount of combiner-level *context*). This wall is deliberate: it keeps
each classifier independently testable and keeps "what the log said" cleanly
separated from "what agent-census concluded."

### 0.2 Context beyond the feature vector

Three facts cannot be measured from a client's own requests, so the pipeline
computes them once and passes them alongside the features:

- **`datacenter`** — whether the origin network is hosting infrastructure rather
  than an eyeball (residential/mobile) network, from attributing the origin IP or
  AS to a known hosting provider.
- **`redirect_shadow`** — which host form, if any, the site redirects *away*:
  `"www"` when `www` 301s to the bare apex, `"apex"` when the apex 301s to `www`,
  or `None`. Inferred from the site's own observed 3xx split. This "arms" the
  *impossible-referer* tell for one direction.
- **Verification results** — the outcomes of optional identity checks against a
  client that declares a known-crawler identity: reverse DNS, published IP ranges,
  origin AS (`BotVerification`), and a Web Bot Auth signature (`WbaResult`).

### 0.3 Where the numbers live

Each classifier and the tag layer read a small schema of named knobs from a
dedicated file ([`browser.toml`](agent_census/data/tuning/browser.toml),
[`tags.toml`](agent_census/data/tuning/tags.toml), …), plus a
[`shared.toml`](agent_census/data/tuning/shared.toml) for thresholds that **must
agree across modules**. The shared file is itself a statement about relationships:
when the browser classifier and the tag layer both ask "does this client co-load
sub-resources like a browser?", they read the *same*
[`shared.toml`](agent_census/data/tuning/shared.toml) `[browser_shape]` number, so
a `loads-assets` tag and a browser co-load signal can never disagree about where
the line sits. The whole set of files is listed in
[`data/tuning/`](agent_census/data/tuning/), with conventions in its
[`README.md`](agent_census/data/tuning/README.md).

### 0.4 Predicates shared between tags and classifiers

A handful of named predicates are the actual connective tissue between the two
verdicts. They are defined once and referenced by both layers; each tag or
classifier description below names the ones it uses.

- **`identifies_as_known_agent`** — the client is a non-browser agent: its UA
  self-declares a bot, *or* it is a `recognised_specific_agent`. Such a client is
  never a browser however it behaves, so it short-circuits the `browser`, `app`,
  and `spoofed_browser` classifiers and gates the browser-spoof tags
  (`forged-referer`, `impossible-referer`).
- **`recognised_specific_agent`** — a *positively identified* agent: a known
  crawler (by UA token or origin AS) or a feed reader. The generic `crawler` and
  `scraper` classifiers defer to it, so a recognised crawler that also crawls
  broadly is never demoted to a generic one.
- **`holds_no_cache`** (a property of the feature record) — the client re-fetches
  URLs, or simply makes many requests, yet never receives a `304`. True when there
  is no 304, at least one path was re-requested, and either the re-fetch count
  clears a hardcoded floor *or* the total request count clears a hardcoded volume
  mark (both hardcoded in [`model.py`](agent_census/model.py), not tuning). Proves
  the client keeps no browser cache. Raises `lacks-cache`; soft-penalises
  `browser`.
- **`refetch_dominant`** — a *stronger* no-cache condition: re-fetching actually
  dominates the traffic (revisits clear a shared floor *and* make up a shared
  fraction of all requests), or the sheer volume alone makes zero revalidations
  damning ([`shared.toml`](agent_census/data/tuning/shared.toml)
  `[no_cache_dominance]`). This is the dispositive "not a browser on cache grounds"
  line, drawn once and read by both `browser` (hard-disqualify) and
  `spoofed_browser` (its no-cache tell), so the two halves of the browser/costume
  question agree.
- **`forbidden_tell`** — the server's 403 refusals are both frequent (a shared
  ratio of the client's traffic) and numerous (a shared count floor): the site's
  standing verdict that the client is unwelcome
  ([`shared.toml`](agent_census/data/tuning/shared.toml) `[forbidden]`). Read by
  the `often-forbidden` tag and, as corroboration, the `vuln_scanner` classifier —
  against the same threshold, so they agree.
- **`looks_like_impossible_referer`** — a browser-shaped client, naming no known
  agent, with no feed activity, carrying a same-site Referer for the site's
  redirect-only host form on a real share of requests
  ([`shared.toml`](agent_census/data/tuning/shared.toml) `[impossible_referer]`;
  the site's redirect regime is inferred via `[redirect_gate]`). Drives the
  `impossible-referer` tag *and* is a dispositive tell inside `spoofed_browser`.
- **`looks_like_fake_browser`** — a browser-UA client that never co-loads assets
  and never follows a referer (or that trips `looks_like_impossible_referer`).
  The intended long-term home of the `spoofed_browser` verdict; today it also
  decides whether many-UAs-on-one-IP reads as `ua-rotating` or `shared-ip`.

---

## 1. Tags

Tags are **orthogonal descriptors layered on top of the kind**. They do not
compete with the kind, and — with the exception of the site-relative tags (§1.5),
which read the final kind — do not depend on it. A client typically carries
several.

Every tag is produced together with the **concrete measurement that earned it** —
a short evidence string such as "co-loaded sub-resources after 0% of 1,204 HTML
pages." Tag and reason come from the same line of code, so they can never drift
apart; inspect mode shows the reason, bulk analysis discards it to save memory.

A tag fires **only when there is enough data to justify it**. An absent tag means
"could not tell," never a silent "no." Dimensions that have two poles
(`has-cache`/`lacks-cache`, `loads-assets`/`no-assets`, …) emit one *only* once
enough evidence exists to choose; below that floor, neither appears.

Tags come from four families assembled while the classification is computed
(§1.1–§1.4), plus the site-relative family applied afterward (§1.5). The
fingerprint dimensions (§1.1) each carry two or more mutually-exclusive poles, so
they are headed by dimension; every other tag is headed by its own name.

### 1.1 Behavioural fingerprint tags

One tag per behavioural dimension that can actually be measured — the evidence a
reader weighs to decide whether a client behaves like a browser.

#### Cadence
*Emits one of `metronomic` / `bursty` / `steady`.*
From the coefficient of variation (CV) of inter-arrival intervals, once the client
has made enough requests. A CV below a lower bound is `metronomic` (clockwork,
machine-like); above an upper bound is `bursty` (irregular, human-like); between
them is `steady`.
*Bearing on classification:* these bounds live in
[`shared.toml`](agent_census/data/tuning/shared.toml) `[cadence]` and are read
directly by `browser` — `bursty` timing **adds** browser confidence, while
`metronomic` timing subtracts it *and* disqualifies the browser hypothesis. A CV
below each classifier's own "regular" bar likewise feeds the `crawler`, `monitor`,
and `feed_reader` scores (steady/regular polling), and `vuln_scanner` weighs a
fast *median* interval. Suppressed on display aggregates (§1.6).

#### Sub-resource co-loading
*Emits `loads-assets` or `no-assets`.*
Once enough HTML pages have been fetched, from `asset_coload_ratio` (the share of
pages followed within seconds by their CSS/JS/image sub-resources, linked via the
referer). Above the shared browser bar → `loads-assets`; below a low bar →
`no-assets`.
*Bearing on classification:* this is the single strongest browser tell — the same
shared bar gates the `browser` co-load signal, admits a client to the
reference-browser pool for site-relative tags (§1.5), and (as its inverse) is
required by `crawler` and `scraper` ("no browser sub-resource loading"). Inside
`spoofed_browser`, fetching pages while co-loading *none* of their sub-resources
is a cold costume tell — but only for a client that co-loads nothing, because a
genuine renderer must never be swept into the costume net.

#### Navigation
*Emits `follows-links` or `cold`.*
Only when some request carried a Referer at all, and over a minimum request count,
from `referer_following_ratio` (the referer names a path the client fetched
earlier). Above the shared browser bar → `follows-links`; below a low bar →
`cold`.
*Bearing on classification:* the shared bar feeds the `browser` and `crawler`
link-following signals; the low bar is the `scraper` "accesses URLs cold" signal
and, at a ratio of exactly zero, a `spoofed_browser` cold tell. Link-following is
also one of the two ways a client qualifies for the reference-browser pool.

#### Caching
*Emits `has-cache` or `lacks-cache`.*
`has-cache` when the client received at least one `304 Not Modified` (a real
cache, proven). Otherwise `lacks-cache` when `holds_no_cache` (§0.4) is true.
*Bearing on classification:* a 304 **adds** confidence in `browser` (revalidates
from cache) and `feed_reader` (polite conditional polling), and is one qualifier
for the reference-browser pool. The no-cache side is graded: `holds_no_cache`
alone only *soft*-penalises `browser`, but when it strengthens to
`refetch_dominant` it **caps** the browser verdict below the confident bar and
becomes the `spoofed_browser` no-cache tell (which counts even for a co-loading
client). `lacks-cache` is one of the automation tells that rescue a below-
threshold client into `automation` (§2.3).

#### Headless engine
*Emits `headless-browser`.*
The UA names an automation/headless browser harness. A machine tell regardless of
behaviour.
*Bearing on classification:* an automation tell — present on a below-threshold
client, it yields `automation` rather than `unknown`.

#### User-Agent shape
*Emits exactly one of: a browser-version age band (`current` / `stale` /
`ancient` / `impossible`-`browser-ua`), a plain `browser-ua`, `generic-ua`, or
`bot-ua` — when a UA is present.*
The age band comes from the claimed version measured against when the client was
active. `browser-ua` is a browser shell with no readable version; `generic-ua` is
a generic HTTP library or tool; `bot-ua` is a self-declared bot naming no identity
we recognise (a feed reader or known crawler names *itself* and so is excluded
here).
*Bearing on classification:* the age band drives `browser` directly — `current`
adds a small bonus, `stale` a penalty, and `ancient`/`impossible` **cap** the
browser hypothesis (an auto-updating browser is rarely years behind, and can never
be from the future); `ancient`/`impossible` are also a `spoofed_browser` tell.
`generic-ua` corresponds to the `scraper` library signal and helps trip the
datacenter-scraper fallback; `generic-ua` and `bot-ua` are both automation tells;
`bot-ua`'s underlying "self-declares a bot" fact is the `crawler` declared-bot
signal.

### 1.2 Conduct tags

Noteworthy — usually hostile — behaviour. These have **no negative pole**: they
are flagged only when present, because the absence of misconduct is unremarkable.

#### `probe-paths`
Requests to known probe paths (e.g. `/.env`). Gated so a broad crawler grazing a
few such URLs among tens of thousands of requests is not mistaken for a scan: it
fires on a raw burst of hits *or* a meaningful share of traffic.
*Bearing:* the same hits feed `vuln_scanner`, which grades them into a strong tier
(a burst, or probes as a large fraction of traffic — so a lone pure probe still
counts) versus an incidental tier (one probe amid normal traffic). In `browser`,
probe hits past a cap are a **disqualifier** — a person at a browser never fetches
attack paths, so this is automation wearing a browser engine.

#### `traversal`
Path-traversal/injection markers in request paths. No legitimate use, so one
suffices.
*Bearing:* a weighted `vuln_scanner` tell; a `browser` disqualifier; its absence
is required by the datacenter-scraper fallback.

#### `encoding-evasion`
Double- or overlong-percent-encoded requests (deliberate WAF evasion). One
suffices.
*Bearing:* weighted *above* traversal in `vuln_scanner`; a `browser` disqualifier;
absence required by the datacenter-scraper fallback.

#### `404-storm`
A high share of 404s across many distinct missing URLs (enumeration, not a broken
link).
*Bearing:* fires the identically-thresholded
([`shared.toml`](agent_census/data/tuning/shared.toml) `[storm_404]`)
`vuln_scanner` tell.

#### `often-forbidden`
`forbidden_tell` (§0.4) is heavy: the server returned 403 to a high, numerous
share of the client's requests.
*Bearing:* the same predicate is a `vuln_scanner` corroboration tell (the site's
own hostility verdict), weighted below the direct probe tells so it can't fire the
scanner alone.

#### `exotic-method`
Requests using uncommon methods (PUT/DELETE/PROPFIND/…).
*Bearing:* a weighted `vuln_scanner` tell.

#### `uses-HEAD`
A notable share of HEAD requests (browsers issue GET); threshold in
[`shared.toml`](agent_census/data/tuning/shared.toml) `[head_traffic]`.
*Bearing:* in `browser`, meaningful HEAD from an otherwise browser-shaped client
**caps** the verdict; it is a `spoofed_browser` HEAD-heavy tell. `monitor` and
`feed_reader` instead treat HEAD polling as *positive* corroboration, against
their own (higher) thresholds — a monitor legitimately HEADs.

#### `post-heavy`
POST is a high share of requests over a minimum volume.
*Bearing:* the `spam_bot` classifier keys on the same shape (POST volume, and POST
without sub-resource loading) against its own thresholds.

#### `forged-referer`
The Referer equals the requested URL on a high share of requests (fabricated
navigation). Gated to a browser-shaped UA that names no known agent — it is only
meaningful for something *posing* as a browser.
*Bearing:* the same condition
([`shared.toml`](agent_census/data/tuning/shared.toml) `[fabricated_referer]`) is a
`browser` disqualifier and a `spoofed_browser` forged-referer tell.

#### `impossible-referer`
`looks_like_impossible_referer` (§0.4): a same-site Referer naming the site's
redirect-only host form, which a compliant browser can never emit (after the
redirect it is on the *other* form).
*Bearing:* the same predicate is a **dispositive** `spoofed_browser` tell (enough
on its own) and forces `looks_like_fake_browser` true.

### 1.3 Fact tags

Established facts about identity and origin — no behaviour.

#### `singleton`
Made exactly one request. A volume fact on any kind (a single request is never its
own kind).

#### `datacenter`
The `datacenter` context flag; annotated with the AS org when known.
*Bearing:* pervasive. It nudges a `browser` verdict down, is a weighted
`spoofed_browser` tell, tips the below-threshold fallback toward `scraper` or
`automation`, and decides the `ua-rotating`/`shared-ip` split.

#### `no-user-agent`
Sent no UA header.
*Bearing:* the `scraper` no-UA signal (empty UA while harvesting), and an
alternative to a library UA in the datacenter-scraper fallback.

#### `checked-robots`
Requested `/robots.txt` at some point.
*Bearing:* nudges `browser` down (a crawler's habit, not a browser's) and adds a
small bonus to the known-bot classifiers.

#### `asn-attributed`
The origin AS is itself a recognised crawler network (identity is the network, not
the UA).
*Bearing:* makes the client a `recognised_specific_agent`, so `crawler`/`scraper`
defer; it is also how the known-bot classifiers recognise an agent that crawls
behind a spoofed browser UA (matching on AS when the UA doesn't name it).

#### Identity-channel verdicts
*Emits `dns-verified` / `dns-unverified` / `dns-violation` and `ip-verified` /
`ip-unverified` / `ip-violation`.*
One tag per independent channel that was actually checked (a channel never checked
emits nothing), surfaced separately so a reader can see *which* channel confirmed
or disagreed.
*Bearing:* directly tied to the impersonation verdict — a definitive
`dns-violation`/`ip-violation` is exactly the evidence behind a network
`impersonator` decision (§2.3, step 4). `verified`/`unverified` are informational.

#### `asn-associated`
The UA names a known crawler and its origin AS is one that crawler is known to use
(corroboration, coarser than a DNS/IP hit).
*Bearing:* confirms a declared crawler; unlike a violation it never triggers
impersonation.

#### `declares-known-bot`
The UA names a known crawler.
*Bearing:* the six declared-identity classifiers fire on the same tokens; it also
makes the client a `recognised_specific_agent`/`identifies_as_known_agent`,
excluding it from `browser`, `spoofed_browser`, `crawler`, and `scraper`.

#### `fetches-feeds`
The UA names a feed reader or feed tool.
*Bearing:* the `feed_reader` UA signal; makes the client a
`recognised_specific_agent`; keeps it out of the `browser`/`spoofed-browser`
heuristics and out of `bot-ua`.

#### `polls-feeds`
The client actually requested RSS/Atom resources, whatever its UA claims (the
behavioural sibling of `fetches-feeds`).
*Bearing:* feeds the `feed_reader` weight; the *dominance* of feed traffic
(`feed_ratio`) is the shared line where `feed_reader` claims the client and
`spoofed_browser` excludes it, so the two never fire for one client.

#### `declares-app-client`
The UA names a native-app networking stack (CFNetwork, dart:io, …).
*Bearing:* the `app` classifier fires on the same token.

#### `user-triggered`
The UA names a fetcher the operator designates as acting on behalf of a present
user, not an autonomous crawler. Informational; no classifier bearing.

#### `ignores-robots`
The client requested paths disallowed by the applicable robots.txt group (the only
robots outcome tagged; respecting robots is the quiet norm).
*Bearing:* deliberately **none** on the kind. Misbehaviour is never treated as
identity theft, and ignoring robots is explicitly *not* a browser disqualifier —
it does not bind a human browsing by hand.

#### `ua-rotating` and `shared-ip`
Many distinct User-Agents on one IP (past a threshold). The same raw fact splits by
context: from a hosting origin, or when `looks_like_fake_browser` (§0.4) holds, it
reads as evasive rotation (`ua-rotating`); otherwise it is a benign shared egress —
NAT/VPN/proxy/carrier — (`shared-ip`).
*Bearing:* the split *consumes* the `spoofed_browser` fake-browser predicate,
making this the one fact tag whose value depends on browser-costume logic.

### 1.4 Web Bot Auth tags

Web Bot Auth is a cryptographic identity channel (a signed request). It
contributes **one mutually-exclusive status tag** — `wba` (present, not yet
verified), `wba-verified`, `wba-expired`, `wba-unverified`, or `wba-violation`
(the signature failed against the operator's authentic key) — plus independent
flags layered on when present: `wba-mixed` (some of the client's signatures
verified and some did not), `wba-replay` (a nonce also seen from a different
origin — a captured signature replayed), and `wba-nonce-reuse` (a nonce reused
across the client's own requests). A request with no signature emits nothing.
*Bearing:* this channel **outranks** the network one in the impersonation verdict
(§2.3, step 4): `wba-violation` forces `impersonator`, while `wba-verified`/
`wba-expired` clear a network impersonator verdict (unless the UA names a
*different* registered operator than the one that validly signed — itself a
forgery).

### 1.5 Site-relative magnitude tags

Some signals are meaningless as global constants: 500 requests/minute is nothing
for a busy site and a flood for a blog. Four tags therefore fire relative to *the
site's own traffic*:

- **`high-rate`** — peak requests/minute well above a typical browser's.
- **`high-bytes`** — high *mean* response size (few large objects — distinct from
  raw volume, which `high-rate` already covers).
- **`wide-breadth`** — a large fraction of consecutive hops that change subtree.
- **`long-session`** — an unusually long session span.

**The reference is the site's own high-confidence real browsers**
(`is_reference_browser`). Bots imitate a browser's UA but not its behaviour, so a
browser baseline stays robust even on a bot-dominated site and auto-calibrates to
it (a JS-heavy site's browsers fire more sub-resource requests, lifting the
envelope on their own). Membership is built **strictly from the absolute browser
signals the fingerprint tags already use** — UA shape, asset co-loading, and
caching/link-following — and **never** from the four magnitudes being calibrated,
which is what breaks the circularity: the pool must not depend on the thing it
measures. (A costume browser, with zero co-loading and zero following, can never
qualify — exactly right.)

Calibration, once per run at end of stream:

```
for each metric the kind is configured to emit:
    if the browser pool is large enough:
        threshold = max(absolute_floor,
                        p95(log(browser samples)) * margin)   # heavy-tailed magnitudes
                    or  high_linear_percentile(browser samples)  # bounded ratio: breadth
    else:
        threshold = absolute_floor          # pool too thin; report notes the fallback
    tag fires when this client's metric exceeds the threshold
```

The unbounded magnitudes use a 95th-percentile-on-a-log-scale bar times a margin;
the one bounded ratio (breadth) can't use a multiplicative margin (it would push
the bar above 1.0, unreachable), so it uses a high linear percentile of the pool
directly. The margin, the thin-pool cutoff, the per-metric floors, and the
per-kind metric sets all live in
[`relative_tags.toml`](agent_census/data/tuning/relative_tags.toml) (`[params]`,
`[default]`, and the `[[kind]]` overrides) — the last being the single lever for
muting a metric that proves noisy for a kind.
*Bearing on classification:* these tags **read** the final primary kind (to select
the per-kind metric set) but never change it. They are applied after the combiner
and are **suppressed on display aggregates** (§1.6).

### 1.6 Suppression and aggregates

A **display aggregate** is a single report row folding many independent clients (a
privacy-relay or VPN egress cluster, keyed by network + UA past throwaway IPs). On
such a row the per-client cadence tags (§1.1) and all site-relative tags (§1.5)
are suppressed — interleaved arrivals and a union span are artifacts of folding,
not properties of one client. An aggregate is also never sampled into the
reference-browser pool.

Separately, the report's actor-grouping excludes purely *observational* tags
(which robots/assets/links a particular slice of traffic happened to hit) from the
key it folds identical actors by, so an already-identical crawler is not split
into separate rows by incidental differences.

---

## 2. Classification

The classification answers *what kind of client is this?* with one primary `Kind`
and a confidence. The kinds:

| Family | Kinds |
| --- | --- |
| Declared crawler identities | `search_engine`, `social_preview`, `archiver`, `ai_crawler`, `seo_marketing`, `data_harvester` |
| Behavioural | `browser`, `app`, `crawler`, `scraper`, `vuln_scanner`, `monitor`, `feed_reader`, `spam_bot` |
| Browser costume | `spoofed_browser` |
| Forged identity | `impersonator` |
| Fallbacks | `automation`, `unknown` |

Classification runs in two stages: **independent classifiers vote**, then a
**combiner** reconciles the votes.

### 2.1 The classifier contract

Each classifier argues, from features alone, that a client is *one* particular
kind. It reads only `ClientFeatures` and its own static data lists — never another
classifier and never the final decision — and emits zero or more **signals**, each
carrying the kind, a confidence in `[0, 1]`, and evidence strings. "This is *not*
a browser" is expressed simply by the browser classifier not firing.

Confidence is an **ordinal strength, not a probability**. An accumulating
classifier sums small per-tell weights (clamped to `[0, 1]`); the combiner takes
the strongest signal per kind rather than multiplying. Classifiers are pure by
default; the two that genuinely need context (`spoofed_browser`, and the
datacenter nudge on `browser`) opt in to receive it.

### 2.2 The classifiers

#### Declared-identity kinds
*Kinds: `search_engine`, `social_preview`, `archiver`, `ai_crawler`,
`seo_marketing`, `data_harvester`.*
All six share one mechanism (a common base class). A token in the User-Agent is
matched against that kind's curated data list; failing that, the origin AS number
is matched against the same operator's network (for operators that crawl behind
spoofed browser UAs, the constant is the network, not the UA). A UA match takes a
high base confidence, with small bonuses for fetching robots.txt and for not
probing; an AS-only match takes a slightly lower base. The declared identity is
taken **at face value** — verifying or refuting it is the combiner's job (a
face-value claim that DNS/IP/AS or Web Bot Auth contradicts becomes
`impersonator`; see §2.3).
*Tag relationships:* fires alongside `declares-known-bot` (or `asn-attributed`);
the `checked-robots` fact is the robots bonus here; the resulting client is a
`recognised_specific_agent`, which is why `crawler`/`scraper` stand down.
*Tuning:* [`known_bot.toml`](agent_census/data/tuning/known_bot.toml) (`[ua_match]`
base and bonuses, `[asn_match]` base). The UA tokens and AS lists themselves are
data, not tuning — under `data/agents/`.

#### `browser`
Interactive browsers. Accumulates positive evidence and applies disqualifiers:

```
if identifies_as_known_agent:            # a declared bot/feed/crawler is never a browser
    return  (no signal)

confidence  = 0
add for:  co-loads sub-resources (strongest) · browser-shaped UA · bursty timing
          · follows on-site links · low error rate & no probing · static-asset share
          · revalidates from cache (304) · current UA version
subtract/cap for (each also marks the hypothesis "disqualified"):
    metronomic timing · stale UA (penalty) · ancient/impossible UA (cap)
    · fetched robots.txt · holds_no_cache  (soft penalty; but refetch_dominant → cap)
    · probes attack paths / traversal / evasion (cap) · fabricated referers (cap)
    · HEAD-heavy (cap)
if browser-shaped UA and not disqualified and confidence < unknown bar:
    confidence = unknown bar             # rescue a brief but genuine visit
```

*Tag relationships:* nearly every line mirrors a fingerprint or conduct tag —
`loads-assets`, `bursty`/`metronomic`, `follows-links`, `has-cache`, the
`*-browser-ua` age bands, `checked-robots`, `lacks-cache` (graded via
`holds_no_cache`/`refetch_dominant`), `probe-paths`/`traversal`/`encoding-evasion`,
`forged-referer`, `uses-HEAD`. The client sees the same measurement; the tag
reports it and the classifier weighs it.
*Tuning:* [`browser.toml`](agent_census/data/tuning/browser.toml) (per-tell
weights, `disqualified_ceiling`, `[probing]` `vuln_hits_cap`), plus
[`shared.toml`](agent_census/data/tuning/shared.toml) `[browser_shape]`,
`[cadence]`, `[head_traffic]`, `[fabricated_referer]`, `[no_cache_dominance]`, and
`[verdict]` `unknown_threshold` (the rescue floor).

#### `spoofed_browser`
The costume verdict: a browser-shaped UA that does not behave like a browser. Reads
context. **Accumulates spoof tells into a score** and fires when the total clears
its threshold on *any* origin (its threshold is constrained at load to sit at or
above the unknown bar, so a firing costume is always a real verdict, never a
below-threshold leftover).

```
if not browser-shaped UA  or  identifies_as_known_agent
   or  feed traffic is dominant  or  too few requests:
    return  (no signal)

active-deception tells (count even if the client also renders like a browser):
    impossible-referer (dispositive) · datacenter origin · HEAD-heavy
    · fabricated referers · holds_no_cache AND refetch_dominant
cold / absence tells (suppressed if the client genuinely co-loads — a real
renderer must be spared):
    fetched pages but co-loaded no sub-resources · followed no links
    · all-cold at volume (almost no request carried a Referer) · frozen (ancient/impossible) UA
fire if score >= threshold  (confidence capped)
```

*Tag relationships:* the tells *are* the tags — `impossible-referer`,
`datacenter`, `uses-HEAD`, `forged-referer`, `lacks-cache`, `no-assets`, `cold`,
and the frozen-UA age bands. The design goal (issue #100) is for
`looks_like_fake_browser` to become the predominant driver of this kind. The
active/cold split is the key subtlety: a URL-replayer that fakes browser-shaped
co-loading is still caught by its active tells, while a privacy-conscious human who
really co-loads assets scores near zero.
*Tuning:* [`spoofed_browser.toml`](agent_census/data/tuning/spoofed_browser.toml)
(`[score]` threshold and cap, `[gate]` `min_requests`, per-tell `[weights]`,
`[cold]` band), plus [`shared.toml`](agent_census/data/tuning/shared.toml)
`[impossible_referer]`, `[fabricated_referer]`, `[head_traffic]`,
`[no_cache_dominance]`, `[browser_shape]`, and `[feed_traffic]` (the exclusion).

#### `crawler`
Generic link-followers. Broad path coverage, steady cadence, on-site
link-following, and a self-declared bot fetching pages without browser sub-resource
loading (broad coverage earns more; a modest path set still clears the floor).
Stands down when `recognised_specific_agent`.
*Tag relationships:* `steady`, `follows-links`, `no-assets`, and the "self-
declares a bot" fact behind `bot-ua`.
*Tuning:* [`crawler.toml`](agent_census/data/tuning/crawler.toml) (`[broad_coverage]`,
`[steady_cadence]`, `[follows_links]`, `[declared_bot]`, `[successful_pages]`),
plus [`shared.toml`](agent_census/data/tuning/shared.toml) `[browser_shape]`.

#### `scraper`
Broad harvesting like a crawler but hitting URLs *cold* (little link-following),
often on a generic-library or empty UA, mostly successful and not probing. Stands
down when `recognised_specific_agent`.
*Tag relationships:* `cold`, `no-assets`, `generic-ua`, `no-user-agent`. Note the
`scraper` kind is *also* reachable from the combiner's fallback (§2.3) for a
datacenter library client that scored nothing here.
*Tuning:* [`scraper.toml`](agent_census/data/tuning/scraper.toml) (`[broad]`,
`[harvest]`, `[cold]`, `[library]`, `[no_user_agent]`, `[benign]`), plus
[`shared.toml`](agent_census/data/tuning/shared.toml) `[browser_shape]`.

#### `vuln_scanner`
Hits to known probe paths (graded strong vs incidental), a 404 storm,
traversal/injection and encoding-evasion markers, exotic methods, a scanner-tool
UA, fast median cadence, and — corroboration only — a heavy 403 rate
(`forbidden_tell`, weighted so it can't fire the scanner alone).
*Tag relationships:* `probe-paths`, `404-storm`, `traversal`, `encoding-evasion`,
`exotic-method`, `often-forbidden`. See §2.3 for how a firing scanner overrides a
costume verdict.
*Tuning:* [`vuln_scanner.toml`](agent_census/data/tuning/vuln_scanner.toml)
(`[scanner_ua]`, graded `[probe_paths]`, `[storm_404]`, `[forbidden]`,
`[traversal]`, `[encoding_evasion]`, `[exotic_method]`, `[fast_cadence]`), plus
[`shared.toml`](agent_census/data/tuning/shared.toml) `[storm_404]` and
`[forbidden]`.

#### `monitor`
Polling a very small set of URLs at a highly regular interval, often with HEAD,
and/or a monitoring-service UA.
*Tag relationships:* `steady`/regular cadence and `uses-HEAD` — but as *positive*
signals here, against higher thresholds than the browser-disqualifying ones.
*Tuning:* [`monitor.toml`](agent_census/data/tuning/monitor.toml) (`[monitor_ua]`,
`[few_urls]`, `[head_polling]`, `[regular_polling]`) — self-contained, no shared
knobs.

#### `feed_reader`
Feeds must be *the point*: either a feed-reader UA or feeds as the majority of
traffic. Corroborated by polling few URLs, steady intervals, conditional requests
(304s), and HEAD freshness checks.
*Tag relationships:* `fetches-feeds`, `polls-feeds`, `has-cache`, `uses-HEAD`,
`steady`. The feed-dominance line is shared with `spoofed_browser`'s exclusion, so
a genuine browser-UA feed poller can't be caught as a costume.
*Tuning:* [`feed_reader.toml`](agent_census/data/tuning/feed_reader.toml)
(`[feed_traffic]` weights, `[feed_ua]`, `[few_urls]`, `[steady_polling]`,
`[conditional]`, `[head_checks]`), plus
[`shared.toml`](agent_census/data/tuning/shared.toml) `[feed_traffic]`
`dominant_ratio_min` (the shared dominance line).

#### `spam_bot`
A POST-heavy mix aimed at submission endpoints (comment/login/xmlrpc) with no
browser sub-resource loading. Volume and target, not intent — it does not
distinguish credential stuffing from comment spam.
*Tag relationships:* `post-heavy`, `no-assets`. (The `post-heavy` *tag* has its own
threshold in [`tags.toml`](agent_census/data/tuning/tags.toml) `[post_heavy]`,
separate from this classifier's `[post_volume]`.)
*Tuning:* [`spam_bot.toml`](agent_census/data/tuning/spam_bot.toml) (`[post_volume]`,
`[post_no_assets]`, `[submission_endpoint]`), plus
[`shared.toml`](agent_census/data/tuning/shared.toml) `[browser_shape]`
`no_coload_max`.

#### `app`
The UA names a native-app networking stack and nothing more specific (the weakest
identity: one match clears the bar on its own, but any named agent wins first via
`identifies_as_known_agent`).
*Tag relationships:* `declares-app-client`.
*Tuning:* none — the single match confidence is fixed in
[`app.py`](agent_census/classify/app.py); the app-stack tokens are data under
`data/signatures/`.

### 2.3 The combiner

The combiner turns the collected signals into one `Classification`:

```
by_kind = { kind : strongest (max) rounded confidence among its signals }

# 1. context adjustments & same-claim overrides
if datacenter and browser present:      lower browser confidence (floored at 0)
if spoofed_browser present:             drop the browser vote entirely
if vuln_scanner present and >= bar:     drop the spoofed_browser vote

tags = derive_tags(features, compliance, verification, wba, context…)   # §1.1–1.4

# 2. impersonation is decisive
if impersonation(verification, wba, features):   return IMPERSONATOR

# 3. nobody cleared the bar → narrow the fallback
if max(by_kind) < unknown bar or by_kind empty:  return below_threshold(...)

# 4. pick the winner
primary = argmax by (confidence, then fixed priority order)
if primary is feed_reader and it also fetched non-feeds:  add fetches-non-feeds tag
return primary
```

**Rounding** guards against float error (a weight sum of `0.44999…`) dropping a
verdict that exactly equals the threshold just below it.

*Tuning:* [`combiner.toml`](agent_census/data/tuning/combiner.toml) —
`round_digits`, `[datacenter]` (the `browser_penalty` and the datacenter-scraper
gate `scraper_min_requests` / `scraper_min_distinct_paths`), `[fallback]` (the
`scraper` and `automation` confidences), and `[impersonator]` `confidence`. The
winning/threshold bar is [`shared.toml`](agent_census/data/tuning/shared.toml)
`[verdict]` `unknown_threshold`. The tie-break priority order and the automation-
tell set are structural, in [`combiner.py`](agent_census/classify/combiner.py).

**Context adjustments and same-claim overrides.**
- *Datacenter browser penalty* — a person rarely browses from hosting, so a
  datacenter `browser` verdict is nudged down: enough to tip a borderline case,
  not to overrule a strongly-behaving real browser. (This is why the browser
  classifier's low-confidence rescue is safe: a hosting "browser" still falls.)
- *Spoofed-browser wins the browser question* — `browser` and `spoofed_browser`
  are one claim with opposite verdicts. The spoof classifier fires only on genuine
  costume/forgery tells a real browser never trips, so once it fires the `browser`
  vote is dropped — a sophisticated costume is not out-competed by the very
  browser-ness it is faking.
- *Vuln-scanner outranks the costume* — a client that probes attack paths is a
  `vuln_scanner` whatever costume it wears; the hostile activity is the more
  actionable verdict. Once the scanner clears the bar, the `spoofed_browser` vote
  is dropped (its costume tags still show on the row).

**Impersonation is decisive** — a client faking a *declared identity* is an
`impersonator` regardless of what else it looks like, with the cryptographic
channel outranking the network one:

```
impersonation(verification, wba, features):
    if wba present:
        if wba forged:                       return True     # crypto forgery
        if wba verified or expired:
            if UA names a different registered operator than the one that signed:
                                             return True     # validly signed, wrong name
            return False                                     # crypto clears the network verdict
    if network status is IMPERSONATOR:       return True     # dns / ip / AS disagree
    return False
```

The `dns-violation`/`ip-violation` and `wba-violation` tags are the visible face
of this decision; misbehaviour tags (`ignores-robots`, `probe-paths`, …) never
reach it — a real crawler can behave badly without forging its identity.

**Below-threshold fallback** — narrow `unknown` where honestly possible, in order:

```
below_threshold(...):
    if datacenter and looks_like_datacenter_scraper:   return SCRAPER
    if tags ∩ {headless-browser, lacks-cache, generic-ua, bot-ua}:  return AUTOMATION
    if datacenter:                                     return AUTOMATION
    return UNKNOWN
```

- A generic-library or UA-less client harvesting several pages from a datacenter
  IP, not probing, is benignly scraping → **`scraper`**.
- A positive **machine tell** — the set `{headless-browser, lacks-cache,
  generic-ua, bot-ua}`, read directly from the tags derived above — means a
  machine of unidentified purpose, not a true unknown → **`automation`**. This is
  the single most direct place a *tag* decides a *kind*.
- Any remaining datacenter origin with no human signal → **`automation`**.
- Otherwise → **`unknown`**, the honest answer, never argued for by a classifier.

**Winner and tie-break.** Above the threshold the primary is the highest
aggregated confidence; ties break by a fixed priority order (`impersonator` first,
through the declared and behavioural kinds, down to `spoofed_browser`,
`automation`, and `unknown` last). Order otherwise has no effect on the outcome. A
`feed_reader` that also requested non-feed resources gains a `fetches-non-feeds`
tag at this point.

The result carries the primary kind, its confidence, the full tag set, the winning
signals' evidence, any recognised agent name, and (for inspect mode) the per-signal
and per-tag rationale.

### 2.4 Kinds that are not their own classifier

`impersonator`, `automation`, and `unknown` have no classifier — they exist only
as combiner outcomes (a forged identity; a purposeless machine tell; the honest
fallback). Likewise a single-request client is not its own kind: "made one
request" is the `singleton` *tag*, on whatever kind the client lands.

---

## 3. Tuning map

Every knob referenced above, collected. Files link to
[`data/tuning/`](agent_census/data/tuning/); the `[section]` names are the stable
anchors within each. "— (data)" means the signal is driven by a data list
(`data/agents/`, `data/signatures/`), not a numeric knob; "— (feature)" means a
structural threshold hardcoded in [`model.py`](agent_census/model.py) or the
feature extractor.

### 3.1 Tags

| Tag(s) | Tuning location |
| --- | --- |
| `metronomic` / `bursty` / `steady` | [`shared.toml`](agent_census/data/tuning/shared.toml) `[cadence]`; gate [`tags.toml`](agent_census/data/tuning/tags.toml) `[cadence]` |
| `loads-assets` / `no-assets` | [`shared.toml`](agent_census/data/tuning/shared.toml) `[browser_shape]` (`coload_ratio_min`, `no_coload_max`, `coload_min_pages`) |
| `follows-links` / `cold` | [`shared.toml`](agent_census/data/tuning/shared.toml) `[browser_shape]` (`follow_ratio_min`, `no_follow_max`); gate [`tags.toml`](agent_census/data/tuning/tags.toml) `[link_following]` |
| `has-cache` | — (feature: a `304` was seen) |
| `lacks-cache` | `holds_no_cache` — (feature); the dispositive form [`shared.toml`](agent_census/data/tuning/shared.toml) `[no_cache_dominance]` |
| `headless-browser`, UA-shape bands, `generic-ua`, `bot-ua` | — (data: UA signatures / agent lists) |
| `probe-paths` | [`tags.toml`](agent_census/data/tuning/tags.toml) `[probe_paths]` |
| `traversal`, `encoding-evasion`, `exotic-method` | — (feature: a count `> 0`) |
| `404-storm` | [`shared.toml`](agent_census/data/tuning/shared.toml) `[storm_404]` |
| `often-forbidden` | [`shared.toml`](agent_census/data/tuning/shared.toml) `[forbidden]` |
| `uses-HEAD` | [`shared.toml`](agent_census/data/tuning/shared.toml) `[head_traffic]` `notable_ratio` |
| `post-heavy` | [`tags.toml`](agent_census/data/tuning/tags.toml) `[post_heavy]` |
| `forged-referer` | [`shared.toml`](agent_census/data/tuning/shared.toml) `[fabricated_referer]` |
| `impossible-referer` | [`shared.toml`](agent_census/data/tuning/shared.toml) `[impossible_referer]`; regime inferred via `[redirect_gate]` |
| `singleton`, `no-user-agent`, `checked-robots` | — (feature) |
| `datacenter` | — (context: origin-network attribution) |
| `asn-attributed`, `asn-associated`, `dns-*`, `ip-*` | — (verification, [`netverify.py`](agent_census/netverify.py) + `data/agents/`) |
| `declares-known-bot`, `fetches-feeds`, `declares-app-client`, `user-triggered` | — (data) |
| `polls-feeds` | — (feature); dominance [`shared.toml`](agent_census/data/tuning/shared.toml) `[feed_traffic]` |
| `ignores-robots` | — (robots compliance) |
| `ua-rotating` / `shared-ip` | [`tags.toml`](agent_census/data/tuning/tags.toml) `[ua_rotation]` (+ `looks_like_fake_browser`, [`tags.toml`](agent_census/data/tuning/tags.toml) `[fake_browser]`) |
| `wba*` | — (cryptographic, no tuning) |
| `high-rate` / `high-bytes` / `wide-breadth` / `long-session` | [`relative_tags.toml`](agent_census/data/tuning/relative_tags.toml) `[params]`, `[default]`, `[[kind]]` |

### 3.2 Classifiers and combiner

| Classifier | Own file | Shared knobs |
| --- | --- | --- |
| declared identities | [`known_bot.toml`](agent_census/data/tuning/known_bot.toml) | — (UA/AS lists are data) |
| `browser` | [`browser.toml`](agent_census/data/tuning/browser.toml) | [`shared.toml`](agent_census/data/tuning/shared.toml) `[browser_shape]`, `[cadence]`, `[head_traffic]`, `[fabricated_referer]`, `[no_cache_dominance]`, `[verdict]` |
| `spoofed_browser` | [`spoofed_browser.toml`](agent_census/data/tuning/spoofed_browser.toml) | [`shared.toml`](agent_census/data/tuning/shared.toml) `[impossible_referer]`, `[fabricated_referer]`, `[head_traffic]`, `[no_cache_dominance]`, `[browser_shape]`, `[feed_traffic]` |
| `crawler` | [`crawler.toml`](agent_census/data/tuning/crawler.toml) | [`shared.toml`](agent_census/data/tuning/shared.toml) `[browser_shape]` |
| `scraper` | [`scraper.toml`](agent_census/data/tuning/scraper.toml) | [`shared.toml`](agent_census/data/tuning/shared.toml) `[browser_shape]` |
| `vuln_scanner` | [`vuln_scanner.toml`](agent_census/data/tuning/vuln_scanner.toml) | [`shared.toml`](agent_census/data/tuning/shared.toml) `[storm_404]`, `[forbidden]` |
| `monitor` | [`monitor.toml`](agent_census/data/tuning/monitor.toml) | — |
| `feed_reader` | [`feed_reader.toml`](agent_census/data/tuning/feed_reader.toml) | [`shared.toml`](agent_census/data/tuning/shared.toml) `[feed_traffic]` |
| `spam_bot` | [`spam_bot.toml`](agent_census/data/tuning/spam_bot.toml) | [`shared.toml`](agent_census/data/tuning/shared.toml) `[browser_shape]` |
| `app` | — (fixed in [`app.py`](agent_census/classify/app.py)) | — |
| combiner | [`combiner.toml`](agent_census/data/tuning/combiner.toml) | [`shared.toml`](agent_census/data/tuning/shared.toml) `[verdict]` |
