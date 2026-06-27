# Product

## Register

product

## Users

Site operators, sysadmins, and developers investigating who and what is hitting
their site. They run `agent-census` over their own Apache or Cloudflare access
logs from the command line and open the resulting self-contained HTML page in a
browser. Their context is investigative and one-off: "what is all this traffic,
which of it is lying about itself, and what is it for?" They are technically
fluent — comfortable with log formats, ASNs, robots.txt, and User-Agent strings
— and they want to scan a dense report quickly, then drill into a specific
client's evidence when something looks off. The report is read, not navigated;
there is no app shell, no login, no server.

## Product Purpose

agent-census classifies the clients in an access log by **how they behave**, not
just what their User-Agent claims. It sorts traffic into kinds (browser, crawler,
search engine, AI crawler, scraper, vuln scanner, feed reader, monitor, and so
on), checks anything declaring a known crawler against DNS and published address
ranges, and surfaces the behavioural and origin evidence behind each call. The
HTML report is the primary deliverable: a summary by kind, a kind×network
cross-tab, and per-kind client tables with collapsible actors, tags, confidence,
and top evidence — plus an `inspect` view that shows every signal that fired for
one client. Success is an operator trusting the breakdown at a glance and being
able to defend any single verdict from the evidence shown.

## Brand Personality

A **forensic instrument** — neutral, evidence-first, and dense, where the tool
disappears and the data does the talking. System fonts, system light/dark, and
color used only to encode meaning, never to decorate. But it is **sharp and
opinionated where it counts**: spoofing, impersonation, and probe behaviour get
clear visual weight and a confident verdict, with calibrated confidence shown so
the stance is honest rather than alarmist. Three words: precise, candid,
unshowy.

## Anti-references

- **Marketing-dashboard slop.** No hero-metric tiles, gradients, glassmorphism,
  or identical icon+heading card grids. This is an instrument, not a SaaS
  landing page.
- **SOC / security-vendor theatrics.** No alarmist red-everywhere, fake
  "threat level" gauges, or dark-cyber cosplay. Color marks real signal, not
  drama — the report stays credible by under-reacting, not over-reacting.
- **Over-chromed enterprise BI.** No heavy chrome, 3D bars, skeuomorphic gauges,
  or decorative chartjunk. The heat shading and bars must read honestly and
  stay legible.

## Design Principles

- **Behaviour over claims.** The whole thesis: a User-Agent is a claim to weigh
  against conduct and origin, not a fact. The design must keep the *measured
  behaviour* and the *declared identity* visibly distinct, never collapsing one
  into the other.
- **Evidence within reach.** No verdict is asserted without its reasoning being
  available — top evidence inline, the full signal trace one `inspect` away.
  Confidence is shown, not hidden, so the reader can calibrate trust.
- **Neutral toward named parties.** Characterise *behaviour*, not companies.
  Provider and network entries stay factual; the report describes what a client
  did, not who is bad. (Both a legal-risk guardrail and what keeps the tool
  credible.)
- **The instrument disappears.** Density and legibility serve the operator's
  scan-then-drill task. Every visual choice — a color, a bar, a fold — must
  encode meaning or earn its place; nothing decorative.
- **One file, no dependencies.** The report is a single self-contained HTML page
  that opens from `file://` with no external assets, fonts, or scripts.
  Portability and longevity are features; honor them in every addition.

## Accessibility & Inclusion

No formal conformance target. Aim for sensible, best-effort defaults: legible
contrast in **both** light and dark modes (the report uses `color-scheme: light
dark` and system `Canvas`/`CanvasText`), readable type sizes, real focus
affordances on the interactive controls (the client filter, the network toggle,
the collapsible rows), and a `prefers-reduced-motion` fallback for any motion
added later. Color currently carries meaning on its own (kind badges, tag colors,
heat shading); pairing it with a non-color cue where cheap is a worthwhile
nicety, but not a hard requirement here.
