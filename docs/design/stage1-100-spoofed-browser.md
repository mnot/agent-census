# Stage 1 (#100): browser-spoof score

Status: **built and verified** on `main` (post-#101). Tracked in #110. Stage 1a
(`ClassifyContext` + `evaluate_in_context`, behaviour-neutral) and Stage 1b (the
`SpoofedBrowserClassifier` + `data/tuning/spoofed_browser.toml`) are committed; the score
model, combiner rule, and weights below are as-built. Sections marked "(as built)" reflect
the shipped code; the rest is the design rationale that led there.

## Goal

Turn `spoofed_browser` from a single hard-`AND` costume test gated on datacenter origin
into a **weighted accumulation of browser-spoof tells** that can reach the verdict on any
origin, with datacenter as one weight among many.

## Root cause (against the #101 tree)

1. **Costume tell is a hard binary `AND`.** `looks_like_fake_browser` fires only on
   `asset_coload_ratio == 0.0 AND referer_following_ratio == 0.0`. A client at
   `coload==0, follow==0.04` fails it outright even with other tells present. #101 added
   `impossible_referer` as an `OR` — right instinct, still boolean.
2. **Datacenter is a hard `AND`-gate on the costume path.** In `_below_threshold` the
   costume pattern reaches `spoofed_browser` only via `… and (datacenter or impossible)`.
   Only `impossible-referer` escapes the origin gate; a residential costume falls through.
3. **`browser.py` disqualifiers dead-end at `unknown`.** Metronomic cadence,
   ancient/impossible UA, dominant no-cache, probing, fabricated referer, HEAD-heavy each
   cap the browser signal below `unknown_threshold`; those clients land in
   `_below_threshold` and — absent datacenter+costume or impossible — become `unknown`,
   though "headless engine capped for probing" *is* the spoofed-browser target.

## Chosen approach: Option B — a first-class `SpoofedBrowserClassifier`

Signed off: `spoofed_browser` becomes a real classifier that emits a scored `Signal`
competing in normal aggregation. The obstacle is that a `Classifier` is a pure function of
`ClientFeatures` — `evaluate(self, features)` receives **neither `datacenter` nor
`redirect_shadow`** (see `classify/base.py`; both are combiner inputs threaded into
`combine()`), yet two tells (datacenter weight, `impossible-referer`) need them. So B
requires **widening the classifier contract to pass those combiner-level inputs** — done
minimally, keeping purity the norm.

### Contract-widening (least-churn, purity-preserving)

Add a small frozen context object and a defaulting context-aware entry point, so the 14
existing classifiers are **untouched**:

```python
# model.py
@dataclass(frozen=True, slots=True)
class ClassifyContext:
    datacenter: bool = False
    redirect_shadow: str | None = None

# classify/base.py — evaluate() stays the pure abstract method for all classifiers.
class Classifier(ABC):
    @abstractmethod
    def evaluate(self, features: ClientFeatures) -> list[Signal]: ...

    def evaluate_in_context(
        self, features: ClientFeatures, context: ClassifyContext
    ) -> list[Signal]:
        """Context-aware entry point the combiner runs. Default: ignore context and
        defer to the pure evaluate(). A classifier needing combiner-level inputs
        (origin, redirect regime) overrides THIS, not evaluate()."""
        return self.evaluate(features)
```

`run_classifiers(features, context)` calls `evaluate_in_context`. Only
`SpoofedBrowserClassifier` overrides it; its plain `evaluate(features)` scores the
feature-only tells (so it's still independently testable and honest about purity), and
`evaluate_in_context` adds the datacenter weight and the `impossible-referer` tell.

### Why B lands cleaner than a combiner scorer

Because the classifier emits a `SPOOFED_BROWSER` `Signal` that competes by confidence, the
combiner's **two special-cased `spoofed_browser` sites from #101 both delete**:

- The `primary is Kind.BROWSER and impossible` conversion — gone; a firing spoof signal at
  ~`fallback.spoofed_browser` (0.6) simply outscores browser's floored 0.45.
- The `_below_threshold` `looks_like_fake_browser(...) and (datacenter or impossible)`
  branch — gone; a residential client with enough tells now clears the bar as a normal
  primary and never reaches the fallback.

And the **capped-browser reconciliation falls out for free**: when `browser.py` caps a
probing/HEAD-heavy browser below 0.45, its BROWSER signal loses to the 0.6 spoof signal in
plain aggregation — `spoofed_browser`, not `unknown`, with no combiner special case.

### Sub-staging (keeps the refactor honest)

- **Stage 1a — contract-widening, behaviour-neutral.** Add `ClassifyContext` +
  `evaluate_in_context` default + thread `context` through `run_classifiers`/`combine`. No
  classifier overrides it yet; **zero behaviour change**, its own small PR, full suite green.
- **Stage 1b — `SpoofedBrowserClassifier` + score + tuning**, plus deleting the two combiner
  special-cases. This is where behaviour moves; calibrate weights/threshold on the digest.

## The score model (as built)

A weighted sum over tells already measured, thresholded in `data/tuning/spoofed_browser.toml`
(knobs out of logic). Base gate first: only a browser-UA, not-a-known-agent, non-feed client
with ≥2 requests scores at all. Then the tells fall in two groups:

**Active-deception / origin — always counted** (a client faking referers or replaying an
impossible one is deceiving even while it renders pages):

| Tell | Source | Weight |
|---|---|--:|
| `impossible-referer` | `looks_like_impossible_referer(features, redirect_shadow)` | **0.60** (dispositive alone) |
| datacenter origin | `context.datacenter` | 0.30 |
| HEAD-heavy | `head_ratio > head_traffic.notable_ratio` | 0.30 |
| fabricated referer | `self_referer_ratio >= fabricated_referer.self_referer_min` | 0.30 |

**Cold / costume — counted only when `asset_coload_ratio <= browser_coload_min`** (a client
that genuinely co-loads a page's sub-resources is rendering like a browser; the design's
"a real browser signal lowers the score" guard):

| Tell | Source | Weight |
|---|---|--:|
| holds no cache at volume | `features.holds_no_cache` | 0.30 |
| no asset co-load | `page_count > 0 and asset_coload_ratio == 0` | 0.15 |
| no link-following | `referer_following_ratio == 0` | 0.15 |
| all-cold at volume | `blank-Referer share >= cold.blank_ratio_min over >= cold.min_requests` (#103) | 0.20 |
| ancient / impossible UA | `uas.version_age_band(...) in {ancient, impossible}` | 0.15 |

`all-cold at volume` and `no link-following` are **not independent**: link-following can't be
observed without a Referer, so at `blank_ratio >= 0.9` the `no-link-following` tell has
necessarily fired too (`cold + no_coload = 0.35` is under the bar on its own — the tipping
cases are exactly the ones where `no_follow` co-fires). So `cold` does not add an independent
0.20; it raises the all-cold non-rendering costume from 0.30 to 0.50 by stacking on a
correlated tell. Deliberate (issue #103), but keep the coupling in mind if these are retuned.

`fire at score >= 0.45`; emitted confidence `= min(score, 0.90)`. A dispositive tell carries
the threshold on its own (preserving #101's `impossible-referer` behaviour). Headless-UA,
metronomic, and UA-rotating were considered and **dropped** from the first cut: headless/
ua-rotating self-declare and lean toward `automation`, and metronomic/ua-rotating would have
coupled this classifier to another module's tuning for a 0.15 corroborator the four anchors
don't need.

### Magnitude: why each tell is binary (measured)

Each tell fires at a gate and adds a fixed weight — one impossible referer above the gate and
seven score identically; 12%-HEAD and 90%-HEAD both add 0.30. Magnitude lives only *across*
tells (the 0.45 / 0.60 / 0.75 / 0.90 confidence ladder = "how many independent ways
suspicious"), not *within* one. This is deliberate, and confirmed not to cost precision on the
live corpus (2,811 spoofed clients):

- Of the **850** clients sitting exactly on the 0.45 boundary — the only place intra-tell
  magnitude could flip a verdict — **zero** were tipped by a graded tell sitting *barely* above
  its gate (HEAD 0.10–0.15: 0; forged 0.50–0.55: 0; no-cache just over its volume gate: 0). The
  boundary is populated by the binary costume tells, not marginal graded ones.
- The graded tells cluster *far* above their gates, not near them: of 193 HEAD-tell clients ~none
  sit near the 10% gate (95 at 30–60%, 90 at >60%); of 179 forged clients 85 are at *exactly*
  100% self-referer, only 38 in the 0.50–0.60 near-gate band (and none of those at the boundary).

So banding a graded tell (the `current/stale/ancient/impossible` UA-age precedent) would refine
confidence *numbers* for high-magnitude clients but flip *zero* classifications — added logic for
a cosmetic gain. Left binary. Revisit only if (a) a second corpus shows a fat near-gate tail, or
(b) a gate is lowered to widen the net (which grows the near-gate population) — re-run the
same measurement (spoofed cohort's confidence histogram × graded-tell intensity at the 0.45
boundary) to check.

## What changes in the combiner (both #101 special-cases delete)

Because the classifier now emits a competing `SPOOFED_BROWSER` signal, the two
special-cased sites #101 added to `combine()` are **removed**:

1. **The `primary is Kind.BROWSER and impossible` conversion** — deleted. A floored
   "brief visit" browser (the 0.45 rescue in `browser.py`) is simply outscored by the spoof
   signal (~0.6) when it fires, via `max()` aggregation. Impossible-referer keeps converting
   because it drives the score to `≥ threshold` on its own.
2. **The `_below_threshold` `looks_like_fake_browser(...) and (datacenter or impossible)`
   branch** — deleted. With datacenter folded into the score as a weight, a residential
   client with enough tells clears `unknown_threshold` as a normal primary and never reaches
   the fallback. (`_below_threshold`'s scraper/automation branches stay.)

`looks_like_impossible_referer` in `tags.py` remains — it still drives the `impossible-referer`
tag and is reused by the classifier as its dispositive tell. The `dc_browser_penalty` on a
datacenter BROWSER verdict stays as-is (independent nudge).

**Replacing the two special-cases: one aggregation rule.** Pure `max()` aggregation lost the
dispositive guarantee — a co-loading URL-replayer (browser signal ~0.65 from its faked co-load)
could out-score its own `impossible-referer` spoof signal (0.60). So the combiner now drops the
`BROWSER` vote whenever a `SPOOFED_BROWSER` signal is present: the two are one claim with
opposite verdicts, and the classifier fires *only* on tells a real browser never trips, so a
firing spoof signal settles the browser question. Every other kind still competes on confidence
(a prober stays `vuln_scanner`). This one rule is the accumulation-model successor to both #101
special-cases.

## Reconciliation with `browser.py` disqualifiers — free under B

When `browser.py` caps a client below 0.45 (probing, HEAD-heavy, ancient UA, dominant
no-cache…), its BROWSER signal simply loses to the ~0.6 spoof signal in plain confidence
aggregation → `spoofed_browser`, not `unknown`. No combiner special case, no change to
`browser.py` — it keeps capping; the competing signal does the rest. This is the payoff of
B over a combiner-level scorer.

## False-positive guardrails (the residential exposure)

Decoupling from datacenter is the point *and* the risk. Guardrails:

- Dispositive tells stay dispositive; **contributing tells must accumulate** — no single
  weak tell (a lone `coload==0`) reaches the threshold. Calibrate the threshold so a
  plausible privacy-conscious real browser (e.g. an extension stripping referers → `follow==0`
  but `coload>0` and 304s present) stays under it.
- A genuine browser signal (co-load present, link-following present, 304s) must *lower* the
  score — the tells are absence-of-browserness, so their presence simply doesn't fire.
- Keep the impossible-referer thresholds under review per #111 — they're the calibration
  most likely to over-fire off mnot.net.

## Test plan (as built)

`tests/test_spoofed_browser.py`, two layers, all live asserts:

- **Behavioural** through `classify_client` — the four calibration anchors (datacenter
  costume; impossible-referer residential; residential costume + one strong tell;
  residential costume alone stays a browser), the genuine-browser guard, and the
  digest-found exclusions (a prober stays `vuln_scanner`; a feed-fetcher behind a browser
  UA is not spoofed).
- **Classifier unit tests** — `evaluate_in_context(features, ClassifyContext(...))`: tells
  accumulate, datacenter raises the score (weight not gate), impossible-referer fires alone,
  known agents / feed-fetchers never fire.

Stage 1a (contract-widening) is covered by the full existing suite staying green (728 passed).

## Decisions (all resolved)

1. **Approach — Option B**, sub-staged 1a (behaviour-neutral plumbing) then 1b (classifier).
2. **Contract-widening** — the `evaluate_in_context` defaulting wrapper (14 classifiers
   untouched, purity the norm).
3. **Weights / threshold** — calibrated on the live digest against the four anchors; see the
   score model above and `data/tuning/spoofed_browser.toml`. Headless / ua-rotating dropped
   from the first cut (lean `automation` / cross-module coupling).
4. **Evidence granularity** — richer: the classifier enumerates the specific tells that fired,
   so inspect shows *which* costume tells drove the verdict (and `boilerplate_lead` is now
   `False`, unlike the old fallback sentence).
5. **Magnitude / binary tells** — measured, kept binary; see "Magnitude" under the score model.

## Verification

Calibrated and re-verified against a live 84 MB mnot.net log (not just tests): the residential
catches are genuine costumes; real browsers and browser-UA feed readers are untouched; one
false-positive class (co-loading clients caught on the weak path) was found in verification and
fixed with the co-load guard. `make tidy && lint && typecheck && test` all green.
