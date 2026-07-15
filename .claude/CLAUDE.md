# agent-census — working notes

Two recurring jobs here are easy to confuse and have different rules. Before
starting either, read its file -- they're not loaded by default:

- **Calibrating** the classifier from a `calibrate` digest → read `.claude/calibrate.md`.
- **Auditing** or extending the datacentre / egress ASN data → read `.claude/audit.md`.

Non-negotiables that apply to both:

- **Data, not logic.** Both jobs edit `data/*.toml`. Changing Python under
  `agent_census/` (the classifiers, `netverify.py`, the pipeline) means you've left
  calibration/audit and need sign-off on the root cause first.
- **Ground every claim in a primary source** -- the operator's own docs for a bot,
  `audit`'s registries for an ASN. Don't launder an aggregator page or memory into
  fact; an honest gap beats a confident guess.
- **Neutral provider entries only.** Record what a network *is* -- datacentre,
  hosting, egress -- without characterising named third parties.
- **Branch, don't work on `main`.** Use the assigned worktree or a fresh branch.

## Keep SPEC.md in sync

`SPEC.md` (repo root) is the authoritative spec for **how every tag and
classification is derived** -- the classifiers, the combiner, the tag layer, and
the tuning that drives them, cross-linked to each knob. If you change that logic
(anything under `agent_census/classify/`, `features.py`, `model.py`, or the
`data/tuning/*.toml` knobs those read), update `SPEC.md` in the same change so
code and spec never drift. This is separate from -- and not gated by -- the
data-only calibrate/audit rules above.

## Design rationale goes in issues, not files

`SPEC.md` documents *current behaviour*; the *why* -- root-cause analyses,
rejected alternatives, implementation records, staging plans -- belongs in the
relevant GitHub issue, not an in-repo `docs/` file. Don't create design-note
files; put that content in the tracking issue.
