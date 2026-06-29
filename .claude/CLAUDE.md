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
