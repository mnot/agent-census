# Calibrating the classifier

`agent-census calibrate` renders a digest (see `report/calibrate.py`) of the
marginal, uncertain, and unrecognised traffic from a run -- the decision
boundaries where the data and heuristics are most likely incomplete. Calibrating
is reading that digest and improving the **data**, nothing else.

In scope -- the data files at those boundaries:

- `data/networks/*.toml` -- datacentre / egress ASN and range lists.
- `data/agents/*.toml` -- declared crawlers (UA token, verification ranges / rDNS / ASN).
- `data/signatures/*.toml` -- feed-reader / app / scanner / monitor UA tokens, vuln paths.
- `data/tuning/*.toml` -- the numeric knobs. Fair game, but high blast radius: a
  weight or threshold change moves *every* client, so change it deliberately and
  re-verify against a real log, not just the tests.

Out of scope -- the Python under `agent_census/`: the classifiers (`classify/`),
verification (`netverify.py`), the pipeline, the combiner. A calibrate pass does
**not** touch logic. If the digest looks like it's exposing a logic bug -- a real
client mislabelled, a check firing wrong -- that's a *finding*: write it up, state
the root cause, and get sign-off before editing code. Don't talk yourself into a
plausible story and then change semantics on the strength of it; that's how a
correct signal gets quietly switched off.

## Traps

- **A crawler `asns = [...]` allowlist makes every out-of-AS sighting an
  impersonator.** Only add it when the bot verifiably crawls from those AS(es)
  *exclusively*; otherwise leave it commented with the reason. SemrushBot is the
  cautionary case -- Semrush publishes no AS/IP verification and says it uses no
  consecutive blocks, so the single-AS claim is third-party only.
- **A false-positive flag is a hypothesis, not a verdict.** The spoof / impersonator
  digest sections are the priority to review, but "this looks like a false positive"
  is something to confirm against the actual client -- never a reason to soften a
  check so the symptom disappears.
- **Verify before declaring done.** `make tidy && make lint && make typecheck &&
  make test`, and don't sweep unrelated reformatting into the change.
