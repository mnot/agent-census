# Classifier data files

These TOML files hold the reference data agent-census classifies against -- known
crawlers, hosting networks, scanner User-Agents, and so on. Editing them is how you
teach it about an agent or network it doesn't yet recognise; nothing here needs code
changes. The files are grouped into subdirectories by role:

- **[`agents/`](agents/README.md)** -- declared crawlers, all sharing the
  `[[agent]]` table format (one file per kind: `search_engine.toml`,
  `ai_crawler.toml`, …).
- **[`signatures/`](signatures/README.md)** -- the string match-lists: the
  User-Agent and request-path markers each classifier substring-matches against.
- **[`networks/`](networks/README.md)** -- IP-range stanzas for hosting/cloud
  providers and shared-egress relays.
- **[`tuning/`](tuning/README.md)** -- the numeric knobs: confidence weights and
  decision thresholds, one file per classifier plus the cross-classifier
  `shared.toml` and the relative-magnitude `relative_tags.toml`.

Each subdirectory's README documents its own files and formats. The only file left
at the top level is:

- `browser_releases.toml` -- browser release cadences, used to flag implausibly old
  (yet auto-updating) browser versions as a spoofed-UA tell (`[[family]]`, one per
  browser family). Its own header comment explains the anchor/cadence model.
