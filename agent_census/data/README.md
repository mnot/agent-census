# Classifier data files

These TOML files hold the lists agent-census classifies against -- known crawlers,
hosting networks, scanner User-Agents, and so on. Editing them is how you teach it
about an agent or network it doesn't yet recognise; nothing here needs code
changes.

The declared-crawler categories all share one format -- the **`[[agent]]`** table --
and live together in **`agents/`** (one file per kind: `agents/search_engine.toml`,
`agents/ai_crawler.toml`, …), documented in [`agents/README.md`](agents/README.md). The
remaining files here each have their own shape, documented in their own header comment:

- `datacenter_ranges.toml` -- hosting/cloud providers (`[[source]]`).
- `egress_networks.toml` -- shared-egress relays, VPNs, and proxies (`[[network]]`).
- `browser_releases.toml` -- browser release cadences, for version-age (`[[family]]`).
- `relative_tags.toml` -- thresholds for site-relative magnitude tags (`[params]`,
  `[default]`, `[[kind]]`); calibrated against the site's real browsers.
- `ua_signatures.toml` -- the User-Agent token lists that decide whether a UA looks
  like a browser, declares a bot, names a headless engine or HTTP library, or names
  a feed reader; grouped into `[browser]`, `[automation]`, etc. sections.
- `request_signatures.toml` -- the path/method marker lists read during feature
  extraction (static assets, pages, traversal, encoding evasion, uncommon methods,
  feed URLs); grouped into sections.
- `feed_readers.toml`, `app_clients.toml`, `scanner_ua.toml`, `vuln_paths.toml`,
  `monitor_uas.toml`, `submit_paths.toml` -- flat lists of substrings/paths, keyed
  by the file name.

The **`tuning/`** subdirectory holds the numeric knobs -- the confidence weights and
decision thresholds each classifier and the tag layer use. There is one file per
classifier (`tuning/browser.toml`, `tuning/crawler.toml`, …), each grouping a signal's
threshold and weight together, plus `tuning/shared.toml` for the thresholds used by
more than one of them (so "what counts as browser-like" is defined once). See
[`tuning/README.md`](tuning/README.md).
