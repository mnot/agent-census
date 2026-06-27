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
- `feed_readers.toml`, `app_clients.toml`, `scanner_ua.toml`, `vuln_paths.toml` --
  flat lists of substrings/paths, keyed by the file name.
