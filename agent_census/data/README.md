# Classifier data files

These TOML files hold the lists agent-census classifies against -- known crawlers,
hosting networks, scanner User-Agents, and so on. Editing them is how you teach it
about an agent or network it doesn't yet recognise; nothing here needs code
changes.

Most of the files share one format: the **`[[agent]]`** table, described below.
A few have their own shape and document it in their own header comment:

- `datacenter_ranges.toml` -- hosting/cloud providers (`[[source]]`).
- `egress_networks.toml` -- shared-egress relays, VPNs, and proxies (`[[network]]`).
- `browser_releases.toml` -- browser release cadences, for version-age (`[[family]]`).
- `feed_readers.toml`, `app_clients.toml`, `scanner_ua.toml`, `vuln_paths.toml` --
  flat lists of substrings/paths, keyed by the file name.

## The `[[agent]]` format

Used by the declared-crawler categories. The file name is the kind an agent is classified as.
Each agent is one `[[agent]]` table; add as many as you like.

```toml
[[agent]]
ua_substring = "AhrefsBot"
domains = ["ahrefs.com", "ahrefs.net"]
ranges_url = "https://api.ahrefs.com/v3/public/crawler-ip-ranges"
asns = [140577]
```

### Identity -- how a client is recognised as this agent

- **`ua_substring`** (string) -- matched case-insensitively as a substring of the
  User-Agent. The usual way an agent is recognised. Required, *unless* the agent is
  `asn_primary` (below).
- **`name`** (string) -- a display label. Optional for a `ua_substring` agent
  (the matched token is used); required for an `asn_primary` one.
- **`asn_primary`** (bool) -- the AS number *is* the identity. All traffic from the
  agent's `asns` folds into one entry and is classified from the AS regardless of
  User-Agent, tagged `asn-attributed`. Use this only for operators that crawl
  behind rotating or spoofed UAs, where there's no stable token to match (e.g.
  Sberbank). Requires `asns`. Without this flag, `asns` means verification, not
  identity (below).

### Verification -- confirming or impeaching the claim

A User-Agent is trivially forged, so an agent can declare how to check a client
that presents its token. Three independent checks, in precedence order:

- **`domains`** (list of strings) -- reverse/forward DNS must resolve the client's
  IP to a host under one of these domains. Runs by default (it makes DNS calls);
  `--no-verify-bots` turns it off.
- **`ranges`** (list of CIDRs) and/or **`ranges_url`** (string) -- the client's IP
  must fall in the agent's published ranges. `ranges_url` is fetched and cached;
  **`format`** (string) says how to parse it (`prefixes`, `json`, `text`,
  `ripestat`, …; default `prefixes`). The range check runs by default;
  `--no-verify-bots` turns it off, and `--no-fetch-ranges` skips the `ranges_url`
  fetch so only the inline `ranges` are checked.
- **`asns`** (list of integers) -- the client's *logged* AS number must be one of
  these. This is the lowest-precedence tier and runs offline (no network), so it
  applies even under `--no-verify-bots`.

How they combine for a `ua_substring` agent that presents its token:

- An agent declaring both `domains` and `ranges` must pass **both** by default
  (either definitive failure is impersonation). **`rdns_fallback`** (bool) makes
  the ranges primary and the domains a fallback used only when the ranges can't be
  obtained.
- `asns` is consulted only when the DNS/range tiers are **absent or inconclusive**
  (no `domains`/`ranges`, or the range feed couldn't be fetched, or a DNS lookup
  timed out). A logged AS in the list yields `asn-associated`; a logged AS *not* in
  the list yields `impersonator`. A client with no logged AS number is simply left
  unverified -- absence is never read as impersonation.

The resulting tags: `verified` (DNS/range confirmed), `asn-associated` (AS
corroborated), or the `impersonator` kind (a definitive mismatch). With
`--no-verify-bots` the DNS/range tiers don't run, so only `asns` can confirm or
impeach.

### Field summary

| Field | Type | Purpose |
| --- | --- | --- |
| `ua_substring` | string | identity by UA token (required unless `asn_primary`) |
| `name` | string | display label (required for `asn_primary`) |
| `asn_primary` | bool | the AS *is* the identity; fold the whole AS, ignore the UA |
| `domains` | string[] | verify by reverse/forward DNS |
| `ranges` | string[] | verify by inline CIDRs |
| `ranges_url` | string | verify by a fetched range list |
| `format` | string | how to parse `ranges_url` (default `prefixes`) |
| `rdns_fallback` | bool | ranges primary, domains only when ranges unobtainable |
| `asns` | int[] | verify by logged AS (lowest precedence), or the identity if `asn_primary` |

Every agent needs at least an identity: a `ua_substring`, or `asn_primary` with
`asns`. Verification fields are all optional -- without any, an agent is recognised
by its UA but its claim is never confirmed (it shows as a declared, unverified
crawler).
