# Network IP ranges

These TOML files map IP ranges (and AS numbers) to the networks that own them, so a
client's source address can be attributed to a hosting provider or a shared-egress
relay. Editing them is how you teach agent-census about a network it doesn't yet
recognise; nothing here needs code changes. The full rationale is in each file's
header comment; this is the map.

Both files share the same range-source shape. Ranges come from three places, any
combination of which a stanza may carry:

- **`ranges`** (list of CIDRs) -- inline, always used, needs no network.
- **`ranges_url`** (string) -- a provider's published list, fetched and cached for a
  week by default; `--no-fetch-ranges` skips the fetch and falls back to inline
  `ranges`. **`format`** says how to parse it (`amazon` | `aws` | `azure` | `csv`
  | `oracle` | `prefixes` | `ripestat` | `subnets` | `text` -- see
  `iprange.extract_cidrs`; default `prefixes`).
- **`asns`** (list of integers) -- matched against the client's *logged* AS number
  (e.g. Apache `%{MM_ASN}e` from mod_maxminddb), so a network with no clean range
  list is still attributed offline. Big networks announce from several ASes; extend
  as needed.

## Files

- **`datacenter_ranges.toml`** -- hosting / cloud providers, one `[[source]]` each.
  A browser User-Agent arriving from one of these is the signature of spoofed-browser
  automation (the `datacenter` tag, the `spoofed_browser` kind). To flag extra
  networks as datacentres, add a source with just a `name` + `asns`.
- **`egress_networks.toml`** -- shared-egress relays, VPNs, and corporate proxies,
  one `[[network]]` each. Traffic is genuinely a browser, but the source IP is
  meaningless as identity, so all of a network's requests collapse into one entry
  per User-Agent. Adds two fields beyond the source shape: **`tag`** (applied to the
  network's clients) and an optional **`group`** (a cross-tab column header only --
  networks sharing a group, e.g. Zscaler + Netskope under "Corporate proxies", are
  summed into one column but keep their own identity and tag).

The `format` and AS-matching machinery is shared with the per-agent verification in
[`../agents/`](../agents/README.md), which uses the same fields for a different
purpose.
