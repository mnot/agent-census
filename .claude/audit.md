# Auditing the network data

`agent-census audit` cross-checks the `(provider, ASN)` entries in
`networks/datacenter_ranges.toml` against Cloudflare Radar, RIPEstat and PeeringDB
(authoritative AS org names, sibling ASNs, a hosting-vs-eyeball hint -- see
`audit.py`). It validates what's already there and, with `--asn N`, assesses an
arbitrary candidate -- e.g. one of the unrecognised ASNs that `calibrate` surfaces.
Needs a Cloudflare Radar token in `$CF_API_TOKEN`.

Audit is the **grounding step** for network data. Before adding an ASN as a
datacentre, or trusting an org name, run it through `audit` -- don't add it on the
strength of a web snippet, an aggregator page, or memory. If the registries
disagree or the signal is weak, that's a reason to leave it out and note why, not
to add it on a hunch.

The same grounding applies the other way: an ASN that looks like hosting from its
name or its traffic (lots of scanners) still belongs in the data only once the
registries agree it's hosting -- behaviour is a hint, not the verdict.
