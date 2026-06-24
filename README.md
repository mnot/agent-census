# agent-census

A command-line tool that reads a Web server access log and characterises the
*clients* hitting your site: it identifies each distinct client, works out what
it's there to do from how it behaves, checks whether it respects `robots.txt`,
and reports how much of your traffic each kind accounts for. Output is Markdown,
or a self-contained HTML page.

It tells browsers apart from crawlers, search engines (Googlebot and friends),
social-preview fetchers (the link-unfurlers behind chat and social cards), AI
crawlers (GPTBot, ClaudeBot, ...), archivers (the Internet Archive, Common
Crawl), SEO and marketing crawlers, scrapers, vulnerability scanners, comment/spam
bots, feed readers, and uptime monitors. It also flags clients pretending to be
something they're not -- a datacentre IP wearing a desktop browser's User-Agent
(`spoofed_browser`), or one that fails crawler verification (`impersonator`) --
and is honest about the clients it can't characterise, which land in `unknown`.

## Install

```
pipx install agent-census
```

## Use

The simplest case -- analyse an Apache log in the default `combined` format:

```
agent-census analyze /var/log/apache2/access.log
```

You can pass several rotated logs at once; they're pooled into one analysis, so
a client spanning the rotation is counted once:

```
agent-census analyze /var/log/httpd/access.log*
```

If your server uses a custom format, pass the `LogFormat`/`CustomLog` directive
string verbatim (the same string from your Apache config). Tab separators
(`\t`), quoted fields containing spaces, `%{...}x` SSL variables, and `%{...}e`
environment variables are all handled:

```
agent-census analyze access.log \
    --log-format '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i" %D'
```

There are presets (`common`, `combined`, `vhost_combined`) via
`--log-format-preset` so you needn't type the common ones. Options may appear
before, after, or between the log files.

Output is Markdown by default; pass `--html` for a self-contained, styled page
(one file, no external assets) you can open in a browser. Both work for `analyze`
and `inspect`:

```
agent-census analyze access.log --html -o census.html
```

The report leads with a summary of each kind, then a cross-tab of where each
kind's traffic came from (see [Networks and hosting](#networks-and-hosting)),
then the notable clients within each kind.

### robots.txt compliance

To check whether clients respect `robots.txt`, give it the file. A local copy is
the default, because it should match the period the log covers:

```
agent-census analyze access.log --robots-file ./robots.txt
```

You can fetch it live instead by naming a host or URL -- doing so opts into the
fetch. A live `robots.txt` may not match the rules that were in force when the
log was written, so the report says so:

```
agent-census analyze access.log --host example.com
```

The summary's robots column reads `N✓ / M✗ / K?`: respected the rules, ignored
them, or made too few requests to tell (a client that simply hasn't wandered
into a disallowed area yet isn't credited either way).

### Verifying declared crawlers

A client can claim to be Googlebot in its User-Agent for free. The real check is
the client's IP: membership in a crawler's published address ranges, or
reverse/forward DNS for crawlers that rely on it. It runs **by default** (it
makes network calls -- DNS lookups and the occasional ranges fetch); turn it off
for a fully offline, faster run:

```
agent-census analyze access.log --no-verify-bots
```

A confirmed crawler's many IPs collapse into one entry keyed by its domain.
A client claiming a crawler whose IP is out of the published ranges (or whose
reverse DNS doesn't check out) is classed `impersonator`. Even with verification
off, a "Googlebot" that probes for `/.env` is still flagged `impersonator` from
its behaviour alone.

### Networks and hosting

A client's origin network is part of its story: a "browser" arriving from a
datacentre rather than a consumer ISP is almost certainly automation in
disguise. agent-census recognises the major cloud and hosting providers (AWS,
Google Cloud, Cloudflare, Hetzner, ...) by their published IP ranges, folds
shared-egress traffic (iCloud Private Relay, Tor) into one entry per network,
and reports a kind-by-network cross-tab so you can see what comes from where. In
the HTML report that table is interactive: toggle between raw counts, share of
each kind, and share of each network, with the busy cells shaded.

Range lists are fetched and cached weekly by default; `--no-fetch-ranges` stays
offline on the bundled data.

If your log carries the client's autonomous-system details -- e.g. from
MaxMind's `mod_maxminddb` as `%{MM_ASORG}e` (the organisation) and `%{MM_ASN}e`
(the number), quoted in your `LogFormat` -- datacentre clients are named by their
hosting organisation, and you can list extra AS numbers to treat as datacentres
by editing the bundled `datacenter_ranges.toml`.

### Inspecting a client

When you want to see *why* something was classified the way it was, use
`inspect`. It dumps every signal that fired (including the runners-up), the
measured features, the `robots.txt` finding, and the actual request trace:

```
agent-census inspect access.log --kind vuln_scanner
agent-census inspect access.log --client 203.0.113.66
agent-census inspect access.log --kind scraper --network aws
```

`--network` filters by origin network (a substring of its name) and composes
with `--kind`, so the two together drill into a single cell of the cross-tab.

### Identity

Grouping requests into clients is the assumption everything else rests on, and
no single rule is right for every deployment. The default, `ip_ua`, groups by
(IP, User-Agent). Behind a CDN you'll want `forwarded` (which trusts the
left-most `X-Forwarded-For`); for IP-rotating bots in one range,
`ip_ua_subnet`. The report notes how the chosen strategy fragmented or merged
the data so you can tell whether it fit.

```
agent-census analyze access.log --identity forwarded
```

### Remembered settings

A few options are sticky, so you needn't retype them: `--log-format` /
`--log-format-preset`, `--identity`, and `--robots-file` / `--robots-url` are
saved to `~/.config/agent-census/config.json` and reused on later runs that omit
them. Passing one updates the saved value.

## How it works

agent-census classifies by *behaviour*, not just the User-Agent string -- which
is trivially forged. Each client's requests are reduced to a set of measured
features (request volume, status mix, timing regularity, sub-resource
co-loading, path coverage, and so on), and a set of independent classifiers vote
on what the client is, each with a confidence and a list of human-readable
reasons. The strongest vote wins, or `unknown` when nothing clears a threshold;
secondary tags (`verified`, `ignores-robots`, `datacenter`, `has-cache`, ...)
annotate the verdict.

A word of caution: the confidence weights and the unknown-threshold are
hand-tuned starting points, not gospel. Sanity-check the classifications on your
own logs before trusting the headline percentages -- and `inspect` is there to
show you exactly why any client landed where it did.

## Contributing

Contributions are welcome -- see [CONTRIBUTING.md](CONTRIBUTING.md) for the
development setup, conventions, and a sketch of how the code is structured.
