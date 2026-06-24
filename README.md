# agent-census

agent-census reads a Web server access log and works out who's been hitting your
site. It groups the requests into distinct clients, classifies each one by how it
behaves, checks whether it respects `robots.txt`, and reports how much of your
traffic each kind accounts for. Output is Markdown, or a self-contained HTML page.

The kinds it knows include browsers, crawlers, search engines, social-preview
fetchers, AI crawlers (GPTBot, ClaudeBot), archivers (Internet Archive, Common
Crawl), SEO and marketing crawlers, scrapers, vulnerability scanners, spam bots,
feed readers, and uptime monitors. Two kinds cover clients pretending to be
something else: `spoofed_browser` (a datacentre IP presenting a desktop browser
User-Agent) and `impersonator` (one that fails crawler verification). Anything it
can't classify with confidence is `unknown`.

## Install

```
pipx install agent-census
```

## Use

The simplest case is an Apache log in the default `combined` format:

```
agent-census analyze /var/log/apache2/access.log
```

You can pass several rotated logs at once. They're pooled into one analysis, so a
client that spans the rotation is counted once:

```
agent-census analyze /var/log/httpd/access.log*
```

For a custom format, pass the `LogFormat`/`CustomLog` directive string verbatim
from your Apache config. Tab separators (`\t`), quoted fields with spaces,
`%{...}x` SSL variables, and `%{...}e` environment variables are all handled:

```
agent-census analyze access.log \
    --log-format '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i" %D'
```

The presets `common`, `combined`, and `vhost_combined` are available via
`--log-format-preset`. Options may appear before, after, or between the log files.

Output is Markdown by default. Pass `--html` for a self-contained, styled page
(one file, no external assets) you can open in a browser. Both formats work for
`analyze` and `inspect`:

```
agent-census analyze access.log --html -o census.html
```

The report opens with a summary of each kind, then a cross-tab of where each
kind's traffic came from (see [Networks and hosting](#networks-and-hosting)),
then the notable clients in each kind.

### robots.txt compliance

To check `robots.txt` compliance, give agent-census the file. A local copy is the
default, since it should match the period the log covers:

```
agent-census analyze access.log --robots-file ./robots.txt
```

Naming a host or URL instead fetches it over the network. A live `robots.txt` may
not match the rules that applied when the log was written, so the report flags it:

```
agent-census analyze access.log --host example.com
```

The summary's robots column reads `N✓ / M✗ / K?`: respected, ignored, or too few
requests to tell (a client that hasn't yet requested a disallowed path isn't
counted either way).

### Verifying declared crawlers

A User-Agent claiming Googlebot proves nothing on its own. Verification checks the
client's IP against the crawler's published address ranges and its reverse/forward
DNS. It runs by default and makes network calls (DNS lookups, and the occasional
ranges fetch); turn it off for an offline, faster run:

```
agent-census analyze access.log --no-verify-bots
```

A verified crawler's IPs collapse into one entry keyed by its domain. A client
whose IP is outside the published ranges, or whose reverse DNS doesn't check out,
is classed `impersonator`, which means a forged identity that verification has
disproved. Misbehaviour is separate: a "Googlebot" that probes for `/.env` keeps
its declared kind and gets a `probing` tag (and `ignores-robots` if it earns one),
because a real crawler can still behave badly. With verification off there's
nothing to disprove the claim, so it stays a declared crawler with those tags.

### Networks and hosting

Where a client comes from matters. A "browser" arriving from a datacentre rather
than a consumer ISP is usually automation. agent-census recognises the major
cloud and hosting providers (AWS, Google Cloud, Cloudflare, Hetzner) from their
published IP ranges, folds shared-egress traffic (iCloud Private Relay, Tor) into
one entry per network, and breaks the kinds down by origin network in a cross-tab.
In the HTML report that table is interactive: switch between raw counts, share of
each kind, and share of each network, with the busier cells shaded.

Range lists are fetched and cached weekly by default. `--no-fetch-ranges` stays
offline on the bundled data.

If your log carries the client's autonomous-system details (for example from
MaxMind's `mod_maxminddb`: `%{MM_ASORG}e` for the organisation and `%{MM_ASN}e`
for the number, quoted in your `LogFormat`), datacentre clients are named by their
hosting organisation. You can also list extra AS numbers to treat as datacentres
in the bundled `datacenter_ranges.toml`.

### Inspecting a client

To see why a client was classified the way it was, use `inspect`. It shows every
signal that fired (including the runners-up), the measured features, the
`robots.txt` finding, and the request trace:

```
agent-census inspect access.log --kind vuln_scanner
agent-census inspect access.log --client 203.0.113.66
agent-census inspect access.log --kind scraper --network aws
```

`--network` matches a substring of the origin-network name and composes with
`--kind`, so the two together select a single cell of the cross-tab.

### Identity

How requests are grouped into clients is configurable, since no single rule fits
every deployment. The default, `ip_ua`, groups by (IP, User-Agent). Behind a CDN,
use `forwarded` (the left-most `X-Forwarded-For`); for IP-rotating bots in one
range, `ip_ua_subnet`. The report notes how the chosen strategy fragmented or
merged the data, so you can judge whether it fit.

```
agent-census analyze access.log --identity forwarded
```

### Remembered settings

Some options are sticky, so you needn't retype them. `--log-format` /
`--log-format-preset`, `--identity`, and `--robots-file` / `--robots-url` are
saved to `~/.config/agent-census/config.json` and reused when a later run omits
them. Passing one updates the saved value.

## How it works

Classification is based on behaviour, not just the User-Agent (which is easy to
forge). Each client's requests are reduced to measured features: request volume,
status mix, timing regularity, sub-resource co-loading, path coverage, and the
like. A set of independent classifiers each vote for a kind, with a confidence and
the reasons behind it. The strongest vote wins, or `unknown` if nothing clears a
threshold. Secondary tags such as `verified`, `ignores-robots`, `datacenter`, and
`has-cache` annotate the result.

The confidence weights and the threshold are hand-tuned, so check the
classifications against your own logs before trusting the headline numbers.
`inspect` shows why any client landed where it did.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
development setup, conventions, and an outline of how the code fits together.
