# agent-census

*What's hitting your site, classified by how it behaves -- not just what it claims to be.*

Most of the traffic to a typical site isn't people; it's software, and a fair bit
of it lies about what it is. agent-census reads your access log and sorts the
clients by what they actually do -- whether they pull a page's sub-resources like
a browser, walk the site like a crawler, poll a feed on a schedule, or go looking
for known-vulnerable paths. Anything claiming to be a known crawler is checked
against DNS and published address ranges, so a Googlebot arriving from some random
datacentre gets called what it is. What you end up with is your traffic broken
down by what each client is for. The User-Agent still counts -- it's just treated
as a claim to weigh against behaviour and origin, not a fact to take on trust.

[Here's a sample report](https://projects.mnot.net/agent-census/) generated from a real access log.

## Install

[pipx](https://pipx.pypa.io/stable/) is recommended:

```
pipx install agent-census
```

## Use: Analysis

The simplest case is analyzing one or more Apache logs in the default `combined` format:

```
agent-census analyze access.log* > census.html
```

Several rotated logs are pooled into one analysis. You can pass them in any order
(a shell glob is fine): each file is peeked and the set is sorted into
chronological order before analysis, so a client spanning rotations is treated as
one and timing metrics see requests in time order. Plain and `.gz` files mix
freely.

The presets `common`, `combined`, and `vhost_combined` are available via
`--log-format-preset`.

For a **custom log format**, pass the `LogFormat`/`CustomLog` directive string verbatim
from your Apache config. Tab separators (`\t`), quoted fields with spaces,
`%{...}x` SSL variables, and `%{...}e` environment variables are all handled:

```
agent-census analyze access.log \
    --log-format '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i" %D'
```

See "What to log" below for the most important information to gather.

**Cloudflare Logpush logs** (newline-delimited JSON) are also supported, as another
preset:

```
agent-census analyze cloudflare-logs.json --log-format-preset cloudflare
```

### Options

*Use `agent-census analyze -h` for the full list of analysis options.*

**robots.txt compliance**: Use `--robots-file` to supply a local file, hostname, or URL:

```
agent-census analyze access.log --robots-file ./robots.txt
```

**Output format**: Output is a self-contained HTML page by default; redirect it with `-o`, or pass
`--md` for Markdown:

```
agent-census analyze access.log -o census.html
agent-census analyze access.log --md
```

**Browsable per-client detail**: when an HTML report is written to a file (`-o`),
each client is clickable — a click opens its full trace and classification
rationale in-page, no separate `inspect` run needed. The per-client files are
written to a directory named after the report (`census.html` →
`census.inspect/`), which the report links to. This is on by default;
`--no-inspect-data` skips it (and its per-client trace capture):

```
agent-census analyze access.log -o census.html
# writes census.html and its sibling census.inspect/ directory
agent-census analyze access.log -o census.html --no-inspect-data
# just census.html, no per-client data
```

The report and its `<name>.inspect/` directory travel together — serve or move
them as a pair. Because the directory is named after the report:

* **Re-running the same report** (e.g. a cron job to `census.html`) overwrites
  `census.inspect/`, pruning files for clients that no longer appear — so disk
  use tracks the latest run, not the sum of all runs.
* **Keeping history** needs nothing special: write to a dated name
  (`census-2024-06-01.html`) and each run gets its own `…inspect/` directory,
  leaving earlier ones untouched.
* **Several reports in one folder** don't collide — each has its own directory.

Serve the report over HTTP (the in-page view fetches the data files); a report
opened as a local file, or one built with `--no-inspect-data`, still copies a
client's id on click, as before.

**Host header filtering**: `--vhost SUBSTRING` analyses only the lines served for a matching host:

```
agent-census analyze access.log --log-format-preset vhost_combined \
    --vhost mnot.net --vhost www.mnot.net
```

**Time window**: `--since` limits the analysis to recent traffic (e.g. `1w`, `36h`,
`90m`; units `s`/`m`/`h`/`d`/`w`). A log file that falls entirely outside the
window is skipped without being read — and the count of skipped files is reported
so it's never a silent omission. The window is anchored at the current time by default; for
archived logs whose newest entry is itself in the past, add `--from-latest` to
anchor it at the newest timestamp in the logs instead.

```
agent-census analyze access.log* --since 1w
agent-census analyze archive/access.log.*.gz --since 1w --from-latest
```

**Client identity**: Use `--identity` to change how requests are associated with clients. The
default, `ip_ua`, groups by (IP, User-Agent). Behind a CDN, use `forwarded` (the left-most
`X-Forwarded-For`); for IP-rotating bots in one range, `ip_ua_subnet`.

```
agent-census analyze access.log --identity forwarded
```

**AS lookups**: If your logs don't record the AS number, point `--mm-asn-db` at a [MaxMind ASN
database](https://dev.maxmind.com/geoip/docs/databases/asn/) to recover it from each client's IP.
The database is consulted first (it can be fresher than the log) and is remembered between runs:

```
agent-census analyze access.log --mm-asn-db ./GeoLite2-ASN.mmdb
```

**Country flags**: point `--mm-country-db` at a [MaxMind country (or city)
database](https://dev.maxmind.com/geoip/docs/databases/country/) to show a small flag next to
the highest-traffic non-human clients we *haven't* tied to a specific operator — an unknown
scraper or an impersonator, where the origin country adds signal (a verified, IP/rDNS-identified
crawler gets none). For a client spanning many IPs the flag is its **traffic-majority** country;
a client with no country above 70% of its traffic shows a neutral 🌐 instead. In HTML the flag
carries the country name as a tooltip and each address gets its own flag on expansion. Also
remembered between runs:

```
agent-census analyze access.log --mm-country-db ./GeoLite2-Country.mmdb
```

**A directory of databases**: if you keep your `.mmdb` files in one place (e.g. a
[`geoipupdate`](https://github.com/maxmind/geoipupdate) target), point `--mm-db-dir` at it and
both databases are picked up automatically — by each file's metadata, so it doesn't matter what
they're named or which vendor they're from. An explicit `--mm-asn-db` / `--mm-country-db` still
wins for that one role.

```
agent-census analyze access.log --mm-db-dir /usr/share/GeoIP
```

### Remembered settings

Some options are sticky, so you needn't retype them. `--log-format` /
`--log-format-preset`, `--identity`, and `--robots-file` / `--robots-url` are
saved to `~/.config/agent-census/config.json` and reused when a later run omits
them; the MaxMind database paths (`--mm-asn-db` / `--mm-country-db` / `--mm-db-dir`)
are remembered the same way, as noted with their own options above. Passing one
updates the saved value, and a run prints a `note:` naming what it saved and its
scope. Use `--config PATH` to read and write a different settings file (handy for
a checked-in, per-project config).

`--no-persist` keeps a run from writing anything: saved settings (and a
`--site`) are still read and applied, but nothing is stored — for one-off runs,
scripts and CI, or trying a setting without disturbing the saved config.

**Per-site settings.** If you analyse more than one site, `--site NAME` keeps
their settings apart. Each site remembers its own log files, `--vhost` filter,
log format, identity, robots source, and output path (`-o`, kept separately per
command), so after seeding a site you can analyse it by name alone:

```sh
# seed the site: its settings, log files, and vhost filter are saved under "blog"
agent-census analyze /var/log/access.log* --site blog \
    --vhost blog.example --robots-file /srv/blog/robots.txt

# later runs need only the name
agent-census analyze --site blog
```

A site's settings override the global defaults; anything passed on the command
line overrides the site (and is remembered under it). Resolution is
**command line → site → defaults**.

What goes per-site vs. global follows what a setting *describes*:

- **Per-site** — settings that describe the site's data: which log files are it,
  which `--vhost` lines are it, how they're formatted, and its robots policy. A
  saved log file that has since rotated away is skipped with a note rather than
  failing the run, so a site's list can name rotated logs that come and go.
- **Global** — settings that describe this machine or account: the Cloudflare API
  token and the MaxMind database paths. These are the same whatever site you look
  at, so they always live in the defaults.

The preference-style keys (log format, identity, robots source) can also be set
*without* `--site` to give a global baseline that any site inherits until it
sets its own. The "which data" keys (log files, `--vhost`) only ever attach to a
site — a global default there would silently filter unrelated runs. The output
path (`-o`) is the same: it's remembered only under a named site (and per
command, so `analyze` and `inspect` don't share a destination), so a run without
`--site` still writes to stdout and never silently overwrites a file.



## Use: Inspecting a client

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

`inspect` emits Markdown. For the same detail browsable from the report itself,
write the HTML report to a file (`-o`) and click a client (see `--inspect-data`
above).

*Most analyze options apply; see `agent-census inspect -h` for a full list of options.*



## What to log

The Apache `combined` format already carries everything the core analysis needs.
The `common` preset drops the User-Agent and the Referer, so prefer `combined`,
or a custom format that includes them.

Required (all present in `combined`):

- **Client address** (`%h`) -- the identity everything else groups on, and the
  basis for the network, datacentre, and crawler-verification checks.
- **Timestamp** (`%t`) -- timing regularity, peak request rate, the reported time
  range, ordering and `--since` windowing across multiple files, and (with
  `--quiescent-hours`) freeing memory mid-run.
- **Request line** (`"%r"`) -- the method and path; the most load-bearing field,
  behind vulnerability probing, feed detection, path coverage, and crawl shape.
- **Status code** (`%>s`) -- the status mix, 404 storms, `304 Not Modified` (the
  `has-cache` tag), and robots.txt compliance.
- **User-Agent** (`"%{User-Agent}i"`) -- browser, bot, and declared-crawler
  recognition.

**Strongly Recommended**. The first two are already in `combined`; the rest aren't in any
preset, so add them to a custom `LogFormat` (quoted) -- they're worth it:

- **Referer** (`"%{Referer}i"`, in `combined`) -- referer-following, which
  separates crawlers from scrapers and flags fabricated referers.
- **Bytes sent** (`%b` or `%B`, in `combined`) -- the bandwidth figures in the
  report.
- **AS organisation and number** (`"%{MM_ASORG}e"` and `"%{MM_ASN}e"`, MaxMind
  `mod_maxminddb`) -- name datacentre clients by their hosting organisation, and
  recognise datacentres and ASN-listed crawlers by AS number. Much of
  [Networks and hosting](#networks-and-hosting) leans on these; log **both** (the
  number drives recognition, the org names it). Can't log them? `--mm-asn-db`
  recovers the AS from a MaxMind database instead (see [Options](#options)).
- **Content-Type** (`"%{Content-Type}o"`) -- the response media type, which
  sharpens feed-reader detection (an RSS/Atom type, not just a feed-shaped URL).
- **X-Forwarded-For** (`"%{X-Forwarded-For}i"`) -- if you're behind a CDN or
  proxy, for `--identity forwarded`.
