# agent-census

A command-line tool that reads a Web server access log and characterises the
*clients* hitting your site: it identifies each distinct client, works out what
it's there to do, checks whether it respects `robots.txt`, and reports the
prevalence and resource use of each kind. Output is Markdown.

It distinguishes browsers, crawlers, declared search/preview bots (Googlebot and
friends), AI crawlers (GPTBot, ClaudeBot, ...), scrapers, vulnerability
scanners, comment/spam bots, feed readers, and uptime monitors -- and is honest
about the clients it can't characterise, which land in `unknown`.

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

Output is Markdown by default; pass `--html` for a self-contained, styled HTML
page (one file, no external assets) that you can open in a browser. It works for
both `analyze` and `inspect`:

```
agent-census analyze access.log --html -o census.html
```

### robots.txt compliance

To check whether clients respect `robots.txt`, give it the file. A local copy is
the default, because it should match the period the log covers:

```
agent-census analyze access.log --robots-file ./robots.txt
```

You can fetch it live instead, but that's opt-in -- a live `robots.txt` may not
match the rules that were in force when the log was written, so the report says
so loudly:

```
agent-census analyze access.log --host example.com --fetch-robots
```

### Verifying declared crawlers

A client can claim to be Googlebot in its User-Agent for free. The real check is
DNS: reverse-resolve the IP and forward-confirm it. That makes network calls, so
it's opt-in:

```
agent-census analyze access.log --verify-bots
```

Without it, a "Googlebot" that probes for `/.env` still gets flagged
`impersonator` from its behaviour alone.

### Inspecting a client

When you want to see *why* something was classified the way it was, use
`inspect`. It dumps every signal that fired (including the runners-up), the
measured features, the `robots.txt` finding, and the actual request trace:

```
agent-census inspect access.log --kind vuln_scanner
agent-census inspect access.log --client 203.0.113.66
```

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

## How it works

The pipeline is **parse -> group into clients -> extract features -> classify ->
report**. Parsing normalises every log line into a common record, so support for
other servers (nginx, ...) is a matter of adding a parser; nothing downstream
changes.

Classification is deliberately modular: each kind has its own classifier that
reads only the measured features and votes with a confidence and a list of
human-readable reasons. A combiner picks the strongest vote (or `unknown` below
a threshold) and layers on secondary tags (`respects-robots`, `verified`,
`impersonator`, ...). Each classifier lives in its own file under
`agent_census/classify/` and can be read, tested, and evolved on its own.

A word of caution: the confidence weights and the unknown-threshold are
hand-tuned starting points, not gospel. Sanity-check the classifications on your
own logs before trusting the headline percentages.

## Development

Standard `make` targets: `make venv` (set `PY` to your Python), `make test`,
`make lint`, `make typecheck`, `make tidy`.
