# Signature match-lists

These TOML files are the string markers the classifiers and feature extraction
match against -- User-Agent tokens and request paths. They are descriptive, not
verdicts: a hit only *starts* an argument that behaviour then corroborates (a UA is
trivially forged). Editing a list changes what is recognised; no code change is
needed. Matching is case-insensitive throughout.

The full rationale for each list lives in its file's header comment; this is the
map.

## Descriptive feature inputs

These two feed the per-request feature extraction shared by every classifier, each
grouped into `[section]` tables holding named arrays:

- **`ua_signatures.toml`** -- how a UA string is read for identity (see
  `agent_census/uas.py`): whether it looks like a browser (`[browser]`), declares
  itself automation (`[automation]`), names a headless engine (`[headless]`) or a
  bare HTTP library (`[http_library]`), or carries feed vocabulary
  (`[feed_reader]`). The `[automation]` tokens are split by how they must sit in the
  string -- `substrings` (anywhere), `standalone_words` (word boundary both sides,
  so "feed" doesn't fire inside "feedback"), `suffix_words` (right boundary only, so
  "bot" matches "Googlebot" but not "robots").
- **`request_signatures.toml`** -- markers read off the request line (see
  `agent_census/features.py`): static-asset vs. page extensions (the co-load and
  breadth anchors), `path_traversal` / `encoding_evasion` markers, `methods` a
  browser never issues, and how a `feed_urls` poll is spotted from the path.

## Corroborating substring lists

Flat or two-bucket lists, each keyed by its file name, that corroborate one
classifier when a token matches:

- **`vuln_paths.toml`** -- path substrings that indicate probing, in two buckets so
  the list auto-tunes per site: `always_probe` (secret files, RCE drops, traversal
  -- hostile regardless of response status) and `probe_if_absent` (real paths on
  sites running WordPress / phpMyAdmin / Spring Boot / Exchange -- a hit counts only
  on a 404/410, i.e. the client is guessing at software this site doesn't run).
- **`scanner_ua.toml`** -- UA tokens naming a scanning / pentest / measurement tool;
  corroborates `vuln_scanner`.
- **`monitor_uas.toml`** -- UA tokens naming an uptime / monitoring service;
  corroborates the `monitor` classifier.
- **`submit_paths.toml`** -- submission-endpoint URL substrings (comment forms,
  login, xmlrpc) that comment/form spam and other submission-endpoint abuse aims
  at; corroborates `spam_bot`.
- **`app_clients.toml`** -- UA substrings for native-app HTTP clients (platform
  networking stacks, app frameworks): not a browser and not a crawler.
- **`feed_readers.toml`** -- feed-reader product-name UA substrings; corroborates
  the behavioural feed detection (the generic feed *vocabulary* lives in
  `ua_signatures.toml`'s `[feed_reader]`).

Each list must be non-empty: an empty array would compile to a match-everything
regex at the call site, so a missing or emptied list is rejected at load time.
