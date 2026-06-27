# Classifier tuning

These TOML files hold the numeric knobs behind classification: the confidence
weights each classifier adds when a signal fires, and the thresholds at which a
signal fires. They are deliberately separate from the *lists* in the parent
directory (which agents/networks to recognise) -- here it is purely "how much does
this signal count, and where is its line drawn".

There is one file per classifier, named for it (`browser.toml`, `crawler.toml`,
`vuln_scanner.toml`, …), plus `tags.toml` for the secondary-tag thresholds and
`combiner.toml` for how signals are aggregated into a verdict. Each file is grouped
into one block per signal, so a signal's threshold and its weight sit together; the
header comment in each file explains the rules of thumb for tuning it.

`shared.toml` holds the thresholds used by more than one classifier or tag -- the
browser-shape cutoffs, the cadence bands, the 404-storm and fabricated-referer lines,
and the unknown-verdict threshold. They live there once so that tuning, say, "what
counts as browser-like" moves every consumer together instead of drifting between
private copies. A threshold only one classifier uses stays in that classifier's file.

Every knob a file's classifier reads must be present and numeric; an unexpected table
or key, a missing knob, or a non-number is rejected at load time, so a file is always
the complete, accurate list of that classifier's knobs. (The relative-magnitude tags
keep their own calibration knobs in `../relative_tags.toml`.)
