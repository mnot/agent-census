# Contributing

Contributions - in the form of code, bugs, or ideas - are very welcome!

## Intellectual Property

By contributing code, bugs or enhancements to this project (whether that be through pull requests, the issues list, e-mail or other means), you are licensing your contribution under the [project's terms](LICENSE.md).


## How the Code is Structured

The pipeline is **parse → group into clients → extract features → classify →
report**. Parsing normalises every log line into a common record, so adding
support for another server (nginx, ...) is a matter of writing a parser and
registering it; nothing downstream changes.

Classification is deliberately modular: each kind lives in its own file under
`agent_census/classify/`, reads only the measured features, and votes with a
confidence. A combiner aggregates the votes into a primary kind plus secondary
tags. Each classifier can be read, tested, and evolved on its own -- usually the
easiest place to start.

[`SPEC.md`](SPEC.md) is the authoritative account of *how every tag and every
classification is derived* -- the classifiers, the combiner, and the shared
predicates that tie them together, each cross-linked to the tuning knob that
sets it. Read it before changing classification behaviour, and keep it in step
with any change you make.

## Coding Conventions

We use [isort](https://pypi.org/project/isort/) and [black](https://pypi.org/project/black/) for Python formatting, which can be run with `make tidy`.

All Python functions and methods need to have type annotations. See `.pylintrc` and `mypy.ini` for specific pylint and mypy settings.


## Setting up a Development Environment

It should be possible to use a modern Unix-like environment, provided that a recent release of Python is installed.

Thanks to [Makefile.venv](https://github.com/sio/Makefile.venv), a Python virtual environment is set up and run each time you use `make`. As long as you use `make`, Python dependencies will be installed automatically.

Helpful make targets include:

* `make shell` - start a shell in the Python virtual environment
* `make python` - start an interactive Python interpreter in the virtual environment
* `make lint` - run pylint
* `make typecheck` - run mypy to check Python types
* `make tidy` - format Python source
* `make test` - run the tests


## Before you Submit

The best way to submit a change is through a pull request. A few things to keep in mind when you're doing so:

* Run `make tidy`.
* Check your code with `make lint` and address any issues found.
* Check your code with `make typecheck` and address any issues found.
* Every new feature should have a test covering it.

If you're not sure how to dig in, feel free to ask for help, or sketch out an idea in an issue first.


## Calibrating the Classifier

The confidence weights and thresholds are hand-tuned, so they need checking
against real logs. `agent-census calibrate` emits a Markdown digest of the
traffic most likely to be misclassified -- a tuning aid, not the human report.
Each section is capped (`--top`), and it keeps every client in memory, so it's
heavier than `analyze`. It surfaces:

* **Unrecognised ASNs** -- clients with an AS number that matched no list and
  fell to residential. High-volume, non-browser ones are candidates for the ASN
  lists; feed them into `audit --asn`.
* **Declared but unverified crawlers** -- self-identified bots we couldn't
  confirm, split into recognised-but-unverified and wholly unrecognised.
* **Anomaly / spoof flags** -- every client tagged as forged or hostile. Scan for
  false positives: a real client flagged here is a heuristic bug.
* **Browser identification quality** -- version-age bands and regex gaps (browser
  UAs we couldn't read a version from), plus tells like a browser UA from a
  datacentre or one that loaded no assets.
* **Singletons, unknown clusters, and conflicting signals** -- one-request
  clients, traffic the combiner couldn't place, and clients where two classifiers
  fired strongly for different kinds.


## Auditing Data

`agent-census audit` audits the packaged data -- currently, the datacentre/ASN
associations. It cross-checks every listed `(provider, ASN)` pair against three
external sources:

* **Cloudflare Radar** -- source for an AS's organisation name
  and its sibling ASNs, and (via the bot-class endpoint) an automated-vs-human
  traffic split. That split is the *datacentre signal*: a real datacentre's
  egress is overwhelmingly automated, so a listing well below the threshold is
  suspect -- it may be an eyeball ISP, or an egress / VPN network. Needs a free
  Radar API token, passed with `--token` or `$CF_API_TOKEN` (it's then persisted
  to your config).
* **RIPEstat** (`as-names`) -- the RIR-registered holder, used as a second opinion
  on the name. The registry handle often keeps the brand we listed even after the
  org has been renamed to its new parent (e.g. `AKAMAI-LINODE-AP - Akamai
  Connected Cloud`), so it's good at telling a genuine mislabelling from a
  rebrand.
* **PeeringDB** -- a weak network-type hint (`NSP`, `Content`, ...).

All responses are cached by URL for a week (atomic write), so re-running the
audit -- or iterating on its output -- doesn't re-hit the APIs.

Pass one or more ASNs with `--asn` to get the same assessment for arbitrary
candidates (handy for triaging the unrecognised networks that
`agent-census calibrate` turns up).


## Validating a Web Bot Auth Setup

`agent-census wba-check HOST` is a diagnostic for the *other* side of Web Bot
Auth -- not verifying a client's signed requests (`wba.py`, driven by
`--verify-bots`), but checking that an operator's own key directory is set up
correctly before adding them to `data/agents/web_bot_auth.toml`.

It fetches `HOST/.well-known/http-message-signatures-directory` and checks
it's reachable over HTTPS, is valid JSON with a `keys` array, and that each
Ed25519 key's declared `kid` (if present) actually matches its RFC 7638
thumbprint -- the value agent-census's verifier keys its key store on, not
whatever `kid` the directory happens to label the key with. A mismatch there
means a signature naming the operator's own declared `kid` wouldn't be found;
only one naming the recomputed thumbprint would.

On success it prints a ready-to-paste `[[operator]]` entry (`agent_urls` +
`keyids`) for `data/agents/web_bot_auth.toml`. It's not a conformance test for
the directory draft -- just enough to catch the mistakes that would keep a
signed request from that host from verifying.

