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
confidence and a list of human-readable reasons. A combiner aggregates the votes
into a primary kind plus secondary tags. Each classifier can be read, tested,
and evolved on its own -- usually the easiest place to start.

The confidence weights and the unknown-threshold are hand-tuned starting points;
calibrating them against real, labelled logs is one of the more valuable things
a contributor can do.

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

