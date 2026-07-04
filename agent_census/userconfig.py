"""Persisted CLI defaults under ``~/.config/agent-census/config.json``.

A handful of options (the log format, identity strategy, robots source, and the
log files themselves) are sticky: the value you last passed is remembered and
reused on later runs that omit it, so you needn't retype them every time.

Settings live in two scopes. Global *defaults* apply to every run; a named
**site** block overrides them for that site (selected with ``--site NAME``).
The effective value for a run is: CLI argument, else the site block, else the
defaults.

The split follows what a setting *describes*. A setting that describes the
site's data -- where its logs live, which vhost lines are it, how they're
formatted, its robots policy -- is per-site. A setting that describes this
machine or account -- the API token, the MaxMind database paths -- is always
global. (Per-run options like the time window or output path aren't persisted at
all.) The preference-style per-site keys (log format, identity, robots source)
may also sit in ``defaults`` as a baseline a site inherits until it overrides;
the "which data" keys (log files, vhost) only ever live under a site.

JSON, not TOML, so it can be both read and written with only the standard
library. The on-disk shape (version 2)::

    {"version": 2,
     "defaults": { ...global keys... },
     "sites": {"mysite": { ...per-site keys... }}}

A legacy flat file (a bare object of keys, no ``version``) is read as the
defaults block, so older configs keep working, and is rewritten in the current
shape on the next run. Any other shape (a newer ``version``, or non-object JSON)
is reported once and treated as empty.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ConfigError

CONFIG_VERSION = 2

# Sticky string keys that a per-site block may override.
SITE_STR_KEYS = ("log_format", "log_format_preset", "identity", "robots_file", "robots_url")
# Sticky string keys that are machine-level and always live in the defaults block.
GLOBAL_STR_KEYS = ("cf_api_token", "mm_asn_db", "mm_country_db", "mm_db_dir")
# All persisted string keys (the union). cf_api_token is a secret, so the file is
# written 0600 (see ConfigStore.save()).
PERSISTED = SITE_STR_KEYS + GLOBAL_STR_KEYS
# Sticky list-valued keys (per-site only): the log files to analyse for a site,
# and the vhost filter terms that pick its lines out of a shared log.
SITE_LIST_KEYS = ("logfiles", "vhost")

# Mutually exclusive alternatives: naming one in a higher-precedence layer masks
# the whole group from lower layers, so a site's robots choice fully supersedes a
# global one even when they picked the other member of the pair.
_ALTERNATIVE_GROUPS = (
    ("log_format", "log_format_preset"),
    ("robots_file", "robots_url"),
)


def config_path(override: Path | None = None) -> Path:
    """Location of the settings file (``--config`` override, else ``$XDG_CONFIG_HOME``)."""
    if override is not None:
        return override
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "agent-census" / "config.json"


def _clean_block(block: object) -> dict[str, object]:
    """Keep only recognised keys with the right value type; drop the rest."""
    if not isinstance(block, dict):
        return {}
    out: dict[str, object] = {}
    for key, value in block.items():
        if key in PERSISTED and isinstance(value, str):
            out[key] = value
        elif (
            key in SITE_LIST_KEYS
            and isinstance(value, list)
            and all(isinstance(item, str) for item in value)
        ):
            out[key] = list(value)
    return out


@dataclass
class ConfigStore:
    """Parsed settings: a global ``defaults`` block plus named ``sites`` blocks."""

    defaults: dict[str, object] = field(default_factory=dict)
    sites: dict[str, dict[str, object]] = field(default_factory=dict)
    path: Path = field(default_factory=config_path)
    # A human-readable note if the on-disk file had an unrecognised shape; the
    # CLI surfaces it once so a hand-edit or a newer format isn't silent.
    warning: str | None = None
    # True when read from a pre-versioning flat file; the CLI rewrites it in the
    # current shape on the next run so the file doesn't stay legacy indefinitely.
    legacy: bool = False

    def effective(self, site: str | None) -> dict[str, object]:
        """Merged read-view for ``site``: defaults overlaid with the site's block."""
        merged = dict(self.defaults)
        block = self.sites.get(site) if site else None
        if block:
            for group in _ALTERNATIVE_GROUPS:
                if any(member in block for member in group):
                    for member in group:
                        merged.pop(member, None)
            merged.update(block)
        return merged

    def site_scope(self, site: str | None) -> dict[str, object]:
        """The block that values passed with ``--site`` persist into (defaults if none)."""
        if site:
            return self.sites.setdefault(site, {})
        return self.defaults

    def save(self) -> bool:
        """Write the settings back; return whether the file was written.

        Refuses to write (and returns False) when ``warning`` is set: such a store
        is the empty fallback for an on-disk file we couldn't parse -- a newer
        ``version``, or a hand-edit -- and overwriting it would silently destroy
        content this build didn't understand. Genuine write failures are likewise
        swallowed (persistence is a convenience, not state) and reported as False.
        """
        if self.warning is not None:
            return False
        doc: dict[str, object] = {"version": CONFIG_VERSION, "defaults": self.defaults}
        # Drop any site blocks that ended up empty so the file stays tidy.
        sites = {name: block for name, block in self.sites.items() if block}
        if sites:
            doc["sites"] = sites
        payload = json.dumps(doc, indent=2) + "\n"
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # The file may hold an API token, so create it owner-only from the start:
            # a plain write-then-chmod leaves a window where a new file sits at the
            # umask default (typically world-readable) before the chmod lands. O_CREAT
            # with mode 0o600 closes that window; the trailing chmod also tightens a
            # pre-existing file that a prior version left at looser permissions.
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.chmod(self.path, 0o600)
        except OSError:
            return False
        return True


def load(override: Path | None = None) -> ConfigStore:
    """Return the parsed settings, or an empty store if none / unreadable."""
    path = config_path(override)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ConfigStore(path=path)
    if not isinstance(data, dict):
        # Valid JSON but not an object (a list, string, number, ...): a hand-edited
        # config shouldn't abort every run, so fall back to an empty store.
        return ConfigStore(path=path, warning=f"ignoring {path}: not a JSON object")
    if "version" in data or "defaults" in data or "sites" in data:
        version = data.get("version")
        if version != CONFIG_VERSION:
            return ConfigStore(
                path=path,
                warning=f"ignoring {path}: unrecognised config version {version!r} "
                f"(this build understands {CONFIG_VERSION})",
            )
        sites_raw = data.get("sites", {})
        sites = (
            {name: _clean_block(block) for name, block in sites_raw.items()}
            if isinstance(sites_raw, dict)
            else {}
        )
        return ConfigStore(
            defaults=_clean_block(data.get("defaults", {})),
            sites={name: block for name, block in sites.items() if block},
            path=path,
        )
    # Legacy flat file: the whole object is the defaults block.
    return ConfigStore(defaults=_clean_block(data), path=path, legacy=True)


def apply_persisted_settings(args: argparse.Namespace) -> None:
    """Fill sticky options from the config when unset; persist any passed now.

    Precedence is CLI argument, else the ``--site`` block, else the global
    defaults. A value passed this run is remembered: per-site keys (log format,
    identity, robots source, log files, vhost) under the named site when
    ``--site`` is given, else -- for the preference-style keys -- in the defaults;
    the API token and MaxMind paths are always global. Naming any robots source
    this run (including ``--host``) suppresses a restored one so it can't
    override. Raises ConfigError if, after resolution, no log files are available.
    """
    site = getattr(args, "site", None)
    store = load(getattr(args, "config", None))
    if store.warning:
        print(f"warning: {store.warning}", file=sys.stderr)
    cfg = store.effective(site)  # merged read-view: defaults overlaid with the site
    scope = store.site_scope(site)  # per-site keys persist here (defaults if no --site)
    gscope = store.defaults  # global keys always persist to the defaults block
    updated = False

    if args.log_format is not None:
        scope["log_format"], updated = args.log_format, True
        scope.pop("log_format_preset", None)
    elif args.log_format_preset is not None:
        scope["log_format_preset"], updated = args.log_format_preset, True
        scope.pop("log_format", None)
    elif cfg.get("log_format") is not None:
        args.log_format = cfg["log_format"]
    elif cfg.get("log_format_preset") is not None:
        args.log_format_preset = cfg["log_format_preset"]

    if args.identity is not None:
        scope["identity"], updated = args.identity, True
    elif cfg.get("identity") is not None:
        args.identity = cfg["identity"]

    passed_source = args.robots_file or args.robots_url or args.host
    if args.robots_file is not None:
        scope["robots_file"], updated = str(args.robots_file), True
        scope.pop("robots_url", None)
    elif args.robots_url is not None:
        scope["robots_url"], updated = args.robots_url, True
        scope.pop("robots_file", None)
    if not passed_source:
        if cfg.get("robots_file") is not None:
            args.robots_file = Path(str(cfg["robots_file"]))
        elif cfg.get("robots_url") is not None:
            args.robots_url = cfg["robots_url"]

    if _apply_site_list(args, cfg, scope, site, "logfiles", as_path=True):
        updated = True
    if _apply_site_list(args, cfg, scope, site, "vhost", as_path=False):
        updated = True

    if _apply_maxmind_settings(args, cfg, gscope):
        updated = True

    # Persist any change; also rewrite a legacy flat file in the current shape,
    # once, even when nothing changed this run (save() no-ops on an unreadable one).
    if updated or store.legacy:
        if store.save() and store.legacy:
            print("note: upgraded the saved config to the current format", file=sys.stderr)
    if args.identity is None:
        args.identity = "ip_ua"  # the built-in default when nothing is set or saved

    if not args.logfiles:
        if site:
            raise ConfigError(
                f"site {site!r} has no saved log files; pass one or more LOGFILE paths"
            )
        raise ConfigError("no log files given; pass one or more LOGFILE paths, or --site NAME")


def _apply_site_list(
    args: argparse.Namespace,
    cfg: dict[str, object],
    scope: dict[str, object],
    site: str | None,
    attr: str,
    *,
    as_path: bool,
) -> bool:
    """Persist/restore a per-site list option (log files, vhost filters).

    These describe *which data* a site is, so they only ever live under a site:
    passing values with ``--site`` remembers them there; passing them without a
    site uses them for this run but saves nothing (there is no site to attach them
    to, and a global default here would silently filter every later run). An empty
    value falls back to the site's saved list. Returns whether anything was saved.
    """
    passed = getattr(args, attr) or []
    if passed:
        if site:
            scope[attr] = [str(item) for item in passed]
            return True
        return False
    saved = cfg.get(attr)
    if site and isinstance(saved, list):
        setattr(args, attr, [Path(p) for p in saved] if as_path else list(saved))
    return False


def _apply_maxmind_settings(
    args: argparse.Namespace, cfg: dict[str, object], gscope: dict[str, object]
) -> bool:
    """Reconcile the (always-global) MaxMind DB paths; return whether any were saved.

    A source is either a directory (discovered) or explicit per-database paths;
    an explicit path overrides the directory for its role. Passing --mm-db-dir this
    run drops any restored explicit paths so the directory can take over cleanly,
    but a path also passed this run still wins.
    """
    updated = False
    passed_dir = args.mm_db_dir is not None
    if passed_dir:
        gscope["mm_db_dir"], updated = str(args.mm_db_dir), True
        if args.mm_asn_db is None:
            gscope.pop("mm_asn_db", None)
        if args.mm_country_db is None:
            gscope.pop("mm_country_db", None)
    elif cfg.get("mm_db_dir") is not None:
        args.mm_db_dir = Path(str(cfg["mm_db_dir"]))

    if args.mm_asn_db is not None:
        gscope["mm_asn_db"], updated = str(args.mm_asn_db), True
    elif not passed_dir and cfg.get("mm_asn_db") is not None:
        args.mm_asn_db = Path(str(cfg["mm_asn_db"]))

    if args.mm_country_db is not None:
        gscope["mm_country_db"], updated = str(args.mm_country_db), True
    elif not passed_dir and cfg.get("mm_country_db") is not None:
        args.mm_country_db = Path(str(cfg["mm_country_db"]))
    return updated
