#!/usr/bin/env python3
"""amap-sandy.py — install the AMAP feature on a sandy host.

NOTHING HERE IS WRITTEN INTO A SANDBOX. The install is three things, ONCE
PER HOST, and sandy applies them to each sandbox at that sandbox's own
launch:

  1. the MANIFEST, `$SANDY_HOME/features/amap/feature.json` — authored by
     the operator; its reserved `feature` key IS the fleet policy, and its
     `agent_args` block hands the agent `--mcp-config` onto the payload's
     `mcp-servers.json` and `--append-system-prompt-file` onto its
     `INBOX-POLICY.md`;
  2. the PAYLOAD, `$SANDY_HOME/features/amap/payload/` — the relay chain
     and both MCP binaries, mounted READ-ONLY at
     `/opt/sandy/features/amap` into every sandbox sandy selects, with the
     manifest's `entry` naming the relay on it;
  3. the ROUTER'S CONFIG, the generated sibling `router.json` beside the
     manifest, in the router's own vocabulary.

The MCP servers are registered by `--mcp-config` rather than a per-workspace
`.mcp.json` because project-scoped servers land as "Pending approval", a
cloned repo cannot approve its own, and each workspace would need an
interactive `claude` run, which does not work with `sandy --start` daemons.

Idempotent by construction: every write is content-compared first, so a
second run reports every part `present` and touches nothing.

SELECTION IS SANDY'S, AT LAUNCH: a sandbox is a member only when its last
launch evaluated the feature manifest (the policy's `sandboxes` / `agents`
include and exclude globs, carried into the manifest verbatim) and sandy
wrote it into `selected.json` beside the manifest. Nothing here selects,
enrols, or predicts what sandy will decide: there is one matcher and it is
sandy's. `list` shows every sandbox with sandy's verdict (`selected`, `not
selected` and why, or `unknown` — not launched since the manifest was
written). `verify --only`/`--match` naming an unselected sandbox is a hard
error, not a silent skip.

`install` writes the manifest's TEMPLATE when there is none, repairs the
deployment-owned blocks of the one there is, installs the payload, refuses
to go further until the policy passes `policy_checks` (naming what to
edit), then renders the router's config and reports every sandbox with
sandy's own verdict. Dry run unless `--apply`, like every verb. It never
starts or stops the router; see `run_sync`'s own docstring for the flow.

No third-party dependencies. Reads the router's lane layout from the
sibling `amap-router-local` checkout (`router.config`), so the lane tree
rendered here and the one the router polls cannot disagree. Nothing here
runs Docker or launches sandy, except the read-only `docker` queries
`verify` makes.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

HERE = Path(__file__).resolve().parent
# The repo's `payload/` IS the host's `$SANDY_HOME/features/amap/payload/`
# minus the connector's four files: the three files this checkout ships,
# under their INSTALLED names, so a listing here reads like the mount.
PAYLOAD_DIR = HERE / "payload"
DEFAULT_SERVERS = PAYLOAD_DIR / "mcp-servers.json"

import launchd_job as lj   # the recreation cadence: renders and reads, never loads
import router_health as rh  # the router process: its container and its health, read only

# `fleet_policy.py` sits beside this module. Guarded rather than bare: this
# module is imported by its tests and by its sibling tools, where HERE is not
# guaranteed to already be on `sys.path` the way it is when the launcher
# (`amap-sandy.py`) runs it.
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import fleet_policy as fp  # noqa: E402
# The connector checkout install copies from, found beside this one.
CONNECTOR_REPO_NAME = "amap-connector-claude"


def _default_connector_src() -> Path:
    """The amap-connector-claude checkout's `bin/`, which `install` copies the
    delivery daemon, its module and both MCP binaries from.

    `$AMAP_CONNECTOR_REPO` names the checkout; otherwise the nearest
    `amap-connector-claude` beside an ancestor of this file, found by walking
    up rather than by a fixed `parents[N]`. When nothing matches, the path
    looked for first is returned, so the error names the layout expected."""
    env = fp.amap_env("CONNECTOR_REPO")
    if env:
        return Path(env).absolute() / "bin"
    for parent in HERE.absolute().parents:
        cand = parent / CONNECTOR_REPO_NAME / "bin"
        if cand.is_dir():
            return cand
    return HERE.absolute().parent / CONNECTOR_REPO_NAME / "bin"


DEFAULT_CONNECTOR_SRC = _default_connector_src()
# The two MCP binaries on the payload. They run IN-ANCESTRY, as MCP servers of
# the agent's own session — an agent that could rewrite one would gain nothing
# it does not already have, because it already chose what to say to them.
# `inbox-delivery` is not among them: sandy's supervisor restarts it out of
# every agent's ancestry, so it belongs to the relay chain below.
CONNECTOR_BINARIES = ("inbox-mcp-vol", "inbox-submit")

# The lane vocabulary is the ROUTER'S: it discovers `instances/<slug>/<lane>`
# and requires every leaf under each lane before it drains (its `provision`
# refuses otherwise, naming all of them), so the manifest's `create` block is
# rendered from the router's own constants rather than from a second list that
# must agree with them. One source, imported; `tests/test_layout_agreement.py`
# pins the derivation.
#
# When `router` is not already importable, the amap-router-local checkout is
# found by WALKING UP from this file until a directory holds one — never by a
# fixed `parents[N]`, which encodes how deeply this repo happens to be nested —
# or taken from `$AMAP_ROUTER_REPO`. A candidate is confirmed by
# `router/reset.py`, which the router pins by test for exactly this purpose: a
# directory with the right name and the wrong contents is not a match.
# `.absolute()`, never `.resolve()`: a symlinked sibling is still the sibling.
def resolve_router_repo() -> Optional[Path]:
    """The router checkout: `$AMAP_ROUTER_REPO` if set, else the nearest
    `amap-router-local` beside an ancestor of this file; None if neither holds
    `router/reset.py`. Anything needing the checkout's PATH (to hand a
    subprocess a working directory) resolves it here, whether or not `router`
    was already importable."""
    env = fp.amap_env("ROUTER_REPO")
    cands = [Path(env)] if env else [c / fp.ROUTER_REPO_NAME for c in HERE.absolute().parents]
    return next((c for c in cands if (c / "router" / "reset.py").is_file()), None)


try:
    import router.config  # noqa: E402,F401 — importable already (e.g. under pytest)
except ImportError:
    _router = resolve_router_repo()
    if _router is None:
        raise ImportError(fp.router_not_found_message("router/reset.py"))
    sys.path.insert(0, str(_router))
from router.config import LANES as _ROUTER_LANES, LANE_LEAVES as _ROUTER_LANE_LEAVES  # noqa: E402


# The policy text every selected agent receives as part of its system prompt.
POLICY_SOURCE = "payload/INBOX-POLICY.md"
# ---------------------------------------------------------- the delivery daemon

# The relay chain: the wrapper sandy supervises, the daemon it execs, and the
# module that daemon loads by path from beside itself.
#
# WHY A WRAPPER AT ALL. Sandy launches the relay as a container-level process
# and this deployment has no hook into its environment, so the
# `AMAP_DELIVERY_*` variables cannot be handed to the daemon any other way.
# The wrapper exports them and `exec`s the daemon, so there is no extra
# process in the tree and signals reach the daemon directly. Eight are paths
# derived from sandy's exports; the ninth, `AMAP_DELIVERY_SELF`, is the
# daemon's own address, `<sandbox_name>@<fleet_domain>`, from sandy's session
# file and the manifest's `AMAP_FLEET_DOMAIN` expose, and is optional by the
# daemon's design.
#
# WHY ALL THREE ARE ON THE READ-ONLY PAYLOAD. Sandy restarts the relay
# forever, out of every agent's ancestry, so the whole exec chain must resolve
# to read-only paths. A wrapper the agent can rewrite hands it that process; a
# read-only wrapper that execs a writable daemon hands it the same thing one
# link down, and a read-only daemon that imports a writable `_inboxlib.py`
# two links down. The chain is only as read-only as its most writable link,
# so all three sit together on the payload mount, with the session lister
# the daemon execs (`SESSION_SOURCE_NAME`). Sandy guarantees only the
# FIRST executable; the wrapper finds its neighbours through `$0`, so the
# WHOLE chain is behind the read-only mount, which is strictly more than sandy
# promises.
#
# The daemon resolves `_inboxlib.py` with `realpath(__file__)`, so these must
# be real files at the read-only path — a symlink into a writable directory
# would resolve to the writable copy and undo this.
DELIVERY_DAEMON_NAME = "inbox-delivery"
DELIVERY_SUPPORT_NAME = "_inboxlib.py"
# The wrapper as SHIPPED in this checkout: `payload/relay`, under the name it
# is installed as, so the repo file and the installed file have one name.
RELAY_WRAPPER_NAME = "relay"
# The session lister the daemon runs as `AMAP_DELIVERY_SESSION_SOURCE`, shipped
# from this checkout like the wrapper and found by the wrapper beside itself.
# It encodes sandy's published pane-identity contract. The daemon EXECS it, so
# it belongs to the relay chain and sits on the read-only payload with the rest.
SESSION_SOURCE_NAME = "handoff-sessions"
# The `inbox-submit` MCP server's command, shipped from this checkout: it
# derives the server's own address, AMAP_SELF, the way the relay derives the
# daemon's, and execs the connector's server from `bin/`.
SUBMIT_SERVER_NAME = "submit-server"

# ------------------------------------------------------------ the feature tree
#
# Sandy reads a feature MANIFEST at `$SANDY_HOME/features/<name>/feature.json`,
# selects each sandbox at launch by the manifest's rule, creates the `create`
# tree and mounts the declared mounts — the payload READ-ONLY at
# `/opt/sandy/features/<name>`. That is where this deployment's payload lives,
# ONCE per host: the relay chain (the wrapper, the daemon and its module) and
# both connector binaries. The manifest's `entry` names the wrapper, so sandy
# supervises it directly and every link of the chain is on a read-only mount.
FEATURE_NAME = "amap"
# The features directory is FIXED at `$SANDY_HOME/features/`, and a feature is
# `$SANDY_HOME/features/<name>/` — its manifest, its read-only payload, and one
# instance tree per selected sandbox.
FEATURES_SUBPATH = "features"                       # $SANDY_HOME/features/<name>
FEATURE_MANIFEST_NAME = "feature.json"
FEATURE_SELECTED_NAME = "selected.json"             # sandy's verdict; written at launch and removal
# The router's config, a GENERATED SIBLING of the authored manifest in the
# feature root. Sandy leaves an unknown regular file in a feature directory
# byte-identical, so the file may sit beside `feature.json`; the router reads
# it by `--config`, which names one file and has no search path.
ROUTER_SIBLING_NAME = "router.json"
# The verdict file's own `schema`. It carries its own number so it can move
# independently of the manifest and the CLI schema. An OPAQUE token like the
# others: a file with any other value is refused by name, never read with this
# shape's meaning.
SELECTED_SCHEMA = 1
# Schema 2 is the same document plus a per-entry `evaluated_at`, stamped at
# EVERY evaluation of that entry (provision, launch, refresh), while `at` keeps
# meaning "when a launch last took this verdict" and is `null` for an entry
# only a refresh has ever evaluated. Two fields, two facts: `evaluated_at`
# older than the manifest means the rule has not been re-applied (run sandy's
# refresh); `at` older than the manifest means the mounts have not caught up
# (relaunch). Both schemas are accepted.
SELECTED_SCHEMAS = (SELECTED_SCHEMA, 2)
FEATURE_PAYLOAD_SUBDIR = "payload"                  # the mount NAMED `payload`, by convention also its source
FEATURE_INSTANCES_SUBDIR = "instances"              # instances/<slug>/{inbox,peer,outbox}
# The three lanes sandy CREATES under `instances/<slug>/` at launch (the
# `create` list) and MOUNTS as siblings under the container home (the mount
# names), each with the export that names its container path. Siblings, not
# a single root mount: sandy emits binds in declaration order and does not
# sort by destination, and whether Docker mounts a parent before a nested
# child is unmeasured — a `.` mount waits on that measurement.
FEATURE_LANES = tuple(_ROUTER_LANES)
# The leaves are the router's list VERBATIM: everything the daemon opens and
# the router requires present. `outbox/ext/` is NOT in it and must not be
# added: it is the connector's side channel (`AMAP_DELIVERY_OUTCOME_DIR`),
# and the daemon's `Outcomes.write` makedirs it per write. On a clean sandbox
# with no peer traffic it does not exist, and that is correct — nothing here
# asserts that directory's presence.
FEATURE_LANE_LEAVES = {lane: tuple(_ROUTER_LANE_LEAVES[lane]) for lane in FEATURE_LANES}
FEATURE_LANE_MODES = {"inbox": "ro", "peer": "ro", "outbox": "rw"}
# Every environment name this manifest exports. `AMAP_`, never `SANDY_`:
# sandy appends a manifest's `-e` flags after its own and validates no names,
# so a `SANDY_*` export would silently override sandy's own.
EXPORT_PAYLOAD_DIR = "AMAP_PAYLOAD_DIR"
EXPORT_LANE_DIR = {"inbox": "AMAP_INBOX_DIR", "peer": "AMAP_PEER_DIR", "outbox": "AMAP_OUTBOX_DIR"}
# The fleet ROSTER: who exists and how to address them, written by the ROUTER
# (the one component that knows the admitted set live, re-read every poll) and
# mounted READ-ONLY into every selected sandbox, where the agent finds it only
# through this export. EDGE-FREE by design: it names who exists, never who may
# task whom, so nothing in it can read as an allowlist; the router decides
# authorisation at submit time.
#
# Mounted as the DIRECTORY, never the file: the router replaces the file by
# rename, and a single-file bind mount pins the old inode and goes silently
# stale. Its source lives under the feature root because a mount's `from` is
# relative to it (the router's own `state_dir` is outside). `install` creates
# the directory EMPTY so the source exists before any launch — sandy skips a
# declared mount with no source, visible only in launch output. The directory
# is ours; everything inside it is the router's.
FEATURE_ROSTER_SUBDIR = "roster"
EXPORT_ROSTER_DIR = "AMAP_ROSTER_DIR"
# The router's file inside it (its `roster.ROSTER_FILENAME`), and how the
# payload's policy text names the directory to the agent. The spec's roster
# section: the DEPLOYMENT must expose read-only whatever it points agents at,
# and should stop pointing before, or together with, ceasing to expose it —
# `verify_roster_pointer_exposed` holds this side to that.
ROSTER_FILE_NAME = "roster.json"
ROSTER_POINTER = "$" + EXPORT_ROSTER_DIR
EXPOSE_FLEET_DOMAIN = "AMAP_FLEET_DOMAIN"
SANDY_RESERVED_ENV_PREFIX = "SANDY_"
MANIFEST_SCHEMA = 1
# The policy lives IN the manifest: its `feature` section is the fleet policy
# (`fleet_policy.load_policy` reads the manifest directly), `sandboxes` and
# `agents` are the selection rule sandy evaluates. Nothing rendered rides in
# the file — an authored document cannot carry generated sections — so the
# router's graph is a generated SIBLING of the manifest,
# `$SANDY_HOME/features/amap/router.json`, never inside it. Sandy reads
# exactly `feature.json` and the sources its `mounts` name, and leaves an
# unknown sibling byte-identical.
MANIFEST_SLUG = "${slug}"                            # the only substitution sandy makes, in `create` and `from`
# sandy's segment predicate for a mount `name` and every `from` segment: the
# marker alphabet, no leading dot, no `..`, non-empty. Applied to what THIS
# repo renders so a manifest it writes can never fail sandy's validator for a
# reason it could have caught first.
SANDY_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")
# `--print-schema`'s `schema_version` tokens this deployment has REVIEWED:
#   3  sandy 2.2.0 to 2.5.x: `relay.state_dir` on --print-state, `SANDY_RELAY=0`
#      stopping a manifest entry too; from 2.4.0 also `feature_entries`.
#   4  sandy with `relay{}` removed from the marker and --print-state. A
#      marker's `feature_entries.<f>` is `{path}` alone (no `relay_alias`, no
#      `disabled_by`), every entry's state_dir is `feature-state/<f>`, setting
#      SANDY_RELAY is a launch error, and there is no relay-legacy inbound
#      default. Every relay question is answered from `feature_entries`.
# OPAQUE TOKENS compared by membership — never parsed,
# ordered or int()ed: `2.0.0-dev` equals `2.0.0` under every version
# comparison. A bump is sandy's signal that a field changed meaning, and the
# gate going FALSE on an unreviewed token is the gate working: add the token
# here only after reading what moved.
SANDY_SCHEMA_VERSIONS = (3, 4)
# The three words `selection_states` answers with, per sandbox. Sandy's
# verdict is `selected` / `not selected`; `unknown` is this side's word for
# "not launched since the manifest was written" — neither answer, and never
# rounded to either.
STATE_SELECTED = "selected"
STATE_NOT_SELECTED = "not selected"
STATE_UNKNOWN = "unknown"
CONTAINER_FEATURES_ROOT = "/opt/sandy/features"
CONTAINER_FEATURE_DIR = f"{CONTAINER_FEATURES_ROOT}/{FEATURE_NAME}"
FEATURE_BIN_SUBDIR = "bin"
CONTAINER_FEATURE_BIN = f"{CONTAINER_FEATURE_DIR}/{FEATURE_BIN_SUBDIR}"
# What sandy supervises: the wrapper on the read-only feature payload, named
# by the manifest's `entry`. From sandy 2.2.0 a feature manifest's `entry` is
# the only relay producer (an operator-set relay path is refused), and sandy
# pins ONE selected feature's entry as the relay. A started relay proves the
# daemon runs; only a delivered message proves sandy's cross-session gate
# accepted it.
MANIFEST_ENTRY = f"{FEATURE_PAYLOAD_SUBDIR}/{RELAY_WRAPPER_NAME}"
# A feature contributes LAUNCH ARGUMENTS to the agent it
# selects, per agent name, applied at the selecting launch before the agent
# reads any configuration. The MCP registration and the policy text are files
# on the read-only payload, and the two flags below point the agent at them.
# Stateless: nothing is written into a sandbox, and nothing reaped on removal.
AGENT_ARGS_KEY = "agent_args"                  # the manifest key; sandy's word, not `args`
MANIFEST_AGENT = "claude"                      # the ONE agent this feature configures
SANDY_FLOOR = "2.2.0"                          # named in remedies only; the GATE is membership
MCP_SERVERS_PAYLOAD_NAME = "mcp-servers.json"  # the registration, copied onto the payload
POLICY_PAYLOAD_NAME = "INBOX-POLICY.md"        # the calibration text, copied onto the payload
MCP_CONFIG_FLAG = "--mcp-config"               # Claude Code: load MCP servers from a file
SYSTEM_PROMPT_FILE_FLAG = "--append-system-prompt-file"   # Claude Code: append prompt text from a file
# sandy's per-sandbox session marker on the HOST (the same document it bind-
# mounts at /etc/sandy-session.json): what THAT launch pinned, readable
# without a container, for a stopped sandbox too. Last launch, not next.
SANDY_SESSION_MARKER_NAME = "sandy-session.json"
# Sandy's per-feature entry record, in the session marker (`{path, relay_alias,
# disabled_by}` per feature under schema 3, `{path}` under schema 4) and in
# `--print-state` (the same, plus `state_dir`, a HOST path, and supervisor
# counters). Where it is reported, this feature's own entry answers every relay
# question and `relay{}` is not read: under schema 3 `relay{}` describes
# whichever ONE entry sandy designated, which need not be ours, and schema 4
# has no `relay{}`.
FEATURE_ENTRIES_KEY = "feature_entries"

# Where that entry RESOLVES inside the container, which is what sandy records
# as `relay.path` in the session marker. The `payload/` component drops out
# because the payload directory is itself what is mounted at the feature dir.
# This is the surface that tells this feature's entry from another selected
# feature's: both set `relay.source` to "manifest", and only this `path` means
# ours.
CONTAINER_ENTRY_PATH = f"{CONTAINER_FEATURE_DIR}/{RELAY_WRAPPER_NAME}"

# The two chain files copied from the connector checkout, in install order;
# the wrapper is this checkout's own `payload/relay`.
RELAY_CHAIN_COPIED = (DELIVERY_DAEMON_NAME, DELIVERY_SUPPORT_NAME)
# The connector state directory, RELATIVE to the container user's home. The
# home is sandy's and may move; this tail does not — it is Claude Code's own
# layout. Anything host-side that has to recognise a container path the
# daemon published matches on this rather than on a whole absolute prefix.
CONNECTOR_REL = ".claude/connector"
DELIVERY_RECEIPT_WINDOW_ENV = "AMAP_DELIVERY_RECEIPT_WINDOW_SECONDS"

# The daemon's private state — its claims and its delivery ledger — lives
# under `claude/connector/` in the sandbox dir, and never under the feature's
# instance tree: the router mounts that tree read-write as the operator, so a
# claim or a ledger there is something a router could delete, letting a second
# consumer back onto the spool or replaying delivered notices. The rule is
# *the daemon keeps what it trusts where no router can write*.
#
# There is no allowlist beside it: authorisation on the peer lane is the
# router's, evidenced by the read-only mount, and an agent-writable list the
# router never consulted would bind nobody.
CONNECTOR_STATE_SUBPATH = Path("claude") / "connector"

class ProvisionError(Exception):
    """Operator-facing failure. Never includes a secret."""


# ---------------------------------------------------------------- discovery

def sandy_home() -> Path:
    return Path(os.environ.get("SANDY_HOME", str(Path.home() / ".sandy")))


def discover_sandboxes(sandy_bin: str = "sandy") -> List[Dict[str, str]]:
    """Ask sandy for its sandboxes. `--print-state` is a documented fast
    path that exits before Docker, image builds, and mutex acquisition, so
    it is cheap to call. Returns `[{name, path, workspace_path, agents}, ...]`.

    `agents` is carried through EXACTLY as sandy reports it,
    `None` included: null means UNKNOWN and is never turned into the default.
    See `discover_sandboxes`'s callers for the two caveats sandy attaches and why they are
    encoded rather than smoothed over.

    Deliberately NOT recomputing the slug: sandy's own guidance is to read
    it rather than derive it."""
    try:
        out = subprocess.run(
            [sandy_bin, "--print-state"], capture_output=True, text=True, timeout=30,
        )
    except FileNotFoundError:
        raise ProvisionError(f"{sandy_bin!r} not found on PATH — pass --sandy")
    except subprocess.TimeoutExpired:
        raise ProvisionError("`sandy --print-state` timed out (it should exit before Docker)")
    if out.returncode != 0:
        raise ProvisionError(f"`sandy --print-state` failed ({out.returncode}): {out.stderr.strip()}")
    try:
        state = json.loads(out.stdout)
    except json.JSONDecodeError as e:
        raise ProvisionError(f"`sandy --print-state` did not return JSON: {e}")
    boxes = state.get("sandboxes") or []
    return [
        {
            "name": b.get("name", ""),
            "path": b.get("path", ""),
            "workspace_path": b.get("workspace_path", ""),
            "agents": b.get("agents"),
            # `{path, source, disabled_by, state_dir, ...}` for the sandbox's
            # LAST LAUNCH. `state_dir` is the HOST path of the relay
            # supervisor's state (`.state`, `supervisor.log`), which
            # `verify_relay_supervisor` opens rather than constructing one.
            # TWO FRAMES IN ONE OBJECT: `path` is a CONTAINER path,
            # `state_dir` a HOST path. Carried whole.
            "relay": b.get("relay"),
            # `{<feature>: {path, state_dir, disabled_by, relay_alias, ...}}`,
            # one per selected feature's entry at the LAST LAUNCH; sandy runs
            # each separately. Same two frames as `relay`. Null or absent on a
            # sandy, or a launch, that predates it. Carried whole.
            FEATURE_ENTRIES_KEY: b.get(FEATURE_ENTRIES_KEY),
            # The feature names sandy will honour (sorted; `[]`
            # never null, and read at QUERY time — no last-launch caveat) and
            # every entry it will not, with the reason. Carried whole.
            "features": b.get("features"),
            "feature_problems": b.get("feature_problems"),
            # The last launch's applied launch arguments, the marker they
            # were read from (`{state, sandy_version, launched_at}`, which says
            # what a null above means), and the cross-session inputs. Absent
            # on a sandy that predates them. Carried whole.
            AGENT_ARGS_KEY: b.get(AGENT_ARGS_KEY),
            MARKER_KEY: b.get(MARKER_KEY),
            CROSS_SESSION_INBOUND_KEY: b.get(CROSS_SESSION_INBOUND_KEY),
        }
        for b in boxes
        if b.get("name") and b.get("path")
    ]


def discover_workspaces(sandy_bin: str = "sandy") -> Dict[str, Path]:
    """`{slug: workspace_path}` for every sandbox sandy reports one for.

    READ, NEVER DERIVED. The slug is a hash of the workspace path, so the
    mapping only runs one way; `$SANDY_HOME/sandboxes/<slug>` is the sandbox
    dir, not the workspace, and there is no third place the pairing is
    written down but sandy's own `WORKSPACE.json` record. A sandbox sandy
    reports without one is simply absent from this map, and every caller
    treats that as "cannot configure the relay", never as "no relay needed".

    Tolerant of sandy being unreachable — the caller decides whether that is
    fatal or merely reduces what can be checked."""
    try:
        return {b["name"]: Path(b["workspace_path"])
                for b in discover_sandboxes(sandy_bin) if b.get("workspace_path")}
    except ProvisionError:
        return {}


# ------------------------------------------------------- instance names
#
# THE INSTANCE NAME IS THE SLUG. The router accepts sandy's slug alphabet
# verbatim, so nothing here derives a second name. One string names the sandbox directory, the container, the router instance,
# `state_dir/<name>/` and the address local part.
#
# Two shapes the router refuses, and this repo refuses at `install` so they
# never reach a config: a leading `-` (reads as a flag to every tool ever
# pointed at the state dir; a leading `.` is already refused as unsafe), and
# the router's own local part (`amap.router` is a legal slug; the router
# refuses it at load and in lookup, and this is the second line).


def instance_names(enrolled) -> Dict[str, str]:
    """`{slug: slug}` for every enrolled slug.

    A function because several callers, here and in sibling tools, read the
    mapping this way. It rejects nothing: sandy guarantees slug uniqueness by
    the path hash, and the router refuses a casefold collision at config
    load. Accepts the enrolled set or a bare iterable of slugs."""
    return {slug: slug for slug in sorted(enrolled)}


def router_refusal(slug: str) -> Optional[str]:
    """Why the router would refuse this slug as an instance name, or None."""
    if slug.startswith("-"):
        return "starts with '-', which every tool pointed at state_dir would read as a flag"
    if slug.casefold() == fp.ROUTER_LOCAL_PART.casefold():
        return (f"is the router's own local part {fp.ROUTER_LOCAL_PART!r}; an instance "
                "by that name could bind a reply to a DSN and claim a peer notice came "
                "from the router")
    return None


# ---------------------------------------------------------------- membership
#
# SELECTION IS ENROLMENT, AND SANDY DECIDES IT. The policy's
# `sandboxes`/`agents` blocks are rendered verbatim into
# `$SANDY_HOME/features/amap/feature.json`; sandy evaluates them at every
# launch against the slug, the workspace's host path and the agent the launch
# runs, and writes its verdict to `selected.json` beside the manifest. This
# repo never evaluates the globs — one matcher, sandy's — and reads membership
# back from two things sandy wrote: `selected.json` (every launch and removal)
# and `--print-state`'s per-sandbox `features` (the last launch's selection).
#
# There is no enrol list, no per-sandbox marker, no enrol command. A new
# sandbox that matches is an agent from its first launch; the router's config
# follows at the next `install --apply`.
#
# HOST-ONLY. The manifest is never mounted into a container and `selected.json`
# is sandy's, so an agent cannot enrol itself or another.

def sandboxes_dir(home: Path) -> Path:
    """sandy's registry: `$SANDY_HOME/sandboxes/<slug>/`, the directories
    `--provision --all` enumerates and `--print-state` reports as `path`."""
    return Path(home) / "sandboxes"


def feature_root(home: Path) -> Path:
    """`$SANDY_HOME/features/amap/` — the feature: manifest, payload, instances."""
    return Path(home) / FEATURES_SUBPATH / FEATURE_NAME


def feature_manifest_path(home: Path) -> Path:
    return feature_root(home) / FEATURE_MANIFEST_NAME


def feature_selected_path(home: Path) -> Path:
    return feature_root(home) / FEATURE_SELECTED_NAME


def router_sibling_path(home: Path) -> Path:
    """`$SANDY_HOME/features/amap/router.json` — the router's config, rendered
    by `install` beside the manifest and read by the router's `--config`."""
    return feature_root(home) / ROUTER_SIBLING_NAME


def feature_roster_dir(home: Path) -> Path:
    """The host side of the `:ro` roster mount: created empty by `install`,
    written into only by the router."""
    return feature_root(home) / FEATURE_ROSTER_SUBDIR


def feature_payload_dir(home: Path) -> Path:
    """The host side of the `:ro` payload mount. Its CONTAINER path comes from
    the mount NAME `payload` (`CONTAINER_FEATURE_DIR`), not from this
    directory's name — the two agreeing is convention."""
    return feature_root(home) / FEATURE_PAYLOAD_SUBDIR


def feature_instances_dir(home: Path) -> Path:
    return feature_root(home) / FEATURE_INSTANCES_SUBDIR


def feature_instance_dir(home: Path, slug: str) -> Path:
    """`instances/<slug>/` — created by SANDY at a selected launch, reaped by
    `--remove-sandbox`, untouched by `--reset-sandbox`. Never created here."""
    _validate_slug_shape(slug)
    return feature_instances_dir(home) / slug


def payload_entry_path(home: Path) -> Path:
    """The wrapper on the payload: what the manifest's `entry` names."""
    return feature_payload_dir(home) / RELAY_WRAPPER_NAME


def membership_source(home: Path) -> str:
    """Where membership is read from, as prose for reports."""
    return f"{feature_selected_path(home)} + `sandy --print-state` sandboxes[].features"


def load_selected(home: Path) -> Dict[str, Any]:
    """`selected.json` as sandy wrote it: `{schema, note, selected: [{slug, at}],
    not_selected: [{slug, why, at}]}`.

    ABSENT IS ITS OWN STATE, and it raises: sandy writes the file at each
    launch and removal, so a manifest no launch has evaluated yet has no
    file — which is "sandy has not decided", never "nobody selected". A
    caller that wants the union with `--print-state` uses
    `load_membership`, which tolerates absence for exactly that reason and
    reports it.

    THE FILE RECORDS WHAT SANDY DECIDED, NOT WHAT CAME UP. Sandy evaluates
    and records the verdict early in a launch, and several launch failures sit after that point, so a sandbox can be
    selected here and never have come up. Nothing on this side may treat a
    verdict as a launch: the mounts are verified in the container
    (`verify_feature_mount`), the relay by sandy's `relay.state`, and a
    member that never came up fails those by name rather than passing on
    the strength of this file."""
    path = feature_selected_path(home)
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ProvisionError(
            f"{path} is absent — sandy has not evaluated the manifest yet (it writes this "
            f"file at each launch and removal). Launch a sandbox, or nothing is selected")
    except (OSError, json.JSONDecodeError) as e:
        raise ProvisionError(f"{path} could not be read: {e} — sandy's verdict is "
                             f"unreadable, and guessing membership is not an option")
    if not isinstance(doc, dict) or not isinstance(doc.get("selected"), list) \
            or not isinstance(doc.get("not_selected"), list):
        raise ProvisionError(f"{path} does not carry `selected` and `not_selected` lists")
    if doc.get("schema") not in SELECTED_SCHEMAS:
        raise ProvisionError(
            f"{path} carries schema={doc.get('schema')!r}, not one of {SELECTED_SCHEMAS!r} — "
            f"sandy moved the verdict file's shape, and this deployment refuses to read it with "
            f"a meaning it no longer has; update amap-deploy-sandy rather than the file")
    return doc


def is_selected(home: Path, slug: str) -> bool:
    """Sandy's verdict for ONE slug, from `selected.json` alone. Raises (via
    `load_selected`) when sandy has written no verdict: absent is not
    False. For the fleet-wide answer that also reads `--print-state`, use
    `load_membership`."""
    doc = load_selected(home)
    return any(isinstance(e, dict) and e.get("slug") == slug for e in doc["selected"])


def load_membership(home: Path, boxes: List[Dict[str, Any]]) -> Dict[str, dict]:
    """`{slug: {"selected_at": <iso or None>, "source": ...}}` — every sandbox
    sandy currently reports whose LAST LAUNCH selected this feature, from the
    union of `selected.json` and `--print-state`'s `features`.

    Two sources because they answer at different times: `features` is
    per-sandbox and current for what sandy reports now; `selected.json` also
    carries WHY a candidate was not selected and the timestamp. A slug in
    neither has not been launched since the manifest was written (sandy's
    own note in the file says so): UNKNOWN, reported by `selection_states`,
    never a member and never a refusal.

    Only slugs sandy REPORTS are members — `selected.json` outlives a removed
    sandbox until sandy re-renders it, and a member sandy cannot find is not
    a target for anything."""
    reported = {b["name"]: b for b in boxes if b.get("name")}
    out: Dict[str, dict] = {}
    try:
        doc = load_selected(home)
    except ProvisionError:
        doc = {"selected": [], "not_selected": []}
    for entry in doc["selected"]:
        slug = entry.get("slug") if isinstance(entry, dict) else None
        if slug in reported and _slug_shape_ok(slug):
            out[slug] = {"selected_at": entry.get("at"), "source": FEATURE_SELECTED_NAME}
    for slug, b in reported.items():
        if slug not in out and FEATURE_NAME in (b.get("features") or []) and _slug_shape_ok(slug):
            out[slug] = {"selected_at": None, "source": "features"}
    return out


def verdict_orphans(home: Path, boxes: List[Dict[str, Any]]) -> List[str]:
    """Slugs sandy's verdict file names (selected or not) that sandy no
    longer reports. Sandy rewrites the file at each launch and removal, so
    an orphan is a sandbox that went away by some other route — not a
    member (`load_membership` keeps only what sandy reports), but worth
    naming, because "the selected set" silently shrank by it. `[]` when the
    file is absent: nothing named, nothing orphaned."""
    try:
        doc = load_selected(home)
    except ProvisionError:
        return []
    reported = {b.get("name") for b in boxes}
    named = {e.get("slug") for key in ("selected", "not_selected")
             for e in doc[key] if isinstance(e, dict)}
    return sorted(s for s in named if s and s not in reported)


def selection_states(home: Path, boxes: List[Dict[str, Any]]) -> Dict[str, Tuple[str, str]]:
    """`{slug: (state, detail)}` for every sandbox sandy reports: `selected`
    (detail: when), `not selected` (detail: sandy's reason), or `unknown`
    (not launched since the manifest was written — neither answer)."""
    try:
        doc = load_selected(home)
    except ProvisionError as e:
        doc = {"selected": [], "not_selected": [], "_absent": str(e)}
    selected = {e.get("slug"): e for e in doc["selected"] if isinstance(e, dict)}
    rejected = {e.get("slug"): e for e in doc["not_selected"] if isinstance(e, dict)}
    stamp = manifest_changed_at(home)
    out: Dict[str, Tuple[str, str]] = {}
    for b in boxes:
        slug = b.get("name")
        if not slug:
            continue
        problems = [str(p) for p in (b.get("feature_problems") or [])
                    if str(p).startswith(FEATURE_NAME + ":")]
        if slug in selected or FEATURE_NAME in (b.get("features") or []):
            at = selected.get(slug, {}).get("at") or "last launch"
            if slug in selected and "evaluated_at" in selected[slug] and selected[slug].get("at") is None:
                at = "no launch yet"
            out[slug] = (STATE_SELECTED, f"at {at}")
        elif slug in rejected or problems:
            why = rejected.get(slug, {}).get("why") or "; ".join(problems)
            out[slug] = (STATE_NOT_SELECTED, why)
        else:
            out[slug] = (STATE_UNKNOWN, "not launched since the manifest was written — sandy "
                                        "decides at launch")
            continue
        # The lag sandy's design leaves: a verdict stands until the sandbox's
        # next launch, so one taken under an older rule is named as such —
        # the same three words, with the age in the detail. Under schema 2
        # the two facts are separate fields: `evaluated_at` says
        # whether the CURRENT rule has been applied, `at` whether a launch
        # (the mounts) has caught up; `at` is null for a refresh-only entry.
        entry = selected.get(slug) or rejected.get(slug) or {}
        reason = verdict_lag(entry, stamp)
        if reason:
            out[slug] = (out[slug][0], out[slug][1] + "; " + reason)
    return out


def _validate_slug_shape(slug: str) -> None:
    """Reject any slug that could escape `boxes_dir` once interpolated
    into a path (`boxes_dir / slug`, `boxes_dir / f"{slug}.claude.json"`)
    — empty, `.`/`..`, containing a path separator, or starting with a
    dot. This needs a hostile or buggy `sandy --print-state` to matter
    (a slug normally only ever comes from sandy's own report or a
    directory name already sitting inside `boxes_dir`) — defense in
    depth, cheap to keep on a tool that removes files. A real slug never
    looks like this; `alpha-0a1b2c3d.bak` (a legitimate odd slug this
    tool must still handle) is untouched by this check since the dot is
    not in the leading position."""
    if not _slug_shape_ok(slug):
        raise ProvisionError(f"refusing unsafe slug {slug!r}")


def _slug_shape_ok(slug: str) -> bool:
    """The predicate form of `_validate_slug_shape`.

    DISCOVERY uses this and SKIPS what fails; code acting on a slug it was
    HANDED uses `_validate_slug_shape` and refuses loudly. The distinction
    matters: `boxes_dir` legitimately contains entries that are not
    sandboxes at all — sandy's own `.<slug>.lock` files, `.DS_Store`,
    editor droppings — and a scan meeting one of those has simply found a
    non-sandbox, not a threat. Aborting the whole run there lets a single
    stray dotfile block the check of every other sandbox on the box."""
    return not (
        not slug or slug in (".", "..") or "/" in slug or os.sep in slug or slug.startswith(".")
    )


# ---------------------------------------------------------------- selection

def _match_selectors(
    known: List[str], only: List[str], match: List[str]
) -> Tuple[List[str], int]:
    """Resolve `--only` (exact match on sandbox NAME) and `--match`
    (substring on NAME) selectors against `known` names. `workspace_path`
    is never matched here.

    Each individual selector must match at least one name, or this raises
    `ProvisionError` naming the full known set, so a typo is an error rather
    than a silent "no sandboxes matched — nothing to do" success.
    Returns `(sorted resolved names, number of selectors given)`, so the
    caller can tell whether the resolved set is larger than what was
    named (only possible via `--match`)."""
    resolved = set()
    for o in only:
        hits = [n for n in known if n == o]
        if not hits:
            raise ProvisionError(
                f"--only {o!r} matched no sandbox (known: {', '.join(known) if known else '(none)'})"
            )
        resolved.update(hits)
    for m in match:
        hits = [n for n in known if m in n]
        if not hits:
            raise ProvisionError(
                f"--match {m!r} matched no sandbox (known: {', '.join(known) if known else '(none)'})"
            )
        resolved.update(hits)
    return sorted(resolved), len(only) + len(match)


# ---------------------------------------------------------------- driver

def load_servers(path: Path) -> Dict[str, dict]:
    try:
        doc = json.loads(path.read_text())
    except OSError as e:
        raise ProvisionError(f"cannot read servers file {path}: {e}")
    except json.JSONDecodeError as e:
        raise ProvisionError(f"servers file {path} is not valid JSON: {e}")
    servers = doc.get("mcpServers", doc)
    if not isinstance(servers, dict) or not servers:
        raise ProvisionError(f"servers file {path} has no server definitions")
    for name, spec in servers.items():
        if not isinstance(spec, dict) or "command" not in spec:
            raise ProvisionError(f"servers file {path}: server {name!r} needs a 'command'")
    return servers


def policy_source_path() -> Path:
    return HERE / POLICY_SOURCE


def _sandy_json(sandy_bin: str, flag: str) -> Any:
    """One fast-path JSON read (`--print-schema`, `--print-state`), or None."""
    try:
        out = subprocess.run([sandy_bin, flag], capture_output=True, text=True,
                             timeout=30, check=True).stdout
        return json.loads(out)
    except Exception:
        return None


def sandy_schema_version(sandy_bin: str = "sandy") -> Tuple[Any, str]:
    """`--print-schema`'s top-level `schema_version`, as sandy printed it, or
    None with the reason. Returned as an OPAQUE TOKEN: compare with `==`,
    never parse it — see `SANDY_SCHEMA_VERSIONS`."""
    schema = _sandy_json(sandy_bin, "--print-schema")
    if not isinstance(schema, dict):
        return None, f"`{sandy_bin} --print-schema` could not be read"
    if "schema_version" not in schema:
        return None, f"`{sandy_bin} --print-schema` carries no schema_version"
    return schema["schema_version"], f"`{sandy_bin} --print-schema` schema_version"


def sandy_manifest_capable(sandy_bin: str = "sandy") -> Tuple[Optional[bool], str]:
    """Is this a sandy whose feature manifests this deployment can use?
    `(verdict, why)`, verdict None when it could not be asked.

    THE CAPABILITY, NOT THE VERSION NUMBER: `schema_version` compared as an
    opaque token against the reviewed set, then MEMBERSHIP of what the
    manifest needs in the parser's own key lists."""
    schema = _sandy_json(sandy_bin, "--print-schema")
    if not isinstance(schema, dict):
        return None, f"`{sandy_bin} --print-schema` could not be read"
    version = schema.get("schema_version")
    if not any(version == known and type(version) is type(known) for known in SANDY_SCHEMA_VERSIONS):
        return False, (f"`{sandy_bin} --print-schema` reports schema_version={version!r}, not one "
                       f"this deployment has reviewed ({', '.join(map(repr, SANDY_SCHEMA_VERSIONS))}) "
                       f"— it requires sandy {SANDY_FLOOR}; a newer schema may "
                       f"have changed the meaning of a field it reads, and it refuses rather "
                       f"than guess")
    # `agent_args`: MEMBERSHIP in the parser's own list of accepted keys,
    # never a version string (a `-dev` build compares equal to its release).
    # A manifest carrying a key the parser does not accept is REFUSED WHOLE,
    # mounts and exports included: an absent feature, not a degraded one.
    manifest = schema.get("manifest")
    keys = manifest.get("top_level_keys") if isinstance(manifest, dict) else None
    if not isinstance(keys, list) or AGENT_ARGS_KEY not in keys:
        return False, (f"`{sandy_bin} --print-schema` lists no `manifest.top_level_keys` "
                       f"containing {AGENT_ARGS_KEY!r} — this sandy cannot read feature launch "
                       f"arguments (sandy {SANDY_FLOOR} can); a manifest carrying "
                       f"them would be refused whole and mount nothing")
    # And the agent name the manifest keys on must be one sandy accepts: an
    # unknown name refuses the whole manifest too. `agents` is an ARRAY of
    # objects — `agents[].name` — not a mapping; a membership test against
    # the array itself would reject every real name while looking like it
    # worked.
    agents = schema.get("agents")
    known = {a.get("name") for a in agents if isinstance(a, dict)} if isinstance(agents, list) else set()
    if MANIFEST_AGENT not in known:
        return False, (f"`{sandy_bin} --print-schema` names no agent {MANIFEST_AGENT!r} under "
                       f"`agents[].name` ({sorted(k for k in known if k)!r}) — the manifest "
                       f"keys {AGENT_ARGS_KEY} on it, and sandy refuses a name it does not know")
    return True, (f"schema_version {version!r} is reviewed, the parser accepts "
                  f"{AGENT_ARGS_KEY} and names {MANIFEST_AGENT!r}")


def sandy_accepts_receives(sandy_bin: str = "sandy") -> Optional[bool]:
    """Does this sandy's manifest parser accept `receives: ["cross_session"]`?
    MEMBERSHIP of the key in `--print-schema`'s `manifest.top_level_keys` and
    of the value in `manifest.receives_values`, never a version. None when
    the schema cannot be read: unknown, and never rounded to either answer."""
    schema = _sandy_json(sandy_bin, "--print-schema")
    if not isinstance(schema, dict):
        return None
    manifest = schema.get("manifest")
    if not isinstance(manifest, dict):
        return False
    keys = manifest.get("top_level_keys")
    values = manifest.get("receives_values")
    return (isinstance(keys, list) and RECEIVES_KEY in keys
            and isinstance(values, list) and RECEIVES_CROSS_SESSION in values)


def require_manifest_capable(sandy_bin: str = "sandy") -> None:
    """Refuse to install against a sandy whose feature manifests this
    deployment cannot use.

    REFUSE, never fall back: a sandy that cannot read this manifest mounts
    nothing from it, and every check downstream would then be green over a
    connector that silently runs nothing."""
    ok, why = sandy_manifest_capable(sandy_bin)
    if ok is None:
        raise ProvisionError(f"cannot confirm feature-manifest support: {why}. Provisioning "
                             f"against a sandy without it installs a payload nothing mounts")
    if not ok:
        raise ProvisionError(f"{why}. Upgrade sandy to {SANDY_FLOOR} or later")


# ------------------------------------------------- the delivery daemon's wiring
#
# Everything the daemon touches is under a tree SANDY mounts — this script
# expresses no per-sandbox mount of its own and never creates an inbound tree.
# The private connector directory is inside sandy's own rw mount of
# `<SANDBOX_DIR>/claude`; the lanes are the manifest's mounts, created by
# sandy at launch.


def connector_state_dir(sandbox_dir: Path) -> Path:
    """`<SANDBOX_DIR>/claude/connector/` — the private mount, seen in the
    container as `/home/claude/.claude/connector/`."""
    return sandbox_dir / CONNECTOR_STATE_SUBPATH


def relay_wrapper_source() -> Path:
    """The SHIPPED wrapper: `payload/relay` in this checkout, checked in,
    copied verbatim onto the feature payload once per host.

    A file, not a rendering: its paths are derived from sandy's exports, so
    nothing in it differs between two sandboxes or two hosts, and a constant
    belongs in a file rather than in a function that returns one.

    The daemon's contract is the explicit `AMAP_DELIVERY_*` variables — eight
    paths and its own address, optional by the daemon's design (a fleet with
    no domain has none) — host-agnostic. Translating sandy's facts into them
    is this deployment's job, and that file is the translation. The one
    input that is neither sandy's nor constant, the fleet domain, reaches
    the wrapper as the manifest's `expose` export (`EXPOSE_FLEET_DOMAIN`), so
    the wrapper itself renders nothing per host."""
    return PAYLOAD_DIR / RELAY_WRAPPER_NAME


def _write_file(path: Path, want: str, *, dry_run: bool, label: str,
                executable: bool = False) -> str:
    """Content-compared, atomic write with the report string every other
    writer in this file returns. One writer, so no file ends up non-atomic.

    Atomic (temp file + `os.replace` in the same directory) because a launch
    racing the install must never read a half-written wrapper and run part
    of it.
    """
    try:
        have = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        have = None
    except OSError as e:
        raise ProvisionError(f"cannot read {path}: {e}")

    mode_ok = True
    if executable and have is not None:
        mode_ok = bool(path.stat().st_mode & 0o111)
    if have == want and mode_ok:
        return f"{label} present"
    verb = "update" if have is not None else "create"
    if dry_run:
        return f"would {verb} {label}"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    try:
        tmp.write_text(want, encoding="utf-8")
        if executable:
            tmp.chmod(0o755)
        os.replace(tmp, path)
    except OSError as e:
        tmp.unlink(missing_ok=True)
        raise ProvisionError(f"cannot write {path}: {e}")
    return f"{verb}d {label}"


def payload_sources(connector_src: Path,
                    servers_path: Path = DEFAULT_SERVERS) -> Tuple[Tuple[str, Path, bool], ...]:
    """`(relative path in the payload, source file, executable)` — every file
    the payload holds, in one place. The wrapper, the session lister, the
    submit server's wrapper, the MCP registration and the policy text come
    from THIS checkout; the
    daemon, its module and both MCP binaries from the connector. The registration and the policy text
    are what the manifest's `agent_args` point the agent at, so they live
    once per host on the read-only mount like everything else here. Sibling
    tools import this tuple: it moves by agreement."""
    src = Path(connector_src)
    return (
        (RELAY_WRAPPER_NAME, relay_wrapper_source(), True),
        (SESSION_SOURCE_NAME, PAYLOAD_DIR / SESSION_SOURCE_NAME, True),
        (SUBMIT_SERVER_NAME, PAYLOAD_DIR / SUBMIT_SERVER_NAME, True),
        (DELIVERY_DAEMON_NAME, src / DELIVERY_DAEMON_NAME, True),
        (DELIVERY_SUPPORT_NAME, src / DELIVERY_SUPPORT_NAME, False),
        (MCP_SERVERS_PAYLOAD_NAME, Path(servers_path), False),
        (POLICY_PAYLOAD_NAME, policy_source_path(), False),
    ) + tuple((f"{FEATURE_BIN_SUBDIR}/{name}", src / name, True) for name in CONNECTOR_BINARIES)


def install_feature_payload(home: Path, connector_src: Path, *, dry_run: bool,
                            servers_path: Path = DEFAULT_SERVERS) -> str:
    """Install the payload ONCE, at `$SANDY_HOME/features/amap/payload/`: the
    copied chain and binaries. Nothing rendered lives here — the fleet domain
    reaches the wrapper as the manifest's `expose` export.

    REAL FILES, NEVER SYMLINKS, byte-compared so an unchanged install writes
    nothing. `inbox-delivery` locates its module with `realpath(__file__)`,
    so a symlink here would resolve to wherever it points; and `_write_file`'s
    `os.replace` onto a symlink would follow it."""
    dest = feature_payload_dir(home)
    parts = []
    for rel, src_file, executable in payload_sources(connector_src, servers_path):
        try:
            data = src_file.read_text(encoding="utf-8")
        except OSError as e:
            raise ProvisionError(f"payload source missing or unreadable: {src_file}: {e}")
        parts.append(_write_file(dest / rel, data, dry_run=dry_run, label=rel,
                                 executable=executable))
    return "; ".join(parts)


def _install_empty_dir(d: Path, what: str, whose: str, *, dry_run: bool) -> str:
    """Create `d`, empty, and nothing inside it. Settled once it exists. A
    symlink or a non-directory at the path is refused rather than followed or
    replaced: a mount source that resolves somewhere else is not the
    directory its writer uses."""
    if d.is_symlink():
        raise ProvisionError(f"{d} is a symlink — the {what} must be a real directory; "
                             f"remove it and re-run")
    if d.is_dir():
        return f"{what} present"
    if d.exists():
        raise ProvisionError(f"{d} exists and is not a directory")
    if dry_run:
        return f"would create {what} (empty; {whose})"
    d.mkdir(parents=True, exist_ok=True)
    return f"created {what} (empty; {whose})"


def install_roster_dir(home: Path, *, dry_run: bool) -> str:
    """The roster mount's SOURCE, empty: the file inside is the router's to
    write."""
    return _install_empty_dir(feature_roster_dir(home), "roster directory",
                              "the router writes into it", dry_run=dry_run)


def install_instances_dir(home: Path, *, dry_run: bool) -> str:
    """The ROOT of the instance lanes, empty. The router mounts it whole and
    finds each sandbox in it at poll time, and `docker/run.sh` refuses to
    start while it is missing. So it exists from install on, and the router
    can be started before any sandbox has launched. Every `<slug>/` lane tree
    inside is sandy's, created at that sandbox's launch."""
    return _install_empty_dir(feature_instances_dir(home), "instances directory",
                              "sandy creates each sandbox's lanes in it at launch",
                              dry_run=dry_run)


def install_router_state_dir(state_dir: Path, *, dry_run: bool) -> str:
    """The router's `state_dir`, empty. `docker/run.sh` refuses a missing
    bind source rather than let Docker create it as root, so without it the
    router cannot start. Every file in it is the router's own: its first-sight
    markers, reply ledger and quarantine."""
    return _install_empty_dir(state_dir, "router state_dir",
                              "the router writes into it", dry_run=dry_run)


# ------------------------------------------------------------- the manifest
#
# `$SANDY_HOME/features/amap/feature.json`, in sandy's schema. The policy
# itself rides in the reserved `feature` key, which sandy stores and never
# interprets.

# The manifest is AUTHORED: the operator edits `feature.json` in place, and
# the policy lives only there — its `feature` section IS the fleet policy
# (`fleet_policy.load_policy` reads the manifest directly). Ownership inside
# the file is by key: the operator owns `sandboxes`, `agents` and `feature`;
# this deployment owns the mechanical blocks below and rewrites them on every
# install from constants and from the operator's own `feature.fleet_domain`, so
# the domain is typed once and the exposed copy sandy hands the container is
# derived. `install --apply` writes the whole file only when it is ABSENT: the
# template, `fleet_policy.default_policy()`, which works as written.
#
# `receives` declares what this feature needs delivered into the session:
# cross-session messages, which the daemon injects. Sandy resolves the
# agent's cross-session inbound setting to accept from a selected feature's
# declaration. It is rendered only where this host's sandy lists the key and
# the value in `--print-schema` (`sandy_accepts_receives`), because an unknown
# key or value refuses the whole manifest.
RECEIVES_KEY = "receives"
RECEIVES_CROSS_SESSION = "cross_session"
ADAPTER_OWNED_KEYS = ("schema", "create", "mounts", "entry", "expose", AGENT_ARGS_KEY,
                      RECEIVES_KEY)


def agent_args_for_manifest() -> Dict[str, List[str]]:
    """The launch arguments this feature contributes, per agent: constants,
    rendered for `claude` ONLY. An unknown agent name refuses the whole
    manifest, so the conservative set is the correct default forever, not
    just today; a second agent gets its own list when someone has measured
    what it accepts.

    Both files are on the payload sandy mounts read-only at
    `CONTAINER_FEATURE_DIR`, so the paths are PAYLOAD-ROOTED literals: the
    feature dir is fixed, while the container home is sandy's to move. The
    `-file` variants, never inline text — a token with whitespace in it
    refuses the whole manifest, and there is no quoting scheme.

    The policy text goes into the SYSTEM PROMPT, not CLAUDE.md, and with
    Claude Code's snapshot left on: a conversation keeps the rules it
    started under until compaction, and removal reaches existing
    conversations then. Accepted deliberately, because that text is
    CALIBRATION, NOT ENFORCEMENT — anything that must hold belongs in the
    router. Measured, not argued: `--add-dir` grants tool access only and
    loads no CLAUDE.md."""
    return {MANIFEST_AGENT: [
        MCP_CONFIG_FLAG, f"{CONTAINER_FEATURE_DIR}/{MCP_SERVERS_PAYLOAD_NAME}",
        SYSTEM_PROMPT_FILE_FLAG, f"{CONTAINER_FEATURE_DIR}/{POLICY_PAYLOAD_NAME}",
    ]}
# `run_provision`'s exit when the manifest's policy is not yet ratified: kept
# apart from 1 (a failed part) so `install` can stop there by name.
EXIT_POLICY_UNRATIFIED = 3


def render_manifest(policy: Dict[str, Any], *,
                    receives: Optional[bool] = None) -> Dict[str, Any]:
    """The manifest document for `policy`: selection verbatim; the lane
    tree under `create`; sibling lane mounts with their exports; the domain
    as an `expose` export; `receives` when `receives` is True (this host's
    sandy accepts it: `sandy_accepts_receives`); the policy itself (minus the
    selection blocks the manifest carries at top level, and the loader's own
    marker) as `feature`. This is the TEMPLATE a first install writes, and
    the source of the deployment-owned blocks every later install repairs."""
    selection = fp.selection(policy)
    create = [f"{FEATURE_INSTANCES_SUBDIR}/{MANIFEST_SLUG}/{lane}/{leaf}"
              for lane in FEATURE_LANES for leaf in FEATURE_LANE_LEAVES[lane]]
    mounts = [{"name": FEATURE_PAYLOAD_SUBDIR, "from": FEATURE_PAYLOAD_SUBDIR, "mode": "ro",
               "export": EXPORT_PAYLOAD_DIR}]
    for lane in FEATURE_LANES:
        mounts.append({"name": lane, "from": f"{FEATURE_INSTANCES_SUBDIR}/{MANIFEST_SLUG}/{lane}",
                       "mode": FEATURE_LANE_MODES[lane], "export": EXPORT_LANE_DIR[lane]})
    # LAST, so every earlier mount keeps its position.
    mounts.append({"name": FEATURE_ROSTER_SUBDIR, "from": FEATURE_ROSTER_SUBDIR, "mode": "ro",
                   "export": EXPORT_ROSTER_DIR})
    feature = {k: v for k, v in policy.items()
               if k not in (fp.SANDBOXES_KEY, fp.AGENTS_KEY, fp.SOURCE_KEY)}
    doc: Dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        fp.SANDBOXES_KEY: selection[fp.SANDBOXES_KEY],
        fp.AGENTS_KEY: selection[fp.AGENTS_KEY],
        "create": create,
        "mounts": mounts,
        "entry": MANIFEST_ENTRY,
        "expose": {},
        AGENT_ARGS_KEY: agent_args_for_manifest(),
        "feature": feature,
    }
    if receives:
        doc[RECEIVES_KEY] = [RECEIVES_CROSS_SESSION]
    domain = policy.get(fp.FLEET_DOMAIN_KEY)
    if domain is not None:
        doc["expose"][EXPOSE_FLEET_DOMAIN] = domain
    _check_manifest_names(doc)
    return doc


def _check_manifest_names(doc: Dict[str, Any]) -> None:
    """What sandy would refuse, refused here first: every mount `name` and
    every `from`/`create` segment passes sandy's segment predicate, and no
    exported name is in sandy's own namespace (sandy validates no export
    names, so one would override sandy's own environment, silently, with attestation still reporting
    sandy's value)."""
    def segment_ok(seg: str) -> bool:
        return bool(SANDY_SEGMENT_RE.match(seg)) and not seg.startswith(".") and seg != ".."

    for m in doc["mounts"]:
        if m["name"] != "." and not segment_ok(m["name"]):
            raise ProvisionError(f"manifest: mount name {m['name']!r} fails sandy's segment rule")
        for seg in m["from"].split("/"):
            if seg != MANIFEST_SLUG and not segment_ok(seg):
                raise ProvisionError(f"manifest: mount {m['name']}: from segment {seg!r} fails "
                                     f"sandy's segment rule")
        name = m.get("export")
        if name is not None and name.startswith(SANDY_RESERVED_ENV_PREFIX):
            raise ProvisionError(f"manifest: export {name!r} is in sandy's own namespace")
    for path in doc["create"]:
        for seg in path.split("/"):
            if seg != MANIFEST_SLUG and not segment_ok(seg):
                raise ProvisionError(f"manifest: create path {path!r} has segment {seg!r} that "
                                     f"fails sandy's segment rule")
    for name, value in doc["expose"].items():
        if name.startswith(SANDY_RESERVED_ENV_PREFIX):
            raise ProvisionError(f"manifest: expose {name!r} is in sandy's own namespace")
        # Sandy carries an expose VALUE verbatim through a tab-separated,
        # newline-terminated record stream: a tab survives by luck, a newline
        # turns the value into RECORDS — an `entry` or a `mount` no manifest
        # key declared, invisible to a reviewer — and downstream the value
        # becomes `-e` on `docker run`, where a newline is a second variable
        # nothing can tell apart afterwards. Refused here, where the value is
        # rendered.
        if not isinstance(value, str) or any(c in value for c in "\t\n\r"):
            raise ProvisionError(f"manifest: expose {name!r} carries a value sandy's record "
                                 f"stream cannot hold verbatim (a tab or newline, or not a "
                                 f"string): {value!r}")
    # Whitespace in a token, or a non-string, makes sandy refuse the WHOLE
    # manifest — mounts and exports included. Caught here first, like the
    # rest, so a manifest this repo writes can never fail sandy for a reason
    # it could have seen. The agent-name check is the capability probe's,
    # which has sandy's own list; this one is static.
    for agent, tokens in doc[AGENT_ARGS_KEY].items():
        if not isinstance(agent, str) or not agent:
            raise ProvisionError(f"manifest: {AGENT_ARGS_KEY} keyed by {agent!r}, not an agent name")
        for tok in tokens:
            if not isinstance(tok, str) or not tok or any(c in tok for c in " \t\n\r"):
                raise ProvisionError(f"manifest: {AGENT_ARGS_KEY}[{agent!r}] token {tok!r} — sandy "
                                     f"refuses whitespace in a token, and the whole manifest "
                                     f"with it; use the -file form of the flag")


def manifest_text(policy: Dict[str, Any], *, receives: Optional[bool] = None) -> str:
    return json.dumps(render_manifest(policy, receives=receives), indent=2) + "\n"


def _owned_keys(receives: Optional[bool]) -> Tuple[str, ...]:
    """The deployment-owned keys an install repairs and `verify` compares.
    `receives` is left out when this sandy's answer is unknown: rendering it
    either way would be a guess, and the capability check reports the
    unreadable schema."""
    return tuple(k for k in ADAPTER_OWNED_KEYS if not (k == RECEIVES_KEY and receives is None))


def _read_manifest(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def install_manifest(home: Path, policy: Dict[str, Any], *, dry_run: bool,
                     receives: Optional[bool] = None) -> str:
    """Write the manifest when it is ABSENT (the template rendered from
    `policy` — on a fresh host the default policy), or REPAIR the
    deployment-owned blocks of the one that is there, leaving the operator's keys and
    their order untouched. A present file that does not parse is refused,
    never overwritten: it is the operator's, and the repair would destroy
    the edit that broke it."""
    path = feature_manifest_path(home)
    if path.exists():
        existing = _read_manifest(path)
        if not isinstance(existing, dict):
            raise ProvisionError(f"{path} exists but is not a JSON object — it is the authored "
                                 f"policy, so it is not overwritten; fix it by hand")
        rendered = render_manifest(policy, receives=receives)
        doc = dict(existing)
        for key in _owned_keys(receives):
            if key in rendered:
                doc[key] = rendered[key]
            else:
                doc.pop(key, None)
        want = json.dumps(doc, indent=2) + "\n"
    else:
        want = manifest_text(policy, receives=receives)
    return _write_file(path, want, dry_run=dry_run, label=FEATURE_MANIFEST_NAME)


def manifest_changed_at(home: Path) -> Optional[str]:
    """When the manifest last changed, as a `YYYY-MM-DDTHH:MM:SSZ` stamp
    from the file's mtime, or None without a readable manifest.

    The file is authored, so its own bytes cannot carry a rendering stamp
    (an install cannot write into the operator's document), and mtime is what
    is left. Sandy's caveat applies and is why every age is a WARNING and
    never a fault: rsync, backups, checkouts and editors move mtime without
    changing the rule, and then every verdict reads older than the manifest
    until each sandbox relaunches."""
    path = feature_manifest_path(home)
    try:
        st = path.stat()
    except OSError:
        return None
    return datetime.fromtimestamp(st.st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def verify_manifest(home: Path, policy: Dict[str, Any], *,
                    receives: Optional[bool] = None) -> List[str]:
    """The manifest on disk is current: its deployment-owned blocks equal
    what this deployment renders for its own policy, its `feature` section is an
    object (the policy loads — `policy` is that load), and its own `expose`
    agrees with its own `feature` (`verify_manifest_domain`)."""
    path = feature_manifest_path(home)
    if path.is_symlink():
        return [f"manifest drift: {path} is a symlink — sandy refuses one, and so does this"]
    try:
        have = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return [f"manifest absent: {path} — run install --apply, which writes the template; "
                f"without it sandy mounts nothing for this feature and selects no sandbox"]
    except OSError as e:
        return [f"manifest unreadable: {path}: {e}"]
    try:
        doc = json.loads(have)
    except json.JSONDecodeError as e:
        return [f"manifest drift: {path} is not JSON ({e}) — fix the edit by hand"]
    if not isinstance(doc, dict) or not isinstance(doc.get("feature"), dict):
        return [f"manifest drift: {path} carries no `feature` object — the policy lives there"]
    problems = []
    rendered = render_manifest(policy, receives=receives)
    stale = [k for k in _owned_keys(receives) if doc.get(k) != rendered.get(k)]
    if stale:
        problems.append(f"manifest drift: {path}: {', '.join(stale)} differ from what this "
                        f"adapter renders — those blocks are the adapter's; re-run install "
                        f"--apply, which repairs them and leaves the policy keys alone")
    problems += verify_manifest_domain(home)
    return problems


VERDICT_AT_UNKNOWN = "?"     # sandy stamps `?` when its clock call fails; never ordered


def verdict_predates_manifest(at: Any, changed_at: Optional[str]) -> Optional[bool]:
    """Was a verdict stamped `at` taken under a rule OLDER than the manifest
    now on disk? None when it cannot be told: no manifest, or sandy's `?`
    (its clock failed at that launch — unknown, never "older"). Both stamps
    are `YYYY-MM-DDTHH:MM:SSZ`, so string order is time order; anything
    else is incomparable."""
    if changed_at is None or not isinstance(at, str) or at == VERDICT_AT_UNKNOWN:
        return None
    if len(at) != len(changed_at) or not at.endswith("Z") or not changed_at.endswith("Z"):
        return None
    return at < changed_at


def verdict_lag(entry: Dict[str, Any], stamp: Optional[str]) -> Optional[str]:
    """THE ONE DEFINITION of what a verdict entry's timestamps say beyond the
    verdict itself, as the sentence an operator reads — appended to the
    `selection_states` detail and returned by `stale_verdicts`, so every
    report prints the same words this module derives, and nobody parses a
    detail string for the clause. None when the entry says
    nothing beyond its verdict. Four cases, in precedence order:

      `at == "?"`           sandy's clock failed at that launch (schema 1+)
      `evaluated_at` OLDER  the current rule has not been applied to this
                            entry — sandy's refresh does that (schema 2)
      `at` NULL             a refresh took the verdict and no launch has,
                            so nothing is mounted yet (schema 2)
      `at` OLDER            the verdict predates the manifest and stands
                            until the next launch (schema 1+)

    Every case is sandy behaving as designed, never a fault; each names the
    act that clears it."""
    at = entry.get("at")
    if at == VERDICT_AT_UNKNOWN:
        return "verdict time unknown (sandy's clock failed at that launch)"
    if "evaluated_at" in entry and verdict_predates_manifest(entry.get("evaluated_at"), stamp):
        return (f"not yet evaluated under the current rule (the manifest changed at {stamp}) "
                f"— run sandy's refresh")
    if "evaluated_at" in entry and at is None:
        return "taken by a refresh, never by a launch — relaunch to mount"
    if verdict_predates_manifest(at, stamp):
        return (f"taken under a previous rule (the manifest changed at {stamp}) — stands "
                f"until its next launch")
    return None


def stale_verdicts(home: Path, boxes: List[Dict[str, Any]]) -> Dict[str, str]:
    """`{slug: reason}` for every reported sandbox whose verdict entry
    (selected or not) says something beyond the verdict — `verdict_lag`'s
    sentence, verbatim — one definition, read by every report. Empty when
    there is no verdict file, or nothing to say. A WARNING everywhere it is
    reported: every reason is sandy behaving as designed, and mtime is the
    clock (see `manifest_changed_at`). Every case is returned, not only the
    age: a report that showed a clean `selected` over a verdict whose time
    sandy could not record would be a false green."""
    try:
        doc = load_selected(home)
    except ProvisionError:
        return {}
    stamp = manifest_changed_at(home)
    reported = {b.get("name") for b in boxes}
    out: Dict[str, str] = {}
    for key in ("selected", "not_selected"):
        for e in doc[key]:
            if isinstance(e, dict) and e.get("slug") in reported:
                reason = verdict_lag(e, stamp)
                if reason:
                    out[e["slug"]] = reason
    return out


def verify_roster_source(home: Path) -> List[str]:
    """The roster mount's SOURCE exists as a real directory. Only that: the
    file inside is the router's, and whether it is present and fresh is a
    separate question, asked once the router writes one. A missing source is
    a problem rather than a note because sandy's reaction to it is silent — it
    launches the sandbox without the mount and prints the skip only in launch
    output, which is exactly the shape `verify_lane_sources` exists for."""
    d = feature_roster_dir(home)
    if d.is_symlink():
        return [f"roster source is a symlink: {d} — the mount source must be a real "
                f"directory; remove it and run install --apply"]
    if not d.is_dir():
        return [f"roster source absent: {d} does not exist — run install --apply; sandy "
                f"launches a selected sandbox WITHOUT a mount whose source is missing, and "
                f"says so only in launch output"]
    return []


def verify_router_mount_sources(home: Path, state_dir: Path) -> List[str]:
    """The two directories `docker/run.sh` needs before the router can start:
    the instances root and the router's `state_dir`. It refuses a missing
    bind source, so either one missing means the router cannot (re)start."""
    problems: List[str] = []
    for d, what in ((feature_instances_dir(home), "instances directory"),
                    (Path(state_dir), "router state_dir")):
        if d.is_symlink():
            problems.append(f"{what} is a symlink: {d} — it must be a real directory; "
                            f"remove it and run install --apply")
        elif not d.is_dir():
            problems.append(f"{what} absent: {d} does not exist — run install --apply; "
                            f"docker/run.sh refuses to start the router without it")
    return problems


def verify_roster(home: Path, *, now: Optional[datetime] = None) -> List[str]:
    """The roster the policy text points every agent at: present, readable,
    and FRESH by this deployment's rule — `written_at` within
    `rh.FRESHNESS_MULTIPLE` x `interval_s`, the bound `router_health` applies
    to the router's own status document, and the number the policy text
    states to agents. The spec fixes no bound; it is ours.

    An absent `interval_s` is UNKNOWN, never a default: the router omits it
    when it does not know it, and inventing one would pass a roster nobody can
    vouch for. UNKNOWN MEMBERS ARE TOLERATED — the roster is runtime-authored,
    and the spec keeps such artifacts open to additions, so failing on an
    extra key would fail on a newer router that is entirely correct."""
    f = feature_roster_dir(home) / ROSTER_FILE_NAME
    try:
        doc = json.loads(f.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [f"roster absent: {f} — the policy text points every agent at it. Is the "
                f"router running a roster-writing build with this feature root mounted? Its "
                f"log names the reason once (look for 'roster')"]
    except (OSError, ValueError) as e:
        return [f"roster unreadable: {f}: {e}"]
    written = doc.get("written_at") if isinstance(doc, dict) else None
    if not isinstance(written, str) or not isinstance(doc.get("members"), list):
        return [f"roster malformed: {f} lacks `written_at` or `members`; agents will read it "
                f"as possibly out of date"]
    try:
        when = datetime.fromisoformat(written.replace("Z", "+00:00"))
    except ValueError:
        when = None
    if when is None or when.tzinfo is None:
        return [f"roster malformed: `written_at` {written!r} in {f} is not an RFC 3339 "
                f"time with an offset"]
    interval = doc.get("interval_s")
    if isinstance(interval, bool) or not isinstance(interval, (int, float)) or interval <= 0:
        return [f"UNKNOWN whether the roster is fresh: {f} carries no usable `interval_s` "
                f"(the router omits it when it does not know it — a one-shot run, or an "
                f"older build); agents are told to treat such a roster as possibly out of date"]
    age = ((now or datetime.now(timezone.utc)) - when).total_seconds()
    bound = interval * rh.FRESHNESS_MULTIPLE
    if age > bound:
        return [f"roster stale: {f} was written {age:.0f}s ago, beyond {bound:.0f}s "
                f"({rh.FRESHNESS_MULTIPLE} x interval_s {interval}) — the router has stopped "
                f"rewriting it; every agent is told to treat it as possibly out of date"]
    return []


def verify_roster_pointer_exposed(home: Path) -> List[str]:
    """Pointer present => mount declared read-only, read off the DEPLOYED
    files. The same `install` writes both, so this cannot fail on an ordinary
    fleet. It exists for the day the two are split — a hand edit, or a partial
    install — because then every agent is told to read a roster its sandbox
    does not expose, which is the one thing the spec's roster section asks the
    deployment never to do."""
    try:
        text = (feature_payload_dir(home) / POLICY_PAYLOAD_NAME).read_text(encoding="utf-8")
    except OSError:
        return []   # an absent payload is verify_feature_payload's to report
    if ROSTER_POINTER not in text:
        return []
    doc = _read_json(feature_manifest_path(home))
    mounts = doc.get("mounts") if isinstance(doc, dict) else None
    if isinstance(mounts, list) and any(
            isinstance(m, dict) and m.get("export") == EXPORT_ROSTER_DIR and m.get("mode") == "ro"
            for m in mounts):
        return []
    return [f"agents pointed at an unexposed roster: the payload's policy text names "
            f"{ROSTER_POINTER}, but the manifest on disk declares no read-only mount "
            f"exporting it. Run install --apply, which writes both together"]


def verify_manifest_domain(home: Path) -> List[str]:
    """Inside the file on disk: `expose.AMAP_FLEET_DOMAIN` equals
    `feature.fleet_domain`, both present or both absent. Sandy rewrites
    nothing in `expose`, so the container receives this value byte for byte,
    and every wrapper on the host computes its address from it; the operator
    types the domain once, in `feature`, and a sync derives the other."""
    path = feature_manifest_path(home)
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return [f"manifest unreadable: {path}: {e}"]
    if not isinstance(doc, dict):
        return [f"manifest drift: {path} is not a JSON object"]
    exposed = (doc.get("expose") or {}).get(EXPOSE_FLEET_DOMAIN)
    declared = (doc.get("feature") or {}).get(fp.FLEET_DOMAIN_KEY)
    if exposed != declared:
        return [f"manifest drift: {path} exposes {EXPOSE_FLEET_DOMAIN}={exposed!r} but its "
                f"feature section declares {fp.FLEET_DOMAIN_KEY}={declared!r} — every wrapper "
                f"on this host would compute an address the router does not route; re-run "
                f"install --apply, which derives the exposed copy from the declared one"]
    return []


def verify_feature_payload(home: Path, connector_src: Optional[Path],
                           servers_path: Path = DEFAULT_SERVERS) -> List[str]:
    """What the payload IS, against what it should be — byte for byte, real
    files, executable where the chain execs them. The host side of the mount
    is an ordinary directory under the operator's uid; a hand-edited copy is
    drift this refuses to adopt."""
    problems: List[str] = []
    dest = feature_payload_dir(home)
    if not dest.is_dir():
        return [f"payload absent: {dest} does not exist — run install --apply; "
                f"sandy mounts nothing for a selected sandbox until it does"]
    sources = payload_sources(connector_src, servers_path) if connector_src is not None else ()
    for rel, src_file, executable in sources:
        path = dest / rel
        if path.is_symlink():
            problems.append(f"payload drift: {path} is a symlink — real files only")
            continue
        try:
            have = path.read_bytes()
        except OSError:
            problems.append(f"payload drift: {path} is missing or unreadable")
            continue
        if executable and not os.access(path, os.X_OK):
            problems.append(f"payload drift: {path} is not executable")
        try:
            want = src_file.read_bytes()
        except OSError:
            problems.append(f"payload drift: cannot read {src_file} to compare against — "
                            f"pass --connector-src")
            continue
        if have != want:
            problems.append(f"payload drift: {path} differs from {src_file} — re-run "
                            f"install --apply rather than editing it")
    # The optional receipt-window variable is unrendered; a hand-set one
    # must still be a positive number, or the daemon's receipt window is
    # nonsense. Checked on the payload's wrapper, where it would be set.
    try:
        text = (dest / RELAY_WRAPPER_NAME).read_text(encoding="utf-8")
    except OSError:
        text = ""
    for line in text.splitlines():
        if line.startswith(DELIVERY_RECEIPT_WINDOW_ENV + "="):
            raw = line.split("=", 1)[1].strip().strip('"')
            try:
                if float(raw) <= 0:
                    raise ValueError
            except ValueError:
                problems.append(f"payload drift: {DELIVERY_RECEIPT_WINDOW_ENV}={raw!r} is not "
                                f"a positive number")
    return problems


def _part_is_settled(part: str) -> bool:
    """Is this install report line "nothing needed doing"?

    Every writer says `... present` for a file that is already right.
    `install_feature_payload` joins its reports with `; `, so each piece is
    judged on its own: a payload with two files present and one just
    written is NOT settled.

    Central because it is a false-green risk: a writer that starts returning
    a new phrase for "nothing to do" would otherwise be silently counted as
    a change forever (noisy, harmless) — or, if the phrase happens to end in
    " present", a change would be counted as settled (quiet, not harmless).
    Every writer's settled phrase is listed here, in one place, so adding a
    writer means adding to this list."""
    return all(
        piece.endswith(" present")
        for piece in part.split("; "))


def _print_sandboxes(sandy_bin: str, home: Path) -> None:
    """Every sandbox sandy currently reports, with sandy's own selection
    verdict for this feature — `selected`, `not selected` (and why), or
    `unknown` (not launched since the manifest was written)."""
    boxes = discover_sandboxes(sandy_bin)
    if not boxes:
        print("sandy reports no sandboxes")
        return
    states = selection_states(home, boxes)
    by_name = {b["name"]: b for b in boxes}
    width = max(len(n) for n in by_name)
    print(f"sandboxes sandy currently reports (selection from {membership_source(home)}):")
    for name in sorted(by_name):
        ws = by_name[name].get("workspace_path") or "(workspace path unknown)"
        agents = by_name[name].get("agents")
        # `null` is printed as unknown, never as the default.
        agent_word = "agents unknown" if agents is None else "agents " + ",".join(agents)
        state, detail = states[name]
        print(f"  {name:<{width}}  ({state}: {detail}; {agent_word})")
        print(f"  {'':<{width}}   workspace: {ws}")


def selection_notes(states: Dict[str, Tuple[str, str]]) -> List[str]:
    """Sandy's word on the sandboxes in `states`, one line per sandbox that
    has a verdict (its reason is sandy's and differs per sandbox) and ONE
    line for every sandbox without one — on a fleet of seventy freshly
    reset sandboxes the `unknown` detail is the same sentence seventy
    times, and a wall of identical notes hides the one line that differs."""
    lines = [f"{slug}: {state} — {detail}"
             for slug, (state, detail) in sorted(states.items()) if state != STATE_UNKNOWN]
    unknown = sorted(s for s, (state, _) in states.items() if state == STATE_UNKNOWN)
    if unknown:
        lines.append(f"{len(unknown)} {STATE_UNKNOWN} — not launched since the manifest was "
                     f"written; sandy decides at launch: {', '.join(unknown)}")
    return lines


def run_provision(
    args: argparse.Namespace, servers: Dict[str, dict], home: Path, boxes_dir: Path, dry: bool,
    policy: Optional[Dict[str, Any]] = None, states_reported: bool = False,
    verifying: bool = False,
) -> int:
    """The manifest and the payload once per host, then every selected
    sandbox. Exit 1 on any part that failed; the count of parts that needed
    changing is printed either way.

    ORDER. The manifest and the payload come FIRST, before any target and
    even when there is no target: a fresh host has nothing selected until
    sandy has read a manifest at a launch, so a run that returned early on
    "nothing selected" would never install the thing that makes anything
    selected. Then every selected slug is checked against the router's
    name rule; a sandbox not yet launched since the manifest is listed, not
    guessed at."""
    # Refuse before anything is WRITTEN: installing against a sandy that
    # cannot read this manifest installs a payload nothing mounts — and every
    # check downstream is green over a fleet that delivers nothing.
    #
    # Only on the write path. `verify` drives this function with `dry=True`
    # to compute staleness, and a read-only command must REPORT a problem, not
    # refuse to answer.
    if not dry:
        require_manifest_capable(args.sandy)
    if policy is None:
        policy = fp.load_policy(feature_manifest_path(home))

    stale = 0
    failed = 0
    # THE MANIFEST AND THE PAYLOAD, ONCE, FIRST.
    try:
        report = install_manifest(home, policy, dry_run=dry,
                                  receives=sandy_accepts_receives(args.sandy))
    except ProvisionError as e:
        print(f"  FAIL  manifest {feature_manifest_path(home)}: {e}", file=sys.stderr)
        failed += 1
    else:
        if not _part_is_settled(report):
            stale += 1
        print(f"  manifest {feature_manifest_path(home)}: {report}")
    try:
        report = install_feature_payload(home, args.connector_src, dry_run=dry,
                                         servers_path=args.servers)
    except ProvisionError as e:
        print(f"  FAIL  payload {feature_payload_dir(home)}: {e}", file=sys.stderr)
        failed += 1
    else:
        if not _part_is_settled(report):
            stale += 1
        print(f"  payload {feature_payload_dir(home)}: {report}")
    try:
        report = install_roster_dir(home, dry_run=dry)
    except ProvisionError as e:
        print(f"  FAIL  roster {feature_roster_dir(home)}: {e}", file=sys.stderr)
        failed += 1
    else:
        if not _part_is_settled(report):
            stale += 1
        print(f"  roster {feature_roster_dir(home)}: {report}")
    try:
        report = install_instances_dir(home, dry_run=dry)
    except ProvisionError as e:
        print(f"  FAIL  instances {feature_instances_dir(home)}: {e}", file=sys.stderr)
        failed += 1
    else:
        if not _part_is_settled(report):
            stale += 1
        print(f"  instances {feature_instances_dir(home)}: {report}")

    boxes = discover_sandboxes(args.sandy)
    by_name = {b["name"]: b for b in boxes}
    members = load_membership(home, boxes)
    # THE POLICY MUST BE RATIFIED before the router's config is rendered from
    # it. Reported on a dry run; a refusal on --apply, after the manifest and payload — so a
    # fresh host gets its template and is told what to edit in it.
    problems = policy_problems(policy, boxes, home)
    if problems:
        for problem in problems:
            print(f"  POLICY  {problem}", file=sys.stderr)
        print(f"  POLICY  edit {feature_manifest_path(home)} (its `feature` section is the "
              f"policy) and re-run; nothing further is installed until it passes", file=sys.stderr)
        if not dry:
            return EXIT_POLICY_UNRATIFIED
    # `--only`/`--match` reach this function only on verify's first pass
    # (the parser gives `install` no such flags); verify's own pass narrows.

    # The slugs sandy reports that are NOT selected, each with sandy's word —
    # unless the caller (`install`) already printed the whole selection
    # report, in which case repeating it is noise at fleet size.
    if not states_reported:
        states = selection_states(home, boxes)
        for line in selection_notes({s: st for s, st in states.items() if s not in members}):
            print(f"  note: {line}", file=sys.stderr)

    # NOTHING PER SANDBOX IS WRITTEN. What remains per selected slug is the
    # one thing that must be said before the router's config is rendered
    # over it: a slug sandy selected that the router would refuse as an
    # instance name. Named here, exit 1, because the fix is in the policy.
    for name in sorted(members):
        _validate_slug_shape(name)
        illegal = router_refusal(name)
        if illegal:
            print(f"  REFUSED {name}: the slug {illegal} — sandy selected it, the router "
                  f"would refuse it as an instance; exclude it in the policy", file=sys.stderr)
            failed += 1
    if not members:
        print(f"no sandbox selected yet (selection is {membership_source(home)}; sandy "
              f"decides at each launch, and applies the manifest's {AGENT_ARGS_KEY} then)")

    print(f"\nhost: {stale} part(s) needed changes"
          f"{' (nothing written — dry run)' if dry else ''}"
          + (f"; {failed} FAILED" if failed else ""))
    if verifying and stale:
        print("verify: out of date — run `install --apply`", file=sys.stderr)
        return 1
    return 1 if failed else 0


def read_session_marker(sandbox_dir: Path) -> Optional[Dict[str, Any]]:
    """sandy's session marker for this sandbox's LAST launch, read on the
    host. `None` when there is none (never launched, or a sandy too old to
    write one) or it cannot be read — the caller says which question it
    could not ask; this function never rounds absence to a document."""
    doc = _read_json(sandbox_dir / SANDY_SESSION_MARKER_NAME)
    return doc if isinstance(doc, dict) else None


SETTINGS_FLAG = "--settings"                  # Claude Code: settings from a file, last-wins


def _has_flag(args: List[str], flag: str) -> bool:
    """`flag` followed by a value in `args`."""
    return any(a == flag and i + 1 < len(args) for i, a in enumerate(args))


def _policy_text_unapplied(slug: str, why: str) -> str:
    """The problem line for a selected sandbox whose last launch did not give
    its agent this feature's MCP config and policy text."""
    return (f"amap launch arguments not applied: {slug}: {why}. Its agent can still be "
            f"delivered delegations, but without the policy text and the inbox-submit "
            f"tool it cannot reply through the router, and tends to try Claude Code's "
            f"SendMessage, which cannot reach a peer. Relaunch it (sandy --stop, then "
            f"sandy --start)")


def verify_agent_args(sandbox_dir: Path, slug: str,
                      record: Optional[Dict[str, Any]] = None) -> Tuple[List[str], List[str]]:
    """`(problems, notes)`: what sandy APPLIED for this feature at the
    sandbox's last launch, against what the manifest asks for now.

    THREE STATES, THREE SPELLINGS, and the middle one is the trap: the
    marker's `agent_args` is ABSENT from a launch under a sandy
    that predates the field — including every launch before a host was
    upgraded — and `{}` from a sandy that has it and applied none. Absent
    is "too old to say" and is LAG, because it clears at the next launch;
    it is never read as "nothing applied".

    A disagreement is LAG, never drift: the record is of the LAST launch and
    the manifest is the NEXT one, so the remedy is always a relaunch (the
    manifest itself is verified against its rendering by `verify_manifest`).
    A different path for the same two flags is a NOTE. A last launch that
    did not give the agent BOTH flags, `--mcp-config` and
    `--append-system-prompt-file`, is a PROBLEM: that agent is delivered
    delegations it cannot answer through the router. So are a launch too old
    to record the field and a marker sandy cannot read, which are UNKNOWN.
    A sandbox not launched yet is a note: it has no agent to be wrong.

    WHERE IT COMES FROM. Where sandy's `--print-state` record carries
    `marker`, `agent_args` is read from the record and a null is read
    against `marker.state` (sandy writes no deliberate null there).
    Otherwise the host copy of the marker is read directly."""
    problems: List[str] = []
    notes: List[str] = []
    marker = record.get(MARKER_KEY) if isinstance(record, dict) else None
    if isinstance(marker, dict):
        state = marker.get("state")
        if state == MARKER_ABSENT:
            notes.append(f"{slug}: sandy reports no marker — not launched yet, so what "
                         f"sandy applies for it is not knowable until it is")
            return problems, notes
        if state != MARKER_PRESENT:
            problems.append(f"agent_args unverifiable: {slug}: sandy reports its marker as "
                            f"{state!r}, so what its last launch applied cannot be read — "
                            f"relaunch it")
            return problems, notes
        recorded = record.get(AGENT_ARGS_KEY)
    else:
        doc = read_session_marker(sandbox_dir)
        if doc is None:
            notes.append(f"{slug}: no {SANDY_SESSION_MARKER_NAME} on the host — not launched "
                         f"yet, so what sandy applies for it is not knowable until it is")
            return problems, notes
        recorded = doc.get(AGENT_ARGS_KEY)
    want = agent_args_for_manifest()[MANIFEST_AGENT]
    if recorded is None:
        problems.append(_policy_text_unapplied(
            slug, f"its last launch was under a sandy that did not record {AGENT_ARGS_KEY} "
                  f"(older than {SANDY_FLOOR}), so whether it has them cannot be told"))
        return problems, notes
    if not isinstance(recorded, dict):
        problems.append(f"{slug}: {SANDY_SESSION_MARKER_NAME} carries {AGENT_ARGS_KEY}="
                        f"{recorded!r}, not an object keyed by agent — a marker this "
                        f"deployment does not recognise")
        return problems, notes
    entries = recorded.get(MANIFEST_AGENT)
    ours = None
    others_with_mcp: List[str] = []
    with_settings: List[str] = []
    for e in (entries if isinstance(entries, list) else []):
        if not isinstance(e, dict):
            continue
        if e.get("feature") == FEATURE_NAME:
            ours = e.get("args")
        elif MCP_CONFIG_FLAG in (e.get("args") or []):
            others_with_mcp.append(str(e.get("feature")))
        if SETTINGS_FLAG in (e.get("args") or []):
            with_settings.append(str(e.get("feature")))
    if with_settings:
        notes.append(f"{slug}: {', '.join(sorted(with_settings))} pass {SETTINGS_FLAG}, which "
                     f"Claude Code reads last-wins and which can set {CROSS_SESSION_KEY}; the "
                     f"cross-session check does not read it")
    if ours is None:
        problems.append(_policy_text_unapplied(
            slug, f"its last launch applied no {AGENT_ARGS_KEY} for {FEATURE_NAME} (the "
                  f"manifest declared none then, or did not select it)"))
    elif not all(_has_flag(list(ours), flag) for flag in (MCP_CONFIG_FLAG,
                                                          SYSTEM_PROMPT_FILE_FLAG)):
        problems.append(_policy_text_unapplied(
            slug, f"its last launch applied {AGENT_ARGS_KEY} {list(ours)!r}, without "
                  f"{MCP_CONFIG_FLAG} and {SYSTEM_PROMPT_FILE_FLAG} both"))
    elif list(ours) != list(want):
        notes.append(f"{slug}: its last launch applied {AGENT_ARGS_KEY} {list(ours)!r}, the "
                     f"manifest now declares {want!r} — LAG: relaunch")
    if others_with_mcp:
        notes.append(f"{slug}: {', '.join(sorted(others_with_mcp))} also pass "
                     f"{MCP_CONFIG_FLAG}; sandy fixes the ORDER, precedence is the agent's "
                     f"parser's, so assume every file loads")
    return problems, notes


# ---------------------------------------------------------------- verify
#
# Everything `install` cannot see: a dead relay is not a file at all, and a
# mount sandy skipped at launch is not something an install would change. The
# staleness check runs first, because it answers "is this host installed at
# all"; what follows are the checks that only make sense once it is.
#
# FAIL LOUD, and name the sandbox. Every failure here returns a line of the
# shape `<what>: <slug>[: <detail>]`, exit 1, because `verify` runs from
# cron too and a cron mail saying "verify failed" is worth nothing.


def _read_json(path: Path) -> Any:
    """The file's parsed content, or an `Unresolved`-shaped string reason.

    ABSENT IS NOT EMPTY. A missing file and an empty one are different facts
    with different remedies, so the caller must be able to tell them apart."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return f"absent ({path})"
    except OSError as e:
        return f"unreadable ({path}): {e}"
    except json.JSONDecodeError as e:
        return f"not valid JSON ({path}): {e}"


SANDY_SESSION_FILE = "/etc/sandy-session.json"
SANDY_SESSION_RELAY_KEY = "relay"             # the session marker's relay object: {"path", "source", "disabled_by"}
RELAY_SOURCE_MANIFEST = "manifest"            # `relay.source` when a feature manifest's `entry` supplied the relay


def own_feature_entry(doc: Any) -> Tuple[bool, Any]:
    """`(reported, entry)` for this feature in a marker or `--print-state`
    record. `reported` is False when `feature_entries` is absent or null (a
    sandy, or a last launch, that predates it): the caller falls back to
    `relay{}`. When it is reported, `entry` is this feature's object, or
    None when sandy adopted no entry for it at that launch. The gate is the
    field's PRESENCE, never sandy's version."""
    entries = doc.get(FEATURE_ENTRIES_KEY) if isinstance(doc, dict) else None
    if not isinstance(entries, dict):
        return False, None
    return True, entries.get(FEATURE_NAME)


def verify_relay_started(slug: str, container: str, *, docker_bin: str = "docker") -> List[str]:
    """SANDY'S OWN SIGNAL — the authority on whether a relay was CONFIGURED.

    Not on whether one is running: the session marker is a `:ro` bind mount
    assembled before `docker run`, so it records what sandy PINNED at launch
    and cannot know whether the relay then started. Liveness is
    `verify_relay_alive` (the daemon's heartbeat and /proc) and
    `verify_relay_supervisor` (sandy's record of every exit).

    What it proves, and nothing else does, is that sandy accepted a relay for
    this sandbox at all — nothing this tool writes can make it true. The
    marker's `relay` object carries `path`, `source` and `disabled_by`. The
    verdict is read off `path`: from sandy 2.2.0 the relay is always some
    selected feature's `entry` (`source` "manifest", or "none" when no entry
    was adopted), and `path` is the one surface that says WHICH feature's.
    Only this feature's entry is the payload this tool verifies. A `source`
    of "explicit" or "slot" is a marker written by a sandy older than
    SANDY_FLOOR, which a relaunch rewrites.

    `disabled_by` names the tier that turned the capability off (env, host
    or workspace): a cloned repository shipping `SANDY_RELAY=0` would
    otherwise disable a connector silently.

    Only meaningful for a RUNNING container: a stopped sandbox has no session
    file, and calling that a dead relay would fail `verify` on a fleet that is
    merely not all up."""
    r = subprocess.run([docker_bin, "exec", container, "cat", SANDY_SESSION_FILE],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        return [f"relay not configured: {slug}: cannot read {SANDY_SESSION_FILE} in "
                f"{container} ({r.stderr.strip() or 'no output'}) — without sandy's own "
                f"signal there is nothing that proves a relay was pinned for it"]
    try:
        doc = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        return [f"relay not configured: {slug}: {SANDY_SESSION_FILE} is not JSON ({e})"]
    if not isinstance(doc, dict):
        return [f"relay not configured: {slug}: {SANDY_SESSION_FILE} is not an object"]
    reported, mine = own_feature_entry(doc)
    if reported:
        return _verify_own_entry_marker(slug, container, mine)
    relay = doc.get(SANDY_SESSION_RELAY_KEY)
    if not isinstance(relay, dict):
        return [f"relay not configured: {slug}: {SANDY_SESSION_FILE} has no "
                f"{SANDY_SESSION_RELAY_KEY!r} object — this container was launched by a sandy "
                f"older than this deployment supports. Upgrade sandy and RELAUNCH it"]
    path = relay.get("path")
    source = relay.get("source")
    by = relay.get("disabled_by")
    if by:
        return [f"relay disabled: {slug}: sandy reports the relay capability off "
                f"(SANDY_RELAY=0 from the {by} tier). Nothing in {container} is running the "
                f"daemon. Set SANDY_RELAY=1 (or remove the 0) at that tier and relaunch"]
    if path == CONTAINER_ENTRY_PATH:
        return []
    if not path:
        return [f"relay not configured: {slug}: sandy pinned no relay at this launch — it "
                f"resolved no `entry` from the manifest. Run `install --apply` (which writes "
                f"the entry) and RELAUNCH; the marker records launch intent and nothing "
                f"since, so it cannot have noticed a later fix"]
    if source != RELAY_SOURCE_MANIFEST:
        return [f"relay elsewhere: {slug}: sandy is running {path!r}"
                + (f" (relay.source={source!r})" if source else "") + f", not the "
                f"manifest's entry at {CONTAINER_ENTRY_PATH}. Only a sandy older than "
                f"{SANDY_FLOOR} records a relay from anywhere but a feature manifest, so "
                f"{container} was launched by one. Relaunch it under sandy {SANDY_FLOOR} "
                f"or later"]
    other = _feature_of_entry_path(path)
    who = f"the {other!r} feature's entry" if other else "another feature's entry"
    return [f"relay elsewhere: {slug}: sandy pinned {who} ({path!r}) as this sandbox's "
            f"relay, not {FEATURE_NAME}'s at {CONTAINER_ENTRY_PATH}. The relay record, "
            f"and the supervisor log this tool reads through it, describe that entry, so "
            f"the payload wrapper everything else here verifies may not be running. "
            f"Exclude {FEATURE_NAME} or that feature from this sandbox, or remove that "
            f"feature's `entry`, and relaunch. There is no relay override to clear: "
            f"sandy {SANDY_FLOOR} and later refuse one"]


def _verify_own_entry_marker(slug: str, container: str, mine: Any) -> List[str]:
    """The marker's verdict off this feature's own `feature_entries` object.
    Sandy runs every selected feature's entry under its own supervisor, so
    which entry `relay{}` describes is irrelevant here and `relay_alias` is
    not read."""
    if mine is None:
        return [f"relay not configured: {slug}: sandy adopted no {FEATURE_NAME} entry at "
                f"this launch ({SANDY_SESSION_FILE} `{FEATURE_ENTRIES_KEY}` has no "
                f"{FEATURE_NAME!r}), so nothing in {container} runs the daemon. Why is "
                f"sandy's to say: `list` shows its verdict and reason. Run install --apply "
                f"and relaunch"]
    if not isinstance(mine, dict):
        return [f"relay not configured: {slug}: {SANDY_SESSION_FILE} "
                f"`{FEATURE_ENTRIES_KEY}.{FEATURE_NAME}` is {mine!r}, not an object"]
    by = mine.get("disabled_by")
    if by:
        return [f"relay disabled: {slug}: sandy reports the {FEATURE_NAME} entry off "
                f"(SANDY_RELAY=0 from the {by} tier). Nothing in {container} is running the "
                f"daemon. Set SANDY_RELAY=1 (or remove the 0) at that tier and relaunch"]
    path = mine.get("path")
    if path == CONTAINER_ENTRY_PATH:
        return []
    return [f"relay elsewhere: {slug}: sandy resolved the {FEATURE_NAME} entry to {path!r}, "
            f"not {CONTAINER_ENTRY_PATH} — the manifest sandy read at this launch names a "
            f"different `entry` from this deployment's. Run install --apply and relaunch"]


def _feature_of_entry_path(path: str) -> Optional[str]:
    """The feature whose payload `path` sits in, when it is under sandy's
    container features root (`/opt/sandy/features/<feature>/...`); None for
    any other path."""
    root = CONTAINER_FEATURES_ROOT + "/"
    if not path.startswith(root):
        return None
    name = path[len(root):].split("/", 1)[0]
    return name or None


# Sandy's relay supervisor writes this file in the relay's state directory,
# which is HOST-VISIBLE — no `docker exec`, and readable for a stopped
# container.
SUPERVISOR_LOG_NAME = "supervisor.log"


def supervisor_log_path(record: Optional[dict]) -> Optional[Path]:
    """The supervisor log, where sandy says it is: this feature's
    `feature_entries.<feature>.state_dir` off `--print-state` where that is
    reported, else `relay.state_dir` (a HOST path either way — `path` beside
    it is a CONTAINER path), joined with the file's name. None when the
    record names no state directory: sandy adopted no entry for this feature
    at its last launch, or that launch predates sandy 2.2.0, and there is no
    other location worth guessing.

    ON THE RECORD ONLY, never the session marker, by sandy's design: the
    marker is read
    in-container, where a host path does not resolve, so the in-container
    reader gets `$SANDY_RELAY_STATE` (a container path) instead and neither
    document can be mistaken for the other. The absence is permanent — a
    host path in the marker would be a NEW field named for its frame — so
    nothing here looks for `state_dir` in the marker."""
    reported, mine = own_feature_entry(record)
    if reported:
        state_dir = mine.get("state_dir") if isinstance(mine, dict) else None
    else:
        relay = record.get("relay") if isinstance(record, dict) else None
        state_dir = relay.get("state_dir") if isinstance(relay, dict) else None
    if state_dir:
        return Path(state_dir) / SUPERVISOR_LOG_NAME
    return None
SUPERVISOR_TAIL_BYTES = 65536
# Two non-zero exits inside this window is a loop, not an incident.
SUPERVISOR_LOOP_WINDOW_SECONDS = 900
# Any bracketed label: sandy's relay-designated entry logs as `[sandy-relay]`,
# any other entry as `[sandy-entry <feature>]`, and each log is one entry's.
_SUPERVISOR_RE = re.compile(
    r"^\[[^\]]+\]\s+(?P<ts>\S+)\s+(?P<event>supervisor started|start|exit rc=(?P<rc>-?\d+))")
# The supervisor refusing to start a second copy of itself: its own line, not
# the relay's stderr, and not an event.
_SUPERVISOR_LOCK_HELD_RE = re.compile(r"^\[[^\]]+\]\s+\S+\s+supervisor already running")


def read_supervisor_log(path: Path) -> Tuple[List[Tuple[str, str, Optional[int]]], List[str]]:
    """`(events, other_lines)` from the tail of sandy's relay supervisor log.

    `events` are `(timestamp, event, rc)` in file order; `other_lines` is
    everything the supervisor did not write — which is the RELAY'S OWN
    STDERR, and therefore the diagnosis. `([], [])` when there is no log.

    Only the tail is read: this file is append-only for the life of the
    sandbox and reached 400 KB in under two days on a looping relay, which is
    itself the signal."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            fh.seek(max(0, fh.tell() - SUPERVISOR_TAIL_BYTES))
            text = fh.read().decode("utf-8", errors="replace")
    except FileNotFoundError:
        return [], []
    except OSError:
        return [], []
    events: List[Tuple[str, str, Optional[int]]] = []
    other: List[str] = []
    for line in text.splitlines()[1:]:          # first line may be a partial read
        m = _SUPERVISOR_RE.match(line)
        if m:
            rc = m.group("rc")
            events.append((m.group("ts"), m.group("event").split()[0],
                           int(rc) if rc is not None else None))
        elif _SUPERVISOR_LOCK_HELD_RE.match(line):
            continue
        elif line.strip():
            other.append(line.strip())
    return events, other


def verify_relay_supervisor(sandbox_dir: Path, slug: str, *, record: Optional[dict] = None,
                            now: Optional[float] = None) -> List[str]:
    """Sandy's own record of every relay start and exit, which nothing read.

    This is the check whose absence cost 37 hours. A delivery daemon exited 2
    on 1,630 consecutive launches, once a minute, each time logging the exact
    cause — `mail notice dir ... is not a directory` — into a file sitting on
    the host the whole time. Every other signal was either silent or
    misleading: the session marker said the relay was configured (it was),
    the heartbeat was simply absent, and absence has many causes. The
    supervisor log is the only one that says WHY.

    TWO FAILURES, NOT ONE, because a relay restarted every 60 s is `started`
    whenever you sample just after a restart. Sampling alone cannot tell a
    healthy relay from a loop, so the count is what distinguishes them:

      * DOWN — the last event is a non-zero exit. Nothing is running now.
      * LOOPING — two or more non-zero exits inside the window, even if the
        most recent event is a start. This is the one a single sample misses.

    The relay's own stderr is carried into the message. An operator who has
    to go and find the log has already lost most of the value of it being
    written.

    `record` is the sandbox's `--print-state` entry, which NAMES the state
    directory (`relay.state_dir`); this reads what it names rather than
    constructing a path, because a constructed path that sandy has moved
    reads nothing, silently."""
    log = supervisor_log_path(record)
    if log is None:
        return []   # unreadable until relaunched — run_verify reports that as a note
    events, other = read_supervisor_log(log)
    if not events:
        return []

    # `_heartbeat_age_seconds` already resolves a None `now` against the clock,
    # and it is the module's one timestamp reader — a second one here would be a
    # second place for the naive-timestamp bug it documents.
    recent_failures = 0
    for ts, event, rc in events:
        if event != "exit" or not rc:
            continue
        age = _heartbeat_age_seconds(ts, now)
        if age is not None and age <= SUPERVISOR_LOOP_WINDOW_SECONDS:
            recent_failures += 1

    last_ts, last_event, last_rc = events[-1]
    why = f' Its last words: "{other[-1][:200]}".' if other else ""

    if last_event == "exit" and last_rc:
        return [f"relay is down: {slug}: sandy's supervisor log records the relay exiting "
                f"rc={last_rc} at {last_ts} and nothing running since.{why} "
                f"(log: {log})"]
    if recent_failures >= 2:
        return [f"relay is looping: {slug}: {recent_failures} non-zero exit(s) in the last "
                f"{SUPERVISOR_LOOP_WINDOW_SECONDS // 60} minutes, most recently at "
                f"{last_ts}. A relay the supervisor restarts every minute looks STARTED to "
                f"any single sample, which is why this counts instead.{why} "
                f"(log: {log})"]
    return []


def verify_relay_disabled_record(slug: str, record: Optional[dict]) -> List[str]:
    """`SANDY_RELAY=0` at the sandbox's LAST LAUNCH, off sandy's own
    `--print-state` record (`relay.disabled_by`, the tier). Readable for a
    stopped sandbox, which is why it is a separate check from the marker
    read: a cloned repo shipping `SANDY_RELAY=0` disables a connector,
    manifest entry included. LAG semantics: the last
    launch, so a tightening removed since reads as still off until the
    relaunch that clears it."""
    reported, mine = own_feature_entry(record)
    if reported:
        by = mine.get("disabled_by") if isinstance(mine, dict) else None
    else:
        relay = record.get("relay") if isinstance(record, dict) else None
        by = relay.get("disabled_by") if isinstance(relay, dict) else None
    if not by:
        return []
    return [f"relay disabled: {slug}: SANDY_RELAY=0 from the {by} tier at its last launch, "
            f"so sandy started no relay for it, the manifest's entry included. "
            f"Set SANDY_RELAY=1 (or remove the 0) at that tier and "
            f"relaunch"]


ENTRY_STATE_ABSENT = "absent"                 # `--print-state` entry `state`: no supervisor state written


def verify_entry_started_record(slug: str, record: Optional[dict]) -> List[str]:
    """For a RUNNING sandbox: this feature's entry, declared and not disabled,
    that sandy's supervisor never started. `--print-state` reports it as
    `feature_entries.<feature>.state` "absent" (no state file in its
    `state_dir`) with `disabled_by` null. The known cause is an agent image
    older than the sandy that launched it, whose container-side supervisor
    starts only the relay-designated entry. The same reading occurs for the
    first seconds of a launch, before the supervisor writes its state, so the
    report says to re-run. Silent where `feature_entries` is not reported,
    where this feature has no entry, or where it is disabled: other checks
    own those."""
    reported, mine = own_feature_entry(record)
    if not reported or not isinstance(mine, dict) or mine.get("disabled_by"):
        return []
    if mine.get("state") != ENTRY_STATE_ABSENT:
        return []
    return [f"entry not started: {slug}: sandy declared the {FEATURE_NAME} entry at the "
            f"last launch but its supervisor never started it (state {ENTRY_STATE_ABSENT!r}). "
            f"If the container started seconds ago, re-run verify. Otherwise the agent image "
            f"is likely older than sandy (a deferred rebuild) and starts only the "
            f"relay-designated entry: relaunch once the build dependencies are reachable, "
            f"or run `sandy --rebuild`"]


def verify_selection(slug: str, box: Optional[dict]) -> List[str]:
    """Sandy's own reading: a member's LAST LAUNCH selected the feature. `box`
    is the record from `discover_sandboxes` (None when sandy reported
    nothing). A candidate sandy refused names its reason in
    `feature_problems`, and the reason is there rather than nowhere."""
    if box is None:
        return [f"selection unverifiable: {slug}: sandy reports no such sandbox"]
    reported = box.get("features")
    if reported is None:
        return [f"selection unverifiable: {slug}: sandy reports no `features` field — this "
                f"sandy predates feature manifests"]
    problems: List[str] = []
    if FEATURE_NAME not in reported:
        problems.append(f"not selected: {slug}: sandy's `features` is {list(reported)!r}, "
                        f"without {FEATURE_NAME!r} — its last launch did not select this feature")
    for entry in box.get("feature_problems") or []:
        if str(entry).startswith(FEATURE_NAME + ":"):
            problems.append(f"not selected: {slug}: {entry}")
    return problems


def verify_feature_env(slug: str, container: str, *, fleet_domain: Optional[str],
                       docker_bin: str = "docker") -> List[str]:
    """The manifest's exports, read back from the RUNNING container's
    environment — the only in-container evidence a feature was applied at
    launch (the session file carries no per-feature entry). The payload
    export must name the payload mount, each lane export must be set, and
    the exposed domain must be the policy's, byte for byte (sandy rewrites
    nothing in `expose`)."""
    r = subprocess.run([docker_bin, "exec", container, "env"],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        return [f"feature env unreadable: {slug}: cannot read the environment of "
                f"{container} ({r.stderr.strip() or 'no output'})"]
    env = dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line)
    problems: List[str] = []
    if env.get(EXPORT_PAYLOAD_DIR) != CONTAINER_FEATURE_DIR:
        problems.append(f"feature not applied: {slug}: {container} has "
                        f"{EXPORT_PAYLOAD_DIR}={env.get(EXPORT_PAYLOAD_DIR)!r}, expected "
                        f"{CONTAINER_FEATURE_DIR!r} — the manifest was not applied at this "
                        f"launch (not selected, or launched before the manifest); relaunch")
    for lane in FEATURE_LANES:
        if not env.get(EXPORT_LANE_DIR[lane]):
            problems.append(f"feature not applied: {slug}: {container} has no "
                            f"{EXPORT_LANE_DIR[lane]} — the {lane} lane was not mounted")
    if env.get(EXPOSE_FLEET_DOMAIN) != fleet_domain:
        problems.append(f"fleet domain drift: {slug}: {container} has "
                        f"{EXPOSE_FLEET_DOMAIN}={env.get(EXPOSE_FLEET_DOMAIN)!r}, the policy "
                        f"declares {fleet_domain!r} — the wrapper computes the daemon's address "
                        f"from the former; relaunch after install --apply")
    return problems


def verify_feature_mount(home: Path, slug: str, container: str, *,
                         docker_bin: str = "docker") -> List[str]:
    """The payload must be MOUNTED, read-only, at its container path — asked
    of the mount table, never inferred from the host directory or sandy's
    selection verdict: both can be right while the container predates the
    manifest and mounts nothing."""
    seen, rw = container_path_for(container, feature_payload_dir(home), docker_bin=docker_bin)
    if seen is None:
        return [f"payload not mounted: {slug}: no mount in {container} covers "
                f"{feature_payload_dir(home)} — the sandbox has not been relaunched since "
                f"the manifest selected it, or its launch skipped the mount (sandy prints a "
                f"named `skip` line for a declared mount with no source)"]
    if seen.rstrip("/") != CONTAINER_FEATURE_DIR:
        return [f"payload mounted elsewhere: {slug}: {feature_payload_dir(home)} appears at "
                f"{seen} in {container}, not {CONTAINER_FEATURE_DIR}; the entry and the "
                f"registration name the latter"]
    if rw:
        return [f"payload WRITABLE: {slug}: {seen} in {container} is mounted read-write — "
                f"the read-only MOUNT is the whole of the guarantee that an agent cannot "
                f"replace the chain sandy restarts forever"]
    return []


def verify_roster_mount(home: Path, slug: str, container: str, *,
                        docker_bin: str = "docker") -> List[str]:
    """The roster directory must be MOUNTED, read-only, in a running
    container — asked of the mount table, like the payload.

    A missing mount is a PROBLEM here, not a relaunch note, although it is
    exactly what a container launched before the mount existed looks like.
    The payload is live-mounted, so an agent restarted inside that container
    reads the policy text that points at the roster without the mount behind
    it. A writable one is worse: an agent could forge the roster every other
    agent reads."""
    seen, rw = container_path_for(container, feature_roster_dir(home), docker_bin=docker_bin)
    if seen is None:
        return [f"roster not mounted: {slug}: no mount in {container} covers "
                f"{feature_roster_dir(home)} — launched before the manifest declared it, or "
                f"its launch skipped the mount; the policy text points its agent at "
                f"{ROSTER_POINTER}. Relaunch the sandbox"]
    if rw:
        return [f"roster WRITABLE: {slug}: {seen} in {container} is mounted read-write — an "
                f"agent could rewrite the fleet roster every other agent reads"]
    return []


def container_path_for(container: str, host_path: Path, *,
                       docker_bin: str = "docker") -> Tuple[Optional[str], bool]:
    """Where `host_path` appears inside `container`, and whether the mount
    carrying it is read-write. `(None, False)` if no mount covers it.

    Longest-prefix match over `docker inspect`'s mount table, not a guess at
    sandy's layout: a `:ro` bind mount may be nested inside a read-write one,
    and the mount that decides whether a path is writable is the innermost
    one covering it — which is exactly the longest matching `Source`.
    Matching the outer one instead would report the outer `RW` and call the
    protected directory writable."""
    r = subprocess.run(
        [docker_bin, "inspect", "-f",
         '{{range .Mounts}}{{.Source}}|{{.Destination}}|{{.RW}}{{"\\n"}}{{end}}', container],
        capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        return None, False
    want = os.path.realpath(str(host_path))
    best: Optional[Tuple[str, str, bool]] = None
    for line in r.stdout.splitlines():
        bits = line.split("|")
        if len(bits) != 3 or not bits[0]:
            continue
        source = os.path.realpath(bits[0])
        if want != source and not want.startswith(source.rstrip("/") + "/"):
            continue
        if best is None or len(source) > len(best[0]):
            best = (source, bits[1], bits[2].strip().lower() == "true")
    if best is None:
        return None, False
    source, dest, rw = best
    rel = os.path.relpath(want, source)
    return (dest if rel == "." else os.path.join(dest, rel)), rw


HEARTBEAT_MAX_AGE_SECONDS = 60


def _claim_host_path(sandbox_dir: Path, published: Any) -> Optional[Path]:
    """Host path of a claim the daemon published as a CONTAINER path.

    The daemon writes the claim paths as it sees them, under
    `CONTAINER_CONNECTOR`, which is `<SANDBOX_DIR>/claude/connector/` on this
    side. A pure prefix swap rather than a `docker inspect`: the mapping is a
    constant this module already owns, and a path that does NOT sit under it
    is a claim we cannot verify — reported, never assumed good."""
    # Matched on the tail, not on a whole absolute prefix: the daemon publishes
    # the path as IT sees it, under the container user's home, and that home is
    # sandy's to move. A prefix match on the home would start reporting every
    # healthy claim as unresolvable the day it moves.
    marker = "/" + CONNECTOR_REL.strip("/") + "/"
    if not isinstance(published, str) or marker not in published:
        return None
    tail = published.rsplit(marker, 1)[1]
    if not tail or tail.startswith("/"):
        return None
    return connector_state_dir(sandbox_dir) / tail


def _proc_starttime(stat_text: str) -> Optional[str]:
    """Field 22 of `/proc/<pid>/stat` — the process start time in clock ticks.

    Split after the LAST `)`: field 2 is the executable name in parentheses
    and may itself contain spaces and parens, so a plain `.split()[21]` reads
    the wrong column for any process whose name is unusual. Everything after
    that paren is field 3 onward, which puts field 22 at index 19."""
    cut = stat_text.rfind(")")
    if cut < 0:
        return None
    fields = stat_text[cut + 1:].split()
    return fields[19] if len(fields) > 19 else None


# One `docker exec`, answering three questions: is the pid running in this
# container, when did it start, and is it actually the daemon. Run through
# `sh -c` deliberately, never `docker exec <c> kill -0 <pid>`: sandy drops
# CAP_KILL from the container's bounding set, which caps root too, so `kill`
# returns EPERM for a live process and would read as "dead".
_PROC_PROBE = ("cat /proc/%(pid)d/stat 2>/dev/null || exit 1; "
               "printf '\\n%(sep)s\\n'; "
               "tr '\\0' ' ' < /proc/%(pid)d/cmdline 2>/dev/null || true")
_PROBE_SEP = "--cmdline--"


def verify_relay_alive(sandbox_dir: Path, slug: str, *, now: Optional[float] = None,
                       docker_bin: str = "docker",
                       container: Optional[str] = None) -> List[str]:
    """Two signals, BOTH required, for a sandbox that is running.

    The launch question is sandy's: it fails the launch when the relay
    cannot start. What remains this repo's is the rest of the container's
    life — a relay crash-looping under sandy's never-give-up supervisor is
    "started" by the session marker and dead in fact.

      * the daemon's HEARTBEAT — `delivery-state/daemon.json`, host-visible
        under `<SANDBOX_DIR>/claude/connector/`, so it costs no `docker
        exec`. It publishes the two claim PATHS, and each claim file must
        name the same pid the heartbeat does.
      * LIVENESS THE AGENT CANNOT WRITE — the pid FROM the heartbeat must be
        running in the container, its `/proc` start time must equal the
        `proc_start` the claims recorded, and its command line must be the
        daemon. The heartbeat and the claims are same-uid files an agent can
        write; `/proc` is not.

    Both, because either alone is satisfiable by an agent with a text editor
    (the files) or by an unrelated process (a pid that happens to exist —
    which is why the pid is read from the file rather than searched for).
    The start time is what makes the pid mean one incarnation rather than
    "some process currently numbered that", and the command line is what
    stops the agent pointing the claim at a shell it happens to own."""
    problems: List[str] = []
    state = connector_state_dir(sandbox_dir) / "delivery-state" / "daemon.json"
    doc = _read_json(state)
    if isinstance(doc, str):
        return [f"relay not alive: {slug}: heartbeat {doc}"]
    if not isinstance(doc, dict):
        return [f"relay not alive: {slug}: heartbeat is not an object"]

    pid = doc.get("pid")
    pid_ok = isinstance(pid, int) and pid > 0
    if not pid_ok:
        problems.append(f"relay not alive: {slug}: heartbeat has no usable pid ({pid!r})")

    # The claims, by the PATHS the heartbeat publishes. Each must exist and
    # name the heartbeat's pid; a claim naming someone else is the second
    # consumer this lock exists to prevent.
    claims = doc.get("claims") or {}
    starts: Dict[str, str] = {}
    for lane in ("mail", "peer"):
        published = claims.get(lane)
        if published is None:
            problems.append(f"relay not alive: {slug}: heartbeat publishes no {lane} claim")
            continue
        host = _claim_host_path(sandbox_dir, published)
        if host is None:
            problems.append(
                f"relay not alive: {slug}: {lane} claim path {published!r} has no "
                f"{CONNECTOR_REL!r} component — it cannot be mapped to a host path, and "
                f"an unverifiable claim is not a held one")
            continue
        claim = _read_json(host)
        if isinstance(claim, str):
            problems.append(f"relay not alive: {slug}: {lane} claim {claim}")
            continue
        if not isinstance(claim, dict):
            problems.append(f"relay not alive: {slug}: {lane} claim is not an object")
            continue
        held_by = claim.get("pid")
        if pid_ok and held_by != pid:
            problems.append(
                f"relay not alive: {slug}: {lane} claim is held by pid {held_by!r}, not the "
                f"heartbeat's {pid} (a claim held by something else means a second "
                f"consumer is running)")
        start = claim.get("proc_start")
        if isinstance(start, str) and start:
            starts[lane] = start

    beat = doc.get("heartbeat_at")
    age = _heartbeat_age_seconds(beat, now)
    if age is None:
        problems.append(f"relay not alive: {slug}: heartbeat_at is missing or unparsable "
                        f"({beat!r})")
    elif age > HEARTBEAT_MAX_AGE_SECONDS:
        problems.append(f"relay not alive: {slug}: heartbeat is {int(age)}s old "
                        f"(max {HEARTBEAT_MAX_AGE_SECONDS}s)")

    if not pid_ok:
        return problems
    if not container:
        problems.append(
            f"relay not alive: {slug}: no running container found, so the pid could not be "
            f"checked. The heartbeat alone is not sufficient — it is a file the agent can "
            f"write. If this sandbox is deliberately not running, it is not in the running "
            f"set and should not have reached this check")
        return problems

    r = subprocess.run(
        [docker_bin, "exec", container, "sh", "-c",
         _PROC_PROBE % {"pid": pid, "sep": _PROBE_SEP}],
        capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        problems.append(
            f"relay not alive: {slug}: pid {pid} from the heartbeat is not running in "
            f"{container} — the heartbeat file is same-uid and forgeable; this check "
            f"is the one that is not")
        return problems

    stat_text, _, cmdline = r.stdout.partition("\n" + _PROBE_SEP + "\n")
    observed = _proc_starttime(stat_text)
    if observed is None:
        problems.append(
            f"relay not alive: {slug}: could not read the start time of pid {pid} in "
            f"{container} — an unread check is not a pass")
    else:
        for lane, recorded in sorted(starts.items()):
            if recorded != observed:
                problems.append(
                    f"relay not alive: {slug}: the {lane} claim records proc_start "
                    f"{recorded!r} but pid {pid} in {container} started at {observed!r} — "
                    f"the claim belongs to an earlier process, not the running one")
    if DELIVERY_DAEMON_NAME not in cmdline:
        problems.append(
            f"relay not alive: {slug}: pid {pid} in {container} is running "
            f"{cmdline.strip()!r}, not {DELIVERY_DAEMON_NAME} — the heartbeat can name any "
            f"live pid, so the pid must be shown to be the daemon")
    return problems


def _heartbeat_age_seconds(value: Any, now: Optional[float] = None) -> Optional[float]:
    """Seconds since `value`, an ISO-8601 timestamp. `None` if unparsable.

    Naive timestamps are read as UTC rather than local: the daemon writes
    inside a container whose timezone this host has no reason to share, and
    guessing local would make a fresh heartbeat look hours stale (or, worse,
    a stale one look fresh) depending on which way the offset ran."""
    if not isinstance(value, str):
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        when = datetime.fromisoformat(text)
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    reference = (datetime.fromtimestamp(now, timezone.utc) if now is not None
                 else datetime.now(timezone.utc))
    return (reference - when).total_seconds()


def running_containers(sandy_bin: str = "sandy",
                       docker_bin: str = "docker") -> Dict[str, str]:
    """`{slug: container}` for every running sandy container.

    From `docker ps` plus the `sandy.session` label. An empty result is a normal state (nothing running),
    never an error — but a sandbox sandy reports as RUNNING and docker does
    not is a disagreement `verify` reports rather than resolves."""
    out: Dict[str, str] = {}
    try:
        p = subprocess.run([docker_bin, "ps", "--format", "{{.Names}}"],
                           capture_output=True, text=True, timeout=60)
    except OSError:
        return out
    if p.returncode != 0:
        return out
    for name in p.stdout.split():
        q = subprocess.run(
            [docker_bin, "inspect", "-f", '{{index .Config.Labels "sandy.session"}}', name],
            capture_output=True, text=True, timeout=60)
        slug = q.stdout.strip()
        if q.returncode == 0 and slug:
            out[slug] = name
    return out


CROSS_SESSION_KEY = "crossSessionInbound"
CROSS_SESSION_ACCEPT = "accept"
#: The values that TIGHTEN. Sandy writes the resolved value into two places and
#: they are not peers: the container's own `claude/settings.json` is what can
#: deliver `accept`, while the workspace's `.claude/settings.local.json` is a
#: tighten-only seam whose `hold`/`refuse` BEAT the other copy. `accept` written
#: to the seam is a delivery no-op that exists only to scrub a stale tightening
#: sandy itself wrote on an earlier launch.
CROSS_SESSION_TIGHTENINGS = ("hold", "refuse")


def _cross_session_value(path: Optional[Path]) -> Optional[str]:
    doc = _read_json(path) if path else None
    value = doc.get(CROSS_SESSION_KEY) if isinstance(doc, dict) else None
    return value if isinstance(value, str) else None


#: The workspace's COMMITTED settings file. Claude Code reads `crossSessionInbound`
#: from it too, and there it can only tighten, like `settings.local.json`. Sandy
#: neither writes nor reports it, so this reads it, with sandy's own guards:
#: it is repository content, and a symlink, a FIFO (which would block the
#: read, and `verify`, forever) or an oversized file is not opened.
WORKSPACE_COMMITTED_SETTINGS = "settings.json"
WORKSPACE_SETTINGS_MAX_BYTES = 1048576
#: `--print-state`'s `cross_session_inbound` statuses this check reads. Any
#: other status is UNKNOWN: sandy's vocabulary may grow.
SETTING_OK = "ok"
SETTING_NONE = ("key_absent", "file_absent")
SETTING_NOT_OBJECT = "not_object"
PINNED_NOT_CLAUDE = "not_claude"
PINNED_NOT_WRITTEN = "not_written"
MARKER_KEY = "marker"
MARKER_ABSENT = "absent"
MARKER_PRESENT = "present"
CROSS_SESSION_INBOUND_KEY = "cross_session_inbound"
#: What the cross-session verdict covers, stated once per run: the check reads
#: these inputs and no others, and Claude Code's precedence among them is the
#: one sandy documents as measured.
CROSS_SESSION_COVERAGE = (
    "cross-session inbound: verify reads the sandbox's claude/settings.json and the "
    "workspace's .claude/settings.local.json (from sandy's --print-state where it reports "
    "them) and the workspace's committed .claude/settings.json; a `--settings` flag in "
    "agent_args is named where one is found and not read")


def _workspace_setting(workspace: Optional[Path], name: str) -> Tuple[Optional[str], Optional[str]]:
    """`(value, trouble)` for `crossSessionInbound` in `<workspace>/.claude/<name>`.
    `trouble` is None when the answer is known (a value, or none there), and
    otherwise says why it is not."""
    if workspace is None:
        return None, None
    d = Path(workspace) / ".claude"
    f = d / name
    if d.is_symlink() or f.is_symlink():
        return None, "is a symlink, which is not followed"
    if not f.exists():
        return None, None
    if not f.is_file():
        return None, "is not a regular file"
    try:
        if f.stat().st_size > WORKSPACE_SETTINGS_MAX_BYTES:
            return None, "is over 1 MiB"
        doc = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as e:
        return None, f"cannot be read ({e})"
    except json.JSONDecodeError:
        return None, "is not valid JSON"
    if not isinstance(doc, dict):
        return None, "is not a JSON object"
    value = doc.get(CROSS_SESSION_KEY)
    if value is None:
        return None, None
    return (value if isinstance(value, str) else json.dumps(value)), None


def _reported_setting(obj: Any) -> Tuple[Optional[str], Optional[str]]:
    """`(value, trouble)` from one `--print-state` settings-file object."""
    status = obj.get("status") if isinstance(obj, dict) else None
    if status == SETTING_OK:
        value = obj.get("value")
        return (value if isinstance(value, str) else None), None
    if status in SETTING_NONE:
        return None, None
    if status == SETTING_NOT_OBJECT:
        return None, ("is torn or not a JSON object (sandy issue #400 tears the user copy "
                      "under a single-file bind mount)")
    return None, f"is reported by sandy as {status!r}"


def _pinned_verdict(slug: str, record: Dict[str, Any],
                    pinned: Any) -> Optional[Tuple[List[str], List[str]]]:
    """The verdict `--print-state`'s `pinned` value settles on its own, or
    None when it is `ok` and the settings files decide. A null `pinned` is
    read against `marker.state`: sandy never writes a deliberate null there."""
    if pinned is None:
        marker = record.get(MARKER_KEY)
        state = marker.get("state") if isinstance(marker, dict) else None
        if state == MARKER_ABSENT:
            return [], [f"{slug}: not launched (sandy reports no marker), so no "
                        f"{CROSS_SESSION_KEY} has been resolved; it is resolved at launch"]
        if state == MARKER_PRESENT:
            return [], [f"{slug}: its last launch was under a sandy that did not record the "
                        f"resolved {CROSS_SESSION_KEY} — LAG: relaunch it"]
        return [f"cross-session inbound unverifiable: {slug}: sandy reports no pinned "
                f"{CROSS_SESSION_KEY} and its marker as {state!r} — relaunch it, and check "
                f"`sandy --print-state` if this persists"], []
    status = pinned.get("status") if isinstance(pinned, dict) else None
    if status == SETTING_OK:
        return None
    if status == PINNED_NOT_CLAUDE:
        return [], [f"{slug}: its last launch ran no Claude Code agent ({CROSS_SESSION_KEY} "
                    f"is Claude-only), so the Claude Code connector installed here can never "
                    f"deliver — exclude this sandbox in the policy"]
    if status == PINNED_NOT_WRITTEN:
        return [f"cross-session inbound not set: {slug}: Claude Code runs, but sandy's "
                f"writes of {CROSS_SESSION_KEY} were refused at its last launch, so nothing "
                f"resolved it and delegations may be refused. Check that the sandbox's "
                f"claude/ and the workspace's .claude/ are writable, then relaunch"], []
    return [f"cross-session inbound unverifiable: {slug}: sandy reports the pinned "
            f"{CROSS_SESSION_KEY} as {status!r} — relaunch it"], []


def verify_cross_session_inbound(
    sandbox_dir: Path, slug: str, workspace: Optional[Path],
    record: Optional[Dict[str, Any]] = None,
) -> Tuple[List[str], List[str]]:
    """`(problems, notes)` for whether this sandbox will ACCEPT an injection.

    A SILENT-REFUSAL PATH. The router will route to an instance that refuses
    on arrival, the daemon reports `refused`, and the sender gets a DSN with
    no reason attached because the router forwards none — while mounts,
    trees and peer edges are all green.

    THE INPUTS ARE NOT PEERS. The container's `claude/settings.json` is the
    copy that can deliver `accept`. The workspace's `.claude/settings.local.json`
    (which sandy writes) and its committed `.claude/settings.json` (which it
    does not) are tighten-only: a `hold` or `refuse` in either wins over the
    first, and the stricter of the two wins. Reading only the container's
    copy would report a sandbox as reachable while a workspace file quietly
    refuses everything.

    WHERE THE VALUES COME FROM. Where sandy's `--print-state` record reports
    `cross_session_inbound`, the pinned launch value and both files it writes
    are read from there, and its statuses decide what is known. Otherwise
    the two files are read directly. The committed file is always read here,
    since sandy does not report it. Anything that cannot be read is UNKNOWN,
    and a problem.

    `hold` is a NOTE, not a problem: it gates delivery behind the recipient
    user's approval rather than breaking it, the router treats the resulting
    `held` outcome as an alert rather than a failure, and an operator who set
    it meant it.

    An ABSENT value is also a note: what Claude Code then defaults to is not
    ours to assert.
    """
    csi = record.get(CROSS_SESSION_INBOUND_KEY) if isinstance(record, dict) else None
    if isinstance(csi, dict):
        settled = _pinned_verdict(slug, record, csi.get("pinned"))
        if settled is not None:
            return settled
        user, user_trouble = _reported_setting(csi.get("user_settings"))
        local, local_trouble = _reported_setting(csi.get("workspace_settings"))
    else:
        user, user_trouble = _cross_session_value(
            Path(sandbox_dir) / "claude" / "settings.json"), None
        local, local_trouble = _cross_session_value(
            Path(workspace) / ".claude" / "settings.local.json" if workspace else None), None
    committed, committed_trouble = _workspace_setting(workspace, WORKSPACE_COMMITTED_SETTINGS)
    troubles = [f"{label} {why}" for label, why in (
        ("the sandbox's claude/settings.json", user_trouble),
        ("the workspace's .claude/settings.local.json", local_trouble),
        ("the workspace's committed .claude/settings.json", committed_trouble)) if why]
    if troubles:
        return [f"cross-session inbound unverifiable: {slug}: {'; '.join(troubles)} — so "
                f"whether this instance accepts delegations cannot be told. Fix or remove "
                f"that file, then relaunch"], []

    seams = ((local, "the workspace seam"),
             (committed, "the workspace's committed .claude/settings.json"))
    effective, where = user, "its own settings"
    for tightening in reversed(CROSS_SESSION_TIGHTENINGS):
        hit = [w for v, w in seams if v == tightening]
        if hit:
            effective, where = tightening, hit[0]
            break
    if effective == CROSS_SESSION_ACCEPT:
        return [], []
    if effective is None:
        # ABSENCE HAS TWO CAUSES AND THEY ARE NOT THE SAME PROBLEM.
        #
        # `SANDY_CROSS_SESSION_INBOUND` is documented Claude-only, so sandy
        # writes NOTHING here for a sandbox running another agent. A sandbox
        # running another agent would get a Claude Code connector and a daemon
        # that injects into a Claude Code session, and its only symptom would
        # be a relay crash-looping on a `~/.claude` tree that never exists —
        # so the note says what the absence can mean. Where `--print-state`
        # reports `pinned`, the second cause arrives as `not_claude` instead.
        return [], [f"{slug}: no {CROSS_SESSION_KEY} resolved. TWO causes, and they need "
                    f"different fixes: this sandbox has not been launched since the "
                    f"setting existed (launch it once), OR it does not run Claude Code at "
                    f"all — the setting is Claude-only, so sandy writes none for another "
                    f"agent. In that case the connector installed here can never work and "
                    f"the sandbox should be excluded in the policy. `docker logs` on "
                    f"its container names the agent sandy launched"]
    if effective == "hold":
        return [], [f"{slug}: {CROSS_SESSION_KEY} is 'hold' ({where}) — delegations are "
                    f"held for the recipient user's approval, not delivered. Deliberate if "
                    f"you set it; the router reports these as `held`, an alert, not a fault"]
    committed_wins = where == seams[1][1]
    remedy = ("Remove it from that file in the repository: sandy does not write it, so a "
              "relaunch does not change it" if committed_wins else
              "Relaunch it so sandy re-resolves; the value is decided at launch")
    return ([f"{slug}: {CROSS_SESSION_KEY} is {effective!r} ({where}) — this instance will "
             f"REFUSE every delegation at the session level, and the sender is told only "
             f"`refused` with no reason. {remedy}"], [])


# ------------------------------------------------ the router's sibling config
#
# The router discovers its instances from `instances_dir` and admits each by
# `selected_json`, so its config carries NO instance table: three roots, the
# fleet's domain, and the two graphs, in the router's exact tokens. MEASURED
# against the router's loader rather than inferred: the wildcard word and the map are DIFFERENT KEYS (`task_graph:
# "all"` xor `peer_senders: {recipient: [senders]}`; `mail_graph: "all"` xor
# `peers: {slug: [slugs]}`), every path is absolute or refused, the three
# roots are required together, `fleet_domain` is optional, and an UNKNOWN
# KEY IS REFUSED — so this document carries no stamp, no comment and no
# marker, and `SIBLING_KEYS` is the whole vocabulary.

SIBLING_STATE_DIR = "state_dir"
SIBLING_INSTANCES_DIR = "instances_dir"
SIBLING_SELECTED_JSON = "selected_json"
SIBLING_FLEET_DOMAIN = fp.FLEET_DOMAIN_KEY
SIBLING_TASK_GRAPH = "task_graph"
SIBLING_PEER_SENDERS = "peer_senders"
SIBLING_MAIL_GRAPH = "mail_graph"
SIBLING_PEERS = "peers"
SIBLING_KEYS = (SIBLING_STATE_DIR, SIBLING_INSTANCES_DIR, SIBLING_SELECTED_JSON,
                SIBLING_FLEET_DOMAIN, SIBLING_TASK_GRAPH, SIBLING_PEER_SENDERS,
                SIBLING_MAIL_GRAPH, SIBLING_PEERS)
# The router's WHOLE top-level vocabulary — its `config._TOP_KEYS` — so that `SIBLING_KEYS` is pinned as a SUBSET of it and this renderer can
# never emit a key the loader refuses. `instances` is the AUTHORED
# alternative to discovery and is never rendered; `intake_dir` is optional
# (absolute, not nested with state_dir; `provision` creates
# `<intake_dir>/<instance>/` under discovery) and nothing in this deployment
# renders it; the attachment limits and the two windows are optional
# tunables with the router's defaults. Zero of a graph pair loads as "no such
# lane", which is why a fleet with no mail edge renders
# neither `mail_graph` nor `peers`.
ROUTER_TOP_KEYS = (
    SIBLING_STATE_DIR, SIBLING_INSTANCES_DIR, SIBLING_SELECTED_JSON, "instances",
    SIBLING_FLEET_DOMAIN, SIBLING_TASK_GRAPH, SIBLING_PEER_SENDERS,
    SIBLING_MAIL_GRAPH, SIBLING_PEERS, "intake_dir",
    "attachment_max_bytes", "attachment_max_count", "attachment_max_total_bytes",
    "sender_exposure_window_seconds", "peer_reply_window_seconds",
)
# What the router reads and this renderer deliberately never writes.
SIBLING_KEYS_NEVER_RENDERED = tuple(k for k in ROUTER_TOP_KEYS if k not in SIBLING_KEYS)
assert set(SIBLING_KEYS) <= set(ROUTER_TOP_KEYS)
# The router's spelling of its two wildcards (`router.config.TASK_GRAPH_ALL`
# / `MAIL_GRAPH_ALL`, the same string by the router's design), pinned against
# the router's own constants in tests/test_layout_agreement.py. The policy's
# spelling (`fp.TASK_GRAPH_ALL`) is different on purpose: this renderer
# translates, the router does not. No policy form maps to `mail_graph: "all"`
# (the policy's `@all` is EXPANDED, so the mail lane is always the map), and
# nothing here emits the word.
ROUTER_TASK_GRAPH_ALL = "all"
ROUTER_MAIL_GRAPH_ALL = "all"
ROUTER_STATE_SUBDIR = "router-state"
ROUTER_FIRST_SIGHT_NAME = "first-seen.json"     # router.firstsight's marker, counted by teardown


def _sibling_path(path: Path) -> Path:
    """Absolute and normalised (no `.` or `..` segment), symlinks untouched:
    the one spelling of a path the sibling carries, so that two renderings
    of one directory are one string."""
    return Path(os.path.normpath(str(Path(path).absolute())))


def sibling_state_dir(home: Path, explicit: Optional[str]) -> Path:
    """The `state_dir` a rendering uses: `--state-dir` when given; otherwise
    the one the sibling ON DISK already carries; otherwise the conventional
    default. The middle case is the point: state_dir is the operator's
    choice and the router refuses a reload that would change it, so a
    re-render or a `verify` without `--state-dir` must keep the one in force
    rather than report the operator's own choice as drift."""
    if explicit:
        return Path(explicit)
    existing = _read_json(router_sibling_path(home))
    if isinstance(existing, dict) and isinstance(existing.get(SIBLING_STATE_DIR), str) \
            and existing[SIBLING_STATE_DIR]:
        return Path(existing[SIBLING_STATE_DIR])
    return home / ROUTER_STATE_SUBDIR


def render_router_sibling(policy: Dict[str, Any], members: Dict[str, dict],
                          home: Path, state_dir: Path,
                          sandbox_paths: Optional[Dict[str, Path]] = None) -> Dict[str, Any]:
    """The sibling document for `policy` over the selected set `members`
    (`load_membership`'s return value: `{slug: record}`), plus the warnings
    the graph resolution raises, as `{"_doc": ..., "_warnings": [...]}`.

    TOTAL OVER THE SELECTED SET, not over what has launched: the router
    reports an edge naming a slug it has not discovered as INERT (pending
    when the host has a verdict for it), never as a load refusal, so a
    selected sandbox that has not relaunched under this manifest is named
    here and becomes reachable at its launch with no re-render. An empty
    selected set renders an empty graph rather than refusing: the router
    discovers as sandboxes launch, and a document written before the first
    launch is the point of discovery.

    `state_dir` is refused inside any sandbox root or the instances tree:
    it holds the first-sight markers, the reply ledger and the quarantine,
    and an agent that can reach it can forge the binding that stops it
    redirecting a reply."""
    names = sorted(members)
    try:
        resolved_peers = fp.resolve_peers(policy, names, members)
        task_graph = fp.resolve_task_graph(policy, names)
    except fp.PolicyError as e:
        raise ProvisionError(str(e)) from e
    warnings = list(fp.one_sided(resolved_peers))
    warnings += fp.overlapping_pairs(policy, resolved_peers, task_graph)

    # `.absolute()` then NORMALISED, never `.resolve()`: a host's paths may
    # run through symlinks, and resolving them would write the real
    # directory's spelling into a config the operator reads back in the
    # symlinked one — but a `..` or `.` segment is not a spelling, it is a
    # second name for the same directory, and `features/amap/../router-state`
    # against a state_dir spelled plainly is byte-for-byte drift between two
    # names of one place. `os.path.normpath` on an absolute path removes the
    # segments and follows no symlink.
    state = _sibling_path(Path(state_dir).expanduser())
    instances = _sibling_path(feature_instances_dir(home))
    roots = {"the instances tree": instances}
    for slug, root in (sandbox_paths or {}).items():
        roots[f"{slug}'s sandbox root"] = Path(root).absolute()
    for what, root in roots.items():
        if state == root or root in state.parents:
            raise ProvisionError(
                f"state_dir {state} is inside {what} {root}. That state is "
                f"router-private — first-sight markers, the reply ledger and the "
                f"quarantine — and an agent that can reach it can forge the binding "
                f"that stops it redirecting a reply. Put it outside every sandbox, "
                f"e.g. $SANDY_HOME/{ROUTER_STATE_SUBDIR}.")

    doc: Dict[str, Any] = {
        SIBLING_STATE_DIR: str(state),
        SIBLING_INSTANCES_DIR: str(instances),
        SIBLING_SELECTED_JSON: str(_sibling_path(feature_selected_path(home))),
    }
    domain = policy.get(fp.FLEET_DOMAIN_KEY)
    if domain is not None:
        doc[SIBLING_FLEET_DOMAIN] = domain
        # The delegation lane exists only under a domain (the router's loader
        # refuses `peer_senders` without one). The wildcard is PASSED THROUGH
        # as the router's one word — rendering its expansion would put N
        # lists in the file that say what one word says, every one of them
        # drift the day a sandbox is selected. An explicit graph is total:
        # an instance nobody may task maps to [], because `verify` diffs
        # this element for element against the router's `peers --json`,
        # which emits [] for exactly that reason.
        if policy.get(fp.TASK_GRAPH_KEY) == fp.TASK_GRAPH_ALL:
            doc[SIBLING_TASK_GRAPH] = ROUTER_TASK_GRAPH_ALL
        else:
            doc[SIBLING_PEER_SENDERS] = {n: list(task_graph[n]) for n in names}
    # The mail lane: only the instances with an entry. A fleet with no mail
    # edge carries no mail key at all — `peers: {}` and an absent key mean
    # the same thing to the router, and neither is required.
    peers = {n: list(resolved_peers[n]) for n in names if resolved_peers[n]}
    if peers:
        doc[SIBLING_PEERS] = peers
    assert set(doc) <= set(SIBLING_KEYS), sorted(set(doc) - set(SIBLING_KEYS))
    return {"_doc": doc, "_warnings": warnings}


def validate_with_router(doc: Dict[str, Any]) -> Optional[str]:
    """Load the rendered sibling through the router's REAL loader when it is
    importable. The renderer producing a document the router then refuses is
    the one failure this rendering exists to prevent, so it is proved rather
    than assumed. Returns an error string, `None` when the loader accepted
    it, and `None` too when no loader is importable (not checked out: not an
    error, and `verify` reports that case by name)."""
    try:
        from router.config import load_obj  # type: ignore
    except ImportError:
        return None
    try:
        load_obj(json.loads(json.dumps(doc)))
        return None
    except Exception as e:                           # noqa: BLE001 — reporting, not handling
        return f"{type(e).__name__}: {e}"


def sibling_text(doc: Dict[str, Any]) -> str:
    return json.dumps(doc, indent=2) + "\n"


def sibling_diff(existing: Any, rendered: Dict[str, Any]) -> List[str]:
    """What differs between the file on disk and the rendering, in operator
    terms, by key. The delegation map is compared ELEMENT FOR ELEMENT (the
    router's `peers --json` is diffed positionally against it); the mail map per slug as a set, because it is
    mutual and a reordered list means the same thing."""
    if not isinstance(existing, dict):
        return ["the file on disk is not a JSON object"]
    out: List[str] = []
    for key in sorted(set(existing) - set(SIBLING_KEYS)):
        out.append(f"- {key}: not a key the router reads — it refuses the file over it")
    for key in SIBLING_KEYS:
        have, want = existing.get(key), rendered.get(key)
        if key in (SIBLING_PEER_SENDERS, SIBLING_PEERS) and isinstance(have, dict) \
                and isinstance(want, dict):
            for slug in sorted(set(have) | set(want)):
                h, w = have.get(slug), want.get(slug)
                if key == SIBLING_PEERS:
                    same = set(h or []) == set(w or [])
                else:
                    same = list(h or []) == list(w or [])
                if not same:
                    out.append(f"~ {key}[{slug}] {h!r} -> {w!r}")
            continue
        if have != want:
            if have is None:
                out.append(f"+ {key}: {want!r}")
            elif want is None:
                out.append(f"- {key}: {have!r} (the policy no longer declares it)")
            else:
                out.append(f"~ {key} {have!r} -> {want!r}")
    return out


def run_render_router(args: argparse.Namespace, home: Path, boxes: List[Dict[str, Any]],
                      policy: Dict[str, Any], *, apply: bool) -> int:
    """Render the sibling and write it (`apply`) or compare it (dry). Exit 0
    when the file matches the rendering; 1 when it differs or is absent and
    was not written; 2 when it cannot be rendered at all. Prints one line per
    outcome; sibling tools parse them, so their spelling moves by agreement."""
    path = router_sibling_path(home)
    members = load_membership(home, boxes)
    state_dir = sibling_state_dir(home, args.state_dir)
    sandbox_paths = {b["name"]: Path(b["path"]) for b in boxes if b.get("name") and b.get("path")}
    try:
        result = render_router_sibling(policy, members, home, state_dir, sandbox_paths)
    except ProvisionError as e:
        print(f"router config: cannot render — {e}", file=sys.stderr)
        return 2
    doc = result["_doc"]
    for w in result["_warnings"]:
        print(f"router config warning: {w}", file=sys.stderr)
    refused = validate_with_router(doc)
    if refused:
        print(f"router config: cannot render — the router's own loader refuses the "
              f"rendering: {refused}", file=sys.stderr)
        return 2
    names = ", ".join(sorted(members))
    # The router cannot start without its state_dir, so it is created here —
    # only after the rendering (state_dir included) has passed the router's
    # own loader, so a placement the router refuses is never created.
    try:
        print(f"router state_dir {state_dir}: "
              f"{install_router_state_dir(state_dir, dry_run=not apply)}")
    except ProvisionError as e:
        print(f"router state_dir: {e}", file=sys.stderr)
        return 2
    want = sibling_text(doc)
    try:
        have = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        have = None
    except OSError as e:
        print(f"router config: cannot read {path}: {e}", file=sys.stderr)
        return 2
    if apply:
        if have == want:
            print(f"router config current: {path} — {len(members)} instance(s): {names}")
            return 0
        _write_file(path, want, dry_run=False, label=ROUTER_SIBLING_NAME)
        print(f"wrote {path} — {len(members)} instance(s): {names}")
        return 0
    if have is None:
        print(f"router config absent: would write {path} — {len(members)} instance(s): "
              f"{names} (pass --apply)")
        return 1
    if have == want:
        print(f"router config in sync: {len(members)} instance(s): {names}")
        return 0
    existing = _read_json(path)
    changes = sibling_diff(existing, doc) if not isinstance(existing, str) else [existing]
    if not changes:
        changes = ["same content, different bytes (whitespace or key order)"]
    print(f"router config DRIFT vs {path} (re-run install --apply to adopt; the file is "
          f"generated and a hand edit is lost then):")
    for c in changes:
        print(f"  {c}")
    return 1


def verify_router_sibling(home: Path, policy: Dict[str, Any], members: Dict[str, dict],
                          state_dir: Path, sandbox_paths: Dict[str, Path]) -> List[str]:
    """`verify`'s half: the file on disk is byte for byte the rendering.
    Absent is a problem (the router has nothing to start from), a hand edit
    is drift with the re-sync as remedy."""
    path = router_sibling_path(home)
    try:
        doc = render_router_sibling(policy, members, home, state_dir, sandbox_paths)["_doc"]
    except ProvisionError as e:
        return [f"router config: cannot render: {e}"]
    try:
        have = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return [f"router config absent: {path} — run install --apply; the router reads it "
                f"by --config and has nothing to start from without it"]
    except OSError as e:
        return [f"router config: cannot read {path}: {e}"]
    if have == sibling_text(doc):
        return []
    existing = _read_json(path)
    changes = sibling_diff(existing, doc) if not isinstance(existing, str) else [existing]
    if not changes:
        changes = ["same content, different bytes (whitespace or key order)"]
    return [f"router config drift: {path}: {c} — re-run install --apply" for c in changes]

# ----------------------------------------------- the lane tree, host-side
#
# Sandy creates every lane from the manifest's `create` at a selected launch
# and SKIPS a declared mount whose source is missing — by name, at launch,
# applying the feature without it — so the daemon then runs with a lane
# unmounted while every other signal stays green. `verify_lane_sources` is the
# check an operator
# sees for that.


def lane_tree_paths(home: Path, slug: str) -> List[Path]:
    """Every directory the manifest's `create` block names for `slug` —
    each lane and each leaf, the router's list — in creation order."""
    dest = feature_instances_dir(home) / slug
    out = []
    for lane in FEATURE_LANES:
        out.append(dest / lane)
        for leaf in FEATURE_LANE_LEAVES[lane]:
            out.append(dest / lane / leaf)
    return out


def verify_lane_sources(home: Path, slug: str) -> List[str]:
    """Every directory the manifest's `create` block names exists for
    `slug`: each lane under `instances/<slug>/` (a mount source — a missing
    one is a NAMED SKIP at launch: the feature applies without that mount,
    the daemon then starts without a lane, and every other signal stays
    green; sandy prints the skip only in launch output, so this is the one
    check the operator sees) AND every leaf under each lane. Lane directories
    present with `inbox/notices` and `inbox/messages` absent is a real shape
    (after a reset): the daemon is fatal on "not a directory" and sandy
    restarts it into a log nobody reads. The router's `provision` refuses on exactly the
    same list (its `LANE_LEAVES`, which `lane_tree_paths` renders)."""
    problems = []
    dest = feature_instances_dir(home) / slug
    for path in lane_tree_paths(home, slug):
        if path.is_dir():
            continue
        if path.parent == dest:
            problems.append(f"lane source absent: {slug}: {path} — sandy skips a declared mount "
                            f"whose source is missing and applies the feature without it; "
                            f"relaunch the sandbox under the manifest (sandy creates every "
                            f"lane from `create` at a selected launch)")
        else:
            problems.append(f"lane leaf absent: {slug}: {path} — the daemon opens it and "
                            f"refuses to start without it (exit 2, restarted by sandy every "
                            f"second), and the router's provision refuses the instance; "
                            f"relaunch under the manifest (sandy creates every leaf from "
                            f"`create` at a selected launch)")
    return problems


class HostFacts:
    """What `verify --host-facts` writes, collected as the run goes so the
    document can be written on EVERY exit — including one that failed
    before the router sections ran. A console must be able to tell "verify
    failed at the manifest and never reached the router" from "the router
    was read and was fine", and it can only do that if the stopping run
    still produces a document saying so."""

    def __init__(self) -> None:
        self.ctx: Optional[rh.Ctx] = None
        self.outcomes: List[rh.Outcome] = []

    def write(self, path: Path, rc: int) -> None:
        rh.write_host_facts(path, self.outcomes, rc, self.ctx)


def run_verify(args: argparse.Namespace, servers: Dict[str, dict], home: Path,
               boxes_dir: Path, facts: Optional[HostFacts] = None) -> int:
    """Every check, over every selected sandbox, then the router process.
    Exit 1 on any problem — an UNKNOWN about the router included, because
    "could not tell" is not a clean bill.

    Order matters only for readability: every check runs for every sandbox
    and every problem is printed, rather than stopping at the first. An
    operator fixing a fleet wants the whole list, and a check that stops
    early makes "how bad is it" take one run per fault."""
    policy = fp.load_policy(feature_manifest_path(home))
    try:
        reported = discover_sandboxes(args.sandy)
        records = {b["name"]: b for b in reported}
        boxes = {name: Path(b["path"]) for name, b in records.items()}
    except ProvisionError as e:
        print(f"FAIL: cannot ask sandy which sandboxes exist ({e}) — verify needs the "
              f"real sandbox paths, and guessing $SANDY_HOME/sandboxes/<slug> would "
              f"verify directories that may not be the ones sandy uses", file=sys.stderr)
        return 2
    enrolled = load_membership(home, reported)
    if args.only or args.match:
        # Narrowing a READ needs no confirmation; an unmatched selector is
        # still a refusal that names the known slugs (`_match_selectors`).
        chosen, _count = _match_selectors(sorted(enrolled), args.only, args.match)
        enrolled = {s: enrolled[s] for s in chosen}
    if not enrolled:
        print(f"no sandbox selected — nothing per-sandbox to verify "
              f"(selection is {membership_source(home)})")
    sandbox_dirs = {s: boxes[s] for s in sorted(enrolled)}
    workspaces = discover_workspaces(args.sandy)
    running = running_containers(args.sandy)

    problems: List[str] = []
    # The enrolled sandboxes that were RUNNING, and so had their relay
    # checked. Reported because "no problems" over a fleet where half the
    # relay checks never ran is not the same verdict as a clean one. Counted
    # over the selected set, never over running containers fleet-wide, which
    # can exceed it and says nothing about coverage.
    live: List[str] = []
    # Kept apart from `problems` on purpose, and printed apart: notes are
    # what an operator may want to tidy, problems are what stops mail.
    notes: List[str] = []
    # THE CAPABILITY, THE MANIFEST AND THE PAYLOAD, ONCE. Reported, never
    # refused: a read-only command answers.
    ok, why = sandy_manifest_capable(args.sandy)
    if not ok:
        problems.append(f"sandy without feature manifests: {why}")
    problems += verify_manifest(home, policy, receives=sandy_accepts_receives(args.sandy))
    problems += verify_feature_payload(home, args.connector_src, servers_path=args.servers)
    problems += verify_roster_source(home)
    problems += verify_router_mount_sources(home, sibling_state_dir(home, args.state_dir))
    problems += verify_roster(home)
    problems += verify_roster_pointer_exposed(home)
    notes.append(CROSS_SESSION_COVERAGE)
    notes.append(f"feature: {feature_root(home)} (manifest, payload, instances; sandy mounts "
                 f"the payload at {CONTAINER_FEATURE_DIR} — the mount is what is verified "
                 f"below, per running sandbox)")
    for slug in sorted(enrolled):
        sandbox_dir = sandbox_dirs[slug]
        workspace = workspaces.get(slug)
        problems += verify_selection(slug, records.get(slug))
        problems += verify_lane_sources(home, slug)
        if supervisor_log_path(records.get(slug)) is None:
            if own_feature_entry(records.get(slug))[0]:
                notes.append(f"{slug}: relay health is not checkable — sandy reports no "
                             f"{FEATURE_NAME} entry state directory for its last launch "
                             f"(no entry adopted, or none named)")
            else:
                notes.append(f"{slug}: relay health is not checkable until it is relaunched — "
                             f"its last launch predates sandy 2.2.0, which names the "
                             f"supervisor's state directory")
        problems += verify_relay_supervisor(sandbox_dir, slug, record=records.get(slug))
        # SANDY_RELAY=0 at the last launch, off sandy's own record — for a
        # STOPPED sandbox too, which the marker read below cannot reach.
        problems += verify_relay_disabled_record(slug, records.get(slug))
        # What sandy APPLIED at this sandbox's last launch, against what the
        # manifest declares now. Host-side, from sandy's own record, for a
        # stopped sandbox too — and every disagreement is LAG (relaunch),
        # never drift: the manifest is verified against its rendering above.
        _args_problems, _args_notes = verify_agent_args(sandbox_dir, slug,
                                                        record=records.get(slug))
        problems += _args_problems
        notes += _args_notes
        # Unconditional, and deliberately NOT gated on the sandbox running:
        # the value is resolved at launch and sits on disk afterwards, so a
        # stopped sandbox's answer is both readable and the one it will use.
        _refuse_problems, _refuse_notes = verify_cross_session_inbound(
            sandbox_dir, slug, workspace, record=records.get(slug))
        problems += _refuse_problems
        notes += _refuse_notes
        # Liveness, the authority, and the invariant — all three only for
        # what sandy reports as running. A stopped sandbox has no relay by
        # definition, no session file to read it out of and no mount to probe,
        # and reporting one as dead would make `verify` fail on a fleet that
        # is simply not all up.
        if slug in running:
            live.append(slug)
            problems += verify_relay_started(slug, running[slug])
            problems += verify_entry_started_record(slug, records.get(slug))
            problems += verify_feature_mount(home, slug, running[slug])
            problems += verify_roster_mount(home, slug, running[slug])
            problems += verify_feature_env(slug, running[slug],
                                           fleet_domain=policy.get(fp.FLEET_DOMAIN_KEY))
            problems += verify_relay_alive(sandbox_dir, slug, container=running[slug])

    # The router's config, once for the fleet: the sibling on disk is the
    # rendering, byte for byte.
    state_dir = sibling_state_dir(home, args.state_dir)
    problems += verify_router_sibling(home, policy, enrolled, state_dir, boxes)

    # THE ROUTER PROCESS, last: its container and its health, three-valued
    # (router_health). Nothing here starts it — the remedy names the
    # router's own docker/run.sh — and every UNKNOWN is a problem by name.
    rctx = rh.Ctx(args, home)
    outcomes = rh.run_sections(rctx)
    if facts is not None:
        facts.ctx, facts.outcomes = rctx, outcomes
    problems += rh.problem_lines(outcomes)
    notes += [f"router: {w}" for w in rctx.warnings]
    passed = sum(1 for o in outcomes for c in o.checks if c.result is rh.PASS)
    total = sum(len(o.checks) for o in outcomes)
    notes.append(f"router: {passed} of {total} checks passed over "
                 f"{', '.join(o.section.id for o in outcomes)} (container "
                 f"{rctx.value('container')})")

    for note in notes:
        print(f"note: {note}")
    if problems:
        print(f"\nverify: {len(problems)} problem(s):", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    skipped = sorted(set(enrolled) - set(live))
    if skipped:
        print(f"note: relay liveness was NOT checked for {len(skipped)} enrolled "
              f"sandbox(es) — {', '.join(skipped)} — because they are not running. "
              f"A clean verdict says nothing about them.")
    print(f"verify: {len(enrolled)} sandbox(es), {len(live)} of them relay-checked "
          f"({len(running)} containers running fleet-wide) — no problems"
          + (f" ({len(notes)} note(s) above)" if notes else ""))
    return 0


# ------------------------------------------------------------------ install
#
# No workspace is enrolled by hand: the policy's selection rule (`sandboxes` /
# `agents`, include and exclude globs) is carried into the feature manifest,
# and SANDY evaluates it at every launch. See `fleet_policy.py`'s module docstring for the two
# invariants this whole feature is built around and must never cross:
#
#   1. Writing the policy IS the human act. `install` renders it for
#      whatever sandy has selected; the router snapshots each
#      instance's outbox on first sight and never delivers what was staged
#      before then (`router/firstsight.py`). Nothing here writes under
#      `state_dir`, and `install --apply` is tested to leave it untouched.
#   2. The rule matches the SLUG sandy already reports — never anything
#      read from inside the workspace — so a repository an agent was pointed
#      at cannot influence its own classification.

def policy_problems(policy: Dict[str, Any], boxes: List[Dict[str, Any]],
                    home: Path) -> List[str]:
    """What the authored manifest's policy still needs before `install
    --apply` renders the router's config from it:

    - ratification: the recreation cadence is present, and a task graph with
      edges has a `fleet_domain` (pure functions of the file);
    - `resolve_peers` and the lane-disjointness rule against the
      PROJECTED membership — what sandy reports at all, plus what it has
      selected — because on a fresh fleet nothing is selected yet and a
      `peers` key naming a real sandbox would otherwise be refused for no
      reason.
    One line per problem; empty means go ahead."""
    import policy_checks as checks
    problems = list(checks.check_ratification(policy))
    membership = checks.projected_membership(load_membership(home, boxes), boxes)
    try:
        checks.check_resolve_peers(policy, membership, sys.modules[__name__])
        problems += checks.check_disjoint(policy, membership, sys.modules[__name__])
    except fp.PolicyError as e:
        problems.append(str(e))
    return problems


def run_sync(args: argparse.Namespace, home: Path, boxes_dir: Path) -> int:
    """`install`: reconcile the host against the manifest's policy in one
    idempotent pass. Dry run unless `--apply`.

    Steps, in order:

      1. Report sandy's selection verdict for every sandbox it reports
         (`selected` / `not selected`, with sandy's reason / `unknown`, not
         launched since the manifest was written). Nothing here decides
         membership; the manifest's rule does, at launch.
      2. `run_provision`: the manifest, the payload and the roster
         directory, once per host; then each selected slug against the
         router's name rule.
      3. The router's config, a generated sibling of the manifest
         (`router_sibling_path`): written under --apply, compared otherwise.
    """
    policy_path = feature_manifest_path(home)
    policy = fp.load_policy(policy_path)
    if policy.get(fp.SOURCE_KEY) == fp.SOURCE_DEFAULT:
        print(f"note: no {policy_path} yet — install --apply writes the TEMPLATE, which works "
              f"as written: every sandbox launched with claude is selected and nothing is "
              f"excluded; every selected sandbox may task every other (task_graph \"ALL\", "
              f"no mail lane); addresses are <slug>@{fp.DEFAULT_FLEET_DOMAIN}; containers are "
              f"recreated every {fp.DEFAULT_RECREATE_INTERVAL_HOURS}h. To narrow it, edit it in "
              f"place: `sandboxes.exclude` keeps a sandbox out, and its `feature` section is "
              f"the policy.")

    boxes = discover_sandboxes(args.sandy)
    apply = args.apply
    states = selection_states(home, boxes)
    print(f"install ({'APPLYING' if apply else 'DRY RUN — pass --apply to provision'}):")
    buckets: Dict[str, List[str]] = {"selected": [], "not selected": [], "unknown": []}
    for slug, (state, _detail) in states.items():
        buckets[state].append(slug)
    print(f"  selected (sandy's last launch of each): {len(buckets['selected'])}"
          + (f" ({', '.join(sorted(buckets['selected']))})" if buckets["selected"] else ""))
    if buckets["not selected"]:
        print("  not selected — sandy's reason at its last launch:")
        for slug in sorted(buckets["not selected"]):
            print(f"    {slug}: {states[slug][1]}")
    if buckets["unknown"]:
        print("  " + selection_notes({s: states[s] for s in buckets["unknown"]})[0])
    if not boxes:
        print("  sandy reports no sandboxes")

    servers = load_servers(args.servers)
    print()
    prov_rc = run_provision(args, servers, home, boxes_dir, dry=not apply, policy=policy,
                            states_reported=True)
    if prov_rc == EXIT_POLICY_UNRATIFIED:
        return prov_rc

    # Step 3: the router's config beside the manifest — written under
    # --apply, compared otherwise. Its exit code is reported, never returned:
    # a dry install answers "what would change", and an absent sibling is one
    # of the answers.
    print()
    run_render_router(args, home, boxes, policy, apply=apply)

    return prov_rc


def run_cadence(args: argparse.Namespace, home: Path) -> int:
    """`cadence`: the container-recreation launch agent, rendered from the
    policy's `container_recreate_interval_hours` and written with --apply.

    It is NEVER loaded from here. A tool that bootstraps a job which
    recreates every container on the box is that tool; `launchd_job` hands
    the operator the exact `launchctl` line and reads the stamp the job
    leaves, and this verb prints both. The interval is the policy's — a
    manifest without one is refused the way `install` refuses it — so the
    number in the plist appears in a reviewed artifact before it runs."""
    policy = fp.load_policy(feature_manifest_path(home))
    boxes = discover_sandboxes(args.sandy)
    problems = policy_problems(policy, boxes, home)
    if problems:
        for problem in problems:
            print(f"  POLICY  {problem}", file=sys.stderr)
        return EXIT_POLICY_UNRATIFIED
    interval = policy[fp.RECREATE_INTERVAL_KEY]
    plist = lj.render_plist(args.sandy, home, interval)
    path = lj.plist_path()
    print(f"cadence: every {interval}h, {lj.LABEL} at "
          f"{lj.RUN_HOUR:02d}:{lj.RUN_MINUTE:02d} local, running `{args.sandy} --update-sessions`")
    record = lj.last_run(home)
    reason = lj.overdue_reason(home, interval)
    print(f"  last run: " + (f"{record['at'].isoformat()} status {record['status']}"
                             if record.get("at") else record.get("reason") or "unknown"))
    print(f"  cadence kept: {'yes' if reason is None else 'NO — ' + reason}")
    if args.apply:
        path.parent.mkdir(parents=True, exist_ok=True)
        print(f"  {_write_file(path, plist, dry_run=False, label=path.name)}")
    else:
        print(f"  would write {path} ({len(plist.splitlines())} lines) — pass --apply")
    print(f"  then, yourself (this tool never loads it): {lj.install_command()}")
    return 0


def _count_files(top: Path, depth: Optional[int] = None) -> int:
    if not top.is_dir():
        return 0
    if depth == 1:
        return sum(1 for p in top.iterdir() if p.is_file())
    return sum(1 for p in top.rglob("*") if p.is_file())


def run_teardown(args: argparse.Namespace, home: Path, boxes_dir: Path) -> int:
    """`teardown`: the fleet back to its pre-install state, for a clean
    rebuild. Removes what THIS tool created and nothing else, in three
    numbered steps, every one of them shown with its count before anything
    goes: (1) the payload; (2) the router's config; (3) `router-state/` —
    first-sight markers, the reply ledger and any HELD requests, which are
    named because they are lost.

    --force also clears what the tool never wrote but a rebuild wants
    empty: the CONTENTS of every instance lane leaf (notices, messages,
    results, processed) — the directories stay, they are sandy's. The daemon's
    `delivery-state/` and `claims/` are left alone either way: removing a
    claim out from under a running daemon is a second daemon starting.

    The manifest (the operator's policy) and `instances/` themselves are
    never touched; `sandy --remove-sandbox` reaps a tree."""
    apply = args.apply
    would = "" if apply else "would "
    rc = 0
    print(f"== teardown ({'APPLYING' if apply else 'DRY RUN — pass --apply'}"
          f"{' +FORCE' if args.force else ''}) ==\n")

    if args.force:
        print("--force: the contents of every instance lane")
        files = 0
        idir = feature_instances_dir(home)
        if idir.is_dir():
            for slug_dir in sorted(idir.iterdir()):
                for lane in FEATURE_LANES:
                    for leaf in FEATURE_LANE_LEAVES[lane]:
                        d = slug_dir / lane / leaf
                        n = _count_files(d, depth=1)
                        files += n
                        if apply and n:
                            for f in d.iterdir():
                                if f.is_file():
                                    f.unlink()
        print(f"  {would}remove {files} file(s) from the instance lanes — the directories stay "
              f"(sandy's)" + ("; includes any notice not yet read and any request not yet "
                              "drained" if files else ""))

    print("\n1. the payload (install --apply rebuilds it; feature.json and instances/ are kept)")
    payload = feature_payload_dir(home)
    if payload.is_dir():
        print(f"  {would}remove {payload} ({_count_files(payload)} file(s))")
        if apply:
            shutil.rmtree(payload)
    else:
        print("  payload already absent")

    # state_dir is read off the sibling, so it is resolved BEFORE step 2 removes it.
    state_dir = sibling_state_dir(home, args.state_dir)
    print("\n2. the router's config (install --apply rebuilds it)")
    sibling = router_sibling_path(home)
    if sibling.is_file():
        print(f"  {would}remove {sibling}")
        if apply:
            sibling.unlink()
    else:
        print("  already absent")

    print("\n3. router state — first-sight markers, the reply ledger, held requests")
    if state_dir.is_dir():
        markers = sum(1 for _ in state_dir.rglob(ROUTER_FIRST_SIGHT_NAME))
        held = sum(1 for p in state_dir.rglob("*") if p.is_file() and "held" in p.parts)
        delivered = sum(1 for p in state_dir.rglob("*") if p.is_file() and "delivered" in p.parts)
        print(f"  {would}remove {state_dir}")
        print(f"    {markers} first-sight marker(s), {delivered} reply-ledger entr(ies), "
              f"{held} held request(s)")
        if held:
            print(f"    !! {held} request(s) are HELD FOR A HUMAN and will be lost — read them first")
        if apply:
            shutil.rmtree(state_dir)
    else:
        print("  already absent")

    print()
    if apply:
        print("== done. To rebuild: amap-sandy.py install --apply, then launch each sandbox "
              "(sandy creates its lanes and applies the manifest), then start the router "
              f"on {sibling} — its first poll of each instance takes the first-sight snapshot ==")
    else:
        print("nothing was changed. Re-run with --apply.")
    return rc


def build_parser() -> argparse.ArgumentParser:
    """One command, six verbs. Subcommands make contradictory combinations
    unexpressible, and `--apply` is the one write switch, on every verb that
    writes.

    Host-wide options come BEFORE the verb (`amap-sandy.py --sandy-home X
    install --apply`): they name the host, and every verb reads them."""
    ap = argparse.ArgumentParser(
        prog="amap-sandy.py",
        description="The AMAP feature for a sandy fleet: install the manifest and the payload "
                    "on this host and render the router's config; sandy applies both to each "
                    "sandbox at its launch, from the manifest. Nothing is written into a "
                    "sandbox. Every verb is a dry run unless --apply.")
    ap.add_argument("--servers", type=Path, default=DEFAULT_SERVERS,
                    help=f"the MCP registration copied onto the payload "
                         f"(default: payload/{DEFAULT_SERVERS.name})")
    ap.add_argument("--connector-src", type=Path, default=DEFAULT_CONNECTOR_SRC,
                    help="directory holding the connector binaries")
    ap.add_argument("--sandy-home", type=Path, default=None,
                    help="override $SANDY_HOME (default: ~/.sandy)")
    ap.add_argument("--sandy", default="sandy", help="sandy executable (for --print-state)")
    ap.add_argument("--state-dir", type=Path, default=None,
                    help=f"router-private state, rendered into the router's config as "
                         f"`state_dir` (default: $SANDY_HOME/{ROUTER_STATE_SUBDIR})")
    sub = ap.add_subparsers(dest="command", required=True, metavar="COMMAND")

    install = sub.add_parser(
        "install", help="the manifest (the template on a fresh host), the payload, and the "
                        "router's config beside the manifest — the whole install, once per "
                        "host; sandy applies it to each sandbox at its launch")
    install.add_argument("--apply", action="store_true", help="write (default: report only)")

    verify = sub.add_parser(
        "verify", help="report only, exit 1 if anything is missing, stale or wrong: the "
                       "manifest against its rendering, the payload byte for byte, and per "
                       "selected sandbox the lanes, the relay, and what sandy applied at its "
                       "last launch")
    verify.add_argument("--only", action="append", default=[],
                        help="limit to sandboxes whose NAME exactly matches this (repeatable)")
    verify.add_argument("--match", action="append", default=[],
                        help="limit to sandboxes whose NAME contains this substring (repeatable)")
    verify.add_argument("--host-facts", type=Path, metavar="PATH",
                        help="also write the router-process facts (docker liveness, the mount "
                             "set, config freshness, sandy's not-selected slugs) to PATH as "
                             "JSON, for the router's operator console. Written atomically on "
                             "every exit, carrying its own generated_ts and this run's exit "
                             "status; cron-safe")
    verify.add_argument("--container", default=rh.DEFAULT_CONTAINER,
                        help="the detached router's container name (default: $CONTAINER, as "
                             "the router's docker/run.sh reads it)")
    verify.add_argument("--image", default=rh.DEFAULT_IMAGE,
                        help="the router image the one-shot `status` reads run under "
                             "(default: $IMAGE, as docker/run.sh reads it)")

    router = sub.add_parser(
        "router-config", help="render ONLY the router's config beside the manifest "
                              f"($SANDY_HOME/features/amap/{ROUTER_SIBLING_NAME}). Prints "
                              "`in sync` (exit 0) or the drift by key (exit 1); install does "
                              "this as its last step")
    router.add_argument("--apply", action="store_true", help="write (default: compare only)")

    sub.add_parser("list", help="every sandbox sandy reports, with sandy's own selection verdict "
                                "for this feature (selected / not selected and why / unknown: "
                                "not launched since the manifest was written)")

    cadence = sub.add_parser(
        "cadence", help="the container-recreation launch agent (macOS launchd), rendered from "
                        "the policy's container_recreate_interval_hours: prints the plist, the "
                        "last run's record, and the `launchctl bootstrap` line — which this tool "
                        "never runs")
    cadence.add_argument("--apply", action="store_true", help="write the plist (default: show it)")

    teardown = sub.add_parser(
        "teardown", help="the fleet back to its pre-install state for a clean rebuild: "
                         "remove the payload, the router's config and router-state/ (held "
                         "requests are named first). The manifest and instances/ are kept")
    teardown.add_argument("--apply", action="store_true", help="remove (default: show)")
    teardown.add_argument("--force", action="store_true",
                          help="also clear the CONTENTS of every instance lane (directories "
                               "stay) — a genuinely empty slate; notices not yet read are lost")
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    home = args.sandy_home or sandy_home()
    boxes_dir = sandboxes_dir(home)

    try:
        if args.command == "install":
            return run_sync(args, home, boxes_dir)

        if args.command == "router-config":
            policy = fp.load_policy(feature_manifest_path(home))
            boxes = discover_sandboxes(args.sandy)
            problems = policy_problems(policy, boxes, home)
            if problems:
                for problem in problems:
                    print(f"  POLICY  {problem}", file=sys.stderr)
                return EXIT_POLICY_UNRATIFIED
            return run_render_router(args, home, boxes, policy, apply=args.apply)

        if args.command == "list":
            _print_sandboxes(args.sandy, home)
            return 0

        if args.command == "cadence":
            return run_cadence(args, home)

        if args.command == "teardown":
            return run_teardown(args, home, boxes_dir)

        return run_verify_command(args, home, boxes_dir)
    except ProvisionError as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 2
    except fp.PolicyError as e:
        # A bad policy file is an operator error like any other and must look
        # like one. PolicyError is not a ProvisionError, so it escaped this
        # handler and reached the operator as a Python traceback, exiting 1
        # instead of 2 — while render-router-config.py handled the identical
        # input cleanly. Same message shape, same exit code, no traceback.
        print(f"FAIL: {e}", file=sys.stderr)
        return 2


def run_verify_command(args: argparse.Namespace, home: Path, boxes_dir: Path) -> int:
    """verify: the staleness question first, through the same path install
    answers it on, because "is the host installed at all" is a precondition
    for every other check; then everything install cannot see, the router
    process last. With `--host-facts`, the document is written on EVERY exit
    — a run that died before the router sections still says so, as
    `cannot_run` with no phases, which the console renders as unanswered
    rather than as a clean bill."""
    facts = HostFacts() if args.host_facts else None
    rc = 2
    try:
        servers = load_servers(args.servers)
        print("verify (1/2): is the install up to date?")
        stale_rc = run_provision(args, servers, home, boxes_dir, dry=True, verifying=True)
        print("\nverify (2/2): the checks the install cannot make")
        live_rc = run_verify(args, servers, home, boxes_dir, facts)
        rc = stale_rc or live_rc
        return rc
    finally:
        if facts is not None:
            facts.write(args.host_facts, rc)


if __name__ == "__main__":
    raise SystemExit(main())
