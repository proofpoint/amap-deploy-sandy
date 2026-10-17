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
import hashlib
import json
import os
import posixpath
import re
import shutil
import stat
import subprocess
import tempfile
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Set, Tuple

HERE = Path(__file__).resolve().parent
# The repo's `payload/` IS the host's `$SANDY_HOME/features/amap/payload/`
# minus the connector's four files: the three files this checkout ships,
# under their INSTALLED names, so a listing here reads like the mount.
PAYLOAD_DIR = HERE / "payload"
DEFAULT_SERVERS = PAYLOAD_DIR / "mcp-servers.json"

import launchd_job as lj   # the recreation cadence: renders and reads, never loads
import router_health as rh  # the router process: its container and its health, read only
import verify_report as vr  # how verify prints: one row per condition, its workspaces beside it
import host_setup as hsu    # a hop deployment's host plan: rendered and checked, never applied
import host_adapter as ha   # the host registry's CLI, run as a subprocess, never imported
import hop_router as hp     # the local router's hop keys, on a host with a hop link
import activation_install as ai   # A3: the activation config, checked before anything is written
import delegation_render as dr    # the delegation block's no-seed check
import partition_setup as ps      # the harness gate A3 requires
import hub_keys as hk             # the local router's container, named in the back-out
import hub_supervise as hv        # the supervision kinds: A5's command on a launchd host
import delivery_checks as dc  # delivery itself: lister mode, session posture, daemon build, backlog
import connector_pin as cpin  # install refuses a connector checkout not at its siblings.json pin
import build_identity as bi  # what each running runtime was built from: verify's "runtime builds" phase
import hub_runtime as hr     # the hub-link router's rendering: where its ledger directory is seen

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

# THE CODEX CONNECTOR, a second sibling, OPTIONAL: a host without its
# checkout installs exactly what it did before, and a Codex sandbox there has
# no supervisor to run (verify says so). Its supervisor runs in the Codex
# sandbox as this feature's entry (payload/codex/relay), so the payload
# carries its source package, its two MCP binaries and their module, and its
# operator instructions, under `codex/`.
CODEX_CONNECTOR_REPO_NAME = "amap-connector-codex"
CODEX_PAYLOAD_SUBDIR = "codex"
CODEX_PACKAGE = "amap_codex"
CODEX_CONNECTOR_BINARIES = ("inbox-mcp-vol", "inbox-submit", "_inboxlib.py")
CODEX_INSTRUCTIONS = "operator-instructions.md"
# What payload/codex/ ships from THIS checkout, `(name, executable)`.
CODEX_PAYLOAD_FILES = (("relay", True), ("mcp.toml", False), ("mcp-reader", True),
                       ("mcp-submit", True), ("kickoff", True), ("status", True))
# The agent names sandy reports, and which connector serves a sandbox: the
# Claude daemon wherever claude is among its agents, the Codex supervisor
# where codex is and claude is not. payload/relay applies the same rule.
AGENT_CLAUDE = "claude"
AGENT_CODEX = "codex"


def _default_codex_connector_src() -> Path:
    """The amap-connector-codex checkout's root: `$AMAP_CODEX_CONNECTOR_REPO`,
    else the nearest `amap-connector-codex` beside an ancestor of this file,
    else the path looked for first, so a message names the layout expected."""
    env = fp.amap_env("CODEX_CONNECTOR_REPO")
    if env:
        return Path(env).absolute()
    for parent in HERE.absolute().parents:
        cand = parent / CODEX_CONNECTOR_REPO_NAME
        if (cand / "src" / CODEX_PACKAGE).is_dir():
            return cand
    return HERE.absolute().parent / CODEX_CONNECTOR_REPO_NAME


DEFAULT_CODEX_CONNECTOR_SRC = _default_codex_connector_src()


def serving_connector(agents: Any) -> Optional[str]:
    """Which connector serves a sandbox launched with `agents` (sandy's list):
    `codex` where codex is among them and claude is not, else `claude`. None
    when sandy reported no list, which nothing here guesses at."""
    if not isinstance(agents, list):
        return None
    return AGENT_CODEX if AGENT_CODEX in agents and AGENT_CLAUDE not in agents else AGENT_CLAUDE


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
            # Named Claude sessions (sandy 2.9.0): carried ONLY where sandy
            # reports the key, because absent (a sandy without them) and
            # null (a last launch it cannot answer for) are different facts.
            **({dc.CLAUDE_SESSIONS_KEY: b[dc.CLAUDE_SESSIONS_KEY]}
               if dc.CLAUDE_SESSIONS_KEY in b else {}),
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


# The identity mount is rendered only for a sandy that SKIPS a declared mount
# whose source is missing and still launches: a sandbox registered after its
# launch must start without the mount, never fail to start. Read in sandy's
# source at schema_version 4 (`[ ! -e "$_src" ]` then `skip`); an earlier
# token is unreviewed for it. Membership, never order.
IDENTITY_SCHEMA_VERSIONS = (4,)
# The policy's opt-in, in the manifest's `feature` section, read only here.
# Absent: no identity mount, no AMAP_IDENTITY, the slug addresses as before.
IDENTITY_KEY = "identity"
IDENTITY_REGISTRY = "registry"


def identity_mode(policy: Dict[str, Any]) -> Optional[str]:
    """The policy's identity source, or None when it names none. Anything
    but the one known value refuses, by name."""
    value = policy.get(IDENTITY_KEY)
    if value is None:
        return None
    if value != IDENTITY_REGISTRY:
        raise ProvisionError(f"the policy's {IDENTITY_KEY!r} is {value!r}; the only value is "
                             f"{IDENTITY_REGISTRY!r}, or leave it out")
    return value


def sandy_skips_missing_mount(sandy_bin: str = "sandy") -> Optional[bool]:
    """Does this sandy launch without a declared mount whose source is
    missing? By `schema_version` membership in IDENTITY_SCHEMA_VERSIONS.
    None when the schema cannot be read."""
    schema = _sandy_json(sandy_bin, "--print-schema")
    if not isinstance(schema, dict):
        return None
    version = schema.get("schema_version")
    return any(version == known and type(version) is type(known)
               for known in IDENTITY_SCHEMA_VERSIONS)


def identity_schema_for(policy: Dict[str, Any], args: argparse.Namespace) -> Optional[str]:
    """The name.json schema id the manifest exposes, or None when the
    policy turns no identity mount on. On, it needs a sandy that skips a
    missing mount source and the deployment overlay's registry section;
    either missing refuses, by name."""
    if identity_mode(policy) is None:
        return None
    ok = sandy_skips_missing_mount(args.sandy)
    if ok is None:
        raise ProvisionError(f"cannot read `{args.sandy} --print-schema` to confirm sandy launches "
                             f"without a missing mount source")
    if not ok:
        raise ProvisionError(f"this sandy's schema_version is not one reviewed for the identity "
                             f"mount ({', '.join(map(repr, IDENTITY_SCHEMA_VERSIONS))}); a sandbox "
                             f"launched before its link exists might fail to start")
    try:
        return ha.load_identifiers(ha.overlay_path(args.overlay)).name_schema
    except ha.OverlayError as e:
        raise ProvisionError(str(e)) from None


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


# The daemon's own layout under the connector state directory, and the lane
# leaf it watches (payload/relay: AMAP_DELIVERY_STATE_DIR and
# AMAP_DELIVERY_PEER_NOTICE_DIR; the connector's Ledger keeps `ledger/`).
DELIVERY_STATE_SUBDIR = "delivery-state"
DELIVERY_LEDGER_SUBDIR = "ledger"
PEER_LANE = "peer"
LANE_NOTICES = "notices"


def connector_checkout(connector_src: Optional[Path]) -> Optional[Path]:
    """The git checkout holding the connector source directory, or None."""
    if connector_src is None or not Path(connector_src).is_dir():
        return None
    r = subprocess.run(["git", "-C", str(connector_src), "rev-parse", "--show-toplevel"],
                       capture_output=True, text=True, timeout=60)
    top = r.stdout.strip()
    return Path(top) if r.returncode == 0 and top else None


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


def codex_payload_sources(codex_src: Path) -> Tuple[Tuple[str, Path, bool], ...]:
    """`(relative path in the payload, source file, executable)` for the Codex
    connector's part of the payload, all under `codex/`: the files
    payload/codex/ ships from this checkout, a copy of payload/submit-server
    (it execs the `bin/inbox-submit` beside it, here the Codex connector's),
    the connector's source package, its MCP binaries and their module, and
    its operator instructions. Empty when `codex_src` holds no package: the
    Codex part is optional."""
    src = Path(codex_src)
    package = src / "src" / CODEX_PACKAGE
    if not package.is_dir():
        return ()
    sub = CODEX_PAYLOAD_SUBDIR
    parts = [(f"{sub}/{name}", PAYLOAD_DIR / sub / name, executable)
             for name, executable in CODEX_PAYLOAD_FILES]
    parts.append((f"{sub}/{SUBMIT_SERVER_NAME}", PAYLOAD_DIR / SUBMIT_SERVER_NAME, True))
    parts += [(f"{sub}/src/{CODEX_PACKAGE}/{p.name}", p, False)
              for p in sorted(package.glob("*.py"))]
    parts += [(f"{sub}/{FEATURE_BIN_SUBDIR}/{name}", src / FEATURE_BIN_SUBDIR / name,
               not name.endswith(".py"))
              for name in CODEX_CONNECTOR_BINARIES]
    parts.append((f"{sub}/{CODEX_INSTRUCTIONS}", src / "config" / CODEX_INSTRUCTIONS, False))
    return tuple(parts)


def install_feature_payload(home: Path, connector_src: Path, *, dry_run: bool,
                            servers_path: Path = DEFAULT_SERVERS,
                            codex_src: Optional[Path] = None,
                            pin: Optional[cpin.PinCheck] = None) -> str:
    """Install the payload ONCE, at `$SANDY_HOME/features/amap/payload/`: the
    copied chain and binaries. Nothing rendered lives here — the fleet domain
    reaches the wrapper as the manifest's `expose` export. With the connector
    checkout's pin check, it also writes the stamp verify's runtime-builds
    phase reads: the commit the connector files were copied from, whether
    that checkout was dirty, and the pin (build_identity).

    REAL FILES, NEVER SYMLINKS, byte-compared so an unchanged install writes
    nothing. `inbox-delivery` locates its module with `realpath(__file__)`,
    so a symlink here would resolve to wherever it points; and `_write_file`'s
    `os.replace` onto a symlink would follow it."""
    dest = feature_payload_dir(home)
    parts = []
    codex = codex_payload_sources(codex_src) if codex_src is not None else ()
    for rel, src_file, executable in payload_sources(connector_src, servers_path) + codex:
        try:
            data = src_file.read_text(encoding="utf-8")
        except OSError as e:
            raise ProvisionError(f"payload source missing or unreadable: {src_file}: {e}")
        parts.append(_write_file(dest / rel, data, dry_run=dry_run, label=rel,
                                 executable=executable))
    if pin is not None:
        parts.append(_write_file(dest / bi.STAMP_NAME, bi.stamp_text(pin.found, pin.dirty, pin.pinned),
                                 dry_run=dry_run, label=bi.STAMP_NAME, executable=False))
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


def render_manifest(policy: Dict[str, Any], *, receives: Optional[bool] = None,
                    identity_schema: Optional[str] = None) -> Dict[str, Any]:
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
    identity = identity_mode(policy)
    if identity is not None:
        if not identity_schema:
            raise ProvisionError(f"the policy's {IDENTITY_KEY!r} is {identity!r}, and no name.json "
                                 f"schema id was given for it")
        mounts.append({"name": IDENTITY_MOUNT_NAME,
                       "from": f"{FEATURE_IDENTITY_SUBDIR}/{MANIFEST_SLUG}", "mode": "ro",
                       "export": EXPORT_IDENTITY_DIR})
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
    if identity is not None:
        doc["expose"][EXPOSE_IDENTITY] = identity_schema
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


def manifest_text(policy: Dict[str, Any], *, receives: Optional[bool] = None,
                  identity_schema: Optional[str] = None) -> str:
    return json.dumps(render_manifest(policy, receives=receives,
                                      identity_schema=identity_schema), indent=2) + "\n"


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
                     receives: Optional[bool] = None,
                     identity_schema: Optional[str] = None) -> str:
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
        rendered = render_manifest(policy, receives=receives, identity_schema=identity_schema)
        doc = dict(existing)
        for key in _owned_keys(receives):
            if key in rendered:
                doc[key] = rendered[key]
            else:
                doc.pop(key, None)
        want = json.dumps(doc, indent=2) + "\n"
    else:
        want = manifest_text(policy, receives=receives, identity_schema=identity_schema)
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
                    receives: Optional[bool] = None,
                    identity_schema: Optional[str] = None) -> List[str]:
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
    rendered = render_manifest(policy, receives=receives, identity_schema=identity_schema)
    stale = [k for k in _owned_keys(receives) if doc.get(k) != rendered.get(k)]
    if stale:
        problems.append(f"manifest drift: {path}: {', '.join(stale)} differ from what this "
                        f"adapter renders — those blocks are the adapter's; re-run install "
                        f"--apply, which repairs them and leaves the policy keys alone")
    problems += verify_manifest_domain(home)
    return problems


def manifest_problems(home: Path, policy: Dict[str, Any], args: argparse.Namespace) -> List[str]:
    """`verify_manifest` with this host's answers. When the identity mount
    the policy turns on cannot be rendered, that is the problem reported,
    and the manifest is not compared against a guess."""
    try:
        identity_schema = identity_schema_for(policy, args)
    except ProvisionError as e:
        return [f"identity: {e}; the manifest is not compared until it is fixed"]
    return verify_manifest(home, policy, receives=sandy_accepts_receives(args.sandy),
                           identity_schema=identity_schema)


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
                           servers_path: Path = DEFAULT_SERVERS,
                           codex_src: Optional[Path] = None) -> List[str]:
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
    sources += codex_payload_sources(codex_src) if codex_src is not None else ()
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


def selection_rows(states: Dict[str, Tuple[str, str]]) -> List[vr.Row]:
    """Sandy's word on the sandboxes in `states`, as rows: one per verdict
    and reason, naming every sandbox it covers, and one for every sandbox
    not launched since the manifest was written."""
    rows: Dict[Tuple[str, str], vr.Row] = {}
    for slug, (state, detail) in sorted(states.items()):
        key = (state, "" if state == STATE_UNKNOWN else detail)
        if key not in rows:
            rows[key] = vr.Row(
                f"{STATE_UNKNOWN} — not launched since the manifest was written; sandy "
                f"decides at launch" if state == STATE_UNKNOWN else f"{state} — {detail}")
        rows[key].slugs.append(slug)
    return [r for (state, _), r in rows.items() if state != STATE_UNKNOWN] + \
           [r for (state, _), r in rows.items() if state == STATE_UNKNOWN]


def run_provision(
    args: argparse.Namespace, servers: Dict[str, dict], home: Path, boxes_dir: Path, dry: bool,
    policy: Optional[Dict[str, Any]] = None, states_reported: bool = False,
    verifying: bool = False, notes_out: Optional[List[vr.Row]] = None,
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
    # Under `verify`, a part already in place is one word on a summary line,
    # and only a part that needs something is printed whole.
    settled_parts: List[str] = []

    def part(label: str, where: Path, report: str) -> None:
        summary = vr.part_summary(label, report, _part_is_settled(report)) if verifying else None
        if summary is not None:
            settled_parts.append(summary)
        else:
            print(f"  {label} {where}: {report}")

    # THE MANIFEST AND THE PAYLOAD, ONCE, FIRST.
    try:
        report = install_manifest(home, policy, dry_run=dry,
                                  receives=sandy_accepts_receives(args.sandy),
                                  identity_schema=identity_schema_for(policy, args))
    except ProvisionError as e:
        print(f"  FAIL  manifest {feature_manifest_path(home)}: {e}", file=sys.stderr)
        failed += 1
    else:
        if not _part_is_settled(report):
            stale += 1
        part("manifest", feature_manifest_path(home), report)
    try:
        report = install_feature_payload(home, args.connector_src, dry_run=dry,
                                         servers_path=args.servers,
                                         codex_src=args.codex_connector_src,
                                         pin=getattr(args, "connector_pin", None))
        if not codex_payload_sources(args.codex_connector_src):
            print(f"  note  no Codex connector at {args.codex_connector_src}: the payload "
                  f"has no {CODEX_PAYLOAD_SUBDIR}/, so a Codex sandbox gets no supervisor")
    except ProvisionError as e:
        print(f"  FAIL  payload {feature_payload_dir(home)}: {e}", file=sys.stderr)
        failed += 1
    else:
        if not _part_is_settled(report):
            stale += 1
        part("payload", feature_payload_dir(home), report)
    try:
        report = install_roster_dir(home, dry_run=dry)
    except ProvisionError as e:
        print(f"  FAIL  roster {feature_roster_dir(home)}: {e}", file=sys.stderr)
        failed += 1
    else:
        if not _part_is_settled(report):
            stale += 1
        part("roster", feature_roster_dir(home), report)
    try:
        report = install_instances_dir(home, dry_run=dry)
    except ProvisionError as e:
        print(f"  FAIL  instances {feature_instances_dir(home)}: {e}", file=sys.stderr)
        failed += 1
    else:
        if not _part_is_settled(report):
            stale += 1
        part("instances", feature_instances_dir(home), report)
    if settled_parts:
        print(f"  in place, nothing to change: {', '.join(settled_parts)}")

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
        outside = {s: st for s, st in states.items() if s not in members}
        if notes_out is not None:
            notes_out.extend(selection_rows(outside))
        else:
            for line in selection_notes(outside):
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

    if verifying and not stale and not failed:
        return 0
    print(f"\nhost: {stale} part(s) needed changes"
          f"{' (nothing written — dry run)' if dry else ''}"
          + (f"; {failed} FAILED" if failed else ""))
    if verifying and stale:
        print("verify: out of date — run `install --apply`", file=sys.stderr)
        return 1
    return 1 if failed else 0


def host_marker(sandbox_dir: Path) -> Any:
    """The host copy of the launch marker: the parsed file, None when there
    is none, or a string saying why it could not be read."""
    path = sandbox_dir / SANDY_SESSION_MARKER_NAME
    if not path.exists() and not path.is_symlink():
        return None
    doc = _read_json(path)
    return doc if isinstance(doc, (dict, str)) else f"not an object ({path})"


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


NAME_JSON = "name.json"


# The relays' name.json checker, read from the shipped payload/relay and run
# as it is, so verify refuses exactly what every runtime reader refuses.
NAME_CHECK_FIRST = "import json, os, re, sys\n"
NAME_CHECK_LAST = 'print("ok " + address)\n'


def name_json_checker() -> str:
    text = (PAYLOAD_DIR / "relay").read_text(encoding="utf-8")
    start = text.index(NAME_CHECK_FIRST)
    return text[start:text.index(NAME_CHECK_LAST, start) + len(NAME_CHECK_LAST)]


def name_json_verdict(text: str, fleet_domain: Optional[str], name_schema: str) -> str:
    """The checker's one line for `text`: "ok <address>" or "no <reason>",
    under the fleet domain and schema id the relay would see."""
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "AMAP_IDENTITY": name_schema}
    if fleet_domain is not None:
        env["AMAP_FLEET_DOMAIN"] = fleet_domain
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / NAME_JSON
        path.write_text(text, encoding="utf-8")
        try:
            p = subprocess.run([sys.executable, "-I", "-c", name_json_checker(), str(path)],
                               env=env, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as e:
            return f"the name.json checker could not run: {e}"
    return p.stdout.strip() or f"the name.json checker gave no verdict: {p.stderr.strip()[-200:]}"


def identity_findings(slug: str, shown: "ha.Result", env: Dict[str, str],
                      name_json: Optional[str], read_error: str,
                      fleet_domain: Optional[str], name_schema: str) -> List[str]:
    """What is wrong with one running sandbox's registry identity, from
    the registry's binding (`shown`), the container's environment, and the
    name.json the container reads (`name_json`, or None with `read_error`).

    The comparison is by the binding's logical_id and address against the
    file the CONTAINER sees, never by a mount path: a mount's recorded root
    is relative to its filesystem and differs between hosts. Every gap is a
    problem, because each one leaves the relay holding or wrong.

    It compares the FILE, not the running daemon: the relay reads name.json
    once, before it starts the daemon, so a name the registry changes later
    (an operator override) reaches the daemon at the sandbox's next
    relaunch, and this check passes in between."""
    if shown.outcome == ha.UNKNOWN:
        return [f"identity unknown: {slug}: the registry's `show` did not answer "
                f"({shown.code}: {shown.detail})"]
    if shown.outcome != ha.REGISTERED or not isinstance(shown.binding, dict):
        if shown.code == ha.CODE_NOT_FOUND:
            return [f"identity not registered: {slug}: the registry has no binding for its "
                    f"workspace, so its relay holds; run migrate-registry, then "
                    f"link-identity --apply, then relaunch"]
        return [f"identity refused: {slug}: the registry's `show` refused ({shown.code}: "
                f"{shown.detail})"]
    b = shown.binding
    if not env.get(EXPORT_IDENTITY_DIR):
        return [f"identity mount absent: {slug}: the container has no {EXPORT_IDENTITY_DIR}, "
                f"so its relay holds; it launched before its link existed. Run link-identity "
                f"--apply, then relaunch"]
    if name_json is None:
        return [f"identity unreadable: {slug}: {NAME_JSON} cannot be read in the container "
                f"({read_error}), so its relay holds"]
    problems: List[str] = []
    verdict = name_json_verdict(name_json, fleet_domain, name_schema)
    doc = json.loads(name_json) if verdict.startswith("ok ") else None
    if doc is None:
        why = verdict[len("no "):] if verdict.startswith("no ") else verdict
        problems.append(f"identity refused: {slug}: {why}; its relay holds")
    elif doc.get("logical_id") != b.get("logical_id"):
        problems.append(f"identity lag: {slug}: the container reads the identity directory of "
                        f"{doc.get('logical_id')!r}, and the registry binds "
                        f"{b.get('logical_id')!r}; relaunch, so the mount follows the link")
    elif (doc.get("address"), doc.get("epoch")) != (b.get("address"), b.get("epoch")):
        problems.append(f"identity stale: {slug}: {NAME_JSON} names {doc.get('address')!r} at "
                        f"epoch {doc.get('epoch')!r}, and the registry binds "
                        f"{b.get('address')!r} at epoch {b.get('epoch')!r}; the registry has "
                        f"not rewritten it")
    dom = ha.address_domain(b)
    if dom != fleet_domain:
        problems.append(f"identity domain: {slug}: the registry's address is in {dom!r}, and "
                        f"the policy's fleet domain is {fleet_domain!r}; the relay holds")
    state = b.get("name_json")
    if state != ha.NAME_JSON_CURRENT:
        problems.append(f"identity delivery: {slug}: the registry reports its {NAME_JSON} as "
                        f"{state!r}, not {ha.NAME_JSON_CURRENT!r}; registering the workspace "
                        f"again redelivers it")
    return problems


def container_identity_findings(slug: str, container: str, shown: "ha.Result", *,
                                fleet_domain: Optional[str], name_schema: str,
                                docker_bin: str = "docker") -> List[str]:
    """`identity_findings` for a running container: its environment, and
    the name.json at the directory its own AMAP_IDENTITY_DIR names."""
    r = subprocess.run([docker_bin, "exec", container, "env"],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        return [f"identity unknown: {slug}: cannot read the environment of {container} "
                f"({r.stderr.strip() or 'no output'})"]
    env = dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line)
    text, why = None, ""
    if env.get(EXPORT_IDENTITY_DIR):
        c = subprocess.run([docker_bin, "exec", container, "cat", "--",
                            f"{env[EXPORT_IDENTITY_DIR]}/{NAME_JSON}"],
                           capture_output=True, text=True, timeout=60)
        if c.returncode == 0:
            text = c.stdout
        else:
            why = c.stderr.strip() or "no output"
    return identity_findings(slug, shown, env, text, why, fleet_domain, name_schema)


IdentityCheck = Callable[[str, str, Optional[Path], bool, Optional[Path]], List[str]]
CODEX_CONTROLLER_NAME = "controller.toml"
_CODEX_SELF_ADDRESS = re.compile(r'^self_address = ("(?:[^"\\]|\\.)*")$', re.M)


def codex_self_address(state: Path) -> Tuple[Optional[str], str]:
    """The address payload/codex/relay last configured the supervisor with,
    from `controller.toml` in its state directory, which the relay writes
    with each value as a JSON string. `(None, why)` when it cannot be read;
    `("", ...)` for a configuration with no self_address (mail only)."""
    try:
        text = (state / CODEX_CONTROLLER_NAME).read_text(encoding="utf-8")
    except OSError as e:
        return None, f"cannot read {state / CODEX_CONTROLLER_NAME}: {e}"
    m = _CODEX_SELF_ADDRESS.search(text)
    if m is None:
        return "", "no self_address"
    try:
        return json.loads(m.group(1)), ""
    except ValueError as e:
        return None, f"{CODEX_CONTROLLER_NAME} self_address is not a string: {e}"


def codex_identity_findings(slug: str, state: Optional[Path], shown: "ha.Result") -> List[str]:
    """For a Codex sandbox: the supervisor runs under the registry's address.
    Nothing while its relay holds (verify reports the hold), and nothing
    when the registry has no binding (the identity check reports that)."""
    if shown.outcome != ha.REGISTERED or not isinstance(shown.binding, dict):
        return []
    if state is None:
        return [f"identity unknown: {slug}: sandy reports no state directory for its Codex "
                f"supervisor"]
    if (state / CODEX_HOLD_NAME).exists():
        return []
    have, why = codex_self_address(state)
    want = shown.binding.get("address")
    if have is None:
        return [f"identity unknown: {slug}: {why}"]
    if have != want:
        return [f"identity not applied: {slug}: the Codex supervisor runs as "
                f"{have or 'no address'!r}, and the registry names {want!r}; relaunch the "
                f"sandbox"]
    return []


def identity_check(policy: Dict[str, Any], args: argparse.Namespace) -> Optional[IdentityCheck]:
    """None when the policy turns no identity on: verify is then what it was.
    Otherwise `(slug, container, workspace, codex, codex_state) -> findings`
    for one running sandbox (a Codex sandbox adds `codex_identity_findings`,
    from its supervisor's state directory), asking the registry's read-only `show` for its workspace. Any
    gap (the overlay, the registry's directory or checkout, sandy's report
    of the workspace, a `show` with no answer) is UNKNOWN for that sandbox,
    never a pass, and never stops the others."""
    try:
        on = identity_mode(policy) is not None
    except ProvisionError as e:
        bad = str(e)
        return lambda slug, *_: [f"identity unknown: {slug}: {bad}"]
    if not on:
        return None
    try:
        ids = ha.load_identifiers(ha.overlay_path(args.overlay))
    except ha.OverlayError as e:
        why = str(e)
        return lambda slug, *_: [f"identity unknown: {slug}: {why}"]
    repo = ha.registry_checkout(ids)
    if ids.directory is None or repo is None:
        why = ("the overlay names no registry.directory" if ids.directory is None else
               f"no registry checkout holding {ids.module}/cli.py (${ha.CHECKOUT_ENV}, or "
               f"the overlay's registry.checkout)")
        return lambda slug, *_: [f"identity unknown: {slug}: {why}"]
    client = ha.Client(Path(ids.directory), repo, ids)
    domain = policy.get(fp.FLEET_DOMAIN_KEY)

    def check(slug: str, container: str, workspace: Optional[Path], codex: bool = False,
              codex_state: Optional[Path] = None) -> List[str]:
        if workspace is None:
            return [f"identity unknown: {slug}: sandy reports no workspace for it, so the "
                    f"registry cannot be asked"]
        shown = client.show(str(workspace))
        found = container_identity_findings(slug, container, shown,
                                            fleet_domain=domain, name_schema=ids.name_schema)
        if codex:
            found += codex_identity_findings(slug, codex_state, shown)
        return found
    return check


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
    state = connector_state_dir(sandbox_dir) / DELIVERY_STATE_SUBDIR / "daemon.json"
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


# The Codex supervisor's own files, under this feature's entry state
# directory (payload/codex/relay writes the hold record; the connector writes
# the status snapshot on every poll and once more as it stops).
CODEX_STATE_SUBDIR = "codex"
CODEX_STATUS_NAME = "status.json"
CODEX_HOLD_NAME = "hold.json"
CODEX_CLAIMS_HELD = "held"


def codex_state_dir(record: Optional[dict]) -> Optional[Path]:
    """This sandbox's Codex supervisor state, a HOST path: the feature entry's
    `state_dir` as sandy reports it, joined with `codex/`. None when sandy
    names no state directory for this feature's entry."""
    log = supervisor_log_path(record)
    return log.parent / CODEX_STATE_SUBDIR if log is not None else None


def verify_codex_supervisor(home: Path, slug: str, record: Optional[dict], *,
                            running: bool, now: Optional[float] = None) -> Tuple[List[str], List[str]]:
    """`(problems, notes)` for a sandbox the Codex supervisor serves
    (`serving_connector`), read host-side from the files the supervisor and
    its relay keep in the entry's state directory.

    Always, running or not: a payload without `codex/` (nothing to run), and
    work the journal holds as UNCERTAIN, which never replays by itself and
    waits for the operator. Only while running: a recorded HOLD (Codex not
    logged in, or a Codex install that reports no build); and liveness, the
    snapshot no older than HEARTBEAT_MAX_AGE_SECONDS with both claims held.
    A missing or unreadable snapshot on a running sandbox is UNKNOWN, a
    problem, never a pass."""
    problems: List[str] = []
    notes: List[str] = []
    if not (feature_payload_dir(home) / CODEX_PAYLOAD_SUBDIR / "relay").is_file():
        problems.append(f"codex supervisor absent: {slug} is a Codex sandbox and the payload has "
                        f"no {CODEX_PAYLOAD_SUBDIR}/ — run install --apply with the "
                        f"{CODEX_CONNECTOR_REPO_NAME} checkout (--codex-connector-src)")
        return problems, notes
    state = codex_state_dir(record)
    if state is None:
        problems.append(f"codex supervisor UNKNOWN: {slug}: sandy reports no {FEATURE_NAME} entry "
                        f"state directory for its last launch — relaunch it")
        return problems, notes
    status = _read_json(state / CODEX_STATUS_NAME)
    if isinstance(status, dict):
        uncertain = status.get("uncertain_count")
        if isinstance(uncertain, int) and uncertain > 0:
            problems.append(f"codex delivery paused: {slug}: {uncertain} event(s) UNCERTAIN — a "
                            f"dispatch may or may not have reached Codex, and nothing replays "
                            f"it. Inspect the thread, then record the decision in the sandbox: "
                            f"python3 -m amap_codex.cli --config <state>/controller.toml recover "
                            f"EVENT_ID --action handled|hold|retry --note ... (do not delete "
                            f"the journal to clear it)")
        if status.get("last_error"):
            notes.append(f"{slug}: codex supervisor's last recorded error: {status['last_error']}")
        if status.get("codex_reviewed") is False:
            notes.append(f"{slug}: Codex build {status.get('codex_version')!r} is not one the "
                         f"connector has reviewed; delivery runs on its live checks (the exact "
                         f"MCP registry per thread, protocol errors that fail loudly)")
    if not running:
        return problems, notes
    hold = _read_json(state / CODEX_HOLD_NAME)
    if isinstance(hold, dict):
        problems.append(f"codex supervisor holding: {slug}: {hold.get('reason')!r} — nothing is "
                        f"delivered until it clears")
        return problems, notes
    if not isinstance(status, dict):
        problems.append(f"codex supervisor UNKNOWN: {slug}: no readable "
                        f"{state / CODEX_STATUS_NAME} ({status}) — it has not started, or its "
                        f"startup fails; read {state.parent / SUPERVISOR_LOG_NAME}")
        return problems, notes
    updated = status.get("updated_at")
    age = ((now if now is not None else time.time()) - updated
           if isinstance(updated, (int, float)) else None)
    if age is None:
        problems.append(f"codex supervisor UNKNOWN: {slug}: its status carries no updated_at")
    elif age > HEARTBEAT_MAX_AGE_SECONDS:
        problems.append(f"codex supervisor stale: {slug}: its status is {int(age)}s old (max "
                        f"{HEARTBEAT_MAX_AGE_SECONDS}s) — it has stopped; read "
                        f"{state.parent / SUPERVISOR_LOG_NAME}")
    elif status.get("claim_state") != CODEX_CLAIMS_HELD:
        problems.append(f"codex supervisor not consuming: {slug}: claim_state is "
                        f"{status.get('claim_state')!r}, not {CODEX_CLAIMS_HELD!r}")
    elif not status.get("thread_id"):
        problems.append(f"codex supervisor UNKNOWN: {slug}: no thread is bound yet")
    return problems, notes


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
SIBLING_OUTCOME_IDS = "connector_outcome_ids"
SIBLING_KEYS = (SIBLING_STATE_DIR, SIBLING_INSTANCES_DIR, SIBLING_SELECTED_JSON,
                SIBLING_FLEET_DOMAIN, SIBLING_TASK_GRAPH, SIBLING_PEER_SENDERS,
                SIBLING_MAIL_GRAPH, SIBLING_PEERS, SIBLING_OUTCOME_IDS)
# The connector ids whose `outbox/ext/<id>/outcomes/` the router reads, in
# scan order. Each is the id its connector chose, once (AMAP §4.1): the
# Claude daemon writes under `claude-code`, the Codex supervisor under
# `codex`. Rendered for every fleet, whichever connectors it runs: a
# directory nobody writes costs the router one failed open per poll.
CONNECTOR_OUTCOME_IDS = ("claude-code", "codex")
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
    SIBLING_MAIL_GRAPH, SIBLING_PEERS, SIBLING_OUTCOME_IDS, "intake_dir",
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
        SIBLING_OUTCOME_IDS: list(CONNECTOR_OUTCOME_IDS),
    }
    domain = policy.get(fp.FLEET_DOMAIN_KEY)
    if domain is not None:
        doc[SIBLING_FLEET_DOMAIN] = domain
        # The delegation lane exists only under a domain (the router's loader
        # refuses `peer_senders` without one). The wildcard with no deny is
        # PASSED THROUGH as the router's one word — rendering its expansion
        # would put N lists in the file that say what one word says, every
        # one of them drift the day a sandbox is selected. The router's word
        # has no exceptions, so a wildcard WITH a deny is rendered expanded,
        # minus the denied pairs: passing the word would drop the deny, and
        # the router would let the denied sender task. That map, like any
        # explicit graph, names only the instances enrolled at render, so a
        # sandbox selected later has no edges until `install` re-renders.
        # An explicit graph is total: an instance nobody may task maps to [],
        # because `verify` diffs it against the router's `peers --json`,
        # which emits [] for exactly that reason.
        if policy.get(fp.TASK_GRAPH_KEY) == fp.TASK_GRAPH_ALL \
                and not policy.get(fp.TASK_DENY_KEY):
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
    for key in sorted(set(existing) - set(SIBLING_KEYS) - set(hp.HOP_KEYS)):
        out.append(f"- {key}: not a key the router reads — it refuses the file over it")
    for key in SIBLING_KEYS + hp.HOP_KEYS:
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


def hop_router_keys(policy: Dict[str, Any], state_dir: Path, overlay: Optional[Path], *,
                    decommission: bool = False, spec_out: Optional[List[Any]] = None,
                    rendered: Optional[Path] = None) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """The local router's hop keys and every problem that stops them, on a
    host whose policy has `hop_link` (hop_router). The trigger is the policy,
    never the host-setup document, which a hop host must then have in full.
    Without `hop_link`, the problems are any hop state left in state_dir,
    unless the run is the explicit decommission. With `rendered`, the
    document's keys.local_config must name that file: the no-signing check
    reads it as the config the local router runs on."""
    try:
        link = hp.parse_hop_link(policy)
    except hp.HopRenderError as e:
        return None, [str(e)]
    if link is None:
        return None, [] if decommission else hp.state_problems(str(state_dir), None)
    try:
        spec = hsu.load_spec(hsu.read_spec(None, overlay))
        keys = hp.hop_keys(spec, link, policy.get(fp.FLEET_DOMAIN_KEY))
    except ValueError as e:     # SpecError and HopRenderError
        return None, [f"a hop host (the policy has {hp.HOP_LINK_KEY}): {e}"]
    if spec_out is not None:
        spec_out.append(spec)
    problems = hp.plugin_problems(keys["transport_plugin"]["path"], keys["transport_plugin"]["sha256"])
    problems += hp.checkout_problems(hp.hop_checkout(), hp.hop_pin())
    problems += hp.state_problems(str(state_dir), keys)
    if rendered is not None and spec.keys is not None and not (
            spec.keys.local_config == str(rendered)
            or os.path.realpath(spec.keys.local_config) == os.path.realpath(rendered)):
        problems.append(f"the host-setup document's keys.local_config is {spec.keys.local_config}, not {rendered}, "
                        f"the router config this renders: the no-signing check would read another file")
    return keys, problems


def run_activation(args: argparse.Namespace, policy: Dict[str, Any], doc: Dict[str, Any], path: Path, *,
                   apply: bool, spec: Any) -> int:
    """A3 (activation_install): the activation config into the operator's
    run directory under --apply, and root's place step printed. Exit 2 on any
    refusal, which writes nothing; the live config is never written here."""
    if not args.activate or not args.activation_sha256:
        print("router config: --activate and --activation-sha256 go together: A3 names A2's run and A1's "
              "printed digest, and neither is ever defaulted", file=sys.stderr)
        return 2
    link = hp.parse_hop_link(policy)
    if spec is None or link is None or link.inbound is None:
        print("router config: cannot activate — the policy's hop_link has no delegation member", file=sys.stderr)
        return 2
    checkout = hp.hop_checkout()
    gate = ps.gate_problems(spec.gate, rl_sha=hp.hop_pin(),
                            hop_sha=(spec.overlay_pin or {}).get("commit", rh.Unresolved("no plugin pin")),
                            plugin_sha256=hp.PLUGIN_SHA256)
    final, refused = ai.activate(
        spec=spec, host=hsu.partition_host(spec), doc=doc, pre_activation=sibling_text(doc).encode("utf-8"),
        fleet_domain=policy.get(fp.FLEET_DOMAIN_KEY), trusted=link.trusted, inbound=link.inbound,
        run_id=args.activate, activation_sha256=args.activation_sha256, gate=gate,
        validate=lambda d: dr.no_seed_problem(d, checkout),
        validate_bytes=lambda b: dr.no_seed_problem_bytes(b, checkout))
    for r in refused:
        print(f"router config: cannot activate — {r}", file=sys.stderr)
    if final is None:
        return 2
    source = Path(spec.secrets.run_dir) / ai.ACTIVATED_NAME
    print(f"router config: activation {_write_file(source, final.decode('utf-8'), dry_run=not apply, label=ai.ACTIVATED_NAME)}")
    print("  A3 to A5, in order, each step required before the next:")
    for line in activation_sequence(spec, str(source), final, path, sibling_text(doc).encode("utf-8")):
        print(f"    {line}")
    return 0


def activation_sequence(spec: Any, source: str, final: bytes, path: Path, pre_activation: bytes) -> List[str]:
    """A3's printed steps after its write, through A5, and the back-out that
    any failure from the root place on leads to. The back-out reads the HOST
    file, the bind's source: a running single-file bind may still show the
    inode it was started with."""
    container = hk.local_container(spec, spec.keys)
    final_sha = hashlib.sha256(final).hexdigest()
    pre = hashlib.sha256(pre_activation).hexdigest()
    return [
        f"1. done: the activation config is {source} (sha256 {final_sha})",
        f"2. as root: {ai.place_step(spec, source, final)}",
        f"3. the host's {path} is byte for byte that file: sha256 {final_sha}",
        f"4. A4: restart the local router: docker/run.sh --config {path} --detach, from the hop checkout",
        ("5. A5: python3 amap-sandy.py verify --a5; every check must PASS except the signing check's UNKNOWN for "
         "the VM file share, which --a5 excuses only by its exact reason"
         if spec.supervision is not None and spec.supervision.kind == hv.KINDS[1] else
         "5. A5: python3 amap-sandy.py verify; the signing check must PASS"),
        f"if step 2, 3, 4 or 5 fails, back out in this order (pre-activation sha256 {pre}); stopping the "
        f"router first (docker stop {container}) shortens the time it may sign:",
        "B1. python3 amap-sandy.py install            (read the diff it prints)",
        "B2. python3 amap-sandy.py install --apply    (it must exit 0; it renders no delegation)",
        f"B3. read the host's {path}, not the container's view: it must parse as a JSON object with no "
        "delegation member. If it carries one, or cannot be read or parsed, STOP: the activated config may "
        "still be in place",
        f"B4. its sha256 against {pre}: equal, or a difference install's diff explains",
        f"B5. docker stop {container} if it runs, then docker start {container}",
    ]


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
    hop_spec: List[Any] = []
    keys, hop_problems = hop_router_keys(policy, state_dir, ha.overlay_path(getattr(args, "overlay", None)),
                                         decommission=getattr(args, "decommission_hop", False), rendered=path,
                                         spec_out=hop_spec)
    for p in hop_problems:
        print(f"router config: cannot render — {p}", file=sys.stderr)
    if hop_problems:
        return 2
    if keys is not None:
        # A hop host: the rendering is validated by the HOP pin's loader, the
        # code its router runs; the primary pin's loader refuses these keys.
        doc = dict(doc, **keys)
        nested = hp.plugin_nesting_problems(doc, hp.loader_roots(doc, hp.hop_checkout()))
        nested += hp.tunable_problems(doc)
        for p in nested:
            print(f"router config: cannot render — {p}", file=sys.stderr)
        if nested:
            return 2
        refused = hp.validate_with_hop_router(doc, hp.hop_checkout())
    else:
        refused = validate_with_router(doc)
    if refused:
        print(f"router config: cannot render — the router's own loader refuses the "
              f"rendering: {refused}", file=sys.stderr)
        return 2
    names = ", ".join(sorted(members))
    render_to = getattr(args, "render_to", None)
    if render_to is not None:
        return run_render_to(Path(render_to), doc, path, apply=apply, hop=keys is not None,
                             combined=getattr(args, "prepare", False) or getattr(args, "activate", None) is not None)
    if getattr(args, "prepare", False):
        return run_prepare(args, policy, doc, path, apply=apply, spec=(hop_spec or [None])[0])
    if getattr(args, "activate", None) is not None or getattr(args, "activation_sha256", None) is not None:
        return run_activation(args, policy, doc, path, apply=apply, spec=(hop_spec or [None])[0])
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
    notice = hp.restart_notice(_read_json(path) if have is not None else None, doc)
    if apply:
        if have == want:
            print(f"router config current: {path} — {len(members)} instance(s): {names}")
            return 0
        _write_file(path, want, dry_run=False, label=ROUTER_SIBLING_NAME)
        print(f"wrote {path} — {len(members)} instance(s): {names}")
        if notice:
            print(f"router config: {notice}")
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
                          state_dir: Path, sandbox_paths: Dict[str, Path],
                          overlay: Optional[Path] = None) -> List[str]:
    """`verify`'s half: the file on disk is byte for byte the rendering.
    Absent is a problem (the router has nothing to start from), a hand edit
    is drift with the re-sync as remedy. On a hop host the rendering carries
    the hop keys, and their problems (the document, the plugin, the hop
    checkout, state_dir's pins) are problems here too."""
    path = router_sibling_path(home)
    try:
        doc = render_router_sibling(policy, members, home, state_dir, sandbox_paths)["_doc"]
    except ProvisionError as e:
        return [f"router config: cannot render: {e}"]
    spec_out: List[Any] = []
    keys, hop_problems = hop_router_keys(policy, state_dir, overlay, spec_out=spec_out, rendered=path)
    if hop_problems:
        return [f"router config: {p}" for p in hop_problems]
    if keys is None:
        # A document that configures the hub-link router while the policy
        # names no hop link is a host half set up.
        try:
            hub_doc = hsu.read_spec(None, overlay) if overlay is not None else None
        except ValueError:
            hub_doc = None
        if isinstance(hub_doc, dict) and hub_doc.get(hsu.hr.SECTION) is not None:
            return [f"router config: the host-setup document configures the hub-link router, and the "
                    f"policy has no {hp.HOP_LINK_KEY}: add it, or remove the hub section"]
    else:
        doc = dict(doc, **keys)
        roots = hp.loader_roots(doc, hp.hop_checkout())
        nested = hp.plugin_nesting_problems(doc, roots) + hp.tunable_problems(doc)
        if nested:
            return [f"router config: {p}" for p in nested]
        live = hp.live_problems(spec_out[0], keys, roots)
        if live:
            return [f"router config: {p}" for p in live]
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


def _builds_spec(overlay: Optional[Path]) -> Any:
    """The host-setup Spec for the runtime-builds phase: None when this host
    has no host-setup document, an Unresolved when it has one that cannot be
    read (which must refuse, never read as "nothing deployed")."""
    if overlay is None:
        return None
    try:
        sec = hsu.overlay_section(overlay)
        return None if sec is None else hsu.load_spec(sec)
    except ValueError as e:
        return rh.Unresolved(f"the host-setup document cannot be read: {e}")


def router_phases(args: argparse.Namespace, home: Path,
                  facts: Optional["HostFacts"]) -> Tuple[rh.Ctx, List[rh.Outcome], List[str]]:
    """verify's last read: the router's sections and the runtime-builds
    phase. Every outcome goes into --host-facts, and every non-passing check
    of either is a problem line (the build phase's prefixed "runtime builds"),
    so an UNKNOWN build never leaves verify's exit clean."""
    rctx = rh.Ctx(args, home)
    outcomes = rh.run_sections(rctx)
    builds = build_identity_outcome(args, home)
    if facts is not None:
        facts.ctx, facts.outcomes = rctx, outcomes + [builds]
    lines = rh.problem_lines(outcomes) + rh.problem_lines([builds], prefix="runtime builds")
    return rctx, outcomes, lines


def build_identity_outcome(args: argparse.Namespace, home: Path) -> rh.Outcome:
    """verify's "runtime builds" phase (build_identity): each runtime's build
    against what the deployment recorded and siblings.json pins, within one
    PHASE_BUDGET_S (every engine call min(its own timeout, the time left)).

    [1] is the local router, on the bare `docker`: its status document is
    read host-side from the state directory its container binds by identity.
    [2] is the hub-link router, on the hub's docker client with the
    supervised engine named (`-H`; sudo -n drops DOCKER_HOST): its status
    document is read by one `docker exec` of HUB_READER, which holds the
    whole progress witness. Each is read inside its inspect bracket, then
    every container sharing the directory is looked for on both engines
    where both routers are deployed (DS-BUILD-ID-HUB-READER design v2.2,
    v2.3)."""
    spec = _builds_spec(ha.overlay_path(getattr(args, "overlay", None)))
    budget = bi.Budget()
    aux = budget.runner(bi.AUX_TIMEOUT_S)
    usable = spec is not None and not isinstance(spec, rh.Unresolved)
    secrets = spec.secrets if usable else None
    supervision = getattr(spec, "supervision", None) if usable else None
    hub_docker = hsu.ss.docker(secrets) + ["-H", supervision.engine] \
        if secrets is not None and supervision is not None else None
    no_engine = rh.Unresolved("the host-setup document names no engine for [2] (no supervision section), so "
                              "the container verify would read may be another engine's")

    def inspect(role: str, name: str) -> Any:
        if role == bi.ROLE_HUB:
            return no_engine if hub_docker is None else bi.inspect_container(hub_docker, name, aux)
        return bi.inspect_container(["docker"], name, aux)

    def labels(image: str) -> Any:
        return no_engine if hub_docker is None else bi.image_labels(hub_docker, image, aux)

    def sharers(path: str, who: str, what: str, own_id: Any, engines: List[List[str]]) -> Any:
        for docker in engines:
            found = bi.state_sharers(docker, path, own_id, aux)
            if isinstance(found, rh.Unresolved):
                return found
            if found:
                return rh.Unresolved(bi.sharers_reason(who, what, path, found))
        return None

    def status(role: str, name: str, live: Any) -> Any:
        # A container not settled, or without a full Id, is refused before
        # anything is read or run against it.
        unsettled = bi._settled(live, f"[{1 if role == bi.ROLE_HOP else 2}] ({name})")
        if unsettled is not None:
            return rh.Unresolved(unsettled)
        return hub_status(name, live) if role == bi.ROLE_HUB else hop_status(name, live)

    def hop_status(name: str, live: Any) -> Any:
        state_dir = str(sibling_state_dir(home, getattr(args, "state_dir", None)))
        who = f"[1] ({name})"
        if bi.no_recorded_exit(live):
            doc = bi.read_progressing(live, state_dir, who, budget)
        else:
            doc = bi.read_status(live, state_dir, who)
        engines = [["docker"]]
        if usable and getattr(spec, "hub", None) is not None:
            if hub_docker is None:
                return no_engine
            engines.append(hub_docker)
        shared = sharers(state_dir, who, "state directory", live.get("Id"), engines)
        return doc if shared is None else shared

    def hub_status(name: str, live: Any) -> Any:
        who = f"[2] ({name})"
        if hub_docker is None:
            return no_engine
        try:
            ledger_host = spec.hub.dirs["RELAY_LEDGER_DIR"]
            m = hr.mount_holding(spec, secrets.principal, ledger_host)
        except (hr.HubSpecError, KeyError, AttributeError) as e:
            return rh.Unresolved(f"{who}'s ledger directory cannot be placed from the host-setup document: {e}")
        ledger = m["container"] + ledger_host[len(m["host"]):]
        refused = bi.own_mounts_refusal(live, m["host"], m["container"], ledger, who) \
            or bi.ledger_env_refusal(live, ledger, who)
        if refused is not None:
            return refused
        doc = bi.read_hub_status(hub_docker, live, posixpath.join(ledger, bi.HUB_STATUS_NAME),
                                 f"{secrets.uid}:{secrets.gid}", who, budget.runner(bi.HUB_EXEC_TIMEOUT_S))
        engines = [hub_docker] + ([["docker"]] if getattr(spec, "router", None) is not None else [])
        shared = sharers(ledger_host, who, "ledger directory", live.get("Id"), engines)
        return doc if shared is None else shared

    try:
        connector = cpin.pinned_commit()
    except (cpin.siblings.SiblingError, OSError, KeyError, ValueError) as e:
        connector = rh.Unresolved(f"siblings.json's connector pin cannot be read: {e}")
    phase = bi.collect(spec, feature_payload_dir(home), hop_pin=hp.hop_pin(), connector_pin=connector,
                       inspect=inspect, labels=labels, status=status)
    return phase.outcome()


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
               boxes_dir: Path, facts: Optional[HostFacts] = None,
               install_notes: Optional[List[vr.Row]] = None) -> int:
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
    problems += manifest_problems(home, policy, args)
    check_identity = identity_check(policy, args)
    problems += verify_feature_payload(home, args.connector_src, servers_path=args.servers,
                                       codex_src=args.codex_connector_src)
    problems += verify_roster_source(home)
    problems += verify_router_mount_sources(home, sibling_state_dir(home, args.state_dir))
    problems += verify_roster(home)
    problems += verify_roster_pointer_exposed(home)
    # WHICH DAEMON the payload runs, once: its bytes against the connector
    # pin, and its own notice pattern for the per-sandbox backlog below.
    payload = feature_payload_dir(home)
    daemon = dc.daemon_version(
        payload / DELIVERY_DAEMON_NAME, connector_checkout(args.connector_src),
        cpin.pinned_commit(),
        companions=[(payload / DELIVERY_SUPPORT_NAME, f"bin/{DELIVERY_SUPPORT_NAME}")]
        + [(payload / FEATURE_BIN_SUBDIR / n, f"bin/{n}") for n in CONNECTOR_BINARIES])
    problems += daemon.problems
    notes += daemon.notes
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
        connector = serving_connector((records.get(slug) or {}).get("agents"))
        # SANDY_RELAY=0 at the last launch, off sandy's own record — for a
        # STOPPED sandbox too, which the marker read below cannot reach.
        problems += verify_relay_disabled_record(slug, records.get(slug))
        # What sandy APPLIED at this sandbox's last launch, against what the
        # manifest declares now. Host-side, from sandy's own record, for a
        # stopped sandbox too — and every disagreement is LAG (relaunch),
        # never drift: the manifest is verified against its rendering above.
        # The launch arguments and the cross-session posture are Claude
        # Code's; a sandbox the Codex supervisor serves has neither, and its
        # own state stands in for both (verify_codex_supervisor).
        if connector == AGENT_CODEX:
            _codex_problems, _codex_notes = verify_codex_supervisor(
                home, slug, records.get(slug), running=slug in running)
            problems += _codex_problems
            notes += _codex_notes
        else:
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
            # Delivery itself: the lister this sandbox's sessions need, and
            # the peer notices its daemon has not handled.
            _mode_problems, _mode_notes = dc.verify_sessions(
                slug, records.get(slug), CONTAINER_FEATURE_DIR,
                marker=host_marker(sandbox_dir))
            problems += _mode_problems
            notes += _mode_notes
            _backlog_problems, _backlog_notes = dc.verify_unhandled(
                slug, feature_instances_dir(home) / slug / PEER_LANE / LANE_NOTICES,
                connector_state_dir(sandbox_dir) / DELIVERY_STATE_SUBDIR / DELIVERY_LEDGER_SUBDIR,
                daemon.notice_re, daemon.why, now=time.time(), running=slug in running)
            problems += _backlog_problems
            notes += _backlog_notes
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
            if check_identity is not None:
                problems += check_identity(slug, running[slug], workspace,
                                           connector == AGENT_CODEX,
                                           codex_state_dir(records.get(slug)))
            if connector != AGENT_CODEX:
                problems += verify_relay_alive(sandbox_dir, slug, container=running[slug])

    # The router's config, once for the fleet: the sibling on disk is the
    # rendering, byte for byte.
    state_dir = sibling_state_dir(home, args.state_dir)
    problems += verify_router_sibling(home, policy, enrolled, state_dir, boxes,
                                      ha.overlay_path(getattr(args, "overlay", None)))

    # THE ROUTER PROCESS, last: its container and its health, three-valued
    # (router_health). Nothing here starts it — the remedy names the
    # router's own docker/run.sh — and every UNKNOWN is a problem by name.
    rctx, outcomes, router_problems = router_phases(args, home, facts)
    problems += router_problems
    notes += [f"router: {w}" for w in rctx.warnings]
    passed = sum(1 for o in outcomes for c in o.checks if c.result is rh.PASS)
    total = sum(len(o.checks) for o in outcomes)
    router_line = (f"{passed} of {total} checks passed over "
                   f"{', '.join(o.section.id for o in outcomes)} (container "
                   f"{rctx.value('container')})")

    # THE REPORT. Every finding above is a sentence naming its sandbox; the
    # same sentence about many sandboxes is one row naming them all.
    known = sorted(set(records) | {slug for _t, _w, slugs in rctx.discovery for slug in slugs})
    problem_rows = vr.group(problems, known)
    note_rows = list(install_notes or []) + vr.group(notes, known)
    note_rows += [vr.Row(f"router reports {tag}: {why}", list(slugs))
                  for tag, why, slugs in rctx.discovery]
    skipped = sorted(set(enrolled) - set(live))
    if skipped:
        note_rows.append(vr.Row("not running, so its relay was not checked: a clean verdict "
                                "says nothing about it", skipped))
    names = vr.display_names(known)
    show_all = bool(getattr(args, "all", False))
    verdict = (f"{len(problems)} problem(s)" if problems else "no problems")
    print(f"\nverify: {len(enrolled)} sandbox(es), {len(live)} of them relay-checked "
          f"({len(running)} containers running fleet-wide) — {verdict}"
          + (f", {len(note_rows)} note(s)" if note_rows else ""))
    print(f"router: {router_line}\n")
    sys.stdout.flush()
    if problems:
        print("\n".join(vr.render("PROBLEMS", problem_rows, names, show_all=show_all)) + "\n",
              file=sys.stderr)
        sys.stderr.flush()
    print("\n".join(vr.render("NOTES", note_rows, names, show_all=show_all)))
    return 1 if problems else 0


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


# The fleet's domain is this host's sandy router's: `sandy.<host>.<base>`, from
# `fleet_policy.derived_fleet_domain` (shared with other runtimes' deployments,
# which pass their own runtime label). It is derived ONCE, when the template
# is written: every address carries it, so changing it is an explicit
# operator act (`fleet-domain --apply`), never a side effect of a renamed host.
FLEET_DOMAIN_RUNTIME_LABEL = "sandy"


def derived_fleet_domain(base: Optional[str] = None, hostname: Optional[str] = None) -> str:
    """This host's `sandy.<host>.<base>`, `base` defaulting to `internal` and
    `hostname` to this host's. Raises ProvisionError for a base the domain
    rule refuses."""
    import socket
    try:
        return fp.derived_fleet_domain(
            FLEET_DOMAIN_RUNTIME_LABEL,
            hostname if hostname is not None else socket.gethostname(),
            base or fp.DEFAULT_DOMAIN_BASE)
    except fp.PolicyError as e:
        raise ProvisionError(str(e))


def run_fleet_domain(args: argparse.Namespace, home: Path) -> int:
    """`fleet-domain`: show this host's derived domain beside the manifest's,
    and with --apply write it into the manifest's `feature.fleet_domain`, the
    one policy key this tool ever writes in an existing manifest, and only
    when asked. Every agent's address changes with it."""
    path = feature_manifest_path(home)
    want = derived_fleet_domain(args.base)
    if not path.is_file():
        print(f"fleet-domain: no {path} yet; install --apply writes the template with "
              f"fleet_domain {want!r}")
        return 0
    doc = _read_manifest(path)
    if not isinstance(doc, dict) or not isinstance(doc.get("feature"), dict):
        raise ProvisionError(f"{path} carries no `feature` object; fix it by hand first")
    have = doc["feature"].get(fp.FLEET_DOMAIN_KEY)
    print(f"fleet-domain: the manifest has {have!r}; this host's derived domain is {want!r}")
    if have == want:
        print("  already set; nothing to do")
        return 0
    consequence = (f"every agent's address changes from <slug>@{have} to <slug>@{want}. "
                   f"Let delegations in flight finish first: a reply to an old address "
                   f"is not delivered. After it: install --apply (the router re-reads its "
                   f"config on its next poll), then relaunch every agent (sandy --stop, then "
                   f"sandy --start) so its daemon and tools carry the new address")
    if not args.apply:
        print(f"  dry run (pass --apply to write it): {consequence}")
        return 0
    doc["feature"][fp.FLEET_DOMAIN_KEY] = want
    _write_file(path, json.dumps(doc, indent=2) + "\n", dry_run=False,
                label=FEATURE_MANIFEST_NAME)
    fp.load_policy(path)
    print(f"  wrote {fp.FLEET_DOMAIN_KEY} = {want!r} into {path}. Now: {consequence}")
    return 0


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
    if getattr(args, "activate", None) is not None or getattr(args, "activation_sha256", None) is not None:
        return run_activate_only(args, home)
    # Before anything is written: the connector checkout the payload is
    # copied from must be at its siblings.json pin (connector_pin).
    try:
        args.connector_pin = cpin.guard(args.connector_src,
                                        override=getattr(args, "allow_unpinned_connector", None),
                                        apply=args.apply, log_dir=feature_root(home),
                                        files=(DELIVERY_DAEMON_NAME, DELIVERY_SUPPORT_NAME) + CONNECTOR_BINARIES)
    except cpin.PinRefused as e:
        raise ProvisionError(str(e)) from None
    policy_path = feature_manifest_path(home)
    policy = fp.load_policy(policy_path)
    base = getattr(args, "fleet_domain_base", None)
    if policy.get(fp.SOURCE_KEY) == fp.SOURCE_DEFAULT:
        policy[fp.FLEET_DOMAIN_KEY] = derived_fleet_domain(base)
        print(f"note: no {policy_path} yet — install --apply writes the TEMPLATE, which works "
              f"as written: every sandbox launched with claude is selected and nothing is "
              f"excluded; every selected sandbox may task every other (task_graph \"ALL\", "
              f"no mail lane); addresses are <slug>@{policy[fp.FLEET_DOMAIN_KEY]}; containers are "
              f"recreated every {fp.DEFAULT_RECREATE_INTERVAL_HOURS}h. To narrow it, edit it in "
              f"place: `sandboxes.exclude` keeps a sandbox out, and its `feature` section is "
              f"the policy.")
    elif base:
        print(f"note: --fleet-domain-base applies only to a fresh host's template; this "
              f"host's manifest exists, so its fleet_domain stays "
              f"{policy.get(fp.FLEET_DOMAIN_KEY)!r}. To move it: fleet-domain --base {base}")

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

    # Step 4: the registry's names, only when the policy turns them on.
    if identity_mode(policy) is not None:
        print()
        prov_rc = max(prov_rc, run_install_identity(args, home, policy, boxes, states))
    return prov_rc


def run_render_to(out: Path, doc: Dict[str, Any], live: Path, *, apply: bool, hop: bool, combined: bool) -> int:
    """`install --render-to FILE`: install's own rendering, after every check
    install makes, written to a NEW file and never to the live config. The
    runbook's R2 renders the pinned router's config this way while the old
    router still runs: that router's loader refuses the hop keys, so the live
    config changes only after it has stopped."""
    if combined:
        print("router config: --render-to goes with neither --prepare nor --activate", file=sys.stderr)
        return 2
    if not hop:
        print("router config: --render-to renders a hop host's config, and the policy has no hop_link",
              file=sys.stderr)
        return 2
    want = sibling_text(doc).encode("utf-8")
    digest = hashlib.sha256(want).hexdigest()
    if not apply:
        print(f"router config: would write the rendering (sha256 {digest}) to {out}, never to {live} "
              f"(pass --apply)")
        return 0
    try:
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        print(f"router config: {out} exists; --render-to writes only a new file", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"router config: cannot create {out}: {e.strerror}", file=sys.stderr)
        return 2
    with os.fdopen(fd, "wb") as f:
        f.write(want)
    print(f"router config: wrote the rendering (sha256 {digest}) to {out}; {live} was not written")
    return 0


def run_prepare(args: argparse.Namespace, policy: Dict[str, Any], doc: Dict[str, Any], path: Path, *,
                apply: bool, spec: Any) -> int:
    """A1 (`partition-activate`): from install's own rendering `doc`, after
    every hop-host check install makes, the staged bytes (held to the
    no-seed check), the prospective run spec for the final config path, and
    A1's record. Under --apply the record is written into the operator's run
    directory, and nothing else; the root place and the two weekly argv are
    printed. Exit 2 on any refusal, which writes nothing."""
    import shlex
    import partition_activation as pa
    import partition_job as pj
    import fleet_keys as fk
    import secret_setup as ss
    link = hp.parse_hop_link(policy)
    refusals = []
    if spec is None or link is None or link.inbound is None:
        refusals.append("the policy's hop_link has no delegation member")
    elif spec.partition is None or spec.router is None or spec.secrets is None or spec.keys is None:
        refusals.append("the host-setup document has no partition, router, secrets or keys section")
    else:
        gate = ps.gate_problems(spec.gate, rl_sha=hp.hop_pin(),
                                hop_sha=(spec.overlay_pin or {}).get("commit", rh.Unresolved("no plugin pin")),
                                plugin_sha256=hp.PLUGIN_SHA256)
        refusals += [f"the harness gate does not hold: {g}" for g in gate]
    if refusals:
        for r in refusals:
            print(f"partition-activate: cannot prepare A1 — {r}; nothing was written", file=sys.stderr)
        return 2
    checkout = hp.hop_checkout()
    try:
        staged = ai.render_staged(spec=spec, doc=doc, fleet_domain=policy.get(fp.FLEET_DOMAIN_KEY),
                                  trusted=link.trusted, inbound=link.inbound,
                                  validate=lambda d: dr.no_seed_problem(d, checkout), read_inventory=fk._read)
        refused = dr.no_seed_problem_bytes(staged, checkout)
        if refused:
            raise ValueError(f"the staged bytes fail the no-seed check: {refused}")
        aspec = pa.prospective_spec(checkout=checkout, final_path=spec.keys.local_config, staged=staged,
                                    image=spec.router.image_digest, container=spec.router.container,
                                    uid=spec.keys.uid, gid=spec.keys.gid, interval=pa.DEFAULT_INTERVAL)
        record = pa.activation_record(host=hsu.partition_host(spec), spec=aspec, staged=staged,
                                      final_config_path=spec.keys.local_config)
    except (fk.FleetKeysError, pa.ActivationError, ValueError) as e:
        print(f"partition-activate: cannot prepare A1 — {e}; nothing was written", file=sys.stderr)
        return 2
    try:
        live = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        live = None
    import partition_check as pcheck
    if pcheck.carries_delegation(live):
        print("partition-activate: NOTE: the live config carries delegation. De-activate first (the back-out "
              "after the place, B1-B5), then A1")
    overlay = ha.overlay_path(getattr(args, "overlay", None))
    if overlay is None:
        print("partition-activate: cannot prepare A1 — no deployment overlay names the approved document; "
              "nothing was written", file=sys.stderr)
        return 2
    # Everything printed is computed before the record is written, so a
    # failure here leaves nothing behind.
    source = Path(spec.secrets.run_dir) / ps.ACTIVATION
    writer = os.path.join(spec.secrets.writer_dir, ss.WRITER)
    try:
        steps = list(pj.activation_steps(spec.partition, writer=writer, source=str(source), activation_bytes=record))
        argv = pj.job_argv(spec.partition, writer=writer, host=hsu.partition_host(spec), document=str(overlay),
                           document_bytes=overlay.read_bytes(), activation_bytes=record)
    except (OSError, ValueError) as e:
        print(f"partition-activate: cannot prepare A1 — {e}; nothing was written", file=sys.stderr)
        return 2
    print(f"partition-activate: A1's record {_write_file(source, record.decode('utf-8'), dry_run=not apply, label=ps.ACTIVATION)}")
    print(f"  its sha256, A3's --activation-sha256: {hashlib.sha256(record).hexdigest()}")
    print(f"  the prospective spec's ROUTER_INTERVAL: {pa.DEFAULT_INTERVAL} (A4's docker/run.sh must use the same)")
    for line in steps:
        print(f"  {line}")
    print("  # 7b, A2 (with the local router stopped):")
    print(f"  /usr/bin/sudo {shlex.join(argv + ['--prospective'])}")
    print("  # 7d, the manual weekly run (after A4):")
    print(f"  /usr/bin/sudo {shlex.join(argv)}")
    return 0


def run_partition_activate(args: argparse.Namespace, home: Path) -> int:
    """`partition-activate [--apply]` (A1): install's rendering path with
    every hop-host check, then A1 (run_prepare). It writes nothing outside
    the run directory, and nothing at all without --apply."""
    policy_path = feature_manifest_path(home)
    if not policy_path.is_file():
        print(f"partition-activate: no {policy_path}: install the host first; nothing was written", file=sys.stderr)
        return 2
    args.prepare = True
    policy = fp.load_policy(policy_path)
    boxes = discover_sandboxes(args.sandy)
    return run_render_router(args, home, boxes, policy, apply=args.apply)


def run_activate_only(args: argparse.Namespace, home: Path) -> int:
    """`install --activate RUN --activation-sha256 HEX` (A3): nothing but the
    activation. Both arguments are checked first; the manifest, the payload,
    the roster, the router's live config and the registry are never written
    on this path. Its one write, A1 + T into the run directory under --apply,
    comes only after every refusal has passed (activation_install)."""
    if not getattr(args, "activate", None) or not getattr(args, "activation_sha256", None):
        print("install: --activate and --activation-sha256 go together: A3 names A2's run and A1's printed "
              "digest, and neither is ever defaulted; nothing was written", file=sys.stderr)
        return 2
    policy_path = feature_manifest_path(home)
    if not policy_path.is_file():
        print(f"install: cannot activate — no {policy_path}: install the host first; nothing was written",
              file=sys.stderr)
        return 2
    policy = fp.load_policy(policy_path)
    boxes = discover_sandboxes(args.sandy)
    return run_render_router(args, home, boxes, policy, apply=args.apply)


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


def migration_members(states: Dict[str, Tuple[str, str]],
                      workspaces: Dict[str, Path]) -> Tuple[Dict[str, Path], Dict[str, str]]:
    """`({slug: workspace}, {slug: why excluded})` for the registry migration.

    Only sandboxes sandy has SELECTED are imported: they are the fleet's
    members, the agents that hold an address today. A sandbox sandy has not
    decided yet (`unknown`) is excluded and named, never guessed: once it
    has launched, a re-run imports it, because the import is idempotent. A
    selected slug the router refuses holds no address, so it is excluded too."""
    members: Dict[str, Path] = {}
    excluded: Dict[str, str] = {}
    for slug, (state, detail) in sorted(states.items()):
        if state != STATE_SELECTED:
            excluded[slug] = f"{state}: {detail}"
        elif slug not in workspaces:
            excluded[slug] = "sandy reports no workspace path for it"
        elif router_refusal(slug):
            excluded[slug] = f"the router refuses it: {router_refusal(slug)}"
        else:
            members[slug] = workspaces[slug]
    return members, excluded


def registry_setup(args: argparse.Namespace) -> Tuple["ha.Identifiers", Path]:
    """The registry's identifiers, from the deployment overlay, and its
    checkout. Either missing refuses the verb by name."""
    try:
        ids = ha.load_identifiers(ha.overlay_path(args.overlay))
    except ha.OverlayError as e:
        raise ProvisionError(str(e)) from None
    repo = ha.registry_checkout(ids, getattr(args, "registry_repo", None))
    if repo is None:
        raise ProvisionError(f"no registry checkout holding {ids.module}/cli.py: pass "
                             f"--registry-repo, set ${ha.CHECKOUT_ENV}, or name `checkout` in "
                             f"the overlay")
    return ids, repo


def registry_dir(args: argparse.Namespace, ids: "ha.Identifiers") -> Path:
    """The registry's directory: --registry, else the overlay's
    `registry.directory`, which is the one verify uses. Both, and different,
    refuses: two commands must not ask two registries."""
    flag = Path(args.registry).absolute() if args.registry else None
    named = Path(ids.directory) if ids.directory else None
    if flag and named and os.path.normpath(flag) != os.path.normpath(named):
        raise ProvisionError(f"--registry {flag} is not the overlay's registry.directory {named}, "
                             f"which verify uses; drop the flag or fix the overlay")
    if flag or named:
        return flag or named
    raise ProvisionError("no registry directory: pass --registry, or name registry.directory "
                         "in the overlay")


def run_migrate_registry(args: argparse.Namespace, home: Path) -> int:
    """`migrate-registry`: the registry migration, PREPARED, never run.

    Writes (with --apply) the batch of every selected sandbox's slug and
    workspace path, and prints the two registry operator commands that
    import it: `plan`, which shows the change and a confirmation code, and
    `apply`, which takes that code and the operator's name and reason. The
    verbs are the operator's; this tool runs neither. A re-run after more
    sandboxes are selected writes a batch whose already-imported items come
    back `already_bound`."""
    boxes = discover_sandboxes(args.sandy)
    states = selection_states(home, boxes)
    workspaces = {b["name"]: Path(b["workspace_path"]) for b in boxes if b.get("workspace_path")}
    members, excluded = migration_members(states, workspaces)
    print(f"migrate-registry: {len(members)} selected sandbox(es) to import under their "
          f"current slug, so no address's local part changes")
    for slug in sorted(members):
        print(f"  import  {slug}")
    for slug, why in sorted(excluded.items()):
        print(f"  skip    {slug}: {why}")
    if not members:
        print("  nothing to import")
        return 0
    ids, repo = registry_setup(args)
    text = ha.import_batch_text(members)
    registry = registry_dir(args, ids)
    if not (registry / "host.json").is_file():
        print(f"  note: {args.registry}/host.json does not exist yet; the import refuses "
              f"(config_absent) until it does")
    if not args.apply:
        print(f"  dry run (pass --apply to write the batch to {args.batch}):")
        print(text, end="")
    else:
        print("  " + _write_file(Path(args.batch), text, dry_run=False, label="import batch"))
    plan, apply_ = ha.import_commands(repo, registry, Path(args.batch), ids)
    print("Then, as the operator (this tool runs neither):")
    print(f"  1. {plan}")
    print(f"  2. {apply_}")
    print("  Step 2 takes the code step 1 prints. Every imported agent's sender quarantine "
          "starts at the import (24 h before a cross-host delegation from it is accepted).")
    return 0


# The identity mount. The host registry keys each agent's identity directory by
# logical_id, and sandy substitutes only `${slug}` in a mount's `from`, so
# the manifest mounts `by-slug/${slug}`: a symlink, one per sandbox, to the
# directory the registry names. Docker binds the link's TARGET at launch, so
# a running sandbox keeps the directory it started with until it relaunches,
# and sees every rename the registry makes inside it live. A sandbox launched
# before its link exists starts without the mount (sandy skips a declared
# mount with no source), and gains it only by relaunching.
FEATURE_IDENTITY_SUBDIR = "by-slug"
IDENTITY_MOUNT_NAME = "identity"
EXPORT_IDENTITY_DIR = "AMAP_IDENTITY_DIR"
# The one `expose` that says this fleet's addresses are the registry's. A
# mount sandy skipped exports nothing, so without this the relay could not
# tell "not registered yet" from "no registry". Its value is name.json's
# schema id, from the deployment overlay, which the relay checks the file
# against: the payload names no registry token of its own.
EXPOSE_IDENTITY = "AMAP_IDENTITY"

LINK_CREATE = "create"
LINK_KEEP = "keep"
LINK_REPOINT = "repoint"
LINK_REFUSE = "refuse"
LINK_SKIP = "skip"
LINK_UNKNOWN = "unknown"
LINK_STRAY = "stray"


def identity_links_dir(home: Path) -> Path:
    return feature_root(home) / FEATURE_IDENTITY_SUBDIR


# The agents that existed before identity was turned on: the roster's members
# when the first `install --apply` with identity on ran, written once beside
# roster/ and never rewritten. Such an agent is live under its slug address,
# and a `register` would give it a new name; it is imported with
# migrate-registry instead. An agent launched later is not in it, and is
# registered zero-touch.
PRE_IDENTITY_FILE = "pre-identity.json"
PRE_IDENTITY_SCHEMA = "amap-deploy-sandy.pre-identity/1"
#: The roster's `contract_version` this repo has reviewed.
ROSTER_CONTRACT_VERSION = "2"
#: The roster schema's address (`router`, each member's): one bare addr-spec.
_ROSTER_ADDRESS = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[A-Za-z0-9.-]+")
#: The roster schema's free text (`written_at`, a member's `state`): no control characters.
_ROSTER_TEXT = re.compile(r"[^\x00-\x1f\x7f]+")


class PreIdentityError(Exception):
    """The roster or the snapshot cannot be read; no sandbox is registered."""


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _strict_json(text: str) -> Any:
    """json.loads, refusing the NaN and Infinity it otherwise accepts."""
    return json.loads(text, parse_constant=_no_constant)


def pre_identity_path(home: Path) -> Path:
    return feature_root(home) / PRE_IDENTITY_FILE


def roster_slugs(home: Path) -> Optional[FrozenSet[str]]:
    """The slugs the router's roster lists (each member's local part), or
    None when there is no roster file: a host whose router has never
    written one. A roster that exists but cannot be read raises."""
    f = feature_roster_dir(home) / ROSTER_FILE_NAME
    try:
        doc = _strict_json(f.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        raise PreIdentityError(f"the roster {f} is unreadable: {e}") from None
    why = roster_schema_problem(doc)
    if why:
        raise PreIdentityError(f"the roster {f} does not match the roster schema: {why}")
    return frozenset(m["address"].partition("@")[0] for m in doc["members"])


def _text(v: Any, pattern: "re.Pattern") -> bool:
    return isinstance(v, str) and pattern.fullmatch(v) is not None


def roster_schema_problem(doc: Any) -> Optional[str]:
    """What in `doc` the roster schema refuses, or None. Every field the
    schema names is checked; a field it does not name is ignored, because the
    envelope is open at every level."""
    if not isinstance(doc, dict):
        return "not an object"
    if doc.get("contract_version") != ROSTER_CONTRACT_VERSION:
        return f"contract_version is not {ROSTER_CONTRACT_VERSION!r}"
    if not _text(doc.get("router"), _ROSTER_ADDRESS):
        return "router is not one bare address"
    if not _text(doc.get("written_at"), _ROSTER_TEXT):
        return "written_at is empty or has a control character"
    if "interval_s" in doc:
        v = doc["interval_s"]
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not v >= 0 or v == float("inf"):
            return "interval_s is not a number of at least 0"
    if not isinstance(doc.get("members"), list):
        return "members is not a list"
    for m in doc["members"]:
        if not isinstance(m, dict) or not _text(m.get("address"), _ROSTER_ADDRESS):
            return "a member's address is not one bare address"
        if not _text(m.get("state"), _ROSTER_TEXT):
            return "a member's state is empty or has a control character"
    return None


def read_pre_identity(path: Path) -> Optional[FrozenSet[str]]:
    """The recorded pre-identity slugs, or None when none is recorded. A
    record that exists but cannot be read raises."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise PreIdentityError(f"the pre-identity record {path} is unreadable: {e}") from None
    try:
        with os.fdopen(fd, encoding="utf-8") as fh:
            doc = _strict_json(fh.read())
    except (OSError, ValueError) as e:
        raise PreIdentityError(f"the pre-identity record {path} is unreadable: {e}") from None
    if not isinstance(doc, dict):
        doc = {}
    slugs = doc.get("slugs")
    if doc.get("schema") != PRE_IDENTITY_SCHEMA or not isinstance(slugs, list) \
            or not all(isinstance(s, str) and s for s in slugs):
        raise PreIdentityError(f"the pre-identity record {path} is not a {PRE_IDENTITY_SCHEMA} "
                               f"record")
    return frozenset(slugs)


def pre_identity(home: Path, *, apply: bool) -> Tuple[FrozenSet[str], Optional[str]]:
    """`(slugs, note)`: the pre-identity agents. The record when there is one;
    otherwise the roster's members, which `--apply` records (once, created
    exclusively, never rewritten) and a dry run only shows. No roster is a
    fresh host: an empty record. `note` says what was recorded."""
    path = pre_identity_path(home)
    recorded = read_pre_identity(path)
    if recorded is not None:
        return recorded, None
    slugs = roster_slugs(home) or frozenset()
    if not apply:
        return slugs, f"would record {len(slugs)} pre-identity agent(s) in {path}"
    doc = {"schema": PRE_IDENTITY_SCHEMA, "recorded_ts": datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"), "slugs": sorted(slugs)}
    try:
        made = _publish_once(path, (json.dumps(doc, indent=2) + "\n").encode("utf-8"))
    except OSError as e:
        raise PreIdentityError(f"cannot record the pre-identity agents in {path}: {e}") from None
    if not made:
        return read_pre_identity(path) or frozenset(), None
    return slugs, f"recorded {len(slugs)} pre-identity agent(s) in {path}; it is never rewritten"


def _publish_once(path: Path, data: bytes) -> bool:
    """Put `data` at `path` only if nothing is there, whole or not at all:
    written and fsynced under a temporary name, then link()ed into place
    (which never replaces an existing file), and the directory fsynced. A
    crash leaves either no record or a complete one. False when `path`
    already existed."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(tmp, path, follow_symlinks=False)
        except FileExistsError:
            return False
    finally:
        os.unlink(tmp)
    dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    return True


def plan_identity_links(links_dir: Path, members: Dict[str, Path],
                        shown: Dict[str, "ha.Result"]) -> List[Tuple[str, str, str, str]]:
    """`[(action, slug, target, why)]`: what `link-identity` would do for
    each member, from what the registry's `show` answered for its workspace.

    Nothing is ever removed. A path that is not a symlink is refused, never
    replaced. A link pointing elsewhere is a REPOINT, named as one, because
    the sandbox keeps the old directory until it relaunches. A link for a
    slug that is not a member is a STRAY: reported, left alone. A `show`
    that could not be answered is UNKNOWN, never a skip."""
    plan: List[Tuple[str, str, str, str]] = []
    for slug in sorted(members):
        r = shown.get(slug)
        if r is None or r.outcome == ha.UNKNOWN:
            why = "the registry was not asked" if r is None else f"{r.code}: {r.detail}"
            plan.append((LINK_UNKNOWN, slug, "", why))
            continue
        if r.outcome != ha.REGISTERED or not isinstance(r.binding, dict):
            if r.code == ha.CODE_NOT_FOUND:
                why = ("not registered: install --apply registers it (migrate-registry imports "
                       "an existing slug)")
            else:
                why = f"the registry refused show: {r.code}: {r.detail}"
            plan.append((LINK_SKIP, slug, "", why))
            continue
        target = r.binding.get("identity_dir")
        lid = r.binding.get("logical_id")
        if (not isinstance(target, str) or not os.path.isabs(target)
                or not isinstance(lid, str) or os.path.basename(target) != lid):
            plan.append((LINK_REFUSE, slug, str(target),
                         f"the binding's identity_dir is not an absolute directory named "
                         f"by its logical_id {lid!r}"))
            continue
        path = links_dir / slug
        try:
            st = path.lstat()
        except FileNotFoundError:
            plan.append((LINK_CREATE, slug, target, ""))
            continue
        except OSError as e:
            plan.append((LINK_UNKNOWN, slug, target, f"cannot read {path}: {e}"))
            continue
        if not stat.S_ISLNK(st.st_mode):
            plan.append((LINK_REFUSE, slug, target,
                         f"{path} exists and is not a symlink; it is left as it is"))
            continue
        have = os.readlink(path)
        if have == target:
            plan.append((LINK_KEEP, slug, target, ""))
        else:
            plan.append((LINK_REPOINT, slug, target,
                         f"it points at {have}; the sandbox keeps that directory "
                         f"until it relaunches"))
    try:
        present = sorted(e.name for e in os.scandir(links_dir))
    except FileNotFoundError:
        present = []
    for name in present:
        if name not in members and not name.startswith("."):
            plan.append((LINK_STRAY, name, "", "not a selected, registered sandbox; left "
                                                "as it is"))
    return plan


def apply_identity_links(links_dir: Path, plan: List[Tuple[str, str, str, str]]) -> List[str]:
    """Make the plan's CREATE and REPOINT links, each by a temporary link
    renamed over the name, so a reader sees the old target or the new one
    and never neither. Each path is looked at again first: a CREATE whose
    path now exists, or a REPOINT whose path is no longer a link, is left
    alone and returned, by slug, as changed since the plan."""
    links_dir.mkdir(parents=True, exist_ok=True)
    moved: List[str] = []
    for action, slug, target, _ in plan:
        if action not in (LINK_CREATE, LINK_REPOINT):
            continue
        path = links_dir / slug
        if (action == LINK_CREATE and os.path.lexists(path)) or \
                (action == LINK_REPOINT and not path.is_symlink()):
            moved.append(slug)
            continue
        tmp = links_dir / f".{slug}.{os.getpid()}.tmp"
        os.symlink(target, tmp)
        os.replace(tmp, path)
    return moved


def install_identity(client: "ha.Client", links_dir: Path, members: Dict[str, Path], *,
                     apply: bool, pre: Any = frozenset()) -> Tuple[List[str], bool]:
    """`(lines, failed)`: install's registration of every selected sandbox,
    then its by-slug link. Zero-touch: a sandbox sandy selected and the
    registry has never seen is registered with the workspace sandy reports,
    and linked, with no operator import. Dry run asks only the read-only
    `show`; --apply calls the idempotent `register`.

    Never before the registry exists. The import (migrate-registry) creates
    it and binds today's slugs as names; a `register` before that would give
    an existing agent a new name, and names are never reused. Each sandbox
    fails closed on its own: one the registry does not answer, or refuses,
    is named and gets no link, and the others go on.

    Per agent: a slug in `pre` (the agents that existed before identity was
    turned on) that the registry has not bound is refused, so the agent is
    imported under its own name rather than registered under a new one.
    When `pre` is a PreIdentityError, no sandbox is registered."""
    lines: List[str] = []
    listed = client.list()
    if listed.outcome != ha.REGISTERED:
        if listed.code == ha.CODE_REGISTRY_ABSENT:
            why = ("the registry does not exist yet: import today's slugs with migrate-registry "
                   "first, so no existing agent is renamed")
        else:
            why = f"the registry did not answer `list` ({listed.code}: {listed.detail})"
        return [f"  FAIL  identity: {why}; nothing registered or linked"], True
    failed = False
    shown: Dict[str, ha.Result] = {}
    for slug in sorted(members):
        ws = str(members[slug])
        if isinstance(pre, PreIdentityError) or slug in pre:
            r = client.show(ws)
            shown[slug] = r
            if isinstance(pre, PreIdentityError):
                failed = True
                lines.append(f"  UNKNOWN register {slug}: {pre}; not registered")
                continue
            if r.code == ha.CODE_NOT_FOUND:
                failed = True
                lines.append(f"  FAIL  register {slug}: it existed before identity was turned on "
                             f"and was never imported; registering would give it a new name. "
                             f"Import it with migrate-registry")
                continue
            if r.outcome != ha.REGISTERED:
                failed = True
                lines.append(f"  UNKNOWN register {slug}: it existed before identity was turned "
                             f"on, and the registry did not say whether it is bound "
                             f"({r.code}: {r.detail}); not registered")
                continue
        if not apply:
            r = client.show(ws)
            if r.code == ha.CODE_NOT_FOUND:
                lines.append(f"  register  {slug}: would register {ws}")
            shown[slug] = r
            continue
        r = client.register(ws)
        if r.outcome == ha.REGISTERED:
            if r.created:
                lines.append(f"  register  {slug}: registered as {r.binding.get('address')}")
        elif r.outcome == ha.UNDELIVERED:
            failed = True
            lines.append(f"  FAIL  register {slug}: bound as {r.binding.get('address')}, but "
                         f"name.json was not delivered ({r.code}: {r.detail}); its relay holds "
                         f"until a later install delivers it")
        else:
            failed = True
            lines.append(f"  FAIL  register {slug}: {r.outcome} ({r.code}: {r.detail}); no link")
        shown[slug] = (ha.Result(ha.REGISTERED, binding=r.binding)
                       if r.binding is not None and r.outcome in (ha.REGISTERED, ha.UNDELIVERED)
                       else r)
    plan = plan_identity_links(links_dir, members, shown)
    for action, slug, target, why in plan:
        if action == LINK_KEEP or (action == LINK_SKIP and not apply):
            continue
        lines.append(f"  link {action:8}{slug}" + (f" -> {target}" if target else "")
                     + (f": {why}" if why else ""))
    failed = failed or any(p[0] in (LINK_UNKNOWN, LINK_REFUSE) for p in plan)
    if apply:
        try:
            moved = apply_identity_links(links_dir, plan)
        except OSError as e:
            return lines + [f"  FAIL  identity: cannot write the links in {links_dir}: {e}"], True
        for slug in moved:
            lines.append(f"  FAIL  link {slug}: changed since the plan; left as it is")
        failed = failed or bool(moved)
    return lines, failed


def run_install_identity(args: argparse.Namespace, home: Path, policy: Dict[str, Any],
                         boxes: List[dict], states: Dict[str, Tuple[str, str]]) -> int:
    """install's identity step, only when the policy's `identity` is on:
    0, or 1 when any sandbox failed. A setup gap (the overlay, the registry
    directory or checkout) fails the step, by name."""
    if identity_mode(policy) is None:
        return 0
    print("identity (the host registry's names):")
    try:
        ids, repo = registry_setup(args)
        registry = registry_dir(argparse.Namespace(registry=None), ids)
    except ProvisionError as e:
        print(f"  FAIL  identity: {e}")
        return 1
    workspaces = {b["name"]: Path(b["workspace_path"]) for b in boxes if b.get("workspace_path")}
    members, excluded = migration_members(states, workspaces)
    try:
        pre, note = pre_identity(home, apply=args.apply)
    except PreIdentityError as e:
        pre, note = e, None
    if note:
        print(f"  {note}")
    lines, failed = install_identity(ha.Client(registry, repo, ids), identity_links_dir(home),
                                     members, apply=args.apply, pre=pre)
    for line in lines or ["  every selected sandbox is registered and linked"]:
        print(line)
    for slug, why in sorted(excluded.items()):
        print(f"  skip  {slug}: {why}")
    if args.apply and not failed:
        print("  a sandbox gains or changes its identity mount when it relaunches")
    return 1 if failed else 0


def run_link_identity(args: argparse.Namespace, home: Path) -> int:
    """`link-identity`: one `by-slug/<slug>` link per selected, registered
    sandbox, to the identity directory the registry names for it. Dry run by
    default. Exits 1 when any sandbox's link is UNKNOWN or refused."""
    boxes = discover_sandboxes(args.sandy)
    states = selection_states(home, boxes)
    workspaces = {b["name"]: Path(b["workspace_path"]) for b in boxes if b.get("workspace_path")}
    members, excluded = migration_members(states, workspaces)
    ids, repo = registry_setup(args)
    client = ha.Client(registry_dir(args, ids), repo, ids)
    shown = {slug: client.show(str(ws)) for slug, ws in members.items()}
    links_dir = identity_links_dir(home)
    try:
        plan = plan_identity_links(links_dir, members, shown)
    except OSError as e:
        raise ProvisionError(f"cannot read the links in {links_dir}: {e}") from None
    print(f"link-identity: {links_dir}")
    for action, slug, target, why in plan:
        tail = f" -> {target}" if target else ""
        print(f"  {action:8}{slug}{tail}" + (f": {why}" if why else ""))
    for slug, why in sorted(excluded.items()):
        print(f"  {LINK_SKIP:8}{slug}: {why}")
    failed = any(p[0] in (LINK_UNKNOWN, LINK_REFUSE) for p in plan)
    if not args.apply:
        print("  dry run (pass --apply to make the create and repoint links)")
    else:
        try:
            moved = apply_identity_links(links_dir, plan)
        except OSError as e:
            raise ProvisionError(f"cannot write the links in {links_dir}: {e}") from None
        for slug in moved:
            print(f"  {LINK_REFUSE:8}{slug}: changed since the plan; left as it is, run again")
        failed = failed or bool(moved)
        print("  applied; a sandbox gains or changes its identity mount when it relaunches")
    return 1 if failed else 0


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
    ap.add_argument(cpin.OVERRIDE_FLAG, dest="allow_unpinned_connector", metavar="REASON", default=None,
                    help="let install use a connector checkout that is not at its siblings.json pin, "
                         "or is dirty; the use, both commits and REASON are recorded in the install "
                         f"log ({cpin.LOG_NAME} beside the manifest) under --apply")
    ap.add_argument("--codex-connector-src", type=Path, default=DEFAULT_CODEX_CONNECTOR_SRC,
                    help=f"the {CODEX_CONNECTOR_REPO_NAME} checkout (optional: without it, "
                         f"a Codex sandbox gets no supervisor)")
    ap.add_argument("--sandy-home", type=Path, default=None,
                    help="override $SANDY_HOME (default: ~/.sandy)")
    ap.add_argument("--sandy", default="sandy", help="sandy executable (for --print-state)")
    ap.add_argument("--overlay", type=Path, default=None,
                    help="the deployment overlay, the private file naming the host registry's "
                         "identifiers (default: $AMAP_DEPLOY_OVERLAY)")
    ap.add_argument("--state-dir", type=Path, default=None,
                    help=f"router-private state, rendered into the router's config as "
                         f"`state_dir` (default: $SANDY_HOME/{ROUTER_STATE_SUBDIR})")
    sub = ap.add_subparsers(dest="command", required=True, metavar="COMMAND")

    install = sub.add_parser(
        "install", help="the manifest (the template on a fresh host), the payload, and the "
                        "router's config beside the manifest — the whole install, once per "
                        "host; sandy applies it to each sandbox at its launch")
    install.add_argument("--apply", action="store_true", help="write (default: report only)")
    install.add_argument("--activate", metavar="RUN_ID",
                         help="A3: write the local router's activation config (A1's staged bytes with the token "
                              "of A2's run RUN_ID) into the run directory and print root's place step; never "
                              "the live config itself. Needs --activation-sha256")
    install.add_argument("--activation-sha256", metavar="HEX",
                         help="the sha256 A1 printed for its record; compared with the PLACED record, never "
                              "taken from it")
    install.add_argument("--render-to", metavar="FILE",
                         help="write the rendering to a NEW file FILE, never to the live config (the runbook's R2: "
                              "the pinned router's config, rendered while the old router still runs)")
    install.add_argument("--decommission-hop", action="store_true",
                         help="render router.json WITHOUT the hop keys although state_dir holds hop "
                              "state: the explicit removal of a hop link (then restart the router)")
    install.add_argument("--fleet-domain-base", metavar="BASE",
                         help="a fresh host's template gets fleet_domain sandy.<host>.BASE "
                              "(default: internal, non-routable); a domain you control is "
                              "what routing between runtimes will need")

    fdom = sub.add_parser(
        "fleet-domain", help="this host's derived fleet domain, sandy.<host>.<base>, beside "
                             "the manifest's; --apply writes it into the manifest. Every "
                             "agent's address changes with it")
    fdom.add_argument("--base", metavar="BASE", help="the domain's base (default: internal)")
    fdom.add_argument("--apply", action="store_true", help="write (default: show)")

    verify = sub.add_parser(
        "verify", help="report only, exit 1 if anything is missing, stale or wrong: the "
                       "manifest against its rendering, the payload byte for byte, and per "
                       "selected sandbox the lanes, the relay, and what sandy applied at its "
                       "last launch")
    verify.add_argument("--only", action="append", default=[],
                        help="limit to sandboxes whose NAME exactly matches this (repeatable)")
    verify.add_argument("--match", action="append", default=[],
                        help="limit to sandboxes whose NAME contains this substring (repeatable)")
    verify.add_argument("--all", action="store_true",
                        help=f"list every workspace a condition applies to (by default a "
                             f"list longer than {vr.COLLAPSE_AFTER} is a count)")
    verify.add_argument("--host-facts", type=Path, metavar="PATH",
                        help="also write the router-process facts (docker liveness, the mount "
                             "set, config freshness, sandy's not-selected slugs) to PATH as "
                             "JSON, for the router's operator console. Written atomically on "
                             "every exit, carrying its own generated_ts and this run's exit "
                             "status; cron-safe")
    verify.add_argument("--a5", action="store_true",
                        help="A5 after activation: on a host whose host-setup document declares launchd, "
                             "the signing check's UNKNOWN with the exact VM-file-share reason under the live "
                             "token is the one non-pass excused; every other check must pass")
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

    migrate = sub.add_parser(
        "migrate-registry", help="prepare the registry migration: write the import batch "
                                 "(every selected sandbox's slug and workspace) and print "
                                 "the registry's operator commands that import it. This tool "
                                 "never runs them")
    migrate.add_argument("--registry", type=Path, default=None,
                         help="the host registry's directory (default: the overlay's "
                              "registry.directory)")
    migrate.add_argument("--batch", type=Path, required=True,
                         help="where to write the batch (operator data: it holds host paths)")
    migrate.add_argument("--registry-repo", type=Path, default=None,
                         help="the registry's checkout (default: $AMAP_REGISTRY_REPO, else the "
                              "overlay's `checkout`)")
    migrate.add_argument("--apply", action="store_true",
                         help="write the batch (default: show it)")

    link = sub.add_parser(
        "link-identity", help="link each selected, registered sandbox's slug to the identity "
                              "directory the registry names for it, which the manifest mounts")
    link.add_argument("--registry", type=Path, default=None,
                      help="the host registry's directory (default: the overlay's "
                           "registry.directory)")
    link.add_argument("--registry-repo", type=Path, default=None,
                      help="the registry's checkout (default: $AMAP_REGISTRY_REPO, else the "
                           "overlay's `checkout`)")
    link.add_argument("--apply", action="store_true", help="make the links (default: show)")

    hsetup = sub.add_parser(
        "host-setup", help="a hop deployment's host plan, from a host-setup document: print "
                           "the root-run steps (uids, groups, directories, the overlay), then "
                           "check the host against them. Applies nothing")
    hsetup.add_argument("--spec", type=Path, default=None,
                        help="the host-setup document (operator data; default: the deployment "
                             "overlay's host_setup section)")
    hsetup.add_argument("--production", action="store_true",
                        help="refuse the stub plugin's pin (default: plumbing, where the stub "
                             "is expected)")

    hrender = sub.add_parser(
        "hub-render", help="the hub-link router's D7 and environment files, rendered from the "
                           "host-setup document into the operator's run directory for the plan "
                           "to place. Writes only with --apply")
    hrender.add_argument("--spec", type=Path, default=None,
                         help="the host-setup document (default: the deployment overlay's "
                              "host_setup section)")
    hrender.add_argument("--apply", action="store_true", help="write the files (default: show)")

    kprobe = sub.add_parser(
        "hub-keyprobe", help="the key-read probe: the hub-link email router's rendered run spec, "
                             "without its secret volume, lstat-ing the local router's key paths; "
                             "PASS only when none exists inside it. Runs only with --apply")
    kprobe.add_argument("--spec", type=Path, default=None,
                        help="the host-setup document (default: the deployment overlay's "
                             "host_setup section)")
    kprobe.add_argument("--apply", action="store_true", help="run the probe (default: show it)")

    hsup = sub.add_parser(
        "hub-supervise", help="the hub-link router's supervisor and the weekly login probe's job, "
                              "rendered into the operator's run directory for the plan to place. "
                              "Writes only with --apply; enables nothing")
    hsup.add_argument("--spec", type=Path, default=None,
                      help="the host-setup document (default: the deployment overlay's host_setup section)")
    hsup.add_argument("--apply", action="store_true", help="write the files (default: show)")

    hstart = sub.add_parser(
        "hub-start-check", help="every check that must pass before the hub-link router starts; on a "
                                "pass, and only then, prints the start step. Runs nothing")
    hstart.add_argument("--spec", type=Path, default=None,
                        help="the host-setup document (default: the deployment overlay's host_setup section)")

    pact = sub.add_parser(
        "partition-activate", help="A1: from install's rendering, the staged delegation config, the prospective "
                                   "run spec and A1's record into the run directory (with --apply), and the root "
                                   "place and the weekly argv printed")
    pact.add_argument("--apply", action="store_true", help="write A1's record into the run directory")

    pprobe = sub.add_parser(
        "partition-probe", help="A5's post-activation document: P01 and P02 against the local router's final "
                                "running identity, into the run directory (with --apply); prints root's place")
    pprobe.add_argument("--post-activation", required=True, metavar="T_RUN_ID",
                        help="the run id of A2's evidence, the one the live token names")
    pprobe.add_argument("--document", required=True, help="the approved host-setup document (the unit argv's)")
    pprobe.add_argument("--document-sha256", required=True, help="that document's sha256")
    pprobe.add_argument("--apply", action="store_true", help="write the document into the run directory")

    pcheck = sub.add_parser(
        "partition-check", help="A5's six claims about an activated local router (V1 V2 E1 E2 T1 R1), read-only, "
                                "as one canonical JSON object (partition-check/2). Exit 0 means only that it was "
                                "written; with --ready, exit 0 only when all six PASS")
    pcheck.add_argument("--document", required=True,
                        help="the approved host-setup document, the path the weekly unit's argv names")
    pcheck.add_argument("--document-sha256", required=True, help="that document's sha256, as the unit's argv pins it")
    pcheck.add_argument("--ready", action="store_true", help="exit 0 only when all six claims PASS (A5's acceptance)")

    rfp = sub.add_parser(
        "router-fingerprint", help="the local router's upgrade base: capture the running router (--step) or an "
                                   "image (--image) into the run directory (with --apply), or match a capture "
                                   "against router-upgrade-bases.json (--match) or one commit (--verify-image). "
                                   "Stops nothing")
    mode = rfp.add_mutually_exclusive_group(required=True)
    mode.add_argument("--step", type=int, choices=(0, 2), help="capture the running local router at activation "
                                                                "step 0 or 2")
    mode.add_argument("--image", metavar="REF", help="capture an image, run by its immutable Id")
    mode.add_argument("--match", metavar="FILE", help="match a running capture: MEASURED (0), UNMEASURED (1), "
                                                      "UNKNOWN (2) or MIGRATE (3)")
    mode.add_argument("--verify-image", metavar="FILE", help="check an image capture against --commit: EXACT (0), "
                                                             "DIFFERS (1) or UNKNOWN (2)")
    rfp.add_argument("--commit", help="the commit --verify-image checks against (the hop pin)")
    rfp.add_argument("--container", help="with --step or --match: the running local router's container name, when it "
                                         "is not yet the host-setup document's router.container (a router started "
                                         "before activation)")
    rfp.add_argument("--spec", type=Path, default=None,
                     help="the host-setup document (default: the deployment overlay's host_setup section)")
    rfp.add_argument("--apply", action="store_true", help="capture and write the file (default: show)")

    rmig = sub.add_parser(
        "router-migrate", help="the runbook's R2: a local router whose state is keyed by instance name, moved to "
                               "the pinned router's registry layout, each step through the pinned router's own "
                               "code (map, preview, move, check, adopt). Exit 0 done, 1 STOP, 2 cannot run")
    rmig.add_argument("step", choices=("map", "preview", "move", "check", "adopt"))
    rmig.add_argument("--config", help="the migration config: install --render-to's file before the stop, the "
                                       "live config after it")
    rmig.add_argument("--map", help="a map step's file (preview, move and check)")
    rmig.add_argument("--preview", help="the preview step's file (check)")
    rmig.add_argument("--check", help="the check step's file (adopt)")
    rmig.add_argument("--reverse", metavar="JOURNAL", help="move: undo that move journal's renames")
    rmig.add_argument("--reason", help="why, written to each instance's audit log by the router")
    rmig.add_argument("--spec", type=Path, default=None,
                      help="the host-setup document (default: the deployment overlay's host_setup section)")
    rmig.add_argument("--apply", action="store_true", help="run the step (default: show)")

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

        if args.command == "fleet-domain":
            return run_fleet_domain(args, home)

        if args.command == "teardown":
            return run_teardown(args, home, boxes_dir)

        if args.command == "host-setup":
            return hsu.run(args.spec, production=args.production, overlay=ha.overlay_path(args.overlay),
                           policy_on=delegation_policy(home))

        if args.command == "hub-render":
            return hsu.hub_render(args.spec, apply=args.apply, overlay=ha.overlay_path(args.overlay))

        if args.command == "hub-keyprobe":
            return hsu.hub_keyprobe(args.spec, apply=args.apply, overlay=ha.overlay_path(args.overlay))

        if args.command == "hub-supervise":
            return hsu.hub_supervise(args.spec, apply=args.apply, overlay=ha.overlay_path(args.overlay))

        if args.command == "hub-start-check":
            return hsu.hub_start_check(args.spec, overlay=ha.overlay_path(args.overlay),
                                       policy_on=delegation_policy(home))

        if args.command == "partition-activate":
            return run_partition_activate(args, home)

        if args.command == "partition-probe":
            import partition_postactivation as ppa
            return ppa.run(args.document, args.document_sha256, args.post_activation, apply=args.apply)

        if args.command == "partition-check":
            import partition_check as pcheck
            return pcheck.run(args.document, args.document_sha256, ready_only=args.ready)

        if args.command == "router-fingerprint":
            import router_fingerprint as rfp
            return rfp.run(args)

        if args.command == "router-migrate":
            import router_migrate as rmig
            return rmig.run(args)

        if args.command == "migrate-registry":
            return run_migrate_registry(args, home)

        if args.command == "link-identity":
            return run_link_identity(args, home)

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


def delegation_policy(home: Path) -> Any:
    """Whether this host's policy turns delegation on (its hop_link carries
    `delegation`): True or False, or an Unresolved naming why the policy
    could not be read. The signing check decides nothing on an Unresolved."""
    try:
        link = hp.parse_hop_link(fp.load_policy(feature_manifest_path(home)))
    except (OSError, ValueError, fp.PolicyError) as e:
        return rh.Unresolved(f"the fleet policy cannot be read: {e}")
    return link is not None and link.inbound is not None


def run_verify_host_setup(args: argparse.Namespace, home: Path) -> int:
    """verify's host-setup part: when the deployment overlay has a
    `host_setup` section, every `host-setup` check, with an UNKNOWN a
    problem like a FAIL. Silent without an overlay. `--host-facts` does not
    carry these checks; its shape is the router's contract."""
    overlay = ha.overlay_path(getattr(args, "overlay", None))
    if overlay is None:
        return 0
    print("\nverify: the hop deployment's host setup")
    return hsu.verify_section(overlay, a5=getattr(args, "a5", False), policy_on=delegation_policy(home))


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
        install_notes: List[vr.Row] = []
        stale_rc = run_provision(args, servers, home, boxes_dir, dry=True, verifying=True,
                                 notes_out=install_notes)
        print("\nverify (2/2): the checks the install cannot make")
        live_rc = run_verify(args, servers, home, boxes_dir, facts, install_notes=install_notes)
        hop_rc = run_verify_host_setup(args, home)
        rc = stale_rc or live_rc or hop_rc
        return rc
    finally:
        if facts is not None:
            facts.write(args.host_facts, rc)


if __name__ == "__main__":
    raise SystemExit(main())
