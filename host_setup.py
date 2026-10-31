"""The host setup a hop deployment needs before its runtimes start: distinct
uids, the hop group, the configured roots with their owners and modes, and
the plugin overlay. Rendered as a plan for the operator; checked by
`host-setup` and by `verify`. NOTHING HERE APPLIES ANYTHING: every change is
a printed step that the operator runs as root.

The plan is DATA, not code. A host's setup is a JSON document (`SPEC_SCHEMA`)
that names the principals (one uid per runtime), the groups, the hops (which
principal is upstream of which), the runtimes (each hop principal's running
container, its image and its umask), every root directory with its owner,
group, mode and the principals that must reach it, each runtime's mounts of
those roots, each image's openssl, and the overlay. This module knows no
runtime's directory names; the document supplies them. A document that
leaves a hop principal without its runtime or its mounts, or an image
without its openssl record, does not load: a check that was never
configured must not read as a check that passed.

What it renders, in order, as calls to `host_steps.py`, which reaches every
path from `/` without following a symbolic link:
1. each root, parents before children, created or re-owned and re-moded
   through its own descriptor; a non-directory at a root path stops the step;
2. a barrier that fsyncs each root and every ancestor, so a root's entry is
   durable before a runtime opens it (a runtime cannot make durable the top
   of a bind-mounted tree from inside it);
3. the overlay file, root-owned and 0444, renamed into place;
4. each root marker, created exclusively;
5. each runtime's peer-uid variable (named per hop): the uid on the other side of its hop;
6. each hop runtime's umask, set in its service unit or launcher, and the
   rule that no runtime starts before the steps above.

What it checks, through router_health's three outcomes:
- every root, and every ancestor of it, is a real directory (a symbolic link
  never is), and each root has the planned owner, group and mode;
- every principal that owns or must reach a root has a mount that holds it
  (a document without one does not load), and can READ and SEARCH each
  directory from the top of that mount down to the root: a directory is
  opened to be fsynced, so an execute-only one fails a runtime's write;
- the overlay is a regular file, owned by root, mode 0444, outside every
  agent path, whose bytes hash to its pin; a production pin is not the stub;
- each runtime's running container is the declared image, binds each
  declared root at its declared path, and that path, seen inside the
  running container, is the host directory the plan created (by inode,
  owner, group and mode, or by the root's marker). The container is read
  with `docker inspect`, and inside it with `docker exec` as root running
  only `stat`, `cat` and a shell loop over /proc: nothing is written;
- each image's openssl, as the image reports it, is the recorded version and
  at least the recorded floor; no floor below 3.0 loads;
- every process of a hop runtime, read from its running container, runs
  under the runtime's declared umask, with the principal's primary group as
  its effective gid and exactly the principal's groups. The reach checks
  above assume those groups; a runtime started without one (a missing
  `--group-add`) cannot reach the roots they say it can.

A document with a `secrets` section adds a runtime's secret file: its plan
steps and its checks are secret_setup's. A document with a `hub` section adds
the hub-link email router's D7 and environment files and its rendering:
hub_runtime's. A `keys` section adds the local router's signing key, its
partition from the email router, the key probe's evidence and the guard
against a delegation block: hub_keys'.

None of these can see whether the barrier ran: durability rests on the plan
having run before any runtime started.

The umask is not taste. A runtime asks for 0750 item and 0700 .stage
directories, and for 0770 inbound item directories, which land 2770 under
their setgid parent so that the other side of the hop can empty them. A
umask that strips a requested bit is repaired by an fchmod after the mkdir,
and a crash between the two leaves a narrowed directory that every later call
refuses. Under 0027 or 0022 no bit of 0750 or 0700 is stripped, so for those
directories that window does not exist; both strip group write from 0770, so
for an inbound item directory it does. A runtime may run under 0027 only,
unless its record lists 0022 in `umasks`: one whose other paths create
directories under the umask alone would otherwise make them readable by
every uid. The runbook says what to do with a refused leftover.

Nothing under a hop root's per-link directory is a root. That directory and
everything beneath it are created by the runtimes, each level checked by its
creator and never repaired, so the plan never creates, re-owns or checks
them, and a document names none of them as a root. Nothing here can tell
which directory is a per-link one, so that rule is the operator's.
"""

import contextlib
import dataclasses
import hashlib
import json
import os
import posixpath
import re
import shlex
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import fleet_keys as fk    # the fleet's public signing keys: the pinned inventory
import hub_keys as hk      # the local router's key, kept from the email router; no delegation block
import hub_runtime as hr   # the hub-link router's files and rendering
import hub_supervise as hv  # the hub-link router's supervision, weekly probe job and start check
import hop_router as hp     # the local router's hop constant and recorded image (the router section)
import partition_activation as pa   # A1's placed record, which the signing check compares the live block with
import partition_evidence as pe   # the evidence document a live token names
import partition_setup as ps   # the partition evidence's directories and the harness gate (two sections)
import router_health as rh
import secret_exposure as se   # who else could reach that secret: every container, every engine
import secret_setup as ss   # a runtime's secret file: its section, plan steps and checks

SPEC_SCHEMA = "amap-deploy-sandy.host-setup/1"
#: The deployment overlay's section that holds a host-setup document.
OVERLAY_SECTION = "host_setup"

HERE = Path(__file__).resolve().parent
STUB_PLUGIN = HERE / "overlay" / "stub-plugin.py"
HOST_STEPS = HERE / "host_steps.py"
#: The stub's digest. A pin equal to it is plumbing, never production.
STUB_SHA256 = "cb88b58e3bad8cb111572732edc0f807d22370644813f9c4c52fba15daad160d"
#: The stub has no source commit; its pin says so with the all-zero commit.
STUB_COMMIT = "0" * 40

OVERLAY_OWNER_UID = 0
OVERLAY_MODE = 0o444

_MODE_RE = re.compile(r"[0-7]{3,4}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}")
_OPENSSL_RE = re.compile(r"OpenSSL (\d+)\.(\d+)\.(\d+)")
_CONTAINER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
_R, _W, _X = 4, 2, 1
#: The umasks a hop runtime may run under: neither strips a bit of 0750 or
#: 0700. Both strip group write from 0770, which the runtime restores with an
#: fchmod after the mkdir.
UMASKS = {"0027": 0o027, "0022": 0o022}
#: What a runtime record that names no `umasks` may run under. 0022 is
#: allowed only where a record lists it: a runtime that creates directories
#: under the umask alone would make them readable by every uid.
DEFAULT_UMASKS = ("0027",)
#: The lowest openssl the plugin's pkeyutl -rawin fallback may run on.
OPENSSL_FLOOR_MIN = (3, 0)
#: The uid the in-container probes run as. No runtime may run as it, so a
#: probe's own processes are never read as a runtime's.
PROBE_UID = 0
_UMASK_FIELD = re.compile(r"^Umask:\s*([0-7]{4})\s*$", re.M)
_UID_FIELD = re.compile(r"^Uid:\s*(\d+)\s+(\d+)", re.M)
_PID_FIELD = re.compile(r"^Pid:\s*(\d+)\s*$", re.M)
_GID_FIELD = re.compile(r"^Gid:\s*(\d+)\s+(\d+)", re.M)
_GROUPS_FIELD = re.compile(r"^Groups:[ \t]*([0-9 \t]*)$", re.M)
_PROBE_LINE = re.compile(r"\Aprobe (\d+)\n")


class SpecError(ValueError):
    """The host-setup document is unusable. Nothing is rendered from it."""


@dataclass(frozen=True)
class Principal:
    name: str
    uid: int
    gids: Tuple[int, ...]          # primary first


@dataclass(frozen=True)
class Root:
    path: str
    owner: str
    group: str
    mode: int
    readers: Tuple[str, ...]
    purpose: str


@dataclass(frozen=True)
class Spec:
    principals: Dict[str, Principal]
    groups: Dict[str, int]
    hops: Tuple[Tuple[str, str, str, str], ...]   # (name, upstream, downstream, peer_uid_env)
    roots: Tuple[Root, ...]
    overlay_path: Optional[str]
    overlay_pin: Optional[Dict[str, str]]
    agent_paths: Tuple[str, ...]
    openssl: Dict[str, Dict[str, Any]]          # image -> {version, floor, source, path}
    mounts: Tuple[Dict[str, str], ...] = ()     # {principal, host, container, marker?}
    runtimes: Tuple[Dict[str, Any], ...] = ()   # {principal, container, image, umask, umasks}
    production: bool = False
    secrets: Optional[ss.SecretSpec] = None     # a runtime's secret file, when the document has one
    hub: Optional[hr.HubSpec] = None            # the hub-link router's rendering, when the document has one
    keys: Optional[hk.KeySpec] = None           # the local router's signing key, when the document has one
    supervision: Optional[hv.SupervisionSpec] = None   # the hub-link router's supervisor, when the document has one
    router: Optional[hp.RouterSpec] = None      # the local router's recorded image, when the document has one
    partition: Optional[ps.PartitionSpec] = None   # the partition evidence's directories and weekly job
    gate: Optional[ps.GateSpec] = None          # the harness's passing record, the operator's alone
    fleet_keys: Optional[fk.FleetKeysPin] = None   # the fleet inventory's path and pin, when the document has one

    def runtime_of(self, principal: str) -> Dict[str, Any]:
        return next(r for r in self.runtimes if r["principal"] == principal)


def _abs_normal(p: Any, what: str) -> str:
    if not isinstance(p, str) or not p.startswith("/") or posixpath.normpath(p) != p or p.startswith("//"):
        raise SpecError(f"{what} must be an absolute, normalised path")
    return p


def _int(v: Any, what: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        raise SpecError(f"{what} must be a non-negative integer")
    return v


def _umask(v: Any, what: str) -> int:
    if not isinstance(v, str) or v not in UMASKS:
        raise SpecError(f"{what} must be one of {', '.join(sorted(UMASKS, reverse=True))}: "
                        f"any other strips a bit a hop directory's requested mode needs")
    return UMASKS[v]


def load_spec(doc: Any) -> Spec:
    """Parse and validate a host-setup document. Refuses rather than guesses:
    an unknown member, a shared uid on a hop, a root uid for a runtime, an
    owner or group nobody declared, and any hop principal or image left
    without what its checks need."""
    if not isinstance(doc, dict) or doc.get("schema") != SPEC_SCHEMA:
        raise SpecError(f"the document is not a {SPEC_SCHEMA} host setup")
    known = {"schema", "principals", "groups", "hops", "roots", "overlay", "agent_paths", "openssl",
             "mounts", "runtimes", "production", ss.SECTION, hr.SECTION, hk.SECTION, hv.SECTION, hp.SECTION,
             ps.SECTION, ps.GATE_SECTION, fk.SECTION}
    if set(doc) - known:
        raise SpecError(f"unknown member(s): {', '.join(sorted(set(doc) - known))}")
    production = doc.get("production", False)
    if not isinstance(production, bool):
        raise SpecError("production must be true or false")
    groups = {}
    for g, gid in (doc.get("groups") or {}).items():
        groups[g] = _int(gid, f"groups.{g}")
    principals = {}
    for name, p in (doc.get("principals") or {}).items():
        if not isinstance(p, dict) or set(p) != {"uid", "groups"}:
            raise SpecError(f"principals.{name} must have exactly uid and groups")
        uid = _int(p["uid"], f"principals.{name}.uid")
        if uid == PROBE_UID:
            raise SpecError(f"principals.{name}: a runtime never runs as root")
        if not isinstance(p["groups"], list) or not p["groups"]:
            raise SpecError(f"principals.{name}.groups must name at least its primary group")
        gids = []
        for g in p["groups"]:
            if g not in groups:
                raise SpecError(f"principals.{name}: group {g!r} is not declared")
            gids.append(groups[g])
        principals[name] = Principal(name, uid, tuple(gids))
    hops = []
    for h in doc.get("hops") or []:
        if not isinstance(h, dict) or set(h) != {"name", "upstream", "downstream", "peer_uid_env"}:
            raise SpecError("each hop must have exactly name, upstream, downstream and peer_uid_env")
        if not isinstance(h["peer_uid_env"], str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*", h["peer_uid_env"]):
            raise SpecError(f"hop {h['name']}: peer_uid_env must be an environment variable name")
        for side in ("upstream", "downstream"):
            if h[side] not in principals:
                raise SpecError(f"hop {h['name']}: {side} {h[side]!r} is not a principal")
        if principals[h["upstream"]].uid == principals[h["downstream"]].uid:
            raise SpecError(f"hop {h['name']}: both sides run as uid "
                            f"{principals[h['upstream']].uid}; each side needs its own uid")
        hops.append((h["name"], h["upstream"], h["downstream"], h["peer_uid_env"]))
    if not hops:
        raise SpecError("the document names no hop: there is nothing to set up or check")
    roots = []
    for i, r in enumerate(doc.get("roots") or []):
        if not isinstance(r, dict) or set(r) != {"path", "owner", "group", "mode", "readers", "purpose"}:
            raise SpecError(f"roots[{i}] must have exactly path, owner, group, mode, readers, purpose")
        path = _abs_normal(r["path"], f"roots[{i}].path")
        if path == "/":
            raise SpecError(f"roots[{i}].path cannot be /")
        if r["owner"] not in principals:
            raise SpecError(f"roots[{i}]: owner {r['owner']!r} is not a principal")
        if r["group"] not in groups:
            raise SpecError(f"roots[{i}]: group {r['group']!r} is not declared")
        if not isinstance(r["mode"], str) or not _MODE_RE.fullmatch(r["mode"]):
            raise SpecError(f"roots[{i}].mode must be an octal string such as \"2750\"")
        readers = tuple(r["readers"]) if isinstance(r["readers"], list) else ()
        if not readers or any(x not in principals for x in readers):
            raise SpecError(f"roots[{i}].readers must name declared principals")
        roots.append(Root(path, r["owner"], r["group"], int(r["mode"], 8), readers, str(r["purpose"])))
    if len({r.path for r in roots}) != len(roots):
        raise SpecError("a root is listed twice")
    ov = doc.get("overlay")
    ov_path, ov_pin = None, None
    if ov is not None:
        if not isinstance(ov, dict) or set(ov) != {"path", "pin"}:
            raise SpecError("overlay must have exactly path and pin")
        ov_path = _abs_normal(ov["path"], "overlay.path")
        ov_pin = parse_pin(ov["pin"])
    agent_paths = tuple(_abs_normal(p, "agent_paths[]") for p in doc.get("agent_paths") or [])
    openssl = {}
    for image, rec in (doc.get("openssl") or {}).items():
        if not isinstance(rec, dict) or not {"version", "floor", "source"} <= set(rec) \
                or set(rec) - {"version", "floor", "source", "path"}:
            raise SpecError(f"openssl.{image} must have version, floor and source, and optionally path")
        if openssl_version(f"OpenSSL {rec['version']}") is None:
            raise SpecError(f"openssl.{image}.version must be X.Y.Z")
        if not isinstance(rec["floor"], str) or not re.fullmatch(r"\d+\.\d+", rec["floor"]):
            raise SpecError(f"openssl.{image}.floor must be X.Y")
        floor = tuple(int(x) for x in rec["floor"].split("."))
        if floor < OPENSSL_FLOOR_MIN:
            raise SpecError(f"openssl.{image}.floor is below {OPENSSL_FLOOR_MIN[0]}.{OPENSSL_FLOOR_MIN[1]}, "
                            f"the lowest the plugin's pkeyutl -rawin fallback may run on")
        if openssl_version(f"OpenSSL {rec['version']}")[:2] < floor:
            raise SpecError(f"openssl.{image}.version is below its own floor")
        binary = _abs_normal(rec["path"], f"openssl.{image}.path") if "path" in rec else "openssl"
        openssl[image] = {"version": rec["version"], "source": str(rec["source"]), "floor": floor,
                          "path": binary}
    runtimes = []
    for i, r in enumerate(doc.get("runtimes") or []):
        if not isinstance(r, dict) or not {"principal", "container", "image", "umask"} <= set(r) \
                or set(r) - {"principal", "container", "image", "umask", "umasks"}:
            raise SpecError(f"runtimes[{i}] must have principal, container, image and umask, "
                            f"and optionally umasks")
        if r["principal"] not in principals:
            raise SpecError(f"runtimes[{i}]: principal {r['principal']!r} is not declared")
        if not isinstance(r["container"], str) or not _CONTAINER_RE.fullmatch(r["container"]):
            raise SpecError(f"runtimes[{i}].container must be a container name")
        if not isinstance(r["image"], str) or not r["image"]:
            raise SpecError(f"runtimes[{i}].image must name the runtime's image")
        if r["image"] not in openssl:
            raise SpecError(f"runtimes[{i}]: image {r['image']!r} has no openssl record")
        allowed = r.get("umasks", list(DEFAULT_UMASKS))
        if not isinstance(allowed, list) or not allowed:
            raise SpecError(f"runtimes[{i}].umasks must list the umasks this runtime may run under")
        allowed_set = {_umask(u, f"runtimes[{i}].umasks[]") for u in allowed}
        umask = _umask(r["umask"], f"runtimes[{i}].umask")
        if umask not in allowed_set:
            raise SpecError(f"runtimes[{i}].umask {r['umask']} is not one this runtime allows "
                            f"({', '.join(allowed)})")
        runtimes.append({"principal": r["principal"], "container": r["container"], "image": r["image"],
                         "umask": umask, "umasks": tuple(sorted(allowed_set, reverse=True))})
    if len({r["container"] for r in runtimes}) != len(runtimes):
        raise SpecError("a runtime's container is listed twice")
    root_paths = {r.path for r in roots}
    mounts = []
    for i, m in enumerate(doc.get("mounts") or []):
        if not isinstance(m, dict) or not {"principal", "host", "container"} <= set(m) \
                or set(m) - {"principal", "host", "container", "marker"}:
            raise SpecError(f"mounts[{i}] must have principal, host and container, and optionally marker")
        if "marker" in m and (not isinstance(m["marker"], str)
                              or not re.fullmatch(r"[A-Za-z0-9._-]+", m["marker"]) or m["marker"] in (".", "..")):
            raise SpecError(f"mounts[{i}].marker must be one file name inside the root")
        if m["principal"] not in principals:
            raise SpecError(f"mounts[{i}]: principal {m['principal']!r} is not declared")
        if not any(r["principal"] == m["principal"] for r in runtimes):
            raise SpecError(f"mounts[{i}]: {m['principal']} has no runtime to hold this mount")
        if _abs_normal(m["host"], f"mounts[{i}].host") not in root_paths:
            raise SpecError(f"mounts[{i}].host must be one of the roots: a runtime's durable "
                            f"root is a directory this plan creates and syncs")
        _abs_normal(m["container"], f"mounts[{i}].container")
        mounts.append({k: m[k] for k in ("principal", "host", "container", "marker") if k in m})
    hop_principals = sorted({p for _, up, down, _ in hops for p in (up, down)})
    for p in hop_principals:
        n = sum(1 for r in runtimes if r["principal"] == p)
        if n != 1:
            raise SpecError(f"hop principal {p} has {n} runtimes entries; it needs exactly one, "
                            f"so its container and umask are checked")
        if not any(m["principal"] == p for m in mounts):
            raise SpecError(f"hop principal {p} has no mounts entry; its durable root must be declared "
                            f"so the running container's mount is checked")
    for r in roots:
        for p in (r.owner,) + r.readers:
            if not any(m["principal"] == p and _holds(m["host"], r.path) for m in mounts):
                raise SpecError(f"root {r.path}: {p} owns or reads it, but no mount of {p}'s runtime "
                                f"holds it; declare the mount that reaches it")
    secrets = None
    if ss.SECTION in doc:
        try:
            secrets = ss.load(doc[ss.SECTION], principals, runtimes)
        except ss.SecretSpecError as e:
            raise SpecError(str(e)) from None
    spec = Spec(principals, groups, tuple(hops), tuple(roots), ov_path, ov_pin, agent_paths, openssl,
                tuple(mounts), tuple(runtimes), production, secrets)
    if hr.SECTION in doc:
        try:
            spec = dataclasses.replace(spec, hub=hr.load(doc[hr.SECTION], spec))
        except hr.HubSpecError as e:
            raise SpecError(str(e)) from None
    if secrets is not None and ss.OPTIONAL_CLONE_ROLE not in secrets.clones \
            and (spec.hub is None or spec.hub.d7_source_sha256 is None):
        # The producer clone may be left out ONLY by the host whose hub pins
        # the D7 source as one file; every other host, the runner included,
        # holds it.
        raise SpecError("secrets.clones has no producer, and no hub pins the D7 source as one file "
                        "({path, sha256, commit, from}): only that host may leave the clone out")
    if hk.SECTION in doc:
        try:
            spec = dataclasses.replace(spec, keys=hk.load(doc[hk.SECTION], spec))
        except hk.KeySpecError as e:
            raise SpecError(str(e)) from None
    if hv.SECTION in doc:
        try:
            spec = dataclasses.replace(spec, supervision=hv.load(doc[hv.SECTION], spec))
        except hv.SupervisionSpecError as e:
            raise SpecError(str(e)) from None
    if hp.SECTION in doc:
        try:
            spec = dataclasses.replace(spec, router=hp.load(doc[hp.SECTION], spec))
        except hp.RouterSpecError as e:
            raise SpecError(str(e)) from None
    try:
        if ps.SECTION in doc:
            spec = dataclasses.replace(spec, partition=ps.load(doc[ps.SECTION], spec))
        if ps.GATE_SECTION in doc:
            spec = dataclasses.replace(spec, gate=ps.load_gate(doc[ps.GATE_SECTION], spec.partition))
    except ps.PartitionSpecError as e:
        raise SpecError(str(e)) from None
    if fk.SECTION in doc:
        if spec.keys is None:
            raise SpecError(f"the {fk.SECTION} section needs a keys section: the inventory names this host's "
                            "signing key, which the keys section places")
        try:
            spec = dataclasses.replace(spec, fleet_keys=fk.load(doc[fk.SECTION]))
        except fk.FleetKeysError as e:
            raise SpecError(str(e)) from None
    if spec.keys is not None and spec.router is not None:
        declared = spec.runtime_of(spec.keys.principal)["container"]
        if declared != spec.router.container:
            raise SpecError(f"the router section's container {spec.router.container} is not the local router's "
                            f"runtime container {declared} ({spec.keys.principal}'s): the checks of the local "
                            f"router would read two different containers")
    return spec


def parse_pin(pin: Any) -> Optional[Dict[str, str]]:
    """The overlay pin, in the host registry's shape: {sha256, commit, path}, or None
    for an explicit "no plugin". sha256 is the pin; commit is provenance."""
    if pin is None:
        return None
    if not isinstance(pin, dict) or set(pin) != {"sha256", "commit", "path"}:
        raise SpecError("the pin must be null, or have exactly sha256, commit and path")
    if not isinstance(pin["sha256"], str) or not _SHA256_RE.fullmatch(pin["sha256"]):
        raise SpecError("pin.sha256 must be 64 lower-case hex")
    if not isinstance(pin["commit"], str) or not _COMMIT_RE.fullmatch(pin["commit"]):
        raise SpecError("pin.commit must be 40 lower-case hex")
    _abs_normal(pin["path"], "pin.path")
    return {"sha256": pin["sha256"], "commit": pin["commit"], "path": pin["path"]}


def stub_pin(in_image_path: str) -> Dict[str, str]:
    """The stub plugin's pin, for exercising the plumbing."""
    return {"sha256": STUB_SHA256, "commit": STUB_COMMIT, "path": in_image_path}


def overlay_record(pin: Optional[Dict[str, str]], schema: str) -> str:
    """The host registry's overlay.json for this pin (or for "no plugin").
    Its schema id is the registry's, from the deployment overlay."""
    return json.dumps({"schema": schema, "plugin": pin}, indent=2, sort_keys=True) + "\n"


def openssl_version(text: str) -> Optional[Tuple[int, int, int]]:
    m = _OPENSSL_RE.search(text or "")
    return tuple(int(x) for x in m.groups()) if m else None


# --- The plan -----------------------------------------------------------------


def peer_uids(spec: Spec) -> Dict[Tuple[str, str], int]:
    """`{(principal, variable): uid}`: each side of a hop gets the uid on the
    other side, under the hop's variable. One variable naming two peers for
    one principal is refused."""
    out: Dict[Tuple[str, str], int] = {}
    for name, up, down, env in spec.hops:
        for me, peer in ((up, down), (down, up)):
            uid = spec.principals[peer].uid
            if out.setdefault((me, env), uid) != uid:
                raise SpecError(f"{me} is on hops with two different peers; one {env} cannot name both")
    return out


def _ancestors(path: str) -> List[str]:
    parts = path.split("/")[1:]
    return ["/" + "/".join(parts[:i]) for i in range(len(parts))] if parts != [""] else []


#: Root's own directories the plan places into are made 0755, root's.
ROOT_DIR_MODE = 0o755


def root_leaves(spec: Spec) -> List[str]:
    """The root-owned directories a later `install -d -o 0 -g 0 -m 0755` line
    makes: the anchor's and the writer's, and the hub's D7 directory, its D7
    source's (the file form) and its environment file's. `install -d` follows a
    link and re-owns and re-modes whatever already sits there, so each is
    prechecked with root's own directories, never adopted."""
    out = set()
    if spec.secrets is not None:
        out.update((spec.secrets.writer_dir, posixpath.dirname(spec.secrets.anchor)))
    if spec.hub is not None:
        out.update((spec.hub.d7_dir, posixpath.dirname(spec.hub.env_file)))
        if spec.hub.d7_source_sha256 is not None:
            out.add(posixpath.dirname(spec.hub.d7_source))
    return sorted(out, key=lambda d: (d.count("/"), d))


def root_dirs(spec: Spec) -> List[str]:
    """The root-owned directories the plan places into but does not make
    itself, with their parents below the first level, shallow first: the
    plugin's directory, and the parents of each of root_leaves (each made by
    its own `install -d`, which would make a missing parent under root's umask,
    not 0755). The first level (/opt) must already exist; nothing here changes it."""
    own = [] if spec.overlay_path is None else [posixpath.dirname(spec.overlay_path)]
    dirs = set(own)
    for d in own + root_leaves(spec):
        dirs.update(a for a in _ancestors(d) if a.count("/") >= 2)
    return sorted(dirs, key=lambda d: (d.count("/"), d))


#: find, by the path both supported hosts give it (GNU on Linux, BSD on macOS), never by PATH.
FIND = "/usr/bin/find"
#: The shell the precheck runs in as root, by path: one line through sudo, never the operator's own shell.
ROOT_SH = "/bin/sh"


def _dir_safe(var: str, find: str = FIND) -> str:
    """A POSIX test that "$var" is a real directory, root's (the precheck runs
    as root, so -O is root), and writable by no group and no other user.
    find's own status is checked: a find that fails is never an empty answer."""
    return (f'[ -d "${var}" ] && [ ! -L "${var}" ] && [ -O "${var}" ] && '
            f'scan=$({find} "${var}" -maxdepth 0 \\( -perm -g+w -o -perm -o+w \\) -print) && [ -z "$scan" ]')


def _dir_exact(var: str, find: str, uid: str, gid: str) -> str:
    """A POSIX test that "$var" is exactly uid:gid 0755 (find's -perm with no
    prefix is an exact match, special bits included, in GNU and BSD find)."""
    return (f'scan=$({find} "${var}" -maxdepth 0 -user {uid} -group {gid} -perm {ROOT_DIR_MODE:04o} -print) '
            f'&& [ "$scan" = "${var}" ]')


def precheck_script(find: str = FIND, uid: str = "0", gid: str = "0") -> str:
    """The precheck, as one constant script over its arguments: the parents,
    then `--`, then the directories to be made. It holds no single quote, so it
    is passed whole to `sh -c`; the paths travel as arguments, never inside it."""
    return ('ok=1; m=0; for d in "$@"; do if [ "$d" = -- ]; then m=1; continue; fi; '
            f'if [ "$m" = 0 ]; then {{ {_dir_safe("d", find)}; }} || '
            '{ echo "STOP: $d is not a real root directory, or a group or other user can write it" >&2; '
            'ok=0; break; }; '
            f'else {{ [ ! -e "$d" ] && [ ! -L "$d" ]; }} || {{ {_dir_safe("d", find)} && {_dir_exact("d", find, uid, gid)}; }} || '
            '{ echo "STOP: $d exists and is not exactly a real root 0:0 0755 directory" >&2; ok=0; break; }; fi; '
            'done; [ "$ok" = 1 ]')


def root_dirs_precheck(dirs: List[str], q: Callable[[str], str], parents: Optional[List[str]] = None,
                       find: str = FIND, sudo: Optional[str] = "/usr/bin/sudo", uid: str = "0",
                       gid: str = "0") -> str:
    """One read-only line, run as root through `sudo /bin/sh -c` before root's
    own directories are made: / and each first-level parent must exist, be
    root's and be writable by no group or other user; each directory to be
    made must be absent (not even a dangling link), or already exactly root
    0:0 0755 (never another owner's or another mode, which the helper or
    `install -d` would otherwise silently re-own or re-mode). Its status is 1
    on any STOP (never `exit`), and 0 only when every directory passed.
    `sudo` None, and `uid`/`gid`, are the suite's stand-ins for root."""
    if parents is None:
        parents = ["/"] + sorted({"/" + d.split("/")[1] for d in dirs})
    script = precheck_script(find, uid, gid)
    if "'" in script:
        raise ValueError("the precheck script must hold no single quote: it is passed whole to sh -c")
    head = f"{sudo} " if sudo else ""
    return (f"{head}{ROOT_SH} -c '{script}' sh " + " ".join(q(p) for p in parents) + " --"
            + "".join(" " + q(d) for d in dirs))


def render_plan(spec: Spec, overlay_source: Optional[Path] = None,
                hub: Optional[hr.Rendered] = None) -> List[str]:
    """The root-run steps, in order, as shell lines. Printed, never run.
    `hub` is the hub-link router's rendering, when the document has one."""
    q = shlex.quote
    # The interpreter root runs is the one step 1 (the partition's validation) vetted, by its path.
    py = spec.partition.tools["python3"] if spec.partition is not None else "python3"
    steps = f"{q(py)} {q(str(HOST_STEPS))}"
    lines = ["# Run as root. Each line is one step; nothing here has run. No host_steps.py step follows a "
             "symbolic link, and each is safe to run again.",
             f"# Run them from a checkout no sandbox mounts read-write (a fresh clone at the recorded "
             f"deploy commit), never from an agent's workspace: these steps run {HOST_STEPS.name} as root.",
             "# Run each command line separately. Continue only after checking that its exit status is 0. "
             "Any STOP or nonzero status ends this run; do not run the following steps."]
    if spec.partition is not None and spec.supervision is not None and spec.secrets is not None:
        # Imported here: host_setup is in the weekly job's bundle, and the job's own installation is not.
        import partition_job as pj
        # Printed first: every later step that runs an interpreter as root comes after this check of what
        # root will run, and goes on only when it passes.
        lines += pj.validation_steps(spec.partition, spec.supervision.kind, q)
    for r in sorted(spec.roots, key=lambda r: (r.path.count("/"), r.path)):
        p = spec.principals[r.owner]
        lines.append(f"{steps} root {q(r.path)} {p.uid} {spec.groups[r.group]} {r.mode:04o}  # {r.purpose}")
    sync_dirs = sorted({a for r in spec.roots for a in _ancestors(r.path)} | {r.path for r in spec.roots},
                       key=lambda d: (-d.count("/"), d))
    lines.append("# The barrier: each root and every ancestor fsynced, deepest first.")
    lines.append(f"{steps} sync " + " ".join(q(d) for d in sync_dirs))
    made = root_dirs(spec)
    checked = sorted(set(made) | set(root_leaves(spec)), key=lambda d: (d.count("/"), d))
    if checked:
        sudo = (spec.secrets.tools.get("sudo") if spec.secrets is not None else None) or "/usr/bin/sudo"
        lines.append("# Root's own directories, before anything is placed in them: made 0755 and root's, "
                     "parents first. A missing one is made fresh; an existing one that is not exactly "
                     "root 0:0 0755 stops the step. The precheck covers the directories the later "
                     "`install -d` lines make too, so none of them adopts what is already there.")
        lines.append(root_dirs_precheck(checked, q, sudo=q(sudo)))
    for d in made:
        lines.append(f"{steps} root {q(d)} 0 0 {ROOT_DIR_MODE:04o}")
    if spec.overlay_path is not None and spec.overlay_pin is not None:
        src = q(str(overlay_source)) if overlay_source else "<the pinned plugin artifact>"
        lines.append(f"{steps} place {src} {q(spec.overlay_path)} --sha256 {spec.overlay_pin['sha256']}"
                     f"  # the overlay, root-owned 0444, refused unless its bytes have the pinned sha256")
    for m in spec.mounts:
        if "marker" in m:
            lines.append(f"{steps} marker {q(posixpath.join(m['host'], m['marker']))}"
                         f"  # {m['principal']}'s root marker: random, root-owned, read-only")
    for (name, env), uid in sorted(peer_uids(spec).items()):
        if spec.hub is not None and spec.secrets is not None and name == spec.secrets.principal:
            uid = spec.hub.peer_uid      # the hub-link router's HOP_PEER_UID is the measured uid
        lines.append(f"# {name}'s runtime environment: {env}={uid}")
    for r in spec.runtimes:
        lines.append(f"# {r['principal']}'s runtime ({r['container']}) starts under umask {r['umask']:04o}: "
                     f"UMask={r['umask']:04o} in its service unit, or `umask {r['umask']:04o}` in its "
                     f"launcher before it execs")
    if spec.secrets is not None:
        lines += ss.render(spec.secrets, q)
        lines += ss.sudo_route_notice(spec.secrets)
    if spec.hub is not None and hub is not None:
        lines += hr.plan(spec, spec.hub, hub, q, steps)
    if spec.keys is not None:
        lines += hk.plan(spec, spec.keys, q, steps)
    if spec.supervision is not None:
        lines += hv.plan(spec, q, steps)
    if spec.partition is not None:
        lines += ps.plan(spec.partition, spec.gate, q, anchor=spec.secrets.anchor if spec.secrets else None)
        if spec.supervision is None or spec.secrets is None:
            lines.append("# The weekly job's validation and bundle steps need the supervision and secrets sections "
                         "(the host's kind, the deploy pin and the pinned writer).")
        else:
            # The validation of what root will run was printed first, above every other step.
            lines += pj.provision_steps(spec.partition, spec.secrets.clones["deploy"]["sha"], spec.secrets.writer, q)
    lines.append("# Start no runtime until every step above has run: each root exists and is synced "
                 "before a runtime opens it.")
    return lines


# --- Verify ---------------------------------------------------------------------


def _fact(name: str, value: Any, provenance: str) -> rh.Fact:
    return rh.Fact(name, value, provenance)


def _can(st, uid: int, gids: Sequence[int], bits: int) -> bool:
    mode = stat.S_IMODE(st.st_mode)
    if st.st_uid == uid:
        return (mode >> 6) & bits == bits
    if st.st_gid in gids:
        return (mode >> 3) & bits == bits
    return mode & bits == bits


def _lstat(path: str, lstat: Callable) -> Any:
    try:
        return lstat(path)
    except FileNotFoundError:
        return None
    except OSError as e:
        return rh.Unresolved(f"cannot inspect {path}: {e}")


def _holds(top: str, path: str) -> bool:
    return path == top or path.startswith(top.rstrip("/") + "/")


def _reach_from(spec: Spec, principal: str, root: str) -> str:
    """Where `principal`'s reach to `root` begins: the deepest host path of
    its own mounts that holds the root (load guarantees one). A directory
    above a container's mount is invisible to it."""
    return max((m["host"] for m in spec.mounts if m["principal"] == principal and _holds(m["host"], root)),
               key=len)


def verify_roots(spec: Spec, lstat: Callable = os.lstat) -> List[rh.Check]:
    checks: List[rh.Check] = []
    for r in spec.roots:
        src = f"the host setup's root for {r.purpose}"
        owner = spec.principals[r.owner]
        chain = _ancestors(r.path)
        sts = {d: _lstat(d, lstat) for d in chain}
        bad = next((d for d in chain if isinstance(sts[d], rh.Unresolved)
                    or sts[d] is None or not stat.S_ISDIR(sts[d].st_mode)), None)
        anc_claim = f"every ancestor of {r.path} is a real directory"
        anc_want = _fact("ancestors", True, "the plan's steps and barrier follow no symbolic link")
        if bad is not None and isinstance(sts[bad], rh.Unresolved):
            checks.append(rh.unknown(anc_claim, anc_want, sts[bad].reason, f"inspect {bad}"))
        else:
            checks.append(rh.check(anc_claim, anc_want, bad is None,
                                   f"replace {bad} with a real directory" if bad else "nothing",
                                   do_not="never point a symlink at another directory to satisfy this"))
        st = _lstat(r.path, lstat)
        want = _fact("root", (owner.uid, spec.groups[r.group], r.mode), src)
        claim = f"{r.path} is a directory owned by {owner.uid}:{spec.groups[r.group]}, mode {r.mode:04o}"
        remedy = f"run the plan's `root` step for {r.path}, as root"
        if isinstance(st, rh.Unresolved):
            checks.append(rh.unknown(claim, want, st.reason, remedy))
            continue
        if st is None or not stat.S_ISDIR(st.st_mode):   # lstat: a symlink is never a directory
            what = "absent" if st is None else "not a real directory"
            checks.append(rh.check(claim, want, what, remedy,
                                   do_not="never point a symlink at another directory to satisfy this"))
            continue
        checks.append(rh.check(claim, want, (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)), remedy,
                               do_not="never widen the mode to make a runtime's write succeed"))
        sts[r.path] = st
        for name in dict.fromkeys((r.owner,) + r.readers):   # the owner reaches it too
            p = spec.principals[name]
            top = _reach_from(spec, name, r.path)
            walk = [d for d in chain + [r.path] if _holds(top, d)]
            blocked: Any = None
            for d in walk:
                dst = sts[d]
                if isinstance(dst, rh.Unresolved):
                    blocked = dst
                    break
                if dst is None or not _can(dst, p.uid, p.gids, _R | _X):
                    blocked = d
                    break
            reach = f"{name} (uid {p.uid}) can read and search every directory from {top} down to {r.path}"
            role = ("owns and reads it" if name == r.owner and name in r.readers else
                    "owns it" if name == r.owner else "reads it")
            want_r = _fact("reach", True, f"{src}: {name} {role}")
            fix = (f"make {blocked} readable AND searchable by uid {p.uid} or one of its groups; "
                   f"a runtime opens each directory below its mount to fsync it") if isinstance(blocked, str) \
                else f"inspect {r.path}'s ancestors as uid {p.uid}"
            if isinstance(blocked, rh.Unresolved):
                checks.append(rh.unknown(reach, want_r, blocked.reason, fix))
            else:
                checks.append(rh.check(reach, want_r, blocked is None, fix,
                                       do_not="an execute-only directory is not enough"))
    return checks


def _sha256(path: str) -> Any:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError as e:
        return rh.Unresolved(f"cannot read {path}: {e}")


def verify_overlay(spec: Spec, *, production: bool, lstat: Callable = os.lstat,
                   digest: Callable[[str], Any] = _sha256) -> List[rh.Check]:
    """The overlay as the host holds it. In production, the stub's digest is
    a failure; during plumbing it is the expected pin."""
    if spec.overlay_pin is None or spec.overlay_path is None:
        return []
    pin, path = spec.overlay_pin, spec.overlay_path
    src = "the host setup's overlay pin"
    checks: List[rh.Check] = []
    st = _lstat(path, lstat)
    want = _fact("overlay", (OVERLAY_OWNER_UID, OVERLAY_MODE), "the overlay rule: root-owned, 0444")
    claim = f"the overlay {path} is a regular file owned by root, mode 0444"
    remedy = "run the plan's overlay `place` step, as root"
    if isinstance(st, rh.Unresolved):
        checks.append(rh.unknown(claim, want, st.reason, remedy))
    elif st is None or not stat.S_ISREG(st.st_mode):
        checks.append(rh.check(claim, want, "absent" if st is None else "not a regular file", remedy))
    else:
        checks.append(rh.check(claim, want, (st.st_uid, stat.S_IMODE(st.st_mode)), remedy,
                               do_not="never chmod it writable to replace it in place"))
    inside = [a for a in spec.agent_paths if path == a or path.startswith(a + "/")]
    checks.append(rh.check(f"the overlay {path} is outside every agent path",
                           _fact("agent_paths", [], "the overlay rule: outside every agent path"),
                           inside, f"move the overlay out of {', '.join(inside) or 'agent paths'}"))
    checks.append(rh.check(f"the overlay's bytes hash to its pin",
                           _fact("sha256", pin["sha256"], f"{src} (sha256 is the pin; commit is provenance)"),
                           digest(path), "install the pinned artifact itself, not a rebuild of it",
                           do_not="never re-pin to whatever the file now hashes to"))
    if production:
        checks.append(rh.check("the overlay pins a reviewed plugin, not the stub",
                               _fact("stub", False, "the stub plugin is plumbing only"),
                               pin["sha256"] == STUB_SHA256,
                               "pin the reviewed plugin artifact's digest"))
    return checks


def verify_openssl(spec: Spec, reported: Dict[str, Any]) -> List[rh.Check]:
    """Each image's `openssl version`, as the image printed it (or an
    Unresolved when it could not be asked), against the floor and the
    recorded version."""
    checks: List[rh.Check] = []
    for image, rec in sorted(spec.openssl.items()):
        out = reported.get(image, rh.Unresolved(f"{image} was not asked"))
        have = out if isinstance(out, rh.Unresolved) else openssl_version(out) or \
            rh.Unresolved(f"{image} printed no OpenSSL version")
        want = _fact("openssl", tuple(int(x) for x in rec["version"].split(".")),
                     f"the recorded pin for {image} (source: {rec['source']})")
        checks.append(rh.check(f"{image}'s openssl is the recorded {rec['version']}", want, have,
                               f"rebuild {image} with the pinned openssl, or record the new pin with its source"))
        floor = rec["floor"]
        checks.append(rh.check(f"{image}'s openssl is at least {floor[0]}.{floor[1]}",
                               _fact("openssl_floor", floor, f"the recorded floor for {image}"),
                               have, f"rebuild {image} on OpenSSL {floor[0]}.{floor[1]} or later",
                               ok=lambda floor, v: tuple(v[:2]) >= floor))
    return checks


# --- The running containers -----------------------------------------------------


def _exec(container: str, script: str, *args: str) -> Any:
    """`docker exec` as the probe uid into the RUNNING container: stdout, or an
    Unresolved naming why it could not be asked. The scripts only read."""
    try:
        p = rh.run(["docker", "exec", "-u", str(PROBE_UID), container, "sh", "-c", script, "sh", *args])
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    if p.rc != 0:
        return rh.Unresolved(f"`docker exec` into {container} exited {p.rc}: {p.err.strip()[:200]}")
    return p.out


def ask_container(container: str) -> Any:
    """`{"image", "binds"}` of the RUNNING container, from `docker inspect`:
    its configured image and each bind mount as `(source, destination)`, or
    an Unresolved. A container that is not running is an Unresolved."""
    try:
        p = rh.run(["docker", "inspect", "-f", "{{json .State.Running}}\t{{json .Config.Image}}\t"
                    "{{json .Mounts}}", container])
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    if p.rc != 0:
        return rh.Unresolved(f"`docker inspect {container}` exited {p.rc}: {p.err.strip()[:200]}")
    try:
        running, image, mounts = (json.loads(x) for x in p.out.strip().split("\t"))
    except ValueError:
        return rh.Unresolved(f"`docker inspect {container}` printed {p.out.strip()[:80]!r}")
    if running is not True:
        return rh.Unresolved(f"{container} is not running")
    if not isinstance(image, str) or not isinstance(mounts, list):
        return rh.Unresolved(f"`docker inspect {container}` printed no image or mount table")
    binds = [(m.get("Source"), m.get("Destination")) for m in mounts
             if isinstance(m, dict) and m.get("Type") == "bind"]
    return {"image": image, "binds": binds}


def ask_identity(ref: str, *, docker: str, engine: str) -> Any:
    """`docker inspect` of the container `ref` names (an id, or a name only
    to compare), asked of the APPROVED engine with the APPROVED docker,
    whatever the operator's PATH, DOCKER_HOST or DOCKER_CONTEXT select: its
    whole document; None when that engine affirms there is no such
    container (a failed inspect, then listings by id and by name that
    succeed and are empty); an Unresolved otherwise. Read-only."""
    env = {"DOCKER_HOST": engine, "DOCKER_CONTEXT": "default"}

    def ask(*args: str) -> Any:
        return rh.run([docker, "--host", engine, *args], extra_env=env)
    try:
        p = ask("inspect", "--type", "container", "--format", "{{json .}}", ref)
        if p.rc == 0:
            doc = json.loads(p.out)
            return doc if isinstance(doc, dict) else rh.Unresolved(f"`docker inspect {ref}` printed no object")
        q = ask("ps", "--all", "--quiet", "--no-trunc", "--filter", f"id={ref}")
        r = ask("ps", "--all", "--quiet", "--no-trunc", "--filter", f"name=^/{ref}$")
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    except ValueError:
        return rh.Unresolved(f"`docker inspect {ref}` printed no JSON")
    if q.rc == 0 and r.rc == 0 and not q.out.strip() and not r.out.strip():
        return None
    return rh.Unresolved(f"`docker inspect {ref}` exited {p.rc}, and the engine does not affirm it is absent")


def ask_mount(container: str, path: str, marker: Optional[str] = None) -> Any:
    """`(identity, marker content or None)` of `path` as the RUNNING container
    `container` sees it, or an Unresolved. Read-only: stat and cat."""
    out = _exec(container, 'stat -c "%i %u %g %a" "$1" && if [ -n "$2" ]; then cat "$1/$2"; fi',
                path, marker or "")
    if isinstance(out, rh.Unresolved):
        return out
    first, _, rest = out.partition("\n")
    parts = first.split()
    if len(parts) != 4 or not all(x.isdigit() for x in parts):
        return rh.Unresolved(f"stat in {container} printed {first.strip()[:80]!r}")
    ident = (int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3], 8))
    return ident, (rest.strip() if marker else None)


def _identity(st) -> Tuple[int, int, int, int]:
    """What a directory is, as both the host and a container can see it:
    inode, owner, group, permission bits. The device number is left out: it
    differs between the host and a container behind a VM's shared
    filesystem even for the same directory."""
    return (st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode))


def _read_marker(path: str) -> Any:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as e:
        return rh.Unresolved(f"cannot read the marker {path}: {e}")
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        return rh.Unresolved(f"the marker {path} is not a regular file")
    try:
        with os.fdopen(fd, encoding="ascii") as f:
            return f.read(256).strip() or None
    except (OSError, ValueError) as e:
        return rh.Unresolved(f"cannot read the marker {path}: {e}")


def verify_containers(spec: Spec, seen: Dict[str, Any]) -> List[rh.Check]:
    """Each runtime's running container is its declared image. `seen` maps a
    container to `ask_container`'s answer."""
    checks = []
    for r in spec.runtimes:
        info = seen.get(r["container"], rh.Unresolved(f"{r['container']} was not asked"))
        claim = f"{r['principal']}'s running container {r['container']} is the image {r['image']}"
        want = _fact("image", r["image"], f"the host setup's runtime for {r['principal']}")
        remedy = f"start {r['principal']}'s runtime as {r['container']} from {r['image']}"
        if isinstance(info, rh.Unresolved):
            checks.append(rh.unknown(claim, want, info.reason, remedy))
        else:
            checks.append(rh.check(claim, want, info["image"], remedy))
    return checks


def verify_mounts(spec: Spec, seen: Dict[str, Any], lstat: Callable = os.lstat,
                  ask: Callable[..., Any] = ask_mount,
                  read_marker: Optional[Callable[[str], Any]] = None) -> List[rh.Check]:
    """Each declared mount, on the RUNNING container: the container binds the
    host root at the declared path, and that path, as the container sees it,
    is the host directory this plan created and synced (by inode, owner,
    group and mode, or by the root's marker)."""
    checks: List[rh.Check] = []
    for m in spec.mounts:
        c = spec.runtime_of(m["principal"])["container"]
        info = seen.get(c, rh.Unresolved(f"{c} was not asked"))
        bind_claim = f"{c} binds {m['host']} at {m['container']}"
        bind_want = _fact("bind", (m["host"], m["container"]), f"the host setup's mount for {m['principal']}")
        bind_fix = f"start {c} with {m['host']} bound at {m['container']}, exactly as declared"
        if isinstance(info, rh.Unresolved):
            checks.append(rh.unknown(bind_claim, bind_want, info.reason, bind_fix))
        else:
            checks.append(rh.check(bind_claim, bind_want, [b for b in info["binds"] if b[1] == m["container"]],
                                   bind_fix, ok=lambda want, have: list(have) == [want]))
        host_st = _lstat(m["host"], lstat)
        claim = f"{m['principal']}'s durable root {m['container']} in {c} is the host directory {m['host']}"
        remedy = (f"mount {m['host']} at {m['container']} exactly as declared, and change no "
                  f"mount between this check and activation")
        if host_st is None or isinstance(host_st, rh.Unresolved):
            reason = host_st.reason if host_st is not None else f"{m['host']} does not exist"
            checks.append(rh.unknown(claim, _fact("mount", rh.Unresolved(reason), "the host directory"),
                                     reason, f"create {m['host']} first (the plan's root step)"))
            continue
        marker = m.get("marker")
        host_marker = (read_marker or _read_marker)(posixpath.join(m["host"], marker)) if marker else None
        got = info if isinstance(info, rh.Unresolved) else ask(c, m["container"], marker)
        if isinstance(got, rh.Unresolved):
            checks.append(rh.unknown(claim, _fact("mount", _identity(host_st), "the host directory"),
                                     got.reason, remedy))
            continue
        ident, seen_marker = got
        by_inode = ident == _identity(host_st)
        by_marker = isinstance(host_marker, str) and host_marker == seen_marker
        how = ("matched by inode, owner, group and mode" if by_inode else
               "matched by the root's marker (the inode differs, as a VM's shared filesystem may make it)"
               if by_marker else
               "neither the inode, owner, group and mode nor " +
               ("the marker" if marker else "a marker (none is declared)") + " matched")
        want = _fact("mount", True, f"{m['host']} on the host: {how}")
        checks.append(rh.check(claim, want, by_inode or by_marker, remedy,
                               do_not="never accept a root merely because it is on the same device"))
    return checks


#: Every process's status, except the probe shell's own: its pid comes first.
_PROC_SCRIPT = ('echo "probe $$"; for f in /proc/[0-9]*/status; do '
                'case "$f" in "/proc/$$/status") continue;; esac; cat "$f" 2>/dev/null; done; true')


def parse_proc_status(text: str) -> List[Tuple[int, Optional[int]]]:
    """`[(effective uid, umask or None)]`, one per process, from the probe's
    output: its own pid on the first line, then concatenated
    /proc/<pid>/status files. The probe's own process is dropped."""
    procs = []
    for block in _proc_blocks(text):
        uid = _UID_FIELD.search(block)
        if uid is None:
            continue
        mask = _UMASK_FIELD.search(block)
        procs.append((int(uid.group(2)), int(mask.group(1), 8) if mask else None))
    return procs


def _proc_blocks(text: str) -> List[str]:
    """The status blocks of the probe's output, the probe's own dropped."""
    text = text or ""
    probe = _PROBE_LINE.match(text)
    me = int(probe.group(1)) if probe else None
    blocks = []
    for block in re.split(r"(?m)^(?=Name:)", text[probe.end():] if probe else text):
        pid = _PID_FIELD.search(block)
        if pid is not None and me is not None and int(pid.group(1)) == me:
            continue
        blocks.append(block)
    return blocks


def parse_proc_groups(text: str) -> List[Tuple[int, Optional[Tuple[int, Tuple[int, ...]]]]]:
    """`[(effective uid, (effective gid, supplementary gids) or None)]`, one
    per process, from the same probe output as `parse_proc_status`. None is
    a block with no Gid or no Groups field."""
    procs = []
    for block in _proc_blocks(text):
        uid = _UID_FIELD.search(block)
        if uid is None:
            continue
        gid, groups = _GID_FIELD.search(block), _GROUPS_FIELD.search(block)
        procs.append((int(uid.group(2)),
                      (int(gid.group(2)), tuple(sorted(int(g) for g in groups.group(1).split())))
                      if gid and groups else None))
    return procs


def ask_groups(container: str) -> Any:
    """Every process in the RUNNING container `container` but the probe's
    own, as `parse_proc_groups` reads it, or an Unresolved."""
    out = _exec(container, _PROC_SCRIPT)
    return out if isinstance(out, rh.Unresolved) else parse_proc_groups(out)


def ask_umasks(container: str) -> Any:
    """Every process in the RUNNING container `container` but the probe's
    own, as `parse_proc_status` reads it, or an Unresolved. The probe runs as
    `PROBE_UID`, which no runtime may run as."""
    out = _exec(container, _PROC_SCRIPT)
    return out if isinstance(out, rh.Unresolved) else parse_proc_status(out)


def verify_umasks(spec: Spec, ask: Callable[[str], Any] = ask_umasks) -> List[rh.Check]:
    """Each hop runtime's processes, as its running container reports them,
    run under its declared umask. A runtime with no process to read, or a
    kernel that reports no umask, is UNKNOWN."""
    checks: List[rh.Check] = []
    for r in spec.runtimes:
        p = spec.principals[r["principal"]]
        claim = f"every process of {r['principal']} (uid {p.uid}) in {r['container']} runs under umask {r['umask']:04o}"
        want = _fact("umask", [r["umask"]], f"the host setup's umask for {r['principal']}'s runtime")
        remedy = (f"set UMask={r['umask']:04o} in {r['principal']}'s service unit, or `umask {r['umask']:04o}` "
                  f"in its launcher before it execs, and restart it")
        procs = ask(r["container"])
        if isinstance(procs, rh.Unresolved):
            checks.append(rh.unknown(claim, want, procs.reason, remedy))
            continue
        mine = [m for uid, m in procs if uid == p.uid]
        if not mine:
            checks.append(rh.unknown(claim, want, f"{r['container']} has no process running as uid {p.uid}",
                                     f"start {r['principal']}'s runtime, then check again"))
        else:
            # As for the groups: a known wrong umask is a FAIL even beside a
            # process that reported none.
            seen = sorted({m for m in mine if m is not None})
            if None in mine and seen in ([], want.value):
                checks.append(rh.unknown(claim, want,
                                         f"{r['container']}'s kernel reports no umask for a process",
                                         f"read {r['principal']}'s service unit or launcher for its umask"))
            else:
                checks.append(rh.check(claim, want, seen, remedy,
                                       do_not="never widen a hop directory's mode to suit a runtime's umask"))
    return checks


def verify_groups(spec: Spec, ask: Callable[[str], Any] = ask_groups) -> List[rh.Check]:
    """Each hop runtime's processes, as its running container reports them,
    run with the principal's primary group as their effective gid and with
    exactly the principal's groups (the effective gid and the supplementary
    list together). A runtime with no process to read, or a kernel that
    reports no groups, is UNKNOWN."""
    checks: List[rh.Check] = []
    for r in spec.runtimes:
        p = spec.principals[r["principal"]]
        claim = (f"every process of {r['principal']} (uid {p.uid}) in {r['container']} runs with "
                 f"gid {p.gids[0]} and the groups {' '.join(str(g) for g in sorted(set(p.gids)))}")
        want = _fact("groups", [(p.gids[0], tuple(sorted(set(p.gids))))],
                     f"the host setup's groups for {r['principal']}, its primary first")
        remedy = (f"start {r['principal']}'s runtime as {p.uid}:{p.gids[0]} with each other group of its "
                  f"own added (docker run --group-add) and no other, and restart it")
        procs = ask(r["container"])
        if isinstance(procs, rh.Unresolved):
            checks.append(rh.unknown(claim, want, procs.reason, remedy))
            continue
        mine = [g for uid, g in procs if uid == p.uid]
        if not mine:
            checks.append(rh.unknown(claim, want, f"{r['container']} has no process running as uid {p.uid}",
                                     f"start {r['principal']}'s runtime, then check again"))
        else:
            # A known wrong answer is a FAIL even beside a process that
            # reported nothing; only an all-correct partial read is UNKNOWN.
            seen = sorted({(egid, tuple(sorted(set(sup) | {egid}))) for egid, sup in
                           (g for g in mine if g is not None)})
            if None in mine and seen in ([], want.value):
                checks.append(rh.unknown(claim, want,
                                         f"{r['container']}'s kernel reports no groups for a process",
                                         f"read {r['principal']}'s container settings for its groups"))
            else:
                checks.append(rh.check(claim, want, seen, remedy,
                                       do_not="never give a runtime another principal's group to reach a "
                                              "root; fix the root's group in the document"))
    return checks


def ask_openssl(images: Dict[str, str]) -> Dict[str, Any]:
    """Each image's own `openssl version` (`images` maps an image to the
    openssl it runs), in a throwaway container with no network that never
    pulls, or an Unresolved naming why it could not be asked. Read-only."""
    out: Dict[str, Any] = {}
    for image, binary in sorted(images.items()):
        try:
            p = rh.run(["docker", "run", "--rm", "--pull", "never", "--network", "none",
                        "--entrypoint", binary, image, "version"])
        except rh.CannotRun as e:
            out[image] = rh.Unresolved(str(e))
            continue
        out[image] = p.out if p.rc == 0 else \
            rh.Unresolved(f"`{binary} version` in {image} exited {p.rc}: {p.err.strip()[:200]}")
    return out


# --- The verb ---------------------------------------------------------------------


def overlay_section(overlay: Path) -> Any:
    """The overlay's `host_setup` section, or None when it has none. An
    unreadable overlay, or a section that is not an object, raises SpecError."""
    try:
        doc = json.loads(Path(overlay).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise SpecError(f"deployment overlay {overlay} is unreadable: {e}") from None
    sec = doc.get(OVERLAY_SECTION) if isinstance(doc, dict) else None
    if sec is not None and not isinstance(sec, dict):
        raise SpecError(f"deployment overlay {overlay}: {OVERLAY_SECTION} is not an object")
    return sec


def read_spec(spec_path: Optional[Path], overlay: Optional[Path]) -> Any:
    """The host-setup document: the file `spec_path`, else the deployment
    overlay's `host_setup` section. With neither, raises SpecError; nothing
    is guessed."""
    if spec_path is not None:
        try:
            return json.loads(Path(spec_path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise SpecError(f"cannot use {spec_path}: {e}") from None
    if overlay is None:
        raise SpecError("no host-setup document: pass --spec, or a deployment overlay (--overlay, "
                        "or its environment variable) with a host_setup section")
    sec = overlay_section(overlay)
    if sec is None:
        raise SpecError(f"deployment overlay {overlay} has no {OVERLAY_SECTION!r} object")
    return sec


def _trust_gate(spec: Spec, lstat: Callable, secrets: Optional[Dict[str, Any]]) -> Any:
    """The live engine route's judgement for a whole run of checks, made with
    the same lstat (and realpath) the tool rows use: no live docker call in the
    run executes unless every d3.3 §5(c) prerequisite PASSes (the interpreter,
    the writer, docker's closure, sudo), and on the sudo route each names the
    document's engine as DOCKER_HOST."""
    if spec.secrets is None:
        return contextlib.nullcontext()
    return ss.trust_gate(spec.secrets, lstat, (secrets or {}).get("realpath", os.path.realpath),
                         engine=spec.supervision.engine if spec.supervision else None)


def checks(spec: Spec, *, production: bool, lstat: Callable = os.lstat, secrets: Optional[Dict[str, Any]] = None,
           **probes: Any) -> List[rh.Check]:
    """_checks, under the live engine route's trust gate."""
    with _trust_gate(spec, lstat, secrets):
        return _checks(spec, production=production, lstat=lstat, secrets=secrets, **probes)


def _checks(spec: Spec, *, production: bool, lstat: Callable = os.lstat,
           digest: Callable[[str], Any] = _sha256,
           openssl: Optional[Dict[str, Any]] = None,
           containers: Optional[Callable[[str], Any]] = None,
           mounts: Optional[Callable[..., Any]] = None,
           umasks: Optional[Callable[[str], Any]] = None,
           groups: Optional[Callable[[str], Any]] = None,
           secrets: Optional[Dict[str, Any]] = None,
           exposure: Optional[Dict[str, Any]] = None, overlay: Optional[Path] = None,
           secret_lock: Optional[Callable[[Any], Any]] = None,
           hub: Optional[Dict[str, Any]] = None,
           keys: Optional[Dict[str, Any]] = None,
           supervision: Optional[Dict[str, Any]] = None,
           enablement: Optional[Dict[str, Any]] = None,
           router: Optional[Dict[str, Any]] = None,
           partition: Optional[Dict[str, Any]] = None,
           policy_on: Any = None) -> List[rh.Check]:
    """Every check of the host against the plan. `production` is ORed with
    the document's own. `secrets` passes probes to the secret's checks;
    `overlay` is the file the document was read from (None for --spec). The
    secret's checks run under the one-shots' lock, taken once."""
    seen = {r["container"]: (containers or ask_container)(r["container"]) for r in spec.runtimes}
    # One /proc probe per container, read for both the umask and the groups,
    # so the two checks see the same processes.
    probed: Dict[str, Any] = {}

    def read_with(parse: Callable[[str], Any]) -> Callable[[str], Any]:
        def ask(container: str) -> Any:
            if container not in probed:
                probed[container] = _exec(container, _PROC_SCRIPT)
            out = probed[container]
            return out if isinstance(out, rh.Unresolved) else parse(out)
        return ask
    out = verify_roots(spec, lstat)
    out += verify_overlay(spec, production=production or spec.production, lstat=lstat, digest=digest)
    out += verify_containers(spec, seen)
    out += verify_mounts(spec, seen, lstat, ask_mount if mounts is None else mounts)
    out += verify_openssl(spec, openssl if openssl is not None else
                          ask_openssl({i: rec["path"] for i, rec in spec.openssl.items()}))
    out += verify_umasks(spec, read_with(parse_proc_status) if umasks is None else umasks)
    out += verify_groups(spec, read_with(parse_proc_groups) if groups is None else groups)
    if spec.secrets is not None:
        out += secret_checks(spec, lstat=lstat, digest=digest, overlay=overlay, secrets=secrets,
                             exposure=exposure, secret_lock=secret_lock)
    if spec.hub is not None:
        out += hr.checks(spec, spec.hub, lstat=lstat, **(hub or {}))
    if spec.keys is not None:
        k = keys or {}
        out += hk.checks(spec, spec.keys, lstat=lstat, signing=signing_inputs(spec, policy_on, partition or {}, k),
                         **{n: v for n, v in k.items() if n not in ("horizon_default", "status", "witness", "now")})
    if spec.hub is not None:
        out += verify_recovery_horizon(spec, (keys or {}).get("read_json_", hk.read_json),
                                       (keys or {}).get("horizon_default"))
    if spec.supervision is not None:
        out += hv.checks(spec, lstat=lstat, **(supervision or {}))
        if hv.labels(spec):
            en = enablement or {}
            out += hv.verify_enablement(
                spec, en["disabled"] if "disabled" in en else hv.ask_disabled(spec),
                en.get("gate") or (lambda: start_gate(spec, lstat=lstat, digest=digest, hub=hub, keys=keys,
                                                      supervision=supervision, overlay=overlay,
                                                      secrets=secrets, exposure=exposure,
                                                      secret_lock=secret_lock, policy_on=policy_on,
                                                      partition=partition)),
                en.get("loaded") or hv.ask_loaded)
    if spec.router is not None:
        out += hp.checks(spec, **(router or {}))
    if spec.partition is not None or spec.gate is not None:
        p = partition or {}
        out += ps.verify(spec.partition, spec.gate, delegation_enabled=policy_on is not False, lstat=lstat,
                         owned_chain=ss._owned_chain,
                         rl_sha=p["rl_sha"] if "rl_sha" in p else hp.hop_pin(),
                         hop_sha=(spec.overlay_pin or {}).get("commit", rh.Unresolved("the overlay has no plugin pin")),
                         plugin_sha256=hp.PLUGIN_SHA256, read=p.get("read", ps.read_record))
        out += verify_stop_target(spec, p)
        out += verify_weekly_runs(spec, p)
    return out


def partition_host(spec: Spec) -> Any:
    """The name the partition records carry for this host: the hub section's
    host label, the one field that names the host."""
    return spec.hub.host_label if spec.hub is not None else rh.Unresolved("the document has no hub section")


def host_view(spec: Spec) -> Any:
    """The document's declared supervision, the host's platform, kernel
    boot_id and the live config's filesystem type, device, inode, ctime and
    sha256 with the host's clock, read together: the host stamps that ctime.
    The config is resolved once and that file alone is stat'ed, read and
    looked up in mountinfo (hub_keys.open_resolved)."""
    try:
        real, st, raw = hk.open_resolved(spec.keys.local_config)
        boot = open("/proc/sys/kernel/random/boot_id").read().strip() if sys.platform == "linux" else None
        fs = hk.mount_fstype(real, hk.read_mountinfo()) if sys.platform == "linux" else None
    except (OSError, ValueError) as e:
        return rh.Unresolved(f"cannot inspect {spec.keys.local_config} or the host's kernel: {e}")
    return {"kind": spec.supervision.kind if spec.supervision is not None else None, "platform": sys.platform,
            "boot_id": boot, "fstype": fs, "dev": st.st_dev, "ino": st.st_ino, "ctime_ns": st.st_ctime_ns,
            "sha256": hashlib.sha256(raw).hexdigest(), "now": time.time()}


def signing_inputs(spec: Spec, policy_on: Any, p: Dict[str, Any], k: Dict[str, Any]) -> hk.Signing:
    """Everything the signing check reads, as read now. `policy_on` is the
    fleet policy's answer (its hop_link has `delegation`), None when this run
    read no policy. `p` may supply `rl_sha`, `read`, `read_placed` and
    `read_evidence`; `k` may supply `status` and `witness`."""
    if policy_on is None:
        policy_on = rh.Unresolved("this run read no fleet policy (verify reads it from the manifest)")
    bad = ps.gate_problems(spec.gate, rl_sha=p["rl_sha"] if "rl_sha" in p else hp.hop_pin(),
                           hop_sha=(spec.overlay_pin or {}).get("commit", rh.Unresolved("the overlay has no plugin pin")),
                           plugin_sha256=hp.PLUGIN_SHA256, read=p.get("read", ps.read_record))
    approved: Any = None
    why = "the document has no partition section"
    host = partition_host(spec)
    if spec.partition is not None:
        path = posixpath.join(spec.partition.evidence_dir, ps.ACTIVATION)
        try:
            approved = pa.parse_activation(p.get("read_placed", ps.read_placed)(path))
        except FileNotFoundError:
            approved, why = None, f"{path} is absent"
        except OSError as e:
            approved = rh.Unresolved(f"cannot read {path} as placed: {e}")
        except pa.ActivationError as e:
            approved, why = None, f"{path} is not an activation record: {e}"
        if isinstance(approved, dict) and (approved["final_config_path"] != spec.keys.local_config
                                           or approved["host"] != host):
            approved, why = None, f"{path} is another host's or another config path's"

    def named(token: Any) -> Any:
        if spec.partition is None or isinstance(host, rh.Unresolved):
            return None, pe.NAMED_MISSING, "the document has no partition or hub section"
        return pe.named_document(token, evidence_dir=spec.partition.evidence_dir, host=host,
                                 read=p.get("read_evidence", pe.read_placed))
    try:
        container = hk.local_container(spec, spec.keys)
    except StopIteration:
        container = None
    missing = rh.Unresolved(f"the document declares no runtime for {spec.keys.principal}, the local router")
    status = k.get("status", hk.ASK)
    if status is hk.ASK:
        status = hk.ask_status(spec, container) if container else missing
    witness = k.get("witness", hk.ASK)
    if witness is hk.ASK:
        witness = (lambda host_sha: hk.adoption(lambda: hk.ask_config_tuple(spec, container),
                                                lambda: hk.ask_status(spec, container), host_sha,
                                                host_view=lambda: host_view(spec))) if container \
            else (lambda host_sha: (rh.UNKNOWN, missing.reason))
    return hk.Signing(policy_on=policy_on, gate_ok=not bad, approved=approved, approved_why=why, named=named,
                      status=status, witness=witness, now=k.get("now", time.time()))


def start_inputs(spec: Spec, policy_on: Any, p: Dict[str, Any]) -> hk.Signing:
    """The static matrix's inputs for the start gate, read as verify reads
    them (`signing_inputs`): the policy's answer, the harness gate, A1's
    placed record and the token's named evidence. The router's status and
    the adoption witness are verify's alone and are never asked here."""
    return signing_inputs(spec, policy_on, p, {
        "status": rh.Unresolved("the start gate reads no router status"),
        "witness": lambda host_sha: (rh.UNKNOWN, "the start gate asks no adoption witness")})


def verify_weekly_runs(spec: Spec, p: Dict[str, Any]) -> List[rh.Check]:
    """No run of the weekly job left undecided, from its own record, in scope
    exactly as the stop target is. `p` may supply `read_placed`, `read` and
    `now`."""
    # Imported here: host_setup is in the weekly job's bundle, and this check is not.
    import partition_runs as pr
    if spec.partition is None:
        return []
    if spec.keys is None:
        return [rh.check(pr.RUNS_CLAIM, rh.Fact("undecided runs", True, "the weekly job's own record"),
                         "cannot be judged: the document has no keys section",
                         "add the keys section: whether the record is required is judged against the local "
                         "router's live config", ok=lambda e, a: a is True)]
    return pr.verify_runs(spec.partition, spec.gate, live_config=spec.keys.local_config,
                          read=p.get("read_placed", ps.read_placed), read_live=p.get("read", ps.read_record),
                          **({"now": p["now"]} if "now" in p else {}))


def verify_stop_target(spec: Spec, p: Dict[str, Any]) -> List[rh.Check]:
    """The weekly job's stop target, against this document's approved values:
    the local router's live config, the engine, the docker it runs (its
    realpath) and the local router's container name, which is inspected only
    to compare. `p` may supply `inspect`, `read_placed`, `read` and
    `realpath`."""
    if spec.partition is None and spec.gate is None:
        return []
    missing = [what for what, absent in (("partition", spec.partition is None), ("keys", spec.keys is None),
                                         ("supervision", spec.supervision is None), ("hops", not spec.hops)) if absent]
    if missing:
        return [rh.check(ps.TARGET_CLAIM, rh.Fact("stop target", True, "the weekly job's record of the local router"),
                         f"cannot be judged: the document has no {', '.join(missing)} section",
                         "add the missing sections: the stop target is judged against the local router's live "
                         "config (keys), its engine (supervision) and its container (hops)",
                         ok=lambda e, a: a is True)]
    docker = p.get("realpath", os.path.realpath)(spec.partition.tools["docker"])
    engine = spec.supervision.engine
    return ps.verify_target(spec.partition, spec.gate, live_config=spec.keys.local_config, engine=engine,
                            docker=docker, router_name=spec.runtime_of(spec.hops[0][1])["container"],
                            inspect=p.get("inspect", lambda ref: ask_identity(ref, docker=docker, engine=engine)),
                            read=p.get("read_placed", ps.read_placed), read_live=p.get("read", ps.read_record))


def verify_recovery_horizon(spec: Spec, read: Callable[[str], Any] = hk.read_json,
                            horizon_default: Optional[Callable[[], Tuple[Optional[int], str]]] = None
                            ) -> List[rh.Check]:
    """The hub-link router's inbound recovery window stays below the local
    router's dedup horizon: an item recovered after the local router forgot
    it would be admitted twice. The window is [2]'s rendered variable, the
    value it validates at start; the horizon is [1]'s config
    (keys.local_config, which install binds to the router.json it renders),
    or the hop checkout's default when the key is absent."""
    claim = (f"the hub-link router's {hr.RECOVERY_ENV} is below the local router's "
             f"{hp.HORIZON_KEY}")
    remedy = (f"keep {hr.RECOVERY_ENV} unset, or set it below the local router's {hp.HORIZON_KEY}, "
              "then render both again")
    env = dict(hr.environment(spec, spec.hub))
    if not env.get(hr.RECOVERY_ENV, "").isdigit():
        return [rh.unknown(claim, rh.Fact("horizon", None, "the local router's config"),
                           f"the environment file renders no {hr.RECOVERY_ENV}",
                           f"render {hr.RECOVERY_ENV}: unset, the hub-link router falls back to a default "
                           "nothing here reads")]
    window, why = int(env[hr.RECOVERY_ENV]), f"{hr.RECOVERY_ENV} as the environment file renders it"
    if spec.keys is None:
        return [rh.unknown(claim, rh.Fact("horizon", None, "the local router's config"),
                           "the document has no keys section, so the local router's config is not named",
                           "add the keys section with local_config")]
    try:
        doc = read(spec.keys.local_config)
    except (OSError, ValueError) as e:
        return [rh.unknown(claim, rh.Fact("horizon", None, spec.keys.local_config),
                           f"cannot read {spec.keys.local_config}: {e}", "render and place the local router's config")]
    if not isinstance(doc, dict):
        return [rh.unknown(claim, rh.Fact("horizon", None, spec.keys.local_config),
                           f"{spec.keys.local_config} is not a JSON object", "render it again")]
    if hp.HORIZON_KEY in doc:
        horizon, where = doc[hp.HORIZON_KEY], f"{hp.HORIZON_KEY} in {spec.keys.local_config}"
    else:
        horizon, where = (horizon_default or (lambda: hp.horizon_default(hp.hop_checkout())))()
    want = rh.Fact("horizon", horizon, where)
    if not isinstance(horizon, int) or isinstance(horizon, bool):
        return [rh.unknown(claim, want, where, "make the hop checkout readable at its pin")]
    return [rh.check(claim, want, window, f"{remedy} (the window read: {window} days, {why})",
                     ok=lambda e, a: a < e)]


def secret_checks(spec: Spec, *, lstat: Callable, digest: Callable[[str], Any], overlay: Optional[Path] = None,
                  secrets: Optional[Dict[str, Any]] = None, exposure: Optional[Dict[str, Any]] = None,
                  secret_lock: Optional[Callable[[Any], Any]] = None) -> List[rh.Check]:
    """The secret's own checks (§7b) and the exposure sweep over every
    container (§7d), both under the one-shots' lock, taken once. Shared by
    `checks` and `start_checks`, so neither calls the other."""
    with (secret_lock or ss.Lock)(spec.secrets) as busy:
        if isinstance(busy, rh.Unresolved):
            return [rh.unknown("the secret's checks ran under the one-shots' lock",
                               rh.Fact("lock", True, "no one-shot may start while verify looks"),
                               busy.reason, "run verify again when the lock is free")]
        return (ss.checks(spec.secrets, lstat=lstat, digest=digest, held=True,
                          overlay=None if overlay is None else str(overlay), **(secrets or {}))
                + se.checks(spec, spec.secrets, lock=contextlib.nullcontext, **(exposure or {})))


def start_gate(spec: Spec, **probes: Any) -> Any:
    """True when every start check passes now, False when one fails, an
    Unresolved when none fails but one cannot be decided."""
    if spec.hub is None:
        return False
    results = [c.result for c in start_checks(spec, **probes)]
    if rh.FAIL in results:
        return False
    if rh.UNKNOWN in results:
        return rh.Unresolved("a start check is UNKNOWN; run hub-start-check")
    return True


def print_notes(spec: Spec, out=print) -> None:
    """What the operator confirms by reading, never a pass or fail."""
    if spec.secrets is not None:
        for line in se.notes(spec.secrets):
            out(f"  NOTE    {line}")
    if spec.hub is not None:
        for line in hr.dd.notes(spec.hub.d7_dir, spec.hub.d7_file):
            out(f"  NOTE    {line}")


def report(found: List[rh.Check], out=print) -> int:
    """Print each check; 0 only when there is at least one and all pass. An
    UNKNOWN is a problem like a FAIL, and no checks at all is never a pass."""
    if not found:
        out("  UNKNOWN the host setup configured nothing to check")
        return 1
    for c in found:
        out(f"  {c.result:7} {c.claim}")
        if c.result != rh.PASS:
            out(f"          expected {c.expected.value!r} ({c.expected.provenance})")
            out(f"          {('why: ' + c.reason) if c.reason else 'found: ' + repr(c.actual)}")
            out(f"          fix: {c.remedy}" + (f"; do not {c.do_not}" if c.do_not else ""))
    return 0 if all(c.result == rh.PASS for c in found) else 1


def run(spec_path: Optional[Path], *, production: bool, overlay: Optional[Path] = None,
        out=print, **probes: Any) -> int:
    """The `host-setup` verb: print the plan, then verify the host against it.
    Exit 0 only when every check passes; an UNKNOWN is a problem like a FAIL."""
    try:
        spec = load_spec(read_spec(spec_path, overlay))
    except ValueError as e:     # SpecError included
        out(f"host-setup: {e}")
        return 2
    out("host-setup (1/2): the plan. Nothing here has run; each step is the operator's, as root.")
    hub = hr.render_all(spec, spec.hub, hr.read_source(spec, spec.hub)) if spec.hub is not None else None
    for line in render_plan(spec, STUB_PLUGIN if spec.overlay_pin and
                            spec.overlay_pin["sha256"] == STUB_SHA256 else None, hub):
        out(f"  {line}")
    out("host-setup (2/2): the host against the plan.")
    rc = report(checks(spec, production=production, overlay=None if spec_path is not None else overlay,
                       **probes), out)
    print_notes(spec, out)
    return rc


def a5_expected(spec: Spec, found: List[rh.Check], read_bytes_: Optional[Callable[[str], bytes]] = None) -> Any:
    """A5's one expected non-pass, or None: on a host whose document
    declares launchd supervision, the signing check UNKNOWN with exactly the
    reason an activated router gives under its live token when the adoption
    witness stops at the platform's kind clause (hk.a5_launchd_reason, the
    token's run id read from the host's live config now). Only that whole
    string matches; anything else, or a second such row, is None."""
    if spec.supervision is None or spec.supervision.kind != hv.KINDS[1] or spec.keys is None:
        return None
    try:
        doc = hk.parse_json((read_bytes_ or hk.read_bytes)(spec.keys.local_config))
        token = doc[hk.DELEGATION_KEY]["partition_verified"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if not isinstance(token, str):
        return None
    reason = hk.a5_launchd_reason(token.partition(":")[0])
    rows = [c for c in found if c.claim == hk.SIGNING_CLAIM]
    # A check carries a reason only when it is UNKNOWN, so the whole-string
    # match is also the result's.
    if len(rows) != 1 or rows[0].reason != reason:
        return None
    return rows[0]


def verify_section(overlay: Optional[Path], out=print, a5: bool = False, **probes: Any) -> int:
    """`verify`'s part: when the deployment overlay has a `host_setup`
    section, every check of the host against it, printed; 0 only when all
    pass. No overlay, or one without the section, is not configured: 0. An
    unusable overlay or document is 1. With `a5` (verify --a5, A5 on a
    launchd host), the one row `a5_expected` names is still printed as
    UNKNOWN and is the only non-pass excused; every other check must pass."""
    if overlay is None:
        return 0
    try:
        sec = overlay_section(overlay)
        if sec is None:
            out("  (the deployment overlay has no host_setup section: the host setup is not checked)")
            return 0
        spec = load_spec(sec)
    except ValueError as e:
        out(f"  UNKNOWN host setup: {e}")
        return 1
    found = checks(spec, production=False, overlay=overlay, **probes)
    rc = report(found, out)
    if a5:
        expected = a5_expected(spec, found)
        if expected is None:
            out("  A5: no expected non-pass applies to this host; every check must pass")
        else:
            out(f"  A5: the one expected non-pass is the signing check's UNKNOWN on a launchd host, matched by its "
                f"exact reason (the gated exception for the Mac's VM file share): {expected.reason}")
            others = [c for c in found if c is not expected]
            rc = 0 if others and all(c.result == rh.PASS for c in others) else 1
    print_notes(spec, out)
    return rc


def hub_render(spec_path: Optional[Path], *, apply: bool, overlay: Optional[Path] = None, out=print) -> int:
    """The `hub-render` verb: render the hub-link router's D7 and environment
    files into the operator's run directory (`--apply`), or say what would
    be written. Placing them is the plan's root step."""
    try:
        spec = load_spec(read_spec(spec_path, overlay))
    except ValueError as e:     # SpecError included
        out(f"hub-render: {e}")
        return 2
    if spec.hub is None:
        out("hub-render: the host-setup document has no hub section")
        return 2
    return hr.write_files(spec, spec.hub, hr.render_all(spec, spec.hub, hr.read_source(spec, spec.hub)),
                          apply=apply, out=out)


def hub_keyprobe(spec_path: Optional[Path], *, apply: bool, overlay: Optional[Path] = None, out=print) -> int:
    """The `hub-keyprobe` verb: show, or with `--apply` run, the key-read
    probe, and write its record into the run directory for the plan to place."""
    try:
        spec = load_spec(read_spec(spec_path, overlay))
    except ValueError as e:     # SpecError included
        out(f"hub-keyprobe: {e}")
        return 2
    if spec.keys is None:
        out("hub-keyprobe: the host-setup document has no keys section")
        return 2
    return hk.run_probe(spec, spec.keys, apply=apply, out=out)


def start_checks(spec: Spec, *, lstat: Callable = os.lstat, secrets: Optional[Dict[str, Any]] = None,
                 **probes: Any) -> List[rh.Check]:
    """_start_checks, under the live engine route's trust gate."""
    with _trust_gate(spec, lstat, secrets):
        return _start_checks(spec, lstat=lstat, secrets=secrets, **probes)


def _start_checks(spec: Spec, *, lstat: Callable = os.lstat, digest: Callable[[str], Any] = _sha256,
                 hub: Optional[Dict[str, Any]] = None, keys: Optional[Dict[str, Any]] = None,
                 supervision: Optional[Dict[str, Any]] = None, state: Any = hr.ASK,
                 overlay: Optional[Path] = None, secrets: Optional[Dict[str, Any]] = None,
                 exposure: Optional[Dict[str, Any]] = None,
                 secret_lock: Optional[Callable[[Any], Any]] = None, policy_on: Any = None,
                 partition: Optional[Dict[str, Any]] = None) -> List[rh.Check]:
    """Everything that must hold before the hub-link
    router starts. The secret's state is active; the secret's own checks
    and the exposure sweep over every container (`secret_checks`, §7b and
    §7d); the D7 file and the environment file are placed and current and
    the rendering meets every rule (hub_runtime); the production overlay
    pin; the key probe's CURRENT evidence and the key's placement (hub_keys,
    without the in-container D7 read, which needs the router running); the
    local router's config unsigned, or signing exactly as A1 approved under
    the static matrix, read from `policy_on` (the fleet policy's answer, None
    when not read) and `partition`'s probes (`start_inputs`); and the
    supervision's files and the live-start ancestry check (hub_supervise).
    It never calls `checks`, which calls it back through `start_gate`. A
    crash or boot restart is the supervisor's and is not gated here."""
    out: List[rh.Check] = []
    st = ss.state(spec.secrets) if state is hr.ASK else state
    claim = "the secret's state is active"
    want = rh.Fact("state", ss.STATES[1], "the router starts only after B5 has written and checked the secret")
    remedy = "finish B5 and write the state as the runbook does"
    out.append(rh.unknown(claim, want, st.reason, remedy) if isinstance(st, rh.Unresolved)
               else rh.check(claim, want, st, remedy))
    out += secret_checks(spec, lstat=lstat, digest=digest, overlay=overlay, secrets=secrets,
                         exposure=exposure, secret_lock=secret_lock)
    out += hr.checks(spec, spec.hub, lstat=lstat, state=st, **(hub or {}))
    out += verify_overlay(spec, production=True, lstat=lstat, digest=digest)
    if spec.keys is None:
        out.append(rh.unknown("the key probe's evidence is current", rh.Fact("keys", True, "the router starts only on current key-probe evidence"),
                              "the document has no keys section", "add the keys section and run the key probe"))
    else:
        k = keys or {}
        out += hk.verify_placement(spec.keys, lstat)
        live = k.get("live", hk.ASK)
        if live is hk.ASK:
            live = hk.ask_live_config(spec, hk.local_container(spec, spec.keys))
        out += hk.verify_start_delegation(spec.keys, live, k.get("read_bytes_", hk.read_bytes),
                                          start_inputs(spec, policy_on, partition or {}), router=spec.router)
        out += hk.verify_evidence_dir(spec.keys, lstat)
        out += hk.verify_evidence_binds(spec.keys, hk.ask_containers(spec) if k.get("containers", hr.ASK)
                                        is hr.ASK else k["containers"])
        out += hk.verify_evidence(spec, spec.keys, lstat, k.get("read_json_", hk.read_json))
    out += verify_recovery_horizon(spec, (keys or {}).get("read_json_", hk.read_json),
                                   (keys or {}).get("horizon_default"))
    out += hv.checks(spec, lstat=lstat, **(supervision or {}))
    return out


def hub_supervise(spec_path: Optional[Path], *, apply: bool, overlay: Optional[Path] = None, out=print) -> int:
    """The `hub-supervise` verb: render the supervision files into the run
    directory (`--apply`), or say what would be written. Placing them is the
    plan's root step; enabling them is the gated start step."""
    try:
        spec = load_spec(read_spec(spec_path, overlay))
    except ValueError as e:     # SpecError included
        out(f"hub-supervise: {e}")
        return 2
    if spec.supervision is None:
        out("hub-supervise: the host-setup document has no supervision section")
        return 2
    return hv.write_files(spec, apply=apply, out=out)


def hub_start_check(spec_path: Optional[Path], *, overlay: Optional[Path] = None, out=print,
                    **probes: Any) -> int:
    """The `hub-start-check` verb: every start check, printed; on a pass, and
    only then, the start step for the operator to run."""
    try:
        spec = load_spec(read_spec(spec_path, overlay))
    except ValueError as e:     # SpecError included
        out(f"hub-start-check: {e}")
        return 2
    if spec.supervision is None or spec.hub is None:
        out("hub-start-check: the host-setup document has no hub and supervision sections")
        return 2
    # The document's provenance, as `run` gives it: a --spec document is never
    # checked as though it were read from the anchored overlay.
    rc = report(start_checks(spec, overlay=None if spec_path is not None else overlay, **probes), out)
    if rc != 0:
        out("hub-start-check: REFUSED. The hub-link router may not start; nothing to run.")
        return rc
    out("hub-start-check: every check passed. `host-setup` (verify) must ALSO pass for this host before "
        "the start: it checks the whole host, which this does not. The start step, as root:")
    for line in hv.start_commands(spec):
        out(f"  {line}")
    return 0
