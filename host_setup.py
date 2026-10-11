"""The host setup a hop deployment needs before its runtimes start: distinct
uids, the hop group, the configured roots with their owners and modes, and
the plugin overlay. Rendered as a plan for the operator; checked by verify.
NOTHING HERE APPLIES ANYTHING: every change is a printed step that the
operator runs as root.

The plan is DATA, not code. A host's setup is a JSON document (`SPEC_SCHEMA`)
that names the principals (one uid per runtime), the groups, the hops (which
principal is upstream of which), every root directory with its owner, group,
mode and the principals that must reach it, and the overlay. This module
knows no runtime's directory names; the document supplies them.

What it renders, in order:
1. one `install -d` per root, parents before children, so each is created with
   its owner, group and mode in one step;
2. a barrier that fsyncs each root and every ancestor, so a root's entry is
   durable before a runtime opens it (a runtime cannot make durable the top
   of a bind-mounted tree from inside it);
3. the overlay file, root-owned and 0444;
4. each runtime's peer-uid variable (named per hop): the uid on the other side of its hop.

What verify checks, through router_health's three outcomes:
- every root exists as a real directory with the planned owner, group and mode;
- every principal that must reach a root can READ and SEARCH every ancestor
  and the root itself: a directory is opened to be fsynced, so an
  execute-only ancestor fails a runtime's write;
- the overlay is a regular file, owned by root, mode 0444, outside every
  agent path, whose bytes hash to its pin;
- a pin equal to the stub plugin's digest is the stub, never production;
- each runtime's declared durable root, seen from a throwaway container with
  the runtime's own mount, is the host directory the plan created and
  synced (same-device ancestry inside a container proves nothing);
- an image's openssl, as the image reports it, is at least the recorded floor
  and is the recorded version.
"""

import hashlib
import json
import os
import posixpath
import re
import shlex
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import router_health as rh

SPEC_SCHEMA = "amap-deploy-sandy.host-setup/1"

HERE = Path(__file__).resolve().parent
STUB_PLUGIN = HERE / "overlay" / "stub-plugin.py"
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
_R, _W, _X = 4, 2, 1


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
    openssl: Dict[str, Dict[str, Any]]          # image -> {version, floor, source}
    mounts: Tuple[Dict[str, str], ...] = ()     # {principal, image, host, container}


def _abs_normal(p: Any, what: str) -> str:
    if not isinstance(p, str) or not p.startswith("/") or posixpath.normpath(p) != p or p.startswith("//"):
        raise SpecError(f"{what} must be an absolute, normalised path")
    return p


def _int(v: Any, what: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        raise SpecError(f"{what} must be a non-negative integer")
    return v


def load_spec(doc: Any) -> Spec:
    """Parse and validate a host-setup document. Refuses rather than guesses:
    an unknown member, a shared uid on a hop, a root uid for a runtime, an
    owner or group nobody declared."""
    if not isinstance(doc, dict) or doc.get("schema") != SPEC_SCHEMA:
        raise SpecError(f"the document is not a {SPEC_SCHEMA} host setup")
    known = {"schema", "principals", "groups", "hops", "roots", "overlay", "agent_paths", "openssl",
             "mounts"}
    if set(doc) - known:
        raise SpecError(f"unknown member(s): {', '.join(sorted(set(doc) - known))}")
    groups = {}
    for g, gid in (doc.get("groups") or {}).items():
        groups[g] = _int(gid, f"groups.{g}")
    principals = {}
    for name, p in (doc.get("principals") or {}).items():
        if not isinstance(p, dict) or set(p) != {"uid", "groups"}:
            raise SpecError(f"principals.{name} must have exactly uid and groups")
        uid = _int(p["uid"], f"principals.{name}.uid")
        if uid == 0:
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
    roots = []
    for i, r in enumerate(doc.get("roots") or []):
        if not isinstance(r, dict) or set(r) != {"path", "owner", "group", "mode", "readers", "purpose"}:
            raise SpecError(f"roots[{i}] must have exactly path, owner, group, mode, readers, purpose")
        path = _abs_normal(r["path"], f"roots[{i}].path")
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
        if not isinstance(rec, dict) or set(rec) != {"version", "floor", "source"}:
            raise SpecError(f"openssl.{image} must have exactly version, floor and source")
        if openssl_version(f"OpenSSL {rec['version']}") is None:
            raise SpecError(f"openssl.{image}.version must be X.Y.Z")
        if not isinstance(rec["floor"], str) or not re.fullmatch(r"\d+\.\d+", rec["floor"]):
            raise SpecError(f"openssl.{image}.floor must be X.Y")
        openssl[image] = {"version": rec["version"], "source": str(rec["source"]),
                          "floor": tuple(int(x) for x in rec["floor"].split("."))}
    root_paths = {r.path for r in roots}
    mounts = []
    for i, m in enumerate(doc.get("mounts") or []):
        if not isinstance(m, dict) or not {"principal", "image", "host", "container"} <= set(m) \
                or set(m) - {"principal", "image", "host", "container", "marker"}:
            raise SpecError(f"mounts[{i}] must have principal, image, host and container, "
                            f"and optionally marker")
        if "marker" in m and (not isinstance(m["marker"], str)
                              or not re.fullmatch(r"[A-Za-z0-9._-]+", m["marker"]) or m["marker"] in (".", "..")):
            raise SpecError(f"mounts[{i}].marker must be one file name inside the root")
        if m["principal"] not in principals:
            raise SpecError(f"mounts[{i}]: principal {m['principal']!r} is not declared")
        if _abs_normal(m["host"], f"mounts[{i}].host") not in root_paths:
            raise SpecError(f"mounts[{i}].host must be one of the roots: a runtime's durable "
                            f"root is a directory this plan creates and syncs")
        _abs_normal(m["container"], f"mounts[{i}].container")
        if not isinstance(m["image"], str) or not m["image"]:
            raise SpecError(f"mounts[{i}].image must name the runtime's image")
        mounts.append({k: m[k] for k in ("principal", "image", "host", "container", "marker") if k in m})
    return Spec(principals, groups, tuple(hops), tuple(roots), ov_path, ov_pin, agent_paths, openssl,
                tuple(mounts))


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


def render_plan(spec: Spec, overlay_source: Optional[Path] = None) -> List[str]:
    """The root-run steps, in order, as shell lines. Printed, never run."""
    q = shlex.quote
    lines = ["# Run as root. Each line is one step; nothing here has run."]
    for r in sorted(spec.roots, key=lambda r: (r.path.count("/"), r.path)):
        p = spec.principals[r.owner]
        lines.append(f"install -d -o {p.uid} -g {spec.groups[r.group]} -m {r.mode:04o} {q(r.path)}"
                     f"  # {r.purpose}")
    sync_dirs = sorted({a for r in spec.roots for a in _ancestors(r.path)} | {r.path for r in spec.roots},
                       key=lambda d: (-d.count("/"), d))
    if sync_dirs:
        lines.append("# The barrier: each root and every ancestor fsynced, deepest first.")
        lines.append("python3 -c 'import os,sys\nfor d in sys.argv[1:]:\n    fd = os.open(d, os.O_RDONLY)\n"
                     "    os.fsync(fd); os.close(fd)' " + " ".join(q(d) for d in sync_dirs))
    if spec.overlay_path is not None and spec.overlay_pin is not None:
        src = q(str(overlay_source)) if overlay_source else "<the pinned plugin artifact>"
        lines.append(f"install -o {OVERLAY_OWNER_UID} -g 0 -m {OVERLAY_MODE:04o} {src} "
                     f"{q(spec.overlay_path)}  # the overlay; sha256 must be {spec.overlay_pin['sha256']}")
    for m in spec.mounts:
        if "marker" in m:
            path = posixpath.join(m["host"], m["marker"])
            lines.append(f"sh -c 'umask 222; head -c 16 /dev/urandom | od -An -tx1 | tr -d \" \\n\" > \"$1\"' "
                         f"sh {q(path)} && chown 0:0 {q(path)} && chmod 0444 {q(path)}"
                         f"  # {m['principal']}'s root marker: random, root-owned, read-only")
    for (name, env), uid in sorted(peer_uids(spec).items()):
        lines.append(f"# {name}'s runtime environment: {env}={uid}")
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


def verify_roots(spec: Spec, lstat: Callable = os.lstat) -> List[rh.Check]:
    checks: List[rh.Check] = []
    for r in spec.roots:
        src = f"the host setup's root for {r.purpose}"
        owner = spec.principals[r.owner]
        st = _lstat(r.path, lstat)
        want = _fact("root", (owner.uid, spec.groups[r.group], r.mode), src)
        claim = f"{r.path} is a directory owned by {owner.uid}:{spec.groups[r.group]}, mode {r.mode:04o}"
        remedy = f"run the plan's `install -d` line for {r.path}, as root"
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
        for name in r.readers:
            p = spec.principals[name]
            blocked: Any = None
            for d in _ancestors(r.path) + [r.path]:
                dst = _lstat(d, lstat)
                if isinstance(dst, rh.Unresolved):
                    blocked = dst
                    break
                if dst is None or not _can(dst, p.uid, p.gids, _R | _X):
                    blocked = d
                    break
            reach = f"{name} (uid {p.uid}) can read and search every directory down to {r.path}"
            want_r = _fact("reach", True, f"{src}: {name} is one of its readers")
            fix = (f"make {blocked} readable AND searchable by uid {p.uid} or one of its groups; "
                   f"a runtime opens each ancestor to fsync it") if isinstance(blocked, str) else \
                  f"inspect {r.path}'s ancestors as uid {p.uid}"
            if isinstance(blocked, rh.Unresolved):
                checks.append(rh.unknown(reach, want_r, blocked.reason, fix))
            else:
                checks.append(rh.check(reach, want_r, blocked is None, fix,
                                       do_not="an execute-only ancestor is not enough"))
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
    remedy = "run the plan's overlay `install` line, as root"
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


def _identity(st) -> Tuple[int, int, int, int]:
    """What a directory is, as both the host and a container can see it:
    inode, owner, group, permission bits. The device number is left out: it
    differs between the host and a container behind a VM's shared
    filesystem even for the same directory."""
    return (st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode))


def ask_mount(image: str, host: str, container: str, marker: Optional[str] = None) -> Any:
    """`(identity, marker content or None)` of `container` as a throwaway
    container of `image` sees it, with `host` bind-mounted there read-only,
    exactly as the runtime declares it. Read-only; nothing is written."""
    try:
        p = rh.run(["docker", "run", "--rm", "--network", "none", "-v", f"{host}:{container}:ro",
                    "--entrypoint", "sh", image, "-c",
                    'stat -c "%i %u %g %a" "$1" && if [ -n "$2" ]; then cat "$1/$2"; fi',
                    "sh", container, marker or ""])
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    if p.rc != 0:
        return rh.Unresolved(f"the probe in {image} exited {p.rc}: {p.err.strip()[:200]}")
    first, _, rest = p.out.partition("\n")
    parts = first.split()
    if len(parts) != 4 or not all(x.isdigit() for x in parts):
        return rh.Unresolved(f"stat in {image} printed {first.strip()[:80]!r}")
    ident = (int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3], 8))
    return ident, (rest.strip() if marker else None)


def _read_marker(path: str) -> Any:
    try:
        with open(path, encoding="ascii") as f:
            return f.read(256).strip() or None
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        return rh.Unresolved(f"cannot read the marker {path}: {e}")


def verify_mounts(spec: Spec, lstat: Callable = os.lstat,
                  ask: Callable[..., Any] = ask_mount,
                  read_marker: Callable[[str], Any] = None) -> List[rh.Check]:
    """Each runtime's declared durable root, as seen inside a container, is
    the host directory this plan created and synced. Same-device ancestry
    inside the container proves nothing about that, so it is compared here,
    from a throwaway container with the runtime's own mount."""
    checks: List[rh.Check] = []
    for m in spec.mounts:
        host_st = _lstat(m["host"], lstat)
        claim = (f"{m['principal']}'s durable root {m['container']} in {m['image']} is the host "
                 f"directory {m['host']}")
        remedy = (f"mount {m['host']} at {m['container']} exactly as declared, and change no "
                  f"mount between this check and activation")
        if host_st is None or isinstance(host_st, rh.Unresolved):
            reason = host_st.reason if host_st is not None else f"{m['host']} does not exist"
            checks.append(rh.unknown(claim, _fact("mount", rh.Unresolved(reason), "the host directory"),
                                     reason, f"create {m['host']} first (the plan's install line)"))
            continue
        marker = m.get("marker")
        host_marker = (read_marker or _read_marker)(posixpath.join(m["host"], marker)) if marker else None
        seen = ask(m["image"], m["host"], m["container"], marker)
        if isinstance(seen, rh.Unresolved):
            checks.append(rh.unknown(claim, _fact("mount", _identity(host_st), "the host directory"),
                                     seen.reason, remedy))
            continue
        ident, seen_marker = seen
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


def ask_openssl(images: Sequence[str]) -> Dict[str, Any]:
    """Each image's own `openssl version`, run in a throwaway container, or
    an Unresolved naming why it could not be asked. Read-only."""
    out: Dict[str, Any] = {}
    for image in images:
        try:
            p = rh.run(["docker", "run", "--rm", "--entrypoint", "openssl", image, "version"])
        except rh.CannotRun as e:
            out[image] = rh.Unresolved(str(e))
            continue
        out[image] = p.out if p.rc == 0 else \
            rh.Unresolved(f"`openssl version` in {image} exited {p.rc}: {p.err.strip()[:200]}")
    return out


def run(spec_path: Path, *, production: bool, lstat: Callable = os.lstat,
        digest: Callable[[str], Any] = _sha256,
        openssl: Optional[Dict[str, Any]] = None,
        mounts: Optional[Callable[..., Any]] = None, out=print) -> int:
    """The `host-setup` verb: print the plan, then verify the host against it.
    Exit 0 only when every check passes; an UNKNOWN is a problem like a FAIL."""
    try:
        spec = load_spec(json.loads(Path(spec_path).read_text(encoding="utf-8")))
    except (OSError, ValueError) as e:
        out(f"host-setup: cannot use {spec_path}: {e}")
        return 2
    out("host-setup (1/2): the plan. Nothing here has run; each step is the operator's, as root.")
    for line in render_plan(spec, STUB_PLUGIN if spec.overlay_pin and
                            spec.overlay_pin["sha256"] == STUB_SHA256 else None):
        out(f"  {line}")
    checks = verify_roots(spec, lstat) + verify_overlay(spec, production=production, lstat=lstat,
                                                        digest=digest)
    checks += verify_mounts(spec, lstat, ask_mount if mounts is None else mounts)
    checks += verify_openssl(spec, openssl if openssl is not None else ask_openssl(sorted(spec.openssl)))
    out("host-setup (2/2): the host against the plan.")
    for c in checks:
        out(f"  {c.result:7} {c.claim}")
        if c.result != rh.PASS:
            out(f"          expected {c.expected.value!r} ({c.expected.provenance})")
            out(f"          {('why: ' + c.reason) if c.reason else 'found: ' + repr(c.actual)}")
            out(f"          fix: {c.remedy}" + (f"; do not {c.do_not}" if c.do_not else ""))
    return 0 if all(c.result == rh.PASS for c in checks) else 1
