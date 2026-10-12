"""Who else could reach a runtime's secret: every container on every engine
this host runs, checked against the secret's volume and the paths that guard
it. Read-only: `docker inspect`, `lstat`, and each tool's own listing.

Every container, running or stopped, on every engine (each `docker context`
endpoint, plus any engine socket the section lists that is no context) is
held to five rules, each a FAIL-STOP:

0. **Direct mounts.** A mount of the secret's volume is allowed only in the
   runtime's own container, read-only, at its container directory. The
   checks run under the one-shots' lock, so a one-shot container seen at all
   is a crash (exited) or an anomaly (running while the lock is held).
1. **Overlap.** A bind's source is compared with every protected path by
   identity, (st_dev, st_ino) up each one's ancestor chain, so a macOS
   firmlink, a case variant, `/var` against `/private/var` or a symlink all
   match. Against a SECRET root (the volume's backing path, an engine
   socket's directory, ssh's, a core directory) any overlap is a FAIL, in
   either direction. Against an INTEGRITY root (the writer, the clones,
   the tools, the anchor) a writable overlap or any bind of a strict
   ancestor is a FAIL; reading code is not reading the secret. A source that
   cannot be stat'ed is compared by its normalised text and is UNKNOWN at
   best, never PASS.
2. **Privileges, by allowlist.** Not privileged; every added capability
   allowed by the section, with its reason, and none of the hard-denied ones
   that reach another process's memory or files; no host or shared pid,
   ipc or user namespace; no devices or device rules; no unconfined
   seccomp, apparmor or labels; no host cgroup namespace; no volumes taken
   from the runtime's container.
3. **Routes to an engine.** No engine socket bound, and no DOCKER_HOST or
   SSH_AUTH_SOCK in the environment: either reaches the volume through an
   engine.
4. **Engines and machines.** Every engine socket listed answers; an OrbStack
   machine (it sees the whole Mac filesystem) is a FAIL.
"""

import fcntl
import json
import os
import posixpath
import stat
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import router_health as rh
import secret_setup as ss

#: Capabilities no allowlist can admit: each reaches another process's memory
#: or the host's files, and so the volume's backing store.
HARD_DENY = frozenset({"ALL", "SYS_ADMIN", "SYS_PTRACE", "DAC_READ_SEARCH", "SYS_MODULE",
                       "SYS_RAWIO", "BPF", "PERFMON", "SYS_BOOT", "MAC_ADMIN", "MAC_OVERRIDE"})
#: Namespace modes that share the host's or another container's.
SHARED_PREFIXES = ("host", "container:")
UNCONFINED = ("seccomp=unconfined", "seccomp:unconfined", "apparmor=unconfined", "apparmor:unconfined",
              "label=disable", "label:disable")
ROUTE_ENV = ("DOCKER_HOST", "SSH_AUTH_SOCK")
ONESHOT_LABEL = "org.amap.oneshot"
LOCK_WAIT_S = 60
LOCK_POLL_S = 0.25


def _fact(name: str, value: Any, provenance: str) -> rh.Fact:
    return rh.Fact(name, value, provenance)


# --- Identity -------------------------------------------------------------------


def chain(path: str, stat_: Callable) -> Any:
    """The (st_dev, st_ino) of `path` and of every ancestor, following links
    the way the kernel does, or None when some component does not exist, or
    an Unresolved when one cannot be asked."""
    out, p = [], path
    while True:
        try:
            st = stat_(p)
        except FileNotFoundError:
            return None
        except OSError as e:
            return rh.Unresolved(f"cannot stat {p}: {e}")
        out.append((st.st_dev, st.st_ino))
        if p == "/":
            return out
        p = posixpath.dirname(p)


def _text(path: str) -> Tuple[str, ...]:
    """The fallback comparison: lower-cased, macOS's data-volume and /private
    prefixes removed, as path components."""
    p = path.lower()
    for prefix in ("/system/volumes/data", "/private"):
        if p == prefix or p.startswith(prefix + "/"):
            p = p[len(prefix):] or "/"
    return tuple(c for c in p.split("/") if c)


class Unsure(rh.Unresolved):
    """An overlap decided by name alone, because a side could not be stat'ed:
    the relation found that way, which is never a PASS."""
    __slots__ = ("relation",)

    def __init__(self, reason: str, relation: Optional[str]):
        super().__init__(reason)
        self.relation = relation


def overlap(source: str, protected: str, stat_: Callable) -> Any:
    """How `source` relates to `protected`: "equal", "ancestor" (source above
    it), "descendant" (source below it), None, or an Unresolved carrying the
    relation found by text alone when either side could not be stat'ed."""
    a, b = chain(source, stat_), chain(protected, stat_)
    if isinstance(a, list) and isinstance(b, list):
        if a[0] == b[0]:
            return "equal"
        if a[0] in b[1:]:
            return "ancestor"
        if b[0] in a[1:]:
            return "descendant"
        return None
    ta, tb = _text(source), _text(protected)
    rel = ("equal" if ta == tb else "ancestor" if tb[:len(ta)] == ta else
           "descendant" if ta[:len(tb)] == tb else None)
    why = getattr(a, "reason", None) or getattr(b, "reason", None) or \
        f"{source if a is None else protected} does not exist here, so it was compared by name"
    return Unsure(why, rel)


# --- Asking the engines ---------------------------------------------------------


def _docker(s: ss.SecretSpec, context: Optional[str], *args: str) -> Any:
    argv = ss.docker(s) + (["--context", context] if context else []) + list(args)
    try:
        p = rh.run(argv)
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    if p.rc != 0:
        return rh.Unresolved(f"{' '.join(args[:2])} on {context or 'the default engine'} exited "
                             f"{p.rc}: {p.err.strip()[:160]}")
    return p.out


def contexts(s: ss.SecretSpec) -> Any:
    """[(name, endpoint)] of every docker context, or an Unresolved."""
    out = _docker(s, None, "context", "ls", "--format", "{{json .}}")
    if isinstance(out, rh.Unresolved):
        return out
    found = []
    for line in out.splitlines():
        if not line.strip():
            continue
        try:
            c = json.loads(line)
            found.append((c["Name"], c.get("DockerEndpoint", "")))
        except (ValueError, KeyError, TypeError):
            return rh.Unresolved("`docker context ls` printed a line that is not a context")
    return found


def containers(s: ss.SecretSpec, context: str) -> Any:
    """`docker inspect` of every container on the context's engine, running
    or stopped, or an Unresolved."""
    ids = _docker(s, context, "ps", "--all", "--quiet", "--no-trunc")
    if isinstance(ids, rh.Unresolved):
        return ids
    ids = ids.split()
    if not ids:
        return []
    out = _docker(s, context, "inspect", *ids)
    if isinstance(out, rh.Unresolved):
        return out
    try:
        doc = json.loads(out)
    except ValueError:
        return rh.Unresolved("`docker inspect` printed something other than JSON")
    return doc if isinstance(doc, list) else rh.Unresolved("`docker inspect` did not print a list")


def image_id(s: ss.SecretSpec, context: str) -> Any:
    out = _docker(s, context, "image", "inspect", "--format", "{{.Id}}", s.image)
    return out if isinstance(out, rh.Unresolved) else out.strip()


def volume_mountpoint(s: ss.SecretSpec, context: str) -> Any:
    out = _docker(s, context, "volume", "inspect", "--format", "{{.Mountpoint}}", s.volume)
    return out if isinstance(out, rh.Unresolved) else out.strip()


# --- The rules ------------------------------------------------------------------


def _name(c: Dict[str, Any]) -> str:
    return str(c.get("Name", "")).lstrip("/") or str(c.get("Id", ""))[:12]


def _host(c: Dict[str, Any]) -> Dict[str, Any]:
    h = c.get("HostConfig")
    return h if isinstance(h, dict) else {}


def _list(v: Any) -> List[Any]:
    return v if isinstance(v, list) else []


def runtime_container(spec: Any, s: ss.SecretSpec) -> str:
    principal = next(name for name, p in spec.principals.items() if p.uid == s.uid)
    return spec.runtime_of(principal)["container"]


def rule_mounts(c: Dict[str, Any], s: ss.SecretSpec, runtime: str) -> List[str]:
    """Why this container's mounts of the volume break rule 0: [] if none."""
    bad = []
    for m in _list(c.get("Mounts")):
        if not isinstance(m, dict) or m.get("Type") != "volume" or m.get("Name") != s.volume:
            continue
        labels = (c.get("Config") or {}).get("Labels") or {}
        if ONESHOT_LABEL in labels:
            running = bool((c.get("State") or {}).get("Running"))
            bad.append(f"a one-shot ({labels[ONESHOT_LABEL]}) "
                       + ("running while verify holds the lock" if running else "left behind by a crash"))
        elif _name(c) != runtime:
            bad.append(f"mounts the secret volume at {m.get('Destination')}")
        elif m.get("RW") or m.get("Destination") != s.container_dir:
            bad.append(f"mounts the secret volume {'read-write' if m.get('RW') else 'read-only'} at "
                       f"{m.get('Destination')}, not read-only at {s.container_dir}")
    return bad


def rule_privileges(c: Dict[str, Any], s: ss.SecretSpec, runtime: str) -> List[str]:
    h = _host(c)
    bad = []
    if h.get("Privileged"):
        bad.append("is privileged")
    caps = {str(x).upper().replace("CAP_", "") for x in _list(h.get("CapAdd"))}
    if _name(c) == runtime and caps:
        bad.append(f"adds capabilities {sorted(caps)}; the runtime adds none")
    for cap in sorted(caps):
        if cap in HARD_DENY:
            bad.append(f"adds {cap}, which no allowlist admits")
        elif cap not in s.extra["caps_allow"]:
            bad.append(f"adds {cap}, which the section does not allow")
    for key in ("PidMode", "IpcMode", "UsernsMode", "CgroupnsMode"):
        v = str(h.get(key) or "")
        if v.startswith(SHARED_PREFIXES):
            bad.append(f"shares a namespace ({key}={v})")
    if _list(h.get("Devices")) or _list(h.get("DeviceCgroupRules")):
        bad.append("has devices")
    opts = [str(x).replace(" ", "") for x in _list(h.get("SecurityOpt"))]
    if any(o in UNCONFINED for o in opts):
        bad.append("runs unconfined")
    if any(str(v).split(":")[0] == runtime for v in _list(h.get("VolumesFrom"))):
        bad.append(f"takes volumes from {runtime}")
    if _name(c) == runtime and "no-new-privileges" not in [o.split("=")[0].split(":")[0] for o in opts]:
        bad.append("may gain privileges; the runtime runs with no-new-privileges")
    return bad


def rule_routes(c: Dict[str, Any], s: ss.SecretSpec, lstat_: Callable) -> List[str]:
    bad = []
    for e in _list((c.get("Config") or {}).get("Env")):
        key = str(e).split("=", 1)[0]
        if key in ROUTE_ENV:
            bad.append(f"has {key} in its environment")
    for m in _list(c.get("Mounts")):
        if not isinstance(m, dict) or m.get("Type") != "bind":
            continue
        src = str(m.get("Source", ""))
        try:
            st = lstat_(src)
            if stat.S_ISSOCK(st.st_mode):
                bad.append(f"binds the socket {src}")
        except OSError:
            pass
        if src in s.extra["exposure"]["engine_sockets"]:
            bad.append(f"binds the engine socket {src}")
    return bad


def rule_overlap(c: Dict[str, Any], secret_roots: Sequence[str], integrity_roots: Sequence[str],
                 stat_: Callable) -> Tuple[List[str], List[str]]:
    """(failures, unknowns) for this container's binds."""
    bad, unk = [], []
    for m in _list(c.get("Mounts")):
        if not isinstance(m, dict) or m.get("Type") != "bind":
            continue
        src, rw = str(m.get("Source", "")), bool(m.get("RW"))
        for root in secret_roots:
            rel = overlap(src, root, stat_)
            if isinstance(rel, rh.Unresolved):
                if rel.relation:
                    unk.append(f"binds {src}, which may be the {rel.relation} of the secret path {root}: "
                               f"{rel.reason}")
            elif rel:
                bad.append(f"binds {src}, the {rel} of the secret path {root}")
        for root in integrity_roots:
            rel = overlap(src, root, stat_)
            relation = rel.relation if isinstance(rel, rh.Unresolved) else rel
            if relation == "ancestor" or (relation and rw):
                line = f"binds {src}{' read-write' if rw else ''}, the {relation} of {root}"
                (unk if isinstance(rel, rh.Unresolved) else bad).append(line)
    return bad, unk


def protected_roots(s: ss.SecretSpec, mountpoints: Iterable[str],
                    realpath: Callable[[str], str] = os.path.realpath) -> Tuple[List[str], List[str]]:
    secret = list(dict.fromkeys(list(mountpoints) + list(s.extra["exposure"]["secret_roots"])
                                + [posixpath.dirname(p) for p in s.extra["exposure"]["engine_sockets"]]))
    integrity = [s.writer_dir, posixpath.dirname(s.anchor), posixpath.dirname(s.state_file),
                 s.run_dir, s.status_dir, s.uv["cache_dir"], s.uv["python_dir"], s.uv["binary"],
                 s.ssh["config"], s.ssh["known_hosts"]]
    integrity += [c["path"] for c in s.clones.values()]
    integrity += [realpath(p) for p in s.tools.values()]
    integrity += list(s.extra["exposure"]["integrity_roots"])
    return secret, list(dict.fromkeys(integrity))


# --- The checks -----------------------------------------------------------------


class _Lock:
    """The one-shots' lock, held by verify for the whole sweep: nothing can
    start a one-shot meanwhile, so any one-shot seen is a crash or an
    anomaly."""

    def __init__(self, path: str, wait_s: float):
        self.path, self.wait_s, self.fd = path, wait_s, None

    def __enter__(self) -> Any:
        try:
            self.fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        except OSError as e:
            return rh.Unresolved(f"cannot open the lock {self.path}: {e}")
        deadline = time.monotonic() + self.wait_s
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return None
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    return rh.Unresolved(f"{self.path} stayed held for {self.wait_s:.0f}s")
                time.sleep(LOCK_POLL_S)

    def __exit__(self, *exc: Any) -> None:
        if self.fd is not None:
            os.close(self.fd)


def _rule_check(claim: str, why: str, remedy: str, bad: List[str], unk: List[str],
                do_not: str = "") -> rh.Check:
    want = _fact("findings", [], why)
    if bad:
        return rh.check(claim, want, bad, remedy, do_not=do_not)
    if unk:
        return rh.unknown(claim, want, "; ".join(unk), remedy, do_not=do_not)
    return rh.check(claim, want, [], remedy, do_not=do_not)


def checks(spec: Any, s: ss.SecretSpec, *, lstat_: Callable = os.lstat, stat_: Callable = os.stat,
           realpath: Callable[[str], str] = os.path.realpath,
           lock: Optional[Callable[[], Any]] = None) -> List[rh.Check]:
    """Every exposure check, under the one-shots' lock."""
    runtime = runtime_container(spec, s)
    held = lock() if lock is not None else _Lock(posixpath.join(s.run_dir, ss.LOCK_FILE), LOCK_WAIT_S)
    with held as busy:
        if isinstance(busy, rh.Unresolved):
            return [rh.unknown("no container can reach the secret", _fact("findings", [], "the sweep needs "
                               "the one-shots' lock"), busy.reason, "run verify again when the lock is free")]
        return _sweep(spec, s, runtime, lstat_, stat_, realpath)


def _sweep(spec: Any, s: ss.SecretSpec, runtime: str, lstat_: Callable, stat_: Callable,
           realpath: Callable[[str], str]) -> List[rh.Check]:
    out: List[rh.Check] = []
    ctx = contexts(s)
    claim = "every engine on this host can be asked"
    if isinstance(ctx, rh.Unresolved):
        return [rh.unknown(claim, _fact("engines", True, "each engine's containers are checked"), ctx.reason,
                           "start every engine, or remove the one that is not used")]
    unk_engines = []
    endpoints = {ep for _, ep in ctx}
    for sock in s.extra["exposure"]["engine_sockets"]:
        try:
            st = lstat_(sock)
        except FileNotFoundError:
            continue
        except OSError as e:
            unk_engines.append(f"{sock}: {e}")
            continue
        if stat.S_ISSOCK(st.st_mode) and f"unix://{sock}" not in endpoints:
            unk_engines.append(f"{sock} is an engine socket that no docker context names")
    by_engine, mountpoints = {}, []
    for name, _ in ctx:
        found = containers(s, name)
        if isinstance(found, rh.Unresolved):
            unk_engines.append(f"{name}: {found.reason}")
            continue
        by_engine[name] = found
        mp = volume_mountpoint(s, name)
        if isinstance(mp, str) and mp:
            mountpoints.append(mp)
    want = _fact("engines", [], "a container on an engine nobody asked could hold the volume")
    out.append(rh.unknown(claim, want, "; ".join(unk_engines), "start the engine, or give it a context")
               if unk_engines else rh.check(claim, want, [], "nothing"))
    secret_roots, integrity_roots = protected_roots(s, mountpoints, realpath)
    found: Dict[str, Tuple[List[str], List[str]]] = {k: ([], []) for k in ("mounts", "overlap", "privileges",
                                                                          "routes")}
    for engine, cs in sorted(by_engine.items()):
        for c in cs:
            if not isinstance(c, dict):
                continue
            who = f"{engine}/{_name(c)}"
            found["mounts"][0].extend(f"{who} {x}" for x in rule_mounts(c, s, runtime))
            b, u = rule_overlap(c, secret_roots, integrity_roots, stat_)
            found["overlap"][0].extend(f"{who} {x}" for x in b)
            found["overlap"][1].extend(f"{who} {x}" for x in u)
            found["privileges"][0].extend(f"{who} {x}" for x in rule_privileges(c, s, runtime))
            found["routes"][0].extend(f"{who} {x}" for x in rule_routes(c, s, lstat_))
    out.append(_rule_check(f"only {runtime} mounts the volume {s.volume}, read-only at {s.container_dir}",
                           "the volume is the secret; a one-shot is never seen while verify holds the lock",
                           "remove the container (a crashed one-shot: `docker rm` it after checking it is "
                           "not mid-write)", *found["mounts"], do_not="never copy the value out of it"))
    out.append(_rule_check("no container binds a path that overlaps the secret or the code that handles it",
                           "a bind of the volume's backing path, an engine or ssh directory, or a core "
                           "directory reaches the secret; a writable bind of the tooling changes it",
                           "remove the bind, or narrow it to a path outside every protected one", *found["overlap"]))
    out.append(_rule_check("no container holds a privilege that reaches another process or the host's files",
                           "privileged, a hard-denied capability, a shared namespace or a device reaches "
                           "the volume's backing store or the runtime's memory",
                           "drop the privilege, or record an allowed capability with its reason",
                           *found["privileges"], do_not="never allowlist a hard-denied capability"))
    out.append(_rule_check("no container can reach an engine", "an engine socket, DOCKER_HOST or an ssh agent "
                           "is root on the host for whoever holds it", "remove the socket bind or the variable",
                           *found["routes"]))
    if "orb" in s.tools:
        claim = "no OrbStack machine runs on this host"
        want = _fact("machines", [], "a machine sees the whole Mac filesystem, OrbStack's volume view included")
        try:
            p = rh.run([s.tools["orb"], "list", "--quiet"])
            if p.rc != 0:
                out.append(rh.unknown(claim, want, f"orb list exited {p.rc}", "ask OrbStack"))
            else:
                out.append(rh.check(claim, want, p.out.split(), "stop and delete the machine"))
        except rh.CannotRun as e:
            out.append(rh.unknown(claim, want, str(e), "ask OrbStack"))
    return out


def notes(s: ss.SecretSpec) -> List[str]:
    """What verify prints for the operator to confirm, not a pass or fail:
    the attestations and the keys that admit a docker-capable account."""
    out = []
    att = s.extra["attestations"]
    for key in ("native_agents", "other_runtimes"):
        out.append(f"attested {key}: {att.get(key, 'NOT RECORDED')}")
    for keys in s.extra["exposure"]["authorized_keys"]:
        try:
            p = rh.run([s.tools["ssh-keygen"], "-l", "-f", keys])
            out.append(f"{keys}: " + ("; ".join(line.strip() for line in p.out.splitlines() if line.strip())
                                      if p.rc == 0 else f"ssh-keygen -l exited {p.rc}"))
        except rh.CannotRun as e:
            out.append(f"{keys}: {e}")
    return out
