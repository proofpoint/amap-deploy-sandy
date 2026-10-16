"""Who else could reach a runtime's secret: every container on every engine
this host runs, checked against the secret's volume and the paths that guard
it. Read-only: `docker inspect`, `lstat`, and each tool's own listing.

Every container, running or stopped, on every engine of THIS host (each
`docker context` with a unix:// endpoint; a listed engine socket that no
context names is UNKNOWN) is held to five rules, each a FAIL-STOP. A remote
context (ssh://, tcp://) is guarded by its own host's lock and swept by that
host's verify; it is named in the notes.

0. **Direct mounts.** A mount of the secret's volume is allowed only in the
   runtime's own container, on the engine that holds the volume, and only as
   it is rendered: the pinned image's resolved ID, its user, one read-only
   mount at its directory, every capability dropped and none added, no new
   privileges. The checks run under the one-shots' lock, so a one-shot
   container seen at all is a crash (exited) or an anomaly (running).
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

import json
import os
import posixpath
import stat
import sys
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import router_health as rh
import secret_setup as ss

HARD_DENY = ss.HARD_DENY
#: Namespace modes that share the host's or another container's.
SHARED_PREFIXES = ("host", "container:")
UNCONFINED = ("seccomp=unconfined", "seccomp:unconfined", "apparmor=unconfined", "apparmor:unconfined",
              "label=disable", "label:disable")
ROUTE_ENV = ("DOCKER_HOST", "SSH_AUTH_SOCK")
ONESHOT_LABEL = "org.amap.oneshot"


def _fact(name: str, value: Any, provenance: str) -> rh.Fact:
    return rh.Fact(name, value, provenance)


# --- Identity -------------------------------------------------------------------


def chain(path: str, stat_: Callable) -> Any:
    """The (st_dev, st_ino) of `path` and of each of its TEXTUAL ancestors,
    or None when some component does not exist, or an Unresolved."""
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


def identity(path: str, stat_: Callable, realpath: Callable[[str], str]) -> Any:
    """(identity, ancestors) of `path` as the kernel walks it: its own
    identity, and the union of the RESOLVED path's ancestors and the literal
    path's (a symlinked source names its target's place, not its own). None
    when it does not exist, or an Unresolved."""
    resolved = ss.identity_chain(path, stat_, realpath)
    if not isinstance(resolved, list):
        return resolved
    literal = chain(path, stat_)
    ancestors = set(resolved[1:]) | (set(literal[1:]) if isinstance(literal, list) else set())
    return resolved[0], ancestors


def _text(path: str) -> Tuple[str, ...]:
    """The fallback comparison: lower-cased, macOS's data-volume and /private
    prefixes removed, as path components."""
    p = path.lower()
    for prefix in ("/system/volumes/data", "/private"):
        if p == prefix or p.startswith(prefix + "/"):
            p = p[len(prefix):] or "/"
    return tuple(c for c in p.split("/") if c)


def _text_relation(a: Tuple[str, ...], b: Tuple[str, ...]) -> Optional[str]:
    return ("equal" if a == b else "ancestor" if b[:len(a)] == a else
            "descendant" if a[:len(b)] == b else None)


class Unsure(rh.Unresolved):
    """An overlap decided by name alone, because a side could not be stat'ed:
    the relation found that way, which is never a PASS."""
    __slots__ = ("relation",)

    def __init__(self, reason: str, relation: Optional[str]):
        super().__init__(reason)
        self.relation = relation


def overlap(source: str, protected: str, stat_: Callable,
            realpath: Callable[[str], str] = os.path.realpath) -> Any:
    """How `source` relates to `protected`: "equal", "ancestor" (source above
    it), "descendant" (source below it), None, or an Unsure carrying the
    relation found by name when either side could not be stat'ed (the
    source's literal and resolved names both count)."""
    a, b = identity(source, stat_, realpath), identity(protected, stat_, realpath)
    if isinstance(a, tuple) and isinstance(b, tuple):
        if a[0] == b[0]:
            return "equal"
        if a[0] in b[1]:
            return "ancestor"
        if b[0] in a[1]:
            return "descendant"
        return None
    tb = _text(protected)
    rel = _text_relation(_text(source), tb) or _text_relation(_text(realpath(source)), tb)
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
    """The ID the pinned image resolves to on that engine, or an Unresolved."""
    out = _docker(s, context, "image", "inspect", "--format", "{{.Id}}", s.image)
    return out if isinstance(out, rh.Unresolved) else out.strip()


def volume_mountpoint(s: ss.SecretSpec, context: str) -> Any:
    """The volume's backing path on that engine: a path, None when the engine
    proves it has no such volume (a listing that succeeds and holds none), or
    an Unresolved when the engine could not be asked."""
    names = _docker(s, context, "volume", "ls", "--quiet", "--filter", f"name=^{s.volume}$")
    if isinstance(names, rh.Unresolved):
        return names
    if s.volume not in names.split():
        return None
    out = _docker(s, context, "volume", "inspect", "--format", "{{.Mountpoint}}", s.volume)
    if isinstance(out, rh.Unresolved):
        return out
    return out.strip() or rh.Unresolved(f"the engine {context} names no mountpoint for {s.volume}")


# --- The rules ------------------------------------------------------------------


def _name(c: Dict[str, Any]) -> str:
    return str(c.get("Name", "")).lstrip("/") or str(c.get("Id", ""))[:12]


def _host(c: Dict[str, Any]) -> Dict[str, Any]:
    h = c.get("HostConfig")
    return h if isinstance(h, dict) else {}


def _list(v: Any) -> List[Any]:
    return v if isinstance(v, list) else []


def runtime_container(spec: Any, s: ss.SecretSpec) -> str:
    """The container of the principal the section declares."""
    return spec.runtime_of(s.principal)["container"]


def _no_new_privileges(opts: Sequence[str]) -> bool:
    return any(o in ("no-new-privileges", "no-new-privileges=true", "no-new-privileges:true") for o in opts)


def rule_mounts(c: Dict[str, Any], s: ss.SecretSpec, runtime: str, engine: str, home: Optional[str],
                runtime_image: Any, unsure: Sequence[str] = ()) -> Tuple[List[str], List[str]]:
    """(failures, unknowns) of this container against rule 0. The runtime is
    exempt only on the engine that holds the volume, and only as it is
    rendered: the pinned image's resolved ID, its user, one read-only mount
    at its directory, every capability dropped, none added, no new
    privileges."""
    bad: List[str] = []
    unk: List[str] = []
    mounts = [m for m in _list(c.get("Mounts")) if isinstance(m, dict)
              and m.get("Type") == "volume" and m.get("Name") == s.volume]
    if not mounts:
        return bad, unk
    labels = (c.get("Config") or {}).get("Labels") or {}
    if ONESHOT_LABEL in labels:
        running = bool((c.get("State") or {}).get("Running"))
        bad.append(f"a one-shot ({labels[ONESHOT_LABEL]}) "
                   + ("running while verify holds the lock" if running else "left behind by a crash"))
        return bad, unk
    if _name(c) != runtime:
        bad.append(f"mounts the secret volume at {mounts[0].get('Destination')}")
        return bad, unk
    if engine != home:
        if unsure:
            unk.append(f"has the runtime's name, and which engine holds the volume is unknown "
                       f"({', '.join(unsure)} could not say)")
        else:
            bad.append(f"has the runtime's name on {engine}, which does not hold the volume")
        return bad, unk
    h, cfg = _host(c), c.get("Config") or {}
    if isinstance(runtime_image, rh.Unresolved):
        unk.append(f"its image cannot be compared: {runtime_image.reason}")
    elif c.get("Image") != runtime_image:
        bad.append(f"runs image {c.get('Image')}, not the pinned image's {runtime_image}")
    if cfg.get("User") != f"{s.uid}:{s.gid}":
        bad.append(f"runs as {cfg.get('User')!r}, not {s.uid}:{s.gid}")
    if len(mounts) != 1 or mounts[0].get("RW") or mounts[0].get("Destination") != s.container_dir:
        bad.append(f"mounts the secret volume {len(mounts)} time(s), "
                   f"{'read-write' if any(m.get('RW') for m in mounts) else 'read-only'}, at "
                   f"{', '.join(str(m.get('Destination')) for m in mounts)}; the runtime mounts it once, "
                   f"read-only, at {s.container_dir}")
    if "ALL" not in {str(x).upper() for x in _list(h.get("CapDrop"))}:
        bad.append("does not drop every capability")
    opts = [str(x).replace(" ", "") for x in _list(h.get("SecurityOpt"))]
    if not _no_new_privileges(opts):
        bad.append("may gain privileges; the runtime runs with no-new-privileges")
    return bad, unk


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
    return bad


def rule_routes(c: Dict[str, Any], s: ss.SecretSpec, lstat_: Callable, stat_: Callable) -> List[str]:
    """An engine reachable from the container: a socket bound (judged by
    lstat AND by stat, so a symlink to a socket counts), or DOCKER_HOST or
    SSH_AUTH_SOCK in its environment."""
    bad = []
    for e in _list((c.get("Config") or {}).get("Env")):
        key = str(e).split("=", 1)[0]
        if key in ROUTE_ENV:
            bad.append(f"has {key} in its environment")
    for m in _list(c.get("Mounts")):
        if not isinstance(m, dict) or m.get("Type") != "bind":
            continue
        src = str(m.get("Source", ""))
        for look in (lstat_, stat_):
            try:
                if stat.S_ISSOCK(look(src).st_mode):
                    bad.append(f"binds the socket {src}")
                    break
            except OSError:
                pass
        if src in s.extra["exposure"]["engine_sockets"]:
            bad.append(f"binds the engine socket {src}")
    return bad


def rule_overlap(c: Dict[str, Any], secret_roots: Sequence[str], integrity_roots: Sequence[str],
                 stat_: Callable, realpath: Callable[[str], str] = os.path.realpath
                 ) -> Tuple[List[str], List[str]]:
    """(failures, unknowns) for this container's binds. A source that cannot
    be stat'ed here is UNKNOWN whatever its name suggests."""
    bad, unk = [], []
    for m in _list(c.get("Mounts")):
        if not isinstance(m, dict) or m.get("Type") != "bind":
            continue
        src, rw = str(m.get("Source", "")), bool(m.get("RW"))
        mine = identity(src, stat_, realpath)
        if not isinstance(mine, tuple):
            rels = sorted({str(r.relation) for r in (overlap(src, root, stat_, realpath)
                                                     for root in list(secret_roots) + list(integrity_roots))
                           if isinstance(r, rh.Unresolved) and r.relation})
            why = getattr(mine, "reason", "it does not exist here")
            unk.append(f"binds {src}, which cannot be stat'ed here ({why}; compared by name: "
                       f"{', '.join(rels) or 'no relation'})")
            continue
        for root in secret_roots:
            rel = overlap(src, root, stat_, realpath)
            if isinstance(rel, rh.Unresolved):
                if rel.relation:
                    unk.append(f"binds {src}, which may be the {rel.relation} of the secret path {root}: "
                               f"{rel.reason}")
            elif rel:
                bad.append(f"binds {src}, the {rel} of the secret path {root}")
        for root in integrity_roots:
            rel = overlap(src, root, stat_, realpath)
            relation = rel.relation if isinstance(rel, rh.Unresolved) else rel
            if relation == "ancestor" or (relation and rw):
                line = f"binds {src}{' read-write' if rw else ''}, the {relation} of {root}"
                (unk if isinstance(rel, rh.Unresolved) else bad).append(line)
    return bad, unk


def protected_roots(s: ss.SecretSpec, mountpoints: Iterable[str],
                    realpath: Callable[[str], str] = os.path.realpath,
                    also: Iterable[str] = ()) -> Tuple[List[str], List[str]]:
    """(secret, integrity) roots. Engine sockets are protected as themselves:
    a bind of one, or of a directory above it, fails; their siblings do
    not."""
    secret = list(dict.fromkeys(list(mountpoints) + list(s.extra["exposure"]["secret_roots"])
                                + list(s.extra["exposure"]["engine_sockets"])))
    integrity = [s.writer_dir, posixpath.dirname(s.anchor), posixpath.dirname(s.state_file),
                 s.run_dir, s.status_dir, s.uv["cache_dir"], s.uv["python_dir"], s.uv["binary"],
                 s.ssh["config"], s.ssh["known_hosts"]]
    integrity += [c["path"] for c in s.clones.values()]
    integrity += [realpath(p) for p in s.tools.values()]
    integrity += list(s.extra["exposure"]["integrity_roots"])
    # Further integrity roots from other sections: the D7 source file, where
    # the hub pins one file instead of reading a producer clone.
    integrity += list(also)
    return secret, list(dict.fromkeys(integrity))


# --- The checks -----------------------------------------------------------------


def _rule_check(claim: str, why: str, remedy: str, bad: List[str], unk: List[str],
                do_not: str = "") -> rh.Check:
    want = _fact("findings", [], why)
    if bad:
        return rh.check(claim, want, bad, remedy, do_not=do_not)
    if unk:
        return rh.unknown(claim, want, "; ".join(unk), remedy, do_not=do_not)
    return rh.check(claim, want, [], remedy, do_not=do_not)


def local(endpoint: str) -> bool:
    """An engine on this host. A remote engine (ssh://, tcp://) is guarded by
    its own host's lock and swept by that host's verify."""
    return endpoint.startswith("unix://")


def checks(spec: Any, s: ss.SecretSpec, *, lstat_: Callable = os.lstat, stat_: Callable = os.stat,
           realpath: Callable[[str], str] = os.path.realpath,
           lock: Optional[Callable[[], Any]] = None, platform: str = sys.platform) -> List[rh.Check]:
    """Every exposure check, under the one-shots' lock (verify passes its
    own, already held)."""
    runtime = runtime_container(spec, s)
    held = lock() if lock is not None else ss.Lock(s)
    with held as busy:
        if isinstance(busy, rh.Unresolved):
            return [rh.unknown("no container can reach the secret", _fact("findings", [], "the sweep needs "
                               "the one-shots' lock"), busy.reason, "run verify again when the lock is free")]
        return _sweep(spec, s, runtime, lstat_, stat_, realpath, platform)


def _sweep(spec: Any, s: ss.SecretSpec, runtime: str, lstat_: Callable, stat_: Callable,
           realpath: Callable[[str], str], platform: str) -> List[rh.Check]:
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
    by_engine, mountpoints, holders, unsure = {}, [], [], []
    for name, endpoint in ctx:
        if not local(endpoint):
            continue
        found = containers(s, name)
        if isinstance(found, rh.Unresolved):
            unk_engines.append(f"{name}: {found.reason}")
            continue
        by_engine[name] = found
        mp = volume_mountpoint(s, name)
        if isinstance(mp, rh.Unresolved):
            unk_engines.append(f"{name}: whether it holds {s.volume}: {mp.reason}")
            unsure.append(name)
        elif mp:
            mountpoints.append(mp)
            holders.append(name)
    if len(holders) > 1:
        unk_engines.append(f"{s.volume} exists on more than one engine here: {', '.join(holders)}")
    home = holders[0] if len(holders) == 1 else None
    runtime_image = image_id(s, home) if home is not None else rh.Unresolved("no single engine holds the volume")
    want = _fact("engines", [], "a container on an engine nobody asked could hold the volume")
    out.append(rh.unknown(claim, want, "; ".join(unk_engines), "start the engine, or give it a context")
               if unk_engines else rh.check(claim, want, [], "nothing"))
    hub = getattr(spec, "hub", None)
    d7_file = [hub.d7_source] if hub is not None and hub.d7_source_sha256 is not None else []
    secret_roots, integrity_roots = protected_roots(s, mountpoints, realpath, also=d7_file)
    found: Dict[str, Tuple[List[str], List[str]]] = {k: ([], []) for k in ("mounts", "overlap", "privileges",
                                                                          "routes")}
    for engine, cs in sorted(by_engine.items()):
        for c in cs:
            if not isinstance(c, dict):
                continue
            who = f"{engine}/{_name(c)}"
            b, u = rule_mounts(c, s, runtime, engine, home, runtime_image, unsure)
            found["mounts"][0].extend(f"{who} {x}" for x in b)
            found["mounts"][1].extend(f"{who} {x}" for x in u)
            b, u = rule_overlap(c, secret_roots, integrity_roots, stat_, realpath)
            found["overlap"][0].extend(f"{who} {x}" for x in b)
            found["overlap"][1].extend(f"{who} {x}" for x in u)
            found["privileges"][0].extend(f"{who} {x}" for x in rule_privileges(c, s, runtime))
            found["routes"][0].extend(f"{who} {x}" for x in rule_routes(c, s, lstat_, stat_))
    out.append(_rule_check(f"only {runtime} mounts the volume {s.volume}, read-only at {s.container_dir}, "
                           f"as rendered", "the volume is the secret; a one-shot is never seen while verify "
                           "holds the lock", "remove the container (a crashed one-shot: `docker rm` it after "
                           "checking it is not mid-write)", *found["mounts"], do_not="never copy the value out of it"))
    out.append(_rule_check("no container binds a path that overlaps the secret or the code that handles it",
                           "a bind of the volume's backing path, an engine socket, an ssh directory or a core "
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
    claim = "no OrbStack machine runs on this host"
    want = _fact("machines", [], "a machine sees the whole Mac filesystem, OrbStack's volume view included")
    if "orb" in s.tools:
        try:
            p = rh.run([s.tools["orb"], "list", "--quiet"])
            if p.rc != 0:
                out.append(rh.unknown(claim, want, f"orb list exited {p.rc}", "ask OrbStack"))
            else:
                out.append(rh.check(claim, want, p.out.split(), "stop and delete the machine"))
        except rh.CannotRun as e:
            out.append(rh.unknown(claim, want, str(e), "ask OrbStack"))
    elif platform == "darwin":
        out.append(rh.unknown(claim, want, "tools has no orb to ask", "record orb's path in tools"))
    return out


#: Agent CLIs whose processes on the host, outside every container, the
#: native_agents attestation answers for.
AGENT_CLIS = ("claude", "codex")
SSHD_LINES = ("passwordauthentication", "kbdinteractiveauthentication", "trustedusercakeys",
              "authorizedkeyscommand", "authorizedprincipalsfile")


def notes(s: ss.SecretSpec, ctx: Any = None) -> List[str]:
    """What verify prints for the operator to confirm, not a pass or fail."""
    ctx = contexts(s) if ctx is None else ctx
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
    if "sshd" in s.tools:
        try:
            p = rh.run([s.tools["sshd"], "-T"])
            lines = [line.strip() for line in p.out.splitlines() if line.split(" ", 1)[0] in SSHD_LINES]
            out.append("sshd -T: " + ("; ".join(lines) if p.rc == 0 else f"exited {p.rc} (run it as root)"))
        except rh.CannotRun as e:
            out.append(f"sshd -T: {e}")
    if "ps" in s.tools:
        try:
            p = rh.run([s.tools["ps"], "-axo", "comm="])
            seen = sorted({posixpath.basename(line.strip()) for line in p.out.splitlines()
                           if posixpath.basename(line.strip()) in AGENT_CLIS})
            out.append(f"agent CLIs running on this host outside containers: {seen or 'none'} "
                       f"(sandy runs agents in containers; reconcile with native_agents)")
        except rh.CannotRun as e:
            out.append(f"processes: {e}")
    if "tmutil" in s.tools:
        for path in s.extra["exposure"]["backup_excluded"]:
            try:
                p = rh.run([s.tools["tmutil"], "isexcluded", path])
                out.append(f"tmutil isexcluded {path}: {p.out.strip() or f'exited {p.rc}'}")
            except rh.CannotRun as e:
                out.append(f"tmutil isexcluded {path}: {e}")
    if isinstance(ctx, list):
        remote = [f"{n} ({ep})" for n, ep in ctx if not local(ep)]
        if remote:
            out.append(f"not swept here, each is swept by its own host's verify: {', '.join(remote)}")
    return out
