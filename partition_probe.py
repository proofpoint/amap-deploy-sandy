"""The partition probes: what each runtime can actually reach, measured from
inside it under its actual mounts and uids. NOTHING HERE CHANGES A RUNTIME:
every probe is a one-shot container from a runtime's own run spec, or a
read-only `docker exec`, and the only file a probe may create is its own
probe name, which a broken partition would let it create and which it then
removes and reports.

The four probes, each with both halves (what is seen, and what did not
happen) and a witness that it could have failed:
- P01, uid: every process of each hop runtime, read from `/proc` AS THE
  RUNTIME'S OWN PRINCIPAL (so the probe's own processes carry the expected
  uid), runs under that principal's uid, and the two ends of a hop do not
  share one. A status the walk cannot read is UNKNOWN, never skipped.
- P02, markers: each marker of the hop tree that is present has its owner
  and mode 0640, and the side that does not own it can neither open it for
  writing nor create a file beside it. The owner's side opening the same
  marker for writing (no truncate, no append, no write) is the witness.
  A frontier or retired marker that is absent is a correct result.
- P03, key read (fail-stop): from the email router's run spec, every path
  that could reach the signing key is ENOENT. Nothing is opened or read.
- P04, peer write (fail-stop): from the email router's run spec, every
  agent's `peer/` and every path reaching one is ENOENT, and no probe name
  appears in any `peer/` afterwards. Each `peer/` is the live lane: the
  source of the agent container's mount, an existing directory, the same
  (device, inode). None of the email router's mount sources is, holds or
  is held by one.

The email router must be running exactly as rendered (hub_runtime.compare
empty) before any probe stands for it: a probe of a spec the running
container does not match measures nothing.
"""

import hashlib
import json
import os
import posixpath
import re
import stat
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import router_health as rh

PROBE_LABEL = "partition-probe"
#: The only name a probe ever creates, and only if a partition is broken.
PROBE_FILE_PREFIX = ".amap-partition-probe-"
MARKER_MODE = 0o640
#: The hop tree's markers: name, directory, and which end writes it, at the
#: hop pin. A marker in `optional` may be absent on a correct host.
MARKERS = (("identity.json", "up", "upstream", False),
           ("versions.json", "up", "upstream", False),
           ("frontier.json", "up", "upstream", True),
           ("retired.json", "up", "upstream", True),
           ("versions.json", "down", "downstream", False))

P01_SCRIPT = (
    "import os\n"
    "for d in sorted(os.listdir('/proc')):\n"
    "    if not d.isdigit(): continue\n"
    "    try:\n"
    "        t = open('/proc/%s/status' % d).read()\n"
    "    except FileNotFoundError: continue\n"
    "    except OSError: print(d, 'UNREADABLE'); continue\n"
    "    u = [l.split()[1:3] for l in t.splitlines() if l.startswith('Uid:')]\n"
    "    print(d, *(u[0] if u else ['UNREADABLE']))\n")
P02_SCRIPT = (
    "import errno,os,stat,sys\n"
    "root, side, probe = sys.argv[1], sys.argv[2], sys.argv[3]\n"
    "names = sys.argv[4:]\n"
    "def cls(e): return errno.errorcode.get(e.errno, 'E%d' % e.errno)\n"
    "for lid in sorted(os.listdir(root)):\n"
    "    if lid.startswith('.'): continue\n"
    "    for gen in sorted(os.listdir(os.path.join(root, lid))):\n"
    "        d = os.path.join(root, lid, gen, side)\n"
    "        if not os.path.isdir(d): continue\n"
    "        for n in names:\n"
    "            p = os.path.join(d, n)\n"
    "            try: st = os.lstat(p)\n"
    "            except OSError as e: print(lid, gen, n, cls(e), '-', '-', '-'); continue\n"
    "            try: os.close(os.open(p, os.O_WRONLY | os.O_NOFOLLOW)); w = 'OPENED'\n"
    "            except OSError as e: w = cls(e)\n"
    "            print(lid, gen, n, 'present', st.st_uid, oct(stat.S_IMODE(st.st_mode)), w)\n"
    "        try:\n"
    "            os.close(os.open(os.path.join(d, probe), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600))\n"
    "            os.unlink(os.path.join(d, probe)); c = 'CREATED'\n"
    "        except OSError as e: c = cls(e)\n"
    "        print(lid, gen, '.', 'create', '-', '-', c)\n")
P03_SCRIPT = (
    "import errno,os,sys\n"
    "for i,p in enumerate(sys.argv[1:]):\n"
    "    try:\n"
    "        os.lstat(p); r='exists'\n"
    "    except OSError as e: r=errno.errorcode.get(e.errno, 'E%d' % e.errno)\n"
    "    print(i, r)\n")
P04_SCRIPT = (
    "import errno,os,sys\n"
    "probe = sys.argv[1]\n"
    "for i,p in enumerate(sys.argv[2:]):\n"
    "    try:\n"
    "        st = os.lstat(p)\n"
    "    except OSError as e:\n"
    "        print(i, errno.errorcode.get(e.errno, 'E%d' % e.errno)); continue\n"
    "    try:\n"
    "        os.close(os.open(os.path.join(p, probe), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600))\n"
    "        os.unlink(os.path.join(p, probe)); r='CREATED'\n"
    "    except OSError as e: r=errno.errorcode.get(e.errno, 'E%d' % e.errno)\n"
    "    print(i, r)\n")
#: The owner's side of P02 and the permitted side of P03: an open that cannot
#: change anything (no create, truncate or append; nothing written or read).
OPEN_WITNESS_SCRIPT = (
    "import errno,os,sys\n"
    "flag = os.O_WRONLY if sys.argv[1] == 'w' else os.O_RDONLY\n"
    "for i,p in enumerate(sys.argv[2:]):\n"
    "    try: os.close(os.open(p, flag | os.O_NOFOLLOW)); r='OPENED'\n"
    "    except OSError as e: r=errno.errorcode.get(e.errno, 'E%d' % e.errno)\n"
    "    print(i, r)\n")
SCRIPTS = {"P01": P01_SCRIPT, "P02": P02_SCRIPT, "P03": P03_SCRIPT, "P04": P04_SCRIPT,
           "witness": OPEN_WITNESS_SCRIPT}
#: The errno classes a refused write may give: the mode, or a read-only mount.
REFUSED = ("EACCES", "EROFS", "EPERM")


def script_sha256() -> Dict[str, str]:
    return {k: hashlib.sha256(v.encode("utf-8")).hexdigest() for k, v in sorted(SCRIPTS.items())}


def probe_file(run_id: str) -> str:
    return PROBE_FILE_PREFIX + run_id


# --- Output parsing ----------------------------------------------------------------


def parse_rows(out: str, n: int) -> Any:
    """[(index, class)] for exactly n arguments, or an Unresolved."""
    rows = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 2 or not parts[0].isdigit():
            return rh.Unresolved("the probe printed something other than its rows")
        rows.append((int(parts[0]), parts[1]))
    if [i for i, _ in rows] != list(range(n)):
        return rh.Unresolved(f"the probe answered {len(rows)} of {n} arguments")
    return rows


def parse_proc(out: str) -> Any:
    """[(pid, real uid, effective uid)], or an Unresolved naming the first
    status that could not be read."""
    rows = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] == "UNREADABLE":
            return rh.Unresolved(f"/proc/{parts[0]}/status could not be read")
        if len(parts) != 3 or not all(p.isdigit() for p in parts):
            return rh.Unresolved("the uid walk printed something other than its rows")
        rows.append((int(parts[0]), int(parts[1]), int(parts[2])))
    if not rows:
        return rh.Unresolved("the uid walk saw no process")
    return rows


def parse_markers(out: str) -> Any:
    """[(lid, gen, name, kind, uid, mode, write class)], or an Unresolved."""
    rows = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 7:
            return rh.Unresolved("the marker probe printed something other than its rows")
        rows.append(tuple(parts))
    return rows


# --- Verdicts ----------------------------------------------------------------------


def verdict_p01(walks: Dict[str, Any], uids: Dict[str, int], hops: Sequence[Tuple[str, str]]) -> Tuple[str, str, str]:
    """`walks`: each runtime's principal → parse_proc's result. Every process
    runs under its principal's uid, real and effective, and no hop's two ends
    share a uid, as the processes show it."""
    for principal in sorted(walks):
        w = walks[principal]
        if isinstance(w, rh.Unresolved):
            return "UNKNOWN", "unresolved", f"{principal}: {w.reason}"
        foreign = sorted({(r, e) for _, r, e in w if (r, e) != (uids[principal], uids[principal])})
        if foreign:
            return "FAIL", "ok", f"{principal}: processes under uid(s) {foreign}, not {uids[principal]}"
    for up, down in hops:
        if up in walks and down in walks and uids[up] == uids[down]:
            return "FAIL", "ok", f"{up} and {down} share uid {uids[up]}"
    return "PASS", "ok", "every process under its principal's uid; no hop's ends share one"


def verdict_p02(nonowner: Dict[str, Any], owner_witness: Dict[str, Any], owner_uid: Dict[str, int]) -> Tuple[str, str, str]:
    """`nonowner`: side → parse_markers's rows, measured from the side that
    does NOT own that side's markers. `owner_witness`: side → parse_rows of
    the owner's open of each present marker. `owner_uid`: side → the uid that
    must own it."""
    optional = {(name, side) for name, side, _, opt in MARKERS if opt}
    for side in sorted(nonowner):
        rows = nonowner[side]
        if isinstance(rows, rh.Unresolved):
            return "UNKNOWN", "unresolved", f"{side}: {rows.reason}"
        for lid, gen, name, kind, uid, mode, w in rows:
            where = f"{lid}/{gen}/{side}/{name}"
            if kind == "create":
                if w == "CREATED":
                    return "FAIL", "ok", f"{lid}/{gen}/{side}: the non-owner created a file there"
                if w not in REFUSED:
                    return "UNKNOWN", "unresolved", f"{lid}/{gen}/{side}: the create attempt gave {w}"
                continue
            if kind != "present":
                if kind == "ENOENT" and (name, side) in optional:
                    continue
                return ("FAIL", "ENOENT", f"{where}: absent") if kind == "ENOENT" else (
                    "UNKNOWN", "unresolved", f"{where}: {kind}")
            if int(uid) != owner_uid[side] or int(mode, 8) != MARKER_MODE:
                return "FAIL", "ok", f"{where}: owner {uid} mode {mode}, not {owner_uid[side]} {oct(MARKER_MODE)}"
            if w == "OPENED":
                return "FAIL", "ok", f"{where}: the non-owner opened it for writing"
            if w not in REFUSED:
                return "UNKNOWN", "unresolved", f"{where}: the write attempt gave {w}"
        witness = owner_witness.get(side)
        if isinstance(witness, rh.Unresolved):
            return "UNKNOWN", "unresolved", f"{side}: the owner's witness could not run: {witness.reason}"
        if witness is None or any(r != "OPENED" for _, r in witness):
            return "UNKNOWN", "unresolved", f"{side}: the owner could not open its own markers, so the refusal proves nothing"
    return "PASS", "EACCES", "every present marker is its owner's, 0640, and refuses the other side"


def verdict_p03(rows: Any, witness: Any) -> Tuple[str, str, str]:
    """Every candidate ENOENT from the email router, and the local router's
    activation spec opening the key: without the witness, ENOENT could mean
    a key that is not there at all."""
    if isinstance(rows, rh.Unresolved):
        return "UNKNOWN", "unresolved", rows.reason
    reached = [(i, r) for i, r in rows if r != "ENOENT"]
    if reached:
        return "FAIL", _errno(reached[0][1]), "the email router reaches the key: " + ", ".join(
            f"candidate {i} {r}" for i, r in reached)
    if isinstance(witness, rh.Unresolved):
        return "UNKNOWN", "ENOENT", f"the local router's witness could not run: {witness.reason}"
    if any(r != "OPENED" for _, r in witness):
        return "UNKNOWN", "ENOENT", "the local router's activation spec cannot open the key, so ENOENT proves nothing"
    return "PASS", "ENOENT", "every candidate ENOENT; the local router opens the key"


def verdict_p04(rows: Any, lanes: Any, holds: Sequence[str]) -> Tuple[str, str, str]:
    """Every candidate ENOENT from the email router; the targets are the live
    lanes (`lanes`: [] when proven, an Unresolved otherwise); and no mount
    source of the email router is, holds or is held by a lane (`holds`)."""
    if isinstance(lanes, rh.Unresolved):
        return "UNKNOWN", "unresolved", f"the live lanes could not be established: {lanes.reason}"
    if holds:
        return "FAIL", "ok", "the email router mounts a lane: " + "; ".join(holds)
    if isinstance(rows, rh.Unresolved):
        return "UNKNOWN", "unresolved", rows.reason
    created = [i for i, r in rows if r == "CREATED"]
    if created:
        return "FAIL", "ok", "the email router created a file in a peer lane: candidates " + ", ".join(map(str, created))
    reached = [(i, r) for i, r in rows if r != "ENOENT"]
    if reached:
        return "FAIL", _errno(reached[0][1]), "the email router sees a peer lane: " + ", ".join(
            f"candidate {i} {r}" for i, r in reached)
    return "PASS", "ENOENT", "every lane ENOENT from the email router; the lanes are the agents' live ones"


def _errno(cls: str) -> str:
    """A probe row's class as an outcome: an errno name, or `ok` when the
    operation succeeded."""
    return cls if re.fullmatch(r"E[A-Z0-9]{1,15}", cls) else "ok"


# --- Candidates and lanes -----------------------------------------------------------


def _related(a: str, b: str) -> bool:
    a, b = a.rstrip("/") or "/", b.rstrip("/") or "/"
    return a == b or a.startswith(b + "/") or b.startswith(a + "/") or b == "/" or a == "/"


def candidates(mounts: Sequence[Dict[str, Any]], targets: Sequence[str]) -> List[str]:
    """Each target's host path, and its in-container path through any bind
    whose source holds it, or the bind's own destination when the source is
    held by it."""
    out: List[str] = []
    for t in targets:
        out.append(t)
        for m in mounts:
            if m.get("type") != "bind":
                continue
            src, dst = m["source"], m["target"]
            if not _related(src, t):
                continue
            if t == src or t.startswith(src.rstrip("/") + "/"):
                out.append(posixpath.normpath(posixpath.join(dst, posixpath.relpath(t, src))))
            else:
                out.append(dst)
    return list(dict.fromkeys(out))


def lane_identity(lanes: Dict[str, str], agent_sources: Dict[str, Any], stat_: Callable = os.stat) -> Any:
    """[] when every enrolled agent's `peer/` (`lanes`: slug → host path) is
    an existing directory with the same (device, inode) as the source of that
    agent's running container's peer mount (`agent_sources`: slug → path, or
    an Unresolved); otherwise an Unresolved naming the first that is not. A
    missing or misnamed lane would make every ENOENT vacuous."""
    if not lanes:
        return rh.Unresolved("no enrolled agent's lane to probe")
    for slug in sorted(lanes):
        src = agent_sources.get(slug)
        if src is None or isinstance(src, rh.Unresolved):
            return rh.Unresolved(f"{slug}: {src.reason if src is not None else 'no running container or no peer mount'}")
        try:
            a, b = stat_(lanes[slug]), stat_(src)
        except OSError as e:
            return rh.Unresolved(f"{slug}: cannot stat its lane: {e}")
        if not stat.S_ISDIR(a.st_mode) or (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino):
            return rh.Unresolved(f"{slug}: {lanes[slug]} is not the live lane its container mounts")
    return []


def mounts_holding(mounts: Sequence[Dict[str, Any]], lanes: Dict[str, str], stat_: Callable = os.stat) -> List[str]:
    """Each bind of the email router whose source is, holds or is held by an
    agent's lane, compared by (device, inode) up each ancestor chain."""
    def chain(p: str) -> List[Tuple[int, int]]:
        ids, cur = [], p
        while True:
            try:
                st = stat_(cur)
                ids.append((st.st_dev, st.st_ino))
            except OSError:
                pass
            parent = posixpath.dirname(cur)
            if parent == cur:
                return ids
            cur = parent
    bad = []
    for m in mounts:
        if m.get("type") != "bind":
            continue
        src_chain = chain(m["source"])
        for slug, lane in sorted(lanes.items()):
            lane_chain = chain(lane)
            if src_chain and lane_chain and (src_chain[0] in lane_chain or lane_chain[0] in src_chain):
                bad.append(f"{m['source']} and {slug}'s lane {lane}")
    return bad


# --- Bindings -----------------------------------------------------------------------


def sha_json(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def lane_binding(lanes: Dict[str, str], stat_: Callable = os.stat) -> Any:
    """The lanes' identities as the evidence binds them: slug → [device, inode]."""
    out = {}
    for slug, p in sorted(lanes.items()):
        try:
            st = stat_(p)
        except OSError as e:
            return rh.Unresolved(f"cannot stat {p}: {e}")
        out[slug] = [st.st_dev, st.st_ino]
    return sha_json(out)


# --- One-shot specs ------------------------------------------------------------------

#: What a one-shot may change in the run spec it stands for, and nothing else.
ONESHOT_CHANGES = frozenset({"name", "network", "restart", "labels", "entrypoint", "command", "remove"})


def oneshot(base: Dict[str, Any], probe: str, run_id: str, script: str, args: Sequence[str],
            drop_volume: Optional[str] = None) -> Dict[str, Any]:
    """`base` (a runtime's run spec, hub_runtime's shape) as a one-shot running
    `script` over `args`: only ONESHOT_CHANGES move, plus the one named
    secret volume dropped. User, groups, capabilities, security options,
    read-only root and every other mount are the runtime's own, so the probe
    is exactly as privileged as what it stands for."""
    p = {k: v for k, v in json.loads(json.dumps(base)).items() if k != "mounts"}
    p.update({"name": f"{base['name']}-{PROBE_LABEL}-{probe.lower()}-{run_id}", "network": "none",
              "restart": "no", "labels": {"org.amap.oneshot": PROBE_LABEL, "org.amap.run": run_id},
              "entrypoint": "python3", "command": ["-I", "-S", "-c", script] + list(args), "remove": True,
              "mounts": [dict(m) for m in base["mounts"]
                         if not (m.get("type") == "volume" and m.get("source") == drop_volume)]})
    return p


def oneshot_diff(base: Dict[str, Any], one: Dict[str, Any], drop_volume: Optional[str] = None) -> List[str]:
    """Every field in which `one` differs from `base` other than
    ONESHOT_CHANGES, and any mount change beyond dropping `drop_volume`."""
    bad = [f"{k} differs from the runtime's" for k in sorted(set(base) | set(one))
           if k not in ONESHOT_CHANGES and k != "mounts" and base.get(k) != one.get(k)]
    want = [m for m in base["mounts"] if not (m.get("type") == "volume" and m.get("source") == drop_volume)]
    if one.get("mounts") != want:
        bad.append("its mounts are not the runtime's")
    if one.get("network") != "none" or one.get("restart") != "no":
        bad.append("it is not offline and one-shot")
    return bad


def oneshot_argv(one: Dict[str, Any], run_argv: Callable[[Dict[str, Any]], List[str]]) -> List[str]:
    """`docker run`'s arguments: the runtime's own (`run_argv`, hub_runtime.argv)
    with --rm, the labels and the entrypoint added, and the command after the
    image."""
    base = {k: v for k, v in one.items() if k not in ("labels", "entrypoint", "command", "remove")}
    a = run_argv(base)
    image = a.pop()
    extra = ["--rm"] if one.get("remove") else []
    for k, v in sorted(one.get("labels", {}).items()):
        extra += ["--label", f"{k}={v}"]
    return extra + ["--entrypoint", one["entrypoint"]] + a + [image] + list(one["command"])


# --- The run -------------------------------------------------------------------------


def _probe_entry(pid: str, vantage: List[Dict[str, Any]], operation: str, roles: List[str],
                 verdict: Tuple[str, str, str], witness: Tuple[str, str]) -> Dict[str, Any]:
    return {"id": pid, "vantage": vantage, "operation": operation, "target_role": list(dict.fromkeys(roles)),
            "outcome": verdict[1], "witness": {"operation": witness[0], "outcome": witness[1]},
            "verdict": verdict[0]}


def spec_vantage(spec: Dict[str, Any]) -> Dict[str, Any]:
    """A run spec as an evidence vantage: {container, image, uid, gids}."""
    uid, _, gid = spec["user"].partition(":")
    return {"container": spec["name"], "image": spec["image"], "uid": int(uid),
            "gids": [int(gid)] + [int(g) for g in spec.get("group_add", [])]}


def _witnessed(rows: Any, want: str = "OPENED") -> str:
    if isinstance(rows, rh.Unresolved):
        return "unresolved"
    bad = [r for _, r in rows if r != want]
    return "ok" if not bad else _errno(bad[0])


class Runner:
    """The one way a probe reaches the engine: `docker` (argv prefix) and
    `run` (argv → rh.Proc). Every call is recorded for the report."""

    def __init__(self, docker: Sequence[str], run: Callable[[List[str]], Any] = None):
        self.docker, self._run, self.calls = list(docker), run or rh.run, []

    def __call__(self, argv: List[str]) -> Any:
        self.calls.append(argv)
        try:
            return self._run(list(self.docker) + argv)
        except rh.CannotRun as e:
            return rh.Unresolved(str(e))


def _out(p: Any) -> Any:
    if isinstance(p, rh.Unresolved):
        return p
    if p.rc != 0:
        return rh.Unresolved(f"exited {p.rc}")
    return p.out


def run_oneshot(runner: Runner, base: Dict[str, Any], probe: str, run_id: str, script: str, args: Sequence[str],
                run_argv: Callable, drop_volume: Optional[str] = None) -> Any:
    one = oneshot(base, probe, run_id, script, args, drop_volume)
    bad = oneshot_diff(base, one, drop_volume)
    if bad:
        return rh.Unresolved(f"the {probe} one-shot would differ from its runtime: {'; '.join(bad)}")
    return _out(runner(["run"] + oneshot_argv(one, run_argv)))


class Plan:
    """Everything one run needs, gathered by the caller from the host-setup
    document, the renderings and the running containers.
    - `email`: the email router's rendered run spec; `email_drift`:
      hub_runtime.compare of the running container with it ([] when equal),
      or an Unresolved; `email_volume`: its secret volume, dropped from its
      one-shots;
    - `router`: the local router's run spec the witnesses use (its activation
      spec, which mounts the key); `key_path`, `key_dir`;
    - `lanes`: slug → the host path of the agent's `peer/`; `agent_sources`:
      slug → the source of that agent's running peer mount, or an Unresolved;
    - `runtimes`: principal → (container, uid, gid) for P01; `vantages`:
      principal → {container, image, uid, gids}; `hops`:
      (upstream, downstream) principal pairs;
    - `sides`: "up" → (spec, in-container hop root) of the side that does NOT
      own up/ (downstream), and the same for "down"; `owners`: side → (spec,
      in-container hop root, uid) of the side that does;
    - `bindings`: name → sha256, as the evidence binds them."""

    def __init__(self, **kw: Any):
        self.__dict__.update(kw)


def run(plan: Plan, runner: Runner, run_argv: Callable, stat_: Callable = os.stat) -> Tuple[Optional[bytes], int, List[str]]:
    """(the evidence document's bytes or None, the exit code, the report).
    0 only when every probe passed; 1 when any failed; 2 when one could not
    establish its facts. A running email router that differs from its
    rendering refuses the whole run: nothing it showed would stand for it."""
    import partition_evidence as pe
    rid = plan.run_id
    drift = plan.email_drift
    if isinstance(drift, rh.Unresolved) or drift:
        why = drift.reason if isinstance(drift, rh.Unresolved) else "; ".join(drift)
        return None, 2, [f"refused: the running email router is not its rendering: {why}"]
    report = []
    email_vantage = [spec_vantage(plan.email)]

    # P01: each hop runtime's processes, read as its own principal.
    walks = {}
    for principal, (container, uid, gid) in sorted(plan.runtimes.items()):
        out = _out(runner(["exec", "-u", f"{uid}:{gid}", container, "python3", "-I", "-S", "-c", P01_SCRIPT]))
        walks[principal] = out if isinstance(out, rh.Unresolved) else parse_proc(out)
    uids = {p: u for p, (_, u, _) in plan.runtimes.items()}
    p01 = verdict_p01(walks, uids, plan.hops)

    # P02: the other side's attempts on each side's markers, and the owner's witness.
    nonowner, witness = {}, {}
    for side in ("up", "down"):
        spec, root = plan.sides[side]
        names = sorted({n for n, s, _, _ in MARKERS if s == side})
        out = run_oneshot(runner, spec, "P02", rid, P02_SCRIPT, [root, side, probe_file(rid)] + names, run_argv,
                          plan.email_volume)
        rows = out if isinstance(out, rh.Unresolved) else parse_markers(out)
        nonowner[side] = rows
        if isinstance(rows, rh.Unresolved):
            continue
        ospec, oroot, _ = plan.owners[side]
        present = [posixpath.join(oroot, lid, gen, side, n) for lid, gen, n, kind, *_ in rows if kind == "present"]
        if present:
            w = run_oneshot(runner, ospec, "P02W", rid, OPEN_WITNESS_SCRIPT, ["w"] + present, run_argv,
                            plan.email_volume)
            witness[side] = w if isinstance(w, rh.Unresolved) else parse_rows(w, len(present))
        else:
            witness[side] = []
    p02 = verdict_p02(nonowner, witness, {side: plan.owners[side][2] for side in plan.owners})

    # P03: every path reaching the key, from the email router; the local router's witness.
    cands = candidates(plan.email["mounts"], [plan.key_path, plan.key_dir])
    out = run_oneshot(runner, plan.email, "P03", rid, P03_SCRIPT, cands, run_argv, plan.email_volume)
    rows3 = out if isinstance(out, rh.Unresolved) else parse_rows(out, len(cands))
    w3 = run_oneshot(runner, plan.router, "P03W", rid, OPEN_WITNESS_SCRIPT, ["r", plan.key_path], run_argv)
    w3 = w3 if isinstance(w3, rh.Unresolved) else parse_rows(w3, 1)
    p03 = verdict_p03(rows3, w3)

    # P04: every live lane and every path reaching one, from the email router.
    lanes = lane_identity(plan.lanes, plan.agent_sources, stat_)
    holds = mounts_holding(plan.email["mounts"], plan.lanes, stat_)
    cands4 = candidates(plan.email["mounts"], [plan.lanes[s] for s in sorted(plan.lanes)])
    rows4: Any = rh.Unresolved("not run: the live lanes are not established")
    if not isinstance(lanes, rh.Unresolved):
        out = run_oneshot(runner, plan.email, "P04", rid, P04_SCRIPT, [probe_file(rid)] + cands4, run_argv,
                          plan.email_volume)
        rows4 = out if isinstance(out, rh.Unresolved) else parse_rows(out, len(cands4))
    p04 = verdict_p04(rows4, lanes, holds)

    p02_witness = "unresolved" if any(isinstance(w, rh.Unresolved) for w in witness.values()) else (
        "ok" if all(_witnessed(w) == "ok" for w in witness.values()) else "EACCES")
    mount_roles = [f"mount:{c}" for c in cands if c not in (plan.key_path, plan.key_dir)]
    probes = [
        _probe_entry("P01", [plan.vantages[p] for p in sorted(plan.runtimes)], "read /proc/*/status as the principal",
                     [f"runtime:{p}" for p in sorted(plan.runtimes)], p01,
                     ("read each uid from the process", "unresolved" if p01[1] == "unresolved" else "ok")),
        _probe_entry("P02", [spec_vantage(plan.sides[s][0]) for s in sorted(plan.sides)],
                     "lstat; open for writing; create beside",
                     [f"marker:{s}/{n}" for n, s, _, _ in MARKERS if s in plan.sides], p02,
                     ("the owner opens its markers for writing", p02_witness)),
        _probe_entry("P03", email_vantage, "lstat", ["key:signing", "key:dir"] + mount_roles, p03,
                     ("the local router opens the key read-only", _witnessed(w3))),
        _probe_entry("P04", email_vantage, "lstat; create the probe name", [f"peer:{s}" for s in sorted(plan.lanes)], p04,
                     ("each lane is its agent's live mount", "unresolved" if isinstance(lanes, rh.Unresolved) else "ok")),
    ]
    details = {"P01": p01[2], "P02": p02[2], "P03": p03[2], "P04": p04[2]}
    probes = json.loads(json.dumps(probes, default=list))
    doc = pe.build(host=plan.host, run_id=rid, at=plan.at, script_sha256=script_sha256(),
                   bindings=plan.bindings, probes=probes)
    verdicts = [p["verdict"] for p in probes]
    for p in probes:
        report.append(f"{p['id']}: {p['verdict']}: {details[p['id']]}")
    code = 1 if "FAIL" in verdicts else 2 if "UNKNOWN" in verdicts else 0
    return doc, code, report


# --- The planted-violation controls ---------------------------------------------------
#
# Each control plants ONE violation, on a throwaway container or a scratch path
# this run created, never on a live runtime or its live paths, and requires the
# probe it controls to go RED, naming that probe. A control that stays green is
# a failure of its probe. A control's document never carries a token.

CONTROL_SCHEMA = "amap-deploy.partition-control/1"
CONTROL_LABEL = "partition-control"
#: The scratch config C05 binds, by its two contents.
C05_BEFORE, C05_AFTER = b'{"c05":"before"}', b'{"c05":"after"}'


def _planted(base: Dict[str, Any], control: str, run_id: str, script: str, args: Sequence[str],
             extra_mounts: Sequence[Dict[str, Any]] = (), user: Optional[str] = None,
             drop_volume: Optional[str] = None) -> Dict[str, Any]:
    one = oneshot(base, control, run_id, script, args, drop_volume)
    one["name"] = f"{base['name']}-{CONTROL_LABEL}-{control.lower()}-{run_id}"
    one["labels"] = {"org.amap.oneshot": CONTROL_LABEL, "org.amap.run": run_id}
    one["mounts"] = one["mounts"] + [dict(m) for m in extra_mounts]
    if user is not None:
        one["user"] = user
    return one


def run_controls(plan: Plan, scratch: Dict[str, str], runner: Runner, run_argv: Callable,
                 read: Callable[[str], bytes] = None) -> List[Dict[str, Any]]:
    """C01-C05 against throwaway containers and the scratch paths in `scratch`
    (each created for this run by the caller): `key_dir` holding a dummy key
    file `key` (random bytes, never a real key); `peer`, a writable directory;
    `markers`, a hop tree whose up/ marker is 0660 group-writable; and the
    two scratch file paths `config` and `config_next`, which C05 fills itself. Returns one
    entry per control: {id, probe, probe_verdict, control}, control PASS only
    when the probe went RED."""
    rid = plan.run_id
    out = []

    def entry(cid: str, probe: str, verdict: Tuple[str, str, str]) -> None:
        out.append({"id": cid, "probe": probe, "probe_verdict": verdict[0], "outcome": verdict[2],
                    "control": "PASS" if verdict[0] == "FAIL" else "FAIL"})

    # C01: a throwaway from the local router's image, run as the email router's uid.
    up_c, up_uid, up_gid = plan.runtimes[plan.hops[0][0]]
    name = f"{up_c}-{CONTROL_LABEL}-c01-{rid}"
    started = _out(runner(["run", "-d", "--rm", "--name", name, "--network", "none", "--user", plan.email["user"],
                           "--label", f"org.amap.oneshot={CONTROL_LABEL}", "--entrypoint", "sleep",
                           plan.router["image"], "120"]))
    if isinstance(started, rh.Unresolved):
        entry("C01", "P01", ("UNKNOWN", "unresolved", f"the throwaway could not start: {started.reason}"))
    else:
        walk = _out(runner(["exec", "-u", f"{up_uid}:{up_gid}", name, "python3", "-I", "-S", "-c", P01_SCRIPT]))
        runner(["rm", "-f", name])
        walk = walk if isinstance(walk, rh.Unresolved) else parse_proc(walk)
        entry("C01", "P01", verdict_p01({plan.hops[0][0]: walk}, {plan.hops[0][0]: up_uid}, []))

    # C02: the non-owner's spec over a scratch hop tree whose marker it can write.
    spec, _ = plan.sides["up"]
    tree = {"type": "bind", "source": scratch["markers"], "target": "/control-hop", "readonly": False}
    o = _out(runner(["run"] + oneshot_argv(_planted(spec, "C02", rid, P02_SCRIPT,
                                                    ["/control-hop", "up", probe_file(rid), "identity.json"],
                                                    [tree], drop_volume=plan.email_volume), run_argv)))
    rows = o if isinstance(o, rh.Unresolved) else parse_markers(o)
    entry("C02", "P02", verdict_p02({"up": rows}, {"up": [(0, "OPENED")]}, {"up": plan.owners["up"][2]}))

    # C03: the email router's spec plus a read-only bind of the dummy key's directory.
    kbind = {"type": "bind", "source": scratch["key_dir"], "target": scratch["key_dir"], "readonly": True}
    o = _out(runner(["run"] + oneshot_argv(_planted(plan.email, "C03", rid, P03_SCRIPT, [scratch["key"]], [kbind],
                                                    drop_volume=plan.email_volume), run_argv)))
    entry("C03", "P03", verdict_p03(o if isinstance(o, rh.Unresolved) else parse_rows(o, 1), [(0, "OPENED")]))

    # C04: the email router's spec plus a read-write bind of a scratch peer/; the
    # create-and-delete witness happens here, never in a live lane.
    pbind = {"type": "bind", "source": scratch["peer"], "target": scratch["peer"], "readonly": False}
    o = _out(runner(["run"] + oneshot_argv(_planted(plan.email, "C04", rid, P04_SCRIPT,
                                                    [probe_file(rid), scratch["peer"]], [pbind],
                                                    drop_volume=plan.email_volume), run_argv)))
    entry("C04", "P04", verdict_p04(o if isinstance(o, rh.Unresolved) else parse_rows(o, 1), [], []))

    # C05: a throwaway from the local router's image binding a scratch config FILE:
    # stop it, replace the file by rename, start it, and read the file through it.
    name = f"{up_c}-{CONTROL_LABEL}-c05-{rid}"
    for path, data in ((scratch["config"], C05_BEFORE), (scratch["config_next"], C05_AFTER)):
        with open(path, "wb") as f:
            f.write(data)
    cbind = f"type=bind,src={scratch['config']},dst=/control-config.json,readonly"
    steps = [["create", "--name", name, "--network", "none", "--label", f"org.amap.oneshot={CONTROL_LABEL}",
              "--mount", cbind, "--entrypoint", "sleep", plan.router["image"], "120"],
             ["start", name], ["stop", "-t", "1", name]]
    failed = next((r for r in (_out(runner(s)) for s in steps) if isinstance(r, rh.Unresolved)), None)
    seen: Any = failed
    if failed is None:
        os.replace(scratch["config_next"], scratch["config"])
        started = _out(runner(["start", name]))
        seen = started if isinstance(started, rh.Unresolved) else _out(runner(
            ["exec", name, "python3", "-I", "-S", "-c",
             "import sys;sys.stdout.write(open('/control-config.json').read())"]))
    runner(["rm", "-f", name])
    if isinstance(seen, rh.Unresolved):
        out.append({"id": "C05", "probe": "bind-resolution", "probe_verdict": "UNKNOWN", "outcome": seen.reason,
                    "control": "FAIL"})
    else:
        fresh = seen.encode("utf-8") == C05_AFTER
        out.append({"id": "C05", "probe": "bind-resolution", "probe_verdict": "PASS" if fresh else "FAIL",
                    "outcome": "a restarted container reads the replaced file" if fresh else
                    "a restarted container still reads the old file",
                    "control": "PASS" if fresh else "FAIL"})
    return out


def control_document(*, host: str, run_id: str, at: str, controls: List[Dict[str, Any]]) -> bytes:
    """The control pass's own document, canonical, with no token member at all."""
    import partition_evidence as pe
    return pe.canonical({"schema": CONTROL_SCHEMA, "host": host, "run_id": run_id, "at": at,
                         "script_sha256": script_sha256(), "controls": controls})
