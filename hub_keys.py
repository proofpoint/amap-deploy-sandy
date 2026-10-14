"""The local router's signing key on a hub-link host, kept out of the email
router's reach; the guard that keeps any `delegation` block out of the local
router's config; and the D7 file as each running router sees it. NOTHING
HERE GENERATES, READS OR COPIES KEY MATERIAL: the key is generated on the
host by the operator, and every check of it is `lstat`.

The host-setup document's `keys` section (it needs a `hub` section) names:
- `dir` and `file`: where the key lives. The directory is the local
  router's, 0700, under root-owned directories nobody else can write; the
  file is the local router's, 0400, one link. The directory must be listed
  in the secrets section's `exposure.secret_roots`, so the exposure sweep
  fails any container (an agent's, the email router's, the local router's
  own) whose bind overlaps it, in either direction. It must sit outside
  every declared root, agent path, the hop root, the registry, the D7 and
  overlay directories and the environment file's directory.
- `evidence_dir`: where the key probe's record is placed, root-owned. It
  must be listed in `exposure.integrity_roots`, so no container may write
  it or bind anything above it.
- `local_config`: the file the local router reads its config from.

The key-read probe runs the email router's own rendered run spec with only
these changes: removed after `run`, no network, its own name and labels, no
restart, an entrypoint of python3 running a fixed script, and the secret
volume NOT mounted (no container but the email router and the secret's
reviewed one-shots may mount it). Everything else (user, groups,
capabilities, security options, read-only root, the other mounts) is the
email router's. A structural diff refuses any other change. The script only
`lstat`s each candidate (the key's path, its directory, and the in-container
path of any mount whose source holds or is held by the directory) and prints
an outcome class per candidate, never content. PASS needs ENOENT for every
candidate: EACCES means the path is there and merely unreadable, which is
what a 0400 key in a 0700 directory looks like through a mount.

The probe's record binds the email router's run-spec hash, the key path,
the candidate set, the probe's image and its command. The operator's verb
writes it into the run directory; the plan's root step places it. A record
whose bound fields differ from the current rendering is no evidence. The
environment file's contents are deliberately not bound: a variable cannot
add a mount, a capability, a namespace or a user, so it cannot change what
the probe tests.

No delegation block. With `delegation` absent from the local router's
config, the router signs nothing and verifies nothing, and nothing else
enables it (the local router's own confirmation; `null` and `{}` are refused
at its load). Until the full signed-case harness passes, `delegation`
present at all, in any form, is a failure. This module never writes one.
"""

import copy
import hashlib
import json
import os
import posixpath
import re
import stat
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import delivered_domains as dd
import hub_runtime as hr
import router_health as rh
import secret_setup as ss

SECTION = "keys"
DIR_MODE = 0o700
KEY_MODE = 0o400
EVIDENCE_NAME = "keyprobe.json"
EVIDENCE_MODE = 0o444
#: The one key whose presence turns signing on in the local router.
DELEGATION_KEY = "delegation"
PROBE_LABEL = "keyprobe"
#: What the probe may change in the email router's run spec, and nothing else.
PROBE_CHANGES = frozenset({"name", "network", "restart", "labels", "entrypoint", "command", "remove"})
PROBE_SCRIPT = (
    "import os,sys\n"
    "for i,p in enumerate(sys.argv[1:]):\n"
    "    try:\n"
    "        os.lstat(p); r='exists'\n"
    "    except FileNotFoundError: r='ENOENT'\n"
    "    except PermissionError: r='EACCES'\n"
    "    except NotADirectoryError: r='ENOTDIR'\n"
    "    except OSError as e: r='E%d' % e.errno\n"
    "    print(i, r)\n")
D7_HASH_SCRIPT = ("import hashlib,sys\n"
                  "print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())\n")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_RUN_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
RECORD_KEYS = frozenset({"run_id", "at", "spec_sha256", "key_path", "candidates_sha256", "probe_image",
                         "probe_command_sha256", "result"})


class KeySpecError(ValueError):
    """The keys section is unusable."""


@dataclass(frozen=True)
class KeySpec:
    dir: str
    file: str
    evidence_dir: str
    local_config: str
    principal: str            # the local router's
    uid: int
    gid: int

    @property
    def path(self) -> str:
        return posixpath.join(self.dir, self.file)

    @property
    def evidence(self) -> str:
        return posixpath.join(self.evidence_dir, EVIDENCE_NAME)


def _abs(p: Any, what: str) -> str:
    if not isinstance(p, str) or not p.startswith("/") or posixpath.normpath(p) != p \
            or p.startswith("//") or p == "/":
        raise KeySpecError(f"keys.{what} must be an absolute, normalised path")
    return p


def _related(a: str, b: str) -> bool:
    """One is the other or inside it, by path components."""
    pa, pb = a.rstrip("/").split("/"), b.rstrip("/").split("/")
    n = min(len(pa), len(pb))
    return pa[:n] == pb[:n]


def load(sec: Any, spec: Any) -> KeySpec:
    if spec.hub is None:
        raise KeySpecError("the keys section needs a hub section")
    if not isinstance(sec, dict) or set(sec) != {"dir", "file", "evidence_dir", "local_config"}:
        raise KeySpecError("keys must have exactly dir, file, evidence_dir and local_config")
    if not isinstance(sec["file"], str) or not _NAME.fullmatch(sec["file"]):
        raise KeySpecError("keys.file must be one file name")
    d, ev = _abs(sec["dir"], "dir"), _abs(sec["evidence_dir"], "evidence_dir")
    cfg = _abs(sec["local_config"], "local_config")
    hs = spec.hub
    local = next(up for name, up, _down, _env in spec.hops if name == hs.hop)
    s = spec.secrets
    exp = s.extra["exposure"]
    if d not in exp["secret_roots"]:
        raise KeySpecError("keys.dir must be listed in secrets.exposure.secret_roots, so the sweep fails "
                           "every container whose bind overlaps it")
    if ev not in exp["integrity_roots"]:
        raise KeySpecError("keys.evidence_dir must be listed in secrets.exposure.integrity_roots, so no "
                           "container may write it")
    others = [r.path for r in spec.roots] + list(spec.agent_paths) + [
        hs.hop_root, hs.registry_dir, hs.d7_dir, posixpath.dirname(hs.env_file), ev,
        posixpath.dirname(spec.overlay_path), posixpath.dirname(hs.prefix_template), s.container_dir,
        s.run_dir]
    for o in others:
        if _related(d, o):
            raise KeySpecError(f"keys.dir {d} overlaps {o}; the key stays outside every root a runtime "
                               f"or an agent reaches")
    p = spec.principals[local]
    return KeySpec(dir=d, file=sec["file"], evidence_dir=ev, local_config=cfg, principal=local, uid=p.uid,
                   gid=p.gids[0])


# --- The probe ------------------------------------------------------------------


def candidates(base: Dict[str, Any], ks: KeySpec) -> List[str]:
    """The paths that must not exist inside the email router: the key's and
    its directory's host paths, and the in-container path of the key and its
    directory through any mount whose source holds, or is held by, the key's
    directory."""
    out = [ks.path, ks.dir]
    for m in base["mounts"]:
        if m["type"] != "bind":
            continue
        src, dst = m["source"], m["target"]
        if _related(src, ks.dir):
            if ks.dir == src or ks.dir.startswith(src.rstrip("/") + "/"):
                inside = posixpath.normpath(posixpath.join(dst, posixpath.relpath(ks.dir, src)))
                out += [inside, posixpath.join(inside, ks.file)]
            else:
                out.append(dst)
    return list(dict.fromkeys(out))


def probe_spec(base: Dict[str, Any], ks: KeySpec, run_id: str) -> Dict[str, Any]:
    """The email router's run spec with only PROBE_CHANGES applied."""
    if not _RUN_ID.fullmatch(run_id):
        raise KeySpecError("the run id must be 1-64 of [A-Za-z0-9._-]")
    p = copy.deepcopy(base)
    p["name"] = f"{base['name']}-{PROBE_LABEL}-{run_id}"
    p["network"] = "none"
    p["restart"] = "no"
    p["labels"] = {"org.amap.oneshot": PROBE_LABEL, "org.amap.run": run_id}
    p["entrypoint"] = "python3"
    p["command"] = ["-I", "-S", "-c", PROBE_SCRIPT] + candidates(base, ks)
    p["remove"] = True
    p["mounts"] = [m for m in base["mounts"] if m["type"] != "volume"]
    return p


def probe_diff(base: Dict[str, Any], probe: Dict[str, Any]) -> List[str]:
    """Every difference between the two specs that PROBE_CHANGES does not
    allow, plus any mount change other than the secret volume's removal."""
    bad = []
    for k in sorted(set(base) | set(probe)):
        if k == "mounts" or k in PROBE_CHANGES:
            continue
        if base.get(k) != probe.get(k):
            bad.append(f"{k} differs")
    kept = [m for m in base["mounts"] if m["type"] != "volume"]
    if probe.get("mounts") != kept:
        bad.append("its mounts are not the email router's without the secret volume")
    if any(m["type"] == "volume" for m in probe.get("mounts", [])):
        bad.append("it mounts a volume")
    return bad


def probe_argv(probe: Dict[str, Any]) -> List[str]:
    """`docker run`'s arguments for the probe."""
    base = {k: v for k, v in probe.items() if k not in ("labels", "entrypoint", "command", "remove")}
    a = hr.argv(base)
    image = a.pop()
    extra = ["--rm"] if probe.get("remove") else []
    for k, v in sorted(probe.get("labels", {}).items()):
        extra += ["--label", f"{k}={v}"]
    extra += ["--entrypoint", probe["entrypoint"]]
    return extra + a + [image] + list(probe["command"])


def parse_probe(out: str, n: int) -> Any:
    """[(index, class)] for exactly n candidates, or an Unresolved."""
    rows = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 2 or not parts[0].isdigit():
            return rh.Unresolved("the probe printed something other than its rows")
        rows.append((int(parts[0]), parts[1]))
    if [i for i, _ in rows] != list(range(n)):
        return rh.Unresolved(f"the probe answered {len(rows)} of {n} candidates")
    return rows


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def bound(base: Dict[str, Any], ks: KeySpec, probe: Dict[str, Any]) -> Dict[str, str]:
    """The fields a record binds, computed from the current rendering."""
    cands = candidates(base, ks)
    return {"spec_sha256": hr.spec_sha256(base), "key_path": ks.path,
            "candidates_sha256": _sha(json.dumps(sorted(cands)).encode()), "probe_image": probe["image"],
            "probe_command_sha256": _sha(json.dumps([probe["entrypoint"]] + list(probe["command"])).encode())}


def record_bytes(base: Dict[str, Any], ks: KeySpec, probe: Dict[str, Any], run_id: str, rows: Any,
                 now: float) -> bytes:
    passed = not isinstance(rows, rh.Unresolved) and all(r == "ENOENT" for _, r in rows)
    doc = dict(bound(base, ks, probe), run_id=run_id,
               at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)), result="PASS" if passed else "FAIL")
    return (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode()


def run_probe(spec: Any, ks: KeySpec, *, apply: bool, run_id: Optional[str] = None, out=print,
              runner: Callable[[List[str]], Any] = None, now: Callable[[], float] = time.time) -> int:
    """The `hub-keyprobe` verb: show the probe, or (`--apply`) run it and
    write its record into the run directory for the plan to place. 0 only
    when every candidate is ENOENT."""
    hs = spec.hub
    base = hr.run_spec(spec, hs)
    rid = run_id or time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now()))
    probe = probe_spec(base, ks, rid)
    bad = probe_diff(base, probe)
    if bad:
        out(f"hub-keyprobe: refused: the probe would differ from the email router: {'; '.join(bad)}")
        return 2
    argv = ss.docker(spec.secrets) + ["run"] + probe_argv(probe)
    if not apply:
        out("hub-keyprobe: would run (nothing ran; run again with --apply):")
        out("  " + " ".join(argv[:-len(probe["command"])]) + f" <the probe script> {len(candidates(base, ks))} path(s)")
        return 0
    try:
        p = (runner or rh.run)(argv)
    except rh.CannotRun as e:
        out(f"hub-keyprobe: could not run: {e}")
        return 1
    rows = parse_probe(p.out, len(candidates(base, ks))) if p.rc == 0 else \
        rh.Unresolved(f"the probe exited {p.rc}")
    data = record_bytes(base, ks, probe, rid, rows, now())
    path = posixpath.join(spec.secrets.run_dir, EVIDENCE_NAME)
    tmp = f"{path}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    result = json.loads(data)["result"]
    for i, r in ([] if isinstance(rows, rh.Unresolved) else rows):
        out(f"  candidate {i}: {r}")
    if isinstance(rows, rh.Unresolved):
        out(f"  {rows.reason}")
    out(f"hub-keyprobe: {result}; wrote {path} (sha256 {_sha(data)}); place it with the plan's step")
    return 0 if result == "PASS" else 1


# --- The plan -------------------------------------------------------------------


def plan(spec: Any, ks: KeySpec, q: Callable[[str], str], steps: str) -> List[str]:
    install = q(spec.secrets.tools.get("install", "install"))
    run_dir = spec.secrets.run_dir
    return [
        f"# The local router's signing key. Its directory, {ks.principal}'s, 0700, under root-owned "
        f"directories:",
        f"{install} -d -o {ks.uid} -g {ks.gid} -m 0700 {q(ks.dir)}",
        f"# The key is generated ON this host by the operator, as {ks.principal} (uid {ks.uid}), into "
        f"{ks.path}, mode 0400; nothing here generates, reads or copies it. Its public key goes into the "
        f"inventory.",
        f"{install} -d -o 0 -g 0 -m 0755 {q(ks.evidence_dir)}",
        "# Then, as the operator: `amap-sandy.py hub-keyprobe --apply` (the email router's run spec, without "
        "its secret volume, lstat-ing the key's paths); it prints the record's sha256. Place the record:",
        f"{steps} place {q(posixpath.join(run_dir, EVIDENCE_NAME))} {q(ks.evidence)} --sha256 <the printed sha256>",
        "# The email router starts only with a PASS record bound to its current run spec. The local "
        "router's config carries no delegation block.",
    ]


# --- Verify ---------------------------------------------------------------------


def _fact(name: str, value: Any, provenance: str) -> rh.Fact:
    return rh.Fact(name, value, provenance)


def _lst(path: str, lstat: Callable) -> Any:
    try:
        return lstat(path)
    except FileNotFoundError:
        return None
    except OSError as e:
        return rh.Unresolved(f"cannot inspect {path}: {e}")


def verify_placement(ks: KeySpec, lstat: Callable) -> List[rh.Check]:
    out = []
    why = "the local router signs with it; no other uid may read it"
    st = _lst(ks.dir, lstat)
    claim = f"the key directory {ks.dir} is {ks.principal}'s, 0700"
    want = _fact("key dir", (ks.uid, DIR_MODE), why)
    remedy = f"create it as the plan does: install -d -o {ks.uid} -g {ks.gid} -m 0700 {ks.dir}"
    if isinstance(st, rh.Unresolved):
        out.append(rh.unknown(claim, want, st.reason, remedy))
    elif st is None or not stat.S_ISDIR(st.st_mode):
        out.append(rh.check(claim, want, "absent" if st is None else "not a directory", remedy))
    else:
        out.append(rh.check(claim, want, (st.st_uid, stat.S_IMODE(st.st_mode)), remedy))
    out.append(ss._owned_chain(f"every directory above {ks.dir} is root-owned and not group- or "
                               f"world-writable", ks.dir, (0,), why, lstat))
    st = _lst(ks.path, lstat)
    claim = f"the key {ks.path} is {ks.principal}'s, 0400, with one link"
    want = _fact("key file", (ks.uid, KEY_MODE, 1), why)
    remedy = f"the operator generates it on this host as {ks.principal}, mode 0400 (contract step 4)"
    if isinstance(st, rh.Unresolved):
        out.append(rh.unknown(claim, want, st.reason, remedy))
    elif st is None or not stat.S_ISREG(st.st_mode):
        out.append(rh.check(claim, want, "absent" if st is None else "not a regular file", remedy,
                            do_not="never generate it from this tooling or copy it from another host"))
    else:
        out.append(rh.check(claim, want, (st.st_uid, stat.S_IMODE(st.st_mode), st.st_nlink), remedy))
    return out


def read_json(path: str) -> Any:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"{path} is not a regular file")
        raw = os.read(fd, (1 << 20) + 1)
    finally:
        os.close(fd)
    return json.loads(raw.decode("utf-8"))


def verify_no_delegation(ks: KeySpec, read: Callable[[str], Any] = read_json) -> List[rh.Check]:
    claim = f"the local router's config {ks.local_config} has no {DELEGATION_KEY} block"
    want = _fact("delegation", False, "the operator's decision: no live peer signing until the full "
                                      "signed-case harness passes; its absence is the whole of 'no signing'")
    remedy = f"remove the {DELEGATION_KEY} member and render the config again"
    try:
        doc = read(ks.local_config)
    except FileNotFoundError:
        return [rh.unknown(claim, want, f"{ks.local_config} is absent", "render and place the local router's config")]
    except (OSError, ValueError) as e:
        return [rh.unknown(claim, want, f"cannot read {ks.local_config}: {e}", "make it readable JSON")]
    if not isinstance(doc, dict):
        return [rh.unknown(claim, want, f"{ks.local_config} is not a JSON object", "render it again")]
    return [rh.check(claim, want, DELEGATION_KEY in doc, remedy,
                     do_not="never add the block by hand to test signing")]


def verify_evidence(spec: Any, ks: KeySpec, lstat: Callable, read: Callable[[str], Any] = read_json
                    ) -> List[rh.Check]:
    out = []
    base = hr.run_spec(spec, spec.hub)
    claim = f"the key probe's record {ks.evidence} is root:root 0444 with one link"
    want = _fact("record", (0, 0, EVIDENCE_MODE, 1), "written by the operator's verb, placed by root")
    remedy = "run `hub-keyprobe --apply` and place its record as the plan does"
    st = _lst(ks.evidence, lstat)
    if isinstance(st, rh.Unresolved):
        out.append(rh.unknown(claim, want, st.reason, remedy))
    elif st is None:
        out.append(rh.unknown(claim, want, "no record yet: the email router may not start", remedy))
        return out
    elif not stat.S_ISREG(st.st_mode):
        out.append(rh.check(claim, want, "not a regular file", remedy))
    else:
        out.append(rh.check(claim, want, (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_nlink), remedy))
    claim = "the key probe passed against the email router's CURRENT run spec"
    want = _fact("evidence", True, "every candidate ENOENT, bound to the current spec, key, candidates and probe")
    try:
        rec = read(ks.evidence)
    except (OSError, ValueError) as e:
        out.append(rh.unknown(claim, want, f"cannot read {ks.evidence}: {e}", remedy))
        return out
    if not isinstance(rec, dict) or set(rec) != RECORD_KEYS:
        out.append(rh.check(claim, want, "the record is malformed", remedy))
        return out
    probe = probe_spec(base, ks, rec["run_id"] if _RUN_ID.fullmatch(str(rec["run_id"])) else "x")
    stale = [k for k, v in bound(base, ks, probe).items() if rec.get(k) != v]
    if stale:
        out.append(rh.check(claim, want, f"stale: {', '.join(stale)} changed since the probe ran",
                            "run the probe again against the current rendering",
                            do_not="never edit the record"))
    else:
        out.append(rh.check(claim, want, rec["result"] == "PASS", "find the mount that reaches the key, "
                            "remove it, render, and run the probe again"))
    return out


def ask_d7_hash(spec: Any, container: str, path: str) -> Any:
    """The D7 file's sha256 as `container` sees it, or an Unresolved naming
    why it could not be asked (the container not running among them)."""
    try:
        p = rh.run(ss.docker(spec.secrets) + ["exec", container, "python3", "-I", "-S", "-c", D7_HASH_SCRIPT, path])
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    if p.rc != 0:
        return rh.Unresolved(f"docker exec {container} exited {p.rc}")
    h = p.out.strip()
    return h if _HEX64.fullmatch(h) else rh.Unresolved(f"{container} printed no hash")


def verify_d7_live(spec: Any, ks: KeySpec, host_hash: Any, ask: Callable[[str, str], Any]) -> List[rh.Check]:
    out = []
    hs = spec.hub
    for principal in (spec.secrets.principal, ks.principal):
        name = spec.runtime_of(principal)["container"]
        claim = f"{name} sees the D7 file the host holds"
        want = _fact("D7 in container", host_hash if isinstance(host_hash, str) else None,
                     "the directory is mounted read-only, so a replaced file is seen at once")
        remedy = f"mount {hs.d7_dir} read-only as a directory into {name}, never the file alone"
        got = ask(name, hs.d7_path)
        if isinstance(host_hash, rh.Unresolved):
            out.append(rh.unknown(claim, want, host_hash.reason, remedy))
        elif isinstance(got, rh.Unresolved):
            out.append(rh.unknown(claim, want, got.reason, "start the router, or make the engine answer"))
        else:
            out.append(rh.check(claim, want, got, remedy))
    return out


ASK = hr.ASK


def checks(spec: Any, ks: KeySpec, *, lstat: Callable = os.lstat, read_json_: Callable[[str], Any] = read_json,
           d7_hash: Any = ASK, ask: Any = ASK) -> List[rh.Check]:
    out = verify_placement(ks, lstat)
    out += verify_no_delegation(ks, read_json_)
    out += verify_evidence(spec, ks, lstat, read_json_)
    if d7_hash is ASK:
        try:
            d7_hash = _sha(dd.read_file(spec.hub.d7_path))
        except OSError as e:
            d7_hash = rh.Unresolved(f"cannot read {spec.hub.d7_path}: {e}")
    out += verify_d7_live(spec, ks, d7_hash, (lambda c, p: ask_d7_hash(spec, c, p)) if ask is ASK else ask)
    return out
