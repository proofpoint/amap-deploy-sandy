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
- `evidence_dir`: where the key probe's record is placed, root-owned 0755
  under root-owned directories. It must be listed in
  `exposure.integrity_roots`, and verify fails any container that binds it
  or anything above it, read-only or not.
- `local_config`: the file the local router reads its config from. On a hop
  host, install refuses any path but the router.json it renders, and verify
  asks the running local router, from inside its container, which file its
  `ROUTER_CONFIG` names and that file's sha256. A delegation block here
  fails; its absence passes only when the router reads this file, byte for
  byte.

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
import secret_exposure as se
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
#: The config the local router reads, as its own process environment names
#: it (`ROUTER_CONFIG`, set by its docker/run.sh), and that file's sha256.
LIVE_CONFIG_SCRIPT = ("import hashlib,os,sys\n"
                      "p=os.environ['ROUTER_CONFIG']\n"
                      "sys.stdout.write(p+'\\t'+hashlib.sha256(open(p,'rb').read()).hexdigest()+'\\n')\n")
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
    volume: str               # the secret volume, the one mount the probe drops

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
    for o in [x for x in others if x != ev] + [d]:
        if _related(ev, o):
            raise KeySpecError(f"keys.evidence_dir {ev} overlaps {o}; no runtime may reach the evidence")
    p = spec.principals[local]
    return KeySpec(dir=d, file=sec["file"], evidence_dir=ev, local_config=cfg, principal=local, uid=p.uid,
                   gid=p.gids[0], volume=s.volume)


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
    p["mounts"] = [m for m in base["mounts"] if not _is_secret_volume(m, ks)]
    return p


def _is_secret_volume(m: Dict[str, Any], ks: KeySpec) -> bool:
    return m.get("type") == "volume" and m.get("source") == ks.volume


def expected_probe(base: Dict[str, Any], ks: KeySpec, run_id: str) -> Dict[str, Any]:
    """The exact probe spec, built field by field from the email router's
    and independently of probe_spec, for probe_diff to hold it to."""
    want: Dict[str, Any] = {k: copy.deepcopy(v) for k, v in base.items() if k != "mounts"}
    want.update({
        "name": base["name"] + "-" + PROBE_LABEL + "-" + run_id,
        "network": "none",
        "restart": "no",
        "labels": {"org.amap.oneshot": PROBE_LABEL, "org.amap.run": run_id},
        "entrypoint": "python3",
        "command": ["-I", "-S", "-c", PROBE_SCRIPT] + candidates(base, ks),
        "remove": True,
        "mounts": [copy.deepcopy(m) for m in base["mounts"]
                   if not (m["type"] == "volume" and m["source"] == ks.volume)],
    })
    return want


def probe_diff(base: Dict[str, Any], probe: Dict[str, Any], ks: KeySpec, run_id: str) -> List[str]:
    """Every field in which `probe` is not exactly the email router's spec
    with PROBE_CHANGES set to their one allowed value each and the one named
    secret volume removed: values are compared, not only which fields move."""
    want = expected_probe(base, ks, run_id)
    bad = [f"{k} is not the allowed value" if k in PROBE_CHANGES else f"{k} differs"
           for k in sorted(set(want) | set(probe)) if k != "mounts" and want.get(k) != probe.get(k)]
    if probe.get("mounts") != want["mounts"]:
        bad.append("its mounts are not the email router's without the secret volume")
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
    bad = probe_diff(base, probe, ks, rid)
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
    dd.write_atomically(path, data)
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


JSON_MAX_BYTES = 1 << 20


def _no_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"the key {k!r} appears twice")
        out[k] = v
    return out


def read_bytes(path: str) -> bytes:
    """A regular file's bytes, never through a symbolic link: read to EOF up
    to the bound plus one, refused when larger."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"{path} is not a regular file")
        raw = dd.read_bounded(fd, JSON_MAX_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > JSON_MAX_BYTES:
        raise ValueError(f"{path} is larger than {JSON_MAX_BYTES} bytes")
    return raw


def read_json(path: str) -> Any:
    """A regular file's JSON, read as `read_bytes` does, duplicate keys and
    NaN refused."""
    return parse_json(read_bytes(path))


def parse_json(raw: bytes) -> Any:
    """`raw` as JSON, duplicate keys and NaN refused."""

    def no_constant(name: str) -> Any:
        raise ValueError(f"{name} is not JSON")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_constant=no_constant)


_AT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


def parse_record(rec: Any) -> Optional[str]:
    """Why `rec` is not a well-formed probe record, or None."""
    if not isinstance(rec, dict) or set(rec) != RECORD_KEYS:
        return "not exactly the record's members"
    if any(not isinstance(v, str) for v in rec.values()):
        return "a member is not a string"
    if not _RUN_ID.fullmatch(rec["run_id"]) or not _AT.fullmatch(rec["at"]):
        return "run_id or at is malformed"
    if rec["result"] not in ("PASS", "FAIL"):
        return "result is neither PASS nor FAIL"
    if not all(_HEX64.fullmatch(rec[k]) for k in ("spec_sha256", "candidates_sha256", "probe_command_sha256")):
        return "a hash is not 64 lower-case hex"
    return None


def local_container(spec: Any, ks: KeySpec) -> str:
    """The local router's container: the router section's on a hop host
    (load_spec refuses a runtime that names another), else the keys
    principal's runtime's."""
    router = getattr(spec, "router", None)
    return router.container if router is not None else spec.runtime_of(ks.principal)["container"]


def ask_live_config(spec: Any, container: str) -> Any:
    """(path, sha256) of the config `container` reads, as its own environment
    names it, or an Unresolved naming why it could not be asked."""
    try:
        p = rh.run(ss.docker(spec.secrets) + ["exec", container, "python3", "-I", "-S", "-c", LIVE_CONFIG_SCRIPT])
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    if p.rc != 0:
        return rh.Unresolved(f"docker exec {container} exited {p.rc}")
    parts = p.out.rstrip("\n").split("\t")
    if len(parts) != 2 or not _HEX64.fullmatch(parts[1]):
        return rh.Unresolved(f"{container} printed no config path and hash")
    return parts[0], parts[1]


SIGNING_CLAIM = "the local router signs exactly as the policy and the gate allow"


@dataclass(frozen=True)
class Signing:
    """What decides whether the local router may sign, each as read now.
    `policy_on`: the policy's hop_link.delegation is present (bool), or
    Unresolved. `gate_ok`: the harness gate holds (gate_problems == []), or
    Unresolved. `approved`: A1's placed record, parsed; None when it is absent
    or invalid (`approved_why` says which); Unresolved when it cannot be read.
    `named(token)`: partition_evidence.named_document for this host.
    `status`: the local router's status.json document, or Unresolved.
    `witness(host_sha)`: `adoption` over the router's container, its result.
    `now`: epoch s."""
    policy_on: Any
    gate_ok: Any
    approved: Any
    approved_why: str
    named: Callable[[str], Tuple[Any, Any, str]]
    status: Any
    witness: Callable[[str], Tuple[str, str]]
    now: float


def _member(doc: Dict[str, Any]) -> bytes:
    """The delegation member as compared: canonical JSON, the token removed."""
    block = dict(doc[DELEGATION_KEY])
    block.pop("partition_verified", None)
    return json.dumps(block, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _verdict(doc: Dict[str, Any], policy_on: bool, gate_ok: bool, sg: Signing) -> Tuple[str, str]:
    """(PASS | FAIL | UNKNOWN, why) for one value of the policy and the gate:
    d2's matrix, row by row."""
    import partition_evidence as pe
    present = DELEGATION_KEY in doc
    if not policy_on:
        return (rh.FAIL, "it signs, and the policy does not enable delegation for this host") if present \
            else (rh.PASS, "it does not sign, and the policy does not enable it")
    if not gate_ok:
        return (rh.FAIL, "it signs while the harness gate does not hold: the fail-stop case") if present \
            else (rh.PASS, "it does not sign: the gate does not hold")
    if not present:
        return rh.UNKNOWN, "NOT YET ACTIVATED: the policy and the gate allow signing, and the router does not sign"
    if isinstance(sg.approved, rh.Unresolved):
        return rh.UNKNOWN, f"A1's placed record cannot be read: {sg.approved.reason}"
    if sg.approved is None:
        return rh.FAIL, f"it signs, and there is no approved activation to compare the block with: {sg.approved_why}"
    try:
        staged = parse_json(sg.approved["staged"].encode("utf-8"))
        same = isinstance(staged, dict) and DELEGATION_KEY in staged and _member(staged) == _member(doc)
    except (ValueError, TypeError):
        same = False
    if not same:
        return rh.FAIL, "its delegation block is not A1's approved block"
    token = doc[DELEGATION_KEY].get("partition_verified") if isinstance(doc[DELEGATION_KEY], dict) else None
    named, raw, why = sg.named(token)
    if named is None:
        return rh.FAIL, f"its token's named document does not hold: {why}"
    age = sg.now - pe.at_seconds(named["at"])
    if age > pe.FRESH_FOR_S or age < -pe.CLOCK_TOLERANCE_S:
        return rh.FAIL, f"its token's document ({named['run_id']}) is not current: re-run A2 to A5, or un-render"
    return rh.PASS, f"it signs under the token of {named['run_id']}, current and passing"


def verify_signing(ks: KeySpec, raw: Any, bind: rh.Check, sg: Signing) -> rh.Check:
    """d2's matrix over the policy, the gate and the live config, held to
    A1's placed record and the token's named document, and to the router's
    own status.json. An input that cannot be read decides nothing: the
    verdict is the one every value of it gives, else UNKNOWN. Evidence
    bindings are not re-checked here (they stat the key's 0700 directory,
    which only root can): the weekly run holds the document to them."""
    claim = SIGNING_CLAIM
    want = _fact("signing", True, "the policy's hop_link.delegation, the harness gate, A1's placed record "
                                  "and the token's named document")
    remedy = (f"make {ks.local_config} what the policy and the gate allow: install --apply renders it without "
              "delegation; activation is A1 to A5")
    if isinstance(raw, rh.Unresolved):
        return rh.unknown(claim, want, raw.reason, "render and place the local router's config")
    try:
        doc = parse_json(raw)
    except ValueError as e:
        return rh.unknown(claim, want, f"{ks.local_config} is not readable JSON: {e}", "render it again")
    if not isinstance(doc, dict):
        return rh.unknown(claim, want, f"{ks.local_config} is not a JSON object", "render it again")
    status = sg.status
    section = status.get("classification") if isinstance(status, dict) else None
    if isinstance(section, dict) and section.get("config_reload_failed") is True:
        return rh.check(claim, want, "the running router refused its config file and runs an older one",
                        f"correct {ks.local_config}, then restart the local router with docker/run.sh --detach (A4)",
                        do_not="never read the file as what the router runs while the flag is set")
    unknown_inputs = [v.reason for v in (sg.policy_on, sg.gate_ok) if isinstance(v, rh.Unresolved)]
    seen = {_verdict(doc, p, g, sg)
            for p in ((sg.policy_on,) if isinstance(sg.policy_on, bool) else (False, True))
            for g in ((sg.gate_ok,) if isinstance(sg.gate_ok, bool) else (False, True))}
    results = {r for r, _ in seen}
    if len(results) > 1:
        return rh.unknown(claim, want, "the verdict depends on what could not be read: " + "; ".join(unknown_inputs),
                          "make the policy and the harness gate readable")
    result, why = sorted(seen)[0]
    if result == rh.FAIL:
        return rh.check(claim, want, why, remedy, do_not="never add or keep a delegation block by hand")
    if result == rh.UNKNOWN:
        return rh.unknown(claim, want, why, "complete A1 to A5" if why.startswith("NOT YET") else remedy)
    if bind.result is not rh.PASS:
        return rh.unknown(claim, want, f"{why}, but the local router is not shown to read {ks.local_config}: "
                                       f"{bind.reason or 'it reads another file'}", "make the binding above pass")
    return _status_witness(claim, want, why, ks, sg, remedy, _sha(raw))


#: The config the local router reads, read from inside its container in one
#: exec: its identity, its change time, its size, its bytes' sha256, and the
#: container's own clock.
CONFIG_TUPLE_SCRIPT = ("import hashlib,json,os,time\n"
                       "p=os.environ['ROUTER_CONFIG']\n"
                       "fd=os.open(p,os.O_RDONLY)\n"
                       "st=os.fstat(fd)\n"
                       "b=b''\n"
                       "while True:\n"
                       "    c=os.read(fd,65536)\n"
                       "    if not c: break\n"
                       "    b+=c\n"
                       "print(json.dumps({'dev':st.st_dev,'ino':st.st_ino,'ctime_ns':st.st_ctime_ns,'size':st.st_size,"
                       "'sha256':hashlib.sha256(b).hexdigest(),'now':time.time()}))\n")
TUPLE_KEYS = ("dev", "ino", "ctime_ns", "size", "sha256")
#: How long the config must have been quiet before the window opens: at
#: least twice the largest ctime tick a capability record may declare
#: (TICK_BOUND_MAX_NS), so no qualifying share can hide an edit inside it.
CTIME_SETTLE_S = 2
#: The host's recorded qualification of this witness: placed by root beside
#: the partition evidence, from the probe run on a throwaway container.
CAPABILITY_NAME = "config-witness.json"
CAPABILITY_SCHEMA = "amap-deploy.config-witness/1"
CAPABILITY_MEMBERS = frozenset({"schema", "host", "engine", "at", "share", "tick_bound_ns", "visible_within_s",
                                "rename", "writes"})
#: The largest ctime tick the witness accepts, and the write paths it covers.
TICK_BOUND_MAX_NS = 1_000_000_000
WRITE_PATHS = ["write", "rename"]


def capability_problem(cap: Any, *, host: Any, engine: Any, host_dev: Any, container_dev: Any,
                       interval_s: Any) -> str:
    """Why the host's recorded capability does not qualify the witness here,
    or "" when it does. An absent or unreadable record never qualifies."""
    if isinstance(cap, rh.Unresolved):
        return f"no qualifying capability record: {cap.reason}"
    if not isinstance(cap, dict) or set(cap) != CAPABILITY_MEMBERS or cap["schema"] != CAPABILITY_SCHEMA:
        return "the capability record is not exactly its members and schema"
    if cap["host"] != host or cap["engine"] != engine:
        return "the capability record is another host's or another engine's"
    if cap["share"] != {"host_dev": host_dev, "container_dev": container_dev}:
        return "the capability record was measured on another share than the live config's"
    tick, visible, rename = cap["tick_bound_ns"], cap["visible_within_s"], cap["rename"]
    if not isinstance(tick, int) or isinstance(tick, bool) or not 0 < tick <= TICK_BOUND_MAX_NS:
        return "the share's ctime tick is unbounded or longer than one second"
    if not isinstance(visible, (int, float)) or isinstance(visible, bool) or not isinstance(interval_s, (int, float)) \
            or not 0 <= visible < interval_s:
        return "a host write is not shown in the container within one poll interval"
    if not isinstance(rename, dict) or not (rename.get("bytes_changed") is True
                                            or rename.get("ino_or_ctime_changed") is True):
        return "a host rename-replace is invisible in the container"
    if cap["writes"] != WRITE_PATHS:
        return "the capability record does not cover every supported write path"
    return ""


def ask_config_tuple(spec: Any, container: str) -> Any:
    try:
        p = rh.run(ss.docker(spec.secrets) + ["exec", container, "python3", "-I", "-S", "-c", CONFIG_TUPLE_SCRIPT])
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    if p.rc != 0:
        return rh.Unresolved(f"docker exec {container} could not read its config (exit {p.rc})")
    try:
        doc = json.loads(p.out)
    except ValueError:
        return rh.Unresolved(f"{container} printed no config identity")
    ok = isinstance(doc, dict) and all(isinstance(doc.get(k), int) and not isinstance(doc.get(k), bool)
                                       for k in ("dev", "ino", "ctime_ns", "size")) \
        and isinstance(doc.get("sha256"), str) and _HEX64.fullmatch(doc["sha256"]) \
        and isinstance(doc.get("now"), (int, float))
    return doc if ok else rh.Unresolved(f"{container} printed a malformed config identity")


def adoption(read_tuple: Callable[[], Any], read_status: Callable[[], Any], host_sha: str, *,
             capability: Callable[[Any, Any], Tuple[str, Any]], host_settle: Callable[[], Any],
             sleep: Callable[[float], None] = time.sleep) -> Tuple[str, str]:
    """(PASS | FAIL | UNKNOWN, why): the running local router runs the
    config the host holds now, by order and by a change generation, never by
    a clock compared with a file. 1: the file the router reads, from inside
    its container, is the host's bytes, quiet for CTIME_SETTLE_S on the
    container's own clock. 2-4: its status shows two more polls by the same
    process (the second poll's reload began after step 1), the last with no
    refused reload. 5: the file it reads has the same device, inode, change
    time, size and bytes: any write to it moved its ctime, which restoring
    the bytes cannot undo, so every reload in the window read those bytes.
    `capability(container_dev, interval_s)` gives ("", the record) when the
    host's recorded capability qualifies the witness here, else (why, None);
    `host_settle()` gives the host's ctime of the live config and the host's
    clock, in one host step, since the host stamps ctime."""
    t1 = read_tuple()
    if isinstance(t1, rh.Unresolved):
        return rh.UNKNOWN, f"the config the router reads cannot be identified: {t1.reason}"
    if t1["sha256"] != host_sha:
        return rh.UNKNOWN, "the router reads other bytes than the host's file (an old bind, or a replacement)"
    s0 = read_status()
    if isinstance(s0, rh.Unresolved):
        return rh.UNKNOWN, f"the router's status.json cannot be read: {s0.reason}"
    polls, started, interval = s0.get("polls"), s0.get("started_ts"), s0.get("interval_s")
    if not isinstance(polls, int) or isinstance(polls, bool) or not isinstance(started, str) \
            or not isinstance(interval, (int, float)) or isinstance(interval, bool) or interval <= 0:
        return rh.UNKNOWN, "status.json carries no polls, started_ts or interval_s"
    why, cap = capability(t1["dev"], interval)
    if why:
        return rh.UNKNOWN, why
    settled = host_settle()
    if isinstance(settled, rh.Unresolved):
        return rh.UNKNOWN, f"the host's view of the live config cannot be read: {settled.reason}"
    host_ctime_ns, host_now = settled
    if host_now - host_ctime_ns / 1e9 < CTIME_SETTLE_S:
        return rh.UNKNOWN, "the config changed moments ago; run verify again"
    waited, bound = 0.0, (2 + rh.FRESHNESS_MULTIPLE) * interval
    while True:
        sleep(interval / 2)
        waited += interval / 2
        s = read_status()
        if isinstance(s, rh.Unresolved):
            return rh.UNKNOWN, f"the router's status.json cannot be read: {s.reason}"
        if s.get("started_ts") != started:
            return rh.UNKNOWN, "the router restarted while verify watched it; run verify again"
        if isinstance(s.get("polls"), int) and s["polls"] >= polls + 2:
            break
        if waited >= bound:
            return rh.UNKNOWN, f"the router did not poll twice within {bound:.0f}s"
    section = s.get("classification")
    if isinstance(section, dict) and section.get("config_reload_failed") is True:
        return rh.FAIL, "the running router refused its config file and runs an older one"
    sleep(cap["visible_within_s"])      # a write inside the window is visible to step 5
    t5 = read_tuple()
    if isinstance(t5, rh.Unresolved):
        return rh.UNKNOWN, f"the config the router reads cannot be identified again: {t5.reason}"
    if any(t5[k] != t1[k] for k in TUPLE_KEYS) or t5["sha256"] != host_sha:
        return rh.UNKNOWN, "the config the router reads changed while verify watched it; run verify again"
    return rh.PASS, "the router adopted the host's config: two polls on unchanged bytes"


def _status_witness(claim: str, want: rh.Fact, why: str, ks: KeySpec, sg: Signing, remedy: str,
                    host_sha: str) -> rh.Check:
    """A PASS needs the adoption witness (`adoption`)."""
    result, reason = sg.witness(host_sha)
    if result == rh.PASS:
        return rh.check(claim, want, True, remedy)
    if result == rh.FAIL:
        return rh.check(claim, want, reason, f"correct {ks.local_config}, then restart the local router with "
                                             "docker/run.sh --detach (A4)")
    return rh.unknown(claim, want, f"{why}; {reason}", "start the local router, or let it run, then run verify again")


#: The local router's own status document, read from inside its container:
#: the state_dir its config names, and status.json there.
STATUS_SCRIPT = ("import json,os,sys\n"
                 "c=json.load(open(os.environ['ROUTER_CONFIG']))\n"
                 "sys.stdout.write(open(os.path.join(c['state_dir'],'status.json')).read())\n")


def ask_status(spec: Any, container: str) -> Any:
    """The local router's status.json, as it wrote it, or an Unresolved."""
    try:
        p = rh.run(ss.docker(spec.secrets) + ["exec", container, "python3", "-I", "-S", "-c", STATUS_SCRIPT])
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    if p.rc != 0:
        return rh.Unresolved(f"docker exec {container} could not read its status.json (exit {p.rc})")
    try:
        doc = parse_json(p.out.encode("utf-8"))
    except ValueError as e:
        return rh.Unresolved(f"{container}'s status.json is not JSON: {e}")
    return doc if isinstance(doc, dict) else rh.Unresolved(f"{container}'s status.json is not an object")


def verify_no_delegation(ks: KeySpec, live: Any = None,
                         read_bytes_: Callable[[str], bytes] = read_bytes, signing: Optional[Signing] = None
                         ) -> List[rh.Check]:
    """The local router reads `local_config`, byte for byte (`live`, from
    inside its container), and signs exactly as the policy and the gate
    allow (`verify_signing`). One read of the file is both hashed and
    judged, so the decision is about the bytes the binding compared."""
    out: List[rh.Check] = []
    bind_claim = f"the local router reads {ks.local_config}, byte for byte the host's copy"
    try:
        raw: Any = read_bytes_(ks.local_config)
        host_sha: Any = _sha(raw)
    except FileNotFoundError:
        raw = host_sha = rh.Unresolved(f"{ks.local_config} is absent")
    except (OSError, ValueError) as e:
        raw = host_sha = rh.Unresolved(f"cannot read {ks.local_config}: {e}")
    bind_want = _fact("live config", (ks.local_config, host_sha if isinstance(host_sha, str) else None),
                      "keys.local_config, which install binds to the router.json it renders, and its bytes "
                      "on the host")
    bind_remedy = (f"start the local router with docker/run.sh --config {ks.local_config}, the file install "
                   "renders, and never a copy")
    if isinstance(host_sha, rh.Unresolved):
        bind = rh.unknown(bind_claim, bind_want, host_sha.reason, "render and place the local router's config")
    elif live is None or isinstance(live, rh.Unresolved):
        bind = rh.unknown(bind_claim, bind_want, live.reason if live is not None else "the local router was "
                          "not asked", "start the local router, or make the engine answer")
    else:
        bind = rh.check(bind_claim, bind_want, tuple(live), bind_remedy,
                        do_not="never point keys.local_config at the file the router happens to read")
    out.append(bind)
    sg = signing or Signing(policy_on=rh.Unresolved("the policy was not read"),
                            gate_ok=rh.Unresolved("the harness gate was not read"),
                            approved=rh.Unresolved("A1's record was not read"), approved_why="",
                            named=lambda t: (None, None, "the evidence was not read"),
                            status=rh.Unresolved("the local router's status.json was not read"),
                            witness=lambda h: (rh.UNKNOWN, "the local router was not watched"), now=time.time())
    return out + [verify_signing(ks, raw, bind, sg)]


def verify_evidence_dir(ks: KeySpec, lstat: Callable) -> List[rh.Check]:
    why = "the probe's record is trusted only as root placed it"
    st = _lst(ks.evidence_dir, lstat)
    claim = f"the evidence directory {ks.evidence_dir} is a root-owned 0755 directory"
    want = _fact("evidence dir", (0, 0, 0o755), why)
    remedy = f"create it as the plan does: install -d -o 0 -g 0 -m 0755 {ks.evidence_dir}"
    if isinstance(st, rh.Unresolved):
        out = [rh.unknown(claim, want, st.reason, remedy)]
    elif st is None or not stat.S_ISDIR(st.st_mode):
        out = [rh.check(claim, want, "absent" if st is None else "not a directory", remedy)]
    else:
        out = [rh.check(claim, want, (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)), remedy)]
    out.append(ss._owned_chain(f"every directory above {ks.evidence_dir} is root-owned and not group- or "
                               f"world-writable", ks.evidence_dir, (0,), why, lstat))
    return out


def ask_containers(spec: Any) -> Any:
    """[(engine, inspect document)] for every container on this host's
    engines, or an Unresolved."""
    s = spec.secrets
    ctx = se.contexts(s)
    if isinstance(ctx, rh.Unresolved):
        return ctx
    found = []
    for name, endpoint in ctx:
        if not se.local(endpoint):
            continue
        cs = se.containers(s, name)
        if isinstance(cs, rh.Unresolved):
            return cs
        found += [(name, c) for c in cs if isinstance(c, dict)]
    return found


def verify_evidence_binds(ks: KeySpec, containers: Any, stat_: Callable = os.stat,
                          realpath: Callable[[str], str] = os.path.realpath) -> List[rh.Check]:
    """No container binds the evidence directory, or anything above or
    inside it, read-only or not."""
    claim = f"no container binds {ks.evidence_dir} or anything above it"
    want = _fact("binds", [], "a container that can see the evidence can be argued to have shaped it; "
                              "none may mount it at all")
    remedy = "remove the bind"
    if isinstance(containers, rh.Unresolved):
        return [rh.unknown(claim, want, containers.reason, "make every engine answer")]
    bad, unk = [], []
    for engine, c in containers:
        b, u = se.rule_overlap(c, [ks.evidence_dir], [], stat_, realpath)
        bad += [f"{engine}/{se._name(c)} {x}" for x in b]
        unk += [f"{engine}/{se._name(c)} {x}" for x in u]
    if bad:
        return [rh.check(claim, want, bad, remedy)]
    if unk:
        return [rh.unknown(claim, want, "; ".join(unk), remedy)]
    return [rh.check(claim, want, [], remedy)]


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
    why = parse_record(rec)
    if why is not None:
        out.append(rh.check(claim, want, f"the record is malformed: {why}", remedy))
        return out
    probe = probe_spec(base, ks, rec["run_id"])
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
           d7_hash: Any = ASK, ask: Any = ASK, containers: Any = ASK, stat_: Callable = os.stat,
           realpath: Callable[[str], str] = os.path.realpath, live: Any = ASK,
           read_bytes_: Callable[[str], bytes] = read_bytes, signing: Optional[Signing] = None) -> List[rh.Check]:
    out = verify_placement(ks, lstat)
    out += verify_no_delegation(ks, ask_live_config(spec, local_container(spec, ks)) if live is ASK else live,
                                read_bytes_, signing)
    out += verify_evidence_dir(ks, lstat)
    out += verify_evidence_binds(ks, ask_containers(spec) if containers is ASK else containers, stat_, realpath)
    out += verify_evidence(spec, ks, lstat, read_json_)
    if d7_hash is ASK:
        try:
            d7_hash = _sha(dd.read_file(spec.hub.d7_path))
        except OSError as e:
            d7_hash = rh.Unresolved(f"cannot read {spec.hub.d7_path}: {e}")
    out += verify_d7_live(spec, ks, d7_hash, (lambda c, p: ask_d7_hash(spec, c, p)) if ask is ASK else ask)
    return out
