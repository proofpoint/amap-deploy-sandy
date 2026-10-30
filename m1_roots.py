"""m1_roots.py: D-ROOTS, the M1 VM's mutable roots on its state disk.
Standard library only.

D-ROOTS runs once per VM, after first boot and before the overlay is installed
(the LIFECYCLE's S4). It creates the roots the role spec names on the mounted
state disk, installs the registry's reviewed host.json (HOSTJ), and copies
sandy's build-hash dotfiles. This module writes nothing itself: every write is
a `host_steps.py` root step, run as root by the operator from the printed plan.

  python3 -I -S amap-m1-roots.py plan --spec SPEC
      the plan: the writer's and the seed copy's sha checks, the mount check,
      one `root` step per root, HOSTJ's `install`, the syncs, the seed copy,
      and the receipt. Read-only.
  python3 -I -S amap-m1-roots.py check-mount --spec SPEC
      exit 0 only when the state disk is mounted at `data` from the device
      whose filesystem UUID is `data_uuid`.
  python3 -I -S amap-m1-roots.py receipt --spec SPEC
      run as root, after the plan: one JSON receipt on stdout. Exit 0 only when
      every root is a real directory with exactly its owner and mode and no
      ACL, the registry directory holds exactly {host.json}, host.json is
      HOSTJ by sha, owned by the registry's uid at 0600, and the state
      directory and the identities directory are empty.

The spec is the role's reviewed parameters, a closed JSON object:

  schema         "amap-m1-roots/1"
  data           the state disk's mountpoint, absolute
  data_uuid      its filesystem UUID
  python3        the interpreter root runs, absolute
  writer         host_steps.py, absolute; writer_sha256 its sha256
  roots          [{path, uid, gid, mode, role}], parents first; every path under
                 `data`, and each one's parent is `data` or an earlier root.
                 Roles: sandy_home, run_dir, state_dir, registry, identities
                 (each exactly once), workspace, dir.
  hostj          {path, sha256}: the reviewed host.json to install
  seed_copy      {path, sha256, uid, argv}: the m1-seed-copy program, the uid it
                 runs as, and its whole argv, which names `path` exactly once. The
                 plan stops unless it exits 0 AND its last stdout line starts
                 `M1-SEED-COPY PASS`.

Exit codes: 0 pass, 1 a check failed, 2 the spec cannot be used."""

import hashlib
import json
import os
import re
import shlex
import stat
import sys
from typing import Any, Callable, Dict, List, Optional

import host_steps as hs

SCHEMA = "amap-m1-roots/1"
RECEIPT_SCHEMA = "amap-m1-roots-receipt/1"
SPEC_KEYS = frozenset({"schema", "data", "data_uuid", "python3", "writer", "writer_sha256", "roots", "hostj",
                       "seed_copy"})
ROOT_KEYS = frozenset({"path", "uid", "gid", "mode", "role"})
#: The roles that must each appear exactly once, and the ones that may repeat.
ONCE = ("sandy_home", "run_dir", "state_dir", "registry", "identities")
ROLES = frozenset(ONCE) | {"workspace", "dir"}
#: The modes a root may have. The registry, identities and state roots are 0700 only.
ROOT_MODES = (0o700, 0o750, 0o755)
PRIVATE_ROLES = ("state_dir", "registry", "identities")
HOSTJ_NAME = "host.json"
#: m1-seed-copy's last stdout line on success; exit 0 without it does not pass.
SEED_PASS = "M1-SEED-COPY PASS"
HOSTJ_MODE = 0o600
MOUNTINFO = "/proc/self/mountinfo"
BY_UUID = "/dev/disk/by-uuid"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_UUID = re.compile(r"[0-9a-fA-F-]{8,36}")

EXIT_PASS, EXIT_FAIL, EXIT_SPEC = 0, 1, 2


class SpecError(Exception):
    pass


def _abs(v: Any, what: str) -> str:
    if not isinstance(v, str) or not v.startswith("/") or os.path.normpath(v) != v or v.startswith("//"):
        raise SpecError(f"{what} must be an absolute, normalised path")
    return v


def _sha(v: Any, what: str) -> str:
    if not isinstance(v, str) or not _HEX64.fullmatch(v):
        raise SpecError(f"{what} must be 64 lowercase hex characters")
    return v


def _id(v: Any, what: str) -> int:
    if not isinstance(v, int) or isinstance(v, bool) or v < 1:
        raise SpecError(f"{what} must be a positive integer (never root)")
    return v


def load_spec(doc: Any) -> Dict[str, Any]:
    """The spec, checked whole: an unknown or missing key, a path outside
    `data`, a root whose parent is not created first, a role out of place,
    or an owner or mode other than the role's refuses the spec."""
    if not isinstance(doc, dict) or set(doc) != SPEC_KEYS:
        raise SpecError("the spec must have exactly: " + ", ".join(sorted(SPEC_KEYS)))
    if doc["schema"] != SCHEMA:
        raise SpecError(f"schema must be {SCHEMA!r}")
    data = _abs(doc["data"], "data")
    if data == "/":
        raise SpecError("data must not be /")
    if not isinstance(doc["data_uuid"], str) or not _UUID.fullmatch(doc["data_uuid"]):
        raise SpecError("data_uuid must be a filesystem UUID")
    _abs(doc["python3"], "python3")
    _abs(doc["writer"], "writer")
    _sha(doc["writer_sha256"], "writer_sha256")
    roots = doc["roots"]
    if not isinstance(roots, list) or not roots:
        raise SpecError("roots must be a non-empty list")
    made = {data}
    seen: Dict[str, Dict[str, Any]] = {}
    for i, r in enumerate(roots):
        if not isinstance(r, dict) or set(r) != ROOT_KEYS:
            raise SpecError(f"roots[{i}] must have exactly: " + ", ".join(sorted(ROOT_KEYS)))
        path = _abs(r["path"], f"roots[{i}].path")
        if not path.startswith(data + "/"):
            raise SpecError(f"roots[{i}].path is not under data")
        if path in made:
            raise SpecError(f"roots[{i}].path is listed twice")
        if os.path.dirname(path) not in made:
            raise SpecError(f"roots[{i}].path's parent is neither data nor an earlier root")
        _id(r["uid"], f"roots[{i}].uid")
        _id(r["gid"], f"roots[{i}].gid")
        if not isinstance(r["mode"], str) or not re.fullmatch(r"0[0-7]{3}", r["mode"]) \
                or int(r["mode"], 8) not in ROOT_MODES:
            raise SpecError(f"roots[{i}].mode must be one of " + ", ".join(f"{m:04o}" for m in ROOT_MODES))
        if r["role"] not in ROLES:
            raise SpecError(f"roots[{i}].role must be one of " + ", ".join(sorted(ROLES)))
        if r["role"] in PRIVATE_ROLES and r["mode"] != "0700":
            raise SpecError(f"roots[{i}]: a {r['role']} root is 0700 only")
        if r["role"] in ONCE:
            if r["role"] in seen:
                raise SpecError(f"roots: role {r['role']!r} appears twice")
            seen[r["role"]] = r
        made.add(path)
    missing = [k for k in ONCE if k not in seen]
    if missing:
        raise SpecError("roots: missing role(s) " + ", ".join(missing))
    reg, ids = seen["registry"], seen["identities"]
    if (reg["uid"], reg["gid"]) != (ids["uid"], ids["gid"]):
        raise SpecError("the registry and identities roots must have the same owner, the registry's uid")
    h = doc["hostj"]
    if not isinstance(h, dict) or set(h) != {"path", "sha256"}:
        raise SpecError("hostj must have exactly: path, sha256")
    _abs(h["path"], "hostj.path")
    _sha(h["sha256"], "hostj.sha256")
    c = doc["seed_copy"]
    if not isinstance(c, dict) or set(c) != {"path", "sha256", "uid", "argv"}:
        raise SpecError("seed_copy must have exactly: argv, path, sha256, uid")
    _abs(c["path"], "seed_copy.path")
    _sha(c["sha256"], "seed_copy.sha256")
    if c["uid"] != seen["sandy_home"]["uid"]:
        raise SpecError("seed_copy.uid must be sandy_home's owner")
    if not isinstance(c["argv"], list) or not c["argv"] or not all(isinstance(a, str) and a for a in c["argv"]) \
            or c["argv"].count(c["path"]) != 1:
        raise SpecError("seed_copy.argv must be non-empty strings naming seed_copy.path exactly once")
    return doc


def roles(spec: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {r["role"]: r for r in spec["roots"] if r["role"] in ONCE}


def hostj_dest(spec: Dict[str, Any]) -> str:
    return roles(spec)["registry"]["path"] + "/" + HOSTJ_NAME


def plan(spec: Dict[str, Any], launcher: str, spec_path: str) -> List[str]:
    """The operator's lines, in order. Each root line runs the pinned writer;
    nothing runs before the writer's own sha check, and the seed copy runs
    only after its program's sha check."""
    q = shlex.quote
    py, w = spec["python3"], spec["writer"]
    root_py = f"sudo {q(py)} -I -S -B {q(w)}"
    reg = roles(spec)["registry"]
    c = spec["seed_copy"]
    lines = [
        "# D-ROOTS (S4). Run each line in order; stop at the first that fails.",
        f"printf '%s  %s\\n' {spec['writer_sha256']} {q(w)} | sha256sum -c --strict -",
        f"{q(py)} -I -S {q(launcher)} check-mount --spec {q(spec_path)}",
    ]
    for r in spec["roots"]:
        lines.append(f"{root_py} root {q(r['path'])} {r['uid']} {r['gid']} {r['mode']}")
    lines.append(f"{root_py} install {q(spec['hostj']['path'])} {q(hostj_dest(spec))} {reg['uid']} {reg['gid']} "
                 f"--sha256 {spec['hostj']['sha256']} --mode {HOSTJ_MODE:04o}")
    lines.append(f"{root_py} sync {q(spec['data'])} " + " ".join(q(r["path"]) for r in spec["roots"]))
    lines.append(f"printf '%s  %s\\n' {c['sha256']} {q(c['path'])} | sha256sum -c --strict - && "
                 f"out=$(sudo -u '#{c['uid']}' -- " + " ".join(q(a) for a in c["argv"]) + ") && "
                 f"printf '%s\\n' \"$out\" && printf '%s\\n' \"$out\" | tail -n 1 | "
                 f"grep -q '^{SEED_PASS} '")
    lines.append(f"sudo {q(py)} -I -S {q(launcher)} receipt --spec {q(spec_path)}")
    return lines


def _unescape(field: str) -> str:
    """A mountinfo path field: octal escapes (\\040 for a space) decoded."""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), field)


def mount_problem(spec: Dict[str, Any], mountinfo: str,
                  realpath: Callable[[str], str] = os.path.realpath) -> Optional[str]:
    """Why `data` is not the state disk, or None. The LAST mountinfo line for
    the mountpoint is what a path there reaches; its source device must be
    the one /dev/disk/by-uuid names for `data_uuid`."""
    data = spec["data"]
    source = None
    for line in mountinfo.splitlines():
        parts = line.split(" - ", 1)
        head = parts[0].split()
        if len(parts) != 2 or len(head) < 5:
            continue
        if _unescape(head[4]) == data:
            tail = parts[1].split()
            source = tail[1] if len(tail) >= 2 else None
    if source is None:
        return f"{data} is not a mountpoint"
    want = realpath(os.path.join(BY_UUID, spec["data_uuid"]))
    if not want.startswith("/dev/") or realpath(source) != want:
        return f"{data} is mounted from {source}, not the device with UUID {spec['data_uuid']}"
    return None


def _dir_record(path: str) -> Dict[str, Any]:
    fd = hs.open_dir(path)
    try:
        st = os.fstat(fd)
        names = sorted(os.listdir(fd))
    finally:
        os.close(fd)
    return {"path": path, "uid": st.st_uid, "gid": st.st_gid, "mode": f"{stat.S_IMODE(st.st_mode):04o}",
            "entries": names}


def _hostj_record(spec: Dict[str, Any]) -> Dict[str, Any]:
    reg = roles(spec)["registry"]["path"]
    dfd = hs.open_dir(reg)
    try:
        fd = os.open(HOSTJ_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise OSError(0, "not a regular file")
            h = hashlib.sha256()
            while True:
                chunk = os.read(fd, 1 << 16)
                if not chunk:
                    break
                h.update(chunk)
        finally:
            os.close(fd)
    finally:
        os.close(dfd)
    return {"uid": st.st_uid, "gid": st.st_gid, "mode": f"{stat.S_IMODE(st.st_mode):04o}", "nlink": st.st_nlink,
            "sha256": h.hexdigest()}


def receipt(spec: Dict[str, Any], mountinfo: str, realpath: Callable[[str], str] = os.path.realpath,
            acl: Callable[[List[str]], List[str]] = hs.acl_problems) -> Dict[str, Any]:
    """What is on the state disk now, against the spec. Reads only."""
    problems: List[str] = []
    m = mount_problem(spec, mountinfo, realpath)
    if m:
        problems.append(m)
    records = []
    by_role = roles(spec)
    for r in spec["roots"]:
        try:
            rec = _dir_record(r["path"])
        except (hs.StepError, OSError) as e:
            problems.append(f"{r['path']}: not a real directory ({e})")
            continue
        rec["role"] = r["role"]
        records.append(rec)
        want = (r["uid"], r["gid"], r["mode"])
        if (rec["uid"], rec["gid"], rec["mode"]) != want:
            problems.append(f"{r['path']}: {rec['uid']}:{rec['gid']} {rec['mode']}, not "
                            f"{r['uid']}:{r['gid']} {r['mode']}")
    problems += acl([r["path"] for r in spec["roots"]])
    rec_by_path = {x["path"]: x for x in records}
    for role in ("state_dir", "identities"):
        rec = rec_by_path.get(by_role[role]["path"])
        if rec is not None and rec["entries"]:
            problems.append(f"{rec['path']}: the {role} root is not empty")
    reg = by_role["registry"]
    hostj = None
    rec = rec_by_path.get(reg["path"])
    if rec is not None:
        if rec["entries"] != [HOSTJ_NAME]:
            problems.append(f"{reg['path']} holds {rec['entries']}, not exactly [{HOSTJ_NAME!r}]")
        if HOSTJ_NAME in rec["entries"]:
            try:
                hostj = _hostj_record(spec)
            except (hs.StepError, OSError) as e:
                problems.append(f"{hostj_dest(spec)}: cannot be read ({e})")
            else:
                want = {"uid": reg["uid"], "gid": reg["gid"], "mode": f"{HOSTJ_MODE:04o}", "nlink": 1,
                        "sha256": spec["hostj"]["sha256"]}
                for k, v in want.items():
                    if hostj[k] != v:
                        problems.append(f"{hostj_dest(spec)}: {k} is {hostj[k]!r}, not {v!r}")
                problems += acl([hostj_dest(spec)])
    return {"schema": RECEIPT_SCHEMA, "result": "FAIL" if problems else "PASS",
            "hostj_sha256": spec["hostj"]["sha256"], "hostj": hostj, "roots": records, "problems": problems}


def _read_spec(path: str) -> Dict[str, Any]:
    try:
        with open(path, "rb") as f:
            raw = f.read(1 << 20)
        doc = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError) as e:
        raise SpecError(f"the spec cannot be read: {e}") from None
    return load_spec(doc)


def _mountinfo() -> str:
    with open(MOUNTINFO, encoding="utf-8", errors="replace") as f:
        return f.read()


def main(argv: List[str], launcher: str = "amap-m1-roots.py") -> int:
    if len(argv) != 3 or argv[0] not in ("plan", "check-mount", "receipt") or argv[1] != "--spec":
        print(__doc__.split("\n\n")[2], file=sys.stderr)
        return EXIT_SPEC
    try:
        spec = _read_spec(argv[2])
    except SpecError as e:
        print(f"m1-roots: {e}", file=sys.stderr)
        return EXIT_SPEC
    if argv[0] == "plan":
        for line in plan(spec, launcher, argv[2]):
            print(line)
        return EXIT_PASS
    try:
        info = _mountinfo()
    except OSError as e:
        print(f"m1-roots: {MOUNTINFO} cannot be read: {e}", file=sys.stderr)
        return EXIT_SPEC
    if argv[0] == "check-mount":
        problem = mount_problem(spec, info)
        print(f"m1-roots: {problem}" if problem else f"m1-roots: mount OK {spec['data']}",
              file=sys.stderr if problem else sys.stdout)
        return EXIT_FAIL if problem else EXIT_PASS
    doc = receipt(spec, info)
    print(json.dumps(doc, sort_keys=True, separators=(",", ":")))
    return EXIT_PASS if doc["result"] == "PASS" else EXIT_FAIL
