"""router-migrate: the local router's migration from state keyed by instance
name to the pinned router's generation layout under the registry, as its own
window (the runbook's R2), before any activation.

Every router step runs the PINNED router's own code: the hop checkout's
`docker/run.sh` (its identity mounts, as the operator's uid), with
`--image` set to the host-setup document's `router.image.digest`, in the
entrypoint's `shell` mode. Nothing here writes the live config.

- `map`: the name -> logical_id mapping and each binding, printed by
  MAP_PROGRAM, the router maintainers' read-only program over the pin's own
  registry functions (persist=False), fed to `python3 -I -S -` on stdin.
- `preview`: before the stop, the PLAN. Each mapped instance whose state is
  pre-generation is either to be renamed (state under its name) or only
  adopted (state already under its logical_id). Its state is copied to a
  scratch state_dir under its logical_id and `generation adopt --dry-run`
  runs there. The plan binds every later step to its context: the
  config's sha256, state_dir and its identity, registry_dir, the checkout,
  the image, the binding, and each instance's source identity and root.
- `move`: after the stop, the plan's renames, each by an atomic no-replace
  rename bound to the source directory's identity, journaled durably first;
  `--reverse` undoes them, idempotently.
- `check`: after the move, the binding dry run on the real state, compared
  with the preview field by field (the router maintainers' rules: COMPARED,
  ZERO and FREE below). N comes only from this dry run's refusal text.
- `adopt`: the real `generation adopt`, with the N `check` recorded.

Every step after `preview` re-reads the map through the pinned code, and
refuses before any mutation unless the config, state_dir, checkout, image
and binding are the plan's. Each step exits 0 when it completed, 1 when it
refused (STOP), and 2 when it could not run.
"""

import contextlib
import ctypes
import errno
import ctypes.util
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

Runner = Callable[..., Any]

#: The router maintainers' program, verbatim (amap-router-local's answer to
#: the deploy's Q5, tested at the pin): it reads the registry with
#: persist=False and writes nothing. It is run as `python3 -I -S - <config>`.
MAP_PROGRAM = (
    'import sys,json; sys.path.insert(0,"/app"); from router.config import load; from router import registry; '
    'c=load(sys.argv[1]); r=registry.report_for(c.registry_dir, c.state_dir, c.instances, persist=False); '
    'reg=registry.load(c.registry_dir, c.state_dir, persist=False); by={e.logical_id: e for e in reg.entries}; '
    'print(json.dumps({"registry_state": r.state, "seq": reg.seq, "instances": {n: {"logical_id": lid, '
    '"adapter": by[lid].adapter, "stable_key": by[lid].stable_key, "binding_seq": by[lid].binding_seq, '
    '"held": r.held.get(n)} for n, lid in sorted(r.known.items())}, "unknown": sorted(set(c.instances) - '
    'set(r.known))}, sort_keys=True))\n')
MAP_PROGRAM_SHA256 = hashlib.sha256(MAP_PROGRAM.encode("utf-8")).hexdigest()

#: Reads an instance root's identity as the router itself does (root_identity:
#: an O_NOFOLLOW|O_DIRECTORY open, then fstat), inside the pinned image, so the
#: identity is the container's view of the path, as the router recorded it.
#: Run as `python3 -I -S - <path>`.
ROOT_PROGRAM = ('import json,os,sys; p=sys.argv[1]; fd=os.open(p, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); '
                'st=os.fstat(fd); os.close(fd); print(json.dumps({"path": p, "st_dev": st.st_dev, '
                '"st_ino": st.st_ino}, sort_keys=True))\n')

#: The container name every one-shot step runs under; `docker run --rm` frees it.
STEP_CONTAINER = "amap-router-migrate"
#: A registry logical_id: lowercase, as the pinned router mints them.
LOGICAL_ID = re.compile(r"[0-9a-f]{32}")
#: The files that make a logical_id directory generation-keyed, or mid-adopt.
GEN_FILE, MIGRATION_FILE = "generations.json", "migration.json"
#: The pinned router's pre-generation entries (router/generations.py
#: GEN_SCOPED): a directory holding none of them needs no adopt, because the
#: router begins its first generation there on its own first poll.
GEN_SCOPED = ("results", "inflight", "transport", "pending", "quarantine", "held", "first-seen.json",
              "approval.json")
#: The refusal that names N: `attest it with --no-transport-history=N`.
ATTEST = re.compile(r"attest it with --no-transport-history=([0-9]+)\s*$")
#: The dry-run summary fields compared between the preview and the binding run.
COMPARED = ("name", "logical_id", "verb", "phase")
ROOT_COMPARED = ("path", "st_dev", "st_ino")
#: The legacy facts that must be null (counter) or zero for a base that never
#: had a transport: anything else is transport history the preview did not see.
ZERO = ("inflight", "transport", "positive_evidence_count", "malformed")
#: Fields that may differ between a running router's copy and the stopped
#: original, and are never compared (named here so a reader sees the choice):
#: generation (minted per run), legacy.local and so N, legacy.manifest_sha256,
#: paths, converted, and legacy.basis moving from empty to attested.
FREE = ("generation", "local", "manifest_sha256", "paths", "converted", "basis")
SCHEMA = "amap-deploy.router-migrate/2"
#: The binding fields the map carries; every step after the preview is bound to them.
BINDING = ("logical_id", "adapter", "stable_key", "binding_seq")
#: How an instance's pre-generation state is found: under its name (renamed,
#: then adopted) or already under its logical_id (adopted in place).
BY_NAME, BY_ID = "name", "logical_id"
#: The context every record carries and every later step must match.
CONTEXT = ("config_sha256", "state_dir", "state_ident", "registry_dir", "checkout", "image")


class Stop(Exception):
    """A refusal: the step stops, and the runbook names the back-out."""


class Cannot(Exception):
    """The step could not run (exit 2)."""


def utc_at() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def run_sh(checkout: str) -> str:
    return os.path.join(checkout, "docker", "run.sh")


def step_argv(checkout: str, image: str, config: str, args: List[str]) -> List[str]:
    """The pinned router's code, under run.sh's own mounts and uid."""
    return [run_sh(checkout), "--config", config, "--image", image, "--name", STEP_CONTAINER, "--",
            "shell"] + args


def map_argv(checkout: str, image: str, config: str) -> List[str]:
    return step_argv(checkout, image, config, ["python3", "-I", "-S", "-", config])


def adopt_argv(checkout: str, image: str, config: str, name: str, reason: str, *, dry_run: bool,
               n: Optional[int]) -> List[str]:
    args = ["python3", "-m", "router", "--config", config, "generation", "adopt", name, "--reason", reason]
    if dry_run:
        args.append("--dry-run")
    if n is not None:
        args.append(f"--no-transport-history={n}")
    return step_argv(checkout, image, config, args)


def _call(argv: List[str], runner: Runner, stdin: Optional[bytes] = None) -> Tuple[int, str, str]:
    try:
        p = runner(argv, input=stdin if stdin is not None else b"", stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE, timeout=600, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Cannot(f"cannot run {argv[0]}: {e}") from None
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


# --- The map -----------------------------------------------------------------------------


def parse_map(text: str) -> Dict[str, Any]:
    """The map's JSON, held to its exact shape, and its STOP rules."""
    try:
        doc = json.loads(text)
    except ValueError:
        raise Cannot("the map program printed no JSON") from None
    if not isinstance(doc, dict) or set(doc) != {"registry_state", "seq", "instances", "unknown"}:
        raise Cannot("the map's members are not registry_state, seq, instances and unknown")
    inst, unknown = doc["instances"], doc["unknown"]
    if not isinstance(inst, dict) or not isinstance(unknown, list) or not all(isinstance(u, str) for u in unknown):
        raise Cannot("the map's instances or unknown have the wrong type")
    for name, e in inst.items():
        if (not isinstance(e, dict) or set(e) != set(BINDING) | {"held"} or not isinstance(e["logical_id"], str)
                or LOGICAL_ID.fullmatch(e["logical_id"]) is None):
            raise Cannot(f"the map's entry for {name!r} is not {{logical_id, adapter, stable_key, binding_seq, held}}")
    if doc["registry_state"] != "ok":
        raise Stop(f"the registry's state is {doc['registry_state']!r}, not \"ok\"")
    if unknown:
        raise Stop("configured instances the registry does not resolve: " + ", ".join(sorted(unknown)))
    return doc


def read_map(checkout: str, image: str, config: str, runner: Runner) -> Dict[str, Any]:
    rc, out, err = _call(map_argv(checkout, image, config), runner, stdin=MAP_PROGRAM.encode("utf-8"))
    if rc != 0:
        raise Cannot(f"the map program exited {rc}: {err.strip()[-400:]}")
    return parse_map(out)


def bindings(the_map: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {n: {k: e[k] for k in BINDING} for n, e in the_map["instances"].items()}


def compare_bindings(plan: Dict[str, Any], now: Dict[str, Any]) -> None:
    """The live registry's binding of every planned instance is the plan's."""
    live = bindings(now)
    for name, want in sorted(plan.items()):
        got = live.get(name)
        if got is None:
            raise Stop(f"the registry no longer resolves {name!r}")
        for k in BINDING:
            if got[k] != want[k]:
                raise Stop(f"{name!r}'s {k} is {got[k]!r} now, {want[k]!r} in the plan")


# --- The adopt dry run ---------------------------------------------------------------------


def dry_run(checkout: str, image: str, config: str, name: str, reason: str,
            runner: Runner) -> Tuple[Dict[str, Any], Optional[int]]:
    """`generation adopt --dry-run`, and once more with N when the first
    refusal asks for it. The plan, and the N it needed (None when none)."""
    rc, out, err = _call(adopt_argv(checkout, image, config, name, reason, dry_run=True, n=None), runner)
    n = None
    if rc == 1:
        m = ATTEST.search(err.strip())
        if m is None:
            raise Stop(f"the adopt dry run for {name!r} refused: {err.strip()[-400:]}")
        n = int(m.group(1))
        rc, out, err = _call(adopt_argv(checkout, image, config, name, reason, dry_run=True, n=n), runner)
    if rc != 0:
        raise (Stop if rc == 1 else Cannot)(f"the adopt dry run for {name!r} exited {rc}: {err.strip()[-400:]}")
    try:
        plan = json.loads(out)
    except ValueError:
        raise Cannot(f"the adopt dry run for {name!r} printed no JSON") from None
    if not isinstance(plan, dict) or plan.get("dry_run") is not True:
        raise Cannot(f"the adopt dry run for {name!r} printed no dry-run plan")
    zero_problems(name, plan)
    return plan, n


def zero_problems(name: str, plan: Dict[str, Any]) -> None:
    legacy = plan.get("legacy")
    if not isinstance(legacy, dict) or legacy.get("counter") is not None:
        raise Stop(f"{name!r}'s legacy state has a transport counter, or no legacy facts: it had a transport")
    for k in ZERO:
        if legacy.get(k) != 0:
            raise Stop(f"{name!r}'s legacy.{k} is {legacy.get(k)!r}, not 0: transport history the preview "
                       "did not account for")


def compare_plans(name: str, preview: Dict[str, Any], binding: Dict[str, Any]) -> None:
    for k in COMPARED:
        if preview.get(k) != binding.get(k):
            raise Stop(f"{name!r}'s {k} is {binding.get(k)!r} after the stop, {preview.get(k)!r} in the preview")
    pr, br = preview.get("root"), binding.get("root")
    if not isinstance(pr, dict) or not isinstance(br, dict):
        raise Stop(f"{name!r}'s plan carries no root")
    for k in ROOT_COMPARED:
        if pr.get(k) != br.get(k):
            raise Stop(f"{name!r}'s root.{k} is {br.get(k)!r} after the stop, {pr.get(k)!r} in the preview")


# --- The state directory -------------------------------------------------------------------


def _lstat(p: Path) -> Optional[os.stat_result]:
    try:
        return os.lstat(p)
    except FileNotFoundError:
        return None


def _ident(st: os.stat_result) -> List[int]:
    return [st.st_dev, st.st_ino]


def _file_state(p: Path) -> bool:
    """The stop gate's rule for generations.json (and here migration.json):
    a regular file is present, no entry is absent, and anything else (a
    directory, a link, a FIFO) STOPs, as the gate reports it UNKNOWN."""
    st = _lstat(p)
    if st is None:
        return False
    if not stat.S_ISREG(st.st_mode):
        raise Stop(f"{p} is not a regular file: the router's state there cannot be judged")
    return True


def _present(p: Path) -> bool:
    """An entry of any type, as the pinned router counts one: an entry that
    cannot be examined (EACCES and the like) counts as present."""
    try:
        os.lstat(p)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


def _legacy(d: Path) -> bool:
    """Whether `d` holds a pre-generation entry, of any type, as the pinned
    router's legacy_entries counts them."""
    return any(_present(d / n) for n in GEN_SCOPED)


def _unlisted(d: Path) -> None:
    """A logical_id directory with no generations file and a gen-* entry is
    the pinned router's state_layout_conflict (check_unlisted): the
    generations file was lost, and no plan guesses past that."""
    with os.scandir(d) as it:
        strays = sorted(e.name for e in it if e.name.startswith("gen-"))
    if strays:
        raise Stop(f"{d} holds {', '.join(strays)} but no {GEN_FILE}: the router holds it as "
                   "state_layout_conflict, and so does this step")


def _at(state_dir: Path, lid: str, ident: List[int]) -> None:
    """The planned instance's state is the recorded directory, under its logical_id."""
    st = _lstat(state_dir / lid)
    if st is None or not stat.S_ISDIR(st.st_mode) or _ident(st) != ident:
        raise Stop(f"{state_dir / lid} is not the instance state the plan recorded")


def classify(state_dir: Path, the_map: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Each mapped instance with pre-generation state: how it is found (by
    name, to be renamed; or by logical_id, adopted in place), and that
    directory's identity. An instance with no state, or already in the
    generation layout, is not planned. Anything the router would not guess
    about STOPs: a name entry that is not a real directory, state under both
    the name and the logical_id, a logical_id entry that is not a directory,
    or an adopt already begun."""
    out = {}
    for name, e in sorted(the_map["instances"].items()):
        lid = e["logical_id"]
        src, dst = _lstat(state_dir / name), _lstat(state_dir / lid)
        if src is not None and not stat.S_ISDIR(src.st_mode):
            raise Stop(f"{state_dir / name} is not a directory: the router holds any entry under the name, and "
                       "this step never moves a link or a file")
        if src is not None and dst is not None:
            raise Stop(f"both {state_dir / name} and {state_dir / lid} exist: the router holds this as "
                       "state_conflict, and so does this step")
        if dst is not None and not stat.S_ISDIR(dst.st_mode):
            raise Stop(f"{state_dir / lid} is not a directory")
        if src is not None:
            _unlisted(state_dir / name)
            out[name] = {"logical_id": lid, "source": BY_NAME, "ident": _ident(src),
                         "adopt": _legacy(state_dir / name)}
        elif dst is not None:
            if _file_state(state_dir / lid / GEN_FILE):
                continue
            _unlisted(state_dir / lid)
            if _file_state(state_dir / lid / MIGRATION_FILE):
                raise Stop(f"{state_dir / lid / MIGRATION_FILE} exists without {GEN_FILE}: an adopt has begun; "
                           "resume it with the adopt step, never with a new plan")
            if _legacy(state_dir / lid):
                out[name] = {"logical_id": lid, "source": BY_ID, "ident": _ident(dst), "adopt": True}
    return out


def layout_needs(state_dir: Path) -> Tuple[set, set]:
    """What the stop gate's layout rule counts as needing migration, read
    the same way: (instance names whose state is under the name, logical_ids
    whose directory has no generations file). An entry the router would not
    guess about STOPs: a link or other entry, a file named like an instance
    or a logical_id, or a directory that is neither the router's own nor an
    instance's."""
    import router_fingerprint as rfp
    names, ids = set(), set()
    with os.scandir(state_dir) as it:
        found = list(it)
    for e in found:
        n = e.name
        if n.casefold() in rfp.RESERVED_STATE_NAMES:
            continue
        hexish = rfp.HEX32.fullmatch(n) is not None
        if e.is_symlink() or not (e.is_dir(follow_symlinks=False) or e.is_file(follow_symlinks=False)):
            raise Stop(f"{state_dir / n} is a link or another kind of entry, which the router does not guess about")
        if e.is_file(follow_symlinks=False):
            if hexish or rfp.INSTANCE_NAME.fullmatch(n):
                raise Stop(f"{state_dir / n} is a file named like an instance's state: the router holds such an "
                           "instance, and this step does not guess")
            continue
        if LOGICAL_ID.fullmatch(n):
            if not _file_state(state_dir / n / GEN_FILE):
                _unlisted(state_dir / n)
                if _legacy(state_dir / n):
                    ids.add(n)
        elif hexish or rfp.INSTANCE_NAME.fullmatch(n) is None:
            raise Stop(f"{state_dir / n} is neither the router's own entry nor an instance's")
        else:
            names.add(n)
    return names, ids


def cover(state_dir: Path, planned: Dict[str, Dict[str, Any]], *, moved: bool) -> None:
    """The plan covers exactly what the layout says needs migration: every
    name-keyed directory is a planned rename (before the move; none remain
    after it), and every logical_id directory without generations is a
    planned instance. Anything else (an unconfigured name, an unmapped
    logical_id, a name that appeared since the plan) STOPs."""
    names, ids = layout_needs(state_dir)
    want_names = set() if moved else {n for n, p in planned.items() if p["source"] == BY_NAME}
    want_ids = {p["logical_id"] for p in planned.values() if p["adopt"]} if moved else \
        {p["logical_id"] for p in planned.values() if p["source"] == BY_ID}
    if names != want_names or ids != want_ids:
        extra = sorted((names - want_names) | (ids - want_ids))
        missing = sorted((want_names - names) | (want_ids - ids))
        raise Stop("the state directory's layout is not the plan's: "
                   + (f"not planned: {', '.join(extra)}" if extra else "")
                   + ("; " if extra and missing else "")
                   + (f"planned but absent: {', '.join(missing)}" if missing else "")
                   + "; the state changed since the preview: take the back-out for this point, then a new preview")


@contextlib.contextmanager
def drain_lock(state_dir: Path) -> Any:
    """The router's own drain lock (flock on state_dir/.router.lock), held
    for the renames: a router that runs on this kernel holds it, so the
    step refuses rather than move state beneath it."""
    fd = os.open(state_dir / ".router.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise Stop(f"{state_dir / '.router.lock'} is held: a router is running on this state") from None
        yield
    finally:
        os.close(fd)


def _sync(fd: int) -> None:
    """fsync, and on darwin F_FULLFSYNC, which also flushes the drive's cache."""
    os.fsync(fd)
    if sys.platform == "darwin" and hasattr(fcntl, "F_FULLFSYNC"):
        try:
            fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
        except OSError as e:
            # A filesystem that refuses it keeps the fsync above, as SQLite does.
            if e.errno not in (errno.ENOTSUP, errno.EINVAL):
                raise


def _fsync_dir(d: Path) -> None:
    fd = os.open(d, os.O_RDONLY)
    try:
        _sync(fd)
    finally:
        os.close(fd)


def _write_new(path: Path, doc: Any) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(json.dumps(doc, sort_keys=True, indent=2) + "\n")
        f.flush()
        _sync(f.fileno())
    _fsync_dir(path.parent)


def _publish(path: Path, doc: Any) -> None:
    """Replace `path` atomically and durably: a temporary beside it, fsynced,
    renamed over it, and the directory fsynced. A crash leaves the old
    record or the new one, never a truncated one."""
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(json.dumps(doc, sort_keys=True, indent=2) + "\n")
        f.flush()
        _sync(f.fileno())
    os.replace(tmp, path)
    _fsync_dir(path.parent)


def _noreplace_supported() -> None:
    """Probe for the atomic no-replace rename before any journal is written,
    so an unsupported platform refuses before anything is recorded."""
    libc = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
    if not ((sys.platform.startswith("linux") and hasattr(libc, "renameat2"))
            or (sys.platform == "darwin" and hasattr(libc, "renamex_np"))):
        raise Cannot("this platform has no atomic no-replace rename")


def rename_noreplace(src: Path, dst: Path) -> None:
    """An atomic rename that never replaces an entry at `dst`, of any type:
    renameat2(RENAME_NOREPLACE) on Linux, renamex_np(RENAME_EXCL) on
    darwin. Anything else cannot run."""
    libc = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
    s, d = os.fsencode(str(src)), os.fsencode(str(dst))
    if sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        fn = libc.renameat2
        fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        fn.restype = ctypes.c_int
        at_fdcwd, rename_noreplace_flag = -100, 1
        rc = fn(at_fdcwd, s, at_fdcwd, d, rename_noreplace_flag)
    elif sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        fn = libc.renamex_np
        fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        fn.restype = ctypes.c_int
        rename_excl = 0x4
        rc = fn(s, d, rename_excl)
    else:
        raise Cannot("this platform has no atomic no-replace rename")
    if rc != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), str(dst))


def _record(run_dir: Path, step: str, suffix: str = ".json") -> Path:
    """A new record name in the run directory: the UTC time, and a counter
    when a step runs twice in one second (a resumed adopt does)."""
    at = utc_at()
    for i in range(1000):
        p = run_dir / f"router-migrate-{step}-{at}{'' if i == 0 else f'-{i}'}{suffix}"
        if not os.path.lexists(p):
            return p
    raise Cannot(f"no free record name for {step} in {run_dir}")


def _read_doc(path: str, step: str) -> Dict[str, Any]:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise Cannot(f"cannot read the {step} record {path}: {e}") from None
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA or doc.get("step") != step:
        raise Cannot(f"{path} is not a router-migrate {step} record")
    return doc


def _config(path: str) -> Dict[str, Any]:
    """The config's own facts, as every step binds them: its sha256, its
    state_dir and that directory's identity, and its registry_dir."""
    try:
        raw = Path(path).read_bytes()
        doc = json.loads(raw)
    except (OSError, ValueError) as e:
        raise Cannot(f"cannot read the config {path}: {e}") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("state_dir"), str) or not doc.get("registry_dir"):
        raise Stop(f"{path} names no state_dir, or sets no registry_dir: it is not a migration config")
    sd = Path(doc["state_dir"])
    st = _lstat(sd)
    if st is None or not stat.S_ISDIR(st.st_mode):
        raise Stop(f"{sd} is not a directory")
    return {"doc": doc, "sha256": hashlib.sha256(raw).hexdigest(), "state_dir": str(sd),
            "state_ident": _ident(st), "registry_dir": doc["registry_dir"]}


def _context(cfg: Dict[str, Any], checkout: str, image: str) -> Dict[str, Any]:
    return {"config_sha256": cfg["sha256"], "state_dir": cfg["state_dir"], "state_ident": cfg["state_ident"],
            "registry_dir": cfg["registry_dir"], "checkout": checkout, "image": image}


def bind_context(want: Dict[str, Any], cfg: Dict[str, Any], checkout: str, image: str) -> None:
    """Refuse unless this invocation's config, state directory, checkout and
    image are the plan's. Runs before any mutation."""
    got = _context(cfg, checkout, image)
    for k in CONTEXT:
        if got[k] != want.get(k):
            raise Stop(f"this run's {k} is {got[k]!r}, not the plan's {want.get(k)!r}")


# --- The steps -----------------------------------------------------------------------------


def do_map(checkout: str, image: str, config: str, run_dir: Path, runner: Runner) -> Path:
    cfg = _config(config)
    the_map = read_map(checkout, image, config, runner)
    out = _record(run_dir, "map")
    _write_new(out, {"schema": SCHEMA, "step": "map", "context": _context(cfg, checkout, image), "map": the_map})
    return out


def do_preview(checkout: str, image: str, config: str, reason: str, run_dir: Path, runner: Runner) -> Path:
    cfg = _config(config)
    the_map = read_map(checkout, image, config, runner)
    state_dir = Path(cfg["state_dir"])
    planned = classify(state_dir, the_map)
    cover(state_dir, planned, moved=False)
    out = _record(run_dir, "preview")
    scratch = out.with_suffix(".d")
    os.mkdir(scratch, 0o700)
    try:
        state = scratch / "state"
        os.mkdir(state, 0o700)
        adopting = {n: p for n, p in planned.items() if p["adopt"]}
        for name, p in adopting.items():
            src = state_dir / (name if p["source"] == BY_NAME else p["logical_id"])
            shutil.copytree(src, state / p["logical_id"], symlinks=True)
        scfg = scratch / "config.json"
        _write_new(scfg, dict(cfg["doc"], state_dir=str(state)))
        for name, p in adopting.items():
            plan, n = dry_run(checkout, image, str(scfg), name, reason, runner)
            if plan.get("logical_id") != p["logical_id"]:
                raise Stop(f"{name!r}'s preview is for {plan.get('logical_id')!r}, not the map's "
                           f"{p['logical_id']}")
            p.update(advisory_n=n, plan=plan)
    except BaseException as e:
        _remove_scratch(scratch, cause=e)
        raise
    _remove_scratch(scratch)
    live = bindings(the_map)
    _write_new(out, {"schema": SCHEMA, "step": "preview", "context": _context(cfg, checkout, image),
                     "binding": {n: live[n] for n in planned}, "instances": planned})
    return out


def _remove_scratch(scratch: Path, cause: Optional[BaseException] = None) -> None:
    """The scratch copy is a copy of the router's private state: a removal
    that fails is reported, chained to any failure already in flight."""
    failed: List[str] = []
    shutil.rmtree(scratch, onerror=lambda fn, path, exc: failed.append(path))
    if failed:
        raise Stop(f"the scratch copy of the state at {scratch} could not be removed ({failed[0]}): remove it by "
                   "hand; it is a copy of the router's private state") from cause


def do_move(checkout: str, image: str, config: str, preview_path: str, run_dir: Path, runner: Runner) -> Path:
    """The plan's renames, after the stop. Each is journaled (intent) and
    published durably before it is made, made by an atomic no-replace
    rename, then checked (the moved directory is the source the plan
    recorded) and journaled done. The first failure stops the step, and its
    message names the journal, which `--reverse` reads."""
    preview = _read_doc(preview_path, "preview")
    cfg = _config(config)
    bind_context(preview["context"], cfg, checkout, image)
    compare_bindings(preview["binding"], read_map(checkout, image, config, runner))
    state_dir = Path(cfg["state_dir"])
    _noreplace_supported()
    with drain_lock(state_dir):
        cover(state_dir, preview["instances"], moved=False)
        return _moves(state_dir, preview, run_dir)


def _moves(state_dir: Path, preview: Dict[str, Any], run_dir: Path) -> Path:
    out = _record(run_dir, "moves")
    journal: Dict[str, Any] = {"schema": SCHEMA, "step": "moves", "context": preview["context"], "moves": [],
                               "planned": sorted(p["logical_id"] for p in preview["instances"].values())}
    _write_new(out, journal)
    try:
        for name, p in sorted(preview["instances"].items()):
            if p["source"] != BY_NAME:
                continue
            src, dst = state_dir / name, state_dir / p["logical_id"]
            st = _lstat(src)
            if st is None or not stat.S_ISDIR(st.st_mode) or _ident(st) != p["ident"]:
                raise Stop(f"{src} is not the directory the plan recorded")
            entry = {"name": name, "logical_id": p["logical_id"], "ident": p["ident"], "state": "intent"}
            journal["moves"].append(entry)
            _publish(out, journal)
            try:
                rename_noreplace(src, dst)
            except OSError as e:
                entry["state"] = "not_applied"
                _publish(out, journal)
                raise Stop(f"cannot move {src} to {dst}: {e.strerror}") from None
            moved = _lstat(dst)
            if moved is None or _ident(moved) != p["ident"] or _lstat(src) is not None:
                raise Stop(f"{dst} is not the directory moved from {src}")
            entry["state"] = "done"
            _publish(out, journal)
            _fsync_dir(state_dir)
    except Stop as e:
        raise Stop(f"{e}; the journal is {out}") from None
    except (OSError, Cannot) as e:
        raise Stop(f"the move failed after its journal was created ({type(e).__name__}: {e}); the journal is "
                   f"{out}") from None
    return out


def do_reverse(config: str, journal_path: str) -> Path:
    """Undo a move journal, newest first, idempotently: an entry whose
    directory is under its logical_id (and is the recorded one) moves back;
    one whose directory is still under its name was never applied, or was
    already reversed; anything else is ambiguous and STOPs."""
    journal = _read_doc(journal_path, "moves")
    cfg = _config(config)
    want = journal["context"]
    for k in ("state_dir", "state_ident"):
        if cfg[k] != want[k]:
            raise Stop(f"this config's {k} is {cfg[k]!r}, not the journal's {want[k]!r}")
    state_dir = Path(want["state_dir"])
    _noreplace_supported()
    with drain_lock(state_dir):
        lids = sorted(set(journal.get("planned", [])) | {e["logical_id"] for e in journal["moves"]})
        adopted = [lid for lid in lids if any(_present(state_dir / lid / f) for f in (MIGRATION_FILE, GEN_FILE))]
        if adopted:
            raise Stop(f"an adopt has begun or finished under {', '.join(adopted)}: the old router cannot read that "
                       "state, so nothing is moved back; R2 only goes forward from here (back-out D)")
        try:
            _reverse(state_dir, journal, journal_path)
        except OSError as e:
            raise Stop(f"the reverse failed ({e.strerror}: {e.filename}); the journal is {journal_path}, and the "
                       "reverse can be run again") from None
    return Path(journal_path)


def _reverse(state_dir: Path, journal: Dict[str, Any], journal_path: str) -> None:
    for entry in reversed(journal["moves"]):
        src, dst = state_dir / entry["name"], state_dir / entry["logical_id"]
        at_name, at_id = _lstat(src), _lstat(dst)
        if at_id is not None and at_name is None and _ident(at_id) == entry["ident"]:
            rename_noreplace(dst, src)
            back = _lstat(src)
            if back is None or _ident(back) != entry["ident"]:
                raise Stop(f"{src} is not the directory moved back from {dst}")
            entry["state"] = "reversed"
            _publish(Path(journal_path), journal)
            _fsync_dir(state_dir)
        elif at_name is not None and at_id is None and _ident(at_name) == entry["ident"]:
            continue
        else:
            raise Stop(f"cannot tell whether {entry['name']!r} was moved: neither {src} alone nor {dst} alone "
                       f"holds the recorded directory; the journal is {journal_path}")


def do_check(checkout: str, image: str, config: str, preview_path: str, reason: str, run_dir: Path,
             runner: Runner) -> Path:
    preview = _read_doc(preview_path, "preview")
    cfg = _config(config)
    bind_context(preview["context"], cfg, checkout, image)
    compare_bindings(preview["binding"], read_map(checkout, image, config, runner))
    state_dir = Path(cfg["state_dir"])
    cover(state_dir, preview["instances"], moved=True)
    plans = {}
    for name, p in sorted(preview["instances"].items()):
        _at(state_dir, p["logical_id"], p["ident"])
        if not p["adopt"]:
            continue
        plan, n = dry_run(checkout, image, config, name, reason, runner)
        compare_plans(name, p["plan"], plan)
        plans[name] = {"logical_id": p["logical_id"], "n": n, "root": plan["root"], "ident": p["ident"]}
    out = _record(run_dir, "check")
    _write_new(out, {"schema": SCHEMA, "step": "check", "context": preview["context"],
                     "binding": preview["binding"], "instances": plans})
    return out


def do_adopt(checkout: str, image: str, config: str, check_path: str, reason: str, run_dir: Path,
             runner: Runner) -> Path:
    """The real adopt, for exactly the checked instances, with the checked N,
    and only while the config, state, checkout, image and binding are the
    checked ones. The router itself re-verifies the root and binding it is
    given; a failure leaves its journal, and re-running this step resumes."""
    check = _read_doc(check_path, "check")
    cfg = _config(config)
    bind_context(check["context"], cfg, checkout, image)
    compare_bindings(check["binding"], read_map(checkout, image, config, runner))
    state_dir = Path(cfg["state_dir"])
    done: Dict[str, Any] = {}
    out = _record(run_dir, "adopt")
    for name, rec in sorted(check["instances"].items()):
        _at(state_dir, rec["logical_id"], rec["ident"])
        if _preflight(checkout, image, config, name, reason, rec, runner):
            done[name] = {"noop": True, "logical_id": rec["logical_id"]}
            continue
        rc, stdout, err = _call(adopt_argv(checkout, image, config, name, reason, dry_run=False, n=rec["n"]),
                                runner)
        try:
            result = json.loads(stdout) if rc == 0 else None
        except ValueError:
            result = None
        root = result.get("root") if isinstance(result, dict) else None
        if (rc != 0 or not isinstance(result, dict) or result.get("logical_id") != rec["logical_id"]
                or not isinstance(root, dict) or any(root.get(k) != rec["root"].get(k) for k in ROOT_COMPARED)):
            _write_new(out, {"schema": SCHEMA, "step": "adopt", "done": done, "failed": name})
            raise Stop(f"adopt for {name!r} exited {rc}, or answered for another identity or root: "
                       f"{err.strip()[-400:]}; re-running the same step resumes it, and an adopt that answered "
                       "for another root is the maintainers' call (back-out D)")
        done[name] = result
    for name, rec in sorted(check["instances"].items()):
        _adopted_root(checkout, image, config, state_dir, name, rec, runner)
    _write_new(out, {"schema": SCHEMA, "step": "adopt", "done": done, "failed": None})
    return out


def do_verify(checkout: str, image: str, config: str, check_path: str, run_dir: Path, runner: Runner) -> Path:
    """Read-only, immediately before the start: the context is still the
    checked one, and every adopted root's four records agree."""
    check = _read_doc(check_path, "check")
    cfg = _config(config)
    bind_context(check["context"], cfg, checkout, image)
    state_dir = Path(cfg["state_dir"])
    for name, rec in sorted(check["instances"].items()):
        _adopted_root(checkout, image, config, state_dir, name, rec, runner)
    out = _record(run_dir, "verify")
    _write_new(out, {"schema": SCHEMA, "step": "verify", "verified": sorted(check["instances"])})
    return out


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_bytes()) if _file_state(path) else None
    except (OSError, ValueError) as e:
        raise Stop(f"{path} cannot be read: {e}") from None


def live_root(checkout: str, image: str, config: str, path: str, runner: Runner) -> Dict[str, Any]:
    rc, out, err = _call(step_argv(checkout, image, config, ["python3", "-I", "-S", "-", path]), runner,
                         stdin=ROOT_PROGRAM.encode("utf-8"))
    if rc != 0:
        raise Stop(f"the instance root {path} cannot be opened as the router opens it: {err.strip()[-400:]}")
    try:
        got = json.loads(out)
    except ValueError:
        raise Cannot(f"the root program printed no JSON for {path}") from None
    if not isinstance(got, dict) or set(got) != {"path", "st_dev", "st_ino"}:
        raise Cannot(f"the root program's answer for {path} is not {{path, st_dev, st_ino}}")
    return got


def _adopted_root(checkout: str, image: str, config: str, state_dir: Path, name: str, rec: Dict[str, Any],
                  runner: Runner) -> None:
    """After the adopt, and again immediately before the start, four records
    of the instance root must be one (path, st_dev, st_ino): the adopt's own
    journal (migration.json source.root), the generation it made
    (generations.json, the current entry), the root recorded at check, and
    the root as the router would open it now. Otherwise STOP: do not start
    the router, because it would begin a new generation (root_changed), take
    a fresh first sight and quarantine waiting requests."""
    d = state_dir / rec["logical_id"]
    journal, gens = _read_json(d / MIGRATION_FILE), _read_json(d / GEN_FILE)
    source = journal.get("source") if isinstance(journal, dict) else None
    from_journal = source.get("root") if isinstance(source, dict) else None
    entries = gens.get("gens") if isinstance(gens, dict) else None
    cur = next((g for g in entries if isinstance(g, dict) and g.get("gen") == gens.get("current")), None) \
        if isinstance(entries, list) else None
    from_gens = cur.get("root") if isinstance(cur, dict) else None
    now = live_root(checkout, image, config, rec["root"]["path"], runner)
    for what, root in (("the adopt's journal", from_journal), ("the adopted generation", from_gens),
                       ("the path now", now)):
        if not isinstance(root, dict) or any(root.get(k) != rec["root"].get(k) for k in ROOT_COMPARED):
            raise Stop(f"{name!r}'s root in {what} is {root!r}, not the checked {rec['root']!r}: do not start the "
                       "router; R2 only goes forward from here (back-out D)")


def _preflight(checkout: str, image: str, config: str, name: str, reason: str, rec: Dict[str, Any],
               runner: Runner) -> bool:
    """Immediately before the real adopt, a fresh read-only plan with the
    checked N: it must be for the checked logical_id and root (path, st_dev,
    st_ino), so a root recreated since the check refuses here. True when the
    router answers that the adopt is already done (a resumed step)."""
    rc, out, err = _call(adopt_argv(checkout, image, config, name, reason, dry_run=True, n=rec["n"]), runner)
    if rc != 0:
        raise (Stop if rc == 1 else Cannot)(f"the adopt's fresh plan for {name!r} exited {rc}: "
                                            f"{err.strip()[-400:]}")
    try:
        plan = json.loads(out)
    except ValueError:
        raise Cannot(f"the adopt's fresh plan for {name!r} printed no JSON") from None
    if not isinstance(plan, dict) or plan.get("logical_id") != rec["logical_id"]:
        raise Stop(f"the adopt's fresh plan for {name!r} is not for {rec['logical_id']}")
    if plan.get("noop") is True:
        return True
    if plan.get("dry_run") is not True:
        raise Cannot(f"the adopt's fresh plan for {name!r} printed no dry-run plan")
    root = plan.get("root")
    if not isinstance(root, dict) or any(root.get(k) != rec["root"].get(k) for k in ROOT_COMPARED):
        raise Stop(f"{name!r}'s root is {root!r} now, {rec['root']!r} when checked: it changed since the check")
    zero_problems(name, plan)
    return False


def run(args: Any, *, out: Callable[[str], None] = print, runner: Runner = subprocess.run) -> int:
    """`router-migrate <step>`: dry run by default; --apply runs it."""
    try:
        return _run(args, out, runner)
    except Stop as e:
        out(f"router-migrate {args.step}: STOP: {e}")
        return 1
    except Cannot as e:
        out(f"router-migrate {args.step}: cannot run: {e}")
        return 2
    except Exception as e:     # noqa: BLE001 — every failure is an answer, never a traceback
        out(f"router-migrate {args.step}: cannot run: {type(e).__name__}: {e}")
        return 2


def _run(args: Any, out: Callable[[str], None], runner: Runner) -> int:
    import hop_router as hp
    import router_fingerprint as rfp
    spec = rfp._load_spec(args, out, secrets=True)
    if spec is None:
        return 2
    if spec.router is None:
        raise Cannot("the host-setup document has no router section (its image)")
    checkout, image, run_dir = str(hp.hop_checkout()), spec.router.image_digest, Path(spec.secrets.run_dir)
    step = args.step
    if getattr(args, "config", None) is not None:
        args.config = os.path.abspath(args.config)
    need = {"map": ("config",), "preview": ("config", "reason"), "move": ("config",),
            "check": ("config", "preview", "reason"), "adopt": ("config", "check", "reason"),
            "verify": ("config", "check")}[step]
    missing = [k for k in need if getattr(args, k, None) is None]
    if step == "move" and (args.preview is None) == (args.reverse is None):
        missing.append("preview or --reverse, exactly one")
    if missing:
        raise Cannot("needs --" + ", --".join(missing))
    if not args.apply:
        out(f"would run router-migrate {step} with the pinned router's code ({image}) through "
            f"{run_sh(checkout)}, writing into {run_dir} (dry run; --apply to run)")
        return 0
    if step == "map":
        path = do_map(checkout, image, args.config, run_dir, runner)
    elif step == "preview":
        path = do_preview(checkout, image, args.config, args.reason, run_dir, runner)
    elif step == "move" and args.reverse is not None:
        path = do_reverse(args.config, args.reverse)
    elif step == "move":
        path = do_move(checkout, image, args.config, args.preview, run_dir, runner)
    elif step == "check":
        path = do_check(checkout, image, args.config, args.preview, args.reason, run_dir, runner)
    elif step == "adopt":
        path = do_adopt(checkout, image, args.config, args.check, args.reason, run_dir, runner)
    else:
        path = do_verify(checkout, image, args.config, args.check, run_dir, runner)
    out(f"router-migrate {step}: done: {path}")
    return 0
