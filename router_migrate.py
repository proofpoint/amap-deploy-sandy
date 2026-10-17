"""router-migrate: the local router's migration from state keyed by instance
name to the pinned router's registry layout, as its own window (the
runbook's R2), before any activation.

Every router step runs the PINNED router's own code: the hop checkout's
`docker/run.sh` (its identity mounts, as the operator's uid), with
`--image` set to the host-setup document's `router.image.digest`, in the
entrypoint's `shell` mode. Nothing here writes the live config.

- `map`: the name -> logical_id mapping and each binding, printed by
  MAP_PROGRAM, the router maintainers' read-only program over the pin's own
  registry functions (persist=False). It is fed to `python3 -I -S -` on
  stdin, so no long line is ever typed or relayed.
- `preview`: before the stop, each name-keyed state directory is copied to a
  scratch state_dir under its logical_id, and `generation adopt --dry-run`
  runs against the migration config with state_dir pointed at the copy. The
  copy of a running router's state is only a preview.
- `move`: after the stop, each `<state_dir>/<name>` is renamed to
  `<state_dir>/<logical_id>`, journaled first; `--reverse` undoes it.
- `check`: after the move, the binding dry run on the real state, compared
  with the preview field by field (the router maintainers' rules: COMPARED,
  ZERO and FREE below). N comes only from this dry run's refusal text.
- `adopt`: the real `generation adopt`, with the N `check` recorded.

Each step exits 0 when it completed, 1 when it refused (STOP), and 2 when it
could not run.
"""

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
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

#: The container name every one-shot step runs under; `docker run --rm` frees it.
STEP_CONTAINER = "amap-router-migrate"
LOGICAL_ID = re.compile(r"[0-9a-fA-F]{32}")
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
SCHEMA = "amap-deploy.router-migrate/1"
#: The binding fields the map carries and the move and adopt are bound to.
BINDING = ("logical_id", "adapter", "stable_key", "binding_seq")


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


def compare_maps(before: Dict[str, Any], after: Dict[str, Any]) -> None:
    if set(before["instances"]) != set(after["instances"]):
        raise Stop("the registry resolves a different set of instances after the stop")
    for name, e in before["instances"].items():
        for k in BINDING:
            if after["instances"][name][k] != e[k]:
                raise Stop(f"{name!r}'s {k} is {after['instances'][name][k]!r} after the stop, {e[k]!r} before")


def _lstat(p: Path) -> Optional[os.stat_result]:
    try:
        return os.lstat(p)
    except FileNotFoundError:
        return None


def to_migrate(state_dir: Path, the_map: Dict[str, Any]) -> List[Tuple[str, str]]:
    """(name, logical_id) for each mapped instance whose state is a real
    directory under its name. A name with an entry under its logical_id as
    well is a conflict the router would not guess: STOP."""
    out = []
    for name, e in sorted(the_map["instances"].items()):
        src, dst = _lstat(state_dir / name), _lstat(state_dir / e["logical_id"])
        if src is None:
            continue
        if not stat.S_ISDIR(src.st_mode):
            raise Stop(f"{state_dir / name} is not a directory (a link or a file is never moved)")
        if dst is not None:
            raise Stop(f"both {state_dir / name} and {state_dir / e['logical_id']} exist: the router holds this as "
                       "state_conflict and so does this step")
        out.append((name, e["logical_id"]))
    return out


def _write_new(path: Path, doc: Any) -> None:
    data = json.dumps(doc, sort_keys=True, indent=2) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(data)


def _record(run_dir: Path, step: str, suffix: str = ".json") -> Path:
    """A new record name in the run directory: the UTC time, and a counter
    when a step runs twice in one second (a resumed adopt does)."""
    at = utc_at()
    for i in range(1000):
        p = run_dir / f"router-migrate-{step}-{at}{'' if i == 0 else f'-{i}'}{suffix}"
        if not os.path.lexists(p):
            return p
    raise Cannot(f"no free record name for {step} in {run_dir}")


def _read_doc(path: str, what: str) -> Dict[str, Any]:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise Cannot(f"cannot read the {what} {path}: {e}") from None
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise Cannot(f"{path} is not a router-migrate {what}")
    return doc


def _config(path: str) -> Tuple[Dict[str, Any], Path, str]:
    try:
        raw = Path(path).read_bytes()
        doc = json.loads(raw)
    except (OSError, ValueError) as e:
        raise Cannot(f"cannot read the config {path}: {e}") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("state_dir"), str) or not doc.get("registry_dir"):
        raise Stop(f"{path} names no state_dir, or sets no registry_dir: it is not a migration config")
    return doc, Path(doc["state_dir"]), hashlib.sha256(raw).hexdigest()


def do_map(checkout: str, image: str, config: str, run_dir: Path, runner: Runner) -> Path:
    _config(config)
    the_map = read_map(checkout, image, config, runner)
    out = _record(run_dir, "map")
    _write_new(out, {"schema": SCHEMA, "step": "map", "config": config, "map": the_map})
    return out


def do_preview(checkout: str, image: str, config: str, map_path: str, reason: str, run_dir: Path,
               runner: Runner) -> Path:
    doc, state_dir, sha = _config(config)
    the_map = _read_doc(map_path, "map")["map"]
    pending = to_migrate(state_dir, the_map)
    out = _record(run_dir, "preview")
    scratch = out.with_suffix(".d")
    os.mkdir(scratch, 0o700)
    try:
        state = scratch / "state"
        os.mkdir(state, 0o700)
        for name, lid in pending:
            shutil.copytree(state_dir / name, state / lid, symlinks=True)
        cfg = scratch / "config.json"
        _write_new(cfg, dict(doc, state_dir=str(state)))
        plans = {}
        for name, lid in pending:
            plan, n = dry_run(checkout, image, str(cfg), name, reason, runner)
            if plan.get("logical_id") != lid:
                raise Stop(f"{name!r}'s preview is for {plan.get('logical_id')!r}, not the map's {lid}")
            plans[name] = {"logical_id": lid, "advisory_n": n, "plan": plan}
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    _write_new(out, {"schema": SCHEMA, "step": "preview", "config_sha256": sha, "map": the_map,
                     "instances": plans})
    return out


def do_move(config: str, map_path: str, run_dir: Path, *, reverse: Optional[str] = None) -> Path:
    """The guarded renames, each journaled before it is made; stops at the
    first failure. With `reverse`, that journal's moves are undone, newest
    first, under the same guards turned around."""
    _, state_dir, _ = _config(config)
    if reverse is not None:
        journal = _read_doc(reverse, "move journal")
        for name, lid in reversed(journal["moves"]):
            src, dst = _lstat(state_dir / lid), _lstat(state_dir / name)
            if src is None or not stat.S_ISDIR(src.st_mode) or dst is not None:
                raise Stop(f"cannot move {state_dir / lid} back to {state_dir / name}: the source is not a "
                           "directory, or the name has an entry again")
            os.rename(state_dir / lid, state_dir / name)
        return Path(reverse)
    the_map = _read_doc(map_path, "map")["map"]
    pending = to_migrate(state_dir, the_map)
    out = _record(run_dir, "moves")
    moves: List[List[str]] = []
    _write_new(out, {"schema": SCHEMA, "step": "move", "state_dir": str(state_dir), "moves": moves})
    for name, lid in pending:
        moves.append([name, lid])
        out.write_text(json.dumps({"schema": SCHEMA, "step": "move", "state_dir": str(state_dir), "moves": moves},
                                  sort_keys=True, indent=2) + "\n", encoding="utf-8")
        if _lstat(state_dir / lid) is not None:
            raise Stop(f"{state_dir / lid} appeared before the move")
        os.rename(state_dir / name, state_dir / lid)
    return out


def do_check(checkout: str, image: str, config: str, preview_path: str, map_path: str, reason: str,
             run_dir: Path, runner: Runner) -> Path:
    _config(config)
    preview = _read_doc(preview_path, "preview")
    after = _read_doc(map_path, "map")["map"]
    compare_maps(preview["map"], after)
    plans = {}
    for name, rec in sorted(preview["instances"].items()):
        plan, n = dry_run(checkout, image, config, name, reason, runner)
        compare_plans(name, rec["plan"], plan)
        plans[name] = {"logical_id": rec["logical_id"], "n": n}
    out = _record(run_dir, "check")
    _write_new(out, {"schema": SCHEMA, "step": "check", "instances": plans})
    return out


def do_adopt(checkout: str, image: str, config: str, check_path: str, reason: str, run_dir: Path,
             runner: Runner) -> Path:
    _config(config)
    check = _read_doc(check_path, "check")
    done = {}
    out = _record(run_dir, "adopt")
    for name, rec in sorted(check["instances"].items()):
        rc, stdout, err = _call(adopt_argv(checkout, image, config, name, reason, dry_run=False, n=rec["n"]),
                                runner)
        if rc != 0:
            _write_new(out, {"schema": SCHEMA, "step": "adopt", "done": done, "failed": name})
            raise Stop(f"adopt for {name!r} exited {rc}: {err.strip()[-400:]}; re-running the same step "
                       "resumes it")
        try:
            done[name] = json.loads(stdout)
        except ValueError:
            done[name] = None
    _write_new(out, {"schema": SCHEMA, "step": "adopt", "done": done, "failed": None})
    return out


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
    need = {"map": ("config",), "preview": ("config", "map", "reason"), "move": ("config",),
            "check": ("config", "preview", "map", "reason"), "adopt": ("config", "check", "reason")}[step]
    missing = [k for k in need if getattr(args, k, None) is None]
    if step == "move" and args.map is None and args.reverse is None:
        missing.append("map or reverse")
    if missing:
        raise Cannot("needs --" + ", --".join(missing))
    if not args.apply:
        out(f"would run router-migrate {step} with the pinned router's code ({image}) through "
            f"{run_sh(checkout)}, writing into {run_dir} (dry run; --apply to run)")
        return 0
    if step == "map":
        path = do_map(checkout, image, args.config, run_dir, runner)
    elif step == "preview":
        path = do_preview(checkout, image, args.config, args.map, args.reason, run_dir, runner)
    elif step == "move":
        path = do_move(args.config, args.map, run_dir, reverse=args.reverse)
    elif step == "check":
        path = do_check(checkout, image, args.config, args.preview, args.map, args.reason, run_dir, runner)
    else:
        path = do_adopt(checkout, image, args.config, args.check, args.reason, run_dir, runner)
    out(f"router-migrate {step}: done: {path}")
    return 0
