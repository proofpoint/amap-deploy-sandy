"""A5's post-activation document: P01 and P02 against the local router's FINAL
running identity, after A4, as the operator with the engine.

`amap-sandy.py partition-probe --post-activation <T's run id>` writes it into
the operator's run directory (with --apply) and prints the root `place` that
puts it in the evidence directory. It is never evidence:
- its schema is `amap-deploy.partition-postactivation/1`, and it has NO
  `delegation_partition_verified` member, so it cannot parse as
  partition-evidence/1;
- its name, `postactivation-<run id>.json`, is outside EVIDENCE_NAME, so the
  weekly job's store can neither create nor replace it;
- E1 and E2 read only the document the live token names.

`names_token` is T, the live token, selected through
partition_evidence.named_document: a token the evidence did not ISSUE names
nothing. `bindings` holds what the operator can compute: host_setup,
email_router, lanes and local_router. The key binding is root's (the key's
directory is [1]'s 0700), and P01 and P02 do not involve the key.
`local_router` hashes the live config FILE beside the running spec; it does
not show that [1] adopted that file, since a refused reload keeps the old
config running. Adoption is partition-check V2's reload flag.

partition_probe is in the weekly job's bundle; this module calls its P01 and
P02 pieces unchanged, so the bundle does not move.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import partition_evidence as pe
import partition_probe as pp
import router_health as rh

SCHEMA = "amap-deploy.partition-postactivation/1"
MEMBERS = ("schema", "host", "run_id", "at", "names_token", "router", "script_sha256", "bindings", "probes")
PROBE_IDS = ("P01", "P02")
BINDING_KEYS = ("host_setup", "email_router", "lanes", "local_router")
_RUN_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")
_HEX64 = re.compile(r"[0-9a-f]{64}")


class PostActivationError(ValueError):
    """Not a post-activation document."""


def name(run_id: str) -> str:
    return f"postactivation-{run_id}.json"


def parse(raw: bytes, *, host: str) -> Dict[str, Any]:
    """The document by its strict grammar, or PostActivationError: canonical
    JSON, exactly its members, this host's, P01 and P02 in order with the
    evidence's probe members and verdicts, and no token member."""
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=pe._no_duplicates, parse_constant=pe._no_constant)
    except (UnicodeDecodeError, ValueError) as e:
        raise PostActivationError(f"not JSON: {e}") from None
    if not isinstance(doc, dict) or tuple(sorted(doc)) != tuple(sorted(MEMBERS)) or doc["schema"] != SCHEMA:
        raise PostActivationError("not exactly the document's members and schema")
    if pe.canonical(doc) != raw:
        raise PostActivationError("not in canonical form")
    if doc["host"] != host:
        raise PostActivationError("another host's")
    if not isinstance(doc["run_id"], str) or not _RUN_ID.fullmatch(doc["run_id"]):
        raise PostActivationError("its run id is malformed")
    pe.at_seconds(doc["at"])
    if not isinstance(doc["names_token"], str) or not doc["names_token"]:
        raise PostActivationError("it names no token")
    router = doc["router"]
    if not isinstance(router, dict) or set(router) != {"container_id", "inspect_digest"} or \
            not all(isinstance(router[k], str) and _HEX64.fullmatch(router[k]) for k in router):
        raise PostActivationError("its router is not {container_id, inspect_digest}, both 64 hex")
    if not isinstance(doc["bindings"], dict) or set(doc["bindings"]) != set(BINDING_KEYS):
        raise PostActivationError("its bindings are not exactly the operator's four")
    probes = doc["probes"]
    if not isinstance(probes, list) or [p.get("id") if isinstance(p, dict) else None for p in probes] != list(PROBE_IDS):
        raise PostActivationError("its probes are not exactly P01 and P02, in order")
    for p in probes:
        try:
            pe._probe_problem(p)
        except pe.EvidenceError as e:
            raise PostActivationError(str(e)) from None
    return doc


def build(*, host: str, run_id: str, at: str, names_token: str, router: Dict[str, str], bindings: Dict[str, str],
          probes: List[Dict[str, Any]]) -> bytes:
    raw = pe.canonical({"schema": SCHEMA, "host": host, "run_id": run_id, "at": at, "names_token": names_token,
                        "router": dict(router), "script_sha256": pp.script_sha256(), "bindings": dict(bindings),
                        "probes": probes})
    parse(raw, host=host)
    return raw


def probe(plan: pp.Plan, runner: pp.Runner, run_argv: Callable, lstat_: Callable) -> Tuple[List[Dict[str, Any]], int, List[str]]:
    """P01 and P02 exactly as partition_probe.run makes them, with nothing
    unmeasured: [1] runs its final identity. (probes, exit, report). Its
    two preconditions are run's own, with run's refusal text: a running
    email router that differs from its rendering, or is not running, refuses
    the whole run (nothing it showed would stand for it), and so does a role
    outside the evidence vocabulary. A refusal is ([], 2, [why])."""
    import os
    drift = plan.email_drift
    if isinstance(drift, rh.Unresolved) or drift:
        why = drift.reason if isinstance(drift, rh.Unresolved) else "; ".join(drift)
        return [], 2, [f"refused: the running email router is not its rendering: {why}"]
    roles = {"P01": [f"runtime:{p}" for p in sorted(plan.runtimes)],
             "P02": [f"marker:{s}/{n}" for n, s, _, _ in pp.MARKERS if s in plan.sides]}
    for pid in PROBE_IDS:
        bad = [r for r in roles[pid] if not pe.role_ok(r)]
        if bad:
            return [], 2, [f"refused: {pid}'s role {bad[0]!r} is outside the evidence vocabulary"]
    walks = {}
    for principal, (container, uid, gid) in sorted(plan.runtimes.items()):
        out = pp._out(runner(["exec", "-u", f"{uid}:{gid}", container, "python3", "-I", "-S", "-c", pp.P01_SCRIPT]))
        walks[principal] = out if isinstance(out, rh.Unresolved) else pp.parse_proc(out)
    uids = {p: u for p, (_, u, _) in plan.runtimes.items()}
    p01 = pp.verdict_p01(walks, uids, plan.hops, None)
    sides, nonowner, witness, marker_dirs = {}, {}, {}, []
    for side in ("up", "down"):
        sides[side], nonowner[side], witness[side] = pp.p02_side(
            runner, plan.sides[side], plan.owners[side], side, plan.links, plan.run_id, run_argv, plan.email_volume)
        if sides[side][0] == "targets":
            marker_dirs += [posixpath.join(plan.hop_root, lid, gen, side) for lid, gen in sides[side][1]]
    p02 = pp.with_non_effect(pp.verdict_p02(sides, nonowner, witness),
                             pp.left_behind(marker_dirs, pp.probe_file(plan.run_id), lstat_ or os.lstat))
    p02_witness = "unresolved" if any(isinstance(w, rh.Unresolved) for w in witness.values()) else (
        "ok" if all(pp._witnessed(w) == "ok" for w in witness.values()) else "EACCES")
    probes = [
        pp._probe_entry("P01", [plan.vantages[p] for p in sorted(plan.runtimes)],
                        "read /proc/*/status as the principal", roles["P01"], p01,
                        ("read each uid from the process", "unresolved" if p01[1] == "unresolved" else "ok")),
        pp._probe_entry("P02", [pp.spec_vantage(plan.sides[s][0]) for s in sorted(plan.sides)],
                        "lstat; open for writing; create beside", roles["P02"], p02,
                        ("the owner enumerates and opens its markers for writing", p02_witness)),
    ]
    probes = json.loads(json.dumps(probes, default=list))
    verdicts = [p["verdict"] for p in probes]
    report = [f"P01: {p01[0]}: {p01[2]}", f"P02: {p02[0]}: {p02[2]}"]
    return probes, (1 if "FAIL" in verdicts else 2 if "UNKNOWN" in verdicts else 0), report


def run(document_path: str, document_sha256: str, t_run_id: str, *, apply: bool, out=print,
        now: Optional[float] = None, p: Optional[Dict[str, Any]] = None) -> int:
    """The verb. Refuses, writing nothing, unless the document is the unit's,
    the live config carries a token of T's run, that token names an ISSUED
    document of this host, and the local router runs. Exit 0 when the
    document was written (or would be, dry), 1 when a probe did not pass, 2
    on a refusal."""
    import os
    import shlex
    import host_setup as hsu
    import hub_runtime as hr
    import partition_activation as pa
    import partition_plan as ppl
    import partition_run as prun
    import partition_setup as ps
    import secret_setup as ss
    p = dict(p or {})
    now = time.time() if now is None else now

    def refuse(why: str) -> int:
        out(f"partition-probe --post-activation: refused, nothing written: {why}")
        return 2
    try:
        with open(document_path, "rb") as f:
            raw = f.read()
        spec = hsu.load_spec(prun.document_section(raw))
    except (OSError, ValueError) as e:
        return refuse(f"the document cannot be loaded: {e}")
    if hashlib.sha256(raw).hexdigest() != document_sha256:
        return refuse("the document's sha256 is not --document-sha256")
    if spec.partition is None or spec.keys is None or spec.secrets is None or spec.hub is None or not spec.hops:
        return refuse("the document has no partition, keys, secrets, hub or hops section")
    host = hsu.partition_host(spec)
    read = p.get("read", ps.read_placed)
    try:
        live_raw = p.get("read_live", ps.read_record)(spec.keys.local_config)
        router_doc = ps._strict(live_raw)
        token = router_doc["delegation"]["partition_verified"]
    except (OSError, ValueError, KeyError, TypeError) as e:
        return refuse(f"the live config carries no token: {e}")
    if not isinstance(token, str) or token.partition(":")[0] != t_run_id:
        return refuse(f"the live token is not of T's run {t_run_id}")
    named, _, why = pe.named_document(token, evidence_dir=spec.partition.evidence_dir, host=host, read=read)
    if named is None:
        return refuse(f"the live token names no issued document: {why}")
    runner = p.get("runner") or pp.Runner(ss.docker(spec.secrets))
    docker = prun.Docker(runner)
    live = docker.inspect(spec.runtime_of(spec.hops[0][1])["container"])
    if not isinstance(live, dict) or pa.is_running(live) is not True:
        return refuse("the local router is not affirmed running (A4 first)")
    router = pa.spec_from_running(live)
    if isinstance(router, rh.Unresolved):
        return refuse(router.reason)
    lanes = prun.selected_lanes(router_doc, read=p["read_lanes"]) if "read_lanes" in p else prun.selected_lanes(router_doc)
    if isinstance(lanes, rh.Unresolved):
        return refuse(lanes.reason)
    lane = pp.lane_binding(lanes, p.get("stat", os.stat))
    if isinstance(lane, rh.Unresolved):
        return refuse(lane.reason)
    email = hr.run_spec(spec, spec.hub)
    bindings = {"host_setup": hashlib.sha256(raw).hexdigest(), "email_router": hr.spec_sha256(email),
                "lanes": lane, "local_router": pa.activation_binding(router, live_raw)}
    run_id = time.strftime("pa-%Y%m%dT%H%M%SZ", time.gmtime(now))
    at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
    try:
        plan = ppl.gather(host=host, run_id=run_id, at=at, email=email,
                          email_view=hr.view(email, hr.environment(spec, spec.hub)),
                          email_live=docker.inspect(email["name"]), email_image_env=docker.image_env(email["image"]),
                          email_volume=spec.secrets.volume, router=router, router_doc=router_doc, lanes=lanes,
                          agent_inspects={s: docker.inspect(s) for s in lanes}, bindings=bindings)
    except ppl.PlanError as e:
        return refuse(f"no plan: {e}")
    probes, code, report = probe(plan, runner, ppl.run_argv_for(router), p.get("lstat", os.lstat))
    if not probes:
        why = report[0]
        return refuse(why[len("refused: "):] if why.startswith("refused: ") else why)
    for line in report:
        out(f"  {line}")
    doc = build(host=host, run_id=run_id, at=at, names_token=token,
                router={"container_id": live["Id"], "inspect_digest": pe.sha_json(pa.inspect_projection(live))},
                bindings=bindings, probes=probes)
    source = os.path.join(spec.secrets.run_dir, name(run_id))
    dest = posixpath.join(spec.partition.evidence_dir, name(run_id))
    if apply:
        with open(source, "xb") as f:
            f.write(doc)
        out(f"partition-probe --post-activation: wrote {source}")
    else:
        out(f"partition-probe --post-activation: would write {source} (pass --apply)")
    writer = os.path.join(spec.secrets.writer_dir, ss.WRITER)
    out("  then, as root:")
    out(f"    sudo {shlex.quote(spec.partition.tools['python3'])} -I -S -B {shlex.quote(writer)} place "
        f"{shlex.quote(source)} {shlex.quote(dest)} --sha256 {hashlib.sha256(doc).hexdigest()}")
    return 0 if code == 0 else 1
