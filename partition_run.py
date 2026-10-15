"""The weekly job's child: one partition run, as root, from the provisioned
bundle, under the lock its writer passed it.

The pinned writer (host_steps.py partition-weekly) verifies the bundle, holds
the per-host lock, writes `context.json` and the approved document's exact
bytes (`document.json`) into the run directory, and starts this with the
lock's descriptor. This child:
1. holds that descriptor open for its whole life, and never unlocks it, so
   the lock outlives a writer that dies;
2. reads `context.json` and `document.json` strictly; a truncated or
   malformed record is absent, never repaired;
3. computes the bindings it will probe under and writes `expect.json`
   BEFORE its first one-shot;
4. runs the probes and places the evidence through the one write choke
   point (partition_store);
5. on a fail-stop FAIL, acts (partition_incident) with the stop target from
   `context.json` and nothing else;
6. writes `outcome.json`.
It never runs git, sandy or the hop checkout: what it knows of the deployment
comes from the approved document, the running containers and the files the
document names, read and never executed.
"""

import hashlib
import json
import os
import posixpath
import stat
from typing import Any, Callable, Dict, List, Optional

import host_setup as hs
import hub_runtime as hr
import hub_supervise as hv
import partition_activation as pa
import partition_evidence as pe
import partition_incident as pi
import partition_plan as ppl
import partition_probe as pp
import partition_store as pst
import router_health as rh

SCHEMA = "amap-deploy.partition-run/1"
CONTEXT, DOCUMENT, EXPECT, OUTCOME = "context.json", "document.json", "expect.json", "outcome.json"
LOCK = "lock"
#: The child's own exit codes, as outcome.json records them.
PASSED, FAILED, INCOMPLETE = 0, 1, 2
#: The members each record carries, and nothing else.
CONTEXT_MEMBERS = frozenset({"schema", "run_id", "host", "started_at", "evidence_dir", "live_config_path",
                             "router_container_id", "engine"})


class ChildError(Exception):
    """The run cannot start: nothing is probed, and the outcome says why."""


def canonical(doc: Dict[str, Any]) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")


def read_record(store: pst.RootedStore, path: str) -> Any:
    """A run record as one strict JSON object, or an Unresolved: absent,
    truncated or malformed are all "not there", never repaired."""
    try:
        return pst.strict_object(store.read(path))
    except FileNotFoundError:
        return rh.Unresolved(f"{posixpath.basename(path)} is absent")
    except (OSError, ValueError, UnicodeDecodeError) as e:
        return rh.Unresolved(f"{posixpath.basename(path)} cannot be read: {e}")


def check_lock(lock_fd: int, exec_root: str, stat_: Callable = os.stat) -> None:
    """The descriptor the writer passed is `<exec_root>/lock` itself: the run
    holds the lock only through it."""
    try:
        a, b = os.fstat(lock_fd), stat_(posixpath.join(exec_root, LOCK))
    except OSError as e:
        raise ChildError(f"the run's lock cannot be checked: {e}") from None
    if not stat.S_ISREG(a.st_mode) or (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino):
        raise ChildError("the descriptor passed is not the run's lock")


def document_section(raw: bytes) -> Dict[str, Any]:
    """The host-setup section of the approved document's bytes."""
    doc = pst.strict_object(raw)
    sec = doc.get("host_setup", doc)
    if not isinstance(sec, dict):
        raise ValueError("the document's host_setup is not an object")
    return sec


def bindings(*, document: bytes, email: Dict[str, Any], lanes: Dict[str, str], key_path: str, key_dir: str,
             router: Dict[str, Any], live_raw: bytes, stat_: Callable = os.stat) -> Any:
    """What the evidence binds, by name: the approved document, the email
    router's rendering, each lane's identity, the key's and its directory's
    identity, and the local router's activation config and spec. An
    Unresolved when an identity cannot be read."""
    lane = pp.lane_binding(lanes, stat_)
    if isinstance(lane, rh.Unresolved):
        return lane
    key = {}
    for role, p in (("signing", key_path), ("dir", key_dir)):
        try:
            st = stat_(p)
        except OSError as e:
            return rh.Unresolved(f"cannot stat the key's {role} {p}: {e}")
        key[role] = [st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode)]
    return {"host_setup": hashlib.sha256(document).hexdigest(), "email_router": hr.spec_sha256(email),
            "lanes": lane, "key": pe.sha_json(key), "local_router": pa.activation_binding(router, live_raw)}


class Docker:
    """The engine's answers the child needs, through the probes' Runner."""

    def __init__(self, runner: pp.Runner):
        self.runner = runner

    def inspect(self, name: str) -> Any:
        p = self.runner(["inspect", "--type", "container", name])
        if isinstance(p, rh.Unresolved):
            return p
        if p.rc != 0:
            return None
        try:
            doc = json.loads(p.out)
        except ValueError:
            return rh.Unresolved(f"docker inspect {name} printed no JSON")
        return doc[0] if isinstance(doc, list) and doc and isinstance(doc[0], dict) else None

    def image_env(self, image: str) -> Any:
        p = self.runner(["image", "inspect", "--format", "{{json .Config.Env}}", image])
        if isinstance(p, rh.Unresolved) or p.rc != 0:
            return rh.Unresolved(f"docker image inspect {image} did not answer")
        try:
            env = json.loads(p.out)
        except ValueError:
            return rh.Unresolved(f"docker image inspect {image} printed no JSON")
        return env if isinstance(env, list) else []

    def running(self, cid: str) -> Any:
        """partition_incident's inspect: {"running": bool}, None, or an
        Unresolved."""
        live = self.inspect(cid)
        if live is None or isinstance(live, rh.Unresolved):
            return live
        return {"running": bool((live.get("State") or {}).get("Running"))}


def selected_lanes(router_doc: Dict[str, Any], read: Callable[[str], bytes] = pst.read_bounded) -> Any:
    """Each enrolled agent's peer lane, by slug: the selected set sandy last
    wrote, under the instances directory the local router reads. An
    Unresolved when either cannot be read."""
    inst, sel = router_doc.get("instances_dir"), router_doc.get("selected_json")
    if not isinstance(inst, str) or not isinstance(sel, str):
        return rh.Unresolved("the local router's config names no instances_dir and selected_json")
    try:
        doc = pst.strict_object(read(sel))
    except (OSError, ValueError, UnicodeDecodeError) as e:
        return rh.Unresolved(f"the selection {sel} cannot be read: {e}")
    slugs = [e.get("slug") for e in doc.get("selected") or [] if isinstance(e, dict)]
    if not all(isinstance(s, str) and s and "/" not in s and not s.startswith(".") for s in slugs):
        return rh.Unresolved(f"the selection {sel} names a slug that is not one path component")
    return {s: posixpath.join(inst, s, "peer") for s in slugs}


def run_child(run_dir: str, lock_fd: int, *, runner: pp.Runner, stat_: Callable = os.stat,
              realpath_: Callable = os.path.realpath, lstat_: Callable = os.lstat,
              emit: Callable[[str], None] = print) -> int:
    """One run, start to outcome. Returns the child's exit code."""
    exec_root = posixpath.dirname(run_dir)
    check_lock(lock_fd, exec_root, stat_)
    boot = pst.RootedStore(evidence_dir=run_dir, run_dir=run_dir, live_config=posixpath.join(run_dir, CONTEXT))
    context = read_record(boot, posixpath.join(run_dir, CONTEXT))
    if isinstance(context, rh.Unresolved) or set(context) != CONTEXT_MEMBERS or context.get("schema") != SCHEMA:
        raise ChildError(f"the run's context is not usable: {getattr(context, 'reason', 'its members')}")
    store = pst.RootedStore(evidence_dir=context["evidence_dir"], run_dir=run_dir,
                            live_config=context["live_config_path"])
    rid, at = context["run_id"], context["started_at"]

    def finish(code: int, incident: bool, seen: Optional[str], why: str) -> int:
        out = {"schema": SCHEMA, "run_id": rid, "code": code, "incident": incident, "router_seen": seen,
               "why": why}
        failed = pi._try(store.new_file, posixpath.join(run_dir, OUTCOME), canonical(out))
        emit(f"partition-weekly {rid}: code {code}: {why}" + (f" (outcome NOT recorded: {failed})" if failed else ""))
        return code

    try:
        document = store.read(posixpath.join(run_dir, DOCUMENT))
        sec = document_section(document)
        spec = hs.load_spec(sec)
        live_raw = store.read(context["live_config_path"])
        router_doc = pst.strict_object(live_raw)
    except (OSError, ValueError, UnicodeDecodeError) as e:
        return finish(INCOMPLETE, False, None, f"the run's inputs cannot be read: {e}")
    docker = Docker(runner)
    email = hr.run_spec(spec, spec.hub)
    email_view = hr.view(email, hr.environment(spec, spec.hub))
    up = spec.hops[0][1]
    router_live = docker.inspect(spec.runtime_of(up)["container"])
    router = pa.spec_from_running(router_live) if isinstance(router_live, dict) else (
        router_live if isinstance(router_live, rh.Unresolved) else rh.Unresolved("the local router is not running"))
    if isinstance(router, rh.Unresolved):
        return finish(INCOMPLETE, False, None, f"the local router's spec cannot be read: {router.reason}")
    seen = router_live.get("Id") if isinstance(router_live, dict) else None
    lanes = selected_lanes(router_doc)
    if isinstance(lanes, rh.Unresolved):
        return finish(INCOMPLETE, False, seen, lanes.reason)
    key = ((router_doc.get("delegation") or {}).get("signing_key") or {}).get("path")
    if not isinstance(key, str):
        return finish(INCOMPLETE, False, seen, "the live config carries no signing key")
    bound = bindings(document=document, email=email, lanes=lanes, key_path=key, key_dir=posixpath.dirname(key),
                     router=router, live_raw=live_raw, stat_=stat_)
    if isinstance(bound, rh.Unresolved):
        return finish(INCOMPLETE, False, seen, bound.reason)
    failed = pi._try(store.new_file, posixpath.join(run_dir, EXPECT),
                     canonical({"schema": SCHEMA, "run_id": rid, "host": context["host"], "bindings": bound}))
    if failed:
        return finish(INCOMPLETE, False, seen, f"the expectation cannot be recorded, so nothing is probed: {failed}")
    try:
        plan = ppl.gather(host=context["host"], run_id=rid, at=at, email=email, email_view=email_view,
                          email_live=docker.inspect(email["name"]), email_image_env=docker.image_env(email["image"]),
                          email_volume=spec.secrets.volume, router=router, router_doc=router_doc, lanes=lanes,
                          agent_inspects={s: docker.inspect(s) for s in lanes}, bindings=bound)
    except ppl.PlanError as e:
        return finish(INCOMPLETE, False, seen, f"no plan: {e}")
    doc, code, report = pp.run(plan, runner, ppl.run_argv_for(router), stat_=stat_, realpath_=realpath_,
                               lstat_=lstat_)
    for line in report:
        emit(line)
    placed = doc is not None and pi._try(store.new_file, posixpath.join(context["evidence_dir"],
                                                                        f"partition-{rid}.json"), doc) is None
    failing = sorted(p["id"] for p in (json.loads(doc)["probes"] if doc else [])
                     if p["id"] in pe.FAIL_STOP and p["verdict"] == "FAIL")
    if not failing:
        return finish(PASSED if code == 0 else INCOMPLETE, False, seen, "no fail-stop failure")
    target = context["router_container_id"]
    fx = pi.Effects(rewrite=lambda: store.replace_live_config(pst.without_delegation(store.read(store.live_config))),
                    inspect=docker.running,
                    stop=lambda cid: runner(["stop", "-t", str(hv.STOP_TIMEOUT_S), cid]),
                    live_has_delegation=lambda: "delegation" in pst.strict_object(store.read(store.live_config)),
                    squatter_signing=lambda: rh.Unresolved("not asked by a weekly run"))
    pi.act(store, fx, evidence_dir=context["evidence_dir"], run_id=rid, at=at, failing=failing,
           token=(router_doc.get("delegation") or {}).get("partition_verified"),
           identity=target if isinstance(target, str) else rh.Unresolved("the run's context names no target"),
           evidence_persisted=placed, emit=emit)
    return finish(FAILED, True, seen, f"fail-stop: {', '.join(failing)}")

