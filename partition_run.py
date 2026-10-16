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
import re
import stat
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

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

#: Each record's schema, and its members with their types, exactly: the
#: pinned writer reads them by the same grammar (a test holds the two equal).
CONTEXT_SCHEMA = "amap-deploy.partition-context/2"
CONTEXT_SCHEMA_V1 = "amap-deploy.partition-context/1"
#: The run modes the context records; a /1 context is a weekly run's.
MODES = ("weekly", "prospective")
#: Why A2 does not read the local router's processes: it runs stopped.
P01_STOPPED = "the local router is stopped for A2; A5's post-activation P01 measures it"
EXPECT_SCHEMA = "amap-deploy.partition-expect/1"
OUTCOME_SCHEMA = "amap-deploy.partition-outcome/1"
_OPT_STR = (str, type(None))
CONTEXT_MEMBERS_V1 = {"schema": str, "run_id": str, "host": str, "started_at": str, "evidence_dir": str,
                      "live_config_path": str, "router_container_id": _OPT_STR, "engine": str, "docker": str}
CONTEXT_MEMBERS = dict(CONTEXT_MEMBERS_V1, mode=str)
EXPECT_MEMBERS = {"schema": str, "run_id": str, "host": str, "bindings": dict}
OUTCOME_MEMBERS = {"schema": str, "run_id": str, "code": int, "incident": bool, "router_seen": _OPT_STR, "why": str,
                   "config_sha256": _OPT_STR, "evidence_run_id": _OPT_STR, "evidence_sha256": _OPT_STR,
                   "inspect_digest": _OPT_STR}
#: The snapshot a passing run records for its writer: all of these, or none.
SNAPSHOT = ("router_seen", "config_sha256", "evidence_run_id", "evidence_sha256", "inspect_digest")
CONTEXT, DOCUMENT, EXPECT, OUTCOME = "context.json", "document.json", "expect.json", "outcome.json"
ACTIVATION = "activation.json"
LOCK = "lock"
#: The child's own exit codes, as outcome.json records them.
PASSED, FAILED, INCOMPLETE = 0, 1, 2


class ChildError(Exception):
    """The run cannot start: nothing is probed, and the outcome says why."""


def canonical(doc: Dict[str, Any]) -> bytes:
    return pe.canonical(doc)


def typed(doc: Any, members: Dict[str, Any], schema: str) -> bool:
    """`doc` exactly `members`, each of its type (a bool is never an int,
    nor a str), with the given schema."""
    if not isinstance(doc, dict) or set(doc) != set(members) or doc.get("schema") != schema:
        return False
    for k, t in members.items():
        v = doc[k]
        if isinstance(v, bool) and t is not bool:
            return False
        if not isinstance(v, t):
            return False
    return True


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


def check_run_dir(run_dir: str, lstat_: Callable = os.lstat, root_uid: int = 0,
                  bundle_dir: Optional[str] = None) -> str:
    """The run directory the writer passed: an absolute, normalised path
    named run-<id>, directly under the exec root this bundle sits in, a real
    directory (never a link) that only root can enter. Returns the exec
    root."""
    exec_root = posixpath.dirname(run_dir)
    if not run_dir.startswith("/") or posixpath.normpath(run_dir) != run_dir \
            or not re.fullmatch(r"run-[A-Za-z0-9._-]{1,64}", posixpath.basename(run_dir)):
        raise ChildError(f"the run directory {run_dir!r} is not <exec_root>/run-<id>")
    here = posixpath.dirname(bundle_dir or posixpath.dirname(os.path.realpath(__file__)))
    if here != exec_root:
        raise ChildError(f"the run directory is not under this bundle's exec root {here}")
    try:
        st = lstat_(run_dir)
    except OSError as e:
        raise ChildError(f"the run directory cannot be checked: {e}") from None
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != root_uid or stat.S_IMODE(st.st_mode) != 0o700:
        raise ChildError("the run directory is not a real directory, root's, mode 0700")
    return exec_root


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

    def image_config(self, image: str) -> Any:
        """The image's own config ({Env, Entrypoint, Cmd}), or an Unresolved."""
        p = self.runner(["image", "inspect", "--format", "{{json .Config}}", image])
        if isinstance(p, rh.Unresolved) or p.rc != 0:
            return rh.Unresolved(f"docker image inspect {image} did not answer")
        try:
            cfg = json.loads(p.out)
        except ValueError:
            return rh.Unresolved(f"docker image inspect {image} printed no JSON")
        return cfg if isinstance(cfg, dict) else rh.Unresolved(f"docker image inspect {image} printed no config")

    def image_env(self, image: str) -> Any:
        p = self.runner(["image", "inspect", "--format", "{{json .Config.Env}}", image])
        if isinstance(p, rh.Unresolved) or p.rc != 0:
            return rh.Unresolved(f"docker image inspect {image} did not answer")
        try:
            env = json.loads(p.out)
        except ValueError:
            return rh.Unresolved(f"docker image inspect {image} printed no JSON")
        return env if isinstance(env, list) else []

    def running_by_name(self, name: str) -> Any:
        """Whether a container under `name` runs: True or False only when the
        engine affirms it (absence is a listing by exact name that lists
        nothing), else an Unresolved. A guard read, never a stop target."""
        p = self.runner(["inspect", "--type", "container", "--format", "{{json .State}}", name])
        if isinstance(p, rh.Unresolved):
            return p
        if p.rc == 0:
            try:
                state = json.loads(p.out)
            except ValueError:
                return rh.Unresolved(f"docker inspect {name} printed no JSON")
            if not isinstance(state, dict) or not isinstance(state.get("Running"), bool):
                return rh.Unresolved(f"docker inspect {name} states no running state")
            return state["Running"] or state.get("Paused") is True or state.get("Restarting") is True
        q = self.runner(["ps", "--all", "--quiet", "--no-trunc", "--filter", f"name=^/{name}$"])
        if not isinstance(q, rh.Unresolved) and q.rc == 0 and not q.out.strip():
            return False
        return rh.Unresolved(f"docker cannot say whether {name} runs")

    def running(self, cid: str) -> Any:
        """partition_incident's inspect, affirmative only: {"running": bool}
        when the engine states it (paused or restarting count as running),
        None only when the engine affirms no such container exists, and an
        Unresolved whenever it cannot say."""
        p = self.runner(["inspect", "--type", "container", "--format", "{{json .State}}", cid])
        if isinstance(p, rh.Unresolved):
            return p
        if p.rc == 0:
            try:
                state = json.loads(p.out)
            except ValueError:
                return rh.Unresolved(f"docker inspect {cid} printed no JSON")
            if not isinstance(state, dict) or not isinstance(state.get("Running"), bool):
                return rh.Unresolved(f"docker inspect {cid} states no running state")
            return {"running": state["Running"] or state.get("Paused") is True or state.get("Restarting") is True}
        q = self.runner(["ps", "--all", "--quiet", "--no-trunc", "--filter", f"id={cid}"])
        if not isinstance(q, rh.Unresolved) and q.rc == 0 and not q.out.strip():
            return None
        return rh.Unresolved(f"docker cannot say whether {cid} exists")


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


def a5_snapshot(*, store: pst.RootedStore, run_dir: str, context: Dict[str, Any], live: Any, image: Any,
                live_raw: bytes, bound: Dict[str, str], now: float,
                read_placed: Callable[[str], bytes] = pe.read_placed) -> Any:
    """The stop target this passing run may report, with the snapshot its
    writer re-checks: only when A5's comparison holds against A1's APPROVED
    record (handed over as activation.json) and the live config's token is
    the current passing evidence's. Otherwise an Unresolved saying why. The
    name only found the candidate; the id is the one these facts are of."""
    try:
        approved = pa.parse_activation(store.read(posixpath.join(run_dir, ACTIVATION)))
    except (OSError, pa.ActivationError) as e:
        return rh.Unresolved(f"no approved activation record: {e}")
    if approved["host"] != context["host"] or approved["final_config_path"] != context["live_config_path"]:
        return rh.Unresolved("the approved activation record is another host's or another config path's")
    bad = pa.a5_differences(live, image, approved, live_raw)
    if bad:
        return rh.Unresolved("the local router is not the approved activation: " + "; ".join(bad))
    token = json.loads(live_raw)["delegation"]["partition_verified"]
    doc, raw, why = pe.named_document(token, evidence_dir=context["evidence_dir"], host=context["host"],
                                      read=read_placed)
    if doc is None:
        if raw == pe.NAMED_NO_RUN:
            return rh.Unresolved("the live config's token names no run")
        if raw == pe.NAMED_MISMATCH:
            return rh.Unresolved("the live config's token is not its evidence's")
        return rh.Unresolved(f"the token's evidence cannot be read: {why}")
    evidence_rid = token.partition(":")[0]
    stale = pe.staleness(doc, now=now, bindings=bound)
    if stale:
        return rh.Unresolved("the token's evidence is not current: " + "; ".join(stale))
    return {"router_seen": live["Id"], "config_sha256": pe.sha_bytes(live_raw), "evidence_run_id": evidence_rid,
            "evidence_sha256": pe.sha_bytes(raw), "inspect_digest": pe.sha_json(pa.inspect_projection(live))}


def a2_outcome(doc: Optional[bytes], placed: bool, p01: List[Any], unmeasured: Dict[str, str]) -> Tuple[int, bool, str]:
    """A2's outcome when no fail-stop probe failed: PASSED only with the
    token in the document, the document placed, P02 PASS and P01 PASS or
    UNKNOWN for exactly the deliberately unmeasured stopped router, judged
    per principal (never by the aggregate or a reason string); any
    other shortfall is INCOMPLETE (a handoff), and T, when placed, is named."""
    parsed = json.loads(doc) if doc else None
    token = parsed[pe.TOKEN_MEMBER] if parsed else None
    verdicts = {p["id"]: p["verdict"] for p in parsed["probes"]} if parsed else {}
    named = f" (its token {token} is placed)" if token and placed else ""
    if not token:
        return INCOMPLETE, False, "A2 produced no token"
    if not placed:
        return INCOMPLETE, False, "A2's evidence was not placed, so it is not A2's evidence"
    dispositions = p01[0]["principals"] if len(p01) == 1 else {}
    measured = {p: v for p, v in dispositions.items() if v != pp.UNMEASURED}
    p01_ok = bool(dispositions) and all(v == "PASS" for v in measured.values()) \
        and set(dispositions) - set(measured) == set(unmeasured) \
        and verdicts.get("P01") in ("PASS", "UNKNOWN") and (verdicts.get("P01") == "PASS") == (not unmeasured)
    if not p01_ok:
        return INCOMPLETE, False, f"A2's P01 is {verdicts.get('P01')}, not PASS or the stopped router's UNKNOWN{named}"
    if verdicts.get("P02") != "PASS":
        return INCOMPLETE, False, f"A2's P02 is {verdicts.get('P02')}, not PASS{named}"
    return PASSED, False, f"A2 passed{named}"


def run_child(run_dir: str, lock_fd: int, *, runner: pp.Runner, stat_: Callable = os.stat,
              realpath_: Callable = os.path.realpath, lstat_: Callable = os.lstat,
              emit: Callable[[str], None] = print, now_: Callable[[], float] = time.time,
              read_placed_: Callable[[str], bytes] = pe.read_placed) -> int:
    """One run, start to outcome. Returns the child's exit code."""
    exec_root = posixpath.dirname(run_dir)
    check_lock(lock_fd, exec_root, stat_)
    boot = pst.RootedStore(evidence_dir=run_dir, run_dir=run_dir, live_config=posixpath.join(run_dir, CONTEXT))
    context = read_record(boot, posixpath.join(run_dir, CONTEXT))
    if not isinstance(context, rh.Unresolved) and typed(context, CONTEXT_MEMBERS_V1, CONTEXT_SCHEMA_V1):
        context = dict(context, mode=MODES[0])
    elif isinstance(context, rh.Unresolved) or not typed(context, CONTEXT_MEMBERS, CONTEXT_SCHEMA) \
            or context["mode"] not in MODES:
        raise ChildError(f"the run's context is not usable: {getattr(context, 'reason', 'its grammar')}")
    prospective = context["mode"] == MODES[1]
    store = pst.RootedStore(evidence_dir=context["evidence_dir"], run_dir=run_dir,
                            live_config=context["live_config_path"])
    rid, at = context["run_id"], context["started_at"]

    def finish(code: int, incident: bool, why: str, snapshot: Optional[Dict[str, str]] = None) -> int:
        out = dict({k: None for k in SNAPSHOT}, **(snapshot or {}), schema=OUTCOME_SCHEMA, run_id=rid, code=code,
                   incident=incident, why=why)
        failed = pi._try(store.new_file, posixpath.join(run_dir, OUTCOME), canonical(out))
        emit(f"partition-weekly {rid}: code {code}: {why}" + (f" (outcome NOT recorded: {failed})" if failed else ""))
        return code

    try:
        document = store.read(posixpath.join(run_dir, DOCUMENT))
        sec = document_section(document)
        spec = hs.load_spec(sec)
        live_raw = store.read(context["live_config_path"])
        router_doc = pst.strict_object(live_raw)
        if prospective:
            # A2: [1]'s inputs are A1's placed record, never the running router
            # (it is stopped) or the live config, which is checked only as G1.
            if "delegation" in router_doc:
                return finish(INCOMPLETE, False, "A2 is pre-activation: the live config now carries delegation")
            approved = pa.parse_activation(store.read(posixpath.join(run_dir, ACTIVATION)))
            if approved["host"] != context["host"] or approved["final_config_path"] != context["live_config_path"]:
                return finish(INCOMPLETE, False, "A1's record is another host's or another config path's")
            live_raw = approved["staged"].encode("utf-8")
            router_doc = pst.strict_object(live_raw)
    except (OSError, ValueError, UnicodeDecodeError) as e:
        return finish(INCOMPLETE, False, f"the run's inputs cannot be read: {e}")
    docker = Docker(runner)
    email = hr.run_spec(spec, spec.hub)
    email_view = hr.view(email, hr.environment(spec, spec.hub))
    up = spec.hops[0][1]
    if prospective:
        router_live, router = None, approved["spec"]
    else:
        router_live = docker.inspect(spec.runtime_of(up)["container"])
        router = pa.spec_from_running(router_live) if isinstance(router_live, dict) else (
            router_live if isinstance(router_live, rh.Unresolved) else rh.Unresolved("the local router is not running"))
    if isinstance(router, rh.Unresolved):
        return finish(INCOMPLETE, False, f"the local router's spec cannot be read: {router.reason}")
    lanes = selected_lanes(router_doc)
    if isinstance(lanes, rh.Unresolved):
        return finish(INCOMPLETE, False, lanes.reason)
    key = ((router_doc.get("delegation") or {}).get("signing_key") or {}).get("path")
    if not isinstance(key, str):
        return finish(INCOMPLETE, False, "the live config carries no signing key")
    bound = bindings(document=document, email=email, lanes=lanes, key_path=key, key_dir=posixpath.dirname(key),
                     router=router, live_raw=live_raw, stat_=stat_)
    if isinstance(bound, rh.Unresolved):
        return finish(INCOMPLETE, False, bound.reason)
    failed = pi._try(store.new_file, posixpath.join(run_dir, EXPECT),
                     canonical({"schema": EXPECT_SCHEMA, "run_id": rid, "host": context["host"], "bindings": bound}))
    if failed:
        return finish(INCOMPLETE, False, f"the expectation cannot be recorded, so nothing is probed: {failed}")
    try:
        plan = ppl.gather(host=context["host"], run_id=rid, at=at, email=email, email_view=email_view,
                          email_live=docker.inspect(email["name"]), email_image_env=docker.image_env(email["image"]),
                          email_volume=spec.secrets.volume, router=router, router_doc=router_doc, lanes=lanes,
                          agent_inspects={s: docker.inspect(s) for s in lanes}, bindings=bound)
    except ppl.PlanError as e:
        return finish(INCOMPLETE, False, f"no plan: {e}")
    p01: List[Any] = []
    unmeasured = {up: P01_STOPPED} if prospective else None
    doc, code, report = pp.run(plan, runner, ppl.run_argv_for(router), stat_=stat_, realpath_=realpath_,
                               lstat_=lstat_, p01_unmeasured=unmeasured, p01_out=p01)
    for line in report:
        emit(line)
    placed = doc is not None and pi._try(store.new_file, posixpath.join(context["evidence_dir"],
                                                                        f"partition-{rid}.json"), doc) is None
    failing = sorted(p["id"] for p in (json.loads(doc)["probes"] if doc else [])
                     if p["id"] in pe.FAIL_STOP and p["verdict"] == "FAIL")
    if not failing and prospective:
        return finish(*a2_outcome(doc, placed, p01, unmeasured))
    if not failing:
        if code != 0:
            return finish(INCOMPLETE, False, "no fail-stop failure, but the run did not pass")
        snap = a5_snapshot(store=store, run_dir=run_dir, context=context, live=router_live,
                           image=docker.image_config(router_live.get("Image")), live_raw=live_raw, bound=bound,
                           now=now_(), read_placed=read_placed_)
        if isinstance(snap, rh.Unresolved):
            return finish(PASSED, False, f"passed; no stop target: {snap.reason}")
        return finish(PASSED, False, "passed", snap)
    target = context["router_container_id"]
    fx = pi.Effects(rewrite=lambda: store.replace_live_config(pst.without_delegation(store.read(store.live_config))),
                    inspect=docker.running,
                    stop=lambda cid: runner(["stop", "-t", str(hv.STOP_TIMEOUT_S), cid]),
                    live_has_delegation=lambda: "delegation" in pst.strict_object(store.read(store.live_config)),
                    squatter_signing=lambda: rh.Unresolved("not asked by a weekly run"))
    if prospective:
        fx.router_running = lambda: docker.running_by_name(router["name"])
    pi.act(store, fx, evidence_dir=context["evidence_dir"], run_id=rid, at=at, failing=failing,
           token=(router_doc.get("delegation") or {}).get("partition_verified"),
           identity=target if isinstance(target, str) else rh.Unresolved("the run's context names no target"),
           evidence_persisted=placed, emit=emit, mode=context["mode"])
    return finish(FAILED, True, f"fail-stop: {', '.join(failing)}")

