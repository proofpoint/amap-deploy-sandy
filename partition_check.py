"""`amap-sandy.py partition-check`: A5's six claims about an activated local
router, read-only, as the operator. It writes and places nothing.

One canonical JSON object, schema `amap-deploy.partition-check/2`:
`schema`, `host`, `at`, `inputs` and `checks`, the six checks in fixed order,
each exactly {id, claim, result, reason, remedy}.
- V1: the running local router is exactly A1's activation spec
  (`partition_activation.verify_activation`'s structure claim).
- V2: its live config is A1's staged bytes plus the live token, and the
  router's own status.json, read with its own clock in one exec, is fresh
  and shows no refused reload.
- E1, E2: A2's evidence document, the one the live token names, judged by
  `partition_evidence.verify_document`. The key identity and P03's mount
  roles are root's observation in the step-7d weekly run that the stop target
  names: the operator cannot stat the key through [1]'s 0700 directory.
  Until every input exists, both are UNKNOWN ("run step 7d"), never the
  stale FAIL that would tell the operator to de-activate. Their
  local_router binding hashes the live config FILE beside the running spec;
  that the router adopted the file is V2's (the reload flag), not E1's.
- T1: the weekly job's stop target (`partition_setup.verify_target`).
- R1: no weekly run is left undecided (`partition_runs.verify_runs`).

The exit status means only "the object was written in full". `--ready`
exits 0 only when all six are PASS: that is A5's acceptance.

Every docker call goes through ss.docker(spec.secrets), with no -H: the
local router and the hub-link router run on the one engine it reaches,
and supervision.engine must be that engine. Another engine fails closed
(its router reads as not running).
"""

from __future__ import annotations

import hashlib
import json
import math
import posixpath
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import partition_activation as pa
import partition_evidence as pe
import partition_setup as ps
import router_health as rh

SCHEMA = "amap-deploy.partition-check/2"
IDS = ("V1", "V2", "E1", "E2", "T1", "R1")
INPUT_MEMBERS = ("live_config_sha256", "evidence_path", "evidence_sha256", "token", "activation_sha256",
                 "router_container_id", "inspect_digest", "key_observed")
#: The not-required suffix verify_target and verify_runs put on their PASS
#: claim, without its parentheses: d2 §4.4 emits that cell as UNKNOWN.
NOT_REQUIRED = "not required: delegation is not rendered and the gate is not set"
NONE = "<none>"
E1_CLAIM = ("the partition evidence {path} is well-formed and passing, with the key identity as root observed it "
            "in run {run_id} at {at}")
RESIDUE = ("the key identity and P03's mount roles are root's observation in run {run_id} at {at} (document "
           "sha256 {sha}); a change after that run is seen only at the next root run")
RUN_7D = "run step 7d"
NO_CURRENT = "no current document yet: run step 7d"
RELOAD_FAILED = "the running router refused its config file and runs an older one"
KEY_CHANGED = "the key changed between A2 and 7d"

#: The router's status.json and the container's own clock, in one exec: the
#: freshness is judged on [1]'s clock. argv[1] is the state_dir A1's staged
#: bytes name.
STATUS_SCRIPT = ("import json,os,sys,time\n"
                 "p=os.path.join(sys.argv[1],'status.json')\n"
                 "try:\n"
                 "    t=open(p).read()\n"
                 "except OSError as e:\n"
                 "    print(json.dumps({'now':time.time(),'error':str(e)}))\n"
                 "else:\n"
                 "    print(json.dumps({'now':time.time(),'status':t}))\n")


def cell(cid: str, c: rh.Check, base: Optional[str] = None) -> Dict[str, str]:
    """One emitted check, keyed on the result it EMITS:
    1. UNKNOWN: reason is Check.reason;
    2. the not-required mapping (T1, R1; `base` given): a PASS whose claim is
       `base (NOT_REQUIRED)` is emitted UNKNOWN, with the base claim and
       NOT_REQUIRED as its reason;
    3. FAIL: reason is str(Check.actual), which holds the sentence;
    4. PASS: reason "" (E1 adds its residue prefix itself)."""
    if base is not None and c.result == rh.PASS and c.claim == f"{base} ({NOT_REQUIRED})":
        return {"id": cid, "claim": base, "result": rh.UNKNOWN, "reason": NOT_REQUIRED, "remedy": c.remedy}
    if c.result == rh.UNKNOWN:
        reason = c.reason
    elif c.result == rh.FAIL:
        reason = str(c.actual)
    else:
        reason = ""
    return {"id": cid, "claim": c.claim, "result": c.result, "reason": reason,
            "remedy": c.remedy if c.result != rh.PASS else ""}


def ready(doc: Dict[str, Any]) -> bool:
    """A5's acceptance: every one of the six ids present, once, and PASS."""
    checks = doc.get("checks") if isinstance(doc, dict) else None
    return (isinstance(checks, list) and [c.get("id") for c in checks] == list(IDS)
            and all(c.get("result") == rh.PASS for c in checks))


# --- V2: the router's own status, on its own clock ------------------------------


def status_problem(read: Any, *, interval_floor: float = 1.0) -> Tuple[str, str]:
    """(PASS | FAIL | UNKNOWN, why) for the in-container read: fresh iff
    -CLOCK_TOLERANCE_S <= now - last_poll_ts <= FRESHNESS_MULTIPLE x
    interval_s, on [1]'s clock; status.json -> classification ->
    config_reload_failed true FAILs. As router_health reads it: an absent or
    null classification, or one without the member, is not failing; a
    present non-object section, or a non-bool member, is UNKNOWN."""
    if isinstance(read, rh.Unresolved):
        return rh.UNKNOWN, read.reason
    now = read.get("now") if isinstance(read, dict) else None
    if not isinstance(now, (int, float)) or isinstance(now, bool) or not math.isfinite(now):
        return rh.UNKNOWN, "the container printed no clock"
    if "status" not in read:
        return rh.UNKNOWN, f"status.json cannot be read in the container: {read.get('error')}"
    try:
        doc = json.loads(read["status"])
    except (TypeError, ValueError) as e:
        return rh.UNKNOWN, f"status.json is not JSON: {e}"
    if not isinstance(doc, dict):
        return rh.UNKNOWN, "status.json is not an object"
    interval = doc.get("interval_s")
    if not isinstance(interval, (int, float)) or isinstance(interval, bool) or not math.isfinite(interval) \
            or interval < interval_floor:
        return rh.UNKNOWN, f"status.json's interval_s is {interval!r}, not a finite number of at least 1"
    last = parse_router_ts(doc.get("last_poll_ts"))
    if last is None:
        return rh.UNKNOWN, f"status.json's last_poll_ts is {doc.get('last_poll_ts')!r}, not the router's timestamp"
    age = now - last
    bound = rh.FRESHNESS_MULTIPLE * interval
    if age < -pe.CLOCK_TOLERANCE_S:
        return rh.UNKNOWN, f"status.json's last poll is {-age:.0f}s ahead of the router's own clock"
    if age > bound:
        return rh.UNKNOWN, f"status.json is {age:.0f}s old on the router's clock, past {bound:.0f}s"
    section = doc.get("classification")
    if section is not None and not isinstance(section, dict):
        return rh.UNKNOWN, "status.json's classification section is not an object"
    flag = (section or {}).get("config_reload_failed", False)
    if not isinstance(flag, bool):
        return rh.UNKNOWN, f"status.json's config_reload_failed is {flag!r}, not a JSON boolean"
    if flag:
        return rh.FAIL, RELOAD_FAILED
    return rh.PASS, ""


def parse_router_ts(ts: Any) -> Optional[float]:
    """The router's UTC timestamp (`YYYY-MM-DDTHH:MM:SS[.ffffff]Z`) as epoch
    seconds, or None."""
    import datetime
    if not isinstance(ts, str) or not ts.endswith("Z"):
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.datetime.strptime(ts, fmt).replace(tzinfo=datetime.timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def v2_check(bytes_check: rh.Check, status: Any) -> rh.Check:
    """V2: verify_activation's live-config claim, then, when the bytes hold,
    the router's own status."""
    if bytes_check.result != rh.PASS:
        return bytes_check
    result, why = status_problem(status)
    want = rh.Fact("status", True, "the router's own status.json, fresh on its clock, with no refused reload")
    remedy = "restart the local router on the activated config (A4: docker/run.sh --config <the live config> --detach)"
    if result == rh.PASS:
        return bytes_check
    if result == rh.FAIL:
        return rh.check(bytes_check.claim, want, why, remedy,
                        do_not="never read the file as what the router runs while the flag is set")
    return rh.unknown(bytes_check.claim, want, why, "start the local router, or wait for its next poll")


# --- E1 and E2: A2's evidence, with root's 7d key observation ---------------------


def key_observation(*, host: str, evidence_dir: str, live: Dict[str, Any], a2_raw: bytes, a2_doc: Dict[str, Any],
                    activation_raw: bytes, approved: Dict[str, Any], key_path: str, now: float,
                    read: Callable[[str], bytes]) -> Tuple[Any, Any, str]:
    """(key_observed, the 7d document, "") when every (β′) clause holds,
    else (None, None, why). Clause 5 (the key differing from A2's) is not
    judged here: it is E1's FAIL."""
    try:
        target = ps.parse_target(read(posixpath.join(evidence_dir, ps.STOP_TARGET)))
    except FileNotFoundError:
        return None, None, f"no stop target yet: {RUN_7D}"
    except (OSError, ValueError, UnicodeDecodeError) as e:
        return None, None, f"the stop target cannot be read as placed: {e}"
    if target["host"] != host:
        return None, None, "the stop target is another host's"
    if target["activation_sha256"] != hashlib.sha256(activation_raw).hexdigest():
        return None, None, "the stop target was recorded against another A1 activation"
    if target["evidence_run_id"] != a2_doc["run_id"] or target["evidence_sha256"] != hashlib.sha256(a2_raw).hexdigest():
        return None, None, "the stop target does not cite A2's document"
    name = f"partition-{target['run_id']}.json"
    try:
        raw = read(posixpath.join(evidence_dir, name))
        doc = pe.parse(raw, host=host)
    except FileNotFoundError:
        return None, None, f"{name}, the 7d document the stop target names, is absent: {RUN_7D}"
    except (OSError, ValueError, UnicodeDecodeError) as e:
        return None, None, f"{name} cannot be read as placed, for this host: {e}"
    if doc["run_id"] != target["run_id"]:
        return None, None, f"{name} is another run's"
    staged_key = (((json.loads(approved["staged"]).get("delegation") or {}).get("signing_key") or {}).get("path"))
    live_key = ((live.get("delegation") or {}).get("signing_key") or {}).get("path")
    if not (staged_key == live_key == key_path):
        return None, None, "the signing key path is not the same in A1, the live config and the document"
    age = now - pe.at_seconds(doc["at"])
    if age > pe.FRESH_FOR_S or age < -pe.CLOCK_TOLERANCE_S:
        return None, None, f"{name} is not current (its at is {doc['at']}): the weekly run renews it"
    if pe.at_seconds(doc["at"]) < pe.at_seconds(a2_doc["at"]):
        return None, None, f"{name} is older than A2's document"
    observed = {"run_id": doc["run_id"], "at": doc["at"], "document_sha256": hashlib.sha256(raw).hexdigest()}
    return observed, doc, ""


def p03_roles(doc: Dict[str, Any]) -> List[str]:
    """P03's target roles as the given run recorded them."""
    return next((list(p["target_role"]) for p in doc["probes"] if p["id"] == "P03"), [])


def residue(observed: Any) -> str:
    o = observed or {}
    return RESIDUE.format(run_id=o.get("run_id", NONE), at=o.get("at", NONE), sha=o.get("document_sha256", NONE))


def e1_claim(path: str, observed: Any) -> str:
    o = observed or {}
    return E1_CLAIM.format(path=path, run_id=o.get("run_id", NONE), at=o.get("at", NONE))


def e1_cell(path: str, observed: Any, c: Optional[rh.Check], why: str = "") -> Dict[str, str]:
    """E1, its claim from E1_CLAIM, its reason always the residue prefix,
    then `; ` and the UNKNOWN's or FAIL's sentence."""
    if c is None:
        out = {"result": rh.UNKNOWN, "sentence": why, "remedy": f"{RUN_7D}, then run partition-check again"}
    else:
        emitted = cell("E1", c)
        out = {"result": emitted["result"], "sentence": emitted["reason"], "remedy": emitted["remedy"]}
    reason = residue(observed) + (f"; {out['sentence']}" if out["result"] != rh.PASS else "")
    return {"id": "E1", "claim": e1_claim(path, observed), "result": out["result"], "reason": reason,
            "remedy": out["remedy"]}


def e2_unknown() -> Dict[str, str]:
    return {"id": "E2", "claim": "the local router signs with the current passing document's token, or not at all",
            "result": rh.UNKNOWN, "reason": NO_CURRENT, "remedy": f"{RUN_7D}, then run partition-check again"}


def worst(checks: List[rh.Check]) -> rh.Check:
    """The first FAIL, else the first UNKNOWN, else the last check."""
    return next((c for c in checks if c.result == rh.FAIL),
                next((c for c in checks if c.result == rh.UNKNOWN), checks[-1]))


# --- The document -----------------------------------------------------------------


def document(*, host: str, at: str, inputs: Dict[str, Any], cells: List[Dict[str, str]]) -> bytes:
    """The canonical object: exactly its members, the six cells in order."""
    if [c["id"] for c in cells] != list(IDS) or set(inputs) != set(INPUT_MEMBERS):
        raise ValueError("partition-check builds exactly its six cells and its inputs")
    return pe.canonical({"schema": SCHEMA, "host": host, "at": at, "inputs": inputs, "checks": cells})


def carries_delegation(live: Any) -> bool:
    """Whether a parsed local-router config has a delegation block: A1's
    de-activate note, read here so the renderer's module names no
    delegation member."""
    return isinstance(live, dict) and "delegation" in live


def utc_now(now: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))


# --- Reading the host, and the six cells ---------------------------------------


def ask_json(spec: Any, argv: List[str], what: str) -> Any:
    """One docker call through ss.docker(spec.secrets), which honours the
    document's docker_via_sudo: its stdout as JSON, or an Unresolved."""
    import secret_setup as ss
    try:
        p = rh.run(ss.docker(spec.secrets) + argv)
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    if p.rc != 0:
        return rh.Unresolved(f"docker could not read {what} (exit {p.rc})")
    try:
        return json.loads(p.out)
    except ValueError:
        return rh.Unresolved(f"docker printed no JSON for {what}")


def ask_inspect(spec: Any, ref: str) -> Any:
    """`docker inspect` of one container: its document, None when the engine
    affirms there is none, or an Unresolved."""
    import secret_setup as ss
    try:
        p = rh.run(ss.docker(spec.secrets) + ["inspect", "--type", "container", ref])
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    if p.rc != 0:
        q = rh.run(ss.docker(spec.secrets) + ["ps", "--all", "--quiet", "--no-trunc", "--filter", f"name=^/{ref}$"])
        return None if q.rc == 0 and not q.out.strip() else rh.Unresolved(f"docker inspect {ref} exited {p.rc}")
    try:
        doc = json.loads(p.out)
    except ValueError:
        return rh.Unresolved(f"docker inspect {ref} printed no JSON")
    return doc[0] if isinstance(doc, list) and doc and isinstance(doc[0], dict) else None


def unknown_cell(cid: str, claim: str, why: str, remedy: str) -> Dict[str, str]:
    return {"id": cid, "claim": claim, "result": rh.UNKNOWN, "reason": why, "remedy": remedy}


V1_CLAIM = "the running local router is exactly its activation spec"
V2_CLAIM = "the local router's live config is the activation rendering plus the token, and nothing else"


def evaluate(spec: Any, *, document_raw: bytes, document_sha256: str, now: float,
             p: Optional[Dict[str, Any]] = None) -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
    """(inputs, the six cells), for the host-setup `spec` loaded from the unit
    argv's `--document`. `p` may supply `read` (placed files), `read_live`,
    `read_lanes` (sandy's selected set), `inspect`, `image`, `status`, `stat`
    and `lstat`; the defaults read the host and ask the engine through
    ss.docker(spec.secrets)."""
    import os
    import host_setup as hsu
    import hub_runtime as hr
    import partition_probe as pp
    import partition_run as prun
    import partition_runs as pruns
    p = dict(p or {})
    read = p.get("read", ps.read_placed)
    read_live = p.get("read_live", ps.read_record)
    inspect = p.get("inspect", lambda ref: ask_inspect(spec, ref))
    host = hsu.partition_host(spec)
    evidence_dir = spec.partition.evidence_dir
    live_path = spec.keys.local_config
    router_name = spec.runtime_of(spec.hops[0][1])["container"]
    inputs: Dict[str, Any] = dict.fromkeys(INPUT_MEMBERS)

    try:
        live_raw = read_live(live_path)
        live_doc = ps._strict(live_raw)
        if not isinstance(live_doc, dict):
            raise ValueError("it is not a JSON object")
        inputs["live_config_sha256"] = hashlib.sha256(live_raw).hexdigest()
    except (OSError, ValueError, UnicodeDecodeError) as e:
        live_raw, live_doc = rh.Unresolved(f"the live config {live_path} cannot be read: {e}"), None
    try:
        activation_raw = read(posixpath.join(evidence_dir, ps.ACTIVATION))
        approved = pa.parse_activation(activation_raw)
        inputs["activation_sha256"] = hashlib.sha256(activation_raw).hexdigest()
    except (OSError, ValueError) as e:
        activation_raw, approved = None, rh.Unresolved(f"A1's placed record cannot be read: {e}")
    live = inspect(router_name)
    if isinstance(live, dict):
        inputs["router_container_id"] = live.get("Id")
        inputs["inspect_digest"] = pe.sha_json(pa.inspect_projection(live))
    token = ((live_doc or {}).get("delegation") or {}).get("partition_verified") if live_doc else None
    inputs["token"] = token if isinstance(token, str) else None
    a2_doc = a2_raw = None
    named_why = "the live config carries no token" if not isinstance(token, str) else ""
    if isinstance(token, str):
        a2_doc, a2_raw, named_why = pe.named_document(token, evidence_dir=evidence_dir, host=host, read=read)
        if a2_doc is not None:
            inputs["evidence_path"] = posixpath.join(evidence_dir, f"partition-{a2_doc['run_id']}.json")
            inputs["evidence_sha256"] = hashlib.sha256(a2_raw).hexdigest()
    evidence_path = inputs["evidence_path"] or posixpath.join(evidence_dir, f"partition-{(token or '').partition(':')[0] or NONE}.json")

    # V1, V2.
    if isinstance(approved, rh.Unresolved) or isinstance(live_raw, rh.Unresolved):
        why = approved.reason if isinstance(approved, rh.Unresolved) else live_raw.reason
        v1 = unknown_cell("V1", V1_CLAIM, why, "place A1's record, and make the live config readable")
        v2 = unknown_cell("V2", V2_CLAIM, why, "place A1's record, and make the live config readable")
    else:
        image = p["image"](live) if "image" in p else (
            ask_json(spec, ["image", "inspect", "--format", "{{json .Config}}", live["Image"]], "the router's image")
            if isinstance(live, dict) else rh.Unresolved("the local router is not running"))
        fresh_token = None
        if a2_doc is not None:
            age = now - pe.at_seconds(a2_doc["at"])
            fresh_token = token if -pe.CLOCK_TOLERANCE_S <= age <= pe.FRESH_FOR_S else None
        checks = pa.verify_activation(live=live if not isinstance(live, rh.Unresolved) else live, image=image,
                                      spec=approved["spec"], staged=approved["staged"].encode("utf-8"),
                                      final_raw=live_raw, token=fresh_token)
        if "status" in p:
            status = p["status"]
        else:
            # The exec names the container V1 judged, by its Id: a recreate
            # between the two calls cannot pair one container's spec with
            # another's status.
            state_dir = json.loads(approved["staged"]).get("state_dir")
            cid = live.get("Id") if isinstance(live, dict) else None
            status = (rh.Unresolved("A1's staged config names no state_dir") if not isinstance(state_dir, str)
                      else rh.Unresolved("the local router is not running") if not isinstance(cid, str)
                      else ask_json(spec, ["exec", cid, "python3", "-I", "-S", "-c", STATUS_SCRIPT, state_dir],
                                    "the router's status.json"))
        v1 = cell("V1", checks[0])
        v2 = cell("V2", v2_check(checks[1], status))

    # E1, E2.
    observed: Any = None
    if a2_doc is None:
        e1 = e1_cell(evidence_path, None, None, named_why or f"no evidence named by the live token: {RUN_7D}")
        e2 = e2_unknown()
    elif isinstance(approved, rh.Unresolved) or live_doc is None:
        e1 = e1_cell(evidence_path, None, None, approved.reason if isinstance(approved, rh.Unresolved)
                     else live_raw.reason)
        e2 = e2_unknown()
    else:
        key_path = ((json.loads(approved["staged"]).get("delegation") or {}).get("signing_key") or {}).get("path")
        observed, doc7d, why = key_observation(
            host=host, evidence_dir=evidence_dir, live=live_doc, a2_raw=a2_raw, a2_doc=a2_doc,
            activation_raw=activation_raw, approved=approved, key_path=key_path, now=now, read=read)
        inputs["key_observed"] = observed
        if observed is None:
            e1, e2 = e1_cell(evidence_path, None, None, why), e2_unknown()
        elif doc7d["bindings"].get("key") != a2_doc["bindings"].get("key"):
            fail = rh.check(e1_claim(evidence_path, observed), rh.Fact("key", a2_doc["bindings"].get("key"),
                            "A2's key binding, which root's 7d run must have observed unchanged"),
                            KEY_CHANGED, "de-activate (the back-out after the place), then A1 to A5 again",
                            do_not="never edit a binding to match")
            e1, e2 = e1_cell(evidence_path, observed, fail), e2_unknown()
        else:
            lanes = prun.selected_lanes(live_doc, read=p["read_lanes"]) if "read_lanes" in p else \
                prun.selected_lanes(live_doc)
            lane = pp.lane_binding(lanes, p.get("stat", os.stat)) if not isinstance(lanes, rh.Unresolved) else lanes
            local = pa.spec_from_running(live) if isinstance(live, dict) else rh.Unresolved(
                "the local router is not running")
            missing = next((v.reason for v in (lane, local) if isinstance(v, rh.Unresolved)), None)
            if hashlib.sha256(document_raw).hexdigest() != document_sha256:
                missing = "the document is not the unit's: its sha256 is not --document-sha256"
            if missing is not None:
                e1, e2 = e1_cell(evidence_path, observed, None, missing), e2_unknown()
            else:
                bindings = {"host_setup": hashlib.sha256(document_raw).hexdigest(),
                            "email_router": hr.spec_sha256(hr.run_spec(spec, spec.hub)),
                            "lanes": lane, "key": doc7d["bindings"]["key"],
                            "local_router": pa.activation_binding(local, live_raw)}
                roles = {"P03": p03_roles(doc7d), "P04": pp.p04_roles(lanes)}
                checks = pe.verify_document(evidence_path, host=host, now=now, bindings=bindings, live_token=token,
                                            roles=roles, lstat=p.get("lstat", os.lstat), read=read)
                e1 = e1_cell(evidence_path, observed, worst(checks[:-1]))
                e2 = cell("E2", checks[-1])

    # T1, R1: their own results, through ss.docker for the engine.
    q = {"inspect": inspect, "read_placed": read, "read": read_live}
    t1 = cell("T1", hsu.verify_stop_target(spec, q)[0], base=ps.TARGET_CLAIM)
    r1 = cell("R1", hsu.verify_weekly_runs(spec, {k: q[k] for k in ("read_placed", "read")})[0], base=pruns.RUNS_CLAIM)
    return inputs, [v1, v2, e1, e2, t1, r1]


def run(document_path: str, document_sha256: str, *, ready_only: bool = False, out=print,
        now: Optional[float] = None, p: Optional[Dict[str, Any]] = None) -> int:
    """The verb: the unit argv's `--document` and `--document-sha256` name the
    approved document. The object is written on every path where the
    document loads; the exit is 0 when it was written in full, or with
    `ready_only` (`--ready`), 0 only when all six are PASS. A document that
    cannot be read or loaded is exit 2 and no object."""
    import host_setup as hsu
    import partition_run as prun
    now = time.time() if now is None else now
    try:
        with open(document_path, "rb") as f:
            raw = f.read()
        spec = hsu.load_spec(prun.document_section(raw))
    except (OSError, ValueError) as e:
        out(f"partition-check: the document cannot be loaded: {e}")
        return 2
    if spec.partition is None or spec.keys is None or not spec.hops:
        out("partition-check: the document has no partition, keys or hops section")
        return 2
    inputs, cells = evaluate(spec, document_raw=raw, document_sha256=document_sha256, now=now, p=p)
    doc = document(host=hsu.partition_host(spec), at=utc_now(now), inputs=inputs, cells=cells)
    out(doc.decode("utf-8"))
    if ready_only:
        return 0 if ready(json.loads(doc)) else 1
    return 0
