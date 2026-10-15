"""One partition run's Plan, gathered read-only from facts already read, and
the dry run that prints what `--apply` would run. NOTHING HERE STARTS, STOPS
OR WRITES, and nothing here asks the engine: the caller reads each fact
(an inspect, an image's environment) and passes it in, so every refusal is
testable without one.

The two hop runtimes are built by different launchers: the email router from
hub_runtime's run spec, the local router from its checkout's docker/run.sh
(partition_activation). A one-shot of each is built by its own launcher's
argv, told apart by image, which the two never share.
"""

import posixpath
import shlex
from typing import Any, Callable, Dict, List, Optional, Sequence

import hub_runtime as hr
import partition_activation as pa
import partition_probe as pp
import router_health as rh

#: The hop's two ends, as P01 names them: the local router upstream, the
#: email router downstream.
UPSTREAM, DOWNSTREAM = "upstream", "downstream"


class PlanError(ValueError):
    """The run's facts cannot make a Plan; nothing is probed."""


def run_argv_for(router: Dict[str, Any]) -> Callable[[Dict[str, Any]], List[str]]:
    """`docker run`'s arguments for a one-shot of either runtime: the local
    router's (by its image) as run.sh builds them, with `--pull never`, which
    every probe carries; anything else as hub_runtime builds it."""
    def run_argv(spec: Dict[str, Any]) -> List[str]:
        if spec["image"] == router["image"]:
            return ["--pull", "never"] + pa.router_argv(spec)
        return hr.argv(spec)
    return run_argv


def email_drift(live: Any, rendered: Dict[str, Any], image_env: Any) -> Any:
    """hub_runtime.compare of the running email router with its rendering
    ([] when equal), or an Unresolved: a router that is not running, or an
    engine that did not answer, stands for nothing."""
    for v in (live, image_env):
        if isinstance(v, rh.Unresolved):
            return v
    if live is None:
        return rh.Unresolved("the email router is not running")
    return hr.compare(live, rendered, image_env)


def agent_source(inspect: Any, destination: str) -> Any:
    """The host source of the bind an agent's container mounts at
    `destination` (its peer lane), or an Unresolved."""
    if isinstance(inspect, rh.Unresolved):
        return inspect
    if inspect is None:
        return rh.Unresolved("its container is not running")
    found = [m for m in inspect.get("Mounts") or [] if m.get("Destination") == destination]
    if len(found) != 1 or found[0].get("Type") != "bind" or not found[0].get("Source"):
        return rh.Unresolved(f"its container has no single bind at {destination}")
    return found[0]["Source"]


def _hop_target(mounts: Sequence[Dict[str, Any]], host_root: str) -> str:
    """Where the email router sees the hop root: its bind of exactly it."""
    found = [m["target"] for m in mounts if m.get("type") == "bind" and m.get("source") == host_root]
    if len(found) != 1:
        raise PlanError(f"the email router's rendering binds the hop root {host_root} {len(found)} times, not once")
    return found[0]


def _uid_gid(spec: Dict[str, Any]) -> tuple:
    uid, _, gid = spec["user"].partition(":")
    return int(uid), int(gid)


def gather(*, host: str, run_id: str, at: str, email: Dict[str, Any], email_view: Dict[str, Any],
           email_live: Any, email_image_env: Any, email_volume: str, router: Dict[str, Any],
           router_doc: Dict[str, Any], lanes: Dict[str, str], agent_inspects: Dict[str, Any], peer_destination: str,
           bindings: Dict[str, str]) -> pp.Plan:
    """The Plan for one run. `email` is the email router's rendered run spec
    (hub_runtime.run_spec) and `email_view` its inspect-shaped view;
    `router` is the local router's activation spec and `router_doc` the
    activation config it reads; `lanes` each enrolled agent's peer lane on
    the host; `agent_inspects` each agent container's inspect (None when
    not running); `peer_destination` where an agent mounts its lane."""
    if email["image"] == router["image"]:
        raise PlanError("the two routers run the same image, so their one-shots cannot be told apart")
    hop, delegation = router_doc.get("hop"), router_doc.get("delegation")
    if not isinstance(hop, dict) or not isinstance(hop.get("root"), str) or not isinstance(hop.get("link"), str):
        raise PlanError("the activation config has no hop root and link")
    if not isinstance(delegation, dict) or not isinstance((delegation.get("signing_key") or {}).get("path"), str):
        raise PlanError("the activation config has no delegation signing key")
    root, key = hop["root"], delegation["signing_key"]["path"]
    email_root = _hop_target(email["mounts"], root)
    up_uid, up_gid = _uid_gid(router)
    down_uid, down_gid = _uid_gid(email)
    return pp.Plan(
        host=host, run_id=run_id, at=at, email=email,
        email_drift=email_drift(email_live, email_view, email_image_env), email_volume=email_volume,
        router=router, key_path=key, key_dir=posixpath.dirname(key),
        lanes=dict(lanes), agent_sources={s: agent_source(agent_inspects.get(s), peer_destination) for s in lanes},
        links=[hop["link"]], hop_root=root,
        runtimes={UPSTREAM: (router["name"], up_uid, up_gid), DOWNSTREAM: (email["name"], down_uid, down_gid)},
        vantages={UPSTREAM: pp.spec_vantage(router), DOWNSTREAM: pp.spec_vantage(email)},
        hops=[(UPSTREAM, DOWNSTREAM)],
        sides={"up": (email, email_root), "down": (router, root)},
        owners={"up": (router, root, up_uid), "down": (email, email_root, down_uid)},
        bindings=dict(bindings))


def dry_run(plan: pp.Plan, run_argv: Callable[[Dict[str, Any]], List[str]], docker: Sequence[str],
            stat_: Callable, realpath_: Callable) -> List[str]:
    """What `--apply` would run, one line per engine call it can name now,
    and what would refuse the run before any probe. It runs nothing."""
    out = []
    drift = plan.email_drift
    if isinstance(drift, rh.Unresolved) or drift:
        why = drift.reason if isinstance(drift, rh.Unresolved) else "; ".join(drift)
        return [f"would refuse: the running email router is not its rendering: {why}"]
    for principal, (container, uid, gid) in sorted(plan.runtimes.items()):
        out.append(f"P01 {principal}: " + _quote(list(docker) + ["exec", "-u", f"{uid}:{gid}", container, "python3",
                                                              "-I", "-S", "-c", "<P01 script>"]))
    cands = pp.candidates(plan.email["mounts"], [plan.key_path, plan.key_dir], stat_, realpath_)
    lanes = [plan.lanes[s] for s in sorted(plan.lanes)]
    cands4 = pp.candidates(plan.email["mounts"], lanes, stat_, realpath_)
    for pid, spec, script, args in (
            ("P03", plan.email, pp.P03_SCRIPT, cands),
            ("P03W", plan.router, pp.OPEN_WITNESS_SCRIPT, ["r", plan.key_path]),
            ("P04", plan.email, pp.P04_SCRIPT, cands4 if isinstance(cands4, rh.Unresolved)
             else [pp.probe_file(plan.run_id)] + cands4)):
        if isinstance(args, rh.Unresolved):
            out.append(f"{pid}: would be UNKNOWN: {args.reason}")
            continue
        drop = plan.email_volume if spec is plan.email else None
        one = pp.oneshot(spec, pid, plan.run_id, script, args, drop)
        argv = pp.oneshot_argv(one, run_argv)
        argv[argv.index(script)] = f"<{pid} script>"
        out.append(f"{pid}: " + _quote(list(docker) + ["run"] + argv))
    out.append("P02 and P04W: their operands are the owner's enumeration and each lane's paths through the "
               "local router's binds, read at --apply")
    return out


def _quote(argv: Sequence[str]) -> str:
    return " ".join(shlex.quote(a) for a in argv)
