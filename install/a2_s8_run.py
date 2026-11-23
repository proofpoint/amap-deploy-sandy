"""S8 START's run (design W13 d3.1): steps 1 and 3 once, before any VM; then, per VM, steps 2 and 4 (a2_s8), RL's
start (step 5, a2_s8_rl), RE's ledger init and start (steps 6 and 7, a2_s8_re), and the receipt facts of step 10.

Step 8 (the agent sandboxes) and the sandbox half of step 9 wait on 3.7 rule 10's list, which is open with sandy's
owner. Until they land, run_s8 is not in a2_main.DISPATCH, so no run reaches it.

Every docker CLI call runs as the agent account; RE's containers run as the relay uid and gid (d3.1 section 2,
RE's answer 738bb7fa). The polls take their clock and sleep from the caller, so the tests drive time.

A refusal after the stage's first write carries the STATE_* facts of every VM in scope (d3.1 step 10, 3.4). Each is
read, never assumed; a read that fails is UNOBSERVED.
"""

import json
import posixpath
import re
import shlex
import time

import a2_s5
import a2_s6
import a2_s8 as S
import a2_s8_checks as checks
import a2_s8_re as re8
import a2_s8_rl as rl
from a2_causes import Refusal

STAGE = "START"
DOCKER = "/usr/bin/docker"
SG = "/usr/bin/sg"
DATE = "/usr/bin/date"
GETENT = "/usr/bin/getent"
#: RL's start script, under the agent's home (S6's checkout of RL's code).
RL_RUN = ".amap-router-code/docker/run.sh"
#: Polling: every POLL_S; RL's first binding poll within RL_WINDOW_S; RE's startup record within RE_STARTUP_S;
#: witness 3 watches at least RE_INBOUND_S. Witness 2's first reading must come within RE_STARTUP_S of startup, and
#: progress must rise within PROGRESS_SLACK x (2 x interval_s + 5 s) of the first reading (d3.1, PROPOSED).
POLL_S = 2
RL_WINDOW_S = 60
RE_STARTUP_S = 120
RE_INBOUND_S = 60
PROGRESS_SLACK = 2
#: Witness 2's fixed ceiling: progress must rise within this many seconds of the first reading, whatever interval_s
#: RE reports (gate B's W13 r4 note N9).
PROGRESS_CEILING_S = 300
#: A stop's layer timeout is the docker stop timeout plus this margin, so ssh never cuts a drain short (note N2).
STOP_MARGIN_S = 60
#: The hub-status file is read inside RE's container, by RE's own python (RE's C2): no -u, no shell.
READ_FILE = "import sys; sys.stdout.write(open(sys.argv[1]).read())"
HUB_STATUS = "hub-status.json"
#: S4's per-VM receipt facts S8 reads (named for S4's own package).
S4_RL_IMAGE, S4_RE_IMAGE = "RL_IMAGE", "RE_IMAGE"
#: S7's per-agent facts as W8 writes them (ruling W13-S7-FACTS-ADAPT-IN-S8; W8 tree b3bbb61e, a2_s7.py): prefix
#: AGENT_<n>_, n the agent's 1-based position in that VM's hosts agents[], not necessarily contiguous from 1 (an
#: --add-agent receipt holds one agent at its position). STANDIN appears on stand-ins only.
S7_AGENT_KEYS = ("ID", "VM", "WORKSPACE", "CONNECTOR_COMMIT", "SECRET_FILE", "START_POSSIBLE", "SLUG", "REGISTRY",
                 "LOGICAL_ID", "IMAGE_ID")
S7_STANDIN = "launched-once"
#: S7's workspace rule (a2_s7.py lines 360-361): the agent account's home + "/dev/agent-" + id, recorded with a
#: literal tilde for the home.
WORKSPACE_PREFIX = "dev/agent-"
_AGENT_KEY = re.compile(r"AGENT_([1-9][0-9]{0,2})_([A-Z][A-Z0-9_]*)")
_SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_AGENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_UINT = re.compile(r"[1-9][0-9]{0,9}")
_TOKEN = re.compile(r"[a-z][a-z0-9_-]{0,31}")


def _incomplete(what):
    return Refusal(STAGE + ".PREDECESSOR_INCOMPLETE", what)


def _read(rec, sid, host):
    """A predecessor's receipt facts; the reader's causes keep their name and take START's prefix."""
    try:
        return rec.read_receipt(sid, host)
    except Refusal as r:
        raise Refusal(STAGE + "." + r.cause.partition(".")[2], sid + "-" + host)


def prior(rec, name):
    """Step 1 for one VM: S4's image ids, S5's key, S6's placed facts, S6b's pass and S7's agents (d3.1 step 1).
    A missing or failed receipt keeps the reader's cause; a fact absent or malformed is PREDECESSOR_INCOMPLETE."""
    s4, s5, s6 = _read(rec, "S4", name), _read(rec, "S5", name), _read(rec, "S6", name)
    _read(rec, "S6b", name)
    s7 = _read(rec, "S7", name)
    images = (s4.get(S4_RL_IMAGE), s4.get(S4_RE_IMAGE))
    if not all(isinstance(i, str) and S._IMAGE_ID.fullmatch(i) for i in images):
        raise _incomplete("S4-" + name)
    kid, kpub = s5.get("KEY_ID"), s5.get("KEY_PUBLIC")
    if not (isinstance(kid, str) and a2_s5.KEY_ID.fullmatch(kid) and isinstance(kpub, str) and _HEX64.fullmatch(kpub)):
        raise _incomplete("S5-" + name)
    shas = [f for f, _rel in S.PLACED] + ["PLUGIN_SHA"]
    ids = ("AGENT_UID", "RELAY_UID", "HOP_GID")
    if (s6.get("CONFIG") != "PLACED" or not all(isinstance(s6.get(f), str) and _HEX64.fullmatch(s6[f]) for f in shas)
            or not all(isinstance(s6.get(k), str) and _UINT.fullmatch(s6[k]) for k in ids)):
        raise _incomplete("S6-" + name)
    agents = s7_agents(s7, name)
    return {"rl_image": images[0], "re_image": images[1], "key_public": s5["KEY_PUBLIC"], "key_id": s5["KEY_ID"],
            "s6": s6, "agent_uid": int(s6["AGENT_UID"]), "relay_uid": int(s6["RELAY_UID"]),
            "hop_gid": int(s6["HOP_GID"]), "agents": agents, "names": [a["slug"] for a in agents]}


def s7_agents(s7, name):
    """S7's agents on one VM, in position order: [{n, id, slug, workspace_rel, image_id, standin}]. Each position
    present (an AGENT_<n>_ID key) must carry every key of S7_AGENT_KEYS, and nothing else but STANDIN; a partial
    set refuses PREDECESSOR_FAILED (ruling W13-S7-FACTS-ADAPT-IN-S8), as does a value that breaks S7's own rules
    (START_POSSIBLE yes, VM this VM, the workspace's tilde form, unique ids and slugs). IMAGE_ID is opaque."""
    failed = Refusal(STAGE + ".PREDECESSOR_FAILED", "S7-" + name)
    keys = {}
    for k, val in s7.items():
        m = _AGENT_KEY.fullmatch(k)
        if m:
            keys.setdefault(int(m.group(1)), {})[m.group(2)] = val
    agents = []
    for n in sorted(keys):
        a = keys[n]
        if set(a) - {"STANDIN"} != set(S7_AGENT_KEYS) or a.get("STANDIN", S7_STANDIN) != S7_STANDIN:
            raise failed
        if (not _AGENT_ID.fullmatch(a["ID"]) or not _SLUG.fullmatch(a["SLUG"]) or a["START_POSSIBLE"] != "yes"
                or a["VM"] != name or a["WORKSPACE"] != "~/" + WORKSPACE_PREFIX + a["ID"] or a["IMAGE_ID"] == ""):
            raise failed
        agents.append({"n": n, "id": a["ID"], "slug": a["SLUG"], "workspace_rel": WORKSPACE_PREFIX + a["ID"],
                       "image_id": a["IMAGE_ID"], "standin": "STANDIN" in a})
    if not agents or len({a["id"] for a in agents}) != len(agents) or len({a["slug"] for a in agents}) != len(agents):
        raise failed
    return agents


def skew(layer, vms, clock):
    """Step 3: each VM's `date +%s.%N`, bracketed by the runner's clock. Returns SKEW_MS, or CLOCK_SKEW."""
    readings = []
    for v in vms:
        before = clock()
        rc, out, _err = layer.exec(v["name"], [DATE, "+%s.%N"], account=v["agent_account"], stage=STAGE,
                                   writes=False)
        after = clock()
        readings.append((before, checks.vm_time(out if rc == 0 else b""), after))
    return checks.check_skew(readings)


def _exec(layer, v, argv, writes=False, account=None, timeout_s=None):
    kw = {} if timeout_s is None else {"timeout_s": timeout_s}
    return layer.exec(v["name"], argv, account=account or v["agent_account"], stage=STAGE, writes=writes, **kw)


def _inspect(layer, v, name):
    """`docker inspect <name>`'s parsed array, or None when it fails or does not parse."""
    rc, out, _err = _exec(layer, v, [DOCKER, "inspect", name])
    if rc != 0:
        return None
    try:
        return json.loads(out)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None


@S._after_write
def read_only(layer, vm, v, p):
    """Steps 2 and 4 and section 3(a) on one VM, with the measured ids held to S6's receipt. Returns what the
    starts need."""
    m = S.measure(layer, vm, v)
    if (m["uid"], m["relay_uid"], m["hop_gid"]) != (p["agent_uid"], p["relay_uid"], p["hop_gid"]):
        raise Refusal(STAGE + ".CONFIG_CHANGED", "account ids")
    cfg = S.config_in_place(layer, vm, v, p["s6"], m["home"])
    env, router = cfg["env"], cfg["router"]
    state_dir = router.get("state_dir")
    if not checks._abs_norm(state_dir) or not state_dir.startswith(m["home"] + "/"):
        raise Refusal(STAGE + ".CONFIG_CHANGED", "router.json state_dir")
    S.trust_resolved(layer, vm, v, env, m["home"], m["relay_home"])
    S.not_started(layer, vm, v, env, p["re_image"], m["relay_uid"], m["relay_gid"])
    rc, out, _err = layer.exec(vm, [GETENT, "group", "docker"], account=v["agent_account"], stage=STAGE,
                               writes=False)
    return dict(m, env=env, router=router, state_dir=state_dir, docker_gid=checks.docker_gid(rc, out))


def rl_argv(v, m, image):
    """RL's start (ruling W13-S8-RL-START): run.sh under `sg <hop group>`, so its primary gid is hop."""
    words = [posixpath.join(m["home"], RL_RUN), "--config", posixpath.join(m["home"], S.PLACED[0][1]),
             "--image", image, "--name", S.RL_NAME, "--group-add", str(m["hop_gid"]), "--detach"]
    return [SG, v["hop_group"], "-c", " ".join(shlex.quote(w) for w in words)]


@S._after_write
def container_trust(layer, doc, trust_paths, gid):
    """Section 3(b) and (c) on one started container's inspect document."""
    checks.check_trust(checks.mounts_of(doc), trust_paths)
    return checks.check_daemon(doc, gid)


@S._after_write
def daemon_reach(layer, doc, gid):
    """Section 3(c) alone, on RE's inspect document: RE's binds are its own mount knobs, which are trust paths by
    design, so 3(b) does not apply to it (d3.4)."""
    return checks.check_daemon(doc, gid)


def start_rl(layer, v, m, p, clock, sleep):
    """Step 5. Returns RL's receipt facts; RL_REFUSED, NOT_ADMITTING or a trust refusal otherwise (the caller
    stops RL)."""
    rc, _out, _err = _exec(layer, v, rl_argv(v, m, p["rl_image"]), writes=True)
    if rc != 0:
        raise rl._refused("start script")
    t0 = clock()
    while True:
        doc = _inspect(layer, v, S.RL_NAME)
        if doc is None:
            raise rl._refused("inspect output")
        started = rl.container_state(json.dumps(doc))
        rc, raw, _err = _exec(layer, v, [S.CAT, "--", posixpath.join(m["state_dir"], "status.json")])
        status = rl.binds(raw, started) if rc == 0 else None
        if status is not None:
            break
        if clock() - t0 >= RL_WINDOW_S:
            raise rl._refused("no first poll")
        sleep(POLL_S)
    plugin = m["router"]["transport_plugin"]["path"]
    notes = rl.admitting(status, p["names"], p["key_public"], p["key_id"], p["s6"]["PLUGIN_SHA"], plugin)
    # Gate A's W13 r4 blocker 1: each bind source is its own realpath before (b) and (c) judge it, so a symlinked
    # source cannot hide a relay trust path or the docker socket.
    S.sources_resolved(layer, v["name"], v, checks.mounts_of(doc))
    container_trust(layer, doc, checks.relay_trust_paths(m["env"], m["home"]), m["docker_gid"])
    cid = doc[0].get("Id")
    if not isinstance(cid, str) or not _HEX64.fullmatch(cid):
        raise rl._refused("inspect output")
    return [("RL_CONTAINER", cid), ("RL_IMAGE", p["rl_image"]), ("RL_POLLS", str(status["polls"])),
            ("RL_ADMITTED", ",".join(p["names"])), ("RL_PLUGIN_SHA", p["s6"]["PLUGIN_SHA"])] + notes


def init_ledger(layer, v, m, p):
    """Step 6: RE's one-shot init, then --verify must report the ledger available."""
    ledger = m["env"]["RELAY_LEDGER_DIR"]
    rc, out, _err = _exec(layer, v, re8.init_argv(ledger, p["re_image"], m["relay_uid"], m["relay_gid"]), writes=True)
    re8.init_ok(rc, out, ledger)
    _rc, out, _err = _exec(layer, v, S.verify_argv(ledger, p["re_image"], m["relay_uid"], m["relay_gid"]))
    re8.available(out)


def _re_running(layer, v):
    doc = _inspect(layer, v, re8.RE_NAME)
    re8.exited(json.dumps(doc) if doc is not None else b"")
    return doc


def _re_records(layer, v):
    """RE's obs records from `docker logs amap-re`: stdout's lines, then stderr's (PENDING CAPTURE: which stream
    RE's records reach)."""
    rc, out, err = _exec(layer, v, [DOCKER, "logs", re8.RE_NAME])
    if rc != 0:
        raise re8._refused("logs")
    return re8.obs_records(out) + re8.obs_records(err)


def start_re(layer, v, m, p, clock, sleep):
    """Step 7: RE's start and its three witnesses, with the container state polled throughout. Returns RE's
    receipt facts; RE_REFUSED otherwise (the caller stops RE)."""
    env, pin = m["env"], p["s6"]["PLUGIN_SHA"]
    env_file = posixpath.join(m["home"], a2_s6.RE_ENV, a2_s6.RE_ENV_NAME)
    argv = re8.start_argv(env, env_file, p["re_image"], m["relay_uid"], m["relay_gid"], m["hop_gid"])
    rc, _out, _err = _exec(layer, v, argv, writes=True)
    if rc != 0:
        raise re8._refused("start")
    doc = _re_running(layer, v)
    daemon_reach(layer, doc, m["docker_gid"])
    created = rl.instant_ns(doc[0].get("Created"))
    cid = doc[0].get("Id")
    if created is None or not isinstance(cid, str) or not _HEX64.fullmatch(cid):
        raise re8._refused("inspect output")
    t0 = clock()
    while not re8.startup(_re_records(layer, v), env.get("HOP_LINK"), pin):
        if clock() - t0 >= RE_STARTUP_S:
            raise re8._refused("no startup record")
        sleep(POLL_S)
        _re_running(layer, v)
    status = posixpath.join(env["RELAY_LEDGER_DIR"], HUB_STATUS)
    first, t1 = None, clock()
    while True:
        _re_running(layer, v)
        rc, raw, _err = _exec(layer, v, [DOCKER, "exec", re8.RE_NAME, "python3", "-c", READ_FILE, status])
        reading = re8.hub_progress(raw, created, pin) if rc == 0 else None
        now = clock()
        if reading is not None:
            here = (int(now * 1e9), reading[0], reading[1])
            if first is None:
                first = here
            elif re8.progressed(first, here):
                break
        limit = (t1 + RE_STARTUP_S if first is None
                 else first[0] / 1e9 + min(PROGRESS_SLACK * (2 * first[2] + re8.PROGRESS_EXTRA_S),
                                           PROGRESS_CEILING_S))
        if now >= limit:
            raise re8._refused("no outbound progress")
        sleep(POLL_S)
    t2 = clock()
    while True:
        _re_running(layer, v)
        re8.inbound_clear(_re_records(layer, v))
        if clock() - t2 >= RE_INBOUND_S:
            break
        sleep(POLL_S)
    return [("RE_CONTAINER", cid), ("RE_IMAGE", p["re_image"]), ("RE_PLUGIN_SHA", pin),
            ("RE_INBOUND", "NO_FAILURE_SEEN"), ("LEDGER", "INITIALISED")]


def _stop(layer, v, argv, timeout_s=None):
    """A stop S8 owes after its own refusal, once the stage has written (note N8): never rm, and its outcome is read
    back in STATE_*, not trusted."""
    if not layer.wrote(STAGE):
        return
    try:
        _exec(layer, v, argv, writes=True, timeout_s=timeout_s)
    except BaseException:
        # A failed stop keeps the refusal's own cause (gate B's W13 r5 note N4); STATE_* reads what it left.
        pass


def _named(layer, e):
    """A failure no step names (gate B's W13 r4 blocker 2), or an interrupt (gate B's W13 r5 blocker 1), as a
    Refusal so the stop and STATE_* still run: UNCLASSIFIED, exit 3 once the stage has written. An interrupt is
    exit 3 even before a write, as a2_main's dispatch gives it (3.4: "an interrupt included")."""
    if isinstance(e, Refusal):
        return e
    interrupt = not isinstance(e, Exception)
    return Refusal(STAGE + ".UNCLASSIFIED", "start", rc=3 if interrupt or layer.wrote(STAGE) else None)


def _reraise(r, e):
    """Raise the named refusal: the original itself when it was one, keeping its own chain (note N3)."""
    if r is e:
        raise
    raise r from e


def run_vm(layer, v, p, skew_ms, clock=time.monotonic, sleep=time.sleep):
    """Steps 2 and 4-7 on one VM. Returns (facts, "CHANGED")."""
    vm = v["name"]
    m = read_only(layer, vm, v, p)
    try:
        facts = start_rl(layer, v, m, p, clock, sleep)
    except BaseException as e:
        r = _named(layer, e)
        _stop(layer, v, [DOCKER, "stop", S.RL_NAME])
        _reraise(r, e)
    init_ledger(layer, v, m, p)
    try:
        facts += start_re(layer, v, m, p, clock, sleep)
    except BaseException as e:
        r = _named(layer, e)
        t = re8.stop_timeout(m["env"])
        _stop(layer, v, [DOCKER, "stop", "-t", str(t), re8.RE_NAME], timeout_s=t + STOP_MARGIN_S)
        _reraise(r, e)
    return [("START", "RUNNING"), ("SKEW_MS", str(skew_ms))] + facts, "CHANGED"


def _status(layer, v, name):
    """A container's state for STATE_*: ABSENT when docker ps lists none, else its State.Status token."""
    try:
        if not S.container_exists(layer, v["name"], v, name):
            return "ABSENT"
        doc = _inspect(layer, v, name)
        st = doc[0]["State"]["Status"] if isinstance(doc, list) and len(doc) == 1 else None
        return st.upper() if isinstance(st, str) and _TOKEN.fullmatch(st) else "UNOBSERVED"
    except BaseException:
        return "UNOBSERVED"


def _ledger(layer, v, env, p, ids):
    """The ledger's state for STATE_*, by step 4's rules: NO_INIT, INITIALISED or UNUSABLE. UNUSABLE is a stat with
    the wrong owner, mode or type, or a report that parses to another state. A relay-account stat that fails, or a
    --verify with a non-zero exit or no report that parses, is UNOBSERVED: a failed read is not a state."""
    try:
        ledger = env["RELAY_LEDGER_DIR"]
        S.ledger_in_place(layer, v["name"], v, ledger, *ids)
        rc, out, _err = _exec(layer, v, S.verify_argv(ledger, p["re_image"], *ids))
        if rc != 0 or S.ledger_report(out) is None:
            # Gate A's W13 r4 blocker 2: a --verify read that failed is not a state of the ledger.
            return "UNOBSERVED"
        return "NO_INIT" if S.ledger_state(out) == "no_init" else "UNOBSERVED"
    except Refusal as r:
        if r.cause == STAGE + ".RUNNING":
            return "INITIALISED"
        if r.cause == STAGE + ".LEDGER_UNUSABLE":
            return "UNUSABLE"
        return "UNOBSERVED"
    except BaseException:
        return "UNOBSERVED"


def state_facts(layer, vms, priors):
    """STATE_VM<i>_* for every VM in scope (d3.1 step 10), read after S8's own stops: the VM's name, RL's and RE's
    container state and the ledger's. The ledger needs the VM's ids and env-file, read again as step 2 reads them;
    where that read fails, the ledger is UNOBSERVED. A read that raises anything, an interrupt included, is
    UNOBSERVED, so the collection always completes (gate B's W13 r5 blocker 1)."""
    known = {}
    for v in vms:
        try:
            known[v["name"]] = read_known(layer, v, priors[v["name"]])
        except BaseException:
            pass
    facts = []
    for i, v in enumerate(vms, 1):
        k = "STATE_VM%d_" % i
        facts.append((k + "NAME", v["name"]))
        facts.append((k + "RL", _status(layer, v, S.RL_NAME)))
        facts.append((k + "RE", _status(layer, v, re8.RE_NAME)))
        m = known.get(v["name"])
        facts.append((k + "LEDGER", _ledger(layer, v, m["env"], priors[v["name"]], (m["relay_uid"], m["relay_gid"]))
                      if m else "UNOBSERVED"))
    return facts


def run_s8(c, site, rec, clock=time.monotonic, sleep=time.sleep):
    """S8 over the run scope's two VMs, one receipt each (a2_stage.per_vm). Before any VM: the scope, the layer,
    step 1 and step 3, each refusal written in the first VM's receipt. A dry-run plans and touches nothing."""
    import a2_stage
    names = [v["name"] for v in c.hosts["vms"] if v["scope"] == a2_stage.scope_of(c.inv.loop)]
    if c.inv.command == "dry-run":
        a2_stage.per_vm(rec, site, "S8", names, None, plan=lambda n: [("START", "PLANNED")], dry_run=True)
        return
    try:
        try:
            _scope, vms = a2_s6.scope_vms(c.hosts, c.inv.loop)
        except Refusal as r:
            raise Refusal(STAGE + "." + r.cause.partition(".")[2], r.detail)
        layer = site.vm_layer
        if layer is None:
            raise Refusal(STAGE + ".TARGET_ACCESS", "the VM layer is not bound")
        priors = {v["name"]: prior(rec, v["name"]) for v in vms}
        skew_ms = skew(layer, vms, clock)
    except Refusal as r:
        a2_stage.refuse_before_vms(rec, site, "S8", names, r)
    by_name = {v["name"]: v for v in vms}

    def step(n):
        try:
            return run_vm(layer, by_name[n], priors[n], skew_ms, clock, sleep)
        except BaseException as e:
            r = _named(layer, e)
            if r.rc == 3:
                r.facts = state_facts(layer, vms, priors)
            _reraise(r, e)
    a2_stage.per_vm(rec, site, "S8", names, step)


def read_known(layer, v, p):
    """What STATE_* needs of a VM, read only: its measured ids and S6's env-file, as step 2 reads them."""
    m = S.measure(layer, v["name"], v)
    cfg = S.config_in_place(layer, v["name"], v, p["s6"], m["home"])
    return dict(m, env=cfg["env"])
