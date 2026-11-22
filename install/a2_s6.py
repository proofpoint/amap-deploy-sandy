"""S6 CONFIG: each VM's router, hop and relay configuration, through the VM layer (design DESIGN-W7-d2-S6).

This module holds the steps as functions of the layer, each one a VM-layer call with its own refusals under the
stage-wide write rule; the stage runner calls them in order per VM:
1. measure (read only): the accounts, the hop group and the interpreter;
2. directories: vm_dirs as the agent account, then the bootstrap's hopintakes for the relay-owned intakes;
then placement, RL's checks (option (i)), the registry, peer-store init and the receipt.
"""

import json
import posixpath
import re

import a2_s6_render as r6
import vm_bootstrap
import vm_dirs
import vm_place
from a2_causes import Refusal

STAGE = "CONFIG"
PYTHON = "/usr/bin/python3"
MEASURE_SCRIPT = "vm_measure.py"
DIRS_SCRIPT = "vm_dirs.py"
#: RL's floor (its pyproject), for option (i): RL's tree runs on the VM's own python3.
PYTHON_MIN = (3, 11)
#: Under the launcher there is no SANDY_HOME, so sandy uses its default under HOME (amap_sandy.sandy_home).
SANDY_SUBDIR = ".sandy"
HOP_ROOT = ".amap-hop"
MEASURE_KEYS = {"home", "uid", "gid", "relay_uid", "relay_gid", "relay_home", "hop_gid", "agent_in_hop",
                "relay_in_hop", "python"}
_MISSING = 4
#: S3's receipt fact: the run scope's hub `hostname` field, the one S3's cert check verifies (ruling
#: W7-S6-HUB-HOSTNAME). S6 renders it as RE's SMTP_HOST and IMAP_HOST and the prefix template's hub_fqdn.
HUB_HOSTNAME_FACT = "HUB_HOSTNAME"
HUB_STAGE = "S3"
_HOSTNAME = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+")


def _strict_line(out):
    if not out.endswith(b"\n") or out.count(b"\n") != 1 or len(out) > 4096:
        return None
    try:
        doc = json.loads(out.decode("utf-8"), parse_constant=lambda _: None)
    except (ValueError, UnicodeDecodeError):
        return None
    return doc if isinstance(doc, dict) else None


def _int(v):
    return type(v) is int and v >= 0


def measure(layer, vm, v):
    """The facts of step 1 for vms[] entry `v`, or a refusal: CONFIG.HOSTS when an account or the group named in
    alpha2.hosts is missing, the relay is root or the agent's uid, or either account lacks the hop group;
    CONFIG.INTERPRETER when the VM's python3 is older than RL's floor."""
    src = layer.pinned_installer_file(MEASURE_SCRIPT, STAGE).decode("utf-8")
    rc, out, _err = layer.exec(vm, [PYTHON, "-I", "-S", "-c", src, v["relay_account"], v["hop_group"]],
                               account=v["agent_account"], stage=STAGE, writes=False)
    if rc == _MISSING:
        raise Refusal(STAGE + ".HOSTS", vm)
    doc = _strict_line(out) if rc == 0 else None
    if (doc is None or set(doc) != MEASURE_KEYS or not isinstance(doc["home"], str)
            or not isinstance(doc["relay_home"], str)
            or not all(_int(doc[k]) for k in ("uid", "gid", "relay_uid", "relay_gid", "hop_gid"))
            or not all(type(doc[k]) is bool for k in ("agent_in_hop", "relay_in_hop"))
            or not isinstance(doc["python"], list) or len(doc["python"]) != 2 or not all(map(_int, doc["python"]))):
        raise Refusal(STAGE + ".UNCLASSIFIED", "measure rc %d" % rc)
    home, relay_home = doc["home"], doc["relay_home"]
    for h in (home, relay_home):
        if not h.startswith("/") or posixpath.normpath(h) != h or h == "/":
            raise Refusal(STAGE + ".UNCLASSIFIED", "measure home")
    if relay_home == home or relay_home.startswith(home + "/") or home.startswith(relay_home + "/"):
        raise Refusal(STAGE + ".HOSTS", vm)
    if (doc["uid"] == 0 or doc["relay_uid"] in (0, doc["uid"]) or not doc["agent_in_hop"]
            or not doc["relay_in_hop"]):
        raise Refusal(STAGE + ".HOSTS", vm)
    if tuple(doc["python"]) < PYTHON_MIN:
        raise Refusal(STAGE + ".INTERPRETER", vm)
    return {"home": home, "relay_home": relay_home, "sandy_home": posixpath.join(home, SANDY_SUBDIR),
            "uid": doc["uid"], "gid": doc["gid"],
            "relay_uid": doc["relay_uid"], "relay_gid": doc["relay_gid"], "hop_gid": doc["hop_gid"],
            "python": "%d.%d" % tuple(doc["python"])}


def directories(layer, vm, v, facts):
    """Step 2: the agent-owned layout (vm_dirs), then the relay-owned hop intakes (the bootstrap's hopintakes).
    Returns [(relpath, CREATED | EXISTING)] plus the intakes' CHANGED or ALREADY. vm_dirs' NOT_ALLOWED is OWNER,
    exit 3 (the call may have made earlier directories), and any other failure is UNCLASSIFIED."""
    src = layer.pinned_installer_file(DIRS_SCRIPT, STAGE).decode("utf-8")
    rc, out, _err = layer.exec(vm, [PYTHON, "-I", "-S", "-c", src, v["hop_group"]], account=v["agent_account"],
                               stage=STAGE, writes=True)
    if rc == _MISSING:
        raise Refusal(STAGE + ".OWNER", vm, rc=3)
    rows = _dirs_rows(out) if rc == 0 else None
    if rows is None:
        raise Refusal(STAGE + ".UNCLASSIFIED", "dirs rc %d" % rc, rc=3)
    intakes = layer.hop_intakes(vm, posixpath.join(facts["home"], HOP_ROOT), v["relay_account"], v["hop_group"],
                                stage=STAGE)
    return rows, intakes


def relay_directories(layer, vm, v):
    """Step 2b: RE's state directories under the relay account's home (vm_dirs --relay, as the relay account). Same
    rules and refusals as `directories`."""
    src = layer.pinned_installer_file(DIRS_SCRIPT, STAGE).decode("utf-8")
    rc, out, _err = layer.exec(vm, [PYTHON, "-I", "-S", "-c", src, vm_dirs.RELAY_FLAG], account=v["relay_account"],
                               stage=STAGE, writes=True)
    if rc == _MISSING:
        raise Refusal(STAGE + ".OWNER", vm, rc=3)
    rows = _dirs_rows(out, vm_dirs.RELAY_DIRS) if rc == 0 else None
    if rows is None:
        raise Refusal(STAGE + ".UNCLASSIFIED", "relay dirs rc %d" % rc, rc=3)
    return rows


def _dirs_rows(out, dirs=vm_dirs.DIRS):
    want = [rel for rel, _, _ in dirs]
    try:
        lines = out.decode("ascii").split("\n")
    except UnicodeDecodeError:
        return None
    if lines[-1] != "" or len(lines) != len(want) + 1:
        return None
    rows = []
    for line, rel in zip(lines, want):
        what, _, got = line.partition(" ")
        if what not in ("CREATED", "EXISTING") or got != rel:
            return None
        rows.append((rel, what))
    return rows


def read_prior(record, stage_id, host):
    """A predecessor's receipt facts. a2_record names its reader causes after the predecessor's stage; S6 refuses in
    its own name, so the cause keeps its NAME and takes CONFIG's prefix."""
    try:
        return record.read_receipt(stage_id, host)
    except Refusal as r:
        raise Refusal(STAGE + "." + r.cause.partition(".")[2], stage_id + ("-" + host if host else ""))


def hub_hostname(record):
    """The hub MTA's hostname from this run's S3 receipt, read before S6's first write. The receipt reader's own
    causes (PREDECESSOR_*) stand; a missing or malformed fact refuses CONFIG.HUB_HOSTNAME."""
    v = read_prior(record, HUB_STAGE, None).get(HUB_HOSTNAME_FACT)
    if not isinstance(v, str) or len(v) > 253 or not _HOSTNAME.fullmatch(v):
        raise Refusal(STAGE + ".HUB_HOSTNAME", "S3 receipt")
    return v


#: R7 option (i) (RL's answers 90f00634 and 300500a2): RL's pinned tree on the VM's own python3, as the agent account. The launcher's
#: cwd is HOME and its environment closed, so the tree goes on sys.path and `router` runs as __main__: RL measured
#: this byte-identical to its `cd <tree> && python3 -B -m router` form at its ALPHA-2 pin.
RL_TREE = ".amap-router-code"
ROUTER_JSON = ".amap-router/router.json"
RL_SHIM = ('import runpy, sys; sys.path.insert(0, sys.argv.pop(1)); '
           'runpy.run_module("router", run_name="__main__", alter_sys=True)')
PEER_ARTEFACTS = ["peer-clock.json", "peer-epochs", "peer-replay"]


def _router(layer, vm, v, home, verb, writes):
    argv = [PYTHON, "-I", "-B", "-c", RL_SHIM, posixpath.join(home, RL_TREE), "--config",
            posixpath.join(home, ROUTER_JSON)] + verb
    return layer.exec(vm, argv, account=v["agent_account"], stage=STAGE, writes=writes)


def _show(layer, vm, v, home):
    rc, out, _err = _router(layer, vm, v, home, ["peer-store", "show", "--json"], False)
    try:
        doc = json.loads(out) if rc == 0 else None
    except ValueError:
        doc = None
    if not isinstance(doc, dict):
        raise Refusal(STAGE + ".PEER_STORE", vm, rc=3 if layer.wrote(STAGE) else None)
    return doc


def _ready(doc):
    clock = doc.get("clock")
    return (doc.get("store") == "ready" and doc.get("problems") == [] and isinstance(clock, dict)
            and clock.get("admission") == "open" and sorted(doc.get("artefacts") or []) == PEER_ARTEFACTS)


def rl_checks(layer, vm, v, facts):
    """After placement: RL's `peers` over the placed router.json (rc 0; its stderr carries a warning while sandy has
    written no selected.json, so only rc is judged), then the peer store. An absent store is initialised once,
    never-admitted, and must then show ready with admission open; a ready one is ALREADY; anything else refuses
    CONFIG.PEER_STORE and is never retried or repaired. The router is not running at S6 (S8 starts it), so init's
    lock is free. Returns the receipt facts [(RL_PEERS, PASS), (PEER_STORE, INITIALISED or ALREADY)]."""
    home = facts["home"]
    rc, _out, _err = _router(layer, vm, v, home, ["peers"], False)
    if rc != 0:
        raise Refusal(STAGE + ".ROUTER_REFUSED", vm, rc=3 if layer.wrote(STAGE) else None)
    doc = _show(layer, vm, v, home)
    if doc.get("store") == "absent":
        rc, _out, _err = _router(layer, vm, v, home, ["peer-store", "init", "--never-admitted"], True)
        if rc != 0 or not _ready(_show(layer, vm, v, home)):
            raise Refusal(STAGE + ".PEER_STORE", vm, rc=3)
        return [("RL_PEERS", "PASS"), ("PEER_STORE", "INITIALISED")]
    if not _ready(doc):
        raise Refusal(STAGE + ".PEER_STORE", vm, rc=3 if layer.wrote(STAGE) else None)
    return [("RL_PEERS", "PASS"), ("PEER_STORE", "ALREADY")]


#: The router's registry entry (design step 6; HOST f46595f6, a2_registry): host.json and the import batch are placed by
#: vm_place, then HOST's plan, apply and show run from the registry program's placed tree (A/.a2-registry-code) through
#: the same shim as RL's (the launcher's environment holds no PYTHONPATH), as the agent account, the registry's writer.
REGISTRY_DIR = ".amap-registry"
REGISTRY_INSTANCES = ".amap-registry/instances"
HOST_TREE = ".a2-registry-code"
BATCH_ROOT = ".amap-registry-batch"
BATCH_NAME = "import.json"
OPERATOR = "a2-installer"
#: plan, then apply with that plan's confirm; HOST's REPLAN answers allow one fresh plan.
REGISTRY_ATTEMPTS = 2


def _shim(module):
    return ('import runpy, sys; sys.path.insert(0, sys.argv.pop(1)); '
            'runpy.run_module("%s", run_name="__main__", alter_sys=True)' % module)


def host_json(fleet_domain, home, config_schema):
    """host.json's bytes: the registry program's config schema (the lock's, pinned), this VM's fleet domain (RE reads the same domain as HUB_OWN_DOMAIN) and the
    sandy adapter's instances directory (vm_dirs makes it)."""
    doc = {"schema": config_schema, "domain": fleet_domain,
           "adapters": {"sandy": {"instances_dir": posixpath.join(home, REGISTRY_INSTANCES)}}}
    return (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _host(layer, vm, v, home, module, args, writes, stdin=None):
    argv = [PYTHON, "-I", "-B", "-c", _shim(module), posixpath.join(home, HOST_TREE)] + args
    return layer.exec(vm, argv, account=v["agent_account"], stage=STAGE, writes=writes, stdin=stdin)


def _registry_refused():
    return Refusal(STAGE + ".REGISTRY", "registry", rc=3)


def registry(layer, vm, v, facts, run_id, program):
    """Plan, apply and show the router's binding, with `program` the lock's registry_program (its package and
    adapter interface, pinned by check_lock). host.json and the batch are already placed. Returns
    [(ROUTER_LOGICAL_ID, 32 hex), (REGISTRY, CREATED or ALREADY)]. Every refusal is CONFIG.REGISTRY, rc 3: S6 has
    written by now. HOST's own REPLAN answers (confirm_mismatch, a committed delivery failure, an unknown commit) get
    one fresh plan; anything else, never retried."""
    import a2_registry as reg
    home, slug, key = facts["home"], v["router"]["slug"], v["router"]["stable_key"]
    r = posixpath.join(home, REGISTRY_DIR)
    batch = posixpath.join(home, BATCH_ROOT, BATCH_NAME)
    for _ in range(REGISTRY_ATTEMPTS):
        rc, out, _err = _host(layer, vm, v, home, program["package"] + ".opverbs",
                              ["--registry", r, "plan", "import", "--batch", batch], False)
        try:
            confirm, action, plan, _stable = reg.parse_plan(rc, out, slug)
            rc, out, _err = _host(layer, vm, v, home, program["package"] + ".opverbs",
                                  ["--registry", r, "apply", "import", "--batch", batch, "--confirm", confirm,
                                   "--operator", OPERATOR, "--reason", "S6 " + run_id], True)
            lid, status, idir = reg.parse_apply(rc, out, slug, plan)
        except reg.RegistryError as e:
            if reg.next_step(e) == reg.REPLAN:
                continue
            raise _registry_refused()
        except reg.RegistryRefused:
            raise _registry_refused()
        rc, out, _err = _host(layer, vm, v, home, program["package"], ["--registry", r], False,
                              stdin=reg.show_input(key, program["adapter_interface"]))
        try:
            lid = reg.parse_show(rc, out, slug, lid, idir, v["fleet_domain"])
        except (reg.RegistryError, reg.RegistryRefused):
            raise _registry_refused()
        return [("ROUTER_LOGICAL_ID", lid), ("REGISTRY", "CREATED" if status == "imported" else "ALREADY")]
    raise _registry_refused()


#: vm_place (design step 3): one root under the agent account's home per call, everything checked before any write.
PLACE_SCRIPT = "vm_place.py"
_PLACE_LINE = re.compile(rb"(PLACED|SAME) ([^\n]+)\n")


def place(layer, vm, v, root, entries, *, exact):
    """Place `entries` ([(path, mode, bytes | None)]) under `root` on the VM. Returns "CHANGED" when anything was
    placed, else "ALREADY". vm_place's DIFFERENT (a present entry of other bytes, mode or type, an extra name, a
    leftover temporary) refuses CONFIG.PLACED_DIFFERENT; NOT_ALLOWED (an owner, an ancestor) CONFIG.OWNER; anything
    else, including output that does not name every entry in order, UNCLASSIFIED. All rc 3: the call may have
    written."""
    src = layer.pinned_installer_file(PLACE_SCRIPT, STAGE).decode("utf-8")
    rc, out, _err = layer.exec(vm, [PYTHON, "-I", "-S", "-c", src, root, "exact" if exact else "subset"],
                               account=v["agent_account"], stage=STAGE, writes=True,
                               stdin=vm_place.encode(entries))
    if rc == vm_place.DIFFERENT:
        raise Refusal(STAGE + ".PLACED_DIFFERENT", vm + ":" + root, rc=3)
    if rc == vm_place.NOT_ALLOWED:
        raise Refusal(STAGE + ".OWNER", vm + ":" + root, rc=3)
    rows = [_PLACE_LINE.fullmatch(ln + b"\n") for ln in out.split(b"\n")[:-1]] if rc == 0 else None
    if not rows or None in rows or [m.group(2).decode() for m in rows] != [p for p, _m, _b in entries]:
        raise Refusal(STAGE + ".UNCLASSIFIED", "place " + root, rc=3)
    return "CHANGED" if any(m.group(1) == b"PLACED" for m in rows) else "ALREADY"


# ---------------------------------------------------------------- the stage runner

#: The roots S6 places under the agent account's home, and whether each is owned exactly (vm_place `exact`) or shared
#: with files another program keeps there (`subset`: sandy's and the router's beside the feature, the router's state
#: beside router.json, the registry program's own files beside host.json).
FEATURE_ROOT = SANDY_SUBDIR + "/features/amap"
#: RL's tree (R7 option (i)): the router package at the top of its component, placed whole.
RL_COMPONENT = "amap-router-local"
RL_PREFIX = "router"
RE_ENV = ".amap-relay-env"
RE_ENV_NAME = "re.env"
RELAY_CONFIG = ".amap-relay-config"
ROUTER_DIR = ".amap-router"
F_FILE, F_EXEC, F_SECRET, F_DIR = 0o100644, 0o100755, 0o100600, 0o40755
_TREE_MODE = {0o644: F_FILE, 0o755: F_EXEC}


def _sha(data):
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _tree_entries(prefix, files):
    """[(path, mode, bytes | None)] of a component tree placed under `prefix/`, each directory before its files."""
    out, dirs = [(prefix, F_DIR, None)], {prefix}
    for rel, mode, data in files:
        parts = rel.split("/")
        for i in range(1, len(parts)):
            d = prefix + "/" + "/".join(parts[:i])
            if d not in dirs:
                dirs.add(d)
                out.append((d, F_DIR, None))
        out.append((prefix + "/" + rel, _TREE_MODE[mode], data))
    return out


def scope_vms(hosts, loop):
    """The run scope's VMs, in alpha2.hosts order: scope `loop` for an L1, L2 or L2-leak run, `l3` otherwise. S6
    renders each VM's router for exactly one other VM (r6.router_json), so a scope of any other size refuses
    CONFIG.HOSTS."""
    import a2_stage
    scope = a2_stage.scope_of(loop)
    vms = [v for v in hosts["vms"] if v["scope"] == scope]
    if len(vms) != 2:
        raise Refusal(STAGE + ".HOSTS", "scope " + scope)
    return scope, vms


def _plugin(layer, lock):
    """The transport plugin's bytes: the one files[] row with plugin.sha256 (check_lock holds it to one), read and
    re-hashed by the VM layer, and equal to this installer's pin (HOP's, a2_s6_render)."""
    import a2_private
    row = a2_private.plugin_rows(lock)[0]
    data = layer.component_file(row["component"], row["path"], stage=STAGE)
    if _sha(data) != r6.PLUGIN_SHA256:
        raise Refusal(STAGE + ".PIN", "plugin", rc=3 if layer.wrote(STAGE) else None)
    return data


def run_vm(layer, c, vm_doc, other_doc, keys, hub_fqdn, run_id):
    """S6 on one VM, every step in the design's order. Returns the receipt's [(KEY, VALUE)] and its RESULT."""
    import a2_s6_d7 as d7
    import a2_s6_env as e6
    import a2_s6_feature as f6
    import a2_s6_payload as p6
    vm, v = vm_doc["name"], vm_doc
    facts = measure(layer, vm, v)
    home = facts["home"]
    rows, intakes = directories(layer, vm, v, facts)
    rows += relay_directories(layer, vm, v)
    changed = intakes == "CHANGED" or any(what == "CREATED" for _rel, what in rows)
    plugin = _plugin(layer, c.lock)
    # The bootstrap's allowlist names the plugin relative to /; router.json and the env-file carry r6.PLUGIN_PATH,
    # the same file from /.
    if layer.install_file(vm, plugin, vm_bootstrap.PLUGIN, mode=0o444, stage=STAGE) != "ALREADY":
        changed = True
    rp = c.lock["registry_program"]
    router = r6.text(r6.router_json(agent_home=home, sandy_home=facts["sandy_home"], fleet_domain=v["fleet_domain"],
                                    relay_uid=facts["relay_uid"], run_id=run_id, own_key_id=keys[vm]["KEY_ID"],
                                    own_public_key=keys[vm]["KEY_PUBLIC"],
                                    other={"slug": other_doc["router"]["slug"],
                                           "fleet_domain": other_doc["fleet_domain"],
                                           "key_id": keys[other_doc["name"]]["KEY_ID"],
                                           "public_key": keys[other_doc["name"]]["KEY_PUBLIC"]}))
    feature = f6.text(f6.manifest(fleet_domain=v["fleet_domain"]))
    env = e6.text(e6.environment(agent_home=home, relay_home=facts["relay_home"], agent_uid=facts["uid"],
                                 fleet_domain=v["fleet_domain"], hub_fqdn=hub_fqdn,
                                 login_local=c.lock["hub_login"]["local"], login_domain=c.lock["hub_login"]["domain"]))
    d7_doc = d7.text(d7.d7(own_domain=v["fleet_domain"], other_domains=[other_doc["fleet_domain"]], run_id=run_id))
    prefix = d7.text(d7.prefix(hub_fqdn=hub_fqdn,
                               hub_short=c.hosts["hub_loop" if v["scope"] == "loop" else "hub"]["name"]))
    payload = p6.entries(layer, p6.connector_of(c.hosts, vm))
    import a2_registry as reg
    placements = [
        (RL_TREE, _tree_entries(RL_PREFIX, layer.component_tree(RL_COMPONENT, RL_PREFIX, stage=STAGE)[1]), True),
        (HOST_TREE, _tree_entries(rp["package"], layer.component_tree(rp["component"], rp["package"],
                                                                      stage=STAGE)[1]), True),
        (FEATURE_ROOT, [("feature.json", F_FILE, feature), ("instances", F_DIR, None), ("roster", F_DIR, None),
                        ("payload", F_DIR, None)] + [("payload/" + p, m, b) for p, m, b in payload], False),
        (ROUTER_DIR, [("router.json", F_FILE, router)], False),
        (RE_ENV, [(RE_ENV_NAME, F_SECRET, env)], True),
        (RELAY_CONFIG, [("d7.json", F_FILE, d7_doc), ("prefix.json", F_FILE, prefix)], True),
        (REGISTRY_DIR, [("host.json", F_FILE, host_json(v["fleet_domain"], home, rp["config_schema"]))], False),
        (BATCH_ROOT, [(BATCH_NAME, F_FILE, reg.batch(v["router"]["stable_key"], v["router"]["slug"]))], True),
    ]
    for root, entries, exact in placements:
        if place(layer, vm, v, root, entries, exact=exact) == "CHANGED":
            changed = True
    out = rl_checks(layer, vm, v, facts)
    out += registry(layer, vm, v, facts, run_id, rp)
    if ("PEER_STORE", "INITIALISED") in out or ("REGISTRY", "CREATED") in out:
        changed = True
    receipt = [("CONFIG", "PLACED"), ("ROUTER_JSON_SHA", _sha(router)), ("FEATURE_JSON_SHA", _sha(feature)),
               ("RE_ENV_SHA", _sha(env)), ("D7_SHA", _sha(d7_doc)), ("PLUGIN_SHA", _sha(plugin)),
               ("AGENT_UID", str(facts["uid"])), ("RELAY_UID", str(facts["relay_uid"])),
               ("HOP_GID", str(facts["hop_gid"])), ("PYTHON", facts["python"])] + out
    return receipt, "CHANGED" if changed else "ALREADY"


def run_s6(c, site, rec):
    """S6 over the run scope's two VMs, one receipt each (a2_stage.per_vm). Before any VM: the scope, S3's hub MTA
    hostname and both VMs' S5 keys, each refusal written in the first VM's receipt. A dry-run plans and touches
    nothing."""
    import a2_stage
    names = [v["name"] for v in c.hosts["vms"] if v["scope"] == a2_stage.scope_of(c.inv.loop)]
    if c.inv.command == "dry-run":
        a2_stage.per_vm(rec, site, "S6", names, None, plan=lambda n: [("CONFIG", "PLANNED")], dry_run=True)
        return
    try:
        _scope, vms = scope_vms(c.hosts, c.inv.loop)
        layer = site.vm_layer
        if layer is None:
            raise Refusal(STAGE + ".TARGET_ACCESS", "the VM layer is not bound")
        hub = hub_hostname(rec)
        keys = {v["name"]: read_prior(rec, "S5", v["name"]) for v in vms}
        for name, k in keys.items():
            if not isinstance(k.get("KEY_ID"), str) or not isinstance(k.get("KEY_PUBLIC"), str):
                raise Refusal(STAGE + ".PREDECESSOR_INCOMPLETE", "S5-" + name)
    except Refusal as r:
        a2_stage.refuse_before_vms(rec, site, "S6", names, r)
    by_name = {v["name"]: v for v in vms}
    other = {vms[0]["name"]: vms[1], vms[1]["name"]: vms[0]}
    a2_stage.per_vm(rec, site, "S6", names,
                    lambda n: run_vm(layer, c, by_name[n], other[n], keys, hub, rec.run_id))
