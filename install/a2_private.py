"""The two private files: strict JSON (section 8 L1), closed objects (L2),
types and patterns (L3), deny patterns (L4), for `alpha2.lock` (6.1) and
`alpha2.hosts` (6.2).

A failure names the check number and a JSON path, never a value. For an
unknown key (L2) the path is the PARENT object's plus the key's ordinal
position, never the key's text.
"""

import json
import re

PATTERNS = {
    "sha256": r"[0-9a-f]{64}",
    "commit": r"[0-9a-f]{40}",
    "image_id": r"sha256:[0-9a-f]{64}",
    "name": r"[a-z][a-z0-9-]{0,62}",
    "vm_id": r"[0-9]{1,9}",
    "domain": r"(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+",
    "repo_url": r"(ssh://git@[a-z0-9.-]{1,253}(:[0-9]{1,5})?/[A-Za-z0-9._/-]{1,200}|https://[a-z0-9.-]{1,253}/[A-Za-z0-9._/-]{1,200})",
    "relpath": r"[A-Za-z0-9._-]{1,100}(/[A-Za-z0-9._-]{1,100}){0,15}",
    "abspath": r"/[A-Za-z0-9._+-]{1,100}(/[A-Za-z0-9._+-]{1,100}){0,15}",
    "plugin_api": r"[0-9]{1,4}\.[0-9]{1,4}",
    "login_part": r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?",
    "pkg_name": r"[a-z_][a-z0-9_]{0,63}",
    "iface_token": r"[a-z0-9]([a-z0-9.-]{0,62}[a-z0-9])?/[1-9][0-9]{0,3}",
    "login_domain": r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+",
    "py_version": r"3\.[0-9]{1,2}\.[0-9]{1,3}",
    "utc": r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
    "run_id": r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}",
    "rc_tag": r"alpha2-rc[1-9][0-9]{0,3}",
    "host_id": r"[A-Za-z0-9-]{8,64}",
    "snaptime": r"[1-9][0-9]{0,11}",
    "slug": r"[a-z0-9][a-z0-9-]{0,62}",
}
_COMPILED = {k: re.compile(v) for k, v in PATTERNS.items()}
_SEGMENTED = ("relpath", "abspath")


class Invalid(Exception):
    """`check` is "L1".."L4"; `path` a JSON path. Never carries a value."""

    def __init__(self, check, path):
        super().__init__(check + " " + path)
        self.check = check
        self.path = path


def matches(pattern, value):
    if not isinstance(value, str) or _COMPILED[pattern].fullmatch(value) is None:
        return False
    if pattern in _SEGMENTED:
        segs = value.split("/")
        if any(s in (".", "..") for s in segs):
            return False
    return True


# ------------------------------------------------------------------ L1


def _no_dup(pairs):
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise Invalid("L1", "$")
        seen.add(k)
    return dict(pairs)


def _no_constant(_name):
    raise Invalid("L1", "$")


def parse(raw, schema_token):
    """L1: UTF-8 without a BOM, JSON with duplicate keys refused, no
    NaN/Infinity, and the `schema` token named."""
    if not isinstance(raw, (bytes, bytearray)):
        raise Invalid("L1", "$")
    if raw[:3] == b"\xef\xbb\xbf":
        raise Invalid("L1", "$")
    try:
        text = bytes(raw).decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise Invalid("L1", "$")
    try:
        doc = json.loads(text, object_pairs_hook=_no_dup, parse_constant=_no_constant)
    except Invalid:
        raise
    except (ValueError, RecursionError):
        raise Invalid("L1", "$")
    if not isinstance(doc, dict) or doc.get("schema") != schema_token:
        raise Invalid("L1", "$.schema")
    return doc


# --------------------------------------------------------- L2 and L3
#
# A field spec is (required, kind, value):
#   kind "str": value is a PATTERNS key, ("const", s) or ("enum", tuple)
#   kind "obj": value is a dict of field specs
#   kind "arr": value is (min, max_or_None, item_field_spec, unique_keys)


def S(p, req=True):
    return (req, "str", p)


def CONST(s):
    return (True, "str", ("const", s))


def ENUM(*vals):
    return (True, "str", ("enum", vals))


def OBJ(fields):
    return (True, "obj", fields)


def ARR(item, lo=1, hi=None, unique=(), req=True):
    return (req, "arr", (lo, hi, item, unique))


def _check_str(spec, value, path):
    if not isinstance(value, str):
        raise Invalid("L3", path)
    if isinstance(spec, tuple):
        kind, arg = spec
        ok = value == arg if kind == "const" else value in arg
    else:
        ok = matches(spec, value)
    if not ok:
        raise Invalid("L3", path)


def _check_obj(fields, value, path):
    if not isinstance(value, dict):
        raise Invalid("L3", path)
    for i, key in enumerate(value):
        if key not in fields:
            raise Invalid("L2", path + "#" + str(i))
    for key, (req, kind, arg) in fields.items():
        if key not in value:
            if req:
                raise Invalid("L3", path + "." + key)
            continue
        _check(kind, arg, value[key], path + "." + key)


def _check_arr(arg, value, path):
    lo, hi, (_, kind, item), unique = arg
    if not isinstance(value, list) or len(value) < lo or (hi is not None and len(value) > hi):
        raise Invalid("L3", path)
    for i, v in enumerate(value):
        _check(kind, item, v, path + "[" + str(i) + "]")
    for key in unique:
        # A key is one field name, or a tuple of field names unique together.
        names = key if isinstance(key, tuple) else (key,)
        vals = [tuple(v[k] for k in names) for v in value]
        if len(set(vals)) != len(vals):
            raise Invalid("L3", path)


def _check(kind, arg, value, path):
    if kind == "str":
        _check_str(arg, value, path)
    elif kind == "obj":
        _check_obj(arg, value, path)
    else:
        _check_arr(arg, value, path)


LOCK_FIELDS = {
    "schema": CONST("alpha2.lock/1"),
    "installer": OBJ({"repo": S("repo_url"), "commit": S("commit"),
                      "entry": CONST("install/alpha2_install.py"), "sha256": S("sha256")}),
    "interpreter": OBJ({"path": CONST("/usr/bin/python3"), "sha256": S("sha256"),
                        "resolved_path": S("abspath"), "resolved_sha256": S("sha256"),
                        "version": S("py_version")}),
    "overlay": OBJ({"repo": S("repo_url"), "commit": S("commit"), "tag": S("rc_tag")}),
    "components": ARR(OBJ({"name": S("name"), "repo": S("repo_url"), "commit": S("commit"),
                           "tag": S("rc_tag")}),
                      unique=("name",)),
    "images": ARR(OBJ({"name": S("name"), "built_from": S("name"), "image_id": S("image_id"),
                        "archive_sha256": S("sha256")}),
                  unique=("name",)),
    "files": ARR(OBJ({"path": S("relpath"), "component": S("name"), "sha256": S("sha256")})),
    "writers": ARR(OBJ({"use": ENUM("api_key", "hub_login"), "path": S("relpath"),
                        "sha256": S("sha256")}), lo=0, hi=2, unique=("use",)),
    "plugin": OBJ({"sha256": S("sha256"), "plugin_api": S("plugin_api")}),
    "d7_source": OBJ({"sha256": S("sha256")}),
    "vm_template": OBJ({"name": S("name")}),
    # The hub login's two private names (W7-HUB-LOGIN-IN-LOCK): the same for every hub; each held to its pin.
    "hub_login": OBJ({"local": S("login_part"), "domain": S("login_domain")}),
    # The registry program's private names (W7-REGISTRY-NAME-IN-LOCK): its Python package and its two interface
    # tokens; each held to its pin below.
    "registry_program": OBJ({"package": S("pkg_name"), "config_schema": S("iface_token"),
                             "adapter_interface": S("iface_token"), "component": S("name")}),
}

HOSTS_FIELDS = {
    "schema": CONST("alpha2.hosts/1"),
    "runner": OBJ({"host_id": S("host_id"), "lock_root": S("abspath"),
                   "loop_account": S("name"), "l3_account": S("name")}),
    "hypervisor": OBJ({"name": S("name"), "ssh_alias": S("name")}),
    "hub": OBJ({"name": S("name"), "domain": S("domain")}),
    # The loop's own hub, a VM on the hypervisor and never a vms[] entry (L2 and L2-leak runs; E1).
    "hub_loop": OBJ({"name": S("name"), "domain": S("domain"), "vm_id": S("vm_id")}),
    # The pinned snapshot set: one entry per member of loop_restore_set, its base snapshot's snaptime.
    "loop_snapshots": ARR(OBJ({"vm": S("name"), "snaptime": S("snaptime")}), unique=("vm",)),
    "vms": ARR(OBJ({"name": S("name"), "scope": ENUM("loop", "l3"), "vm_id": S("vm_id"),
                    "fleet_domain": S("domain"), "ssh_alias": S("name"),
                    # The VM's accounts (W7): sandy, the agents and RL run as agent_account; RE's container as
                    # relay_account; hop_group holds both.
                    "agent_account": S("name"), "relay_account": S("name"), "hop_group": S("name"),
                    # The VM's router (RL, HOST): slug authored, stable_key the registry key (an absolute path on
                    # the VM); the logical id is never authored, it is read back (S6).
                    "router": OBJ({"slug": S("slug"), "stable_key": S("abspath")})}),
               unique=("name", "vm_id", "fleet_domain", "ssh_alias")),
    # E9: an agent id may repeat on different VMs (different fleet domains); it is
    # unique per VM.
    "agents": ARR(OBJ({"id": S("name"), "vm": S("name"), "connector": S("name")}),
                  unique=(("vm", "id"),)),
    # Optional: absent is UNCONFIGURED, and destroy refuses (6.2).
    "destroy_deny": ARR((True, "str", "name"), lo=0, req=False),
}


#: The stage that runs each writer (3.7). A lock may omit a writer (6.1);
#: a run needs each writer whose stage is in its stage set (`writers_required`).
WRITER_STAGE = {"hub_login": "S6b", "api_key": "S7"}


def writers_required(inv, stage_ids):
    """The writers a run needs pinned. Only an L1 run (`--only` or `--from`)
    may lack one, and only when its stage set leaves out that writer's
    stage; every other command needs both."""
    if inv.command == "install" and inv.loop == "L1":
        if "only" in inv.opts:
            stages = {inv.opts["only"]}
        else:
            stages = set(stage_ids[stage_ids.index(inv.opts["from"]):])
        return {use for use, stage in WRITER_STAGE.items() if stage in stages}
    return set(WRITER_STAGE)


#: The hub login's frozen names are private identifiers: this public code pins each by sha256 (hub_runtime's pins,
#: held equal by tests/test_a2_s6_agreement.py) and the lock supplies the value.
LOGIN_LOCAL_SHA256 = "74c95604043427f0bee1d0e16bfa53afd537f736ad0073c4cc4e1ccb3a82b5dc"
LOGIN_DOMAIN_SHA256 = "4a28207acfde319b5b21e4bbf0cec138201f1242e9b966029ae6e9a8122e5889"


#: The registry program's names are private identifiers too: pinned by sha256 here (the values at its pinned commit,
#: held by a private agreement check), supplied by the lock's registry_program.
REGISTRY_PACKAGE_SHA256 = "08839ced62ba20aba0dd60aac3876f15df67ec9087a13fc0d1ebe107afc4b0ae"
REGISTRY_CONFIG_SCHEMA_SHA256 = "77369da2fd759bae9c6acfc6f098ef4605b1e46c0c45e63518b579531b01b893"
REGISTRY_ADAPTER_INTERFACE_SHA256 = "31fe5b260ff0475d8cbe310acf2bbee1f595b5d577c90a928a9a1156803e33c5"
#: The installer's own component in components[] (a2_s6_payload.INSTALLER_COMPONENT): its commit is installer.commit.
INSTALLER_COMPONENT = "amap-deploy-sandy"
REGISTRY_COMPONENT_SHA256 = "d607d98b73729498bc0ccf3863c38b915daad7be1c08215ec43940f70541b3ab"


def _pin(value):
    import hashlib
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def plugin_rows(doc):
    """The files[] rows whose sha256 is the plugin's: exactly one in a lock check_lock accepts."""
    return [f for f in doc["files"] if f["sha256"] == doc["plugin"]["sha256"]]


def check_lock(doc):
    _check_obj(LOCK_FIELDS, doc, "$")
    if _pin(doc["hub_login"]["local"]) != LOGIN_LOCAL_SHA256:
        raise Invalid("L3", "$.hub_login.local")
    if _pin(doc["hub_login"]["domain"]) != LOGIN_DOMAIN_SHA256:
        raise Invalid("L3", "$.hub_login.domain")
    rp = doc["registry_program"]
    for key, pin in (("package", REGISTRY_PACKAGE_SHA256), ("config_schema", REGISTRY_CONFIG_SCHEMA_SHA256),
                     ("adapter_interface", REGISTRY_ADAPTER_INTERFACE_SHA256), ("component", REGISTRY_COMPONENT_SHA256)):
        if _pin(rp[key]) != pin:
            raise Invalid("L3", "$.registry_program." + key)
    if [c["name"] for c in doc["components"]].count(rp["component"]) != 1:
        raise Invalid("L3", "$.registry_program.component")
    # The transport plugin is the one files[] row with plugin.sha256 (W7-PRIVATE-COMPONENT-LOOKUP): S6 reads it by
    # that row's component and path, which public code never names.
    if len(plugin_rows(doc)) != 1:
        raise Invalid("L3", "$.plugin.sha256")
    names = {c["name"] for c in doc["components"]}
    # One alpha2-rcN for the whole lock (E24): every component tag and the overlay tag.
    for i, c in enumerate(doc["components"]):
        if c["tag"] != doc["overlay"]["tag"]:
            raise Invalid("L3", "$.components[" + str(i) + "].tag")
        # The installer's own component is the installer checkout: S4 reads its root files there, by files[] rows of
        # this component, so the two commits are one.
        if c["name"] == INSTALLER_COMPONENT and c["commit"] != doc["installer"]["commit"]:
            raise Invalid("L3", "$.components[" + str(i) + "].commit")
    for i, img in enumerate(doc["images"]):
        if img["built_from"] not in names:
            raise Invalid("L3", "$.images[" + str(i) + "].built_from")
    seen = set()
    for i, f in enumerate(doc["files"]):
        if f["component"] not in names:
            raise Invalid("L3", "$.files[" + str(i) + "].component")
        if (f["component"], f["path"]) in seen:
            raise Invalid("L3", "$.files")
        seen.add((f["component"], f["path"]))


#: Names no router slug may take (RL: they collide with the router's own and the mail roles).
RESERVED_SLUGS = ("postmaster", "abuse")


def skeleton(name):
    """RL's confusable skeleton of a fleet name: NFC, casefold, 0->o 1->l i->l 5->s, then -, _ and . dropped. Two
    names with the same skeleton cannot both be in one fleet."""
    import unicodedata
    s = unicodedata.normalize("NFC", name).casefold()
    s = s.translate(str.maketrans({"0": "o", "1": "l", "i": "l", "5": "s"}))
    return "".join(ch for ch in s if ch not in "-_.")


def loop_restore_set(hosts):
    """The loop's snapshot set: every vms[] entry of scope `loop`, and hub_loop. The one definition: S0's check, S2's
    restore and the hosts rule below all use it."""
    return tuple(sorted([v["name"] for v in hosts["vms"] if v["scope"] == "loop"] + [hosts["hub_loop"]["name"]]))


def hub_for_scope(hosts, scope):
    """The hub a run of `scope` uses: hub_loop for `loop`, hub for `l3`."""
    if scope == "loop":
        h = hosts["hub_loop"]
    elif scope == "l3":
        h = hosts["hub"]
    else:
        raise ValueError("scope")
    return {"name": h["name"], "domain": h["domain"]}


#: A VM's fleet domain is exactly "<host>.internal" (FLEET-DOMAIN-RULE): RE's own domain (HUB_OWN_DOMAIN) is that
#: domain, and the hub names the VM's mailbox and router login by <host>. A fleet domain is never the hub login's own
#: domain, which RE refuses as one (W7-LOGIN-DOMAIN-BY-PIN): held by its sha256 pin, never by name.
_FLEET_DOMAIN = re.compile(r"([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)\.internal")


def fleet_host(domain):
    """The <host> label of a fleet domain "<host>.internal", or None for any other domain or the login domain."""
    m = _FLEET_DOMAIN.fullmatch(domain) if isinstance(domain, str) else None
    if m is None or _pin(domain) == LOGIN_DOMAIN_SHA256:
        return None
    return m.group(1)


def check_hosts(doc, lock_doc=None):
    _check_obj(HOSTS_FIELDS, doc, "$")
    for i, v in enumerate(doc["vms"]):
        if fleet_host(v["fleet_domain"]) is None:
            raise Invalid("L3", "$.vms[" + str(i) + "].fleet_domain")
        if v["relay_account"] == v["agent_account"]:
            raise Invalid("L3", "$.vms[" + str(i) + "].relay_account")
        if v["router"]["slug"] in RESERVED_SLUGS:
            raise Invalid("L3", "$.vms[" + str(i) + "].router.slug")
    keys = [v["router"]["stable_key"] for v in doc["vms"]]
    if len(set(keys)) != len(keys):
        raise Invalid("L3", "$.vms")
    # RL's names are per router: on each VM, its router slug and its agents' ids have distinct skeletons. Across
    # VMs only the router slugs must (an agent id may repeat on another VM: another fleet domain, E9).
    slugs = [v["router"]["slug"] for v in doc["vms"]]
    if len({skeleton(n) for n in slugs}) != len(slugs):
        raise Invalid("L3", "$.vms")
    for v in doc["vms"]:
        names = [v["router"]["slug"]] + [a["id"] for a in doc["agents"] if a["vm"] == v["name"]]
        if len({skeleton(n) for n in names}) != len(names):
            raise Invalid("L3", "$.agents")
    if doc["hub_loop"]["domain"] == doc["hub"]["domain"]:
        raise Invalid("L3", "$.hub_loop.domain")
    if sorted(e["vm"] for e in doc["loop_snapshots"]) != list(loop_restore_set(doc)):
        raise Invalid("L3", "$.loop_snapshots")
    r = doc["runner"]
    if r["loop_account"] == r["l3_account"]:
        raise Invalid("L3", "$.runner.l3_account")
    scopes = {v["scope"] for v in doc["vms"]}
    if scopes != {"loop", "l3"}:
        raise Invalid("L3", "$.vms")
    vm_names = {v["name"] for v in doc["vms"]}
    for i, a in enumerate(doc["agents"]):
        if a["vm"] not in vm_names:
            raise Invalid("L3", "$.agents[" + str(i) + "].vm")
    deny = doc.get("destroy_deny")
    if deny is not None:
        if len(set(deny)) != len(deny):
            raise Invalid("L3", "$.destroy_deny")
        for i, n in enumerate(deny):
            if n not in vm_names:
                raise Invalid("L3", "$.destroy_deny[" + str(i) + "]")
    if lock_doc is not None:
        comps = {c["name"] for c in lock_doc["components"]}
        for i, a in enumerate(doc["agents"]):
            if a["connector"] not in comps:
                raise Invalid("L3", "$.agents[" + str(i) + "].connector")


# ------------------------------------------------------------------ L4

#: The API-key shape is [OPEN: the shapes, from the S1 review]; it is
#: added here by that review.
DENY = [
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    re.compile(r"ghp_"),
    re.compile(r"github_pat_"),
    re.compile(r"glpat-"),
    re.compile(r"://[^/@]*:[^/@]*@"),
]


def _strings(node, path):
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, dict):
        for i, (k, v) in enumerate(node.items()):
            yield path + "#" + str(i), k
            yield from _strings(v, path + "." + k if isinstance(k, str) else path)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _strings(v, path + "[" + str(i) + "]")


def check_deny(raw, doc):
    text = bytes(raw).decode("utf-8", errors="replace")
    for rx in DENY:
        if rx.search(text):
            raise Invalid("L4", "$")
    for path, s in _strings(doc, "$"):
        for rx in DENY:
            if rx.search(s):
                raise Invalid("L4", path if "#" not in path else path.split("#")[0])


# --------------------------------------------------------- one entry


def load_pair(lock_raw, hosts_raw):
    """L1 to L4 on both in-memory files. Returns (lock_doc, hosts_doc) or
    raises (which_file, Invalid) via PairInvalid."""
    try:
        lock = parse(lock_raw, "alpha2.lock/1")
        check_lock(lock)
        check_deny(lock_raw, lock)
    except Invalid as e:
        raise PairInvalid("lock", e)
    try:
        hosts = parse(hosts_raw, "alpha2.hosts/1")
        check_hosts(hosts, lock)
        check_deny(hosts_raw, hosts)
    except Invalid as e:
        raise PairInvalid("hosts", e)
    return lock, hosts


class PairInvalid(Exception):
    def __init__(self, which, inv):
        super().__init__(which + " " + str(inv))
        self.which = which
        self.inv = inv

    @property
    def cause(self):
        return "PREFLIGHT.LEAK_LOCK" if self.which == "lock" else "PREFLIGHT.LEAK_HOSTS"

    @property
    def detail(self):
        return "check " + self.inv.check + " at " + self.inv.path
