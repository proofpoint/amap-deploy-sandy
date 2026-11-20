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
    "key_id": r"[a-z][a-z0-9-]{0,62}",
    "vm_id": r"[0-9]{1,9}",
    "domain": r"(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+",
    "repo_url": r"(ssh://git@[a-z0-9.-]{1,253}(:[0-9]{1,5})?/[A-Za-z0-9._/-]{1,200}|https://[a-z0-9.-]{1,253}/[A-Za-z0-9._/-]{1,200})",
    "relpath": r"[A-Za-z0-9._-]{1,100}(/[A-Za-z0-9._-]{1,100}){0,15}",
    "abspath": r"/[A-Za-z0-9._+-]{1,100}(/[A-Za-z0-9._+-]{1,100}){0,15}",
    "plugin_api": r"[0-9]{1,4}\.[0-9]{1,4}",
    "py_version": r"3\.[0-9]{1,2}\.[0-9]{1,3}",
    "utc": r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
    "run_id": r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}",
    "rc_tag": r"alpha2-rc[1-9][0-9]{0,3}",
    "host_id": r"[A-Za-z0-9-]{8,64}",
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
        vals = [v[key] for v in value]
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
    "images": ARR(OBJ({"name": S("name"), "built_from": S("name"), "image_id": S("image_id")}),
                  unique=("name",)),
    "files": ARR(OBJ({"path": S("relpath"), "component": S("name"), "sha256": S("sha256")})),
    "writers": ARR(OBJ({"use": ENUM("api_key", "hub_login"), "path": S("relpath"),
                        "sha256": S("sha256")}), lo=2, hi=2, unique=("use",)),
    "plugin": OBJ({"sha256": S("sha256"), "plugin_api": S("plugin_api")}),
    "d7_source": OBJ({"sha256": S("sha256")}),
    "vm_template": OBJ({"name": S("name")}),
}

HOSTS_FIELDS = {
    "schema": CONST("alpha2.hosts/1"),
    "runner": OBJ({"host_id": S("host_id"), "lock_root": S("abspath"),
                   "loop_account": S("name"), "l3_account": S("name")}),
    "hypervisor": OBJ({"name": S("name"), "ssh_alias": S("name")}),
    "hub": OBJ({"name": S("name"), "domain": S("domain")}),
    "vms": ARR(OBJ({"name": S("name"), "scope": ENUM("loop", "l3"), "vm_id": S("vm_id"),
                    "fleet_domain": S("domain"), "key_id": S("key_id"), "ssh_alias": S("name")}),
               unique=("name", "vm_id", "fleet_domain", "key_id", "ssh_alias")),
    "agents": ARR(OBJ({"id": S("name"), "vm": S("name"), "connector": S("name")}),
                  unique=("id",)),
    # Optional: absent is UNCONFIGURED, and destroy refuses (6.2).
    "destroy_deny": ARR((True, "str", "name"), lo=0, req=False),
}


def check_lock(doc):
    _check_obj(LOCK_FIELDS, doc, "$")
    names = {c["name"] for c in doc["components"]}
    # One alpha2-rcN for the whole lock (E24): every component tag and the overlay tag.
    for i, c in enumerate(doc["components"]):
        if c["tag"] != doc["overlay"]["tag"]:
            raise Invalid("L3", "$.components[" + str(i) + "].tag")
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


def check_hosts(doc, lock_doc=None):
    _check_obj(HOSTS_FIELDS, doc, "$")
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
