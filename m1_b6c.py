"""m1_b6c.py: B6c's receipt for the M1 VMs: its byte forms, the O-n file map,
its shared pre-flight, its reader and its atomic write. Standard library only.

B6c renders each VM's overlay O-n in a clone of the base image and writes one
receipt, `OUT/b6c-receipt.json`, that later steps bind to: HAR-PFV verifies
it, both start gos quote that verification, and ADM compares the installed
O-n with it. This module holds what every producer and reader of that
receipt must agree on byte for byte (schema `amap-m1-b6c-receipt/1`):

  canonical(obj)          sorted keys, compact, ASCII, no NaN
  receipt_bytes(doc)      the receipt file: canonical(doc) and one LF
  artifact_bytes(v)       the fleet artifact in the router's own canonical rule;
                          for V = 0, exactly {"min_sender_age_s":0,"v":1}
  strict_loads(data)      refuses a repeated key, a non-finite number and any
                          non-ASCII byte
  walk(dir_fd)            one VM's O-n as {key: {"mode", "sha256"}}, read
                          without following a link; every file exactly 0444 or
                          0555 (its sealed mode), the set closed
  vm_facts(out_fd, n)     OUT/<n>'s walk and its four fixed files, parsed
  preflight(...)          every pre-flight equality, computed from inputs; the
                          writer and the reader call this one function
  read_receipt(...)       the receipt verified from OUT's own bytes and the
                          caller's MAN, vectors and ancestry result
  write_receipt(out, doc) the run's last write: a fixed temp name, fsync,
                          link() that refuses an existing receipt, fsync OUT

The file owners and the sealing of OUT's payload directories are not this
module's to check: ADM and D-SEAL own them on the installed copy.

Nothing here renders, installs or runs anything; it refuses by raising
Refused, with the rule it broke. NET's values file is parsed in its closed
shape, NET-VALUES-SHAPE r2."""

import hashlib
import json
import math
import os
import posixpath
import re
import stat
from typing import Any, Dict, List, Tuple

SCHEMA = "amap-m1-b6c-receipt/1"
RECEIPT_NAME = "b6c-receipt.json"
RECEIPT_TEMP = ".b6c-receipt.json.tmp"
ARTIFACT_NAME = "fleet-admission-policy.json"
NET_VALUES_NAME = "net-values.json"
VMS = ("vm1", "vm2")
ROLE_OF = {"vm1": "H1", "vm2": "H2"}
#: OUT's top level after a run, exactly; the temp name exists only during the write.
OUT_ENTRIES = frozenset({ARTIFACT_NAME, NET_VALUES_NAME, *VMS, RECEIPT_NAME})
#: Each VM's four fixed O-n names, never executable; everything else is under payload/.
FIXED_FILES = ("feature.json", "router.json", "m1-role.json", "deploy-overlay.json")
PAYLOAD_DIR = "payload"
MODE_PLAIN, MODE_EXEC = "0444", "0555"
MIN_SENDER_AGE_MAX_S = 31536000
#: The deploy checkout MAN records, by its absolute path.
DEPLOY_CHECKOUT = "/opt/amap/src/amap-deploy-sandy"
#: The commit whose ancestry proves the hop pin carries the router's sender-age setting.
ENROL_COMMIT = "6d104e705974b0f9c90507629f5371755fbe0ca4"

#: NET-VALUES-SHAPE r2's closed key sets.
NET_KEYS = frozenset({"version", *VMS})
NET_VM_KEYS = frozenset({"vm", "hostname", "own_domain", "login", "probe_domain", "statement", "fleet_hosts",
                         "d7_source"})
#: The hub's frozen login parts and probe domain, as sha256 pins: hub_runtime's
#: LOGIN_LOCAL_SHA256, LOGIN_DOMAIN_SHA256 and PROBE_DOMAIN_SHA256, which a test holds equal.
LOGIN_LOCAL_SHA256 = "74c95604043427f0bee1d0e16bfa53afd537f736ad0073c4cc4e1ccb3a82b5dc"
LOGIN_DOMAIN_SHA256 = "4a28207acfde319b5b21e4bbf0cec138201f1242e9b966029ae6e9a8122e5889"
PROBE_DOMAIN_SHA256 = "f40f36185588e8a6292c654f632086d5b204c5d763779ce632bd5138b805af56"
#: The fields the pre-flight compares with each role manifest.
NET_MATCH_KEYS = ("vm", "hostname", "own_domain")

ROLE_SCHEMA = "amap-m1-role/1"
#: ROLE-MANIFEST-INTERFACE r3's closed key sets.
ROLE_KEYS = frozenset({"schema", "role", "vm", "hostname", "fd", "own_domain", "ids", "units",
                       "fleet_policy_digest", "start"})
IDS_KEYS = frozenset({"op", "m1-admin", "adm", "uid-1", "uid-2", "registry"})
START_KEYS = frozenset({"uid_1", "group_add", "config", "image", "name"})
RECEIPT_KEYS = frozenset({"schema", "deploy_commit", "deploy_tree", "hop_pin", "t0_manifest_sha256",
                          "net_values_sha256", "sandy_schema_version", "v", "fleet_artifact", "vms",
                          "preflight"})
ARTIFACT_KEYS = frozenset({"path", "sha256", "digest", "schema_v", "min_sender_age_s"})
VM_KEYS = frozenset({"role", "vm", "hostname", "own_domain", "fd", "files", "on_manifest_sha256",
                     "role_sha256", "carried_digest", "router_min_sender_age_s", "start", "state_dir",
                     "run_dir", "router_container"})
_GLOBAL_CHECKS = ("artifact_known_answer", "artifact_value_is_v", "v_in_range", "hop_pin_has_enrol",
                  "deploy_commit_is_man", "deploy_tree_is_man", "hop_pin_is_man", "role_differ", "fd_differ",
                  "own_domain_differ")
_VM_CHECKS = ("net_values_match", "manifest_is_receipt", "role_digest", "feature_value", "feature_fd",
              "router_value", "start_is_role", "container_is_start_name", "modes_match", "state_dir_is_router",
              "run_dir_is_overlay", "container_is_overlay", "image_is_overlay", "image_commit_is_hop_pin")
#: Every pre-flight key, exactly; a receipt with any other set refuses.
PREFLIGHT_KEYS = frozenset(_GLOBAL_CHECKS + tuple(f"{c}_{n}" for c in _VM_CHECKS for n in VMS))

_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX40 = re.compile(r"[0-9a-f]{40}")
_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,32}")
_VM_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
_HOSTNAME = re.compile(_LABEL)
_DNS = re.compile(rf"{_LABEL}(\.{_LABEL})*")
_CONTAINER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_IMAGE_NAME = re.compile(r"[a-z0-9][a-z0-9._/-]*")
#: The factory router's own image tag, which hop_router.load refuses as the hop
#: router's image name (as a basename); a test holds it equal to hop_router's.
FACTORY_IMAGE = "amap-router-local"
_OWN = re.compile(rf"{_LABEL}\.internal")
_STATEMENT = re.compile(r"[ -~]{1,400}")
_REPO_PATH = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]*(/[A-Za-z0-9_][A-Za-z0-9._-]*)*")
_UNIT = re.compile(r"[A-Za-z0-9:_.@\\-]+\.(service|mount|timer|socket|target|path)")
_KEY_PART = re.compile(r"[\x21-\x7e]+")
_OPEN = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)


class Refused(Exception):
    """One broken rule, named."""


# --- byte forms -------------------------------------------------------------------

def canonical(obj: Any) -> bytes:
    """The schema's canonical JSON: sorted keys, `,` and `:` with no space,
    ASCII with escapes, NaN and Infinity refused."""
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                          allow_nan=False).encode("ascii")
    except ValueError as e:
        raise Refused(f"not canonical JSON: {e}") from None


def receipt_bytes(doc: Dict[str, Any]) -> bytes:
    """The receipt file's exact bytes: one compact ASCII line ending in LF."""
    return canonical(doc) + b"\n"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(sha: Any) -> str:
    """A digest is the string "sha256:" + 64 lowercase hex."""
    if not isinstance(sha, str) or not _HEX64.fullmatch(sha):
        raise Refused(f"{sha!r} is not 64 lowercase hex")
    return "sha256:" + sha


def artifact_bytes(v: Any) -> bytes:
    """The fleet artifact for V = `v`, in the router's canonical rule
    (sort_keys, (",", ":"), ensure_ascii=False, allow_nan=False, UTF-8):
    for V = 0 the bytes are exactly {"min_sender_age_s":0,"v":1}."""
    _int(v, "V")
    return json.dumps({"min_sender_age_s": v, "v": 1}, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _no_repeat(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise Refused(f"the key {k!r} appears twice")
        out[k] = v
    return out


def _no_constant(name: str) -> Any:
    raise Refused(f"{name} is not a JSON number this schema accepts")


def _finite(text: str) -> float:
    v = float(text)
    if not math.isfinite(v):
        raise Refused(f"{text} is not a finite number")
    return v


def strict_loads(data: bytes, what: str) -> Any:
    """`data` parsed as JSON, refusing a non-ASCII byte, a repeated key, and
    NaN, Infinity or an overflowing literal."""
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise Refused(f"{what} is not ASCII") from None
    try:
        return json.loads(text, object_pairs_hook=_no_repeat, parse_constant=_no_constant, parse_float=_finite)
    except ValueError as e:
        raise Refused(f"{what} is not JSON: {e}") from None


# --- typed field validators -------------------------------------------------------

def _closed(obj: Any, keys: frozenset, what: str) -> Dict[str, Any]:
    if not isinstance(obj, dict) or set(obj) != keys:
        have = sorted(obj) if isinstance(obj, dict) else type(obj).__name__
        raise Refused(f"{what} must have exactly {sorted(keys)}; it has {have}")
    return obj


def _int(v: Any, what: str, lo: int = 0, hi: int = MIN_SENDER_AGE_MAX_S) -> int:
    """Exactly an int (never a bool, a float or an int subclass) in [lo, hi]."""
    if type(v) is not int or not lo <= v <= hi:
        raise Refused(f"{what} {v!r} is not an int from {lo} to {hi}")
    return v


def _match(v: Any, pattern: "re.Pattern[str]", what: str) -> str:
    if type(v) is not str or not pattern.fullmatch(v):
        raise Refused(f"{what} {v!r} is malformed")
    return v


def _dns(v: Any, what: str) -> str:
    if type(v) is not str or len(v) > 253:
        raise Refused(f"{what} {v!r} is not a DNS name")
    return _match(v, _DNS, what)


def _abs_path(v: Any, what: str) -> str:
    """An absolute, normalised, printable-ASCII path."""
    if (type(v) is not str or not v.startswith("/") or v.startswith("//") or posixpath.normpath(v) != v
            or not all("\x21" <= c <= "\x7e" for c in v)):
        raise Refused(f"{what} {v!r} is not an absolute, normalised ASCII path")
    return v


def _digest_str(v: Any, what: str) -> str:
    if type(v) is not str or not v.startswith("sha256:"):
        raise Refused(f"{what} {v!r} is not sha256:<64 hex>")
    digest(v[len("sha256:"):])
    return v


def _start(obj: Any, what: str) -> Dict[str, Any]:
    s = _closed(obj, START_KEYS, what)
    _int(s["uid_1"], f"{what}.uid_1", 1, 2 ** 31 - 1)
    _int(s["group_add"], f"{what}.group_add", 1, 2 ** 31 - 1)
    _abs_path(s["config"], f"{what}.config")
    _match(s["image"], _IMAGE_ID, f"{what}.image")
    _match(s["name"], _CONTAINER, f"{what}.name")
    return s


def same(a: Any, b: Any) -> bool:
    """Equality of two JSON values, type for type: their canonical bytes."""
    return canonical(a) == canonical(b)


# --- the O-n file map -------------------------------------------------------------

def check_key(key: Any) -> str:
    """A `files` key: a relative POSIX path, `/`-separated, with no empty,
    `.` or `..` component and no leading `/`, printable ASCII without
    spaces, equal to its own normalisation."""
    if type(key) is not str or not key or key.startswith("/") or posixpath.normpath(key) != key:
        raise Refused(f"the files key {key!r} is not a normalised relative path")
    for part in key.split("/"):
        if part in ("", ".", "..") or not _KEY_PART.fullmatch(part):
            raise Refused(f"the files key {key!r} has the component {part!r}")
    return key


def mode_class(mode: int, key: str) -> str:
    """The sealed mode a file takes, from its x bits: all three set is 0555,
    none set is 0444, anything between refuses. A fixed name is never
    executable."""
    x = stat.S_IMODE(mode) & 0o111
    if x == 0o111:
        cls = MODE_EXEC
    elif x == 0:
        cls = MODE_PLAIN
    else:
        raise Refused(f"{key} has a partial execute pattern {stat.S_IMODE(mode):04o}")
    if key in FIXED_FILES and cls != MODE_PLAIN:
        raise Refused(f"{key} is a fixed O-n name and is never executable")
    return cls


def _hash_fd(fd: int) -> str:
    h = hashlib.sha256()
    while True:
        chunk = os.read(fd, 1 << 20)
        if not chunk:
            return h.hexdigest()
        h.update(chunk)


def _open_dir(dir_fd: int, name: str, what: str) -> int:
    """`name` under `dir_fd` as a directory: lstat, open without following a
    link, and the opened directory must be the one lstat saw."""
    try:
        st = os.lstat(name, dir_fd=dir_fd)
        if not stat.S_ISDIR(st.st_mode):
            raise Refused(f"{what} is not a directory")
        fd = os.open(name, _OPEN | os.O_DIRECTORY, dir_fd=dir_fd)
    except OSError as e:
        raise Refused(f"{what} cannot be opened without following a link ({e.strerror})") from None
    st2 = os.fstat(fd)
    if (st2.st_dev, st2.st_ino) != (st.st_dev, st.st_ino):
        os.close(fd)
        raise Refused(f"{what} changed while it was opened")
    return fd


def walk(dir_fd: int) -> Dict[str, Dict[str, str]]:
    """One VM's O-n under `dir_fd`, as {key: {"mode", "sha256"}}: each entry
    reached descriptor-relative without following a link, each a regular
    file with one link or a directory with a file under it, the four fixed
    names present and at least one file under payload/. Every file's mode
    is EXACTLY its sealed class, 0444 or 0555: OUT holds the class itself."""
    files: Dict[str, Dict[str, str]] = {}

    def visit(dfd: int, prefix: str) -> int:
        found = 0
        for name in sorted(os.listdir(dfd)):
            key = check_key(posixpath.join(prefix, name) if prefix else name)
            st = os.lstat(name, dir_fd=dfd)
            if stat.S_ISDIR(st.st_mode):
                sub = _open_dir(dfd, name, key)
                try:
                    n = visit(sub, key)
                finally:
                    os.close(sub)
                if n == 0:
                    raise Refused(f"{key}/ holds no file")
                found += n
            elif stat.S_ISREG(st.st_mode):
                fd = os.open(name, _OPEN, dir_fd=dfd)
                try:
                    st2 = os.fstat(fd)
                    if (st2.st_dev, st2.st_ino) != (st.st_dev, st.st_ino) or st2.st_nlink != 1:
                        raise Refused(f"{key} changed while it was read, or has more than one link")
                    cls = mode_class(st2.st_mode, key)
                    if stat.S_IMODE(st2.st_mode) != int(cls, 8):
                        raise Refused(f"{key} is {stat.S_IMODE(st2.st_mode):04o}, not exactly {cls}")
                    files[key] = {"mode": cls, "sha256": _hash_fd(fd)}
                finally:
                    os.close(fd)
                found += 1
            else:
                raise Refused(f"{key} is neither a regular file nor a directory")
        return found

    try:
        visit(dir_fd, "")
    except OSError as e:
        raise Refused(f"the O-n cannot be read: {e.strerror}") from None
    missing = [k for k in FIXED_FILES if k not in files]
    if missing:
        raise Refused("the O-n lacks " + ", ".join(missing))
    stray = [k for k in files if k not in FIXED_FILES and not k.startswith(PAYLOAD_DIR + "/")]
    if stray:
        raise Refused("outside the fixed names and payload/: " + ", ".join(stray))
    if not any(k.startswith(PAYLOAD_DIR + "/") for k in files):
        raise Refused("payload/ holds no file")
    return files


def on_manifest_sha256(files: Dict[str, Dict[str, str]]) -> str:
    """The O-n manifest's sha256: the canonical form of `files`, no LF."""
    return sha256(canonical(files))


# --- the parsed inputs ------------------------------------------------------------

def net_values(data: bytes) -> Dict[str, Dict[str, Any]]:
    """NET's values file under NET-VALUES-SHAPE r2: its bytes exactly
    canonical(doc) and one LF; the top level closed {version, vm1, vm2},
    version the int 1; each VM closed, every field typed, vm == hostname,
    and the login parts and probe domain equal to the hub's pins. Returns
    {vm1: ..., vm2: ...}, each VM's object as written."""
    doc = _closed(strict_loads(data, "NET's values file"), NET_KEYS, "NET's values file")
    if data != receipt_bytes(doc):
        raise Refused("NET's values file is not canonical JSON and one LF")
    if type(doc["version"]) is not int or doc["version"] != 1:
        raise Refused("NET's values file's version is not the int 1")
    out = {}
    for n in VMS:
        what = f"NET's values for {n}"
        e = _closed(doc[n], NET_VM_KEYS, what)
        _match(e["vm"], _HOSTNAME, f"{what}: vm")
        _match(e["hostname"], _HOSTNAME, f"{what}: hostname")
        if e["vm"] != e["hostname"]:
            raise Refused(f"{what}: vm is not hostname")
        own = _match(e["own_domain"], _OWN, f"{what}: own_domain")
        login = _closed(e["login"], frozenset({"local", "domain"}), f"{what}: login")
        if (type(login["local"]) is not str or type(login["domain"]) is not str
                or sha256(login["local"].encode()) != LOGIN_LOCAL_SHA256
                or sha256(login["domain"].encode()) != LOGIN_DOMAIN_SHA256):
            raise Refused(f"{what}: login is not the hub's frozen login local part and domain")
        if sha256(_match(e["probe_domain"], _OWN, f"{what}: probe_domain").encode()) != PROBE_DOMAIN_SHA256:
            raise Refused(f"{what}: probe_domain is not the hub's frozen probe domain")
        _match(e["statement"], _STATEMENT, f"{what}: statement")
        fleet = e["fleet_hosts"]
        if type(fleet) is not list:
            raise Refused(f"{what}: fleet_hosts is not a list")
        for d in fleet:
            _match(d, _OWN, f"{what}: a fleet host")
        if not fleet or fleet != sorted(set(fleet)) or own in fleet:
            raise Refused(f"{what}: fleet_hosts is not a sorted, distinct, non-empty list without own_domain")
        src = _closed(e["d7_source"], frozenset({"sha256", "commit", "from"}), f"{what}: d7_source")
        _match(src["sha256"], _HEX64, f"{what}: d7_source.sha256")
        _match(src["commit"], _HEX40, f"{what}: d7_source.commit")
        _match(src["from"], _REPO_PATH, f"{what}: d7_source.from")
        out[n] = e
    return out


def parse_role_manifest(data: bytes) -> Dict[str, Any]:
    """A role manifest under ROLE-MANIFEST-INTERFACE r3: strict JSON, the
    closed key sets, and every field's type."""
    doc = _closed(strict_loads(data, "the role manifest"), ROLE_KEYS, "the role manifest")
    if doc["schema"] != ROLE_SCHEMA:
        raise Refused(f"the role manifest's schema is not {ROLE_SCHEMA}")
    if doc["role"] not in ROLE_OF.values():
        raise Refused(f"the role manifest's role {doc['role']!r} is not H1 or H2")
    _match(doc["vm"], _VM_NAME, "the role manifest's vm")
    _match(doc["hostname"], _HOSTNAME, "the role manifest's hostname")
    _dns(doc["fd"], "the role manifest's fd")
    _dns(doc["own_domain"], "the role manifest's own_domain")
    ids = _closed(doc["ids"], IDS_KEYS, "the role manifest's ids")
    for k in sorted(ids):
        _int(ids[k], f"the role manifest's ids.{k}", 0, 2 ** 31 - 1)
    units = doc["units"]
    if type(units) is not list or not units or units != sorted(set(units)):
        raise Refused("the role manifest's units is not a sorted, distinct, non-empty list")
    for u in units:
        _match(u, _UNIT, "a role manifest unit")
    _digest_str(doc["fleet_policy_digest"], "the role manifest's fleet_policy_digest")
    _start(doc["start"], "the role manifest's start")
    return doc


def parse_router(data: bytes) -> Tuple[int, str]:
    """router.json, strictly: its top-level min_sender_age_s (exactly an int
    in range) and its state_dir (an absolute path), as the router loads them."""
    doc = strict_loads(data, "router.json")
    if not isinstance(doc, dict) or "min_sender_age_s" not in doc:
        raise Refused("router.json carries no min_sender_age_s")
    if "state_dir" not in doc:
        raise Refused("router.json names no state_dir")
    return (_int(doc["min_sender_age_s"], "router.json's min_sender_age_s"),
            _abs_path(doc["state_dir"], "router.json's state_dir"))


def parse_feature(data: bytes) -> Tuple[int, str]:
    """feature.json, strictly: the policy's min_sender_age_s and fleet_domain,
    from its `feature` section."""
    doc = strict_loads(data, "feature.json")
    feature = doc.get("feature") if isinstance(doc, dict) else None
    if not isinstance(feature, dict):
        raise Refused("feature.json has no feature section")
    if "min_sender_age_s" not in feature or "fleet_domain" not in feature:
        raise Refused("feature.json's feature section lacks min_sender_age_s or fleet_domain")
    return (_int(feature["min_sender_age_s"], "feature.json's min_sender_age_s"),
            _dns(feature["fleet_domain"], "feature.json's fleet_domain"))


def parse_overlay(data: bytes) -> Dict[str, str]:
    """deploy-overlay.json, strictly: exactly the `registry` and `host_setup`
    sections; from host_setup (the host-setup document), its router section,
    closed as hop_router.load closes it (image {name, digest, commit} and
    container, each in that module's grammar), and its secrets section's
    run_dir. A value it does not name refuses by name. Nothing else in the
    overlay is read: registry, the host-setup document's other sections and
    secrets' other keys stay open here, since the overlay's bytes are bound
    by its files sha and their own parsers type them."""
    doc = _closed(strict_loads(data, "the overlay"), frozenset({"registry", "host_setup"}), "the overlay")
    hs = doc["host_setup"]
    if not isinstance(hs, dict):
        raise Refused("the overlay's host_setup is not an object")
    router, secrets = hs.get("router"), hs.get("secrets")
    if not isinstance(router, dict) or "container" not in router:
        raise Refused("the overlay names no router.container")
    _closed(router, frozenset({"image", "container"}), "the overlay's router")
    image = _closed(router["image"], frozenset({"name", "digest", "commit"}), "the overlay's router.image")
    if posixpath.basename(_match(image["name"], _IMAGE_NAME, "the overlay's router.image.name")) == FACTORY_IMAGE:
        raise Refused(f"the overlay's router.image.name is the factory router's own tag ({FACTORY_IMAGE})")
    if not isinstance(secrets, dict) or "run_dir" not in secrets:
        raise Refused("the overlay names no run_dir")
    return {"run_dir": _abs_path(secrets["run_dir"], "the overlay's secrets.run_dir"),
            "router_container": _match(router["container"], _CONTAINER, "the overlay's router.container"),
            "image_digest": _match(image["digest"], _IMAGE_ID, "the overlay's router.image.digest"),
            "image_commit": _match(image["commit"], _HEX40, "the overlay's router.image.commit")}


def parse_artifact(data: bytes) -> int:
    """The fleet artifact: the closed {min_sender_age_s, v} object, v == 1,
    whose bytes are exactly the router's canonical form. Returns V."""
    doc = _closed(strict_loads(data, "the fleet artifact"), frozenset({"min_sender_age_s", "v"}),
                  "the fleet artifact")
    if type(doc["v"]) is not int or doc["v"] != 1:
        raise Refused("the fleet artifact's v is not 1")
    v = _int(doc["min_sender_age_s"], "the fleet artifact's min_sender_age_s")
    if data != artifact_bytes(v):
        raise Refused("the fleet artifact's bytes are not the router's canonical form")
    return v


def known_answer(vectors: bytes, v: int) -> str:
    """The digest the router's vectors file gives for V: the closed
    {description, cases}, each case closed, and EXACTLY ONE case for V,
    itself exactly an int in range."""
    _int(v, "V")
    doc = _closed(strict_loads(vectors, "the vectors file"), frozenset({"description", "cases"}),
                  "the vectors file")
    if type(doc["cases"]) is not list:
        raise Refused("the vectors file's cases is not a list")
    hits = [c for c in doc["cases"]
            if _closed(c, frozenset({"min_sender_age_s", "canonical", "digest"}), "a vectors case")
            and type(c["min_sender_age_s"]) is int and c["min_sender_age_s"] == v]
    if len(hits) != 1:
        raise Refused(f"the vectors file has {len(hits)} cases for V {v}, not exactly one")
    return _digest_str(hits[0]["digest"], "the vectors case's digest")


def man_values(man: bytes) -> Tuple[str, str, str]:
    """MAN's deploy checkout head and tree, and its router1 build commit,
    read by key lookup."""
    doc = strict_loads(man, "MAN")
    try:
        co = doc["checkouts"][DEPLOY_CHECKOUT]
        head, tree, hop = co["head"], co["tree"], doc["builds"]["router1"]["commit"]
    except (KeyError, TypeError):
        raise Refused(f"MAN lacks checkouts[{DEPLOY_CHECKOUT!r}].head/.tree or builds.router1.commit") from None
    return (_match(head, _HEX40, "MAN's deploy head"), _match(tree, _HEX40, "MAN's deploy tree"),
            _match(hop, _HEX40, "MAN's router1 commit"))


# --- the receipt ------------------------------------------------------------------

def parse_receipt(data: bytes) -> Dict[str, Any]:
    """The receipt's own bytes: strict, canonical (the bytes equal their
    re-serialisation plus one LF), closed at every level, every field typed,
    and the pre-flight exactly PREFLIGHT_KEYS, every value true."""
    doc = _closed(strict_loads(data, "the receipt"), RECEIPT_KEYS, "the receipt")
    if data != receipt_bytes(doc):
        raise Refused("the receipt is not in its canonical form")
    if doc["schema"] != SCHEMA:
        raise Refused(f"the receipt's schema is not {SCHEMA}")
    for k in ("deploy_commit", "deploy_tree", "hop_pin"):
        _match(doc[k], _HEX40, f"the receipt's {k}")
    for k in ("t0_manifest_sha256", "net_values_sha256"):
        _match(doc[k], _HEX64, f"the receipt's {k}")
    _match(doc["sandy_schema_version"], _TOKEN, "the receipt's sandy_schema_version")
    v = _int(doc["v"], "the receipt's v")
    art = _closed(doc["fleet_artifact"], ARTIFACT_KEYS, "the receipt's fleet_artifact")
    if art["path"] != ARTIFACT_NAME:
        raise Refused(f"the receipt's fleet_artifact.path is not {ARTIFACT_NAME}")
    if type(art["schema_v"]) is not int or art["schema_v"] != 1:
        raise Refused("the receipt's fleet_artifact.schema_v is not the int 1")
    if _int(art["min_sender_age_s"], "the receipt's fleet_artifact.min_sender_age_s") != v:
        raise Refused("the receipt's fleet_artifact.min_sender_age_s is not v")
    _match(art["sha256"], _HEX64, "the receipt's fleet_artifact.sha256")
    if art["digest"] != digest(art["sha256"]):
        raise Refused("the receipt's fleet_artifact.digest is not sha256: + its sha256")
    _closed(doc["vms"], frozenset(VMS), "the receipt's vms")
    for n in VMS:
        what = f"the receipt's vms.{n}"
        e = _closed(doc["vms"][n], VM_KEYS, what)
        if e["role"] != ROLE_OF[n]:
            raise Refused(f"{what}.role is not {ROLE_OF[n]}")
        _match(e["vm"], _VM_NAME, f"{what}.vm")
        _match(e["hostname"], _HOSTNAME, f"{what}.hostname")
        _dns(e["own_domain"], f"{what}.own_domain")
        _dns(e["fd"], f"{what}.fd")
        if type(e["files"]) is not dict or not e["files"]:
            raise Refused(f"{what}.files is not a non-empty object")
        for key, val in e["files"].items():
            check_key(key)
            _closed(val, frozenset({"mode", "sha256"}), f"{what}.files[{key!r}]")
            if val["mode"] not in (MODE_PLAIN, MODE_EXEC):
                raise Refused(f"{what}.files[{key!r}].mode is not 0444 or 0555")
            _match(val["sha256"], _HEX64, f"{what}.files[{key!r}].sha256")
        _match(e["on_manifest_sha256"], _HEX64, f"{what}.on_manifest_sha256")
        _match(e["role_sha256"], _HEX64, f"{what}.role_sha256")
        _digest_str(e["carried_digest"], f"{what}.carried_digest")
        _int(e["router_min_sender_age_s"], f"{what}.router_min_sender_age_s")
        _start(e["start"], f"{what}.start")
        _abs_path(e["state_dir"], f"{what}.state_dir")
        _abs_path(e["run_dir"], f"{what}.run_dir")
        _match(e["router_container"], _CONTAINER, f"{what}.router_container")
    pf = doc["preflight"]
    if type(pf) is not dict or set(pf) != PREFLIGHT_KEYS or not all(x is True for x in pf.values()):
        raise Refused("the receipt's preflight is not exactly the pre-flight keys, every one true")
    return doc


def preflight(receipt: Dict[str, Any], *, man: bytes, vectors: bytes, hop_ancestry: bool,
              artifact: bytes, net: Any, vms: Dict[str, Dict[str, Any]]) -> Dict[str, bool]:
    """Every pre-flight equality, computed from inputs, never copied, and
    compared type for type. `vms` maps vm1/vm2 to the parsed facts of that
    VM's OUT tree: `files` (walk), `role` (parse_role_manifest), `router`
    ((age, state_dir), parse_router), `feature` ((age, fleet_domain),
    parse_feature), `overlay` (parse_overlay). `net` is net_values()'s
    result. Writer and reader both call this one function."""
    v = receipt["v"]
    head, tree, hop = man_values(man)
    art_digest = digest(sha256(artifact))
    out = {
        "artifact_known_answer": art_digest == known_answer(vectors, v),
        "artifact_value_is_v": parse_artifact(artifact) == v,
        "v_in_range": type(v) is int and 0 <= v <= MIN_SENDER_AGE_MAX_S,
        "hop_pin_has_enrol": hop_ancestry is True,
        "deploy_commit_is_man": receipt["deploy_commit"] == head,
        "deploy_tree_is_man": receipt["deploy_tree"] == tree,
        "hop_pin_is_man": receipt["hop_pin"] == hop,
        "role_differ": vms["vm1"]["role"]["role"] != vms["vm2"]["role"]["role"],
        "fd_differ": vms["vm1"]["role"]["fd"] != vms["vm2"]["role"]["fd"],
        "own_domain_differ": vms["vm1"]["role"]["own_domain"] != vms["vm2"]["role"]["own_domain"],
    }
    for n in VMS:
        f, e = vms[n], receipt["vms"][n]
        role, (router_age, state_dir), ov = f["role"], f["router"], f["overlay"]
        out[f"net_values_match_{n}"] = same({k: net[n][k] for k in NET_MATCH_KEYS}, {k: role[k] for k in NET_MATCH_KEYS})
        out[f"manifest_is_receipt_{n}"] = (role["role"] == ROLE_OF[n] and
                                            same({k: role[k] for k in ("role", "vm", "hostname", "fd", "own_domain")},
                                                 {k: e[k] for k in ("role", "vm", "hostname", "fd", "own_domain")}))
        out[f"role_digest_{n}"] = role["fleet_policy_digest"] == art_digest
        out[f"feature_value_{n}"] = same(f["feature"][0], v)
        out[f"feature_fd_{n}"] = f["feature"][1] == e["fd"]
        out[f"router_value_{n}"] = same(router_age, v)
        out[f"start_is_role_{n}"] = same(e["start"], role["start"])
        out[f"container_is_start_name_{n}"] = e["router_container"] == role["start"]["name"]
        out[f"modes_match_{n}"] = same(e["files"], f["files"])
        out[f"state_dir_is_router_{n}"] = e["state_dir"] == state_dir
        out[f"run_dir_is_overlay_{n}"] = e["run_dir"] == ov["run_dir"]
        out[f"container_is_overlay_{n}"] = e["router_container"] == ov["router_container"]
        out[f"image_is_overlay_{n}"] = role["start"]["image"] == ov["image_digest"]
        out[f"image_commit_is_hop_pin_{n}"] = ov["image_commit"] == receipt["hop_pin"]
    if set(out) != PREFLIGHT_KEYS:
        raise Refused("the pre-flight computed keys other than PREFLIGHT_KEYS")
    return out


def _read(dir_fd: int, name: str, what: str) -> bytes:
    try:
        fd = os.open(name, _OPEN, dir_fd=dir_fd)
    except OSError as e:
        raise Refused(f"{what} cannot be read without following a link ({e.strerror})") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Refused(f"{what} is not a regular file")
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
    finally:
        os.close(fd)


def _read_bound(dir_fd: int, name: str, files: Dict[str, Dict[str, str]], what: str) -> bytes:
    """A fixed O-n file's bytes, which must be the bytes the walk hashed."""
    data = _read(dir_fd, name, what)
    if sha256(data) != files[name]["sha256"]:
        raise Refused(f"{what} is not the file the walk hashed")
    return data


def vm_facts(out_fd: int, n: str) -> Dict[str, Any]:
    """The parsed facts of OUT/<n>, opened from OUT's descriptor: its walk,
    and the four fixed files' bytes, each bound to the sha the walk hashed and
    parsed strictly. These are preflight()'s `vms[n]`; writer and reader
    both build them here."""
    vfd = _open_dir(out_fd, n, f"OUT/{n}")
    try:
        files = walk(vfd)
        role_bytes = _read_bound(vfd, "m1-role.json", files, f"OUT/{n}/m1-role.json")
        router = parse_router(_read_bound(vfd, "router.json", files, f"OUT/{n}/router.json"))
        feature = parse_feature(_read_bound(vfd, "feature.json", files, f"OUT/{n}/feature.json"))
        overlay = parse_overlay(_read_bound(vfd, "deploy-overlay.json", files, f"OUT/{n}/deploy-overlay.json"))
    finally:
        os.close(vfd)
    return {"files": files, "role": parse_role_manifest(role_bytes), "role_sha256": sha256(role_bytes),
            "router": router, "feature": feature, "overlay": overlay}


def read_receipt(out: str, man: bytes, vectors: bytes, hop_ancestry: bool) -> Dict[str, Any]:
    """The receipt under OUT, verified from OUT's own bytes and the caller's
    MAN, the vectors file at hop_pin, and the caller's ancestry measurement:
    every input is required. Returns HAR-PFV's projection and each VM's
    carried digest, or raises Refused. Nothing stored is trusted: every
    copied field is re-derived, and the pre-flight is recomputed and must
    equal the stored one."""
    if type(man) is not bytes or type(vectors) is not bytes or type(hop_ancestry) is not bool:
        raise Refused("read_receipt needs MAN's bytes, the vectors file's bytes and the caller's ancestry result")
    try:
        dfd = os.open(out, _OPEN | os.O_DIRECTORY)
    except OSError as e:
        raise Refused(f"OUT {out} cannot be opened without following a link ({e.strerror})") from None
    try:
        entries = set(os.listdir(dfd))
        if entries != OUT_ENTRIES:
            raise Refused(f"OUT's top level is {sorted(entries)}, not {sorted(OUT_ENTRIES)}")
        doc = parse_receipt(_read(dfd, RECEIPT_NAME, "the receipt"))
        artifact = _read(dfd, ARTIFACT_NAME, "the fleet artifact")
        net_bytes = _read(dfd, NET_VALUES_NAME, "NET's values file")
        if sha256(man) != doc["t0_manifest_sha256"]:
            raise Refused("MAN's sha256 is not the receipt's t0_manifest_sha256")
        art = doc["fleet_artifact"]
        if sha256(artifact) != art["sha256"]:
            raise Refused("the fleet artifact is not the one the receipt names")
        if parse_artifact(artifact) != art["min_sender_age_s"]:
            raise Refused("the fleet artifact's V is not the receipt's")
        if sha256(net_bytes) != doc["net_values_sha256"]:
            raise Refused("NET's values file is not the one the receipt names")
        facts: Dict[str, Dict[str, Any]] = {}
        for n in VMS:
            e, f = doc["vms"][n], vm_facts(dfd, n)
            if not same(f["files"], e["files"]):
                raise Refused(f"vms.{n}.files is not the walk of OUT/{n} (keys, modes or shas differ)")
            if on_manifest_sha256(f["files"]) != e["on_manifest_sha256"]:
                raise Refused(f"vms.{n}.on_manifest_sha256 is not the sha of its files")
            if f["role_sha256"] != e["role_sha256"]:
                raise Refused(f"vms.{n}.role_sha256 is not the sha of OUT/{n}/m1-role.json")
            if e["carried_digest"] != f["role"]["fleet_policy_digest"]:
                raise Refused(f"vms.{n}.carried_digest is not the manifest's fleet_policy_digest")
            if not same(e["router_min_sender_age_s"], f["router"][0]):
                raise Refused(f"vms.{n}.router_min_sender_age_s is not router.json's value")
            facts[n] = f
    finally:
        os.close(dfd)
    net = net_values(net_bytes)
    got = preflight(doc, man=man, vectors=vectors, hop_ancestry=hop_ancestry, artifact=artifact, net=net,
                    vms=facts)
    if not same(doc["preflight"], got) or not all(got.values()):
        failed = sorted(k for k, ok in got.items() if not ok)
        raise Refused("the recomputed pre-flight is not the stored all-true one: " + ", ".join(failed or ["keys differ"]))
    return {
        "projection": {"result": "PASS", "artifact_sha256": art["sha256"],
                       "render_sha256": {ROLE_OF[n]: doc["vms"][n]["files"]["router.json"]["sha256"] for n in VMS},
                       "manifest_sha256": {ROLE_OF[n]: doc["vms"][n]["role_sha256"] for n in VMS}},
        "carried_digest": {ROLE_OF[n]: facts[n]["role"]["fleet_policy_digest"] for n in VMS},
    }


def write_receipt(out: str, doc: Dict[str, Any]) -> str:
    """The receipt, as the run's last write. Its bytes must parse as a
    receipt; they go to the fixed temp name (which must not exist), are
    synced, and are linked to the receipt name, which link() refuses if it
    exists; then the temp is unlinked and OUT synced. Returns the sha256."""
    data = receipt_bytes(doc)
    parse_receipt(data)
    dfd = os.open(out, _OPEN | os.O_DIRECTORY)
    try:
        try:
            fd = os.open(RECEIPT_TEMP, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444, dir_fd=dfd)
        except FileExistsError:
            raise Refused(f"{RECEIPT_TEMP} is left from an earlier run: OUT must be fresh") from None
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(RECEIPT_TEMP, RECEIPT_NAME, src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=False)
        except FileExistsError:
            raise Refused(f"{RECEIPT_NAME} already exists: OUT must be fresh") from None
        os.unlink(RECEIPT_TEMP, dir_fd=dfd)
        os.fsync(dfd)
    finally:
        os.close(dfd)
    return sha256(data)
