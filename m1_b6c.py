"""m1_b6c.py: B6c's receipt for the M1 VMs: its byte forms, the O-n file map,
and its atomic write. Standard library only.

B6c renders each VM's overlay O-n in a clone of the base image and writes one
receipt, `OUT/b6c-receipt.json`, that every later step binds to: HAR-PFV
verifies it, both start gos quote that verification, and ADM compares the
installed O-n with it. This module holds the parts every producer and reader
of that receipt must agree on byte for byte (the B6c receipt schema
`amap-m1-b6c-receipt/1`):

  canonical(obj)          the one canonical JSON form: sorted keys, compact,
                          ASCII, no NaN
  receipt_bytes(doc)      the receipt file: canonical(doc) and one LF
  artifact_bytes(v)       the fleet artifact, in the router's own canonical
                          rule; for V = 0, exactly {"min_sender_age_s":0,"v":1}
  strict_loads(data)      a parse that refuses a repeated key, NaN and
                          Infinity, and any non-ASCII byte
  walk(root)              the {key: {"mode", "sha256"}} map of one VM's O-n,
                          read without following a link, closed: every entry a
                          regular file or a directory with a file under it
  on_manifest_sha256(files)   the O-n manifest's sha256: canonical(files), no LF
  write_receipt(out, doc)     the last write of a render: a fixed temp name,
                          fsync, link() that refuses an existing receipt,
                          unlink the temp, fsync OUT

Nothing here renders, installs or runs anything; it refuses by raising
Refused, with the rule it broke."""

import hashlib
import json
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
#: OUT's top level after a run, exactly; the temp name exists only during the write.
OUT_ENTRIES = frozenset({ARTIFACT_NAME, NET_VALUES_NAME, *VMS, RECEIPT_NAME})
#: Each VM's four fixed O-n names, never executable; everything else is under payload/.
FIXED_FILES = ("feature.json", "router.json", "m1-role.json", "deploy-overlay.json")
PAYLOAD_DIR = "payload"
MODE_PLAIN, MODE_EXEC = "0444", "0555"
MIN_SENDER_AGE_MAX_S = 31536000
_HEX64 = re.compile(r"[0-9a-f]{64}")
_KEY_PART = re.compile(r"[\x21-\x7e]+")


class Refused(Exception):
    """One broken rule, named."""


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


def digest(sha: str) -> str:
    """A digest is the string "sha256:" + 64 lowercase hex."""
    if not isinstance(sha, str) or not _HEX64.fullmatch(sha):
        raise Refused(f"{sha!r} is not 64 lowercase hex")
    return "sha256:" + sha


def artifact_bytes(v: Any) -> bytes:
    """The fleet artifact for V = `v`, in the router's canonical rule
    (sort_keys, (",", ":"), ensure_ascii=False, allow_nan=False, UTF-8):
    for V = 0 the bytes are exactly {"min_sender_age_s":0,"v":1}."""
    if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= MIN_SENDER_AGE_MAX_S:
        raise Refused(f"V {v!r} is not a whole number of seconds from 0 to {MIN_SENDER_AGE_MAX_S}")
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


def strict_loads(data: bytes, what: str) -> Any:
    """`data` parsed as JSON, refusing a non-ASCII byte, a repeated key, and
    NaN or Infinity."""
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise Refused(f"{what} is not ASCII") from None
    try:
        return json.loads(text, object_pairs_hook=_no_repeat, parse_constant=_no_constant)
    except ValueError as e:
        raise Refused(f"{what} is not JSON: {e}") from None


def check_key(key: Any) -> str:
    """A `files` key: a relative POSIX path, `/`-separated, with no empty,
    `.` or `..` component and no leading `/`, printable ASCII without
    spaces, equal to its own normalisation."""
    if not isinstance(key, str) or not key or key.startswith("/") or posixpath.normpath(key) != key:
        raise Refused(f"the files key {key!r} is not a normalised relative path")
    for part in key.split("/"):
        if part in ("", ".", "..") or not _KEY_PART.fullmatch(part):
            raise Refused(f"the files key {key!r} has the component {part!r}")
    return key


def mode_class(mode: int, key: str) -> str:
    """The sealed mode a file gets, from its x bits: all three set is 0555,
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


def walk(root: str) -> Dict[str, Dict[str, str]]:
    """One VM's O-n under `root`, as {key: {"mode", "sha256"}}: each entry
    reached descriptor-relative without following a link, each a regular
    file or a directory, every directory an ancestor of some file, the four
    fixed names present and at least one file under payload/. The mode is
    the class of the file's own x bits (mode_class)."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    files: Dict[str, Dict[str, str]] = {}

    def visit(dir_fd: int, prefix: str) -> int:
        found = 0
        for name in sorted(os.listdir(dir_fd)):
            key = check_key(posixpath.join(prefix, name) if prefix else name)
            st = os.lstat(name, dir_fd=dir_fd)
            if stat.S_ISDIR(st.st_mode):
                sub = os.open(name, flags | os.O_DIRECTORY, dir_fd=dir_fd)
                try:
                    n = visit(sub, key)
                finally:
                    os.close(sub)
                if n == 0:
                    raise Refused(f"{key}/ holds no file")
                found += n
            elif stat.S_ISREG(st.st_mode):
                fd = os.open(name, flags, dir_fd=dir_fd)
                try:
                    st2 = os.fstat(fd)
                    if (st2.st_dev, st2.st_ino) != (st.st_dev, st.st_ino) or st2.st_nlink != 1:
                        raise Refused(f"{key} changed while it was read, or has more than one link")
                    files[key] = {"mode": mode_class(st2.st_mode, key), "sha256": _hash_fd(fd)}
                finally:
                    os.close(fd)
                found += 1
            else:
                raise Refused(f"{key} is neither a regular file nor a directory")
        return found

    try:
        top = os.open(root, flags | os.O_DIRECTORY)
    except OSError as e:
        raise Refused(f"{root} cannot be opened as a directory without following a link ({e.strerror})") from None
    try:
        visit(top, "")
    except OSError as e:
        raise Refused(f"{root} cannot be read: {e.strerror}") from None
    finally:
        os.close(top)
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


def net_values(data: bytes) -> Any:
    """NET's values file. Its closed shape is not fixed yet, so every input
    refuses: no receipt can carry values from a file whose keys nobody has
    reviewed."""
    raise Refused("NET's net-values shape is not fixed yet (B6c schema d5.3 §2b.3): no receipt can be written")


def write_receipt(out: str, doc: Dict[str, Any]) -> str:
    """The receipt, as the run's last write: its bytes go to the fixed temp
    name (which must not exist), are synced, and are linked to the receipt
    name, which link() refuses if it exists; then the temp is unlinked and
    OUT synced. Returns the receipt's sha256."""
    data = receipt_bytes(doc)
    dfd = os.open(out, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
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


# --- The receipt's closed shape, and its pre-flight ------------------------------

#: The role manifest's closed top-level keys (ROLE-MANIFEST-INTERFACE r3).
ROLE_KEYS = frozenset({"schema", "role", "vm", "hostname", "fd", "own_domain", "ids", "units",
                       "fleet_policy_digest", "start"})
ROLE_SCHEMA = "amap-m1-role/1"
START_KEYS = frozenset({"uid_1", "group_add", "config", "image", "name"})
ROLE_OF = {"vm1": "H1", "vm2": "H2"}
RECEIPT_KEYS = frozenset({"schema", "deploy_commit", "deploy_tree", "hop_pin", "t0_manifest_sha256",
                          "net_values_sha256", "sandy_schema_version", "v", "fleet_artifact", "vms",
                          "preflight"})
ARTIFACT_KEYS = frozenset({"path", "sha256", "digest", "schema_v", "min_sender_age_s"})
VM_KEYS = frozenset({"role", "vm", "hostname", "own_domain", "fd", "files", "on_manifest_sha256",
                     "role_sha256", "carried_digest", "router_min_sender_age_s", "start", "state_dir",
                     "run_dir", "router_container"})
#: The deploy checkout MAN records, by its absolute path.
DEPLOY_CHECKOUT = "/opt/amap/src/amap-deploy-sandy"
#: The commit whose ancestry proves the hop pin carries the router's sender-age setting.
ENROL_COMMIT = "6d104e705974b0f9c90507629f5371755fbe0ca4"
_HEX40 = re.compile(r"[0-9a-f]{40}")
_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,32}")
_LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
_HOSTNAME = re.compile(_LABEL)
_DNS = re.compile(rf"{_LABEL}(\.{_LABEL})*")


def _closed(obj: Any, keys: frozenset, what: str) -> Dict[str, Any]:
    if not isinstance(obj, dict) or set(obj) != keys:
        have = sorted(obj) if isinstance(obj, dict) else type(obj).__name__
        raise Refused(f"{what} must have exactly {sorted(keys)}; it has {have}")
    return obj


def _int(v: Any, what: str, lo: int = 0, hi: int = MIN_SENDER_AGE_MAX_S) -> int:
    if type(v) is not int or not lo <= v <= hi:
        raise Refused(f"{what} {v!r} is not an int from {lo} to {hi}")
    return v


def _hex(v: Any, pattern: "re.Pattern[str]", what: str) -> str:
    if not isinstance(v, str) or not pattern.fullmatch(v):
        raise Refused(f"{what} {v!r} is malformed")
    return v


def parse_role_manifest(data: bytes) -> Dict[str, Any]:
    """A role manifest under ROLE-MANIFEST-INTERFACE r3: strict JSON, the
    closed key set, the schema, and the field shapes the receipt copies."""
    doc = _closed(strict_loads(data, "the role manifest"), ROLE_KEYS, "the role manifest")
    if doc["schema"] != ROLE_SCHEMA:
        raise Refused(f"the role manifest's schema is not {ROLE_SCHEMA}")
    if doc["role"] not in ROLE_OF.values():
        raise Refused(f"the role manifest's role {doc['role']!r} is not H1 or H2")
    _hex(doc["hostname"], _HOSTNAME, "the role manifest's hostname")
    for k in ("fd", "own_domain"):
        if not isinstance(doc[k], str) or len(doc[k]) > 253:
            raise Refused(f"the role manifest's {k} is not a DNS name")
        _hex(doc[k], _DNS, f"the role manifest's {k}")
    fpd = doc["fleet_policy_digest"]
    if not isinstance(fpd, str) or not fpd.startswith("sha256:"):
        raise Refused("the role manifest's fleet_policy_digest is not sha256:<64 hex>")
    digest(fpd[len("sha256:"):])
    _closed(doc["start"], START_KEYS, "the role manifest's start")
    return doc


def parse_router(data: bytes) -> Any:
    """router.json, strictly; returns its top-level min_sender_age_s, which
    must be present and exactly an int in range."""
    doc = strict_loads(data, "router.json")
    if not isinstance(doc, dict) or "min_sender_age_s" not in doc:
        raise Refused("router.json carries no min_sender_age_s")
    return _int(doc["min_sender_age_s"], "router.json's min_sender_age_s")


def parse_feature(data: bytes) -> Tuple[int, str]:
    """feature.json, strictly; returns the policy's min_sender_age_s and
    fleet_domain, read from its `feature` section."""
    doc = strict_loads(data, "feature.json")
    feature = doc.get("feature") if isinstance(doc, dict) else None
    if not isinstance(feature, dict):
        raise Refused("feature.json has no feature section")
    if "min_sender_age_s" not in feature or "fleet_domain" not in feature:
        raise Refused("feature.json's feature section lacks min_sender_age_s or fleet_domain")
    return _int(feature["min_sender_age_s"], "feature.json's min_sender_age_s"), feature["fleet_domain"]


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
    {description, cases}, each case closed, and EXACTLY ONE case for V."""
    doc = _closed(strict_loads(vectors, "the vectors file"), frozenset({"description", "cases"}),
                  "the vectors file")
    if not isinstance(doc["cases"], list):
        raise Refused("the vectors file's cases is not a list")
    hits = [c for c in doc["cases"]
            if _closed(c, frozenset({"min_sender_age_s", "canonical", "digest"}), "a vectors case")
            and type(c["min_sender_age_s"]) is int and c["min_sender_age_s"] == v]
    if len(hits) != 1:
        raise Refused(f"the vectors file has {len(hits)} cases for V {v}, not exactly one")
    return hits[0]["digest"]


def man_values(man: bytes) -> Tuple[str, str, str]:
    """MAN's deploy checkout head and tree, and its router1 build commit,
    read by key lookup."""
    doc = strict_loads(man, "MAN")
    try:
        co = doc["checkouts"][DEPLOY_CHECKOUT]
        head, tree, hop = co["head"], co["tree"], doc["builds"]["router1"]["commit"]
    except (KeyError, TypeError):
        raise Refused(f"MAN lacks checkouts[{DEPLOY_CHECKOUT!r}].head/.tree or builds.router1.commit") from None
    return (_hex(head, _HEX40, "MAN's deploy head"), _hex(tree, _HEX40, "MAN's deploy tree"),
            _hex(hop, _HEX40, "MAN's router1 commit"))


def preflight(receipt: Dict[str, Any], *, man: bytes, vectors: bytes, hop_ancestry: bool,
              artifact: bytes, net: Any, vms: Dict[str, Dict[str, Any]]) -> Dict[str, bool]:
    """Every pre-flight equality, computed from inputs, never copied. `vms`
    maps vm1/vm2 to the parsed facts of that VM's OUT tree: `files` (the
    walk), `role` (parse_role_manifest), `router_age` (parse_router),
    `feature` ((age, fleet_domain), parse_feature). `net` is NET's parsed
    values, or the refusal stands before this is reached. Writer and reader
    both call this one function."""
    v = receipt["v"]
    head, tree, hop = man_values(man)
    out = {
        "artifact_known_answer": digest(sha256(artifact)) == known_answer(vectors, v),
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
    art_digest = digest(sha256(artifact))
    for n in VMS:
        facts, entry = vms[n], receipt["vms"][n]
        role = facts["role"]
        out[f"net_values_match_{n}"] = net[n] == {k: role[k] for k in ("vm", "hostname", "own_domain")}
        out[f"manifest_is_receipt_{n}"] = (role["role"] == ROLE_OF[n] and
                                            all(role[k] == entry[k] for k in ("role", "vm", "hostname", "fd",
                                                                               "own_domain")))
        out[f"role_digest_{n}"] = role["fleet_policy_digest"] == art_digest
        out[f"feature_value_{n}"] = facts["feature"][0] == v
        out[f"feature_fd_{n}"] = facts["feature"][1] == entry["fd"]
        out[f"router_value_{n}"] = facts["router_age"] == v
        out[f"start_is_role_{n}"] = entry["start"] == role["start"]
        out[f"container_is_start_name_{n}"] = entry["router_container"] == role["start"]["name"]
        out[f"modes_match_{n}"] = entry["files"] == facts["files"]
    return out


def _read(dir_fd: int, name: str, what: str) -> bytes:
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(name, flags, dir_fd=dir_fd)
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


def parse_receipt(data: bytes) -> Dict[str, Any]:
    """The receipt's own bytes: strict, canonical (the bytes equal their
    re-serialisation plus one LF), and closed at every level."""
    doc = strict_loads(data, "the receipt")
    _closed(doc, RECEIPT_KEYS, "the receipt")
    if data != receipt_bytes(doc):
        raise Refused("the receipt is not in its canonical form")
    if doc["schema"] != SCHEMA:
        raise Refused(f"the receipt's schema is not {SCHEMA}")
    for k in ("deploy_commit", "deploy_tree", "hop_pin"):
        _hex(doc[k], _HEX40, f"the receipt's {k}")
    for k in ("t0_manifest_sha256", "net_values_sha256"):
        _hex(doc[k], _HEX64, f"the receipt's {k}")
    _hex(doc["sandy_schema_version"], _TOKEN, "the receipt's sandy_schema_version")
    _int(doc["v"], "the receipt's v")
    art = _closed(doc["fleet_artifact"], ARTIFACT_KEYS, "the receipt's fleet_artifact")
    if art["path"] != ARTIFACT_NAME or art["schema_v"] != 1 or type(art["schema_v"]) is not int:
        raise Refused("the receipt's fleet_artifact path or schema_v is wrong")
    if art["digest"] != digest(art["sha256"]):
        raise Refused("the receipt's fleet_artifact digest is not sha256: + its sha256")
    _closed(doc["vms"], frozenset(VMS), "the receipt's vms")
    for n in VMS:
        entry = _closed(doc["vms"][n], VM_KEYS, f"the receipt's vms.{n}")
        if entry["role"] != ROLE_OF[n]:
            raise Refused(f"the receipt's vms.{n}.role is not {ROLE_OF[n]}")
        if not isinstance(entry["files"], dict):
            raise Refused(f"the receipt's vms.{n}.files is not an object")
        for key, val in entry["files"].items():
            check_key(key)
            _closed(val, frozenset({"mode", "sha256"}), f"the receipt's vms.{n}.files[{key!r}]")
            if val["mode"] not in (MODE_PLAIN, MODE_EXEC):
                raise Refused(f"vms.{n}.files[{key!r}].mode is not 0444 or 0555")
            _hex(val["sha256"], _HEX64, f"vms.{n}.files[{key!r}].sha256")
    if not isinstance(doc["preflight"], dict) or not all(v is True for v in doc["preflight"].values()):
        raise Refused("the receipt's preflight is not an all-true object")
    return doc


def read_receipt(out: str, man: bytes, vectors: bytes, hop_ancestry: bool) -> Dict[str, Any]:
    """The receipt under OUT, verified from OUT's own bytes and the caller's
    MAN, the vectors file at hop_pin, and the caller's ancestry measurement:
    every input is required. Returns HAR-PFV's projection, and each VM's
    carried digest, or raises Refused. A stored boolean is never trusted:
    the pre-flight is recomputed and must equal the stored all-true one."""
    if not isinstance(man, bytes) or not isinstance(vectors, bytes) or not isinstance(hop_ancestry, bool):
        raise Refused("read_receipt needs MAN's bytes, the vectors file's bytes and the caller's ancestry result")
    try:
        dfd = os.open(out, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    except OSError as e:
        raise Refused(f"OUT {out} cannot be opened without following a link ({e.strerror})") from None
    try:
        entries = set(os.listdir(dfd))
        if entries != OUT_ENTRIES:
            raise Refused(f"OUT's top level is {sorted(entries)}, not {sorted(OUT_ENTRIES)}")
        doc = parse_receipt(_read(dfd, RECEIPT_NAME, "the receipt"))
        artifact = _read(dfd, ARTIFACT_NAME, "the fleet artifact")
        net_bytes = _read(dfd, NET_VALUES_NAME, "NET's values file")
    finally:
        os.close(dfd)
    if man is None or sha256(man) != doc["t0_manifest_sha256"]:
        raise Refused("MAN's sha256 is not the receipt's t0_manifest_sha256")
    v = parse_artifact(artifact)
    art = doc["fleet_artifact"]
    if sha256(artifact) != art["sha256"] or v != art["min_sender_age_s"]:
        raise Refused("the fleet artifact is not the one the receipt names")
    if sha256(net_bytes) != doc["net_values_sha256"]:
        raise Refused("NET's values file is not the one the receipt names")
    facts: Dict[str, Dict[str, Any]] = {}
    for n in VMS:
        root = os.path.join(out, n)
        files = walk(root)
        entry = doc["vms"][n]
        if files != entry["files"]:
            raise Refused(f"vms.{n}.files is not the walk of OUT/{n} (keys, modes or shas differ)")
        if on_manifest_sha256(files) != entry["on_manifest_sha256"]:
            raise Refused(f"vms.{n}.on_manifest_sha256 is not the sha of its files")
        vfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        try:
            role_bytes = _read(vfd, "m1-role.json", f"OUT/{n}/m1-role.json")
            role = parse_role_manifest(role_bytes)
            router_age = parse_router(_read(vfd, "router.json", f"OUT/{n}/router.json"))
            feature = parse_feature(_read(vfd, "feature.json", f"OUT/{n}/feature.json"))
        finally:
            os.close(vfd)
        if sha256(role_bytes) != entry["role_sha256"] or entry["role_sha256"] != files["m1-role.json"]["sha256"]:
            raise Refused(f"vms.{n}.role_sha256 is not the sha of OUT/{n}/m1-role.json")
        if entry["carried_digest"] != role["fleet_policy_digest"]:
            raise Refused(f"vms.{n}.carried_digest is not the manifest's fleet_policy_digest")
        if entry["router_min_sender_age_s"] != router_age or type(entry["router_min_sender_age_s"]) is not int:
            raise Refused(f"vms.{n}.router_min_sender_age_s is not router.json's value")
        facts[n] = {"files": files, "role": role, "router_age": router_age, "feature": feature}
    net = net_values(net_bytes)
    got = preflight(doc, man=man, vectors=vectors, hop_ancestry=hop_ancestry, artifact=artifact, net=net,
                    vms=facts)
    if doc["preflight"] != got or not all(got.values()):
        failed = sorted(k for k, ok in got.items() if not ok)
        raise Refused("the recomputed pre-flight is not the stored all-true one: " + ", ".join(failed or ["keys differ"]))
    return {
        "projection": {"result": "PASS", "artifact_sha256": art["sha256"],
                       "render_sha256": {ROLE_OF[n]: doc["vms"][n]["files"]["router.json"]["sha256"] for n in VMS},
                       "manifest_sha256": {ROLE_OF[n]: doc["vms"][n]["role_sha256"] for n in VMS}},
        "carried_digest": {ROLE_OF[n]: facts[n]["role"]["fleet_policy_digest"] for n in VMS},
    }
