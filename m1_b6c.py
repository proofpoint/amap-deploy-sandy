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
