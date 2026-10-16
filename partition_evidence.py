"""The partition evidence: the one document a partition-probe run writes per
host, the token that names it, and the checks that decide whether it is
current. NOTHING HERE RUNS A PROBE OR WRITES A FILE: the probes and the
writer that places the document are elsewhere; this module defines the
document's bytes and judges a document it is handed.

The document is canonical JSON (sorted keys, separators `(",", ":")`, UTF-8,
no trailing newline) with exactly these members:
- `schema`, `host`, `run_id`, `at` (`YYYY-MM-DDTHH:MM:SSZ`);
- `script_sha256`: each probe script's and the verb's own file hash, over
  the RAW bytes of each file;
- `bindings`: each input the run was bound to, by the sha256 of its
  canonical JSON (structures) or of its raw bytes (files);
- `probes`: one entry per probe, P01 to P04 (the design's M1-P01 to
  M1-P04), each with:
  - `vantage`: the runtimes it was measured from, each {container, image,
    uid, gids};
  - `operation`: what it did;
  - `target_role`: the roles it targeted (`key:signing`, `key:dir`,
    `mount:<name>`, `peer:<slug>`, `marker:<side>/<name>`,
    `runtime:<principal>`), never a path;
  - `outcome`: the decisive observation's errno name, `ok` when the
    operation succeeded, or `unresolved` when it could not be made;
  - `witness`: {operation, outcome}, the could-fail witness;
  - `verdict`: PASS, FAIL or UNKNOWN. A fail-stop probe passes only with
    outcome ENOENT, its witness `ok`, and its roles covering its targets;
- `fail_stop`: the verdicts of the two fail-stop probes, P03 and P04;
- `delegation_partition_verified`: the token, or null.

The token is `<run_id>:<sha256 of the canonical bytes with the token
member null>`. It is present only when BOTH fail-stop probes passed in this
one run; every other outcome, an unrun or erroring probe included, leaves
it null. The local router's config is bound with
`delegation.partition_verified` removed, so placing the token there cannot
change the binding it was derived from.

A document counts while it is at most a week plus a 24-hour grace old AND
every binding equals the current one. The self-hash proves the document is
consistent, not where it came from: provenance is the root-owned, protected
placement, which `verify_document` checks before it reads a byte.
"""

import datetime
import hashlib
import json
import os
import re
import stat
from typing import Any, Callable, Dict, List, Optional, Tuple

import router_health as rh
import secret_setup as ss

SCHEMA = "amap-deploy.partition-evidence/1"
MEMBERS = frozenset({"schema", "host", "run_id", "at", "script_sha256", "bindings", "probes", "fail_stop",
                     "delegation_partition_verified"})
PROBE_MEMBERS = frozenset({"id", "vantage", "operation", "target_role", "outcome", "witness", "verdict"})
PROBE_IDS = ("P01", "P02", "P03", "P04")
#: The fail-stop set: a key read and a peer write from inside the email router.
FAIL_STOP = ("P03", "P04")
VERDICTS = ("PASS", "FAIL", "UNKNOWN")
TOKEN_MEMBER = "delegation_partition_verified"
#: How long a passing document counts: weekly, with a 24-hour grace.
FRESH_FOR_S = 7 * 86400 + 24 * 3600
#: How far `at` may lie ahead of this host's clock.
CLOCK_TOLERANCE_S = 120
MAX_BYTES = 1 << 20
_HEX64 = re.compile(r"[0-9a-f]{64}")
_RUN_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")
_AT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_ROLE = re.compile(r"(key:(signing|dir)|mount:[A-Za-z0-9._/-]{1,128}|peer:[A-Za-z0-9._-]{1,64}"
                   r"|marker:(up|down)/[A-Za-z0-9._-]{1,64}|runtime:[A-Za-z0-9._-]{1,64})")
_OUTCOME = re.compile(r"E[A-Z0-9]{1,15}|ok|unresolved")
VANTAGE_MEMBERS = frozenset({"container", "image", "uid", "gids"})
WITNESS_MEMBERS = frozenset({"operation", "outcome"})
#: The roles each fail-stop probe must cover whatever else it targets.
REQUIRED_ROLES = {"P03": frozenset({"key:signing", "key:dir"})}


class EvidenceError(ValueError):
    """The document is not a well-formed partition evidence document."""


def canonical(doc: Any) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def sha_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha_json(obj: Any) -> str:
    return sha_bytes(canonical(obj))


def token_of(doc: Dict[str, Any]) -> str:
    return f"{doc['run_id']}:{sha_json(dict(doc, **{TOKEN_MEMBER: None}))}"


def config_binding(cfg: Dict[str, Any]) -> str:
    """The local router's config as the evidence binds it: canonical JSON with
    `delegation.partition_verified` removed and nothing else changed."""
    bound = json.loads(canonical(cfg))
    delegation = bound.get("delegation")
    if isinstance(delegation, dict):
        delegation.pop("partition_verified", None)
    return sha_json(bound)


def build(*, host: str, run_id: str, at: str, script_sha256: Dict[str, str], bindings: Dict[str, str],
          probes: List[Dict[str, Any]]) -> bytes:
    """The canonical bytes of a document for one run: the fail-stop summary
    and the token are derived here from the probes' verdicts, never passed
    in. The result is checked by `parse` before it is returned."""
    verdicts = {p["id"]: p["verdict"] for p in probes}
    doc = {"schema": SCHEMA, "host": host, "run_id": run_id, "at": at, "script_sha256": dict(script_sha256),
           "bindings": dict(bindings), "probes": [dict(p) for p in probes],
           "fail_stop": {i: verdicts.get(i) for i in FAIL_STOP}, TOKEN_MEMBER: None}
    if all(verdicts.get(i) == "PASS" for i in FAIL_STOP):
        doc[TOKEN_MEMBER] = token_of(doc)
    raw = canonical(doc)
    parse(raw, host=host)
    return raw


def role_ok(role: str) -> bool:
    """Whether `role` is in the evidence vocabulary a probe's target_role holds."""
    return isinstance(role, str) and _ROLE.fullmatch(role) is not None


def _no_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise EvidenceError(f"the key {k!r} appears twice")
        out[k] = v
    return out


def _no_constant(name: str) -> Any:
    raise EvidenceError(f"{name} is not JSON")


def _hexmap(v: Any, what: str) -> Dict[str, str]:
    if not isinstance(v, dict) or not v:
        raise EvidenceError(f"{what} must be a non-empty object")
    for k, h in v.items():
        if not _NAME.fullmatch(k) or not isinstance(h, str) or not _HEX64.fullmatch(h):
            raise EvidenceError(f"{what}.{k} must be 64 lower-case hex")
    return v


def parse(raw: bytes, *, host: str) -> Dict[str, Any]:
    """`raw` as a partition evidence document for `host`, or EvidenceError.
    The bytes must be exactly the document's canonical form, so the bytes the
    caller hashed are the bytes judged here."""
    if len(raw) > MAX_BYTES:
        raise EvidenceError(f"larger than {MAX_BYTES} bytes")
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise EvidenceError(f"not JSON: {e}") from None
    if not isinstance(doc, dict) or set(doc) != MEMBERS:
        raise EvidenceError("not exactly the document's members")
    if canonical(doc) != raw:
        raise EvidenceError("not in canonical form")
    if doc["schema"] != SCHEMA:
        raise EvidenceError(f"schema is not {SCHEMA}")
    if doc["host"] != host:
        raise EvidenceError(f"written for host {doc['host']!r}, not {host!r}")
    if not isinstance(doc["run_id"], str) or not _RUN_ID.fullmatch(doc["run_id"]):
        raise EvidenceError("run_id is malformed")
    if not isinstance(doc["at"], str) or not _AT.fullmatch(doc["at"]):
        raise EvidenceError("at is not YYYY-MM-DDTHH:MM:SSZ")
    try:
        at_seconds(doc["at"])
    except ValueError:
        raise EvidenceError(f"at {doc['at']!r} is not a real UTC time") from None
    _hexmap(doc["script_sha256"], "script_sha256")
    _hexmap(doc["bindings"], "bindings")
    probes = doc["probes"]
    if not isinstance(probes, list) or [p.get("id") if isinstance(p, dict) else None for p in probes] \
            != list(PROBE_IDS):
        raise EvidenceError(f"probes must be exactly {', '.join(PROBE_IDS)}, in order")
    for p in probes:
        _probe_problem(p)
    verdicts = {p["id"]: p["verdict"] for p in probes}
    if doc["fail_stop"] != {i: verdicts.get(i) for i in FAIL_STOP}:
        raise EvidenceError("fail_stop does not repeat the fail-stop probes' verdicts")
    token = doc[TOKEN_MEMBER]
    if all(verdicts.get(i) == "PASS" for i in FAIL_STOP):
        if token != token_of(doc):
            raise EvidenceError("both fail-stop probes passed, but the token is not this document's")
    elif token is not None:
        raise EvidenceError("a token is present although a fail-stop probe did not pass")
    return doc


def _probe_problem(p: Dict[str, Any]) -> None:
    """Refuse a probe entry whose members, types or payload shapes are not the
    document's, or a fail-stop PASS that the entry does not support."""
    pid = p["id"]
    if set(p) != PROBE_MEMBERS:
        raise EvidenceError(f"{pid} is not exactly the probe's members")
    if p["verdict"] not in VERDICTS:
        raise EvidenceError(f"{pid}'s verdict is not one of {', '.join(VERDICTS)}")
    v = p["vantage"]
    if not isinstance(v, list) or not v or not all(
            isinstance(x, dict) and set(x) == VANTAGE_MEMBERS and isinstance(x["container"], str) and x["container"]
            and isinstance(x["image"], str) and x["image"] and _int(x["uid"])
            and isinstance(x["gids"], list) and all(_int(g) for g in x["gids"]) for x in v):
        raise EvidenceError(f"{pid}'s vantage is not a list of {{container, image, uid, gids}}")
    if not isinstance(p["operation"], str) or not p["operation"]:
        raise EvidenceError(f"{pid}'s operation must be a non-empty string")
    roles = p["target_role"]
    if not isinstance(roles, list) or not roles or not all(role_ok(r) for r in roles):
        raise EvidenceError(f"{pid}'s target_role must be a list of typed roles")
    if len(set(roles)) != len(roles):
        raise EvidenceError(f"{pid}'s target_role must not repeat a role")
    if not isinstance(p["outcome"], str) or not _OUTCOME.fullmatch(p["outcome"]):
        raise EvidenceError(f"{pid}'s outcome must be an errno name, ok or unresolved")
    w = p["witness"]
    if not isinstance(w, dict) or set(w) != WITNESS_MEMBERS or not isinstance(w["operation"], str) \
            or not w["operation"] or not isinstance(w["outcome"], str) or not _OUTCOME.fullmatch(w["outcome"]):
        raise EvidenceError(f"{pid}'s witness must be {{operation, outcome}}")
    if pid in FAIL_STOP:
        if not REQUIRED_ROLES.get(pid, frozenset()) <= set(roles):
            raise EvidenceError(f"{pid}'s roles do not cover {', '.join(sorted(REQUIRED_ROLES[pid]))}")
        if pid == "P04" and not all(r.startswith("peer:") for r in roles):
            raise EvidenceError("P04's roles must be the agents' lanes")
        if p["verdict"] == "PASS" and (p["outcome"] != "ENOENT" or w["outcome"] != "ok"):
            raise EvidenceError(f"{pid} passes only with outcome ENOENT and its witness ok")


def _int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def at_seconds(at: str) -> float:
    return datetime.datetime.strptime(at, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc).timestamp()


def staleness(doc: Dict[str, Any], *, now: float, bindings: Dict[str, str],
              roles: Optional[Dict[str, List[str]]] = None) -> List[str]:
    """Why `doc` does not count now, against the current `bindings` and, per
    fail-stop probe, the roles it must have targeted now (`roles`: P03 → the
    key's roles and every mount reaching it, P04 → every enrolled agent's
    lane); empty when it counts. A document whose fail-stop probes did not
    both pass never counts."""
    why = []
    if roles is not None:
        missing = [pid for pid in FAIL_STOP if pid not in roles]
        if missing:
            why.append(f"today's roles for {', '.join(missing)} were not given, so the document cannot be held to them")
    for p in doc["probes"]:
        want = (roles or {}).get(p["id"])
        if want is not None and set(p["target_role"]) != set(want):
            why.append(f"{p['id']} targeted {sorted(p['target_role'])}, not {sorted(want)}")
    if doc[TOKEN_MEMBER] is None:
        why.append("its fail-stop probes did not both pass")
    age = now - at_seconds(doc["at"])
    if age < -CLOCK_TOLERANCE_S:
        why.append(f"it is dated {-age:.0f}s in the future")
    elif age > FRESH_FOR_S:
        why.append(f"it is {age / 86400:.1f} days old, past a week plus the 24-hour grace")
    if set(doc["bindings"]) != set(bindings):
        why.append(f"it binds {sorted(doc['bindings'])}, not {sorted(bindings)}")
    else:
        why += [f"{k} has changed since the run" for k in sorted(bindings) if doc["bindings"].get(k) != bindings[k]]
    return why


def read_protected(path: str) -> bytes:
    """`path`'s bytes, never through a symbolic link, bounded."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"{path} is not a regular file")
        return _read_fd(fd)
    finally:
        os.close(fd)


def read_placed(path: str) -> bytes:
    """`read_protected`, and the opened file itself as the placement requires
    (root:root 0444, one link), so the bytes read are the file the placement
    checks judged."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_nlink) != (0, 0, 0o444, 1):
            raise OSError(f"{path} as opened is not a root:root 0444 file with one link")
        return _read_fd(fd)
    finally:
        os.close(fd)


def _read_fd(fd: int) -> bytes:
    """Up to MAX_BYTES + 1 bytes from `fd`: one more than the limit, so an
    oversized file is seen as one."""
    chunks, total = [], 0
    while total <= MAX_BYTES:
        chunk = os.read(fd, MAX_BYTES + 1 - total)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


#: The outcomes of `named_document`, besides a document: why no document is
#: selected for a token. Each is its own answer, never a reason to search.
NAMED_NO_RUN, NAMED_MISSING, NAMED_UNREADABLE, NAMED_MALFORMED, NAMED_MISMATCH, NAMED_UNISSUED = (
    "no_run", "missing", "unreadable", "malformed", "mismatch", "unissued")


def named_document(token: Any, *, evidence_dir: str, host: str,
                   read: Callable[[str], bytes] = read_placed) -> Tuple[Any, Any, str]:
    """The evidence a token names, and only that one: (doc, raw, "") or
    (None, outcome, why). The token's run id gives exactly
    `partition-<run id>.json` in the evidence directory, read as placed,
    parsed for this host, and the token it ISSUED must be the token: a
    document whose fail-stop probes did not pass issued none, whatever
    token_of would compute for it. Never the newest document, and never a
    glob."""
    rid = token.partition(":")[0] if isinstance(token, str) else ""
    if not _RUN_ID.fullmatch(rid):
        return None, NAMED_NO_RUN, "the token names no run"
    path = os.path.join(evidence_dir, f"partition-{rid}.json")
    try:
        raw = read(path)
    except FileNotFoundError:
        return None, NAMED_MISSING, f"{path}, the document the token names, is absent"
    except OSError as e:
        return None, NAMED_UNREADABLE, f"{path} cannot be read as placed: {e}"
    try:
        doc = parse(raw, host=host)
    except ValueError as e:
        return None, NAMED_MALFORMED, f"{path} is not this host's evidence document: {e}"
    if doc[TOKEN_MEMBER] is None:
        return None, NAMED_UNISSUED, f"{path} issued no token: a fail-stop probe did not pass"
    if doc[TOKEN_MEMBER] != token:
        return None, NAMED_MISMATCH, f"the token is not {path}'s own"
    return doc, raw, ""


#: What a running local router must be told when it signs without a current
#: passing document: the same action the weekly job takes on a failure.
UNSIGN_REMEDY = ("render the local router's config without delegation (install --apply) and restart it; "
                 "a token without a current passing document must never stay live")


def verify_document(path: str, *, host: str, now: float, bindings: Dict[str, str], live_token: Any,
                    roles: Dict[str, List[str]], lstat: Callable = os.lstat,
                    read: Callable[[str], bytes] = read_placed) -> List[rh.Check]:
    """The evidence document at `path`: placed as only root could place it,
    well-formed for `host`, current against `bindings`; and, on EVERY path,
    whether the running local router signs with the current passing
    document's token or not at all (`live_token`: None when it carries none,
    an Unresolved when it could not be asked). With no current passing
    document, the only acceptable token is none."""
    why = "the evidence is trusted only as root placed it"
    out = [ss._pinned_file(f"the partition evidence {path} is root:root 0444 with one link", path, why, lstat),
           ss._owned_chain(f"every directory above {path} is root-owned and not group- or world-writable",
                           path, (0,), why, lstat)]
    claim = f"the partition evidence {path} is well-formed, current and passing"
    want = rh.Fact("evidence", True, "a week plus a 24-hour grace, both fail-stop probes passing, every "
                                     "binding unchanged since the run")
    remedy = "run partition-probe --apply again against the current rendering"
    current: Optional[str] = None
    try:
        raw = read(path)
    except FileNotFoundError:
        out.append(rh.unknown(claim, want, f"{path} is absent", "run partition-probe --apply"))
    except OSError as e:
        out.append(rh.unknown(claim, want, f"cannot read {path}: {e}", remedy))
    else:
        try:
            doc = parse(raw, host=host)
        except EvidenceError as e:
            out.append(rh.check(claim, want, f"malformed: {e}", remedy, do_not="never edit the document"))
        else:
            stale = staleness(doc, now=now, bindings=bindings, roles=roles)
            out.append(rh.check(claim, want, "; ".join(stale) if stale else True, remedy,
                                do_not="never move the clock or a binding to make a document current"))
            current = None if stale else doc[TOKEN_MEMBER]
    claim = "the local router signs with the current passing document's token, or not at all"
    want = rh.Fact("token", current, "the token of the current passing document; none when there is none")
    if isinstance(live_token, rh.Unresolved):
        out.append(rh.unknown(claim, want, live_token.reason, "start the local router, or make the engine answer"))
    elif live_token is None:
        out.append(rh.check(claim, want, True, UNSIGN_REMEDY, ok=lambda e, a: True))
    else:
        out.append(rh.check(claim, want, live_token, UNSIGN_REMEDY,
                            do_not="never keep signing while the evidence is being regenerated"))
    return out
