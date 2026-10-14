"""The delivered-domain (D7) file a hub link's two routers read: rendered from
the network's generated D7 document, placed root-owned 0444 in a directory
that holds nothing else, and checked against that document. NOTHING HERE
AUTHORS AN ATTESTATION OR APPLIES ANYTHING: the source's attestation is
copied verbatim, the bytes are written only into the operator's run
directory by an explicit `--apply`, and placing them is the operator's
root step.

The source (version 1) is a JSON object with exactly `version`, `hub`,
`attested`, `host_domains` and `links`; each link has exactly `host`, `hub`,
`delivered_domains`, `delivered_domains_sha256` and `attestation`
(`by`, `at`, `statement`). A different version or member refuses: the
producer changes names only with a version bump.

The render takes the one link whose `host` is this host's label and refuses
anything the strictest reader would refuse:
- duplicate JSON keys, NaN or Infinity, more than `MAX_BYTES`;
- a domain that is not already one lower-case `<label>.internal` (it is
  refused, never lower-cased), the host's own domain, an excluded domain
  (the probe's and the logins'), or a duplicate;
- a hash that is not 64 lower-case hex, or that differs from the hash
  recomputed over the domains (each followed by a newline, sorted, UTF-8);
- an attestation member that is blank, an `at` not in `YYYY-MM-DDTHH:MM:SSZ`,
  or a statement that is not the approved one, byte for byte;
- a domain set that differs from the fleet hosts the local router is given.

The source's own `host_domains` is the canonical record of each host's
domain: this host's entry must be exactly the overlay's own domain, and the
link's set must be exactly every other host's domains, so the overlay's own
domain and fleet hosts cannot drift from the producer together.

A source that does not attest, or holds no link for this host, renders
NOTHING (`NotAttested`): no hub-link router starts without an attested set,
and a file already deployed stays until the operator stops that router.
More than one link for this host refuses.

The deployed file has exactly `delivered_domains` (sorted), `sha256` and
`attestation`, as compact sorted-key JSON plus a newline, so two renders of
one link are byte-identical. `host` and `hub` are checked, then dropped:
the hub-link reader refuses any other member.

verify compares the deployed file with a fresh render as BYTES, and with the
source as PARSED fields (the source is never re-serialised), recomputing
the hash on the deployed copy.
"""

import hashlib
import json
import os
import posixpath
import re
import stat
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

import router_health as rh

SOURCE_VERSION = 1
SOURCE_KEYS = frozenset({"version", "hub", "attested", "host_domains", "links"})
LINK_KEYS = frozenset({"host", "hub", "delivered_domains", "delivered_domains_sha256", "attestation"})
ATTESTATION_KEYS = frozenset({"by", "at", "statement"})
DEPLOYED_KEYS = frozenset({"delivered_domains", "sha256", "attestation"})
#: The strictest reader's bound on the deployed file, applied to the source too.
MAX_BYTES = 64 * 1024
FILE_MODE = 0o444
DIR_MODE = 0o755
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN = re.compile(rf"{_LABEL}\.internal")
_AT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


class D7Error(ValueError):
    """The source or a deployed file breaks a rule; `rule` names which."""

    def __init__(self, rule: str, detail: str):
        super().__init__(f"{rule}: {detail}")
        self.rule = rule


@dataclass(frozen=True)
class Rules:
    """What a link must satisfy on this host."""
    host_label: str
    own_domain: str
    excluded: Tuple[str, ...]          # never delivered: the probe's and the logins' domains
    statement: str                     # the approved attestation statement, byte for byte
    fleet_hosts: Tuple[str, ...]       # the local router's fleet hosts: the set must equal them


@dataclass(frozen=True)
class NotAttested:
    """Render nothing: the source does not attest, or names no link here."""
    reason: str


def domains_sha256(domains: Sequence[str]) -> str:
    """The hash both readers recompute: each domain followed by a newline,
    sorted, UTF-8."""
    return hashlib.sha256("".join(d + "\n" for d in sorted(domains)).encode("utf-8")).hexdigest()


def _no_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    seen: Dict[str, Any] = {}
    for k, v in pairs:
        if k in seen:
            raise D7Error("duplicate_key", f"the key {k!r} appears twice in one object")
        seen[k] = v
    return seen


def _no_constant(name: str) -> Any:
    raise D7Error("not_json", f"{name} is not JSON")


def strict_json(raw: bytes) -> Any:
    """JSON, refusing what a lenient parser would accept."""
    if len(raw) > MAX_BYTES:
        raise D7Error("size", f"more than {MAX_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise D7Error("not_json", "not UTF-8") from None
    try:
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except D7Error:
        raise
    except ValueError as e:
        raise D7Error("not_json", str(e)) from None


def _exact(obj: Any, keys: frozenset, what: str) -> Dict[str, Any]:
    if not isinstance(obj, dict) or set(obj) != keys:
        got = sorted(obj) if isinstance(obj, dict) else type(obj).__name__
        raise D7Error("shape", f"{what} must have exactly {sorted(keys)}; got {got}")
    return obj


def check_domains(domains: Any, rules: Rules) -> List[str]:
    if not isinstance(domains, list) or not domains:
        raise D7Error("domains", "delivered_domains must be a non-empty list")
    seen = set()
    for d in domains:
        if not isinstance(d, str) or not _DOMAIN.fullmatch(d):
            raise D7Error("domains", f"{d!r} is not one lower-case <label>.internal")
        if d == rules.own_domain:
            raise D7Error("domains", f"{d} is this host's own domain")
        if d in rules.excluded:
            raise D7Error("domains", f"{d} is never a delivered domain")
        if d in seen:
            raise D7Error("domains", f"{d} is listed twice")
        seen.add(d)
    return list(domains)


def check_hash(claimed: Any, domains: Sequence[str], member: str) -> str:
    if not isinstance(claimed, str) or not _HEX64.fullmatch(claimed):
        raise D7Error("hash", f"{member} must be 64 lower-case hex digits")
    if claimed != domains_sha256(domains):
        raise D7Error("hash", f"{member} is not the hash of the delivered domains")
    return claimed


def check_attestation(att: Any, rules: Rules) -> Dict[str, str]:
    att = _exact(att, ATTESTATION_KEYS, "attestation")
    for k in sorted(ATTESTATION_KEYS):
        if not isinstance(att[k], str) or not att[k].strip():
            raise D7Error("attestation", f"attestation.{k} must be a non-blank string")
    if not _AT.fullmatch(att["at"]):
        raise D7Error("attestation", "attestation.at must be YYYY-MM-DDTHH:MM:SSZ")
    if att["statement"] != rules.statement:
        raise D7Error("attestation", "attestation.statement is not the approved statement")
    return {k: att[k] for k in sorted(ATTESTATION_KEYS)}


def deployed_bytes(domains: Sequence[str], sha256: str, attestation: Dict[str, str]) -> bytes:
    doc = {"delivered_domains": sorted(domains), "sha256": sha256, "attestation": attestation}
    return (json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def source_link(raw: bytes, rules: Rules) -> Union[Dict[str, Any], NotAttested]:
    """This host's link from the source, checked, or NotAttested."""
    doc = _exact(strict_json(raw), SOURCE_KEYS, "the source")
    if type(doc["version"]) is not int or doc["version"] != SOURCE_VERSION:
        raise D7Error("version", f"version must be {SOURCE_VERSION}; got {doc['version']!r}")
    if not isinstance(doc["hub"], str) or not doc["hub"]:
        raise D7Error("shape", "hub must be a non-empty string")
    if type(doc["attested"]) is not bool:
        raise D7Error("shape", "attested must be true or false")
    if not isinstance(doc["host_domains"], dict) or not isinstance(doc["links"], list):
        raise D7Error("shape", "host_domains must be an object and links a list")
    if doc["attested"] is not True:
        return NotAttested("the source is not attested")
    for i, ln in enumerate(doc["links"]):
        if not isinstance(ln, dict) or not isinstance(ln.get("host"), str) or not ln["host"]:
            raise D7Error("links", f"links[{i}] is not a link object naming its host")
    others = _host_domains(doc["host_domains"], rules)
    mine = [ln for ln in doc["links"] if ln["host"] == rules.host_label]
    if not mine:
        return NotAttested(f"the source has no link for {rules.host_label}")
    if len(mine) > 1:
        raise D7Error("links", f"the source has {len(mine)} links for {rules.host_label}")
    link = _exact(mine[0], LINK_KEYS, "the link")
    if link["hub"] != doc["hub"]:
        raise D7Error("shape", "the link's hub is not the source's hub")
    domains = check_domains(link["delivered_domains"], rules)
    check_hash(link["delivered_domains_sha256"], domains, "delivered_domains_sha256")
    attestation = check_attestation(link["attestation"], rules)
    if set(domains) != others:
        raise D7Error("host_domains", "the link's domains are not exactly every other host's domains in "
                                      "the source's host_domains")
    if set(domains) != set(rules.fleet_hosts):
        raise D7Error("fleet", f"{len(set(domains) - set(rules.fleet_hosts))} delivered domain(s) are not "
                               f"fleet hosts and {len(set(rules.fleet_hosts) - set(domains))} fleet host(s) "
                               f"are not delivered")
    return {"delivered_domains": domains, "sha256": link["delivered_domains_sha256"],
            "attestation": attestation}


def _host_domains(hd: Any, rules: Rules) -> set:
    """The canonical record of each host's domains: this host's must be
    exactly the own domain; returns every other host's."""
    if not isinstance(hd, dict) or not hd:
        raise D7Error("host_domains", "host_domains must be a non-empty object")
    others = set()
    for host, ds in hd.items():
        if not isinstance(ds, list) or not ds or any(not isinstance(d, str) or not _DOMAIN.fullmatch(d)
                                                     for d in ds):
            raise D7Error("host_domains", f"host_domains.{host} must list lower-case <label>.internal domains")
        if host != rules.host_label:
            others |= set(ds)
    if hd.get(rules.host_label) != [rules.own_domain]:
        raise D7Error("host_domains", f"host_domains.{rules.host_label} is not exactly [{rules.own_domain}], "
                                      f"the overlay's own domain")
    if rules.own_domain in others:
        raise D7Error("host_domains", f"{rules.own_domain} is listed for another host too")
    return others


def render(raw: bytes, rules: Rules) -> Union[bytes, NotAttested]:
    """The deployed file's bytes for this host, or NotAttested. D7Error on
    any rule; nothing is written here."""
    link = source_link(raw, rules)
    if isinstance(link, NotAttested):
        return link
    return deployed_bytes(link["delivered_domains"], link["sha256"], link["attestation"])


def parse_deployed(raw: bytes, rules: Rules) -> Dict[str, Any]:
    """A deployed file, held to the same rules, its hash recomputed."""
    doc = _exact(strict_json(raw), DEPLOYED_KEYS, "the deployed file")
    domains = check_domains(doc["delivered_domains"], rules)
    check_hash(doc["sha256"], domains, "sha256")
    return {"delivered_domains": domains, "sha256": doc["sha256"],
            "attestation": check_attestation(doc["attestation"], rules)}


# --- Verify ---------------------------------------------------------------------


def place_temp(name: str) -> re.Pattern:
    """`host_steps.py place`'s own temporary name for `name`."""
    return re.compile(r"\." + re.escape(name) + r"\.[0-9]+\.tmp")


def _fact(name: str, value: Any, provenance: str) -> rh.Fact:
    return rh.Fact(name, value, provenance)


def _lst(path: str, lstat: Callable) -> Any:
    try:
        return lstat(path)
    except FileNotFoundError:
        return None
    except OSError as e:
        return rh.Unresolved(f"cannot inspect {path}: {e}")


def _ancestors(path: str) -> List[str]:
    out, p = [], posixpath.dirname(path)
    while True:
        out.append(p)
        if p == "/":
            return out
        p = posixpath.dirname(p)


def read_file(path: str) -> bytes:
    """A regular file's bytes, never through a symbolic link, at most one
    byte past the bound so an oversized file is seen as oversized."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"{path} is not a regular file")
        return read_bounded(fd, MAX_BYTES + 1)
    finally:
        os.close(fd)


def read_bounded(fd: int, limit: int) -> bytes:
    """Read to EOF or `limit` bytes, whichever comes first: a short read is
    not the end."""
    chunks, total = [], 0
    while total < limit:
        chunk = os.read(fd, limit - total)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def write_all(fd: int, data: bytes) -> None:
    """Write every byte: a short write is continued, never taken as done."""
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        if n <= 0:
            raise OSError("write made no progress")
        view = view[n:]


def write_atomically(path: str, data: bytes) -> None:
    """`data` into `path` by a fresh temporary name and a rename; the
    temporary file is removed if anything fails before the rename."""
    tmp = f"{path}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600)
    try:
        try:
            write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def verify(d7_dir: str, name: str, rules: Rules, source: Any, *, lstat: Callable = os.lstat,
           listdir: Callable[[str], List[str]] = os.listdir,
           read: Callable[[str], bytes] = read_file) -> List[rh.Check]:
    """The deployed D7 file against its rules, its re-render and its source.
    `source` is the source's bytes, or an Unresolved when it could not be read."""
    out: List[rh.Check] = []
    path = posixpath.join(d7_dir, name)
    why = "both hub-link routers read it; only root may change it"
    st = _lst(d7_dir, lstat)
    claim = f"the D7 directory {d7_dir} is a root-owned 0755 directory"
    want = _fact("D7 directory", (0, 0, DIR_MODE), why)
    remedy = f"create it with `install -d -o 0 -g 0 -m 0755 {d7_dir}`"
    if isinstance(st, rh.Unresolved):
        out.append(rh.unknown(claim, want, st.reason, remedy))
    elif st is None or not stat.S_ISDIR(st.st_mode):
        out.append(rh.check(claim, want, "absent" if st is None else "not a directory", remedy))
    else:
        out.append(rh.check(claim, want, (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)), remedy))
    claim = f"every directory above {d7_dir} is root-owned and not group- or world-writable"
    want = _fact("ancestors", True, why)
    remedy = f"make every directory above {d7_dir} root-owned and not group- or world-writable"
    bad = None
    for d in _ancestors(d7_dir):
        a = _lst(d, lstat)
        if isinstance(a, rh.Unresolved):
            bad = a
            break
        if a is None or not stat.S_ISDIR(a.st_mode) or a.st_uid != 0 or stat.S_IMODE(a.st_mode) & 0o022:
            bad = d
            break
    out.append(rh.unknown(claim, want, bad.reason, remedy) if isinstance(bad, rh.Unresolved)
               else rh.check(claim, want, True if bad is None else f"{bad} is not", remedy))
    claim = f"the D7 directory holds only {name}"
    want = _fact("entries", [name], "it is mounted whole into both routers; anything else there is "
                                    "readable by them")
    remedy = f"remove every other entry from {d7_dir}"
    try:
        entries = sorted(e for e in listdir(d7_dir) if not place_temp(name).fullmatch(e))
        out.append(rh.check(claim, want, entries, remedy))
    except FileNotFoundError:
        out.append(rh.check(claim, want, "the directory is absent", remedy))
    except OSError as e:
        out.append(rh.unknown(claim, want, f"cannot list {d7_dir}: {e}", remedy))
    st = _lst(path, lstat)
    claim = f"the D7 file {path} is root:root 0444 with one link"
    want = _fact("D7 file", (0, 0, FILE_MODE, 1), why)
    remedy = f"place it with `host_steps.py place <the rendered file> {path} --sha256 <its hash>`"
    if isinstance(st, rh.Unresolved):
        out.append(rh.unknown(claim, want, st.reason, remedy))
    elif st is None or not stat.S_ISREG(st.st_mode):
        out.append(rh.check(claim, want, "absent" if st is None else "not a regular file", remedy))
    else:
        out.append(rh.check(claim, want, (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_nlink),
                            remedy, do_not="never make it writable to update it; place a new one"))
    try:
        deployed = read(path)
    except FileNotFoundError:
        deployed = None
    except OSError as e:
        deployed = rh.Unresolved(f"cannot read {path}: {e}")
    out += _content(path, deployed, rules, source)
    return out


def _content(path: str, deployed: Any, rules: Rules, source: Any) -> List[rh.Check]:
    out = []
    claim = f"the D7 file {path} meets the hub-link reader's rules, its hash recomputed"
    want = _fact("D7 rules", True, "the strictest reader refuses the link's start on any of them")
    remedy = "render it again from the attested source and place it"
    parsed = None
    if isinstance(deployed, rh.Unresolved):
        out.append(rh.unknown(claim, want, deployed.reason, remedy))
    elif deployed is None:
        out.append(rh.check(claim, want, "absent", remedy))
    else:
        try:
            parsed = parse_deployed(deployed, rules)
            out.append(rh.check(claim, want, True, remedy))
        except D7Error as e:
            out.append(rh.check(claim, want, str(e), remedy,
                                do_not="never edit the deployed file; correct the source and render"))
    claim = f"the D7 file {path} is byte-identical to a fresh render of the source"
    want = _fact("D7 bytes", True, "both are compact sorted-key JSON, so bytes are comparable")
    remedy = "render from the attested source and place the result"
    if isinstance(source, rh.Unresolved):
        out.append(rh.unknown(claim, want, source.reason, "make the source's clone readable"))
        return out
    try:
        fresh = render(source, rules)
    except D7Error as e:
        out.append(rh.check(claim, want, f"the source refuses: {e}", "correct the source (its producer's step)"))
        return out
    if isinstance(fresh, NotAttested):
        if deployed is None:
            out.append(rh.check(claim, want, f"{fresh.reason}: not attested yet, so nothing is rendered",
                                "the operator attests the link in the source; the hub-link router stays "
                                "stopped until then"))
        else:
            out.append(rh.check(claim, want, f"{fresh.reason}: the source no longer attests this link",
                                "stop the hub-link router (the operator's step) until the source attests again",
                                do_not="never keep it running on a set the source no longer attests"))
        return out
    if isinstance(deployed, rh.Unresolved) or deployed is None:
        out.append(rh.unknown(claim, want, "the deployed file could not be read", remedy)
                   if isinstance(deployed, rh.Unresolved) else rh.check(claim, want, "absent", remedy))
        return out
    out.append(rh.check(claim, want, deployed == fresh, remedy))
    claim = f"the D7 file {path} carries the source link's domains, hash and attestation"
    want = _fact("D7 fields", True, "compared parsed, never by re-serialising the source")
    link = source_link(source, rules)
    same = parsed is not None and not isinstance(link, NotAttested) and \
        sorted(parsed["delivered_domains"]) == sorted(link["delivered_domains"]) and \
        all(parsed[k] == link[k] for k in ("sha256", "attestation"))
    out.append(rh.check(claim, want, same, remedy))
    return out


def notes(d7_dir: str, name: str, listdir: Callable[[str], List[str]] = os.listdir) -> List[str]:
    """What verify tolerates but the operator should see."""
    try:
        temps = sorted(e for e in listdir(d7_dir) if place_temp(name).fullmatch(e))
    except OSError:
        return []
    return [f"{d7_dir}/{t}: a placement in progress, or a crashed one; run the place step again" for t in temps]
