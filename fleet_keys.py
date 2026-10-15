"""The fleet's public signing keys: one inventory document, pinned by sha256
in each host's host-setup document, from which every host renders its own
`delegation` key table. NOTHING HERE READS, GENERATES OR DERIVES KEY
MATERIAL: the inventory carries each host's public key and the `key_id`
its key-generation step printed, and the deploy only checks them.

The host-setup document's `fleet_keys` section is exactly {`path`,
`sha256`}: where the inventory file is, and the sha256 its bytes must have.
The file is authored in the private overlay repository; a change is one
reviewed document plus a re-pin in every host's section, so every host
renders its table from identical bytes.

The inventory is canonical JSON, schema `amap-deploy.fleet-keys/1`, exactly
{`schema`, `hosts`}. `hosts` is sorted by `name`, each exactly {`name`,
`domains`, `runtime`, `key_id`, `public_key`}:
- `domains`: canonical host domains, sorted, at least one; no domain is
  listed by two hosts;
- `runtime`: `amap.router@<one of its domains>`, the local router's rule;
- `public_key`: the raw 32-byte Ed25519 public key, 64 lower-case hex;
- `key_id`: the sha256 of those 32 bytes, 64 lower-case hex, as printed at
  generation. It is compared with the public key's sha256 and refused on a
  mismatch, never substituted: a key_id is the operator's, not derived here.

This host is the one entry whose domains contain the policy's fleet domain;
every other entry is a peer, and each peer's domains must all be trusted
fleet hosts, which is the local router's own rule for a runtime it verifies.
"""

import hashlib
import json
import posixpath
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Sequence, Tuple

import fleet_policy

SECTION = "fleet_keys"
SCHEMA = "amap-deploy.fleet-keys/1"
SECTION_MEMBERS = frozenset({"path", "sha256"})
DOC_MEMBERS = frozenset({"schema", "hosts"})
HOST_MEMBERS = frozenset({"name", "domains", "runtime", "key_id", "public_key"})
#: Bounds the read: an inventory names a handful of hosts.
MAX_BYTES = 1 << 20
_HEX64 = re.compile(r"[0-9a-f]{64}")
#: The hop plugin's key_id grammar (keys.py); the 64-hex rule implies it,
#: and both are checked so a change to either is caught here.
KEY_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


class FleetKeysError(ValueError):
    """The section, the file or the inventory is unusable; the message names
    the entry it refuses."""


@dataclass(frozen=True)
class FleetKeysPin:
    path: str
    sha256: str


@dataclass(frozen=True)
class Host:
    name: str
    domains: Tuple[str, ...]
    runtime: str
    key_id: str
    public_key: str

    def table_entry(self) -> Dict[str, Any]:
        """This host as a `delegation.runtimes` entry: its one key."""
        return {"name": self.name, "runtime": self.runtime, "domains": list(self.domains),
                "keys": [{"key_id": self.key_id, "public_key": self.public_key}]}


def load(sec: Any) -> FleetKeysPin:
    if not isinstance(sec, dict) or set(sec) != SECTION_MEMBERS:
        raise FleetKeysError(f"{SECTION} must be exactly {{path, sha256}}")
    p = sec["path"]
    if not isinstance(p, str) or not p.startswith("/") or p.startswith("//") or posixpath.normpath(p) != p:
        raise FleetKeysError(f"{SECTION}.path must be an absolute, normalised path")
    if not isinstance(sec["sha256"], str) or not _HEX64.fullmatch(sec["sha256"]):
        raise FleetKeysError(f"{SECTION}.sha256 must be 64 lower-case hex digits")
    return FleetKeysPin(p, sec["sha256"])


def canonical(doc: Any) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _no_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise FleetKeysError(f"the inventory names {k!r} twice in one object")
        out[k] = v
    return out


def _no_constant(name: str) -> Any:
    raise FleetKeysError(f"the inventory holds {name}, which is not JSON")


def _host(i: int, h: Any) -> Host:
    where = f"hosts[{i}]"
    if not isinstance(h, dict) or set(h) != HOST_MEMBERS:
        raise FleetKeysError(f"{where} must be exactly {{{', '.join(sorted(HOST_MEMBERS))}}}")
    name = h["name"]
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise FleetKeysError(f"{where}.name is not a name")
    where = f"the inventory entry {name!r}"
    d = h["domains"]
    if not isinstance(d, list) or not d or any(not isinstance(x, str) or not fleet_policy.FLEET_DOMAIN_RE.match(x)
                                                for x in d):
        raise FleetKeysError(f"{where}: domains must be a non-empty list of canonical host domains")
    if d != sorted(set(d)):
        raise FleetKeysError(f"{where}: domains must be sorted, each once")
    if not isinstance(h["runtime"], str) or h["runtime"] not in {fleet_policy.router_address(x) for x in d}:
        raise FleetKeysError(f"{where}: runtime must be {fleet_policy.ROUTER_LOCAL_PART}@<one of its domains>")
    pk, kid = h["public_key"], h["key_id"]
    if not isinstance(pk, str) or not _HEX64.fullmatch(pk):
        raise FleetKeysError(f"{where}: public_key must be 64 lower-case hex digits (the raw 32-byte key)")
    if not isinstance(kid, str) or not KEY_ID_RE.fullmatch(kid) or not _HEX64.fullmatch(kid):
        raise FleetKeysError(f"{where}: key_id must be 64 lower-case hex digits, as the key step printed it")
    if kid != hashlib.sha256(bytes.fromhex(pk)).hexdigest():
        raise FleetKeysError(f"{where}: key_id is not the sha256 of its public_key; the inventory is wrong, "
                             "and the deploy never substitutes a key_id")
    return Host(name, tuple(d), h["runtime"], kid, pk)


def parse(raw: bytes) -> Tuple[Host, ...]:
    """The inventory's hosts, or a refusal naming what is wrong. Strict: no
    duplicate member, no non-finite number, no member the schema does not
    name, and the bytes must be the document's canonical form."""
    if len(raw) > MAX_BYTES:
        raise FleetKeysError(f"the inventory is more than {MAX_BYTES} bytes")
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except (UnicodeDecodeError, ValueError) as e:
        if isinstance(e, FleetKeysError):
            raise
        raise FleetKeysError(f"the inventory is not JSON: {e}") from None
    if not isinstance(doc, dict) or set(doc) != DOC_MEMBERS:
        raise FleetKeysError("the inventory must be exactly {schema, hosts}")
    if doc["schema"] != SCHEMA:
        raise FleetKeysError(f"the inventory's schema is not {SCHEMA}")
    if canonical(doc) != raw:
        raise FleetKeysError("the inventory is not in canonical form (sorted keys, no whitespace)")
    if not isinstance(doc["hosts"], list) or not doc["hosts"]:
        raise FleetKeysError("the inventory's hosts must be a non-empty list")
    hosts = tuple(_host(i, h) for i, h in enumerate(doc["hosts"]))
    names = [h.name for h in hosts]
    if names != sorted(set(names)):
        raise FleetKeysError("the inventory's hosts must be sorted by name, each name once")
    owner: Dict[str, str] = {}
    seen_ids: Dict[str, str] = {}
    for h in hosts:
        for d in h.domains:
            if d in owner:
                raise FleetKeysError(f"the inventory entries {owner[d]!r} and {h.name!r} both list {d}; "
                                     "a domain belongs to one runtime")
            owner[d] = h.name
        if h.key_id in seen_ids:
            raise FleetKeysError(f"the inventory entries {seen_ids[h.key_id]!r} and {h.name!r} share a key_id")
        seen_ids[h.key_id] = h.name
    return hosts


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read(MAX_BYTES + 1)


def read(pin: FleetKeysPin, read_bytes: Callable[[str], bytes] = _read) -> Tuple[Host, ...]:
    """The pinned inventory: its bytes must hash to the pin before anything
    in them is parsed."""
    try:
        raw = read_bytes(pin.path)
    except OSError as e:
        raise FleetKeysError(f"cannot read the inventory {pin.path}: {e.strerror or e}") from None
    got = hashlib.sha256(raw).hexdigest()
    if got != pin.sha256:
        raise FleetKeysError(f"the inventory {pin.path} hashes to {got}, not the pinned {pin.sha256}")
    return parse(raw)


def select(hosts: Sequence[Host], fleet_domain: str, trusted: Sequence[str]) -> Tuple[Host, Tuple[Host, ...]]:
    """(this host, its peers). This host is the one entry listing the fleet
    domain; every other entry is a peer whose domains must all be trusted."""
    own = [h for h in hosts if fleet_domain in h.domains]
    if len(own) != 1:
        raise FleetKeysError(f"{len(own)} inventory entries list this host's fleet domain {fleet_domain}; "
                             "exactly one must")
    me = own[0]
    peers = tuple(h for h in hosts if h is not me)
    allowed = set(trusted)
    for p in peers:
        outside = [d for d in p.domains if d not in allowed]
        if outside:
            raise FleetKeysError(f"the inventory entry {p.name!r} lists {', '.join(outside)}, which this host "
                                 "does not trust (hop_link.trusted_fleet_hosts)")
    return me, peers
