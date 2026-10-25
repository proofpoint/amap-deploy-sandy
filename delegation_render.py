"""The local router's `delegation` block, rendered from the pinned fleet
inventory, and the check that holds a rendering to the hop pin's own code
WITHOUT ever touching the signing key.

The block (the local router's `_delegation` at the hop pin):
- `signing_key`: the keys section's path, and this host's inventory entry's
  `key_id` and `public_key`;
- `runtimes`: every other inventory entry, each with its one key;
- `crypto`: exactly `{"crypto_backend": "pyca"}`. The openssl backend and its
  path are never rendered, so no new tool joins the router's closure;
- `inbound`: present, and true, only where the policy turns it on.
`partition_verified` is never rendered here: A3 adds the token.

The per-host switch is the policy's `hop_link.delegation`, exactly
{`inbound`}, a boolean with no default. Absent, the host renders no block.

The no-seed check runs in a SEPARATE process with only the hop checkout on
its path, as `hop_router.validate_with_hop_router` does:
1. the strict parse of the rendered bytes (a duplicate member or a
   non-finite number refuses here, since the router's loader takes a parsed
   object), then the router's `config.load_obj`;
2. the plugin's key gate, called as the router's `peerlane.activate` calls
   it, up to and never including the seed: `transport.load_plugin` on the
   pinned plugin with the agent-reachable roots the router's start passes,
   `check_delegation`, `make_peer_codec({})`, the codec's methods, reason
   sets and candidate view, `load_key_table` on the peers and on this host's
   own entry (built as activate builds it), the signing key_id among the
   peers', and the own key's selection and length. The peer table must be
   non-empty, each runtime with exactly one key, and every configured peer
   key is selected from the table the gate returned, at one UTC instant,
   with the same public bytes and, where the table exposes them, the same
   runtime and domains: a gate that loads without error is not enough.

`render_block` itself refuses a block with no peer runtime, a runtime that is
not its peer's (name, runtime, domains) with exactly that peer's one key, and
this host's own entry rendered as a peer.
`read_seed`, `make_signer` and `make_verifier` are never called. An audit
hook in that process refuses any open of the signing key or of anything in
its directory, so the check cannot read the key even by accident. The own
key's selection and length catch the SELECT form of signing_key_mismatch
without the seed; the check never proves the key pair. The seed's own
proof, its signature verified by the configured public key, is only the
router's, when it starts (A4).
"""

import json
import subprocess
import sys
from typing import Any, Dict, List, Optional, Sequence

import fleet_keys as fk

POLICY_MEMBER = "delegation"
POLICY_MEMBERS = frozenset({"inbound"})
CRYPTO = {"crypto_backend": "pyca"}


class DelegationRenderError(ValueError):
    """No block can be rendered; the message names why."""


def parse_policy(raw: Any) -> Optional[bool]:
    """The hop link's `delegation` member: None when absent (no block), else
    whether inbound verification is on."""
    if not isinstance(raw, dict) or set(raw) != POLICY_MEMBERS or not isinstance(raw["inbound"], bool):
        raise DelegationRenderError(f"hop_link.{POLICY_MEMBER} must be exactly {{inbound: true|false}}")
    return raw["inbound"]


def _check_runtimes(runtimes: List[Dict[str, Any]], me: fk.Host, peers: Sequence[fk.Host]) -> None:
    """Each rendered runtime is its peer's, carrying exactly that peer's one
    key; there is at least one, and none is this host's own signing entry."""
    if not runtimes:
        raise DelegationRenderError("the block has no peer runtime: it would verify nothing")
    if len(runtimes) != len(peers):
        raise DelegationRenderError(f"{len(runtimes)} runtimes rendered for {len(peers)} peers")
    for r, p in zip(runtimes, peers):
        if p.name == me.name or p.key_id == me.key_id:
            raise DelegationRenderError(f"the runtime {p.name!r} is this host's own signing entry, not a peer")
        if (r.get("name"), r.get("runtime"), r.get("domains")) != (p.name, p.runtime, list(p.domains)):
            raise DelegationRenderError(f"the runtime rendered for {p.name!r} is not that peer's name, runtime "
                                        "and domains")
        if r.get("keys") != [{"key_id": p.key_id, "public_key": p.public_key}]:
            raise DelegationRenderError(f"the runtime {p.name!r} must carry exactly its one inventory key")


def render_block(*, key_path: str, me: fk.Host, peers: Sequence[fk.Host], inbound: bool) -> Dict[str, Any]:
    runtimes = [p.table_entry() for p in peers]
    _check_runtimes(runtimes, me, peers)
    block: Dict[str, Any] = {
        "signing_key": {"path": key_path, "key_id": me.key_id, "public_key": me.public_key},
        "runtimes": runtimes,
        "crypto": dict(CRYPTO),
    }
    if inbound:
        block["inbound"] = True
    return block


#: Run with the hop checkout as argv[1]; reads {config, key_path,
#: trusted_uids} on stdin. Prints {"ok": true} or {"refused": reason,
#: "detail": text}; any other ending is a check that could not run.
NO_SEED_SCRIPT = r'''
import datetime, json, os, sys
sys.path.insert(0, sys.argv[1])
args = json.loads(sys.stdin.read())
key_path = args["key_path"]
key_dir = os.path.dirname(key_path)

def no_key(event, a):
    if event == "open" and a and isinstance(a[0], (str, bytes, os.PathLike)):
        p = os.fsdecode(a[0])
        if p == key_path or p == key_dir or p.startswith(key_dir.rstrip("/") + "/"):
            raise RuntimeError("the no-seed check would have opened " + p)

sys.addaudithook(no_key)
from router import config as C, peerlane as P, transport as T

def refused(reason, detail):
    print(json.dumps({"refused": reason, "detail": detail}))
    sys.exit(0)

try:
    cfg = C.load_obj(args["config"])
except C.ConfigError as e:
    refused("config", str(e))
dc = cfg.delegation
if dc is None or cfg.transport_plugin is None:
    refused("config", "the rendering carries no delegation block and plugin")
kw = {} if args["trusted_uids"] is None else {"trusted_uids": tuple(args["trusted_uids"])}
try:
    # The roots the router's own start passes: no plugin may sit where an agent reaches.
    plugin = T.load_plugin(cfg.transport_plugin.path, cfg.transport_plugin.sha256,
                           forbidden_roots=C.agent_reachable_roots(cfg.instances), **kw)
    caps = T.check_delegation(plugin)
except T.PluginRefused as e:
    refused(e.reason, str(e))
try:
    codec = caps.make_peer_codec({})
except Exception as e:
    if type(e) is caps.errors["ConfigError"]:
        refused("codec", "make_peer_codec({}) refused: %s" % e)
    raise
for m in P._CODEC_METHODS:
    if not callable(getattr(codec, m, None)):
        refused("codec", "the peer codec has no callable %r" % m)
try:
    reasons = P._reason_set(getattr(codec, "REASONS", None), "REASONS")
    kcr = P._reason_set(getattr(codec, "KEY_CONFIG_REASONS", None), "KEY_CONFIG_REASONS")
    P.candidate_view_of(codec, tuple(plugin.api))
except P.DelegationRefused as e:
    refused(e.reason, e.detail)
probe = P.Delegation(config=dc, signer=None, verifier=None, codec=codec, errors=caps.errors,
                     key_table=None, reasons=reasons, key_config_reasons=kcr)

def gate(peers, what):
    try:
        return codec.load_key_table(peers)
    except Exception as e:
        if P.error_kind(probe, e) == "KeyConfigError":
            refused(e.reason, "%s: %s" % (what, e))
        raise

now = datetime.datetime.now(datetime.timezone.utc)
# The loader accepts an empty runtimes list and an empty keys list, and the
# gate loads either as a table that verifies nothing.
if not dc.runtimes:
    refused("no_peer", "delegation.runtimes is empty: the key table would verify nothing")
for r in dc.runtimes:
    if len(r.keys) != 1:
        refused("key_malformed", "the runtime %r carries %d keys, not its one" % (r.name, len(r.keys)))
table = gate(dc.key_table_input(), "delegation.runtimes")
if dc.signing_key_id in {k["key_id"] for r in dc.runtimes for k in r.keys}:
    refused("duplicate_key_id", "the signing key_id %r is also a peer's" % dc.signing_key_id)
# Every configured peer key is selected from the table the gate returned, so
# a gate that drops or alters a key refuses here rather than at first use.
for r in dc.runtimes:
    k = r.keys[0]
    try:
        want = bytes.fromhex(k["public_key"])
    except ValueError:
        refused("key_malformed", "the runtime %r public_key is not hex" % r.name)
    try:
        got = table.select(k["key_id"], now)
    except Exception as e:
        if P.error_kind(probe, e) == "CodecError":
            refused("peer_key_unselectable", "the runtime %r key %r cannot be selected: %s"
                    % (r.name, k["key_id"], e.reason))
        raise
    if not (type(getattr(got, "public_key", None)) is bytes and got.public_key == want):
        refused("peer_key_mismatch", "the key table gives the runtime %r key %r other public bytes"
                % (r.name, k["key_id"]))
    if hasattr(got, "runtime") and got.runtime != r.runtime:
        refused("peer_key_mismatch", "the key table binds the runtime %r key to %r" % (r.name, got.runtime))
    if hasattr(got, "domains") and tuple(got.domains) != tuple(r.domains):
        refused("peer_key_mismatch", "the key table binds the runtime %r key to other domains" % r.name)
own = gate([{"name": "self", "runtime": C.router_runtime(cfg.fleet_domain), "domains": [cfg.fleet_domain or ""],
             "keys": [{"key_id": dc.signing_key_id, "public_key": dc.signing_public_key}]}],
           "delegation.signing_key")
try:
    pub = own.select(dc.signing_key_id, now).public_key
except Exception as e:
    if P.error_kind(probe, e) == "CodecError":
        refused("signing_key_mismatch", "the signing key cannot be selected: %s" % e.reason)
    raise
if not (type(pub) is bytes and len(pub) == 32):
    refused("codec", "the key gate's public key is not 32 bytes")
print(json.dumps({"ok": True}))
'''


def no_seed_problem(doc: Dict[str, Any], checkout: str, *, trusted_uids: Optional[Sequence[int]] = None) -> Optional[str]:
    """None when the hop pin's loader and key gate accept `doc` (a parsed
    config carrying a delegation block), else why not. `trusted_uids`
    replaces the plugin loader's owner rule (root only) and exists for tests,
    whose plugin file the test user owns; production never passes it."""
    block = doc.get("delegation")
    if not isinstance(block, dict) or not isinstance(block.get("signing_key"), dict) \
            or not isinstance(block["signing_key"].get("path"), str):
        return "the rendering carries no delegation block with a signing key path"
    args = {"config": doc, "key_path": block["signing_key"]["path"],
            "trusted_uids": None if trusted_uids is None else list(trusted_uids)}
    try:
        p = subprocess.run([sys.executable, "-I", "-B", "-c", NO_SEED_SCRIPT, checkout], input=json.dumps(args),
                           capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"the no-seed check could not run: {e}"
    try:
        out = json.loads(p.stdout) if p.returncode == 0 else None
    except ValueError:
        out = None
    if out == {"ok": True}:
        return None
    if isinstance(out, dict) and set(out) == {"refused", "detail"}:
        return f"{out['refused']}: {out['detail']}"
    lines = [l for l in p.stderr.strip().splitlines() if l.strip()]
    return f"the no-seed check could not run: {lines[-1] if lines else 'exit ' + str(p.returncode)}"


def no_seed_problem_bytes(raw: bytes, checkout: str, *, trusted_uids: Optional[Sequence[int]] = None) -> Optional[str]:
    """`no_seed_problem` on file bytes, after the strict parse the router's
    loader does not make: a duplicate member or a non-finite number refuses
    here, before the router's code is called."""
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except (UnicodeDecodeError, ValueError) as e:
        return f"the rendering is not strict JSON: {e}"
    if not isinstance(doc, dict):
        return "the rendering is not a JSON object"
    return no_seed_problem(doc, checkout, trusted_uids=trusted_uids)


def _no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"{k!r} appears twice in one object")
        out[k] = v
    return out


def _no_constant(name):
    raise ValueError(f"{name} is not JSON")
