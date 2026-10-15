"""A3: the local router's activation config, A1's staged bytes with the token
of the evidence A2 produced for that A1, checked before anything is written.

`install --apply --activate <run id> --activation-sha256 <hex>` names both
inputs explicitly: the run whose evidence document carries the token, and the
sha256 A1 printed for its record. Neither is ever defaulted, searched for or
taken from the file it is meant to check. Every refusal below writes nothing:
(a) the harness gate holds now;
(b) A1's record is the PLACED activation.json (root:root 0444, one link) and
    hashes to the sha256 given, and it is this host's for this config path;
(c) the run's document is this host's, passing (its token is present and its
    own), current, and bound to THIS A1's local router (the activation
    binding of A1's spec and staged bytes);
(d) a fresh rendering of the staged bytes, from today's policy, inventory and
    install rendering, is A1's staged bytes, byte for byte;
(e) the config now at the final path is the pre-activation rendering or
    already exactly A1 + T (an idempotent re-run); any third state refuses;
(f) A1 + T passes the no-seed check on the bytes that will be placed.
The bytes go into the operator's run directory; root places them at the final
path with the pinned writer's `place --sha256`. A3 never writes the final
path, and the activation takes effect only when the local router restarts
(A4): a reload of a changed delegation block is refused by the router.
"""

import hashlib
import posixpath
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import delegation_render as dr
import fleet_keys as fk
import partition_activation as pa
import partition_evidence as pe
import partition_setup as ps
import secret_setup as ss

ACTIVATED_NAME = "router.activated.json"


def _hex64(v: Any) -> bool:
    return isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdef" for c in v)


def render_staged(*, spec: Any, doc: Dict[str, Any], fleet_domain: str, trusted: Sequence[str], inbound: bool,
                  validate: Callable[[Dict[str, Any]], Optional[str]],
                  read_inventory: Callable[[str], bytes] = fk._read) -> bytes:
    """A1's staged bytes, rendered now: install's rendering `doc` with the
    delegation block from the pinned inventory, held to the no-seed check."""
    if spec.fleet_keys is None:
        raise fk.FleetKeysError("the host-setup document has no fleet_keys section")
    me, peers = fk.select(fk.read(spec.fleet_keys, read_inventory), fleet_domain, trusted)
    block = dr.render_block(key_path=spec.keys.path, me=me, peers=peers, inbound=inbound)
    return pa.staged_bytes(doc, block, validate)


def activate(*, spec: Any, host: str, doc: Dict[str, Any], pre_activation: bytes, fleet_domain: str,
             trusted: Sequence[str], inbound: bool, run_id: str, activation_sha256: str, gate: List[str],
             validate: Callable[[Dict[str, Any]], Optional[str]],
             validate_bytes: Callable[[bytes], Optional[str]],
             read_placed: Callable[[str], bytes] = ps.read_placed,
             read_final: Callable[[str], bytes] = lambda p: open(p, "rb").read(),
             read_inventory: Callable[[str], bytes] = fk._read,
             now: Optional[float] = None) -> Tuple[Optional[bytes], List[str]]:
    """(A1 + T, []) or (None, [the refusal]). `gate` is gate_problems now;
    `pre_activation` is install's rendering's bytes without delegation."""
    now = time.time() if now is None else now
    if not _hex64(activation_sha256):
        return None, ["--activation-sha256 must be 64 lower-case hex digits, as A1 printed it"]
    if not pe._RUN_ID.fullmatch(run_id or ""):
        return None, ["--activate must name A2's run id"]
    if spec.partition is None or spec.keys is None:
        return None, ["the host-setup document needs its partition and keys sections"]
    # (a)
    if gate:
        return None, ["(a) the harness gate does not hold: " + "; ".join(gate)]
    # (b)
    path = posixpath.join(spec.partition.evidence_dir, ps.ACTIVATION)
    try:
        raw = read_placed(path)
    except OSError as e:
        return None, [f"(b) A1's record {path} is not placed as root placed it: {e}"]
    got = hashlib.sha256(raw).hexdigest()
    if got != activation_sha256:
        return None, [f"(b) A1's placed record hashes to {got}, not the {activation_sha256} given"]
    try:
        approved = pa.parse_activation(raw)
    except pa.ActivationError as e:
        return None, [f"(b) {path}: {e}"]
    if approved["host"] != host or approved["final_config_path"] != spec.keys.local_config:
        return None, [f"(b) {path} is another host's or another config path's"]
    staged = approved["staged"].encode("utf-8")
    # (c)
    evidence = posixpath.join(spec.partition.evidence_dir, f"partition-{run_id}.json")
    try:
        edoc = pe.parse(read_placed(evidence), host=host)
    except (OSError, ValueError) as e:
        return None, [f"(c) {evidence} is not this host's placed evidence: {e}"]
    token = edoc[pe.TOKEN_MEMBER]
    if token is None:
        return None, [f"(c) {evidence} is not passing: a fail-stop probe did not pass"]
    if token != pe.token_of(edoc):
        return None, [f"(c) {evidence}'s token is not its own"]
    age = now - pe.at_seconds(edoc["at"])
    if age > pe.FRESH_FOR_S or age < -pe.CLOCK_TOLERANCE_S:
        return None, [f"(c) {evidence} is not current: run A2 again"]
    if edoc["bindings"].get("local_router") != pa.activation_binding(approved["spec"], staged):
        return None, [f"(c) {evidence} was not produced for this A1: its local router binding differs"]
    # (d)
    try:
        fresh = render_staged(spec=spec, doc=doc, fleet_domain=fleet_domain, trusted=trusted, inbound=inbound,
                              validate=validate, read_inventory=read_inventory)
    except (ValueError, pa.ActivationError) as e:
        return None, [f"(d) the staged bytes cannot be rendered now: {e}"]
    if fresh != staged:
        return None, ["(d) today's rendering is not A1's staged bytes: the policy, the inventory or the "
                      "install rendering changed since A1; run A1 again"]
    final = pa.final_bytes(staged, token)
    # (e)
    try:
        current = read_final(spec.keys.local_config)
    except OSError as e:
        return None, [f"(e) {spec.keys.local_config} cannot be read: {e}"]
    if current not in (pre_activation, final):
        return None, [f"(e) {spec.keys.local_config} is neither the pre-activation rendering nor A1 + T: "
                      "render it with install --apply, then activate"]
    # (f)
    refused = validate_bytes(final)
    if refused:
        return None, [f"(f) A1 + T does not pass the no-seed check: {refused}"]
    return final, []


def place_step(spec: Any, source: str, final: bytes) -> str:
    """The root step that installs A1 + T at the final path, bound to its
    sha256, through the pinned writer."""
    import shlex
    writer = posixpath.join(spec.secrets.writer_dir, ss.WRITER)
    return (f"sudo {shlex.quote(spec.partition.tools['python3'])} -I -S -B {shlex.quote(writer)} place "
            f"{shlex.quote(source)} {shlex.quote(spec.keys.local_config)} --sha256 {hashlib.sha256(final).hexdigest()}")
