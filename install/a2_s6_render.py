"""S6 CONFIG: one VM's router.json, rendered on the runner in RL's closed vocabulary.

The installer imports nothing outside install/, so the values this repo's reviewed renderers own are restated here
as constants, and tests/test_a2_s6_agreement.py (run with the siblings, like the rest of tests/) holds each one to
its source: the base keys to amap_sandy.render_router_sibling for the ALPHA-2 policy, the hop caps, version and
plugin pin to hop_router, the delegation block to delegation_render.render_block (crypto=CRYPTO_OPENSSL).

What the document carries (RL at its ALPHA-2 pin: 90f00634, 4a844e3a):
- the sibling base: state_dir, instances_dir, selected_json (the agent account's sandy feature), connector_outcome_ids,
  fleet_domain, task_graph "all" (the ALPHA-2 policy: every agent may task; no mail edge, so no mail key);
- min_sender_age_s 0; egress false, explicit (it is in the sender's policy digest);
- transport_plugin at the root-owned plugin path, with the reviewed pin;
- hop {root, peer_uid = the relay account's uid, version_write, caps, link};
- registry_dir; fleet_hosts and trusted_fleet_hosts, both [the other VM's fleet domain];
- delegation {partition_verified "partition-<run_id>", signing_key (this VM's S5 facts), runtimes [the other VM],
  crypto openssl, inbound true}.
No delivered_domains_file: RL's is its own provisional artifact, never RE's D7 file.
RL's own `peers` on the VM is the authority on whether it loads.
"""

import json
import posixpath
import re

#: The router's top-level keys this renderer writes: a subset of RL's vocabulary at its ALPHA-2 pin.
KEYS = ("state_dir", "instances_dir", "selected_json", "connector_outcome_ids", "fleet_domain", "task_graph",
        "min_sender_age_s", "egress", "transport_plugin", "hop", "registry_dir", "fleet_hosts", "trusted_fleet_hosts",
        "delegation")
#: amap_sandy: the feature's place under SANDY_HOME, its instances tree and sandy's verdict, and the connector ids.
FEATURE_ROOT = "features/amap"
INSTANCES = "instances"
SELECTED = "selected.json"
CONNECTOR_OUTCOME_IDS = ("claude-code", "codex")
TASK_GRAPH_ALL = "all"
#: hop_router: the reviewed hop constant and the plugin it was reviewed for.
PLUGIN_SHA256 = "f15855c974df021c2ae5c551aff2448d934725a6796fb03434e573305d24fe93"
VERSION_WRITE = 1
CAPS = (("document", 23418699), ("request", 1048576), ("attachment", 1048576), ("total", 20971520))
#: delegation_render.CRYPTO_OPENSSL (ruling W7-CRYPTO-OPENSSL).
CRYPTO_OPENSSL = (("crypto_backend", "openssl"), ("openssl_path", "/usr/bin/openssl"))
#: vm_bootstrap.PLUGIN, from /.
PLUGIN_PATH = "/opt/amap-plugin/amap_hop_plugin.py"
#: The ALPHA-2 hop link's name: RL's hop.link and RE's HOP_LINK.
LINK = "alpha2"
#: The paths under the agent account's home (design S6 section 2).
ROUTER_DIR = ".amap-router"
STATE = ".amap-router/state"
HOP_ROOT = ".amap-hop"
REGISTRY = ".amap-registry"
SEED = ".amap-delegation/seed"

_DOMAIN = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+")
_SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_RUN_ID = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}")
_ABS = re.compile(r"(/[A-Za-z0-9._-]+)+")


class RenderRefused(ValueError):
    """An input breaks its rule; nothing is rendered."""


def _abspath(p, what):
    if not isinstance(p, str) or not _ABS.fullmatch(p) or posixpath.normpath(p) != p \
            or any(s in (".", "..") for s in p.split("/")):
        raise RenderRefused(what)
    return p


def _match(rx, v, what):
    if not isinstance(v, str) or not rx.fullmatch(v):
        raise RenderRefused(what)
    return v


def router_json(*, agent_home, sandy_home, fleet_domain, relay_uid, run_id, own_key_id, own_public_key, other):
    """This VM's router.json as a dict. `other` is the other VM: {slug, fleet_domain, key_id, public_key}, the last
    two from its S5 receipt."""
    home = _abspath(agent_home, "agent home")
    sandy = _abspath(sandy_home, "sandy home")
    own = _match(_DOMAIN, fleet_domain, "fleet domain")
    if type(relay_uid) is not int or relay_uid <= 0:
        raise RenderRefused("relay uid")
    run = _match(_RUN_ID, run_id, "run id")
    kid = _match(_KEY_ID, own_key_id, "own key id")
    pub = _match(_HEX64, own_public_key, "own public key")
    if not isinstance(other, dict) or set(other) != {"slug", "fleet_domain", "key_id", "public_key"}:
        raise RenderRefused("other vm")
    o_slug = _match(_SLUG, other["slug"], "other slug")
    o_dom = _match(_DOMAIN, other["fleet_domain"], "other fleet domain")
    o_kid = _match(_KEY_ID, other["key_id"], "other key id")
    o_pub = _match(_HEX64, other["public_key"], "other public key")
    if o_dom == own:
        raise RenderRefused("the other vm has this vm's fleet domain")
    if o_kid == kid or o_pub == pub:
        raise RenderRefused("the other vm has this vm's key")
    feature = posixpath.join(sandy, FEATURE_ROOT)
    doc = {
        "state_dir": posixpath.join(home, STATE),
        "instances_dir": posixpath.join(feature, INSTANCES),
        "selected_json": posixpath.join(feature, SELECTED),
        "connector_outcome_ids": list(CONNECTOR_OUTCOME_IDS),
        "fleet_domain": own,
        "task_graph": TASK_GRAPH_ALL,
        "min_sender_age_s": 0,
        "egress": False,
        "transport_plugin": {"path": PLUGIN_PATH, "sha256": PLUGIN_SHA256},
        "hop": {"root": posixpath.join(home, HOP_ROOT), "peer_uid": relay_uid, "version_write": VERSION_WRITE,
                "caps": dict(CAPS), "link": LINK},
        "registry_dir": posixpath.join(home, REGISTRY),
        "fleet_hosts": [o_dom],
        "trusted_fleet_hosts": [o_dom],
        "delegation": {
            "partition_verified": "partition-" + run,
            "signing_key": {"path": posixpath.join(home, SEED), "key_id": kid, "public_key": pub},
            "runtimes": [{"name": o_slug, "runtime": "amap.router@" + o_dom, "domains": [o_dom],
                          "keys": [{"key_id": o_kid, "public_key": o_pub}]}],
            "crypto": dict(CRYPTO_OPENSSL),
            "inbound": True,
        },
    }
    assert tuple(doc) == KEYS
    return doc


def text(doc):
    """The bytes S6 places and hashes: sorted keys, two-space indent, one trailing newline."""
    return (json.dumps(doc, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
