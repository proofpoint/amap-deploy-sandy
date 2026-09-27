"""The layout-agreement test: router, manifest and connector name one layout.

Pins THREE things to agree with each other mechanically, never just by
convention: `provision()`'s own derivation (`config.py`'s `_derive_roots`),
the four env vars `provision()` emits, and the container-side paths shipped
in `payload/mcp-servers.json` (the ONE registration `amap-sandy.py` copies
onto the payload). A mismatch here is the class of bug that only shows on a
live host — the router derives one layout, the connector binaries are told
to look at a different one, and nothing catches it until a real agent's
first message goes nowhere.

The host <-> container mapping this test encodes: the router discovers
`instances_dir/<slug>/` (a HOST tree, sandy-made from the manifest's
`create`) and requires every LEAF under each lane before it drains
(`config.LANE_LEAVES`); sandy bind-mounts each lane —
`instances/<slug>/inbox` (:ro), `peer` (:ro), `outbox` (rw) — as a SEPARATE
mount wherever it chooses and exports that container path under the
mount's `export` name (`AMAP_INBOX_DIR` and the rest), which is what
`payload/mcp-servers.json`'s env values and the relay wrapper are rooted at. So
three lists must agree, tail for tail: the router's leaves, the manifest's
`create` block, and the tails the registration and the wrapper read under
the exports.

ALL FOUR `provision()`-emitted env vars are accounted for here, not just the
three directory ones: `ENV_NOTICE_DIR`/`ENV_MSG_DIR`/`ENV_DROPBOX_DIR` are
static tails `payload/mcp-servers.json` carries as constants (checked directly
against the shipped file below); `ENV_AGENT_ID` is DELIBERATELY NOT CARRIED
— `inbox-submit` omits `agent_id` when the variable is unset, and the
router binds a sender by its drop-box (amap-spec core SS2, where the field
is Optional) — and `TestTheRegistrationCarriesNoAgentId` pins its absence.
Every key the router emits is therefore either a pinned tail or a pinned
absence; a fifth key trips the assertion below, so no variable can ship
unwired (a wrongly wired agent id rejects every submit as
`agent_id_mismatch`) without a test noticing.
"""

from __future__ import annotations

import json
import unittest
import _wrapper
import sys
from pathlib import Path

# Drives the REAL router package from the sibling `amap-router-local`
# checkout, located by `_workspace` (walk-up, or `$AMAP_ROUTER_REPO`) — one
# resolver, so no test encodes this repo's nesting depth a second time.
# `.absolute()`, never `.resolve()`: sibling checkouts may be symlinked.
import _workspace  # noqa: E402

_workspace.skip_if_incomplete()
_ROUTER_ROOT = _workspace.ROUTER_ROOT
if str(_ROUTER_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROUTER_ROOT))

from router.provision import (
    ENV_AGENT_ID, ENV_DROPBOX_DIR, ENV_KEYS, ENV_MSG_DIR, ENV_NOTICE_DIR, provision,
)
from router.tests.helpers import RouterTestCase

_SANDY_ROOT = Path(__file__).absolute().parents[1]
_MCP_SERVERS_JSON = _SANDY_ROOT / "payload" / "mcp-servers.json"

if str(_SANDY_ROOT) not in sys.path:
    sys.path.insert(0, str(_SANDY_ROOT))
import amap_sandy as _prov_sandboxes  # noqa: E402

# The exact container-side relative tails `payload/mcp-servers.json` must carry,
# rooted at the lane exports sandy passes in — MUST equal the relative tails
# `provision()` derives beneath an authored instance's root (host-side; the
# same tails the discovery layout requires under each lane).
# `ENV_AGENT_ID` is deliberately NOT here — it isn't a directory tail, and it
# is not carried at all; see the module docstring and
# `TestTheRegistrationCarriesNoAgentId` below.
_EXPECTED_TAILS = {
    ENV_NOTICE_DIR: ("inbox", "notices"),
    ENV_MSG_DIR: ("inbox", "messages"),
    ENV_DROPBOX_DIR: ("outbox",),
}

# Every key `provision()` emits must be accounted for below — as a pinned
# tail, or as a pinned ABSENCE (`ENV_AGENT_ID`), so no variable can ship
# unwired.
assert set(_EXPECTED_TAILS) | {ENV_AGENT_ID} == set(ENV_KEYS), (
    "a new env var was added to provision()'s ENV_KEYS without being "
    "accounted for here — add it to _EXPECTED_TAILS (if it's a static "
    "directory tail payload/mcp-servers.json can carry as a constant) or give it "
    "its own test saying why the registration does or does not carry it"
)


def _export(lane: str) -> str:
    """`${AMAP_<LANE>_DIR}` — the registration's root for that lane, spelled
    from the provisioner's own export names (the manifest's `mounts[].export`)."""
    return "${" + _prov_sandboxes.EXPORT_LANE_DIR[lane] + "}"


class TestMcpServersJsonLayout(unittest.TestCase):
    # The three lanes, read off the SHIPPED file: it is rooted at the lane
    # EXPORTS and constant (Claude Code expands `${VAR}` from the process
    # environment; where sandy mounted a lane is nobody's business on this
    # side), so what is pinned is the tail each server reads under its
    # export — `messages` under the inbox and peer lanes, the outbox root —
    # against the router's own leaf names.

    def test_mcp_servers_json_matches_the_routers_lane_leaves(self):
        from router.config import LANE_INBOX, LANE_LEAVES, LANE_OUTBOX, LANE_PEER
        doc = json.loads(_MCP_SERVERS_JSON.read_text(encoding="utf-8"))
        servers = doc["mcpServers"]
        messages = ENV_MSG_DIR and _EXPECTED_TAILS[ENV_MSG_DIR][-1]
        self.assertIn(messages, LANE_LEAVES[LANE_INBOX])
        self.assertIn(messages, LANE_LEAVES[LANE_PEER])
        self.assertEqual(servers["inbox"]["env"]["INBOX_MESSAGE_DIR"],
                         _export(LANE_INBOX) + "/" + messages)
        # The PEER lane's reader. Same binary as `inbox`, different lane —
        # the registration is named for the connector's use (`delegation`),
        # the lane and the wire kind are `peer`.
        self.assertEqual(servers["delegation"]["env"]["INBOX_MESSAGE_DIR"],
                         _export(LANE_PEER) + "/" + messages)
        self.assertEqual(servers["inbox-submit"]["env"]["OUTBOX_DIR"], _export(LANE_OUTBOX))

    def test_the_manifests_create_block_is_the_routers_lane_leaves(self):
        """The provisioner renders `create` from the router's constants —
        DERIVATION pinned, not values: a leaf the router adds or renames
        changes the manifest at the next `install`, and a leaf this side
        added on its own (the outbox's `ext/`, say) fails here by name."""
        from router.config import LANES, LANE_LEAVES
        prov = _prov_sandboxes
        self.assertEqual(tuple(prov.FEATURE_LANES), tuple(LANES))
        self.assertEqual({lane: tuple(leaves) for lane, leaves in prov.FEATURE_LANE_LEAVES.items()},
                         {lane: tuple(LANE_LEAVES[lane]) for lane in LANES})
        policy = {**prov.fp.default_policy(), prov.fp.RECREATE_INTERVAL_KEY: 24}
        create = prov.render_manifest(policy)["create"]
        want = [f"{prov.FEATURE_INSTANCES_SUBDIR}/{prov.MANIFEST_SLUG}/{lane}/{leaf}"
                for lane in LANES for leaf in LANE_LEAVES[lane]]
        self.assertEqual(create, want)
        self.assertNotIn(f"{prov.FEATURE_INSTANCES_SUBDIR}/{prov.MANIFEST_SLUG}/outbox/ext", create,
                         "outbox/ext is the daemon's own (Outcomes.write makedirs it); "
                         "not a leaf the router requires, not created here")


class NoChannelRegistrationTest(unittest.TestCase):
    """The registration carries no `inbox-channel` server: the delivery
    daemon's doorbell is the sole mail-lane wake.

    Pinned in the SHIPPED FILE: an entry for it would register, on the next
    `install --apply`, a binary the connector does not ship — a server
    Claude Code cannot start, in every sandbox."""

    def test_the_shipped_registration_has_no_channel(self):
        doc = json.loads(_MCP_SERVERS_JSON.read_text(encoding="utf-8"))
        self.assertNotIn("inbox-channel", doc["mcpServers"])

    def test_the_shipped_registration_carries_no_development_channel_flag(self):
        text = _MCP_SERVERS_JSON.read_text(encoding="utf-8")
        self.assertNotIn("--dangerously-load-development-channels", text)



class PeerLaneTailsAgreeWithTheRouterTest(RouterTestCase):
    """The peer lane's container-side paths equal the router's own host-side
    derivation, tail for tail — the same guard `_EXPECTED_TAILS` gives the
    mail lane, extended to the tree the delegation lane uses.

    The router requires
    `<root>/peer/{notices,messages}` (its `LANE_LEAVES`) and derives the same
    tails for an authored root; sandy mounts `instances/<slug>/peer`
    read-only and exports the container path as `AMAP_PEER_DIR`; the daemon
    is told `$AMAP_PEER_DIR/{notices,messages}` by the wrapper and the
    `delegation` server is told the messages half under the same export.
    Four independent statements of one layout, and nothing but this test
    makes them agree."""

    def _peer_report(self):
        cfg = self.make_config({"alice": []}, mode="handoff")
        # A fleet_domain is what turns the peer lane on in the router's
        # config; without one `report()["peer"]` is None by design.
        return cfg

    def test_the_daemon_and_the_delegation_server_use_the_routers_peer_tails(self):
        cfg = self._peer_report()
        root = cfg.instances["alice"].root
        # The relay wrapper's path values are derived from sandy's exports,
        # so they are resolved here against a deliberately FOREIGN layout —
        # asserting at a conventional layout would pass even if re-baked. The
        # MCP registration is a constant rooted at the lane exports, so its
        # half is read off the shipped file and compared by TAIL: the two
        # roots differ by construction (`${AMAP_PEER_DIR}` vs its value), and
        # it is the tail under each that must agree.
        layout = {"home": "/home/agent", "inbox": "/mnt/h/inbox",
                  "outbox": "/mnt/h/outbox", "peer": "/mnt/h/peer"}
        env = _wrapper.run_wrapper(layout)[2]
        container_root = "/mnt/h"
        for var, tail in (("AMAP_DELIVERY_PEER_NOTICE_DIR", ("peer", "notices")),
                          ("AMAP_DELIVERY_PEER_MESSAGE_DIR", ("peer", "messages"))):
            got = env[var]
            self.assertTrue(got.startswith(container_root + "/"), got)
            self.assertEqual(got[len(container_root) + 1:].split("/"), list(tail))
            # and the host side, from the router's own root derivation
            self.assertEqual(root.joinpath(*tail).name, tail[-1])

        doc = json.loads(_MCP_SERVERS_JSON.read_text(encoding="utf-8"))
        registered = doc["mcpServers"]["delegation"]["env"]["INBOX_MESSAGE_DIR"]
        # The registration is rooted at the PEER lane's export, the wrapper at
        # the same export's value: the tails under each must agree.
        prefix = _export("peer") + "/"
        self.assertTrue(registered.startswith(prefix), registered)
        self.assertEqual(registered[len(prefix):].split("/"),
                         env["AMAP_DELIVERY_PEER_MESSAGE_DIR"][len(container_root) + 1:].split("/")[1:])


class TestProvisionAgreesWithMcpServersJson(RouterTestCase):
    def test_provision_tails_match_mcp_servers_json_tails(self):
        """The RELATIVE TAILS provision() derives under an instance root
        (host-side; the router test helper's authored `mode="handoff"`) are
        exactly the relative tails `payload/mcp-servers.json` carries under
        the lane exports (container-side) — pinning router
        derivation, provision output, and the shipped MCP registration to
        one structure mechanically, so a change to either side that
        drifts from the other fails HERE."""
        cfg = self.make_config({"alice": []}, mode="handoff")
        root = cfg.instances["alice"].root
        env = provision(cfg, "alice", create=False)

        for env_key, tail in _EXPECTED_TAILS.items():
            derived = Path(env[env_key])
            expected = root.joinpath(*tail)
            self.assertEqual(
                derived, expected,
                f"{env_key}: provision() derived {derived}, expected root/{'/'.join(tail)}",
            )


class TestTheRegistrationCarriesNoAgentId(RouterTestCase):
    def test_provision_still_emits_the_agent_id_and_the_registration_omits_it(self):
        """The router's `provision()` still emits `ENV_AGENT_ID` for a hand-
        wired deployment; this adapter deliberately does not carry it. An
        unset `MAILBOX_AGENT_ID` makes `inbox-submit` OMIT `agent_id` from the
        request and the router binds the sender by its
        drop-box, so nothing per-sandbox is left in the registration — which
        is what lets it be one constant file. Both halves pinned: the router
        emits the key (so this test notices if that changes), and the shipped
        registration carries neither the key nor its old placeholder."""
        cfg = self.make_config({"alice": []}, mode="handoff")
        self.assertEqual(provision(cfg, "alice", create=False)[ENV_AGENT_ID], "alice")
        shipped = json.loads(_MCP_SERVERS_JSON.read_text(encoding="utf-8"))["mcpServers"]
        for name, spec in shipped.items():
            with self.subTest(server=name):
                self.assertNotIn(ENV_AGENT_ID, spec.get("env") or {})
        self.assertNotIn("__REPLACE_WITH", json.dumps(shipped))


class TrustedStateStaysOnThePrivateMountTest(unittest.TestCase):
    """Everything the daemon TRUSTS lives where no router can write.

    The daemon has trusted paths (two claims and the delivery ledger), and
    the rule that places them is stronger than "outside the read-only
    inbound tree":

        the daemon keeps what it trusts where NO ROUTER CAN WRITE.

    The local router mounts the instance trees read-write as the operator,
    so anything under a lane — including the rw `outbox/` — is something a
    router could delete: a deleted claim lets a second consumer onto the
    spool, a deleted ledger replays delivered notices. The connector's
    directory under the agent's home satisfies the rule because the router
    mounts only its state, its config and the feature tree.

    The one deliberate exception is `AMAP_DELIVERY_OUTCOME_DIR`, which is
    under the rw outbox BY DESIGN — outcomes are the connector's side
    channel TO the router (`outbox/ext/<name>/`, the spec's
    connector-owned prefix), not something the daemon trusts."""

    _TRUSTED = ("AMAP_DELIVERY_MAIL_CLAIM", "AMAP_DELIVERY_PEER_CLAIM",
                "AMAP_DELIVERY_STATE_DIR")

    def test_trusted_paths_are_under_the_private_connector_mount(self):
        env = _wrapper.run_wrapper(_wrapper.FOREIGN_LAYOUT)[2]
        install_root = "/home/agent/" + _prov_sandboxes.CONNECTOR_REL
        for var in self._TRUSTED:
            self.assertTrue(
                env[var].startswith(install_root + "/"),
                f"{var}={env[var]!r} is not under the connector install root "
                f"{install_root!r}, which is the only tree no router mounts")

    def test_no_trusted_path_is_under_any_router_writable_tree(self):
        env = _wrapper.run_wrapper(_wrapper.FOREIGN_LAYOUT)[2]
        lanes = "/mnt/h"
        for var in self._TRUSTED:
            self.assertFalse(
                env[var].startswith(lanes + "/"),
                f"{var}={env[var]!r} is under {lanes!r}, which the local router "
                f"mounts read-write — a router could delete it")

    def test_the_outcome_dir_is_the_one_deliberate_exception(self):
        """Stated as an assertion so the exception stays deliberate: if
        outcomes ever move onto the private mount, this test says so rather
        than the rule above quietly covering four paths instead of three."""
        env = _wrapper.run_wrapper(_wrapper.FOREIGN_LAYOUT)[2]
        self.assertTrue(env["AMAP_DELIVERY_OUTCOME_DIR"].startswith(
            "/mnt/h/outbox/ext/"))


    def test_the_chain_lives_ONCE_on_the_feature_payload(self):
        """The written files above are STATE the daemon must be able to write;
        the relay chain is CODE sandy execs out of every agent's ancestry, and
        it must be on a mount the agent cannot write. Different requirements,
        different trees — which is why the chain is not in the loop above.

        ALL of it is on the payload, once per host at
        `$SANDY_HOME/features/amap/payload/`, mounted `:ro` at
        `/opt/sandy/features/amap`: the wrapper, the daemon, its module and
        both MCP binaries."""
        src = Path("/fake/connector/bin")
        payload = _prov_sandboxes.payload_sources(src)
        names = [rel for rel, _s, _x in payload]
        self.assertEqual(names[0], _prov_sandboxes.RELAY_WRAPPER_NAME,
                         "the manifest's entry names the payload's `relay`")
        self.assertIn(_prov_sandboxes.DELIVERY_DAEMON_NAME, names)
        self.assertIn(_prov_sandboxes.DELIVERY_SUPPORT_NAME, names)
        for b in _prov_sandboxes.CONNECTOR_BINARIES:
            self.assertIn(f"{_prov_sandboxes.FEATURE_BIN_SUBDIR}/{b}", names)
        # The manifest's `entry` names the wrapper there — so what sandy
        # supervises is a path under the feature mount, not a file in any sandbox.
        self.assertEqual(_prov_sandboxes.MANIFEST_ENTRY,
                         f"{_prov_sandboxes.FEATURE_PAYLOAD_SUBDIR}/"
                         f"{_prov_sandboxes.RELAY_WRAPPER_NAME}")
        self.assertIn("entry", _prov_sandboxes.ADAPTER_OWNED_KEYS)
        self.assertNotIn("/home/", _prov_sandboxes.MANIFEST_ENTRY)



class TheWildcardTokenIsTheRoutersTest(unittest.TestCase):
    """The one token the router refuses to translate, pinned against the
    ROUTER'S OWN public constant rather than against this repo's copy of it
    (amap-router-local lists `config` in PUBLIC_MODULES, so the import is a
    supported dependency). A pin between two copies on this side proves
    only that this side agrees with itself; this one fails when the token
    moves over there.

    Only the sibling renderer carries the tokens: the manifest is AUTHORED
    (its `feature` section is the policy, in the policy's own spelling) and
    carries no rendered graph — that is the generated sibling `router.json`
    beside it, which the router reads and the manifest never carries."""

    def test_the_lane_names_are_the_routers_constants(self):
        """This adapter names the three lanes in the manifest's `create` and
        `mounts` (sandy creates the directories); the router discovers and
        drains them by the same names (`config.LANES`). One
        source: a rename on either side fails here, by name. The leaf names
        under them are the connector's, pinned elsewhere."""
        from router.config import LANE_INBOX, LANE_OUTBOX, LANE_PEER, LANES
        self.assertEqual(tuple(_prov_sandboxes.FEATURE_LANES), (LANE_INBOX, LANE_PEER, LANE_OUTBOX))
        self.assertEqual(tuple(_prov_sandboxes.FEATURE_LANES), tuple(LANES))
        self.assertEqual(set(_prov_sandboxes.FEATURE_LANE_MODES), set(LANES))

    def test_the_task_graph_wildcard_is_the_routers_constant(self):
        from router.config import MAIL_GRAPH_ALL, TASK_GRAPH_ALL
        self.assertEqual(_prov_sandboxes.ROUTER_TASK_GRAPH_ALL, TASK_GRAPH_ALL)
        self.assertEqual(_prov_sandboxes.ROUTER_MAIL_GRAPH_ALL, MAIL_GRAPH_ALL)
        self.assertNotEqual(TASK_GRAPH_ALL, _prov_sandboxes.fp.TASK_GRAPH_ALL,
                            "the policy's spelling and the router's are different on purpose; "
                            "the renderer translates, the router does not")

    def test_the_sibling_carries_only_keys_the_router_reads(self):
        """The router refuses an unknown key, so the
        renderer's whole vocabulary is pinned against the loader when it is
        importable: a rendering with a domain, a wildcard graph and a mail
        map must load, and the loader's refusal of a stray key must still be
        real (the guard this side's `sibling_diff` names is the router's)."""
        try:
            from router.config import load_obj
        except ImportError:
            self.skipTest("router.config.load_obj is not importable here")
        prov = _prov_sandboxes
        policy = {**prov.fp.default_policy(), prov.fp.RECREATE_INTERVAL_KEY: 24,
                  prov.fp.FLEET_DOMAIN_KEY: "agents.example.org",
                  prov.fp.TASK_GRAPH_KEY: prov.fp.TASK_GRAPH_ALL}
        with __import__("tempfile").TemporaryDirectory() as d:
            home = Path(d)
            doc = prov.render_router_sibling(policy, {"alpha-1": {}, "bravo-2": {}}, home,
                                             home / "router-state")["_doc"]
            load_obj(json.loads(json.dumps(doc)))
            with self.assertRaises(Exception):
                load_obj(json.loads(json.dumps({**doc, "rendered_at": "x"})))


if __name__ == "__main__":
    unittest.main()
