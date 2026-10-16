"""delegation_render: the delegation block from the pinned inventory, and the
no-seed check against the hop pin's own loader and key gate.

The plugin these tests load is a real plugin FILE, loaded by the hop pin's
`transport.load_plugin`, whose peer seam is the router's own published
stand-in (`router/tests/peer_standin.py` in the hop checkout): the same
factories and reason vocabularies as the reviewed plugin, with synthetic
crypto. Its key gate refuses the public keys the file seeds as small order
or non-canonical, which is how these rows reach each refusal. The reviewed
plugin is not in a public repository, so it is not used here. The loader's
owner rule is widened to this user for that file (`trusted_uids`), which
production never does.
"""

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

import delegation_render as dr
import fleet_keys as fk
import hop_router as hp
import partition_activation as pa
from _workspace import HOP_ROUTER_ROOT
from test_hop_render import FLEET_DOMAIN, link, router_doc, spec
from test_hub_runtime import setUpModule, tearDownModule  # noqa: F401 -- the fixture's pins, restored

SMALL = bytes([0x51]) * 32
NON_CANONICAL = bytes([0x52]) * 32

PLUGIN = '''\
import importlib.util as _u
_s = _u.spec_from_file_location("ds_peer_standin", {standin!r})
_m = _u.module_from_spec(_s)
_s.loader.exec_module(_m)
_m.SMALL_ORDER.add(bytes.fromhex({small!r}))
_m.NON_CANONICAL.add(bytes.fromhex({noncanon!r}))
{codec_patch}
globals().update(_m.namespace(api=(3, 4)))
PLUGIN_API = (3, 4)
OPTIONAL_FACTORIES = {{"make_peer_codec": (3, 3), "make_peer_errors": (3, 3)}}


def make_sender(settings, fsops):
    raise RuntimeError("the no-seed check never sends")


def make_intake_reader(settings, fsops):
    raise RuntimeError("the no-seed check never reads intake")


def make_upstream_marker_store(settings, fsops):
    raise RuntimeError("the no-seed check never marks")
'''


def entry(name, domains, n):
    pub = hashlib.sha256(b"key" + bytes([n])).digest()
    return {"name": name, "domains": sorted(domains), "runtime": "amap.router@" + sorted(domains)[0],
            "public_key": pub.hex(), "key_id": hashlib.sha256(pub).hexdigest()}


def inventory(*entries):
    return fk.parse(json.dumps({"schema": fk.SCHEMA, "hosts": sorted(entries, key=lambda e: e["name"])},
                               sort_keys=True, separators=(",", ":")).encode())


class Fixture(unittest.TestCase):

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.t = Path(td.name)
        self.plugin = self.t / "plugin" / "amap_hop_plugin.py"
        self.plugin.parent.mkdir(mode=0o755)
        self.write_plugin()
        self.plugin.chmod(0o444)
        domains = ["beta.internal"]
        text = "".join(d + "\n" for d in domains)
        self.d7 = self.t / "d7.json"
        self.d7.write_text(json.dumps({"delivered_domains": domains,
                                       "sha256": hashlib.sha256(text.encode()).hexdigest(), "attestation": {}}))
        self.d7.chmod(0o444)
        self.key = self.t / "keys" / "signing.key"     # never created unless a row says so
        self.uids = (0, os.getuid())

    def write_plugin(self, codec_patch=""):
        if self.plugin.exists():
            self.plugin.chmod(0o644)
        self.plugin.write_text(PLUGIN.format(standin=str(HOP_ROUTER_ROOT / "router" / "tests" / "peer_standin.py"),
                                             small=SMALL.hex(), noncanon=NON_CANONICAL.hex(), codec_patch=codec_patch))
        self.plugin.chmod(0o444)

    def config(self, hosts, *, inbound=False):
        keys = hp.hop_keys(spec(), link(), FLEET_DOMAIN)
        keys["delivered_domains_file"] = str(self.d7)
        keys["transport_plugin"] = {"path": str(self.plugin),
                                    "sha256": hashlib.sha256(self.plugin.read_bytes()).hexdigest()}
        me, peers = fk.select(hosts, FLEET_DOMAIN, list(link().trusted))
        doc = router_doc(keys)
        doc["delegation"] = dict(dr.render_block(key_path=str(self.key), me=me, peers=peers, inbound=inbound),
                                 partition_verified=pa.LOADER_PLACEHOLDER)
        return doc

    def check(self, doc):
        return dr.no_seed_problem(doc, str(HOP_ROUTER_ROOT), trusted_uids=self.uids)


GOOD = (entry("alpha", [FLEET_DOMAIN], 1), entry("beta", ["beta.internal"], 2))


class RenderTest(Fixture):

    def test_the_block_carries_the_inventory_and_no_token(self):
        me, peers = fk.select(inventory(*GOOD), FLEET_DOMAIN, ["beta.internal"])
        block = dr.render_block(key_path="/opt/ex/keys/signing.key", me=me, peers=peers, inbound=False)
        self.assertEqual(block["signing_key"], {"path": "/opt/ex/keys/signing.key", "key_id": GOOD[0]["key_id"],
                                                "public_key": GOOD[0]["public_key"]})
        self.assertEqual([r["name"] for r in block["runtimes"]], ["beta"])
        self.assertEqual(block["crypto"], {"crypto_backend": "pyca"})
        self.assertNotIn("inbound", block)
        self.assertNotIn("partition_verified", block)
        self.assertIs(dr.render_block(key_path="/k", me=me, peers=peers, inbound=True)["inbound"], True)

    def test_the_hop_link_carries_the_switch_and_nothing_else_new(self):
        self.assertIsNone(link().inbound)
        self.assertIs(link(delegation={"inbound": True}).inbound, True)
        for bad in ({"inbound": 1}, {}):
            with self.assertRaises(hp.HopRenderError):
                link(delegation=bad)
        with self.assertRaises(hp.HopRenderError):
            link(signing=True)

    def test_the_policy_member_is_exactly_inbound(self):
        self.assertIs(dr.parse_policy({"inbound": False}), False)
        for bad in ({}, {"inbound": "yes"}, {"inbound": True, "crypto": "openssl"}, None):
            with self.assertRaises(dr.DelegationRenderError):
                dr.parse_policy(bad)


class NoSeedTest(Fixture):

    def test_a_public_only_table_passes_with_the_key_absent(self):
        self.assertIsNone(self.check(self.config(inventory(*GOOD))))

    def test_a_key_that_is_there_is_never_opened(self):
        for mode in (0o400, 0o000):
            with self.subTest(mode=oct(mode)):
                self.key.parent.mkdir(mode=0o700, exist_ok=True)
                if self.key.exists():
                    self.key.unlink()
                self.key.write_bytes(b"\x00" * 32)
                self.key.chmod(mode)
                self.assertIsNone(self.check(self.config(inventory(*GOOD))))

    def test_the_audit_hook_refuses_an_open_of_the_key(self):
        """The guard that keeps the check from reading the seed, proved by a
        script that tries: it never reaches the router's code."""
        script = dr.NO_SEED_SCRIPT
        self.addCleanup(setattr, dr, "NO_SEED_SCRIPT", script)
        dr.NO_SEED_SCRIPT = script.replace("from router import", "open(key_path, 'rb')\nfrom router import", 1)
        why = self.check(self.config(inventory(*GOOD)))
        self.assertIn("would have opened " + str(self.key), why)

    def test_each_key_gate_refusal_is_reached_before_anything_is_written(self):
        small, noncanon = dict(GOOD[1]), dict(GOOD[1])
        small.update(public_key=SMALL.hex(), key_id=hashlib.sha256(SMALL).hexdigest())
        noncanon.update(public_key=NON_CANONICAL.hex(), key_id=hashlib.sha256(NON_CANONICAL).hexdigest())
        for peer, reason in ((small, "key_small_order"), (noncanon, "key_not_canonical")):
            with self.subTest(reason=reason):
                why = self.check(self.config(inventory(GOOD[0], peer)))
                self.assertTrue(why and why.startswith(reason + ":"), why)

    def test_a_codec_with_the_wrong_candidate_vocabulary_refuses_as_activate_does(self):
        self.write_plugin('_m.PeerCodec.CANDIDATE_REASONS = frozenset({"not_the_set"})')
        why = self.check(self.config(inventory(*GOOD)))
        self.assertTrue(why and why.startswith("codec:") and "CANDIDATE_REASONS" in why, why)

    def test_the_signing_key_id_among_the_peers_refuses(self):
        doc = self.config(inventory(*GOOD))
        doc["delegation"]["runtimes"][0]["keys"].append(
            {"key_id": doc["delegation"]["signing_key"]["key_id"], "public_key": "ab" * 32})
        why = self.check(doc)
        self.assertTrue(why and why.startswith("duplicate_key_id:"), why)

    def test_the_loader_refuses_before_the_gate_runs(self):
        doc = self.config(inventory(*GOOD))
        del doc["delegation"]["partition_verified"]
        why = self.check(doc)
        self.assertTrue(why and why.startswith("config:") and "partition_verified" in why, why)

    def test_a_duplicate_member_refuses_before_the_router_is_called(self):
        raw = json.dumps(self.config(inventory(*GOOD))).encode()
        raw = raw.replace(b'"crypto":', b'"crypto": {"crypto_backend": "pyca"}, "crypto":', 1)
        why = dr.no_seed_problem_bytes(raw, "/nonexistent-checkout", trusted_uids=self.uids)
        self.assertIn("appears twice", why)

    def test_a1_staged_bytes_never_carry_the_placeholder(self):
        doc = self.config(inventory(*GOOD))
        block = doc.pop("delegation")
        block.pop("partition_verified")
        staged = pa.staged_bytes(doc, block, self.check)
        self.assertNotIn(b"partition_verified", staged)
        self.assertNotIn(pa.LOADER_PLACEHOLDER.encode(), staged)


if __name__ == "__main__":
    unittest.main()
