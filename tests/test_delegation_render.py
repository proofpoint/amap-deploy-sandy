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

    def config(self, hosts, *, inbound=False, fleet_domain=FLEET_DOMAIN, trusted=None, hub=None):
        lk = link() if trusted is None else link(trusted_fleet_hosts=trusted)
        keys = hp.hop_keys(spec(**(hub or {})), lk, fleet_domain)
        keys["delivered_domains_file"] = str(self.d7)
        keys["transport_plugin"] = {"path": str(self.plugin),
                                    "sha256": hashlib.sha256(self.plugin.read_bytes()).hexdigest()}
        me, peers = fk.select(hosts, fleet_domain, list(lk.trusted))
        doc = router_doc(keys)
        doc["fleet_domain"] = fleet_domain
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

    def test_each_host_renders_the_other_as_its_one_peer(self):
        hosts = inventory(*GOOD)
        for domain, trusted, mine, theirs in ((FLEET_DOMAIN, ["beta.internal"], GOOD[0], GOOD[1]),
                                              ("beta.internal", [FLEET_DOMAIN], GOOD[1], GOOD[0])):
            with self.subTest(host=mine["name"]):
                me, peers = fk.select(hosts, domain, trusted)
                block = dr.render_block(key_path="/k", me=me, peers=peers, inbound=False)
                self.assertEqual(block["signing_key"]["key_id"], mine["key_id"])
                self.assertEqual(block["runtimes"], [{"name": theirs["name"], "runtime": theirs["runtime"],
                                                      "domains": theirs["domains"],
                                                      "keys": [{"key_id": theirs["key_id"],
                                                                "public_key": theirs["public_key"]}]}])

    def test_a_block_with_no_peer_runtime_refuses_at_render(self):
        me = inventory(GOOD[0])[0]
        with self.assertRaises(dr.DelegationRenderError) as cm:
            dr.render_block(key_path="/k", me=me, peers=(), inbound=False)
        self.assertIn("no peer runtime", str(cm.exception))

    def test_this_host_is_never_rendered_as_its_own_peer(self):
        me = inventory(*GOOD)[0]
        with self.assertRaises(dr.DelegationRenderError) as cm:
            dr.render_block(key_path="/k", me=me, peers=(me,), inbound=False)
        self.assertIn("own signing entry", str(cm.exception))

    def test_a_projection_that_is_not_the_peers_one_key_refuses(self):
        me, peers = fk.select(inventory(*GOOD), FLEET_DOMAIN, ["beta.internal"])
        orig = fk.Host.table_entry
        self.addCleanup(setattr, fk.Host, "table_entry", orig)
        two = {"key_id": "a" * 64, "public_key": "b" * 64}
        for label, change, words in (
                ("no key", lambda e: e.update(keys=[]), "exactly its one inventory key"),
                ("two keys", lambda e: e["keys"].append(two), "exactly its one inventory key"),
                ("malformed key", lambda e: e["keys"][0].pop("public_key"), "exactly its one inventory key"),
                ("another key", lambda e: e["keys"][0].update(two), "exactly its one inventory key"),
                ("another runtime", lambda e: e.update(runtime="amap.router@gamma.internal"), "runtime and domains"),
                ("other domains", lambda e: e.update(domains=["gamma.internal"]), "runtime and domains")):
            with self.subTest(label):
                def mutated(host, change=change):
                    e = orig(host)
                    change(e)
                    return e
                fk.Host.table_entry = mutated
                with self.assertRaises(dr.DelegationRenderError) as cm:
                    dr.render_block(key_path="/k", me=me, peers=peers, inbound=False)
                self.assertIn(words, str(cm.exception))

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

    def test_both_hosts_renderings_pass_through_the_routers_input_and_the_gate(self):
        """One inventory, as the crossing has it: each router's domain is the
        `<label>.internal` the other trusts, and each host's rendering passes
        the router's loader, its key_table_input and the gate. The hub section
        is the fixture's own, which only the hop keys read; its fleet_hosts is
        the one other host, so each side's own domain stays outside it."""
        hosts = inventory(entry("beta", ["beta.internal"], 1), entry("gamma", ["gamma.internal"], 2))
        for label, other in (("beta", "gamma"), ("gamma", "beta")):
            domain, other = label + ".internal", other + ".internal"
            with self.subTest(host=label):
                doc = self.config(hosts, fleet_domain=domain, trusted=[other], hub={"fleet_hosts": [other]})
                self.assertEqual([r["domains"] for r in doc["delegation"]["runtimes"]], [[other]])
                self.assertIsNone(self.check(doc))

    def test_an_empty_or_keyless_peer_table_refuses(self):
        """The router's loader accepts both shapes; the gate would load each
        as a table that verifies nothing."""
        second = entry("gamma", ["gamma.internal"], 3)
        for label, change, reason in (
                ("no runtime", lambda d: d.update(runtimes=[]), "no_peer"),
                ("no key", lambda d: d["runtimes"][0].update(keys=[]), "key_malformed"),
                ("two keys", lambda d: d["runtimes"][0]["keys"].append(
                    {"key_id": second["key_id"], "public_key": second["public_key"]}), "key_malformed")):
            with self.subTest(label):
                doc = self.config(inventory(*GOOD))
                change(doc["delegation"])
                why = self.check(doc)
                self.assertTrue(why and why.startswith(reason + ":"), why)

    def test_a_gate_that_drops_or_alters_a_peer_key_refuses(self):
        """A plugin whose key gate loads without error but returns a table
        missing or misbinding a configured key: the check selects every one."""
        wrap = ('_orig = _m.load_key_table\n'
                'def _patched(peers):\n'
                '    t = _orig(peers)\n'
                '    for k in [k for k in t._keys.values() if k.runtime != "amap.router@" + {own!r}]:\n'
                '        {change}\n'
                '    return t\n'
                '_m.PeerCodec.load_key_table = staticmethod(_patched)')
        for label, change, reason in (
                ("dropped", "del t._keys[k.key_id]", "peer_key_unselectable"),
                ("other bytes", "k.public_key = bytes(32)", "peer_key_mismatch"),
                ("other runtime", "k.runtime = 'amap.router@gamma.internal'", "peer_key_mismatch"),
                ("other domains", "k.domains = ('gamma.internal',)", "peer_key_mismatch")):
            with self.subTest(label):
                self.write_plugin(wrap.format(own=FLEET_DOMAIN, change=change))
                why = self.check(self.config(inventory(*GOOD)))
                self.assertTrue(why and why.startswith(reason + ":"), why)

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
        # The peer's one key is replaced, not joined: a second key is refused
        # first, by the one-key rule.
        doc = self.config(inventory(*GOOD))
        doc["delegation"]["runtimes"][0]["keys"] = [
            {"key_id": doc["delegation"]["signing_key"]["key_id"], "public_key": "ab" * 32}]
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
