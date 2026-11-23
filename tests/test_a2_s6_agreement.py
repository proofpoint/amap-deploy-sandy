"""install/a2_s6_render restates values this repo's reviewed renderers own, because the installer imports nothing
outside install/. Each restated value is held here to its source, run with the siblings like the rest of tests/."""

import json
import sys
import unittest
from pathlib import Path

import amap_sandy
import delegation_render as dr
import fleet_keys as fk
import fleet_policy as fp
import hop_router as hr
import hub_runtime as hrt

INSTALL = Path(__file__).resolve().parent.parent / "install"
sys.path.insert(0, str(INSTALL))
import a2_s6_env as e6  # noqa: E402
import a2_s6_feature as f6  # noqa: E402
import a2_s6_payload as p6  # noqa: E402
import a2_sandy_caps as caps  # noqa: E402
import a2_s6_render as r6  # noqa: E402
import vm_bootstrap  # noqa: E402

A = "/home/agent"
SANDY = "/home/agent/.sandy"
OWN = "vm1.example.org"
OTHER = {"slug": "router-b", "fleet_domain": "vm2.example.org", "key_id": "router-b-k1", "public_key": "ab" * 32}
RUN = "20261120T224500Z-0123abcd"


def render():
    return r6.router_json(agent_home=A, sandy_home=SANDY, fleet_domain=OWN, relay_uid=1001, run_id=RUN,
                          own_key_id="router-a-k1", own_public_key="cd" * 32, other=dict(OTHER))


class AgreementTest(unittest.TestCase):

    def test_the_base_is_the_sibling_renderers_for_the_alpha2_policy(self):
        policy = {fp.FLEET_DOMAIN_KEY: OWN, fp.TASK_GRAPH_KEY: fp.TASK_GRAPH_ALL}
        base = amap_sandy.render_router_sibling(policy, {}, Path(SANDY), Path(A + "/" + r6.STATE))
        self.assertEqual(base["_warnings"], [])
        doc = render()
        self.assertEqual({k: doc[k] for k in base["_doc"]}, base["_doc"])
        self.assertEqual(r6.TASK_GRAPH_ALL, amap_sandy.ROUTER_TASK_GRAPH_ALL)
        self.assertEqual(r6.CONNECTOR_OUTCOME_IDS, amap_sandy.CONNECTOR_OUTCOME_IDS)

    def test_the_hop_constant_and_plugin_pin_are_hop_routers(self):
        self.assertEqual(r6.CAPS, hr.HOP_CAPS)
        self.assertEqual(r6.VERSION_WRITE, hr.HOP_VERSION_WRITE)
        self.assertEqual(r6.PLUGIN_SHA256, hr.PLUGIN_SHA256)
        self.assertEqual(hr.cap_problems(dict(r6.CAPS), r6.VERSION_WRITE), [])
        self.assertEqual(r6.PLUGIN_PATH, "/" + vm_bootstrap.PLUGIN)

    def test_the_delegation_block_is_delegation_renders_with_the_openssl_choice(self):
        doc = render()
        me = fk.Host(name="router-a", domains=(OWN,), runtime="amap.router@" + OWN, key_id="router-a-k1",
                     public_key="cd" * 32)
        peer = fk.Host(name=OTHER["slug"], domains=(OTHER["fleet_domain"],),
                       runtime="amap.router@" + OTHER["fleet_domain"], key_id=OTHER["key_id"],
                       public_key=OTHER["public_key"])
        block = dr.render_block(key_path=A + "/" + r6.SEED, me=me, peers=[peer], inbound=True,
                                crypto=dr.CRYPTO_OPENSSL)
        got = dict(doc["delegation"])
        self.assertEqual(got.pop("partition_verified"), "partition-" + RUN)
        self.assertEqual(got, block)
        self.assertEqual(dict(r6.CRYPTO_OPENSSL), dr.CRYPTO_OPENSSL)

    def test_every_key_is_in_the_routers_vocabulary(self):
        """amap_sandy's vocabulary is RL's at the deploy pin; the ALPHA-2 pin adds min_sender_age_s and has the hop
        keys (RL's answer 4a844e3a). The hop pin's router is the nearest checkout that carries them."""
        import ast
        src = (Path(hr.hop_checkout()) / "router" / "config.py").read_text(encoding="utf-8")
        keys = None
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.Assign) and [getattr(t, "id", None) for t in node.targets] == ["_TOP_KEYS"]:
                keys = ast.literal_eval(node.value)
        self.assertIsNotNone(keys)
        self.assertLessEqual(set(r6.KEYS) - {"min_sender_age_s"}, set(keys))

    def test_the_env_constants_are_hub_runtimes(self):
        self.assertEqual(e6.ROLE, hrt.ROLE)
        self.assertEqual(e6.AUTH_METHOD, hrt.AUTH_METHOD)
        self.assertEqual((e6.IMAP_PORT, e6.IMAP_MAILBOX), (hrt.IMAP_PORT, hrt.IMAP_MAILBOX))
        self.assertEqual((e6.BUDGET_S, e6.BUDGETS), (hrt.BUDGET_S, tuple(hrt.BUDGETS)))
        self.assertEqual(e6.SWITCHES_OFF, hrt.SWITCHES_OFF)
        self.assertEqual((e6.RECOVERY_ENV, e6.RECOVERY_DAYS), (hrt.RECOVERY_ENV, hrt.RECOVERY_DAYS))
        self.assertEqual(e6.RELAY_LOG_FILE, hrt.RELAY_LOG_FILE)
        self.assertLessEqual(set(e6.ABSENT) - {"OUTBOX_DIR"}, set(hrt.ABSENT))
        self.assertEqual(e6.ABSENT_PREFIXES, hrt.ABSENT_PREFIXES)

    def test_the_sandy_capabilities_are_ones_this_repo_reviewed(self):
        self.assertIn(caps.SCHEMA_VERSION, amap_sandy.SANDY_SCHEMA_VERSIONS)
        self.assertEqual(caps.MANIFEST_KEYS, (amap_sandy.RECEIVES_KEY, amap_sandy.AGENT_WRAPPER_KEY))
        self.assertEqual(caps.RECEIVES_VALUES, (amap_sandy.RECEIVES_CROSS_SESSION,))

    def test_the_login_pins_are_hub_runtimes(self):
        import a2_private
        import importlib
        fresh = importlib.reload(a2_private)
        self.assertEqual(fresh.LOGIN_LOCAL_SHA256, hrt.LOGIN_LOCAL_SHA256)
        self.assertEqual(fresh.LOGIN_DOMAIN_SHA256, hrt.LOGIN_DOMAIN_SHA256)

    def test_the_bytes_are_strict_json(self):
        raw = r6.text(render())
        self.assertEqual(json.loads(raw), render())
        self.assertTrue(raw.endswith(b"}\n"))

    def test_the_feature_manifest_is_amap_sandys_for_the_alpha2_policy(self):
        for domain in ("vm1.internal", "vm2.internal"):
            policy = fp.default_policy()
            policy[fp.FLEET_DOMAIN_KEY] = domain
            want = amap_sandy.manifest_text(policy, receives=True, agent_wrapper=False).encode("utf-8")
            self.assertEqual(f6.text(f6.manifest(fleet_domain=domain)), want)
            self.assertEqual(f6.FEATURE_DIR, amap_sandy.CONTAINER_FEATURE_DIR)

    def test_the_feature_refuses_a_domain_the_lock_would(self):
        for bad in ("a.b.internal", "", None, "Vm1.internal"):
            with self.subTest(bad=bad), self.assertRaises(f6.FeatureRefused):
                f6.manifest(fleet_domain=bad)

    def test_the_feature_refuses_without_the_receives_capability(self):
        for name, value in (("MANIFEST_KEYS", ("agent_wrapper",)), ("RECEIVES_VALUES", ())):
            with self.subTest(name=name):
                old = getattr(caps, name)
                setattr(caps, name, value)
                self.addCleanup(setattr, caps, name, old)
                with self.assertRaises(f6.FeatureRefused):
                    f6.manifest(fleet_domain="vm1.internal")
                setattr(caps, name, old)

    def test_the_payload_is_amap_sandys_payload_sources(self):
        conn = Path("/connector-checkout/bin")
        want = []
        for rel, src, executable in amap_sandy.payload_sources(conn):
            src = Path(src)
            if src.parent == conn:
                want.append((rel, "connector", src.name, executable))
            else:
                self.assertEqual(src.parent, amap_sandy.PAYLOAD_DIR, rel)
                want.append((rel, "installer", src.name, executable))
        self.assertEqual(sorted(p6.PAYLOAD), sorted(want))
        self.assertEqual(p6.INSTALLER_PREFIX, amap_sandy.PAYLOAD_DIR.name)
        self.assertEqual(p6.CONNECTOR_PREFIX, amap_sandy.FEATURE_BIN_SUBDIR)


if __name__ == "__main__":
    unittest.main()
