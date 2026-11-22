"""a2_s6_render: one VM's router.json. The key sets are RL's, measured at its ALPHA-2 pin (RL's answer 90f00634: a
validating config, rc 0 from `peers`; 4a844e3a: the 30-key top-level vocabulary). Agreement with this repo's own
renderers is tests/test_a2_s6_agreement.py."""

import json
import unittest

import a2fix  # noqa: F401  (puts install/ on sys.path)
import a2_s6_render as r6

#: RL 4a844e3a: the top-level vocabulary at its ALPHA-2 pin.
RL_TOP_KEYS = {
    "aliases", "attachment_max_bytes", "attachment_max_count", "attachment_max_total_bytes", "connector_outcome_ids",
    "delegation", "delivered_domains_file", "egress", "fleet_domain", "fleet_hosts", "hop",
    "ingress_dedup_horizon_days", "ingress_quarantine_days", "instances", "instances_dir", "intake_dir", "mail_graph",
    "mail_reply_window_seconds", "min_sender_age_s", "peer_reply_window_seconds", "peer_senders", "peer_sent_prune",
    "peers", "registry_dir", "selected_json", "sender_exposure_window_seconds", "state_dir", "task_graph",
    "transport_plugin", "trusted_fleet_hosts"}
#: RL 90f00634's validating config: the nested key sets.
RL_HOP_KEYS = {"root", "peer_uid", "version_write", "caps", "link"}
RL_CAPS_KEYS = {"document", "request", "attachment", "total"}
RL_DELEGATION_KEYS = {"partition_verified", "signing_key", "runtimes", "crypto", "inbound"}
RL_SIGNING_KEYS = {"path", "key_id", "public_key"}
RL_RUNTIME_KEYS = {"name", "runtime", "domains", "keys"}

OTHER = {"slug": "router-b", "fleet_domain": "vm2.example.org", "key_id": "router-b-k1", "public_key": "ab" * 32}
GOOD = dict(agent_home="/home/agent", sandy_home="/home/agent/.sandy", fleet_domain="vm1.example.org", relay_uid=1001,
            run_id="20261120T224500Z-0123abcd", own_key_id="router-a-k1", own_public_key="cd" * 32)


def render(**kw):
    args = dict(GOOD, other=dict(OTHER))
    args.update(kw)
    return r6.router_json(**args)


class RouterJsonTest(unittest.TestCase):

    def test_the_document(self):
        d = render()
        self.assertEqual(len(RL_TOP_KEYS), 30)
        self.assertLessEqual(set(d), RL_TOP_KEYS)
        self.assertEqual(tuple(d), r6.KEYS)
        self.assertNotIn("delivered_domains_file", d)
        self.assertEqual(d["state_dir"], "/home/agent/.amap-router/state")
        self.assertEqual(d["instances_dir"], "/home/agent/.sandy/features/amap/instances")
        self.assertEqual(d["selected_json"], "/home/agent/.sandy/features/amap/selected.json")
        self.assertEqual(d["fleet_domain"], "vm1.example.org")
        self.assertEqual(d["task_graph"], "all")
        self.assertIs(d["egress"], False)
        self.assertEqual(d["min_sender_age_s"], 0)
        self.assertEqual(d["transport_plugin"], {"path": "/opt/amap-plugin/amap_hop_plugin.py",
                                                 "sha256": r6.PLUGIN_SHA256})
        self.assertEqual(set(d["hop"]), RL_HOP_KEYS)
        self.assertEqual(set(d["hop"]["caps"]), RL_CAPS_KEYS)
        self.assertEqual(d["hop"]["root"], "/home/agent/.amap-hop")
        self.assertEqual(d["hop"]["peer_uid"], 1001)
        self.assertEqual(d["hop"]["link"], r6.LINK)
        self.assertEqual(d["registry_dir"], "/home/agent/.amap-registry")
        self.assertEqual(d["fleet_hosts"], ["vm2.example.org"])
        self.assertEqual(d["trusted_fleet_hosts"], d["fleet_hosts"])
        g = d["delegation"]
        self.assertEqual(set(g), RL_DELEGATION_KEYS)
        self.assertEqual(g["partition_verified"], "partition-20261120T224500Z-0123abcd")
        self.assertEqual(set(g["signing_key"]), RL_SIGNING_KEYS)
        self.assertEqual(g["signing_key"], {"path": "/home/agent/.amap-delegation/seed", "key_id": "router-a-k1",
                                            "public_key": "cd" * 32})
        self.assertEqual(len(g["runtimes"]), 1)
        self.assertEqual(set(g["runtimes"][0]), RL_RUNTIME_KEYS)
        self.assertEqual(g["runtimes"][0], {"name": "router-b", "runtime": "amap.router@vm2.example.org",
                                            "domains": ["vm2.example.org"],
                                            "keys": [{"key_id": "router-b-k1", "public_key": "ab" * 32}]})
        self.assertEqual(g["crypto"], {"crypto_backend": "openssl", "openssl_path": "/usr/bin/openssl"})
        self.assertIs(g["inbound"], True)

    def test_the_bytes(self):
        raw = r6.text(render())
        self.assertEqual(json.loads(raw), render())
        self.assertTrue(raw.endswith(b"}\n") and not raw.endswith(b"\n\n"))
        self.assertEqual(raw, r6.text(render()))
        self.assertLess(raw.index(b'"delegation"'), raw.index(b'"egress"'))

    def test_the_caps_are_not_shared_between_renders(self):
        a = render()
        a["hop"]["caps"]["document"] = 1
        a["delegation"]["crypto"]["openssl_path"] = "/x"
        b = render()
        self.assertEqual(b["hop"]["caps"]["document"], dict(r6.CAPS)["document"])
        self.assertEqual(b["delegation"]["crypto"]["openssl_path"], "/usr/bin/openssl")

    def test_refusals(self):
        bad = [
            dict(agent_home="home/agent"), dict(agent_home="/home/agent/"), dict(agent_home="/home/../agent"),
            dict(agent_home="/home//agent"), dict(sandy_home="/home/agent/./.sandy"), dict(sandy_home=None),
            dict(fleet_domain="VM1.example.org"), dict(fleet_domain="vm1"), dict(fleet_domain="vm1.example.org."),
            dict(relay_uid=0), dict(relay_uid=-1), dict(relay_uid=True), dict(relay_uid="1001"),
            dict(run_id="20261120T224500Z"), dict(own_key_id="-k1"), dict(own_public_key="CD" * 32),
            dict(own_public_key="cd" * 31),
            dict(other=dict(OTHER, slug="Router-b")), dict(other=dict(OTHER, fleet_domain="vm1.example.org")),
            dict(other=dict(OTHER, key_id="router-a-k1")), dict(other=dict(OTHER, public_key="cd" * 32)),
            dict(other=dict(OTHER, public_key="ab" * 33)), dict(other=dict(OTHER, extra=1)),
            dict(other={k: v for k, v in OTHER.items() if k != "key_id"}), dict(other=[OTHER]),
        ]
        for kw in bad:
            with self.subTest(kw=kw):
                with self.assertRaises(r6.RenderRefused):
                    render(**kw)


if __name__ == "__main__":
    unittest.main()
