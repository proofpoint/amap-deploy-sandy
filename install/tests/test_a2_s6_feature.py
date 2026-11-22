"""a2_s6_feature: one VM's amap feature manifest. Byte agreement with this repo's own renderer
(amap_sandy.manifest_text, default policy with the VM's fleet domain) is tests/test_a2_s6_agreement.py; this
holds the refusals and the per-VM values, which that test cannot reach from the installer's own suite."""

import json
import unittest

import a2fix  # noqa: F401  (puts install/ on sys.path)
import a2_sandy_caps as caps
import a2_s6_feature as f6


class FeatureTest(unittest.TestCase):

    def test_the_vms_domain_is_the_policys_and_the_export(self):
        for dom in ("vm1.internal", "vm2.internal"):
            doc = f6.manifest(fleet_domain=dom)
            self.assertEqual(doc["feature"]["fleet_domain"], dom)
            self.assertEqual(doc["expose"], {"AMAP_FLEET_DOMAIN": dom})

    def test_receives_cross_session_is_rendered(self):
        self.assertEqual(f6.manifest(fleet_domain="vm1.internal")["receives"], ["cross_session"])

    def test_the_policy_is_all_with_no_deny_and_no_mail_lane(self):
        feat = f6.manifest(fleet_domain="vm1.internal")["feature"]
        self.assertEqual((feat["task_graph"], feat["task_deny"], feat["peers"], feat["default_peers"]),
                         ("ALL", [], {}, []))

    def test_the_lane_modes(self):
        mounts = {m["name"]: m["mode"] for m in f6.manifest(fleet_domain="vm1.internal")["mounts"]}
        self.assertEqual(mounts, {"payload": "ro", "inbox": "ro", "peer": "ro", "outbox": "rw", "roster": "ro"})

    def test_a_domain_the_lock_refuses_is_refused(self):
        for bad in ("a.b.internal", "vm1.example.org", "", None, "Vm1.internal"):
            with self.subTest(bad=bad), self.assertRaises(f6.FeatureRefused):
                f6.manifest(fleet_domain=bad)

    def test_no_receives_capability_refuses(self):
        for name, value in (("MANIFEST_KEYS", ("agent_wrapper",)), ("RECEIVES_VALUES", ())):
            with self.subTest(name=name):
                old = getattr(caps, name)
                setattr(caps, name, value)
                try:
                    with self.assertRaises(f6.FeatureRefused):
                        f6.manifest(fleet_domain="vm1.internal")
                finally:
                    setattr(caps, name, old)

    def test_the_bytes_are_indented_json_with_a_newline(self):
        doc = f6.manifest(fleet_domain="vm1.internal")
        raw = f6.text(doc)
        self.assertEqual(json.loads(raw), doc)
        self.assertEqual(raw, (json.dumps(doc, indent=2) + "\n").encode())
        self.assertTrue(raw.startswith(b'{\n  "schema": 1,'))


if __name__ == "__main__":
    unittest.main()
