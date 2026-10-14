"""The hop renderer's router: siblings.json's temporary second pin of
amap-router-local, checked out at that commit beside the main router.

These read the real checkout that `amap-siblings.py --apply` made (CI runs it
before the suite), so they fail, never skip, without it: the hop renderer is
validated against exactly this commit.
"""

import subprocess
import unittest

import _workspace
import siblings

#: The keys the hop deployment's local-router rendering sets. The main pin's router has
#: none of the hop ones, which is why the second pin exists.
HOP_KEYS = ("delivered_domains_file", "fleet_hosts", "trusted_fleet_hosts", "registry_dir",
            "intake_dir", "version_write", "peer_uid", "caps")


def hop_pin():
    return next(p for p in siblings.load_pins() if p["name"] == "amap-router-local" and "dir" in p)


class HopRouterCheckoutTest(unittest.TestCase):
    def test_the_checkout_is_at_the_hop_pin(self):
        root = _workspace.HOP_ROUTER_ROOT
        head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True,
                              text=True)
        self.assertEqual(head.returncode, 0, f"no checkout at {root}: run amap-siblings.py --apply")
        self.assertEqual(head.stdout.strip(), hop_pin()["commit"])

    def test_its_config_loader_names_every_key_the_hop_rendering_sets(self):
        text = (_workspace.HOP_ROUTER_ROOT / "router" / "config.py").read_text(encoding="utf-8")
        self.assertEqual([k for k in HOP_KEYS if f'"{k}"' not in text], [])

    def test_the_main_router_pin_is_a_different_commit(self):
        main = siblings.primary(siblings.load_pins(), "amap-router-local")
        self.assertNotEqual(main["commit"], hop_pin()["commit"])


if __name__ == "__main__":
    unittest.main()
