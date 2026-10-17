"""hop_router: the local router's hop constant and its recorded image.

The hop constant is checked against the router code it will run under: the
hop checkout's own `hoplink.document_floor` recomputes `caps.document`, and
the hop checkout's own loader accepts the constant and refuses a document
cap one byte smaller. Both run in a SEPARATE process with only the hop
checkout on its path, because the primary checkout is also a package named
`router`. Every other value is invented.
"""

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest

import host_setup as hs
import hop_router as hp
import router_health as rh
from _workspace import HOP_ROUTER_ROOT
from test_hub_keys import full_doc as keys_doc
from test_hub_runtime import setUpModule, tearDownModule  # noqa: F401 -- the fixture's pins, restored

IMAGE = {"name": "example.org/hop-router", "digest": "sha256:" + "c" * 64, "commit": "d" * 40}


def spec(**image_over):
    d = keys_doc()
    d[hp.SECTION] = {"image": dict(IMAGE, **image_over), "container": "ex-up"}  # the hub hop's upstream
    return hs.load_spec(d)


def in_hop_checkout(code: str) -> str:
    """`code` run by the hop checkout's router, alone on the path; its stdout."""
    p = subprocess.run([sys.executable, "-I", "-c", f"import sys\nsys.path.insert(0, {str(HOP_ROUTER_ROOT)!r})\n"
                        + textwrap.dedent(code)], capture_output=True, text=True, timeout=120)
    if p.returncode:
        raise AssertionError(p.stderr)
    return p.stdout.strip()


class ConstantTest(unittest.TestCase):
    def test_the_document_cap_is_the_hop_checkouts_own_floor(self):
        caps = hp.caps()
        got = in_hop_checkout(f"""
            from router import hoplink
            from router.config import (ATTACHMENT_MAX_COUNT_DEFAULT as C, ATTACHMENT_MAX_BYTES_DEFAULT as F,
                                       ATTACHMENT_MAX_TOTAL_BYTES_DEFAULT as T)
            print(C, F, hoplink.document_floor(request_cap={caps['request']}, count_cap=C,
                                       file_cap=min({caps['attachment']}, F), total_cap=min({caps['total']}, T),
                                       version_write={hp.HOP_VERSION_WRITE}))
            """)
        count, file_, floor = map(int, got.split())
        self.assertEqual((count, file_), (hp.FLOOR_COUNT_CAP, hp.FLOOR_FILE_CAP))
        self.assertEqual(floor, caps["document"])

    def test_the_hop_checkouts_loader_accepts_the_constant_and_refuses_one_byte_less(self):
        doc = {"state_dir": "/srv/x/state", "instances": {"a": {"handoff_dir": "/srv/x/a"}},
               "registry_dir": "/srv/x/reg", "transport_plugin": {"path": "/srv/x/p.py", "sha256": hp.PLUGIN_SHA256},
               "hop": {"root": "/srv/x/hop", "peer_uid": 2102, "version_write": hp.HOP_VERSION_WRITE,
                       "caps": hp.caps()}}
        got = in_hop_checkout(f"""
            import json
            from router.config import load_obj
            doc = json.loads({json.dumps(json.dumps(doc))})
            out = []
            for less in (0, 1):
                d = json.loads(json.dumps(doc))
                d["hop"]["caps"]["document"] -= less
                try:
                    load_obj(d)
                    out.append("accepted")
                except Exception as e:
                    out.append("refused:" + str(e).split(":")[0])
            print(" ".join(out))
            """)
        self.assertEqual(got, "accepted refused:config.hop.caps.document")

    def test_the_constant_meets_the_hub_routers_bounds_and_each_bound_bites(self):
        self.assertEqual(hp.cap_problems(hp.caps(), hp.HOP_VERSION_WRITE), [])
        for key, value, words in (("request", hp.REQUEST_CAP_MAX + 1, "caps.request"),
                                  ("attachment", hp.ATTACHMENT_CAP_MIN - 1, "caps.attachment"),
                                  ("attachment", hp.HUB_ATTACH_MAX_BYTES + 1, "caps.attachment"),
                                  ("total", hp.HUB_ATTACH_MAX_TOTAL + 1, "caps.total")):
            with self.subTest(key=key, value=value):
                bad = hp.cap_problems(dict(hp.caps(), **{key: value}), hp.HOP_VERSION_WRITE)
                self.assertTrue(any(words in p for p in bad), bad)
        self.assertTrue(any("version_write" in p for p in hp.cap_problems(hp.caps(), 2)),
                        "a hop contract other than 1 is a problem")

    def test_the_reviewed_values(self):
        self.assertEqual(hp.caps(), {"document": 23418699, "request": 1048576, "attachment": 1048576,
                                     "total": 20971520})
        self.assertEqual(hp.HOP_VERSION_WRITE, 1)


class PlanTest(unittest.TestCase):
    def test_the_plan_says_which_checkout_its_root_steps_run_from(self):
        """HOST's condition: root runs host_steps.py from the checkout that
        printed the plan, so the plan says it must be one no sandbox can write."""
        lines = hs.render_plan(spec())
        self.assertTrue(lines[0].startswith("# Each line is one step; nothing here has run."))
        self.assertIn("a checkout no sandbox mounts read-write", lines[1])
        self.assertIn("never from an agent's workspace", lines[1])


class LoadTest(unittest.TestCase):
    def test_the_section_loads(self):
        r = spec().router
        self.assertEqual((r.image_name, r.image_commit), (IMAGE["name"], IMAGE["commit"]))

    def test_refusals(self):
        for over, words in (({"name": "amap-router-local"}, "factory router"),
                            ({"name": "example.org/amap-router-local"}, "factory router"),
                            ({"digest": "sha256:abc"}, "digest"), ({"commit": "abc"}, "full commit"),
                            ({"extra": 1}, "exactly name")):
            with self.subTest(over=over):
                with self.assertRaises(hs.SpecError) as e:
                    spec(**over)
                self.assertIn(words, str(e.exception))


class ChecksTest(unittest.TestCase):
    def results(self, s, pin):
        return {c.claim.split(" ")[0] + c.claim.split(" ")[-1]: c.result for c in hp.checks(s, pin=pin)}

    def by_claim(self, s, pin, fragment):
        [c] = [c for c in hp.checks(s, pin=pin) if fragment in c.claim]
        return c.result

    def test_the_image_must_be_built_from_the_hop_pin(self):
        s = spec()
        self.assertEqual(self.by_claim(s, IMAGE["commit"], "built from the hop pin"), rh.PASS)
        self.assertEqual(self.by_claim(s, "e" * 40, "built from the hop pin"), rh.FAIL)
        self.assertEqual(self.by_claim(s, rh.Unresolved("no siblings.json"), "built from the hop pin"), rh.UNKNOWN)

    def test_the_pin_is_siblings_jsons_hop_entry(self):
        pins = [{"name": "amap-router-local", "commit": "1" * 40},
                {"name": "amap-router-local", "commit": "2" * 40, "dir": hp.HOP_PIN_DIR}]
        self.assertEqual(hp.hop_pin(lambda: pins), "2" * 40)
        self.assertIsInstance(hp.hop_pin(lambda: pins[:1]), rh.Unresolved)
        self.assertIsInstance(hp.hop_pin(lambda: pins + pins[1:]), rh.Unresolved)
        live = hp.hop_pin()
        self.assertFalse(isinstance(live, rh.Unresolved), "the repository's siblings.json has the hop pin")

    def test_the_constant_is_versioned_with_the_plugin(self):
        s = spec()
        self.assertNotEqual(s.overlay_pin.get("sha256"), hp.PLUGIN_SHA256, "the fixture pins another plugin")
        self.assertEqual(self.by_claim(s, IMAGE["commit"], "reviewed for this transport plugin"), rh.FAIL)
        import dataclasses
        moved = dataclasses.replace(s, overlay_pin=dict(s.overlay_pin, sha256=hp.PLUGIN_SHA256))
        self.assertEqual(self.by_claim(moved, IMAGE["commit"], "reviewed for this transport plugin"), rh.PASS)
        other = dataclasses.replace(s, overlay_pin=dict(s.overlay_pin, sha256="0" * 64))
        self.assertEqual(self.by_claim(other, IMAGE["commit"], "reviewed for this transport plugin"), rh.FAIL)
        none = dataclasses.replace(s, overlay_pin=None)
        self.assertEqual(self.by_claim(none, IMAGE["commit"], "reviewed for this transport plugin"), rh.UNKNOWN)

    def test_host_verify_runs_the_router_checks(self):
        calls = []
        orig = hs.hp.checks
        self.addCleanup(setattr, hs.hp, "checks", orig)
        hs.hp.checks = lambda s, **k: calls.append(k) or []
        for name in ("verify_roots", "verify_overlay", "verify_containers", "verify_mounts", "verify_openssl",
                     "verify_umasks", "verify_groups", "secret_checks"):
            self.addCleanup(setattr, hs, name, getattr(hs, name))
            setattr(hs, name, lambda *a, **k: [])
        for mod in (hs.hr, hs.hk):
            self.addCleanup(setattr, mod, "checks", mod.checks)
            mod.checks = lambda *a, **k: []
        import dataclasses
        s = dataclasses.replace(spec(), runtimes=[])
        hs.checks(s, production=False, router={"pin": "x"})
        self.assertEqual(calls, [{"pin": "x"}])


if __name__ == "__main__":
    unittest.main()
