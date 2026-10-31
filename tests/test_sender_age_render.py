"""The policy's `min_sender_age_s` rendered into router [1]'s router.json.

The hop pin's router enforces a top-level `min_sender_age_s` (an int from 0
to one year, a bool refused); the primary pin's router has no such key and
refuses it as unknown. So the key is rendered only into a configuration the
hop pin's loader validates, the hop keys' and the registry render's, and a
host whose router is the primary pin's renders it nowhere. The real hop
loader is the checkout at the hop pin (`_workspace.HOP_ROUTER_ROOT`). Every
other value is invented.
"""

import argparse
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

import amap_sandy as prov
import fleet_policy as fp
import host_adapter as ha
import hop_router as hp
from _workspace import HOP_ROUTER_ROOT

KEY = fp.MIN_SENDER_AGE_KEY
IDS = {"interface": "example.adapter/1", "module": "example_host", "operator_module": "example_host.ops",
       "name_schema": "example.name/1"}


def overlay(t: Path, **section) -> Path:
    p = t / "overlay.json"
    p.write_text(json.dumps({ha.OVERLAY_SECTION: dict(IDS, **section)}))
    return p


class SenderAgeKeyTest(unittest.TestCase):

    def test_absent_renders_nothing(self):
        self.assertEqual(prov.sender_age_key({}), {})

    def test_the_known_answers(self):
        for age in (0, 86400, fp.MIN_SENDER_AGE_MAX_S):
            with self.subTest(age=age):
                self.assertEqual(prov.sender_age_key({KEY: age}), {KEY: age})

    def test_a_bool_is_refused(self):
        for age in (True, False):
            with self.subTest(age=age):
                with self.assertRaisesRegex(prov.ProvisionError, "not a whole number of seconds"):
                    prov.sender_age_key({KEY: age})

    def test_other_shapes_are_refused(self):
        for age in (-1, fp.MIN_SENDER_AGE_MAX_S + 1, 1.0, "0", None):
            with self.subTest(age=age):
                with self.assertRaises(prov.ProvisionError):
                    prov.sender_age_key({KEY: age})


class RegistryKeysTest(unittest.TestCase):
    """registry_router_keys carries the key beside registry_dir."""

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.t = Path(os.path.realpath(td.name))
        self.reg = self.t / "registry"
        self.reg.mkdir()
        self.ov = overlay(self.t, directory=str(self.reg))
        self.addCleanup(setattr, hp, "checkout_problems", hp.checkout_problems)
        hp.checkout_problems = lambda path, pin: []

    def test_zero_and_the_default_are_rendered(self):
        for age in (0, 86400):
            with self.subTest(age=age):
                self.assertEqual(prov.registry_router_keys({hp.REGISTRY_POLICY_KEY: True, KEY: age}, self.ov, None),
                                 ({"registry_dir": str(self.reg), KEY: age}, []))

    def test_absent_renders_registry_dir_only(self):
        self.assertEqual(prov.registry_router_keys({hp.REGISTRY_POLICY_KEY: True}, self.ov, None),
                         ({"registry_dir": str(self.reg)}, []))

    def test_a_bool_is_a_problem_and_renders_nothing(self):
        keys, problems = prov.registry_router_keys({hp.REGISTRY_POLICY_KEY: True, KEY: True}, self.ov, None)
        self.assertIsNone(keys)
        self.assertTrue(problems and KEY in problems[0], problems)


class HopKeysTest(unittest.TestCase):
    """hop_router_keys carries the key beside the hop keys."""

    def setUp(self):
        self.hop = {"transport_plugin": {"path": "/x/plugin.py", "sha256": "0" * 64}, "hop": {"links": []}}
        for (mod, name), value in {
                (hp, "parse_hop_link"): lambda policy: object(),
                (prov.hsu, "read_spec"): lambda spec, overlay: {},
                (prov.hsu, "load_spec"): lambda raw: argparse.Namespace(keys=None),
                (hp, "hop_keys"): lambda spec, link, domain: dict(self.hop),
                (hp, "plugin_problems"): lambda path, sha: [],
                (hp, "checkout_problems"): lambda path, pin: [],
                (hp, "state_problems"): lambda state_dir, keys: []}.items():
            self.addCleanup(setattr, mod, name, getattr(mod, name))
            setattr(mod, name, value)

    def test_the_key_joins_the_hop_keys(self):
        keys, problems = prov.hop_router_keys({KEY: 0}, Path("/x/state"), None)
        self.assertEqual(problems, [])
        self.assertEqual(keys, dict(self.hop, **{KEY: 0}))

    def test_absent_leaves_the_hop_keys_alone(self):
        keys, problems = prov.hop_router_keys({}, Path("/x/state"), None)
        self.assertEqual((keys, problems), (self.hop, []))

    def test_a_bool_is_a_problem(self):
        keys, problems = prov.hop_router_keys({KEY: False}, Path("/x/state"), None)
        self.assertIsNone(keys)
        self.assertTrue(problems and KEY in problems[0], problems)


class HopLoaderTest(unittest.TestCase):
    """The hop pin's own loader accepts the rendered key and refuses a bool:
    the router's acceptance is the router's code, not an assumption here."""

    def doc(self, age):
        return {"state_dir": "/srv/x/state", "instances_dir": "/srv/x/instances",
                "selected_json": "/srv/x/selected.json", "connector_outcome_ids": ["claude-code", "codex"],
                "fleet_domain": "sandy.alpha.internal", "task_graph": "all", "registry_dir": "/srv/registry",
                KEY: age}

    def test_zero_and_the_default_load(self):
        for age in (0, 86400):
            with self.subTest(age=age):
                self.assertIsNone(hp.validate_with_hop_router(self.doc(age), str(HOP_ROUTER_ROOT)))

    def test_a_bool_is_refused_by_the_router(self):
        refused = hp.validate_with_hop_router(self.doc(True), str(HOP_ROUTER_ROOT))
        self.assertIsNotNone(refused)
        self.assertIn(KEY, refused)


class RenderTest(unittest.TestCase):
    """install's real run_render_router: the key reaches the written file
    exactly where the hop loader validates, and nowhere else."""

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.t = Path(os.path.realpath(td.name))
        self.reg = self.t / "registry"
        self.reg.mkdir()
        self.ov = overlay(self.t, directory=str(self.reg))
        self.hop_validated, self.primary_validated = [], []
        base = {"state_dir": str(self.t / "state"), "instances_dir": str(self.t / "inst"),
                "selected_json": str(self.t / "sel" / "selected.json")}
        for (mod, name), value in {
                (prov, "router_sibling_path"): lambda home: self.t / "router.json",
                (prov, "load_membership"): lambda home, boxes: {},
                (prov, "sibling_state_dir"): lambda home, explicit: self.t / "state",
                (prov, "render_router_sibling"): lambda *a, **k: {"_doc": dict(base), "_warnings": []},
                (prov, "install_router_state_dir"): lambda state_dir, dry_run: "ok",
                (prov, "hop_router_keys"): lambda *a, **k: (None, []),
                (prov, "validate_with_router"): lambda doc: self.primary_validated.append(doc) or None,
                (hp, "validate_with_hop_router"): lambda doc, checkout: self.hop_validated.append(doc) or None,
                (hp, "checkout_problems"): lambda path, pin: []}.items():
            self.addCleanup(setattr, mod, name, getattr(mod, name))
            setattr(mod, name, value)

    def render(self, policy):
        args = argparse.Namespace(state_dir=None, overlay=str(self.ov), decommission_hop=False)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            rc = prov.run_render_router(args, self.t, [], policy, apply=True)
        return rc, out.getvalue()

    def test_a_registry_host_writes_the_key_for_the_hop_loader(self):
        for age in (0, 86400):
            with self.subTest(age=age):
                self.hop_validated.clear()
                rc, said = self.render({hp.REGISTRY_POLICY_KEY: True, KEY: age})
                self.assertEqual(rc, 0, said)
                written = json.loads((self.t / "router.json").read_text())
                self.assertEqual(written.get(KEY), age)
                self.assertNotIsInstance(written.get(KEY), bool)
                self.assertEqual([d.get(KEY) for d in self.hop_validated], [age])
                self.assertEqual(self.primary_validated, [])

    def test_a_primary_router_host_renders_no_key(self):
        """The policy carries the key (policy_checks requires it), but the
        primary pin's router would refuse it: nothing is rendered."""
        rc, said = self.render({KEY: 0})
        self.assertEqual(rc, 0, said)
        written = json.loads((self.t / "router.json").read_text())
        self.assertNotIn(KEY, written)
        self.assertEqual([KEY in d for d in self.primary_validated], [False])
        self.assertEqual(self.hop_validated, [])

    def test_a_bool_writes_nothing(self):
        rc, said = self.render({hp.REGISTRY_POLICY_KEY: True, KEY: True})
        self.assertEqual(rc, 2, said)
        self.assertIn(KEY, said)
        self.assertFalse((self.t / "router.json").exists())


class VerifyTest(unittest.TestCase):
    """verify compares the file with the same render, so the key's absence
    on a registry host is drift."""

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.t = Path(os.path.realpath(td.name))
        self.reg = self.t / "registry"
        self.reg.mkdir()
        self.ov = overlay(self.t, directory=str(self.reg))
        self.base = {"state_dir": str(self.t / "s")}
        for (mod, name), value in {
                (prov, "render_router_sibling"): lambda *a, **k: {"_doc": dict(self.base), "_warnings": []},
                (prov, "router_sibling_path"): lambda home: self.t / "router.json",
                (hp, "checkout_problems"): lambda path, pin: []}.items():
            self.addCleanup(setattr, mod, name, getattr(mod, name))
            setattr(mod, name, value)

    def verify(self, policy, on_disk):
        (self.t / "router.json").write_text(json.dumps(on_disk, indent=2) + "\n")
        return prov.verify_router_sibling(self.t, policy, {}, self.t / "s", {}, self.ov)

    def test_the_file_must_carry_the_key(self):
        policy = {hp.REGISTRY_POLICY_KEY: True, KEY: 0}
        self.assertEqual(self.verify(policy, dict(self.base, registry_dir=str(self.reg), **{KEY: 0})), [])
        got = self.verify(policy, dict(self.base, registry_dir=str(self.reg)))
        self.assertTrue(got and "drift" in got[0], got)
        self.assertTrue(any(f"+ {KEY}: 0" in g for g in got), got)

    def test_a_changed_value_is_named(self):
        policy = {hp.REGISTRY_POLICY_KEY: True, KEY: 0}
        got = self.verify(policy, dict(self.base, registry_dir=str(self.reg), **{KEY: 86400}))
        self.assertTrue(any(f"~ {KEY} 86400 -> 0" in g for g in got), got)

    def test_the_key_is_not_called_unknown_to_the_router(self):
        got = prov.sibling_diff(dict(self.base, **{KEY: 0}), dict(self.base, **{KEY: 0}))
        self.assertEqual(got, [])


if __name__ == "__main__":
    unittest.main()
