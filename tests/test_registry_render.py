"""`router_registry`: the policy key that renders `registry_dir` on a host
with no hop link. The hop pin's loader accepts that config (RL measured
registry state ok and a generation per registered instance on the same
shape); the value is the overlay's `registry.directory`, never defaulted;
a hop link's own registry_dir must be the same directory; and without the
key the render is exactly what it was. Every value is invented.
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
import host_adapter as ha
import hop_router as hp
from _workspace import HOP_ROUTER_ROOT

IDS = {"interface": "example.adapter/1", "module": "example_host", "operator_module": "example_host.ops",
       "name_schema": "example.name/1"}


def overlay(t: Path, **section) -> Path:
    p = t / "overlay.json"
    p.write_text(json.dumps({ha.OVERLAY_SECTION: dict(IDS, **section)}))
    return p


class KeysTest(unittest.TestCase):
    """registry_router_keys alone, the hop checkout's own check stubbed."""

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.t = Path(os.path.realpath(td.name))
        self.reg = self.t / "registry"
        self.reg.mkdir()
        self.addCleanup(setattr, hp, "checkout_problems", hp.checkout_problems)
        hp.checkout_problems = lambda path, pin: []
        self.on = {hp.REGISTRY_POLICY_KEY: True}

    def keys(self, policy, ov, hop=None):
        return prov.registry_router_keys(policy, ov, hop)

    def test_the_overlay_directory_is_rendered(self):
        self.assertEqual(self.keys(self.on, overlay(self.t, directory=str(self.reg))),
                         ({"registry_dir": str(self.reg)}, []))

    def test_without_the_key_nothing_is_rendered_or_read(self):
        self.assertEqual(self.keys({}, None), (None, []))

    def test_only_true_turns_it_on(self):
        for value in (False, "true", 1, None):
            with self.subTest(value=value):
                keys, problems = self.keys({hp.REGISTRY_POLICY_KEY: value}, overlay(self.t, directory=str(self.reg)))
                self.assertIsNone(keys)
                self.assertTrue(problems and "must be true" in problems[0], problems)

    def test_the_directory_is_never_defaulted(self):
        keys, problems = self.keys(self.on, overlay(self.t))
        self.assertIsNone(keys)
        self.assertTrue(problems and "never defaulted" in problems[0], problems)
        keys, problems = self.keys(self.on, None)
        self.assertIsNone(keys)
        self.assertIn("no deployment overlay", problems[0])

    def test_a_second_spelling_is_refused(self):
        link = self.t / "link"
        link.symlink_to(self.reg)
        for spelled in (str(link), str(self.reg) + "/", str(self.t / "x" / ".." / "registry")):
            with self.subTest(spelled=spelled):
                keys, problems = self.keys(self.on, overlay(self.t, directory=spelled))
                self.assertIsNone(keys)
                self.assertIn("physical", problems[0])

    def test_a_missing_directory_is_refused(self):
        keys, problems = self.keys(self.on, overlay(self.t, directory=str(self.t / "absent")))
        self.assertIsNone(keys)
        self.assertIn("not a directory", problems[0])

    def test_the_hop_checkout_is_checked(self):
        hp.checkout_problems = lambda path, pin: ["the hop checkout is elsewhere"]
        keys, problems = self.keys(self.on, overlay(self.t, directory=str(self.reg)))
        self.assertEqual(problems, ["the hop checkout is elsewhere"])

    def test_a_hop_link_must_name_the_same_registry(self):
        ov = overlay(self.t, directory=str(self.reg))
        self.assertEqual(self.keys(self.on, ov, {"registry_dir": str(self.reg)}), (None, []))
        keys, problems = self.keys(self.on, ov, {"registry_dir": str(self.t / "other")})
        self.assertIsNone(keys)
        self.assertTrue(problems and "one registry" in problems[0], problems)


class HopLoaderTest(unittest.TestCase):
    """The hop pin's own loader, in a separate process: a config with
    registry_dir and no hop block loads, and the loader's nesting rule
    still bites."""

    def doc(self, registry):
        return {"state_dir": "/srv/x/state", "instances_dir": "/srv/x/instances",
                "selected_json": "/srv/x/selected.json", "connector_outcome_ids": ["claude-code", "codex"],
                "fleet_domain": "sandy.alpha.internal", "task_graph": "all", "registry_dir": registry}

    def test_registry_without_hop_loads(self):
        self.assertIsNone(hp.validate_with_hop_router(self.doc("/srv/registry"), str(HOP_ROUTER_ROOT)))

    def test_a_registry_inside_state_dir_is_refused(self):
        refused = hp.validate_with_hop_router(self.doc("/srv/x/state/registry"), str(HOP_ROUTER_ROOT))
        self.assertIsNotNone(refused)
        self.assertIn("config.registry_dir", refused)


class RenderTest(unittest.TestCase):
    """install's real run_render_router, its collaborators stubbed: with the
    key, registry_dir is written and the HOP loader validates; without it,
    the primary loader validates the unchanged render."""

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
        stubs = {
            (prov, "router_sibling_path"): lambda home: self.t / "router.json",
            (prov, "load_membership"): lambda home, boxes: {},
            (prov, "sibling_state_dir"): lambda home, explicit: self.t / "state",
            (prov, "render_router_sibling"): lambda *a, **k: {"_doc": dict(base), "_warnings": []},
            (prov, "install_router_state_dir"): lambda state_dir, dry_run: "ok",
            (prov, "hop_router_keys"): lambda *a, **k: (None, []),
            (prov, "validate_with_router"): lambda doc: self.primary_validated.append(doc) or None,
            (hp, "validate_with_hop_router"): lambda doc, checkout: self.hop_validated.append(doc) or None,
            (hp, "checkout_problems"): lambda path, pin: [],
        }
        for (mod, name), value in stubs.items():
            self.addCleanup(setattr, mod, name, getattr(mod, name))
            setattr(mod, name, value)

    def render(self, policy, **extra):
        args = argparse.Namespace(state_dir=None, overlay=str(self.ov), decommission_hop=False, **extra)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            rc = prov.run_render_router(args, self.t, [], policy, apply=True)
        return rc, out.getvalue()

    def test_the_key_writes_registry_dir_validated_by_the_hop_loader(self):
        rc, said = self.render({hp.REGISTRY_POLICY_KEY: True})
        self.assertEqual(rc, 0, said)
        written = json.loads((self.t / "router.json").read_text())
        self.assertEqual(written.get("registry_dir"), str(self.reg))
        self.assertFalse(set(hp.HOP_KEYS) - {"registry_dir"} & set(written), written)
        self.assertEqual([d["registry_dir"] for d in self.hop_validated], [str(self.reg)])
        self.assertEqual(self.primary_validated, [])

    def test_without_the_key_the_render_is_unchanged(self):
        rc, said = self.render({})
        self.assertEqual(rc, 0, said)
        written = json.loads((self.t / "router.json").read_text())
        self.assertNotIn("registry_dir", written)
        self.assertEqual(len(self.primary_validated), 1)
        self.assertEqual(self.hop_validated, [])

    def test_a_refused_key_writes_nothing(self):
        rc, said = self.render({hp.REGISTRY_POLICY_KEY: "yes"})
        self.assertEqual(rc, 2, said)
        self.assertIn("must be true", said)
        self.assertFalse((self.t / "router.json").exists())

    def test_render_to_takes_the_registry_render(self):
        out = self.t / "candidate.json"
        rc, said = self.render({hp.REGISTRY_POLICY_KEY: True}, render_to=str(out))
        self.assertEqual(rc, 0, said)
        self.assertEqual(json.loads(out.read_text()).get("registry_dir"), str(self.reg))
        self.assertFalse((self.t / "router.json").exists(), "render-to never writes the live config")
        rc, said = self.render({}, render_to=str(self.t / "other.json"))
        self.assertEqual(rc, 2, said)
        self.assertIn(hp.REGISTRY_POLICY_KEY, said)


class HopLinkPendingTest(unittest.TestCase):
    """verify's half-set-up rule against a host-setup document with a hub
    section and no hop link: a problem, except under router_registry, where
    it is a note and the registry rendering is still compared."""

    def setUp(self):
        from test_hop_render import doc as setup_doc
        import host_setup as hs
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.t = Path(os.path.realpath(td.name))
        self.reg = self.t / "registry"
        self.reg.mkdir()
        self.ov = self.t / "overlay.json"
        self.ov.write_text(json.dumps({ha.OVERLAY_SECTION: dict(IDS, directory=str(self.reg)),
                                       hs.OVERLAY_SECTION: setup_doc()}))
        self.base = {"state_dir": str(self.t / "s")}
        for (mod, name), value in {
                (prov, "render_router_sibling"): lambda *a, **k: {"_doc": dict(self.base), "_warnings": []},
                (prov, "router_sibling_path"): lambda home: self.t / "router.json",
                (hp, "checkout_problems"): lambda path, pin: []}.items():
            self.addCleanup(setattr, mod, name, getattr(mod, name))
            setattr(mod, name, value)

    def verify(self, policy, on_disk):
        (self.t / "router.json").write_text(json.dumps(on_disk, indent=2) + "\n")
        notes = []
        return prov.verify_router_sibling(self.t, policy, {}, self.t / "s", {}, self.ov, notes=notes), notes

    def test_under_router_registry_the_pending_link_is_a_note(self):
        problems, notes = self.verify({hp.REGISTRY_POLICY_KEY: True}, dict(self.base, registry_dir=str(self.reg)))
        self.assertEqual(problems, [])
        self.assertTrue(any("hop link pending" in n for n in notes), notes)

    def test_without_router_registry_it_is_still_a_problem(self):
        problems, notes = self.verify({}, self.base)
        self.assertTrue(problems and "hub-link router" in problems[0], problems)
        self.assertEqual(notes, [])

    def test_the_note_never_excuses_the_rendering(self):
        problems, notes = self.verify({hp.REGISTRY_POLICY_KEY: True}, self.base)
        self.assertTrue(problems and "registry_dir" in problems[0] and "drift" in problems[0], problems)


class VerifyTest(unittest.TestCase):
    """verify_router_sibling compares the file with the registry render."""

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

    def test_the_file_must_carry_registry_dir(self):
        on = {hp.REGISTRY_POLICY_KEY: True}
        self.assertEqual(self.verify(on, dict(self.base, registry_dir=str(self.reg))), [])
        got = self.verify(on, self.base)
        self.assertTrue(got and "registry_dir" in got[0] and "drift" in got[0], got)

    def test_a_registry_problem_is_a_problem(self):
        got = self.verify({hp.REGISTRY_POLICY_KEY: 1}, self.base)
        self.assertTrue(got and "must be true" in got[0], got)

    def test_without_the_key_registry_dir_is_drift(self):
        got = self.verify({}, dict(self.base, registry_dir=str(self.reg)))
        self.assertTrue(got and "registry_dir" in got[0], got)


if __name__ == "__main__":
    unittest.main()
