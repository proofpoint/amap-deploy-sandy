"""An explicit authored fleet choice reaches the manifest, without migrating state."""
import json
import os
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import _workspace
_workspace.skip_if_incomplete()
import amap_sandy as prov
import codex_fleet as fleet
import fleet_policy as fp

HERE = Path(__file__).resolve().parents[1]


class FleetChoiceTest(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory(dir=os.environ.get("AMAP_TEST_TMPDIR"))
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.policy = fp.default_policy()

    def test_absent_choice_keeps_separate_and_no_new_export(self):
        before = dict(self.policy)
        manifest = prov.render_manifest(self.policy)
        self.assertEqual(fleet.mode(self.policy), "separate")
        self.assertNotIn(fleet.POLICY_KEY, manifest["feature"])
        self.assertNotIn(fleet.EXPORT, manifest["expose"])
        self.assertEqual(self.policy, before)
        self.assertEqual(fleet.environment({}), "separate")

    def test_bad_authored_or_exported_choice_refuses(self):
        for value in (None, True, "", "UNIFIED", "foreign", []):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    fleet.mode({fleet.POLICY_KEY: value})
                with self.assertRaises(ValueError):
                    fleet.environment({fleet.EXPORT: value})

    def test_unified_requires_protected_wrapper_and_renders_consistently(self):
        policy = fleet.select(self.policy, "unified")
        for capability in (None, False):
            with self.subTest(capability=capability):
                with self.assertRaisesRegex(prov.ProvisionError, "agent_wrapper"):
                    prov.render_manifest(policy, agent_wrapper=capability)
        doc = prov.render_manifest(policy, agent_wrapper=True)
        self.assertEqual(doc["feature"][fleet.POLICY_KEY], "unified")
        self.assertEqual(doc["expose"][fleet.EXPORT], "unified")
        self.assertEqual(doc[prov.AGENT_WRAPPER_KEY]["codex"], "payload/codex/interactive-launch")
        self.assertEqual(doc[fp.AGENTS_KEY], fp.selection(self.policy)[fp.AGENTS_KEY])

    def test_explicit_install_choice_previews_then_authors_only_its_field(self):
        self.policy["unrelated_operator_policy"] = {"retain": ["literal"]}
        prov.install_manifest(self.home, self.policy, dry_run=False, agent_wrapper=True)
        path = prov.feature_manifest_path(self.home)
        old = path.read_bytes()
        prov.install_manifest(self.home, self.policy, dry_run=True,
                              agent_wrapper=True, codex_mode="unified")
        self.assertEqual(path.read_bytes(), old)
        prov.install_manifest(self.home, self.policy, dry_run=False,
                              agent_wrapper=True, codex_mode="unified")
        after = json.loads(path.read_bytes())
        expected = json.loads(old)["feature"]
        expected[fleet.POLICY_KEY] = "unified"
        self.assertEqual(after["feature"], expected)
        self.assertEqual(after["expose"][fleet.EXPORT], "unified")
        loaded = fp.load_policy(path)
        self.assertEqual(fleet.mode(loaded), "unified")
        self.assertEqual(loaded["unrelated_operator_policy"], {"retain": ["literal"]})
        saved = path.read_bytes()
        prov.install_manifest(self.home, loaded, dry_run=False, agent_wrapper=True)
        self.assertEqual(path.read_bytes(), saved)

    def test_manifest_drift_reports_an_export_disagreeing_with_authored_choice(self):
        policy = fleet.select(self.policy, "unified")
        prov.install_manifest(self.home, policy, dry_run=False, agent_wrapper=True)
        self.assertEqual(prov.verify_manifest(self.home, policy, agent_wrapper=True), [])
        path = prov.feature_manifest_path(self.home)
        doc = json.loads(path.read_bytes())
        doc["expose"][fleet.EXPORT] = "separate"
        path.write_text(json.dumps(doc))
        problems = prov.verify_manifest(self.home, policy, agent_wrapper=True)
        self.assertTrue(any("expose" in problem for problem in problems), problems)

    def test_missing_wrapper_refuses_before_authoring_policy(self):
        prov.install_manifest(self.home, self.policy, dry_run=False)
        path = prov.feature_manifest_path(self.home)
        old = path.read_bytes()
        with self.assertRaisesRegex(prov.ProvisionError, "agent_wrapper"):
            prov.install_manifest(self.home, self.policy, dry_run=False,
                                  agent_wrapper=False, codex_mode="unified")
        self.assertEqual(path.read_bytes(), old)

    def test_install_parser_carries_explicit_choice_and_defaults_to_no_change(self):
        parser = prov.build_parser()
        self.assertIsNone(parser.parse_args(["install"]).codex_mode)
        self.assertEqual(parser.parse_args(["install", "--codex-mode", "unified"]).codex_mode, "unified")

    def test_shipped_wrapper_rejects_empty_or_unknown_mode_before_any_mixed_bypass(self):
        for agents in ("codex", "claude,codex"):
            for mode in ("", "foreign"):
                with self.subTest(agents=agents, mode=mode):
                    result = subprocess.run(
                        [str(HERE / "payload/codex/interactive-launch"), "/bin/echo", "BARE_NATIVE"],
                        env=dict(os.environ, SANDY_AGENT=agents,
                                 AMAP_CODEX_CONVERSATION_MODE=mode, AMAP_OUTBOX_DIR=str(self.home)),
                        capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("unknown fleet conversation mode", result.stderr)
                    self.assertNotIn("BARE_NATIVE", result.stdout)
