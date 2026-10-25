"""Existing launcher model export precedence and conservative permission facts."""
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import codex_assets as assets
import codex_settings as settings


@unittest.skipUnless(sys.version_info >= (3, 11), "native model configuration needs Python 3.11")
class SharedSettingsTest(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory(prefix=".cs-", dir=HERE)
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        native = self.root / "native"
        native.mkdir()
        self.config = native / "config.toml"
        self.config.write_text('model = "configured-model"\n')
        self.env = {"HOME": str(self.root), "CODEX_HOME": str(native),
                    "SANDY_SKIP_PERMISSIONS": "true"}

    def test_existing_nonempty_export_wins_and_is_preserved_literally(self):
        for model in ("pane-model", "literal model $(unused)"):
            selected = settings.resolve({**self.env, "CODEX_MODEL": model, "AMAP_CODEX_MODEL": "ignored"})
            self.assertEqual((selected["selected_model"], selected["model_source"]), (model, "CODEX_MODEL"))
        self.config.write_text("invalid native TOML")
        self.assertEqual(settings.resolve({**self.env, "CODEX_MODEL": "explicit"})["selected_model"], "explicit")

    def test_unset_and_empty_export_use_codex_home_model_then_native_default(self):
        for env in (self.env, {**self.env, "CODEX_MODEL": "", "AMAP_CODEX_MODEL": "ignored"}):
            self.assertEqual(settings.resolve(env)["selected_model"], "configured-model")
            self.assertEqual(settings.resolve(env)["model_source"], "native_config")
        self.config.unlink()
        selection = settings.resolve(self.env)
        self.assertIsNone(selection["selected_model"])
        self.assertEqual(selection["model_source"], "native_default")

    def test_missing_codex_home_uses_native_home_subdirectory(self):
        native = self.root / ".codex"
        native.mkdir()
        (native / "config.toml").write_text('model = "home-model"\n')
        self.assertEqual(settings.resolve({"HOME": str(self.root)})["selected_model"], "home-model")

    def test_entry_preserves_separate_native_model_until_explicit_transition(self):
        state = self.root / "state"
        state.mkdir()
        env = {**self.env, "CODEX_MODEL": "unified-pane-model"}
        selected = settings.entry_selection(env, state)
        self.assertEqual((selected["selected_model"], selected["model_source"]),
                         ("configured-model", "native_config"))
        self.config.unlink()
        self.assertEqual(settings.entry_selection(env, state)["model_source"], "native_default")
        (state / "adapter-transition.json").write_text("prepared transition fixture")
        selected = settings.entry_selection(env, state)
        self.assertEqual((selected["selected_model"], selected["model_source"]),
                         ("unified-pane-model", "CODEX_MODEL"))

    def test_bad_native_model_facts_refuse_instead_of_guessing_default(self):
        for raw in ('model = 42\n', 'model = ""\n', 'model = [\n'):
            with self.subTest(raw=raw):
                self.config.write_text(raw)
                with self.assertRaises(ValueError):
                    settings.resolve(self.env)
        with self.assertRaisesRegex(ValueError, "single-line"):
            settings.resolve({**self.env, "CODEX_MODEL": "model\n"})

    def test_unified_permissions_require_explicit_supported_selection_and_retained_profile(self):
        config = SimpleNamespace(sandbox="danger-full-access", approval_policy="never")
        selected = settings.resolve(self.env)
        settings.require_unified_permissions(selected, config)
        for raw in (None, "", "false", "1", "unknown"):
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, "unknown or conflicting"):
                settings.require_unified_permissions({**selected, "skip_permissions": raw}, config)
        with self.assertRaisesRegex(ValueError, "unknown or conflicting"):
            settings.require_unified_permissions(selected, SimpleNamespace(sandbox="read-only", approval_policy="never"))

    def test_entry_receipt_has_explicit_scope_and_binds_current_controller_bytes(self):
        state = self.root / "state"
        state.mkdir(mode=0o700)
        (state / "controller.toml").write_bytes(b"controller bytes")
        selection = settings.resolve(self.env)
        receipt = settings.capture(state, "instance", selection)
        record = dict(instance_id="instance", codex_model="configured-model",
                      target_sha256=assets.digest(b"controller bytes"))
        self.assertEqual(receipt["scope"], "entry_environment")
        self.assertEqual(settings.evidence_problems(receipt, record), [])
        self.assertTrue(any("model differs" in p for p in settings.evidence_problems(
            {**receipt, "selected_model": "foreign"}, record)))
        self.assertTrue(any("another controller" in p for p in settings.evidence_problems(
            {**receipt, "controller_sha256": "foreign"}, record)))
        self.assertEqual(json.loads((state / settings.RECEIPT).read_text()), receipt)
        self.assertFalse(os.stat(state / settings.RECEIPT).st_mode & 0o077)

    def test_environment_identity_is_stable_across_entry_retries_and_changes_on_recreation(self):
        proc = self.root / "proc"
        for child in ("sys/kernel/random", "1", "self/ns"):
            (proc / child).mkdir(parents=True)
        (proc / "sys/kernel/random/boot_id").write_text("11111111-1111-4111-8111-111111111111")
        (proc / "self/ns/pid").write_text("namespace fixture")
        def started(at):
            (proc / "1/stat").write_text("1 (fixture init) " + " ".join(["S"] + ["0"] * 18 + [str(at)]))
        started(123)
        old = settings.environment_generation(proc)
        self.assertEqual(settings.environment_generation(proc), old)
        started(456)
        self.assertNotEqual(settings.environment_generation(proc), old)
        (proc / "1/stat").write_text("unknown")
        with self.assertRaisesRegex(ValueError, "identity unavailable"):
            settings.environment_generation(proc)


if __name__ == "__main__":
    unittest.main()
