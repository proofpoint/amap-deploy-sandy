"""Unified verify evidence from the connector's shipped write_status producer."""
import copy
import json
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_codex_transition as transition_tests
from amap_codex.journal import Journal
from amap_codex.unified import UnifiedService
import codex_transition as transition
import codex_settings as settings
import codex_unified_status as verifier


class UnifiedEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.fixture = f = transition_tests.TransitionTest()
        f.setUp()
        self.addCleanup(f.doCleanups)
        f.prepare(apply=True)
        f.commit_adoption_fixture()
        transition.confirm(f.state, apply=True)
        config = transition.config_at(f.state)
        self.entry_generation = settings.environment_generation()
        settings.capture(f.state, config.instance_id, settings.resolve(os.environ), generation=self.entry_generation)
        with self.assertRaisesRegex(ValueError, "full native argv selection is pending"):
            transition.startup_gate(f.state, self.entry_generation, apply=True)
        transition.select_pane(f.state, ["codex", "--model", "test-model", "-s", "danger-full-access", "-a", "never"], apply=True)
        transition.startup_gate(f.state, self.entry_generation, apply=True)
        journal = Journal(f.state, config.instance_id, config.fingerprint(), config.codex_version, config.codex_model)
        self.addCleanup(journal.close)
        generation = "a" * 32
        service = SimpleNamespace(config=config, journal=journal,
            backend=SimpleNamespace(generation=generation, front_path=f.state / ("u-" + generation) / "t",
                process=SimpleNamespace(returncode=None, pid=1), client=SimpleNamespace(blocked={})),
            gate=SimpleNamespace(client_count=0), tools_validation={"scope": "startup",
                "backend_generation": generation, "validated_at": time.time()},
            effective={"model": config.codex_model, "sandbox": {"type": "dangerFullAccess"},
                "approval_policy": "never", "model_source": "connector.codex_model",
                "permission_source": "connector pane configuration"})
        UnifiedService.write_status(service, True,
            {"thread": {"id": transition_tests.THREAD, "status": {"type": "idle"}, "turns": []}}, [])
        self.status = json.loads((f.state / "status.json").read_bytes())
        self.descriptor = json.loads((f.state / "unified.json").read_bytes())
        self.record = transition.read_record(f.state)
        self.binding = {"thread_id": transition_tests.THREAD, "fingerprint": config.fingerprint(),
                        "policy_hash": self.record["policy_hash"], "effective_model": config.codex_model}
        self.now = time.time()

    def problems(self, status=None, descriptor=None, binding=None):
        return verifier.evidence_problems(self.status if status is None else status,
            self.descriptor if descriptor is None else descriptor, self.record,
            self.binding if binding is None else binding, now=self.now)

    def test_real_producer_positive_and_host_read_path(self):
        self.assertEqual(self.problems(), [])
        self.assertEqual(verifier.problems(self.fixture.state, self.status, now=self.now), [])

    def test_each_required_check_is_required_on_both_surfaces(self):
        for surface in ("status", "descriptor"):
            for name in verifier.REQUIRED:
                with self.subTest(surface=surface, name=name):
                    value = copy.deepcopy(getattr(self, surface))
                    del value["readiness"]["checks"][name]
                    self.assertTrue(any(name + "=unknown" in p for p in self.problems(**{surface: value})))

    def test_stale_future_missing_and_nonfinite_stamps_never_pass(self):
        for stamp in (self.now - 60, self.now + 1, None, float("nan"), float("inf"), True):
            with self.subTest(stamp=stamp):
                status = copy.deepcopy(self.status)
                status["updated_at"] = stamp
                self.assertTrue(any("fresh_heartbeat" in p for p in self.problems(status=status)))

    def test_identity_generation_model_permissions_and_queue_negative_controls(self):
        changes = [("schema_version", 2, "schema_version"), ("backend_generation", "b" * 32, "disagree"),
                   ("canonical_thread_id", "foreign", "canonical_binding"),
                   ("scheduler_state", "unknown", "scheduler"), ("queue_depth", None, "queue facts"),
                   ("attached_client_count", True, "attached_client_count"),
                   ("endpoint", "unix:///foreign", "endpoint"),
                   ("heartbeat_max_age_seconds", 600, "fresh_heartbeat")]
        for key, value, reason in changes:
            with self.subTest(key=key):
                status = copy.deepcopy(self.status)
                status[key] = value
                self.assertTrue(any(reason in p for p in self.problems(status=status)))
        for key, value in (("model", "foreign"), ("approval_policy", "on-request"),
                           ("sandbox", {"type": "readOnly"})):
            status = copy.deepcopy(self.status)
            status["effective_settings"][key] = value
            self.assertTrue(any("permissions differ" in p for p in self.problems(status=status)))

    def test_startup_validation_is_generation_scoped(self):
        for key, value in (("scope", "continuous"), ("backend_generation", "foreign"), ("validated_at", None)):
            status = copy.deepcopy(self.status)
            status["protected_tools_validation"][key] = value
            self.assertTrue(any("startup validation" in p for p in self.problems(status=status)))

    def test_journal_policy_disagreement_and_config_edit_are_problems(self):
        binding = {**self.binding, "policy_hash": "c" * 64}
        self.assertTrue(any("protected policy" in p for p in self.problems(binding=binding)))
        (self.fixture.state / "controller.toml").write_text("edited = true\n")
        self.assertTrue(any("controller differs" in p for p in verifier.problems(self.fixture.state, self.status)))

    def test_real_verify_reports_the_descriptor_guard_by_name(self):
        import amap_sandy as prov
        home = self.fixture.root / "host-home"
        relay = prov.feature_payload_dir(home) / "codex/relay"
        relay.parent.mkdir(parents=True)
        relay.write_text("fixture relay")
        record = {prov.FEATURE_ENTRIES_KEY: {prov.FEATURE_NAME: {"state_dir": str(self.fixture.state.parent)}}}
        self.assertEqual(prov.verify_codex_supervisor(home, "codex-test", record,
                                                    running=True, now=self.now)[0], [])
        self.assertTrue(any("model source is native config.toml" in note for note in
            prov.verify_codex_supervisor(home, "codex-test", record, running=True, now=self.now)[1]))
        descriptor = copy.deepcopy(self.descriptor)
        descriptor["updated_at"] = self.now - 60
        (self.fixture.state / "unified.json").write_text(json.dumps(descriptor))
        problems, _ = prov.verify_codex_supervisor(home, "codex-test", record, running=True, now=self.now)
        self.assertTrue(any("descriptor fresh_heartbeat" in p for p in problems), problems)

    def test_malformed_transition_is_unknown(self):
        (self.fixture.state / "adapter-transition.json").write_text("[]")
        self.assertTrue(any("not confirmed" in p for p in verifier.problems(self.fixture.state, self.status)))

    def test_malformed_entry_roots_are_unknown_through_actual_host_caller(self):
        import amap_sandy as prov
        home = self.fixture.root / "host-home"
        relay = prov.feature_payload_dir(home) / "codex/relay"
        relay.parent.mkdir(parents=True)
        relay.write_text("fixture relay")
        record = {prov.FEATURE_ENTRIES_KEY: {prov.FEATURE_NAME: {"state_dir": str(self.fixture.state.parent)}}}
        path = self.fixture.state / settings.RECEIPT
        valid = path.read_bytes()
        self.assertEqual(prov.verify_codex_supervisor(home, "codex-test", record,
                                                    running=True, now=self.now)[0], [])
        for value in ([], None, "malformed", 42, True):
            with self.subTest(root=value):
                path.write_text(json.dumps(value))
                problems, _ = prov.verify_codex_supervisor(home, "codex-test", record,
                                                          running=True, now=self.now)
                self.assertTrue(any("entry" in p and ("malformed" in p or "unknown" in p) for p in problems), problems)
        path.write_bytes(valid)
        self.assertEqual(prov.verify_codex_supervisor(home, "codex-test", record,
                                                    running=True, now=self.now)[0], [])

    def test_entry_model_and_permissions_mismatch_are_reported_by_host_verify(self):
        receipt = json.loads((self.fixture.state / settings.RECEIPT).read_text())
        for key, value, name in (("selected_model", "foreign-model", "model differs"),
                                 ("skip_permissions", "false", "SANDY_SKIP_PERMISSIONS"),
                                 ("controller_sha256", "foreign-controller", "another controller")):
            with self.subTest(key=key):
                (self.fixture.state / settings.RECEIPT).write_text(json.dumps({**receipt, key: value}))
                self.assertTrue(any(name in p for p in verifier.problems(self.fixture.state, self.status)), key)


if __name__ == "__main__":
    unittest.main()
