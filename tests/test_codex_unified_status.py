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

    def _host(self):
        import amap_sandy as prov
        home = self.fixture.root / "host-home"
        relay = prov.feature_payload_dir(home) / "codex/relay"
        relay.parent.mkdir(parents=True, exist_ok=True)
        relay.write_text("fixture relay")
        record = {prov.FEATURE_ENTRIES_KEY: {prov.FEATURE_NAME: {"state_dir": str(self.fixture.state.parent)}}}
        return prov, home, record

    def test_a_confirmed_adoption_verifies_clean_under_authored_unified_mode(self):
        prov, home, record = self._host()
        self.assertFalse((self.fixture.state / "fresh-birth.json").exists())
        problems, _ = prov.verify_codex_supervisor(home, "codex-test", record, running=True, now=self.now,
                                                   expected_mode="unified")
        self.assertEqual(problems, [])

    def test_an_unconfirmed_adoption_under_unified_mode_is_unknown_not_accepted(self):
        prov, home, record = self._host()
        (self.fixture.state / "adapter-transition.json").write_text("[]")
        problems, _ = prov.verify_codex_supervisor(home, "codex-test", record, running=True, now=self.now,
                                                   expected_mode="unified")
        self.assertTrue(any("codex unified UNKNOWN" in p and "not confirmed" in p for p in problems), problems)

    def test_unified_mode_without_fresh_birth_or_adoption_holds_for_recreation(self):
        prov, home, record = self._host()
        (self.fixture.state / "adapter-transition.json").unlink()
        problems, _ = prov.verify_codex_supervisor(home, "codex-test", record, running=True, now=self.now,
                                                   expected_mode="unified")
        self.assertTrue(any("fleet mode requires fresh initialization" in p for p in problems), problems)

    def test_an_adoption_mixed_with_fresh_evidence_still_holds_under_unified_mode(self):
        prov, home, record = self._host()
        (self.fixture.state / "fresh-plan.json").write_text("{}")
        self.assertFalse((self.fixture.state / "fresh-birth.json").exists())
        problems, _ = prov.verify_codex_supervisor(home, "codex-test", record, running=True, now=self.now,
                                                   expected_mode="unified")
        self.assertTrue(any("fleet mode requires fresh initialization" in p for p in problems), problems)

    def _unified(self, prov, home, record, slug="codex-test"):
        return prov.verify_codex_supervisor(home, slug, record, running=True, now=self.now,
                                            expected_mode="unified")[0]

    def test_a_prepared_transition_under_unified_mode_is_unknown(self):
        prov, home, record = self._host()
        path = self.fixture.state / "adapter-transition.json"
        path.write_text(json.dumps({**json.loads(path.read_text()), "state": "prepared"}))
        problems = self._unified(prov, home, record)
        self.assertTrue(any("codex unified UNKNOWN" in p and "not confirmed" in p for p in problems), problems)

    def test_policy_drift_under_unified_mode_is_a_problem(self):
        prov, home, record = self._host()
        path = self.fixture.state / "adapter-transition.json"
        path.write_text(json.dumps({**json.loads(path.read_text()), "policy_hash": "c" * 64}))
        self.assertNotEqual(self._unified(prov, home, record), [])

    def test_settings_drift_under_unified_mode_is_a_problem(self):
        prov, home, record = self._host()
        path = self.fixture.state / settings.RECEIPT
        path.write_text(json.dumps({**json.loads(path.read_text()), "selected_model": "foreign-model"}))
        self.assertTrue(any("model differs" in p for p in self._unified(prov, home, record)))

    def test_an_adoption_verified_for_another_sandbox_is_unknown(self):
        prov, home, record = self._host()
        problems = self._unified(prov, home, record, slug="other-sandbox")
        self.assertTrue(any("names another Sandy instance" in p for p in problems), problems)

    def test_an_adoption_record_without_an_instance_is_unknown(self):
        prov, home, record = self._host()
        path = self.fixture.state / "adapter-transition.json"
        value = json.loads(path.read_text())
        del value["instance_id"]
        path.write_text(json.dumps(value))
        problems = self._unified(prov, home, record)
        self.assertTrue(any("names another Sandy instance" in p for p in problems), problems)

    def test_a_failed_binding_read_is_unknown_not_a_skipped_instance_check(self):
        from unittest import mock
        prov, home, record = self._host()
        real = prov.ca.regular
        calls = []

        def first_read_fails(path, *args, **kwargs):
            calls.append(path)
            if len(calls) == 1:
                raise NotImplementedError("dir_fd unavailable")
            return real(path, *args, **kwargs)

        with mock.patch.object(prov.ca, "regular", side_effect=first_read_fails):
            problems = self._unified(prov, home, record, slug="other-sandbox")
        self.assertEqual(calls[0].name, "adapter-transition.json")
        self.assertTrue(any("adoption record unreadable for instance binding" in p for p in problems), problems)

    def test_an_adopted_sandbox_carries_the_workspace_binding_note(self):
        prov, home, record = self._host()
        problems, notes = prov.verify_codex_supervisor(home, "codex-test", record, running=True, now=self.now,
                                                       expected_mode="unified")
        self.assertEqual(problems, [])
        self.assertIn("codex-test: adopted workspace binding relies on in-sandbox startup checks; "
                      "host/container workspace mapping is not independently verified", notes)

    def test_fresh_intent_beside_an_adoption_still_holds(self):
        prov, home, record = self._host()
        intent = self.fixture.state.parent / (".fresh-intent-" + self.fixture.state.name + ".json")
        intent.write_text("{}")
        problems = self._unified(prov, home, record)
        self.assertTrue(any("fleet mode requires fresh initialization" in p for p in problems), problems)

    def test_outbox_custody_beside_an_adoption_still_holds(self):
        prov, home, record = self._host()
        outbox = prov.feature_instance_dir(home, "codex-test") / "outbox"
        outbox.mkdir(parents=True)
        (outbox / prov.cf.CUSTODY).write_text("{}")
        problems = self._unified(prov, home, record)
        self.assertTrue(any("custody" in p for p in problems), problems)
        self.assertTrue(any("fleet mode requires fresh initialization" in p for p in problems), problems)

    def test_fresh_evidence_under_separate_mode_is_a_downgrade_hold(self):
        prov, home, record = self._host()
        (self.fixture.state / "fresh-birth.json").write_text("{}")
        problems, _ = prov.verify_codex_supervisor(home, "codex-test", record, running=True, now=self.now,
                                                   expected_mode="separate")
        self.assertTrue(any("no automatic downgrade" in p for p in problems), problems)

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
