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
        self.service = service
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

    def test_upgraded_build_requires_new_entry_selection_and_real_current_status(self):
        from unittest import mock
        import subprocess
        state = self.fixture.state
        original_record = (state / transition.RECORD).read_bytes()
        version = "codex-cli 0.166.0"
        with mock.patch.object(transition.subprocess, 'run', return_value=
                subprocess.CompletedProcess(['codex', '--version'], 0, version + '\n', '')):
            transition.refresh_build(state, version, apply=True)
        self.assertTrue(verifier.problems(state, self.status, now=time.time()))
        config = transition.config_at(state)
        settings.capture(state, config.instance_id, settings.resolve(os.environ), generation=self.entry_generation)
        with self.assertRaises(ValueError):
            transition.startup_gate(state, self.entry_generation, apply=True)
        transition.select_pane(state, ['codex', '-s', 'danger-full-access', '-a', 'never'], apply=True)
        transition.startup_gate(state, self.entry_generation, apply=True)
        with Journal(state, config.instance_id, config.fingerprint(), version, config.codex_model) as journal:
            self.service.config, self.service.journal = config, journal
            UnifiedService.write_status(self.service, True,
                {'thread': {'id': transition_tests.THREAD, 'status': {'type': 'idle'}, 'turns': []}}, [])
        status = json.loads((state / 'status.json').read_bytes())
        self.assertEqual(verifier.problems(state, status, now=time.time()), [])
        prov, home, record = self._host()
        self.assertEqual(prov.verify_codex_supervisor(home, 'codex-test', record, running=True,
            now=time.time(), expected_mode='unified')[0], [])
        self.assertEqual((state / transition.RECORD).read_bytes(), original_record)

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
        # An exception with an empty message is still a failed read.
        for error in (NotImplementedError("dir_fd unavailable"), NotImplementedError()):
            with self.subTest(message=str(error)):
                calls = []

                def first_read_fails(path, *args, **kwargs):
                    calls.append(path)
                    if len(calls) == 1:
                        raise error
                    return real(path, *args, **kwargs)

                with mock.patch.object(prov.ca, "regular", side_effect=first_read_fails):
                    problems = self._unified(prov, home, record, slug="other-sandbox")
                self.assertEqual(calls[0].name, "adapter-transition.json")
                self.assertTrue(any("adoption record unreadable for instance binding" in p for p in problems),
                                problems)

    def _native_adoption(self, sql):
        import sqlite3
        from contextlib import closing
        with closing(sqlite3.connect(self.fixture.state / "journal.sqlite3")) as db, db:
            db.execute(sql)

    def test_each_native_adoption_disagreement_is_unknown_through_host_verify(self):
        """The connector's own startup gate refuses each of these rows."""
        prov, home, record = self._host()
        self.assertEqual(self._unified(prov, home, record), [])
        other = "00000000-0000-4000-8000-000000000000"
        cases = {
            "planned": ("UPDATE unified_adoptions SET state='planned'", "native adoption is not confirmed"),
            "row deleted": ("DELETE FROM unified_adoptions", "native adoption record is unavailable"),
            "table missing": ("DROP TABLE unified_adoptions", "native adoption record is unavailable"),
            "thread": (f"UPDATE unified_adoptions SET thread_id='{other}'", "native adoption thread is malformed or differs"),
            "fingerprint": ("UPDATE unified_adoptions SET fingerprint='" + "c" * 64 + "'",
                            "native adoption fingerprint is malformed or differs"),
            "policy_hash": ("UPDATE unified_adoptions SET policy_hash='" + "b" * 64 + "'",
                            "native adoption policy_hash is malformed or differs"),
            "history": ("UPDATE unified_adoptions SET history_sha256=''", "native adoption history digest is malformed"),
            "previous fingerprint": ("UPDATE unified_adoptions SET previous_fingerprint='" + "F" * 64 + "'",
                                     "native adoption previous_fingerprint is malformed or differs"),
        }
        journal = self.fixture.state / "journal.sqlite3"
        original = journal.read_bytes()
        for label, (sql, expected) in cases.items():
            with self.subTest(label):
                journal.write_bytes(original)
                self._native_adoption(sql)
                problems = self._unified(prov, home, record)
                self.assertTrue(any(p.startswith("codex unified UNKNOWN: codex-test: ") and expected in p
                                    for p in problems), problems)
        journal.write_bytes(original)
        self.assertEqual(self._unified(prov, home, record), [])

    def _adoption_named(self, prov, home, record, label):
        expected = "codex unified UNKNOWN: codex-test: native adoption " + label + " is malformed or differs"
        problems = self._unified(prov, home, record)
        self.assertTrue(any(p.startswith(expected) for p in problems), problems)

    def test_a_non_text_native_adoption_value_is_named_not_a_traceback(self):
        prov, home, record = self._host()
        self._native_adoption("UPDATE unified_adoptions SET policy_hash=X'61'")
        self._adoption_named(prov, home, record, "policy_hash")

    def test_an_adoption_agreeing_with_only_one_side_is_unknown(self):
        """The row must match the transition and the binding, each on its own."""
        other = "00000000-0000-4000-8000-000000000000"
        cases = {
            "policy_hash binding only": ("policy_hash", ["UPDATE unified_binding SET policy_hash='" + "d" * 64 + "'"]),
            "policy_hash transition only": ("policy_hash", [
                "UPDATE unified_binding SET policy_hash='" + "d" * 64 + "'",
                "UPDATE unified_adoptions SET policy_hash='" + "d" * 64 + "'"]),
            "thread binding only": ("thread", [f"UPDATE unified_binding SET thread_id='{other}'"]),
            "thread transition only": ("thread", [f"UPDATE unified_binding SET thread_id='{other}'",
                                                  f"UPDATE unified_adoptions SET thread_id='{other}'"]),
        }
        prov, home, record = self._host()
        journal = self.fixture.state / "journal.sqlite3"
        original = journal.read_bytes()
        for name, (label, statements) in cases.items():
            with self.subTest(name):
                journal.write_bytes(original)
                for sql in statements:
                    self._native_adoption(sql)
                self._adoption_named(prov, home, record, label)
        journal.write_bytes(original)

    def test_a_malformed_policy_hash_equal_everywhere_is_unknown(self):
        prov, home, record = self._host()
        malformed = "A" * 64
        path = self.fixture.state / "adapter-transition.json"
        path.write_text(json.dumps({**json.loads(path.read_text()), "policy_hash": malformed}))
        self._native_adoption(f"UPDATE unified_binding SET policy_hash='{malformed}'")
        self._native_adoption(f"UPDATE unified_adoptions SET policy_hash='{malformed}'")
        self.assertIn("codex unified UNKNOWN: codex-test: native adoption policy_hash has no valid expected value",
                      self._unified(prov, home, record))

    def test_a_writer_between_the_two_journal_reads_cannot_mix_snapshots(self):
        """Before, the row's policy_hash disagrees with the binding. A writer commits a new binding and
        a new row: read as the OLD binding with the NEW row they would agree, and both whole states are
        refused. The writer runs immediately before the adoption SELECT."""
        import sqlite3
        from contextlib import closing
        from unittest import mock
        prov, home, record = self._host()
        journal = self.fixture.state / "journal.sqlite3"
        good, other = self.record["policy_hash"], "d" * 64
        self._native_adoption(f"UPDATE unified_adoptions SET policy_hash='{other}'")
        real_connect = sqlite3.connect
        outcome = []

        def writer():
            try:
                with closing(real_connect(journal, timeout=0)) as db, db:
                    db.execute(f"UPDATE unified_binding SET policy_hash='{other}'")
                    db.execute(f"UPDATE unified_adoptions SET policy_hash='{good}'")
                outcome.append("committed")
            except sqlite3.OperationalError as exc:
                outcome.append("refused: " + str(exc))

        class Interleaved:
            def __init__(self, db):
                object.__setattr__(self, "db", db)

            def __getattr__(self, name):
                return getattr(self.db, name)

            def __setattr__(self, name, value):
                setattr(self.db, name, value)

            def execute(self, sql, *args):
                if "FROM unified_adoptions" in sql and not outcome:
                    writer()
                return self.db.execute(sql, *args)

        with mock.patch.object(verifier.sqlite3, "connect", side_effect=lambda *a, **k: Interleaved(real_connect(*a, **k))):
            problems = self._unified(prov, home, record)
        self.assertEqual(len(outcome), 1, outcome)
        self.assertTrue(any("native adoption policy_hash is malformed or differs" in p for p in problems),
                        (outcome, problems))

    def test_stale_or_holding_runtime_evidence_is_named_through_host_verify(self):
        prov, home, record = self._host()
        problems, _ = prov.verify_codex_supervisor(home, "codex-test", record, running=True, now=self.now + 3600,
                                                   expected_mode="unified")
        self.assertTrue(any("status fresh_heartbeat is unknown or stale" in p for p in problems), problems)
        path = self.fixture.state / "status.json"
        status = json.loads(path.read_text())
        status["readiness"]["state"] = "holding"
        path.write_text(json.dumps(status))
        self.assertTrue(any("status readiness is holding or unknown" in p for p in self._unified(prov, home, record)))

    def _record(self, change):
        path = self.fixture.state / "adapter-transition.json"
        value = json.loads(path.read_text())
        change(value)
        path.write_text(json.dumps(value))
        return path

    def test_prepare_records_the_previous_fingerprint_from_the_retained_configuration(self):
        from amap_codex.config import Config
        derived = Config.load(self.fixture.state / transition.PREVIOUS, create_state=False).fingerprint()
        self.assertEqual(self.record["previous_fingerprint"], derived)

    def test_a_changed_native_previous_fingerprint_is_refused_by_host_and_startup(self):
        """The witness both gates reproduced: only the row's previous_fingerprint changes."""
        prov, home, record = self._host()
        self._native_adoption("UPDATE unified_adoptions SET previous_fingerprint='" + "f" * 64 + "'")
        self.assertTrue(any("native adoption previous_fingerprint is malformed or differs" in p
                            for p in self._unified(prov, home, record)))
        with self.assertRaisesRegex(ValueError, "not confirmed"):
            transition.confirmed_adoption(transition.config_at(self.fixture.state), transition.read_record(self.fixture.state))

    def test_a_record_without_the_expectation_is_pending_revalidation_everywhere(self):
        prov, home, record = self._host()
        self._record(lambda value: value.pop("previous_fingerprint"))
        self.assertTrue(any("pending explicit revalidation" in p for p in self._unified(prov, home, record)))
        with self.assertRaisesRegex(ValueError, "pending explicit revalidation"):
            transition.read_record(self.fixture.state)
        with self.assertRaisesRegex(ValueError, "pending explicit revalidation"):
            transition.entry_mode(self.fixture.state)
        self._record(lambda value: value.update(previous_fingerprint="F" * 64))
        self.assertTrue(any("pending explicit revalidation" in p for p in self._unified(prov, home, record)))
        with self.assertRaisesRegex(ValueError, "invalid adapter transition previous_fingerprint"):
            transition.read_record(self.fixture.state)

    def test_a_record_expectation_that_differs_from_the_row_is_refused_by_startup(self):
        self._record(lambda value: value.update(previous_fingerprint="e" * 64))
        with self.assertRaisesRegex(ValueError, "not confirmed"):
            transition.confirmed_adoption(transition.config_at(self.fixture.state), transition.read_record(self.fixture.state))

    def _bytes(self):
        state = self.fixture.state
        return {name: (state / name).read_bytes()
                for name in ("controller.toml", transition.PREVIOUS, "journal.sqlite3")}

    def test_confirm_enriches_a_legacy_record_with_only_the_expected_previous_fingerprint(self):
        """The pre-r4 record of a confirmed adoption: it is pending revalidation everywhere until
        confirm --apply adds the one field, and then host verify and startup accept it."""
        prov, home, record = self._host()
        expected = json.loads((self.fixture.state / "adapter-transition.json").read_bytes())
        path = self._record(lambda value: value.pop("previous_fingerprint"))
        legacy = path.read_bytes()
        self.assertTrue(any("pending explicit revalidation" in p for p in self._unified(prov, home, record)))
        before = self._bytes()
        dry = transition.confirm(self.fixture.state)
        self.assertEqual((dry["apply"], dry["previous_fingerprint"]), (False, expected["previous_fingerprint"]))
        self.assertEqual(path.read_bytes(), legacy)
        transition.confirm(self.fixture.state, apply=True)
        self.assertEqual(json.loads(path.read_bytes()), expected)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self._bytes(), before)
        self.assertEqual(self._unified(prov, home, record), [])
        self.assertIsNone(self._startup_refuses())
        transition.confirm(self.fixture.state, apply=True)
        self.assertEqual(json.loads(path.read_bytes()), expected)

    def test_confirm_refuses_to_enrich_against_conflicting_evidence(self):
        cases = {
            "native row": ("row", "UPDATE unified_adoptions SET previous_fingerprint='" + "f" * 64 + "'",
                           "not confirmed"),
            "retained previous bytes": ("previous", b"# edited\n", "retained previous configuration differs"),
            "recorded expectation": ("record", {"previous_fingerprint": "e" * 64},
                                     "recorded previous fingerprint differs"),
            "settings": ("record", {"poll_interval_ms": 1}, "transition settings differ"),
            "policy binding": ("record", {"policy_hash": "c" * 64}, "policy binding differs"),
        }
        state = self.fixture.state
        journal, previous = state / "journal.sqlite3", state / transition.PREVIOUS
        record = state / "adapter-transition.json"
        originals = {journal: journal.read_bytes(), previous: previous.read_bytes(), record: record.read_bytes()}
        for name, (kind, change, message) in cases.items():
            with self.subTest(name):
                for target, data in originals.items():
                    target.write_bytes(data)
                path = self._record(lambda value: value.pop("previous_fingerprint"))
                if kind == "row":
                    self._native_adoption(change)
                elif kind == "previous":
                    previous.write_bytes(originals[previous] + change)
                else:
                    self._record(lambda value: value.update(change))
                held = path.read_bytes()
                for apply in (False, True):
                    with self.assertRaisesRegex(ValueError, message):
                        transition.confirm(state, apply=apply)
                    self.assertEqual(path.read_bytes(), held)
        for target, data in originals.items():
            target.write_bytes(data)

    def test_confirm_enrichment_needs_controller_ownership(self):
        """A running controller holds controller.lock; the enrichment refuses and writes nothing."""
        import fcntl
        import os
        path = self._record(lambda value: value.pop("previous_fingerprint"))
        legacy = path.read_bytes()
        fd = os.open(self.fixture.state / "controller.lock", os.O_CREAT | os.O_RDWR, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with self.assertRaisesRegex(RuntimeError, "another controller owns this state directory"):
            transition.confirm(self.fixture.state, apply=True)
        self.assertEqual(path.read_bytes(), legacy)
        fcntl.flock(fd, fcntl.LOCK_UN)

    def test_confirm_enrichment_refuses_a_record_changed_while_taking_ownership(self):
        from unittest import mock
        import amap_codex.supervisor as supervisor
        path = self._record(lambda value: value.pop("previous_fingerprint"))
        real = supervisor.Ownership

        class Racing(real):
            def __enter__(self):
                entered = super().__enter__()
                path.write_bytes(path.read_bytes().replace(b'"confirmed"', b'"prepared"'))
                return entered

        with mock.patch.object(supervisor, "Ownership", Racing):
            with self.assertRaisesRegex(ValueError, "changed while acquiring controller ownership"):
                transition.confirm(self.fixture.state, apply=True)
        self.assertNotIn(b"previous_fingerprint", path.read_bytes())

    def test_confirm_enrichment_refuses_a_record_changed_during_its_checks(self):
        """The second byte check: an edit made after ownership is taken, while the checks run."""
        from unittest import mock
        path = self._record(lambda value: value.pop("previous_fingerprint"))
        real = transition.matching_status

        def edits_then_checks(*args, **kwargs):
            path.write_bytes(path.read_bytes().replace(b'"confirmed"', b'"prepared"'))
            return real(*args, **kwargs)

        with mock.patch.object(transition, "matching_status", side_effect=edits_then_checks):
            with self.assertRaisesRegex(ValueError, "changed during confirmation"):
                transition.confirm(self.fixture.state, apply=True)
        self.assertNotIn(b"previous_fingerprint", path.read_bytes())

    def test_a_legacy_prepared_record_names_operator_inspection(self):
        self._record(lambda value: (value.pop("previous_fingerprint"), value.update(state="prepared")))
        with self.assertRaisesRegex(ValueError, "needs operator inspection"):
            transition.read_record(self.fixture.state)

    def test_only_confirm_accepts_a_record_without_the_expectation(self):
        self._record(lambda value: value.pop("previous_fingerprint"))
        self.assertNotIn("previous_fingerprint", transition.read_record(self.fixture.state, legacy=True))
        for call in (lambda: transition.read_record(self.fixture.state),
                     lambda: transition.entry_mode(self.fixture.state)):
            with self.assertRaisesRegex(ValueError, "pending explicit revalidation"):
                call()

    def _startup_refuses(self):
        try:
            transition.confirmed_adoption(transition.config_at(self.fixture.state),
                                          transition.read_record(self.fixture.state))
        except ValueError as exc:
            return str(exc)
        return None

    def test_host_verify_names_a_problem_wherever_startup_refuses(self):
        """One mutation matrix through both callers of codex_adoption: startup's refusal must
        never meet a clean host verdict."""
        other = "00000000-0000-4000-8000-000000000000"
        matrix = {
            "planned": "UPDATE unified_adoptions SET state='planned'",
            "row deleted": "DELETE FROM unified_adoptions",
            "table missing": "DROP TABLE unified_adoptions",
            "thread": f"UPDATE unified_adoptions SET thread_id='{other}'",
            "fingerprint": "UPDATE unified_adoptions SET fingerprint='" + "c" * 64 + "'",
            "previous_fingerprint": "UPDATE unified_adoptions SET previous_fingerprint='" + "f" * 64 + "'",
            "policy_hash": "UPDATE unified_adoptions SET policy_hash='" + "b" * 64 + "'",
            "history empty": "UPDATE unified_adoptions SET history_sha256=''",
            "history upper": "UPDATE unified_adoptions SET history_sha256='" + "B" * 64 + "'",
            "binding policy": "UPDATE unified_binding SET policy_hash='" + "d" * 64 + "'",
            "binding thread": f"UPDATE unified_binding SET thread_id='{other}'",
            "binding model": "UPDATE unified_binding SET effective_model='another-model'",
            "instance fingerprint": "UPDATE instance SET fingerprint='" + "e" * 64 + "'",
        }
        prov, home, record = self._host()
        self.assertIsNone(self._startup_refuses())
        self.assertEqual(self._unified(prov, home, record), [])
        journal = self.fixture.state / "journal.sqlite3"
        original = journal.read_bytes()
        for label, sql in matrix.items():
            with self.subTest(label):
                journal.write_bytes(original)
                self._native_adoption(sql)
                refusal = self._startup_refuses()
                self.assertIsNotNone(refusal, "startup accepts " + label)
                self.assertNotEqual(self._unified(prov, home, record), [], (label, refusal))
        journal.write_bytes(original)

    def test_null_adoption_values_are_named_by_both_callers(self):
        """Defensive only: the connector's NOT NULL columns make these rows unreachable on a real
        journal, so the table is rebuilt here without its constraints."""
        columns = ("thread_id", "previous_fingerprint", "fingerprint", "policy_hash", "history_sha256", "state")
        prov, home, record = self._host()
        journal = self.fixture.state / "journal.sqlite3"
        original = journal.read_bytes()
        for column in columns:
            with self.subTest(column):
                journal.write_bytes(original)
                self._native_adoption("ALTER TABLE unified_adoptions RENAME TO constrained")
                self._native_adoption("CREATE TABLE unified_adoptions AS SELECT * FROM constrained")
                self._native_adoption(f"UPDATE unified_adoptions SET {column}=NULL")
                self.assertIsNotNone(self._startup_refuses())
                self.assertNotEqual(self._unified(prov, home, record), [])
        journal.write_bytes(original)

    def test_startup_reads_the_binding_and_adoption_row_in_one_snapshot(self):
        """The writer that would pair an old binding with a new row, run against startup."""
        import sqlite3
        from contextlib import closing
        from unittest import mock
        journal = self.fixture.state / "journal.sqlite3"
        good, other = self.record["policy_hash"], "d" * 64
        self._native_adoption(f"UPDATE unified_adoptions SET policy_hash='{other}'")
        real_connect = sqlite3.connect
        outcome = []

        def writer():
            try:
                with closing(real_connect(journal, timeout=0)) as db, db:
                    db.execute(f"UPDATE unified_binding SET policy_hash='{other}'")
                    db.execute(f"UPDATE unified_adoptions SET policy_hash='{good}'")
                outcome.append("committed")
            except sqlite3.OperationalError as exc:
                outcome.append("refused: " + str(exc))

        class Interleaved:
            def __init__(self, db):
                object.__setattr__(self, "db", db)

            def __getattr__(self, name):
                return getattr(self.db, name)

            def __setattr__(self, name, value):
                setattr(self.db, name, value)

            def execute(self, sql, *args):
                if "FROM unified_adoptions" in sql and not outcome:
                    writer()
                return self.db.execute(sql, *args)

        with mock.patch.object(sqlite3, "connect", side_effect=lambda *a, **k: Interleaved(real_connect(*a, **k))):
            refusal = self._startup_refuses()
        self.assertEqual(len(outcome), 1, outcome)
        self.assertIsNotNone(refusal, outcome)
        self.assertIn("native adoption policy_hash is malformed or differs", refusal)

    def test_a_symlinked_journal_is_not_read(self):
        prov, home, record = self._host()
        journal = self.fixture.state / "journal.sqlite3"
        copy = self.fixture.state.parent / "journal-copy.sqlite3"
        copy.write_bytes(journal.read_bytes())
        journal.unlink()
        journal.symlink_to(copy)
        self.assertTrue(any("journal is unavailable or a symlink" in p for p in self._unified(prov, home, record)))
        self.assertIn("journal is unavailable or a symlink", self._startup_refuses())

    def test_an_empty_or_malformed_trust_binds_nothing(self):
        import codex_adoption as adoptions
        row = {"state": "confirmed", "thread_id": transition_tests.THREAD, "fingerprint": "a" * 64,
               "previous_fingerprint": "b" * 64, "policy_hash": "c" * 64, "history_sha256": "d" * 64}
        trusted = {"thread": (row["thread_id"],), "fingerprint": (row["fingerprint"],),
                   "previous_fingerprint": (row["previous_fingerprint"],), "policy_hash": (row["policy_hash"],)}
        self.assertEqual(adoptions.problems(row, **trusted), [])
        for name in trusted:
            for bound in ((), (None,), ("A" * 64,)):
                if name == "thread" and bound == ("A" * 64,):
                    continue
                with self.subTest(name=name, bound=bound):
                    found = adoptions.problems(row, **{**trusted, name: bound})
                    label = "thread" if name == "thread" else name
                    self.assertTrue(any(f"native adoption {label} has no valid expected value" in p for p in found), found)

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

class InstalledAdoptionClosureTest(unittest.TestCase):
    """The installed payload's Codex modules import with only the payload on the path (-I -S, from an
    unrelated directory), so every module a startup or verify path reaches is shipped beside it."""

    def test_every_installed_codex_module_imports_and_the_transition_entry_runs(self):
        import subprocess
        import tempfile
        import _workspace
        import amap_sandy as prov
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            prov.feature_root(home).mkdir(parents=True)
            prov.install_feature_payload(home, prov.DEFAULT_CONNECTOR_SRC, dry_run=False,
                                         codex_src=_workspace.CODEX_CONNECTOR_ROOT)
            installed = prov.feature_payload_dir(home) / "codex"
            modules = sorted(p.stem for p in installed.glob("codex_*.py"))
            self.assertIn("codex_adoption", modules)
            elsewhere = root / "elsewhere"
            elsewhere.mkdir()
            code = "import sys; sys.path[:0] = [sys.argv[1]]\nfor name in sys.argv[2:]: __import__(name)"
            run = subprocess.run([sys.executable, "-I", "-S", "-c", code, str(installed), *modules],
                                 cwd=elsewhere, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            state = root / "state"
            state.mkdir()
            # The relay runs the entry as a script, whose own directory leads sys.path; -I would drop it
            # (-P), so the entry keeps -I's other isolation: -E -s, plus -S.
            route = subprocess.run([sys.executable, "-E", "-s", "-S", str(installed / "transition"), "--state",
                                    str(state), "entry-mode"], cwd=elsewhere, capture_output=True, text=True)
            self.assertEqual((route.returncode, route.stdout.strip()), (0, "separate"), route.stderr)


if __name__ == "__main__":
    unittest.main()
