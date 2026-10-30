"""Stopped transition ordering against the real connector configuration/journal.

No native process is started. Confirmation fixtures use the connector's actual
committed adoption/binding schema, as emitted by unified_maintenance.adopt.
"""
import json
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

if sys.version_info < (3, 11):
    raise unittest.SkipTest("connector execution requires Python 3.11")

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import _workspace
sys.path.insert(0, str(_workspace.CODEX_CONNECTOR_ROOT / "src"))
import codex_assets as assets
import codex_transition as transition
from amap_codex.config import Config
from amap_codex.journal import Journal
from amap_codex.supervisor import Ownership

THREAD = "11111111-1111-4111-8111-111111111111"
OLD_THREAD = "22222222-2222-4222-8222-222222222222"


class TransitionTest(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory(prefix=".ct-", dir=os.environ.get("AMAP_TEST_TMPDIR"))
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        import _execution_identity
        self.identity_driver = _execution_identity.fixture(self, self.root)
        self.native_home = self.root / "native-home"
        self.native_home.mkdir()
        (self.native_home / "config.toml").write_text('model = "test-model"\n')
        environment = mock.patch.dict(os.environ, {"CODEX_HOME": str(self.native_home),
            "CODEX_MODEL": "", "SANDY_SKIP_PERMISSIONS": "true"})
        environment.start()
        self.addCleanup(environment.stop)
        self.state = self.root / "codex"
        self.state.mkdir(mode=0o700)
        self.payload = self.root / "payload"
        self.policy = self.root / "policy"
        self.policy.write_text("previous protected policy")
        self.mcp = HERE / "payload/codex/mcp.toml"
        assets.install(self.payload, self.policy, self.mcp, dry_run=False)
        self.doc = dict(instance_id="codex-test", self_address="codex@example.org",
                        launch_argv=["codex", "app-server", "--listen", "stdio://"],
                        codex_model="test-model", codex_version="codex-cli 0.164.0",
                        state_dir=str(self.state), cwd=str(self.root), sandbox="danger-full-access",
                        approval_policy="never", operator_kickoff_enabled=True,
                        operator_instructions=str(self.payload / "operator-instructions.md"),
                        trusted_config_file=str(self.payload / "mcp.toml"))
        claims = self.state / "claims"
        claims.mkdir()
        self.doc["lanes"] = {}
        for name in ("mail", "peer"):
            root = self.root / name
            for leaf in ("notices", "messages"):
                (root / leaf).mkdir(parents=True)
            self.doc["lanes"][name] = dict(notice_dir=str(root / "notices"),
                message_dir=str(root / "messages"), claim_path=str(claims / (name + ".json")))
        (self.state / "controller.toml").write_bytes(transition.toml_bytes(self.doc))
        self.previous_raw = (self.state / "controller.toml").read_bytes()
        self.previous = Config.load(self.state / "controller.toml", create_state=False)
        journal = Journal(self.state, self.previous.instance_id, self.previous.fingerprint(),
                          self.previous.codex_version, self.previous.codex_model)
        journal.bind_thread(OLD_THREAD)
        journal.close()
        self.policy.write_text("new protected policy")
        assets.install(self.payload, self.policy, self.mcp, dry_run=False)

    def prepare(self, **kw):
        return transition.prepare(self.state, self.payload, THREAD, **kw)

    def test_complete_endpoint_path_has_valid_fixture_and_long_state_refuses_before_writes(self):
        endpoint = self.state / ("u-" + "0" * 32) / "b"
        with self.subTest(endpoint=str(endpoint), path_bytes=len(os.fsencode(str(endpoint)))):
            self.prepare()
        long_state = self.root / ("state-" + "x" * 120)
        long_state.mkdir(mode=0o700)
        endpoint = long_state / ("u-" + "0" * 32) / "b"
        with self.subTest(endpoint=str(endpoint), path_bytes=len(os.fsencode(str(endpoint)))):
            with self.assertRaisesRegex(ValueError, "native Unix endpoint path bound"):
                transition.prepare(long_state, self.payload, THREAD, apply=True)
        self.assertEqual(list(long_state.iterdir()), [])

    def commit_adoption_fixture(self, *, policy_matches=True, confirmed=True):
        """Populate exactly the fields committed atomically by the connector."""
        target = transition.config_at(self.state)
        with closing(sqlite3.connect(self.state / "journal.sqlite3")) as db, db:
            db.execute("UPDATE instance SET fingerprint=?,thread_id=?", (target.fingerprint(), THREAD))
            # The connector's DDL (amap_codex.unified_maintenance), constraints included.
            db.execute("CREATE TABLE unified_adoptions (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
                       "thread_id TEXT NOT NULL, previous_fingerprint TEXT NOT NULL, fingerprint TEXT NOT NULL, "
                       "policy_hash TEXT NOT NULL, history_sha256 TEXT NOT NULL, state TEXT NOT NULL)")
            db.execute("INSERT INTO unified_adoptions VALUES(1,?,?,?,?,?,?)", (THREAD, self.previous.fingerprint(),
                       target.fingerprint(), "a" * 64, "b" * 64, "confirmed" if confirmed else "planned"))
            db.execute("CREATE TABLE unified_binding (instance_id TEXT PRIMARY KEY, thread_id TEXT NOT NULL, "
                       "policy_hash TEXT NOT NULL, effective_model TEXT NOT NULL)")
            db.execute("INSERT INTO unified_binding VALUES(?,?,?,?)", (target.instance_id, THREAD,
                       ("a" if policy_matches else "c") * 64, target.codex_model))

    def test_prepare_refuses_when_the_retained_previous_bytes_differ(self):
        """The expected previous fingerprint is recorded only from the exact retained bytes."""
        real = assets.place

        def altered(path, raw, **kwargs):
            if path == self.state / transition.PREVIOUS:
                raw = raw + b"\n# altered after placement\n"
            return real(path, raw, **kwargs)

        with mock.patch.object(assets, "place", side_effect=altered):
            with self.assertRaisesRegex(ValueError, "does not yield the recorded previous fingerprint"):
                self.prepare(apply=True)
        self.assertFalse((self.state / transition.RECORD).exists())
        self.assertEqual((self.state / "controller.toml").read_bytes(), self.previous_raw)

    def test_dry_run_preserves_controller_and_does_not_create_gate(self):
        self.assertFalse(self.prepare()["apply"])
        self.assertEqual((self.state / "controller.toml").read_bytes(), self.previous_raw)
        self.assertFalse((self.state / transition.RECORD).exists())
        self.assertEqual(transition.entry_mode(self.state), "separate")

    def route(self, **session_overrides):
        path = self.root / "session.json"
        path.write_text(json.dumps({"sandbox_name": self.previous.instance_id,
                                    "workspace": self.previous.cwd, **session_overrides}))
        with mock.patch.dict(os.environ, {"AMAP_INBOX_DIR": str(self.root / "mail"),
                                         "AMAP_PEER_DIR": str(self.root / "peer")}):
            return transition.startup_route(self.state, path)

    def test_startup_route_keeps_unadopted_state_on_the_fresh_guard(self):
        before = (self.state / "controller.toml").read_bytes()
        self.assertEqual(self.route(), "fresh")
        self.assertEqual((self.state / "controller.toml").read_bytes(), before)
        self.assertFalse((self.state / "fresh-birth.json").exists())

    def test_confirmed_adoption_routes_read_only_and_retains_pause(self):
        self.prepare(apply=True)
        self.commit_adoption_fixture()
        transition.confirm(self.state, apply=True)
        transition.pause(self.state, "maintenance", apply=True)
        before = {p: p.read_bytes() for p in self.state.rglob("*") if p.is_file()}
        self.assertEqual(self.route(), "adopted")
        self.assertEqual({p: p.read_bytes() for p in self.state.rglob("*") if p.is_file()}, before)
        for session in ({"sandbox_name": "foreign"}, {"workspace": "/foreign"}, {"workspace": "relative"}):
            with self.subTest(session=session), self.assertRaisesRegex(ValueError, "another Sandy"):
                self.route(**session)

    def test_prepared_or_malformed_adoption_never_falls_back_to_fresh(self):
        self.prepare(apply=True)
        with self.assertRaisesRegex(ValueError, "adoption is pending"):
            self.route()
        (self.state / transition.RECORD).write_text("{}")
        with self.assertRaises(ValueError):
            self.route()
        self.assertFalse((self.state / "fresh-birth.json").exists())

    def test_routing_requires_committed_adoption_not_only_a_confirmed_adapter_marker(self):
        self.prepare(apply=True)
        self.commit_adoption_fixture()
        transition.confirm(self.state, apply=True)
        with closing(sqlite3.connect(self.state / "journal.sqlite3")) as db, db:
            db.execute("UPDATE unified_adoptions SET state='planned'")
        with self.assertRaisesRegex(ValueError, "not confirmed"):
            self.route()

    def test_mixed_fresh_and_adopted_evidence_refuses_routing(self):
        self.prepare(apply=True)
        self.commit_adoption_fixture()
        transition.confirm(self.state, apply=True)
        (self.state / "fresh-birth.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "cannot enter"):
            self.route()

    def test_prepare_saves_original_before_gate_before_final_path_replacement(self):
        calls = []
        real = assets.place

        def checked(path, raw, **kw):
            calls.append(path.name)
            if path.name == "controller.toml":
                self.assertEqual((self.state / transition.PREVIOUS).read_bytes(), self.previous_raw)
                self.assertEqual(transition.read_record(self.state)["state"], "prepared")
            return real(path, raw, **kw)

        with mock.patch.object(assets, "place", side_effect=checked):
            self.prepare(apply=True)
        self.assertLess(calls.index(transition.PREVIOUS), calls.index(transition.RECORD))
        self.assertLess(calls.index(transition.RECORD), calls.index("controller.toml"))
        self.assertEqual(Config.load(self.state / transition.PREVIOUS).fingerprint(), self.previous.fingerprint())
        target = transition.config_at(self.state)
        self.assertEqual(target.conversation_mode, "unified")
        self.assertFalse(target.operator_kickoff_enabled)
        self.assertEqual(target.codex_model, self.previous.codex_model)
        self.assertEqual((target.sandbox, target.approval_policy), (self.previous.sandbox, self.previous.approval_policy))
        with self.assertRaisesRegex(ValueError, "adoption is pending"):
            transition.entry_mode(self.state)

    def test_repeated_prepare_is_byte_stable_and_foreign_thread_refuses(self):
        self.prepare(apply=True)
        paths = [self.state / n for n in (transition.RECORD, transition.PREVIOUS, "controller.toml")]
        before = [(p.read_bytes(), p.stat().st_mtime_ns) for p in paths]
        self.prepare(apply=True)
        self.assertEqual(before, [(p.read_bytes(), p.stat().st_mtime_ns) for p in paths])
        with self.assertRaisesRegex(ValueError, "another"):
            transition.prepare(self.state, self.payload, OLD_THREAD, apply=True)

    def test_interruption_after_gate_keeps_original_and_retries_exact_target(self):
        real = assets.place

        def interrupt(path, raw, **kw):
            if path.name == "controller.toml":
                raise OSError("interrupted before target")
            return real(path, raw, **kw)

        with mock.patch.object(assets, "place", side_effect=interrupt):
            with self.assertRaises(OSError):
                self.prepare(apply=True)
        self.assertEqual((self.state / "controller.toml").read_bytes(), self.previous_raw)
        with self.assertRaisesRegex(ValueError, "adoption is pending"):
            transition.entry_mode(self.state)
        self.prepare(apply=True)
        self.assertEqual(transition.config_at(self.state).conversation_mode, "unified")

    def test_active_controller_refuses_without_snapshot_or_gate(self):
        with Ownership(self.previous):
            with self.assertRaisesRegex(RuntimeError, "another controller"):
                self.prepare(apply=True)
        self.assertFalse((self.state / transition.RECORD).exists())
        self.assertFalse((self.state / transition.PREVIOUS).exists())
        self.assertEqual((self.state / "controller.toml").read_bytes(), self.previous_raw)

    def test_uncommitted_or_mismatched_policy_cannot_release_gate(self):
        self.prepare(apply=True)
        with self.assertRaisesRegex(ValueError, "journal"):
            transition.confirm(self.state, apply=True)
        self.commit_adoption_fixture(policy_matches=False)
        with self.assertRaisesRegex(ValueError, "protected policy"):
            transition.confirm(self.state, apply=True)
        self.assertEqual(transition.read_record(self.state)["state"], "prepared")

    def test_confirmed_adoption_allows_only_canonical_unchanged_settings(self):
        self.prepare(apply=True)
        self.commit_adoption_fixture()
        self.assertFalse(transition.confirm(self.state)["apply"])
        self.assertEqual(transition.read_record(self.state)["state"], "prepared")
        transition.confirm(self.state, apply=True)
        self.assertEqual(transition.entry_mode(self.state, selected_model="test-model",
                                              observed_version="codex-cli 0.164.0"), "unified")
        with self.assertRaisesRegex(ValueError, "model changed"):
            transition.entry_mode(self.state, selected_model="other")
        with self.assertRaisesRegex(ValueError, "build changed"):
            transition.entry_mode(self.state, observed_version="codex-cli 0.165.0")
        before = (self.state / transition.RECORD).stat().st_mtime_ns
        transition.confirm(self.state, apply=True)
        self.assertEqual((self.state / transition.RECORD).stat().st_mtime_ns, before)

    def test_native_planned_adoption_is_not_confirmation(self):
        self.prepare(apply=True)
        self.commit_adoption_fixture(confirmed=False)
        with self.assertRaisesRegex(ValueError, "not confirmed"):
            transition.confirm(self.state, apply=True)

    def confirmed(self):
        self.prepare(apply=True)
        self.commit_adoption_fixture()
        transition.confirm(self.state, apply=True)

    def measured_build(self, version):
        return mock.patch.object(transition.subprocess, "run", return_value=
            subprocess.CompletedProcess(["codex", "--version"], 0, version + "\n", ""))

    def test_sandy_build_updates_preserve_adoption_and_audit_on_service_restart(self):
        self.confirmed()
        original_record = (self.state / transition.RECORD).read_bytes()
        original_previous = (self.state / transition.PREVIOUS).read_bytes()
        original_controller = (self.state / "controller.toml").read_bytes()
        baseline = transition.read_record(self.state)
        with closing(sqlite3.connect(self.state / "journal.sqlite3")) as db:
            original_adoption = db.execute("SELECT * FROM unified_adoptions").fetchall()
            original_binding = db.execute("SELECT * FROM unified_binding").fetchall()
        for version in ("codex-cli 0.166.0", "codex-cli 0.167.0"):
            with self.subTest(version=version), self.measured_build(version):
                preview = transition.refresh_build(self.state, version)
                self.assertTrue(preview["changed"])
                transition.refresh_build(self.state, version, apply=True)
                config = transition.config_at(self.state)
                self.assertEqual(config.codex_version, version)
                self.assertEqual(config.fingerprint(), baseline["fingerprint"])
                self.assertEqual(transition.entry_mode(self.state, observed_version=version), "unified")
                self.assertEqual(transition.read_record(self.state)["codex_version"], version)
                self.assertEqual((self.state / transition.RECORD).read_bytes(), original_record)
                self.assertEqual((self.state / transition.PREVIOUS).read_bytes(), original_previous)
                with closing(sqlite3.connect(self.state / "journal.sqlite3")) as db:
                    self.assertEqual(db.execute("SELECT * FROM unified_adoptions").fetchall(), original_adoption)
                    self.assertEqual(db.execute("SELECT * FROM unified_binding").fetchall(), original_binding)
                with Journal(self.state, config.instance_id, config.fingerprint(), version, config.codex_model) as journal:
                    self.assertEqual(journal.thread_id, THREAD)
                    self.assertEqual(journal.db.execute("SELECT note FROM audit WHERE action='codex_version_changed' ORDER BY id DESC").fetchone()[0].split(' -> ')[-1], version)
                self.assertFalse(transition.refresh_build(self.state, version, apply=True)["changed"])
        self.assertEqual((self.state / 'controller-history' / (assets.digest(original_controller) + '.toml')).read_bytes(), original_controller)

    def test_build_refresh_refuses_active_service_pause_downgrade_and_changed_measurement(self):
        self.confirmed()
        config = transition.config_at(self.state)
        before = (self.state / 'controller.toml').read_bytes()
        with Ownership(config), self.measured_build("codex-cli 0.166.0"):
            with self.assertRaisesRegex(RuntimeError, "another controller"):
                transition.refresh_build(self.state, "codex-cli 0.166.0", apply=True)
        transition.pause(self.state, "maintenance", apply=True)
        with self.measured_build("codex-cli 0.166.0"), self.assertRaisesRegex(ValueError, "pause"):
            transition.refresh_build(self.state, "codex-cli 0.166.0", apply=True)
        transition.unpause(self.state, apply=True)
        with self.assertRaisesRegex(ValueError, "backwards"):
            transition.refresh_build(self.state, "codex-cli 0.163.0", apply=True)
        with self.measured_build("codex-cli 0.167.0"), self.assertRaisesRegex(ValueError, "measurement"):
            transition.refresh_build(self.state, "codex-cli 0.166.0", apply=True)
        self.assertEqual((self.state / 'controller.toml').read_bytes(), before)

    def test_build_projection_never_accepts_model_or_permission_edits(self):
        import codex_adoption as adoption
        self.confirmed()
        baseline = transition.read_record(self.state)
        path = self.state / "controller.toml"
        raw = path.read_bytes()
        for previous, updated in ((b'test-model', b'foreign-model'), (b'danger-full-access', b'read-only')):
            with self.subTest(updated=updated):
                path.write_bytes(adoption.with_build(raw, "codex-cli 0.166.0").replace(previous, updated))
                with self.assertRaisesRegex(ValueError, "beyond an advancing Codex build"):
                    transition.read_record(self.state)
        path.write_bytes(raw)

    def test_build_refresh_refuses_missing_native_confirmation_and_bad_measurements(self):
        self.confirmed()
        path = self.state / "controller.toml"
        before = path.read_bytes()
        for version in ('', 'codex-cli unknown', 'codex-cli 0.166.0\nextra'):
            with self.subTest(version=version), self.assertRaises(ValueError):
                transition.refresh_build(self.state, version, apply=True)
        with mock.patch.object(transition.subprocess, 'run', side_effect=subprocess.TimeoutExpired('codex', 10)):
            with self.assertRaises(subprocess.TimeoutExpired):
                transition.refresh_build(self.state, 'codex-cli 0.166.0', apply=True)
        with closing(sqlite3.connect(self.state / 'journal.sqlite3')) as db, db:
            db.execute("UPDATE unified_adoptions SET state='planned'")
        with self.assertRaisesRegex(ValueError, 'not confirmed'):
            transition.refresh_build(self.state, 'codex-cli 0.166.0', apply=True)
        self.assertEqual(path.read_bytes(), before)

    def test_wait_selection_times_out_with_the_relay_reason_and_accepts_current_challenge(self):
        import codex_settings as settings
        self.confirmed()
        generation = settings.environment_generation()
        settings.capture(self.state, self.previous.instance_id, settings.resolve(os.environ), generation=generation)
        (self.state / 'hold.json').write_text(json.dumps({'reason': 'installed backend cannot initialize'}))
        with self.assertRaisesRegex(ValueError, 'installed backend cannot initialize'):
            transition.wait_selection(self.state, wait=0)
        with self.assertRaises(ValueError):
            transition.startup_gate(self.state, generation, apply=True)
        transition.wait_selection(self.state)

    def test_pane_waits_for_the_current_generation_instead_of_using_old_challenge(self):
        import codex_settings as settings
        self.confirmed()
        generation = settings.environment_generation()
        settings.capture(self.state, self.previous.instance_id, settings.resolve(os.environ), generation=generation)
        config = transition.config_at(self.state)
        stale = settings.startup_request(self.state, config, THREAD, 'b' * 32)
        (self.state / settings.STARTUP).write_bytes(assets.encoded(stale))
        def relay_publishes(_):
            current = settings.startup_request(self.state, config, THREAD, generation)
            (self.state / settings.STARTUP).write_bytes(assets.encoded(current))
        with mock.patch.object(transition.time, 'sleep', side_effect=relay_publishes) as sleep:
            transition.wait_selection(self.state)
        sleep.assert_called_once()

    def test_manual_unified_mode_without_transition_never_defaults_to_separate(self):
        self.doc.update(conversation_mode="unified", unified_argv=["codex"], operator_kickoff_enabled=False)
        (self.state / "controller.toml").write_bytes(transition.toml_bytes(self.doc))
        with self.assertRaisesRegex(ValueError, "lacks explicit"):
            transition.entry_mode(self.state)

    def test_prepare_selects_forwarded_pane_model_before_native_config_and_old_controller(self):
        with mock.patch.dict(os.environ, {"CODEX_MODEL": "selected-pane-model"}):
            result = self.prepare(apply=True)
            self.assertEqual(result["model_source"], "CODEX_MODEL")
            self.assertEqual(transition.config_at(self.state).codex_model, "selected-pane-model")
            self.assertEqual(Config.load(self.state / transition.PREVIOUS).codex_model, "test-model")
            self.commit_adoption_fixture()
            transition.confirm(self.state, apply=True)
            self.assertEqual(transition.entry_mode(self.state, check_pane_settings=True), "unified")
        with self.assertRaisesRegex(ValueError, "pane CODEX_MODEL/native model differs"):
            transition.entry_mode(self.state, check_pane_settings=True)

    def test_unified_unknown_or_conflicting_permissions_refuse_before_writing(self):
        for value in ("", "false", "unknown"):
            with self.subTest(value=value), mock.patch.dict(os.environ, {"SANDY_SKIP_PERMISSIONS": value}):
                with self.assertRaisesRegex(ValueError, "permissions are unknown or conflicting"):
                    self.prepare(apply=True)
                self.assertEqual((self.state / "controller.toml").read_bytes(), self.previous_raw)
                self.assertFalse((self.state / transition.RECORD).exists())

    def test_full_argv_selection_precedes_service_and_is_entry_generation_bound(self):
        import codex_settings as settings
        self.prepare(apply=True)
        self.commit_adoption_fixture()
        transition.confirm(self.state, apply=True)
        selection = settings.resolve(os.environ)
        generation = settings.environment_generation()
        settings.capture(self.state, self.previous.instance_id, selection, generation=generation)
        with self.assertRaisesRegex(ValueError, "full native argv selection is pending"):
            transition.startup_gate(self.state, generation, apply=True)
        for argv in (["codex", "-a", "on-request"], ["codex", "-m", "foreign"],
                     ["codex"], ["codex", "-s", "danger-full-access"], ["codex", "-a", "never"],
                     ["codex", "--profile", "custom"], ["codex", "-c", 'model_reasoning_effort="high"']):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                transition.select_pane(self.state, argv, apply=True)
            self.assertFalse((self.state / settings.PANE_SELECTION).exists())
        transition.select_pane(self.state, ["codex", "--model", "test-model", "--sandbox", "danger-full-access", "-a", "never"], apply=True)
        self.assertTrue(transition.startup_gate(self.state, generation, apply=True)["selected"])
        settings.capture(self.state, self.previous.instance_id, selection, generation="b" * 32)
        with self.assertRaisesRegex(ValueError, "generation differs"):
            transition.startup_gate(self.state, "b" * 32, apply=True)

    def test_first_upgrade_stale_capture_refuses_even_when_fingerprint_is_unchanged(self):
        import codex_bootstrap_pause as bootstrap
        bootstrap.pause(self.state, "first upgrade", apply=True)
        path = self.state / "controller.toml"
        path.write_bytes(self.previous_raw + b"\n# another entry rendering\n")
        self.assertEqual(Config.load(path).fingerprint(), self.previous.fingerprint())
        with self.assertRaisesRegex(ValueError, "inputs changed"):
            self.prepare(apply=True)
        self.assertFalse((self.state / transition.RECORD).exists())

    def test_protected_drift_after_prepare_cannot_confirm_a_different_target(self):
        self.prepare(apply=True)
        target = transition.config_at(self.state)
        target.operator_instructions.write_text("changed protected target")
        self.assertNotEqual(target.fingerprint(), transition.read_record(self.state)["fingerprint"])
        # Model the connector's valid adoption of the changed current target.
        self.commit_adoption_fixture()
        with self.assertRaisesRegex(ValueError, "differs"):
            transition.confirm(self.state, apply=True)
        record = transition.read_record(self.state)
        self.assertEqual(record["state"], "prepared")
        record.update(state="confirmed", policy_hash="a" * 64)
        assets.place(self.state / transition.RECORD, assets.encoded(record), replace=True, mode=0o600)
        with self.assertRaisesRegex(ValueError, "differs"):
            transition.entry_mode(self.state)

    def test_pause_is_explicit_does_not_stop_and_blocks_unpause_during_transition(self):
        transition.pause(self.state, "operator-selected maintenance")
        self.assertFalse((self.state / transition.PAUSE).exists())
        with Ownership(self.previous):
            transition.pause(self.state, "operator-selected maintenance", apply=True)
            with self.assertRaisesRegex(RuntimeError, "another controller"):
                transition.unpause(self.state, apply=True)
        self.prepare(apply=True)
        with self.assertRaisesRegex(ValueError, "adoption is pending"):
            transition.unpause(self.state, apply=True)
        self.commit_adoption_fixture()
        transition.confirm(self.state, apply=True)
        transition.unpause(self.state, apply=True)
        self.assertFalse((self.state / transition.PAUSE).exists())


if __name__ == "__main__":
    unittest.main()
