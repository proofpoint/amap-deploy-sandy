"""Fresh birth and preselection guard the real core's journal and service calls.

The native protocol is a local in-memory fake. UnifiedService and Journal run
unmodified; these fixtures never manufacture an adoption or canonical SQL row.
"""
import asyncio
import json
import os
from pathlib import Path
import shutil
import shlex
import signal
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

import _workspace
_workspace.skip_if_incomplete()
import amap_sandy as prov
import codex_assets as assets
import codex_fleet as fleet
import codex_fresh as fresh
import codex_settings as settings

HERE = Path(__file__).resolve().parents[1]
NATIVE = ["codex", "--model", "fixture-model", "--dangerously-bypass-approvals-and-sandbox"]


class NativeProtocol:
    def __init__(self, config):
        self.config = config
        self.thread = None
        self.starts = self.resumes = self.names = self.model_requests = 0
        self.lost_ack = False
        self.blocked = []
        self.closed = False
        self.notifications = asyncio.Queue()
        self.sequence = 0
        self.calls = []
        self.active = False

    def reserve_id(self):
        self.sequence += 1
        return self.sequence

    async def request(self, method, params, **kwargs):
        self.calls.append(method)
        if method == "config/read":
            return {"config": {}}
        if method == "thread/start":
            self.starts += 1
            self.thread = str(uuid.uuid4())
            if self.lost_ack:
                from amap_codex.app_server import Uncertain
                raise Uncertain("fixture lost native start acknowledgement")
        elif method == "thread/resume":
            self.resumes += 1
            if params["threadId"] != self.thread:
                raise AssertionError("attempted foreign native history")
        elif method == "thread/name/set":
            self.names += 1
            return {}
        elif method == "mcpServerStatus/list":
            protected = self.config.trusted_overrides()["mcp_servers"]
            return {"data": [{"name": name, "tools": dict.fromkeys(value["enabled_tools"], {})}
                              for name, value in protected.items()] +
                             [{"name": "amap_fleet", "tools": {"activity": {}}}]}
        elif method == "thread/read":
            return {"thread": {"id": self.thread, "status": {"type": "active" if self.active else "idle"}}}
        elif method in {"thread/turns/list", "thread/items/list", "thread/queue/list"}:
            return {"data": []}
        else:
            self.model_requests += 1
            raise AssertionError("unexpected native/model request: " + method)
        return {"thread": {"id": self.thread}, "model": self.config.codex_model,
                "approvalPolicy": "never", "sandbox": {"type": "dangerFullAccess"}, "cwd": self.config.cwd}


class FakeGate:
    def __init__(self, backend, policy):
        self.client_count = 0
        self.accepting = False
    async def start(self): pass
    async def close(self): pass


@unittest.skipUnless(sys.version_info >= (3, 11), "fresh native execution requires Python 3.11")
class FreshBirthTest(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory(prefix="f-", dir=os.environ.get("AMAP_TEST_TMPDIR"))
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / "s"
        self.payload = self.root / "p"
        self.native = self.root / "n"
        self.native.mkdir()
        (self.native / "config.toml").write_text('model = "fixture-model"\n')
        self.env = dict(os.environ, AMAP_CODEX_CONVERSATION_MODE="unified", CODEX_HOME=str(self.native),
                        CODEX_MODEL="fixture-model", SANDY_SKIP_PERMISSIONS="true")
        for key, name in (("AMAP_INBOX_DIR", "mail"), ("AMAP_PEER_DIR", "peer"), ("AMAP_OUTBOX_DIR", "out")):
            root = self.root / name
            root.mkdir()
            for leaf in ("notices", "messages"):
                (root / leaf).mkdir()
            self.env[key] = str(root)
        patch = mock.patch.dict(os.environ, self.env)
        patch.start()
        self.addCleanup(patch.stop)
        sys.path.insert(0, str(_workspace.CODEX_CONNECTOR_ROOT / "src"))
        self.addCleanup(sys.path.remove, str(_workspace.CODEX_CONNECTOR_ROOT / "src"))
        policy = self.root / "policy"
        policy.write_text("Protected fixture policy")
        assets.install(self.payload, policy, HERE / "payload/codex/mcp.toml", dry_run=False)
        self.session = {"sandbox_name": "fresh-fixture", "workspace": str(self.root)}
        self.born = fresh.birth(self.state, self.session, self.env)
        self.context = {**self.born["identity"], "payload": str(self.payload), "codex_version": "codex-cli 0.164.0",
                        "self_address": "fresh@example.org"}

    def prepare(self):
        return fresh.prepare(self.state, self.payload, self.context, self.env)

    def select(self):
        fresh.publish_request(self.state, self.env)
        return fresh.select_pane(self.state, NATIVE, self.env)

    def runtime(self):
        config = fresh.config_at(self.state)
        self.protocol = getattr(self, "protocol", NativeProtocol(config))
        protocol = self.protocol
        state = self.state
        class Backend:
            def __init__(self, *args, **kwargs):
                self.generation = uuid.uuid4().hex
                self.front_path = state / ("u-" + self.generation) / "t"
                self.process = None
                self.client = protocol
            async def start(self):
                self.process = SimpleNamespace(returncode=None, pid=os.getpid())
                return self.client
            async def stop(self):
                if self.process is not None:
                    self.process.returncode = 0
        import amap_codex.unified as core
        return mock.patch.multiple(core, ManagedBackend=Backend, AttachGate=FakeGate)

    def test_birth_is_exclusive_and_repeat_has_the_same_identity(self):
        self.assertEqual(fresh.birth(self.state, self.session, self.env), self.born)
        self.assertFalse((self.state / "controller.toml").exists())
        other = self.root / "old"
        other.mkdir(mode=0o700)
        for name in (None, "controller.toml", "journal.sqlite3", "adapter-transition.json"):
            with self.subTest(existing=name):
                if name:
                    (other / name).write_bytes(b"retained old bytes")
                before = {p.name: p.read_bytes() for p in other.iterdir()}
                with self.assertRaisesRegex(ValueError, "operator recreation"):
                    fresh.birth(other, self.session, self.env)
                self.assertEqual({p.name: p.read_bytes() for p in other.iterdir()}, before)
                if name:
                    (other / name).unlink()

    def test_retained_mailbox_work_blocks_first_birth_but_new_work_after_birth_is_retained(self):
        notice = Path(self.env["AMAP_INBOX_DIR"]) / "notices" / "retained.json"
        notice.write_bytes(b"retained work; never replay automatically")
        other = self.root / "b"
        with self.assertRaisesRegex(ValueError, "retained mailbox entries"):
            fresh.birth(other, self.session, self.env)
        self.assertFalse(other.exists())
        self.assertEqual(notice.read_bytes(), b"retained work; never replay automatically")
        self.assertEqual(fresh.birth(self.state, self.session, self.env), self.born)
        self.assertEqual(notice.read_bytes(), b"retained work; never replay automatically")
        notice.unlink()
        target = self.root / "outside"
        target.mkdir()
        (Path(self.env["AMAP_OUTBOX_DIR"]) / "link").symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "retained mailbox entries"):
            fresh.birth(other, self.session, self.env)
        self.assertEqual(list(target.iterdir()), [])

    def test_partial_birth_cannot_enter_the_legacy_separate_helper(self):
        import codex_transition as transition
        for mode in (None, "separate"):
            with self.subTest(mode=mode), mock.patch.dict(os.environ):
                if mode is None:
                    os.environ.pop(fleet.EXPORT, None)
                else:
                    os.environ[fleet.EXPORT] = mode
                with self.assertRaisesRegex(ValueError, "cannot enter"):
                    transition.entry_mode(self.state)
        separate = self.root / "legacy"
        separate.mkdir(mode=0o700)
        self.assertEqual(transition.entry_mode(separate), "separate")
        self.assertEqual(list(separate.iterdir()), [])

    def test_shipped_separate_or_absent_mode_preserves_partial_fresh_birth_without_renderer(self):
        home = self.root / "h"
        prov.install_feature_payload(home, prov.DEFAULT_CONNECTOR_SRC, dry_run=False,
                                     codex_src=_workspace.CODEX_CONNECTOR_ROOT)
        installed = prov.feature_payload_dir(home) / "codex"
        session = self.root / "session.json"
        session.write_text(json.dumps(self.session))
        relay = installed / "relay"
        relay.write_text(relay.read_text().replace("SANDY_SESSION_FILE=/etc/sandy-session.json",
                                                  "SANDY_SESSION_FILE=" + str(session)))
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        (bin_dir / "codex").write_text("#!/bin/sh\necho called >> \"$NATIVE_CALLS\"\ncase \"$1\" in\n"
            "login) exit 0 ;;\n--version) echo 'codex-cli 0.164.0'; exit 0 ;;\n*) exit 9 ;;\nesac\n")
        (bin_dir / "python3").write_text("#!/bin/sh\nif [ \"$1\" = -m ] && [ \"$2\" = amap_codex.cli ]; then "
            "echo legacy >> \"$LEGACY_RUNS\"; exit 0; fi\nexec " + shlex.quote(sys.executable) + " \"$@\"\n")
        for name in ("codex", "python3"):
            (bin_dir / name).chmod(0o755)
        case = 0
        for with_plan in (False, True):
            for mode in (None, "separate", "", "foreign"):
                with self.subTest(plan=with_plan, mode=mode):
                    parent = self.root / ("e" + str(case))
                    parent.mkdir()
                    state = parent / "codex"
                    calls = self.root / ("calls" + str(case))
                    legacy = self.root / ("runs" + str(case))
                    case += 1
                    fresh.birth(state, self.session, self.env)
                    if with_plan:
                        (state / fresh.PLAN).write_text("{}")
                    env = dict(self.env, PATH=str(bin_dir) + os.pathsep + self.env["PATH"],
                               SANDY_FEATURE_STATE=str(parent), SANDY_AGENT="codex", NATIVE_CALLS=str(calls),
                               LEGACY_RUNS=str(legacy))
                    if mode is None:
                        env.pop(fleet.EXPORT, None)
                    else:
                        env[fleet.EXPORT] = mode
                    before = {p.name: p.read_bytes() for p in state.iterdir()}
                    log = self.root / "entry-error"
                    with log.open("w") as error:
                        proc = subprocess.Popen(["/bin/sh", str(relay)], cwd=self.root, env=env,
                                                stdout=subprocess.DEVNULL, stderr=error, start_new_session=True)
                        try:
                            until = time.monotonic() + 3
                            expected = "unknown fleet conversation mode" if mode in {"", "foreign"} else "cannot downgrade"
                            while time.monotonic() < until and expected not in log.read_text() and proc.poll() is None:
                                time.sleep(.02)
                            self.assertIsNone(proc.poll())
                            self.assertIn(expected, log.read_text())
                            self.assertEqual({p.name: p.read_bytes() for p in state.iterdir()}, before)
                            self.assertFalse(calls.exists())
                            self.assertFalse(legacy.exists())
                        finally:
                            if proc.poll() is None:
                                os.killpg(proc.pid, signal.SIGTERM)
                            proc.wait(timeout=5)

    def test_foreign_birth_and_unexplained_files_cannot_get_a_controller(self):
        (self.state / "unexplained").write_bytes(b"retain")
        with self.assertRaisesRegex(ValueError, "unexplained"):
            self.prepare()
        self.assertFalse((self.state / "controller.toml").exists())
        self.assertEqual((self.state / "unexplained").read_bytes(), b"retain")
        with self.assertRaisesRegex(ValueError, "birth identity differs"):
            fresh.birth(self.state, dict(self.session, sandbox_name="foreign"), self.env)

    def test_preparation_is_idempotent_and_preserves_legacy_assets(self):
        legacy = {n: (self.payload / n).read_bytes() for n in assets.ASSETS}
        plan = self.prepare()
        raw = (self.state / "controller.toml").read_bytes()
        self.assertEqual(self.prepare(), plan)
        self.assertEqual((self.state / "controller.toml").read_bytes(), raw)
        self.assertFalse((self.state / "adapter-transition.json").exists())
        self.assertFalse((self.state / "journal.sqlite3").exists())
        self.assertEqual(fresh.initialization(self.state, plan)["phase"], "prepared")
        for name, data in legacy.items():
            self.assertEqual((self.payload / name).read_bytes(), data)
        config = fresh.config_at(self.state)
        self.assertIn("/protected/", str(config.operator_instructions))
        self.assertEqual(config.conversation_mode, "unified")

    def test_interrupted_known_preparation_reuses_only_equal_bytes(self):
        real = assets.place
        def interrupted(path, raw, **kwargs):
            if path.name == "controller.toml":
                self.assertTrue((self.state / fresh.PLAN).is_file())
                raise OSError("fixture interruption before controller publication")
            return real(path, raw, **kwargs)
        with mock.patch.object(assets, "place", side_effect=interrupted):
            with self.assertRaisesRegex(OSError, "fixture interruption"):
                self.prepare()
        self.assertFalse((self.state / "journal.sqlite3").exists())
        self.prepare()
        self.assertEqual(fresh.initialization(self.state, fresh.load_plan(self.state))["phase"], "prepared")

    def test_preselection_does_not_create_a_canonical_or_claim_readiness(self):
        self.prepare()
        self.select()
        fresh.selection_guard(self.state, self.env)
        self.assertFalse((self.state / "journal.sqlite3").exists())
        inspected = fresh.inspect(self.state, self.env)
        self.assertFalse(inspected["ready"])
        self.assertIsNone(inspected["canonical_thread_id"])
        self.assertEqual(inspected["initialization_phase"], "prepared")
        self.assertFalse((self.state / "journal.sqlite3").exists())
        with self.assertRaisesRegex(ValueError, "not readiness"):
            fresh.require_initialized(self.state, self.env)
        for suffix in (["resume", "--last"], ["resume", str(uuid.uuid4())]):
            with self.subTest(resume=suffix):
                with self.assertRaisesRegex(ValueError, "already owned"):
                    fresh.select_pane(self.state, NATIVE + suffix, self.env)

    def test_missing_or_foreign_selection_never_calls_the_core(self):
        self.prepare()
        fresh.publish_request(self.state, self.env)
        with self.runtime():
            async def check():
                service = fresh.service_class()(fresh.config_at(self.state), self.state / "controller.toml")
                try:
                    with self.assertRaises(OSError):
                        await service.start()
                finally:
                    await service.close()
            asyncio.run(check())
        self.assertEqual(self.protocol.starts, 0)
        self.assertFalse((self.state / "journal.sqlite3").exists())
        self.select()
        receipt = fresh.read_json(self.state / fresh.SELECTION)
        receipt["entry_generation"] = "f" * 32
        (self.state / fresh.SELECTION).write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, "another environment"):
            fresh.selection_guard(self.state, self.env)

    def test_forged_birth_kind_cannot_publish_configuration(self):
        value = fresh.read_json(self.state / fresh.BIRTH)
        value["kind"] = "foreign"
        (self.state / fresh.BIRTH).write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "birth evidence is malformed"):
            self.prepare()
        self.assertFalse((self.state / "controller.toml").exists())
        self.assertFalse((self.state / fresh.PLAN).exists())

    def test_full_argv_and_policy_drift_guards_fire(self):
        self.prepare()
        self.select()
        for argv in (["codex", "-m", "foreign", "--dangerously-bypass-approvals-and-sandbox"],
                     ["codex", "-a", "on-request", "-s", "danger-full-access"],
                     NATIVE + ["--cd", str(self.native)], NATIVE + ["-c", "developer_instructions=foreign"]):
            with self.subTest(argv=argv):
                with self.assertRaises(ValueError):
                    fresh.select_pane(self.state, argv, self.env)
        for key, value in (("CODEX_MODEL", "foreign"), ("SANDY_SKIP_PERMISSIONS", "false"),
                           (fleet.EXPORT, "separate")):
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, "drifted"):
                    fresh.current_guard(self.state, dict(self.env, **{key: value}))
        (self.native / "config.toml").write_text('model = "fixture-model"\n# changed controls\n')
        with self.assertRaisesRegex(ValueError, "native configuration changed"):
            fresh.current_guard(self.state, self.env)

    def test_pause_and_endpoint_bound_refuse_before_runtime(self):
        (self.state / "adapter-pause.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "maintenance pause"):
            self.prepare()
        (self.state / "adapter-pause.json").unlink()
        long = self.root / ("long-" + "x" * 100)
        fresh.birth(long, self.session, self.env)
        with self.assertRaisesRegex(ValueError, "Unix socket length"):
            fresh.prepare(long, self.payload, self.context, self.env)
        self.assertFalse((long / "controller.toml").exists())
        self.assertFalse((long / "journal.sqlite3").exists())
        self.prepare()
        self.select()
        (self.state / "adapter-pause.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "maintenance pause"):
            fresh.selection_guard(self.state, self.env)

    def test_real_core_birth_and_idle_restart_keep_one_empty_canonical(self):
        self.prepare()
        self.select()
        with self.runtime():
            async def check():
                service_type = fresh.service_class()
                for index in range(2):
                    service = service_type(fresh.config_at(self.state), self.state / "controller.toml")
                    try:
                        await service.start()
                        plan, config, bound = fresh.require_initialized(self.state, self.env)
                        self.assertEqual(bound["thread_id"], self.protocol.thread)
                        self.assertEqual(fresh.evidence_problems(self.state, service.status), [])
                        inspected = fresh.inspect(self.state, self.env)
                        self.assertTrue(inspected["ready"])
                        self.assertEqual(inspected["canonical_thread_id"], self.protocol.thread)
                        self.assertEqual(service.journal.db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)
                        self.assertEqual(self.protocol.model_requests, 0)
                        await service.tick()
                        if index == 0:
                            fresh.select_pane(self.state, NATIVE + ["resume", "--last"], self.env)
                    finally:
                        await service.close()
            asyncio.run(check())
        self.assertEqual((self.protocol.starts, self.protocol.names, self.protocol.resumes), (1, 1, 1))
        self.assertFalse((self.state / "adapter-transition.json").exists())

    def test_lost_adapter_final_receipt_recovers_real_binding_without_new_thread(self):
        self.prepare()
        self.select()
        with self.runtime():
            async def check():
                kind = fresh.service_class()
                first = kind(fresh.config_at(self.state), self.state / "controller.toml")
                try:
                    with mock.patch.object(fresh, "finalize", side_effect=OSError("fixture lost adapter receipt")):
                        await first.start()
                    self.assertFalse(first.stop_requested.is_set())
                    self.assertIsNone(first.backend.process.returncode)
                    self.assertFalse(first.gate.accepting)
                finally:
                    await first.close()
                self.assertEqual(fresh.read_json(self.state / fresh.INITIALIZATION)["phase"], "start_attempted")
                fresh.select_pane(self.state, NATIVE + ["resume", "--last"], self.env)
                second = kind(fresh.config_at(self.state), self.state / "controller.toml")
                try:
                    await second.start()
                    fresh.require_initialized(self.state, self.env)
                finally:
                    await second.close()
            asyncio.run(check())
        self.assertEqual((self.protocol.starts, self.protocol.resumes), (1, 1))

    def test_lost_native_start_ack_holds_without_creating_another_history(self):
        self.prepare()
        self.select()
        with self.runtime():
            self.protocol.lost_ack = True
            async def check():
                from amap_codex.app_server import Uncertain
                kind = fresh.service_class()
                first = kind(fresh.config_at(self.state), self.state / "controller.toml")
                try:
                    with self.assertRaises(Uncertain):
                        await first.start()
                finally:
                    await first.close()
                second = kind(fresh.config_at(self.state), self.state / "controller.toml")
                try:
                    with self.assertRaisesRegex(ValueError, "binding is unavailable"):
                        await second.start()
                finally:
                    await second.close()
            asyncio.run(check())
        self.assertEqual(self.protocol.starts, 1)
        self.assertEqual(fresh.read_json(self.state / fresh.INITIALIZATION)["phase"], "start_attempted")

    def test_installed_birth_helper_runs_from_unrelated_working_directory(self):
        home = self.root / "h"
        prov.install_feature_payload(home, prov.DEFAULT_CONNECTOR_SRC, dry_run=False,
                                     codex_src=_workspace.CODEX_CONNECTOR_ROOT)
        installed = prov.feature_payload_dir(home) / "codex"
        for name in ("codex_fresh.py", "codex_fleet.py", "codex_settings.py"):
            self.assertEqual((installed / name).read_bytes(), (HERE / name).read_bytes())
        other = self.root / "u"
        other.mkdir()
        session = self.root / "session.json"
        session.write_text(json.dumps(self.session))
        state = self.root / "b"
        result = subprocess.run([sys.executable, str(installed / "codex_fresh.py"), "--state", str(state),
                                 "birth", "--session", str(session)], env=self.env, cwd=other,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(fresh.read_json(state / fresh.BIRTH)["identity"], self.born["identity"])
        self.assertFalse((state / "journal.sqlite3").exists())


    def test_production_run_loop_pause_and_read_gap_hold_without_closing_active_backend(self):
        import codex_transition as transition
        self.prepare()
        self.select()
        with self.runtime():
            self.protocol.active = True
            async def check():
                service = fresh.service_class()(fresh.config_at(self.state), self.state / "controller.toml")
                task = asyncio.create_task(service.run())
                try:
                    until = time.monotonic() + 5
                    while time.monotonic() < until and fresh.read_json(self.state / fresh.INITIALIZATION)["phase"] != "initialized":
                        await asyncio.sleep(.02)
                    self.assertEqual(fresh.read_json(self.state / fresh.INITIALIZATION)["phase"], "initialized")
                    transition.pause(self.state, "Fixture active work remains owned", apply=True)
                    await asyncio.sleep(1.1)
                    self.assertFalse(task.done(), "pause ended the production run loop")
                    self.assertFalse(service.stop_requested.is_set())
                    self.assertIsNone(service.backend.process.returncode)
                    self.assertFalse(self.protocol.closed)
                    self.assertFalse(service.gate.accepting)
                    self.assertEqual(service.status["readiness"]["state"], "holding")
                    self.assertIn("maintenance pause", service.status["last_error"])
                    (self.state / "adapter-pause.json").unlink()
                    receipt = self.state / fresh.SELECTION
                    raw = receipt.read_bytes()
                    receipt.unlink()
                    await asyncio.sleep(1.1)
                    self.assertFalse(task.done(), "missing observation killed owned work")
                    self.assertFalse(service.stop_requested.is_set())
                    self.assertIsNone(service.backend.process.returncode)
                    self.assertFalse(self.protocol.closed)
                    self.assertFalse(service.gate.accepting)
                    receipt.write_bytes(raw)
                    await asyncio.sleep(1.1)
                    self.assertFalse(task.done())
                    self.assertEqual(self.protocol.starts, 1)
                    self.assertEqual(service.status["scheduler_state"], "active")
                finally:
                    service.stop_requested.set()
                    await asyncio.gather(task, return_exceptions=True)
            asyncio.run(check())

    def test_failed_holding_publication_does_not_close_owned_backend(self):
        self.prepare()
        self.select()
        with self.runtime():
            async def check():
                import amap_codex.supervisor as supervisor
                service = fresh.service_class()(fresh.config_at(self.state), self.state / "controller.toml")
                try:
                    await service.start()
                    (self.state / "adapter-pause.json").write_text("{}")
                    with mock.patch.object(supervisor, "atomic_json", side_effect=OSError("fixture status write unavailable")):
                        await service.tick()
                    self.assertFalse(service.stop_requested.is_set())
                    self.assertIsNone(service.backend.process.returncode)
                    self.assertFalse(service.gate.accepting)
                    self.assertEqual(service.status["readiness"]["state"], "holding")
                finally:
                    await service.close()
            asyncio.run(check())

    def test_host_alias_uses_recorded_runtime_endpoint_namespace(self):
        self.prepare()
        self.select()
        with self.runtime():
            async def check():
                service = fresh.service_class()(fresh.config_at(self.state), self.state / "controller.toml")
                try:
                    await service.start()
                    host_alias = self.root / "host-view"
                    shutil.copytree(self.state, host_alias)
                    self.assertNotEqual(str(host_alias), str(self.state))
                    self.assertEqual(fresh.evidence_problems(host_alias, service.status), [])
                finally:
                    await service.close()
            asyncio.run(check())

    def test_existing_pause_controls_resume_only_known_matching_fresh_state(self):
        import codex_transition as transition
        self.prepare()
        self.select()
        with self.runtime():
            async def check():
                service = fresh.service_class()(fresh.config_at(self.state), self.state / "controller.toml")
                try:
                    await service.start()
                finally:
                    await service.close()
            asyncio.run(check())
        canonical = self.protocol.thread
        before = list(self.protocol.calls)
        transition.pause(self.state, "Fixture operator maintenance", apply=True)
        with self.assertRaisesRegex(ValueError, "maintenance pause"):
            fresh.current_guard(self.state, self.env)
        transition.unpause(self.state)
        self.assertTrue((self.state / transition.PAUSE).exists())
        with mock.patch.dict(os.environ, {"CODEX_MODEL": "foreign"}):
            with self.assertRaisesRegex(ValueError, "drifted"):
                transition.unpause(self.state, apply=True)
        self.assertTrue((self.state / transition.PAUSE).exists())
        transition.unpause(self.state, apply=True)
        self.assertFalse((self.state / transition.PAUSE).exists())
        self.assertEqual(self.protocol.thread, canonical)
        self.assertEqual(self.protocol.calls, before)

    def test_binding_corruption_holds_before_any_more_core_observation(self):
        self.prepare()
        self.select()
        with self.runtime():
            async def check():
                service = fresh.service_class()(fresh.config_at(self.state), self.state / "controller.toml")
                try:
                    await service.start()
                    before = list(self.protocol.calls)
                    with sqlite3.connect(self.state / "journal.sqlite3") as db:
                        db.execute("UPDATE unified_binding SET policy_hash=?", ("b" * 64,))
                    await service.tick()
                    self.assertIn("initialized binding changed", service.status["last_error"])
                    self.assertEqual(service.status["readiness"]["state"], "holding")
                    self.assertFalse(service.gate.accepting)
                    self.assertFalse(service.stop_requested.is_set())
                    self.assertIsNone(service.backend.process.returncode)
                    self.assertEqual(self.protocol.calls, before)
                finally:
                    await service.close()
            asyncio.run(check())

    def test_detached_and_busy_tick_keep_preselection_gate_and_canonical(self):
        self.prepare()
        self.select()
        with self.runtime():
            async def check():
                service = fresh.service_class()(fresh.config_at(self.state), self.state / "controller.toml")
                try:
                    await service.start()
                    canonical = self.protocol.thread
                    service.gate.client_count = 1
                    self.protocol.active = True
                    await service.tick()
                    self.assertEqual(service.status["scheduler_state"], "active")
                    service.gate.client_count = 0
                    await service.tick()
                    self.assertEqual(self.protocol.thread, canonical)
                    before = list(self.protocol.calls)
                    receipt = fresh.read_json(self.state / fresh.SELECTION)
                    receipt["entry_generation"] = "f" * 32
                    (self.state / fresh.SELECTION).write_text(json.dumps(receipt))
                    await service.tick()
                    self.assertIn("another environment", service.status["last_error"])
                    self.assertFalse(service.gate.accepting)
                    self.assertFalse(service.stop_requested.is_set())
                    self.assertIsNone(service.backend.process.returncode)
                    self.assertEqual(self.protocol.calls, before)
                finally:
                    await service.close()
            asyncio.run(check())
        self.assertEqual(self.protocol.starts, 1)

    def test_new_execution_generation_requires_new_argv_receipt_before_resume(self):
        self.prepare()
        self.select()
        with mock.patch.object(settings, "environment_generation", return_value="f" * 32):
            fresh.publish_request(self.state, self.env)
            with self.assertRaisesRegex(ValueError, "another environment"):
                fresh.selection_guard(self.state, self.env)
            fresh.select_pane(self.state, NATIVE, self.env)
            fresh.selection_guard(self.state, self.env)
        with self.assertRaisesRegex(ValueError, "another environment"):
            fresh.selection_guard(self.state, self.env)
        self.assertFalse((self.state / "journal.sqlite3").exists())

    def test_pause_arriving_before_controller_placement_preserves_the_hold(self):
        real = assets.place
        def pausing(path, raw, **kwargs):
            result = real(path, raw, **kwargs)
            if path.name == fresh.PLAN:
                (self.state / "adapter-pause.json").write_text("{}")
            return result
        with mock.patch.object(assets, "place", side_effect=pausing):
            with self.assertRaisesRegex(ValueError, "maintenance pause"):
                self.prepare()
        self.assertFalse((self.state / "controller.toml").exists())
        self.assertFalse((self.state / "journal.sqlite3").exists())

    def test_attachment_uses_real_binding_readiness_and_checks_pause_after_wait(self):
        self.prepare()
        self.select()
        with self.runtime():
            async def check():
                service = fresh.service_class()(fresh.config_at(self.state), self.state / "controller.toml")
                try:
                    await service.start()
                    native = ["codex", "--remote", service.status["endpoint"], "resume", self.protocol.thread]
                    response = SimpleNamespace(returncode=0, stdout=json.dumps(native), stderr="")
                    with mock.patch.object(fresh.subprocess, "run", return_value=response) as prepare_attach:
                        with mock.patch.object(fresh.os, "execvp") as execute:
                            fresh.launch_pane(self.state, NATIVE, self.env, wait=1)
                        execute.assert_called_once_with("codex", native)
                        self.assertIn("interactive-args", prepare_attach.call_args[0][0])
                    def paused(*args, **kwargs):
                        (self.state / "adapter-pause.json").write_text("{}")
                        return response
                    with mock.patch.object(fresh.subprocess, "run", side_effect=paused):
                        with mock.patch.object(fresh.os, "execvp") as execute:
                            with self.assertRaisesRegex(ValueError, "maintenance pause"):
                                fresh.launch_pane(self.state, NATIVE, self.env, wait=1)
                            execute.assert_not_called()
                    (self.state / "adapter-pause.json").unlink()
                    descriptor = fresh.read_json(self.state / "unified.json")
                    descriptor["canonical_thread_id"] = str(uuid.uuid4())
                    (self.state / "unified.json").write_text(json.dumps(descriptor))
                    with mock.patch.object(fresh.subprocess, "run") as prepare_attach:
                        with self.assertRaisesRegex(ValueError, "canonical_binding"):
                            fresh.launch_pane(self.state, NATIVE, self.env, wait=.05)
                        prepare_attach.assert_not_called()
                finally:
                    await service.close()
            asyncio.run(check())


    def test_shipped_fresh_entry_waits_for_wrapper_argv_and_never_fabricates_readiness(self):
        home = self.root / "h"
        prov.install_feature_payload(home, prov.DEFAULT_CONNECTOR_SRC, dry_run=False,
                                     codex_src=_workspace.CODEX_CONNECTOR_ROOT)
        installed = prov.feature_payload_dir(home) / "codex"
        feature_state = self.root / "e"
        feature_state.mkdir()
        state = feature_state / "codex"
        self.assertLessEqual(len(os.fsencode(state / ("u-" + "0" * 32) / "b")), 100)
        session = self.root / "session.json"
        session.write_text(json.dumps(self.session))
        relay = installed / "relay"
        relay.write_text(relay.read_text().replace("SANDY_SESSION_FILE=/etc/sandy-session.json",
                                                  "SANDY_SESSION_FILE=" + str(session)))
        wrapper = installed / "interactive-launch"
        wrapper.write_text(wrapper.read_text().replace("STATE=/opt/sandy/feature-state/amap/codex",
                                                       "STATE=" + str(state)))
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        native_calls = self.root / "native-calls"
        (bin_dir / "codex").write_text("#!/bin/sh\ncase \"$1\" in\n"
            "login) exit 0 ;;\n--version) echo 'codex-cli 0.164.0'; exit 0 ;;\n"
            "*) echo backend >> \"$NATIVE_CALLS\"; exit 9 ;;\nesac\n")
        (bin_dir / "codex").chmod(0o755)
        (bin_dir / "python3").write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " \"$@\"\n")
        (bin_dir / "python3").chmod(0o755)
        env = dict(self.env, PATH=str(bin_dir) + os.pathsep + self.env["PATH"],
                   SANDY_FEATURE_STATE=str(feature_state), SANDY_AGENT="codex", NATIVE_CALLS=str(native_calls),
                   AMAP_CODEX_LAUNCH_WAIT_SECONDS="2")
        env.pop("AMAP_IDENTITY", None)
        env.pop("AMAP_IDENTITY_DIR", None)
        env.pop("AMAP_FLEET_DOMAIN", None)
        proc = subprocess.Popen(["/bin/sh", str(relay)], cwd=self.root, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            until = time.monotonic() + 10
            while time.monotonic() < until and not (state / fresh.REQUEST).exists():
                if proc.poll() is not None:
                    self.fail("shipped entry exited before preselection: " + proc.communicate()[1])
                time.sleep(.05)
            self.assertTrue((state / fresh.REQUEST).exists())
            self.assertFalse(native_calls.exists())
            self.assertFalse((state / "journal.sqlite3").exists())
            self.assertEqual(fresh.read_json(state / fresh.INITIALIZATION)["phase"], "prepared")
            result = subprocess.run(["/bin/sh", str(wrapper), *NATIVE], cwd=self.root, env=env,
                                    capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("fresh canonical attachment remains held", result.stderr)
            self.assertTrue((state / fresh.SELECTION).exists())
            until = time.monotonic() + 5
            while time.monotonic() < until and not native_calls.exists():
                time.sleep(.05)
            self.assertEqual(native_calls.read_text().splitlines(), ["backend"])
            self.assertEqual(fresh.read_json(state / fresh.INITIALIZATION)["phase"], "start_attempted")
            self.assertFalse((state / "adapter-transition.json").exists())
            time.sleep(1.1)
            self.assertEqual(native_calls.read_text().splitlines(), ["backend"])
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.communicate()


class FreshHostBoundaryTest(unittest.TestCase):
    def test_shipped_wrapper_validates_empty_and_unknown_modes_before_mixed_bypass(self):
        import test_codex_interactive as surface
        box = surface._Sandbox(self)
        for agents in ("codex", "claude,codex"):
            for mode in ("", "foreign"):
                with self.subTest(agents=agents, mode=mode):
                    result = box.run("interactive-launch", "/bin/echo", "UNWRAPPED", SANDY_AGENT=agents,
                                     AMAP_CODEX_CONVERSATION_MODE=mode)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("unknown fleet conversation mode", result.stderr)
                    self.assertNotIn("UNWRAPPED", result.stdout)
        for mode in (None, "separate"):
            extra = {} if mode is None else {fleet.EXPORT: mode}
            result = box.run("interactive-launch", "/bin/echo", "LEGACY", SANDY_AGENT="claude,codex", **extra)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "LEGACY")
        result = box.run("interactive-launch", "/bin/echo", "UNWRAPPED", SANDY_AGENT="claude,codex",
                         AMAP_CODEX_CONVERSATION_MODE="unified")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not support", result.stderr)
        self.assertNotIn("UNWRAPPED", result.stdout)


    def test_host_can_import_and_report_unknown_without_connector_or_native_toml(self):
        import builtins
        real = builtins.__import__
        def denied(name, *args, **kwargs):
            if name == "tomllib" or name.startswith("amap_codex"):
                raise AssertionError("host proof imported native dependency")
            return real(name, *args, **kwargs)
        with TemporaryDirectory(dir=os.environ.get("AMAP_TEST_TMPDIR")) as directory:
            state = Path(directory)
            with mock.patch.object(sys, "version_info", (3, 9, 18)), mock.patch("builtins.__import__", denied):
                self.assertTrue(fresh.evidence_problems(state, {}))
                with self.assertRaisesRegex(ValueError, "Python 3.11"):
                    fresh.birth(state / "new", {}, {})
            self.assertEqual(list(state.iterdir()), [])
