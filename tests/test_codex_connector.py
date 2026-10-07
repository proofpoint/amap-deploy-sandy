"""The Codex connector's part of the deployment, against the REAL connector.

The amap-connector-codex checkout is a sibling like the router: found by
`_workspace.codex_connector_root()`, and a missing one FAILS this module
rather than skipping it. What it proves:

- which connector serves a sandbox, by sandy's agent list;
- the manifest exposes the fleet's Codex model, and the router config names
  both connectors' outcome directories in a form the router's own loader
  accepts;
- the payload carries the connector's files byte for byte, and verify
  reports a hand edit to one;
- the SHIPPED payload/relay hands a Codex sandbox to payload/codex/relay;
- the SHIPPED payload/codex/relay writes a supervisor configuration the
  connector's own `Config.load` accepts (lanes, trusted MCP file, operator
  instructions, private state), and holds, with a recorded reason, while
  Codex is not logged in or its install reports no build, and runs any
  build it can name;
- verify reads the status snapshot the connector's own `Supervisor` writes.

`codex` is a stub and the supervisor is never started: a `python3` shim
records the final `exec` instead of running it.
"""
from __future__ import annotations

import contextlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

HERE = Path(__file__).resolve().parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import _workspace  # noqa: E402

_workspace.skip_if_incomplete()
import amap_sandy as prov  # noqa: E402
import fleet_policy as fp  # noqa: E402

CODEX_ROOT = _workspace.CODEX_CONNECTOR_ROOT
if not (CODEX_ROOT / "src" / prov.CODEX_PACKAGE).is_dir():
    raise RuntimeError(f"amap-connector-codex checkout not found at {CODEX_ROOT}: set "
                       f"$AMAP_CODEX_CONNECTOR_REPO or check it out beside this repository")
sys.path.insert(0, str(CODEX_ROOT / "src"))
from amap_codex.config import Config, Lane, REVIEWED_CODEX_VERSIONS  # noqa: E402
from amap_codex.journal import Journal  # noqa: E402
from amap_codex.supervisor import Supervisor  # noqa: E402

SESSION_LINE = "SANDY_SESSION_FILE=/etc/sandy-session.json"

FAKE_CODEX = """#!/bin/sh
case "$1" in
  login) if [ -f "$FAKE_LOGGED_IN" ]; then echo "Logged in using ChatGPT"; exit 0; fi
         echo "Not logged in"; exit 1 ;;
  --version) echo "$FAKE_CODEX_VERSION" ;;
  *) exit 2 ;;
esac
"""

# Records the supervisor's command line instead of starting it; every other
# python3 call (the relay's own helpers) runs for real.
PYTHON_SHIM = """#!/bin/sh
if [ "$1" = "-m" ] && [ "$2" = "amap_codex.cli" ]; then
  printf '%s\\n' "$@" > "$SHIM_ARGV"
  if [ -n "$SHIM_RUN_UNTIL_TERM" ]; then
    trap 'echo stopped > "$SHIM_RUN_UNTIL_TERM"; exit 0' TERM
    while :; do sleep 1; done
  fi
  exit "${{SHIM_RC:-0}}"
fi
exec {python} "$@"
"""


class ServingConnectorTest(unittest.TestCase):

    def test_claude_anywhere_is_claudes_and_codex_alone_is_codexs(self):
        for agents, want in ((["claude"], "claude"), (["codex"], "codex"),
                             (["claude", "codex"], "claude"), (["codex", "claude"], "claude"),
                             (["codex", "gemini"], "codex"), (["gemini"], "claude"),
                             (None, None), ("codex", None)):
            with self.subTest(agents=agents):
                self.assertEqual(prov.serving_connector(agents), want)


class ManifestAndRouterTest(unittest.TestCase):

    def test_the_manifest_carries_no_model(self):
        """The model is the agent's own: a `codex_model` left in the policy
        is kept verbatim and reaches no sandbox."""
        policy = fp.default_policy()
        policy["codex_model"] = "gpt-test.1"
        doc = prov.render_manifest(policy)
        self.assertEqual(doc["feature"]["codex_model"], "gpt-test.1")
        self.assertNotIn("gpt-test.1", json.dumps(doc["expose"]))

    def test_the_router_config_names_both_outcome_directories_and_the_router_loads_it(self):
        with TemporaryDirectory() as d:
            home = Path(d)
            doc = prov.render_router_sibling(fp.default_policy(), {"alpha-1": {}}, home,
                                             home / "router-state")["_doc"]
        self.assertEqual(doc[prov.SIBLING_OUTCOME_IDS], ["claude-code", "codex"])
        self.assertIsNone(prov.validate_with_router(doc))
        # The Codex id is the directory the shipped Codex relay points the
        # supervisor at; the Claude id is the Claude relay's.
        self.assertIn("/ext/codex/outcomes", (HERE / "payload/codex/relay").read_text())
        self.assertIn("/ext/claude-code/outcomes", (HERE / "payload/relay").read_text())


class PayloadTest(unittest.TestCase):

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = Path(self._tmp.name)

    def _install(self, codex_src):
        prov.install_feature_payload(self.home, prov.DEFAULT_CONNECTOR_SRC, dry_run=False,
                                     codex_src=codex_src)
        return prov.feature_payload_dir(self.home)

    def test_the_codex_part_is_the_connectors_files_and_a_hand_edit_is_drift(self):
        dest = self._install(CODEX_ROOT)
        sources = prov.codex_payload_sources(CODEX_ROOT)
        self.assertTrue(sources)
        for rel, src, executable in sources:
            with self.subTest(rel=rel):
                self.assertEqual((dest / rel).read_bytes(), src.read_bytes())
                self.assertEqual(os.access(dest / rel, os.X_OK), executable)
        self.assertTrue((dest / "codex/src/amap_codex/supervisor.py").is_file())
        self.assertEqual(prov.verify_feature_payload(self.home, prov.DEFAULT_CONNECTOR_SRC,
                                                     codex_src=CODEX_ROOT), [])
        (dest / "codex/mcp.toml").write_text("[mcp_servers]\n")
        problems = prov.verify_feature_payload(self.home, prov.DEFAULT_CONNECTOR_SRC,
                                               codex_src=CODEX_ROOT)
        self.assertTrue(any("codex/mcp.toml" in p for p in problems), problems)

    def test_without_the_codex_checkout_there_is_no_codex_part(self):
        dest = self._install(self.home / "nowhere")
        self.assertFalse((dest / "codex").exists())
        self.assertTrue((dest / prov.RELAY_WRAPPER_NAME).is_file())


class RelayDispatchTest(unittest.TestCase):
    """The SHIPPED payload/relay, with a stub codex/relay beside it."""

    def _run(self, agent, *, with_codex=True):
        with TemporaryDirectory() as d:
            root = Path(d)
            shutil.copy(HERE / "payload/relay", root / "relay")
            (root / "inbox-delivery").write_text("#!/bin/sh\necho claude-daemon\n")
            (root / "inbox-delivery").chmod(0o755)
            if with_codex:
                (root / "codex").mkdir()
                (root / "codex/relay").write_text("#!/bin/sh\necho codex-supervisor\n")
                (root / "codex/relay").chmod(0o755)
            env = {"PATH": os.environ["PATH"], "HOME": d, "SANDY_AGENT": agent,
                   "AMAP_INBOX_DIR": d, "AMAP_OUTBOX_DIR": d, "AMAP_PEER_DIR": d}
            proc = subprocess.Popen(["/bin/sh", str(root / "relay")], env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                    start_new_session=True)
            try:
                out, err = proc.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)   # the shell and its sleep
                proc.communicate()
                return None, "waited"
            return out.strip(), err

    def test_codex_alone_runs_the_codex_supervisor_and_claude_anywhere_the_daemon(self):
        for agent, want in (("codex", "codex-supervisor"), ("claude", "claude-daemon"),
                            ("claude,codex", "claude-daemon"), ("codex,claude", "claude-daemon"),
                            ("codex,gemini", "codex-supervisor")):
            with self.subTest(agent=agent):
                self.assertEqual(self._run(agent)[0], want)

    def test_a_codex_sandbox_without_the_codex_payload_waits_rather_than_fails(self):
        self.assertEqual(self._run("codex", with_codex=False), (None, "waited"))


class CodexRelayTest(unittest.TestCase):
    """The SHIPPED payload/codex/relay, from an installed payload."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = self.root = Path(self._tmp.name)
        home = root / "sandy-home"
        prov.install_feature_payload(home, prov.DEFAULT_CONNECTOR_SRC, dry_run=False,
                                     codex_src=CODEX_ROOT)
        self.payload = prov.feature_payload_dir(home)
        session = root / "sandy-session.json"
        session.write_text(json.dumps({"sandbox_name": "codex-1a2b3c4d",
                                       "workspace": "/home/sandy/work/codex"}))
        relay = self.payload / "codex/relay"
        text = relay.read_text()
        self.assertIn(SESSION_LINE, text)
        relay.write_text(text.replace(SESSION_LINE, f"SANDY_SESSION_FILE={session}", 1))
        bindir = root / "bin"
        bindir.mkdir()
        (bindir / "codex").write_text(FAKE_CODEX)
        (bindir / "python3").write_text(PYTHON_SHIM.format(python=sys.executable))
        for name in ("codex", "python3"):
            (bindir / name).chmod(0o755)
        lanes = {}
        for lane, export in prov.EXPORT_LANE_DIR.items():
            lanes[export] = root / "lanes" / lane
            for leaf in ("notices", "messages"):
                (lanes[export] / leaf).mkdir(parents=True)
        self.state = root / "feature-state"
        self.state.mkdir()
        self.codex_config = root / "agent-home" / ".codex" / "config.toml"
        self.codex_config.parent.mkdir(parents=True)
        self.codex_config.write_text('model = "gpt-test"\nsandbox_mode = "danger-full-access"\n')
        self.env = {"PATH": f"{bindir}:{os.environ['PATH']}", "HOME": str(root / "agent-home"),
                    "SANDY_FEATURE_STATE": str(self.state), "SANDY_AGENT": "codex",
                    "AMAP_FLEET_DOMAIN": "sandy.host.internal",
                    "FAKE_LOGGED_IN": str(root / "logged-in"),
                    "FAKE_CODEX_VERSION": REVIEWED_CODEX_VERSIONS[0],
                    "SHIM_ARGV": str(root / "argv"),
                    **{k: str(v) for k, v in lanes.items()}}

    def _start(self, **env):
        return subprocess.Popen(["/bin/sh", str(self.payload / "codex/relay")],
                                env={**self.env, **env}, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, start_new_session=True)

    def _hold_reason(self, proc):
        hold = self.state / prov.CODEX_STATE_SUBDIR / prov.CODEX_HOLD_NAME
        try:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline and not hold.is_file():
                time.sleep(0.05)
            self.assertIsNone(proc.poll(), "a hold must wait, never exit")
            return json.loads(hold.read_text())["reason"]
        finally:
            os.killpg(proc.pid, signal.SIGKILL)   # the shell and its sleep
            proc.communicate()

    def test_the_configuration_it_writes_is_one_the_connector_accepts(self):
        (self.root / "logged-in").write_text("")
        proc = self._start()
        out, err = proc.communicate(timeout=30)
        self.assertEqual(proc.returncode, 0, err)
        argv = (self.root / "argv").read_text().split("\n")
        config_path = Path(argv[argv.index("--config") + 1])
        self.assertEqual(argv[-2], "run")
        config = Config.load(config_path)
        self.assertEqual(config.instance_id, "codex-1a2b3c4d")
        self.assertEqual(config.self_address, "codex-1a2b3c4d@sandy.host.internal")
        self.assertEqual(config.codex_model, "gpt-test")
        self.assertEqual(config.cwd, "/home/sandy/work/codex")
        self.assertEqual(config.sandbox, "danger-full-access")
        self.assertEqual(sorted(l.name for l in config.lanes), ["mail", "peer"])
        self.assertEqual(config.trusted_config_file, self.payload / "codex/mcp.toml")
        self.assertEqual(set(config.trusted_overrides()["mcp_servers"]),
                         {"inbox", "delegation", "inbox_submit"})
        self.assertTrue(str(config.outcome_dir).endswith("/ext/codex/outcomes"))
        self.assertFalse((config_path.parent / prov.CODEX_HOLD_NAME).exists())

    def test_without_a_domain_it_serves_mail_only(self):
        (self.root / "logged-in").write_text("")
        env = dict(self.env)
        del env["AMAP_FLEET_DOMAIN"]
        proc = subprocess.run(["/bin/sh", str(self.payload / "codex/relay")], env=env,
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        config = Config.load(self.state / "codex/controller.toml")
        self.assertIsNone(config.self_address)
        self.assertEqual([l.name for l in config.lanes], ["mail"])

    def test_not_logged_in_holds_with_the_reason(self):
        self.assertIn("not logged in", self._hold_reason(self._start()))

    def test_the_model_is_the_agents_own_and_nothing_else(self):
        """An AMAP_CODEX_MODEL or CODEX_MODEL in the environment is not a
        source: the agent's config.toml is the only one."""
        (self.root / "logged-in").write_text("")
        proc = subprocess.run(["/bin/sh", str(self.payload / "codex/relay")],
                              env={**self.env, "AMAP_CODEX_MODEL": "gpt-env",
                                   "CODEX_MODEL": "gpt-env"},
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(Config.load(self.state / "codex/controller.toml").codex_model,
                         "gpt-test")

    def test_no_model_in_the_agents_config_leaves_the_choice_to_codex(self):
        (self.root / "logged-in").write_text("")
        self.codex_config.write_text('sandbox_mode = "danger-full-access"\n')
        proc = subprocess.run(["/bin/sh", str(self.payload / "codex/relay")], env=self.env,
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        controller = self.state / "codex/controller.toml"
        self.assertNotIn("codex_model", controller.read_text())
        self.assertIsNone(Config.load(controller).codex_model)

    def test_a_supervisor_that_fails_is_a_hold_not_an_exit(self):
        """An exit inside sandy's startup window fails the agent's whole
        launch, so a supervisor that cannot start is held and retried."""
        (self.root / "logged-in").write_text("")
        reason = self._hold_reason(self._start(SHIM_RC="1"))
        self.assertIn("codex supervisor exited 1", reason)

    def test_a_stop_reaches_the_supervisor_and_ends_the_relay(self):
        (self.root / "logged-in").write_text("")
        stopped = self.root / "stopped"
        proc = self._start(SHIM_RUN_UNTIL_TERM=str(stopped))
        try:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline and not (self.root / "argv").exists():
                time.sleep(0.05)
            self.assertIsNone(proc.poll(), "the relay runs while its supervisor does")
            proc.send_signal(signal.SIGTERM)
            proc.communicate(timeout=20)
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(stopped.read_text().strip(), "stopped")
        finally:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)

    def test_an_unreviewed_build_runs_and_is_stated(self):
        (self.root / "logged-in").write_text("")
        proc = subprocess.run(["/bin/sh", str(self.payload / "codex/relay")],
                              env={**self.env, "FAKE_CODEX_VERSION": "codex-cli 9.9.9"},
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        config = Config.load(self.state / "codex/controller.toml")
        self.assertEqual(config.codex_version, "codex-cli 9.9.9")
        self.assertFalse(config.codex_reviewed)

    def test_a_codex_that_reports_no_build_holds(self):
        (self.root / "logged-in").write_text("")
        self.assertIn("reports no build", self._hold_reason(self._start(FAKE_CODEX_VERSION="")))


class VerifyCodexSupervisorTest(unittest.TestCase):
    """verify against the snapshot the connector's own Supervisor writes."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.home = root / "sandy-home"
        prov.install_feature_payload(self.home, prov.DEFAULT_CONNECTOR_SRC, dry_run=False,
                                     codex_src=CODEX_ROOT)
        self.entry_state = root / "entry-state"
        self.codex_state = self.entry_state / prov.CODEX_STATE_SUBDIR
        lanes = root / "lanes"
        for leaf in ("notices", "messages"):
            (lanes / leaf).mkdir(parents=True)
        payload = prov.feature_payload_dir(self.home) / "codex"
        self.config = Config("codex-1", None, ["codex", "app-server"],
                             [Lane("mail", lanes / "notices", lanes / "messages",
                                   root / "mail.claim")],
                             self.codex_state, "gpt-test", "/work", "danger-full-access",
                             "never", payload / "operator-instructions.md",
                             trusted_config_file=payload / "mcp.toml").validate()
        self.record = {prov.FEATURE_ENTRIES_KEY: {prov.FEATURE_NAME: {
            "state_dir": str(self.entry_state)}}}

    def _snapshot(self, *, held=True, thread="thread-1", uncertain=False):
        self.config.validate()
        supervisor = Supervisor(self.config)
        supervisor.journal = Journal(self.config.state_dir, self.config.instance_id,
                                     self.config.fingerprint(), self.config.codex_version,
                                     self.config.codex_model)
        try:
            if thread:
                supervisor.journal.bind_thread(thread)
            if uncertain:
                supervisor.journal.db.execute(
                    "INSERT INTO events(event_id,instance_id,lane,notice_id,artifact_hash,payload,"
                    "state,detail,created_at,updated_at,eligible_at) VALUES('e1','codex-1','mail',"
                    "'n1','h','{}','uncertain','',0,0,0)")
            if held:
                supervisor.ownership.claims.append(object())
            supervisor.write_status()
        finally:
            supervisor.ownership.claims.clear()
            supervisor.journal.close()

    def _verify(self, *, running=True, now=None):
        return prov.verify_codex_supervisor(self.home, "codex-1", self.record,
                                            running=running, now=now)

    def test_a_live_supervisor_holding_its_claims_with_a_thread_passes(self):
        self._snapshot()
        self.assertEqual(self._verify(), ([], []))

    def test_each_failure_names_its_cause(self):
        cases = {
            "not consuming": dict(held=False),
            "no thread": dict(thread=None),
            "UNCERTAIN": dict(uncertain=True),
        }
        for want, kw in cases.items():
            with self.subTest(want=want):
                shutil.rmtree(self.codex_state, ignore_errors=True)
                self.config.validate()
                self._snapshot(**kw)
                problems, _ = self._verify()
                self.assertEqual(len(problems), 1, problems)
                self.assertIn(want, problems[0])

    def test_a_stale_snapshot_a_hold_and_a_missing_one_fail(self):
        self._snapshot()
        problems, _ = self._verify(now=time.time() + prov.HEARTBEAT_MAX_AGE_SECONDS + 5)
        self.assertTrue(problems and "stale" in problems[0], problems)
        (self.codex_state / prov.CODEX_HOLD_NAME).write_text(
            json.dumps({"reason": "codex is not logged in", "since": 0}))
        problems, _ = self._verify()
        self.assertTrue(problems and "not logged in" in problems[0], problems)
        (self.codex_state / prov.CODEX_HOLD_NAME).unlink()
        (self.codex_state / prov.CODEX_STATUS_NAME).unlink()
        problems, _ = self._verify()
        self.assertTrue(problems and "UNKNOWN" in problems[0], problems)

    def test_an_unreviewed_build_is_a_note_not_a_problem(self):
        self.config.codex_version = "codex-cli 9.9.9"
        self._snapshot()
        problems, notes = self._verify()
        self.assertEqual(problems, [])
        self.assertEqual(len(notes), 1, notes)
        self.assertIn("'codex-cli 9.9.9' is not one the connector has reviewed", notes[0])

    def test_a_stopped_sandbox_reports_only_what_persists(self):
        self._snapshot(held=False, uncertain=True)
        problems, _ = self._verify(running=False)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("UNCERTAIN", problems[0])

    def test_no_codex_payload_is_a_problem_for_a_codex_sandbox(self):
        shutil.rmtree(prov.feature_payload_dir(self.home) / "codex")
        problems, _ = self._verify()
        self.assertTrue(problems and "no codex/" in problems[0], problems)


if __name__ == "__main__":
    unittest.main()
