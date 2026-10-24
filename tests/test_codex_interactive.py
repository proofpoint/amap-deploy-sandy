"""The Codex connector's interactive surface, as this deployment installs it.

- The SHIPPED payload/codex/interactive-launch, run as sandy's `agent_wrapper`
  runs it: the complete native command line as its arguments, binary first.
  It waits for the supervisor to be ready, then execs the connector's
  `interactive` with that command line after `--`, as an array; it refuses
  rather than start Codex beside a supervisor that is not ready, and leaves a
  Claude-served sandbox's codex pane alone.
- The SHIPPED payload/codex/activity, the visible companion view.
- The manifest's `agent_wrapper`, rendered only where sandy's schema lists the
  key and the payload carries the launcher.

The connector is a `python3` shim: `-m amap_codex.cli activity` prints the
snapshot the test sets, and `interactive` records its arguments NUL-separated
and exits as the test sets; every other python3 call runs for real. The
snapshot's fields are the connector's own: `heartbeat` from
amap_codex/interactive.py `read_activity`, and `status` from amap_codex/cli.py
`read_status` (`instance_id`, `enabled_lanes`, `thread_id`, `claim_state` per
lane, `uncertain_count`), at the pinned commit.
"""
from __future__ import annotations

import json
import os
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

STATE_LINE = "STATE=/opt/sandy/feature-state/amap/codex"

FAKE_CODEX = """#!/bin/sh
printf '%s\\0' "$0" "$@" > "$CODEX_ARGV"
"""

PYTHON_SHIM = """#!/bin/sh
if [ "$1" = "-m" ] && [ "$2" = "amap_codex.cli" ]; then
  printf '%s\\n' "$@" >> "$SHIM_CALLS"
  for a in "$@"; do
    case "$a" in
      activity) [ -n "$SHIM_ACTIVITY_RC" ] && { echo "activity broke" >&2; exit "$SHIM_ACTIVITY_RC"; }
                printf '%s\\n' "$SHIM_ACTIVITY"; exit 0 ;;
      interactive) printf '%s\\0' "$@" > "$SHIM_INTERACTIVE"
                [ -n "$SHIM_INTERACTIVE_RC" ] && { echo "unsupported native option or subcommand" >&2; exit "$SHIM_INTERACTIVE_RC"; }
                exit 0 ;;
    esac
  done
  exit 9
fi
exec @PYTHON@ "$@"
"""


def snapshot(**status):
    base = {"instance_id": "codex-1", "enabled_lanes": ["mail", "peer"], "thread_id": "thr-1",
            "claim_state": {"mail": "live", "peer": "live"}, "uncertain_count": 0, "pending_count": 0}
    heartbeat = status.pop("heartbeat", "fresh")
    base.update(status)
    return json.dumps({"heartbeat": heartbeat, "status": base, "events": []})


class _Sandbox:
    def __init__(self, test: unittest.TestCase):
        self._tmp = TemporaryDirectory()
        test.addCleanup(self._tmp.cleanup)
        self.root = root = Path(self._tmp.name)
        home = root / "sandy-home"
        prov.install_feature_payload(home, prov.DEFAULT_CONNECTOR_SRC, dry_run=False,
                                     codex_src=CODEX_ROOT)
        self.payload = prov.feature_payload_dir(home) / "codex"
        self.state = root / "feature-state" / "codex"
        self.state.mkdir(parents=True)
        for name in ("interactive-launch", "activity"):
            path = self.payload / name
            text = path.read_text()
            test.assertEqual(text.count(STATE_LINE), 1, name)
            path.write_text(text.replace(STATE_LINE, f"STATE={self.state}", 1))
        bindir = root / "bin"
        bindir.mkdir()
        (bindir / "codex").write_text(FAKE_CODEX)
        (bindir / "python3").write_text(PYTHON_SHIM.replace("@PYTHON@", sys.executable))
        for name in ("codex", "python3"):
            (bindir / name).chmod(0o755)
        self.outbox = root / "outbox"
        (self.outbox / "results").mkdir(parents=True)
        self.env = {"PATH": f"{bindir}:{os.environ['PATH']}", "HOME": str(root / "agent-home"),
                    "SANDY_AGENT": "codex", "AMAP_OUTBOX_DIR": str(self.outbox),
                    "AMAP_CODEX_LAUNCH_WAIT_SECONDS": "0",
                    "CODEX_ARGV": str(root / "codex-argv"), "SHIM_CALLS": str(root / "calls"),
                    "SHIM_INTERACTIVE": str(root / "interactive-argv"),
                    "SHIM_ACTIVITY": snapshot()}

    def ready(self):
        (self.state / "controller.toml").write_text('instance_id = "codex-1"\n')

    def run(self, script, *argv, **env):
        return subprocess.run(["/bin/sh", str(self.payload / script), *argv],
                              env={**self.env, **env}, capture_output=True, text=True, timeout=60)

    def _nul(self, name):
        path = self.root / name
        return None if not path.exists() else [a.decode() for a in path.read_bytes().split(b"\0")[:-1]]

    def execd(self):
        argv = self._nul("codex-argv")
        return None if argv is None else argv[1:]

    def interactive(self):
        return self._nul("interactive-argv")

    def calls(self):
        path = self.root / "calls"
        return path.read_text().split("\n") if path.exists() else []


NATIVE = ["codex", "--sandbox", "danger-full-access", "--ask-for-approval", "never", "--no-daemon",
          "--model", "gpt-test", "-c", "model_reasoning_effort=high", "-c", "x=\"a b $(c)\""]


class InteractiveLaunchTest(unittest.TestCase):

    def setUp(self):
        self.box = _Sandbox(self)

    def _ok(self, *native, **env):
        r = self.box.run("interactive-launch", *native, **env)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r

    def test_it_hands_sandys_whole_command_line_to_the_connector_after_a_separator(self):
        self.box.ready()
        self._ok(*NATIVE)
        self.assertEqual(self.box.interactive(),
                         ["-m", "amap_codex.cli", "--config", str(self.box.state / "controller.toml"),
                          "interactive", "--outbox-dir", str(self.box.outbox), "--", *NATIVE])
        self.assertIsNone(self.box.execd(), "the launcher started codex itself")

    def test_the_connectors_refusal_is_the_launchers_exit_and_nothing_is_dropped(self):
        self.box.ready()
        native = ["codex", "resume", "--last", "--sandbox", "danger-full-access"]
        r = self.box.run("interactive-launch", *native, SHIM_INTERACTIVE_RC="2")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertEqual(self.box.interactive()[-len(native) - 1:], ["--", *native])
        self.assertIn("unsupported native option or subcommand", r.stderr)
        self.assertIsNone(self.box.execd())

    def test_a_claude_served_sandbox_gets_sandys_codex_unchanged(self):
        r = self._ok(*NATIVE, SANDY_AGENT="claude,codex")
        self.assertEqual(self.box.execd(), NATIVE[1:])
        self.assertEqual(self.box.calls(), [])
        self.assertIn("Claude daemon serves this sandbox", r.stderr)

    def _refused(self, must, **env):
        r = self.box.run("interactive-launch", *NATIVE, **env)
        self.assertNotEqual(r.returncode, 0)
        self.assertIsNone(self.box.interactive(), "the connector was launched after a refusal")
        self.assertIsNone(self.box.execd(), "codex was started after a refusal")
        self.assertIn(must, r.stderr)
        self.assertIn("not starting Codex", r.stderr)
        return r

    def test_no_supervisor_configuration_refuses(self):
        self._refused("the supervisor has not written")

    def test_a_holding_supervisor_refuses_with_its_reason(self):
        self.box.ready()
        (self.box.state / "hold.json").write_text(json.dumps({"reason": "codex is not logged in"}))
        self._refused("the supervisor holds: codex is not logged in")

    def test_a_stale_heartbeat_refuses(self):
        self.box.ready()
        self._refused("the supervisor heartbeat is stale", SHIM_ACTIVITY=snapshot(heartbeat="stale"))

    def test_no_bound_thread_refuses(self):
        self.box.ready()
        self._refused("no bound thread", SHIM_ACTIVITY=snapshot(thread_id=None))

    def test_a_lane_claim_that_is_not_live_refuses_and_names_it(self):
        self.box.ready()
        self._refused("peer=stale", SHIM_ACTIVITY=snapshot(claim_state={"mail": "live", "peer": "stale"}))
        self._refused("peer=None", SHIM_ACTIVITY=snapshot(claim_state={"mail": "live"}))

    def test_no_enabled_lane_refuses(self):
        self.box.ready()
        self._refused("no enabled lanes", SHIM_ACTIVITY=snapshot(enabled_lanes=[]))

    def test_an_uncertain_dispatch_refuses(self):
        self.box.ready()
        self._refused("1 uncertain dispatches", SHIM_ACTIVITY=snapshot(uncertain_count=1))

    def test_a_failed_or_unreadable_activity_check_refuses(self):
        self.box.ready()
        self._refused("the connector activity check failed (exit 4)", SHIM_ACTIVITY_RC="4")
        self._refused("not one this launcher reads", SHIM_ACTIVITY="not json")
        self._refused("not one this launcher reads", SHIM_ACTIVITY=json.dumps({"heartbeat": "fresh"}))

    def test_it_waits_for_the_supervisor_within_its_bound(self):
        proc = subprocess.Popen(["/bin/sh", str(self.box.payload / "interactive-launch"), *NATIVE],
                                env={**self.box.env, "AMAP_CODEX_LAUNCH_WAIT_SECONDS": "20"},
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(1.5)
        self.assertIsNone(proc.poll(), "it must wait, not refuse, inside its bound")
        self.box.ready()
        _, err = proc.communicate(timeout=30)
        self.assertEqual(proc.returncode, 0, err)
        self.assertEqual(self.box.interactive()[-len(NATIVE) - 1:], ["--", *NATIVE])

    def test_before_the_first_send_it_starts_without_outbound_activity_and_says_so(self):
        self.box.ready()
        (self.box.outbox / "results").rmdir()
        r = self._ok(*NATIVE)
        self.assertNotIn("--outbox-dir", self.box.interactive())
        self.assertIn("has no results/ yet", r.stderr)

    def test_without_the_outbox_lane_it_refuses(self):
        self.box.ready()
        env = {k: v for k, v in self.box.env.items() if k != "AMAP_OUTBOX_DIR"}
        r = subprocess.run(["/bin/sh", str(self.box.payload / "interactive-launch"), *NATIVE],
                           env=env, capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIsNone(self.box.interactive())
        self.assertIn("no AMAP_OUTBOX_DIR", r.stderr)


class ActivityTest(unittest.TestCase):

    def setUp(self):
        self.box = _Sandbox(self)

    def test_it_follows_with_the_outbox_once_results_exist(self):
        self.box.ready()
        r = self.box.run("activity", "--limit", "5")
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.box.calls()
        i = calls.index("activity")
        self.assertEqual(calls[i + 1:], ["--follow", "--limit", "5", "--outbox-dir", str(self.box.outbox), ""])

    def test_before_the_first_send_it_follows_without_the_outbox(self):
        self.box.ready()
        (self.box.outbox / "results").rmdir()
        r = self.box.run("activity")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("--outbox-dir", self.box.calls())
        self.assertIn("no results/ yet", r.stderr)

    def test_without_a_supervisor_configuration_it_says_so(self):
        r = self.box.run("activity")
        self.assertEqual(r.returncode, 1)
        self.assertIn("no supervisor configuration", r.stderr)


class PayloadAndManifestTest(unittest.TestCase):

    def test_the_payload_ships_both_wrappers_executable(self):
        names = {rel: executable for rel, _, executable in prov.codex_payload_sources(CODEX_ROOT)}
        for name in ("interactive-launch", "activity"):
            self.assertIs(names.get(f"{prov.CODEX_PAYLOAD_SUBDIR}/{name}"), True, name)
        # The connector's own source carries the module the new subcommands live in.
        self.assertIn(f"{prov.CODEX_PAYLOAD_SUBDIR}/src/{prov.CODEX_PACKAGE}/interactive.py", names)

    def test_agent_wrapper_is_rendered_only_when_it_is_true(self):
        policy = fp.default_policy()
        on = prov.render_manifest(policy, agent_wrapper=True)
        self.assertEqual(on[prov.AGENT_WRAPPER_KEY], {"codex": "payload/codex/interactive-launch"})
        self.assertEqual(on["entry"].split("/")[0], on[prov.AGENT_WRAPPER_KEY]["codex"].split("/")[0])
        for value in (False, None):
            self.assertNotIn(prov.AGENT_WRAPPER_KEY, prov.render_manifest(policy, agent_wrapper=value))

    def _schema(self, schema):
        saved = prov._sandy_json
        self.addCleanup(setattr, prov, "_sandy_json", saved)
        prov._sandy_json = lambda sandy_bin, flag: schema

    def test_the_gate_is_sandys_key_and_the_payloads_launcher(self):
        with_key = {"manifest": {"top_level_keys": ["schema", prov.AGENT_WRAPPER_KEY]}}
        self._schema(with_key)
        self.assertIs(prov.codex_agent_wrapper("sandy", CODEX_ROOT), True)
        with TemporaryDirectory() as empty:
            self.assertIs(prov.codex_agent_wrapper("sandy", Path(empty)), False)
        self._schema({"manifest": {"top_level_keys": ["schema"]}})
        self.assertIs(prov.codex_agent_wrapper("sandy", CODEX_ROOT), False)
        self._schema(None)
        self.assertIsNone(prov.codex_agent_wrapper("sandy", CODEX_ROOT))

    def test_an_unknown_answer_leaves_the_operators_key_as_it_is(self):
        with TemporaryDirectory() as d:
            home = Path(d)
            policy = fp.default_policy()
            prov.install_manifest(home, policy, dry_run=False, agent_wrapper=True)
            path = prov.feature_manifest_path(home)
            self.assertIn(prov.AGENT_WRAPPER_KEY, json.loads(path.read_text()))
            prov.install_manifest(home, policy, dry_run=False, agent_wrapper=None)
            self.assertIn(prov.AGENT_WRAPPER_KEY, json.loads(path.read_text()))
            self.assertEqual(prov.verify_manifest(home, policy, agent_wrapper=None), [])
            prov.install_manifest(home, policy, dry_run=False, agent_wrapper=False)
            self.assertNotIn(prov.AGENT_WRAPPER_KEY, json.loads(path.read_text()))

    def test_verify_reports_a_stale_wrapper_as_drift(self):
        with TemporaryDirectory() as d:
            home = Path(d)
            policy = fp.default_policy()
            prov.install_manifest(home, policy, dry_run=False, agent_wrapper=False)
            found = prov.verify_manifest(home, policy, agent_wrapper=True)
            self.assertEqual(len(found), 1)
            self.assertIn(prov.AGENT_WRAPPER_KEY, found[0])
