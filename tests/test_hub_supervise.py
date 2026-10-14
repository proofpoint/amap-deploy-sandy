"""hub_supervise: the hub-link router's supervisor (the systemd unit; the
macOS wrapper and its LaunchDaemon), the weekly login probe's job, the
live-start ancestry check, and the gated start step.

Every value is invented; the document is test_hub_keys' plus a supervision
section. The wrapper is the RENDERED script, run under dash and under
`bash --posix` against a stub `docker` that records its argv and answers
from files, so the rows exercise what ships. No docker, systemd or launchd
runs.
"""

import dataclasses
import json
import os
import plistlib
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import host_setup as hs
import hub_runtime as hr
import hub_supervise as hv
import router_health as rh
from test_hub_keys import full_doc as keys_doc
from test_hub_runtime import setUpModule, tearDownModule  # noqa: F401 -- the fixture's pins, restored

REQ = [{"name": "the IMAP secret unit", "commit": "a" * 40}, {"name": "the image env unit", "commit": "b" * 40}]


def sup_section(kind="systemd"):
    if kind == "systemd":
        return {"kind": "systemd", "engine": "unix:///var/run/docker.sock",
                "hub": {"unit": "/etc/systemd/system/hub-link.service"},
                "weekly": {"service": "/etc/systemd/system/hub-link-probe.service",
                           "timer": "/etc/systemd/system/hub-link-probe.timer", "weekday": 1, "hour": 4, "minute": 17},
                "requires": REQ}
    return {"kind": "launchd", "engine": "unix:///Users/op/.orbstack/run/docker.sock",
            "hub": {"label": "org.example.hub", "plist": "/Library/LaunchDaemons/org.example.hub.plist",
                    "wrapper": "/opt/ex/libexec/hub-link-run", "status": "/opt/ex/status/hub-run"},
            "weekly": {"label": "org.example.hub-probe", "plist": "/Library/LaunchDaemons/org.example.hub-probe.plist",
                       "weekday": 1, "hour": 4, "minute": 17},
            "requires": REQ}


def spec(kind_="systemd", **over):
    d = keys_doc()
    sec = sup_section(kind_)
    sec.update(over)
    d[hv.SECTION] = sec
    return hs.load_spec(d)


class LoadTest(unittest.TestCase):
    def refuses(self, words, **over):
        with self.assertRaises(hs.SpecError) as e:
            spec(**over)
        self.assertIn(words, str(e.exception))

    def test_both_kinds_load(self):
        self.assertEqual(spec().supervision.kind, "systemd")
        self.assertEqual(spec("launchd").supervision.kind, "launchd")

    def test_refusals(self):
        self.refuses("supervision.kind", kind="upstart")
        self.refuses("supervision.engine", engine="tcp://x:2375")
        self.refuses("supervision.requires", requires=[])
        self.refuses("full commit sha", requires=[{"name": "x", "commit": "abc"}])
        self.refuses(".service path", hub={"unit": "/etc/systemd/system/hub-link"})
        with self.assertRaises(hs.SpecError) as e:
            spec("launchd", hub=dict(sup_section("launchd")["hub"], plist="/Library/LaunchDaemons/other.plist"))
        self.assertIn("<label>.plist", str(e.exception))

    def test_the_section_needs_the_hub_section(self):
        d = keys_doc()
        del d[hr.SECTION]
        d.pop("keys", None)
        d[hv.SECTION] = sup_section()
        with self.assertRaises(hs.SpecError):
            hs.load_spec(d)


class SystemdTest(unittest.TestCase):
    def unit(self):
        return hv.systemd_unit(spec()).decode()

    def line(self, key):
        [l] = [l for l in self.unit().splitlines() if l.startswith(key + "=")]
        return l.split("=", 1)[1]

    def test_the_restart_policy_never_restarts_0_or_2_to_11_and_143_is_a_success(self):
        self.assertEqual(self.line("RestartPreventExitStatus").split(), [str(c) for c in range(2, 12)])
        self.assertEqual(self.line("SuccessExitStatus"), "143")
        self.assertNotIn("143", self.line("RestartPreventExitStatus").split())
        self.assertNotIn("137", self.unit())
        self.assertEqual(self.line("Restart"), "on-failure")

    def test_the_stop_bounds_sit_above_the_dot_budget(self):
        self.assertGreaterEqual(hv.STOP_TIMEOUT_S, hr.BUDGET_S + 60)
        self.assertGreater(hv.SUPERVISOR_STOP_S, hv.STOP_TIMEOUT_S)
        self.assertEqual(self.line("TimeoutStopSec"), str(hv.SUPERVISOR_STOP_S))
        self.assertIn(f"stop -t {hv.STOP_TIMEOUT_S} ", self.line("ExecStop") + " ")

    def test_it_runs_the_rendered_spec_and_never_force_removes(self):
        s = spec()
        self.assertEqual(self.line("ExecStart").split(), hv.run_argv(s))
        self.assertTrue(self.line("ExecStartPre").startswith("-"))
        self.assertNotIn("-f", self.line("ExecStartPre").split())
        self.assertEqual(self.line("Environment"), "DOCKER_HOST=unix:///var/run/docker.sock")

    def test_it_can_be_enabled_and_enabling_is_not_placing(self):
        self.assertIn("[Install]\nWantedBy=multi-user.target", self.unit())
        plan = "\n".join(hv.plan(spec(), lambda x: x, "steps"))
        self.assertNotIn("systemctl", plan)
        self.assertNotIn("launchctl", hv.plan(spec("launchd"), lambda x: x, "steps")[-1])
        self.assertIn("systemctl enable --now hub-link.service", hv.start_commands(spec()))

    def test_the_weekly_job_runs_the_probe_under_the_lock(self):
        service, timer = hv.systemd_weekly(spec())
        argv = hv.weekly_argv(spec())
        self.assertEqual(argv[4:6], ["lock", spec().secrets.run_dir])
        self.assertIn("probe-weekly", argv)
        self.assertIn("probe-login", argv)
        self.assertIn(b"OnCalendar=Mon *-*-* 04:17:00", timer)
        self.assertIn(b"Unit=hub-link-probe.service", timer)
        self.assertIn(b"Type=oneshot", service)


class LaunchdTest(unittest.TestCase):
    def test_the_daemon_runs_the_wrapper_only_through_sh(self):
        s = spec("launchd")
        doc = plistlib.loads(hv.hub_plist(s))
        self.assertEqual(doc["ProgramArguments"], ["/bin/sh", "/opt/ex/libexec/hub-link-run"])
        self.assertEqual(doc["KeepAlive"], {"SuccessfulExit": False})
        self.assertGreater(doc["ExitTimeOut"], hv.STOP_TIMEOUT_S)
        others = [data for path, data in hv.rendered(s) if path != s.supervision.hub["plist"]]
        self.assertFalse(any(b"/opt/ex/libexec/hub-link-run" in d for d in others),
                         "something other than the daemon's plist invokes the wrapper")

    def test_the_weekly_daemon_sets_the_engine_and_the_schedule(self):
        doc = plistlib.loads(hv.weekly_plist(spec("launchd")))
        self.assertEqual(doc["StartCalendarInterval"], {"Weekday": 1, "Hour": 4, "Minute": 17})
        self.assertEqual(doc["EnvironmentVariables"], {"DOCKER_HOST": "unix:///Users/op/.orbstack/run/docker.sock"})
        self.assertEqual(doc["ProgramArguments"], hv.weekly_argv(spec("launchd")))


STUB_DOCKER = r"""#!/bin/sh
printf '%s\n' "$*" >> "$STUB/log"
case "$1" in
  inspect) [ -f "$STUB/state" ] || exit 1; cat "$STUB/state" ;;
  ps) [ -f "$STUB/ps_fail" ] && exit 1; [ -f "$STUB/state" ] && echo abc; exit 0 ;;
  rm) exit 0 ;;
  stop) : > "$STUB/stopped"; exit 0 ;;
  run)
    if [ -f "$STUB/hold" ]; then
      : > "$STUB/running"
      while [ ! -f "$STUB/stopped" ]; do sleep 0.05; done
      exit 143
    fi
    exit "$(cat "$STUB/code")" ;;
esac
"""


class WrapperTest(unittest.TestCase):
    """The rendered wrapper, under dash and bash --posix."""

    SHELLS = [["/bin/sh"], ["bash", "--posix"]]

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.t = Path(td.name)
        self.stub = self.t / "stub"
        self.stub.mkdir()
        docker = self.t / "docker"
        docker.write_text(STUB_DOCKER)
        docker.chmod(0o755)
        s = spec("launchd")
        sec = dataclasses.replace(s.secrets, tools=dict(s.secrets.tools, docker=str(docker)))
        sup = dataclasses.replace(s.supervision, hub=dict(s.supervision.hub, status=str(self.t / "status")))
        self.script = self.t / "hub-link-run"
        self.script.write_bytes(hv.wrapper(dataclasses.replace(s, secrets=sec, supervision=sup)))

    def run_it(self, shell, code=None, state=None):
        for f in ("log", "state", "code", "stopped", "running", "hold", "ps_fail"):
            (self.stub / f).unlink(missing_ok=True)
        (self.t / "status").unlink(missing_ok=True)
        if state is not None:
            (self.stub / "state").write_text(state + "\n")
        if code is not None:
            (self.stub / "code").write_text(str(code))
        r = subprocess.run(shell + [str(self.script)], env={"STUB": str(self.stub), "PATH": "/usr/bin:/bin"},
                           capture_output=True, text=True, timeout=30)
        return r.returncode, self.log(), self.status()

    def log(self):
        p = self.stub / "log"
        return p.read_text().splitlines() if p.exists() else []

    def status(self):
        p = self.t / "status"
        return p.read_text().split()[0] if p.exists() else None

    def test_every_code_maps_as_the_restart_policy_says(self):
        for shell in self.SHELLS:
            for code in list(range(0, 14)) + [125, 126, 127, 137, 143]:
                with self.subTest(shell=shell, code=code):
                    rc, log, status = self.run_it(shell, code=code)
                    if code == 0 or 2 <= code <= 11:
                        self.assertEqual((rc, status), (0, str(code)))
                    else:
                        self.assertEqual((rc, status), (code, None))
                    self.assertTrue(any(l.startswith("run --name") for l in log), log)

    def test_a_stopped_leftover_is_removed_without_force_then_run(self):
        for shell in self.SHELLS:
            for state in ("created", "exited", "dead"):
                with self.subTest(shell=shell, state=state):
                    rc, log, _ = self.run_it(shell, code=0, state=state)
                    self.assertEqual(rc, 0)
                    self.assertIn(f"rm {hv.hub_name(spec())}", log)
                    self.assertFalse(any("-f" in l.split() for l in log if l.startswith("rm")))

    def test_a_running_orphan_is_left_alone_and_the_run_ends_cleanly(self):
        for shell in self.SHELLS:
            for state in ("running", "paused", "restarting"):
                with self.subTest(shell=shell, state=state):
                    rc, log, status = self.run_it(shell, state=state)
                    self.assertEqual((rc, status), (0, hv.ORPHAN))
                    self.assertFalse(any(l.split()[0] in ("rm", "stop", "run") for l in log), log)

    def test_an_engine_that_does_not_answer_is_125(self):
        for shell in self.SHELLS:
            with self.subTest(shell=shell):
                (self.stub / "ps_fail").touch()
                for f in ("log", "state"):
                    (self.stub / f).unlink(missing_ok=True)
                r = subprocess.run(shell + [str(self.script)], env={"STUB": str(self.stub), "PATH": "/usr/bin:/bin"},
                                   capture_output=True, text=True, timeout=30)
                self.assertEqual(r.returncode, 125)
                (self.stub / "ps_fail").unlink()

    def test_a_signal_while_the_run_is_in_flight_stops_it_and_passes_its_code(self):
        """POSIX sh defers a trap during a foreground command; the wrapper
        backgrounds the run and waits, so TERM is handled while it runs."""
        for shell in self.SHELLS:
            with self.subTest(shell=shell):
                for f in ("log", "state", "stopped", "running"):
                    (self.stub / f).unlink(missing_ok=True)
                (self.stub / "hold").touch()
                p = subprocess.Popen(shell + [str(self.script)], env={"STUB": str(self.stub), "PATH": "/usr/bin:/bin"},
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                deadline = time.time() + 10
                while not (self.stub / "running").exists() and time.time() < deadline:
                    time.sleep(0.05)
                p.send_signal(signal.SIGTERM)
                rc = p.wait(timeout=20)
                self.assertIn(f"stop -t {hv.STOP_TIMEOUT_S} {hv.hub_name(spec())}", self.log())
                self.assertEqual(rc, 143, "the run's own code is passed on")
                self.assertIsNone(self.status())
                (self.stub / "hold").unlink()


def st_(mode, uid=0, nlink=1, kind=stat.S_IFREG):
    return os.stat_result((kind | mode, 0, 0, nlink, uid, 0, 0, 0, 0, 0))


class VerifyTest(unittest.TestCase):
    def files(self, s, data_over=None, mode_over=None):
        data = {p: b for p, b in hv.rendered(s)}
        data.update(data_over or {})

        def read(p):
            if p not in data:
                raise FileNotFoundError(p)
            return data[p]

        def lstat(p):
            if p in data:
                return (mode_over or {}).get(p, st_(0o444))
            return st_(0o755, kind=stat.S_IFDIR)
        return lstat, read

    def results(self, s, **kw):
        lstat, read = self.files(s, **kw)
        return [c for c in hv.verify_files(s, lstat, read)]

    def test_placed_files_identical_and_root_0444_pass(self):
        s = spec()
        self.assertTrue(all(c.result == rh.PASS for c in self.results(s)))

    def test_a_placed_file_that_differs_fails_naming_it(self):
        s = spec()
        unit = s.supervision.hub["unit"]
        bad = [c for c in self.results(s, data_over={unit: b"edited"}) if c.result != rh.PASS]
        self.assertEqual(len(bad), 1)
        self.assertIn(unit, bad[0].claim)

    def test_a_writable_or_foreign_owned_file_fails(self):
        s = spec()
        unit = s.supervision.hub["unit"]
        for over in (st_(0o644), st_(0o444, uid=501), st_(0o444, nlink=2)):
            with self.subTest(over=over):
                self.assertTrue(any(c.result != rh.PASS for c in self.results(s, mode_over={unit: over})))


class AncestryTest(unittest.TestCase):
    def test_each_required_commit_must_be_an_ancestor(self):
        s = spec()
        ok = hv.verify_ancestry(s, lambda c, o: True, None)
        self.assertTrue(all(c.result == rh.PASS for c in ok))
        bad = hv.verify_ancestry(s, lambda c, o: c != "b" * 40, None)
        failed = [c for c in bad if c.result == rh.FAIL]
        self.assertEqual(len(failed), 1)
        self.assertIn("the image env unit", failed[0].claim)
        unknown = hv.verify_ancestry(s, lambda c, o: rh.Unresolved("git failed"), None)
        self.assertTrue(all(c.result == rh.UNKNOWN for c in unknown[:len(REQ)]))

    def test_the_label_where_present_must_be_the_recorded_commit(self):
        s = spec()
        sha = s.secrets.clones["runtime"]["sha"]
        last = lambda label: hv.verify_ancestry(s, lambda c, o: True, label)[-1].result
        self.assertEqual((last(None), last(sha), last("c" * 40), last(rh.Unresolved("x"))),
                         (rh.PASS, rh.PASS, rh.FAIL, rh.UNKNOWN))

    def test_the_git_answer_is_read_from_merge_base_exit_codes(self):
        s = spec()
        seen = []

        def fake(argv, **kw):
            seen.append(argv)
            return rh.Proc(tuple(argv), fake.rc, "", "boom")
        orig = hv.rh.run
        self.addCleanup(setattr, hv.rh, "run", orig)
        hv.rh.run = fake
        for rc, want in ((0, True), (1, False)):
            fake.rc = rc
            self.assertIs(hv.ask_ancestor(s, "a" * 40, "f" * 40), want)
        fake.rc = 128
        self.assertIsInstance(hv.ask_ancestor(s, "a" * 40, "f" * 40), rh.Unresolved)
        self.assertEqual(seen[0][-4:], ["merge-base", "--is-ancestor", "a" * 40, "f" * 40])
        self.assertIn("core.hooksPath=/dev/null", seen[0])


class StartGateTest(unittest.TestCase):
    """The start step is printed only when every start check passes."""

    def check(self, result):
        want = rh.Fact("x", True, "a test")
        if result == rh.UNKNOWN:
            return rh.unknown("x", want, "unknown", "fix it")
        return rh.check("x", want, result == rh.PASS, "fix it")

    def run_gate(self, results):
        orig_load, orig_read, orig_start = hs.load_spec, hs.read_spec, hs.start_checks
        self.addCleanup(setattr, hs, "load_spec", orig_load)
        self.addCleanup(setattr, hs, "read_spec", orig_read)
        self.addCleanup(setattr, hs, "start_checks", orig_start)
        built = spec()
        hs.read_spec = lambda *a, **k: None
        hs.load_spec = lambda doc: built
        hs.start_checks = lambda s, **k: [self.check(r) for r in results]
        said = []
        rc = hs.hub_start_check(None, out=said.append)
        return rc, "\n".join(said)

    def test_a_pass_prints_the_start_step(self):
        rc, said = self.run_gate([rh.PASS, rh.PASS])
        self.assertEqual(rc, 0)
        self.assertIn("systemctl enable --now hub-link.service", said)

    def test_any_fail_or_unknown_refuses_and_prints_no_start_step(self):
        for bad in (rh.FAIL, rh.UNKNOWN):
            with self.subTest(bad=bad):
                rc, said = self.run_gate([rh.PASS, bad])
                self.assertEqual(rc, 1)
                self.assertIn("REFUSED", said)
                self.assertNotIn("systemctl", said)


if __name__ == "__main__":
    unittest.main()


class StartChecksCompositionTest(unittest.TestCase):
    """The start check is the secret's state, the hub's
    files and rendering, the production overlay pin, the key probe's current
    evidence (without the in-container D7 read) and the supervision's files
    and ancestry. Each group is replaced by a marker to show it is called."""

    def test_every_group_is_in_the_start_check_and_the_d7_live_read_is_not(self):
        marks = {}

        def mark(name):
            def f(*a, **k):
                marks[name] = marks.get(name, 0) + 1
                return [rh.check(name, rh.Fact(name, True, "a test"), True, "x")]
            return f
        patches = {(hs.hr, "checks"): "hub", (hs, "verify_overlay"): "overlay",
                   (hs.hk, "verify_placement"): "placement", (hs.hk, "verify_no_delegation"): "delegation",
                   (hs.hk, "verify_evidence_dir"): "evidence_dir", (hs.hk, "verify_evidence_binds"): "binds",
                   (hs.hk, "verify_evidence"): "evidence", (hs.hv, "checks"): "supervision",
                   (hs.hk, "verify_d7_live"): "d7_live"}
        for (mod, name), label in patches.items():
            self.addCleanup(setattr, mod, name, getattr(mod, name))
            setattr(mod, name, mark(label))
        out = hs.start_checks(spec(), state="active", keys={"containers": []})
        self.assertEqual(out[0].claim, "the secret's state is active")
        self.assertEqual(out[0].result, rh.PASS)
        self.assertEqual(set(marks), {"hub", "overlay", "placement", "delegation", "evidence_dir", "binds",
                                      "evidence", "supervision"})
        not_active = hs.start_checks(spec(), state="pending_b5", keys={"containers": []})
        self.assertEqual(not_active[0].result, rh.FAIL)
