"""hub_supervise: the hub-link router's supervisor (the systemd unit; the
macOS wrapper and its LaunchDaemon), the weekly login probe's job, the
live-start ancestry check, and the gated start step.

Every value is invented; the document is test_hub_keys' plus a supervision
section. The wrapper is the RENDERED script, run under dash and under
`bash --posix` against a stub `docker` that records its argv and answers
from files, so the rows exercise what ships. No docker, systemd or launchd
runs.
"""

import contextlib
import dataclasses
import hashlib
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

    def test_each_file_must_be_where_its_supervisor_reads_it(self):
        """A unit outside /etc/systemd/system/ or a plist outside
        /Library/LaunchDaemons/ is never loaded, so the section refuses it."""
        for kind_, key, field, bad in (
                ("systemd", "hub", "unit", "/etc/systemd/user/hub-link.service"),
                ("systemd", "weekly", "service", "/opt/x/hub-link-probe.service"),
                ("systemd", "weekly", "timer", "/etc/systemd/system/sub/hub-link-probe.timer"),
                ("launchd", "hub", "plist", "/Library/LaunchAgents/org.example.hub.plist"),
                ("launchd", "weekly", "plist", "/Users/op/org.example.hub-probe.plist")):
            with self.subTest(field=f"{key}.{field}"):
                with self.assertRaises(hs.SpecError) as e:
                    spec(kind_, **{key: dict(sup_section(kind_)[key], **{field: bad})})
                self.assertIn(f"supervision.{key}.{field} must be directly in", str(e.exception))

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


def st_(mode, uid=0, nlink=1, kind=stat.S_IFREG, gid=0):
    return os.stat_result((kind | mode, 0, 0, nlink, uid, gid, 0, 0, 0, 0))


class VerifyTest(unittest.TestCase):
    def files(self, s, data_over=None, mode_over=None):
        data = {p: b for p, b in hv.rendered(s)}
        data.update(data_over or {})

        def read(p):
            if p not in data:
                raise FileNotFoundError(p)
            return data[p]

        def lstat(p):
            if p in (mode_over or {}):
                return mode_over[p]
            if p in data:
                return st_(hv.mode_of(s, p))
            return st_(0o755, kind=stat.S_IFDIR)
        return lstat, read

    def results(self, s, **kw):
        lstat, read = self.files(s, **kw)
        return [c for c in hv.verify_files(s, lstat, read)]

    def test_placed_files_identical_root_owned_plists_0644_and_the_rest_0444_pass(self):
        for kind_ in ("systemd", "launchd"):
            with self.subTest(kind=kind_):
                self.assertTrue(all(c.result == rh.PASS for c in self.results(spec(kind_))))
        s = spec("launchd")
        self.assertEqual({p: hv.mode_of(s, p) for p, _ in hv.rendered(s)},
                         {s.supervision.hub["wrapper"]: 0o444, s.supervision.hub["plist"]: 0o644,
                          s.supervision.weekly["plist"]: 0o644})

    def test_a_plist_at_0444_a_wrapper_at_0644_a_wrong_gid_or_a_writable_parent_fails(self):
        """Erratum 5(a): the plist is root:wheel 0644 in /Library/LaunchDaemons;
        the wrapper stays 0444. Each fault fails the check naming that file."""
        s = spec("launchd")
        sup = s.supervision
        for path, over in ((sup.hub["plist"], st_(0o444)), (sup.weekly["plist"], st_(0o444)),
                           (sup.hub["wrapper"], st_(0o644)), (sup.hub["plist"], st_(0o644, gid=20)),
                           ("/Library/LaunchDaemons", st_(0o775, kind=stat.S_IFDIR))):
            with self.subTest(path=path, mode=oct(over.st_mode & 0o7777), gid=over.st_gid):
                bad = [c for c in self.results(s, mode_over={path: over}) if c.result != rh.PASS]
                self.assertTrue(bad)
                self.assertTrue(all(path in c.claim or path in str(c.actual) for c in bad), [c.claim for c in bad])

    def test_the_plan_places_each_plist_with_mode_0644_and_nothing_else_with_a_mode(self):
        s = spec("launchd")
        places = [l for l in hv.plan(s, lambda x: x, "STEPS") if l.startswith("STEPS place ")]
        self.assertEqual([l.split()[3] for l in places if l.endswith(" --mode 0644")],
                         [s.supervision.hub["plist"], s.supervision.weekly["plist"]])
        self.assertEqual(sum("--mode" in l for l in places), 2)
        self.assertFalse(any("--mode" in l for l in hv.plan(spec(), lambda x: x, "STEPS")))

    def test_a_placed_file_that_differs_fails_naming_it(self):
        s = spec()
        unit = s.supervision.hub["unit"]
        bad = [c for c in self.results(s, data_over={unit: b"edited"}) if c.result != rh.PASS]
        self.assertEqual(len(bad), 1)
        self.assertIn(unit, bad[0].claim)

    def test_a_writable_or_foreign_owned_file_fails(self):
        s = spec()
        unit = s.supervision.hub["unit"]
        for over in (st_(0o644), st_(0o444, uid=501), st_(0o444, nlink=2), st_(0o444, gid=20)):
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


UNPATCHED = object()


@contextlib.contextmanager
def free_lock(_s=None):
    yield None


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
        self.addCleanup(setattr, hs, "checks", hs.checks)
        hs.checks = lambda *a, **k: self.fail("start_checks must never call checks (it calls start_gate back)")
        patches = {(hs.ss, "checks"): "secret", (hs.se, "checks"): "exposure",
                   (hs.hr, "checks"): "hub", (hs, "verify_overlay"): "overlay",
                   (hs.hk, "verify_placement"): "placement", (hs.hk, "verify_start_delegation"): "delegation",
                   (hs.hk, "verify_evidence_dir"): "evidence_dir", (hs.hk, "verify_evidence_binds"): "binds",
                   (hs.hk, "verify_evidence"): "evidence", (hs.hv, "checks"): "supervision",
                   (hs.hk, "verify_d7_live"): "d7_live"}
        for (mod, name), label in patches.items():
            self.addCleanup(setattr, mod, name, getattr(mod, name))
            setattr(mod, name, mark(label))
        out = hs.start_checks(spec(), state="active", keys={"containers": []}, secret_lock=free_lock)
        self.assertEqual(out[0].claim, "the secret's state is active")
        self.assertEqual(out[0].result, rh.PASS)
        self.assertEqual(set(marks), {"secret", "exposure", "hub", "overlay", "placement", "delegation",
                                      "evidence_dir", "binds", "evidence", "supervision"})
        not_active = hs.start_checks(spec(), state="pending_b5", keys={"containers": []}, secret_lock=free_lock)
        self.assertEqual(not_active[0].result, rh.FAIL)


class StartSweepTest(unittest.TestCase):
    """The exposure sweep (§7d) is part of the start check: a container that
    also mounts the secret volume refuses the start step. The overlap is the
    REAL sweep's finding, from secret_exposure's own fixture (another
    container mounting the volume read-only)."""

    def planted_overlap(self):
        import test_secret_exposure as tse
        spec_x, sx = tse.specs()
        orig = rh.run
        rh.run = tse.engine(by_context={"default": [tse.runtime(), tse.container("other", [tse.vol("/x")])]})
        try:
            found = hs.se.checks(spec_x, sx, lstat_=lambda p: tse.Id(1, 1), stat_=tse.stat_of(),
                                 realpath=lambda p: p, lock=tse.free_lock, platform="linux")
        finally:
            rh.run = orig
        fails = [c for c in found if c.result == rh.FAIL and "only ex-down mounts the volume" in c.claim]
        self.assertTrue(fails)
        return found

    def gate(self, exposure_found, secrets_checks=None, overlay=None, spec_path=None, horizon=None,
             no_delegation=None, keys=None):
        good = [rh.check("x", rh.Fact("x", True, "a test"), True, "x")]
        built = spec()

        def same(*a, **k):
            return good
        patches = [(hs, "read_spec", lambda *a, **k: None), (hs, "load_spec", lambda doc: built),
                   (hs.ss, "checks", secrets_checks or same), (hs.se, "checks", lambda *a, **k: exposure_found),
                   (hs.hr, "checks", same), (hs, "verify_overlay", same), (hs.hk, "verify_placement", same),
                   (hs.hk, "verify_start_delegation", no_delegation or same), (hs.hk, "verify_evidence_dir", same),
                   (hs.hk, "verify_evidence_binds", same), (hs.hk, "verify_evidence", same), (hs.hv, "checks", same),
                   (hs, "verify_recovery_horizon", horizon or same)]
        for mod, name, value in patches:
            if value is UNPATCHED:
                continue
            self.addCleanup(setattr, mod, name, getattr(mod, name))
            setattr(mod, name, value)
        said = []
        rc = hs.hub_start_check(spec_path, overlay=overlay, out=said.append, state="active",
                                keys=keys or {"containers": []}, secret_lock=free_lock)
        return rc, "\n".join(said)

    def test_the_start_check_hands_the_routers_own_answer_to_the_no_signing_check(self):
        """Its absence passes only when the running router reads the file, so the
        start check must pass what the router answered, never nothing."""
        seen = []
        answer = ("/opt/ex/local/router.json", "a" * 64)
        self.gate([], no_delegation=lambda ks, live, rb, sg: seen.append(live) or [],
                  keys={"containers": [], "live": answer})
        self.assertEqual(seen, [answer])

    def test_a_bound_delegation_free_config_passes_the_real_gate(self):
        """hub_keys.verify_start_delegation unstubbed, with every other group
        passing: a delegation-free config the router is shown to read lets
        the hub-link router start; a block with no activation inputs refuses."""
        path = spec().keys.local_config
        self.addCleanup(setattr, hs, "start_inputs", hs.start_inputs)
        hs.start_inputs = lambda s, policy_on, p: None
        for body, rc_want in ((b'{"state_dir": "/s"}\n', 0), (b'{"state_dir": "/s", "delegation": {}}\n', 1)):
            with self.subTest(body=body):
                sha = hashlib.sha256(body).hexdigest()
                rc, said = self.gate([], no_delegation=UNPATCHED,
                                     keys={"containers": [], "live": (path, sha), "read_bytes_": lambda p, b=body: b})
                self.assertEqual(rc, rc_want, said)

    def test_the_recovery_window_is_part_of_the_start_check(self):
        bad = [rh.check("the recovery window is below the horizon", rh.Fact("h", 30, "a test"), 30, "lower it",
                        ok=lambda e, a: a < e)]
        rc, said = self.gate([], horizon=lambda *a, **k: bad)
        self.assertNotEqual(rc, 0, said)
        self.assertIn("the recovery window is below the horizon", said)

    def test_a_start_check_from_the_overlay_hands_the_overlay_to_the_secrets_checks(self):
        """The secret's own checks FAIL a document read from --spec rather than
        the overlay (`verify_overlay_source`): the overlay hub-start-check read
        must reach them, or every overlay run is refused."""
        ov = Path("/srv/overlay/host.json")

        def secrets(spec_, **k):
            ok = k.get("overlay") == str(ov)
            return [rh.check("the document was read from the overlay", rh.Fact("o", True, "a test"), ok, "x")]
        clean = [rh.check("y", rh.Fact("y", True, "a test"), True, "x")]
        rc, said = self.gate(clean, secrets_checks=secrets, overlay=ov)
        self.assertEqual(rc, 0, said)

    def test_a_spec_document_is_never_checked_as_the_overlay(self):
        """The CLI supplies the overlay path even with --spec: the document
        actually read is the --spec copy, so the secrets checks must see no
        overlay, and their provenance check FAILs."""
        ov = Path("/srv/overlay/host.json")
        seen = []

        def secrets(spec_, **k):
            seen.append(k.get("overlay"))
            ok = k.get("overlay") == str(ov)
            return [rh.check("the document was read from the overlay", rh.Fact("o", True, "a test"), ok, "x")]
        clean = [rh.check("y", rh.Fact("y", True, "a test"), True, "x")]
        rc, said = self.gate(clean, secrets_checks=secrets, overlay=ov, spec_path=Path("/tmp/copied-host.json"))
        self.assertNotEqual(rc, 0, said)
        self.assertEqual(seen, [None])
        self.assertIn("REFUSED", said)

    def test_a_planted_overlap_refuses_the_start_step(self):
        rc, said = self.gate(self.planted_overlap())
        self.assertNotEqual(rc, 0)
        self.assertIn("REFUSED", said)
        self.assertIn("only ex-down mounts the volume", said)
        self.assertNotIn("systemctl", said)

    def test_a_clean_sweep_passes_and_says_verify_must_also_pass(self):
        rc, said = self.gate([rh.check("y", rh.Fact("y", True, "a test"), True, "x")])
        self.assertEqual(rc, 0, said)
        self.assertIn("`host-setup` (verify) must ALSO pass", said)
        self.assertIn("systemctl enable --now hub-link.service", said)


class LaunchdEnablementTest(unittest.TestCase):
    """macOS: launchd loads every plist in /Library/LaunchDaemons at boot, so
    both labels are disabled BEFORE placing, the start step enables then
    bootstraps, and verify FAILs a label that is not disabled unless every
    start check passes now."""

    def test_the_plan_disables_both_labels_before_placing_anything(self):
        s = spec("launchd")
        lines = hv.plan(s, lambda x: x, "STEPS")
        dis = [i for i, l in enumerate(lines) if l.startswith(f"{hv.LAUNCHCTL} disable system/")]
        place = [i for i, l in enumerate(lines) if l.startswith("STEPS place ")]
        self.assertEqual([lines[i].split()[2] for i in dis],
                         ["system/org.example.hub-probe", "system/org.example.hub"])
        self.assertTrue(place and max(dis) < min(place))
        self.assertFalse(any("enable" in l.replace("enables nothing", "") and "disable" not in l for l in lines))

    def test_systemd_needs_no_override(self):
        self.assertEqual(hv.labels(spec()), [])
        self.assertFalse(any("launchctl" in l for l in hv.plan(spec(), lambda x: x, "STEPS")))

    def test_the_start_step_enables_each_label_then_bootstraps_it(self):
        self.assertEqual(hv.start_commands(spec("launchd")), [
            f"{hv.LAUNCHCTL} enable system/org.example.hub-probe",
            f"{hv.LAUNCHCTL} bootstrap system /Library/LaunchDaemons/org.example.hub-probe.plist",
            f"{hv.LAUNCHCTL} enable system/org.example.hub",
            f"{hv.LAUNCHCTL} bootstrap system /Library/LaunchDaemons/org.example.hub.plist"])

    def test_print_disabled_is_read_in_both_spellings(self):
        """The two spellings `launchctl print-disabled system` is documented to
        use (disabled/enabled, and true/false on older macOS). NOT measured
        on a host here."""
        text = ('disabled services = {\n\t"org.example.hub" => disabled\n'
                '\t"org.example.hub-probe" => enabled\n\t"com.other" => true\n\t"com.more" => false\n}\n')
        self.assertEqual(hv.parse_disabled(text), {"org.example.hub": True, "org.example.hub-probe": False,
                                                   "com.other": True, "com.more": False})

    def results(self, disabled, gate, loaded=False):
        asked = []

        def g():
            asked.append(1)
            return gate
        return [c.result for c in hv.verify_enablement(spec("launchd"), disabled, g, lambda label: loaded)], asked

    def test_a_disabled_label_already_loaded_still_faces_the_gate(self):
        """Disabling does not unload: a label bootstrapped before its override
        is running, so it passes only when the start checks pass now."""
        both = {"org.example.hub": True, "org.example.hub-probe": True}
        r, asked = self.results(both, False, loaded=True)
        self.assertEqual(r, [rh.FAIL, rh.FAIL])
        self.assertEqual(len(asked), 1)
        self.assertEqual(self.results(both, True, loaded=True)[0], [rh.PASS, rh.PASS])
        self.assertEqual(self.results(both, False, loaded=rh.Unresolved("no answer"))[0], [rh.UNKNOWN, rh.UNKNOWN])

    def test_print_disabled_output_not_in_its_form_is_unknown(self):
        good = 'disabled services = {\n\t"org.example.hub" => disabled\n}\n'
        self.assertEqual(hv.parse_disabled(good), {"org.example.hub": True})
        self.assertEqual(hv.parse_disabled("disabled services = {\n}\n"), {})
        for bad in ("", "garbage\n", 'disabled services = {\n\t"org.example.hub" => maybe\n}\n',
                    'disabled services = {\n\t"org.example.hub" => disabled\n',
                    'other = {\n}\n', '"org.example.hub" => disabled\n'):
            with self.subTest(bad=bad):
                self.assertIsInstance(hv.parse_disabled(bad), rh.Unresolved)
        r, _ = self.results(hv.parse_disabled("garbage\n"), True)
        self.assertEqual(r, [rh.UNKNOWN, rh.UNKNOWN])

    def test_loaded_is_read_from_launchctl_print(self):
        """`launchctl print system/<label>`: exit 0 is loaded; its documented
        not-found message is not loaded; anything else is unknown."""
        calls = []

        def fake(rc, out="", err=""):
            def run(argv, **k):
                calls.append(list(argv))
                return rh.Proc(tuple(argv), rc, out, err)
            return run
        self.addCleanup(setattr, hv.rh, "run", hv.rh.run)
        hv.rh.run = fake(0)
        self.assertIs(hv.ask_loaded("org.example.hub"), True)
        self.assertEqual(calls[-1], [hv.LAUNCHCTL, "print", "system/org.example.hub"])
        hv.rh.run = fake(113, err='Could not find service "org.example.hub" in domain for system')
        self.assertIs(hv.ask_loaded("org.example.hub"), False)
        hv.rh.run = fake(5, err="Operation not permitted")
        self.assertIsInstance(hv.ask_loaded("org.example.hub"), rh.Unresolved)

    def test_disabled_labels_pass_without_asking_the_gate(self):
        r, asked = self.results({"org.example.hub": True, "org.example.hub-probe": True}, False)
        self.assertEqual(r, [rh.PASS, rh.PASS])
        self.assertEqual(asked, [])

    def test_an_enabled_or_unoverridden_label_fails_unless_the_start_checks_pass_now(self):
        for state in ({"org.example.hub": False, "org.example.hub-probe": True}, {"org.example.hub-probe": True}):
            with self.subTest(state=state):
                r, asked = self.results(state, False)
                self.assertEqual(r, [rh.PASS, rh.FAIL])
                r, asked = self.results(state, True)
                self.assertEqual(r, [rh.PASS, rh.PASS])
                self.assertEqual(len(asked), 1)

    def test_an_unreadable_override_or_gate_is_unknown(self):
        r, _ = self.results(rh.Unresolved("no launchctl"), True)
        self.assertEqual(r, [rh.UNKNOWN, rh.UNKNOWN])
        r, _ = self.results({}, rh.Unresolved("a start check is UNKNOWN"))
        self.assertEqual(r, [rh.UNKNOWN, rh.UNKNOWN])

    def test_host_verify_runs_the_enablement_check_for_launchd_only(self):
        calls = []
        orig = hs.hv.verify_enablement
        self.addCleanup(setattr, hs.hv, "verify_enablement", orig)
        hs.hv.verify_enablement = lambda s, d, g, loaded: calls.append((d, g())) or []
        self.addCleanup(setattr, hs.hv, "checks", hs.hv.checks)
        hs.hv.checks = lambda *a, **k: []
        for name in ("verify_roots", "verify_overlay", "verify_containers", "verify_mounts", "verify_openssl",
                     "verify_umasks", "verify_groups"):
            self.addCleanup(setattr, hs, name, getattr(hs, name))
            setattr(hs, name, lambda *a, **k: [])
        en = {"disabled": {"org.example.hub": True}, "gate": lambda: "gate-asked"}
        for kind_, want in (("launchd", [({"org.example.hub": True}, "gate-asked")]), ("systemd", [])):
            with self.subTest(kind=kind_):
                calls.clear()
                s = dataclasses.replace(spec(kind_), runtimes=[], secrets=None, hub=None, keys=None)
                hs.checks(s, production=False, enablement=en)
                self.assertEqual(calls, want)

    def test_verify_from_the_overlay_hands_the_overlay_to_the_start_gate(self):
        """HOST's probe: with every start check passing, an enabled label PASSes
        only if verify's overlay reaches the start checks the gate runs."""
        ov = Path("/srv/overlay/host.json")
        seen = []

        def start(s, **k):
            seen.append(k.get("overlay"))
            return [rh.check("x", rh.Fact("x", True, "a test"), k.get("overlay") == ov, "x")]
        for mod, name in ((hs, "start_checks"), (hs, "secret_checks"), (hs.hv, "checks"), (hs.hr, "checks"),
                          (hs.hk, "checks"), (hs, "verify_roots"), (hs, "verify_overlay"),
                          (hs, "verify_containers"), (hs, "verify_mounts"), (hs, "verify_openssl"),
                          (hs, "verify_umasks"), (hs, "verify_groups")):
            self.addCleanup(setattr, mod, name, getattr(mod, name))
            setattr(mod, name, lambda *a, **k: [])
        hs.start_checks = start
        s = dataclasses.replace(spec("launchd"), runtimes=[])
        out = hs.checks(s, production=False, overlay=ov, enablement={"disabled": {}, "loaded": lambda l: False})
        results = [c.result for c in out if "is disabled, or every start check passes" in c.claim]
        self.assertEqual(results, [rh.PASS, rh.PASS])
        self.assertEqual(seen, [ov])

    def test_the_gate_is_false_on_a_fail_and_unresolved_on_an_unknown(self):
        orig = hs.start_checks
        self.addCleanup(setattr, hs, "start_checks", orig)
        want = rh.Fact("x", True, "a test")
        for checks, expect in (([rh.check("a", want, True, "f")], True),
                               ([rh.check("a", want, False, "f"), rh.unknown("b", want, "?", "f")], False)):
            hs.start_checks = lambda s, **k: checks
            self.assertIs(hs.start_gate(spec("launchd")), expect)
        hs.start_checks = lambda s, **k: [rh.unknown("b", want, "?", "f")]
        self.assertIsInstance(hs.start_gate(spec("launchd")), rh.Unresolved)


if __name__ == "__main__":
    unittest.main()


class StopBudgetTest(unittest.TestCase):
    """The stop timeout against the router's own join bound, derived from the
    rendered budgets; and the start probe's window, named."""

    def test_the_rendered_budgets_give_91_and_185_and_100_covers_the_join(self):
        env = dict(hs.hr.environment(spec(), spec().hub))
        self.assertEqual(hv.stop_budget(env), (91, 185))
        [c] = hv.verify_stop_budget(spec())
        self.assertEqual(c.result, rh.PASS)
        self.assertIn("does not cover the start probe's login window (185 s)", c.claim)

    def test_a_dot_budget_past_the_stop_timeout_fails(self):
        self.addCleanup(setattr, hs.hr, "environment", hs.hr.environment)
        real = hs.hr.environment
        hs.hr.environment = lambda sp, hub: [(k, "60" if k == "RELAY_SMTP_DOT_TIMEOUT" else v) for k, v in real(sp, hub)]
        [c] = hv.verify_stop_budget(spec())
        self.assertEqual((c.result, c.expected.value), (rh.FAIL, 121))

    def test_budgets_are_read_as_the_email_router_reads_them(self):
        """Unset is its default; a fraction rounds up; a value it would refuse
        is a FAIL by name, never a crash."""
        self.assertEqual(hv.stop_budget({}), (600 + hv.JOIN_SLACK_S + hv.DONE_POLL_S, 300 + 5 * 300 + hv.QUIT_S))
        env = {"RELAY_SMTP_DOT_TIMEOUT": "29.2", "RELAY_SMTP_CONNECT_TIMEOUT": "7.5", "RELAY_SMTP_COMMAND_TIMEOUT": "3"}
        self.assertEqual(hv.stop_budget(env), (30 + hv.JOIN_SLACK_S + hv.DONE_POLL_S, 23 + hv.QUIT_S))
        self.assertEqual(hv.RE_BUDGET_MAX, 3600)
        self.assertEqual(hv.stop_budget({"RELAY_SMTP_DOT_TIMEOUT": "3600"})[0], 3600 + hv.JOIN_SLACK_S + hv.DONE_POLL_S)
        for bad in ("0", "-5", "3601", "nan", "inf", "thirty"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError) as e:
                    hv.stop_budget({"RELAY_SMTP_DOT_TIMEOUT": bad})
                self.assertIn("RELAY_SMTP_DOT_TIMEOUT", str(e.exception))
        self.addCleanup(setattr, hs.hr, "environment", hs.hr.environment)
        real = hs.hr.environment
        hs.hr.environment = lambda sp, hub: [(k, "nan" if k == "RELAY_SMTP_DOT_TIMEOUT" else v) for k, v in real(sp, hub)]
        [c] = hv.verify_stop_budget(spec())
        self.assertEqual(c.result, rh.FAIL)
        self.assertIn("RELAY_SMTP_DOT_TIMEOUT", str(c.actual))

    def test_each_term_of_the_bound_counts(self):
        env = {"RELAY_SMTP_DOT_TIMEOUT": "10", "RELAY_SMTP_CONNECT_TIMEOUT": "7", "RELAY_SMTP_COMMAND_TIMEOUT": "3"}
        self.assertEqual(hv.stop_budget(env), (10 + hv.JOIN_SLACK_S + hv.DONE_POLL_S, 7 + 5 * 3 + hv.QUIT_S))


class ActivatedEnablementTest(unittest.TestCase):
    """An activated launchd host's enablement, through the REAL start_gate,
    start_checks and verify_start_delegation, with every other start check
    passing and both labels enabled and loaded: A1's approved block under
    the static matrix passes; anything else refuses. The matrix's inputs are
    built from test_signing_matrix's fixtures; start_inputs reading them is
    pinned separately."""

    def setUp(self):
        import test_signing_matrix as tsm
        self.tsm = tsm
        self.spec = spec("launchd")
        good = [rh.check("x", rh.Fact("x", True, "a test"), True, "x")]
        same = lambda *a, **k: good
        for mod, name, value in ((hs.ss, "checks", same), (hs.se, "checks", lambda *a, **k: []),
                                 (hs.hr, "checks", same), (hs, "verify_overlay", same),
                                 (hs.hk, "verify_placement", same), (hs.hk, "verify_evidence_dir", same),
                                 (hs.hk, "verify_evidence_binds", same), (hs.hk, "verify_evidence", same),
                                 (hs.hv, "checks", same), (hs, "verify_recovery_horizon", same),
                                 (hs, "start_inputs", lambda s, policy_on, p: self.inputs(policy_on))):
            self.addCleanup(setattr, mod, name, getattr(mod, name))
            setattr(mod, name, value)
        self.over = {}

    def inputs(self, policy_on):
        tsm = self.tsm
        fields = dict(policy_on=policy_on, gate_ok=True, approved=tsm.approved(), approved_why="",
                      named=tsm.named(), status=rh.Unresolved("not read"),
                      witness=lambda h: self.fail("the start gate asked the adoption witness"), now=tsm.NOW)
        fields.update(self.over)
        return hs.hk.Signing(**fields)

    def labels(self, body, policy_on=True):
        path = self.spec.keys.local_config
        keys = {"containers": [], "live": (path, hashlib.sha256(body).hexdigest()), "read_bytes_": lambda p: body}
        gate = lambda: hs.start_gate(self.spec, state="active", keys=keys, secret_lock=free_lock, policy_on=policy_on)
        enabled = {label: False for label in hv.labels(self.spec)}
        return [c.result for c in hv.verify_enablement(self.spec, enabled, gate, lambda label: True)]

    def test_a1_s_approved_block_passes_enablement(self):
        self.assertEqual(self.labels(self.tsm.live(self.tsm.SIGNED)), [rh.PASS, rh.PASS])

    def test_an_unapproved_block_fails_enablement(self):
        other = dict(self.tsm.SIGNED, crypto={"crypto_backend": "openssl"})
        self.assertEqual(self.labels(self.tsm.live(other)), [rh.FAIL, rh.FAIL])

    def test_a_failing_static_matrix_fails_enablement(self):
        for label, over, policy_on in (("policy off", {}, False), ("gate not holding", dict(gate_ok=False), True),
                                       ("stale evidence", dict(named=self.tsm.named(at=self.tsm.NOW - 9 * 86400)), True)):
            with self.subTest(label):
                self.over = over
                self.assertEqual(self.labels(self.tsm.live(self.tsm.SIGNED), policy_on), [rh.FAIL, rh.FAIL])

    def test_unreadable_inputs_leave_enablement_unknown(self):
        self.assertEqual(self.labels(self.tsm.live(self.tsm.SIGNED), rh.Unresolved("no manifest")),
                         [rh.UNKNOWN, rh.UNKNOWN])

    def test_unsigned_passes_and_an_unreadable_config_does_not(self):
        self.assertEqual(self.labels(self.tsm.live()), [rh.PASS, rh.PASS])
        self.assertEqual(self.labels(b"[1]"), [rh.UNKNOWN, rh.UNKNOWN])


class StartInputsTest(unittest.TestCase):
    """host_setup.start_inputs: the policy's own answer and the document's
    activation inputs, as verify reads them; the router's status and the
    adoption witness are never asked."""

    def test_the_policy_answer_passes_through_and_nothing_is_asked_of_the_router(self):
        self.addCleanup(setattr, hs.hk, "ask_status", hs.hk.ask_status)
        hs.hk.ask_status = lambda *a, **k: self.fail("the start gate asked the router's status")
        s = spec("launchd")
        for answer in (True, False):
            with self.subTest(policy_on=answer):
                sg = hs.start_inputs(s, answer, {"rl_sha": "a" * 40, "read": lambda p: b"{}"})
                self.assertIs(sg.policy_on, answer)
                self.assertIsInstance(sg.status, rh.Unresolved)
                self.assertEqual(sg.witness("0" * 64)[0], rh.UNKNOWN)
        self.assertIsInstance(hs.start_inputs(s, None, {"rl_sha": "a" * 40, "read": lambda p: b"{}"}).policy_on,
                              rh.Unresolved)


class EnablementWiringTest(unittest.TestCase):
    """verify's host-setup checks hand the enablement gate the same policy
    answer and partition probes the signing check reads."""

    def test_checks_passes_the_policy_and_the_partition_probes_to_the_gate(self):
        seen = []
        self.addCleanup(setattr, hs, "start_gate", hs.start_gate)
        hs.start_gate = lambda sp, **k: seen.append(k) or True
        s = spec("launchd")
        probes = {"rl_sha": "a" * 40}
        hs.checks(s, production=False, policy_on=True, partition=probes, secret_lock=free_lock,
                  enablement={"disabled": {label: False for label in hv.labels(s)}, "loaded": lambda label: True},
                  keys={"containers": [], "status": rh.Unresolved("not asked"),
                        "witness": lambda h: (rh.UNKNOWN, "not asked")})
        self.assertEqual([(k.get("policy_on"), k.get("partition")) for k in seen], [(True, probes)])


class StartCheckVerbTest(unittest.TestCase):
    """`amap-sandy.py hub-start-check` reads the fleet policy's answer from
    the manifest and hands it to the start check."""

    def test_the_verb_passes_the_policy_answer(self):
        import amap_sandy as prov
        seen = []
        for mod, name, value in ((prov.hsu, "hub_start_check", lambda spec_path, **k: seen.append(k) or 0),
                                 (prov, "delegation_policy", lambda home: "the policy's answer")):
            self.addCleanup(setattr, mod, name, getattr(mod, name))
            setattr(mod, name, value)
        with tempfile.TemporaryDirectory() as home:
            self.assertEqual(prov.main(["--sandy-home", home, "hub-start-check"]), 0)
        self.assertEqual([k.get("policy_on") for k in seen], ["the policy's answer"])


class A5OnLaunchdTest(unittest.TestCase):
    """verify --a5 on a launchd host: the signing check's UNKNOWN is excused
    only with the whole reason an activated router gives under the live
    token when the adoption witness stops at the kind clause, and only when
    every other check passes. The reason is the one verify_signing emits,
    through the real adoption witness and a launchd host view."""

    def setUp(self):
        import test_signing_matrix as tsm
        self.tsm = tsm
        self.spec = spec("launchd")
        self.live = tsm.live(tsm.SIGNED)

    def emitted(self, kind="launchd"):
        """verify_signing's own row for an activated router on this host."""
        tsm, raw = self.tsm, self.live
        sha = hashlib.sha256(raw).hexdigest()
        t = {"dev": 1, "ino": 7, "ctime_ns": 10 ** 18, "size": len(raw), "sha256": sha, "now": 0.0,
             "boot_id": "b", "fstype": "virtiofs"}
        view = {"kind": kind, "platform": "linux", "boot_id": "b", "fstype": "virtiofs", "dev": 1, "ino": 7,
                "ctime_ns": 10 ** 18, "sha256": sha, "now": 10 ** 9 + 60}
        sg = hs.hk.Signing(policy_on=True, gate_ok=True, approved=tsm.approved(), approved_why="", named=tsm.named(),
                           status=tsm.fresh_status(), now=tsm.NOW,
                           witness=lambda h: hs.hk.adoption(lambda: dict(t), lambda: tsm.fresh_status(polls=1), h,
                                                            host_view=lambda: dict(view), sleep=lambda x: None))
        bind = rh.check("bind", rh.Fact("live config", 1, "test"), 1, "r")
        return hs.hk.verify_signing(self.spec.keys, raw, bind, sg)

    def expected(self, found, body=None):
        return hs.a5_expected(self.spec, found, lambda p: self.live if body is None else body)

    def test_the_emitted_reason_is_the_one_excused(self):
        row = self.emitted()
        self.assertEqual(row.result, rh.UNKNOWN)
        self.assertEqual(row.reason, hs.hk.a5_launchd_reason(self.tsm.RID))
        self.assertIs(self.expected([row]), row)

    def test_nothing_else_is_excused(self):
        row = self.emitted()
        other_kind = rh.unknown(row.claim, row.expected, row.reason.replace(hs.hk.KIND_NOT_LINUX, "another clause"),
                                row.remedy)
        other_token = self.tsm.live(dict(self.tsm.SIGNED, partition_verified="r9:" + "a" * 64))
        for label, found, body in (("another clause", [other_kind], None),
                                   ("another token's run", [row], other_token),
                                   ("no token", [row], self.tsm.live()),
                                   ("unreadable config", [row], b"{"),
                                   ("two signing rows", [row, row], None),
                                   ("a FAIL", [rh.check(row.claim, row.expected, row.reason, row.remedy)], None)):
            with self.subTest(label):
                self.assertIsNone(self.expected(found, body))
        self.assertIsNone(hs.a5_expected(spec("systemd"), [row], lambda p: self.live))

    def section(self, found, a5):
        for mod, name, value in ((hs, "overlay_section", lambda overlay: {}), (hs, "load_spec", lambda sec: self.spec),
                                 (hs, "checks", lambda *a, **k: found), (hs, "print_notes", lambda *a, **k: None),
                                 (hs.hk, "read_bytes", lambda p: self.live)):
            self.addCleanup(setattr, mod, name, getattr(mod, name))
            setattr(mod, name, value)
        said = []
        return hs.verify_section(Path("/overlay.json"), out=said.append, a5=a5), "\n".join(said)

    def test_verify_a5_passes_only_with_every_other_check_passing(self):
        row, good = self.emitted(), rh.check("x", rh.Fact("x", True, "a test"), True, "x")
        bad = rh.check("y", rh.Fact("y", True, "a test"), False, "fix y")
        self.assertEqual(self.section([good, row], a5=True)[0], 0)
        self.assertEqual(self.section([good, row], a5=False)[0], 1)
        self.assertEqual(self.section([bad, row], a5=True)[0], 1)
        rc, said = self.section([good, row], a5=True)
        self.assertIn("UNKNOWN", said)                         # still printed as what it is
        self.assertIn("the one expected non-pass", said)


class VerifyA5FlagTest(unittest.TestCase):
    """`verify --a5` reaches the host-setup section, and plain verify does
    not ask for it."""

    def test_the_flag_reaches_the_section(self):
        import argparse
        import amap_sandy as prov
        seen = []
        for mod, name, value in ((prov.hsu, "verify_section", lambda overlay, **k: seen.append(k.get("a5")) or 0),
                                 (prov.ha, "overlay_path", lambda p: Path("/overlay.json")),
                                 (prov, "delegation_policy", lambda home: True)):
            self.addCleanup(setattr, mod, name, getattr(mod, name))
            setattr(mod, name, value)
        for flag in (True, False):
            prov.run_verify_host_setup(argparse.Namespace(overlay=None, a5=flag), Path("/home"))
        self.assertEqual(seen, [True, False])
