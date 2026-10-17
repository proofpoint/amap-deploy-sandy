"""host_steps.service (d3.3 §5(d) §4): the service manager's calls as root,
from a whitelist in the writer, the manager judged in process on the exact
path run, the environment exactly {PATH, LC_ALL}, the manager's own status
never passed through, and a bootout confirmed only by the measured
not-found answer within one budget.

The manager is a recording stub passed as `run`. Phase A's judge is
replaced where the row is not about it. The plist rows use real files with
root mapped to this test's uid and LAUNCHD_DIR moved into a temporary
directory; the directories above it are taken as root's by identity."""

import os
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest

import host_steps as hs
import hub_supervise as hv
import root_trust as rt
import router_health as rh
from test_hub_runtime import setUpModule, tearDownModule  # noqa: F401 -- the fixture's pins, restored
from test_hub_supervise import MANAGER, spec

SYSTEMCTL, LAUNCHCTL = "/usr/bin/systemctl", "/bin/launchctl"
NOT_FOUND = (113, "Could not find service \"x\" in domain for system")


class Proc:
    def __init__(self, rc, out=b"", err=b""):
        self.returncode, self.stdout, self.stderr = rc, out, err


class Verb(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.said = []
        self.judged = []
        self.patch("judge", lambda argv0, also=(), recorded=(), **k: (self.judged.append(list(also)),
                                                                       hs.Judgment([], "clean"))[1])
        self.patch("_plist_problem", lambda plist, platform=None: None)

    def patch(self, name, value):
        self.addCleanup(setattr, hs, name, getattr(hs, name))
        setattr(hs, name, value)

    def runner(self, *answers):
        """A manager that records each call and answers in turn (the last repeats)."""
        answers = list(answers) or [Proc(0)]

        def run(argv, **kw):
            self.calls.append((list(argv), kw))
            a = answers.pop(0) if len(answers) > 1 else answers[0]
            if isinstance(a, BaseException):
                raise a
            return a
        return run

    def service(self, manager, kind, action, *args, run=None, **kw):
        return hs.service(manager, kind, action, list(args), run=run or self.runner(), out=self.said.append, **kw)

    def refused(self, manager, kind, action, *args):
        with self.assertRaises(hs.Tooling):
            self.service(manager, kind, action, *args)
        self.assertEqual((self.calls, self.judged), ([], []), "nothing is judged or called before the table")


class TableRows(Verb):
    ROWS = [
        (LAUNCHCTL, "launchd", "disable", ["org.example.hub"], ["disable", "system/org.example.hub"]),
        (LAUNCHCTL, "launchd", "enable", ["org.example.hub"], ["enable", "system/org.example.hub"]),
        (LAUNCHCTL, "launchd", "bootstrap", ["org.example.hub", "/Library/LaunchDaemons/org.example.hub.plist"],
         ["bootstrap", "system", "/Library/LaunchDaemons/org.example.hub.plist"]),
        (SYSTEMCTL, "systemd", "daemon-reload", [], ["--no-ask-password", "--no-pager", "daemon-reload"]),
        (SYSTEMCTL, "systemd", "enable-now", ["hub-link.service"],
         ["--no-ask-password", "--no-pager", "enable", "--now", "hub-link.service"]),
        (SYSTEMCTL, "systemd", "enable-now", ["hub-link-probe.timer"],
         ["--no-ask-password", "--no-pager", "enable", "--now", "hub-link-probe.timer"]),
        (SYSTEMCTL, "systemd", "restart", ["hub-link.service"],
         ["--no-ask-password", "--no-pager", "restart", "hub-link.service"]),
        (SYSTEMCTL, "systemd", "stop", ["hub-link.service"],
         ["--no-ask-password", "--no-pager", "stop", "hub-link.service"]),
        (SYSTEMCTL, "systemd", "stop", ["hub-link-probe.timer"],
         ["--no-ask-password", "--no-pager", "stop", "hub-link-probe.timer"]),
        (SYSTEMCTL, "systemd", "reset-failed", ["hub-link.service"],
         ["--no-ask-password", "--no-pager", "reset-failed", "hub-link.service"]),
    ]

    def test_each_row_runs_exactly_its_argv_under_exactly_path_and_lc_all(self):
        for m, kind, action, args, tail in self.ROWS:
            with self.subTest(kind=kind, action=action, args=args):
                self.calls.clear()
                self.judged.clear()
                self.assertEqual(self.service(m, kind, action, *args), 0)
                [(argv, kw)] = self.calls
                self.assertEqual(argv, [m] + tail)
                self.assertEqual(kw["env"], {"PATH": rt.PATH, "LC_ALL": "C"})
                self.assertEqual((kw["shell"], kw["close_fds"], kw["stdin"], kw["timeout"]),
                                 (False, True, subprocess.DEVNULL, hs.SERVICE_TIMEOUT_S))
                self.assertEqual(self.judged, [[m]], "the manager is judged in process on the path run")

    def test_the_table_is_these_rows_and_no_others(self):
        self.assertEqual(sorted(hs.SERVICE_TABLE), sorted({(k, a) for _, k, a, _, _ in self.ROWS} |
                                                          {("launchd", "bootout")}))

    def test_every_systemctl_argv_carries_no_ask_password_and_no_pager(self):
        for (kind, action), (kinds, build) in hs.SERVICE_TABLE.items():
            if kind == "systemd":
                with self.subTest(action=action):
                    self.assertEqual(build(["hub-link.service"] * len(kinds))[:2],
                                     ["--no-ask-password", "--no-pager"])

    def test_the_service_path_is_root_trusts(self):
        self.assertEqual(hs.SERVICE_PATH, rt.PATH)


class RefusalRows(Verb):
    def test_an_action_outside_the_table_or_of_the_other_kind_is_refused(self):
        for m, kind, action, args in ((SYSTEMCTL, "systemd", "edit", ["hub-link.service"]),
                                      (SYSTEMCTL, "systemd", "set-environment", ["A=1"]),
                                      (SYSTEMCTL, "systemd", "link", ["/tmp/x.service"]),
                                      (LAUNCHCTL, "launchd", "setenv", ["A", "1"]),
                                      (LAUNCHCTL, "launchd", "submit", ["x"]),
                                      (LAUNCHCTL, "launchd", "config", ["system", "path"]),
                                      (SYSTEMCTL, "systemd", "disable", ["org.example.hub"]),
                                      (LAUNCHCTL, "launchd", "daemon-reload", []),
                                      (LAUNCHCTL, "launchd", "restart", ["hub-link.service"])):
            with self.subTest(kind=kind, action=action):
                self.refused(m, kind, action, *args)

    def test_a_label_outside_its_rule_is_refused(self):
        for label in ("a/b", "-x", "a b", "", "a\nb", ".x"):
            with self.subTest(label=label):
                self.refused(LAUNCHCTL, "launchd", "disable", label)

    def test_a_unit_outside_its_rule_is_refused(self):
        for unit in ("hub-link", "a/b.service", "-x.service", "hub-link.socket", "hub-link.service ", ""):
            with self.subTest(unit=unit):
                self.refused(SYSTEMCTL, "systemd", "enable-now", unit)

    def test_restart_and_reset_failed_never_take_a_timer_and_stop_takes_only_a_service_or_a_timer(self):
        for action in ("restart", "reset-failed"):
            with self.subTest(action=action):
                self.refused(SYSTEMCTL, "systemd", action, "hub-link-probe.timer")
        for unit in ("hub-link.socket", "hub-link.target", "hub-link"):
            with self.subTest(unit=unit):
                self.refused(SYSTEMCTL, "systemd", "stop", unit)

    def test_a_bootstrap_plist_must_be_the_labels_own_in_launchdaemons(self):
        for plist in ("/Library/LaunchDaemons/other.plist", "/Library/LaunchDaemons/sub/org.example.hub.plist",
                      "/Library/LaunchAgents/org.example.hub.plist", "/tmp/org.example.hub.plist",
                      "/Library/LaunchDaemons/../LaunchDaemons/org.example.hub.plist"):
            with self.subTest(plist=plist):
                self.refused(LAUNCHCTL, "launchd", "bootstrap", "org.example.hub", plist)

    def test_the_manager_must_be_the_kinds_by_name_and_absolute(self):
        for m, kind in (("systemctl", "systemd"), (LAUNCHCTL, "systemd"), (SYSTEMCTL, "launchd"),
                        ("/usr/bin/systemctl2", "systemd"), (SYSTEMCTL, "upstart")):
            with self.subTest(m=m, kind=kind):
                self.refused(m, kind, "daemon-reload")

    def test_the_wrong_number_of_arguments_is_refused(self):
        self.refused(SYSTEMCTL, "systemd", "daemon-reload", "hub-link.service")
        self.refused(LAUNCHCTL, "launchd", "bootstrap", "org.example.hub")
        self.refused(SYSTEMCTL, "systemd", "restart")


class JudgeRows(Verb):
    def test_a_manager_judge_refuses_is_untrusted_and_nothing_is_called(self):
        self.patch("judge", lambda *a, **k: hs.Judgment(["/tmp/x/systemctl is the operator's"], "tools"))
        with self.assertRaises(hs.Untrusted):
            self.service(SYSTEMCTL, "systemd", "daemon-reload")
        self.assertEqual(self.calls, [])

    def test_a_same_basename_operator_owned_manager_exits_12_with_nothing_called(self):
        """--also names the recorded manager, --manager an operator-owned file
        of the same name: the writer's own judge refuses it."""
        self.patch("judge", JUDGE)
        self.patch("_bound", lambda argv: None)
        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d, True)
        for name, kind in (("systemctl", "systemd"), ("launchctl", "launchd")):
            with self.subTest(name=name):
                stub = os.path.join(d, name)
                with open(stub, "w") as f:
                    f.write("#!/bin/sh\nexit 0\n")
                os.chmod(stub, 0o755)
                called = []
                self.patch("subprocess", FakeSubprocess(called))
                action = ["daemon-reload"] if kind == "systemd" else ["enable", "org.example.hub"]
                rc = hs.main(["service", "--manager", stub, kind] + action)
                self.assertEqual((rc, called), (hs.ROOT_TRUST_EXIT, []))


JUDGE = hs.judge


class FakeSubprocess:
    """subprocess with run recorded and refused: the rows that reach main()."""
    DEVNULL, PIPE, TimeoutExpired, Popen = subprocess.DEVNULL, subprocess.PIPE, subprocess.TimeoutExpired, None

    def __init__(self, called):
        self.called = called

    def run(self, argv, **kw):
        self.called.append(argv)
        raise AssertionError("the manager was called")


class ExitRows(Verb):
    def test_the_managers_own_status_is_never_passed_through(self):
        for rc in (12, 4, 3, 1, 255):
            with self.subTest(rc=rc):
                self.said.clear()
                self.assertEqual(self.service(SYSTEMCTL, "systemd", "daemon-reload", run=self.runner(Proc(rc))), 1)
                self.assertIn(f"exited {rc}", self.said[-1])
        self.assertEqual(self.service(SYSTEMCTL, "systemd", "daemon-reload", run=self.runner(Proc(0))), 0)

    def test_a_timeout_is_1_and_says_the_job_may_still_be_running(self):
        rc = self.service(SYSTEMCTL, "systemd", "restart", "hub-link.service",
                          run=self.runner(subprocess.TimeoutExpired("systemctl", hs.SERVICE_TIMEOUT_S)))
        self.assertEqual(rc, 1)
        self.assertTrue(self.said, "a timeout says what it means")
        self.assertIn(f"did not finish in {hs.SERVICE_TIMEOUT_S} s; the manager's job may still be running",
                      self.said[-1])

    def test_main_maps_each_refusal_to_its_exit(self):
        self.assertEqual(hs.main(["service", "--manager", SYSTEMCTL, "systemd", "edit", "x.service"]),
                         hs.EXIT_TOOLING)
        self.assertEqual(hs.main(["service", SYSTEMCTL, "systemd", "daemon-reload"]), hs.EXIT_TOOLING)
        self.patch("judge", lambda *a, **k: hs.Judgment(["x"], "closure"))
        self.assertEqual(hs.main(["service", "--manager", SYSTEMCTL, "systemd", "daemon-reload"]), hs.ROOT_TRUST_EXIT)


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


class BootoutRows(Verb):
    def bootout(self, *answers, clock=None):
        clock = clock or Clock()
        return self.service(LAUNCHCTL, "launchd", "bootout", "org.example.hub", run=self.runner(*answers),
                            clock=clock, sleep=clock.sleep), clock

    def prints(self):
        return [argv for argv, _ in self.calls if argv[1] == "print"]

    def test_unmeasured_wording_never_confirms_a_bootout(self):
        self.assertIsNone(hs.LAUNCHD_NOT_FOUND, "the not-found answer is a Mac fact still owed")
        rc, _ = self.bootout(Proc(0), Proc(*NOT_FOUND[:1], err=NOT_FOUND[1].encode()))
        self.assertEqual(rc, 1)
        self.assertIn("bootout could not be confirmed; run the NOT-RUNNING check", self.said[-1])

    def test_a_bootout_in_progress_waits_for_the_measured_not_found_answer(self):
        self.patch("LAUNCHD_NOT_FOUND", NOT_FOUND)
        rc, clock = self.bootout(Proc(hs.BOOTOUT_IN_PROGRESS), Proc(0), Proc(0), Proc(0),
                                 Proc(NOT_FOUND[0], err=NOT_FOUND[1].encode()))
        self.assertEqual(rc, 0)
        self.assertEqual(self.prints(), [[LAUNCHCTL, "print", "system/org.example.hub"]] * 4)
        self.assertEqual(clock.t, 3.0, "polled once a second until gone")

    def test_a_label_already_gone_is_confirmed_by_the_poll(self):
        self.patch("LAUNCHD_NOT_FOUND", NOT_FOUND)
        rc, _ = self.bootout(Proc(3), Proc(NOT_FOUND[0], err=NOT_FOUND[1].encode()))
        self.assertEqual(rc, 0)

    def test_a_failed_bootout_with_the_label_still_loaded_is_1(self):
        self.patch("LAUNCHD_NOT_FOUND", NOT_FOUND)
        rc, _ = self.bootout(Proc(5), Proc(0))
        self.assertEqual(rc, 1)
        self.assertIn("exited 5", self.said[-1])

    def test_another_print_answer_is_unknown_never_success(self):
        self.patch("LAUNCHD_NOT_FOUND", NOT_FOUND)
        for answer in (Proc(NOT_FOUND[0], err=b"could not find service"), Proc(NOT_FOUND[0] + 1, err=NOT_FOUND[1].encode())):
            with self.subTest(err=answer.stderr):
                rc, _ = self.bootout(Proc(0), answer)
                self.assertEqual(rc, 1)

    def test_one_budget_covers_the_bootout_and_the_polling(self):
        """A bootout that takes most of the budget leaves only the rest for
        polling: the total never passes SERVICE_TIMEOUT_S."""
        self.patch("LAUNCHD_NOT_FOUND", NOT_FOUND)
        clock = Clock()
        budgets = []

        def run(argv, **kw):
            budgets.append(kw["timeout"])
            if argv[1] == "bootout":
                clock.t += hs.SERVICE_TIMEOUT_S - 2.5
                return Proc(0)
            return Proc(0)
        rc = hs.service(LAUNCHCTL, "launchd", "bootout", ["org.example.hub"], run=run, out=self.said.append,
                        clock=clock, sleep=clock.sleep)
        self.assertEqual(rc, 1)
        self.assertLessEqual(clock.t, hs.SERVICE_TIMEOUT_S)
        self.assertTrue(all(b <= hs.SERVICE_TIMEOUT_S - (hs.SERVICE_TIMEOUT_S - 2.5) for b in budgets[1:]), budgets)
        self.assertIn("did not finish", self.said[-1])


class PlistRows(Verb):
    """The bootstrap plist on real files: root mapped to this test's uid."""

    def setUp(self):
        super().setUp()
        self.patch("_plist_problem", PLIST)
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.d = os.path.realpath(t.name)
        self.ld = os.path.join(self.d, "LaunchDaemons")
        os.mkdir(self.ld, 0o755)
        self.patch("LAUNCHD_DIR", self.ld)
        self.patch("ROOT_UID", os.getuid())
        self.trusted = set()
        p = "/"
        for part in [x for x in self.ld.split("/") if x]:
            self.trusted.add(self.ident(p))
            p = os.path.join(p, part)
        self.trusted.add(self.ident(self.ld))
        self.patch("_ancestor_ok", lambda st: (st.st_dev, st.st_ino) in self.trusted)
        self.acls = []
        self.patch("acl_problems", lambda paths, platform=None: (self.acls.append(list(paths)),
                                                                   [f"{p} carries an ACL" for p in paths
                                                                    if p in self.acl_on])[1])
        self.acl_on = set()
        self.plist = os.path.join(self.ld, "org.example.hub.plist")
        with open(self.plist, "w") as f:
            f.write("<plist/>\n")
        os.chmod(self.plist, 0o644)

    @staticmethod
    def ident(p):
        st = os.lstat(p)
        return st.st_dev, st.st_ino

    def bootstrap(self):
        return self.service(LAUNCHCTL, "launchd", "bootstrap", "org.example.hub", self.plist)

    def refuses(self):
        with self.assertRaises(hs.Tooling):
            self.bootstrap()
        self.assertEqual(self.calls, [])

    def test_a_root_owned_plist_on_a_root_route_bootstraps(self):
        self.assertEqual(self.bootstrap(), 0)
        self.assertEqual(self.acls[-1][-1], self.plist)
        self.assertEqual(self.acls[-1][0], "/")

    def test_an_operator_owned_plist_is_refused(self):
        self.patch("ROOT_UID", os.getuid() + 1)
        self.patch("_ancestor_ok", lambda st: True)
        self.refuses()

    def test_a_group_writable_plist_is_refused(self):
        os.chmod(self.plist, 0o664)
        self.refuses()

    def test_a_symlinked_plist_is_refused(self):
        real = os.path.join(self.d, "real.plist")
        os.rename(self.plist, real)
        os.symlink(real, self.plist)
        self.refuses()

    def test_a_hard_linked_plist_is_refused(self):
        os.link(self.plist, os.path.join(self.d, "other"))
        self.refuses()

    def test_a_plist_carrying_an_acl_is_refused(self):
        self.acl_on.add(self.plist)
        self.refuses()

    def test_an_acl_on_its_directory_is_refused(self):
        self.acl_on.add(self.ld)
        self.refuses()

    def test_a_plist_under_an_ancestor_others_hold_is_refused(self):
        self.trusted.discard(self.ident(self.ld))
        self.refuses()


PLIST = hs._plist_problem


class SpecRows(unittest.TestCase):
    def test_the_kinds_manager_is_required(self):
        import host_setup as hset
        from test_hub_keys import full_doc as keys_doc
        from test_hub_supervise import supervise
        for kind in ("systemd", "launchd"):
            with self.subTest(kind=kind):
                d = supervise(keys_doc(), kind)
                del d["secrets"]["tools"][hv.MANAGERS[kind]]
                with self.assertRaisesRegex(hset.SpecError, f"secrets.tools.{hv.MANAGERS[kind]}"):
                    hset.load_spec(d)

    def test_a_recorded_launchctl_must_be_the_one_launchd_ships(self):
        import host_setup as hset
        from test_hub_keys import full_doc as keys_doc
        from test_hub_supervise import supervise
        for kind in ("systemd", "launchd"):
            with self.subTest(kind=kind):
                d = supervise(keys_doc(), kind)
                d["secrets"]["tools"]["launchctl"] = "/usr/local/bin/launchctl"
                with self.assertRaisesRegex(hset.SpecError, "launchctl must be /bin/launchctl"):
                    hset.load_spec(d)

    def test_each_launchd_plist_is_exactly_launchdaemons_label_plist(self):
        """F3: dirname equality and the <label>.plist basename, at load."""
        import host_setup as hset
        from test_hub_supervise import sup_section
        for key, other in (("hub", "org.example.hub-probe"), ("weekly", "org.example.hub")):
            sec = sup_section("launchd")[key]
            label = sec["label"]
            for plist in (f"/Library/LaunchDaemons/sub/{label}.plist", f"/Library/LaunchAgents/{label}.plist",
                          f"/Library/LaunchDaemons/{other}.plist"):
                with self.subTest(key=key, plist=plist):
                    with self.assertRaises(hset.SpecError):
                        spec("launchd", **{key: dict(sec, plist=plist)})


class BoundRows(unittest.TestCase):
    def test_the_service_budget_covers_a_planned_restart_and_fails_one_below(self):
        s = spec()
        [c] = hv.verify_service_bound(s)
        self.assertEqual(c.result, rh.PASS)
        self.addCleanup(setattr, hs, "SERVICE_TIMEOUT_S", hs.SERVICE_TIMEOUT_S)
        hs.SERVICE_TIMEOUT_S = hv.SUPERVISOR_STOP_S + hv.RESTART_BARRIER_LINES * hv.BARRIER_S + hv.SERVICE_MARGIN_S - 1
        [c] = hv.verify_service_bound(s)
        self.assertEqual(c.result, rh.FAIL)
        self.assertIn("lower SUPERVISOR_STOP_S", c.do_not)

    def test_verify_runs_the_bound(self):
        import inspect
        self.assertIn("verify_service_bound(spec)", inspect.getsource(hv.checks))


class BindingRows(unittest.TestCase):
    """The walk: every rendered service line's --also is its --manager, one
    recorded value, and stands before `--`."""

    def lines(self, s):
        out = [l for l in hv.plan(s, shlex.quote, "STEPS") if " service --manager " in l and not l.startswith("#")]
        for label in hv.labels(s):
            out += [hv.service_line(s, a, label) for a in ("disable", "bootout")]
        return out

    def test_also_equals_manager_on_every_rendered_service_line(self):
        s = spec("launchd")
        lines = self.lines(s)
        self.assertTrue(lines)
        for line in lines:
            with self.subTest(line=line[-60:]):
                a = shlex.split(line)
                cut = a.index("--")
                also = [a[i + 1] for i in range(cut) if a[i] == "--also"]
                self.assertEqual(also, [a[a.index("--manager") + 1]])
                self.assertEqual(also, [MANAGER["launchd"]])
                self.assertGreater(a.index("--manager"), cut)
                self.assertEqual(a[cut + 1:cut + 6], [s.secrets.tools["python3"], "-I", "-S", "-B", s.secrets.writer])

    def test_the_enablement_remedy_names_the_typed_lines(self):
        s = spec("launchd")
        found = hv.verify_enablement(s, {}, gate=lambda: False, loaded=lambda l: True)
        remedy = found[0].remedy
        self.assertIn(hv.service_line(s, "disable", "org.example.hub-probe"), remedy)
        self.assertIn(hv.service_line(s, "bootout", "org.example.hub-probe"), remedy)


if __name__ == "__main__":
    unittest.main()
