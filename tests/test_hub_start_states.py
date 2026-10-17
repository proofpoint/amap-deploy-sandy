"""hub-start-check's state reading (d3.3 §5(d) §4.3): each unit or label
read on its own, one outcome printed, every start line typed through the
writer's service verb; and its NOT-RUNNING check, with and without the
deployed context (§3.1 U0's old-context read).

The managers and the engine are answered by the rows' own probes, since
the suite never runs systemctl, launchctl or docker. The context rows read
real files with root mapped to this test's uid."""

import hashlib
import json
import os
import shlex
import tempfile
import unittest
from unittest import mock

import host_setup as hs
import hub_supervise as hv
import root_trust as rt
import router_health as rh
from test_hub_runtime import setUpModule, tearDownModule  # noqa: F401 -- the fixture's pins, restored
from test_hub_supervise import spec

IDLE, RUNNING = "\tstate = not running", "\tstate = running"


def actions(lines):
    """Each typed service line's (action, args) after `--manager M kind`; other lines verbatim."""
    out = []
    for l in lines:
        if " service --manager " in l and not l.startswith("#"):
            a = shlex.split(l)
            i = a.index("--manager")
            out.append(tuple(a[i + 3:]))
        else:
            out.append(l)
    return out


class SystemdRestartRows(unittest.TestCase):
    def setUp(self):
        self.s = spec()

    def lines(self, hub):
        return actions(hv.restart_commands(self.s, {"hub": hub, "timer": hv.STOPPED}))

    def test_not_running_gets_the_first_start(self):
        self.assertEqual(self.lines(hv.STOPPED), [("daemon-reload",), ("enable-now", "hub-link-probe.timer"),
                                                  ("enable-now", "hub-link.service")])
        self.assertEqual(hv.restart_commands(self.s, {"hub": hv.STOPPED, "timer": hv.STOPPED}),
                         hv.start_commands(self.s))

    def test_running_is_restarted_after_daemon_reload(self):
        self.assertEqual(self.lines(hv.RUNNING), [("daemon-reload",), ("enable-now", "hub-link-probe.timer"),
                                                  ("restart", "hub-link.service")])

    def test_failed_gets_reset_failed_before_enable_now(self):
        self.assertEqual(self.lines(hv.FAILED), [("daemon-reload",), ("reset-failed", "hub-link.service"),
                                                 ("enable-now", "hub-link-probe.timer"),
                                                 ("enable-now", "hub-link.service")])

    def test_each_is_active_pair_maps_as_the_table_says(self):
        for pair, want in (((0, "active"), hv.RUNNING), ((0, "reloading"), hv.RUNNING), ((3, "inactive"), hv.STOPPED),
                           ((3, "failed"), hv.FAILED)):
            with self.subTest(pair=pair):
                self.assertEqual(hv.active_state(pair), want)
        for pair in ((0, "activating"), (3, "activating")):
            with self.subTest(pair=pair):
                got = hv.active_state(pair)
                self.assertIsInstance(got, rh.Unresolved)
                self.assertIn("a restart loop or a start in progress", got.reason)
        for pair in ((3, "deactivating"), (4, "unknown"), (0, "inactive"), (3, "active"), (1, "failed"), (3, "")):
            with self.subTest(pair=pair):
                self.assertIsInstance(hv.active_state(pair), rh.Unresolved)


class MissingUnitStateRows(unittest.TestCase):
    """E1, the Python half: the measured missing-unit answer is not running."""

    def test_the_exact_tuple_only_and_only_while_measured(self):
        self.assertEqual(hv.active_state((4, "inactive")), hv.STOPPED)
        for pair in ((4, "unknown"), (5, "inactive"), (4, "inactive ")):
            with self.subTest(pair=pair):
                self.assertIsInstance(hv.active_state(pair), rh.Unresolved)
        with mock.patch.object(rt, "SYSTEMD_UNIT_MISSING_ACTIVE", None):
            self.assertIsInstance(hv.active_state((4, "inactive")), rh.Unresolved)

    def test_not_running_with_every_unit_missing(self):
        last = hv.not_running(spec(), old_context=False, active=lambda u: (4, "inactive"), container=lambda sp: False)
        self.assertEqual(last, "NOT-RUNNING")

    def test_a_missing_hub_unit_gets_the_first_start(self):
        s = spec()
        states = hs.unit_states(s, active=lambda u: (4, "inactive"))
        self.assertEqual(hv.restart_commands(s, states), hv.start_commands(s))


class LaunchdRestartRows(unittest.TestCase):
    def setUp(self):
        self.s = spec("launchd")
        self.W, self.H = "org.example.hub-probe", "org.example.hub"
        self.WP, self.HP = f"/Library/LaunchDaemons/{self.W}.plist", f"/Library/LaunchDaemons/{self.H}.plist"

    def lines(self, weekly, hub):
        return actions(hv.restart_commands(self.s, {"weekly": weekly, "hub": hub}))

    def test_both_not_loaded_is_the_first_start(self):
        self.assertEqual(self.lines(hv.NOT_LOADED, hv.NOT_LOADED),
                         [("enable", self.W), ("bootstrap", self.W, self.WP), ("enable", self.H),
                          ("bootstrap", self.H, self.HP)])

    def test_a_loaded_hub_is_booted_out_and_waited_for_before_enable_and_bootstrap(self):
        got = self.lines(hv.NOT_LOADED, hv.LOADED)
        self.assertEqual(got[2], ("bootout", self.H))
        self.assertEqual(got[3], "# Do not go on until this prints NOT-RUNNING:")
        self.assertTrue(got[4].endswith("hub-start-check --until-stopped"), got[4])
        self.assertEqual(got[5:], [("enable", self.H), ("bootstrap", self.H, self.HP)])

    def test_a_loaded_weekly_is_reregistered_and_no_loaded_label_is_bootstrapped_twice(self):
        got = self.lines(hv.LOADED, hv.NOT_LOADED)
        self.assertEqual(got, [("bootout", self.W), ("enable", self.W), ("bootstrap", self.W, self.WP),
                               ("enable", self.H), ("bootstrap", self.H, self.HP)])
        both = self.lines(hv.LOADED, hv.LOADED)
        for label in (self.W, self.H):
            i, j = both.index(("bootout", label)), [k for k, x in enumerate(both) if x[:2] == ("bootstrap", label)]
            self.assertEqual(len(j), 1)
            self.assertLess(i, j[0])

    def test_every_label_is_enabled_before_it_is_bootstrapped(self):
        for got in (actions(hv.start_commands(self.s)), self.lines(hv.LOADED, hv.LOADED)):
            for label in (self.W, self.H):
                with self.subTest(label=label):
                    steps = [x[0] for x in got if isinstance(x, tuple) and x[1] == label]
                    self.assertLess(steps.index("enable"), steps.index("bootstrap"))

    def test_a_weekly_run_in_progress_gets_nothing_for_its_label(self):
        got = self.lines(hv.IN_PROGRESS, hv.NOT_LOADED)
        self.assertFalse([x for x in got if isinstance(x, tuple) and self.W in x])
        self.assertIn("a weekly run is in progress", got[0].lower())

    def test_the_weekly_label_is_read_by_its_measured_lines_only(self):
        for out, measured, want in ((f"x\n{IDLE}\n", True, hv.LOADED), (f"x\n{RUNNING}\n", True, hv.IN_PROGRESS),
                                    (f"x\n{IDLE}\n", False, None), ("x\n\tstate = spawned\n", True, None)):
            with self.subTest(out=out, measured=measured):
                with mock.patch.object(rt, "LAUNCHD_STATE_IDLE", IDLE if measured else None), \
                        mock.patch.object(rt, "LAUNCHD_STATE_RUNNING", RUNNING if measured else None):
                    got = hv.weekly_state((0, out))
                if want is None:
                    self.assertIsInstance(got, rh.Unresolved)
                else:
                    self.assertEqual(got, want)


class NotLoadedRows(unittest.TestCase):
    def test_not_loaded_is_only_the_measured_exact_answer(self):
        nf = (113, 'Could not find service "x" in domain for system')
        with mock.patch.object(rt, "LAUNCHD_NOT_FOUND", None):
            self.assertIsInstance(hv.weekly_state((113, nf[1] + "\n")), rh.Unresolved)
        with mock.patch.object(rt, "LAUNCHD_NOT_FOUND", nf):
            self.assertEqual(hv.weekly_state((113, nf[1] + "\n")), hv.NOT_LOADED)
            for answer in ((113, "Could not find service"), (114, nf[1]), (113, "could not find service, maybe")):
                with self.subTest(answer=answer):
                    self.assertIsInstance(hv.weekly_state(answer), rh.Unresolved)


class AbsenceReaderRows(unittest.TestCase):
    """Every absence reader takes not-loaded only from the measured exact
    answer: None, a mismatched status or text, and blank-line answers under
    each partial measurement are unknown, and unknown never prints
    NOT-RUNNING or a start line."""
    NF = (113, 'Could not find service "org.example.hub" in domain for system')

    def answering(self, answers):
        def run(argv, **k):
            rc, out = answers[argv[-1].split("/", 1)[1]]
            return rh.Proc(tuple(argv), rc, "", out + "\n")
        p = mock.patch.object(hv.rh, "run", run)
        p.start()
        self.addCleanup(p.stop)

    def test_the_old_context_not_running_path(self):
        s = spec("launchd")
        doc = hv.context_doc(s, "f" * 64)
        for nf, answer, want in ((None, self.NF, "unknown: "), (self.NF, (self.NF[0] + 1, self.NF[1]), "unknown: "),
                                 (self.NF, (self.NF[0], "could not find service"), "unknown: "),
                                 (self.NF, self.NF, "NOT-RUNNING")):
            with self.subTest(nf=nf, answer=answer):
                self.answering({"org.example.hub": answer})
                with mock.patch.object(rt, "LAUNCHD_NOT_FOUND", nf):
                    last = hv.not_running(s, old_context=True, context=lambda sp: doc, container=lambda sp: False)
                self.assertTrue(last.startswith(want), last)

    def test_the_start_states(self):
        s = spec("launchd")
        blank = f"x = {{\n\n\tstate = spawned\n}}"
        cases = [({}, {"org.example.hub": self.NF, "org.example.hub-probe": self.NF}),
                 ({"LAUNCHD_NOT_FOUND": self.NF}, {"org.example.hub": (self.NF[0], "could not find service"),
                                                   "org.example.hub-probe": self.NF}),
                 ({"LAUNCHD_NOT_FOUND": self.NF}, {"org.example.hub": self.NF, "org.example.hub-probe": (0, blank)}),
                 ({"LAUNCHD_NOT_FOUND": self.NF, "LAUNCHD_STATE_RUNNING": RUNNING},
                  {"org.example.hub": self.NF, "org.example.hub-probe": (0, blank)}),
                 ({"LAUNCHD_NOT_FOUND": self.NF, "LAUNCHD_STATE_IDLE": IDLE},
                  {"org.example.hub": self.NF, "org.example.hub-probe": (0, blank)})]
        for measured, answers in cases:
            with self.subTest(measured=sorted(measured), answers=answers):
                self.answering(answers)
                with mock.patch.multiple(rt, LAUNCHD_NOT_FOUND=measured.get("LAUNCHD_NOT_FOUND"),
                                         LAUNCHD_STATE_RUNNING=measured.get("LAUNCHD_STATE_RUNNING"),
                                         LAUNCHD_STATE_IDLE=measured.get("LAUNCHD_STATE_IDLE")):
                    self.assertIsInstance(hs.unit_states(s), rh.Unresolved)
        self.answering({"org.example.hub": self.NF, "org.example.hub-probe": self.NF})
        with mock.patch.object(rt, "LAUNCHD_NOT_FOUND", self.NF):
            self.assertEqual(hs.unit_states(s), {"weekly": hv.NOT_LOADED, "hub": hv.NOT_LOADED})


class OutcomeRows(unittest.TestCase):
    """hub_start_check prints exactly one outcome for the states it reads."""

    def run_check(self, kind, **states):
        built = spec(kind)
        patches = [mock.patch.object(hs, "read_spec", lambda *a, **k: None),
                   mock.patch.object(hs, "load_spec", lambda doc: built),
                   mock.patch.object(hs, "start_checks", lambda s, **k: [
                       rh.check("x", rh.Fact("x", True, "a test"), True, "fix")])]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        said = []
        rc = hs.hub_start_check(None, out=said.append, states=states)
        return rc, said

    def test_an_active_hub_prints_daemon_reload_then_restart(self):
        rc, said = self.run_check("systemd", active=lambda u: (0, "active") if u == "hub-link.service" else (3, "inactive"))
        self.assertEqual(rc, 0)
        got = [x for x in actions(s.strip() for s in said) if isinstance(x, tuple)]
        self.assertEqual(got[0], ("daemon-reload",))
        self.assertEqual(got[-1], ("restart", "hub-link.service"))

    def test_an_unknown_state_for_either_prints_no_start_line(self):
        for name, answers in (("hub", {"hub-link.service": (4, "unknown")}),
                              ("timer", {"hub-link-probe.timer": (3, "deactivating")}),
                              ("activating", {"hub-link.service": (0, "activating")})):
            with self.subTest(name=name):
                rc, said = self.run_check("systemd", active=lambda u: answers.get(u, (3, "inactive")))
                self.assertEqual(rc, 1)
                self.assertFalse([l for l in said if " service --manager " in l])
                self.assertTrue(said[-1].startswith("hub-start-check: no start line:"))
        rc, said = self.run_check("systemd", active=lambda u: (0, "activating") if u == "hub-link.service" else (3, "inactive"))
        self.assertIn("a restart loop or a start in progress", said[-1])

    def test_launchd_either_label_unknown_prints_no_start_line(self):
        for loaded, out in ((lambda l: rh.Unresolved("print failed"), (1, "Could not find service")),
                            (lambda l: False, (5, "an I/O error"))):
            with self.subTest(out=out):
                rc, said = self.run_check("launchd", loaded=loaded, print_=lambda l: out)
                self.assertEqual(rc, 1)
                self.assertFalse([l for l in said if " service --manager " in l])

    def test_launchd_hub_not_loaded_with_weekly_loaded(self):
        with mock.patch.object(rt, "LAUNCHD_STATE_IDLE", IDLE):
            rc, said = self.run_check("launchd", loaded=lambda l: False, print_=lambda l: (0, IDLE))
        self.assertEqual(rc, 0)
        got = [x for x in actions(s.strip() for s in said) if isinstance(x, tuple)]
        self.assertEqual([x[0] for x in got], ["bootout", "enable", "bootstrap", "enable", "bootstrap"])


class NotRunningRows(unittest.TestCase):
    def test_systemd_prints_not_running_only_when_every_unit_is_stopped_and_no_container_runs(self):
        s = spec()
        quiet = {"hub-link.service": (3, "inactive"), "hub-link-probe.service": (3, "inactive"),
                 "hub-link-probe.timer": (3, "inactive")}
        for name, over, there, want in (
                ("quiet", {}, False, "NOT-RUNNING"),
                ("failed hub, no container", {"hub-link.service": (3, "failed")}, False, "NOT-RUNNING"),
                ("failed weekly service", {"hub-link-probe.service": (3, "failed")}, False, "NOT-RUNNING"),
                ("failed hub, container running", {"hub-link.service": (3, "failed")}, True, "running container: "),
                ("running hub", {"hub-link.service": (0, "active")}, False, "running: hub-link.service"),
                ("failed timer", {"hub-link-probe.timer": (3, "failed")}, False, "running: hub-link-probe.timer"),
                ("unknown unit", {"hub-link-probe.service": (4, "")}, False, "unknown: hub-link-probe.service"),
                ("engine unread", {}, rh.Unresolved("sudo -n: a password is required"), "unknown: the engine could")):
            with self.subTest(name=name):
                answers = dict(quiet, **over)
                last = hv.not_running(s, old_context=False, active=answers.get, container=lambda sp: there)
                self.assertTrue(last.startswith(want), last)

    def test_launchd_needs_the_label_unloaded_and_no_running_container(self):
        s = spec("launchd")
        for loaded, there, want in ((False, False, "NOT-RUNNING"), (True, False, "running: org.example.hub"),
                                    (False, True, "running container: "), (rh.Unresolved("x"), False, "unknown: "),
                                    (False, rh.Unresolved("no engine"), "unknown: the engine could")):
            with self.subTest(loaded=loaded, there=there):
                last = hv.not_running(s, old_context=False, loaded=lambda l: loaded, container=lambda sp: there)
                self.assertTrue(last.startswith(want), last)

    def test_the_verb_exits_0_only_on_not_running_as_its_last_line(self):
        built = spec()
        with mock.patch.object(hs, "read_spec", lambda *a, **k: None), mock.patch.object(hs, "load_spec", lambda d: built):
            for there, rc_want in ((False, 0), (True, 1)):
                said = []
                rc = hs.hub_start_check(None, out=said.append, until_stopped=True,
                                        states={"active": lambda u: (3, "inactive"), "container": lambda sp: there})
                self.assertEqual((rc, said[-1] == "NOT-RUNNING"), (rc_want, rc_want == 0))

    def test_old_context_reads_the_engine_under_the_contexts_writer_pin(self):
        s = spec()
        old = "e" * 64
        seen = []
        doc = dict(hv.context_doc(s, "f" * 64), writer_sha256=old)
        last = hv.not_running(s, old_context=True, active=lambda u: (3, "inactive"), context=lambda sp: doc,
                              container=lambda sp: seen.append(sp.secrets.writer_sha256) or False)
        self.assertEqual((last, seen), ("NOT-RUNNING", [old]))

    def test_an_unusable_context_is_the_named_stop(self):
        s = spec()
        last = hv.not_running(s, old_context=True, active=lambda u: (3, "inactive"),
                              context=lambda sp: rh.Unresolved("absent"), container=lambda sp: False)
        self.assertEqual(last, f"unknown: {hv.NO_OLD_CONTEXT} (absent)")


class ContextReadRows(unittest.TestCase):
    """read_old_context on real files, root mapped to this test's uid."""

    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.d = os.path.realpath(t.name)
        self.s = spec()
        self.path = hv.context_path(self.s)
        self.files = {}
        self.doc = hv.context_doc(self.s, "f" * 64)
        self.real = os.path.join(self.d, "ctx.json")
        self.place(self.doc)

    def place(self, doc, raw=None, mode=0o444):
        if os.path.exists(self.real):
            os.chmod(self.real, 0o644)
            os.unlink(self.real)
        with open(self.real, "wb") as f:
            f.write(raw if raw is not None else json.dumps(doc).encode())
        os.chmod(self.real, mode)

    def read(self, acl=lambda paths: [], digest=None, leaf_uid=None, leaf_gid=0, read=os.read):
        uid = os.getuid()
        real = os.lstat(self.real)

        class St:
            def __init__(self, **kw):
                self.__dict__.update(kw)

        def lstat(p):
            if p == self.path:
                return St(st_mode=real.st_mode, st_uid=uid if leaf_uid is None else leaf_uid, st_gid=leaf_gid,
                          st_nlink=real.st_nlink, st_dev=real.st_dev, st_ino=real.st_ino)
            return St(st_mode=0o040755, st_uid=uid, st_gid=0, st_nlink=2, st_dev=0, st_ino=0)
        pins = {self.s.secrets.writer: self.doc["writer_sha256"], hv.rt_path(self.s): self.doc["root_trust_sha256"]}
        real_open = os.open
        with mock.patch.object(os, "open", lambda p, *a, **k: real_open(self.real if p == self.path else p, *a, **k)):
            return hv.read_old_context(self.s, lstat=lstat, digest=digest or pins.get, acl=acl, root_uid=uid,
                                       read=read)

    def test_a_good_context_reads(self):
        self.assertEqual(self.read(), self.doc)

    def test_each_departure_is_refused(self):
        for name, kw in (("operator-owned", dict(leaf_uid=os.getuid() + 1)), ("not group 0", dict(leaf_gid=7)),
                         ("an acl", dict(acl=lambda paths: ["it carries an ACL"])),
                         ("other pins", dict(digest=lambda p: "0" * 64))):
            with self.subTest(name=name):
                self.assertIsInstance(self.read(**kw), rh.Unresolved, name)

    def test_short_reads_are_read_to_the_end(self):
        """A short read is not EOF: a document split across chunks reads
        whole, and trailing data after it or a size past the bound refuses."""
        def short(fd, n):
            return os.read(fd, min(n, 5))
        self.assertEqual(self.read(read=short), self.doc)
        self.place(None, json.dumps(self.doc).encode() + b" trailing")
        self.assertIsInstance(self.read(read=short), rh.Unresolved)
        self.place(None, json.dumps(self.doc).encode() + b" " * hv.CONTEXT_MAX)
        self.assertIsInstance(self.read(read=short), rh.Unresolved)

    def test_a_fifo_at_the_context_is_refused_without_a_read(self):
        os.unlink(self.real)
        os.mkfifo(self.real, 0o444)
        uid = os.getuid()
        real = os.lstat(self.real)
        got = hv.read_old_context(self.s, lstat=lambda p: real if p == self.path else type("S", (), dict(
            st_mode=0o040755, st_uid=uid, st_gid=0, st_nlink=2))(), digest=lambda p: None,
            acl=lambda paths: [], root_uid=uid, read=lambda fd, n: self.fail("read a FIFO"))
        self.assertIsInstance(got, rh.Unresolved)

    def test_mode_schema_members_duplicates_and_size_are_strict(self):
        for name, doc, raw, mode in (
                ("0644", self.doc, None, 0o644),
                ("schema", dict(self.doc, schema="amap-deploy.deployed-context/2"), None, 0o444),
                ("extra member", dict(self.doc, extra=1), None, 0o444),
                ("missing member", {k: v for k, v in self.doc.items() if k != "weekly"}, None, 0o444),
                ("duplicate", None, b'{"schema": "a", ' + json.dumps(self.doc).encode()[1:], 0o444),
                ("not utf-8", None, b'{"schema": "\xff"}', 0o444),
                ("too large", None, b" " * (hv.CONTEXT_MAX + 1), 0o444),
                ("another engine", dict(self.doc, engine="unix:///elsewhere.sock"), None, 0o444),
                ("other weekly", dict(self.doc, weekly=list(reversed(self.doc["weekly"]))), None, 0o444),
                ("uppercase pin", dict(self.doc, overlay_sha256="F" * 64), None, 0o444)):
            with self.subTest(name=name):
                self.place(doc, raw, mode)
                self.assertIsInstance(self.read(), rh.Unresolved, name)


if __name__ == "__main__":
    unittest.main()
