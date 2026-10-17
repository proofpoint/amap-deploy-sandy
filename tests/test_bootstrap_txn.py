"""The bootstrap (d3.3 §5(d) §3): TXN and G, each through its ACTUAL
rendered code, on a staged tree with root mapped to this test's uid.

The walk's top is the staged tree's root, so the host's own / and its
ancestors are not judged. Stubs stand in for sudo (an inert copy-entry
shim that records each call and performs install's copy without the
chown), systemctl, launchctl and the old-context reader; each records
what it was asked, so a row can say a call was NEVER made. Facts a host
has not yet measured are passed in as fixtures where a row needs them,
and every unmeasured answer refuses."""

import hashlib
import json
import os
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest

import root_trust as rt
from test_hub_runtime import setUpModule, tearDownModule  # noqa: F401 -- the fixture's pins, restored

PY = sys.executable
UID = os.getuid()
NOT_FOUND = (113, 'Could not find service "x" in domain for system')
RUNNING_LINE, IDLE_LINE = "\tstate = running", "\tstate = not running"

SUDO = r'''#!{py} -I
import json, os, sys
log, cfg = {log!r}, json.load(open({cfg!r}))
argv = sys.argv[1:]
with open(log, "a") as f:
    f.write(json.dumps(argv) + "\n")
a = argv[argv.index("/usr/bin/install") + 1:]
dest = a[-1]
if dest in cfg.get("fail", []):
    sys.exit(1)
if "-d" in a:
    os.mkdir(dest)
    os.chmod(dest, int(a[a.index("-m") + 1], 8))
    sys.exit(0)
src = cfg.get("grow", {{}}).get(dest)
if src:
    with open(src, "ab") as f:
        f.write(b"#" * (4194304 + 1))
over = cfg.get("overwrite", {{}}).get(dest)
if over:
    with open(over, "r+b") as f:
        f.write(b"X")
moved = cfg.get("replace", {{}}).get(dest)
if moved:
    os.rename(moved, moved + ".old")
    with open(moved, "wb") as f:
        f.write(b"replacement bytes\n")
data = sys.stdin.buffer.read()
tmp = dest + ".shim"
with open(tmp, "wb") as f:
    f.write(data)
os.chmod(tmp, int(a[a.index("-m") + 1], 8))
os.rename(tmp, dest)
'''

MANAGER = r'''#!{py} -I
import json, sys
log, cfg = {log!r}, json.load(open({cfg!r}))
with open(log, "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\n")
args = [a for a in sys.argv[1:] if a != "--no-pager"]
if args[0] == "print":
    rc, out = cfg.get(args[1].split("/", 1)[1], [1, "unanswered"])
    sys.stdout.write(out + "\n")
    sys.exit(rc)
ans = cfg.get(args[1], {{}}).get(args[0], [1, "unanswered"])
sys.stdout.write(ans[1] + "\n")
if len(ans) > 2 and ans[2]:
    sys.stderr.write(ans[2] + "\n")
sys.exit(ans[0])
'''

READER = r'''#!{py} -I
import json, os, sys
log, cfg = {log!r}, json.load(open({cfg!r}))
with open(log, "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\n")
sys.stderr.write(cfg.get("stderr", ""))
sys.stdout.buffer.write(cfg.get("stdout", "NOT-RUNNING\n").encode("latin-1"))
sys.stdout.flush()
if cfg.get("replace_out"):
    out = os.readlink("/proc/self/fd/1")
    os.unlink(out)
    os.mkdir(out) if cfg["replace_out"] == "dir" else os.mkfifo(out)
sys.exit(cfg.get("rc", 0))
'''


def sha(b):
    return hashlib.sha256(b).hexdigest()


class Tree(unittest.TestCase):
    """A staged host: <top>/opt/ex/libexec is the writer's directory, the
    operator's run directory and deploy clone beside it."""
    KIND = "systemd"
    WRITER = b"# the pinned writer\nX = 1\n"
    RT = b"# root-trust.sh as this host renders it\n"

    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.d = os.path.realpath(t.name)
        self.top = os.path.join(self.d, "root")
        for p in ("root", "root/opt", "root/opt/ex"):
            os.mkdir(os.path.join(self.d, p))
            os.chmod(os.path.join(self.d, p), 0o755)
        self.wd = os.path.join(self.top, "opt", "ex", "libexec")
        self.writer, self.rt = os.path.join(self.wd, "host_steps.py"), os.path.join(self.wd, rt.NAME)
        self.context = os.path.join(self.wd, rt.CONTEXT_NAME)
        self.run = os.path.join(self.d, "run")
        self.clone = os.path.join(self.d, "clone")
        self.bin = os.path.join(self.d, "bin")
        for p in (self.run, self.clone, self.bin):
            os.mkdir(p, 0o700)
        self.src = os.path.join(self.clone, "host_steps.py")
        self.rt_src = os.path.join(self.run, "supervise-" + rt.NAME)
        self.write(self.src, self.WRITER)
        self.write(self.rt_src, self.RT)
        self.cfg = {}
        for name, body in (("sudo", SUDO), ("systemctl", MANAGER), ("launchctl", MANAGER), ("reader", READER)):
            self.cfg[name] = {}
            path = os.path.join(self.bin, name)
            self.write(path, body.format(py=PY, log=self.log(name), cfg=self.conf(name)).encode())
            os.chmod(path, 0o755)
        self.amap = os.path.join(self.bin, "reader")
        self.doc = os.path.join(self.d, "doc.json")
        self.write(self.doc, b"{}")
        self.ld = os.path.join(self.top, "Library", "LaunchDaemons")
        os.makedirs(self.ld)
        os.chmod(os.path.join(self.top, "Library"), 0o755)
        os.chmod(self.ld, 0o755)
        self.placed = os.path.join(self.ld, "org.example.hub-probe.plist")
        self.staged = os.path.join(self.run, "supervise-org.example.hub-probe.plist")
        self.measured = {}
        self.root, self.docsource = UID, "spec"
        self.answer_quiescent()

    @staticmethod
    def write(path, data, mode=None):
        if os.path.lexists(path) and not os.path.isdir(path):
            os.unlink(path)
        with open(path, "wb") as f:
            f.write(data)
        if mode is not None:
            os.chmod(path, mode)

    def log(self, name):
        return os.path.join(self.d, f"{name}.log")

    def conf(self, name):
        return os.path.join(self.d, f"{name}.json")

    def save(self):
        for name, c in self.cfg.items():
            with open(self.conf(name), "w") as f:
                json.dump(c, f)

    def calls(self, name):
        try:
            with open(self.log(name)) as f:
                return [json.loads(l) for l in f]
        except FileNotFoundError:
            return []

    def answer_quiescent(self):
        self.cfg["systemctl"] = {"hub-link.service": {"is-active": [3, "inactive"]},
                                 "hub-link-probe.service": {"is-active": [3, "inactive"]},
                                 "hub-link-probe.timer": {"is-active": [3, "inactive"], "is-enabled": [1, "disabled"]}}
        self.cfg["launchctl"] = {"org.example.hub": list(NOT_FOUND), "org.example.hub-probe": list(NOT_FOUND)}

    def installed(self, wd=True, writer=True, rt_=True, context=False, writer_bytes=None, rt_bytes=None):
        """A previous install, as root would have left it (root mapped to this uid)."""
        if wd:
            os.mkdir(self.wd, 0o755)
            os.chmod(self.wd, 0o755)
        if writer:
            self.write(self.writer, self.WRITER if writer_bytes is None else writer_bytes, 0o444)
        if rt_:
            self.write(self.rt, self.RT if rt_bytes is None else rt_bytes, 0o444)
        if context:
            self.write(self.context, b'{"schema": "amap-deploy.deployed-context/1"}\n', 0o444)

    def operands(self, kind=None, **over):
        kind = kind or self.KIND
        names = ["hub-link.service", "hub-link-probe.service", "hub-link-probe.timer"] if kind == "systemd" \
            else ["org.example.hub", "org.example.hub-probe"]
        o = [self.wd, self.writer, self.rt, self.context, sha(self.WRITER), sha(self.RT), "sha256sum", self.src,
             self.rt_src, kind] + names + [PY, self.amap, self.docsource, self.doc]
        if kind == "launchd":
            o += [self.staged, self.placed]
        return o

    def txn(self, kind=None, **kw):
        kind = kind or self.KIND
        args = dict(root=self.root, top=self.top, sudo=os.path.join(self.bin, "sudo"),
                    launchctl=os.path.join(self.bin, "launchctl"), launchd_dir=self.ld, measured=self.measured)
        if kind == "launchd":
            args.update(lsopt="", size=rt.SIZE["systemd"])
        args.update(kw)
        return rt.render_txn(kind, os.path.join(self.bin, "systemctl"), **args)

    def bounded(self, argv, timeout, stdin=None):
        """A shell that blocks (on a FIFO, say) fails its row, never errors it."""
        try:
            return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=stdin)
        except subprocess.TimeoutExpired:
            self.fail(f"blocked for {timeout} s: a read reached a special file")

    def run_txn(self, operands=None, kind=None, timeout=20, stdin=None, **kw):
        self.save()
        argv = rt.OPERATOR_ENV + [self.txn(kind, **kw), "sh"] + (operands or self.operands(kind))
        return self.bounded(argv, timeout, stdin)

    def gate(self, paths=None, writer_pin=None, rt_pin=None, root=None, **kw):
        g = rt.render_gate(self.KIND, root=self.root if root is None else root, **kw)
        dirs = paths if paths is not None else [os.path.join(self.top, "opt"), os.path.join(self.top, "opt", "ex"),
                                                self.wd]
        argv = rt.OPERATOR_ENV + [g, "sh", "sha256sum", writer_pin or sha(self.WRITER), rt_pin or sha(self.RT),
                                  self.writer, self.rt] + dirs
        return self.bounded(argv, 20)

    def ok(self, p, cls):
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(p.stdout.splitlines()[-2:], ["GATE0-OK", f"TXN-OK {cls}"])

    def refused(self, p, words, rc=1):
        self.assertEqual(p.returncode, rc, p.stdout + p.stderr)
        self.assertIn(words, p.stderr)
        self.assertEqual(self.calls("sudo"), [], "no sudo call")
        self.assertNotIn("GATE0-OK", p.stdout)

    def b_lines(self):
        return [c[c.index("/usr/bin/install") + 1:][-1] for c in self.calls("sudo")]


class FreshRows(Tree):
    def test_a_fresh_host_runs_b1_b2_b3_in_order_and_g_then_passes(self):
        p = self.run_txn()
        self.ok(p, "FRESH")
        self.assertEqual(self.b_lines(), [self.wd, self.writer, self.rt])
        for c in self.calls("sudo"):
            self.assertEqual(c[:4], ["/usr/bin/env", "-i", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"])
        self.assertTrue(self.calls("systemctl"), "FRESH runs U0's units arm: its premise is measured")
        g = self.gate()
        self.assertEqual((g.returncode, g.stdout.split()), (0, ["G-ROUTE-OK", "G-BYTES-OK", "BOOTSTRAP-OK"]), g.stderr)

    def test_an_existing_root_only_writer_dir_with_absent_leaves_runs_b2_and_b3_only(self):
        self.installed(writer=False, rt_=False)
        self.ok(self.run_txn(), "FRESH")
        self.assertEqual(self.b_lines(), [self.writer, self.rt])

    def test_the_reader_is_never_called_outside_writer_only(self):
        self.ok(self.run_txn(), "FRESH")
        self.assertEqual(self.calls("reader"), [])

    def test_fresh_with_a_loaded_hub_label_refuses_with_no_sudo(self):
        self.measured = {"LAUNCHD_NOT_FOUND": NOT_FOUND}
        self.cfg["launchctl"]["org.example.hub"] = [0, "system/org.example.hub = {"]
        self.refused(self.run_txn(kind="launchd"), "org.example.hub is loaded")

    def test_fresh_on_launchd_refuses_until_the_not_found_answer_is_measured(self):
        self.assertIsNone(rt.LAUNCHD_NOT_FOUND)
        self.refused(self.run_txn(kind="launchd"), "unknown")
        self.measured = {"LAUNCHD_NOT_FOUND": NOT_FOUND}
        self.ok(self.run_txn(kind="launchd"), "FRESH")


class Gate0Rows(Tree):
    """GATE0 refuses before any mutation: no sudo call, and a sentinel
    destination stays byte- and mode-identical."""

    def sentinel(self):
        s = os.path.join(self.top, "sentinel")
        self.write(s, b"untouched", 0o644)
        return s

    def assertNothing(self, p, words, rc=1):
        s = self.sentinel()
        before = (open(s, "rb").read(), os.stat(s).st_mode)
        self.refused(p, words, rc)
        self.assertEqual((open(s, "rb").read(), os.stat(s).st_mode), before)

    def test_an_ancestor_that_is_a_symlink(self):
        real = os.path.join(self.d, "elsewhere")
        os.rename(os.path.join(self.top, "opt", "ex"), real)
        os.symlink(real, os.path.join(self.top, "opt", "ex"))
        self.assertNothing(self.run_txn(), "is not a directory")

    def test_an_operator_owned_ancestor(self):
        self.root = UID + 1
        self.assertNothing(self.run_txn(), "is not root-owned")

    def test_an_ancestor_others_can_write(self):
        for mode in (0o775, 0o757):
            with self.subTest(mode=oct(mode)):
                os.chmod(os.path.join(self.top, "opt"), mode)
                self.assertNothing(self.run_txn(), "is writable by others")

    def test_an_ancestor_others_cannot_search(self):
        for mode in (0o750, 0o700):
            with self.subTest(mode=oct(mode)):
                os.chmod(os.path.join(self.top, "opt", "ex"), mode)
                self.assertNothing(self.run_txn(), "is not searchable by others")

    def test_a_missing_parent(self):
        shutil.rmtree(os.path.join(self.top, "opt", "ex"))
        self.assertNothing(self.run_txn(), "cannot be read")

    def test_an_existing_writer_dir_others_can_write_or_cannot_search_is_never_adopted(self):
        self.installed(writer=False, rt_=False)
        for mode in (0o775, 0o700):
            with self.subTest(mode=oct(mode)):
                os.chmod(self.wd, mode)
                self.assertNothing(self.run_txn(), "GATE0: " + self.wd)

    def test_a_link_fifo_or_hard_linked_leaf_is_same_3(self):
        cases = {"link": lambda: (os.unlink(self.writer), os.symlink(self.src, self.writer)),
                 "fifo": lambda: (os.unlink(self.rt), os.mkfifo(self.rt)),
                 "two links": lambda: os.link(self.writer, os.path.join(self.top, "second"))}
        for name, how in cases.items():
            with self.subTest(name=name):
                self.installed()
                how()
                self.assertNothing(self.run_txn(), "SAME failed", rc=3)
                shutil.rmtree(self.wd)
                if os.path.exists(os.path.join(self.top, "second")):
                    os.unlink(os.path.join(self.top, "second"))

    def test_an_ls_failure_other_than_absence_refuses(self):
        stub = os.path.join(self.bin, "ls")
        self.write(stub, f"#!/bin/sh\ncase \"$*\" in *-a1*) exit 2 ;; esac\nexec /bin/ls \"$@\"\n".encode(), 0o755)
        self.assertNothing(self.run_txn(ls=stub), "cannot be listed")

    def test_absence_is_the_exact_line_never_a_substring(self):
        self.installed(writer=False, rt_=False)
        self.write(os.path.join(self.wd, "host_steps.py.old"), b"x", 0o444)
        self.write(os.path.join(self.wd, "x" + rt.NAME), b"x", 0o444)
        self.ok(self.run_txn(), "FRESH")

    @unittest.skipUnless(shutil.which("setfacl"), "setfacl is not installed")
    def test_an_acl_on_an_ancestor(self):
        subprocess.run(["setfacl", "-m", f"u:{UID}:rwx", os.path.join(self.top, "opt")], check=True)
        self.assertNothing(self.run_txn(), "carries an ACL")


class ClassRows(Tree):
    def test_writer_only_with_a_quiet_old_hub_copies_the_writer_only(self):
        self.installed(writer_bytes=b"# the old writer\n", context=True)
        p = self.run_txn()
        self.ok(p, "WRITER-ONLY")
        self.assertEqual(self.b_lines(), [self.writer])
        self.assertEqual(len(self.calls("reader")), 1)
        g = self.gate()
        self.assertEqual(g.returncode, 0, g.stderr)

    def test_both_leaves_differing_stops_with_no_sudo(self):
        self.installed(writer_bytes=b"old\n", rt_bytes=b"old rt\n", context=True)
        self.refused(self.run_txn(), "a two-leaf update is not supported yet")

    def test_rt_only_stops_with_no_sudo(self):
        self.installed(rt_bytes=b"old rt\n", context=True)
        self.refused(self.run_txn(), "root-trust.sh's render changed")

    def test_b3_failing_after_b2_leaves_a_partial_pair_the_retry_never_reads_as_fresh(self):
        self.cfg["sudo"] = {"fail": [self.rt]}
        p = self.run_txn()
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("B3 failed", p.stderr)
        os.unlink(self.log("sudo"))
        self.cfg["sudo"] = {}
        self.refused(self.run_txn(), "a partial bootstrap pair: the maintainers' call")

    def test_a_writer_deleted_after_an_install_is_partial(self):
        self.installed(writer=False, context=True)
        p = self.run_txn()
        self.refused(p, "a partial bootstrap pair")
        self.assertIn(f"expected sha256 {sha(self.WRITER)}", p.stderr)
        self.assertIn("The writer: absent", p.stderr)

    def test_an_unchanged_pin_rerun_makes_no_copy_and_no_probe(self):
        self.installed(context=True)
        self.ok(self.run_txn(), "NOTHING")
        self.assertEqual((self.calls("sudo"), self.calls("systemctl"), self.calls("reader")), ([], [], []))

    def test_a_completed_pair_with_no_published_context_is_nothing(self):
        self.installed(context=False)
        self.ok(self.run_txn(), "NOTHING")

    def test_an_unhashable_leaf_is_same_3_never_skipped_never_copied(self):
        if UID == 0:
            self.skipTest("root reads a mode-000 file")
        self.installed()
        os.chmod(self.writer, 0o000)
        self.refused(self.run_txn(), "cannot be hashed", rc=3)

    def test_a_failing_copy_stops_before_g(self):
        self.installed(writer_bytes=b"old\n", context=True)
        self.cfg["sudo"] = {"fail": [self.writer]}
        p = self.run_txn()
        self.assertEqual(p.returncode, 1)
        self.assertIn("B2 failed", p.stderr)
        self.assertNotIn("TXN-OK", p.stdout)


class ReaderRows(Tree):
    """WRITER-ONLY's one old-context read: a fresh directory, the reader's
    stdout captured inside it, exit 0 AND the exact last line."""

    def setUp(self):
        super().setUp()
        self.installed(writer_bytes=b"# the old writer\n", context=True)

    def reader(self, **cfg):
        self.cfg["reader"] = cfg

    def test_the_document_reaches_the_reader_by_its_source_under_env_i(self):
        for source, want in (("spec", ["hub-start-check", "--until-stopped", "--old-context", "--spec", None]),
                             ("overlay", ["--overlay", None, "hub-start-check", "--until-stopped", "--old-context"])):
            for kind in ("systemd", "launchd"):
                with self.subTest(source=source, kind=kind):
                    self.docsource = source
                    self.measured = {"LAUNCHD_NOT_FOUND": NOT_FOUND}
                    for f in (self.log("reader"), self.log("sudo")):
                        if os.path.exists(f):
                            os.unlink(f)
                    self.write(self.writer, b"# the old writer\n", 0o444)
                    if kind == "launchd":
                        self.write(self.staged, b"<plist/>")
                    self.ok(self.run_txn(kind=kind), "WRITER-ONLY")
                    self.assertEqual(self.calls("reader"), [[w if w else self.doc for w in want]])

    def test_an_unknown_document_source_stops(self):
        self.docsource = "environment"
        self.refused(self.run_txn(), "the document source is neither spec nor overlay")

    def test_only_exit_0_and_the_exact_last_line_pass(self):
        for name, cfg, passes in (
                ("trailing LF", {"stdout": "checking\nNOT-RUNNING\n"}, True),
                ("no LF", {"stdout": "NOT-RUNNING"}, True),
                ("non-zero exit", {"stdout": "NOT-RUNNING\n", "rc": 1}, False),
                ("another line", {"stdout": "running: hub-link.service\n", "rc": 0}, False),
                ("CRLF", {"stdout": "NOT-RUNNING\r\n"}, False),
                ("blank final line", {"stdout": "NOT-RUNNING\n\n"}, False),
                ("a line after", {"stdout": "NOT-RUNNING\nlater\n"}, False),
                ("trailing space", {"stdout": "NOT-RUNNING \n"}, False),
                ("empty", {"stdout": ""}, False),
                ("stderr only", {"stdout": "", "stderr": "NOT-RUNNING\n"}, False),
                ("over the bound", {"stdout": "x" * rt.CAPTURE_MAX + "\nNOT-RUNNING\n"}, False),
                ("the named stop", {"stdout": "unknown: no approved old context for the placed writer\n", "rc": 1},
                 False)):
            with self.subTest(name=name):
                for f in (self.log("reader"), self.log("sudo")):
                    if os.path.exists(f):
                        os.unlink(f)
                self.reader(**cfg)
                p = self.run_txn()
                if passes:
                    self.ok(p, "WRITER-ONLY")
                    self.write(self.writer, b"# the old writer\n", 0o444)
                else:
                    self.refused(p, "the old hub is not shown stopped")
                self.assertEqual(len(self.calls("reader")), 1, "called exactly once")

    def test_a_capture_that_is_not_a_regular_file_after_the_run_refuses(self):
        if not os.path.isdir("/proc/self/fd"):
            self.skipTest("the reader stub finds its capture through /proc")
        for how in ("dir", "fifo"):
            with self.subTest(how=how):
                self.reader(replace_out=how)
                self.refused(self.run_txn(), "the old hub is not shown stopped")

    def test_the_capture_directory_is_new_and_made_before_the_reader(self):
        date = os.path.join(self.bin, "date")
        self.write(date, b"#!/bin/sh\necho 20261017T000000Z\n", 0o755)
        planted = os.path.join(self.run, "hsc.20261017T000000Z")
        os.mkfifo(planted)
        p = self.run_txn(date=date)
        self.ok(p, "WRITER-ONLY")
        self.assertTrue(stat.S_ISFIFO(os.lstat(planted).st_mode), "what was there is never used")
        made = os.path.join(self.run, "hsc.20261017T000000Z-1")
        self.assertEqual((stat.S_IMODE(os.stat(made).st_mode), os.listdir(made)), (0o700, ["out"]))

    def test_a_capture_directory_that_cannot_be_made_stops_before_the_reader(self):
        mkdir = os.path.join(self.bin, "mkdir")
        self.write(mkdir, b"#!/bin/sh\nexit 1\n", 0o755)
        self.refused(self.run_txn(mkdir=mkdir), "cannot be made: nothing was read")
        self.assertEqual(self.calls("reader"), [])

    def test_a_running_old_hub_refuses_with_zero_installs(self):
        self.reader(stdout="running: hub-link.service\n", rc=1)
        p = self.run_txn()
        self.refused(p, "running: hub-link.service")


class U0Rows(Tree):
    def test_systemd_quiescence_and_each_unit_asked_on_its_own(self):
        self.ok(self.run_txn(), "FRESH")
        asked = [c for c in self.calls("systemctl")]
        self.assertEqual(asked, [["--no-pager", "is-active", "hub-link.service"],
                                 ["--no-pager", "is-active", "hub-link-probe.service"],
                                 ["--no-pager", "is-active", "hub-link-probe.timer"],
                                 ["--no-pager", "is-enabled", "hub-link-probe.timer"]])

    def test_a_failed_hub_or_weekly_service_is_stopped_and_a_failed_timer_is_not(self):
        self.cfg["systemctl"]["hub-link.service"]["is-active"] = [3, "failed"]
        self.cfg["systemctl"]["hub-link-probe.service"]["is-active"] = [3, "failed"]
        self.ok(self.run_txn(), "FRESH")
        shutil.rmtree(self.wd)
        os.unlink(self.log("sudo"))
        self.cfg["systemctl"]["hub-link-probe.timer"]["is-active"] = [3, "failed"]
        self.refused(self.run_txn(), "unknown")

    def test_running_enabled_and_unknown_answers_each_refuse(self):
        for unit, verb, ans, words in (
                ("hub-link.service", "is-active", [0, "active"], "A running or enabled job holds the old pin"),
                ("hub-link-probe.service", "is-active", [0, "active"], "A running or enabled job"),
                ("hub-link-probe.timer", "is-enabled", [0, "enabled"], "A running or enabled job"),
                ("hub-link-probe.timer", "is-enabled", [0, "static"], "unknown"),
                ("hub-link-probe.timer", "is-enabled", [1, "not-found"], "unknown"),
                ("hub-link.service", "is-active", [4, "inactive"], "unknown"),
                ("hub-link.service", "is-active", [3, "deactivating"], "unknown"),
                ("hub-link.service", "is-active", [3, "activating"], "A running or enabled job")):
            with self.subTest(unit=unit, ans=ans):
                self.answer_quiescent()
                self.cfg["systemctl"][unit][verb] = ans
                p = self.run_txn()
                self.refused(p, words)
                self.assertNotIn("N5" if "unknown" in words else "\0", p.stderr)

    def test_a_masked_timer_and_a_measured_missing_one_pass(self):
        self.cfg["systemctl"]["hub-link-probe.timer"]["is-enabled"] = [1, "masked"]
        self.ok(self.run_txn(), "FRESH")
        shutil.rmtree(self.wd)
        self.cfg["systemctl"]["hub-link-probe.timer"]["is-enabled"] = [4, "", "No such file or directory"]
        self.measured = {"SYSTEMD_TIMER_MISSING": (4, None, "No such file or directory")}
        self.ok(self.run_txn(), "FRESH")

    def test_the_n5_quiescence_modelled_lets_the_retry_pass(self):
        self.cfg["systemctl"]["hub-link-probe.timer"] = {"is-active": [0, "active"], "is-enabled": [0, "enabled"]}
        self.refused(self.run_txn(), "A running or enabled job")
        self.cfg["systemctl"]["hub-link-probe.timer"] = {"is-active": [3, "inactive"], "is-enabled": [0, "enabled"]}
        self.refused(self.run_txn(), "A running or enabled job")
        self.cfg["systemctl"]["hub-link-probe.timer"] = {"is-active": [3, "inactive"], "is-enabled": [1, "disabled"]}
        self.ok(self.run_txn(), "FRESH")


class NothingRows(Tree):
    KIND = "launchd"

    def setUp(self):
        super().setUp()
        self.installed(context=True)
        self.write(self.placed, b"<plist>old</plist>", 0o644)
        self.write(self.staged, b"<plist>new</plist>")
        self.measured = {"LAUNCHD_NOT_FOUND": NOT_FOUND, "LAUNCHD_STATE_RUNNING": RUNNING_LINE,
                         "LAUNCHD_STATE_IDLE": IDLE_LINE}

    def test_a_changed_weekly_plist_with_the_label_idle_runs_only_the_weekly_arm(self):
        self.cfg["launchctl"] = {"org.example.hub-probe": [0, f"system/x = {{\n{IDLE_LINE}\n}}"],
                                 "org.example.hub": [0, "loaded, its container running"]}
        self.ok(self.run_txn(kind="launchd"), "NOTHING")
        self.assertEqual(self.calls("launchctl"), [["print", "system/org.example.hub-probe"]],
                         "no hub arm and no container arm under NOTHING")
        self.assertEqual((self.calls("sudo"), self.calls("reader")), ([], []))

    def test_a_weekly_run_in_progress_refuses_and_names_no_exception(self):
        self.cfg["launchctl"] = {"org.example.hub-probe": [0, f"system/x = {{\n{RUNNING_LINE}\n}}"]}
        p = self.run_txn(kind="launchd")
        self.refused(p, "a weekly run is in progress; re-run after it ends")
        self.assertNotIn("N5", p.stderr)

    def test_unmeasured_or_unknown_wording_refuses(self):
        self.cfg["launchctl"] = {"org.example.hub-probe": [0, "system/x = {\n\tstate = spawned\n}"]}
        self.refused(self.run_txn(kind="launchd"), "unknown")
        self.measured = {}
        self.cfg["launchctl"] = {"org.example.hub-probe": [0, f"system/x = {{\n{IDLE_LINE}\n}}"]}
        self.refused(self.run_txn(kind="launchd"), "unknown")

    def test_an_identical_weekly_plist_probes_nothing(self):
        self.write(self.staged, b"<plist>old</plist>")
        self.ok(self.run_txn(kind="launchd"), "NOTHING")
        self.assertEqual(self.calls("launchctl"), [])

    def test_a_plist_compare_error_stops_with_3_even_under_nothing(self):
        os.unlink(self.staged)
        self.refused(self.run_txn(kind="launchd"), "cannot be compared", rc=3)

    def test_writer_only_with_a_loaded_weekly_label_refuses(self):
        self.write(self.writer, b"# the old writer\n", 0o444)
        self.cfg["launchctl"] = {"org.example.hub": list(NOT_FOUND), "org.example.hub-probe": [0, IDLE_LINE]}
        self.refused(self.run_txn(kind="launchd"), "org.example.hub-probe is loaded")


class MeasuredRows(NothingRows):
    """An unmeasured answer is tested by its presence flag, never by its
    quoted word: an empty word must not read as present, and a blank line
    must not match it."""
    BLANK = "system/x = {\n\n\tstate = spawned\n}"

    def weekly(self, rc, out):
        for f in (self.log("launchctl"), self.log("sudo")):
            if os.path.exists(f):
                os.unlink(f)
        self.cfg["launchctl"] = {"org.example.hub-probe": [rc, out]}
        return self.run_txn(kind="launchd")

    def test_unmeasured_wordings_and_a_blank_line_are_unknown(self):
        self.measured = {"LAUNCHD_NOT_FOUND": NOT_FOUND}
        p = self.weekly(0, self.BLANK)
        self.refused(p, "unknown")
        self.assertNotIn("in progress", p.stderr)

    def test_only_running_measured_never_reads_a_blank_line_as_idle(self):
        self.measured = {"LAUNCHD_NOT_FOUND": NOT_FOUND, "LAUNCHD_STATE_RUNNING": RUNNING_LINE}
        self.refused(self.weekly(0, self.BLANK), "unknown")

    def test_only_idle_measured_never_reads_a_blank_line_as_running(self):
        self.measured = {"LAUNCHD_NOT_FOUND": NOT_FOUND, "LAUNCHD_STATE_IDLE": IDLE_LINE}
        p = self.weekly(0, self.BLANK)
        self.refused(p, "unknown")
        self.assertNotIn("in progress", p.stderr)

    def test_parity_with_weekly_state_on_the_same_answers(self):
        import hub_supervise as hv
        from unittest import mock
        answers = [(0, f"system/x = {{\n{IDLE_LINE}\n}}"), (0, f"system/x = {{\n{RUNNING_LINE}\n}}"),
                   (0, self.BLANK), (0, ""), list(NOT_FOUND), (NOT_FOUND[0], "could not find service"), (5, "")]
        configs = [{}, {"LAUNCHD_NOT_FOUND": NOT_FOUND},
                   {"LAUNCHD_NOT_FOUND": NOT_FOUND, "LAUNCHD_STATE_RUNNING": RUNNING_LINE},
                   {"LAUNCHD_NOT_FOUND": NOT_FOUND, "LAUNCHD_STATE_IDLE": IDLE_LINE},
                   {"LAUNCHD_NOT_FOUND": NOT_FOUND, "LAUNCHD_STATE_RUNNING": RUNNING_LINE,
                    "LAUNCHD_STATE_IDLE": IDLE_LINE}]
        for config in configs:
            for rc, out in answers:
                with self.subTest(config=sorted(config), rc=rc, out=out[:30]):
                    self.measured = config
                    p = self.weekly(rc, out)
                    txn = "ok" if p.returncode == 0 else "in progress" if "in progress" in p.stderr else "unknown"
                    with mock.patch.multiple(rt, LAUNCHD_NOT_FOUND=config.get("LAUNCHD_NOT_FOUND"),
                                             LAUNCHD_STATE_RUNNING=config.get("LAUNCHD_STATE_RUNNING"),
                                             LAUNCHD_STATE_IDLE=config.get("LAUNCHD_STATE_IDLE")):
                        got = hv.weekly_state((rc, out + "\n"))
                    py = "unknown" if isinstance(got, rt_unresolved()) else \
                        "in progress" if got == hv.IN_PROGRESS else "ok"
                    self.assertEqual(txn, py)


def rt_unresolved():
    import router_health as rh
    return rh.Unresolved


class TimerMissingRows(Tree):
    """The missing timer's measured answer with one text unmeasured: an empty
    stdout or stderr never matches the field that was not measured."""

    def test_a_none_field_never_matches_an_empty_answer(self):
        for measured, answer in (((4, None, "No such file or directory"), [4, "", "another error"]),
                                 ((4, None, "No such file or directory"), [4, "", ""]),
                                 ((4, "not-found", None), [4, "", ""])):
            with self.subTest(measured=measured, answer=answer):
                if os.path.exists(self.wd):
                    shutil.rmtree(self.wd)
                if os.path.exists(self.log("sudo")):
                    os.unlink(self.log("sudo"))
                self.measured = {"SYSTEMD_TIMER_MISSING": measured}
                self.cfg["systemctl"]["hub-link-probe.timer"]["is-enabled"] = answer
                self.refused(self.run_txn(), "unknown")

    def test_the_measured_field_still_matches(self):
        self.measured = {"SYSTEMD_TIMER_MISSING": (4, None, "No such file or directory")}
        self.cfg["systemctl"]["hub-link-probe.timer"]["is-enabled"] = [4, "", "No such file or directory"]
        self.ok(self.run_txn(), "FRESH")


class RoleRows(Tree):
    def test_wrong_operand_counts_refuse_before_anything(self):
        o = self.operands("systemd")
        p = self.run_txn(operands=o[:11] + o[12:])
        self.refused(p, "TXN: wrong operand count for systemd")
        self.assertEqual(self.calls("systemctl"), [])
        o = self.operands("launchd")
        self.refused(self.run_txn(operands=o[:-2], kind="launchd"), "wrong operand count for launchd")

    def test_a_same_count_swap_fails_the_role_check(self):
        o = self.operands("systemd")
        o[11], o[12] = o[12], o[11]
        self.refused(self.run_txn(operands=o), "the units are not")
        o = self.operands("systemd")
        o[10], o[11] = o[11], o[10]
        self.assertEqual(o[10].endswith(".service") and o[11].endswith(".service"), True)
        o = self.operands("systemd")
        o[10], o[12] = o[12], o[10]
        self.refused(self.run_txn(operands=o), "the units are not")
        o = self.operands("launchd")
        o[-1], o[-2] = o[-2], o[-1]
        self.refused(self.run_txn(operands=o, kind="launchd"), "the placed weekly plist is not")

    def test_two_launchd_labels_swapped_fail_on_the_placed_plist(self):
        o = self.operands("launchd")
        o[10], o[11] = o[11], o[10]
        self.refused(self.run_txn(operands=o, kind="launchd"), "the placed weekly plist is not")

    def test_the_staged_plist_must_lie_under_the_run_directory_by_component(self):
        for staged in (self.run + "x/supervise-a.plist", os.path.join(self.run, "..", "x.plist"),
                       os.path.join(self.d, "x.plist"), os.path.join(self.run, "a.json")):
            with self.subTest(staged=staged):
                o = self.operands("launchd")
                o[-2] = staged
                self.refused(self.run_txn(operands=o, kind="launchd"), "staged weekly plist")


class SourceRows(Tree):
    """B2's source is opened by the operator's own sh, as install's stdin."""

    def test_a_source_the_operator_cannot_open_never_reaches_sudo(self):
        if UID == 0:
            self.skipTest("root opens a mode-000 file")
        secret = os.path.join(self.d, "secret")
        self.write(secret, b"root only\n", 0o000)
        os.unlink(self.src)
        os.symlink(secret, self.src)
        p = self.run_txn()
        self.assertEqual(p.returncode, 1)
        self.assertEqual(self.b_lines(), [self.wd], "B1 ran; no copy did")
        self.assertFalse(os.path.exists(self.writer))

    def test_a_fifo_with_a_writer_fails_test_f_and_never_reaches_sudo(self):
        os.unlink(self.src)
        os.mkfifo(self.src)
        w = subprocess.Popen(["/bin/sh", "-c", f"exec 3>{shlex.quote(self.src)}; sleep 5"])
        self.addCleanup(w.kill)
        p = self.run_txn()
        self.assertIn("B2 failed", p.stderr)
        self.assertEqual(self.b_lines(), [self.wd])

    def test_a_source_over_the_bound_at_the_check_is_refused_before_sudo(self):
        with open(self.src, "ab") as f:
            f.truncate(rt.SOURCE_MAX + 1)
        p = self.run_txn()
        self.assertIn("B2 failed", p.stderr)
        self.assertEqual(self.b_lines(), [self.wd])

    def test_same_inode_growth_or_overwrite_is_copied_and_g_refuses_it(self):
        for key in ("grow", "overwrite"):
            with self.subTest(key=key):
                self.write(self.src, self.WRITER)
                self.cfg["sudo"] = {key: {self.writer: self.src}}
                self.ok(self.run_txn(), "FRESH")
                g = self.gate()
                self.assertEqual(g.returncode, 1)
                self.assertIn("G-ROUTE-OK", g.stdout)
                self.assertNotIn("G-BYTES-OK", g.stdout)
                shutil.rmtree(self.wd)
                os.unlink(self.log("sudo"))

    def test_the_source_path_replaced_after_the_open_copies_the_original_inode(self):
        self.cfg["sudo"] = {"replace": {self.writer: self.src}}
        self.ok(self.run_txn(), "FRESH")
        with open(self.writer, "rb") as f:
            self.assertEqual(f.read(), self.WRITER)

    def test_the_b_lines_are_literal_and_read_dev_stdin(self):
        t = rt.TXN
        self.assertIn('/usr/bin/install -o 0 -g 0 -m 0444 /dev/stdin "$writer"; } < "$writer_src"', t)
        self.assertIn('/usr/bin/install -o 0 -g 0 -m 0444 /dev/stdin "$rt"; } < "$rt_src"', t)
        self.assertIn('/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C /usr/bin/install -d -o 0 -g 0 '
                      '-m 0755 "$writer_dir"', t)
        self.assertEqual(t.count("@SUDO@"), 3, "exactly three unbarriered root lines")


class GateRows(Tree):
    def setUp(self):
        super().setUp()
        self.installed()

    def assertRefused(self, g, route_ok=False):
        self.assertEqual(g.returncode, 1, g.stdout + g.stderr)
        self.assertNotIn("BOOTSTRAP-OK", g.stdout)
        self.assertEqual("G-ROUTE-OK" in g.stdout, route_ok, g.stdout)

    def test_a_clean_tree_prints_the_three_lines(self):
        g = self.gate()
        self.assertEqual((g.returncode, g.stdout.split()), (0, ["G-ROUTE-OK", "G-BYTES-OK", "BOOTSTRAP-OK"]))

    def test_a_changed_byte_passes_the_route_and_fails_the_bytes(self):
        for leaf in (self.writer, self.rt):
            with self.subTest(leaf=leaf):
                os.chmod(leaf, 0o644)
                with open(leaf, "ab") as f:
                    f.write(b"#")
                os.chmod(leaf, 0o444)
                self.assertRefused(self.gate(), route_ok=True)

    def test_each_route_fault_fails_before_the_bytes(self):
        ex = os.path.join(self.top, "opt", "ex")
        faults = {
            "g+w ancestor": lambda: os.chmod(ex, 0o775),
            "o+w ancestor": lambda: os.chmod(ex, 0o757),
            "symlink ancestor": lambda: (os.rename(ex, ex + ".real"), os.symlink(ex + ".real", ex)),
            "file ancestor": lambda: (shutil.move(ex, ex + ".real"), self.write(ex, b"x", 0o755)),
            "a second link to the writer": lambda: os.link(self.writer, os.path.join(self.top, "w2")),
            "a second link to root-trust.sh": lambda: os.link(self.rt, os.path.join(self.top, "r2")),
            "root-trust.sh a directory": lambda: (os.unlink(self.rt), os.mkdir(self.rt, 0o755)),
            "root-trust.sh a FIFO": lambda: (os.unlink(self.rt), os.mkfifo(self.rt, 0o644)),
            "a missing writer": lambda: os.unlink(self.writer),
            "a writer others can write": lambda: os.chmod(self.writer, 0o666),
        }
        for name, how in faults.items():
            with self.subTest(fault=name):
                how()
                self.assertRefused(self.gate())
                for extra in ("w2", "r2"):
                    if os.path.lexists(os.path.join(self.top, extra)):
                        os.unlink(os.path.join(self.top, extra))
                shutil.rmtree(self.top)
                self.setUp_tree()

    def setUp_tree(self):
        for p in ("root", "root/opt", "root/opt/ex"):
            os.mkdir(os.path.join(self.d, p))
            os.chmod(os.path.join(self.d, p), 0o755)
        os.makedirs(self.ld)
        self.installed()

    def test_an_operator_owned_route_fails(self):
        self.assertRefused(self.gate(root=UID + 1))

    def test_a_mode_000_parent_fails_on_the_read(self):
        if UID == 0:
            self.skipTest("root reads through a mode-000 directory")
        os.chmod(self.wd, 0o000)
        self.addCleanup(os.chmod, self.wd, 0o755)
        self.assertRefused(self.gate())

    def test_a_pin_word_not_64_lowercase_hex_never_passes_the_bytes(self):
        for word in (" ", "a" * 63, "a" * 65, sha(self.WRITER).upper()):
            with self.subTest(word=word[:8]):
                self.assertRefused(self.gate(writer_pin=word), route_ok=True)
                self.assertRefused(self.gate(rt_pin=word), route_ok=True)
        g = rt.render_gate("systemd", root=UID)
        argv = rt.OPERATOR_ENV + [g, "sh", "sha256sum", "", sha(self.RT), self.writer, self.rt,
                                  os.path.join(self.top, "opt"), self.wd]
        p = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        self.assertEqual((p.returncode, "G-BYTES-OK" in p.stdout), (1, False), "an empty pin word")

    def test_g_agrees_with_root_trust_shs_own_judge(self):
        body = rt.render("systemd", self.rt, root=UID, top=self.top)
        cases = {"clean": lambda: None, "o+w": lambda: os.chmod(self.wd, 0o757),
                 "operator writable writer": lambda: os.chmod(self.writer, 0o664)}
        for name, how in cases.items():
            with self.subTest(case=name):
                how()
                g = self.gate().returncode == 0
                ok = all(subprocess.run(["/bin/sh", "-c", body + '\n_rt_judge "$1"', "sh", p],
                                        capture_output=True).returncode == 0
                         for p in (os.path.join(self.top, "opt"), os.path.join(self.top, "opt", "ex"), self.wd,
                                   self.writer, self.rt))
                self.assertEqual(g, ok)
                os.chmod(self.wd, 0o755)
                os.chmod(self.writer, 0o444)

    @unittest.skipUnless(shutil.which("setfacl"), "setfacl is not installed")
    def test_an_acl_fails_on_the_writer_rt_or_an_ancestor_even_granting_what_mode_denies(self):
        for p in (self.writer, self.rt, os.path.join(self.top, "opt")):
            with self.subTest(p=p):
                subprocess.run(["setfacl", "-m", "u:65534:rwx", p], check=True)
                self.assertRefused(self.gate())
                subprocess.run(["setfacl", "-b", p], check=True)


class AclStubRows(Tree):
    """G's and GATE0's ACL refusal on any host: a stub for the listing tool
    they call reports a recorded ACL for one path, in each form the rule
    reads (Linux: `+` after the mode; macOS `ls -le`: an entry line), and
    passes every other listing through unchanged."""
    FORMS = {"plus": "sed '1s/^\\(..........\\)./\\1+/'",
             "entry": "sed '1a\\\n 0: user:nobody allow write'"}

    def stub(self, target, form):
        ls = os.path.join(self.bin, f"ls-{form}")
        self.write(ls, (f"#!/bin/sh\nlast=\nfor a in \"$@\"; do last=$a; done\n"
                        f"if [ \"$last\" = {shlex.quote(target)} ] && [ \"$1\" != -a1 ]; then\n"
                        f"  /bin/ls \"$@\" | {self.FORMS[form]}\nelse\n  exec /bin/ls \"$@\"\nfi\n").encode(), 0o755)
        return ls

    def test_g_refuses_a_recorded_acl_in_either_form_and_passes_without_one(self):
        self.installed()
        clean = self.gate(ls=self.stub("/nonexistent", "plus"))
        self.assertEqual(clean.returncode, 0, clean.stderr)
        for target in (self.writer, self.rt, os.path.join(self.top, "opt")):
            for form in self.FORMS:
                with self.subTest(target=target, form=form):
                    g = self.gate(ls=self.stub(target, form))
                    self.assertEqual(g.returncode, 1, g.stdout + g.stderr)
                    self.assertIn("carries an ACL", g.stderr)
                    self.assertNotIn("BOOTSTRAP-OK", g.stdout)

    def test_gate0_refuses_a_recorded_acl_on_an_ancestor_or_a_leaf(self):
        for target, rc in ((os.path.join(self.top, "opt"), 1), (self.writer, 3)):
            for form in self.FORMS:
                with self.subTest(target=target, form=form):
                    if os.path.exists(self.wd):
                        shutil.rmtree(self.wd)
                    if os.path.exists(self.log("sudo")):
                        os.unlink(self.log("sudo"))
                    self.installed()
                    p = self.run_txn(ls=self.stub(target, form))
                    self.assertEqual(p.returncode, rc, p.stdout + p.stderr)
                    self.assertIn("carries an ACL", p.stderr)
                    self.assertEqual(self.calls("sudo"), [])


class RenderRows(unittest.TestCase):
    """The plan's bootstrap: its order, its values, its operands."""

    def plan(self, kind="systemd", partition=True):
        import host_setup as hs
        from test_hub_supervise import supervise
        from test_partition_setup import doc
        from test_hub_keys import full_doc as keys_doc
        d = supervise(doc() if partition else keys_doc(), kind)
        if kind == "launchd" and partition:
            import partition_setup as ps
            d["partition"]["tools"].update({"git": ps.CLT_GIT, "git-remote-https": ps.CLT_GIT_REMOTE_HTTPS})
        spec = hs.load_spec(d)
        return spec, hs.render_plan(spec, document=("spec", "/srv/op/host-setup.json"))

    def code(self, lines):
        return [l for l in lines if l and not l.startswith("#")]

    def test_step_1_then_txn_then_g_then_partition_judge_first_among_the_barrier_lines(self):
        for kind in ("systemd", "launchd"):
            with self.subTest(kind=kind):
                spec, lines = self.plan(kind)
                code = self.code(lines)
                env = " ".join(rt.OPERATOR_ENV)
                self.assertTrue(code[0].endswith(shlex.quote(spec.secrets.clones["deploy"]["path"] + "/host_steps.py")))
                self.assertTrue(code[1].startswith(env) and " TXN-OK " not in code[1] and "GATE0" in code[1])
                self.assertTrue(code[2].startswith(env) and "G-ROUTE-OK" in code[2])
                self.assertIn(" partition-judge ", code[3])
                step0 = next(i for i, l in enumerate(lines) if l.startswith("# 0. As the operator"))
                self.assertLess(step0, lines.index(code[0]))

    def test_the_txn_line_carries_exactly_its_operands(self):
        import hub_supervise as hv
        for kind, count in (("systemd", 17), ("launchd", 18)):
            with self.subTest(kind=kind):
                spec, lines = self.plan(kind)
                s, sup = spec.secrets, spec.supervision
                argv = shlex.split(self.code(lines)[1])
                n = len(rt.OPERATOR_ENV)
                self.assertEqual(argv[:n], rt.OPERATOR_ENV)
                self.assertEqual(argv[n], rt.render_txn(kind, s.tools.get("systemctl", "/usr/bin/systemctl")))
                ops = argv[n + 2:]
                self.assertEqual(len(ops), count)
                clone = s.clones["deploy"]["path"]
                names = [os.path.basename(sup.hub["unit"]), os.path.basename(sup.weekly["service"]),
                         os.path.basename(sup.weekly["timer"])] if kind == "systemd" else \
                    [sup.hub["label"], sup.weekly["label"]]
                want = [s.writer_dir, s.writer, hv.rt_path(spec), os.path.join(s.writer_dir, rt.CONTEXT_NAME),
                        s.writer_sha256, hv.rt_sha256(spec), rt.HASHWORD[kind], clone + "/host_steps.py",
                        os.path.join(s.run_dir, "supervise-" + rt.NAME), kind] + names + \
                    [s.tools["python3"], clone + "/amap-sandy.py", "spec", "/srv/op/host-setup.json"]
                if kind == "launchd":
                    want += [os.path.join(s.run_dir, hv.staged(sup.weekly["plist"])), sup.weekly["plist"]]
                self.assertEqual(ops, want)

    def test_g_names_the_pins_and_every_ancestor_of_the_writers_directory(self):
        import hub_supervise as hv
        spec, lines = self.plan()
        argv = shlex.split(self.code(lines)[2])
        n = len(rt.OPERATOR_ENV)
        s = spec.secrets
        self.assertEqual(argv[n], rt.render_gate("systemd"))
        self.assertEqual(argv[n + 2:n + 7], ["sha256sum", s.writer_sha256, hv.rt_sha256(spec), s.writer,
                                             hv.rt_path(spec)])
        self.assertEqual(argv[n + 7:], ["/", "/opt", "/opt/ex", "/opt/ex/libexec"])
        self.assertEqual(hv.rt_sha256(spec), sha(dict(hv.rendered(spec))[hv.rt_path(spec)]))

    def test_every_root_line_is_txn_or_a_typed_line(self):
        """The walk: a line naming sudo is the TXN line or the §3 grammar; a
        typed line has no -n and no shell after `--`; no bare python3,
        install, launchctl or systemctl after sudo; the clone's host_steps.py
        only in step 1 and TXN."""
        for kind in ("systemd", "launchd"):
            with self.subTest(kind=kind):
                spec, lines = self.plan(kind)
                code = self.code(lines)
                clone_writer = spec.secrets.clones["deploy"]["path"] + "/host_steps.py"
                for i, l in enumerate(code):
                    if clone_writer in l:
                        self.assertIn(i, (0, 1), l[:80])
                    if l.startswith("python3 "):
                        self.fail(f"a bare python3 line: {l[:80]}")
                    if "sudo" not in l or i == 1:
                        continue
                    argv = shlex.split(l, comments=True)
                    if argv[0] != rt.SUDO:
                        continue
                    self.assertNotEqual(argv[1], "-n", l[:80])
                    self.assertEqual(argv[1:1 + len(rt.anchor())], rt.anchor(), l[:80])
                    after = argv[argv.index("--") + 1:]
                    self.assertNotIn(after[0], ("/bin/sh", "sh", "bash", "install", "launchctl", "systemctl",
                                                "python3"), l[:80])

    def test_the_context_is_published_last_with_the_staged_bytes_digest(self):
        import hub_supervise as hv
        import host_setup as hs
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        doc_path = os.path.join(d, "host-setup.json")
        with open(doc_path, "w") as f:
            f.write("{}")
        spec, _ = self.plan()
        lines = hs.render_plan(spec, document=("spec", doc_path))
        place = [l for l in self.code(lines) if hv.context_path(spec) in l and " place " in l]
        self.assertEqual(len(place), 1)
        self.assertEqual(self.code(lines)[-1], place[0])
        digest = sha(hv.context_bytes(spec, sha(b"{}")))
        self.assertTrue(place[0].endswith(f"--sha256 {digest}"))
        doc = json.loads(hv.context_bytes(spec, "f" * 64))
        self.assertEqual(sorted(doc), ["engine", "host", "hub", "hub_container", "overlay_sha256",
                                       "root_trust_sha256", "schema", "weekly", "writer_sha256"])
        self.assertEqual((doc["schema"], doc["weekly"]), (hv.CONTEXT_SCHEMA, ["hub-link-probe.service",
                                                                               "hub-link-probe.timer"]))

    def test_a_document_missing_either_section_prints_no_runnable_root_line(self):
        import host_setup as hs
        import secret_setup as ss
        from test_partition_setup import doc
        spec = hs.load_spec(doc())
        self.assertIsNone(spec.supervision)
        lines = hs.render_plan(spec)
        self.assertFalse([l for l in lines if "sudo" in l])
        self.assertTrue([l for l in lines if l.startswith(ss.NO_BARRIER)])


if __name__ == "__main__":
    unittest.main()
