"""host_steps.py partition-weekly and partition-provision: the weekly job's
root half, run as a real process over a real temporary tree.

What is real: the writer (host_steps.main, unchanged), its lock, its child
process and the descriptor it passes, the files it reads and writes, and a
unix socket where the engine would be. What stands in: root, by the test's
own uid (ROOT_UID and the ancestor rule, set by a three-line wrapper); the
tool trust rule, which has its own rows below; the bundle's child, a script
that does what each case needs and nothing else; and docker, a script that
keeps each container's running state in a file and records every call."""

import hashlib
import json
import os
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import host_steps as hs

REPO = Path(__file__).resolve().parent.parent
PIN = "a" * 40
TARGET = "c" * 64

#: The bundle's child: reads its plan, does what it says, in order.
CHILD = r'''
import fcntl, json, os, sys, time
args = dict(zip(sys.argv[1::2], sys.argv[2::2]))
run_dir, fd = args["--run-dir"], int(args["--lock-fd"])
plan = json.load(open(PLAN))
ctx = json.load(open(os.path.join(run_dir, "context.json")))
rid, ev = ctx["run_id"], ctx["evidence_dir"]
def note(name, value):
    with open(os.path.join(SIDE, name), "w") as f:
        json.dump(value, f)
a, b = os.fstat(fd), os.stat(os.path.join(os.path.dirname(run_dir), "lock"))
note("child-lock.json", [a.st_dev == b.st_dev and a.st_ino == b.st_ino])
note("child-started.json", True)
def canonical(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()
def place(path, data, mode):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.chmod(tmp, mode)
    os.rename(tmp, path)
for step in plan:
    kind = step[0]
    if kind == "sleep":
        time.sleep(step[1])
    elif kind == "expect":
        place(os.path.join(run_dir, "expect.json"), canonical({"schema": "x", "run_id": rid, "host": ctx["host"],
                                                                "bindings": step[1]}), 0o400)
    elif kind == "evidence":
        doc = {"run_id": rid, "host": ctx["host"], "bindings": step[1],
               "probes": [{"id": p, "verdict": v} for p, v in sorted(step[2].items())]}
        place(os.path.join(ev, "partition-%s.json" % rid), canonical(doc), 0o444)
    elif kind == "detected":
        d = os.path.join(ev, "incident-" + rid)
        os.makedirs(d, exist_ok=True)
        place(os.path.join(d, "detected.json"), canonical({"run_id": rid, "at": "x", "failing": step[1],
                                                           "identity": None, "pending": ["rewrite", "stop"]}), 0o444)
    elif kind == "outcome":
        place(os.path.join(run_dir, "outcome.json"), canonical({"schema": "x", "run_id": rid, "code": step[1],
                                                               "router_seen": step[2], "why": "test"}), 0o400)
    elif kind == "exit":
        note("child-fd-open-at-end.json", fcntl.fcntl(fd, fcntl.F_GETFD) >= 0)
        os._exit(step[1])
note("child-fd-open-at-end.json", fcntl.fcntl(fd, fcntl.F_GETFD) >= 0)
'''

#: docker, as the job asks it: inspect a container's running state, stop it,
#: list and remove a run's labelled containers. State in a file; every call
#: recorded.
DOCKER = r'''#!PYTHON
import json, sys
STATE, LOG = %r, %r
with open(LOG, "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\n")
state = json.load(open(STATE))
a = sys.argv[1:]
if a[:2] == ["inspect", "--type"]:
    cid = a[-1]
    if cid not in state:
        sys.exit(1)
    print("true" if state[cid] else "false")
elif a[0] == "stop":
    if not state.get("_stuck"):
        state[a[-1]] = False
    json.dump(state, open(STATE, "w"))
elif a[0] == "ps":
    pass
'''

#: The writer as root would run it, with root's uid mapped to this test's.
WRAPPER = r'''
import os, sys
sys.path.insert(0, %r)
import host_steps as hs
hs.ROOT_UID = os.getuid()
hs._ancestor_ok = lambda st: True
hs._trusted_tool = lambda p: os.path.realpath(p)
hs.CHILD_TIMEOUT_S = float(os.environ.get("PW_CHILD_TIMEOUT", hs.CHILD_TIMEOUT_S))
sys.exit(hs.main(sys.argv[1:]))
'''


class Host:
    """The temporary host: exec root, bundle, evidence, live config, the
    engine's socket, docker, and the approved document."""

    def __init__(self, root):
        self.root = r = root
        self.exec = f"{r}/exec"
        self.ev = f"{r}/evidence"
        self.side = f"{r}/side"
        self.conf = f"{r}/conf/router.json"
        for d in (self.ev, self.side, f"{r}/conf", f"{r}/bin"):
            os.makedirs(d)
        os.mkdir(self.exec, 0o700)
        os.chmod(self.exec, 0o700)
        with open(self.conf, "w") as f:
            f.write(json.dumps({"state_dir": "/s", "delegation": {"partition_verified": "r0:x"}}, indent=2) + "\n")
        self.sock_path = f"{r}/e.sock"
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.sock_path)
        self.state, self.log = f"{r}/docker-state.json", f"{r}/docker.log"
        self.containers({TARGET: True})
        self.docker = f"{r}/bin/docker"
        with open(self.docker, "w") as f:
            f.write((DOCKER % (self.state, self.log)).replace("#!PYTHON", "#!" + sys.executable))
        os.chmod(self.docker, 0o755)
        self.wrapper = f"{r}/writer.py"
        with open(self.wrapper, "w") as f:
            f.write(WRAPPER % str(REPO))
        self.plan([])
        self.bundle()
        self.document()

    def containers(self, running):
        with open(self.state, "w") as f:
            json.dump(running, f)

    def calls(self):
        try:
            return [json.loads(l) for l in open(self.log)]
        except FileNotFoundError:
            return []

    def plan(self, steps):
        with open(f"{self.root}/plan.json", "w") as f:
            json.dump(steps, f)

    def bundle(self, extra=None, pin=PIN, closure=("partition_weekly.py",)):
        b = f"{self.exec}/bundle"
        if os.path.exists(b):
            os.chmod(b, 0o755)
            for n in os.listdir(b):
                os.chmod(f"{b}/{n}", 0o644)
                os.unlink(f"{b}/{n}")
            os.rmdir(b)
        os.mkdir(b)
        files = {"partition_weekly.py": f"PLAN, SIDE = {self.root + '/plan.json'!r}, {self.side!r}\n" + CHILD,
                 "partition_weekly.closure": "".join(c + "\n" for c in closure), "PIN": pin + "\n"}
        files.update(extra or {})
        for n, data in files.items():
            with open(f"{b}/{n}", "wb") as f:
                f.write(data.encode() if isinstance(data, str) else data)
            os.chmod(f"{b}/{n}", 0o444)
        os.chmod(b, 0o555)

    def document(self, **over):
        sec = {"partition": {"evidence_dir": self.ev, "exec_root": self.exec,
                             "tools": {"python3": sys.executable, "docker": self.docker}},
               "supervision": {"engine": "unix://" + self.sock_path}, "keys": {"local_config": self.conf},
               "secrets": {"clones": {"deploy": {"sha": PIN}}}}
        sec.update(over)
        self.doc = f"{self.root}/doc.json"
        with open(self.doc, "w") as f:
            json.dump({"host_setup": sec}, f)
        self.digest = hashlib.sha256(open(self.doc, "rb").read()).hexdigest()

    def recovery(self, target=TARGET):
        data = json.dumps({"schema": hs.RECOVERY_SCHEMA, "host": "alpha", "at": "x", "evidence_dir": self.ev,
                           "live_config_path": self.conf, "router_container_id": target,
                           "engine": "unix://" + self.sock_path, "docker": self.docker}, sort_keys=True,
                          separators=(",", ":"))
        p = f"{self.exec}/recovery.json"
        with open(p, "w") as f:
            f.write(data)
        os.chmod(p, 0o444)

    def argv(self, digest=None):
        return [sys.executable, "-I", "-S", "-B", self.wrapper, "partition-weekly", "--exec-root", self.exec,
                "--host", "alpha", "--document", self.doc, "--document-sha256", digest or self.digest]

    def run(self, env=None, **kw):
        return subprocess.run(self.argv(**kw), capture_output=True, text=True, timeout=120,
                              env=dict(os.environ, **(env or {})))

    def side_read(self, name):
        try:
            return json.load(open(f"{self.side}/{name}"))
        except FileNotFoundError:
            return None

    def runs(self):
        return sorted(n for n in os.listdir(self.exec) if n.startswith("run-"))


B = {"host_setup": "1" * 64}
FAIL3 = {"P01": "PASS", "P02": "PASS", "P03": "FAIL", "P04": "PASS"}
PASS = {"P01": "PASS", "P02": "PASS", "P03": "PASS", "P04": "PASS"}


class WriterTest(unittest.TestCase):
    def setUp(self):
        t = tempfile.mkdtemp(dir="/tmp", prefix="pw")
        self.addCleanup(self._rm, t)
        self.h = Host(os.path.realpath(t))
        self.addCleanup(self.h.sock.close)

    @staticmethod
    def _rm(t):
        for d, ds, fs in os.walk(t):
            os.chmod(d, 0o755)
        subprocess.run(["rm", "-rf", t])

    def events(self, rid_prefix="incident-"):
        out = []
        for n in os.listdir(self.h.ev):
            if n.startswith(rid_prefix):
                p = f"{self.h.ev}/{n}/events.jsonl"
                if os.path.exists(p):
                    out += [json.loads(l)["event"] for l in open(p)]
        return out

    def delegation(self):
        return "delegation" in json.load(open(self.h.conf))

    # The acceptance witnesses
    def test_a_passing_run_records_its_target_for_recovery_and_removes_its_directory(self):
        self.h.plan([["expect", B], ["evidence", B, PASS], ["outcome", 0, TARGET]])
        p = self.h.run()
        self.assertEqual(p.returncode, hs.EXIT_PASS, p.stdout + p.stderr)
        rec = json.load(open(f"{self.h.exec}/recovery.json"))
        self.assertEqual((rec["router_container_id"], rec["live_config_path"]), (TARGET, self.h.conf))
        self.assertEqual(self.h.runs(), [])
        self.assertEqual([c for c in self.h.calls() if c[0] == "stop"], [])

    def test_the_child_holds_the_runs_own_lock_to_its_end(self):
        self.h.plan([["expect", B], ["evidence", B, PASS], ["outcome", 0, TARGET]])
        self.h.run()
        self.assertEqual(self.h.side_read("child-lock.json"), [True])
        self.assertIs(self.h.side_read("child-fd-open-at-end.json"), True)

    def test_a_child_that_dies_without_a_word_is_a_handoff_and_stops_nothing(self):
        self.h.recovery()
        self.h.plan([["exit", 1]])
        p = self.h.run()
        self.assertEqual(p.returncode, hs.EXIT_HANDOFF, p.stdout + p.stderr)
        self.assertEqual([c for c in self.h.calls() if c[0] == "stop"], [])
        self.assertTrue(self.delegation())

    def test_a_fail_left_without_an_outcome_is_completed_with_its_original_cause(self):
        self.h.recovery()
        self.h.plan([["expect", B], ["evidence", B, FAIL3], ["exit", 9]])
        p = self.h.run()
        self.assertEqual(p.returncode, hs.EXIT_INCIDENT, p.stdout + p.stderr)
        rid = [n for n in os.listdir(self.h.ev) if n.startswith("incident-")][0]
        det = json.load(open(f"{self.h.ev}/{rid}/detected.json"))
        self.assertEqual((det["failing"], det["identity"]), (["P03"], TARGET))
        self.assertEqual(self.events(), ["rewrite_ok", "stop_ok"])
        self.assertFalse(self.delegation())
        self.assertEqual([c[-1] for c in self.h.calls() if c[0] == "stop"], [TARGET])

    def test_a_stop_that_does_not_take_is_never_recorded_as_done(self):
        self.h.recovery()
        self.h.containers({TARGET: True, "_stuck": True})
        self.h.plan([["expect", B], ["evidence", B, FAIL3], ["exit", 9]])
        self.assertEqual(self.h.run().returncode, hs.EXIT_INCIDENT)
        self.assertEqual(self.events(), ["rewrite_ok", "stop_failed"])

    def test_a_target_that_is_not_running_is_never_stopped(self):
        self.h.recovery()
        self.h.containers({TARGET: False})
        self.h.plan([["expect", B], ["evidence", B, FAIL3], ["exit", 9]])
        self.assertEqual(self.h.run().returncode, hs.EXIT_INCIDENT)
        self.assertEqual([c for c in self.h.calls() if c[0] == "stop"], [])
        self.assertIn("stop_not_attempted", self.events())

    def test_a_child_that_outruns_its_bound_is_killed_with_its_group(self):
        self.h.plan([["sleep", 30], ["expect", B]])
        p = self.h.run(env={"PW_CHILD_TIMEOUT": "2"})
        self.assertEqual(p.returncode, hs.EXIT_HANDOFF, p.stdout + p.stderr)
        self.assertIn("outran", p.stdout)
        time.sleep(0.5)
        self.assertIsNone(self.h.side_read("child-fd-open-at-end.json"), "the child never finished")
        self.assertEqual(self.h.runs(), [])

    def test_evidence_under_other_bindings_than_expected_is_never_used(self):
        self.h.recovery()
        self.h.plan([["expect", B], ["evidence", {"host_setup": "2" * 64}, FAIL3], ["exit", 9]])
        p = self.h.run()
        self.assertEqual(p.returncode, hs.EXIT_HANDOFF, p.stdout + p.stderr)
        self.assertEqual([c for c in self.h.calls() if c[0] == "stop"], [])
        self.assertTrue(self.delegation())

    def test_no_expectation_means_no_evidence_of_the_run_is_used(self):
        self.h.recovery()
        self.h.plan([["evidence", B, FAIL3], ["exit", 9]])
        self.assertEqual(self.h.run().returncode, hs.EXIT_HANDOFF)
        self.assertEqual([c for c in self.h.calls() if c[0] == "stop"], [])

    def test_a_null_target_never_stops(self):
        self.h.plan([["expect", B], ["evidence", B, FAIL3], ["exit", 9]])
        p = self.h.run()
        self.assertEqual(p.returncode, hs.EXIT_INCIDENT, p.stdout + p.stderr)
        self.assertEqual([c for c in self.h.calls() if c[0] == "stop"], [])
        self.assertIn("stop_not_attempted", self.events())
        self.assertFalse(self.delegation(), "the rewrite still happens")

    def test_a_crash_after_the_childs_own_record_completes_once_keeping_its_cause(self):
        self.h.recovery()
        self.h.plan([["expect", B], ["evidence", B, FAIL3], ["detected", ["P03"]], ["exit", 9]])
        self.assertEqual(self.h.run().returncode, hs.EXIT_INCIDENT)
        rid = [n for n in os.listdir(self.h.ev) if n.startswith("incident-")][0]
        self.assertEqual(json.load(open(f"{self.h.ev}/{rid}/detected.json"))["failing"], ["P03"])
        self.assertEqual(self.events(), ["rewrite_ok", "stop_ok"])
        self.assertEqual(len([c for c in self.h.calls() if c[0] == "stop"]), 1)

    def test_a_dead_writer_leaves_the_lock_with_its_live_child_and_the_next_holder_decides(self):
        self.h.plan([["sleep", 3], ["expect", B], ["evidence", B, PASS], ["outcome", 0, TARGET]])
        first = subprocess.Popen(self.h.argv(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 30
        while self.h.side_read("child-started.json") is None and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(self.h.side_read("child-started.json"))
        first.send_signal(signal.SIGKILL)
        first.wait()
        second = self.h.run()
        self.assertEqual(second.returncode, hs.EXIT_HANDOFF)
        self.assertIn("another run holds the lock", second.stdout + second.stderr)
        while self.h.side_read("child-fd-open-at-end.json") is None and time.monotonic() < deadline:
            time.sleep(0.05)
        time.sleep(0.3)
        self.assertEqual(len(self.h.runs()), 1, "the dead writer's run is still there, undecided")
        self.h.plan([["expect", B], ["evidence", B, PASS], ["outcome", 0, TARGET]])
        third = self.h.run()
        self.assertEqual(third.returncode, hs.EXIT_PASS, third.stdout + third.stderr)
        self.assertIn("abandoned", third.stdout)
        self.assertEqual(self.h.runs(), [], "decided, then removed")

    def test_an_abandoned_run_that_left_a_fail_is_completed_by_the_next_holder(self):
        self.h.recovery()
        self.h.plan([["expect", B], ["evidence", B, FAIL3], ["sleep", 3], ["outcome", 1, None]])
        first = subprocess.Popen(self.h.argv(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 30
        while self.h.side_read("child-started.json") is None and time.monotonic() < deadline:
            time.sleep(0.05)
        first.send_signal(signal.SIGKILL)
        first.wait()
        while self.h.side_read("child-fd-open-at-end.json") is None and time.monotonic() < deadline:
            time.sleep(0.05)
        time.sleep(0.3)
        self.assertEqual([c for c in self.h.calls() if c[0] == "stop"], [], "the dead writer decided nothing")
        self.h.plan([["expect", B], ["evidence", B, PASS], ["outcome", 0, TARGET]])
        self.h.run()
        self.assertEqual([c[-1] for c in self.h.calls() if c[0] == "stop"], [TARGET])
        self.assertEqual(self.events(), ["rewrite_ok", "stop_ok"])
        self.assertEqual(self.h.runs(), [])

    # The input boundary
    def test_a_document_that_is_not_the_approved_one_runs_nothing(self):
        p = self.h.run(digest="0" * 64)
        self.assertEqual(p.returncode, hs.EXIT_HANDOFF)
        self.assertIsNone(self.h.side_read("child-started.json"))
        self.h.document(supervision={"engine": "unix:///elsewhere.sock"})
        p = subprocess.run(self.h.argv(digest=hashlib.sha256(b"approved earlier").hexdigest()),
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, hs.EXIT_HANDOFF)
        self.assertIsNone(self.h.side_read("child-started.json"))

    def test_a_bundle_at_another_pin_is_a_handoff_and_a_tampered_one_is_tooling(self):
        self.h.bundle(pin="b" * 40)
        self.assertEqual(self.h.run().returncode, hs.EXIT_HANDOFF)
        for extra in ({"stray.py": "x = 1\n"}, {"partition_weekly.py": b"\xff\xfe"}, {"partition_weekly.py": "a\0b"}):
            with self.subTest(extra=list(extra)):
                self.h.bundle(extra=extra)
                p = self.h.run()
                self.assertEqual(p.returncode, hs.EXIT_TOOLING, p.stdout + p.stderr)
                self.assertIsNone(self.h.side_read("child-started.json"))

    def test_tooling_with_a_recovery_description_stops_its_target_and_without_one_stops_nothing(self):
        self.h.bundle(extra={"stray.py": "x = 1\n"})
        self.assertEqual(self.h.run().returncode, hs.EXIT_TOOLING)
        self.assertEqual([c for c in self.h.calls() if c[0] == "stop"], [])
        self.h.recovery()
        self.assertEqual(self.h.run().returncode, hs.EXIT_TOOLING)
        self.assertEqual([c[-1] for c in self.h.calls() if c[0] == "stop"], [TARGET])

    def test_provisioning_swaps_a_verified_bundle_in_under_the_lock_and_refuses_another(self):
        new = f"{self.h.exec}/bundle.new"
        os.mkdir(new)
        for n in ("partition_weekly.py", "partition_weekly.closure", "PIN"):
            src = f"{self.h.exec}/bundle/{n}"
            with open(src, "rb") as f, open(f"{new}/{n}", "wb") as g:
                g.write(f.read())
            os.chmod(f"{new}/{n}", 0o444)
        os.chmod(new, 0o555)
        provision = [sys.executable, "-I", "-S", "-B", self.h.wrapper, "partition-provision", self.h.exec]
        p = subprocess.run(provision, capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(sorted(os.listdir(self.h.exec)), ["bundle", "lock"])
        before = sorted(os.listdir(f"{self.h.exec}/bundle"))
        os.mkdir(new)
        for n, data in (("partition_weekly.py", "x = 1\n"), ("partition_weekly.closure", "partition_weekly.py\n"),
                        ("PIN", PIN + "\n"), ("stray.py", "y = 2\n")):
            with open(f"{new}/{n}", "w") as f:
                f.write(data)
            os.chmod(f"{new}/{n}", 0o444)
        os.chmod(new, 0o555)
        p = subprocess.run(provision, capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, hs.EXIT_TOOLING, p.stdout + p.stderr)
        self.assertEqual(sorted(os.listdir(f"{self.h.exec}/bundle")), before, "the verified bundle stays")
        self.assertIn("stray.py", os.listdir(new), "the refused one is left where it was, for a look")


class ToolTrustTest(unittest.TestCase):
    """The tool rule, on real files, with root mapped to this test's uid."""

    def setUp(self):
        self.addCleanup(setattr, hs, "ROOT_UID", hs.ROOT_UID)
        hs.ROOT_UID = os.getuid()
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.d = os.path.realpath(t.name)

    def tool(self, mode):
        p = f"{self.d}/tool"
        with open(p, "w") as f:
            f.write("#!/bin/sh\n")
        os.chmod(p, mode)
        return p

    def test_a_tool_others_can_write_or_not_executable_is_not_trusted(self):
        self.addCleanup(setattr, hs, "_ancestor_ok", hs._ancestor_ok)
        hs._ancestor_ok = lambda st: True
        for mode in (0o775, 0o757, 0o644):
            with self.subTest(mode=oct(mode)):
                with self.assertRaises(hs.Tooling):
                    hs._trusted_tool(self.tool(mode))
        self.assertEqual(hs._trusted_tool(self.tool(0o755)), f"{self.d}/tool")

    def test_a_tool_under_a_directory_others_can_write_is_not_trusted(self):
        with self.assertRaises(hs.Tooling):
            hs._trusted_tool(self.tool(0o755))


if __name__ == "__main__":
    unittest.main()
