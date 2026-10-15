"""host_steps.py partition-weekly and partition-provision: the weekly job's
root half, run as a real process over a real temporary tree.

What is real: the writer (host_steps.main, unchanged), its lock, its child
process and the descriptor it passes, the files it reads and writes, and a
unix socket where the engine would be. What stands in: root, by the test's
own uid (ROOT_UID and the ancestor rule, set by a three-line wrapper); the
tool trust rule and the startup closure's discovery, which have their own
rows below; the bundle's child, a script that does what each case needs and
nothing else, writing records by their real grammars and evidence through
partition_evidence.build; and docker, a script that keeps each container's
state in a file, answers as the engine does (or fails as it can), and
records every call with the path it was run as."""

import hashlib
import json
import types
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
import partition_evidence as pe
import partition_incident as pi
import partition_run as pr

REPO = Path(__file__).resolve().parent.parent
PIN = "a" * 40
TARGET = "c" * 64

#: The bundle's child: reads its plan, does what it says, in order.
CHILD = r'''
import fcntl, json, os, sys, time
sys.path.insert(0, REPO)
import partition_evidence as pe
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
canonical = pe.canonical
def probe(pid, verdict, name):
    roles = {"P03": ["key:signing", "key:dir"], "P04": ["peer:alpha"]}.get(pid, ["mount:/x"])
    ok = verdict == "PASS" and pid in ("P03", "P04")
    return {"id": pid, "vantage": [{"container": name, "image": "i", "uid": 0, "gids": []}], "operation": "read",
            "target_role": roles, "outcome": "ENOENT" if ok else "ok", "witness": {"operation": "w", "outcome": "ok"},
            "verdict": verdict}
def evidence(bindings, verdicts, variant):
    at = "2000-01-01T00:00:00Z" if variant == "early" else ctx["started_at"]
    name = "rout\u00e9r" if variant == "nonascii" else "router"
    raw = pe.build(host=ctx["host"], run_id=rid, at=at, script_sha256={"partition_weekly.py": "0" * 64},
                   bindings=bindings, probes=[probe(p, v, name) for p, v in sorted(verdicts.items())])
    if variant == "spaced":
        raw = json.dumps(json.loads(raw), sort_keys=True).encode()
    if variant == "short":
        d = json.loads(raw)
        del d["fail_stop"]
        raw = canonical(d)
    if variant == "badprobe":
        d = json.loads(raw)
        d["probes"][2]["outcome"] = "bad outcome"
        raw = canonical(d)
    return raw
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
        schema = step[2] if len(step) > 2 else "amap-deploy.partition-expect/1"
        place(os.path.join(run_dir, "expect.json"), canonical({"schema": schema, "run_id": rid, "host": ctx["host"],
                                                                "bindings": step[1]}), 0o400)
    elif kind == "evidence":
        place(os.path.join(ev, "partition-%s.json" % rid),
              evidence(step[1], step[2], step[4] if len(step) > 4 else None), step[3] if len(step) > 3 else 0o444)
    elif kind == "events":
        d = os.path.join(ev, "incident-" + rid)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "events.jsonl"), "a") as f:
            f.write(step[1])
    elif kind == "stop":
        import subprocess
        subprocess.run([ctx["docker"], "stop", "-t", "1", ctx["router_container_id"]])
    elif kind == "detected":
        d = os.path.join(ev, "incident-" + rid)
        os.makedirs(d, exist_ok=True)
        place(os.path.join(d, "detected.json"), canonical({"run_id": rid, "at": "x", "failing": step[1],
                                                           "identity": None, "pending": ["rewrite", "stop"]})
              if step[1] else b"{not json", 0o444)
    elif kind == "outcome":
        schema = step[3] if len(step) > 3 else "amap-deploy.partition-outcome/1"
        place(os.path.join(run_dir, "outcome.json"), canonical({"schema": schema, "run_id": rid, "code": step[1],
                                                               "incident": step[1] == 1, "router_seen": step[2],
                                                               "why": "test"}), 0o400)
    elif kind == "exit":
        note("child-fd-open-at-end.json", fcntl.fcntl(fd, fcntl.F_GETFD) >= 0)
        os._exit(step[1])
note("child-fd-open-at-end.json", fcntl.fcntl(fd, fcntl.F_GETFD) >= 0)
'''

#: docker, as the job asks it: inspect a container's state, confirm by id
#: that no such container exists, stop it, list and remove a run's labelled
#: containers. State in a file: a container is True/False (running or not),
#: "paused", or "badstate" (an inspect stating no bool); "_inspect_fail" and
#: "_ps_fail" make those calls fail, "_stuck" a stop not take. Every call is
#: recorded, last with the path docker was run as.
DOCKER = r'''#!PYTHON
import json, sys
STATE, LOG = %r, %r
with open(LOG, "a") as f:
    f.write(json.dumps(sys.argv[1:] + [sys.argv[0]]) + "\n")
state = json.load(open(STATE))
a = sys.argv[1:]
if a[:2] == ["inspect", "--type"]:
    cid = a[-1]
    if cid not in state or state.get("_inspect_fail"):
        sys.exit(1)
    v = state[cid]
    print(json.dumps({"Running": "yes"} if v == "badstate" else
                     {"Running": False, "Paused": True} if v == "paused" else {"Running": v}))
elif a[0] == "stop":
    if not state.get("_stuck"):
        state[a[-1]] = False
    json.dump(state, open(STATE, "w"))
elif a[0] == "ps":
    if state.get("_ps_fail"):
        sys.exit(1)
    f = [x for x in a if x.startswith("id=")]
    if f and f[0][3:] in state:
        print(f[0][3:])
'''

#: The writer as root would run it, with root's uid mapped to this test's.
WRAPPER = r'''
import os, sys
import json
sys.path.insert(0, %r)
import host_steps as hs
hs.ROOT_UID, hs.ROOT_GID = os.getuid(), os.getgid()
hs.startup_closure = lambda python, docker: json.loads(os.environ.get("PW_CLOSURE", "[]"))
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
        os.chmod(self.ev, 0o755)
        os.chmod(f"{r}/conf", 0o755)
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
        self.docker_link = f"{r}/bin/docker-link"
        os.symlink(self.docker, self.docker_link)
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
        """Each docker call's arguments."""
        return [c[:-1] for c in self.logged()]

    def logged(self):
        try:
            with open(self.log) as f:
                return [json.loads(l) for l in f]
        except FileNotFoundError:
            return []

    def stops(self):
        return [c[-1] for c in self.calls() if c[0] == "stop"]

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
        files = {"partition_weekly.py": f"PLAN, SIDE, REPO = {self.root + '/plan.json'!r}, {self.side!r}, "
                                        f"{str(REPO)!r}\n" + CHILD,
                 "partition_weekly.closure": "".join(c + "\n" for c in closure), "PIN": pin + "\n"}
        files.update(extra or {})
        for n, data in files.items():
            with open(f"{b}/{n}", "wb") as f:
                f.write(data.encode() if isinstance(data, str) else data)
            os.chmod(f"{b}/{n}", 0o444)
        os.chmod(b, 0o555)

    def document(self, **over):
        sec = {"partition": {"evidence_dir": self.ev, "exec_root": self.exec,
                             "tools": {"python3": sys.executable, "docker": self.docker_link}},
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
        if os.path.exists(p):
            os.unlink(p)
        with open(p, "w") as f:
            f.write(data)
        os.chmod(p, 0o444)

    def abandoned(self, rid, verdicts=None, target=TARGET, engine=None, docker=None, expect=True):
        """A run a dead writer and child left: its records as they wrote
        them, started a minute ago, and its evidence if `verdicts`."""
        run = f"{self.exec}/run-{rid}"
        os.mkdir(run, 0o700)
        at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 60))
        records = {"context.json": {"schema": pr.CONTEXT_SCHEMA, "run_id": rid, "host": "alpha", "started_at": at,
                                    "evidence_dir": self.ev, "live_config_path": self.conf,
                                    "router_container_id": target, "engine": engine or "unix://" + self.sock_path,
                                    "docker": docker or self.docker}}
        if expect:
            records["expect.json"] = {"schema": pr.EXPECT_SCHEMA, "run_id": rid, "host": "alpha", "bindings": B}
        for n, doc in records.items():
            with open(f"{run}/{n}", "wb") as f:
                f.write(pe.canonical(doc))
            os.chmod(f"{run}/{n}", 0o400)
        if verdicts:
            raw = pe.build(host="alpha", run_id=rid, at=at, script_sha256={"partition_weekly.py": "0" * 64},
                           bindings=B, probes=[probe(p, v) for p, v in sorted(verdicts.items())])
            with open(f"{self.ev}/partition-{rid}.json", "wb") as f:
                f.write(raw)
            os.chmod(f"{self.ev}/partition-{rid}.json", 0o444)

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


def probe(pid, verdict, name="router"):
    """One probe entry by the evidence grammar, as the child's script builds it."""
    roles = {"P03": ["key:signing", "key:dir"], "P04": ["peer:alpha"]}.get(pid, ["mount:/x"])
    ok = verdict == "PASS" and pid in ("P03", "P04")
    return {"id": pid, "vantage": [{"container": name, "image": "i", "uid": 0, "gids": []}], "operation": "read",
            "target_role": roles, "outcome": "ENOENT" if ok else "ok", "witness": {"operation": "w", "outcome": "ok"},
            "verdict": verdict}


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

    def event_records(self):
        out = []
        for n in sorted(os.listdir(self.h.ev)):
            p = f"{self.h.ev}/{n}/events.jsonl"
            if n.startswith("incident-") and os.path.exists(p):
                with open(p) as f:
                    out += [json.loads(l) for l in f]
        return out

    def delegation(self):
        return "delegation" in json.load(open(self.h.conf))

    # The acceptance witnesses
    def test_a_passing_run_records_its_target_for_recovery_and_removes_its_directory(self):
        self.h.plan([["expect", B], ["evidence", B, PASS], ["outcome", 0, TARGET]])
        p = self.h.run()
        self.assertEqual(p.returncode, hs.EXIT_PASS, p.stdout + p.stderr)
        self.assertTrue(os.path.exists(f"{self.h.exec}/recovery.json"), "a passing run records its target")
        rec = json.load(open(f"{self.h.exec}/recovery.json"))
        self.assertEqual((rec["router_container_id"], rec["live_config_path"]), (TARGET, self.h.conf))
        self.assertEqual(self.h.runs(), [])
        self.assertEqual(self.h.stops(), [])

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
        self.assertEqual(self.h.stops(), [])
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
        self.assertEqual(self.h.stops(), [TARGET])

    def test_a_stop_that_does_not_take_is_never_recorded_as_done(self):
        self.h.recovery()
        self.h.containers({TARGET: True, "_stuck": True})
        self.h.plan([["expect", B], ["evidence", B, FAIL3], ["exit", 9]])
        self.assertEqual(self.h.run().returncode, hs.EXIT_INCIDENT)
        self.assertEqual(self.events(), ["rewrite_ok", "stop_failed"])

    def test_a_target_the_engine_affirms_is_not_running_is_never_stopped_and_counts_as_stopped(self):
        self.h.recovery()
        for state in ({TARGET: False}, {}):
            with self.subTest(state=state):
                self.h.containers(state)
                self.h.plan([["expect", B], ["evidence", B, FAIL3], ["exit", 9]])
                self.assertEqual(self.h.run().returncode, hs.EXIT_INCIDENT)
                self.assertEqual(self.h.stops(), [])
                self.assertEqual(self.event_records()[-1]["event"], "stop_ok")
                self.assertIn("observed", self.event_records()[-1])
                self.assertEqual(self.h.runs(), [], "every effect is shown done")
                time.sleep(1.1)  # the next run's id is the next second

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
        self.assertEqual(self.h.stops(), [])
        self.assertTrue(self.delegation())

    def test_evidence_not_placed_as_root_places_it_is_never_used(self):
        self.h.recovery()
        self.h.plan([["expect", B], ["evidence", B, FAIL3, 0o644], ["exit", 9]])
        self.assertEqual(self.h.run().returncode, hs.EXIT_HANDOFF)
        self.assertEqual(self.h.stops(), [])
        self.assertTrue(self.delegation())

    def test_no_expectation_means_no_evidence_of_the_run_is_used(self):
        self.h.recovery()
        self.h.plan([["evidence", B, FAIL3], ["exit", 9]])
        self.assertEqual(self.h.run().returncode, hs.EXIT_HANDOFF)
        self.assertEqual(self.h.stops(), [])

    def test_a_null_target_never_stops_and_its_run_is_kept_while_the_stop_is_pending(self):
        self.h.plan([["expect", B], ["evidence", B, FAIL3], ["exit", 9]])
        p = self.h.run()
        self.assertEqual(p.returncode, hs.EXIT_INCIDENT, p.stdout + p.stderr)
        self.assertEqual(self.h.stops(), [])
        self.assertIn("stop_not_attempted", self.events())
        self.assertFalse(self.delegation(), "the rewrite still happens")
        self.assertEqual(len(self.h.runs()), 1, "its context is the recovery context while the stop is pending")

    def test_a_crash_after_the_childs_own_record_completes_once_keeping_its_cause(self):
        self.h.recovery()
        self.h.plan([["expect", B], ["evidence", B, FAIL3], ["detected", ["P03"]], ["exit", 9]])
        self.assertEqual(self.h.run().returncode, hs.EXIT_INCIDENT)
        rid = [n for n in os.listdir(self.h.ev) if n.startswith("incident-")][0]
        self.assertEqual(json.load(open(f"{self.h.ev}/{rid}/detected.json"))["failing"], ["P03"])
        self.assertEqual(self.events(), ["rewrite_ok", "stop_ok"])
        self.assertEqual(len(self.h.stops()), 1)

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
        self.assertEqual(self.h.stops(), [], "the dead writer decided nothing")
        self.h.plan([["expect", B], ["evidence", B, PASS], ["outcome", 0, TARGET]])
        self.h.run()
        self.assertEqual(self.h.stops(), [TARGET])
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

    def test_a_document_naming_another_exec_root_than_the_unit_runs_nothing(self):
        self.h.document(partition={"evidence_dir": self.h.ev, "exec_root": self.h.root + "/other",
                                   "tools": {"python3": sys.executable, "docker": self.h.docker}})
        p = self.h.run()
        self.assertEqual(p.returncode, hs.EXIT_HANDOFF, p.stdout + p.stderr)
        self.assertIn("exec_root", p.stdout)
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
        self.assertEqual(self.h.stops(), [])
        self.h.recovery()
        self.assertEqual(self.h.run().returncode, hs.EXIT_TOOLING)
        self.assertEqual(self.h.stops(), [TARGET])

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

    # B1: everything root runs is verified before any engine call
    def test_nothing_reaches_the_engine_before_the_startup_closure_is_verified(self):
        self.h.abandoned("wold", FAIL3)
        bad = f"{self.h.root}/lib"
        os.mkdir(bad)
        os.chmod(bad, 0o777)
        p = self.h.run(env={"PW_CLOSURE": json.dumps([bad])})
        self.assertEqual(p.returncode, hs.EXIT_TOOLING, p.stdout + p.stderr)
        self.assertIn("startup closure", p.stdout)
        self.assertEqual(self.h.logged(), [], "no engine call at all, not even for the abandoned run")
        self.assertEqual(self.h.runs(), ["run-wold"], "the abandoned run is left undecided")
        self.assertTrue(self.delegation())
        self.assertIsNone(self.h.side_read("child-started.json"))

    def test_every_engine_call_runs_the_verified_realpath_never_the_documents_link(self):
        self.h.recovery()
        self.h.abandoned("wold", FAIL3)
        self.h.plan([["expect", B], ["evidence", B, FAIL3], ["stop"], ["exit", 9]])
        self.assertEqual(self.h.run().returncode, hs.EXIT_INCIDENT)
        ran_as = {c[-1] for c in self.h.logged()}
        self.assertEqual(ran_as, {self.h.docker}, "the child too is handed the realpath")
        self.assertNotEqual(self.h.docker, self.h.docker_link)

    # B2: strict per-run provenance
    def test_evidence_that_is_not_partition_evidence_by_its_whole_grammar_is_never_used(self):
        self.h.recovery()
        for variant in ("spaced", "short", "badprobe", "early"):
            with self.subTest(variant=variant):
                self.h.plan([["expect", B], ["evidence", B, FAIL3, 0o444, variant], ["exit", 9]])
                p = self.h.run()
                self.assertEqual(p.returncode, hs.EXIT_HANDOFF, variant + p.stdout + p.stderr)
                self.assertEqual(self.h.stops(), [])
                self.assertTrue(self.delegation())

    def test_non_ascii_evidence_in_its_canonical_form_is_used(self):
        self.h.recovery()
        self.h.plan([["expect", B], ["evidence", B, FAIL3, 0o444, "nonascii"], ["exit", 9]])
        p = self.h.run()
        self.assertEqual(p.returncode, hs.EXIT_INCIDENT, p.stdout + p.stderr)
        self.assertEqual(self.h.stops(), [TARGET])

    def test_records_by_another_schema_are_absent(self):
        self.h.recovery()
        self.h.plan([["expect", B, "x"], ["evidence", B, FAIL3], ["exit", 9]])
        self.assertEqual(self.h.run().returncode, hs.EXIT_HANDOFF)
        self.assertEqual(self.h.stops(), [])
        os.unlink(f"{self.h.exec}/recovery.json")
        self.h.plan([["expect", B], ["evidence", B, PASS], ["outcome", 0, TARGET, "x"]])
        self.assertEqual(self.h.run().returncode, hs.EXIT_HANDOFF)
        self.assertFalse(os.path.exists(f"{self.h.exec}/recovery.json"), "no passing outcome, no recovery record")

    def test_an_abandoned_run_on_another_engine_or_docker_is_kept_and_never_stopped(self):
        for kw in ({"engine": "unix:///elsewhere.sock"}, {"docker": "/usr/bin/docker"}):
            with self.subTest(kw=kw):
                self.h.abandoned("wold", FAIL3, **kw)
                self.h.plan([["expect", B], ["evidence", B, PASS], ["outcome", 0, TARGET]])
                p = self.h.run()
                self.assertEqual(p.returncode, hs.EXIT_PASS, p.stdout + p.stderr)
                self.assertIn("never an old id on another engine", p.stdout)
                self.assertEqual(self.h.stops(), [])
                self.assertEqual(self.h.runs(), ["run-wold"])
                self.assertTrue(self.delegation())
                subprocess.run(["rm", "-rf", f"{self.h.exec}/run-wold", f"{self.h.ev}/partition-wold.json"])

    def test_the_stop_id_comes_from_the_runs_context_only(self):
        self.h.recovery()
        self.h.abandoned("wold", FAIL3, target=None)
        self.h.plan([["expect", B], ["evidence", B, PASS], ["outcome", 0, TARGET]])
        self.h.run()
        self.assertEqual(self.h.stops(), [], "the recovery record's target is never the abandoned run's")
        self.assertIn("stop_not_attempted", self.events())

    # B3: durable incidents are never erased
    def test_the_runs_own_incident_is_completed_with_no_evidence_at_all(self):
        self.h.recovery()
        self.h.plan([["detected", ["P03"]], ["exit", 9]])
        p = self.h.run()
        self.assertEqual(p.returncode, hs.EXIT_INCIDENT, p.stdout + p.stderr)
        self.assertEqual(self.h.stops(), [TARGET])
        rid = [n for n in os.listdir(self.h.ev) if n.startswith("incident-")][0]
        self.assertEqual(json.load(open(f"{self.h.ev}/{rid}/detected.json"))["failing"], ["P03"])

    def test_an_incident_whose_records_cannot_be_read_is_completed_never_trusted_done(self):
        resolved_short = json.dumps({"event": "resolved", "at": "x"}) + "\n"
        for steps in ([["detected", []]], [["detected", ["P03"]], ["events", "garbage\n"]],
                      [["detected", ["P03"]], ["events", resolved_short]]):
            with self.subTest(steps=steps):
                self.h.recovery()
                self.h.containers({TARGET: True})
                open(self.h.log, "w").close()
                self.h.plan(steps + [["exit", 9]])
                self.assertEqual(self.h.run().returncode, hs.EXIT_INCIDENT)
                self.assertEqual(self.h.stops(), [TARGET])
                subprocess.run(["rm", "-rf"] + [f"{self.h.ev}/{n}" for n in os.listdir(self.h.ev)])
                time.sleep(1.1)

    def test_a_well_formed_resolved_incident_is_left_alone(self):
        self.h.recovery()
        line = json.dumps({"event": "resolved", "at": "x", "evidence": "e", "reason": "r"}) + "\n"
        for steps in ([], [["expect", B], ["evidence", B, FAIL3]]):
            with self.subTest(evidence=bool(steps)):
                self.h.plan(steps + [["detected", ["P03"]], ["events", line], ["exit", 9]])
                self.h.run()
                self.assertEqual(self.h.stops(), [])
                self.assertTrue(self.delegation())
                subprocess.run(["rm", "-rf"] + [f"{self.h.ev}/{n}" for n in os.listdir(self.h.ev)])
                time.sleep(1.1)

    def test_tooling_without_the_lock_acts_on_nothing(self):
        self.h.recovery()
        os.mkfifo(f"{self.h.exec}/lock", 0o600)
        p = self.h.run()
        self.assertEqual(p.returncode, hs.EXIT_TOOLING, p.stdout + p.stderr)
        self.assertEqual(self.h.logged(), [])
        self.assertTrue(self.delegation())

    # B4: only the engine's affirmative answer counts
    def test_an_engine_that_cannot_say_is_never_a_stop(self):
        for state in ({TARGET: True, "_inspect_fail": True}, {TARGET: True, "_inspect_fail": True, "_ps_fail": True},
                      {TARGET: "badstate"}):
            with self.subTest(state=state):
                self.h.recovery()
                self.h.containers(state)
                self.h.plan([["expect", B], ["evidence", B, FAIL3], ["exit", 9]])
                self.assertEqual(self.h.run().returncode, hs.EXIT_INCIDENT)
                self.assertEqual(self.h.stops(), [])
                self.assertNotIn("stop_ok", self.events())
                self.assertEqual(len(self.h.runs()), 1, "kept: the stop is not shown done")
                subprocess.run(["rm", "-rf"] + [f"{self.h.ev}/{n}" for n in os.listdir(self.h.ev)]
                               + [f"{self.h.exec}/{n}" for n in self.h.runs()])
                time.sleep(1.1)

    def test_a_paused_target_is_running_and_is_stopped(self):
        self.h.recovery()
        self.h.containers({TARGET: "paused"})
        self.h.plan([["expect", B], ["evidence", B, FAIL3], ["exit", 9]])
        self.assertEqual(self.h.run().returncode, hs.EXIT_INCIDENT)
        self.assertEqual(self.h.stops(), [TARGET])

    def test_a_child_that_stopped_the_target_leaves_the_parent_only_to_confirm_it(self):
        self.h.recovery()
        done = "".join(json.dumps(dict(e, at="x")) + "\n" for e in
                       ({"event": "rewrite_ok"}, {"event": "stop_ok", "id": TARGET}))
        self.h.plan([["expect", B], ["evidence", B, FAIL3], ["detected", ["P03"]], ["stop"], ["events", done],
                     ["outcome", 1, TARGET]])
        self.assertEqual(self.h.run().returncode, hs.EXIT_INCIDENT)
        self.assertEqual(self.h.stops(), [TARGET], "the child's stop, and no second one")
        self.assertEqual(self.event_records()[-1]["event"], "stop_ok")
        self.assertEqual(self.h.runs(), [])

    # B5: protected roots
    def test_a_writable_evidence_directory_or_live_config_runs_nothing(self):
        conf_dir = os.path.dirname(self.h.conf)
        for path, mode in ((self.h.ev, 0o775), (self.h.ev, 0o757), (conf_dir, 0o775), (conf_dir, 0o757),
                           (self.h.conf, 0o646), (self.h.conf, 0o664)):
            with self.subTest(path=path, mode=oct(mode)):
                before = stat.S_IMODE(os.stat(path).st_mode)
                os.chmod(path, mode)
                try:
                    p = self.h.run()
                finally:
                    os.chmod(path, before)
                self.assertEqual(p.returncode, hs.EXIT_TOOLING, p.stdout + p.stderr)
                self.assertEqual(self.h.logged(), [])
                self.assertIsNone(self.h.side_read("child-started.json"))

    def test_a_live_config_that_is_a_link_runs_nothing(self):
        real = f"{self.h.root}/conf/real.json"
        os.rename(self.h.conf, real)
        os.symlink(real, self.h.conf)
        self.assertEqual(self.h.run().returncode, hs.EXIT_TOOLING)
        self.assertIsNone(self.h.side_read("child-started.json"))

    def test_overlapping_roots_run_nothing(self):
        inside = f"{self.h.exec}/evidence"
        for over in ({"partition": {"evidence_dir": inside, "exec_root": self.h.exec,
                                    "tools": {"python3": sys.executable, "docker": self.h.docker_link}}},
                     {"keys": {"local_config": f"{self.h.ev}/router.json"}}):
            with self.subTest(over=list(over)):
                self.h.document(**over)
                p = self.h.run()
                self.assertEqual(p.returncode, hs.EXIT_HANDOFF, p.stdout + p.stderr)
                self.assertIn("overlap", p.stdout)
                self.assertIsNone(self.h.side_read("child-started.json"))


class InProcess(unittest.TestCase):
    """The writer's functions, called directly, with root mapped to this
    test's uid and gid and the ancestor rule set aside."""

    def setUp(self):
        for name, value in (("ROOT_UID", os.getuid()), ("ROOT_GID", os.getgid()), ("_ancestor_ok", lambda st: True)):
            self.addCleanup(setattr, hs, name, getattr(hs, name))
            setattr(hs, name, value)
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.d = os.path.realpath(t.name)


class RootsTest(InProcess):
    def test_a_root_of_another_owner_or_group_is_refused(self):
        os.mkdir(f"{self.d}/e", 0o755)
        os.chmod(f"{self.d}/e", 0o755)
        os.close(hs._evidence_dir(f"{self.d}/e"))
        for name, value in (("ROOT_UID", os.getuid() + 1), ("ROOT_GID", os.getgid() + 1)):
            with self.subTest(name=name):
                old = getattr(hs, name)
                setattr(hs, name, value)
                try:
                    with self.assertRaises(hs.Tooling):
                        hs._evidence_dir(f"{self.d}/e")
                    with self.assertRaises(hs.Tooling):
                        hs._root_dir(f"{self.d}/e", 0o755)
                finally:
                    setattr(hs, name, old)


class Engine:
    def __init__(self, states):
        self.states, self.stopped = list(states), []

    def running(self, cid):
        return self.states.pop(0)

    def run(self, args, timeout=None):
        self.stopped.append(args[-1])


class ActTest(InProcess):
    """_act: no record, history or diagnostic failure blocks the stop. A
    crash is converted to a failure: _act must never raise."""

    def act(self, target, engine, said):
        try:
            return hs._act(self.ev, self.conf, target, "r1", "2026-10-15T03:00:00Z", ["P03"], engine, said)
        except Exception as e:  # a crash is not an outcome
            self.fail(f"_act raised {e!r}")

    def setUp(self):
        super().setUp()
        self.ev, self.conf = f"{self.d}/ev", f"{self.d}/conf/router.json"
        os.mkdir(self.ev, 0o755)
        os.chmod(self.ev, 0o755)
        os.mkdir(f"{self.d}/conf", 0o755)
        with open(self.conf, "w") as f:
            f.write('{"delegation": {}}\n')

    def test_a_failing_diagnostic_sink_and_an_unwritable_history_never_block_the_stop(self):
        class Sink(list):
            def append(self, x):
                raise OSError("the sink is gone")
        os.makedirs(f"{self.ev}/incident-r1/events.jsonl")
        engine = Engine([True, False])
        done = self.act(TARGET, engine, Sink())
        self.assertEqual(engine.stopped, [TARGET])
        self.assertTrue(done)
        with open(self.conf) as f:
            self.assertNotIn("delegation", json.load(f))

    def test_an_unrecordable_incident_still_rewrites_and_stops(self):
        os.chmod(self.ev, 0o555)
        self.addCleanup(os.chmod, self.ev, 0o755)
        said, engine = [], Engine([True, False])
        self.act(TARGET, engine, said)
        self.assertEqual(engine.stopped, [TARGET])
        self.assertTrue(any("NOT recorded" in s for s in said), said)

    def test_only_a_full_id_is_ever_stopped(self):
        for target in (None, "router-up", "c" * 12):
            with self.subTest(target=target):
                engine = Engine([True, False])
                self.assertFalse(self.act(target, engine, []))
                self.assertEqual(engine.stopped, [])

    def test_a_stop_is_done_only_when_the_engine_then_affirms_it_is_not_running(self):
        for after in (None, True):
            with self.subTest(after=after):
                engine = Engine([True, after])
                self.assertFalse(self.act(TARGET, engine, []))
                self.assertEqual(engine.stopped, [TARGET])
                with open(f"{self.ev}/incident-r1/events.jsonl") as f:
                    self.assertEqual(json.loads(f.read().splitlines()[-1])["event"], "stop_failed")


class EngineTest(unittest.TestCase):
    """_Engine.running against a recorded docker: an answer only when the
    engine affirms one."""

    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        d = os.path.realpath(t.name)
        self.state, log, self.docker = f"{d}/s.json", f"{d}/l", f"{d}/docker"
        with open(self.docker, "w") as f:
            f.write((DOCKER % (self.state, log)).replace("#!PYTHON", "#!" + sys.executable))
        os.chmod(self.docker, 0o755)
        self.engine = hs._Engine(self.docker, "unix:///nowhere.sock", d)

    def running(self, state):
        with open(self.state, "w") as f:
            json.dump(state, f)
        return self.engine.running(TARGET)

    def test_running_is_true_false_or_unknown(self):
        self.assertIs(self.running({TARGET: True}), True)
        self.assertIs(self.running({TARGET: "paused"}), True)
        self.assertIs(self.running({TARGET: False}), False)
        self.assertIs(self.running({}), False, "absence, confirmed by id")
        for state in ({TARGET: "badstate"}, {TARGET: True, "_inspect_fail": True},
                      {TARGET: True, "_inspect_fail": True, "_ps_fail": True}, {"_inspect_fail": True, "_ps_fail": True}):
            with self.subTest(state=state):
                self.assertIsNone(self.running(state))
        self.assertIsNone(hs._Engine(f"{self.docker}-missing", "unix:///x", "/").running(TARGET), "no transport")


class ClosureTest(unittest.TestCase):
    """The startup closure: discovered by the operating system's own tools,
    and judged path by path, up every parent and down every tree."""

    def fs(self, entries):
        """A fake tree: path -> (uid, mode); lstat and walk over it."""
        def lstat(p):
            if p not in entries:
                raise FileNotFoundError(2, "No such file or directory")
            uid, mode = entries[p]
            return types.SimpleNamespace(st_uid=uid, st_mode=mode)

        def walk(top):
            if not stat.S_ISDIR(entries.get(top, (0, 0))[1]):
                return
            kids = [p for p in entries if os.path.dirname(p) == top and p != top]
            yield top, [os.path.basename(k) for k in kids if stat.S_ISDIR(entries[k][1])], \
                [os.path.basename(k) for k in kids if not stat.S_ISDIR(entries[k][1])]
            for k in kids:
                if stat.S_ISDIR(entries[k][1]):
                    yield from walk(k)
        return lstat, walk

    D, F, L = stat.S_IFDIR | 0o755, stat.S_IFREG | 0o644, stat.S_IFLNK | 0o777

    def tree(self, **over):
        t = {"/": (0, self.D), "/usr": (0, self.D), "/usr/lib": (0, self.D), "/usr/lib/python3": (0, self.D),
             "/usr/lib/python3/os.py": (0, self.F), "/usr/lib/python3/lib-dynload": (0, self.D),
             "/usr/lib/python3/lib-dynload/_ssl.so": (0, self.F), "/usr/lib/libssl.so.3": (0, self.F),
             "/usr/lib/python3/link.py": (0, self.L),
             "/Library": (0, self.D), "/Library/Developer": (0, self.D),
             "/Library/Developer/CommandLineTools": (0, self.D),
             "/Library/Developer/CommandLineTools/usr": (0, self.D)}
        t.update(over)
        return t

    PATHS = ["/usr/lib/python3", "/usr/lib/libssl.so.3", "/Library/Developer/CommandLineTools"]

    def test_a_closure_root_alone_has_no_problems(self):
        lstat, walk = self.fs(self.tree())
        self.assertEqual(hs.closure_problems(self.PATHS, lstat, walk), [])

    def test_every_writable_or_foreign_startup_dependency_is_a_problem(self):
        rows = {"a module others can write": {"/usr/lib/python3/os.py": (0, stat.S_IFREG | 0o666)},
                "an extension module its group can write": {
                    "/usr/lib/python3/lib-dynload/_ssl.so": (0, stat.S_IFREG | 0o664)},
                "a linked library of another owner": {"/usr/lib/libssl.so.3": (501, self.F)},
                "a parent others can write": {"/usr/lib": (0, stat.S_IFDIR | 0o777)},
                "a parent of another owner": {"/usr": (501, self.D)},
                "the macOS developer directory, user-owned": {"/Library/Developer/CommandLineTools/usr": (501, self.D)},
                "the macOS developer directory's parent, group-writable": {
                    "/Library/Developer": (0, stat.S_IFDIR | 0o775)}}
        for what, over in rows.items():
            with self.subTest(what):
                lstat, walk = self.fs(self.tree(**over))
                bad = hs.closure_problems(self.PATHS, lstat, walk)
                self.assertEqual([b.split(" ")[0] for b in bad], list(over), bad)
        lstat, walk = self.fs({k: v for k, v in self.tree().items() if k != "/usr/lib/libssl.so.3"})
        self.assertTrue(hs.closure_problems(self.PATHS, lstat, walk), "a missing dependency is a problem")

    def test_discovery_names_the_library_its_extension_modules_and_every_linked_library(self):
        found = hs.startup_closure(os.path.realpath(sys.executable), os.path.realpath("/bin/sh"))
        import sysconfig
        self.assertIn(sysconfig.get_paths()["stdlib"], found)
        self.assertTrue(any(os.path.basename(p).startswith("libc.") for p in found), found)
        if os.path.exists("/usr/bin/ldd"):
            dynload = sysconfig.get_config_var("DESTSHARED")
            mods = [os.path.join(dynload, n) for n in os.listdir(dynload) if n.endswith(".so")]
            out = subprocess.run(["/usr/bin/ldd"] + mods, capture_output=True, text=True).stdout
            linked = {l.split("=>")[1].split()[0] for l in out.splitlines() if "=>" in l and "/" in l.split("=>")[1]}
            self.assertTrue(linked, "the extension modules link libraries of their own")
            self.assertLessEqual(linked, set(found), "every extension module's links are in the closure")

    def test_on_macos_the_chosen_developer_directory_is_in_the_closure(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        xs = os.path.join(os.path.realpath(t.name), "xcode-select")
        with open(xs, "w") as f:
            f.write("#!/bin/sh\necho /Library/Developer/CommandLineTools\n")
        os.chmod(xs, 0o755)
        for name, value in (("XCODE_SELECT", xs), ("sys", types.SimpleNamespace(platform="darwin"))):
            self.addCleanup(setattr, hs, name, getattr(hs, name))
            setattr(hs, name, value)
        found = hs.startup_closure(os.path.realpath(sys.executable), os.path.realpath("/bin/sh"))
        self.assertIn("/Library/Developer/CommandLineTools", found)


class GrammarDriftTest(unittest.TestCase):
    """The writer imports nothing of the library, so its copies of the
    grammars are held equal to the library's here."""

    def test_the_incident_grammar_is_partition_incidents(self):
        self.assertEqual((hs.EVENT_GRAMMAR, hs._COMMON, hs.ACTIONS, hs.DETECTED_REQUIRED, hs.DETECTED_OPTIONAL),
                         (pi.EVENT_GRAMMAR, pi._COMMON, pi.ACTIONS, pi.DETECTED_REQUIRED, pi.DETECTED_OPTIONAL))
        good = {"rewrite_ok": {}, "rewrite_failed": {"reason": "r"}, "stop_ok": {"id": "i", "observed": "o"},
                "stop_failed": {"reason": "r"}, "stop_not_attempted": {"reason": "r"},
                "resolved": {"evidence": "e", "reason": "r"}}
        corpus = [dict(event=k, at="x", **v) for k, v in good.items()]
        corpus += [dict(e, at="") for e in corpus] + [dict(e, by=1) for e in corpus] + \
            [dict(e, completion="yes") for e in corpus] + [dict(e, extra="x") for e in corpus] + \
            [{"event": "resolved", "at": "x"}, {"event": "other", "at": "x"}, {"at": "x"}, [], None]
        for e in corpus:
            with self.subTest(e=e):
                self.assertEqual(hs.event_problem(e) is None, pi.event_problem(e) is None)
        det = {"run_id": "r1", "at": "x", "failing": ["P03"], "pending": ["rewrite", "stop"]}
        for d in (det, dict(det, run_id="r2"), dict(det, failing=[]), dict(det, pending=["stop", "stop"]),
                  dict(det, pending=["other"]), dict(det, token=1), dict(det, recorded_late=1),
                  dict(det, extra=1), {k: v for k, v in det.items() if k != "at"}, dict(det, identity=None)):
            with self.subTest(d=d):
                self.assertEqual(hs.detected_problem(d, "r1") is None, pi.detected_problem(d, "r1") is None)

    def test_the_run_records_grammar_is_the_childs(self):
        self.assertEqual((hs.CONTEXT_SCHEMA, hs.EXPECT_SCHEMA, hs.OUTCOME_SCHEMA),
                         (pr.CONTEXT_SCHEMA, pr.EXPECT_SCHEMA, pr.OUTCOME_SCHEMA))
        self.assertEqual((hs.CONTEXT_MEMBERS, hs.EXPECT_MEMBERS, hs.OUTCOME_MEMBERS),
                         (pr.CONTEXT_MEMBERS, pr.EXPECT_MEMBERS, pr.OUTCOME_MEMBERS))

    def test_the_evidence_grammar_is_partition_evidences(self):
        def built(verdicts=PASS, name="router"):
            return pe.build(host="alpha", run_id="r1", at="2026-10-15T03:00:00Z", script_sha256={"s": "0" * 64},
                            bindings=B, probes=[probe(p, v, name) for p, v in sorted(verdicts.items())])
        corpus = [built(), built(FAIL3), built(name="rout\u00e9r"),
                  built({"P01": "UNKNOWN", "P02": "FAIL", "P03": "PASS", "P04": "FAIL"})]
        base = json.loads(built(FAIL3))

        def edit(fn):
            d = json.loads(json.dumps(base))
            fn(d)
            return pe.canonical(d)
        corpus += [edit(lambda d, k=k: d.pop(k)) for k in sorted(base)]
        corpus += [edit(lambda d: d.update(host="beta")), edit(lambda d: d.update(at="2026-13-01T00:00:00Z")),
                   edit(lambda d: d.update(run_id="a/b")), edit(lambda d: d.update(bindings={})),
                   edit(lambda d: d.update(script_sha256={"s": "0"})), edit(lambda d: d["probes"].reverse()),
                   edit(lambda d: d["probes"][0].update(verdict="MAYBE")),
                   edit(lambda d: d["probes"][0]["vantage"][0].update(uid=True)),
                   edit(lambda d: d["probes"][3].update(target_role=["mount:/x"])),
                   edit(lambda d: d["probes"][2].update(target_role=["key:signing"])),
                   edit(lambda d: d["probes"][2].update(target_role=["key:signing", "key:dir", "key:dir"])),
                   edit(lambda d: d.update(fail_stop={"P03": "PASS", "P04": "PASS"})),
                   edit(lambda d: d.update(delegation_partition_verified="r1:" + "0" * 64)),
                   edit(lambda d: d["probes"][1]["witness"].update(outcome="bad")),
                   json.dumps(base, sort_keys=True).encode(), built() + b" ", b"\xff", b"[]"]
        for raw in corpus:
            with self.subTest(raw=raw[:60]):
                try:
                    pe.parse(raw, host="alpha")
                    theirs = True
                except pe.EvidenceError:
                    theirs = False
                self.assertEqual(hs._evidence_problem(raw, "alpha")[0] is None, theirs)


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
