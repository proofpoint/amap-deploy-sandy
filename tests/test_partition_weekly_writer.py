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
import re
import os
import signal
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import host_steps as hs
from _fakefs import FakeFS
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
import hashlib, subprocess
import partition_activation as pa
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
try:
    note("record-at-start.json", json.load(open(os.path.join(ev, "weekly-runs.json"))))
except OSError:
    note("record-at-start.json", None)
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
    elif kind == "containers":
        # The engine's world changing during the run (a router started).
        with open(STATE) as f:
            state = json.load(f)
        state.update(step[1])
        with open(STATE, "w") as f:
            json.dump(state, f)
    elif kind == "liveconf":
        # The live config replaced during the run, as a placement would.
        place(ctx["live_config_path"], (json.dumps(step[1], indent=2) + "\n").encode(), 0o644)
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
        schema = step[3] if len(step) > 3 and step[3] else "amap-deploy.partition-outcome/1"
        mode = step[4] if len(step) > 4 else None
        snap = dict.fromkeys(("router_seen", "config_sha256", "evidence_run_id", "evidence_sha256", "inspect_digest"))
        if step[1] == 0 and step[2] and mode != "noshot":
            # The snapshot as partition_run records it: the container inspected
            # by id, the live config and the evidence read, each hashed.
            live = json.loads(subprocess.run([ctx["docker"], "inspect", "--type", "container", "--format",
                                              "{{json .}}", step[2]], capture_output=True).stdout)
            with open(ctx["live_config_path"], "rb") as f:
                cfg = f.read()
            # The token's evidence is A2's document, not this run's.
            with open(os.path.join(ev, "partition-a2.json"), "rb") as f:
                evidence = f.read()
            snap = {"router_seen": "ex-up" if mode == "nameonly" else step[2],
                    "config_sha256": hashlib.sha256(cfg).hexdigest(),
                    "evidence_run_id": "../a2" if mode == "badrun" else "a2",
                    "evidence_sha256": hashlib.sha256(evidence).hexdigest(),
                    "inspect_digest": pe.sha_json(pa.inspect_projection(live))}
            if mode == "touchconf":
                with open(ctx["live_config_path"], "ab") as f:
                    f.write(b" ")
            if mode in ("touchevidence", "evidence0644"):
                p = os.path.join(ev, "partition-a2.json")
                if mode == "touchevidence":
                    place(p, evidence + b" ", 0o444)
                else:
                    os.chmod(p, 0o644)
            if mode == "mutate":
                with open(STATE) as f:
                    state = json.load(f)
                state["_doc"] = {"Image": "another-image"}
                with open(STATE, "w") as f:
                    json.dump(state, f)
        place(os.path.join(run_dir, "outcome.json"), canonical(dict(snap, schema=schema, run_id=rid, code=step[1],
                                                                    incident=step[1] == 1, why="test")), 0o400)
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
STATE, LOG, CONF = %r, %r, %r
with open(LOG, "a") as f:
    f.write(json.dumps(sys.argv[1:] + [sys.argv[0]]) + "\n")
state = json.load(open(STATE))
a = sys.argv[1:]
if a[:2] == ["inspect", "--type"] and "{{json .}}" in a:
    cid = a[-1]
    if cid not in state or state.get("_inspect_fail"):
        sys.exit(1)
    v = state[cid]
    doc = {"Id": cid, "Created": state.get("_created", "2026-01-01T00:00:00.123456789Z"), "Image": "img",
           "State": {"Running": v is True or v == "paused", "Paused": v == "paused", "Restarting": False},
           "Config": {"User": "2101:2101", "Env": ["ROUTER_CONFIG=" + CONF]},
           "HostConfig": {"NetworkMode": "none", "RestartPolicy": {"Name": "unless-stopped"}},
           "Mounts": [{"Type": "bind", "Source": CONF, "Destination": CONF, "RW": False}]}
    doc.update(state.get("_doc", {}))
    print(json.dumps(doc))
elif a[:2] == ["inspect", "--type"]:
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
hs.startup_closure = lambda python, docker, spelled=(), platform=None: json.loads(os.environ.get("PW_CLOSURE", "[]"))
hs._docker_closure = lambda docker, spelled=None: json.loads(os.environ.get("PW_DOCKER_CLOSURE", "[]"))
hs._ancestor_ok = lambda st: True
hs._trusted_tool = lambda p: os.path.realpath(p)
hs.CHILD_TIMEOUT_S = float(os.environ.get("PW_CHILD_TIMEOUT", hs.CHILD_TIMEOUT_S))
# PW_RUNS_FAULT=<phase>:<call>[#<n>] fails the n-th such call of the run
# record's filesystem in that phase (W2, W5 or W7); PW_REMOVE_FAIL names run
# directories whose removal fails.
if os.environ.get("PW_RUNS_FAULT"):
    phase, call = os.environ["PW_RUNS_FAULT"].split(":")
    call, nth = (call.split("#") + ["1"])[:2]
    class Faulty:
        def __init__(self):
            self.seen = 0
        def __getattr__(self, name):
            real = getattr(os, name)
            if name != call:
                return real
            def maybe(*a, **k):
                self.seen += 1
                if self.seen == int(nth):
                    raise OSError(5, "injected " + call)
                return real(*a, **k)
            return maybe
    real_fs = hs._runs_fs
    hs._runs_fs = lambda p: Faulty() if p == phase else real_fs(p)
# PW_SETUP_FAULT names one step between W2 and the child that fails with an
# OSError: mkdir of the run directory or of its docker directory, the
# context record, W5's listing, or the child's launch.
_fault = os.environ.get("PW_SETUP_FAULT")
if _fault in ("mkdir-run", "mkdir-docker"):
    _real_mkdir = os.mkdir
    def _mkdir(path, *a, **k):
        if (path.startswith("run-") if _fault == "mkdir-run" else path == "docker"):
            raise OSError(28, "No space left on device", path)
        return _real_mkdir(path, *a, **k)
    os.mkdir = _mkdir
elif _fault == "context":
    _real_write_at = hs._write_at
    def _write_at(dfd, name, *a, **k):
        if name == "context.json":
            raise OSError(28, "No space left on device", name)
        return _real_write_at(dfd, name, *a, **k)
    hs._write_at = _write_at
elif _fault == "listing":
    _real_record, _calls = hs._runs_record, []
    def _runs_record(*a, **k):
        _calls.append(1)
        if len(_calls) == 1:
            raise OSError(5, "Input/output error", "exec_root")
        return _real_record(*a, **k)
    hs._runs_record = _runs_record
elif _fault == "launch":
    def _launch(*a, **k):
        raise OSError(8, "Exec format error", a[0][0])
    hs._launch = _launch
if os.environ.get("PW_REMOVE_FAIL"):
    import re as _re
    real_rm = hs._remove_tree
    def failing(dfd, name):
        if _re.fullmatch(os.environ["PW_REMOVE_FAIL"], name):
            raise OSError(5, "injected removal")
        return real_rm(dfd, name)
    hs._remove_tree = failing
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
            f.write((DOCKER % (self.state, self.log, self.conf)).replace("#!PYTHON", "#!" + sys.executable))
        os.chmod(self.docker, 0o755)
        self.docker_link = f"{r}/bin/docker-link"
        os.symlink(self.docker, self.docker_link)
        self.wrapper = f"{r}/writer.py"
        with open(self.wrapper, "w") as f:
            f.write(WRAPPER % str(REPO))
        self.plan([])
        self.bundle()
        self.document()
        self.activation()
        self.a2()

    def a2(self):
        """A2's evidence document, whose token the live config carries."""
        p = f"{self.ev}/partition-a2.json"
        if os.path.exists(p):
            os.unlink(p)
        with open(p, "wb") as f:
            f.write(b'{"a2": "the token\'s evidence, placed by A2"}')
        os.chmod(p, 0o444)

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
        files = {"partition_weekly.py": f"PLAN, SIDE, REPO, STATE = {self.root + '/plan.json'!r}, {self.side!r}, "
                                        f"{str(REPO)!r}, {self.state!r}\n" + CHILD,
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

    def activation(self, data=b'{"approved": "A1"}'):
        """A1's approved record at its one place; the writer judges only its
        digest and hands its bytes over."""
        p = f"{self.ev}/activation.json"
        if os.path.exists(p):
            os.unlink(p)
        with open(p, "wb") as f:
            f.write(data)
        os.chmod(p, 0o444)
        self.act_path, self.act_digest = p, hashlib.sha256(data).hexdigest()

    def recovery(self, target=TARGET):
        data = json.dumps({"schema": hs.RECOVERY_SCHEMA, "host": "alpha", "run_id": "r0", "at": "x",
                           "evidence_dir": self.ev, "live_config_path": self.conf, "router_container_id": target,
                           "engine": "unix://" + self.sock_path, "docker": self.docker, "config_sha256": "1" * 64,
                           "evidence_run_id": "r0", "evidence_sha256": "2" * 64, "inspect_digest": "3" * 64,
                           "activation_sha256": "4" * 64}, sort_keys=True, separators=(",", ":"))
        p = f"{self.exec}/recovery.json"
        if os.path.exists(p):
            os.unlink(p)
        with open(p, "w") as f:
            f.write(data)
        os.chmod(p, 0o444)

    def abandoned(self, rid, verdicts=None, target=TARGET, engine=None, docker=None, expect=True, mode="weekly"):
        """A run a dead writer and child left: its records as they wrote
        them, started a minute ago, and its evidence if `verdicts`."""
        run = f"{self.exec}/run-{rid}"
        os.mkdir(run, 0o700)
        at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 60))
        records = {"context.json": {"schema": pr.CONTEXT_SCHEMA, "run_id": rid, "host": "alpha", "started_at": at,
                                    "evidence_dir": self.ev, "live_config_path": self.conf,
                                    "router_container_id": target, "engine": engine or "unix://" + self.sock_path,
                                    "docker": docker or self.docker, "mode": mode}}
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

    def argv(self, digest=None, activation=None, activation_digest=None):
        return [sys.executable, "-I", "-S", "-B", self.wrapper, "partition-weekly", "--exec-root", self.exec,
                "--host", "alpha", "--document", self.doc, "--document-sha256", digest or self.digest,
                "--activation", activation or self.act_path, "--activation-sha256", activation_digest or self.act_digest]

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

    def test_a_stale_target_is_never_stopped_and_never_certified_stopped(self):
        """After [1] is recreated, the recorded id is not running or gone,
        while the router that replaced it runs: the stop stays pending."""
        self.h.recovery()
        replacement = "d" * 64
        for state in ({TARGET: False, replacement: True}, {replacement: True}):
            with self.subTest(state=sorted(state)):
                self.h.containers(state)
                self.h.plan([["expect", B], ["evidence", B, FAIL3], ["exit", 9]])
                self.assertEqual(self.h.run().returncode, hs.EXIT_INCIDENT)
                self.assertEqual(self.h.stops(), [], "nothing stopped, by id or by name")
                last = self.event_records()[-1]
                self.assertEqual(last["event"], "stop_not_attempted")
                self.assertIn("may be stale", last["reason"])
                self.assertNotIn("stop_ok", self.events())
                self.assertEqual(len(self.h.runs()), 1, "kept: the stop is pending")
                subprocess.run(["rm", "-rf"] + [f"{self.h.ev}/{n}" for n in os.listdir(self.h.ev) if n not in ("activation.json", "partition-a2.json")]
                               + [f"{self.h.exec}/{n}" for n in self.h.runs()])
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

    def test_tooling_whose_fallback_docker_has_an_untrusted_dependency_runs_no_docker(self):
        self.h.recovery()
        self.h.bundle(extra={"stray.py": "x = 1\n"})
        dep = f"{self.h.root}/libdocker.so"
        with open(dep, "w") as f:
            f.write("x")
        os.chmod(dep, 0o666)
        p = self.h.run(env={"PW_DOCKER_CLOSURE": json.dumps([dep])})
        self.assertEqual(p.returncode, hs.EXIT_TOOLING, p.stdout + p.stderr)
        self.assertIn("not verified either", p.stdout)
        self.assertEqual(self.h.logged(), [], "no engine call at all")
        self.assertTrue(self.delegation())

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

    def test_provisioning_with_the_lock_held_hands_off_and_touches_nothing(self):
        """The plan's swap step on both systems is this subcommand, never
        flock(1): with the lock held by another, it is a handoff, and the
        bundle, bundle.new and the lock are byte- and inode-unchanged."""
        import fcntl
        new = f"{self.h.exec}/bundle.new"
        os.mkdir(new)
        for n in ("partition_weekly.py", "partition_weekly.closure", "PIN"):
            with open(f"{self.h.exec}/bundle/{n}", "rb") as f, open(f"{new}/{n}", "wb") as g:
                g.write(f.read())
            os.chmod(f"{new}/{n}", 0o444)
        os.chmod(new, 0o555)
        lock = f"{self.h.exec}/lock"
        fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

        def state():
            out = {}
            for top in (f"{self.h.exec}/bundle", new):
                for n in sorted(os.listdir(top)):
                    st = os.lstat(f"{top}/{n}")
                    with open(f"{top}/{n}", "rb") as f:
                        out[f"{top}/{n}"] = (st.st_ino, f.read())
                out[top] = os.lstat(top).st_ino
            st = os.lstat(lock)
            with open(lock, "rb") as f:
                out[lock] = (st.st_ino, f.read())
            return out
        before = state()
        provision = [sys.executable, "-I", "-S", "-B", self.h.wrapper, "partition-provision", self.h.exec]
        p = subprocess.run(provision, capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, hs.EXIT_HANDOFF, p.stdout + p.stderr)
        self.assertEqual(state(), before)

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
                subprocess.run(["rm", "-rf"] + [f"{self.h.ev}/{n}" for n in os.listdir(self.h.ev) if n not in ("activation.json", "partition-a2.json")])
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
                subprocess.run(["rm", "-rf"] + [f"{self.h.ev}/{n}" for n in os.listdir(self.h.ev) if n not in ("activation.json", "partition-a2.json")])
                time.sleep(1.1)

    def test_an_abandoned_run_that_cannot_be_opened_is_kept_and_the_job_goes_on(self):
        self.h.abandoned("wold", FAIL3)
        os.chmod(f"{self.h.exec}/run-wold", 0)
        self.h.plan([["expect", B], ["evidence", B, PASS], ["outcome", 0, TARGET]])
        p = self.h.run()
        os.chmod(f"{self.h.exec}/run-wold", 0o700)
        self.assertEqual(p.returncode, hs.EXIT_PASS, p.stdout + p.stderr)
        self.assertIn("run-wold: cannot be read", p.stdout)
        self.assertEqual(self.h.runs(), ["run-wold"])
        self.assertEqual(self.h.stops(), [])

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
                subprocess.run(["rm", "-rf"] + [f"{self.h.ev}/{n}" for n in os.listdir(self.h.ev) if n not in ("activation.json", "partition-a2.json")]
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

    # The stop target (the first one comes from A5's last step)
    def published(self):
        out = {}
        for where, name in ((self.h.exec, "recovery.json"), (self.h.ev, "stop-target.json")):
            p = f"{where}/{name}"
            out[name] = open(p, "rb").read() if os.path.exists(p) else None
        return out

    def test_a_passing_run_publishes_the_same_record_twice_and_exits_zero(self):
        self.h.plan([["expect", B], ["evidence", B, PASS], ["outcome", 0, TARGET]])
        p = self.h.run()
        self.assertEqual(p.returncode, hs.EXIT_PASS, p.stdout + p.stderr)
        got = self.published()
        self.assertIsNotNone(got["recovery.json"])
        self.assertEqual(got["recovery.json"], got["stop-target.json"], "byte-identical")
        rec = json.loads(got["recovery.json"])
        self.assertEqual(set(rec), set(hs.RECOVERY_MEMBERS))
        self.assertEqual((rec["router_container_id"], rec["activation_sha256"], rec["docker"]),
                         (TARGET, self.h.act_digest, self.h.docker))
        st = os.stat(f"{self.h.ev}/stop-target.json")
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o444)

    def test_every_refused_acquisition_exits_three_and_publishes_nothing(self):
        rows = {"no snapshot": ({}, "noshot"), "a name, not an id": ({}, "nameonly"),
                "the live config changed after the run judged it": ({}, "touchconf"),
                "the container changed after the run judged it": ({}, "mutate"),
                "a decoy config mount": ({"_doc": {"Mounts": [{"Type": "bind", "Source": "/decoy",
                                                                "Destination": "/c", "RW": False}]}}, None),
                "the config bound read-write": ({"_doc": {"Mounts": [{"Type": "bind", "Source": "CONF",
                                                                       "Destination": "CONF", "RW": True}]}}, None),
                "no ROUTER_CONFIG": ({"_doc": {"Config": {"User": "2101:2101", "Env": []}}}, None),
                "another id answers": ({"_doc": {"Id": "d" * 64}}, None),
                "the container is paused": ({"_doc": {"State": {"Running": True, "Paused": True,
                                                                 "Restarting": False}}}, None),
                "the evidence changed after the run judged it": ({}, "touchevidence"),
                "the evidence no longer placed as root places it": ({}, "evidence0644"),
                "an evidence run id that is not a run id": ({}, "badrun")}
        for what, (extra, mode) in rows.items():
            with self.subTest(what):
                self.h.a2()
                state = dict({TARGET: True}, **json.loads(json.dumps(extra).replace("CONF", self.h.conf)))
                self.h.containers(state)
                self.h.plan([["expect", B], ["evidence", B, PASS], ["outcome", 0, TARGET, None, mode]])
                p = self.h.run()
                self.assertEqual(p.returncode, hs.EXIT_HANDOFF, what + p.stdout + p.stderr)
                self.assertIn("no stop target recorded", p.stdout)
                if mode in ("noshot", "nameonly", "badrun"):
                    self.assertIn("no whole snapshot", p.stdout, "refused as a snapshot, before any read")
                self.assertEqual(self.published(), {"recovery.json": None, "stop-target.json": None})
                with open(self.h.conf, "rb") as f:
                    raw = f.read().rstrip(b" ")
                with open(self.h.conf, "wb") as f:
                    f.write(raw)
                time.sleep(1.1)

    def test_a_publication_that_fails_exits_three_with_its_state(self):
        os.mkdir(f"{self.h.ev}/stop-target.json")
        self.h.plan([["expect", B], ["evidence", B, PASS], ["outcome", 0, TARGET]])
        p = self.h.run()
        self.assertEqual(p.returncode, hs.EXIT_HANDOFF, p.stdout + p.stderr)
        self.assertIn("the old copy could not be invalidated", p.stdout)
        self.assertFalse(os.path.exists(f"{self.h.exec}/recovery.json"))

    def test_an_activation_record_not_the_units_runs_nothing(self):
        for kw in ({"activation_digest": "0" * 64}, {"activation": f"{self.h.root}/activation.json"}):
            with self.subTest(kw=list(kw)):
                p = self.h.run(**kw)
                self.assertEqual(p.returncode, hs.EXIT_HANDOFF, p.stdout + p.stderr)
                self.assertIn("activation", p.stdout)
                self.assertIsNone(self.h.side_read("child-started.json"))
                self.assertEqual(self.h.logged(), [])

    def test_the_child_is_handed_the_approved_records_exact_bytes(self):
        self.h.activation(b'{"approved": "A1, exactly"}')
        self.h.plan([["sleep", 2]])
        first = subprocess.Popen(self.h.argv(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 30
        while self.h.side_read("child-started.json") is None and time.monotonic() < deadline:
            time.sleep(0.05)
        run = f"{self.h.exec}/{self.h.runs()[0]}"
        self.assertTrue(os.path.exists(f"{run}/activation.json"), "the child is handed the approved record")
        with open(f"{run}/activation.json", "rb") as f:
            self.assertEqual(f.read(), b'{"approved": "A1, exactly"}')
        self.assertEqual(stat.S_IMODE(os.stat(f"{run}/activation.json").st_mode), 0o400)
        first.wait()


class PublishTest(unittest.TestCase):
    """_publish_target's three steps, each failure injected: the exact state
    and message, and never success."""

    def setUp(self):
        for name, value in (("ROOT_UID", os.getuid()), ("ROOT_GID", os.getgid()), ("_ancestor_ok", lambda st: True)):
            self.addCleanup(setattr, hs, name, getattr(hs, name))
            setattr(hs, name, value)
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        d = os.path.realpath(t.name)
        self.exec, self.ev = f"{d}/exec", f"{d}/ev"
        os.mkdir(self.exec, 0o700)
        os.mkdir(self.ev, 0o755)
        os.chmod(self.ev, 0o755)
        self.efd = os.open(self.exec, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.efd)
        self.old, self.new = b'{"old": 1}', b'{"new": 2}'
        for where in (self.exec + "/recovery.json", self.ev + "/stop-target.json"):
            with open(where, "wb") as f:
                f.write(self.old)

    def files(self):
        out = []
        for p in (self.exec + "/recovery.json", self.ev + "/stop-target.json"):
            out.append(open(p, "rb").read() if os.path.exists(p) else None)
        return out

    class FS:
        """os, with one call failing: `fail` = (name, the n-th call of it, 1-based)."""

        def __init__(self, fail):
            self.fail, self.seen = fail, {}

        def __getattr__(self, name):
            real = getattr(os, name)

            def call(*a, **k):
                self.seen[name] = self.seen.get(name, 0) + 1
                if self.fail == (name, self.seen[name]):
                    raise OSError(5, f"injected {name}")
                return real(*a, **k)
            return call

    def publish(self, fail=None):
        try:
            return hs._publish_target(self.efd, self.ev, self.new, fs=self.FS(fail))
        except Exception as e:  # a crash is not an outcome
            self.fail(f"_publish_target raised {e!r}")

    def test_success_writes_both_byte_identical(self):
        self.assertEqual(self.publish(), "")
        self.assertEqual(self.files(), [self.new, self.new])

    def test_each_failure_is_its_own_state_and_never_success(self):
        # fsync calls in order: 1 the evidence dir after the unlink; 2 recovery.json; 3 exec_root;
        # 4 the copy; 5 the evidence dir after the copy's rename.
        rows = [(("unlink", 1), "the old copy could not be invalidated", [self.old, self.old]),
                (("fsync", 1), "the old copy could not be invalidated", [self.old, None]),
                (("open", 1), "recovery.json not written", [self.old, None]),
                (("write", 1), "recovery.json not written", [self.old, None]),
                (("fsync", 2), "recovery.json not written", [self.old, None]),
                (("rename", 1), "recovery.json not written", [self.old, None]),
                (("fsync", 3), "recovery.json written, its durability uncertain", [self.new, None]),
                (("open", 2), "stop target not published", [self.new, None]),
                (("write", 2), "stop target not published", [self.new, None]),
                (("fsync", 4), "stop target not published", [self.new, None]),
                (("rename", 2), "stop target not published", [self.new, None]),
                (("fsync", 5), "stop target published, its durability uncertain", [self.new, self.new])]
        for fail, words, after in rows:
            with self.subTest(fail=fail):
                for where in (self.exec + "/recovery.json", self.ev + "/stop-target.json"):
                    if os.path.exists(where):
                        os.unlink(where)
                    with open(where, "wb") as f:
                        f.write(self.old)
                why = self.publish(fail)
                self.assertIn(words, why)
                self.assertEqual(self.files(), after)
                self.assertEqual([n for n in os.listdir(self.exec) + os.listdir(self.ev) if n.endswith(".tmp")], [],
                                 "no temporary file is left")

    def test_a_rerun_after_any_crash_invalidates_then_republishes(self):
        """A crash leaves one of the states above; the rerun (under the lock)
        starts again from step one and ends with both new and identical."""
        for fail in (("fsync", 1), ("fsync", 3), ("fsync", 5)):
            with self.subTest(fail=fail):
                self.publish(fail)
                self.new = self.new + b" "
                self.assertEqual(self.publish(), "")
                self.assertEqual(self.files(), [self.new, self.new])


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

    def test_a_resolved_incident_is_never_acted_on_again(self):
        """The operator's resolution is final for that incident: _act
        neither rewrites nor stops for it, whoever calls it."""
        d = f"{self.ev}/incident-r1"
        os.mkdir(d)
        with open(f"{d}/detected.json", "wb") as f:
            f.write(pe.canonical({"run_id": "r1", "at": "x", "failing": ["P03"], "pending": ["rewrite", "stop"]}))
        with open(f"{d}/events.jsonl", "w") as f:
            f.write(json.dumps({"event": "resolved", "at": "x", "evidence": "e", "reason": "r"}) + "\n")
        engine = Engine([True, False])
        self.assertTrue(self.act(TARGET, engine, []))
        self.assertEqual(engine.stopped, [])
        with open(self.conf) as f:
            self.assertIn("delegation", json.load(f))

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


class ModeActTest(InProcess):
    """_act's eligibility for stop_not_required: a prospective run's only,
    and only when the engine AFFIRMS that neither the certified target nor
    anything under the local router's name runs."""

    def setUp(self):
        super().setUp()
        self.ev, self.conf = f"{self.d}/ev", f"{self.d}/conf/router.json"
        os.mkdir(self.ev, 0o755)
        os.chmod(self.ev, 0o755)
        os.mkdir(f"{self.d}/conf", 0o755)
        with open(self.conf, "w") as f:
            f.write('{"state_dir": "/s"}\n')                       # observed: no delegation

    def kinds(self, target, states, mode, named):
        said = []
        hs._act(self.ev, self.conf, target, "r1", "2026-10-15T03:00:00Z", ["P03"], Engine(states), said, mode=mode,
                router_running=lambda: named)
        with open(f"{self.ev}/incident-r1/events.jsonl") as f:
            return [json.loads(l) for l in f]

    def test_a_weekly_act_never_records_stop_not_required(self):
        """The config observed clean, no target, nothing under the name:
        still a weekly run's stop that was not attempted."""
        events = self.kinds(None, [], hs.MODES[0], False)
        self.assertEqual([e["event"] for e in events], ["rewrite_ok", "stop_not_attempted"])
        self.assertEqual(events[0].get("observed"), hs.NO_DELEGATION)

    def test_an_engine_that_cannot_say_about_the_local_router_is_never_not_required(self):
        events = self.kinds(None, [], hs.MODES[1], None)
        self.assertEqual([e["event"] for e in events], ["rewrite_ok", "stop_not_attempted"])
        self.assertIn("cannot say whether the local router runs", events[-1]["reason"])

    def test_an_engine_that_cannot_say_about_the_target_is_never_not_required(self):
        events = self.kinds(TARGET, [None], hs.MODES[1], False)
        self.assertEqual([e["event"] for e in events], ["rewrite_ok", "stop_not_attempted"])
        self.assertIn("cannot say whether it runs", events[-1]["reason"])

    def test_affirmed_absence_on_both_is_not_required(self):
        events = self.kinds(TARGET, [False], hs.MODES[1], False)
        self.assertEqual([e["event"] for e in events], ["rewrite_ok", "stop_not_required"])


class DecideModeTest(InProcess):
    """The parent's decision for an abandoned run reads ITS context's mode:
    stop_not_required closes a prospective run's incident only, and only
    over a history whose every rewrite observed no delegation."""

    RID = "wold"

    def setUp(self):
        super().setUp()
        self.h = Host(self.d)
        self.addCleanup(self.h.sock.close)
        with open(self.h.conf, "w") as f:
            f.write('{"state_dir": "/s"}\n')
        self.h.containers({TARGET: True})

    def decide(self, mode, history):
        self.h.abandoned(self.RID, FAIL3, mode=mode)
        d = f"{self.h.ev}/incident-{self.RID}"
        os.mkdir(d, 0o755)
        det = {"run_id": self.RID, "at": "x", "failing": ["P03"], "pending": ["rewrite", "stop"]}
        with open(f"{d}/detected.json", "wb") as f:
            f.write(pe.canonical(dict(det, **({"mode": mode} if mode == hs.MODES[1] else {}))))
        with open(f"{d}/events.jsonl", "w") as f:
            f.write("".join(json.dumps(dict(e, at="x")) + "\n" for e in history))
        said = []
        efd = os.open(self.h.exec, os.O_RDONLY | os.O_DIRECTORY)
        try:
            got = hs._decide(efd, f"run-{self.RID}",
                             {"engine": "unix://" + self.h.sock_path, "docker": self.h.docker, "exec_root": self.h.exec},
                             said)
        finally:
            os.close(efd)
        return got, "\n".join(said)

    OBSERVED = {"event": "rewrite_ok", "observed": hs.NO_DELEGATION}
    NOT_REQUIRED = {"event": "stop_not_required", "reason": "r"}

    def test_a_prospective_run_s_closed_incident_is_done_for_an_ordinary_run_too(self):
        got, said = self.decide(hs.MODES[1], [self.OBSERVED, self.NOT_REQUIRED])
        self.assertEqual(got, (hs.EXIT_INCIDENT, None, False), said)
        self.assertIn("already shows every effect done", said)
        self.assertEqual(self.h.stops(), [])

    def test_stop_not_required_never_closes_a_weekly_run_s_incident(self):
        got, said = self.decide(hs.MODES[0], [self.OBSERVED, self.NOT_REQUIRED])
        self.assertNotIn("already shows every effect done", said)
        self.assertEqual(self.h.stops(), [TARGET])

    def test_a_history_with_a_live_removal_is_never_closed_by_stop_not_required(self):
        got, said = self.decide(hs.MODES[1], [{"event": "rewrite_ok"}, self.OBSERVED, self.NOT_REQUIRED])
        self.assertNotIn("already shows every effect done", said)
        self.assertEqual(self.h.stops(), [TARGET])


class EngineTest(unittest.TestCase):
    """_Engine.running against a recorded docker: an answer only when the
    engine affirms one."""

    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        d = os.path.realpath(t.name)
        self.state, log, self.docker = f"{d}/s.json", f"{d}/l", f"{d}/docker"
        with open(self.docker, "w") as f:
            f.write((DOCKER % (self.state, log, "/c")).replace("#!PYTHON", "#!" + sys.executable))
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

    def fs(self, entries, links=None):
        """A fake tree: path -> (uid, mode), with `links` mapping each link to
        its textual target (the tree's own link.py points at os.py beside it)."""
        if "/usr/lib/python3/link.py" in entries:
            links = dict({"/usr/lib/python3/link.py": "os.py"}, **(links or {}))
        return FakeFS(entries, links)

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
        fx = self.fs(self.tree())
        self.assertEqual(hs.closure_problems(self.PATHS, **fx.kw()), [])

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
                fx = self.fs(self.tree(**over))
                bad = hs.closure_problems(self.PATHS, **fx.kw())
                self.assertEqual([b.split(" ")[0] for b in bad], list(over), bad)
        fx = self.fs({k: v for k, v in self.tree().items() if k != "/usr/lib/libssl.so.3"})
        self.assertTrue(hs.closure_problems(self.PATHS, **fx.kw()), "a missing dependency is a problem")

    def test_a_link_is_judged_by_its_target_and_the_targets_directories_too(self):
        out = {"/opt": (0, self.D), "/opt/w": (501, stat.S_IFDIR | 0o777), "/opt/w/libssl.so.3": (501, self.F)}
        rows = {"a root-owned link in the tree to a writable file outside it": (
                    {"/usr/lib/python3/evil.py": (0, self.L)}, {"/usr/lib/python3/evil.py": "/opt/w/libssl.so.3"}),
                "a linked library that is a root-owned link to a writable file": (
                    {"/usr/lib/libssl.so.3": (0, self.L)}, {"/usr/lib/libssl.so.3": "/opt/w/libssl.so.3"}),
                "a parent that is a link to a writable directory": (
                    {"/Library": (0, self.L)}, {"/Library": "/opt/w"}),
                "a closure directory that is a link to a tree holding a writable file": (
                    {"/Library/Developer/CommandLineTools": (0, self.L), "/opt/clt": (0, self.D),
                     "/opt/clt/bin": (0, self.D), "/opt/clt/bin/clang": (0, stat.S_IFREG | 0o666)},
                    {"/Library/Developer/CommandLineTools": "/opt/clt"})}
        for what, (over, links) in rows.items():
            with self.subTest(what):
                tree = dict(self.tree(**over), **out)
                fx = self.fs(tree, links)
                bad = hs.closure_problems(self.PATHS, **fx.kw())
                self.assertTrue(any(b.startswith(("/opt/w", "/opt/clt")) for b in bad), bad)

    def test_a_link_cycle_ends(self):
        tree = dict(self.tree(**{"/usr/lib/python3/a": (0, self.L), "/usr/lib/python3/b": (0, self.L)}))
        fx = self.fs(tree, {"/usr/lib/python3/a": "/usr/lib/python3/b",
                                               "/usr/lib/python3/b": "/usr/lib/python3/a"})
        self.assertEqual(hs.closure_problems(self.PATHS, **fx.kw()), [])

    def test_on_macos_only_a_discovered_system_library_may_be_in_the_shared_cache(self):
        tree = {k: v for k, v in self.tree().items() if k != "/usr/lib/libssl.so.3"}
        fx = self.fs(tree)
        closure = {hs.REQUIRED: ["/usr/lib/python3"], hs.LIBRARIES: ["/usr/lib/libssl.so.3"], hs.OPTIONAL: []}
        self.assertEqual(hs.closure_problems(closure, **fx.kw(), platform="darwin"), [])
        self.assertEqual(hs.closure_problems(closure, **fx.kw(), platform="linux"),
                         ["/usr/lib/libssl.so.3: absent"])
        for absent in ("/usr/lib/absent-python-tree", "/usr/lib/absent-python.zip", "/System/Library/absent"):
            with self.subTest(absent=absent):
                required = dict(closure, **{hs.REQUIRED: ["/usr/lib/python3", absent]})
                self.assertIn(f"{absent}: absent", hs.closure_problems(required, **fx.kw(),
                                                                         platform="darwin"),
                              "a required path is never excused as cached")

    def test_an_absent_optional_zip_is_judged_by_its_would_be_place(self):
        zipped = "/usr/lib/python313.zip"
        closure = {hs.REQUIRED: ["/usr/lib/python3"], hs.LIBRARIES: [], hs.OPTIONAL: [zipped]}
        fx = self.fs(self.tree())
        self.assertEqual(hs.closure_problems(closure, **fx.kw()), [], "absent, under root's directories")
        own = {hs.REQUIRED: ["/usr/lib/python3"], hs.LIBRARIES: [], hs.OPTIONAL: ["/opt/pyzip/python313.zip"]}
        fx = self.fs(self.tree(**{"/opt": (0, self.D), "/opt/pyzip": (501, self.D)}))
        self.assertEqual(hs.closure_problems(own, **fx.kw()),
                         ["/opt/pyzip is not root-owned, or is writable by others"],
                         "whoever owns the would-be place could plant it, though no required path is there")
        fx = self.fs(self.tree(**{zipped: (0, stat.S_IFREG | 0o666)}))
        self.assertEqual(hs.closure_problems(closure, **fx.kw()),
                         [f"{zipped} is not root-owned, or is writable by others"], "present, it is judged whole")

    def test_this_hosts_own_interpreter_has_no_closure_problem(self):
        """The real discovery on a healthy interpreter (an absent zip on its
        path is ordinary): no finding, so the weekly job does not refuse."""
        if not os.path.exists("/usr/bin/ldd") or sys.platform != "linux":
            self.skipTest("measured on Linux")
        py, sh = os.path.realpath("/usr/bin/python3"), os.path.realpath("/bin/sh")
        if not all(os.path.exists(x) and os.stat(x).st_uid == 0 for x in (py, sh)):
            self.skipTest("this host's interpreter is not root's")
        closure = hs.startup_closure(py, sh)
        self.assertTrue(closure[hs.LIBRARIES])
        self.assertEqual(hs.closure_problems(closure), [])

    @staticmethod
    def elf(path, kind):
        """A minimal 64-bit little-endian ELF, `kind`: "static" (ET_EXEC, one
        PT_LOAD), "dynamic" (PT_INTERP), "shared" (ET_DYN with a dynamic
        section naming a needed library, no interpreter: an extension module)
        or "static-pie" (ET_DYN with a dynamic section naming none)."""
        import struct
        dyn_entries = {"shared": [(1, 1), (0, 0)], "static-pie": [(5, 0), (0, 0)]}.get(kind)
        etype = 2 if kind in ("static", "dynamic") else 3
        phs = [(3 if kind == "dynamic" else 1, 0, 0, 0)]
        dyn_off = 64 + 56 * 2
        if dyn_entries is not None:
            phs.append((2, dyn_off, 16 * len(dyn_entries), 0))
        head = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9) + struct.pack("<HHIQQQIHHHHHH", etype, 62, 1, 0, 64, 0, 0,
                                                                         64, 56, len(phs), 0, 0, 0)
        body = b"".join(struct.pack("<IIQQQQQQ", t, 0, off, 0, 0, size, size, 0) for t, off, size, _ in phs)
        body = body.ljust(56 * 2, b"\0")
        dyn = b"".join(struct.pack("<qQ", tag, val) for tag, val in dyn_entries or [])
        with open(path, "wb") as f:
            f.write(head + body + dyn)

    def test_only_a_binary_proven_to_link_nothing_may_be_unlisted(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        made = {k: os.path.join(t.name, k) for k in ("static", "static-pie", "dynamic", "shared")}
        for kind, path in made.items():
            self.elf(path, kind)
        text = os.path.join(t.name, "text")
        with open(text, "w") as f:
            f.write("#!/bin/sh\n")
        self.assertEqual({k: hs._links_nothing(p) for k, p in made.items()},
                         {"static": True, "static-pie": True, "dynamic": False, "shared": False})
        self.assertIsNone(hs._links_nothing(text))
        not_dyn = b"\tnot a dynamic executable\n"
        self.assertEqual(hs._ldd_libraries(made["static"], b"", not_dyn, 1), [], "a static ELF links nothing")
        self.assertEqual(hs._ldd_libraries(made["static-pie"], b"\tstatically linked\n", b"", 0), [])
        good = (b"\tlinux-vdso.so.1 (0x1)\n\tlibc.so.6 => /lib/libc.so.6 (0x2)\n"
                b"\t/lib/ld-linux-aarch64.so.1 (0x3)\n")
        self.assertEqual(hs._ldd_libraries(made["dynamic"], good, b"", 0),
                         ["/lib/libc.so.6", "/lib/ld-linux-aarch64.so.1"], "the loader is part of the closure")
        refused = [(made["shared"], b"", 2, "an extension module with dependencies, its listing failed"),
                   (made["dynamic"], b"", 2, "a dynamic binary, its listing failed"),
                   (text, b"", 1, "not an ELF"),
                   (text, b"\tstatically linked\n", 0, "not an ELF, though the text says static"),
                   (made["shared"], b"\tstatically linked\n", 0, "the text says static, the binary needs a library"),
                   (made["dynamic"], b"\tlibz.so.1 => not found\n", 0, "an unresolved library"),
                   (made["dynamic"], b"", 0, "nothing listed for a dynamic binary"),
                   (made["dynamic"], b"\tsomething else\n", 0, "unexpected output"),
                   (text, good, 1, "a failed listing")]
        for b, out, rc, what in refused:
            with self.subTest(what):
                with self.assertRaises(hs.Tooling):
                    hs._ldd_libraries(b, out, not_dyn, rc)
        for out, rc in ((b"x:\n", 1), (b"x:\n\t/usr/lib/libSystem.B.dylib (compat 1)\n", 1),
                        (b"x:\n\t@rpath/libz.dylib (compat 1)\n", 0), (b"x:\n", 0)):
            with self.subTest(out=out, rc=rc):
                with self.assertRaises(hs.Tooling):
                    hs._otool_libraries(made["dynamic"], out, b"", rc)
        self.assertEqual(hs._otool_libraries(made["dynamic"], b"x:\n\t/usr/lib/libSystem.B.dylib (compat 1)\n", b"", 0),
                         ["/usr/lib/libSystem.B.dylib"])

    def test_this_hosts_extension_modules_are_not_taken_for_static_binaries(self):
        import glob
        mods = glob.glob(os.path.join(sysconfig_dynload(), "_ssl*.so"))
        if not mods:
            self.skipTest("no _ssl extension module here")
        self.assertIs(hs._links_nothing(mods[0]), False)

    def test_the_fallback_dockers_closure_is_the_binary_and_everything_it_links(self):
        if not os.path.exists("/usr/bin/ldd"):
            self.skipTest("no ldd here")
        sh = os.path.realpath("/bin/sh")
        closure = hs._docker_closure(sh)
        self.assertEqual(closure[hs.REQUIRED], [sh])
        found = closure[hs.LIBRARIES]
        self.assertTrue(any(os.path.basename(p).startswith("libc.") for p in found), found)
        self.assertTrue(any("/ld-linux" in p for p in found), found)

    def test_discovery_names_the_library_its_extension_modules_and_every_linked_library(self):
        found = sum(hs.startup_closure(os.path.realpath(sys.executable), os.path.realpath("/bin/sh")).values(), [])
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
        for name, value in (("XCODE_SELECT", xs), ("_macho_closure", lambda images, main, *a, **k: ([], []))):
            self.addCleanup(setattr, hs, name, getattr(hs, name))
            setattr(hs, name, value)
        found = sum(hs.startup_closure(os.path.realpath(sys.executable), os.path.realpath("/bin/sh"),
                                       platform="darwin").values(), [])
        self.assertIn("/Library/Developer/CommandLineTools", found)


def sysconfig_dynload():
    import sysconfig
    return sysconfig.get_config_var("DESTSHARED") or os.path.join(sysconfig.get_paths()["platstdlib"], "lib-dynload")


class GrammarDriftTest(unittest.TestCase):
    """The writer imports nothing of the library, so its copies of the
    grammars are held equal to the library's here."""

    def test_the_incident_grammar_is_partition_incidents(self):
        self.assertEqual((hs.EVENT_GRAMMAR, hs._COMMON, hs.ACTIONS, hs.DETECTED_REQUIRED, hs.DETECTED_OPTIONAL),
                         (pi.EVENT_GRAMMAR, pi._COMMON, pi.ACTIONS, pi.DETECTED_REQUIRED, pi.DETECTED_OPTIONAL))
        good = {"rewrite_ok": {}, "rewrite_failed": {"reason": "r"}, "stop_ok": {"id": "i", "observed": "o"},
                "stop_failed": {"reason": "r"}, "stop_not_attempted": {"reason": "r"},
                "stop_not_required": {"reason": "r"},
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

    def test_the_stop_targets_grammar_and_names_are_verifys_and_the_jobs(self):
        import partition_activation as pa
        import partition_job as pj
        import partition_setup as ps
        self.assertEqual((hs.RECOVERY_SCHEMA, hs.RECOVERY_MEMBERS), (ps.TARGET_SCHEMA, ps.TARGET_MEMBERS))
        self.assertEqual((hs.STOP_TARGET, hs.ACTIVATION), (ps.STOP_TARGET, ps.ACTIVATION))
        self.assertEqual(hs.ACTIVATION, pj.ACTIVATION)
        live = {"Id": "c" * 64, "Created": "2026-01-01T00:00:00Z", "Image": "i", "Config": {"User": "u",
                "Env": ["B=2", "A=1"]}, "HostConfig": {"NetworkMode": "none", "RestartPolicy": {"Name": "no"}},
                "Mounts": [{"Type": "bind", "Source": "/b", "Destination": "/b", "RW": False},
                           {"Type": "bind", "Source": "/a", "Destination": "/x", "RW": True}], "State": {}}
        self.assertEqual(hs.inspect_projection(live), pa.inspect_projection(live))
        self.assertEqual(hs._canonical(hs.inspect_projection(live)), pe.canonical(pa.inspect_projection(live)))

    def test_the_writer_only_names_are_outside_the_stores_reach(self):
        import partition_setup as ps
        import partition_store as pst
        for name in (hs.STOP_TARGET, hs.ACTIVATION):
            with self.subTest(name=name):
                self.assertFalse(ps.evidence_name_ok(name))
                self.assertIsNone(re.fullmatch(r"partition-[A-Za-z0-9._-]{1,64}\.json", name),
                                  "no run id can make a document of that name")
                with tempfile.TemporaryDirectory() as t:
                    d = os.path.realpath(t)
                    store = pst.RootedStore(evidence_dir=d, run_dir=f"{d}/run-r1", live_config=f"{d}/c.json")
                    with self.assertRaises(pst.Refused):
                        store.new_file(f"{d}/{name}", b"{}")
                    self.assertEqual(os.listdir(d), [])

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


class ProspectiveWriterTest(unittest.TestCase):
    """A2: partition-weekly --prospective, with the local router stopped.
    The refusals come before W2 and write nothing; a pass records no stop
    target; a fail-stop's stop is not required only when nothing in the
    incident's history, and nothing running, could be signing."""

    NAME = "ex-up"

    def setUp(self):
        t = tempfile.mkdtemp(dir="/tmp", prefix="pw")
        self.addCleanup(WriterTest._rm, t)
        self.h = Host(os.path.realpath(t))
        self.addCleanup(self.h.sock.close)
        with open(self.h.conf, "w") as f:
            f.write(json.dumps({"state_dir": "/s"}, indent=2) + "\n")       # pre-activation: no delegation
        self.h.activation(pe.canonical({"spec": {"name": self.NAME}, "host": "alpha",
                                        "final_config_path": self.h.conf}))
        self.h.containers({})                                             # nothing runs: [1] is stopped

    def run_a2(self):
        argv = self.h.argv() + ["--prospective"]
        return subprocess.run(argv, capture_output=True, text=True, timeout=120)

    def snapshot(self):
        """Every persistent thing a refusal must leave as it was. The empty
        lock file is the lock itself, made when it is first taken, before any
        guard can run, and is not compared."""
        out = {}
        for d in (self.h.exec, self.h.ev, os.path.dirname(self.h.conf)):
            for root, dirs, files in os.walk(d):
                for n in files:
                    p = os.path.join(root, n)
                    if p == os.path.join(self.h.exec, "lock"):
                        continue
                    with open(p, "rb") as f:
                        out[p] = f.read()
                for n in dirs:
                    out[os.path.join(root, n)] = None
        return out

    def refused(self, words):
        before = self.snapshot()
        p = self.run_a2()
        self.assertEqual(p.returncode, hs.EXIT_HANDOFF, p.stdout + p.stderr)
        self.assertIn("refused, nothing written", p.stdout + p.stderr)
        self.assertIn(words, p.stdout + p.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertIsNone(self.h.side_read("child-started.json"))
        self.assertEqual(self.h.stops(), [])

    def kinds(self):
        return [e["event"] for e in WriterTest.event_records(self)]

    def test_a_passing_a2_exits_zero_and_records_no_stop_target(self):
        self.h.recovery()                         # an earlier certification, its router no longer running
        rec = open(f"{self.h.exec}/recovery.json", "rb").read()
        self.h.plan([["expect", B], ["evidence", B, PASS], ["outcome", 0, None]])
        p = self.run_a2()
        self.assertEqual(p.returncode, hs.EXIT_PASS, p.stdout + p.stderr)
        self.assertIn("A2 passed", p.stdout + p.stderr)
        sha = hashlib.sha256(open(self.h.conf, "rb").read()).hexdigest()
        self.assertIn(f"pre-activation live config sha256 {sha}", p.stdout + p.stderr)
        self.assertIn("the host's live config file, not the container's view, must parse as a JSON object with no "
                      "delegation member (if it carries one, or cannot be read or parsed, stop", p.stdout + p.stderr)
        self.assertEqual(open(f"{self.h.exec}/recovery.json", "rb").read(), rec)
        self.assertFalse(os.path.exists(f"{self.h.ev}/stop-target.json"))
        self.assertEqual((self.h.runs(), self.h.stops()), ([], []))
        ctx = self.h.side_read("context.json") or {}
        self.assertIn(ctx.get("mode", "prospective"), ("prospective",))

    def test_a_live_delegation_refuses_before_anything(self):
        with open(self.h.conf, "w") as f:
            f.write(json.dumps({"state_dir": "/s", "delegation": {}}, indent=2) + "\n")
        self.refused("already carries delegation")

    def test_a_running_local_router_refuses_before_anything(self):
        """G4': no timestamp can show which config a running one adopted."""
        self.h.containers({self.NAME: True})
        self.refused("A2 runs with the local router stopped")

    def test_a_running_certified_router_refuses_before_anything(self):
        self.h.recovery()
        self.h.containers({TARGET: True})
        self.refused("the weekly job certified")

    def test_an_engine_that_cannot_say_refuses(self):
        self.h.containers({"_inspect_fail": True, "_ps_fail": True})
        self.refused("cannot say")

    def test_a_run_awaiting_a_decision_refuses_and_is_left_to_the_ordinary_run(self):
        self.h.abandoned("old", verdicts=FAIL3)
        self.refused("awaits a decision")

    def test_a_fail_stop_with_nothing_live_needs_no_stop(self):
        """The history holds only observed rewrites, nothing runs."""
        self.h.plan([["expect", B], ["evidence", B, FAIL3], ["outcome", 1, None]])
        conf = open(self.h.conf, "rb").read()
        p = self.run_a2()
        self.assertEqual(p.returncode, hs.EXIT_INCIDENT, p.stdout + p.stderr)
        self.assertEqual(self.kinds(), ["rewrite_ok", "stop_not_required"])
        self.assertEqual(open(self.h.conf, "rb").read(), conf)
        self.assertEqual(self.h.runs(), [])

    def test_a_live_removal_in_the_child_keeps_the_stop_pending(self):
        """Across the child's act and the writer's own decision on
        the same invocation: the child removed a live delegation; the writer
        then observes none, and the stop is still not 'not required'."""
        self.h.plan([["expect", B], ["evidence", B, FAIL3], ["detected", ["P03"]],
                     ["events", '{"at":"x","event":"rewrite_ok"}\n'
                                '{"at":"x","event":"stop_not_attempted","reason":"no target"}\n'],
                     ["outcome", 1, None]])
        p = self.run_a2()
        self.assertEqual(p.returncode, hs.EXIT_INCIDENT, p.stdout + p.stderr)
        kinds = self.kinds()
        self.assertNotIn("stop_not_required", kinds)
        self.assertEqual(kinds[-1], "stop_not_attempted")
        self.assertEqual(len(self.h.runs()), 1, "kept: the stop is not shown done")

    def test_a2_that_does_not_pass_prints_the_back_out(self):
        """A2's exit 3 after the stop names the command that brings
        the stopped router back on its unchanged live config."""
        self.h.plan([["expect", B], ["evidence", B, PASS], ["outcome", 2, None]])
        p = self.run_a2()
        self.assertEqual(p.returncode, hs.EXIT_HANDOFF, p.stdout + p.stderr)
        sha = hashlib.sha256(open(self.h.conf, "rb").read()).hexdigest()
        self.assertIn(f"back-out: the local router was stopped for A2 and its live config is unchanged "
                      f"(its sha256 {sha}): docker start {self.NAME}", p.stdout + p.stderr)

    def test_g1_refusing_a_live_delegation_names_no_start_on_it(self):
        """[1] stopped and the live config carrying delegation is the state
        after A3's place: the back-out is install's, gated on the host file,
        and never "unchanged: docker start"."""
        with open(self.h.conf, "w") as f:
            f.write(json.dumps({"state_dir": "/s", "delegation": {}}, indent=2) + "\n")
        p = self.run_a2()
        out = p.stdout + p.stderr
        self.assertEqual(p.returncode, hs.EXIT_HANDOFF, out)
        self.assertNotIn("unchanged", out)
        self.assertNotIn(f"docker start {self.NAME}", out)
        self.assertIn("do not start the local router on it", out)
        self.assertIn("must parse as a JSON object with no delegation member", out)

    def test_a_refusal_before_g1_read_the_config_names_no_start(self):
        """A1's record for another host, a live config that is not an
        object, or a refusal before the guards: nothing showed the live
        config is pre-activation, so nothing says it is unchanged."""
        def other_host():
            self.h.activation(pe.canonical({"spec": {"name": self.NAME}, "host": "beta",
                                            "final_config_path": self.h.conf}))

        def not_an_object():
            with open(self.h.conf, "w") as f:
                f.write("[]\n")
        for label, arrange, argv in (("another host's A1", other_host, None),
                                     ("not an object", not_an_object, None),
                                     ("A1's digest wrong", lambda: None, dict(activation_digest="0" * 64))):
            with self.subTest(label):
                self.setUp()
                arrange()
                p = subprocess.run(self.h.argv(**(argv or {})) + ["--prospective"], capture_output=True, text=True,
                                   timeout=120)
                out = p.stdout + p.stderr
                self.assertNotEqual(p.returncode, hs.EXIT_PASS, out)
                self.assertNotIn("unchanged", out)
                self.assertNotIn(f"docker start {self.NAME}", out)
                self.assertIn("did not show the live config is pre-activation, so it names no start", out)

    def test_a_refusal_with_the_router_running_prints_no_start(self):
        self.h.containers({self.NAME: True})
        p = self.run_a2()
        self.assertNotIn("docker start", p.stdout + p.stderr)

    def test_a_live_removal_s_remedy_is_resolved_only(self):
        """After a live removal no ordinary run can close it."""
        self.h.plan([["expect", B], ["evidence", B, FAIL3], ["detected", ["P03"]],
                     ["events", '{"at":"x","event":"rewrite_ok"}\n'
                                '{"at":"x","event":"stop_not_attempted","reason":"no target"}\n'],
                     ["outcome", 1, None]])
        p = self.run_a2()
        self.assertIn("record resolved; a delegation was live during this incident", p.stdout + p.stderr)
        self.assertIn("then docker start", p.stdout + p.stderr)          # the kept run's remedy comes first

    def test_a_local_router_started_during_the_run_is_never_stop_not_required(self):
        """Delegation placed, [1] restarted on it, removed again
        without a restart: the file says none, a router under the name runs."""
        self.h.plan([["expect", B], ["evidence", B, FAIL3], ["containers", {self.NAME: True}],
                     ["outcome", 1, None]])
        p = self.run_a2()
        self.assertEqual(p.returncode, hs.EXIT_INCIDENT, p.stdout + p.stderr)
        self.assertEqual(self.kinds(), ["rewrite_ok", "stop_not_attempted"])
        self.assertEqual(len(self.h.runs()), 1)
        self.assertEqual(self.h.stops(), [], "never stopped by name")


class ContextModeTest(unittest.TestCase):
    """The run's mode is read from its context only: a /1 context (before
    the mode was recorded) is a weekly run's; a /2 context names its mode,
    and any other value is no context at all."""

    def read(self, doc):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        with open(os.path.join(d, "context.json"), "wb") as f:
            f.write(pe.canonical(doc))
        fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
        try:
            return hs._context(fd)
        finally:
            os.close(fd)

    def test_v1_is_weekly_v2_names_its_mode_and_nothing_else_is_a_context(self):
        base = {"run_id": "r1", "host": "alpha", "started_at": "x", "evidence_dir": "/e", "live_config_path": "/c",
                "router_container_id": None, "engine": "unix:///s", "docker": "/d"}
        self.assertEqual(self.read(dict(base, schema=hs.CONTEXT_SCHEMA_V1))["mode"], "weekly")
        self.assertEqual(self.read(dict(base, schema=hs.CONTEXT_SCHEMA, mode="prospective"))["mode"], "prospective")
        self.assertIsNone(self.read(dict(base, schema=hs.CONTEXT_SCHEMA, mode="other")))
        self.assertIsNone(self.read(dict(base, schema=hs.CONTEXT_SCHEMA)))
        self.assertIsNone(self.read(dict(base, schema=hs.CONTEXT_SCHEMA_V1, mode="prospective")))
