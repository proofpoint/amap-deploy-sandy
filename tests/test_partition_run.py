"""partition_run and partition_weekly: the weekly job's child, from the
provisioned bundle, under its writer's lock.

The launcher is EXECUTED from a copy of exactly partition_weekly.closure's
files, with `-I -S -B`, to prove the bundle's import closure. The child's run
uses a real temporary tree for every path the probes stat and the store
writes, and a fake engine that answers by script and argv."""

import json
import os
import re
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import types
import unittest
from pathlib import Path

import hub_runtime as hr
import partition_probe as pp
import partition_run as pr
import partition_store as pst
import router_health as rh
from test_partition_probe import EMAIL, Engine, proc, rebased

REPO = Path(__file__).resolve().parent.parent
CLOSURE = [l for l in (REPO / "partition_weekly.closure").read_text().splitlines() if l]


class ClosureTest(unittest.TestCase):
    """The cold start: the bundle and the interpreter's own library, nothing
    else on the path, and no bytecode written into the bundle."""

    def test_the_launcher_loads_exactly_the_closure_from_the_bundle(self):
        with tempfile.TemporaryDirectory() as t:
            bundle = os.path.join(os.path.realpath(t), "bundle")
            os.mkdir(bundle)
            for f in CLOSURE + ["partition_weekly.closure"]:
                shutil.copy(REPO / f, bundle)
            p = subprocess.run([sys.executable, "-I", "-S", "-B", "-v", os.path.join(bundle, "partition_weekly.py")],
                               capture_output=True, text=True, timeout=120, cwd=t, env={})
            self.assertEqual(p.returncode, pr.INCOMPLETE, p.stderr[-2000:])
            loaded = set(re.findall(r"code object from '?([^'\s]+\.py)'?", p.stderr))
            stdlib = os.path.realpath(sysconfig.get_paths()["stdlib"])
            outside = sorted(f for f in loaded if not os.path.realpath(f).startswith((bundle + "/", stdlib + "/")))
            self.assertEqual(outside, [], "nothing outside the bundle and the interpreter's own library")
            mine = {os.path.basename(f) for f in loaded if os.path.realpath(f).startswith(bundle + "/")}
            mine.add("partition_weekly.py")  # the entry itself runs as __main__, not as an import
            self.assertEqual(mine, set(CLOSURE), "the bundle's imports are exactly the closure list")
            self.assertFalse(any(d == "__pycache__" for _, ds, _ in os.walk(bundle) for d in ds), "no bytecode written")

    def test_nothing_the_child_runs_unlocks_the_runs_lock(self):
        """The child holds its writer's lock descriptor for its whole life.
        Its own modules never call flock or lockf, nor name the unlock; the
        one flock anywhere in the closure is secret_setup.Lock's, which locks
        a descriptor of its own on another file (an flock only ever releases
        its own open file description), and the child never uses it."""
        import ast
        sites = []
        for f in CLOSURE:
            tree = ast.parse((REPO / f).read_text(encoding="utf-8"))
            for fn in ast.walk(tree):
                if isinstance(fn, (ast.FunctionDef, ast.ClassDef)):
                    for node in ast.walk(fn):
                        if isinstance(node, ast.Attribute) and node.attr in ("flock", "lockf", "LOCK_UN"):
                            sites.append((f, fn.name, node.attr))
        own = {"partition_weekly.py", "partition_run.py", "partition_store.py"}
        self.assertEqual([x for x in sites if x[0] in own], [])
        self.assertEqual(sorted({(f, a) for f, _, a in sites}), [("secret_setup.py", "flock")])
        for f in own:
            src = (REPO / f).read_text(encoding="utf-8")
            self.assertNotIn("ss.Lock", src, f)
            self.assertNotIn("secret_setup", src, f)

    def test_the_closure_names_only_files_of_this_repository(self):
        for f in CLOSURE:
            self.assertTrue((REPO / f).is_file(), f)
            self.assertNotIn("/", f)


class RecordTest(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.run = os.path.realpath(t.name)
        self.store = pst.RootedStore(evidence_dir=self.run, run_dir=self.run, live_config=self.run + "/x")

    def write(self, raw):
        with open(os.path.join(self.run, "context.json"), "wb") as f:
            f.write(raw)

    def test_a_truncated_or_malformed_record_is_absent_never_repaired(self):
        for raw in (b'{"run_id": "r1"', b"[]", b'{"a": 1, "a": 2}', b"\xff\xfe", b""):
            with self.subTest(raw=raw):
                self.write(raw)
                self.assertIsInstance(pr.read_record(self.store, self.run + "/context.json"), rh.Unresolved)
        os.unlink(self.run + "/context.json")
        self.assertIn("absent", pr.read_record(self.store, self.run + "/context.json").reason)

    def test_a_whole_record_reads(self):
        self.write(b'{"run_id": "r1"}')
        self.assertEqual(pr.read_record(self.store, self.run + "/context.json"), {"run_id": "r1"})


class SelectionTest(unittest.TestCase):
    def test_a_slug_that_could_name_another_path_is_refused(self):
        doc = {"instances_dir": "/i", "selected_json": "/s/selected.json"}
        for slug in ("../x", "a/b", ".hidden", "", 7):
            with self.subTest(slug=slug):
                got = pr.selected_lanes(doc, read=lambda p, s=slug: json.dumps({"selected": [{"slug": s}]}).encode())
                self.assertIsInstance(got, rh.Unresolved)
        got = pr.selected_lanes(doc, read=lambda p: b'{"selected": [{"slug": "alpha"}]}')
        self.assertEqual(got, {"alpha": "/i/alpha/peer"})


class LockTest(unittest.TestCase):
    def test_only_the_runs_own_lock_descriptor_is_accepted(self):
        with tempfile.TemporaryDirectory() as t:
            lock, other = os.path.join(t, "lock"), os.path.join(t, "other")
            for p in (lock, other):
                open(p, "w").close()
            fd = os.open(lock, os.O_RDONLY)
            self.addCleanup(os.close, fd)
            pr.check_lock(fd, t)
            fd2 = os.open(other, os.O_RDONLY)
            self.addCleanup(os.close, fd2)
            with self.assertRaises(pr.ChildError):
                pr.check_lock(fd2, t)


class RunEngine(Engine):
    """Engine, with the inspects and the stop the child itself asks for."""

    def __init__(self, inspects, image_env):
        super().__init__()
        self.inspects, self.image_env, self.stopped = inspects, image_env, []
        self.walks = {"ex-up": "1 2101 2101\n", "ex-down": "1 2102 2102\n"}

    def __call__(self, argv):
        argv = list(argv)
        if argv[1:3] == ["inspect", "--type"]:
            self.seen.append(argv)
            doc = self.find(argv[-1])
            if doc is None:
                return proc(1, "")
            return proc(0, json.dumps(doc["State"]) if "--format" in argv else json.dumps([doc]))
        if argv[1] == "ps" and "--no-trunc" in argv:
            self.seen.append(argv)
            doc = self.find(argv[-1].split("=", 1)[1])
            return proc(0, "" if doc is None else doc.get("Id", "") + "\n")
        if argv[1:3] == ["image", "inspect"]:
            self.seen.append(argv)
            return proc(0, json.dumps(self.image_env))
        if argv[1] == "stop":
            self.seen.append(argv)
            self.stopped.append(argv[-1])
            self.find(argv[-1])["State"] = {"Running": False}
            return proc(0, "")
        return super().__call__(argv)

    def find(self, ref):
        """A container by name or by id, as the engine answers either."""
        return self.inspects.get(ref) or next((d for d in self.inspects.values() if d.get("Id") == ref), None)


class ChildTest(unittest.TestCase):
    """One run of the child over a real tree: the lock, the context, the
    approved document, the live config, the selection and the lanes."""
    TARGET = "f" * 64

    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        r = self.root = os.path.realpath(t.name)
        for d in ("exec/run-r1", "evidence", "conf", "sel", "instances/alpha/peer", "srv/hop", "opt/d7", "keys"):
            os.makedirs(os.path.join(r, d))
        open(f"{r}/exec/lock", "w").close()
        open(f"{r}/keys/signing.key", "w").close()
        self.live = f"{r}/conf/router.json"
        self.config = {"instances_dir": f"{r}/instances", "selected_json": f"{r}/sel/selected.json",
                       "hop": {"root": f"{r}/srv/hop", "link": "l1"},
                       "delegation": {"signing_key": {"path": f"{r}/keys/signing.key", "key_id": "k1"},
                                      "partition_verified": "r0:" + "a" * 64}}
        with open(self.live, "w") as f:
            f.write(json.dumps(self.config, indent=2) + "\n")
        with open(f"{r}/sel/selected.json", "w") as f:
            json.dump({"schema": 2, "selected": [{"slug": "alpha", "at": "x"}], "not_selected": []}, f)
        self.run_dir = f"{r}/exec/run-r1"
        self.context = {"schema": pr.CONTEXT_SCHEMA, "run_id": "r1", "host": "alpha",
                        "started_at": "2026-10-15T03:00:00Z", "evidence_dir": f"{r}/evidence",
                        "live_config_path": self.live, "router_container_id": self.TARGET,
                        "engine": "unix:///var/run/docker.sock", "docker": "/usr/bin/docker"}
        self.document = b'{"host_setup": {"schema": 1}}'
        self.email = rebased(EMAIL, r)
        self.email["mounts"][1]["source"] = f"{r}/srv/hop"
        mounts = [(f"{r}/srv/hop", False), (f"{r}/instances", False), (f"{r}/keys", True), (self.live, True)]
        self.router_live = {"Id": self.TARGET, "Name": "/ex-up", "Image": "sha256:" + "b" * 64, "State": {"Running": True},
                            "Config": {"User": "2101:2101", "Env": [f"ROUTER_CONFIG={self.live}", "ROUTER_INTERVAL=5"]},
                            "HostConfig": {"NetworkMode": "none", "RestartPolicy": {"Name": "unless-stopped"}},
                            "Mounts": [{"Type": "bind", "Source": s, "Destination": s, "RW": not ro} for s, ro in mounts]}
        self.inspects = {"ex-up": self.router_live, "ex-down": {"Id": "e" * 64, "State": {"Running": True}},
                         "alpha": {"State": {"Running": True}, "Config": {"Env": ["AMAP_PEER_DIR=/agent/peer"]},
                                   "Mounts": [{"Type": "bind", "Source": f"{r}/instances/alpha/peer",
                                               "Destination": "/agent/peer"}]}}
        self.engine = RunEngine(self.inspects, [])
        spec = types.SimpleNamespace(hops=[("l1", "upstream", "downstream", "X")], hub=object(),
                                     secrets=types.SimpleNamespace(volume="ex-secret"),
                                     runtime_of=lambda p: {"container": "ex-up"})
        for mod, name, value in ((pr.hs, "load_spec", lambda sec: spec), (pr.hr, "run_spec", lambda s, h: self.email),
                                 (pr.hr, "view", lambda e, env: {}), (pr.hr, "environment", lambda s, h: []),
                                 (pr.hr, "compare", lambda live, rendered, env: [])):
            self.addCleanup(setattr, mod, name, getattr(mod, name))
            setattr(mod, name, value)
        self.said = []

    def place(self, context=True, document=True):
        if context:
            with open(f"{self.run_dir}/context.json", "wb") as f:
                f.write(pr.canonical(self.context) if context is True else context)
        if document:
            with open(f"{self.run_dir}/document.json", "wb") as f:
                f.write(self.document)

    def run_it(self):
        fd = os.open(f"{self.root}/exec/lock", os.O_RDONLY)
        self.addCleanup(os.close, fd)
        try:
            return pr.run_child(self.run_dir, fd, runner=pp.Runner(["docker"], self.engine), emit=self.said.append)
        except pr.ChildError:
            raise
        except Exception as e:  # a crash is not an outcome
            self.fail(f"run_child raised {e!r}")

    def outcome(self):
        with open(f"{self.run_dir}/outcome.json") as f:
            return json.load(f)

    def test_a_healthy_run_passes_places_its_evidence_and_records_its_outcome(self):
        self.place()
        self.assertEqual(self.run_it(), pr.PASSED, self.said)
        doc = json.loads(open(f"{self.root}/evidence/partition-r1.json").read())
        self.assertEqual({p["id"]: p["verdict"] for p in doc["probes"]},
                         {"P01": "PASS", "P02": "PASS", "P03": "PASS", "P04": "PASS"})
        self.assertEqual((self.outcome()["code"], self.outcome()["router_seen"]), (0, self.TARGET))
        self.assertEqual(self.engine.stopped, [])

    def test_the_expectation_is_recorded_before_the_first_one_shot_and_binds_the_evidence(self):
        self.place()
        first = []
        real = self.engine.__call__

        def watch(argv):
            if argv[1] == "run" and not first:
                first.append(os.path.exists(f"{self.run_dir}/expect.json"))
            return real(argv)
        fd = os.open(f"{self.root}/exec/lock", os.O_RDONLY)
        self.addCleanup(os.close, fd)
        pr.run_child(self.run_dir, fd, runner=pp.Runner(["docker"], watch), emit=self.said.append)
        self.assertEqual(first, [True])
        expect = json.load(open(f"{self.run_dir}/expect.json"))
        doc = json.loads(open(f"{self.root}/evidence/partition-r1.json").read())
        self.assertEqual(expect["bindings"], doc["bindings"])
        self.assertEqual(set(expect["bindings"]), {"host_setup", "email_router", "lanes", "key", "local_router"})

    def test_a_fail_stop_failure_stops_the_contexts_target_and_only_it(self):
        self.engine.p04 = "EACCES"
        self.inspects["intruder"] = {"Id": "intruder", "State": {"Running": True}}
        self.place()
        self.assertEqual(self.run_it(), pr.FAILED)
        self.assertEqual(self.engine.stopped, [self.TARGET])
        with open(self.live) as f:
            self.assertNotIn("delegation", json.load(f))
        det = json.load(open(f"{self.root}/evidence/incident-r1/detected.json"))
        self.assertEqual((det["failing"], det["identity"]), (["P04"], self.TARGET))
        self.assertTrue(self.outcome()["incident"])

    def test_a_null_target_never_stops(self):
        self.engine.p03 = "EACCES"
        self.context["router_container_id"] = None
        self.place()
        self.assertEqual(self.run_it(), pr.FAILED)
        self.assertEqual(self.engine.stopped, [])
        events = [json.loads(l)["event"] for l in open(f"{self.root}/evidence/incident-r1/events.jsonl")]
        self.assertIn("stop_not_attempted", events)

    def test_an_unusable_context_or_lock_starts_nothing(self):
        for raw in (b'{"run_id": "r1"', pr.canonical(dict(self.context, extra=1)),
                    pr.canonical(dict(self.context, schema="other/1")), pr.canonical(dict(self.context, docker=None)),
                    pr.canonical(dict(self.context, router_container_id=1))):
            with self.subTest(raw=raw[:30]):
                self.place(context=raw)
                with self.assertRaises(pr.ChildError):
                    self.run_it()
                self.assertEqual(self.engine.seen, [])
        os.unlink(f"{self.run_dir}/context.json")
        with self.assertRaises(pr.ChildError):
            self.run_it()

    def test_a_router_run_sh_could_not_have_started_is_incomplete_and_probes_nothing(self):
        self.router_live["Mounts"].append({"Type": "volume", "Source": "v", "Destination": "/v", "RW": True})
        self.place()
        self.assertEqual(self.run_it(), pr.INCOMPLETE)
        self.assertFalse([a for a in self.engine.seen if a[1] == "run"])
        self.assertFalse(os.path.exists(f"{self.run_dir}/expect.json"))


class AffirmativeInspectTest(unittest.TestCase):
    """The child's inspect for the incident's stop: only the engine's own
    statement counts. A failed inspect is "no such container" only when the
    engine then lists no container of that id."""

    CID = "c" * 64

    def running(self, *answers):
        replies = list(answers)
        return pr.Docker(pp.Runner(["docker"], lambda argv: replies.pop(0))).running(self.CID)

    def test_only_a_stated_running_state_or_a_listed_absence_is_an_answer(self):
        self.assertEqual(self.running(proc(0, '{"Running": true}')), {"running": True})
        self.assertEqual(self.running(proc(0, '{"Running": false}')), {"running": False})
        self.assertEqual(self.running(proc(0, '{"Running": false, "Paused": true}')), {"running": True})
        self.assertEqual(self.running(proc(0, '{"Running": false, "Restarting": true}')), {"running": True})
        self.assertIsNone(self.running(proc(1, ""), proc(0, "")), "absence the engine affirms")
        for answers in ((proc(0, "{}"),), (proc(0, '{"Running": "yes"}'),), (proc(0, "not json"),),
                        (proc(0, "[]"),), (proc(1, ""), proc(1, "")), (proc(1, ""), proc(0, self.CID + "\n")),
                        (rh.Unresolved("transport"),), (proc(1, ""), rh.Unresolved("transport"))):
            with self.subTest(answers=answers):
                self.assertIsInstance(self.running(*answers), rh.Unresolved)


if __name__ == "__main__":
    unittest.main()
