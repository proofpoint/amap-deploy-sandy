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
import partition_evidence as pe
import partition_probe as pp
import partition_run as pr
import partition_store as pst
import router_health as rh
from test_partition_evidence import probe as _probe
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
                        "engine": "unix:///var/run/docker.sock", "docker": "/usr/bin/docker", "mode": "weekly"}
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
        out = self.outcome()
        self.assertEqual((out["code"], out["router_seen"]), (0, None),
                         "with no approved activation record, no stop target is reported")
        self.assertIn("no stop target", out["why"])
        self.assertEqual({k: out[k] for k in pr.SNAPSHOT}, dict.fromkeys(pr.SNAPSHOT))
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


class SnapshotTest(unittest.TestCase):
    """a5_snapshot: the stop target a passing run may report, only when A5's
    comparison holds against the APPROVED record and the live config's
    token is the current passing evidence's."""

    CID = "c" * 64
    BINDINGS = {"host_setup": "1" * 64}
    AT = "2026-10-15T03:00:00Z"

    def setUp(self):
        import partition_activation as pa
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        r = self.root = os.path.realpath(t.name)
        for d in ("run-r1", "evidence", "conf"):
            os.makedirs(f"{r}/{d}")
        self.live_path = f"{r}/conf/router.json"
        self.evidence = pe.build(host="alpha", run_id="r0", at=self.AT, script_sha256={"s": "0" * 64},
                                 bindings=self.BINDINGS, probes=[_probe(p, "PASS") for p in pe.PROBE_IDS])
        with open(f"{r}/evidence/partition-r0.json", "wb") as f:
            f.write(self.evidence)
        self.token = pe.token_of(json.loads(self.evidence))
        self.staged = (json.dumps({"state_dir": "/s", "delegation": {"signing_key": {"path": "/k/s"}}}, indent=2)
                       + "\n").encode()
        self.live_raw = pa.final_bytes(self.staged, self.token)
        self.live = {"Id": self.CID, "Image": "sha256:" + "b" * 64, "State": {"Running": True},
                     "Config": {"User": "2101:2101", "Env": [f"ROUTER_CONFIG={self.live_path}"]},
                     "HostConfig": {"NetworkMode": "none", "RestartPolicy": {"Name": "unless-stopped"}},
                     "Mounts": [{"Type": "bind", "Source": self.live_path, "Destination": self.live_path,
                                 "RW": False}]}
        self.approve(pa.spec_from_running(self.live))
        self.context = {"host": "alpha", "evidence_dir": f"{r}/evidence", "live_config_path": self.live_path}

    def approve(self, spec, host="alpha", final=None):
        import partition_activation as pa
        raw = pa.activation_record(host=host, spec=spec, staged=self.staged, final_config_path=final or self.live_path)
        p = f"{self.root}/run-r1/activation.json"
        if os.path.exists(p):
            os.unlink(p)
        with open(p, "wb") as f:
            f.write(raw)

    def snap(self, live=None, live_raw=None, now=None):
        store = pst.RootedStore(evidence_dir=f"{self.root}/evidence", run_dir=f"{self.root}/run-r1",
                                live_config=self.live_path)
        return pr.a5_snapshot(store=store, run_dir=f"{self.root}/run-r1", context=self.context,
                              live=live or self.live, image={}, live_raw=live_raw or self.live_raw,
                              bound=self.BINDINGS, now=now or pe.at_seconds(self.AT) + 60,
                              read_placed=lambda p: open(p, "rb").read())

    def test_the_approved_router_with_a_current_token_is_reported_with_its_snapshot(self):
        import partition_activation as pa
        got = self.snap()
        self.assertEqual(got, {"router_seen": self.CID, "config_sha256": pe.sha_bytes(self.live_raw),
                               "evidence_run_id": "r0", "evidence_sha256": pe.sha_bytes(self.evidence),
                               "inspect_digest": pe.sha_json(pa.inspect_projection(self.live))})
        self.assertEqual(set(got), set(pr.SNAPSHOT))

    def test_anything_short_of_the_approved_activation_and_a_current_token_reports_none(self):
        import partition_activation as pa
        other = pe.build(host="alpha", run_id="r0", at=self.AT, script_sha256={"s": "0" * 64},
                         bindings={"host_setup": "2" * 64}, probes=[_probe(p, "PASS") for p in pe.PROBE_IDS])
        rows = {"another image": lambda: self.snap(live=dict(self.live, Image="sha256:" + "9" * 64)),
                "a decoy config mount": lambda: self.snap(live=dict(self.live, Mounts=[
                    {"Type": "bind", "Source": "/decoy", "Destination": self.live_path, "RW": False}])),
                "not running": lambda: self.snap(live=dict(self.live, State={"Running": False})),
                "a stale token": lambda: self.snap(now=pe.at_seconds(self.AT) + 30 * 86400),
                "a token of no run": lambda: self.snap(live_raw=pa.final_bytes(self.staged, "../x:" + "a" * 64)),
                "a token not its evidence's": lambda: self.snap(
                    live_raw=pa.final_bytes(self.staged, "r0:" + "f" * 64))}
        for what, run in rows.items():
            with self.subTest(what):
                self.assertIsInstance(run(), rh.Unresolved, what)
        with open(f"{self.root}/evidence/partition-r0.json", "wb") as f:
            f.write(other)
        self.assertIsInstance(self.snap(live_raw=pa.final_bytes(self.staged, pe.token_of(json.loads(other)))),
                              rh.Unresolved, "evidence under other bindings than today's")

    def test_an_approval_for_another_host_or_path_or_none_at_all_reports_none(self):
        import partition_activation as pa
        spec = pa.spec_from_running(self.live)
        for kw in ({"host": "beta"}, {"final": "/elsewhere.json"}):
            with self.subTest(kw=kw):
                self.approve(spec, **kw)
                self.assertIsInstance(self.snap(), rh.Unresolved)
        os.unlink(f"{self.root}/run-r1/activation.json")
        self.assertIsInstance(self.snap(), rh.Unresolved)


class RunDirTest(unittest.TestCase):
    """The launcher's check of the run directory it is handed: run-<id>,
    directly under its own bundle's exec root, a real root 0700 directory."""

    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = os.path.realpath(t.name)
        self.bundle = f"{self.root}/bundle"
        os.mkdir(self.bundle)
        self.run = f"{self.root}/run-r1"
        os.mkdir(self.run, 0o700)
        os.chmod(self.run, 0o700)

    def check(self, run_dir, root_uid=None):
        return pr.check_run_dir(run_dir, root_uid=os.getuid() if root_uid is None else root_uid,
                                bundle_dir=self.bundle)

    def test_the_run_directory_the_writer_makes_is_accepted(self):
        self.assertEqual(self.check(self.run), self.root)

    def test_any_other_run_directory_is_refused_before_anything_is_read(self):
        other = tempfile.TemporaryDirectory()
        self.addCleanup(other.cleanup)
        elsewhere = os.path.join(os.path.realpath(other.name), "run-r1")
        os.mkdir(elsewhere, 0o700)
        os.symlink(self.run, f"{self.root}/run-link")
        os.mkdir(f"{self.root}/run-open", 0o755)
        os.chmod(f"{self.root}/run-open", 0o755)
        for bad in ("run-r1", f"{self.root}/other", f"{self.root}/run-r1/", f"{self.root}/x/../run-r1", elsewhere,
                    f"{self.root}/run-link", f"{self.root}/run-open", f"{self.root}/run-absent"):
            with self.subTest(bad=bad):
                with self.assertRaises(pr.ChildError):
                    self.check(bad)
        with self.assertRaises(pr.ChildError):
            self.check(self.run, root_uid=os.getuid() + 1)

    def test_the_launcher_refuses_a_run_directory_outside_its_exec_root(self):
        with tempfile.TemporaryDirectory() as t:
            bundle = os.path.join(os.path.realpath(t), "bundle")
            os.mkdir(bundle)
            for f in CLOSURE + ["partition_weekly.closure"]:
                shutil.copy(REPO / f, bundle)
            p = subprocess.run([sys.executable, "-I", "-S", "-B", os.path.join(bundle, "partition_weekly.py"),
                                "--run-dir", self.run, "--lock-fd", "0"],
                               capture_output=True, text=True, timeout=120, cwd=t, env={})
            self.assertEqual(p.returncode, pr.INCOMPLETE, p.stderr[-2000:])
            self.assertIn("exec root", p.stderr)


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


class A2OutcomeTest(unittest.TestCase):
    """partition_run.a2_outcome: A2 passes only with the token, the evidence
    placed, P02 PASS, and P01 PASS or UNKNOWN for exactly the stopped router.
    The documents are partition_evidence.build's."""

    UNMEASURED = {"upstream": pr.P01_STOPPED}

    def doc(self, **verdicts):
        from test_partition_evidence import build
        return build(verdicts=verdicts)

    def outcome(self, doc, placed=True, p01=None):
        p01 = [("UNKNOWN", "unresolved", pp.unmeasured_detail(self.UNMEASURED))] if p01 is None else p01
        return pr.a2_outcome(doc, placed, p01, self.UNMEASURED)

    def test_the_stopped_router_s_unknown_passes(self):
        code, incident, why = self.outcome(self.doc(P01="UNKNOWN"))
        self.assertEqual((code, incident), (pr.PASSED, False))
        self.assertIn("is placed", why)

    def test_each_shortfall_is_a_handoff_never_a_silent_pass(self):
        for name, args in (("no token", dict(doc=self.doc(P03="FAIL"))),
                           ("not placed", dict(doc=self.doc(P01="UNKNOWN"), placed=False)),
                           ("P02", dict(doc=self.doc(P01="UNKNOWN", P02="FAIL"))),
                           ("P01 FAIL", dict(doc=self.doc(P01="FAIL"), p01=[("FAIL", "ok", "x")])),
                           ("P01 other UNKNOWN", dict(doc=self.doc(P01="UNKNOWN"),
                                                      p01=[("UNKNOWN", "unresolved", "downstream: exec failed")]))):
            with self.subTest(name=name):
                self.assertEqual(self.outcome(**args)[0], pr.INCOMPLETE)

    def test_the_unmeasured_router_never_hides_a_failure(self):
        walks = {"downstream": [(1, 2102, 2102), (2, 0, 0)]}
        self.assertEqual(pp.verdict_p01(walks, {"upstream": 2101, "downstream": 2102}, [("upstream", "downstream")],
                                        self.UNMEASURED)[0], "FAIL")
        ok = {"downstream": [(1, 2102, 2102)]}
        verdict, _, detail = pp.verdict_p01(ok, {"upstream": 2101, "downstream": 2102},
                                            [("upstream", "downstream")], self.UNMEASURED)
        self.assertEqual((verdict, detail), ("UNKNOWN", pp.unmeasured_detail(self.UNMEASURED)))
