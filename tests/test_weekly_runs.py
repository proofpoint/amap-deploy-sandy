"""The weekly job's run record, weekly-runs.json: a writer-only name the
child's store can never write; the writer's order (W2 invalidates before any
run directory, W5 publishes before the child, W7 publishes what remains from
a fresh listing) under every fault, so that whenever a run directory exists
the record is absent or lists it; and verify's reading of it, where any
kept, undecided or overdue run FAILs and only an empty list PASSes."""

import json
import os
import signal
import subprocess
import tempfile
import time
import unittest

import host_steps as hs
import partition_activation as pa
import partition_evidence as pe
import partition_runs as pr
import partition_setup as ps
import partition_store as pst
import router_health as rh
import test_partition_setup as tps
from test_partition_setup import EV, EXEC, SCRATCH, TOOLS
from test_partition_weekly_writer import B, FAIL3, PASS, TARGET, Host, InProcess

LIVE = "/opt/ex/router.json"
NOW = 1_800_000_000


def at(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def activation(host="alpha"):
    staged = (json.dumps({"state_dir": "/s"}, indent=2) + "\n").encode()
    return pa.activation_record(host=host, spec=tps.StopTargetTest.SPEC, staged=staged, final_config_path=LIVE)


def record(runs, host="alpha", when=NOW):
    return pe.canonical({"schema": pr.RUNS_SCHEMA, "host": host, "at": at(when), "runs": runs})


def run(rid, state, since=NOW):
    return {"run_id": rid, "state": state, "since": at(since)}


PART = ps.PartitionSpec(evidence_dir=EV, scratch_dir=SCRATCH, weekday=0, hour=3, exec_root=EXEC, tools=dict(TOOLS))


class NameTest(unittest.TestCase):
    def test_the_name_is_outside_every_child_store_pattern(self):
        self.assertFalse(ps.evidence_name_ok(hs.WEEKLY_RUNS))
        self.assertTrue(ps.evidence_name_ok("partition-runs.json"), "the old name was the evidence of run 'runs'")
        self.assertNotIn(hs.WEEKLY_RUNS, pst.RUN_RECORDS)

    def test_one_name_and_one_set_of_bounds_on_both_sides(self):
        self.assertEqual((pr.WEEKLY_RUNS, pr.RUNS_SCHEMA, pr.STALE_AFTER_S, pr.PLACED_SLACK_S),
                         (hs.WEEKLY_RUNS, hs.RUNS_SCHEMA, hs.STALE_AFTER_S, hs.PLACED_SLACK_S))
        self.assertEqual((pr.RUNNING, pr.KEPT, pr.UNDECIDED), (hs.RUNNING, hs.KEPT, hs.UNDECIDED))

    def test_the_childs_store_can_neither_create_nor_replace_it(self):
        with tempfile.TemporaryDirectory() as t:
            ev = os.path.join(os.path.realpath(t), "ev")
            os.mkdir(ev)
            run_dir = os.path.join(os.path.realpath(t), "exec", "run-runs")
            os.makedirs(run_dir)
            store = pst.RootedStore(evidence_dir=ev, run_dir=run_dir, live_config=os.path.join(t, "conf", "r.json"))
            store.new_file(os.path.join(ev, "partition-runs.json"), b"{}")
            self.assertTrue(os.path.exists(os.path.join(ev, "partition-runs.json")), "the control: it writes evidence")
            path = os.path.join(ev, hs.WEEKLY_RUNS)
            for present in (False, True):
                if present:
                    with open(path, "wb") as f:
                        f.write(b"placed")
                for exclusive in (True, False):
                    with self.subTest(present=present, exclusive=exclusive):
                        with self.assertRaises(pst.Refused):
                            store.new_file(path, b"forged", exclusive=exclusive)
            with open(path, "rb") as f:
                self.assertEqual(f.read(), b"placed")


class BoundTest(InProcess):
    """STALE_AFTER_S from the writer's own bounds, with the post-child call
    count measured on the worst trace rather than restated."""

    class Recorder:
        """An engine whose every call is counted, answering by `script`: for
        an inspect, whether it succeeds with the container running; for a ps,
        whether it lists something."""

        def __init__(self, script):
            self.script, self.calls = list(script), 0

        def run(self, args, timeout=None):
            self.calls += 1
            ok = self.script.pop(0) if self.script else False
            out = (json.dumps({"Running": True}) if args[0] == "inspect" else ("x" if ok else "")).encode()
            return subprocess.CompletedProcess(args, 0 if (ok or args[0] != "inspect") else 1, out, b"")

    def most_calls(self):
        ev, conf = f"{self.d}/ev", f"{self.d}/conf/router.json"
        os.mkdir(ev, 0o755)
        os.chmod(ev, 0o755)
        os.mkdir(f"{self.d}/conf", 0o755)
        most = 0
        import itertools
        for script in itertools.product((True, False), repeat=6):
            with open(conf, "w") as f:
                f.write('{"delegation": {}}\n')
            for n in os.listdir(ev):
                import shutil
                shutil.rmtree(f"{ev}/{n}")
            e = self.Recorder(script)
            e.running, e.identity = hs._Engine.running.__get__(e), hs._Engine.identity.__get__(e)
            hs._act(ev, conf, TARGET, "r1", "2026-10-15T03:00:00Z", ["P03"], e, [])
            act = e.calls
            e = self.Recorder([True])
            hs._Engine.remove_run(e, "r1")
            most = max(most, e.calls + max(act, 1))
        return most

    def test_the_stale_bound_covers_the_parents_calls_after_its_child(self):
        measured = self.most_calls()
        self.assertLessEqual(measured, hs.POST_CHILD_ENGINE_CALLS)
        self.assertEqual(hs.ENGINE_CALL_S, hs.STOP_TIMEOUT_S + 60)
        self.assertEqual(hs._Engine.run.__defaults__, (hs.ENGINE_CALL_S,))
        self.assertGreaterEqual(hs.STALE_AFTER_S, hs.CHILD_TIMEOUT_S + measured * hs.ENGINE_CALL_S + hs.STALE_MARGIN_S)
        self.assertEqual(hs.STALE_AFTER_S, hs.CHILD_TIMEOUT_S + hs.POST_CHILD_ENGINE_CALLS * hs.ENGINE_CALL_S
                         + hs.STALE_MARGIN_S)

    def test_a_slow_engine_still_deciding_is_not_read_as_overdue(self):
        slow = hs.CHILD_TIMEOUT_S + self.most_calls() * hs.ENGINE_CALL_S
        out = VerifyTest.verdict(self, record([run("w1", pr.RUNNING, NOW - slow)]))
        self.assertEqual(out.result, rh.UNKNOWN)


class VerifyTest(unittest.TestCase):
    def verdict(self, raw, live=b'{"delegation": {}}', gate=None, act=None, now=NOW, error=None):
        files = {f"{EV}/{pr.WEEKLY_RUNS}": raw, f"{EV}/activation.json": act or activation()}

        def read(path):
            if error is not None and path.endswith(pr.WEEKLY_RUNS):
                raise error
            if files.get(path) is None:
                raise FileNotFoundError(2, "No such file or directory", path)
            return files[path]

        def read_live(path):
            if isinstance(live, Exception):
                raise live
            return live
        out = pr.verify_runs(PART, gate, live_config=LIVE, read=read, read_live=read_live, now=lambda: now)
        self.assertEqual(len(out), 1)
        return out[0]

    def test_each_state(self):
        rows = {"empty": ([], rh.PASS),
                "recent running": ([run("w1", pr.RUNNING, NOW - 60)], rh.UNKNOWN),
                "overdue running": ([run("w1", pr.RUNNING, NOW - pr.STALE_AFTER_S - 1)], rh.FAIL),
                "running, ahead of the clock": ([run("w1", pr.RUNNING, NOW + 60)], rh.UNKNOWN),
                "kept, with no incident": ([run("w1", pr.KEPT)], rh.FAIL),
                "undecided": ([run("w1", pr.UNDECIDED)], rh.FAIL),
                "kept beside recent": ([run("w1", pr.KEPT), run("w2", pr.RUNNING, NOW - 60)], rh.FAIL),
                "overdue beside recent": ([run("w1", pr.UNDECIDED), run("w2", pr.RUNNING, NOW - pr.STALE_AFTER_S - 9)],
                                          rh.FAIL)}
        for what, (runs, want) in rows.items():
            with self.subTest(what):
                out = self.verdict(record(runs))
                self.assertEqual(out.result, want, out.actual)
                for r in runs:
                    if want == rh.FAIL:
                        self.assertIn(f"run {r['run_id']}", out.actual, "every entry is named")
        ahead = self.verdict(record([run("w1", pr.RUNNING, NOW + 60)]))
        self.assertIn("ahead of this host's clock", ahead.actual.reason, "never read as recent")
        kept = self.verdict(record([run("w1", pr.KEPT)]))
        self.assertIn("if one exists", kept.remedy, "kept never assumes an incident")
        overdue = self.verdict(record([run("w1", pr.RUNNING, NOW - pr.STALE_AFTER_S - 1)]))
        self.assertIn("another holder still owns the per-host lock", overdue.remedy)
        self.assertNotIn("child", overdue.remedy + overdue.actual)
        self.assertNotIn("stopped", overdue.remedy + overdue.actual)

    def test_scope_and_what_cannot_be_read(self):
        self.assertEqual(self.verdict(None).result, rh.FAIL, "absent in scope")
        off = self.verdict(None, live=b'{"state_dir": "/s"}')
        self.assertEqual((off.result, "not required" in off.claim), (rh.PASS, True))
        self.assertEqual(self.verdict(None, live=b'{"state_dir": "/s"}', gate=object()).result, rh.FAIL)
        self.assertEqual(self.verdict(None, live=OSError(13, "Permission denied")).result, rh.UNKNOWN,
                         "an unreadable live config is never the not-required pass")
        self.assertEqual(self.verdict(None, live=b'[1]').result, rh.UNKNOWN)
        self.assertEqual(self.verdict(b"", error=OSError("x is not a root:root 0444 regular file with one link"))
                         .result, rh.FAIL, "foreign-owned, two links, oversized")
        self.assertEqual(self.verdict(b"", error=OSError(5, "Input/output error")).result, rh.UNKNOWN)
        self.assertEqual(self.verdict(record([]), act=b"{}").result, rh.UNKNOWN, "no host to bind it to")
        self.assertEqual(self.verdict(record([]), act=activation("beta")).result, rh.FAIL, "another host's")
        self.assertEqual(self.verdict(record([], when=NOW + 60)).result, rh.UNKNOWN, "a record ahead of the clock")

    def test_a_record_ahead_of_the_clock_still_fails_what_it_knows(self):
        rows = {"kept": ([run("w1", pr.KEPT)], rh.FAIL), "undecided": ([run("w1", pr.UNDECIDED)], rh.FAIL),
                "overdue": ([run("w1", pr.RUNNING, NOW - pr.STALE_AFTER_S - 1)], rh.FAIL),
                "empty": ([], rh.UNKNOWN), "recent running": ([run("w1", pr.RUNNING, NOW - 60)], rh.UNKNOWN)}
        for what, (runs, want) in rows.items():
            with self.subTest(what):
                out = self.verdict(record(runs, when=NOW + 60))
                self.assertEqual(out.result, want)
                detail = out.actual if want == rh.FAIL else out.actual.reason
                self.assertIn("ahead of this host's clock", detail, "the observation is kept")
                for r in runs:
                    self.assertIn(f"run {r['run_id']}", detail, "every entry's detail is kept")

    def test_only_the_grammar_is_read(self):
        good = json.loads(record([run("w1", pr.KEPT), run("w2", pr.RUNNING)]))
        rows = {"an extra member": dict(good, extra=1),
                "a member missing": {k: v for k, v in good.items() if k != "at"},
                "another schema": dict(good, schema="x/1"),
                "a bad time": dict(good, at="2026-13-45T99:00:00Z"),
                "a run with an extra member": dict(good, runs=[dict(good["runs"][0], x=1)]),
                "a bad state": dict(good, runs=[dict(good["runs"][0], state="done")]),
                "a bad run id": dict(good, runs=[dict(good["runs"][0], run_id="a/b")]),
                "a repeated run": dict(good, runs=[good["runs"][0], good["runs"][0]]),
                "out of order": dict(good, runs=list(reversed(good["runs"]))),
                "two running": dict(good, runs=[run("w1", pr.RUNNING), run("w2", pr.RUNNING)])}
        for what, doc in rows.items():
            with self.subTest(what):
                self.assertEqual(self.verdict(pe.canonical(doc)).result, rh.FAIL)
        spaced = json.dumps(json.loads(record([])), indent=1).encode()
        self.assertEqual(self.verdict(spaced).result, rh.FAIL, "not canonical")
        self.assertEqual(self.verdict(b'{"a":1,"a":2}').result, rh.FAIL, "a duplicate member")

    def test_it_is_read_like_the_stop_targets_copy(self):
        with tempfile.TemporaryDirectory() as t:
            path = os.path.join(t, pr.WEEKLY_RUNS)
            with open(path, "wb") as f:
                f.write(record([]))
            os.chmod(path, 0o444)
            with self.assertRaises(OSError) as e:
                ps.read_placed(path)
            self.assertIsNone(e.exception.errno, "not root's: a structural refusal, which FAILs")
            mapped = lambda p: _Mapped(os.lstat(p))
            os.link(path, path + ".2")
            with self.assertRaises(OSError):
                ps.read_placed(path, lstat=mapped, fstat=lambda fd: _Mapped(os.fstat(fd)))


class WiringTest(unittest.TestCase):
    def test_verify_runs_the_record_check_for_a_document_with_a_partition_section(self):
        import host_setup as hset
        import hub_supervise as hv
        from test_hub_runtime import setUpModule, tearDownModule
        from test_hub_supervise import sup_section
        from test_partition_setup import doc
        setUpModule()
        self.addCleanup(tearDownModule)
        d = doc()
        d[hv.SECTION] = sup_section()
        spec = hset.load_spec(d)
        for name in ("verify_roots", "verify_overlay", "verify_containers", "verify_mounts", "verify_openssl",
                     "verify_umasks", "verify_groups", "secret_checks", "start_checks", "verify_recovery_horizon",
                     "verify_stop_target"):
            self.addCleanup(setattr, hset, name, getattr(hset, name))
            setattr(hset, name, lambda *a, **k: [])
        for mod in (hset.hr, hset.hk, hset.hv, hset.hp, hset.ps):
            for name in ("checks", "verify"):
                if hasattr(mod, name):
                    self.addCleanup(setattr, mod, name, getattr(mod, name))
                    setattr(mod, name, lambda *a, **k: [])
        seen = []
        self.addCleanup(setattr, hset, "verify_weekly_runs", hset.verify_weekly_runs)
        hset.verify_weekly_runs = lambda sp, p: seen.append((sp, p)) or []
        probes = {"rl_sha": "x", "inspect": lambda ref: None}
        hset.checks(spec, production=False, containers=lambda c: None, openssl={}, partition=probes,
                    enablement={"disabled": {}, "loaded": lambda l: False})
        self.assertEqual(seen, [(spec, probes)])

    def test_the_record_is_judged_against_the_documents_own_live_config(self):
        import host_setup as hset
        import hub_supervise as hv
        from test_hub_runtime import setUpModule, tearDownModule
        from test_hub_supervise import sup_section
        from test_partition_setup import doc
        setUpModule()
        self.addCleanup(tearDownModule)
        d = doc()
        d[hv.SECTION] = sup_section()
        spec = hset.load_spec(d)
        asked = []
        out = hset.verify_weekly_runs(spec, {"read": lambda p: asked.append(p) or b'{"delegation": {}}',
                                             "read_placed": lambda p: (_ for _ in ()).throw(FileNotFoundError(p))})
        self.assertEqual((asked, [c.result for c in out]), ([spec.keys.local_config], [rh.FAIL]))


class _Mapped:
    def __init__(self, st):
        self._st = st

    def __getattr__(self, n):
        return 0 if n in ("st_uid", "st_gid") else getattr(self._st, n)


class WriterRunsTest(unittest.TestCase):
    """The writer's order, through the real subcommand, with the record's
    filesystem faulted one call at a time (PW_RUNS_FAULT) and run removal
    failing on demand (PW_REMOVE_FAIL)."""

    def setUp(self):
        t = tempfile.mkdtemp(dir="/tmp", prefix="pw")
        self.addCleanup(self._rm, t)
        self.h = Host(os.path.realpath(t))
        self.addCleanup(self.h.sock.close)

    @staticmethod
    def _rm(t):
        for top, dirs, _ in os.walk(t):
            for d in dirs:
                try:
                    os.chmod(os.path.join(top, d), 0o755)
                except OSError:
                    pass
        import shutil
        shutil.rmtree(t, ignore_errors=True)

    def path(self):
        return f"{self.h.ev}/{hs.WEEKLY_RUNS}"

    def doc(self):
        try:
            with open(self.path(), "rb") as f:
                raw = f.read()
        except FileNotFoundError:
            return None
        return pr.parse_runs(raw)

    def states(self):
        d = self.doc()
        return None if d is None else {r["run_id"]: r["state"] for r in d["runs"]}

    def invariant(self):
        """Whenever a run directory exists, the record is absent or lists it."""
        listed = self.states()
        for n in self.h.runs():
            if listed is not None:
                self.assertIn(n[len("run-"):], listed, f"{n} exists and the record does not list it")

    def run_(self, fault=None, remove=None):
        env = {}
        if fault:
            env["PW_RUNS_FAULT"] = fault
        if remove:
            env["PW_REMOVE_FAIL"] = remove
        p = self.h.run(env=env)
        self.invariant()
        return p

    def test_a_passing_run_leaves_an_empty_record_placed_as_the_writers(self):
        self.h.plan([["expect", B], ["evidence", B, PASS], ["outcome", 0, TARGET]])
        p = self.run_()
        self.assertEqual(p.returncode, hs.EXIT_PASS, p.stdout + p.stderr)
        doc = self.doc()
        self.assertEqual((doc["host"], doc["runs"]), ("alpha", []))
        self.assertEqual(os.stat(self.path()).st_mode & 0o777, 0o444)

    def test_the_child_starts_only_once_it_is_published_as_running(self):
        self.h.plan([["expect", B], ["evidence", B, PASS], ["outcome", 0, TARGET]])
        self.run_()
        seen = self.h.side_read("record-at-start.json")
        self.assertIsNotNone(seen, "the record was there when the child started")
        self.assertEqual([r["state"] for r in seen["runs"]], [pr.RUNNING])

    def test_a_dead_writer_leaves_running_and_the_next_holder_hands_off_touching_nothing(self):
        self.h.plan([["sleep", 3], ["expect", B], ["evidence", B, PASS], ["outcome", 0, TARGET]])
        first = subprocess.Popen(self.h.argv(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 30
        while self.h.side_read("child-started.json") is None and time.monotonic() < deadline:
            time.sleep(0.05)
        first.send_signal(signal.SIGKILL)
        first.wait()
        self.assertEqual(list(self.states().values()), [pr.RUNNING])
        before = (os.stat(self.path()).st_ino, open(self.path(), "rb").read())
        second = self.run_()
        self.assertEqual(second.returncode, hs.EXIT_HANDOFF)
        self.assertEqual((os.stat(self.path()).st_ino, open(self.path(), "rb").read()), before)
        raw = before[1]
        since = pr._seconds(pr.parse_runs(raw)["runs"][0]["since"])
        for now, want in ((since + 60, rh.UNKNOWN), (since + pr.STALE_AFTER_S + 1, rh.FAIL)):
            out = VerifyTest.verdict(self, raw.replace(b'"host":"alpha"', b'"host":"alpha"'), now=now)
            self.assertEqual(out.result, want)
        while self.h.side_read("child-fd-open-at-end.json") is None and time.monotonic() < deadline:
            time.sleep(0.05)
        time.sleep(0.3)
        self.h.plan([["expect", B], ["evidence", B, PASS], ["outcome", 0, TARGET]])
        third = self.run_()
        self.assertEqual(third.returncode, hs.EXIT_PASS, third.stdout)
        self.assertEqual(self.states(), {}, "both gone: decided, then published empty")

    def test_w2_failing_starts_no_run(self):
        old = record([run("wold", pr.KEPT)])
        for fault, visible in (("W2:unlink", old), ("W2:fsync", None)):
            with self.subTest(fault):
                if os.path.exists(self.path()):
                    os.unlink(self.path())
                with open(self.path(), "wb") as f:
                    f.write(old)
                os.chmod(self.path(), 0o444)
                self.h.plan([["expect", B], ["evidence", B, PASS], ["outcome", 0, TARGET]])
                p = self.run_(fault)
                self.assertEqual(p.returncode, hs.EXIT_HANDOFF, p.stdout)
                self.assertIn("the run record cannot be invalidated", p.stdout)
                self.assertIsNone(self.h.side_read("child-started.json"), "no child")
                self.assertEqual(self.h.runs(), [])
                if visible is None:
                    self.assertFalse(os.path.exists(self.path()), "the unlink took: absent now")
                else:
                    self.assertEqual(open(self.path(), "rb").read(), visible, "the old record, unchanged")

    def test_w2_failing_after_an_abandoned_incident_exits_with_the_incident(self):
        self.h.recovery()
        self.h.abandoned("wold", FAIL3)
        p = self.run_("W2:unlink")
        self.assertEqual(p.returncode, hs.EXIT_INCIDENT, p.stdout)
        self.assertEqual(self.h.stops(), [TARGET], "the abandoned run's stop is never suppressed")

    def test_w5_failing_at_each_step_starts_no_child(self):
        for fault in ("W5:open", "W5:write", "W5:fsync#1", "W5:rename", "W5:fsync#2"):
            with self.subTest(fault):
                self.h.plan([["expect", B], ["evidence", B, PASS], ["outcome", 0, TARGET]])
                try:
                    os.unlink(f"{self.h.side}/child-started.json")
                except FileNotFoundError:
                    pass
                p = self.run_(fault)
                self.assertEqual(p.returncode, hs.EXIT_HANDOFF, p.stdout)
                self.assertIn("the run record cannot be published", p.stdout)
                self.assertIsNone(self.h.side_read("child-started.json"))
                self.assertEqual(self.h.runs(), [], "this run's directory, which had no child, is gone")

    def test_a_setup_failure_before_the_child_is_a_handoff_and_the_end_record_is_still_published(self):
        """Each step between W2 and the child, failing with an OSError: no
        child and no engine call, this run's directory (made, no child) gone,
        the end record published from a fresh listing, and exit 3; with an
        abandoned run whose decision was an incident, exit 1."""
        for fault in ("mkdir-run", "mkdir-docker", "context", "listing", "launch"):
            with self.subTest(fault):
                self.setUp()
                self.h.plan([["expect", B], ["evidence", B, PASS], ["outcome", 0, TARGET]])
                p = self.h.run(env={"PW_SETUP_FAULT": fault})
                self.invariant()
                self.assertEqual(p.returncode, hs.EXIT_HANDOFF, p.stdout + p.stderr)
                self.assertNotIn("Traceback", p.stderr)
                self.assertIn("handoff:", p.stdout)
                self.assertIsNone(self.h.side_read("child-started.json"))
                self.assertEqual(self.h.logged(), [], "no engine call")
                self.assertEqual(self.h.runs(), [], "a run whose child never started has no directory left")
                self.assertEqual(self.states(), {}, "the end record was published, from a fresh listing")
        self.setUp()
        self.h.recovery()
        self.h.abandoned("wfail", FAIL3)
        p = self.h.run(env={"PW_SETUP_FAULT": "launch"})
        self.assertEqual(p.returncode, hs.EXIT_INCIDENT, p.stdout + p.stderr)
        self.assertEqual(self.h.stops(), [TARGET], "the abandoned run's effects stand")

    def test_w7_failing_after_a_pass_is_never_a_pass(self):
        for fault, left in (("W7:open", "running"), ("W7:rename", "running"), ("W7:fsync#2", "empty")):
            with self.subTest(fault):
                self.h.plan([["expect", B], ["evidence", B, PASS], ["outcome", 0, TARGET]])
                p = self.run_(fault)
                self.assertEqual(p.returncode, hs.EXIT_HANDOFF, p.stdout)
                self.assertIn("cannot be published durably", p.stdout)
                if left == "empty":
                    self.assertEqual(self.states(), {}, "visible, truthful, and not durable: exit 3 still")
                else:
                    self.assertEqual(list(self.states().values()), [pr.RUNNING], "(1)'s record, over-reporting")

    def test_w7_failing_after_a_fail_stop_keeps_the_incident(self):
        self.h.recovery()
        self.h.plan([["expect", B], ["evidence", B, FAIL3], ["outcome", 1, None]])
        p = self.run_("W7:rename")
        self.assertEqual(p.returncode, hs.EXIT_INCIDENT, p.stdout)
        self.assertEqual(self.h.stops(), [TARGET])

    def test_a_retained_run_is_listed_undecided_and_fails(self):
        os.symlink("/nonexistent", f"{self.h.exec}/run-wlink")
        self.h.plan([["expect", B], ["evidence", B, PASS], ["outcome", 0, TARGET]])
        p = self.run_()
        self.assertIn("run-wlink: cannot be read", p.stdout)
        self.assertEqual(self.states(), {"wlink": pr.UNDECIDED})
        out = VerifyTest.verdict(self, open(self.path(), "rb").read())
        self.assertEqual(out.result, rh.FAIL)

    def test_an_unusable_context_is_decided_and_removed_not_retained(self):
        self.h.abandoned("wold")
        os.chmod(f"{self.h.exec}/run-wold/context.json", 0)
        self.h.plan([["expect", B], ["evidence", B, PASS], ["outcome", 0, TARGET]])
        p = self.run_()
        self.assertEqual(p.returncode, hs.EXIT_PASS, p.stdout)
        self.assertEqual(self.states(), {})

    def test_a_failed_removal_is_undecided_and_maps_the_exit_once(self):
        rows = [("this run passes", PASS, 0, None, r"run-w[0-9TZ]+", hs.EXIT_HANDOFF),
                ("this run is a fail-stop", FAIL3, 1, None, r"run-w[0-9TZ]+", hs.EXIT_INCIDENT),
                ("an abandoned no-effect run, this one passing", PASS, 0, "wold", r"run-wold", hs.EXIT_HANDOFF),
                ("an abandoned incident, this one passing", PASS, 0, "wfail", r"run-wfail", hs.EXIT_HANDOFF)]
        for what, verdicts, code, abandoned, pattern, want in rows:
            with self.subTest(what):
                self.setUp()
                self.h.recovery()
                if abandoned == "wold":
                    self.h.abandoned("wold")
                elif abandoned == "wfail":
                    self.h.abandoned("wfail", FAIL3)
                self.h.plan([["expect", B], ["evidence", B, verdicts], ["outcome", code, TARGET if code == 0 else None]])
                p = self.run_(remove=pattern)
                self.assertEqual(p.returncode, want, p.stdout)
                self.assertIn(pr.UNDECIDED, self.states().values())
                self.assertIn("cannot be removed", p.stdout)

    def test_an_abandoned_incident_whose_removal_fails_with_no_child_exits_with_the_incident(self):
        self.h.recovery()
        self.h.abandoned("wfail", FAIL3)
        p = self.run_(fault="W5:rename", remove=r"run-wfail")
        self.assertEqual(p.returncode, hs.EXIT_INCIDENT, p.stdout)
        self.assertIn("wfail", self.states())

    def test_a_live_config_at_the_records_place_is_refused_before_anything(self):
        with open(self.path(), "wb") as f:
            f.write(b"before")
        self.h.document(keys={"local_config": self.path()})
        p = self.h.run()   # the record holds what is not a record: the invariant is not read here
        self.assertEqual(p.returncode, hs.EXIT_HANDOFF, p.stdout)
        self.assertIn("overlap", p.stdout)
        self.assertEqual(open(self.path(), "rb").read(), b"before")
        self.assertIsNone(self.h.side_read("child-started.json"))


if __name__ == "__main__":
    unittest.main()
