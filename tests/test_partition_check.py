"""partition_check: A5's six claims, read-only, as the operator.

The records are the producers' own: A1's record and staged bytes from
activation_install's A3 fixture, the evidence from partition_evidence.build,
the stop target and run record in the writer's canonical form, and the
running router as `docker inspect` shows a run.sh container
(test_partition_activation.inspect_of). Every claim is judged by the REAL
functions: verify_activation, verify_document, verify_target and
verify_runs, through partition_check.evaluate. Only the reads are injected:
nothing here touches docker, the host's files or a router.
"""

import hashlib
import json
import os
import stat
import unittest
from types import SimpleNamespace

import partition_activation as pa
import partition_check as pc
import partition_evidence as pe
import partition_probe as pp
import partition_runs as pruns
import partition_setup as ps
import router_health as rh
import test_activation_install as tai
from test_hub_runtime import setUpModule, tearDownModule  # noqa: F401 -- the fixture's pins, restored
from test_hub_supervise import sup_section
from test_partition_activation import IMAGE, inspect_of
from test_partition_evidence import AT, NOW, BINDINGS, build, probe

CID = "c" * 64
CREATED = "2026-10-14T12:20:00.000000000Z"
AT_7D = "2026-10-14T12:30:00Z"
LANES = b'{"selected": [{"slug": "alpha"}, {"slug": "beta"}]}'


def ts(t):
    return __import__("time").strftime("%Y-%m-%dT%H:%M:%S.000000Z", __import__("time").gmtime(t))


class FakeStat:
    def __init__(self, mode, uid=0, gid=0, nlink=1, dev=1, ino=1):
        self.st_mode, self.st_uid, self.st_gid, self.st_nlink, self.st_dev, self.st_ino = mode, uid, gid, nlink, dev, ino


class Host(tai.A3):
    """A3's activated host, with a supervision section (T1 judges the
    engine), after A4: the live config is A1 + T, the router runs A1's
    spec. `files` holds what root placed; `seven_d()` adds step 7d's
    outputs."""

    def setUp(self):
        orig = tai.partition_doc
        tai.partition_doc = lambda *a, **k: dict(orig(*a, **k), supervision=sup_section("systemd"))
        try:
            tai.A3.setUp(self)
        finally:
            tai.partition_doc = orig
        self.document_raw = b'{"host_setup": {"fixture": "the unit argv\'s document"}}'
        self.ev = self.spec.partition.evidence_dir
        name = self.spec.runtime_of(self.spec.hops[0][1])["container"]
        final = self.spec.keys.local_config
        # A1's spec as prospective_spec builds one: the final path bound
        # read-only and named in ROUTER_CONFIG.
        self.a1_spec = dict(tai.SPEC, name=name, restart="unless-stopped",
                            env={"ROUTER_CONFIG": final, "ROUTER_INTERVAL": pa.DEFAULT_INTERVAL},
                            mounts=[{"type": "bind", "source": final, "target": final, "readonly": True}])
        self.record = pa.activation_record(host="alpha", spec=self.a1_spec, staged=self.staged,
                                           final_config_path=final)
        self.live = inspect_of(self.a1_spec, Id=CID, Name=f"/{name}", Created=CREATED)
        self.inspects = {CID: self.live, name: self.live}
        self.lane_stat = {}
        self.a2_raw = self.document(run_id="r1", at=AT)
        self.token = json.loads(self.a2_raw)[pe.TOKEN_MEMBER]
        self.live_raw = pa.final_bytes(self.staged, self.token)
        self.files = {f"{self.ev}/activation.json": self.record, f"{self.ev}/partition-r1.json": self.a2_raw,
                      f"{self.ev}/weekly-runs.json": self.runs()}
        self.status = {"now": NOW, "status": json.dumps({"interval_s": 5, "last_poll_ts": ts(NOW - 1)})}

    # -- the producers' records ------------------------------------------------

    def bindings(self, **over):
        """The five bindings as root computes them for this host."""
        import hub_runtime as hr
        import partition_run as prun
        lanes = prun.selected_lanes(json.loads(tai.pa.final_bytes(self.staged, "r1:" + "0" * 64)),
                                    read=lambda p: LANES)
        out = {"host_setup": hashlib.sha256(self.document_raw).hexdigest(),
               "email_router": hr.spec_sha256(hr.run_spec(self.spec, self.spec.hub)),
               "lanes": pp.lane_binding(lanes, self.stat), "key": "f" * 64,
               "local_router": pa.activation_binding(self.a1_spec, self.staged)}
        out.update(over)
        return out

    def document(self, *, run_id, at, verdicts=None, p03=None, **over):
        probes = [probe(i, (verdicts or {}).get(i, "PASS")) for i in pe.PROBE_IDS]
        if p03 is not None:
            next(x for x in probes if x["id"] == "P03")["target_role"] = p03
        return build(host="alpha", run_id=run_id, at=at, probes=probes, bindings=self.bindings(**over))

    def runs(self, runs=()):
        return pe.canonical({"schema": pruns.RUNS_SCHEMA, "host": "alpha", "at": AT_7D, "runs": list(runs)})

    def seven_d(self, *, run_id="r7", at=AT_7D, **over):
        raw = self.document(run_id=run_id, at=at, **over)
        self.files[f"{self.ev}/partition-{run_id}.json"] = raw
        self.files[f"{self.ev}/stop-target.json"] = pe.canonical({
            "schema": ps.TARGET_SCHEMA, "host": "alpha", "run_id": run_id, "at": at, "evidence_dir": self.ev,
            "live_config_path": self.spec.keys.local_config, "engine": self.spec.supervision.engine,
            "docker": os.path.realpath(self.spec.partition.tools["docker"]), "router_container_id": CID,
            "config_sha256": hashlib.sha256(self.live_raw).hexdigest(), "evidence_run_id": "r1",
            "evidence_sha256": hashlib.sha256(self.a2_raw).hexdigest(), "inspect_digest": "e" * 64,
            "activation_sha256": hashlib.sha256(self.record).hexdigest()})
        return raw

    # -- the injected reads ----------------------------------------------------

    def read(self, path):
        if path not in self.files:
            raise FileNotFoundError(2, "No such file or directory", path)
        return self.files[path]

    def stat(self, path):
        return self.lane_stat.setdefault(path, FakeStat(stat.S_IFDIR | 0o755, ino=len(self.lane_stat) + 10))

    def lstat(self, path):
        if path in self.files:
            return FakeStat(stat.S_IFREG | 0o444)
        return FakeStat(stat.S_IFDIR | 0o755)

    def check(self, **over):
        p = {"read": self.read, "read_live": lambda path: self.live_raw, "read_lanes": lambda path: LANES,
             "inspect": lambda ref: self.inspects.get(ref), "image": lambda live: IMAGE,
             "status": self.status, "stat": self.stat, "lstat": self.lstat}
        p.update(over)
        try:
            inputs, cells = pc.evaluate(self.spec, document_raw=self.document_raw,
                                        document_sha256=hashlib.sha256(self.document_raw).hexdigest(), now=NOW, p=p)
        except Exception as e:  # a crash is not a verdict
            self.fail(f"evaluate raised {e!r}")
        doc = json.loads(pc.document(host="alpha", at=pc.utc_now(NOW), inputs=inputs, cells=cells))
        return doc, {c["id"]: c for c in doc["checks"]}


class SequenceTest(Host):
    """The first activation's two readings, through the real functions."""

    def test_after_a4_and_before_7d(self):
        """Step 6: V1 and V2 PASS; T1 FAILs with the step-7d remedy; R1
        PASSes on A2's empty run record; E1 and E2 are UNKNOWN, never FAIL;
        --ready refuses."""
        doc, c = self.check()
        self.assertEqual([c[i]["result"] for i in pc.IDS],
                         [rh.PASS, rh.PASS, rh.UNKNOWN, rh.UNKNOWN, rh.FAIL, rh.PASS], doc)
        self.assertEqual(c["T1"]["reason"], "no stop target: the weekly job has not recorded one")
        self.assertEqual(c["E1"]["reason"], pc.residue(None) + "; no stop target yet: run step 7d")
        self.assertIn("<none>", c["E1"]["claim"])
        self.assertEqual(c["E2"]["reason"], pc.NO_CURRENT)
        self.assertIsNone(doc["inputs"]["key_observed"])
        self.assertFalse(pc.ready(doc))

    def test_after_7d_all_six_pass(self):
        raw = self.seven_d()
        doc, c = self.check()
        self.assertEqual([c[i]["result"] for i in pc.IDS], [rh.PASS] * 6, doc)
        self.assertTrue(pc.ready(doc))
        observed = {"run_id": "r7", "at": AT_7D, "document_sha256": hashlib.sha256(raw).hexdigest()}
        self.assertEqual(doc["inputs"]["key_observed"], observed)
        self.assertEqual(c["E1"]["claim"], pc.E1_CLAIM.format(path=f"{self.ev}/partition-r1.json", run_id="r7",
                                                            at=AT_7D))
        self.assertEqual(c["E1"]["reason"], pc.residue(observed))     # the prefix alone on a PASS
        self.assertEqual(doc["schema"], "amap-deploy.partition-check/2")

    def test_the_key_changing_between_a2_and_7d_fails_e1(self):
        self.seven_d(key="e" * 64)
        doc, c = self.check()
        self.assertEqual(c["E1"]["result"], rh.FAIL)
        self.assertTrue(c["E1"]["reason"].endswith("; " + pc.KEY_CHANGED), c["E1"]["reason"])
        self.assertFalse(pc.ready(doc))

    def test_p03_roles_come_from_7d_and_a_difference_is_not_pass(self):
        """A2's P03 roles meet 7d's here first (a5_snapshot passes none)."""
        self.seven_d(p03=["key:signing", "key:dir", "mount:hop", "mount:other"])
        self.assertNotEqual(self.check()[1]["E1"]["result"], rh.PASS)

    def test_a_newer_third_document_is_never_the_7d_one(self):
        self.seven_d()
        self.files[f"{self.ev}/partition-r9.json"] = self.document(run_id="r9", at=AT_7D, key="e" * 64)
        doc, c = self.check()
        self.assertEqual((c["E1"]["result"], doc["inputs"]["key_observed"]["run_id"]), (rh.PASS, "r7"))

    def test_each_7d_clause_failing_is_unknown_and_names_it(self):
        rows = {
            "the 7d document absent": (lambda: self.files.pop(f"{self.ev}/partition-r7.json"), "is absent"),
            "the 7d document too old": (lambda: self.seven_d(at="2026-10-01T00:00:00Z"), "not current"),
            "a stop target citing another document": (
                lambda: self.files.update({f"{self.ev}/stop-target.json": self.files[f"{self.ev}/stop-target.json"]
                                           .replace(hashlib.sha256(self.a2_raw).hexdigest().encode(),
                                                    b"0" * 64)}), "does not cite A2's document"),
        }
        for label, (change, words) in rows.items():
            with self.subTest(label):
                self.setUp()
                self.seven_d()
                change()
                doc, c = self.check()
                self.assertEqual(c["E1"]["result"], rh.UNKNOWN, c["E1"])
                self.assertIn(words, c["E1"]["reason"])
                self.assertEqual(c["E2"]["reason"], pc.NO_CURRENT)


class NotRequiredTest(Host):
    """d2 §4.4's mapping: a live config without delegation and no gate makes
    verify_target's and verify_runs' PASS a not-required cell, emitted as
    UNKNOWN with the base claim and the not-required reason."""

    def test_t1_and_r1(self):
        self.live_raw = json.dumps({"state_dir": "/s"}).encode()
        doc, c = self.check()
        for cid, base in (("T1", ps.TARGET_CLAIM), ("R1", pruns.RUNS_CLAIM)):
            with self.subTest(cid):
                self.assertEqual((c[cid]["result"], c[cid]["claim"], c[cid]["reason"]),
                                 (rh.UNKNOWN, base, pc.NOT_REQUIRED))


class CellTest(unittest.TestCase):
    """The emitter's four cases, on checks the real constructors build."""

    WANT = rh.Fact("x", True, "a test")

    def test_unknown_fail_and_pass(self):
        u = rh.unknown("a claim", self.WANT, "the engine did not answer", "ask it")
        f = rh.check("a claim", self.WANT, "a sentence that says why", "fix it", ok=lambda e, a: a is True)
        g = rh.check("a claim", self.WANT, True, "fix it", ok=lambda e, a: a is True)
        self.assertEqual(pc.cell("T1", u)["reason"], "the engine did not answer")
        self.assertEqual(pc.cell("T1", f)["reason"], "a sentence that says why")
        self.assertEqual((pc.cell("T1", g)["reason"], pc.cell("T1", g)["remedy"]), ("", ""))


class StatusTest(unittest.TestCase):
    """V2's in-container read: one predicate on [1]'s clock, and the reload
    flag as router_health reads it."""

    def read(self, age=1.0, interval=5, **doc):
        body = {"interval_s": interval, "last_poll_ts": ts(NOW - age)}
        body.update(doc)
        return {"now": NOW, "status": json.dumps(body)}

    def test_the_freshness_boundaries(self):
        bound = rh.FRESHNESS_MULTIPLE * 5
        for age, want in ((-pe.CLOCK_TOLERANCE_S, rh.PASS), (-pe.CLOCK_TOLERANCE_S - 1, rh.UNKNOWN),
                          (bound, rh.PASS), (bound + 1, rh.UNKNOWN)):
            with self.subTest(age=age):
                self.assertEqual(pc.status_problem(self.read(age=age))[0], want)

    def test_the_host_clock_never_enters(self):
        import time
        real = time.time
        self.addCleanup(setattr, time, "time", real)
        for skew in (-3600, 3600):
            time.time = lambda s=skew: real() + s
            self.assertEqual(pc.status_problem(self.read())[0], rh.PASS)

    def test_malformed_inputs_are_unknown(self):
        rows = {"a malformed timestamp": dict(self.read(), status=json.dumps({"interval_s": 5, "last_poll_ts": "x"})),
                "no clock": {"status": self.read()["status"]},
                "a clock that is not a number": dict(self.read(), now="soon"),
                "status unreadable": {"now": NOW, "error": "EACCES"}}
        for label, r in rows.items():
            with self.subTest(label):
                self.assertEqual(pc.status_problem(r)[0], rh.UNKNOWN)
        for bad in (True, "5", float("nan"), 0.5):
            with self.subTest(interval=bad):
                self.assertEqual(pc.status_problem(self.read(interval=bad))[0], rh.UNKNOWN)

    def test_the_six_classification_cases(self):
        rows = [({}, rh.PASS), ({"classification": None}, rh.PASS), ({"classification": {"other": 1}}, rh.PASS),
                ({"classification": {"config_reload_failed": False}}, rh.PASS),
                ({"classification": {"config_reload_failed": True}}, rh.FAIL),
                ({"classification": []}, rh.UNKNOWN), ({"classification": {"config_reload_failed": "yes"}}, rh.UNKNOWN)]
        for extra, want in rows:
            with self.subTest(extra=extra):
                got = pc.status_problem(self.read(**extra))
                self.assertEqual(got[0], want, got)
                if want == rh.FAIL:
                    self.assertEqual(got[1], pc.RELOAD_FAILED)


class DocumentTest(unittest.TestCase):

    def test_the_document_is_exactly_its_members(self):
        cells = [{"id": i, "claim": "c", "result": rh.PASS, "reason": "", "remedy": ""} for i in pc.IDS]
        doc = json.loads(pc.document(host="alpha", at=pc.utc_now(NOW), inputs=dict.fromkeys(pc.INPUT_MEMBERS),
                                     cells=cells))
        self.assertEqual(set(doc), {"schema", "host", "at", "inputs", "checks"})
        self.assertEqual(doc["schema"], "amap-deploy.partition-check/2")
        self.assertEqual(set(doc["inputs"]), set(pc.INPUT_MEMBERS))
        with self.assertRaises(ValueError):
            pc.document(host="alpha", at="x", inputs={}, cells=cells)
        self.assertTrue(pc.ready(doc))
        self.assertFalse(pc.ready(dict(doc, checks=cells[:5])))

    def test_e1_literal(self):
        self.assertEqual(pc.E1_CLAIM, "the partition evidence {path} is well-formed and passing, with the key "
                                      "identity as root observed it in run {run_id} at {at}")


class VerbTest(Host):
    """`partition-check`: the object is written whenever the document loads;
    exit 0 means only that, and --ready means six PASS."""

    def run_verb(self, ready_only, tmp):
        import host_setup as hsu
        path = os.path.join(tmp, "document.json")
        with open(path, "wb") as f:
            f.write(self.document_raw)
        self.addCleanup(setattr, hsu, "load_spec", hsu.load_spec)
        hsu.load_spec = lambda sec: self.spec
        said = []
        p = {"read": self.read, "read_live": lambda q: self.live_raw, "read_lanes": lambda q: LANES,
             "inspect": lambda ref: self.inspects.get(ref), "image": lambda live: IMAGE, "status": self.status,
             "stat": self.stat, "lstat": self.lstat}
        rc = pc.run(path, hashlib.sha256(self.document_raw).hexdigest(), ready_only=ready_only, out=said.append,
                    now=NOW, p=p)
        return rc, said

    def test_exit_status(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            for ready_only, want in ((False, 0), (True, 1)):          # before 7d: written, not ready
                with self.subTest(ready_only=ready_only):
                    rc, said = self.run_verb(ready_only, tmp)
                    self.assertEqual(rc, want)
                    self.assertEqual(json.loads(said[-1])["schema"], pc.SCHEMA)
            self.seven_d()
            self.assertEqual(self.run_verb(True, tmp)[0], 0)         # after 7d: ready
        self.assertEqual(pc.run("/nonexistent/document.json", "0" * 64, out=lambda s: None), 2)

    def test_the_cli_passes_the_flag(self):
        import amap_sandy as prov
        seen = []
        self.addCleanup(setattr, pc, "run", pc.run)
        pc.run = lambda path, sha, ready_only=False, **k: seen.append((path, sha, ready_only)) or 0
        self.assertEqual(prov.main(["partition-check", "--document", "/d.json", "--document-sha256", "a" * 64,
                                    "--ready"]), 0)
        self.assertEqual(seen, [("/d.json", "a" * 64, True)])
