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
from test_hub_supervise import supervise
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
        tai.partition_doc = lambda *a, **k: supervise(orig(*a, **k), "systemd")
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
        self.assertEqual((c["E1"]["result"], (doc["inputs"]["key_observed"] or {}).get("run_id")), (rh.PASS, "r7"))

    def retarget(self, **over):
        path = f"{self.ev}/stop-target.json"
        self.files[path] = pe.canonical(dict(json.loads(self.files[path]), **over))

    def move_live_key(self):
        live = json.loads(self.live_raw)
        live["delegation"]["signing_key"]["path"] = "/opt/ex/other-keys/key"
        self.live_raw = json.dumps(live).encode()

    def test_each_7d_clause_failing_is_unknown_and_names_it(self):
        rows = {
            "the 7d document absent": (lambda: self.files.pop(f"{self.ev}/partition-r7.json"), "is absent"),
            "the 7d document too old": (lambda: self.seven_d(at="2026-10-01T00:00:00Z"), "not current"),
            "a stop target citing another document": (
                lambda: self.files.update({f"{self.ev}/stop-target.json": self.files[f"{self.ev}/stop-target.json"]
                                           .replace(hashlib.sha256(self.a2_raw).hexdigest().encode(),
                                                    b"0" * 64)}), "does not cite A2's document"),
            "a stop target of another host": (lambda: self.retarget(host="beta"), "another host's"),
            "a stop target from another activation_sha256": (
                lambda: self.retarget(activation_sha256="0" * 64), "another A1 activation"),
            "a signing key path differing in the live config": (self.move_live_key, "signing key path"),
            "a 7d document ahead of the clock": (
                lambda: self.seven_d(at=pc.utc_now(NOW + pe.CLOCK_TOLERANCE_S + 60)), "not current"),
            "a 7d document older than A2's": (
                lambda: self.seven_d(at=pc.utc_now(pe.at_seconds(AT) - 60)), "older than A2's document"),
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


class StatusExecTest(Host):
    """V2's exec names the container V1 judged by its inspect Id, never by
    name."""

    def test_the_exec_targets_the_inspected_id(self):
        seen = []
        self.addCleanup(setattr, pc, "ask_json", pc.ask_json)
        pc.ask_json = lambda spec, argv, what: seen.append(argv) or rh.Unresolved("recorded")
        p = {"read": self.read, "read_live": lambda path: self.live_raw, "read_lanes": lambda path: LANES,
             "inspect": lambda ref: self.inspects.get(ref), "image": lambda live: IMAGE,
             "stat": self.stat, "lstat": self.lstat}
        pc.evaluate(self.spec, document_raw=self.document_raw,
                    document_sha256=hashlib.sha256(self.document_raw).hexdigest(), now=NOW, p=p)
        execs = [a for a in seen if a[:1] == ["exec"]]
        self.assertEqual([a[1] for a in execs], [CID])


class MalformedLiveTest(Host):
    """Wherever the host-setup document loads, a malformed live config or
    status still yields the whole six-cell object, with no PASS on a claim
    the malformed value decides, in both the normal and --ready modes."""

    SHAPES = ("bad", "", 0, 1.5, True, False, None, [], ["x"], {})

    def configs(self):
        base = json.loads(self.live_raw)
        block = base["delegation"]
        rows = {}
        for shape in self.SHAPES:
            rows[f"delegation={shape!r}"] = json.dumps(dict(base, delegation=shape)).encode()
            rows[f"partition_verified={shape!r}"] = json.dumps(
                dict(base, delegation=dict(block, partition_verified=shape))).encode()
            rows[f"signing_key={shape!r}"] = json.dumps(dict(base, delegation=dict(block, signing_key=shape))).encode()
        for label, raw in (("not JSON", b"not json"), ("null", b"null"), ("a list", b"[1]"), ("a string", b'"x"'),
                           ("deeply nested", b"[" * 100000 + b"]" * 100000), ("not UTF-8", b"\xff\xfe")):
            rows[label] = raw
        return rows

    def test_every_shape_keeps_the_six_cells(self):
        import tempfile
        verb = VerbTest.run_verb
        for seven in (False, True):
            self.setUp()
            if seven:
                self.seven_d()
            for label, raw in self.configs().items():
                with self.subTest(label, after_7d=seven):
                    self.setUp()
                    if seven:
                        self.seven_d()
                    good = self.live_raw
                    self.live_raw = raw
                    doc, cells = self.check()
                    self.assertEqual(list(cells), list(pc.IDS))
                    if raw != good:
                        self.assertNotEqual(cells["E2"]["result"], rh.PASS, cells["E2"])
                        self.assertNotEqual(cells["V2"]["result"], rh.PASS, cells["V2"])
                    with tempfile.TemporaryDirectory() as tmp:
                        for ready_only, want in ((False, 0), (True, 1)):
                            rc, said = verb(self, ready_only, tmp)
                            self.assertEqual(rc, want, said)
                            written = [json.loads(x) for x in said if x.startswith("{")]
                            self.assertEqual(len(written), 1, said)
                            self.assertEqual([c["id"] for c in written[0]["checks"]], list(pc.IDS))

    def test_a_malformed_status_keeps_the_six_cells(self):
        import tempfile
        self.seven_d()
        for label, status in (("a huge clock", {"now": 10 ** 400, "status": self.status["status"]}),
                              ("a huge interval", {"now": NOW, "status": json.dumps(
                                  {"interval_s": 10 ** 400, "last_poll_ts": ts(NOW - 1)})}),
                              ("a bool interval", {"now": NOW, "status": json.dumps(
                                  {"interval_s": True, "last_poll_ts": ts(NOW - 1)})})):
            with self.subTest(label):
                self.status = status
                with tempfile.TemporaryDirectory() as tmp:
                    for ready_only, want in ((False, 0), (True, 1)):
                        rc, said = VerbTest.run_verb(self, ready_only, tmp)
                        self.assertEqual(rc, want, said)
                        checks = {c["id"]: c for c in json.loads(said[-1])["checks"]}
                        self.assertEqual(list(checks), list(pc.IDS))
                        self.assertEqual(checks["V2"]["result"], rh.UNKNOWN, checks["V2"])

    def test_the_valid_control(self):
        import tempfile
        self.seven_d()
        with tempfile.TemporaryDirectory() as tmp:
            for ready_only in (False, True):
                rc, said = VerbTest.run_verb(self, ready_only, tmp)
                self.assertEqual(rc, 0, said)
                self.assertEqual({c["result"] for c in json.loads(said[-1])["checks"]}, {rh.PASS})


CLAIMS = {
    "V1": "the running local router is exactly its activation spec",
    "V2": "the local router's live config is the activation rendering plus the token, and nothing else",
    "E1": ("the partition evidence /opt/ex/partition-evidence/partition-r1.json is well-formed and passing, with "
           "the key identity as root observed it in run {run_id} at {at}"),
    "E2": "the local router signs with the current passing document's token, or not at all",
    "T1": "the weekly job has a stop target: the recorded id is the running local router",
    "R1": "no run of the weekly job is left undecided",
}


class ClaimsTest(Host):
    """d2 §4.4: the six ids pinned to their claim strings, on every path that
    emits them; and an unreadable input keeps all six ids, UNKNOWN."""

    def claims(self, cells, run_id="r7", at=AT_7D):
        return {k: v["claim"] for k, v in cells.items()}, dict(CLAIMS, E1=CLAIMS["E1"].format(run_id=run_id, at=at))

    def test_the_six_claims_after_7d(self):
        self.seven_d()
        got, want = self.claims(self.check()[1])
        self.assertEqual(got, want)

    def test_the_six_claims_before_7d(self):
        got, want = self.claims(self.check()[1], run_id=pc.NONE, at=pc.NONE)
        self.assertEqual(got, want)

    def test_a1_s_record_unreadable(self):
        self.seven_d()
        self.files.pop(f"{self.ev}/{ps.ACTIVATION}")
        doc, cells = self.check()
        self.assertEqual(list(cells), list(pc.IDS))
        for cid in ("V1", "V2", "E1", "E2"):
            with self.subTest(cid):
                self.assertEqual(cells[cid]["result"], rh.UNKNOWN, cells[cid])
                self.assertTrue(cells[cid]["reason"], cells[cid])
        self.assertEqual({k: cells[k]["claim"] for k in ("V1", "V2", "E2")},
                         {k: CLAIMS[k] for k in ("V1", "V2", "E2")})

    def test_the_evidence_unreadable(self):
        self.seven_d()
        self.files.pop(f"{self.ev}/partition-r1.json")
        doc, cells = self.check()
        self.assertEqual(list(cells), list(pc.IDS))
        for cid in ("E1", "E2"):
            with self.subTest(cid):
                self.assertEqual(cells[cid]["result"], rh.UNKNOWN, cells[cid])
                self.assertTrue(cells[cid]["reason"], cells[cid])
        self.assertEqual(cells["E2"]["claim"], CLAIMS["E2"])


class V2WiringTest(Host):
    """V2's cell carries the router's own status through evaluate and the
    verb: a refused reload FAILs with its sentence; a stale status, or one
    ahead of the router's clock, is UNKNOWN; --ready refuses each."""

    def status_of(self, age=1.0, **doc):
        body = {"interval_s": 5, "last_poll_ts": ts(NOW - age)}
        body.update(doc)
        return {"now": NOW, "status": json.dumps(body)}

    def test_each_status_reaches_the_cell(self):
        import tempfile
        rows = {"a refused reload": (self.status_of(classification={"config_reload_failed": True}), rh.FAIL),
                "stale": (self.status_of(age=rh.FRESHNESS_MULTIPLE * 5 + 1), rh.UNKNOWN),
                "ahead of the router's clock": (self.status_of(age=-pe.CLOCK_TOLERANCE_S - 1), rh.UNKNOWN)}
        for label, (status, want) in rows.items():
            with self.subTest(label):
                self.setUp()
                self.seven_d()
                self.status = status
                cells = self.check()[1]
                self.assertEqual(cells["V2"]["result"], want, cells["V2"])
                if want == rh.FAIL:
                    self.assertEqual(cells["V2"]["reason"], pc.RELOAD_FAILED)
                self.assertEqual({k: v["result"] for k, v in cells.items() if k != "V2"},
                                 dict.fromkeys(("V1", "E1", "E2", "T1", "R1"), rh.PASS))
                with tempfile.TemporaryDirectory() as tmp:
                    self.assertEqual(VerbTest.run_verb(self, True, tmp)[0], 1)


class WriterHostSetupTest(unittest.TestCase):
    """PRb-d3 B3: on the writer harness's own output, the host_setup the
    weekly run binds is the one partition-check computes. The real writer
    (host_steps partition-weekly, as a process) hands its child the document
    as `document.json`; the weekly child binds sha256 of those bytes
    (partition_run.bindings), and partition-check binds sha256 of the bytes
    at the unit's --document. The harness's child copies what it was handed
    out of its run directory."""

    def test_the_child_s_document_is_the_unit_s(self):
        import subprocess
        import tempfile
        import host_steps as hsteps
        import partition_run as prun
        import test_partition_weekly_writer as tw
        root = tempfile.mkdtemp(dir="/tmp", prefix="pc")
        self.addCleanup(tw.WriterTest._rm, root)
        h = tw.Host(os.path.realpath(root))
        self.addCleanup(h.sock.close)
        copy = ("run_dir, fd = args[\"--run-dir\"], int(args[\"--lock-fd\"])\n"
                "import shutil; shutil.copyfile(os.path.join(run_dir, 'document.json'), "
                "os.path.join(SIDE, 'document.json'))\n")
        child = tw.CHILD.replace('run_dir, fd = args["--run-dir"], int(args["--lock-fd"])\n', copy)
        self.assertNotEqual(child, tw.CHILD)
        h.bundle(extra={"partition_weekly.py": f"PLAN, SIDE, REPO, STATE = {h.root + '/plan.json'!r}, {h.side!r}, "
                                               f"{str(tw.REPO)!r}, {h.state!r}\n" + child})
        h.plan([["expect", tw.B], ["evidence", tw.B, tw.PASS], ["outcome", 0, tw.TARGET]])
        p = h.run()
        self.assertEqual(p.returncode, hsteps.EXIT_PASS, p.stdout + p.stderr)
        with open(os.path.join(h.side, "document.json"), "rb") as f:
            handed = f.read()
        with open(h.doc, "rb") as f:
            unit = f.read()
        weekly = prun.bindings(document=handed, email={}, lanes={}, key_path=h.doc, key_dir=root,
                               router={"mounts": []}, live_raw=b"{}")
        self.assertEqual(handed, unit)
        self.assertEqual(weekly["host_setup"], hashlib.sha256(unit).hexdigest())
        self.assertEqual(weekly["host_setup"], h.digest)                     # the unit's --document-sha256


class VerifySequenceTest(Host):
    """d4 S1 / d5: the fresh-host sequence through `verify`'s host-setup
    section on the same fixture: host_setup.checks and report, the real
    stop-target and weekly-runs checks (T1, R1) over the fixture's placed
    files and engine, and verify --a5's real exception logic. The host's
    other sections are stubbed empty, and the signing row is the verdict
    each platform gives an activated router (proved in test_signing_matrix
    and test_hub_supervise): PASS where the adoption witness runs, the
    launchd UNKNOWN with its exact reason on the Mac."""

    def verify(self, *, a5=False, launchd=False):
        import dataclasses
        import host_setup as hsu
        import hub_supervise as hv
        from pathlib import Path
        spec = self.spec
        if launchd:
            spec = dataclasses.replace(spec, supervision=dataclasses.replace(spec.supervision, kind=hv.KINDS[1]))
        run_id = json.loads(self.live_raw)["delegation"]["partition_verified"].partition(":")[0]
        want = rh.Fact("signing", True, "the policy and the gate")
        signing = (rh.unknown(hsu.hk.SIGNING_CLAIM, want, hsu.hk.a5_launchd_reason(run_id), "use a Linux host")
                   if launchd else rh.check(hsu.hk.SIGNING_CLAIM, want, True, "x"))
        stubs = [(hsu, "overlay_section", lambda overlay: {}), (hsu, "load_spec", lambda sec: spec),
                 (hsu, "print_notes", lambda *a, **k: None), (hsu.hk, "read_bytes", lambda p: self.live_raw),
                 (hsu.hk, "checks", lambda *a, **k: [signing])]
        for name in ("verify_roots", "verify_overlay", "verify_containers", "verify_mounts", "verify_openssl",
                     "verify_umasks", "verify_groups", "secret_checks", "verify_recovery_horizon"):
            stubs.append((hsu, name, lambda *a, **k: []))
        for mod, name in ((hsu.hr, "checks"), (hsu.hv, "checks"), (hsu.hv, "verify_enablement"), (hsu.hv, "labels"),
                          (hsu.hp, "checks"), (hsu.ps, "verify")):
            stubs.append((mod, name, lambda *a, **k: []))
        for mod, name, value in stubs:
            self.addCleanup(setattr, mod, name, getattr(mod, name))
            setattr(mod, name, value)
        said = []
        q = {"inspect": lambda ref: self.inspects.get(ref), "read_placed": self.read, "read": lambda p: self.live_raw}
        rc = hsu.verify_section(Path("/overlay.json"), out=said.append, a5=a5, containers=lambda c: None,
                                openssl={}, partition=q, policy_on=True)
        return rc, said

    def t1_lines(self, said):
        at = next(i for i, l in enumerate(said) if ps.TARGET_CLAIM in l)
        return said[at:at + 4]

    def test_before_7d_verify_fails_on_t1_with_its_found_line(self):
        rc, said = self.verify()
        self.assertEqual(rc, 1, said)
        lines = self.t1_lines(said)
        self.assertEqual(lines[0].split()[0], rh.FAIL, lines)
        self.assertIn("found: 'no stop target: the weekly job has not recorded one'", lines[2])
        self.assertEqual([l.split()[0] for l in said if l.startswith("  ") and not l.startswith("   ")],
                         [rh.PASS, rh.FAIL, rh.PASS], said)        # signing, T1, R1

    def test_after_7d_verify_passes(self):
        self.seven_d()
        rc, said = self.verify()
        self.assertEqual(rc, 0, said)
        self.assertIn(f"  {rh.PASS:7} {ps.TARGET_CLAIM}", said)

    def test_after_7d_verify_a5_passes_on_launchd_with_the_one_excused_row(self):
        self.seven_d()
        rc, said = self.verify(a5=True, launchd=True)
        self.assertEqual(rc, 0, said)
        self.assertTrue(any("the one expected non-pass" in l for l in said), said)
        import host_setup as hsu
        self.assertIn(f"  {rh.UNKNOWN:7} {hsu.hk.SIGNING_CLAIM}", said)
        self.assertEqual(self.verify(launchd=True)[0], 1)                 # plain verify does not excuse it

    def test_before_7d_verify_a5_still_fails_on_t1(self):
        rc, said = self.verify(a5=True, launchd=True)
        self.assertEqual(rc, 1, said)


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

    def judge(self, read):
        try:
            return pc.status_problem(read)
        except Exception as e:  # a crash is not a verdict
            self.fail(f"status_problem raised {e!r}")

    def test_numeric_admission_is_total(self):
        """Any JSON number reaching the clock or interval_s is admitted or
        UNKNOWN, never an exception: huge ints (past a float), non-finite
        floats and bools. The approved predicate stands: a huge but finite
        interval is in range."""
        huge = 10 ** 400
        for bad in (huge, -huge, True, False, float("inf"), float("-inf"), float("nan"), None, [1], {"n": 1}):
            with self.subTest(now=bad):
                got = self.judge(dict(self.read(), now=bad))
                self.assertEqual(got, (rh.UNKNOWN, "the container printed no clock"))
            with self.subTest(interval=bad):
                got = self.judge(self.read(interval=bad))
                self.assertEqual(got[0], rh.UNKNOWN, got)
                self.assertIn("interval_s is", got[1])
                self.assertLess(len(got[1]), 200)
        self.assertEqual(self.judge(self.read(interval=10.0 ** 300))[0], rh.PASS)
        deep = self.judge(dict(self.read(), status="[" * 100000 + "]" * 100000))
        self.assertEqual(deep[0], rh.UNKNOWN, deep)
        self.assertIn("not JSON", deep[1])
        self.assertEqual(self.judge(dict(self.read(), now=NOW + 0.5, status=json.dumps(
            {"interval_s": 5, "last_poll_ts": ts(NOW)})))[0], rh.PASS)

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
        for bad in (rh.FAIL, rh.UNKNOWN):
            with self.subTest(result=bad):
                one = [dict(c, result=bad) if c["id"] == "T1" else c for c in cells]
                self.assertFalse(pc.ready(dict(doc, checks=one)))

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
