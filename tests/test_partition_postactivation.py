"""A5's post-activation document: P01 and P02 against the final router, never
evidence. Its probes are partition_probe's own pieces, held equal to the
weekly run's P01 and P02 on the same plan (test_partition_probe's fixture).
"""

import hashlib
import json
import os
import tempfile
import unittest

import partition_check as pc
import partition_evidence as pe
import partition_postactivation as ppa
import partition_probe as pp
import partition_setup as ps
import router_health as rh
from test_hub_runtime import setUpModule, tearDownModule  # noqa: F401 -- the fixture's pins, restored
from test_partition_check import Host
from test_partition_evidence import AT, probe as evidence_probe
import test_partition_probe as tpp

import hub_runtime as hr


def doc(**over):
    args = dict(host="alpha", run_id="pa-1", at=AT, names_token="r1:" + "a" * 64,
                router={"container_id": "c" * 64, "inspect_digest": "d" * 64},
                bindings={k: "e" * 64 for k in ppa.BINDING_KEYS},
                probes=[evidence_probe("P01"), evidence_probe("P02")])
    args.update(over)
    return ppa.build(**args)


class GrammarTest(unittest.TestCase):

    def test_it_round_trips_and_is_never_evidence(self):
        raw = doc()
        self.assertEqual(ppa.parse(raw, host="alpha")["schema"], ppa.SCHEMA)
        self.assertNotIn(pe.TOKEN_MEMBER, json.loads(raw))
        with self.assertRaises(pe.EvidenceError):           # refused at its members first, or its schema
            pe.parse(raw, host="alpha")
        self.assertFalse(ps.evidence_name_ok(ppa.name("pa-1")))
        self.assertTrue(ps.evidence_name_ok("partition-pa-1.json"))

    def test_refusals(self):
        good = json.loads(doc())
        rows = {"a token member": dict(good, **{pe.TOKEN_MEMBER: None}),
                "another host": dict(good, host="beta"),
                "P03 among the probes": dict(good, probes=good["probes"] + [evidence_probe("P03")]),
                "P02 before P01": dict(good, probes=list(reversed(good["probes"]))),
                "a key binding": dict(good, bindings=dict(good["bindings"], key="f" * 64)),
                "a short container id": dict(good, router={"container_id": "c", "inspect_digest": "d" * 64}),
                "the evidence schema": dict(good, schema=pe.SCHEMA)}
        for label, d in rows.items():
            with self.subTest(label):
                with self.assertRaises(ppa.PostActivationError):
                    ppa.parse(pe.canonical(d), host="alpha")
        with self.assertRaises(ppa.PostActivationError):
            ppa.parse(json.dumps(good).encode(), host="alpha")       # not canonical


class ProbeTest(unittest.TestCase):
    """P01 and P02 from partition_probe's pieces equal the weekly run's. The
    plan, engine and paths are test_partition_probe's fixture, borrowed
    without its tests."""

    setUp, plan, run_it = tpp.ProbeRunTest.setUp, tpp.ProbeRunTest.plan, tpp.ProbeRunTest.run_it

    def test_p01_and_p02_equal_the_weekly_run_s(self):
        weekly, _, _ = self.run_it()
        want = {p["id"]: p for p in json.loads(weekly)["probes"] if p["id"] in ppa.PROBE_IDS}
        self.engine.seen.clear()
        probes, code, report = ppa.probe(self.plan(), pp.Runner(["docker"], self.engine), hr.argv, self.lstat)
        self.assertEqual({p["id"]: p for p in probes}, want)
        self.assertEqual(code, 0, report)

    def test_a_role_outside_the_vocabulary_runs_no_probe(self):
        """partition_probe.run's other precondition: refused before any
        exec, run or lstat."""
        looked = []
        self.addCleanup(setattr, pe, "role_ok", pe.role_ok)
        pe.role_ok = lambda r: not r.startswith("marker:")
        self.engine.seen.clear()
        probes, code, report = ppa.probe(self.plan(), pp.Runner(["docker"], self.engine), hr.argv,
                                         lambda q: looked.append(q))
        self.assertEqual((probes, code, self.engine.seen, looked), ([], 2, [], []), report)
        self.assertIn("is outside the evidence vocabulary", report[0])


class EvidenceIgnoresItTest(Host):
    """A placed post-activation document is never what E1 and E2 judge."""

    def test_e1_still_judges_a2_s_document(self):
        self.seven_d()
        self.files[f"{self.ev}/{ppa.name('pa-1')}"] = doc(names_token=self.token)
        d, c = self.check()
        self.assertEqual((c["E1"]["result"], d["inputs"]["evidence_path"]),
                         (rh.PASS, f"{self.ev}/partition-r1.json"))


class RefusalTest(Host):
    """Each refusal writes nothing and runs no probe."""

    def verb(self, t_run_id="r1", document_sha256=None, **over):
        import host_setup as hsu
        tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, tmp)
        path = os.path.join(tmp, "document.json")
        with open(path, "wb") as f:
            f.write(self.document_raw)
        real_load = hsu.load_spec
        import dataclasses
        self.spec = dataclasses.replace(self.spec, secrets=dataclasses.replace(self.spec.secrets, run_dir=tmp))
        calls = []
        p = {"read": self.read, "read_live": lambda q: self.live_raw, "read_lanes": lambda q: b"{}",
             "runner": lambda argv: calls.append(argv) or rh.Unresolved("no engine in this row")}
        p.update(over)
        said = []
        hsu.load_spec = lambda sec: self.spec
        try:
            rc = ppa.run(path, document_sha256 or hashlib.sha256(self.document_raw).hexdigest(), t_run_id,
                         apply=True, out=said.append, now=pe.at_seconds(AT), p=p)
        finally:
            hsu.load_spec = real_load
        return rc, said, sorted(os.listdir(tmp)), calls

    def engine(self, email):
        """docker as the verb asks it: [1] runs A1's spec; the email router is
        `email` (None: no such container); its image's environment is empty."""
        router = self.spec.runtime_of(self.spec.hops[0][1])["container"]

        def answer(argv):
            calls.append(argv)
            if argv[:3] == ["inspect", "--type", "container"]:
                doc = {router: self.live}.get(argv[3], email if argv[3] != router else None)
                return rh.Proc(tuple(argv), 1, "", "") if doc is None else rh.Proc(tuple(argv), 0, json.dumps([doc]), "")
            if argv[:2] == ["image", "inspect"]:
                return rh.Proc(tuple(argv), 0, "[]", "")
            return rh.Proc(tuple(argv), 1, "", "")
        calls = []
        return answer, calls

    def test_the_email_router_must_be_its_running_rendering(self):
        """partition_probe.run's own precondition: nothing a differing or
        absent email router showed would stand for it."""
        for label, email in (("not running", None), ("differs from its rendering", {"Config": {"Image": "other"}})):
            with self.subTest(label):
                self.setUp()
                runner, calls = self.engine(email)
                rc, said, written, _ = self.verb(runner=runner, read_lanes=lambda q: b'{"selected": []}',
                                                 stat=lambda q: None)
                self.assertEqual(rc, 2, said)
                self.assertIn("the running email router is not its rendering", "\n".join(said))
                self.assertEqual(written, ["document.json"])
                self.assertFalse([c for c in calls if c[:1] in (["run"], ["exec"])])

    def test_an_unresolved_lane_binding_writes_nothing(self):
        runner, calls = self.engine(None)
        rc, said, written, _ = self.verb(runner=runner, read_lanes=lambda q: b"not json")
        self.assertEqual((rc, written), (2, ["document.json"]), said)
        self.assertFalse([c for c in calls if c[:1] in (["run"], ["exec"])])

    def test_each_refusal(self):
        def unissued():
            raw = self.document(run_id="r1", at=AT, verdicts={"P03": "FAIL"})
            self.files[f"{self.ev}/partition-r1.json"] = raw
            self.live_raw = __import__("partition_activation").final_bytes(
                self.staged, pe.token_of(json.loads(raw)))
        rows = {"another run's token": (dict(t_run_id="r9"), None, "not of T's run"),
                "a document that is not the unit's": (dict(document_sha256="0" * 64), None, "--document-sha256"),
                "a token no document issued": ({}, unissued, "names no issued document"),
                "the router not running": ({}, None, "not affirmed running")}
        for label, (kw, change, words) in rows.items():
            with self.subTest(label):
                self.setUp()
                if change:
                    change()
                rc, said, written, calls = self.verb(**kw)
                self.assertEqual(rc, 2, said)
                self.assertIn(words, "\n".join(said))
                self.assertEqual(written, ["document.json"])
                self.assertFalse([c for c in calls if c[:1] in (["run"], ["exec"])])


class BundleTest(unittest.TestCase):
    """PR-b's new modules stay outside the weekly job's bundle, so the writer
    bundle's digest does not move with them."""

    def test_the_new_modules_are_not_in_the_closure(self):
        from pathlib import Path
        closure = (Path(__file__).resolve().parent.parent / "partition_weekly.closure").read_text().split()
        for module in ("partition_postactivation.py", "partition_check.py"):
            with self.subTest(module):
                self.assertNotIn(module, closure)
