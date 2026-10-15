"""partition_setup: the `partition` and `delegation_gate` sections, loaded from
the host-setup document test_hub_keys builds, and the gate judged against a
record built from harness_gate's healthy example."""

import hashlib
import json
import os
import stat
import tempfile
import unittest

import harness_gate as hg
import host_setup as hs
import partition_setup as ps
import router_health as rh
import secret_setup as ss
from test_harness_gate import IDS, SCHEMA, UNIT, healthy
from test_hub_keys import full_doc
from test_hub_runtime import setUpModule, tearDownModule  # noqa: F401 -- the fixture's pins, restored

EV = "/opt/ex/partition-evidence"
SCRATCH = "/opt/ex/partition-scratch"
PART = {"evidence_dir": EV, "scratch_dir": SCRATCH, "weekly": {"weekday": 0, "hour": 3}}


def doc(partition=PART, gate=None):
    d = full_doc()
    d[ss.SECTION]["exposure"]["integrity_roots"].append(EV)
    if partition is not None:
        d[ps.SECTION] = json.loads(json.dumps(partition))
    if gate is not None:
        d[ps.GATE_SECTION] = gate
    return d


def gate(**over):
    g = {"harness_sha": "4" * 40, "record_sha256": "0" * 64, "record_path": f"{EV}/gate-record.json"}
    g.update(over)
    return g


class LoadTest(unittest.TestCase):
    def refuses(self, d, words):
        with self.assertRaises(hs.SpecError) as e:
            hs.load_spec(d)
        self.assertIn(words, str(e.exception))

    def test_both_sections_load(self):
        s = hs.load_spec(doc(gate=gate()))
        self.assertEqual((s.partition.evidence_dir, s.partition.weekday, s.partition.hour), (EV, 0, 3))
        self.assertEqual(s.gate.record_path, f"{EV}/gate-record.json")

    def test_closed_member_sets(self):
        self.refuses(doc(partition=dict(PART, extra=1)), "exactly evidence_dir")
        self.refuses(doc(partition={k: v for k, v in PART.items() if k != "weekly"}), "exactly evidence_dir")
        self.refuses(doc(gate=dict(gate(), extra=1)), "exactly harness_sha")
        self.refuses(doc(gate={k: v for k, v in gate().items() if k != "record_sha256"}), "exactly harness_sha")

    def test_a_gate_without_the_partition_section_refuses(self):
        self.refuses(doc(partition=None, gate=gate()), "needs the partition section")

    def test_the_record_path_is_exactly_the_evidence_dirs_gate_record(self):
        self.refuses(doc(gate=gate(record_path=f"{EV}/other.json")), "must be exactly")
        self.refuses(doc(gate=gate(record_path="/tmp/gate-record.json")), "must be exactly")

    def test_the_evidence_dir_must_be_an_integrity_root(self):
        d = doc()
        d[ss.SECTION]["exposure"]["integrity_roots"].remove(EV)
        self.refuses(d, "integrity_roots")

    def test_a_scratch_dir_overlapping_a_live_path_refuses(self):
        self.refuses(doc(partition=dict(PART, scratch_dir=EV + "/s")), "overlaps")

    def test_the_weekly_schedule_is_bounded(self):
        self.refuses(doc(partition=dict(PART, weekly={"weekday": 7, "hour": 3})), "weekly")
        self.refuses(doc(partition=dict(PART, weekly={"weekday": 0, "hour": True})), "weekly")


class NamesTest(unittest.TestCase):
    def test_the_writer_places_only_its_own_products_never_the_gate_record(self):
        for ok in ("partition-r1.json", "partition-control-r1.json", "partition-risk.json",
                   "incident-r1/detected.json", "incident-r1/events.jsonl"):
            self.assertTrue(ps.evidence_name_ok(ok), ok)
        for bad in ("gate-record.json", "partition-../x.json", "incident-r1/other", "partition-r1.json.tmp", ""):
            self.assertFalse(ps.evidence_name_ok(bad), bad)


def st(mode, uid=0, gid=0):
    return os.stat_result((mode, 0, 0, 1, uid, gid, 0, 0, 0, 0))


class GateTest(unittest.TestCase):
    RL, HOP, PLUGIN = "1" * 40, "2" * 40, "3" * 64

    def setUp(self):
        for name, value in (("MUTANT_IDS_SHA256", hg.set_sha256(IDS)), ("MUTANT_COUNT", len(IDS)),
                            ("SCHEMA_SHA256", hashlib.sha256(SCHEMA.encode()).hexdigest()),
                            ("UNIT_SHA256", hashlib.sha256(UNIT.encode()).hexdigest())):
            self.addCleanup(setattr, hg, name, getattr(hg, name))
            setattr(hg, name, value)
        self.raw = hg.canonical(healthy())
        self.gs = ps.GateSpec(harness_sha="4" * 40, record_sha256=hashlib.sha256(self.raw).hexdigest(),
                              record_path=f"{EV}/gate-record.json")

    def problems(self, gs="default", **over):
        args = dict(rl_sha=self.RL, hop_sha=self.HOP, plugin_sha256=self.PLUGIN, read=lambda p: self.raw)
        args.update(over)
        return ps.gate_problems(self.gs if gs == "default" else gs, **args)

    def test_a_placed_passing_record_for_this_deployment_holds(self):
        self.assertEqual(self.problems(), [])

    def test_no_section_or_no_record_keeps_it_shut(self):
        self.assertEqual(self.problems(gs=None), ["the document has no delegation_gate section"])

        def gone(p):
            raise FileNotFoundError(p)
        self.assertIn("is absent", self.problems(read=gone)[0])

    def test_a_record_for_another_router_commit_keeps_it_shut(self):
        self.assertTrue(any(w.startswith("G3") for w in self.problems(rl_sha="9" * 40)))

    def test_an_unreadable_pin_keeps_it_shut(self):
        self.assertIn("cannot be read", self.problems(rl_sha=rh.Unresolved("no siblings.json"))[0])

    def test_a_harness_sha_not_copied_from_the_record_keeps_it_shut(self):
        gs = ps.GateSpec(harness_sha="5" * 40, record_sha256=self.gs.record_sha256, record_path=self.gs.record_path)
        self.assertEqual(self.problems(gs=gs),
                         ["delegation_gate.harness_sha is not the record's own harness_sha (copy it from the record)"])

    def test_verify_reports_the_gate_and_the_directories(self):
        files = {"/": st(stat.S_IFDIR | 0o755), "/opt": st(stat.S_IFDIR | 0o755), "/opt/ex": st(stat.S_IFDIR | 0o755),
                 EV: st(stat.S_IFDIR | 0o755), SCRATCH: st(stat.S_IFDIR | 0o700)}

        def lstat(p):
            if p not in files:
                raise FileNotFoundError(p)
            return files[p]
        part = ps.PartitionSpec(evidence_dir=EV, scratch_dir=SCRATCH, weekday=0, hour=3)
        found = ps.verify(part, self.gs, delegation_enabled=True, lstat=lstat, owned_chain=ss._owned_chain,
                          rl_sha=self.RL, hop_sha=self.HOP, plugin_sha256=self.PLUGIN, read=lambda p: self.raw)
        self.assertEqual([(c.claim, c.result) for c in found if c.result != rh.PASS], [])
        files[SCRATCH] = st(stat.S_IFDIR | 0o755)
        found = ps.verify(part, self.gs, delegation_enabled=True, lstat=lstat, owned_chain=ss._owned_chain,
                          rl_sha=self.RL, hop_sha=self.HOP, plugin_sha256=self.PLUGIN, read=lambda p: self.raw)
        self.assertEqual([c.claim for c in found if c.result == rh.FAIL],
                         [f"the partition scratch directory {SCRATCH} is root:root 700"])

    def test_absent_sections_are_a_note_without_delegation_and_a_fail_with_it(self):
        kw = dict(lstat=lambda p: None, owned_chain=ss._owned_chain, rl_sha=self.RL, hop_sha=self.HOP,
                  plugin_sha256=self.PLUGIN, read=lambda p: self.raw)
        [c] = ps.verify(None, None, delegation_enabled=False, **kw)
        self.assertEqual(c.result, rh.PASS)
        found = ps.verify(None, None, delegation_enabled=True, **kw)
        self.assertEqual({c.result for c in found}, {rh.FAIL})


class ReadRecordTest(unittest.TestCase):
    def test_the_record_is_checked_and_read_through_one_descriptor(self):
        import unittest.mock as um
        opened = []
        real_open = os.open

        def counting(*a, **k):
            opened.append(a[0])
            return real_open(*a, **k)
        fake = os.stat_result((0o100444, 0, 0, 1, 0, 0, 2, 0, 0, 0))
        with tempfile.TemporaryDirectory() as t:
            f = os.path.join(t, "gate-record.json")
            with open(f, "wb") as fh:
                fh.write(b"{}")
            with um.patch.object(ps.os, "open", counting), um.patch.object(ps.os, "fstat", lambda fd: fake):
                self.assertEqual(ps.read_record(f), b"{}")
        self.assertEqual(opened, [f])

    def test_a_record_not_placed_by_root_is_refused_as_opened(self):
        with tempfile.TemporaryDirectory() as t:
            f = os.path.join(t, "gate-record.json")
            with open(f, "wb") as fh:
                fh.write(b"{}")
            os.chmod(f, 0o444)
            if os.geteuid() == 0:
                self.skipTest("root owns what it writes")
            with self.assertRaises(OSError):
                ps.read_record(f)

    def test_a_symbolic_link_is_never_followed(self):
        with tempfile.TemporaryDirectory() as t:
            real = os.path.join(t, "real.json")
            open(real, "wb").close()
            link = os.path.join(t, "gate-record.json")
            os.symlink(real, link)
            with self.assertRaises(OSError):
                ps.read_record(link)


if __name__ == "__main__":
    unittest.main()
