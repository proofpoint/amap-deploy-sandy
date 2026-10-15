"""partition_store: the weekly job's one write choke point. Every write site
is driven at a path outside its roots and must be refused before anything is
opened; inside them, each write is what its root allows, and no write goes
through a symbolic link."""

import json
import os
import stat
import tempfile
import unittest

import partition_incident as pi
import partition_store as pst


class StoreTest(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        r = self.root = os.path.realpath(t.name)
        self.ev, self.run, self.conf = f"{r}/evidence", f"{r}/exec/run-r1", f"{r}/conf/router.json"
        for d in (self.ev, self.run, f"{r}/conf", f"{r}/elsewhere"):
            os.makedirs(d)
        with open(self.conf, "w") as f:
            f.write('{"state_dir": "/s", "delegation": {"partition_verified": "r0:x"}}\n')
        os.chmod(self.conf, 0o640)
        self.store = pst.RootedStore(evidence_dir=self.ev, run_dir=self.run, live_config=self.conf)

    def refused(self, fn, *args):
        with self.assertRaises(pst.Refused):
            fn(*args)

    def test_every_write_outside_the_roots_is_refused_and_nothing_is_written(self):
        outside = [f"{self.root}/elsewhere/x.json", f"{self.ev}/gate-record.json", f"{self.ev}/notes.txt",
                   f"{self.ev}/../evidence/partition-r1.json", f"{self.run}/other.json", f"{self.root}/conf/other.json",
                   "relative.json"]
        for path in outside:
            with self.subTest(path=path):
                self.refused(self.store.new_file, path, b"{}")
                self.refused(self.store.append, path, b"{}\n")
        self.refused(self.store.mkdir, f"{self.root}/elsewhere/incident-r1")
        self.refused(self.store.mkdir, f"{self.ev}/not-an-incident")
        self.refused(self.store.append, f"{self.ev}/partition-r1.json", b"x\n")
        self.assertEqual(os.listdir(f"{self.root}/elsewhere"), [])
        self.assertEqual(os.listdir(self.ev), [])

    def test_the_evidence_writers_own_names_are_placed_root_readable(self):
        self.store.new_file(f"{self.ev}/partition-r1.json", b"{}")
        self.store.mkdir(f"{self.ev}/incident-r1")
        self.store.new_file(f"{self.ev}/incident-r1/detected.json", b"{}")
        self.store.append(f"{self.ev}/incident-r1/events.jsonl", b'{"event":"rewrite_ok"}\n')
        self.assertEqual(stat.S_IMODE(os.stat(f"{self.ev}/partition-r1.json").st_mode), 0o444)
        self.assertEqual(sorted(os.listdir(f"{self.ev}/incident-r1")), ["detected.json", "events.jsonl"])

    def test_a_runs_records_are_created_once(self):
        self.store.new_file(f"{self.run}/context.json", b"{}")
        self.assertEqual(stat.S_IMODE(os.stat(f"{self.run}/context.json").st_mode), 0o400)
        self.refused(self.store.new_file, f"{self.run}/context.json", b"{}")

    def test_the_live_config_is_replaced_keeping_its_owner_and_mode_never_created(self):
        before = os.stat(self.conf)
        self.store.replace_live_config(pst.without_delegation(self.store.read(self.conf)))
        after = os.stat(self.conf)
        with open(self.conf) as f:
            self.assertEqual(json.load(f), {"state_dir": "/s"})
        self.assertEqual((after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)),
                         (before.st_uid, before.st_gid, 0o640))
        self.assertNotEqual(after.st_ino, before.st_ino, "replaced by rename, never written through")
        os.unlink(self.conf)
        self.refused(self.store.replace_live_config, b"{}")
        self.assertFalse(os.path.exists(self.conf))

    def test_no_write_goes_through_a_symbolic_link(self):
        os.rmdir(self.ev)
        os.symlink(f"{self.root}/elsewhere", self.ev)
        with self.assertRaises(OSError):
            self.store.new_file(f"{self.ev}/partition-r1.json", b"{}")
        self.assertEqual(os.listdir(f"{self.root}/elsewhere"), [])
        os.unlink(self.conf)
        os.symlink(f"{self.root}/elsewhere/target.json", self.conf)
        with open(f"{self.root}/elsewhere/target.json", "w") as f:
            f.write("{}")
        self.refused(self.store.replace_live_config, b'{"changed": true}')
        with open(f"{self.root}/elsewhere/target.json") as f:
            self.assertEqual(f.read(), "{}")

    def test_the_incident_code_writes_only_through_the_store(self):
        """partition_incident's act over the rooted store: every file it
        made is inside the evidence root."""
        fx = pi.Effects(rewrite=lambda: None, inspect=lambda cid: {"running": False}, stop=lambda cid: None,
                        live_has_delegation=lambda: False, squatter_signing=lambda: False)
        pi.act(self.store, fx, evidence_dir=self.ev, run_id="r1", at="2026-10-15T03:00:00Z", failing=["P04"],
               token=None, identity="c" * 64, evidence_persisted=True, emit=lambda s: None)
        made = sorted(os.path.relpath(os.path.join(d, f), self.root) for d, _, fs in os.walk(self.root) for f in fs)
        self.assertEqual(made, ["conf/router.json", "evidence/incident-r1/detected.json",
                                "evidence/incident-r1/events.jsonl"])

    def test_a_config_that_is_not_one_strict_object_is_never_rewritten(self):
        for raw in (b'{"a": 1, "a": 2}', b"[]", b'{"x": NaN}', b"\xff"):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    pst.without_delegation(raw)


if __name__ == "__main__":
    unittest.main()
