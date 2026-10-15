"""partition_incident: the FAIL-STOP action, its record, completion after a
crash or an unrecordable run, and resolution. The store is real (a temporary
directory) except where one named operation is made to fail; the world is a
fake router that a stop really stops, so "stopped" can only be recorded when
it happened."""

import json
import os
import tempfile
import unittest

import partition_incident as pi
import router_health as rh

ID = "c0ffee" * 10 + "abcd"
AT = "2026-10-15T00:00:00Z"


class Router:
    """The world the job acts on: the local router's container by id, its live
    config's delegation, and any container squatting on its name."""

    def __init__(self):
        self.running = {ID: True}
        self.delegation = True
        self.squatter = False
        self.rewrite_error = None
        self.stop_works = True
        self.stops = []
        self.inspect_error = None

    def effects(self):
        return pi.Effects(rewrite=self.rewrite, inspect=self.inspect, stop=self.stop,
                          live_has_delegation=lambda: self.delegation, squatter_signing=lambda: self.squatter)

    def rewrite(self):
        if self.rewrite_error:
            raise OSError(self.rewrite_error)
        self.delegation = False

    def inspect(self, cid):
        if self.inspect_error:
            return rh.Unresolved(self.inspect_error)
        if cid not in self.running:
            return None
        return {"running": self.running[cid]}

    def stop(self, cid):
        self.stops.append(cid)
        if self.stop_works:
            self.running[cid] = False


class Failing(pi.Store):
    """A real store whose one named operation fails, `times` times."""

    def __init__(self, op, times=1, error="No space left on device"):
        self.op, self.times, self.error = op, times, error

    def _maybe(self, op):
        if op == self.op and self.times:
            self.times -= 1
            raise OSError(28, self.error)

    def mkdir(self, path):
        self._maybe("mkdir")
        super().mkdir(path)

    def new_file(self, path, data):
        self._maybe("new_file")
        super().new_file(path, data)

    def append(self, path, line):
        self._maybe("append")
        super().append(path, line)


class ActTest(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.dir = t.name
        self.router = Router()
        self.said = []

    def act(self, store=None, identity=ID):
        return pi.act(store or pi.Store(), self.router.effects(), evidence_dir=self.dir, run_id="r1", at=AT,
                      failing=["P04"], token="r0:" + "a" * 64, identity=identity, evidence_persisted=True,
                      emit=self.said.append)

    def events(self):
        with open(os.path.join(self.dir, "incident-r1", "events.jsonl")) as f:
            return [json.loads(l)["event"] for l in f]

    def test_the_happy_path_records_first_rewrites_then_stops_and_exits_nonzero(self):
        code, status = self.act()
        self.assertEqual(code, 1)
        self.assertEqual(status, "incident recorded; rewrite ok; stop ok")
        self.assertEqual(self.events(), ["rewrite_ok", "stop_ok"])
        self.assertEqual(self.router.stops, [ID])
        self.assertFalse(self.router.delegation)
        with open(os.path.join(self.dir, "incident-r1", "detected.json")) as f:
            detected = json.load(f)
        self.assertEqual((detected["identity"], detected["failing"], detected["pending"]), (ID, ["P04"], ["rewrite", "stop"]))

    def test_a_rewrite_failure_still_stops(self):
        self.router.rewrite_error = "rename failed"
        code, status = self.act()
        self.assertEqual(self.events(), ["rewrite_failed", "stop_ok"])
        self.assertEqual(self.router.stops, [ID])
        self.assertIn("rewrite failed", status)
        self.assertEqual(code, 1)

    def test_a_stop_that_does_not_stop_is_never_recorded_as_stopped(self):
        self.router.stop_works = False
        code, status = self.act()
        self.assertEqual(self.events(), ["rewrite_ok", "stop_failed"])
        self.assertIn("stop failed", status)

    def test_an_id_that_is_not_running_is_not_stopped_and_never_by_name(self):
        self.router.running = {"another": True}
        _, status = self.act()
        self.assertEqual(self.router.stops, [])
        self.assertEqual(self.events(), ["rewrite_ok", "stop_not_attempted"])
        self.assertIn("not_attempted", status)

    def test_an_unreadable_identity_stops_nothing(self):
        code, status = self.act(identity=rh.Unresolved("no activation document"))
        self.assertEqual(self.router.stops, [])
        self.assertIn("identity is unreadable", status)
        self.assertEqual(code, 1)

    def test_an_uninspectable_router_is_not_recorded_as_stopped(self):
        self.router.inspect_error = "engine down"
        self.act()
        self.assertEqual(self.events(), ["rewrite_ok", "stop_not_attempted"])

    def test_the_record_failing_still_rewrites_and_stops_and_says_so_exactly(self):
        for op in ("mkdir", "new_file"):
            with self.subTest(op=op):
                self.setUp()
                code, status = self.act(store=Failing(op))
                self.assertEqual(self.router.stops, [ID], "the stop never depends on the record")
                self.assertFalse(self.router.delegation)
                self.assertTrue(status.startswith("incident NOT recorded: OSError: [Errno 28]"), status)
                self.assertTrue(status.endswith("; rewrite ok; stop ok"), status)
                self.assertEqual(code, 1)
                self.assertIn(status, self.said)

    def test_an_event_append_failing_never_aborts_the_stop(self):
        code, status = self.act(store=Failing("append"))
        self.assertEqual(self.router.stops, [ID])
        self.assertEqual(status, "incident recorded; rewrite ok; stop ok")
        self.assertTrue(any("could not record rewrite_ok" in s for s in self.said))
        self.assertEqual(self.events(), ["stop_ok"], "the lost event is not claimed")
        self.assertEqual(code, 1)

    def test_every_sink_failing_still_stops(self):
        class Dead(pi.Store):
            def mkdir(self, p): raise OSError(30, "Read-only file system")
            def new_file(self, p, d): raise OSError(30, "Read-only file system")
            def append(self, p, l): raise OSError(30, "Read-only file system")
        code, status = self.act(store=Dead())
        self.assertEqual(self.router.stops, [ID])
        self.assertTrue(status.startswith("incident NOT recorded"))
        self.assertEqual(code, 1)


class LifecycleTest(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.dir = t.name
        self.router = Router()
        self.store = pi.Store()

    def act(self, store=None):
        pi.act(store or self.store, self.router.effects(), evidence_dir=self.dir, run_id="r1", at=AT,
               failing=["P03"], token=None, identity=ID, evidence_persisted=True, emit=lambda s: None)

    def fresh(self, at="2026-10-16T00:00:00Z", stale=()):
        return {"run_id": "r2", "at": at}, list(stale)

    def resolve(self, **over):
        args = dict(evidence_dir=self.dir, run_id="r1", reason="the peer mount was removed", at="2026-10-16T01:00:00Z",
                    fresh=self.fresh(), identity=ID)
        args.update(over)
        return pi.resolve(self.store, self.router.effects(), **args)

    def test_an_incident_is_open_until_resolved_and_vetoes_meanwhile(self):
        self.act()
        self.assertEqual([i.run_id for i in pi.open_incidents(self.store, self.dir)], ["r1"])
        self.assertEqual(self.resolve(), [])
        self.assertEqual(pi.open_incidents(self.store, self.dir), [])

    def test_resolve_refuses_each_missing_prerequisite(self):
        self.act()
        cases = {
            "no reason": (dict(reason=" "), "an operator reason"),
            "stale evidence": (dict(fresh=self.fresh(stale=["it is 9.0 days old"])), "does not count"),
            "old evidence": (dict(fresh=self.fresh(at="2026-10-14T00:00:00Z")), "not later than the incident"),
            "no evidence": (dict(fresh=rh.Unresolved("absent")), "no fresh evidence"),
        }
        for name, (over, words) in cases.items():
            with self.subTest(name=name):
                why = self.resolve(**over)
                self.assertTrue(any(words in w for w in why), why)
        self.assertEqual([i.run_id for i in pi.open_incidents(self.store, self.dir)], ["r1"])

    def test_resolve_checks_current_facts_not_history(self):
        self.act()
        self.router.delegation = True
        self.assertTrue(any("still carries delegation" in w for w in self.resolve()))
        self.router.delegation = False
        self.router.squatter = True
        self.assertTrue(any("holding the local router's name" in w for w in self.resolve()))

    def test_a_crash_after_the_record_is_completed_by_the_next_run(self):
        os.makedirs(os.path.join(self.dir, "incident-r1"))
        with open(os.path.join(self.dir, "incident-r1", "detected.json"), "w") as f:
            json.dump({"run_id": "r1", "at": AT, "pending": ["rewrite", "stop"]}, f)
        said = pi.complete(self.store, self.router.effects(), evidence_dir=self.dir, at=AT, identity=ID,
                           emit=lambda s: None)
        self.assertEqual(said, ["r1: rewrite_ok", "r1: stop_ok"])
        self.assertEqual(self.router.stops, [ID])
        self.assertEqual(pi.read_all(self.store, self.dir)[0].pending(), [])

    def test_completion_is_idempotent_and_reads_current_facts(self):
        self.act(store=Failing("append", times=2))
        self.assertEqual(self.router.stops, [ID])
        said = pi.complete(self.store, self.router.effects(), evidence_dir=self.dir, at=AT, identity=ID,
                           emit=lambda s: None)
        self.assertEqual(self.router.stops, [ID], "a stopped router is not stopped again")
        self.assertEqual(said, ["r1: rewrite_ok", "r1: stop_ok"])
        self.assertEqual(pi.read_all(self.store, self.dir)[0].pending(), [], "nothing left to repeat")
        events = pi.read_all(self.store, self.dir)[0].events
        self.assertTrue(all(e["completion"] for e in events))

    def test_an_unrecorded_incident_is_written_late_and_vetoes(self):
        pi.act(Failing("mkdir"), self.router.effects(), evidence_dir=self.dir, run_id="r1", at=AT, failing=["P04"],
               token=None, identity=ID, evidence_persisted=False, emit=lambda s: None)
        self.assertEqual(pi.open_incidents(self.store, self.dir), [])
        pi.complete(self.store, self.router.effects(), evidence_dir=self.dir, at=AT, identity=ID,
                    late={"run_id": "r1", "at": AT, "failing": ["P04"], "token": None, "failing_evidence_persisted": False},
                    emit=lambda s: None)
        inc = pi.open_incidents(self.store, self.dir)[0]
        self.assertEqual(inc.run_id, "r1")
        for k in ("recorded_late", "taken_without_record"):
            self.assertIs(inc.detected[k], True)
        self.assertIs(inc.detected["failing_evidence_persisted"], False)

    def test_a_malformed_or_truncated_history_is_open(self):
        self.act()
        self.assertEqual(self.resolve(), [])
        path = os.path.join(self.dir, "incident-r1", "events.jsonl")
        with open(path, "a") as f:
            f.write('{"event":"resolved"')
        self.assertEqual([i.run_id for i in pi.open_incidents(self.store, self.dir)], ["r1"])
        with open(path, "w") as f:
            f.write('{"event":"closed_by_hand"}\n')
        self.assertEqual([i.run_id for i in pi.open_incidents(self.store, self.dir)], ["r1"])

    def test_nothing_is_ever_deleted(self):
        self.act()
        self.resolve()
        self.assertEqual(sorted(os.listdir(os.path.join(self.dir, "incident-r1"))), ["detected.json", "events.jsonl"])

    def test_an_unlistable_evidence_directory_vetoes(self):
        got = pi.open_incidents(self.store, os.path.join(self.dir, "missing"))
        self.assertIsInstance(got, rh.Unresolved)


if __name__ == "__main__":
    unittest.main()
