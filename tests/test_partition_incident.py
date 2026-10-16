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


def called(test, fn, *a, **k):
    """`fn`'s result; any exception it raises fails the test, so a crash is
    never taken for a verdict."""
    try:
        return fn(*a, **k)
    except Exception as e:  # a crash is not a verdict
        test.fail(f"{fn.__name__} raised {e!r}")
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

    def new_file(self, path, data, exclusive=False):
        self._maybe("new_file")
        super().new_file(path, data, exclusive=exclusive)

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

    def act(self, store=None, identity=ID, run_id="r1"):
        return called(self, pi.act, store or pi.Store(), self.router.effects(), evidence_dir=self.dir, run_id=run_id,
                      at=AT, failing=["P04"], token="r0:" + "a" * 64, identity=identity, evidence_persisted=True,
                      emit=self.said.append)

    def test_a_run_id_that_could_name_another_path_refuses_before_anything(self):
        for bad in ("../r1", "a/b", ""):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    pi.act(pi.Store(), self.router.effects(), evidence_dir=self.dir, run_id=bad, at=AT,
                           failing=["P04"], token=None, identity=ID, evidence_persisted=True, emit=lambda s: None)
        self.assertEqual((os.listdir(self.dir), self.router.stops), ([], []))

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


class NothingStopsTheStopTest(unittest.TestCase):
    """Whatever an effect, a record or a diagnostic sink raises, the verified
    stop is still attempted, and act still returns its status."""

    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.dir = t.name
        self.router = Router()

    def act(self, store=None, emit=lambda s: None):
        return called(self, pi.act, store or pi.Store(), self.router.effects(), evidence_dir=self.dir, run_id="r1",
                      at=AT, failing=["P04"], token=None, identity=ID, evidence_persisted=True, emit=emit)

    def test_a_failed_append_and_a_broken_diagnostic_sink_never_prevent_the_stop(self):
        for error in (BrokenPipeError(32, "Broken pipe"), ValueError("I/O operation on closed file")):
            with self.subTest(error=error):
                self.setUp()

                def broken(text, error=error):
                    raise error
                code, status = self.act(store=Failing("append", times=2), emit=broken)
                self.assertEqual((self.router.stops, code), ([ID], 1))
                self.assertTrue(status.endswith("stop ok"), status)

    def test_a_rewrite_or_a_stop_that_raises_anything_is_recorded_and_the_stop_still_tried(self):
        def cannot(*a):
            raise rh.CannotRun("the engine is gone")
        fx = self.router.effects()
        fx.rewrite = cannot
        code, status = called(self, pi.act, pi.Store(), fx, evidence_dir=self.dir, run_id="r1", at=AT,
                              failing=["P04"], token=None, identity=ID, evidence_persisted=True, emit=lambda s: None)
        self.assertEqual(self.router.stops, [ID])
        self.assertIn("rewrite failed (CannotRun", status)
        self.setUp()
        fx = self.router.effects()
        fx.stop = cannot
        code, status = called(self, pi.act, pi.Store(), fx, evidence_dir=self.dir, run_id="r1", at=AT,
                              failing=["P04"], token=None, identity=ID, evidence_persisted=True, emit=lambda s: None)
        self.assertIn("stop failed", status)
        with open(os.path.join(self.dir, "incident-r1", "events.jsonl")) as f:
            self.assertEqual([json.loads(l)["event"] for l in f], ["rewrite_ok", "stop_failed"])


class LifecycleTest(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.dir = t.name
        self.router = Router()
        self.store = pi.Store()

    def act(self, store=None):
        called(self, pi.act, store or self.store, self.router.effects(), evidence_dir=self.dir, run_id="r1", at=AT,
               failing=["P03"], token=None, identity=ID, evidence_persisted=True, emit=lambda s: None)

    def opened(self):
        got = called(self, pi.open_incidents, self.store, self.dir)
        return got if isinstance(got, rh.Unresolved) else [i.run_id for i in got]

    def complete(self, **k):
        return called(self, pi.complete, self.store, self.router.effects(), evidence_dir=self.dir, at=AT,
                      identity=ID, emit=lambda s: None, **k)

    def fresh(self, at="2026-10-16T00:00:00Z", stale=()):
        return {"run_id": "r2", "at": at}, list(stale)

    def resolve(self, **over):
        args = dict(evidence_dir=self.dir, run_id="r1", reason="the peer mount was removed", at="2026-10-16T01:00:00Z",
                    fresh=self.fresh(), identity=ID)
        args.update(over)
        return called(self, pi.resolve, self.store, self.router.effects(), **args)

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

    def test_resolve_refuses_an_unobservable_config_and_a_pending_rewrite(self):
        self.act()
        self.router.delegation = rh.Unresolved("the config cannot be read")
        self.assertTrue(any("cannot observe the live config" in w for w in self.resolve()))
        self.setUp()
        self.router.rewrite_error = "rename failed"
        self.act()
        self.router.delegation = False
        self.assertTrue(any("its rewrite is not complete" in w for w in self.resolve()))
        self.assertEqual(self.opened(), ["r1"])

    def test_resolve_refuses_while_the_stop_is_not_shown_done(self):
        self.router.stop_works = False
        self.act()
        self.router.delegation = False
        self.assertTrue(any("still running" in w for w in self.resolve()), "stop_failed and running")
        self.router.running[ID] = False
        self.router.inspect_error = "engine down"
        self.assertTrue(any("cannot inspect" in w for w in self.resolve()))
        self.router.inspect_error = None
        self.assertTrue(any("identity is unreadable" in w for w in self.resolve(identity=rh.Unresolved("gone"))))
        self.assertEqual(self.resolve(), [], "confirmed not running resolves")

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
        said = self.complete()
        self.assertEqual(said, ["r1: rewrite_ok", "r1: stop_ok"])
        self.assertEqual(self.router.stops, [ID])
        self.assertFalse(self.router.delegation, "the rewrite was done, not only recorded")
        self.assertEqual(pi.read_all(self.store, self.dir)[0].pending(), [])

    def test_completion_is_idempotent_and_reads_current_facts(self):
        self.act(store=Failing("append", times=2))
        self.assertEqual(self.router.stops, [ID])
        said = self.complete()
        self.assertEqual(self.router.stops, [ID], "a stopped router is not stopped again")
        self.assertEqual(said, ["r1: rewrite_ok", "r1: stop_not_attempted"],
                         "a stop whose record was lost is not certified from an id not running")
        self.assertEqual(pi.read_all(self.store, self.dir)[0].pending(), ["stop"], "left to the operator's --resolve")
        events = pi.read_all(self.store, self.dir)[0].events
        self.assertTrue(all(e["completion"] for e in events))
        self.assertEqual(self.router.stops, [ID])

    def test_completion_never_certifies_a_stale_id_stopped(self):
        """[1] recreated under a new id after the incident: the recorded id
        is gone or not running, the replacement runs. Nothing is stopped,
        and the stop stays pending."""
        for running in ({}, {ID: False}):
            with self.subTest(running=running):
                self.setUp()
                self.act(store=Failing("append", times=2))
                self.router.running = dict(running, **{"d" * 64: True})
                self.router.stops = []
                said = self.complete()
                self.assertEqual(self.router.stops, [])
                self.assertEqual(said[-1], "r1: stop_not_attempted")
                last = pi.read_all(self.store, self.dir)[0].events[-1]
                self.assertIn("may be stale", last["reason"])
                self.assertEqual(pi.read_all(self.store, self.dir)[0].pending(), ["stop"])

    def test_an_unrecorded_incident_is_written_late_and_vetoes(self):
        pi.act(Failing("mkdir"), self.router.effects(), evidence_dir=self.dir, run_id="r1", at=AT, failing=["P04"],
               token=None, identity=ID, evidence_persisted=False, emit=lambda s: None)
        self.assertEqual(pi.open_incidents(self.store, self.dir), [])
        self.complete(late={"run_id": "r1", "at": AT, "failing": ["P04"], "token": None,
                            "failing_evidence_persisted": False})
        inc = called(self, pi.open_incidents, self.store, self.dir)[0]
        self.assertEqual(inc.run_id, "r1")
        for k in ("recorded_late", "taken_without_record"):
            self.assertIs(inc.detected.get(k), True, k)
        self.assertIs(inc.detected["failing_evidence_persisted"], False)

    def test_an_existing_record_keeps_its_original_cause(self):
        self.act()
        for failing in (["P04"], ["P04"]):
            self.complete(late={"run_id": "r1", "at": AT, "failing": failing, "token": None,
                                "failing_evidence_persisted": False})
        with open(os.path.join(self.dir, "incident-r1", "detected.json")) as f:
            self.assertEqual(json.load(f)["failing"], ["P03"], "a late record never replaces the original cause")

    def test_a_malformed_detected_record_or_event_leaves_the_incident_open(self):
        self.act()
        self.assertEqual(self.resolve(), [])
        detected = os.path.join(self.dir, "incident-r1", "detected.json")
        os.chmod(detected, 0o644)
        good = open(detected).read()
        for raw in ("{}", '{"run_id": "r9", "at": "x", "failing": ["P03"], "pending": []}',
                    '{"run_id": "r1", "at": "x", "failing": [], "pending": []}',
                    '{"run_id": "r1", "run_id": "r1", "at": "x", "failing": ["P03"], "pending": []}',
                    '{"run_id": "r1", "at": NaN, "failing": ["P03"], "pending": []}'):
            with self.subTest(raw=raw):
                with open(detected, "w") as f:
                    f.write(raw)
                self.assertEqual(self.opened(), ["r1"])
        with open(detected, "w") as f:
            f.write(good)
        path = os.path.join(self.dir, "incident-r1", "events.jsonl")
        for tail in ('{"event":"resolved","at":"x"}\n', '{"event":"resolved","at":"x","evidence":"r2","reason":" "}\n',
                     '{"event":"resolved","evidence":"r2","reason":"r"}\n'):
            with self.subTest(tail=tail):
                with open(path, "w") as f:
                    f.write(tail)
                self.assertEqual(self.opened(), ["r1"])

    def test_the_records_grammar_is_whole_or_the_incident_stays_open(self):
        """Codex's two cases, and the rest of the emitted grammar: a pending
        list outside the actions, an event lacking a required member, one
        with a member outside its kind's grammar, or one of the wrong type."""
        self.act()
        detected = os.path.join(self.dir, "incident-r1", "detected.json")
        os.chmod(detected, 0o644)
        good = json.load(open(detected))
        path = os.path.join(self.dir, "incident-r1", "events.jsonl")
        resolved = '{"event":"resolved","at":"x","evidence":"r2","reason":"fixed"}\n'
        with open(path, "a") as f:
            f.write(resolved)
        self.assertEqual(self.opened(), [], "a whole history with a resolution closes")
        for pending in (["rewrite", 17], ["rewrite", "rewrite"], ["reboot"]):
            with self.subTest(pending=pending):
                with open(detected, "w") as f:
                    json.dump(dict(good, pending=pending), f)
                self.assertEqual(self.opened(), ["r1"], "a resolution never closes a malformed record")
        with open(detected, "w") as f:
            json.dump(good, f)
        for line in ('{"event":"stop_ok","at":"x"}', '{"event":"stop_ok","at":"x","id":""}',
                     '{"event":"stop_failed","at":"x"}', '{"event":"rewrite_failed","at":"x"}',
                     '{"event":"stop_not_attempted","at":"x","reason":"r","seen":{}}',
                     '{"event":"rewrite_ok","at":"x","completion":"yes"}', '{"event":"rewrite_ok"}'):
            with self.subTest(line=line):
                with open(path, "w") as f:
                    f.write(line + "\n" + resolved)
                self.assertEqual(self.opened(), ["r1"])
        with open(path, "w") as f:
            f.write('{"event":"rewrite_ok","at":"x"}\n{"event":"stop_ok","at":"x","id":"c"}\n' + resolved)
        self.assertEqual(self.opened(), [], "a whole, well-formed history closes")

    def test_every_event_this_module_writes_is_in_its_grammar(self):
        self.router.stop_works = False
        self.act()
        self.router.stop_works = True
        self.complete()
        self.complete(late={"run_id": "r1", "at": AT, "failing": ["P03"], "token": None,
                            "failing_evidence_persisted": False})
        inc = called(self, pi.read_all, self.store, self.dir)[0]
        self.assertNotIsInstance(inc.events, rh.Unresolved, inc.events)
        self.assertNotIsInstance(inc.detected, rh.Unresolved, inc.detected)

    def test_a_repeated_act_on_a_recorded_incident_still_records_its_effects(self):
        self.act()
        self.router.running[ID] = True
        self.router.delegation = True
        called(self, pi.act, self.store, self.router.effects(), evidence_dir=self.dir, run_id="r1", at=AT,
               failing=["P04"], token=None, identity=ID, evidence_persisted=True, emit=lambda s: None)
        events = [json.loads(l)["event"] for l in open(os.path.join(self.dir, "incident-r1", "events.jsonl"))]
        self.assertEqual(events, ["rewrite_ok", "stop_ok", "rewrite_ok", "stop_ok"])
        self.assertEqual(json.load(open(os.path.join(self.dir, "incident-r1", "detected.json")))["failing"], ["P03"])

    def test_a_malformed_or_truncated_history_is_open(self):
        self.act()
        path = os.path.join(self.dir, "incident-r1", "events.jsonl")
        for name, tail in (("a broken last line", '{"event":"resolved"'),
                           ("a whole last line with no newline", '{"event":"resolved","at":"x","evidence":"r2","reason":"r"}'),
                           ("an event outside the vocabulary",
                            '{"event":"closed_by_hand","at":"x"}\n'
                            '{"event":"resolved","at":"x","evidence":"r2","reason":"by hand"}\n')):
            with self.subTest(name=name):
                with open(path, "w") as f:
                    f.write('{"event":"rewrite_ok","at":"x"}\n' + tail)
                self.assertEqual(self.opened(), ["r1"])
        detected = os.path.join(self.dir, "incident-r1", "detected.json")
        os.chmod(detected, 0o644)
        with open(detected, "w") as f:
            f.write("[]")
        with open(path, "w") as f:
            f.write('{"event":"resolved"}\n')
        self.assertEqual(self.opened(), ["r1"], "an unreadable detected.json is open")

    def test_nothing_is_ever_deleted(self):
        self.act()
        self.resolve()
        self.assertEqual(sorted(os.listdir(os.path.join(self.dir, "incident-r1"))), ["detected.json", "events.jsonl"])

    def test_an_unlistable_evidence_directory_vetoes(self):
        got = pi.open_incidents(self.store, os.path.join(self.dir, "missing"))
        self.assertIsInstance(got, rh.Unresolved)


if __name__ == "__main__":
    unittest.main()


class ProspectiveActTest(unittest.TestCase):
    """A2's incident: observe first, and stop_not_required only when nothing
    in the incident's history, and nothing running, could be signing. The
    history is read back through the library's own strict reader."""

    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.dir = t.name
        self.router = Router()
        self.router.delegation = False          # pre-activation: the live config has none
        self.router.running = {}                # no certified target exists
        self.named_running = False              # the plan's [1] is stopped for A2
        self.rewrites = []

    def effects(self):
        fx = self.router.effects()
        real = fx.rewrite
        fx.rewrite = lambda: (self.rewrites.append(1), real())[1]
        fx.router_running = lambda: self.named_running
        return fx

    def act(self, identity=None):
        return called(self, pi.act, pi.Store(), self.effects(), evidence_dir=self.dir, run_id="r1", at=AT,
                      failing=["P04"], token=None, identity=identity, evidence_persisted=True,
                      emit=lambda s: None, mode="prospective")

    def incident(self):
        found = pi.read_all(pi.Store(), self.dir)
        self.assertEqual(len(found), 1)
        return found[0]

    def kinds(self):
        return [e["event"] for e in self.incident().events]

    def test_nothing_live_and_nothing_running_needs_no_stop(self):
        self.act()
        self.assertEqual(self.kinds(), ["rewrite_ok", "stop_not_required"])
        self.assertEqual(self.rewrites, [])                      # the live config was never replaced
        self.assertEqual(self.incident().detected["mode"], "prospective")
        self.assertEqual(self.incident().pending(), [])

    def test_a_running_local_router_by_name_is_never_stop_not_required(self):
        """Delegation placed, [1] restarted on it, then removed
        from the file without a restart."""
        self.named_running = True
        self.act()
        self.assertEqual(self.kinds(), ["rewrite_ok", "stop_not_attempted"])
        self.assertEqual(self.incident().pending(), ["stop"])

    def test_the_remedy_follows_the_history(self):
        self.named_running = True
        self.act()
        self.assertIn("then run the ordinary partition-weekly", self.incident().events[-1]["reason"])
        self.router.delegation = True
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.dir = t.name
        self.act()
        self.assertIn("record resolved", self.incident().events[-1]["reason"])

    def test_an_engine_that_cannot_say_is_never_stop_not_required(self):
        self.named_running = rh.Unresolved("no engine")
        self.act()
        self.assertEqual(self.kinds()[-1], "stop_not_attempted")

    def test_an_engine_that_cannot_say_about_the_certified_target_is_never_stop_not_required(self):
        """The certified identity cannot be inspected while nothing runs
        under the local router's name: the stop is still owed."""
        self.router.inspect_error = "no engine"
        self.act(identity=ID)
        self.assertEqual(self.kinds(), ["rewrite_ok", "stop_not_attempted"])
        self.assertEqual(self.incident().pending(), ["stop"])

    def test_a_live_removal_anywhere_in_the_history_keeps_the_stop_pending(self):
        """The child removed a live delegation (a bare rewrite_ok);
        the next act observes none, and still may not call the stop needless."""
        self.router.delegation = True
        self.act()
        self.assertEqual(self.kinds(), ["rewrite_ok", "stop_not_attempted"])
        self.act()
        kinds = self.kinds()
        self.assertEqual(kinds, ["rewrite_ok", "stop_not_attempted", "rewrite_ok", "stop_not_attempted"])
        self.assertNotIn("stop_not_required", kinds)
        self.assertEqual(self.incident().pending(), ["stop"])

    def test_a_running_certified_target_is_stopped_as_the_weekly_job_stops_it(self):
        self.router.running = {ID: True}
        self.act(identity=ID)
        self.assertEqual(self.kinds(), ["rewrite_ok", "stop_ok"])
        self.assertEqual(self.router.stops, [ID])

    def test_a_weekly_incident_never_closes_on_stop_not_required(self):
        inc = pi.Incident("r1", {"run_id": "r1"}, [{"event": "rewrite_ok", "observed": pi.NO_DELEGATION},
                                                   {"event": "stop_not_required", "reason": "x"}])
        self.assertEqual(inc.pending(), ["stop"])


class ProspectivePendingTest(unittest.TestCase):

    def test_stop_not_required_closes_nothing_after_a_live_removal(self):
        """The reader holds the history-wide rule itself: a history in which a
        live delegation was removed, whoever then wrote stop_not_required,
        keeps its stop pending."""
        detected = {"run_id": "r1", "mode": "prospective"}
        tail = [{"event": "rewrite_ok", "observed": pi.NO_DELEGATION}, {"event": "stop_not_required", "reason": "x"}]
        self.assertEqual(pi.Incident("r1", detected, tail).pending(), [])
        for head in ({"event": "rewrite_ok"}, {"event": "rewrite_failed", "reason": "EIO"}):
            with self.subTest(head=head["event"]):
                history = [head, {"event": "stop_not_attempted", "reason": "x"}] + tail
                self.assertEqual(pi.Incident("r1", detected, history).pending(), ["stop"])
