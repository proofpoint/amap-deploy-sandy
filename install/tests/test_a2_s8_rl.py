"""S8 step 5's decisions (a2_s8_rl) on RL's documents.

status.json is RL's REAL first-poll document (rl_capture, sha256 pinned), changed one member at a time; a case that
needs a loaded plugin adds `transport_plugin`, which the capture lacks (no plugin was loaded there), and says so.
`docker inspect` is FAKED with only the field names RL named (2b79f2e1): State.Status, State.Restarting,
State.StartedAt and the top-level RestartCount. A real capture is PENDING (a loop-VM item).
"""

import copy
import json
import unittest

import a2fix  # noqa: F401  (puts install/ on sys.path)
import a2_s8_rl as R
import rl_capture
from a2_causes import Refusal

CAPTURE = json.loads(rl_capture.STATUS_FIRST_POLL)
# The capture's own values: its instance, its signing key and id, its process start.
NAMES = ["planner"]
KEY = CAPTURE["delegation"]["signing_public_key"]
KEY_ID = CAPTURE["delegation"]["signing_key_id"]
PLUGIN_SHA = "2aca9e214a8cca789bd081d43a04de776dc9eb6844f6c3b180d148e01b7dd893"
PLUGIN_PATH = "/opt/amap-plugin/amap_hop_plugin.py"
STARTED = R.instant_ns("2026-11-22T18:06:50.171086Z")


def loaded(doc=None):
    """The capture with a loaded plugin added (the capture has none): RL's transport_plugin member, path and sha."""
    d = copy.deepcopy(doc if doc is not None else CAPTURE)
    d["transport_plugin"] = {"path": PLUGIN_PATH, "sha256": PLUGIN_SHA}
    return d


def raw(doc):
    return json.dumps(doc).encode()


def inspect(**state):
    st = {"Status": "running", "Restarting": False, "StartedAt": "2026-11-22T18:06:49.900000000Z"}
    top = {"RestartCount": state.pop("RestartCount", 0)}
    st.update(state)
    return raw([dict(top, State=st)])


class Refuses(unittest.TestCase):
    def refuses(self, cause, fn, *a):
        with self.assertRaises(Refusal) as cm:
            fn(*a)
        self.assertEqual((cm.exception.cause, cm.exception.rc), (cause, 3))
        return cm.exception


class InstantTest(unittest.TestCase):
    def test_docker_and_rl_forms(self):
        self.assertEqual(R.instant_ns("1970-01-01T00:00:01Z"), 1_000_000_000)
        self.assertEqual(R.instant_ns("1970-01-01T00:00:01.5Z"), 1_500_000_000)
        self.assertEqual(R.instant_ns("1970-01-01T00:00:01.000000001Z"), 1_000_000_001)
        self.assertEqual(R.instant_ns("2026-11-22T18:06:50.171086Z") - R.instant_ns("2026-11-22T18:06:50Z"), 171_086_000)
        self.assertEqual(R.instant_ns("2024-02-29T00:00:00Z") - R.instant_ns("2024-02-28T00:00:00Z"), 86400 * 10**9)

    def test_anything_else_is_none(self):
        for s in ("2026-11-22T18:06:50", "2026-11-22T18:06:50+00:00", "2026-11-22 18:06:50Z", "2026-13-01T00:00:00Z",
                  "2026-11-22T24:00:00Z", "2026-11-22T18:06:50.1234567890Z", "", None, 5,
                  # Gate A's W13 r4 note N8: an impossible date is refused, not normalised by timegm.
                  "2026-02-31T00:00:00Z", "2026-04-31T00:00:00Z", "2025-02-29T00:00:00Z", "0000-01-01T00:00:00Z"):
            with self.subTest(s=s):
                self.assertIsNone(R.instant_ns(s))


class ContainerStateTest(Refuses):
    def test_running_gives_started_at(self):
        self.assertEqual(R.container_state(inspect()), R.instant_ns("2026-11-22T18:06:49.9Z"))

    def test_not_running_restarting_or_restarted_refuses_at_once(self):
        for kw in (dict(Status="exited"), dict(Status="restarting"), dict(Restarting=True), dict(Restarting=None),
                   dict(RestartCount=1), dict(RestartCount="0"), dict(StartedAt="later")):
            with self.subTest(kw=kw):
                self.refuses("START.RL_REFUSED", R.container_state, inspect(**kw))

    def test_inspect_that_is_not_one_object_refuses(self):
        for out in (b"", b"[]\n", raw([{}, {}]), b"{}", b"not json", raw([{"State": "running"}])):
            with self.subTest(out=out[:20]):
                self.refuses("START.RL_REFUSED", R.container_state, out)


class BindsTest(unittest.TestCase):
    def test_this_processs_first_poll_binds(self):
        self.assertEqual(R.binds(rl_capture.STATUS_FIRST_POLL, STARTED)["polls"], 1)
        # A process start up to 1 s before docker's StartedAt still binds (clock resolution, as RL states it).
        self.assertIsNotNone(R.binds(rl_capture.STATUS_FIRST_POLL, STARTED + R.BIND_SLACK_NS))

    def test_an_earlier_process_or_no_poll_does_not_bind(self):
        self.assertIsNone(R.binds(rl_capture.STATUS_FIRST_POLL, STARTED + R.BIND_SLACK_NS + 1))
        for change in (dict(polls=0), dict(polls="1"), dict(polls=None), dict(process_started_ts="2026-11-22T18:06:50"),
                       dict(process_started_ts=None)):
            with self.subTest(change=change):
                self.assertIsNone(R.binds(raw(dict(CAPTURE, **change)), STARTED))
        for out in (b"", b"[]", b"{", b"\xff"):
            self.assertIsNone(R.binds(out, STARTED))


class AdmittingTest(Refuses):
    def admit(self, doc, names=NAMES, key=KEY, key_id=KEY_ID):
        return R.admitting(doc, names, key, key_id, PLUGIN_SHA, PLUGIN_PATH)

    def test_the_capture_with_its_plugin_loaded_admits_with_no_notes(self):
        self.assertEqual(self.admit(loaded()), [])

    def test_the_capture_as_measured_has_no_plugin_so_condition_6_refuses(self):
        e = self.refuses("START.NOT_ADMITTING", self.admit, copy.deepcopy(CAPTURE))
        self.assertEqual(e.detail, "transport plugin")

    def broken(self, detail, change, **kw):
        d = loaded()
        change(d)
        e = self.refuses("START.NOT_ADMITTING", self.admit, d, *[kw[k] for k in ("names",) if k in kw])
        self.assertEqual(e.detail, detail)

    def test_each_condition_refuses_by_its_own_name(self):
        cases = [
            ("instance", lambda d: d["admitted"].remove("planner")),
            ("instance", lambda d: d["instances"]["planner"].update(poll=0)),
            ("instance", lambda d: d["instances"].pop("planner")),
            ("instance", lambda d: d["instances"]["planner"]["totals"].update(instance_errored=1)),
            ("instance", lambda d: d["instances"]["planner"]["totals"].pop("instance_errored")),
            ("registry", lambda d: d.pop("registry")),
            ("registry", lambda d: d["registry"].update(state="stranded")),
            ("registry", lambda d: d["registry"].update(held={"x": 1})),
            ("registry", lambda d: d["registry"].pop("held")),
            ("peer store admission", lambda d: d["peer_store"].update(admission="closed")),
            ("peer store admission", lambda d: d.pop("peer_store")),
            ("delegation", lambda d: d["delegation"].update(active=False)),
            ("delegation", lambda d: d["delegation"].update(error="bad format")),
            ("delegation", lambda d: d["delegation"].update(signing_public_key="0" * 64)),
            ("delegation", lambda d: d["delegation"].update(signing_key_id="other")),
            ("delegation", lambda d: d.pop("delegation")),
            ("classification", lambda d: d["classification"].update(config_reload_failed=True)),
            ("classification", lambda d: d.update(classification=[])),
            ("transport plugin", lambda d: d["transport_plugin"].update(sha256="0" * 64)),
            ("transport plugin", lambda d: d["transport_plugin"].update(path="/opt/other.py")),
            ("transport plugin", lambda d: d.update(transport_plugin=None)),
        ]
        for detail, change in cases:
            with self.subTest(detail=detail):
                self.broken(detail, change)

    def test_an_expected_name_rl_does_not_know_refuses(self):
        self.broken("instance", lambda d: None, names=["planner", "other"])
        self.broken("instance", lambda d: None, names=[])

    def test_absent_classification_is_fine(self):
        d = loaded()
        d.pop("classification")
        self.assertEqual(self.admit(d), [])

    def test_why_and_warnings_are_notes_never_refusals(self):
        d = loaded()
        d["peer_store"].update(why="settling", warnings=["clock_behind_h", "Odd Value!"])
        self.assertEqual(self.admit(d), [("RL_PEER_STORE_WHY", "settling"),
                                         ("RL_PEER_STORE_WARNINGS", "clock_behind_h,other")])
        d["peer_store"].update(why={"x": 1}, warnings=["w%d" % i for i in range(20)])
        notes = dict(self.admit(d))
        self.assertEqual(notes["RL_PEER_STORE_WHY"], "other")
        self.assertEqual(len(notes["RL_PEER_STORE_WARNINGS"].split(",")), R.NOTE_MAX)


class CaptureTest(unittest.TestCase):
    def test_the_fixture_is_the_capture(self):
        import hashlib
        self.assertEqual(hashlib.sha256(rl_capture.STATUS_FIRST_POLL).hexdigest(), rl_capture.SHA256)
        self.assertTrue(rl_capture.SHA256.startswith("2a7b2a3a"))



class RlSentenceTest(unittest.TestCase):
    def test_the_sentence_covers_a_start_script_refusal_with_no_container(self):
        """run.sh can refuse before any container exists, so the sentence names the script's error, and says only a
        started container was stopped (the same flaw Codex's W13 r1 found in RE_REFUSED's)."""
        import a2_causes
        text = a2_causes.sentence("START.RL_REFUSED")
        self.assertIn("its start script refused", text)
        # Gate A's W13 r4 note N2: an inspect that fails or does not parse.
        self.assertIn("its container could not be inspected", text)
        self.assertIn("the script's error", text)
        self.assertIn("a started container was stopped, not removed", text)
        self.assertNotIn("; it was stopped", text)


if __name__ == "__main__":
    unittest.main()
