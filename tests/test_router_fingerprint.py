"""The local router's upgrade base (`router-fingerprint`): the capture, the
history, the stop gate and the image check.

Rows marked SYNTHETIC use a function-level seam or a history no real hop
checkout produces; every other match row starts from ONE complete MEASURED
capture and changes one thing. The real-history rows read the hop checkout
at the pin (`_workspace.HOP_ROUTER_ROOT`), whose first-parent chain from
99329945 is 70 commits, with 6479a05c at index 11 and 45 router entries at
the target (measured with `git rev-list --first-parent` and `git ls-tree`).
"""

import copy
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zlib
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import _workspace
import hop_router as hp
import router_fingerprint as rf

NS = rf.NS
B = 1_800_000_000          # the synthetic rows' epoch origin, in seconds
GIT = shutil.which("git") or "git"
HOP = str(_workspace.HOP_ROUTER_ROOT)
REAL_TARGET = "99329945edd20adb4b8b83f025ea1ef6382456ff"
REAL_FROM = "6479a05c164b11e2ff38df08b3f93e9e0079d779"
PLUGIN = hp.PLUGIN_SHA256


def read_or_fail(case, repo, target, measured_from, git=GIT):
    """read_history, where an exception fails the test rather than erroring
    it: the mutant harness counts only a failure as a kill."""
    try:
        return rf.read_history(str(repo), target, measured_from, git=git)
    except Exception as e:     # noqa: BLE001
        case.fail(f"read_history raised {type(e).__name__}: {e}")


def oid(label: str) -> str:
    return hashlib.sha1(label.encode()).hexdigest()


def at_ns(seconds) -> int:
    return B * NS + int(Decimal(str(seconds)) * NS)


def whole(seconds) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(B + int(seconds)))


def docker_ts(seconds) -> str:
    s, f = divmod(at_ns(seconds), NS)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(s)) + ".%09dZ" % f


# --- A synthetic history: c0 (the target) down to c6; measured_from is c3 ---------

ENTRY = oid("entrypoint")


def router(i: int, a=None, b=None):
    return {"__init__.py": ["file", oid("init")], "a.py": ["file", a or oid(f"a{i}")],
            "b.py": ["file", b or oid(f"b{i}")], "tests": ["dir", oid("tests")],
            "README.md": ["file", oid("readme")], "py.typed": ["file", oid("typed")]}


C = [oid(f"c{i}") for i in range(7)]
TARGET, FROM = C[0], C[3]


def history(trees=None, fp=None, types=None):
    fp = list(C) if fp is None else fp
    trees = trees or {c: {"router": router(i), "entrypoint": ENTRY} for i, c in enumerate(C)}
    return {"shallow": False, "promisor": False,
            "types": types if types is not None else {TARGET: "commit", FROM: "commit"},
            "first_parent": fp, "trees": {c: trees[c] for c in fp}}


def bases(target=TARGET, measured_from=FROM, before=None, **ov):
    """The repository's bases file, with the synthetic (or a fixture's) ids.
    pre_registry.before defaults to the synthetic chain's oldest commit, so
    no synthetic commit is a pre-registry base unless a row says so."""
    doc = json.loads(rf.BASES_PATH.read_text(encoding="utf-8"))
    doc.update(target=target, measured_from=measured_from, **ov)
    doc["pre_registry"] = dict(doc["pre_registry"], before=before or C[6])
    return json.dumps(doc).encode()


def result_of(tree):
    """The capture's view of one commit's router package: what a clean image
    of it holds (tests, README.md and py.typed included)."""
    r = tree["router"]
    return {"entries": {n: v[0] for n, v in r.items()}, "py": rf.py_map(r), "entrypoint": tree["entrypoint"]}


def capture(tree, *, sa="100.7", started_ts=100, pst="100.8", lp=105, now="110", est="100.75", ctime="90",
            at=None, at_before=None, source="running"):
    """ONE complete MEASURED capture of `tree`'s package. The clock values
    are seconds after B; the uptime is derived so that PID 1's estimated
    start is `est` (clk_tck 100, start tick 1000)."""
    at = now if at is None else at
    at_before = str(Decimal(at) - Decimal("0.5")) if at_before is None else at_before
    uptime = float(Decimal(now) - Decimal(est) + 10)
    res = result_of(tree)
    status = {
        "started_ts": {"present": started_ts is not None, "value": None if started_ts is None else whole(started_ts)},
        "process_started_ts": {"present": pst is not None, "value": None if pst is None else rf.utc_at(at_ns(pst))},
        "last_poll_ts": {"present": True, "value": whole(lp)},
        "classification": {"present": True, "value": {"egress": "open"}},
        "transport_plugin": {"present": True, "value": {"path": "/opt/plugin/amap_hop_plugin.py", "sha256": PLUGIN}},
    }
    doc = {
        "schema": rf.SCHEMA, "source": "running", "step": 2, "at_before": rf.utc_at(at_ns(at_before)),
        "at": rf.utc_at(at_ns(at)),
        "container": {"id": "f" * 64, "name": "/amap-rl", "image": "sha256:" + "e" * 64, "started_at": docker_ts(sa)},
        "image": None,
        "image_python_env": {"PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1", "PYTHON_VERSION": "3.11.9"},
        "program_sha256": rf.PROGRAM_SHA256,
        "result": {
            "app": {"router": "dir", "docker": "dir"}, "docker": {"entrypoint.sh": "file"},
            "entries": res["entries"], "py": res["py"], "entrypoint": res["entrypoint"],
            "process": {"argv": ["python3", "-m", "router", "--config", "/cfg/router.json", "run", "--interval", "10"],
                        "cwd": "/app", "router_config": "/cfg/router.json",
                        "python_env": {"PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1"},
                        "ld_env": [], "umask": "0027"},
            "clock": {"now_ns": at_ns(now), "uptime_s": uptime, "pid1_starttime_ticks": 1000, "clk_tck": 100},
            "interpreter": {"name": "cpython", "major": 3, "minor": 11, "exec_exe": "/usr/local/bin/python3.11",
                            "pid1_exe": "/usr/local/bin/python3.11", "user_site": False},
            "config": {"path": "/cfg/router.json", "realpath_ok": True, "regular": True, "stable": True,
                       "dev": 41, "ino": 7, "ctime_ns": at_ns(ctime), "state_dir": "/state",
                       "transport_plugin": {"present": True, "sha256": PLUGIN}},
            "status": status,
            "peer_lane": {"state_dir": "/state", "peer_entries": False},
            "errors": [],
        },
    }
    if source == "image":
        doc.update(source="image", step=None, container=None,
                   image={"ref": "example.org/rl:pin", "id": "sha256:" + "e" * 64})
        r = doc["result"]
        r.update(process=None, clock=None, config=None, status=None, peer_lane=None)
        r["interpreter"].update(pid1_exe=None, user_site=None)
    return doc


def b(doc) -> bytes:
    return rf.canonical(doc)


H = history()
TREE = {c: H["trees"][c] for c in C}


def gate(doc, hist=None, *, pin=TARGET, bases_bytes=None, plugin=PLUGIN):
    return rf.match(b(doc), bases_bytes if bases_bytes is not None else bases(), hist if hist is not None else H,
                    pin, plugin)


#: The exit each outcome must give, stated here rather than read from the
#: module, so a change to the module's exit map shows.
EXITS = {"MEASURED": 0, "UNMEASURED": 1, "UNKNOWN": 2, "EXACT": 0, "DIFFERS": 1}


class Outcome(unittest.TestCase):

    def assertGate(self, got, outcome, reason):
        self.assertEqual((got[0], got[1], got[2]), (outcome, EXITS[outcome], reason), got[3])


# --- The match: the domains ---------------------------------------------------------


class DomainRows(Outcome):

    def test_inside_the_range_target_and_measured_from_are_measured(self):
        for c in (C[1], TARGET, FROM):
            with self.subTest(commit=c):
                self.assertGate(gate(capture(TREE[c])), rf.MEASURED, "measured")

    def test_the_boundary_and_an_older_unique_match_are_unmeasured(self):
        for c in (C[4], C[6]):
            with self.subTest(commit=c):
                self.assertGate(gate(capture(TREE[c])), rf.UNMEASURED, "unmeasured")

    def test_a_base_older_than_pre_registry_before_is_a_pre_registry_base(self):
        """before = c5: c6 predates registry_dir, so it is sent to the
        migration branch; c5 itself and c4 stay `unmeasured`."""
        bb = bases(before=C[5])
        self.assertGate(rf.match(b(capture(TREE[C[6]])), bb, H, TARGET, PLUGIN), rf.UNMEASURED, "pre_registry_base")
        for c in (C[4], C[5]):
            with self.subTest(commit=c):
                self.assertGate(rf.match(b(capture(TREE[c])), bb, H, TARGET, PLUGIN), rf.UNMEASURED, "unmeasured")

    def test_a_class_on_both_sides_of_before_stays_unmeasured(self):
        trees = {c: {"router": router(i), "entrypoint": ENTRY} for i, c in enumerate(C)}
        trees[C[6]]["router"] = copy.deepcopy(trees[C[4]]["router"])
        got = rf.match(b(capture(trees[C[4]])), bases(before=C[5]), history(trees), TARGET, PLUGIN)
        self.assertGate(got, rf.UNMEASURED, "unmeasured")

    def test_pre_registry_before_off_the_chain_or_too_new(self):
        self.assertGate(gate(capture(TREE[C[1]]), bases_bytes=bases(before=oid("elsewhere"))), rf.UNKNOWN,
                        "pre_registry_off_chain")
        for before in (C[2], FROM):
            with self.subTest(before=before):
                self.assertGate(gate(capture(TREE[C[1]]), bases_bytes=bases(before=before)), rf.UNKNOWN,
                                "pre_registry_order")

    def test_a_class_straddling_the_boundary_is_mixed(self):
        trees = {c: {"router": router(i), "entrypoint": ENTRY} for i, c in enumerate(C)}
        trees[C[4]]["router"] = copy.deepcopy(trees[FROM]["router"])
        self.assertGate(gate(capture(trees[FROM]), history(trees)), rf.UNKNOWN, "mixed")

    def test_an_off_first_parent_map_is_no_match(self):
        tree = {"router": router(99), "entrypoint": ENTRY}
        self.assertGate(gate(capture(tree)), rf.UNKNOWN, "no_match")

    def test_a_name_swap_is_no_match(self):
        """Two existing names with distinct blobs swapped: the names and
        types are unchanged, and no searched commit has the swapped map."""
        r = router(1)
        swapped = {"router": router(1, a=r["b.py"][1], b=r["a.py"][1]), "entrypoint": ENTRY}
        self.assertGate(gate(capture(swapped)), rf.UNKNOWN, "no_match")

    def test_a_different_entrypoint_is_no_match(self):
        tree = {"router": router(1), "entrypoint": oid("another entrypoint")}
        self.assertGate(gate(capture(tree)), rf.UNKNOWN, "no_match")

    def test_measured_prints_every_commit_of_m_newest_first(self):
        trees = {c: {"router": router(i), "entrypoint": ENTRY} for i, c in enumerate(C)}
        trees[C[2]]["router"] = copy.deepcopy(trees[C[1]]["router"])
        got = gate(capture(trees[C[1]]), history(trees))
        self.assertGate(got, rf.MEASURED, "measured")
        self.assertIn(f"{C[1]}, {C[2]}", got[3])
        d = capture(trees[C[1]])
        self.assertIn(f"capture step 2 at {d['at']}", got[3])


class MapHelperRows(unittest.TestCase):
    """SYNTHETIC: the map helper alone, for the subset and superset mutants."""

    def test_py_minus_one_file_does_not_match(self):
        r = router(1)
        py = rf.py_map(r)
        py.pop("b.py")
        self.assertFalse(rf.py_map_matches(py, r))

    def test_py_plus_one_file_does_not_match(self):
        r = router(1)
        py = dict(rf.py_map(r), **{"c.py": oid("c")})
        self.assertFalse(rf.py_map_matches(py, r))

    def test_the_exact_map_matches(self):
        r = router(1)
        self.assertTrue(rf.py_map_matches(rf.py_map(r), r))


# --- The match: step 1, the capture ---------------------------------------------


class CaptureRows(Outcome):

    def good(self):
        return capture(TREE[C[1]])

    def test_errors(self):
        d = self.good()
        d["result"]["errors"] = ["x"]
        self.assertGate(gate(d), rf.UNKNOWN, "errors")

    def test_py_empty(self):
        d = self.good()
        d["result"]["py"] = {}
        self.assertGate(gate(d), rf.UNKNOWN, "py_empty")

    def test_program(self):
        d = self.good()
        d["program_sha256"] = "0" * 64
        self.assertGate(gate(d), rf.UNKNOWN, "program")

    def test_an_image_capture_is_not_running(self):
        """The full-capture image row: a precedence control for the source."""
        self.assertGate(gate(capture(TREE[C[1]], source="image")), rf.UNKNOWN, "not_running")

    def test_source_eligible_alone(self):
        """SYNTHETIC: the source helper alone."""
        self.assertFalse(rf.source_eligible("image"))
        self.assertTrue(rf.source_eligible("running"))

    def test_each_schema_member_missing(self):
        paths = [("schema",), ("step",), ("at",), ("container", "started_at"), ("image_python_env",),
                 ("result", "clock"), ("result", "process", "umask"), ("result", "config", "transport_plugin"),
                 ("result", "config", "ctime_ns"), ("result", "status", "classification"),
                 ("result", "status", "last_poll_ts", "value"), ("result", "interpreter", "user_site"),
                 ("result", "peer_lane", "peer_entries"), ("result", "errors")]
        for path in paths:
            with self.subTest(path=path):
                d = self.good()
                node = d
                for k in path[:-1]:
                    node = node[k]
                del node[path[-1]]
                self.assertGate(gate(d), rf.UNKNOWN, "schema")

    def test_a_non_canonical_capture_is_schema(self):
        raw = json.dumps(self.good(), indent=1).encode()
        self.assertGate(rf.match(raw, bases(), H, TARGET, PLUGIN), rf.UNKNOWN, "schema")

    def test_null_members_are_admitted_only_with_errors(self):
        d = self.good()
        d["result"]["clock"] = None
        self.assertGate(gate(d), rf.UNKNOWN, "schema")
        d["result"]["errors"] = ["the clock could not be read"]
        self.assertGate(gate(d), rf.UNKNOWN, "errors")

    def test_the_schema_witness_moves_the_reason_id(self):
        """`config.transport_plugin` omitted, with no status member and the
        flag absent: `schema`. The kill is the reason id's transition."""
        d = self.good()
        del d["result"]["config"]["transport_plugin"]
        d["result"]["status"]["transport_plugin"] = {"present": False, "value": None}
        self.assertGate(gate(d), rf.UNKNOWN, "schema")

    def test_time_format_one_per_field(self):
        cases = {
            "at without six fractional digits": lambda d: d.update(at=d["at"][:-4] + "Z"),
            "at_before without Z": lambda d: d.update(at_before=d["at_before"][:-1]),
            "started_at": lambda d: d["container"].update(started_at="yesterday"),
            "started_ts": lambda d: d["result"]["status"]["started_ts"].update(value="2026-10-16 10:00:00"),
            "last_poll_ts": lambda d: d["result"]["status"]["last_poll_ts"].update(value=17),
            "process_started_ts": lambda d: d["result"]["status"]["process_started_ts"].update(
                value="2026-10-16T10:00:00Z"),
            "status.transport_plugin.value": lambda d: d["result"]["status"]["transport_plugin"].update(value=PLUGIN),
        }
        for name, change in cases.items():
            with self.subTest(field=name):
                d = self.good()
                change(d)
                self.assertGate(gate(d), rf.UNKNOWN, "time_format")

    #: Each field's character positions in `YYYY-MM-DDTHH:MM:SS[.f…]Z`.
    FIELDS = {"year": 0, "month": 5, "day": 8, "hour": 11, "minute": 14, "second": 17, "fraction": 20}

    def other_script(self, value, pos):
        """`value` with the ASCII digit at `pos` replaced by the same digit in
        Arabic-Indic, which int() still reads: only the grammar can refuse it."""
        self.assertTrue(value[pos].isdigit() and value[pos].isascii(), (value, pos))
        return value[:pos] + chr(0x660 + int(value[pos])) + value[pos + 1:]

    def test_digits_of_another_script_are_time_format_in_every_field(self):
        """One subTest per field of each grammar: _AT (at), _WHOLE
        (last_poll_ts) and _DOCKER_TS (StartedAt)."""
        grammars = {
            "_AT at": (lambda d: d["at"], lambda d, v: d.update(at=v), self.FIELDS),
            "_WHOLE last_poll_ts": (lambda d: d["result"]["status"]["last_poll_ts"]["value"],
                                    lambda d, v: d["result"]["status"]["last_poll_ts"].update(value=v),
                                    {k: v for k, v in self.FIELDS.items() if k != "fraction"}),
            "_DOCKER_TS started_at": (lambda d: d["container"]["started_at"],
                                      lambda d, v: d["container"].update(started_at=v), self.FIELDS),
        }
        for grammar, (get, put, fields) in grammars.items():
            for field, pos in fields.items():
                with self.subTest(grammar=grammar, field=field):
                    d = self.good()
                    put(d, self.other_script(get(d), pos))
                    self.assertGate(gate(d), rf.UNKNOWN, "time_format")

    def test_at_before_after_at_is_time_format_with_its_own_message(self):
        d = capture(TREE[C[1]], at_before="110.2")
        got = gate(d)
        self.assertGate(got, rf.UNKNOWN, "time_format")
        self.assertIn("the host clock moved backward during the capture; fingerprint again", got[3])

    def test_history_schema(self):
        h = copy.deepcopy(H)
        h["trees"][C[1]]["router"]["a.py"] = ("file", oid("a1"))
        self.assertGate(gate(self.good(), h), rf.UNKNOWN, "history_schema")
        h = copy.deepcopy(H)
        del h["trees"][C[6]]
        self.assertGate(gate(self.good(), h), rf.UNKNOWN, "history_schema")


# --- The match: steps 2 and 3 -------------------------------------------------------


class BasesAndHistoryRows(Outcome):

    def good(self):
        return capture(TREE[C[1]])

    def test_pin(self):
        self.assertGate(gate(self.good(), pin=C[1]), rf.UNKNOWN, "pin")

    def test_each_bases_schema_defect(self):
        doc = json.loads(bases())
        defects = {"not JSON": b"{", "schema 1": bases(schema=1), "schema 3": bases(schema=3), "schema true": bases(schema=True),
                   "short target": bases(target=TARGET[:39]), "an extra key": bases(extra="x")}
        for key in ("premises", "peer_lane"):
            d = dict(doc)
            del d[key]
            defects[f"{key} absent"] = json.dumps(d).encode()
        for name, raw in defects.items():
            with self.subTest(defect=name):
                self.assertGate(gate(self.good(), bases_bytes=raw), rf.UNKNOWN, "bases_schema")

    def test_shallow_and_promisor(self):
        for key in ("shallow", "promisor"):
            with self.subTest(key=key):
                h = copy.deepcopy(H)
                h[key] = True
                self.assertGate(gate(self.good(), h), rf.UNKNOWN, key)

    def test_history_keys_synthetic(self):
        """SYNTHETIC: a third `types` key."""
        h = copy.deepcopy(H)
        h["types"][C[5]] = "commit"
        self.assertGate(gate(self.good(), h), rf.UNKNOWN, "history_keys")

    def test_not_commit(self):
        for which, kind in ((TARGET, None), (FROM, "tree"), (FROM, None)):
            with self.subTest(which=which, kind=kind):
                h = copy.deepcopy(H)
                h["types"][which] = kind
                self.assertGate(gate(self.good(), h), rf.UNKNOWN, "not_commit")

    def test_history_root_empty_chain(self):
        """SYNTHETIC: types say commit, and the chain is empty."""
        self.assertGate(gate(self.good(), history(fp=[])), rf.UNKNOWN, "history_root")

    def test_history_root_chain_not_at_target(self):
        """first_parent[0] is not the target, with a valid structure and bases."""
        self.assertGate(gate(self.good(), history(fp=C[1:])), rf.UNKNOWN, "history_root")

    def test_off_chain(self):
        side = oid("side")
        h = copy.deepcopy(H)
        h["types"] = {TARGET: "commit", side: "commit"}
        self.assertGate(gate(self.good(), h, bases_bytes=bases(measured_from=side)), rf.UNKNOWN, "off_chain")


# --- The match: step 6 ----------------------------------------------------------------


class LayoutProcessRows(Outcome):

    def good(self):
        return capture(TREE[C[1]])

    def change(self, fn, reason):
        d = self.good()
        fn(d)
        self.assertGate(gate(d), rf.UNKNOWN, reason)

    def test_pycache(self):
        self.change(lambda d: d["result"]["entries"].update(__pycache__="dir"), "pycache")

    def test_layout(self):
        cases = [lambda d: d["result"]["app"].update({"json.py": "file"}),
                 lambda d: d["result"]["app"].update(extra="dir"),
                 lambda d: d["result"]["docker"].update({"run.sh": "file"})]
        for fn in cases:
            with self.subTest():
                self.change(fn, "layout")

    def test_run_form(self):
        p = lambda d: d["result"]["process"]
        cases = {"shell mode with another config": lambda d: p(d).update(
                     argv=["python3", "-m", "router", "--config", "/other.json", "run", "--interval", "10"]),
                 "once": lambda d: p(d)["argv"].__setitem__(5, "once"),
                 "seven tokens": lambda d: p(d)["argv"].pop(),
                 "argv[4] is not ROUTER_CONFIG": lambda d: p(d).update(router_config="/other.json")}
        for name, fn in cases.items():
            with self.subTest(case=name):
                self.change(fn, "run_form")

    def test_cwd_ld_umask_user_site(self):
        self.change(lambda d: d["result"]["process"].update(cwd="/"), "cwd")
        self.change(lambda d: d["result"]["process"].update(ld_env=["LD_PRELOAD"]), "ld_env")
        self.change(lambda d: d["result"]["process"].update(umask="0022"), "umask")
        self.change(lambda d: d["result"]["interpreter"].update(user_site=True), "user_site")

    def test_interpreter(self):
        i = lambda d: d["result"]["interpreter"]
        for fn in (lambda d: i(d).update(name="pypy"), lambda d: i(d).update(minor=12),
                   lambda d: i(d).update(pid1_exe="/usr/bin/python3.11")):
            with self.subTest():
                self.change(fn, "interpreter")

    def test_each_refused_name_in_both_environments_is_env_allow(self):
        names = ("PYTHONPYCACHEPREFIX", "PYTHONPLATLIBDIR", "PYTHONOPTIMIZE", "PYTHONPATH", "PYTHONHOME",
                 "PYTHONUSERBASE", "PYTHONSTARTUP", "PYTHONSAFEPATH", "PYTHONINSPECT")
        for name in names:
            with self.subTest(name=name):
                d = self.good()
                d["image_python_env"][name] = "/x"
                d["result"]["process"]["python_env"][name] = "/x"
                self.assertGate(gate(d), rf.UNKNOWN, "env_allow")

    def test_pythondontwritebytecode_empty_or_absent_is_env_allow(self):
        for value in ("", None):
            with self.subTest(value=value):
                d = self.good()
                for env in (d["image_python_env"], d["result"]["process"]["python_env"]):
                    if value is None:
                        del env["PYTHONDONTWRITEBYTECODE"]
                    else:
                        env["PYTHONDONTWRITEBYTECODE"] = value
                self.assertGate(gate(d), rf.UNKNOWN, "env_allow")

    def test_a_process_only_name_or_a_changed_value_is_env_subset(self):
        self.change(lambda d: d["result"]["process"]["python_env"].update(PYTHON_X="1"), "env_subset")
        self.change(lambda d: d["result"]["process"]["python_env"].update(PYTHON_VERSION="3.11.8"), "env_subset")

    def test_the_environment_positive_control(self):
        d = self.good()
        d["result"]["process"]["python_env"]["PYTHON_VERSION"] = "3.11.9"
        self.assertGate(gate(d), rf.MEASURED, "measured")


# --- The match: step 7 ----------------------------------------------------------------


class ClockRows(Outcome):

    def run_gate(self, **kw):
        return gate(capture(TREE[C[1]], **kw))

    def test_refusal_backward_step_previous_process(self):
        """REFUSAL TEST (the backward-step witness): SA 101.9, last_poll 110, T 100,
        ctime 91, capture wall 112, PID 1 real age 10.1 s."""
        self.assertGate(self.run_gate(sa="101.9", lp=110, started_ts=100, pst=None, ctime="91", now="112",
                                      est="101.9"), rf.UNKNOWN, "pid1_age")

    def test_refusal_a_status_from_the_future(self):
        """REFUSAL TEST: last_poll_ts > now + 1."""
        self.assertGate(self.run_gate(lp=112, now="110"), rf.UNKNOWN, "stale_status")

    def test_unsupported_premise_control_one_second_step(self):
        """UNSUPPORTED-PREMISE CONTROL: PID 1 starts at 0, µs T 0.3, a 1 s
        backward step, then an edit 0.5 s after T stamped -0.2. It passes:
        premise C1's residue, which no check here can see."""
        self.assertGate(self.run_gate(sa="0", started_ts=0, pst="0.3", lp=3, ctime="-0.2", now="5", est="-1"),
                        rf.MEASURED, "measured")

    def test_refusal_the_same_with_a_six_second_step(self):
        self.assertGate(self.run_gate(sa="0", started_ts=0, pst="0.3", lp=3, ctime="-0.2", now="5", est="-6"),
                        rf.UNKNOWN, "pid1_age")

    def test_refusal_a_healthy_start_six_seconds_late(self):
        """REFUSAL TEST: T 6 s after PID 1's start (the conservative limit)."""
        self.assertGate(self.run_gate(sa="0", started_ts=6, pst="6", lp=8, ctime="-1", now="10", est="0"),
                        rf.UNKNOWN, "pid1_age")

    def test_refusal_clock_skew_router_ahead(self):
        """REFUSAL TEST: at_before = at - 0.1, now = at + 2."""
        self.assertGate(self.run_gate(at="108", at_before="107.9", now="110"), rf.UNKNOWN, "clock_skew")

    def test_refusal_clock_skew_router_behind(self):
        """REFUSAL TEST: at_before = at - 0.1, now = at - 2."""
        self.assertGate(self.run_gate(at="112", at_before="111.9", now="110"), rf.UNKNOWN, "clock_skew")

    def test_long_exec_control(self):
        """LONG-EXEC CONTROL, must pass: at - at_before = 5 s, now = at - 0.01."""
        self.assertGate(self.run_gate(at="110.01", at_before="105.01", now="110"), rf.MEASURED, "measured")

    def test_unsupported_premise_control_round_trip(self):
        """UNSUPPORTED-PREMISE CONTROL: an A->B->A excursion with equal
        endpoint offsets during an edit; the edit's ctime reads before T."""
        self.assertGate(self.run_gate(ctime="96.8"), rf.MEASURED, "measured")

    def test_the_microsecond_lower_bound(self):
        """T - est of -0.06 s is refused; -0.04 s passes."""
        self.assertGate(self.run_gate(pst="100.8", est="100.86"), rf.UNKNOWN, "pid1_age")
        self.assertGate(self.run_gate(pst="100.8", est="100.84"), rf.MEASURED, "measured")

    def test_healthy_starts(self):
        self.assertGate(self.run_gate(pst="100.8", est="100.5"), rf.MEASURED, "measured")
        self.assertGate(self.run_gate(pst=None, started_ts=100, est="100.6"), rf.MEASURED, "measured")


class StaleStatusRows(Outcome):

    def run_gate(self, **kw):
        return gate(capture(TREE[C[1]], **kw))

    def test_fast_restart_whole_seconds(self):
        self.assertGate(self.run_gate(sa="101.9", started_ts=100, pst=None, lp=101, ctime="90", now="105",
                                      est="100.2"), rf.UNKNOWN, "stale_status")

    def test_fast_restart_microseconds(self):
        self.assertGate(self.run_gate(sa="101.9", pst="100.8", lp=101, ctime="90", now="105", est="100.7"),
                        rf.UNKNOWN, "stale_status")

    def test_healthy(self):
        self.assertGate(self.run_gate(sa="100.7", pst="100.8", lp=104, est="100.75"), rf.MEASURED, "measured")

    def test_a_late_stamp_passes(self):
        """StartedAt one second after T."""
        self.assertGate(self.run_gate(sa="101.5", pst="100.9", lp=104, est="100.85"), rf.MEASURED, "measured")

    def test_an_earlier_process_t(self):
        self.assertGate(self.run_gate(sa="101.9", pst="98", lp=104, ctime="90", est="97.9"),
                        rf.UNKNOWN, "stale_status")

    def test_the_two_second_edge(self):
        """last_poll_ts one second after floor(StartedAt) is refused; two passes."""
        self.assertGate(self.run_gate(sa="100.7", lp=101), rf.UNKNOWN, "stale_status")
        self.assertGate(self.run_gate(sa="100.7", lp=102), rf.MEASURED, "measured")

    def test_no_start_time_at_all(self):
        self.assertGate(self.run_gate(pst=None, started_ts=None), rf.UNKNOWN, "stale_status")

    def test_selected_t_binding_synthetic(self):
        """SYNTHETIC: process_started_ts 90 with SA 101.9, last_poll_ts 105,
        ctime 85, and PID 1's age in its window."""
        self.assertGate(self.run_gate(sa="101.9", pst="90", lp=105, ctime="85", est="89.9"),
                        rf.UNKNOWN, "stale_status")

    def test_process_started_ts_is_preferred_synthetic(self):
        """SYNTHETIC: a stale started_ts and a fresh process_started_ts."""
        self.assertGate(self.run_gate(sa="101.9", started_ts=90, pst="101.95", lp=105, ctime="85", est="101.9"),
                        rf.MEASURED, "measured")


class ConfigRows(Outcome):

    def good(self, **kw):
        return capture(TREE[C[1]], **kw)

    def test_ctime_after_t_is_config_changed(self):
        self.assertGate(gate(self.good(ctime="101")), rf.UNKNOWN, "config_changed")

    def test_ctime_before_t_passes(self):
        self.assertGate(gate(self.good(ctime="100.7")), rf.MEASURED, "measured")

    def test_config_identity(self):
        for key in ("realpath_ok", "stable"):
            with self.subTest(key=key):
                d = self.good()
                d["result"]["config"][key] = False
                self.assertGate(gate(d), rf.UNKNOWN, "config_identity")

    def test_regular_false_synthetic(self):
        """SYNTHETIC: a faithful capture of a non-regular config stops at
        step 1 `errors`; this data-only row reaches the guard."""
        d = self.good()
        d["result"]["config"]["regular"] = False
        self.assertGate(gate(d), rf.UNKNOWN, "config_identity")

    def test_the_reload_flag(self):
        cls = lambda v: (lambda d: d["result"]["status"]["classification"].update(v))
        passes = {"absent": cls({"present": False, "value": None}), "null": cls({"value": None}),
                  "no member": cls({"value": {"egress": "open"}})}
        refused = {"true": cls({"value": {"config_reload_failed": True}}),
                   "false": cls({"value": {"config_reload_failed": False}}),
                   "a non-object": cls({"value": "reloading"})}
        for name, fn in passes.items():
            with self.subTest(flag=name):
                d = self.good()
                fn(d)
                self.assertGate(gate(d), rf.MEASURED, "measured")
        for name, fn in refused.items():
            with self.subTest(flag=name):
                d = self.good()
                fn(d)
                self.assertGate(gate(d), rf.UNKNOWN, "reload_flag")


# --- The match: steps 8 and 9 -------------------------------------------------------


class PeerAndPluginRows(Outcome):

    def good(self):
        return capture(TREE[C[1]])

    def test_peer_lane(self):
        d = self.good()
        d["result"]["peer_lane"]["peer_entries"] = True
        self.assertGate(gate(d), rf.UNMEASURED, "peer_lane")
        d["result"]["peer_lane"]["peer_entries"] = None
        self.assertGate(gate(d), rf.UNKNOWN, "peer_unknown")

    def test_the_status_plugin(self):
        d = self.good()
        self.assertGate(gate(d), rf.MEASURED, "measured")
        d["result"]["status"]["transport_plugin"]["value"]["sha256"] = "0" * 64
        self.assertGate(gate(d), rf.UNMEASURED, "plugin")

    def test_no_status_member_and_no_config_plugin_passes(self):
        d = self.good()
        d["result"]["status"]["transport_plugin"] = {"present": False, "value": None}
        d["result"]["config"]["transport_plugin"] = {"present": False, "sha256": None}
        self.assertGate(gate(d), rf.MEASURED, "measured")

    def test_the_config_plugin(self):
        d = self.good()
        d["result"]["status"]["transport_plugin"] = {"present": False, "value": None}
        self.assertGate(gate(d), rf.MEASURED, "measured")
        d["result"]["config"]["transport_plugin"]["sha256"] = "0" * 64
        self.assertGate(gate(d), rf.UNMEASURED, "plugin")


class InternalRow(Outcome):

    def test_an_internal_exception_is_unknown(self):
        """SYNTHETIC: a raising helper."""
        real = rf.commit_matches
        self.addCleanup(setattr, rf, "commit_matches", real)

        def boom(*a):
            raise KeyError("x")
        rf.commit_matches = boom
        try:
            got = gate(capture(TREE[C[1]]))
        except Exception as e:     # noqa: BLE001
            self.fail(f"an exception escaped match: {type(e).__name__}")
        self.assertGate(got, rf.UNKNOWN, "internal")


class ContainerName(unittest.TestCase):

    def test_the_inspect_name_carries_a_slash(self):
        self.assertTrue(rf.container_name_ok("/amap-rl", "amap-rl"))
        self.assertFalse(rf.container_name_ok("amap-rl", "amap-rl"))
        self.assertFalse(rf.container_name_ok("/amap-rl2", "amap-rl"))


# --- verify_image -----------------------------------------------------------------


class VerifyImageRows(Outcome):

    def image(self, tree=None):
        return capture(tree or TREE[C[1]], source="image")

    def hist(self, commit=C[1]):
        h = history(fp=C[1:])
        h["types"] = {commit: "commit"}
        return h

    def check(self, doc, hist=None, commit=C[1]):
        return rf.verify_image(b(doc), hist if hist is not None else self.hist(), commit)

    def test_clean_with_tests_readme_and_py_typed_is_exact(self):
        self.assertGate(self.check(self.image()), rf.EXACT, "exact")

    def test_differences(self):
        cases = {"a changed blob": lambda d: d["result"]["py"].update({"a.py": oid("changed")}),
                 "a __pycache__": lambda d: d["result"]["entries"].update(__pycache__="dir"),
                 "an extra /app file": lambda d: d["result"]["app"].update({"json.py": "file"}),
                 "a different entrypoint": lambda d: d["result"].update(entrypoint=oid("other"))}
        for name, fn in cases.items():
            with self.subTest(case=name):
                d = self.image()
                fn(d)
                self.assertGate(self.check(d), rf.DIFFERS, "differs")

    def test_a_running_capture_is_not_image(self):
        self.assertGate(self.check(capture(TREE[C[1]])), rf.UNKNOWN, "not_image")

    def test_a_commit_absent_from_the_history(self):
        h = self.hist()
        h.update(types={C[1]: None}, first_parent=[], trees={})
        self.assertGate(self.check(self.image(), h), rf.UNKNOWN, "commit_absent")

    def test_shallow_and_promisor(self):
        for key in ("shallow", "promisor"):
            with self.subTest(key=key):
                h = self.hist()
                h[key] = True
                self.assertGate(self.check(self.image(), h), rf.UNKNOWN, key)

    def test_a_second_types_key_is_history_keys(self):
        """SYNTHETIC."""
        h = self.hist()
        h["types"][C[2]] = "commit"
        self.assertGate(self.check(self.image(), h), rf.UNKNOWN, "history_keys")


# --- The real hop history -----------------------------------------------------------


class RealHistory(Outcome):
    """The hop checkout at the pin, read by read_history itself."""

    def setUp(self):
        self.h = read_or_fail(self, HOP, REAL_TARGET, REAL_FROM)

    def real_capture(self, commit):
        return capture(self.h["trees"][commit])

    def test_the_measured_shape(self):
        fp = self.h["first_parent"]
        self.assertEqual((len(fp), fp.index(REAL_FROM), len(self.h["trees"][REAL_TARGET]["router"])), (70, 11, 45))
        rl = subprocess.run([GIT, "-C", HOP, "rev-list", "--first-parent", REAL_TARGET], capture_output=True,
                            text=True, check=True).stdout.split()
        self.assertEqual(fp, rl)

    def test_the_signed_target_reads_its_physical_parent(self):
        """POSITIVE CONTROL (kills no listed mutant): the target carries a
        gpgsig header with TWO space-only continuation lines, and reads with
        its physical parent."""
        raw = subprocess.run([GIT, "-C", HOP, "cat-file", "commit", REAL_TARGET], capture_output=True,
                             check=True).stdout
        self.assertEqual(raw.split(b"\n\n")[0].split(b"\n").count(b" "), 2)
        self.assertEqual(self.h["first_parent"][1][:8], "7e150f3d")

    def test_measured_at_target_measured_from_and_inside(self):
        bases_bytes = rf.BASES_PATH.read_bytes()
        for c in (REAL_TARGET, REAL_FROM, self.h["first_parent"][5]):
            with self.subTest(commit=c):
                self.assertGate(rf.match(b(self.real_capture(c)), bases_bytes, self.h, REAL_TARGET, PLUGIN),
                                rf.MEASURED, "measured")

    def test_a_base_older_than_registry_dir_is_a_pre_registry_base(self):
        """The real chain: a84e0d98 is the first commit whose router config
        has registry_dir; a capture of 9854a5e8, older, is sent to the
        migration branch."""
        bases_bytes = rf.BASES_PATH.read_bytes()
        fp = self.h["first_parent"]
        old = next(c for c in fp if c.startswith("9854a5e8"))
        got = rf.match(b(self.real_capture(old)), bases_bytes, self.h, REAL_TARGET, PLUGIN)
        self.assertGate(got, rf.UNMEASURED, "pre_registry_base")
        self.assertIn("migration required", got[3])

    def test_below_the_range_is_unmeasured(self):
        bases_bytes = rf.BASES_PATH.read_bytes()
        c = self.h["first_parent"][12]
        self.assertGate(rf.match(b(self.real_capture(c)), bases_bytes, self.h, REAL_TARGET, PLUGIN),
                        rf.UNMEASURED, "unmeasured")

    def test_router_tests_are_not_in_the_extraction(self):
        """The in-range control: a clean image carries router/tests whole,
        and the extraction holds only router/'s top-level entries."""
        t = self.h["trees"][REAL_TARGET]["router"]
        self.assertEqual(t["tests"][0], "dir")
        self.assertFalse(any("/" in n for n in t))

    def test_the_raw_router_mode_is_40000(self):
        top = subprocess.run([GIT, "-C", HOP, "cat-file", "-p", REAL_TARGET + "^{tree}"], capture_output=True,
                             check=True, text=True).stdout
        self.assertIn("040000 tree", top)
        self.assertTrue(self.h["trees"][REAL_TARGET]["router"])


# --- read_history against fixture repositories ----------------------------------------


def _git(repo, *args, data=None, env=None):
    e = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.org", GIT_COMMITTER_NAME="t",
             GIT_COMMITTER_EMAIL="t@example.org", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    e.update(env or {})
    return subprocess.run([GIT, "-C", str(repo), *args], input=data, capture_output=True, check=True,
                          env=e).stdout


class Repo:
    """A fixture hop checkout: n commits on one line, each with router/a.py
    (distinct), router/tests/ and docker/entrypoint.sh."""

    def __init__(self, base: Path, n: int = 5, object_format: str = "sha1"):
        self.path = base / "hop"
        self.path.mkdir()
        _git(self.path, "init", "-q", f"--object-format={object_format}")
        self.commits = []
        for i in range(n):
            (self.path / "router" / "tests").mkdir(parents=True, exist_ok=True)
            (self.path / "docker").mkdir(exist_ok=True)
            (self.path / "router" / "a.py").write_text(f"A = {i}\n")
            (self.path / "router" / "tests" / "t.py").write_text("T = 1\n")
            (self.path / "docker" / "entrypoint.sh").write_text("#!/bin/sh\nexec \"$@\"\n")
            _git(self.path, "add", "-A")
            _git(self.path, "commit", "-q", "-m", f"c{i}")
            self.commits.append(_git(self.path, "rev-parse", "HEAD").decode().strip())

    def head(self):
        return self.commits[-1]

    def obj(self, kind, data: bytes) -> str:
        return _git(self.path, "hash-object", "-t", kind, "--literally", "-w", "--stdin", data=data).decode().strip()

    def tree_of(self, commit):
        return _git(self.path, "rev-parse", commit + "^{tree}").decode().strip()

    def commit_obj(self, header: bytes, body=b"msg\n") -> str:
        return self.obj("commit", header + b"\n" + body)


class RecordingGit:
    """A git wrapper that records each call's arguments, then runs git."""

    def __init__(self, base: Path):
        self.log = base / "calls.log"
        self.path = base / "git-wrapper"
        self.path.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{self.log}'\nexec '{GIT}' \"$@\"\n")
        self.path.chmod(0o755)

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []


class HistoryRows(unittest.TestCase):

    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)

    def read(self, repo, target, measured_from=None, git=GIT):
        return read_or_fail(self, repo.path, target, measured_from or target, git=git)

    def read_raw(self, repo, target, measured_from=None):
        return rf.read_history(str(repo.path), target, measured_from or target, git=GIT)

    def test_ids_are_refused_before_any_git_call(self):
        rec = RecordingGit(self.base)
        for bad in ("main", "-x", "a" * 39, "A" * 40):
            with self.subTest(id=bad):
                with self.assertRaises(rf.HistoryReadError):
                    rf.read_history(str(self.base), bad, "a" * 40, git=str(rec.path))
        self.assertEqual(rec.calls(), [])

    def test_the_given_git_runs(self):
        repo = Repo(self.base)
        rec = RecordingGit(self.base)
        self.read(repo, repo.head(), git=str(rec.path))
        self.assertTrue(rec.calls())

    def test_head_ahead_of_target_walks_target(self):
        """Helper-level: the chain starts at target, not HEAD."""
        repo = Repo(self.base)
        h = self.read(repo, repo.commits[2], repo.commits[0])
        self.assertEqual(h["first_parent"][0], repo.commits[2])
        self.assertEqual(h["first_parent"], repo.commits[2::-1])

    def test_measured_from_equal_to_target_is_one_key(self):
        repo = Repo(self.base)
        self.assertEqual(set(self.read(repo, repo.head())["types"]), {repo.head()})

    def test_a_forged_loose_object_fails_the_rehash(self):
        repo = Repo(self.base)
        c3 = repo.commits[3]
        y = repo.commit_obj(b"tree %s\nauthor t <t@example.org> 1 +0000\ncommitter t <t@example.org> 1 +0000\n"
                            % repo.tree_of(repo.commits[1]).encode())
        forged = b"tree %s\nparent %s\nauthor t <t@example.org> 1 +0000\ncommitter t <t@example.org> 1 +0000\n\nf\n" % (
            repo.tree_of(c3).encode(), y.encode())
        loose = repo.path / ".git" / "objects" / c3[:2] / c3[2:]
        loose.chmod(0o644)
        loose.write_bytes(zlib.compress(b"commit %d\0" % len(forged) + forged))
        with self.assertRaises(rf.HistoryReadError):
            self.read_raw(repo, repo.head())

    def test_replace_graft_leaves_the_chain_physical(self):
        repo = Repo(self.base)
        y = repo.commit_obj(b"tree %s\nauthor t <t@example.org> 1 +0000\ncommitter t <t@example.org> 1 +0000\n"
                            % repo.tree_of(repo.commits[0]).encode())
        _git(repo.path, "replace", "--graft", repo.commits[3], y)
        self.assertEqual(self.read(repo, repo.head())["first_parent"], repo.commits[::-1])

    def test_a_replaced_router_tree_leaves_the_trees_physical(self):
        repo = Repo(self.base)
        rtree = lambda c: _git(repo.path, "rev-parse", c + ":router").decode().strip()
        _git(repo.path, "replace", rtree(repo.head()), rtree(repo.commits[0]))
        h = self.read(repo, repo.head())
        a = h["trees"][repo.head()]["router"]["a.py"][1]
        self.assertEqual(a, _git(repo.path, "rev-parse", repo.head() + ":router/a.py",
                                 env={"GIT_NO_REPLACE_OBJECTS": "1"}).decode().strip())

    def test_a_grafts_file_leaves_the_chain_physical(self):
        repo = Repo(self.base)
        (repo.path / ".git" / "info").mkdir(exist_ok=True)
        (repo.path / ".git" / "info" / "grafts").write_text(f"{repo.commits[3]} {repo.commits[0]}\n")
        self.assertEqual(self.read(repo, repo.head())["first_parent"], repo.commits[::-1])

    def test_a_commit_graph_with_a_splice_leaves_the_chain_physical(self):
        """A commit-graph written while a graft was in force, then the graft
        removed: the graph records the spliced parent; the byte reader does
        not read the graph."""
        repo = Repo(self.base)
        (repo.path / ".git" / "info").mkdir(exist_ok=True)
        grafts = repo.path / ".git" / "info" / "grafts"
        grafts.write_text(f"{repo.commits[3]} {repo.commits[0]}\n")
        _git(repo.path, "-c", "core.commitGraph=true", "commit-graph", "write", "--reachable")
        grafts.unlink()
        self.assertEqual(self.read(repo, repo.head())["first_parent"], repo.commits[::-1])

    def test_promisor_configs(self):
        for key, value in (("remote.o.promisor", "true"), ("remote.o.promisor", "false"),
                           ("extensions.partialClone", "o")):
            with self.subTest(key=key, value=value):
                base = Path(tempfile.mkdtemp(dir=self.base))
                repo = Repo(base, n=2)
                _git(repo.path, "config", key, value)
                self.assertTrue(self.read(repo, repo.head())["promisor"])

    def test_a_malformed_config_raises(self):
        repo = Repo(self.base, n=2)
        with open(repo.path / ".git" / "config", "a") as f:
            f.write("[remote \"o\"\n\tpromisor = \n")
        with self.assertRaises(rf.HistoryReadError):
            self.read_raw(repo, repo.head())

    def test_a_promisor_lookup_exit_other_than_0_or_1_raises(self):
        """Isolated: a git that answers everything but `config --get-regexp`,
        which exits 3."""
        repo = Repo(self.base, n=2)
        wrapper = self.base / "git-config-fails"
        wrapper.write_text(f"#!/bin/sh\ncase \" $* \" in *' config --get-regexp '*) exit 3 ;; esac\nexec '{GIT}' \"$@\"\n")
        wrapper.chmod(0o755)
        with self.assertRaises(rf.HistoryReadError):
            rf.read_history(str(repo.path), repo.head(), repo.head(), git=str(wrapper))

    def test_the_shallow_clone_takes_the_early_marker(self):
        """`git clone --no-local --depth 2` of a fixture with three or more
        ancestors below the target: shallow, with no walk."""
        repo = Repo(self.base, n=5)
        clone = self.base / "clone"
        _git(self.base, "clone", "-q", "--no-local", "--depth", "2", str(repo.path), str(clone))
        h = read_or_fail(self, clone, repo.head(), repo.commits[-2])
        self.assertTrue(h["shallow"])
        self.assertEqual((h["first_parent"], h["trees"]), ([], {}))
        self.assertEqual(set(h["types"].values()), {"commit"})

    def test_a_sha256_repository_raises_before_any_lookup(self):
        repo = Repo(self.base, n=2, object_format="sha256")
        rec = RecordingGit(self.base)
        with self.assertRaises(rf.HistoryReadError):
            rf.read_history(str(repo.path), repo.head()[:40], repo.head()[:40], git=str(rec.path))
        self.assertFalse([c for c in rec.calls() if "cat-file" in c])

    def test_absence(self):
        repo = Repo(self.base, n=3)
        absent = "0" * 40
        h = self.read(repo, absent, repo.commits[0])
        self.assertEqual((h["types"][absent], h["first_parent"]), (None, []))
        tree = repo.tree_of(repo.head())
        h = self.read(repo, tree, repo.commits[0])
        self.assertEqual((h["types"][tree], h["first_parent"]), ("tree", []))
        h = self.read(repo, repo.head(), absent)
        self.assertIsNone(h["types"][absent])

    def header(self, repo, extra=b"", parent=None):
        p = b"parent %s\n" % (parent or repo.commits[0]).encode()
        return (b"tree %s\n" % repo.tree_of(repo.commits[1]).encode() + p
                + b"author t <t@example.org> 1 +0000\ncommitter t <t@example.org> 1 +0000\n" + extra)

    def test_a_body_parent_line_is_not_a_parent(self):
        repo = Repo(self.base, n=2)
        y = repo.commits[1]
        c = repo.commit_obj(self.header(repo), body=b"parent %s\n" % y.encode())
        self.assertEqual(self.read(repo, c)["first_parent"], [c, repo.commits[0]])

    def test_a_gpgsig_continuation_parent_is_not_a_parent(self):
        repo = Repo(self.base, n=2)
        sig = b"gpgsig -----BEGIN PGP SIGNATURE-----\n \n parent %s\n -----END PGP SIGNATURE-----\n" % (
            repo.commits[1].encode())
        c = repo.commit_obj(self.header(repo, extra=sig))
        self.assertEqual(self.read(repo, c)["first_parent"], [c, repo.commits[0]])

    def test_a_parent_header_after_author_raises(self):
        repo = Repo(self.base, n=2)
        c = repo.commit_obj(self.header(repo, extra=b"parent %s\n" % repo.commits[1].encode()))
        with self.assertRaises(rf.HistoryReadError):
            self.read_raw(repo, c)

    def test_a_parent_header_after_a_signed_block_raises(self):
        repo = Repo(self.base, n=2)
        sig = b"gpgsig -----BEGIN PGP SIGNATURE-----\n \n abc\n \n -----END PGP SIGNATURE-----\n"
        c = repo.commit_obj(self.header(repo, extra=sig + b"parent %s\n" % repo.commits[1].encode()))
        with self.assertRaises(rf.HistoryReadError):
            self.read_raw(repo, c)

    def test_a_bare_or_tab_parent_after_the_tree_raises(self):
        repo = Repo(self.base, n=2)
        tree = repo.tree_of(repo.commits[1]).encode()
        for line in (b"parent", b"parent\t" + repo.commits[0].encode(), b"tree\t" + tree):
            with self.subTest(line=line):
                c = repo.commit_obj(b"tree " + tree + b"\n" + line + b"\n"
                                    b"author t <t@example.org> 1 +0000\ncommitter t <t@example.org> 1 +0000\n")
                with self.assertRaises(rf.HistoryReadError):
                    self.read_raw(repo, c)

    def test_a_malformed_tree_line_raises(self):
        repo = Repo(self.base, n=2)
        c = repo.obj("commit", b"tree XYZ\nauthor t <t@example.org> 1 +0000\n\nm\n")
        with self.assertRaises(rf.HistoryReadError):
            self.read_raw(repo, c)

    def test_a_commit_with_no_empty_line_raises(self):
        repo = Repo(self.base, n=2)
        c = repo.obj("commit", self.header(repo))
        with self.assertRaises(rf.HistoryReadError):
            self.read_raw(repo, c)

    def raw_tree(self, repo, entries):
        return repo.obj("tree", b"".join(m + b" " + n + b"\0" + bytes.fromhex(i) for m, n, i in entries))

    def commit_with_root(self, repo, root):
        return repo.commit_obj(b"tree %s\nauthor t <t@example.org> 1 +0000\ncommitter t <t@example.org> 1 +0000\n"
                               % root.encode())

    def test_raw_40000_is_dir_and_040000_is_other(self):
        repo = Repo(self.base, n=1)
        rtree = _git(repo.path, "rev-parse", repo.head() + ":router").decode().strip()
        for mode, followed in ((b"40000", True), (b"040000", False)):
            with self.subTest(mode=mode):
                c = self.commit_with_root(repo, self.raw_tree(repo, [(mode, b"router", rtree)]))
                r = self.read(repo, c)["trees"][c]["router"]
                self.assertEqual(bool(r), followed)

    def test_a_link_router_is_not_followed(self):
        repo = Repo(self.base, n=1)
        link = repo.obj("blob", b"elsewhere")
        c = self.commit_with_root(repo, self.raw_tree(repo, [(b"120000", b"router", link)]))
        self.assertEqual(self.read(repo, c)["trees"][c]["router"], {})

    def test_tree_grammar_refusals(self):
        repo = Repo(self.base, n=1)
        blob = repo.obj("blob", b"A = 1\n")
        cases = {"a duplicate a.py": [(b"100644", b"a.py", blob), (b"100644", b"a.py", blob)],
                 "an empty name": [(b"100644", b"", blob)],
                 "a non-UTF-8 name": [(b"100644", b"\xff.py", blob)]}
        for name, entries in cases.items():
            with self.subTest(case=name):
                router = self.raw_tree(repo, entries)
                c = self.commit_with_root(repo, self.raw_tree(repo, [(b"40000", b"router", router)]))
                with self.assertRaises(rf.HistoryReadError):
                    self.read_raw(repo, c)
        router = repo.obj("tree", b"100644 a.py\0" + bytes.fromhex(blob)[:10])
        c = self.commit_with_root(repo, self.raw_tree(repo, [(b"40000", b"router", router)]))
        with self.assertRaises(rf.HistoryReadError):
            self.read_raw(repo, c)

    def test_a_tag_requested_as_a_commit_fails_the_rehash(self):
        repo = Repo(self.base, n=2)
        _git(repo.path, "tag", "-a", "-m", "t", "v1", repo.commits[0])
        tag = _git(repo.path, "rev-parse", "v1").decode().strip()
        c = repo.commit_obj(self.header(repo, parent=tag))
        with self.assertRaises(rf.HistoryReadError):
            self.read_raw(repo, c)

    def test_a_link_entrypoint_is_null(self):
        repo = Repo(self.base, n=1)
        rtree = _git(repo.path, "rev-parse", repo.head() + ":router").decode().strip()
        link = repo.obj("blob", b"elsewhere")
        docker = self.raw_tree(repo, [(b"120000", b"entrypoint.sh", link)])
        c = self.commit_with_root(repo, self.raw_tree(repo, [(b"40000", b"docker", docker),
                                                             (b"40000", b"router", rtree)]))
        self.assertIsNone(self.read(repo, c)["trees"][c]["entrypoint"])

    def test_the_fixture_history_is_the_exact_structure(self):
        repo = Repo(self.base)
        h = self.read(repo, repo.head(), repo.commits[1])
        self.assertTrue(rf.history_schema_ok(h))
        self.assertEqual(set(h["trees"]), set(h["first_parent"]))
        self.assertEqual(json.loads(json.dumps(h)), h)


class HistoryGatedRows(Outcome):
    """read_history's output, through the gate, on fixture repositories."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)

    def test_a_shallow_clone_is_shallow_at_the_gate(self):
        """measured_from pinned to the target's in-depth parent, so both
        types are commit."""
        repo = Repo(self.base, n=5)
        clone = self.base / "clone"
        _git(self.base, "clone", "-q", "--no-local", "--depth", "2", str(repo.path), str(clone))
        h = read_or_fail(self, clone, repo.head(), repo.commits[-2])
        full = read_or_fail(self, repo.path, repo.head(), repo.commits[-2])
        d = capture(full["trees"][repo.commits[-2]])
        got = rf.match(b(d), bases(repo.head(), repo.commits[-2]), h, repo.head(), PLUGIN)
        self.assertGate(got, rf.UNKNOWN, "shallow")

    def test_a_promisor_remote_is_promisor_at_the_gate(self):
        repo = Repo(self.base, n=3)
        _git(repo.path, "config", "remote.o.promisor", "true")
        h = read_or_fail(self, repo.path, repo.head(), repo.commits[0])
        d = capture(h["trees"][repo.commits[1]])
        got = rf.match(b(d), bases(repo.head(), repo.commits[0]), h, repo.head(), PLUGIN)
        self.assertGate(got, rf.UNKNOWN, "promisor")

    def test_absent_target_and_tree_target_are_not_commit(self):
        repo = Repo(self.base, n=3)
        good = read_or_fail(self, repo.path, repo.head(), repo.commits[0])
        d = capture(good["trees"][repo.commits[1]])
        for target in ("0" * 40, repo.tree_of(repo.head())):
            with self.subTest(target=target):
                h = read_or_fail(self, repo.path, target, repo.commits[0])
                got = rf.match(b(d), bases(target, repo.commits[0]), h, target, PLUGIN)
                self.assertGate(got, rf.UNKNOWN, "not_commit")
        h = read_or_fail(self, repo.path, repo.head(), "0" * 40)
        self.assertGate(rf.match(b(d), bases(repo.head(), "0" * 40), h, repo.head(), PLUGIN), rf.UNKNOWN,
                        "not_commit")

    def test_a_grafted_splice_does_not_reach_the_gate(self):
        """Y's router map equals the capture; Y is spliced below c3 by a
        grafts file. The physical chain does not hold Y: `no_match`."""
        repo = Repo(self.base, n=5)
        y_tree = repo.tree_of(repo.commits[0])
        (repo.path / "router" / "a.py").write_text("A = 'y'\n")
        _git(repo.path, "add", "-A")
        y_tree = _git(repo.path, "write-tree").decode().strip()
        y = repo.commit_obj(b"tree %s\nauthor t <t@example.org> 1 +0000\ncommitter t <t@example.org> 1 +0000\n"
                            % y_tree.encode())
        _git(repo.path, "reset", "-q", "--hard")
        (repo.path / ".git" / "info").mkdir(exist_ok=True)
        (repo.path / ".git" / "info" / "grafts").write_text(f"{repo.commits[3]} {y}\n")
        ych = read_or_fail(self, repo.path, y, y)
        d = capture(ych["trees"][y])
        h = read_or_fail(self, repo.path, repo.head(), repo.commits[1])
        self.assertGate(rf.match(b(d), bases(repo.head(), repo.commits[1], before=repo.commits[0]), h, repo.head(),
                                 PLUGIN), rf.UNKNOWN, "no_match")

    def test_the_parent_reader_seam_synthetic(self):
        """SYNTHETIC, reduced scope: this test's OWN environment removes
        GIT_GRAFT_FILE (unset, never /dev/null), so a reader that took
        parents from `rev-list` would follow a grafts splice of Y, whose map
        equals the capture. The byte reader does not: `no_match`. In
        production every switch is on, and the two readers agree."""
        repo = Repo(self.base, n=5)
        (repo.path / "router" / "a.py").write_text("A = 'y'\n")
        _git(repo.path, "add", "-A")
        y_tree = _git(repo.path, "write-tree").decode().strip()
        y = repo.commit_obj(b"tree %s\nparent %s\nauthor t <t@example.org> 1 +0000\n"
                            b"committer t <t@example.org> 1 +0000\n" % (y_tree.encode(), repo.commits[2].encode()))
        _git(repo.path, "reset", "-q", "--hard")
        (repo.path / ".git" / "info").mkdir(exist_ok=True)
        (repo.path / ".git" / "info" / "grafts").write_text(f"{repo.head()} {y}\n")
        real = rf.hg.git_env
        self.addCleanup(setattr, rf.hg, "git_env", real)
        rf.hg.git_env = lambda: {k: v for k, v in real().items() if k != "GIT_GRAFT_FILE"}
        d = capture(read_or_fail(self, repo.path, y, y)["trees"][y])
        h = read_or_fail(self, repo.path, repo.head(), repo.commits[2])
        self.assertGate(rf.match(b(d), bases(repo.head(), repo.commits[2], before=repo.commits[1]), h, repo.head(),
                                 PLUGIN),
                        rf.UNKNOWN, "no_match")

    def test_a_replace_graft_does_not_reach_the_gate(self):
        repo = Repo(self.base, n=5)
        (repo.path / "router" / "a.py").write_text("A = 'y'\n")
        _git(repo.path, "add", "-A")
        y_tree = _git(repo.path, "write-tree").decode().strip()
        y = repo.commit_obj(b"tree %s\nauthor t <t@example.org> 1 +0000\ncommitter t <t@example.org> 1 +0000\n"
                            % y_tree.encode())
        _git(repo.path, "reset", "-q", "--hard")
        _git(repo.path, "replace", "--graft", repo.commits[3], y)
        d = capture(read_or_fail(self, repo.path, y, y)["trees"][y])
        h = read_or_fail(self, repo.path, repo.head(), repo.commits[1])
        self.assertGate(rf.match(b(d), bases(repo.head(), repo.commits[1], before=repo.commits[0]), h, repo.head(),
                                 PLUGIN), rf.UNKNOWN, "no_match")


# --- PROGRAM ----------------------------------------------------------------------


def program():
    ns = {"__name__": "router_fingerprint_test"}
    exec(rf.PROGRAM, ns)
    return ns


@unittest.skipUnless(os.path.isdir("/proc/self"), "PROGRAM reads /proc")
class ProgramRows(unittest.TestCase):
    """PROGRAM against real files, FIFOs and spawned children. Three parts of
    the config's `stable` are defence in depth with no isolating row here:
    the same-path stat after the read, the size check, and the realpath after
    the read. The rename row sees `stable` false through the old inode's
    ctime, and an unprivileged test cannot swap a bind mount; they stay
    residue."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(self._clean)

    def _clean(self):
        for root, dirs, _ in os.walk(self.base):
            for d in dirs:
                os.chmod(os.path.join(root, d), 0o755)
        shutil.rmtree(self.base, ignore_errors=True)

    def app(self):
        app = self.base / "app"
        (app / "router" / "tests").mkdir(parents=True)
        (app / "docker").mkdir()
        (app / "router" / "a.py").write_text("A = 1\n")
        (app / "router" / "README.md").write_text("r\n")
        (app / "docker" / "entrypoint.sh").write_text("#!/bin/sh\n")
        return app

    def test_the_blobs_equal_git_hash_object(self):
        p = program()
        app = self.app()
        got = p["read_app"](str(app))
        want = subprocess.run([GIT, "hash-object", str(app / "router" / "a.py")], capture_output=True, text=True,
                              check=True).stdout.strip()
        self.assertEqual(got["py"], {"a.py": want})
        self.assertEqual(got["entries"], {"a.py": "file", "README.md": "file", "tests": "dir"})
        self.assertEqual(got["app"], {"router": "dir", "docker": "dir"})
        ep = subprocess.run([GIT, "hash-object", str(app / "docker" / "entrypoint.sh")], capture_output=True,
                            text=True, check=True).stdout.strip()
        self.assertEqual(got["entrypoint"], ep)
        self.assertEqual(p["ERRORS"], [])

    @unittest.skipIf(os.geteuid() == 0, "root reads a mode-000 file")
    def test_an_unreadable_py_lands_in_errors(self):
        p = program()
        app = self.app()
        (app / "router" / "a.py").chmod(0)
        p["read_app"](str(app))
        self.assertTrue(any("a.py" in e for e in p["ERRORS"]))

    @unittest.skipIf(os.geteuid() == 0, "root walks a mode-000 directory")
    def test_a_mode_000_directory_lands_in_errors_never_false(self):
        p = program()
        sd = self.base / "state"
        (sd / "inst" / "deep").mkdir(parents=True)
        (sd / "inst").chmod(0)
        got = p["walk_peer"](str(sd))
        self.assertIsNone(got["peer_entries"])
        self.assertTrue(p["ERRORS"])

    def test_a_peer_entry_at_depth_is_true(self):
        p = program()
        sd = self.base / "state"
        (sd / "inst" / "x" / "peer-abc").mkdir(parents=True)
        self.assertTrue(p["walk_peer"](str(sd))["peer_entries"])
        self.assertEqual(p["ERRORS"], [])
        (sd / "inst" / "x" / "peer-abc").rmdir()
        self.assertIs(p["walk_peer"](str(sd))["peer_entries"], False)

    def test_status(self):
        p = program()
        sd = self.base / "state"
        sd.mkdir()
        self.assertIsNone(p["read_status"](str(sd)))
        self.assertTrue(p["ERRORS"])
        (sd / "status.json").write_text(json.dumps({"started_ts": "x", "last_poll_ts": "y"}))
        got = p["read_status"](str(sd))
        self.assertEqual(got["classification"], {"present": False, "value": None})
        self.assertEqual(got["started_ts"], {"present": True, "value": "x"})

    def config(self, doc=None):
        cfg = self.base / "cfg" / "router.json"
        cfg.parent.mkdir(exist_ok=True)
        cfg.write_text(json.dumps(doc or {"state_dir": "/state", "transport_plugin": {"path": "/p", "sha256": "ab"}}))
        return cfg

    def test_config_positive_control(self):
        p = program()
        cfg = self.config()
        st = os.stat(cfg)
        got = p["read_config"](str(cfg))
        self.assertEqual((got["realpath_ok"], got["regular"], got["stable"]), (True, True, True))
        self.assertEqual((got["dev"], got["ino"], got["ctime_ns"]), (st.st_dev, st.st_ino, st.st_ctime_ns))
        self.assertEqual(got["state_dir"], "/state")
        self.assertEqual(got["transport_plugin"], {"present": True, "sha256": "ab"})
        self.assertEqual(p["ERRORS"], [])

    def test_a_final_component_symlink_is_an_errors_row(self):
        p = program()
        cfg = self.config()
        link = self.base / "link.json"
        link.symlink_to(cfg)
        p["read_config"](str(link))
        self.assertTrue(p["ERRORS"])

    def test_a_symlinked_parent_is_realpath_false_and_stable(self):
        p = program()
        cfg = self.config()
        alias = self.base / "alias"
        alias.symlink_to(cfg.parent)
        got = p["read_config"](str(alias / "router.json"))
        self.assertEqual((got["realpath_ok"], got["regular"], got["stable"]), (False, True, True))
        self.assertEqual(p["ERRORS"], [])

    def test_an_edit_between_the_first_fstat_and_the_read(self):
        p = program()
        cfg = self.config()
        first = os.stat(cfg).st_ctime_ns

        def hook():
            time.sleep(0.02)
            with open(cfg, "a") as f:
                f.write(" ")
        p["HOOK"] = hook
        got = p["read_config"](str(cfg))
        self.assertIs(got["stable"], False)
        self.assertEqual(got["ctime_ns"], first)

    def test_a_rename_replacement_during_the_read(self):
        p = program()
        cfg = self.config()

        def hook():
            other = cfg.parent / "new.json"
            other.write_text(cfg.read_text())
            os.replace(other, cfg)
        p["HOOK"] = hook
        self.assertIs(p["read_config"](str(cfg))["stable"], False)

    def test_a_directory_is_not_regular_and_not_read(self):
        p = program()
        d = self.base / "cfgdir"
        d.mkdir()
        got = p["read_config"](str(d))
        self.assertIs(got["regular"], False)
        self.assertIsNone(got["state_dir"])
        self.assertIn("the live config is not a regular file", p["ERRORS"])

    def test_a_fifo_with_no_writer_does_not_hang(self):
        fifo = self.base / "fifo"
        os.mkfifo(fifo)
        code = ("import json,sys\nns={'__name__':'t'}\nexec(sys.stdin.read(),ns)\n"
                f"print(json.dumps([ns['read_config']({str(fifo)!r}), ns['ERRORS']]))")
        try:
            out = subprocess.run([sys.executable, "-I", "-c", code], input=rf.PROGRAM, capture_output=True,
                                 text=True, timeout=20, check=True).stdout
        except subprocess.TimeoutExpired:
            self.fail("opening a FIFO with no writer blocked")
        got, errors = json.loads(out)
        self.assertIs(got["regular"], False)
        self.assertIn("the live config is not a regular file", errors)

    def spawn(self, argv, env=None):
        p = subprocess.Popen(argv, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(p.wait)
        self.addCleanup(p.kill)
        return p

    def test_ld_env_and_umask_come_from_proc(self):
        p = program()
        child = self.spawn(["/bin/sh", "-c", "umask 0027; exec sleep 30"],
                           env={"LD_TESTVAR": "1", "PYTHONX": "2", "ROUTER_CONFIG": "/c", "PATH": "/usr/bin:/bin"})
        for _ in range(100):
            with open(f"/proc/{child.pid}/cmdline", "rb") as f:
                if f.read().startswith(b"sleep"):
                    break
            time.sleep(0.02)
        doc, env = p["read_process"](child.pid)
        self.assertEqual(doc["ld_env"], ["LD_TESTVAR"])
        self.assertEqual(doc["umask"], "0027")
        self.assertEqual(doc["python_env"], {"PYTHONX": "2"})
        self.assertEqual(doc["router_config"], "/c")
        self.assertEqual(doc["argv"], ["sleep", "30"])

    def test_the_clock_estimates_a_childs_spawn_within_one_tick(self):
        """The same arithmetic, on a spawned child whose comm holds ")"."""
        p = program()
        odd = self.base / "a) b"
        shutil.copy(shutil.which("sleep"), odd)
        t0 = time.time_ns()
        child = self.spawn([str(odd), "30"])
        t1 = time.time_ns()
        time.sleep(0.05)
        k = p["read_clock"](child.pid)
        est = k["now_ns"] - (k["uptime_s"] - k["pid1_starttime_ticks"] / k["clk_tck"]) * NS
        tick = NS / k["clk_tck"]
        self.assertLessEqual(t0 - 2 * tick, est)
        self.assertLessEqual(est, t1 + 2 * tick)

    def test_user_site_is_resolved_under_pid_1s_home(self):
        """PID 1's HOME, with no PYTHONUSERBASE: the lookup is made under its
        environment, never this process's."""
        p = program()
        home = self.base / "home"
        home.mkdir()
        saved = {k: os.environ.get(k) for k in ("HOME", "PYTHONUSERBASE")}
        self.assertFalse(p["user_site"]({"HOME": str(home)}))
        import site
        os.environ["HOME"] = str(home)
        os.environ.pop("PYTHONUSERBASE", None)
        site.USER_BASE = site.USER_SITE = None
        try:
            path = site.getusersitepackages()
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            site.USER_BASE = site.USER_SITE = None
        self.assertTrue(path.startswith(str(home)))
        os.makedirs(path)
        self.assertTrue(p["user_site"]({"HOME": str(home)}))
        self.assertEqual({k: os.environ.get(k) for k in saved}, saved)

    def test_a_symlinked_router_reads_as_a_link_and_is_refused(self):
        """No link is followed: /app/router as a symlink reads as `link`,
        and the gate refuses the layout."""
        p = program()
        app = self.app()
        real = self.base / "elsewhere"
        (app / "router").rename(real)
        (app / "router").symlink_to(real)
        self.assertEqual(p["read_app"](str(app))["app"]["router"], "link")
        d = capture(TREE[C[1]])
        d["result"]["app"]["router"] = "link"
        self.assertEqual(rf.match(b(d), bases(), H, TARGET, PLUGIN)[2], "layout")

    def test_a_name_set_twice_in_the_environ_is_an_error(self):
        p = program()
        env = p["parse_environ"](b"A=1\0PYTHONDONTWRITEBYTECODE=\0PYTHONDONTWRITEBYTECODE=1\0", "/proc/1")
        self.assertEqual(env["A"], "1")
        self.assertTrue(any("PYTHONDONTWRITEBYTECODE more than once" in e for e in p["ERRORS"]))

    def test_an_image_run_has_no_pid_1_members(self):
        p = program()
        got = p["collect"]("image", app=str(self.app()))
        for k in ("process", "clock", "config", "status", "peer_lane"):
            self.assertIsNone(got[k])
        self.assertIsNone(got["interpreter"]["pid1_exe"])
        self.assertEqual(got["errors"], [])

    def test_the_program_runs_under_dash_i_dash_s(self):
        out = subprocess.run([sys.executable, "-I", "-S", "-c", rf.PROGRAM, "image"], capture_output=True,
                             text=True, timeout=30, check=True).stdout
        self.assertEqual(set(json.loads(out)), set(rf.RESULT))

    def test_the_hook_cannot_be_set_in_production(self):
        self.assertIn('globals().get("HOOK")', rf.PROGRAM)
        self.assertNotIn("HOOK =", rf.PROGRAM)


class PycachePrefixEndToEnd(Outcome):
    """A local CPython stand-in for `python3 -m router`: under
    PYTHONPYCACHEPREFIX it runs a cached .pyc in place of the source, while
    PROGRAM reads the source's bytes. The matcher refuses the variable."""

    def test_the_cache_runs_and_the_gate_refuses_it(self):
        import importlib._bootstrap_external as be
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        app = base / "app"
        (app / "router").mkdir(parents=True)
        src = app / "router" / "__main__.py"
        src.write_text("print('source')\n")
        (app / "router" / "__init__.py").write_text("")
        prefix = base / "cache"
        st = src.stat()
        code = compile("print('cached')\n", str(src), "exec")
        pyc = Path(str(prefix) + str(src.parent.resolve())) / ("__main__." + sys.implementation.cache_tag + ".pyc")
        pyc.parent.mkdir(parents=True)
        pyc.write_bytes(be._code_to_timestamp_pyc(code, int(st.st_mtime), st.st_size))
        env = dict(os.environ, PYTHONPYCACHEPREFIX=str(prefix))
        ran = subprocess.run([sys.executable, "-m", "router"], cwd=app, env=env, capture_output=True, text=True,
                             timeout=30).stdout.strip()
        self.assertEqual(ran, "cached")
        p = program()
        read = p["read_app"](str(app))
        want = subprocess.run([GIT, "hash-object", str(src)], capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(read["py"]["__main__.py"], want)
        d = capture(TREE[C[1]])
        d["image_python_env"]["PYTHONPYCACHEPREFIX"] = str(prefix)
        d["result"]["process"]["python_env"]["PYTHONPYCACHEPREFIX"] = str(prefix)
        self.assertGate(gate(d), rf.UNKNOWN, "env_allow")


# --- The capture ------------------------------------------------------------------


class Engine:
    """A stub docker: answers inspect, image inspect, exec and run."""

    def __init__(self, result, *, running=True, paused=False, env=True, exec_rc=0, exec_out=None,
                 second_started="2026-10-16T10:00:00.5Z", image_rc=0):
        self.calls = []
        self.result, self.running, self.paused, self.env = result, running, paused, env
        self.exec_rc, self.exec_out, self.second, self.image_rc = exec_rc, exec_out, second_started, image_rc
        self.inspects = 0

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        rest = argv[1:]
        done = lambda out=b"", rc=0: subprocess.CompletedProcess(argv, rc, out, b"err")
        if rest[0] == "inspect":
            self.inspects += 1
            started = "2026-10-16T10:00:00.5Z" if self.inspects == 1 else self.second
            return done(json.dumps([{"Id": "f" * 64, "Name": "/amap-rl", "Image": "sha256:" + "e" * 64,
                                     "State": {"Running": self.running, "Paused": self.paused,
                                               "StartedAt": started}}]).encode())
        if rest[:2] == ["image", "inspect"]:
            cfg = {"Env": ["PATH=/usr/bin", "PYTHONUNBUFFERED=1", "PYTHON_VERSION=3.11.9"]} if self.env else {}
            return done(json.dumps([{"Id": "sha256:" + "e" * 64, "Config": cfg}]).encode(), self.image_rc)
        if rest[0] in ("exec", "run"):
            out = self.exec_out if self.exec_out is not None else json.dumps(self.result).encode()
            return done(out, self.exec_rc)
        raise AssertionError(argv)


class CaptureVerb(unittest.TestCase):

    def setUp(self):
        self.run_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.run_dir, ignore_errors=True)
        real = rf._load_spec
        self.addCleanup(setattr, rf, "_load_spec", real)
        spec = SimpleNamespace(secrets=SimpleNamespace(run_dir=str(self.run_dir), docker_via_sudo=False,
                                                       tools={"docker": "docker"}),
                               router=SimpleNamespace(container="amap-rl"))
        rf._load_spec = lambda *a, **k: spec
        real_docker = rf.ss_docker
        self.addCleanup(setattr, rf, "ss_docker", real_docker)
        rf.ss_docker = lambda spec: ["docker"]
        self.result = capture(TREE[C[1]])["result"]

    def args(self, **kw):
        base = dict(verify_image=None, match=None, image=None, step=None, apply=False, commit=None, spec=None,
                    overlay=None)
        base.update(kw)
        return SimpleNamespace(**base)

    def test_a_dry_run_makes_no_call(self):
        eng = Engine(self.result)
        for a in (self.args(step=2), self.args(image="example.org/rl:pin")):
            with self.subTest(args=a):
                self.assertEqual(rf.run(a, out=lambda s: None, runner=eng), 0)
        self.assertEqual(eng.calls, [])
        self.assertEqual(list(self.run_dir.iterdir()), [])

    def test_apply_makes_exactly_four_calls_and_one_file(self):
        eng = Engine(self.result)
        self.assertEqual(rf.run(self.args(step=2, apply=True), out=lambda s: None, runner=eng), 0)
        verbs = [c[1:3] if c[1] == "image" else c[1:2] for c in eng.calls]
        self.assertEqual(verbs, [["inspect"], ["image", "inspect"], ["exec"], ["inspect"]])
        self.assertEqual(eng.calls[2][2:8], ["f" * 64, "python3", "-I", "-S", "-c", rf.PROGRAM])
        self.assertEqual(eng.calls[2][8], "running")
        self.assertEqual(eng.calls[3][1:], ["inspect", "f" * 64])
        files = list(self.run_dir.iterdir())
        self.assertEqual(len(files), 1)
        self.assertTrue(files[0].name.startswith("router-fingerprint-2-"))
        doc = json.loads(files[0].read_bytes())
        self.assertEqual(files[0].read_bytes(), rf.canonical(doc))
        self.assertEqual(doc["image_python_env"], {"PYTHONUNBUFFERED": "1", "PYTHON_VERSION": "3.11.9"})
        self.assertEqual(doc["container"]["name"], "/amap-rl")

    def test_each_failure_is_exit_2_and_no_file(self):
        cases = {"not running": dict(running=False), "paused": dict(paused=True), "no Config.Env": dict(env=False),
                 "a failed image inspect": dict(image_rc=1), "a failed exec": dict(exec_rc=1),
                 "non-JSON output": dict(exec_out=b"Traceback"), "a restart between": dict(second_started="x")}
        for name, kw in cases.items():
            with self.subTest(case=name):
                eng = Engine(self.result, **kw)
                self.assertEqual(rf.run(self.args(step=2, apply=True), out=lambda s: None, runner=eng), 2)
                self.assertEqual(list(self.run_dir.iterdir()), [])

    def test_container_names_the_router_started_before_activation(self):
        eng = Engine(self.result)
        self.assertEqual(rf.run(self.args(step=2, apply=True, container="amap-router-local"), out=lambda s: None,
                                runner=eng), 0)
        self.assertEqual(eng.calls[0][1:], ["inspect", "amap-router-local"])
        self.assertEqual(eng.calls[3][1:], ["inspect", "f" * 64])

    def test_an_image_capture_runs_by_the_inspected_id(self):
        eng = Engine(capture(TREE[C[1]], source="image")["result"])
        self.assertEqual(rf.run(self.args(image="example.org/rl:pin", apply=True), out=lambda s: None,
                               runner=eng), 0)
        self.assertEqual([c[1] for c in eng.calls], ["image", "run"])
        run = eng.calls[1]
        self.assertEqual(run[1:7], ["run", "--rm", "--network", "none", "--entrypoint", "python3"])
        self.assertEqual(run[7], "sha256:" + "e" * 64)
        self.assertEqual(run[-1], "image")
        files = list(self.run_dir.iterdir())
        self.assertTrue(files[0].name.startswith("router-fingerprint-image-"))


class MatchVerb(Outcome):
    """The CLI: precheck before any git call, then bases_dirty and the
    container name, then read_history with the given git, then match."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        real = rf._load_spec
        self.addCleanup(setattr, rf, "_load_spec", real)
        rf._load_spec = lambda *a, **k: SimpleNamespace(secrets=None, router=SimpleNamespace(container="amap-rl"))
        real_dirty = rf.bases_dirty
        self.addCleanup(setattr, rf, "bases_dirty", real_dirty)
        rf.bases_dirty = lambda *a, **k: None
        self.h = read_or_fail(self, HOP, REAL_TARGET, REAL_FROM)

    def cli(self, capture_doc, bases_bytes=None, git=GIT, container=None):
        real_bases = rf.BASES_PATH
        self.addCleanup(setattr, rf, "BASES_PATH", real_bases)
        if bases_bytes is not None:
            p = self.base / "bases.json"
            p.write_bytes(bases_bytes)
            rf.BASES_PATH = p
        f = self.base / "cap.json"
        f.write_bytes(b(capture_doc))
        lines = []
        args = SimpleNamespace(verify_image=None, match=str(f), image=None, step=None, apply=False, commit=None,
                               spec=None, overlay=None, container=container)
        code = rf.run(args, out=lines.append, git=git)
        return code, lines

    def test_the_cli_history_equals_the_history_passed(self):
        d = capture(self.h["trees"][self.h["first_parent"][3]])
        code, lines = self.cli(d)
        want = rf.match(b(d), rf.BASES_PATH.read_bytes(), self.h, REAL_TARGET, PLUGIN)
        self.assertEqual(code, want[1])
        self.assertEqual(lines[-1], f"{want[0]} {want[2]}: {want[3]}")
        self.assertEqual(want[0], rf.MEASURED)

    def test_a_dirty_bases_file(self):
        rf.bases_dirty = lambda *a, **k: "router-upgrade-bases.json is modified in the deploy checkout"
        code, lines = self.cli(capture(self.h["trees"][REAL_TARGET]))
        self.assertEqual((code, lines[-1].split(":")[0]), (2, "UNKNOWN bases_dirty"))

    def test_container_names_the_router_the_capture_was_of(self):
        d = capture(self.h["trees"][REAL_TARGET])
        d["container"]["name"] = "/amap-router-local"
        code, lines = self.cli(d)
        self.assertEqual((code, lines[-1].split(":")[0]), (2, "UNKNOWN container_name"))
        code, lines = self.cli(d, container="amap-router-local")
        self.assertEqual(code, 0, lines[-1])

    def test_another_container(self):
        d = capture(self.h["trees"][REAL_TARGET])
        d["container"]["name"] = "/other"
        code, lines = self.cli(d)
        self.assertEqual((code, lines[-1].split(":")[0]), (2, "UNKNOWN container_name"))

    def test_the_cli_uses_the_hop_pin_not_the_bases_target(self):
        """A bases file for a different existing target: the CLI answers `pin`."""
        fp = self.h["first_parent"]
        doc = json.loads(rf.BASES_PATH.read_bytes())
        doc.update(target=fp[1], measured_from=fp[11])
        code, lines = self.cli(capture(self.h["trees"][fp[2]]), json.dumps(doc).encode())
        self.assertEqual((code, lines[-1].split(":")[0]), (2, "UNKNOWN pin"))

    def test_verify_image_end_to_end_is_exact(self):
        f = self.base / "img.json"
        f.write_bytes(b(capture(self.h["trees"][REAL_TARGET], source="image")))
        lines = []
        args = SimpleNamespace(verify_image=str(f), match=None, image=None, step=None, apply=False,
                               commit=REAL_TARGET, spec=None, overlay=None)
        self.assertEqual(rf.run(args, out=lines.append, git=GIT), 0)
        self.assertTrue(lines[-1].startswith("EXACT exact"))


class MatchVerbNoHop(Outcome):
    """The CLI rows that must refuse before any git command: they need no
    hop checkout, so the precheck's kill does not depend on one."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        real = rf._load_spec
        self.addCleanup(setattr, rf, "_load_spec", real)
        rf._load_spec = lambda *a, **k: SimpleNamespace(secrets=None, router=SimpleNamespace(container="amap-rl"))
        real_dirty = rf.bases_dirty
        self.addCleanup(setattr, rf, "bases_dirty", real_dirty)
        rf.bases_dirty = lambda *a, **k: None

    def test_a_bases_schema_defect_runs_no_git(self):
        rec = RecordingGit(self.base)
        real_bases = rf.BASES_PATH
        self.addCleanup(setattr, rf, "BASES_PATH", real_bases)
        doc = json.loads(rf.BASES_PATH.read_bytes())
        doc["schema"] = 3
        rf.BASES_PATH = self.base / "bases.json"
        rf.BASES_PATH.write_text(json.dumps(doc))
        f = self.base / "cap.json"
        f.write_bytes(b(capture(TREE[C[1]])))
        lines = []
        args = SimpleNamespace(verify_image=None, match=str(f), image=None, step=None, apply=False, commit=None,
                               spec=None, overlay=None)
        self.assertEqual(rf.run(args, out=lines.append, git=str(rec.path)), 2)
        self.assertIn("bases_schema", lines[-1])
        self.assertEqual(rec.calls(), [])

    def test_verify_image_refuses_a_malformed_commit_with_no_git(self):
        rec = RecordingGit(self.base)
        lines = []
        args = SimpleNamespace(verify_image=str(self.base / "x.json"), match=None, image=None, step=None,
                               apply=False, commit="main", spec=None, overlay=None)
        self.assertEqual(rf.run(args, out=lines.append, git=str(rec.path)), 2)
        self.assertIn("commit_format", lines[-1])
        self.assertEqual(rec.calls(), [])

    def test_an_unexpected_failure_is_unknown_never_a_traceback(self):
        real = rf._run
        self.addCleanup(setattr, rf, "_run", real)

        def boom(*a, **k):
            raise FileExistsError("router-fingerprint-2-x.json")
        rf._run = boom
        lines = []
        args = SimpleNamespace(verify_image=None, match=None, image=None, step=2, apply=True, commit=None,
                               spec=None, overlay=None)
        try:
            code = rf.run(args, out=lines.append)
        except Exception as e:     # noqa: BLE001
            self.fail(f"an exception escaped run(): {type(e).__name__}")
        self.assertEqual(code, 2)
        self.assertIn("UNKNOWN internal", lines[-1])


class BasesDirty(unittest.TestCase):
    """The bases file's provenance on a real repository: the bytes given to
    the matcher must equal the committed bytes, and the index must hold that
    blob, whatever the index's flags hide from `git status`."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        _git(self.base, "init", "-q")
        self.f = self.base / rf.BASES_NAME
        self.committed = b'{"measured_from": "a"}\n'
        self.f.write_bytes(self.committed)
        _git(self.base, "add", "-A")
        _git(self.base, "commit", "-q", "-m", "b")

    def test_the_committed_file_is_clean(self):
        self.assertIsNone(rf.bases_dirty(self.f))
        self.assertIsNone(rf.bases_dirty(self.f, self.committed))

    def test_a_visible_edit(self):
        self.f.write_bytes(b'{"measured_from": "b"}\n')
        self.assertIsNotNone(rf.bases_dirty(self.f))

    def test_an_edit_under_skip_worktree(self):
        _git(self.base, "update-index", "--skip-worktree", rf.BASES_NAME)
        self.f.write_bytes(b'{"measured_from": "b"}\n')
        self.assertEqual(_git(self.base, "status", "--porcelain"), b"")
        self.assertIsNotNone(rf.bases_dirty(self.f))

    def test_an_edit_under_assume_unchanged(self):
        _git(self.base, "update-index", "--assume-unchanged", rf.BASES_NAME)
        self.f.write_bytes(b'{"measured_from": "b"}\n')
        self.assertEqual(_git(self.base, "status", "--porcelain"), b"")
        self.assertIsNotNone(rf.bases_dirty(self.f))

    def test_an_untracked_or_ignored_file(self):
        other = Path(tempfile.mkdtemp(dir=self.base))
        _git(other, "init", "-q")
        (other / ".gitignore").write_text(rf.BASES_NAME + "\n")
        _git(other, "add", "-A")
        _git(other, "commit", "-q", "-m", "i")
        g = other / rf.BASES_NAME
        g.write_bytes(self.committed)
        self.assertEqual(_git(other, "status", "--porcelain"), b"")
        self.assertIsNotNone(rf.bases_dirty(g))
        (other / ".gitignore").unlink()
        self.assertIsNotNone(rf.bases_dirty(g))

    def test_a_staged_change_with_the_file_restored(self):
        self.f.write_bytes(b'{"measured_from": "b"}\n')
        _git(self.base, "add", rf.BASES_NAME)
        self.f.write_bytes(self.committed)
        self.assertIsNotNone(rf.bases_dirty(self.f))

    def test_a_staged_edit_with_the_worktree_equal_to_the_index(self):
        """Committed, then edited and `git add`ed: the worktree equals the
        index and both differ from HEAD. Only a reader of HEAD refuses it."""
        self.f.write_bytes(b'{"measured_from": "b"}\n')
        _git(self.base, "add", rf.BASES_NAME)
        self.assertEqual(_git(self.base, "diff", "--stat"), b"")
        self.assertIsNotNone(rf.bases_dirty(self.f))

    def test_a_single_unmerged_stage(self):
        info = f"0 {'0' * 40}\t{rf.BASES_NAME}\n100644 {self.blob()} 2\t{rf.BASES_NAME}\n"
        _git(self.base, "update-index", "--index-info", data=info.encode())
        self.assertEqual(len(_git(self.base, "ls-files", "--stage", "--", rf.BASES_NAME).splitlines()), 1)
        self.assertIsNotNone(rf.bases_dirty(self.f))

    def test_a_record_name_may_hold_a_tab(self):
        """git's -z output separates the fields from the path at the FIRST tab."""
        self.assertEqual(rf._records(b"100644 blob " + b"a" * 40 + b"\tx\ty\0"),
                         [(["100644", "blob", "a" * 40], "x\ty")])

    def test_a_committed_file_missing_from_the_index(self):
        _git(self.base, "rm", "-q", "--cached", rf.BASES_NAME)
        self.assertEqual(self.f.read_bytes(), self.committed)
        self.assertIsNotNone(rf.bases_dirty(self.f))

    def test_the_bytes_given_are_what_is_compared(self):
        self.assertIsNotNone(rf.bases_dirty(self.f, b'{"measured_from": "b"}\n'))

    def blob(self):
        return _git(self.base, "rev-parse", "HEAD:" + rf.BASES_NAME).decode().strip()

    def test_a_staged_executable_mode_with_the_same_blob(self):
        _git(self.base, "update-index", "--chmod=+x", rf.BASES_NAME)
        self.assertEqual(self.f.read_bytes(), self.committed)
        self.assertIsNotNone(rf.bases_dirty(self.f))

    def test_a_staged_symlink_entry_with_the_same_blob(self):
        _git(self.base, "update-index", "--cacheinfo", f"120000,{self.blob()},{rf.BASES_NAME}")
        self.assertIsNotNone(rf.bases_dirty(self.f))

    def test_unmerged_stages_on_the_same_blob(self):
        z = "0" * 40
        info = f"0 {z}\t{rf.BASES_NAME}\n" + "".join(f"100644 {self.blob()} {n}\t{rf.BASES_NAME}\n" for n in (1, 2, 3))
        _git(self.base, "update-index", "--index-info", data=info.encode())
        self.assertEqual(len(_git(self.base, "ls-files", "--stage", "--", rf.BASES_NAME).splitlines()), 3)
        self.assertIsNotNone(rf.bases_dirty(self.f))

    def test_a_committed_executable_mode(self):
        _git(self.base, "update-index", "--chmod=+x", rf.BASES_NAME)
        _git(self.base, "commit", "-q", "-m", "x")
        self.assertIsNotNone(rf.bases_dirty(self.f))

    def test_the_cli_answers_unknown_bases_dirty(self):
        """The real check through the verb: a staged mode change refuses
        before any history is read."""
        repo = Path(tempfile.mkdtemp(dir=self.base))
        _git(repo, "init", "-q")
        f = repo / rf.BASES_NAME
        f.write_bytes(rf.BASES_PATH.read_bytes())
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "b")
        _git(repo, "update-index", "--chmod=+x", rf.BASES_NAME)
        for attr, value in (("BASES_PATH", f),
                            ("_load_spec", lambda *a, **k: SimpleNamespace(secrets=None,
                                                                         router=SimpleNamespace(container="amap-rl")))):
            self.addCleanup(setattr, rf, attr, getattr(rf, attr))
            setattr(rf, attr, value)
        rec = RecordingGit(self.base)
        cap = self.base / "cap.json"
        cap.write_bytes(b(capture(TREE[C[1]])))
        lines = []
        args = SimpleNamespace(verify_image=None, match=str(cap), image=None, step=None, apply=False, commit=None,
                               spec=None, overlay=None)
        self.assertEqual(rf.run(args, out=lines.append, git=str(rec.path)), 2)
        self.assertTrue(lines[-1].startswith("UNKNOWN bases_dirty"), lines[-1])
        self.assertEqual(rec.calls(), [])


class Pins(unittest.TestCase):

    def test_pre_registry_before_is_where_registry_dir_lands(self):
        """Measured on the hop checkout: the first first-parent commit whose
        router/config.py names registry_dir, and the one below it does not."""
        before = json.loads(rf.BASES_PATH.read_bytes())["pre_registry"]["before"]
        self.assertEqual(before, "a84e0d986e96460a4c1ad0563675fbf32c6a104f")
        show = lambda c: subprocess.run([GIT, "-C", HOP, "show", c + ":router/config.py"], capture_output=True,
                                        text=True).stdout
        self.assertIn('"registry_dir"', show(before))
        self.assertNotIn('"registry_dir"', show(before + "^"))

    def test_the_bases_target_is_the_hop_pin(self):
        doc = json.loads(rf.BASES_PATH.read_bytes())
        self.assertEqual(doc["target"], hp.hop_pin())
        self.assertEqual((doc["target"], doc["measured_from"]), (REAL_TARGET, REAL_FROM))

    def test_the_premises_string(self):
        p = json.loads(rf.BASES_PATH.read_bytes())["premises"].encode("utf-8")
        self.assertEqual(len(p), 1202)
        self.assertEqual(hashlib.sha256(p).hexdigest(),
                         "ca45c0ac00df86a5c61b9d06e1313848b3efdd3d19fb134f1cbde83e25b4c67a")

    def test_the_plugin_digest(self):
        self.assertEqual(hp.PLUGIN_SHA256, "f15855c974df021c2ae5c551aff2448d934725a6796fb03434e573305d24fe93")

    def test_the_program_sha256(self):
        self.assertEqual(rf.PROGRAM_SHA256, "e808f20f8a59a2dec9716c35d3a4206cee07489beb848c1906765c48052d6186")


if __name__ == "__main__":
    unittest.main()
