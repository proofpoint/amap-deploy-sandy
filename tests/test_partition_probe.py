"""partition_probe: the four probes, each with both halves and its witness.

The engine is faked at the one place the module reaches it (Runner), and the
fake answers each one-shot by the script and the arguments in its argv, so a
probe that sent the wrong script or the wrong paths gets the wrong answer.
The scripts themselves are also EXECUTED here, against temporary trees,
because a verdict is only as good as the script that produced its rows."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

import hub_runtime as hr
import partition_evidence as pe
import partition_probe as pp
import router_health as rh

EMAIL = {"name": "ex-down", "image": "sha256:" + "a" * 64, "user": "2102:2102", "group_add": ["2200"],
         "read_only": True, "ulimits": {"core": "0:0"}, "security_opt": ["no-new-privileges"],
         "cap_drop": ["ALL"], "cap_add": [], "network": "amapnet", "restart": "no", "env_file": "/etc/amap/hub.env",
         "mounts": [{"type": "volume", "source": "ex-secret", "target": "/run/secret", "readonly": True,
                     "nocopy": True},
                    {"type": "bind", "source": "/srv/hop", "target": "/hop", "readonly": False},
                    {"type": "bind", "source": "/opt/d7", "target": "/opt/d7", "readonly": True}]}
ROUTER = {"name": "ex-up", "image": "sha256:" + "b" * 64, "user": "2101:2101", "group_add": ["2200"],
          "read_only": False, "ulimits": {"core": "0:0"}, "security_opt": [], "cap_drop": [], "cap_add": [],
          "network": "none", "restart": "unless-stopped", "env_file": "/etc/amap/router.env",
          "mounts": [{"type": "bind", "source": "/srv/hop", "target": "/srv/hop", "readonly": False},
                     {"type": "bind", "source": "/opt/ex/keys", "target": "/opt/ex/keys", "readonly": True}]}
KEY = "/opt/ex/keys/signing.key"


def proc(rc, out):
    return rh.Proc(("docker",), rc, out, "")


class Engine:
    """Answers `docker exec` (P01) and `docker run` one-shots by script."""

    def __init__(self):
        self.walks = {"ex-up": "1 2101 2101\n7 2101 2101\n", "ex-down": "1 2102 2102\n"}
        self.markers = {"up": ["l1 g1 identity.json present 2101 0o640 EACCES",
                               "l1 g1 versions.json present 2101 0o640 EACCES",
                               "l1 g1 frontier.json ENOENT - - -", "l1 g1 retired.json ENOENT - - -",
                               "l1 g1 . create - - EACCES"],
                        "down": ["l1 g1 versions.json present 2102 0o640 EROFS",
                                 "l1 g1 . create - - EROFS"]}
        self.p03 = "ENOENT"
        self.p04 = "ENOENT"
        self.witness = "OPENED"
        self.fail = set()
        self.seen = []

    def __call__(self, argv):
        argv = list(argv)
        self.seen.append(argv)
        if argv[1] == "exec":
            container = argv[4]
            return proc(1, "") if container in self.fail else proc(0, self.walks[container])
        i = argv.index("-c")
        script, args = argv[i + 1], argv[i + 2:]
        name = argv[argv.index("--name") + 1]
        if name in self.fail:
            return proc(125, "")
        if script == pp.P02_SCRIPT:
            return proc(0, "\n".join(self.markers[args[1]]) + "\n")
        if script == pp.P03_SCRIPT:
            return proc(0, "".join(f"{n} {self.p03}\n" for n in range(len(args))))
        if script == pp.P04_SCRIPT:
            return proc(0, "".join(f"{n} {self.p04}\n" for n in range(len(args) - 1)))
        if script == pp.OPEN_WITNESS_SCRIPT:
            return proc(0, "".join(f"{n} {self.witness}\n" for n in range(len(args) - 1)))
        raise AssertionError(f"an unknown script: {script[:40]!r}")


class ProbeRunTest(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = os.path.realpath(t.name)
        self.lanes = {}
        for slug in ("alpha", "beta"):
            d = os.path.join(self.root, "instances", slug, "peer")
            os.makedirs(d)
            self.lanes[slug] = d
        self.sources = dict(self.lanes)
        self.engine = Engine()
        self.drift = []
        self.email = json.loads(json.dumps(EMAIL))

    def plan(self):
        return pp.Plan(host="alpha", run_id="r1", at="2026-10-14T12:00:00Z", email=self.email,
                       email_drift=self.drift, email_volume="ex-secret", router=ROUTER, key_path=KEY,
                       key_dir="/opt/ex/keys", lanes=self.lanes, agent_sources=self.sources,
                       runtimes={"upstream": ("ex-up", 2101, 2101), "downstream": ("ex-down", 2102, 2102)},
                       vantages={"upstream": pp.spec_vantage(ROUTER), "downstream": pp.spec_vantage(self.email)},
                       hops=[("upstream", "downstream")],
                       sides={"up": (self.email, "/hop"), "down": (ROUTER, "/srv/hop")},
                       owners={"up": (ROUTER, "/srv/hop", 2101), "down": (self.email, "/hop", 2102)},
                       bindings={"host_setup": "c" * 64})

    def run_it(self):
        return pp.run(self.plan(), pp.Runner(["docker"], self.engine), hr.argv)

    def verdicts(self, doc):
        return {p["id"]: p["verdict"] for p in json.loads(doc)["probes"]}

    def test_a_healthy_host_passes_every_probe_and_gets_a_token(self):
        doc, code, report = self.run_it()
        self.assertEqual(code, 0, report)
        probes = {p["id"]: p for p in json.loads(doc)["probes"]}
        self.assertEqual(probes["P03"]["target_role"], ["key:signing", "key:dir"])
        self.assertEqual(probes["P04"]["target_role"], ["peer:alpha", "peer:beta"])
        self.assertEqual((probes["P03"]["outcome"], probes["P03"]["witness"]["outcome"]), ("ENOENT", "ok"))
        self.assertEqual(probes["P03"]["vantage"], [{"container": "ex-down", "image": EMAIL["image"], "uid": 2102,
                                                     "gids": [2102, 2200]}])
        self.assertEqual(self.verdicts(doc), {"P01": "PASS", "P02": "PASS", "P03": "PASS", "P04": "PASS"})
        self.assertIsNotNone(json.loads(doc)[pe.TOKEN_MEMBER])
        self.assertEqual(json.loads(doc)["script_sha256"], pp.script_sha256())

    def test_a_running_email_router_that_is_not_its_rendering_refuses_the_whole_run(self):
        self.drift = ["its mounts differ from the rendering"]
        doc, code, report = self.run_it()
        self.assertEqual((doc, code), (None, 2))
        self.assertIn("not its rendering", report[0])
        self.assertEqual(self.engine.seen, [], "no probe runs against a container that is not its spec")

    # P03
    def test_a_reachable_key_fails_p03_and_withholds_the_token(self):
        self.engine.p03 = "EACCES"
        doc, code, _ = self.run_it()
        self.assertEqual((self.verdicts(doc)["P03"], code), ("FAIL", 1))
        self.assertIsNone(json.loads(doc)[pe.TOKEN_MEMBER])

    def test_a_router_that_cannot_open_the_key_makes_p03_unknown(self):
        self.engine.witness = "ENOENT"
        doc, code, _ = self.run_it()
        self.assertEqual(self.verdicts(doc)["P03"], "UNKNOWN")
        self.assertIsNone(json.loads(doc)[pe.TOKEN_MEMBER])

    def test_p03_probes_the_key_and_its_directory_through_every_mount(self):
        self.email["mounts"].append({"type": "bind", "source": "/opt/ex", "target": "/mnt/ex", "readonly": True})
        doc, _, _ = self.run_it()
        roles = next(p for p in json.loads(doc)["probes"] if p["id"] == "P03")["target_role"]
        self.assertEqual(roles, ["key:signing", "key:dir", "mount:1", "mount:3"])
        p03 = [a for a in self.engine.seen if pp.P03_SCRIPT in a][0]
        args = p03[p03.index("-c") + 2:]
        self.assertEqual(sorted(args), sorted([KEY, "/opt/ex/keys", "/mnt/ex/keys/signing.key", "/mnt/ex/keys"]))

    # Host facts outside the evidence vocabulary
    def test_a_mount_path_no_role_could_spell_still_produces_evidence(self):
        """Roles name a candidate by its index, so a host's real paths (a
        space, an @, more than 128 characters) never reach the vocabulary."""
        for where in ("/Library/Application Support/ex", "/run/user@1000", "/" + "d" * 140):
            with self.subTest(where=where):
                self.email = json.loads(json.dumps(EMAIL))
                self.email["mounts"].append({"type": "bind", "source": "/opt/ex", "target": where, "readonly": True})
                self.engine.seen = []
                doc, code, report = self.run_it()
                self.assertEqual(code, 0, report)
                p03 = next(p for p in json.loads(doc)["probes"] if p["id"] == "P03")
                self.assertEqual(p03["target_role"], ["key:signing", "key:dir", "mount:1", "mount:3"])
                argv = [a for a in self.engine.seen if pp.P03_SCRIPT in a][0]
                self.assertIn(where + "/keys/signing.key", argv)

    def test_a_lane_no_role_could_spell_or_no_lane_at_all_refuses_with_exit_2(self):
        for slugs, words in ((["al+pha"], "'peer:al+pha'"), (["a" * 65], "'peer:" + "a" * 65 + "'"),
                             ([], "no lane to probe")):
            with self.subTest(slugs=slugs):
                self.lanes = {s: os.path.join(self.root, "instances", "alpha", "peer") for s in slugs}
                self.sources = dict(self.lanes)
                self.engine.seen = []
                doc, code, report = self.run_it()
                self.assertEqual((doc, code), (None, 2))
                self.assertIn(words, report[-1])
                self.assertEqual(self.engine.seen, [], "refused before any probe runs")

    def test_evidence_that_cannot_be_built_is_exit_2_never_a_traceback(self):
        plan = self.plan()
        plan = pp.Plan(**dict(plan.__dict__, bindings={"host_setup": "not a sha256"}))
        try:
            doc, code, report = pp.run(plan, pp.Runner(["docker"], self.engine), hr.argv)
        except Exception as e:  # a crash is not a verdict
            self.fail(f"the run raised {e!r}")
        self.assertEqual((doc, code), (None, 2))
        self.assertIn("cannot be built", report[-1])
        self.assertTrue(report[0].startswith("P01: PASS"), "the probes' own lines are kept")

    # P04
    def test_a_created_file_in_a_lane_fails_p04(self):
        self.engine.p04 = "CREATED"
        doc, code, report = self.run_it()
        self.assertEqual((self.verdicts(doc)["P04"], code), ("FAIL", 1))
        self.assertIn("created a file in a peer lane", report[3])

    def test_a_visible_lane_fails_p04_even_unwritten(self):
        self.engine.p04 = "EACCES"
        self.assertEqual(self.verdicts(self.run_it()[0])["P04"], "FAIL")

    def test_a_lane_that_is_not_the_agents_live_one_is_unknown_and_not_probed(self):
        other = os.path.join(self.root, "elsewhere")
        os.makedirs(other)
        self.sources["beta"] = other
        doc, code, _ = self.run_it()
        self.assertEqual((self.verdicts(doc)["P04"], code), ("UNKNOWN", 2))
        self.assertFalse([a for a in self.engine.seen if pp.P04_SCRIPT in a], "never a vacuous ENOENT")

    def test_a_missing_lane_or_agent_mount_is_unknown(self):
        self.sources["alpha"] = rh.Unresolved("alpha's container is not running")
        self.assertEqual(self.verdicts(self.run_it()[0])["P04"], "UNKNOWN")
        self.sources = dict(self.lanes)
        os.rmdir(self.lanes["beta"])
        self.assertEqual(self.verdicts(self.run_it()[0])["P04"], "UNKNOWN")

    def test_an_email_router_mount_holding_a_lane_fails_p04(self):
        self.email["mounts"].append({"type": "bind", "source": os.path.join(self.root, "instances"),
                                     "target": "/x", "readonly": True})
        doc, _, _ = self.run_it()
        self.assertEqual(self.verdicts(doc)["P04"], "FAIL")

    def test_p04_creates_only_its_own_probe_name(self):
        self.run_it()
        p04 = [a for a in self.engine.seen if pp.P04_SCRIPT in a][0]
        self.assertEqual(p04[p04.index("-c") + 2], pp.probe_file("r1"))

    # P01
    def test_a_foreign_uid_process_fails_p01_but_keeps_the_token(self):
        self.engine.walks["ex-down"] += "9 0 0\n"
        doc, code, _ = self.run_it()
        self.assertEqual((self.verdicts(doc)["P01"], code), ("FAIL", 1))
        self.assertIsNotNone(json.loads(doc)[pe.TOKEN_MEMBER], "P01 is not fail-stop")

    def test_an_unreadable_status_makes_p01_unknown(self):
        self.engine.walks["ex-up"] += "12 UNREADABLE\n"
        doc, _, report = self.run_it()
        self.assertEqual(self.verdicts(doc)["P01"], "UNKNOWN")
        self.assertIn("/proc/12/status could not be read", report[0])

    def test_p01_reads_proc_as_each_principal_never_as_root(self):
        self.run_it()
        execs = [a for a in self.engine.seen if a[1] == "exec"]
        self.assertEqual(sorted(a[3] for a in execs), ["2101:2101", "2102:2102"])

    # P02
    def test_a_non_owner_opening_a_marker_for_writing_fails_p02(self):
        self.engine.markers["up"][0] = "l1 g1 identity.json present 2101 0o640 OPENED"
        self.assertEqual(self.verdicts(self.run_it()[0])["P02"], "FAIL")

    def test_a_non_owner_creating_beside_the_markers_fails_p02(self):
        self.engine.markers["down"][1] = "l1 g1 . create - - CREATED"
        self.assertEqual(self.verdicts(self.run_it()[0])["P02"], "FAIL")

    def test_a_wrong_owner_or_mode_fails_p02(self):
        self.engine.markers["up"][1] = "l1 g1 versions.json present 2101 0o664 EACCES"
        self.assertEqual(self.verdicts(self.run_it()[0])["P02"], "FAIL")
        self.engine.markers["up"][1] = "l1 g1 versions.json present 2102 0o640 EACCES"
        self.assertEqual(self.verdicts(self.run_it()[0])["P02"], "FAIL")

    def test_a_missing_required_marker_fails_and_a_missing_optional_one_passes(self):
        self.assertEqual(self.verdicts(self.run_it()[0])["P02"], "PASS", "frontier and retired absent")
        self.engine.markers["up"][0] = "l1 g1 identity.json ENOENT - - -"
        self.assertEqual(self.verdicts(self.run_it()[0])["P02"], "FAIL")

    def test_an_owner_that_cannot_open_its_marker_makes_p02_unknown(self):
        self.engine.witness = "EACCES"
        doc, _, _ = self.run_it()
        self.assertEqual(self.verdicts(doc)["P02"], "UNKNOWN")

    def test_a_router_witness_that_could_not_run_makes_p03_unknown(self):
        self.engine.fail.add("ex-up-partition-probe-p03w-r1")
        try:
            doc, code, _ = self.run_it()
        except Exception as e:  # a crash is not a verdict
            self.fail(f"the run raised {e!r}")
        self.assertEqual((self.verdicts(doc)["P03"], code), ("UNKNOWN", 2))
        self.assertIsNone(json.loads(doc)[pe.TOKEN_MEMBER])

    def test_a_probe_that_could_not_run_is_unknown_and_exits_2(self):
        self.engine.fail.add("ex-down-partition-probe-p03-r1")
        doc, code, _ = self.run_it()
        self.assertEqual((self.verdicts(doc)["P03"], code), ("UNKNOWN", 2))
        self.assertIsNone(json.loads(doc)[pe.TOKEN_MEMBER])


class VerdictTest(unittest.TestCase):
    """The guards a whole run cannot reach on its own: run() never hands a
    verdict a shape its earlier steps already refused, so each is judged
    directly here."""

    def judged(self, fn, *args):
        try:
            return fn(*args)
        except Exception as e:  # a crash is not a verdict
            self.fail(f"{fn.__name__} raised {e!r}")

    def test_hop_ends_sharing_a_uid_fail_p01(self):
        walks = {"upstream": [(1, 2101, 2101)], "downstream": [(1, 2101, 2101)]}
        got = self.judged(pp.verdict_p01, walks, {"upstream": 2101, "downstream": 2101}, [("upstream", "downstream")])
        self.assertEqual(got[0], "FAIL")
        self.assertIn("share uid 2101", got[2])

    def test_unestablished_lanes_are_unknown_whatever_the_rows_say(self):
        got = self.judged(pp.verdict_p04, [(0, "ENOENT")], rh.Unresolved("beta is not running"), [])
        self.assertEqual(got[:2], ("UNKNOWN", "unresolved"))

    def test_a_router_witness_that_did_not_open_the_key_is_unknown(self):
        got = self.judged(pp.verdict_p03, [(0, "ENOENT")], [(0, "ENOENT")])
        self.assertEqual(got[:2], ("UNKNOWN", "ENOENT"))

    def test_an_unresolved_router_witness_is_unknown(self):
        got = self.judged(pp.verdict_p03, [(0, "ENOENT")], rh.Unresolved("the one-shot did not start"))
        self.assertEqual(got[:2], ("UNKNOWN", "ENOENT"))


class OneshotTest(unittest.TestCase):
    def test_a_oneshot_keeps_every_privilege_of_its_runtime(self):
        one = pp.oneshot(ROUTER, "P03W", "r1", pp.OPEN_WITNESS_SCRIPT, ["r", KEY])
        for k in ("user", "group_add", "read_only", "security_opt", "cap_drop", "cap_add", "image", "env_file"):
            self.assertEqual(one[k], ROUTER[k], k)
        argv = pp.oneshot_argv(one, hr.argv)
        self.assertNotIn("--read-only", argv, "never hardening the runtime lacks")
        self.assertIn("--rm", argv)
        self.assertEqual(argv[argv.index("--network") + 1], "none")

    def test_only_the_named_secret_volume_is_dropped(self):
        one = pp.oneshot(EMAIL, "P03", "r1", pp.P03_SCRIPT, [KEY], "ex-secret")
        self.assertEqual(one["mounts"], EMAIL["mounts"][1:])
        self.assertEqual(pp.oneshot_diff(EMAIL, one, "ex-secret"), [])

    def test_a_tampered_oneshot_is_named(self):
        one = pp.oneshot(EMAIL, "P03", "r1", pp.P03_SCRIPT, [KEY], "ex-secret")
        one["cap_drop"] = []
        self.assertEqual(pp.oneshot_diff(EMAIL, one, "ex-secret"), ["cap_drop differs from the runtime's"])
        one = pp.oneshot(EMAIL, "P03", "r1", pp.P03_SCRIPT, [KEY], "ex-secret")
        one["mounts"] = one["mounts"][:1]
        self.assertIn("its mounts are not the runtime's", pp.oneshot_diff(EMAIL, one, "ex-secret"))


class ControlEngine:
    """The controls' engine: each planted one-shot answers as a broken
    partition would, unless told the probe stayed green. C05's exec reads the
    scratch config as a re-resolved bind would, unless `stale`."""

    def __init__(self, scratch):
        self.scratch, self.green, self.stale, self.seen = scratch, set(), False, []
        self.c05_before = None

    def __call__(self, argv):
        argv = list(argv)
        self.seen.append(argv)
        verb = argv[1]
        if verb in ("rm", "stop", "start") or (verb == "run" and "-d" in argv):
            return proc(0, "")
        if verb == "create":
            with open(self.scratch["config"], "rb") as f:
                self.c05_before = f.read()
            return proc(0, "")
        if verb == "exec":
            if "-u" in argv:
                return proc(0, "1 2102 2102\n" if "C01" not in self.green else "1 2101 2101\n")
            if self.stale:
                return proc(0, self.c05_before.decode())
            with open(self.scratch["config"]) as f:
                return proc(0, f.read())
        i = argv.index("-c")
        script = argv[i + 1]
        if script == pp.P02_SCRIPT:
            w = "EACCES" if "C02" in self.green else "OPENED"
            return proc(0, f"l1 g1 identity.json present 2101 0o640 {w}\n")
        if script == pp.P03_SCRIPT:
            return proc(0, "0 ENOENT\n" if "C03" in self.green else "0 exists\n")
        if script == pp.P04_SCRIPT:
            return proc(0, "0 ENOENT\n" if "C04" in self.green else "0 CREATED\n")
        raise AssertionError(argv)


class ControlsTest(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        root = t.name
        self.scratch = {"key_dir": os.path.join(root, "keys"), "key": os.path.join(root, "keys", "dummy"),
                        "peer": os.path.join(root, "peer"), "markers": os.path.join(root, "hop"),
                        "config": os.path.join(root, "c.json"), "config_next": os.path.join(root, "c.next")}
        with open(self.scratch["config"], "wb") as f:
            f.write(pp.C05_BEFORE)
        with open(self.scratch["config_next"], "wb") as f:
            f.write(pp.C05_AFTER)
        self.engine = ControlEngine(self.scratch)
        self.plan = pp.Plan(host="alpha", run_id="r1", at="2026-10-14T12:00:00Z", email=EMAIL, email_volume="ex-secret",
                            router=ROUTER, runtimes={"upstream": ("ex-up", 2101, 2101),
                                                     "downstream": ("ex-down", 2102, 2102)},
                            hops=[("upstream", "downstream")], sides={"up": (EMAIL, "/hop")},
                            owners={"up": (ROUTER, "/srv/hop", 2101)})

    def run_it(self):
        return {c["id"]: c for c in pp.run_controls(self.plan, self.scratch, pp.Runner(["docker"], self.engine),
                                                     hr.argv)}

    def test_every_control_turns_its_probe_red(self):
        got = self.run_it()
        self.assertEqual({k: (v["probe_verdict"], v["control"]) for k, v in got.items()},
                         {"C01": ("FAIL", "PASS"), "C02": ("FAIL", "PASS"), "C03": ("FAIL", "PASS"),
                          "C04": ("FAIL", "PASS"), "C05": ("PASS", "PASS")})

    def test_a_control_that_stays_green_fails_by_name(self):
        for cid in ("C01", "C02", "C03", "C04"):
            with self.subTest(cid=cid):
                self.engine.green = {cid}
                self.assertEqual(self.run_it()[cid]["control"], "FAIL")

    def test_c05_fails_when_a_restarted_container_reads_the_old_file(self):
        self.engine.stale = True
        c = self.run_it()["C05"]
        self.assertEqual((c["probe_verdict"], c["control"]), ("FAIL", "FAIL"))

    def test_no_control_touches_a_live_container(self):
        self.run_it()
        for argv in self.engine.seen:
            names = [a for a in argv if a.startswith(("ex-up", "ex-down"))]
            for n in names:
                self.assertIn(pp.CONTROL_LABEL, n, argv)

    def test_the_control_document_never_carries_a_token(self):
        doc = json.loads(pp.control_document(host="alpha", run_id="r1", at="2026-10-14T12:00:00Z",
                                             controls=list(self.run_it().values())))
        self.assertNotIn(pe.TOKEN_MEMBER, doc)
        self.assertEqual(doc["schema"], pp.CONTROL_SCHEMA)


def run_script(script, *args):
    p = subprocess.run([sys.executable, "-I", "-S", "-c", script, *args], capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, p.stderr
    return p.stdout


class ScriptsTest(unittest.TestCase):
    """The shipped scripts, executed."""

    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.t = t.name

    def test_p03_only_lstats_and_classifies(self):
        open(os.path.join(self.t, "k"), "w").close()
        out = run_script(pp.P03_SCRIPT, os.path.join(self.t, "k"), os.path.join(self.t, "none"))
        self.assertEqual(out, "0 exists\n1 ENOENT\n")
        self.assertNotIn("open(", pp.P03_SCRIPT, "nothing is opened, let alone read")

    def test_p04_creates_its_probe_name_in_a_writable_lane_and_removes_it(self):
        lane = os.path.join(self.t, "peer")
        os.mkdir(lane)
        out = run_script(pp.P04_SCRIPT, pp.probe_file("r1"), lane, os.path.join(self.t, "none"))
        self.assertEqual(out, "0 CREATED\n1 ENOENT\n")
        self.assertEqual(os.listdir(lane), [], "the probe name never stays")

    def test_p04_in_a_read_only_lane_is_refused(self):
        lane = os.path.join(self.t, "peer")
        os.mkdir(lane)
        os.chmod(lane, 0o500)
        self.addCleanup(os.chmod, lane, 0o700)
        if os.geteuid() == 0:
            self.skipTest("root bypasses the mode")
        self.assertEqual(run_script(pp.P04_SCRIPT, pp.probe_file("r1"), lane), "0 EACCES\n")

    def test_p02_reports_each_marker_and_the_create_attempt(self):
        side = os.path.join(self.t, "l1", "g1", "up")
        os.makedirs(side)
        m = os.path.join(side, "identity.json")
        open(m, "w").close()
        os.chmod(m, 0o640)
        out = run_script(pp.P02_SCRIPT, self.t, "up", pp.probe_file("r1"), "identity.json", "frontier.json")
        rows = [l.split() for l in out.splitlines()]
        self.assertEqual(rows[0][:4], ["l1", "g1", "identity.json", "present"])
        self.assertEqual(rows[0][5], "0o640")
        self.assertEqual(rows[1][:4], ["l1", "g1", "frontier.json", "ENOENT"])
        self.assertEqual(rows[2][:4], ["l1", "g1", ".", "create"])
        self.assertNotIn(pp.probe_file("r1"), os.listdir(side), "the probe name never stays")

    def test_the_write_witness_never_truncates_appends_or_writes(self):
        f = os.path.join(self.t, "m")
        with open(f, "w") as fh:
            fh.write("keep")
        self.assertEqual(run_script(pp.OPEN_WITNESS_SCRIPT, "w", f), "0 OPENED\n")
        with open(f) as fh:
            self.assertEqual(fh.read(), "keep")
        for script in (pp.OPEN_WITNESS_SCRIPT, pp.P02_SCRIPT):
            for word in ("O_TRUNC", "O_APPEND", ".write(", "os.write"):
                self.assertNotIn(word, script)

    def test_p01_prints_each_process_uid(self):
        out = run_script(pp.P01_SCRIPT)
        rows = pp.parse_proc(out)
        if isinstance(rows, rh.Unresolved):
            self.skipTest(f"this host's /proc: {rows.reason}")
        self.assertIn(os.getuid(), {r for _, r, _ in rows})


if __name__ == "__main__":
    unittest.main()
