"""partition_probe: the four probes, each with both halves and its witness.

The engine is faked at the one place the module reaches it (Runner), and the
fake answers each one-shot by the script and the arguments in its argv, so a
probe that sent the wrong script or the wrong paths gets the wrong answer.
The host side is a real temporary tree, because the path model stats it.
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


def after(argv, flag):
    """The value after `flag` in `argv`, or None: an absent flag is a
    failed assertion, never an error."""
    return argv[argv.index(flag) + 1] if flag in argv else None


def reported(report, pid):
    """A probe's verdict as the report line names it, whether or not a
    document could be built."""
    return next((l.split(":")[1].strip() for l in report if l.startswith(pid + ":")), None)


def rebased(spec, root):
    """`spec` with each bind's host source moved under `root`, so the path
    model can stat it; an identity bind stays an identity bind."""
    s = json.loads(json.dumps(spec))
    for m in s["mounts"]:
        if m["type"] == "bind":
            same = m["target"] == m["source"]
            m["source"] = root + m["source"]
            if same:
                m["target"] = m["source"]
    return s


def owner_rows(side_rows):
    return {"up": {"dir": "2101 0o750 ok", "identity.json": "present 2101 0o640 REG",
                   "versions.json": "present 2101 0o640 REG", "frontier.json": "ENOENT - - -",
                   "retired.json": "ENOENT - - -"},
            "down": {"dir": "2102 0o750 ok", "versions.json": "present 2102 0o640 REG"}}


class Engine:
    """Answers `docker exec` (P01) and `docker run` one-shots by script and
    operand. `owner[side]` is the owner's view of l1/g1 by name ("dir" for
    the side directory, "gens" for the link's generations); `markers[side]`
    the non-owner's answers by name, "." for its create attempt; `p04_at`
    the email router's answer per P04 operand; `access_at` the local
    router's per P04W operand."""

    def __init__(self):
        self.walks = {"ex-up": "1 2101 2101\n7 2101 2101\n", "ex-down": "1 2102 2102\n"}
        self.owner = owner_rows(None)
        self.gens = {"l1": ["g1"]}
        self.markers = {"up": {"identity.json": "present 2101 0o640 EACCES",
                               "versions.json": "present 2101 0o640 EACCES",
                               "frontier.json": "ENOENT - - -", "retired.json": "ENOENT - - -", ".": "EACCES"},
                        "down": {"versions.json": "present 2102 0o640 EROFS", ".": "EROFS"}}
        self.drop = set()
        self.p03 = "ENOENT"
        self.p04, self.p04_at = "ENOENT", {}
        self.access, self.access_at = "DIRW", {}
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
        if script == pp.P02_OWNER_SCRIPT:
            side, k = args[1], int(args[2])
            names, links = args[3:3 + k], args[3 + k:]
            out = []
            for lid in links:
                if not self.gens.get(lid):
                    out.append(f"{lid} - . enum - - {'EMPTY' if lid in self.gens else 'ENOENT'}")
                    continue
                for gen in self.gens[lid]:
                    d = self.owner[side]["dir"]
                    out.append(f"{lid} {gen} . dir {d}")
                    if not d.endswith(" ok"):
                        continue
                    out += [f"{lid} {gen} {n} {self.owner[side].get(n, 'ENOENT - - -')}" for n in names]
            return proc(0, "".join(l + "\n" for l in out))
        if script == pp.P02_SCRIPT:
            side, k = args[1], int(args[3])
            names, targets = args[4:4 + k], args[4 + k:]
            out = []
            for t in targets:
                lid, gen = t.split("/")
                out += [f"{lid} {gen} {n} {self.markers[side][n]}" for n in names if (side, n) not in self.drop]
                out.append(f"{lid} {gen} . create - - {self.markers[side]['.']}")
            return proc(0, "".join(l + "\n" for l in out))
        if script == pp.P03_SCRIPT:
            return proc(0, "".join(f"{n} {self.p03}\n" for n in range(len(args))))
        if script == pp.P04_SCRIPT:
            return proc(0, "".join(f"{n} {self.p04_at.get(p, self.p04)}\n" for n, p in enumerate(args[1:])))
        if script == pp.ACCESS_WITNESS_SCRIPT:
            return proc(0, "".join(f"{n} {self.access_at.get(p, self.access)}\n" for n, p in enumerate(args)))
        if script == pp.OPEN_WITNESS_SCRIPT:
            return proc(0, "".join(f"{n} {self.witness}\n" for n in range(len(args) - 1)))
        raise AssertionError(f"an unknown script: {script[:40]!r}")


class ProbeRunTest(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = os.path.realpath(t.name)
        for d in ("srv/hop", "opt/d7", "opt/ex/keys"):
            os.makedirs(os.path.join(self.root, d))
        open(self.root + KEY, "w").close()
        self.lanes = {}
        for slug in ("alpha", "beta"):
            d = os.path.join(self.root, "instances", slug, "peer")
            os.makedirs(d)
            self.lanes[slug] = d
        self.sources = dict(self.lanes)
        self.engine = Engine()
        self.drift = []
        self.email = rebased(EMAIL, self.root)
        self.router = rebased(ROUTER, self.root)
        inst = os.path.join(self.root, "instances")
        self.router["mounts"].append({"type": "bind", "source": inst, "target": inst, "readonly": False})
        self.stat, self.lstat = os.stat, os.lstat

    def plan(self):
        return pp.Plan(host="alpha", run_id="r1", at="2026-10-14T12:00:00Z", email=self.email,
                       email_drift=self.drift, email_volume="ex-secret", router=self.router,
                       key_path=self.root + KEY, key_dir=self.root + "/opt/ex/keys", lanes=self.lanes,
                       agent_sources=self.sources, links=["l1"], hop_root=self.root + "/srv/hop",
                       runtimes={"upstream": ("ex-up", 2101, 2101), "downstream": ("ex-down", 2102, 2102)},
                       vantages={"upstream": pp.spec_vantage(ROUTER), "downstream": pp.spec_vantage(EMAIL)},
                       hops=[("upstream", "downstream")],
                       sides={"up": (self.email, "/hop"), "down": (self.router, self.root + "/srv/hop")},
                       owners={"up": (self.router, self.root + "/srv/hop", 2101), "down": (self.email, "/hop", 2102)},
                       bindings={"host_setup": "c" * 64})

    def run_it(self, plan=None):
        try:
            return pp.run(plan or self.plan(), pp.Runner(["docker"], self.engine), hr.argv, stat_=self.stat,
                          lstat_=self.lstat)
        except Exception as e:  # a crash is not a verdict
            self.fail(f"the run raised {e!r}")

    def verdicts(self, doc):
        return {p["id"]: p["verdict"] for p in json.loads(doc)["probes"]}

    def p04_args(self):
        p04 = [a for a in self.engine.seen if pp.P04_SCRIPT in a][0]
        return p04[p04.index("-c") + 3:]

    def test_a_healthy_host_passes_every_probe_and_gets_a_token(self):
        doc, code, report = self.run_it()
        self.assertEqual(code, 0, report)
        probes = {p["id"]: p for p in json.loads(doc)["probes"]}
        self.assertEqual(probes["P03"]["target_role"], ["key:signing", "key:dir"])
        self.assertEqual(probes["P04"]["target_role"], ["peer:alpha", "peer:beta"])
        self.assertEqual((probes["P03"]["outcome"], probes["P03"]["witness"]["outcome"]), ("ENOENT", "ok"))
        self.assertEqual(probes["P04"]["witness"]["outcome"], "ok")
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

    # The one-shot's argv
    def test_every_probe_one_shot_replaces_the_image_program_and_carries_only_its_operands(self):
        self.run_it()
        runs = [a for a in self.engine.seen if a[1] == "run"]
        self.assertTrue(runs)
        for a in runs:
            with self.subTest(name=a[a.index("--name") + 1]):
                self.assertEqual(after(a, "--entrypoint"), "python3")
                self.assertEqual(after(a, "--pull"), "never")
                self.assertEqual(after(a, "--network"), "none")
                image = next(x for x in a if x.startswith("sha256:"))
                tail = a[a.index(image) + 1:]
                self.assertEqual(tail[:3], ["-I", "-S", "-c"], "nothing of the image's own command")
        p03 = [a for a in self.engine.seen if pp.P03_SCRIPT in a][0]
        self.assertEqual(p03[p03.index("-c") + 2:], [self.root + KEY, self.root + "/opt/ex/keys"])

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

    def test_a_router_witness_that_could_not_run_makes_p03_unknown(self):
        self.engine.fail.add("ex-up-partition-probe-p03w-r1")
        doc, code, _ = self.run_it()
        self.assertEqual((self.verdicts(doc)["P03"], code), ("UNKNOWN", 2))
        self.assertIsNone(json.loads(doc)[pe.TOKEN_MEMBER])

    def test_p03_probes_the_key_and_its_directory_through_every_mount(self):
        self.email["mounts"].append({"type": "bind", "source": self.root + "/opt/ex", "target": "/mnt/ex",
                                     "readonly": True})
        doc, _, _ = self.run_it()
        roles = next(p for p in json.loads(doc)["probes"] if p["id"] == "P03")["target_role"]
        self.assertEqual(roles, ["key:signing", "key:dir", "mount:1", "mount:3"])
        p03 = [a for a in self.engine.seen if pp.P03_SCRIPT in a][0]
        self.assertEqual(sorted(p03[p03.index("-c") + 2:]), sorted(
            [self.root + KEY, self.root + "/opt/ex/keys", "/mnt/ex/keys/signing.key", "/mnt/ex/keys"]))

    def test_a_key_reached_through_a_symlinked_source_is_still_a_candidate(self):
        os.symlink(self.root + "/opt/ex", self.root + "/ex-alias")
        self.email["mounts"].append({"type": "bind", "source": self.root + "/ex-alias", "target": "/mnt/ex",
                                     "readonly": True})
        self.run_it()
        p03 = [a for a in self.engine.seen if pp.P03_SCRIPT in a][0]
        self.assertIn("/mnt/ex/keys/signing.key", p03)

    # Host facts outside the evidence vocabulary
    def test_a_mount_path_no_role_could_spell_still_produces_evidence(self):
        for where in ("/Library/Application Support/ex", "/run/user@1000", "/" + "d" * 140):
            with self.subTest(where=where):
                self.email = rebased(EMAIL, self.root)
                self.email["mounts"].append({"type": "bind", "source": self.root + "/opt/ex", "target": where,
                                             "readonly": True})
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
        doc, code, report = self.run_it(plan)
        self.assertEqual((doc, code), (None, 2))
        self.assertIn("cannot be built", report[-1])
        self.assertTrue(report[0].startswith("P01: PASS"), "the probes' own lines are kept")

    # P04
    def test_a_created_file_in_a_lane_fails_p04(self):
        for cls in ("CREATED", "LEFT"):
            with self.subTest(cls=cls):
                self.engine.p04 = cls
                doc, code, report = self.run_it()
                self.assertEqual((self.verdicts(doc)["P04"], code), ("FAIL", 1))
                self.assertIn("created a file in a peer lane", report[3])

    def test_a_visible_lane_fails_p04_even_unwritten(self):
        self.engine.p04 = "EACCES"
        self.assertEqual(self.verdicts(self.run_it()[0])["P04"], "FAIL")

    def test_a_lane_reached_through_an_alias_is_still_probed_where_the_email_router_sees_it(self):
        """real/peer is the live lane, lane-alias points to it,
        and the email router binds `real` at /visible. /visible/peer must be
        a candidate, so the EACCES there FAILs P04."""
        real = os.path.join(self.root, "real", "peer")
        os.makedirs(real)
        alias = os.path.join(self.root, "lane-alias")
        os.symlink(real, alias)
        self.lanes, self.sources = {"alpha": alias}, {"alpha": real}
        self.email["mounts"].append({"type": "bind", "source": os.path.join(self.root, "real"), "target": "/visible",
                                     "readonly": True})
        self.router["mounts"].append({"type": "bind", "source": os.path.join(self.root, "real"),
                                      "target": os.path.join(self.root, "real"), "readonly": False})
        self.engine.p04_at = {"/visible/peer": "EACCES"}
        doc, code, report = self.run_it()
        self.assertIn("/visible/peer", self.p04_args())
        self.assertEqual((self.verdicts(doc)["P04"], code), ("FAIL", 1), report)

    def test_a_directory_at_a_second_host_path_is_related_by_identity(self):
        """A bind source that is the instances tree under another spelling
        (here a symbolic link to it) is caught as holding the lanes."""
        os.symlink(os.path.join(self.root, "instances"), os.path.join(self.root, "inst-alias"))
        self.email["mounts"].append({"type": "bind", "source": os.path.join(self.root, "inst-alias"), "target": "/x",
                                     "readonly": True})
        doc, _, report = self.run_it()
        self.assertEqual(self.verdicts(doc)["P04"], "FAIL")
        self.assertIn("mounts a lane", report[3])

    def test_an_ancestor_that_cannot_be_stat_ed_is_unknown_never_pass(self):
        blocked = os.path.join(self.root, "instances")

        def stat_(p):
            if p == blocked:
                raise PermissionError(13, "denied", p)
            return os.stat(p)
        self.stat = stat_
        doc, code, _ = self.run_it()
        self.assertEqual((self.verdicts(doc)["P04"], code), ("UNKNOWN", 2))

    def test_a_lane_the_local_router_cannot_be_shown_to_reach_is_unknown(self):
        """The permitted side's read-only witness, per lane."""
        for case in ("no answer", "an errno", "no mount"):
            with self.subTest(case=case):
                self.engine = Engine()
                self.router = rebased(ROUTER, self.root)
                inst = os.path.join(self.root, "instances")
                if case != "no mount":
                    self.router["mounts"].append({"type": "bind", "source": inst, "target": inst, "readonly": False})
                if case == "no answer":
                    self.engine.fail.add("ex-up-partition-probe-p04w-r1")
                if case == "an errno":
                    self.engine.access_at = {self.lanes["beta"]: "EACCES"}
                doc, code, report = self.run_it()
                self.assertEqual((reported(report, "P04"), code), ("UNKNOWN", 2), report)
                self.assertIsNotNone(doc, report)

    def test_the_local_routers_witness_only_looks(self):
        self.run_it()
        w = [a for a in self.engine.seen if pp.ACCESS_WITNESS_SCRIPT in a][0]
        self.assertEqual(w[w.index("--name") + 1], "ex-up-partition-probe-p04w-r1")
        self.assertEqual(sorted(w[w.index("-c") + 2:]), sorted(self.lanes.values()))
        for word in ("os.open", "O_CREAT", "listdir", "unlink", "mkdir"):
            self.assertNotIn(word, pp.ACCESS_WITNESS_SCRIPT)

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

    # The non-effect, host-side
    def test_a_probe_name_left_in_a_lane_or_a_marker_directory_fails_on_the_host(self):
        for where, pid in ((lambda: self.lanes["beta"], "P04"),
                           (lambda: os.path.join(self.root, "srv", "hop", "l1", "g1", "up"), "P02")):
            with self.subTest(pid=pid):
                d = where()
                os.makedirs(d, exist_ok=True)
                left = os.path.join(d, pp.probe_file("r1"))
                open(left, "w").close()
                doc, code, report = self.run_it()
                os.unlink(left)
                self.assertEqual((self.verdicts(doc)[pid], code), ("FAIL", 1))
                self.assertIn(left, "\n".join(report))

    def test_a_non_effect_check_that_cannot_be_made_is_unknown(self):
        def lstat_(p):
            if p.endswith(pp.probe_file("r1")):
                raise PermissionError(13, "denied", p)
            return os.lstat(p)
        self.lstat = lstat_
        doc, code, _ = self.run_it()
        v = self.verdicts(doc)
        self.assertEqual((v["P02"], v["P04"], code), ("UNKNOWN", "UNKNOWN", 2))

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
        self.engine.markers["up"]["identity.json"] = "present 2101 0o640 OPENED"
        self.assertEqual(self.verdicts(self.run_it()[0])["P02"], "FAIL")

    def test_a_non_owner_creating_beside_the_markers_fails_p02(self):
        for cls in ("CREATED", "LEFT"):
            with self.subTest(cls=cls):
                self.engine.markers["down"]["."] = cls
                self.assertEqual(self.verdicts(self.run_it()[0])["P02"], "FAIL")

    def test_a_wrong_owner_mode_or_type_fails_p02(self):
        for row in ("present 2101 0o664 REG", "present 2102 0o640 REG", "present 2101 0o640 NOTREG"):
            with self.subTest(row=row):
                self.engine.owner["up"]["versions.json"] = row
                self.assertEqual(self.verdicts(self.run_it()[0])["P02"], "FAIL")

    def test_a_missing_required_marker_or_side_fails_and_a_missing_optional_one_passes(self):
        self.assertEqual(self.verdicts(self.run_it()[0])["P02"], "PASS", "frontier and retired absent")
        self.engine.owner["up"]["identity.json"] = "ENOENT - - -"
        self.engine.markers["up"]["identity.json"] = "ENOENT - - -"
        self.assertEqual(self.verdicts(self.run_it()[0])["P02"], "FAIL")
        self.engine = Engine()
        self.engine.owner["down"]["dir"] = "- - ENOENT"
        self.assertEqual(self.verdicts(self.run_it()[0])["P02"], "FAIL")

    def test_an_incomplete_or_empty_observation_is_unknown(self):
        """A configured link with no generation, a link the owner cannot
        list, a row missing from the non-owner's answer, and a marker the
        owner sees but the non-owner's path does not reach."""
        cases = {"no generation": lambda e: e.gens.update(l1=[]),
                 "a link the owner cannot list": lambda e: e.gens.pop("l1"),
                 "a missing answer": lambda e: e.drop.add(("up", "identity.json")),
                 "an unreached marker": lambda e: e.markers["up"].update({"identity.json": "ENOENT - - -"})}
        for name, breaks in cases.items():
            with self.subTest(name=name):
                self.engine = Engine()
                breaks(self.engine)
                doc, code, report = self.run_it()
                self.assertEqual((self.verdicts(doc)["P02"], code), ("UNKNOWN", 2), report)

    def test_an_owner_that_cannot_open_its_marker_makes_p02_unknown(self):
        self.engine.witness = "EACCES"
        doc, _, _ = self.run_it()
        self.assertEqual(self.verdicts(doc)["P02"], "UNKNOWN")

    def test_the_non_owner_is_given_exactly_the_owners_targets(self):
        self.engine.gens = {"l1": ["g1", "g2"]}
        self.run_it()
        p02 = [a for a in self.engine.seen if pp.P02_SCRIPT in a]
        self.assertEqual({tuple(a[-2:]) for a in p02}, {("l1/g1", "l1/g2")})

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
        got = self.judged(pp.verdict_p04, [(0, "ENOENT")], rh.Unresolved("beta is not running"), [], [])
        self.assertEqual(got[:2], ("UNKNOWN", "unresolved"))

    def test_an_unprovable_mount_relation_is_unknown(self):
        got = self.judged(pp.verdict_p04, [(0, "ENOENT")], [], rh.Unresolved("cannot stat /x"), [])
        self.assertEqual(got[:2], ("UNKNOWN", "unresolved"))

    def test_a_fail_stands_whatever_the_permitted_witness_says(self):
        got = self.judged(pp.verdict_p04, [(0, "EACCES")], [], [], rh.Unresolved("no witness"))
        self.assertEqual(got[0], "FAIL")

    def test_a_router_witness_that_did_not_open_the_key_is_unknown(self):
        got = self.judged(pp.verdict_p03, [(0, "ENOENT")], [(0, "ENOENT")])
        self.assertEqual(got[:2], ("UNKNOWN", "ENOENT"))

    def test_an_unresolved_router_witness_is_unknown(self):
        got = self.judged(pp.verdict_p03, [(0, "ENOENT")], rh.Unresolved("the one-shot did not start"))
        self.assertEqual(got[:2], ("UNKNOWN", "ENOENT"))

    def test_a_non_effect_check_holds_a_verdict(self):
        self.assertEqual(pp.with_non_effect(("PASS", "ENOENT", "x"), ["/l/.p"])[0], "FAIL")
        self.assertEqual(pp.with_non_effect(("PASS", "ENOENT", "x"), rh.Unresolved("EACCES"))[0], "UNKNOWN")
        self.assertEqual(pp.with_non_effect(("FAIL", "ok", "x"), rh.Unresolved("EACCES"))[0], "FAIL")


class P02TargetsTest(unittest.TestCase):
    """The owner's enumeration and the non-owner's answers, judged directly:
    the shapes a whole run reaches only through an earlier refusal."""
    OK = [("l1", "g1", ".", "dir", "2101", "0o750", "ok"),
          ("l1", "g1", "identity.json", "present", "2101", "0o640", "REG"),
          ("l1", "g1", "versions.json", "present", "2101", "0o640", "REG"),
          ("l1", "g1", "frontier.json", "ENOENT", "-", "-", "-"),
          ("l1", "g1", "retired.json", "ENOENT", "-", "-", "-")]

    def targets(self, rows, links=("l1",)):
        return pp.p02_targets(list(rows), "up", list(links), 2101)

    def test_a_complete_enumeration_gives_its_targets(self):
        self.assertEqual(self.targets(self.OK)[:2], ("targets", [("l1", "g1")]))

    def test_one_unlistable_link_among_good_ones_is_unknown(self):
        got = self.targets(self.OK + [("l2", "-", ".", "enum", "-", "-", "ENOENT")], ("l1", "l2"))
        self.assertEqual(got[0], "UNKNOWN")
        self.assertIn("l2", got[2])

    def test_a_configured_link_the_owner_never_mentions_is_unknown(self):
        got = self.targets(self.OK, ("l1", "l2"))
        self.assertEqual(got[0], "UNKNOWN")
        self.assertIn("l2", got[2])

    def test_no_configured_link_at_all_is_unknown(self):
        self.assertEqual(self.targets([], ())[0], "UNKNOWN")

    def answers(self, extra=()):
        rows = [("l1", "g1", n, "present", "2101", "0o640", "EACCES") for n in ("identity.json", "versions.json")]
        rows += [("l1", "g1", n, "ENOENT", "-", "-", "-") for n in ("frontier.json", "retired.json")]
        rows += [("l1", "g1", ".", "create", "-", "-", "EACCES")] + list(extra)
        return pp.verdict_p02({"up": self.targets(self.OK)}, {"up": rows}, {"up": [(0, "OPENED"), (1, "OPENED")]})

    def test_complete_answers_pass(self):
        self.assertEqual(self.answers()[0], "PASS")

    def test_a_repeated_answer_is_unknown_even_when_the_set_is_complete(self):
        got = self.answers([("l1", "g1", "identity.json", "present", "2101", "0o640", "OPENED")])
        self.assertEqual(got[0], "UNKNOWN")
        self.assertIn("answered twice", got[2])


class PathModelTest(unittest.TestCase):
    """candidates() by identity, on a real tree, with stat answering as a
    host bind mount would where the test needs one."""

    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = os.path.realpath(t.name)
        self.lane = os.path.join(self.root, "instances", "alpha", "peer")
        os.makedirs(self.lane)

    def test_a_source_held_by_the_target_gives_the_bind_destination(self):
        sub = os.path.join(self.lane, "sub")
        os.mkdir(sub)
        got = pp.candidates([{"type": "bind", "source": sub, "target": "/y", "readonly": True}], [self.lane])
        self.assertIn("/y", got)

    def test_the_same_directory_at_a_second_host_path_is_related_by_identity(self):
        """`other` is a distinct path that the host shows as the instances
        directory (a host bind mount): only (device, inode) can see it."""
        other = os.path.join(self.root, "other")
        os.mkdir(other)
        inst = os.path.join(self.root, "instances")

        def stat_(p):
            return os.stat(inst if p == other else p)
        got = pp.candidates([{"type": "bind", "source": other, "target": "/v", "readonly": True}], [self.lane],
                            stat_=stat_)
        self.assertIn("/v/alpha/peer", got)
        self.assertEqual(pp.mounts_holding([{"type": "bind", "source": other, "target": "/v", "readonly": True}],
                                           {"alpha": self.lane}, stat_=stat_), [f"{other} and alpha's lane {self.lane}"])


class OneshotTest(unittest.TestCase):
    def test_a_oneshot_keeps_every_privilege_of_its_runtime(self):
        one = pp.oneshot(ROUTER, "P03W", "r1", pp.OPEN_WITNESS_SCRIPT, ["r", KEY])
        for k in ("user", "group_add", "read_only", "security_opt", "cap_drop", "cap_add", "image", "env_file"):
            self.assertEqual(one[k], ROUTER[k], k)
        argv = pp.oneshot_argv(one, hr.argv)
        self.assertNotIn("--read-only", argv, "never hardening the runtime lacks")
        self.assertIn("--rm", argv)
        self.assertEqual(argv[argv.index("--network") + 1], "none")

    def test_the_command_after_the_image_is_exactly_the_script_and_its_operands(self):
        one = pp.oneshot(EMAIL, "P03", "r1", pp.P03_SCRIPT, [KEY, "/opt/ex/keys"], "ex-secret")
        argv = pp.oneshot_argv(one, hr.argv)
        self.assertEqual(after(argv, "--entrypoint"), "python3")
        self.assertEqual(argv[argv.index(EMAIL["image"]) + 1:], ["-I", "-S", "-c", pp.P03_SCRIPT, KEY, "/opt/ex/keys"])
        self.assertEqual(after(argv, "--pull"), "never")

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
    scratch config as a re-resolved bind would, unless `stale`. `c04` is the
    scratch lane's create-and-delete answer."""

    def __init__(self, scratch):
        self.scratch, self.green, self.stale, self.seen = scratch, set(), False, []
        self.c05_before = None
        self.c04 = "CREATED"

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
        if script == pp.P02_OWNER_SCRIPT:
            mode = "0o640" if "C02" in self.green else "0o660"
            return proc(0, "l1 g1 . dir 2101 0o750 ok\n"
                           "l1 g1 frontier.json ENOENT - - -\n"
                           f"l1 g1 identity.json present 2101 {mode} REG\n"
                           "l1 g1 retired.json ENOENT - - -\n"
                           "l1 g1 versions.json present 2101 0o640 REG\n")
        if script == pp.P02_SCRIPT:
            w = "EACCES" if "C02" in self.green else "OPENED"
            return proc(0, "l1 g1 frontier.json ENOENT - - -\n"
                           f"l1 g1 identity.json present 2101 0o640 {w}\n"
                           "l1 g1 retired.json ENOENT - - -\n"
                           "l1 g1 versions.json present 2101 0o640 EACCES\n"
                           "l1 g1 . create - - EACCES\n")
        if script == pp.OPEN_WITNESS_SCRIPT:
            return proc(0, "".join(f"{n} OPENED\n" for n in range(len(argv) - i - 3)))
        if script == pp.P03_SCRIPT:
            return proc(0, "0 ENOENT\n" if "C03" in self.green else "0 exists\n")
        if script == pp.P04_SCRIPT:
            return proc(0, "0 ENOENT\n" if "C04" in self.green else f"0 {self.c04}\n")
        raise AssertionError(argv)


class ControlsTest(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        root = t.name
        self.scratch = {"key_dir": os.path.join(root, "keys"), "key": os.path.join(root, "keys", "dummy"),
                        "peer": os.path.join(root, "peer"), "markers": os.path.join(root, "hop"),
                        "config": os.path.join(root, "c.json"), "config_next": os.path.join(root, "c.next")}
        os.makedirs(self.scratch["peer"])
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

    def test_c04_passes_only_on_a_created_and_removed_probe_name(self):
        """Any other red P04 answer is not the witness."""
        for answer in ("EACCES", "LEFT"):
            with self.subTest(answer=answer):
                self.engine.c04 = answer
                self.assertEqual(self.run_it()["C04"]["control"], "FAIL")
        self.engine.c04 = "CREATED"
        left = os.path.join(self.scratch["peer"], pp.probe_file("r1"))
        open(left, "w").close()
        c = self.run_it()["C04"]
        self.assertEqual(c["control"], "FAIL")
        self.assertIn("left the probe name", c["outcome"])

    def test_c05_fails_when_a_restarted_container_reads_the_old_file(self):
        self.engine.stale = True
        c = self.run_it()["C05"]
        self.assertEqual((c["probe_verdict"], c["control"]), ("FAIL", "FAIL"))

    def test_the_throwaways_are_hardened(self):
        self.run_it()
        for argv in self.engine.seen:
            if argv[1] in ("create",) or (argv[1] == "run" and "-d" in argv):
                with self.subTest(verb=argv[1]):
                    for flag, value in (("--pull", "never"), ("--cap-drop", "ALL"),
                                        ("--security-opt", "no-new-privileges")):
                        self.assertEqual(after(argv, flag), value)
                    self.assertIn("--read-only", argv)

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


def run_script(script, *args, prelude=""):
    code = script if not prelude else prelude + "\nexec(compile(SCRIPT, '<probe>', 'exec'))"
    env_args = [] if not prelude else ["-c", f"SCRIPT = {script!r}\n" + code]
    argv = [sys.executable, "-I", "-S"] + (env_args or ["-c", script]) + list(args)
    p = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, p.stderr
    return p.stdout


#: Makes every os.unlink fail, as a lane whose removal is refused would.
NO_UNLINK = "import os\ndef _no(p, *a, **k): raise PermissionError(13, 'refused', p)\nos.unlink = _no"


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

    def test_a_create_whose_removal_fails_is_left_never_refused(self):
        """Create and unlink are separate steps, in P04 and P02."""
        lane = os.path.join(self.t, "peer")
        os.mkdir(lane)
        self.assertEqual(run_script(pp.P04_SCRIPT, pp.probe_file("r1"), lane, prelude=NO_UNLINK), "0 LEFT\n")
        side = os.path.join(self.t, "hop", "l1", "g1", "down")
        os.makedirs(side)
        out = run_script(pp.P02_SCRIPT, os.path.join(self.t, "hop"), "down", pp.probe_file("r2"), "0", "l1/g1",
                         prelude=NO_UNLINK)
        self.assertEqual(out, "l1 g1 . create - - LEFT\n")

    def test_p04_in_a_read_only_lane_is_refused(self):
        lane = os.path.join(self.t, "peer")
        os.mkdir(lane)
        os.chmod(lane, 0o500)
        self.addCleanup(os.chmod, lane, 0o700)
        if os.geteuid() == 0:
            self.skipTest("root bypasses the mode")
        self.assertEqual(run_script(pp.P04_SCRIPT, pp.probe_file("r1"), lane), "0 EACCES\n")

    def test_p02_answers_every_target_and_marker_and_the_create_attempt(self):
        side = os.path.join(self.t, "l1", "g1", "up")
        os.makedirs(side)
        m = os.path.join(side, "identity.json")
        open(m, "w").close()
        os.chmod(m, 0o640)
        out = run_script(pp.P02_SCRIPT, self.t, "up", pp.probe_file("r1"), "2", "identity.json", "frontier.json",
                         "l1/g1", "l1/g9")
        rows = [l.split() for l in out.splitlines()]
        self.assertEqual([r[:4] for r in rows], [["l1", "g1", "identity.json", "present"],
                                                 ["l1", "g1", "frontier.json", "ENOENT"],
                                                 ["l1", "g1", ".", "create"],
                                                 ["l1", "g9", "identity.json", "ENOENT"],
                                                 ["l1", "g9", "frontier.json", "ENOENT"],
                                                 ["l1", "g9", ".", "create"]])
        self.assertEqual(rows[0][5], "0o640")
        self.assertNotIn(pp.probe_file("r1"), os.listdir(side), "the probe name never stays")

    def test_the_owner_enumerates_generations_sides_and_markers(self):
        os.makedirs(os.path.join(self.t, "l1", "g1", "up"))
        os.makedirs(os.path.join(self.t, "l1", "g2"))
        os.makedirs(os.path.join(self.t, "l2"))
        m = os.path.join(self.t, "l1", "g1", "up", "versions.json")
        open(m, "w").close()
        os.chmod(m, 0o640)
        out = run_script(pp.P02_OWNER_SCRIPT, self.t, "up", "1", "versions.json", "l1", "l2", "l3")
        rows = [l.split() for l in out.splitlines()]
        self.assertEqual([(r[0], r[1], r[2], r[3], r[6]) for r in rows],
                         [("l1", "g1", ".", "dir", "ok"), ("l1", "g1", "versions.json", "present", "REG"),
                          ("l1", "g2", ".", "dir", "ENOENT"), ("l2", "-", ".", "enum", "EMPTY"),
                          ("l3", "-", ".", "enum", "ENOENT")])
        for word in ("os.open", "O_CREAT", "unlink"):
            self.assertNotIn(word, pp.P02_OWNER_SCRIPT)

    def test_the_access_witness_reports_a_searchable_writable_directory(self):
        d = os.path.join(self.t, "peer")
        os.mkdir(d)
        f = os.path.join(self.t, "file")
        open(f, "w").close()
        out = run_script(pp.ACCESS_WITNESS_SCRIPT, d, f, os.path.join(self.t, "none"))
        self.assertEqual(out, "0 DIRW\n1 NOTDIR\n2 ENOENT\n")
        self.assertEqual(os.listdir(d), [], "nothing created")

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
