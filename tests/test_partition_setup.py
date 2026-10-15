"""partition_setup: the `partition` and `delegation_gate` sections, loaded from
the host-setup document test_hub_keys builds, and the gate judged against a
record built from harness_gate's healthy example."""

import hashlib
from dataclasses import replace as dataclasses_replace
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
EXEC = "/opt/ex/partition-exec"
TOOLS = {"python3": "/usr/bin/python3", "docker": "/usr/local/libexec/amap/docker"}
PART = {"evidence_dir": EV, "scratch_dir": SCRATCH, "exec_root": EXEC, "tools": dict(TOOLS),
        "weekly": {"weekday": 0, "hour": 3}}


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
        self.assertEqual((s.partition.exec_root, s.partition.tools), (EXEC, TOOLS))
        self.assertEqual(s.gate.record_path, f"{EV}/gate-record.json")

    def test_closed_member_sets(self):
        self.refuses(doc(partition=dict(PART, extra=1)), "exactly evidence_dir")
        self.refuses(doc(partition={k: v for k, v in PART.items() if k != "weekly"}), "exactly evidence_dir")
        self.refuses(doc(partition={k: v for k, v in PART.items() if k != "exec_root"}), "exactly evidence_dir")
        self.refuses(doc(partition=dict(PART, tools=dict(TOOLS, git="/usr/bin/git"))), "exactly docker, python3")
        self.refuses(doc(partition=dict(PART, tools={"python3": "/usr/bin/python3"})), "exactly docker, python3")
        self.refuses(doc(partition=dict(PART, tools=dict(TOOLS, docker="docker"))), "absolute")
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

    def test_the_exec_root_stays_apart_from_live_paths_and_the_scratch(self):
        self.refuses(doc(partition=dict(PART, exec_root=EV + "/x")), "overlaps")
        self.refuses(doc(partition=dict(PART, exec_root=SCRATCH)), "overlaps")
        self.refuses(doc(partition=dict(PART, exec_root=SCRATCH + "/run")), "overlaps")

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

    def host(self):
        """A host where every partition directory and tool is as the design
        wants it, as lstat shows it; realpath is the identity."""
        d = stat.S_IFDIR
        files = {p: st(d | 0o755) for p in ("/", "/opt", "/opt/ex", "/usr", "/usr/bin", "/usr/local",
                                              "/usr/local/libexec", "/usr/local/libexec/amap", EV)}
        files.update({SCRATCH: st(d | 0o700), EXEC: st(d | 0o700)})
        files.update({t: st(stat.S_IFREG | 0o755) for t in TOOLS.values()})
        return files

    def verify(self, files):
        def lstat(p):
            if p not in files:
                raise FileNotFoundError(p)
            return files[p]
        part = ps.PartitionSpec(evidence_dir=EV, scratch_dir=SCRATCH, weekday=0, hour=3, exec_root=EXEC, tools=TOOLS)
        return ps.verify(part, self.gs, delegation_enabled=True, lstat=lstat, owned_chain=ss._owned_chain,
                         rl_sha=self.RL, hop_sha=self.HOP, plugin_sha256=self.PLUGIN, read=lambda p: self.raw,
                         realpath=lambda p: p)

    def test_verify_reports_the_gate_and_the_directories(self):
        files = self.host()
        self.assertEqual([(c.claim, c.result) for c in self.verify(files) if c.result != rh.PASS], [])
        for path, words in ((SCRATCH, "scratch"), (EXEC, "weekly job's")):
            with self.subTest(path=path):
                files = self.host()
                files[path] = st(stat.S_IFDIR | 0o755)
                self.assertEqual([c.claim for c in self.verify(files) if c.result == rh.FAIL],
                                 [f"the partition {words} directory {path} is root:root 700"])

    def test_a_tool_the_operator_could_replace_fails(self):
        docker = TOOLS["docker"]
        for name, bad in (("operator-owned", st(stat.S_IFREG | 0o755, uid=501)),
                          ("group-writable", st(stat.S_IFREG | 0o775)),
                          ("not executable", st(stat.S_IFREG | 0o644))):
            with self.subTest(name=name):
                files = self.host()
                files[docker] = bad
                failed = [c.claim for c in self.verify(files) if c.result == rh.FAIL]
                self.assertEqual(len(failed), 1, failed)
                self.assertIn(docker, failed[0])
        files = self.host()
        files["/usr/local/libexec/amap"] = st(stat.S_IFDIR | 0o755, uid=501)
        self.assertTrue(any("/usr/local/libexec/amap/docker" in c.claim
                            for c in self.verify(files) if c.result == rh.FAIL))

    def test_a_tool_reached_through_a_link_in_a_writable_directory_fails(self):
        """The link's own directory is held too: whoever can write it can
        point the configured path at another tool."""
        files = self.host()
        files["/opt/brew"] = st(stat.S_IFDIR | 0o775, uid=501)
        files["/opt/brew/python3"] = st(stat.S_IFLNK | 0o777, uid=501)
        part = ps.PartitionSpec(evidence_dir=EV, scratch_dir=SCRATCH, weekday=0, hour=3, exec_root=EXEC,
                                tools=dict(TOOLS, python3="/opt/brew/python3"))

        def lstat(p):
            if p not in files:
                raise FileNotFoundError(p)
            return files[p]
        found = ps.verify(part, self.gs, delegation_enabled=True, lstat=lstat, owned_chain=ss._owned_chain,
                          rl_sha=self.RL, hop_sha=self.HOP, plugin_sha256=self.PLUGIN, read=lambda p: self.raw,
                          realpath=lambda p: "/usr/bin/python3" if p == "/opt/brew/python3" else p)
        self.assertTrue(any("/opt/brew/python3" in c.claim for c in found if c.result == rh.FAIL),
                        [(c.claim, c.result) for c in found if c.result != rh.PASS])

    def test_a_tool_that_cannot_be_inspected_is_unknown(self):
        files = self.host()
        del files[TOOLS["python3"]]
        self.assertEqual([c.result for c in self.verify(files) if TOOLS["python3"] in c.claim][0], rh.UNKNOWN)

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
        """Even to a file the descriptor checks would accept: the link is
        refused at the open."""
        import unittest.mock as um
        fake = os.stat_result((0o100444, 0, 0, 1, 0, 0, 2, 0, 0, 0))
        with tempfile.TemporaryDirectory() as t:
            real = os.path.join(t, "real.json")
            with open(real, "wb") as f:
                f.write(b"{}")
            link = os.path.join(t, "gate-record.json")
            os.symlink(real, link)
            with um.patch.object(ps.os, "fstat", lambda fd: fake):
                with self.assertRaises(OSError):
                    ps.read_record(link)



class PlanTest(unittest.TestCase):
    def setUp(self):
        for name, value in (("MUTANT_IDS_SHA256", hg.set_sha256(IDS)), ("MUTANT_COUNT", len(IDS)),
                            ("SCHEMA_SHA256", hashlib.sha256(SCHEMA.encode()).hexdigest()),
                            ("UNIT_SHA256", hashlib.sha256(UNIT.encode()).hexdigest())):
            self.addCleanup(setattr, hg, name, getattr(hg, name))
            setattr(hg, name, value)
        self.part = ps.PartitionSpec(evidence_dir=EV, scratch_dir=SCRATCH, weekday=0, hour=3, exec_root=EXEC,
                                     tools=TOOLS)

    def test_the_plan_prints_the_six_steps_with_this_hosts_paths(self):
        def gone(p):
            raise FileNotFoundError(p)
        text = "\n".join(ps.plan(self.part, None, lambda s: s, anchor="/opt/amap/etc/overlay.sha", read=gone))
        for words in (f"install -d -o 0 -g 0 -m 0755 {EV}", f"install -d -o 0 -g 0 -m 0700 {SCRATCH}",
                      f"install -d -o 0 -g 0 -m 0700 {EXEC}",
                      f"{EV}/gate-record.json", "COPIED from the record's own", "squash",
                      "/opt/amap/etc/overlay.sha", "no placed record"):
            self.assertIn(words, text)

    def test_a_placed_record_has_its_harness_sha_printed_with_no_url(self):
        raw = hg.canonical(healthy())
        text = "\n".join(ps.plan(self.part, None, lambda s: s, anchor=None, read=lambda p: raw))
        self.assertIn("the placed record's harness_sha is " + "4" * 40, text)
        self.assertIn("reachable from the harness PR's head ref in the harness repository", text)
        self.assertNotIn("://", text, "no URL: the harness repository is not named in public code")


class StopTargetTest(unittest.TestCase):
    """verify's stop-target check, judged from the writer's verify copy by
    its strict grammar. The records are real: A1's record by
    activation_record, the evidence by partition_evidence.build, the copy in
    the writer's canonical form, the live config carrying the evidence's
    token. A NOTE only when delegation and the gate are both affirmatively
    off."""

    CID, OTHER = "c" * 64, "d" * 64
    LIVE = "/opt/ex/router.json"
    ENGINE, DOCKER = "unix:///var/run/docker.sock", "/usr/local/libexec/amap/docker"
    AT, CREATED = "2026-10-15T06:00:05Z", "2026-10-15T06:00:05.900000000Z"
    SPEC = {"name": "ex-up", "image": "sha256:" + "b" * 64, "user": "2101:2101", "network": "none",
            "restart": "unless-stopped", "env": {"ROUTER_CONFIG": "/opt/ex/router.json"},
            "mounts": [{"type": "bind", "source": "/opt/ex/router.json", "target": "/opt/ex/router.json",
                        "readonly": True}]}

    def setUp(self):
        self.part = ps.PartitionSpec(evidence_dir=EV, scratch_dir=SCRATCH, weekday=0, hour=3, exec_root=EXEC,
                                     tools=dict(TOOLS))
        self.build()

    def evidence_doc(self, host="alpha", run_id="r1"):
        import partition_evidence as pe
        from test_partition_evidence import probe
        return pe.build(host=host, run_id=run_id, at="2026-10-15T05:00:00Z", script_sha256={"s": "0" * 64},
                        bindings={"b": "1" * 64}, probes=[probe(p) for p in pe.PROBE_IDS])

    def build(self, live=None, engine=None, docker=None, evidence_dir=EV, host="alpha"):
        import partition_activation as pa
        import partition_evidence as pe
        self.live = live or self.LIVE
        staged = (json.dumps({"state_dir": "/s", "delegation": {"signing_key": {"path": "/k/s"}}}, indent=2)
                  + "\n").encode()
        self.activation = pa.activation_record(host=host, spec=self.SPEC, staged=staged, final_config_path=self.live)
        self.evidence = self.evidence_doc(host=host)
        self.token = pe.token_of(json.loads(self.evidence))
        self.config = pa.final_bytes(staged, self.token)
        self.record = {"schema": ps.TARGET_SCHEMA, "host": host, "run_id": "w1", "at": self.AT,
                       "evidence_dir": evidence_dir, "live_config_path": self.live, "engine": engine or self.ENGINE,
                       "docker": docker or self.DOCKER, "router_container_id": self.CID,
                       "config_sha256": hashlib.sha256(self.config).hexdigest(), "evidence_run_id": "r1",
                       "evidence_sha256": hashlib.sha256(self.evidence).hexdigest(), "inspect_digest": "e" * 64,
                       "activation_sha256": hashlib.sha256(self.activation).hexdigest()}
        self.running = {self.CID: {"Id": self.CID, "Created": self.CREATED, "State": {"Running": True}},
                        "ex-up": {"Id": self.CID, "Created": self.CREATED, "State": {"Running": True}}}
        self.files = {f"{evidence_dir}/stop-target.json": None, f"{evidence_dir}/activation.json": self.activation,
                      f"{evidence_dir}/partition-r1.json": self.evidence}

    def read(self, path):
        import partition_evidence as pe
        data = self.files.get(path)
        if path.endswith("stop-target.json") and data is None:
            data = pe.canonical(self.record)
        if data is None or data is FileNotFoundError:
            raise FileNotFoundError(2, "No such file or directory", path)
        if isinstance(data, Exception):
            raise data
        return data

    def judge(self, gs=None, config=None):
        try:
            return ps.verify_target(self.part, gs, live_config=self.live, engine=self.ENGINE, docker=self.DOCKER,
                                    router_name="ex-up", inspect=lambda ref: self.running.get(ref), read=self.read,
                                    read_live=lambda p: self.config if config is None else config)
        except Exception as e:  # a crash is not a verdict
            self.fail(f"verify_target raised {e!r}")

    def result(self, **kw):
        out = self.judge(**kw)
        self.assertEqual(len(out), 1)
        return out[0]

    def judged(self, rows, want):
        for what, change in rows.items():
            with self.subTest(what):
                self.build()
                change()
                c = self.result()
                self.assertEqual(c.result, want, f"{what}: {c.actual}")
                if want == rh.FAIL:
                    self.assertIn("no stop target", str(c.actual))
                    self.assertIn("A5", c.remedy)

    def test_the_running_routers_own_real_record_passes(self):
        self.assertEqual(self.result().result, rh.PASS)

    def test_no_record_or_any_field_not_the_approved_ones_fails_with_the_remedy(self):
        self.judged({
            "absent": lambda: self.files.update({f"{EV}/stop-target.json": FileNotFoundError}),
            "a foreign owner, a link or a mode": lambda: self.files.update(
                {f"{EV}/stop-target.json": OSError("not a root:root 0444 regular file with one link")}),
            "another engine": lambda: self.record.update(engine="unix:///other.sock"),
            "another docker": lambda: self.record.update(docker="/usr/bin/docker"),
            "another live config": lambda: self.record.update(live_config_path="/elsewhere.json"),
            "another evidence directory": lambda: self.record.update(evidence_dir="/elsewhere"),
            "another activation": lambda: self.files.update({f"{EV}/activation.json": b"{}"}),
            "the evidence changed": lambda: self.files.update({f"{EV}/partition-r1.json": b"{}"}),
            "a member short": lambda: self.record.pop("inspect_digest"),
            "a member of the wrong type": lambda: self.record.update(at=5),
            "stale: the router was recreated": lambda: self.running.update(
                {"ex-up": {"Id": self.OTHER, "Created": self.CREATED, "State": {"Running": True}}}),
            "the recorded container is gone": lambda: self.running.update({self.CID: None}),
            "recorded a second before the router was created": lambda: self.record.update(
                at="2026-10-15T06:00:04Z")}, rh.FAIL)
        self.build()
        self.assertEqual(self.result(config=self.config + b" ").result, rh.FAIL, "the live config changed")

    def test_the_record_is_held_to_its_strict_grammar_and_its_host(self):
        import partition_evidence as pe

        def raw(data):
            return lambda: self.files.update({f"{EV}/stop-target.json": data})

        def foreign_evidence():
            """A separately valid document of another host, its own token in the
            live config, and every recorded digest matching it."""
            import partition_activation as pa
            other = self.evidence_doc(host="beta")
            self.files[f"{EV}/partition-r1.json"] = other
            staged = json.loads(self.activation)["staged"].encode()
            self.config = pa.final_bytes(staged, pe.token_of(json.loads(other)))
            self.record.update(evidence_sha256=hashlib.sha256(other).hexdigest(),
                               config_sha256=hashlib.sha256(self.config).hexdigest())
        def other_run():
            import partition_activation as pa
            other = self.evidence_doc(run_id="r2")
            self.files[f"{EV}/partition-r1.json"] = other
            staged = json.loads(self.activation)["staged"].encode()
            self.config = pa.final_bytes(staged, pe.token_of(json.loads(other)))
            self.record.update(evidence_sha256=hashlib.sha256(other).hexdigest(),
                               config_sha256=hashlib.sha256(self.config).hexdigest())

        def other_host_activation():
            import partition_activation as pa
            staged = json.loads(self.activation)["staged"].encode()
            beta = pa.activation_record(host="beta", spec=self.SPEC, staged=staged, final_config_path=self.live)
            self.files[f"{EV}/activation.json"] = beta
            self.record.update(activation_sha256=hashlib.sha256(beta).hexdigest())
        canonical = pe.canonical(self.record)
        self.judged({
            "a foreign host in the record": lambda: self.record.update(host="beta"),
            "a foreign host's evidence, consistent with itself": foreign_evidence,
            "a name for the id": lambda: (self.record.update(router_container_id="ex-up"),
                                          self.running.update({"ex-up": dict(self.running["ex-up"], Id="ex-up")})),
            "a short id": lambda: self.record.update(router_container_id="c" * 12),
            "an id in upper case": lambda: self.record.update(router_container_id="C" * 64),
            "a digest that is not hex": lambda: self.record.update(activation_sha256="z" * 64),
            "an evidence run that is a path": lambda: self.record.update(evidence_run_id="../r1"),
            "a time that is not a time": lambda: self.record.update(at="2026-13-45T99:00:00Z"),
            "duplicate members": raw(canonical[:-1] + b',"host":"alpha"}'),
            "not canonical": raw(json.dumps(self.record, indent=1).encode()),
            "a non-finite number": raw(canonical.replace(b'"at":"' + self.AT.encode() + b'"', b'"at":NaN')),
            "not JSON": raw(b"\xff{"),
            "the evidence is another run's, its token in the live config": other_run,
            "an activation of another host, all else consistent": other_host_activation,
            "the live config's token not the evidence's": lambda: (
                setattr(self, "config", self.config.replace(self.token.encode(), b"r1:" + b"0" * 64)),
                self.record.update(config_sha256=hashlib.sha256(self.config).hexdigest()))}, rh.FAIL)

    def test_both_answers_must_affirm_the_recorded_id_running_and_a_creation_time(self):
        running = {"Running": True}
        self.judged({
            "by id, another full id": lambda: self.running.update(
                {self.CID: {"Id": self.OTHER, "Created": self.CREATED, "State": running}}),
            "by name, not running": lambda: self.running.update(
                {"ex-up": {"Id": self.CID, "Created": self.CREATED, "State": {"Running": False}}}),
            "by id, not running": lambda: self.running.update(
                {self.CID: {"Id": self.CID, "Created": self.CREATED, "State": {"Running": False}}})}, rh.FAIL)
        self.judged({
            "by id, no id": lambda: self.running.update({self.CID: {"Created": self.CREATED, "State": running}}),
            "by id, not a container": lambda: self.running.update({self.CID: "x"}),
            "by name, a state that is not one": lambda: self.running.update(
                {"ex-up": {"Id": self.CID, "Created": self.CREATED, "State": "running"}}),
            "by name, a list": lambda: self.running.update({"ex-up": [1]}),
            "a creation time with a bad suffix": lambda: [d.update(Created="2026-10-15T06:00:05.garbage")
                                                          for d in self.running.values()],
            "no creation time": lambda: [d.pop("Created") for d in self.running.values()],
            "a creation time in another zone": lambda: [d.update(Created="2026-10-15T06:00:05+02:00")
                                                        for d in self.running.values()],
            "the two answers disagree on the creation": lambda: self.running[self.CID].update(
                Created="2026-10-15T07:00:00Z")}, rh.UNKNOWN)

    def test_the_creation_boundary_is_the_second_and_the_id_comes_first(self):
        """A record dated the same second the router was created is fresh; one
        second earlier is not. The Id comparison decides first: a record of
        another container fails whatever its time."""
        self.assertEqual(self.result().result, rh.PASS, "at == Created, to the second")
        self.record["at"] = "2026-10-15T07:00:00Z"
        self.running["ex-up"] = {"Id": self.OTHER, "Created": self.CREATED, "State": {"Running": True}}
        self.assertEqual(self.result().result, rh.FAIL, "a later time never makes another container's record fresh")

    def test_a_restart_of_the_same_container_keeps_its_record_fresh(self):
        """A plain restart keeps the Id and Created (only StartedAt moves)."""
        for ref in (self.CID, "ex-up"):
            self.running[ref] = dict(self.running[ref], State={"Running": True, "StartedAt": "2026-10-16T00:00:00Z"})
        self.assertEqual(self.result().result, rh.PASS)

    def test_a_note_only_when_both_are_affirmatively_off_and_unknown_when_untold(self):
        off = b'{"state_dir": "/s"}\n'
        self.files[f"{EV}/stop-target.json"] = FileNotFoundError
        c = self.result(config=off)
        self.assertEqual(c.result, rh.PASS)
        self.assertIn("not required", c.claim)
        self.assertEqual(self.result(config=off, gs=gate()).result, rh.FAIL, "the gate set: required")
        self.assertEqual(self.result().result, rh.FAIL, "delegation rendered: required")
        for raw in (b"[]", b'"x"', b'{"a": 1, "a": 2}', b'{"delegation": NaN}', b"\xff"):
            with self.subTest(raw=raw):
                self.assertEqual(self.result(config=raw).result, rh.UNKNOWN,
                                 "no strict object, no proof delegation is off")
        out = ps.verify_target(self.part, None, live_config=self.LIVE, engine=self.ENGINE, docker=self.DOCKER,
                               router_name="ex-up", inspect=lambda ref: None, read=self.read,
                               read_live=lambda p: (_ for _ in ()).throw(OSError("unreadable")))
        self.assertEqual(out[0].result, rh.UNKNOWN, "an unreadable live config is not proof delegation is off")

    def document_spec(self, **drop):
        import hub_supervise as hv
        from test_hub_supervise import sup_section
        d = doc(gate=gate()) if drop.pop("gate", False) else doc()
        d[hv.SECTION] = sup_section()
        for section in drop:
            d.pop(section, None)
        return hs.load_spec(d)

    def test_host_setup_judges_it_with_the_documents_own_values(self):
        spec = self.document_spec()
        seen = {}

        def inspect(ref):
            seen.setdefault("refs", []).append(ref)
            return None

        out = hs.verify_stop_target(spec, {"inspect": inspect, "read_placed": self.read, "realpath": lambda p: p,
                                           "read": lambda p: seen.setdefault("live", p) and self.config})
        self.assertEqual([c.claim for c in out], [ps.TARGET_CLAIM])
        self.assertEqual(seen["live"], spec.keys.local_config)
        self.assertEqual(out[0].result, rh.FAIL, "the record is not this document's (another config, engine, docker)")
        self.build(live=spec.keys.local_config, engine=spec.supervision.engine, docker=spec.partition.tools["docker"],
                   evidence_dir=spec.partition.evidence_dir)
        name = spec.runtime_of(spec.hops[0][1])["container"]
        self.running[name] = self.running.pop("ex-up")
        out = hs.verify_stop_target(spec, {"inspect": lambda ref: self.running.get(ref), "read_placed": self.read,
                                           "realpath": lambda p: p, "read": lambda p: self.config})
        self.assertEqual(out[0].result, rh.PASS, "the document's own values, and its local router by name")
        self.assertEqual(hs.verify_stop_target(dataclasses_replace(spec, partition=None), {}), [])

    def test_a_document_in_scope_without_the_context_to_judge_it_is_never_silent(self):
        import hub_supervise as hv
        for drop in ({hv.SECTION: True}, {"keys": True}, {hv.SECTION: True, "gate": True}):
            with self.subTest(drop=sorted(drop)):
                try:
                    spec = self.document_spec(**dict(drop))
                except hs.SpecError as e:
                    self.skipTest(f"the loader refuses such a document itself: {e}")
                out = hs.verify_stop_target(spec, {"inspect": lambda ref: None, "read_placed": self.read,
                                                   "read": lambda p: self.config})
                self.assertEqual([(c.claim, c.result) for c in out], [(ps.TARGET_CLAIM, rh.FAIL)])
                self.assertIn("no", str(out[0].actual))

    def test_the_default_inspector_asks_the_approved_engine_with_the_approved_docker(self):
        """Ambient PATH, DOCKER_HOST and DOCKER_CONTEXT point elsewhere; every
        query of the default inspector (by id, by name, and the absence
        listings) runs the approved docker against the approved engine."""
        spec = self.document_spec()
        approved_docker = spec.partition.tools["docker"]
        calls = []

        def run(argv, extra_env=None, **kw):
            calls.append((list(argv), dict(extra_env or {})))
            if "inspect" in argv:
                return rh.Proc(tuple(argv), 1, "", "No such object")
            return rh.Proc(tuple(argv), 0, "", "")
        self.addCleanup(setattr, hs.rh, "run", hs.rh.run)
        hs.rh.run = run
        ambient = {"PATH": "/elsewhere/bin", "DOCKER_HOST": "tcp://elsewhere:2375", "DOCKER_CONTEXT": "elsewhere"}
        saved = {k: os.environ.get(k) for k in ambient}
        self.addCleanup(lambda: [os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
                                 for k, v in saved.items()])
        os.environ.update(ambient)
        self.build(live=spec.keys.local_config, engine=spec.supervision.engine, docker=approved_docker,
                   evidence_dir=spec.partition.evidence_dir)
        out = hs.verify_stop_target(spec, {"read_placed": self.read, "realpath": lambda p: p,
                                           "read": lambda p: self.config})
        self.assertEqual(out[0].result, rh.FAIL, "the engine affirms no such container")
        name = spec.runtime_of(spec.hops[0][1])["container"]
        asked = [a for a, _ in calls]
        self.assertTrue(any(self.CID in a and "inspect" in a for a in asked), asked)
        self.assertTrue(any(f"id={self.CID}" in a for a in asked), asked)
        self.assertTrue(any(f"name=^/{name}$" in a for a in asked) or not any(name in a for a in asked), asked)
        for argv, env in calls:
            with self.subTest(argv=argv):
                self.assertEqual(argv[0], approved_docker, "the approved docker, by path")
                self.assertEqual(argv[1:3], ["--host", spec.supervision.engine], "the approved engine")
                self.assertEqual(env, {"DOCKER_HOST": spec.supervision.engine, "DOCKER_CONTEXT": "default"})

    def test_verify_runs_the_stop_target_check_for_a_document_with_a_partition_section(self):
        spec = self.document_spec()
        for name in ("verify_roots", "verify_overlay", "verify_containers", "verify_mounts", "verify_openssl",
                     "verify_umasks", "verify_groups", "secret_checks", "start_checks", "verify_recovery_horizon"):
            self.addCleanup(setattr, hs, name, getattr(hs, name))
            setattr(hs, name, lambda *a, **k: [])
        for mod in (hs.hr, hs.hk, hs.hv, hs.hp, hs.ps):
            for name in ("checks", "verify"):
                if hasattr(mod, name):
                    self.addCleanup(setattr, mod, name, getattr(mod, name))
                    setattr(mod, name, lambda *a, **k: [])
        seen = []
        self.addCleanup(setattr, hs, "verify_stop_target", hs.verify_stop_target)
        hs.verify_stop_target = lambda sp, p: seen.append((sp, p)) or []
        probes = {"rl_sha": "x", "inspect": lambda ref: None}
        hs.checks(spec, production=False, containers=lambda c: None, openssl={}, partition=probes,
                  enablement={"disabled": {}, "loaded": lambda l: False})
        self.assertEqual(seen, [(spec, probes)])

    def test_only_a_root_placed_regular_file_is_read_whole_as_opened(self):
        def as_root(stat_fn, **over):
            def f(p):
                st = stat_fn(p)
                fields = dict(mode=st.st_mode, nlink=st.st_nlink, uid=0, gid=0)
                fields.update(over)
                return os.stat_result((fields["mode"], st.st_ino, st.st_dev, fields["nlink"], fields["uid"],
                                       fields["gid"]) + tuple(st)[6:])
            return f
        with tempfile.TemporaryDirectory() as t:
            f = os.path.join(t, "stop-target.json")
            with open(f, "w") as h:
                h.write("{}")
            os.chmod(f, 0o444)
            os.symlink(f, os.path.join(t, "link"))
            for path in (f, os.path.join(t, "link"), os.path.join(t, "absent")):
                with self.subTest(path=os.path.basename(path)):
                    with self.assertRaises(OSError):
                        ps.read_placed(path)
            lst, fst = as_root(os.lstat), as_root(os.fstat)
            self.assertEqual(ps.read_placed(f, lstat=lst, fstat=fst), b"{}", "root:root 0444, one link, as opened")
            rows = {"the path is not 0444, as lstat sees it": dict(lstat=as_root(os.lstat, mode=0o100666)),
                    "the descriptor is not root's": dict(fstat=as_root(os.fstat, uid=501)),
                    "the descriptor is not 0444": dict(fstat=as_root(os.fstat, mode=0o100666)),
                    "the descriptor has two links": dict(fstat=as_root(os.fstat, nlink=2)),
                    "the descriptor is another file": dict(fstat=lambda fd: as_root(os.lstat)(t))}
            for what, kw in rows.items():
                with self.subTest(what):
                    with self.assertRaises(OSError):
                        ps.read_placed(f, **dict({"lstat": lst, "fstat": fst}, **kw))
            os.link(f, os.path.join(t, "second"))
            with self.assertRaises(OSError):
                ps.read_placed(f, lstat=as_root(os.lstat), fstat=as_root(os.fstat))
            os.unlink(os.path.join(t, "second"))
            big = os.path.join(t, "big.json")
            with open(big, "wb") as h:
                h.write(b"{}" + b" " * (ps.PLACED_MAX - 2) + b"not json")
            os.chmod(big, 0o444)
            with self.assertRaises(OSError, msg="read whole, never cut to a parseable prefix"):
                ps.read_placed(big, lstat=lst, fstat=fst)

    def test_an_engine_that_cannot_answer_is_unknown(self):
        self.running[self.CID] = rh.Unresolved("the engine did not answer")
        self.assertEqual(self.result().result, rh.UNKNOWN)
        self.build()
        self.running["ex-up"] = rh.Unresolved("the engine did not answer")
        self.assertEqual(self.result().result, rh.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
