"""Root runs docker only when it is root's alone.

The hub's supervisor (systemd's ExecStartPre, launchd's wrapper) runs the
barrier over docker first; `probe-weekly` checks its own tools
before it runs anything; partition-weekly already did. All three rest on
host_steps._trusted_tool and the startup closure. These rows hold the rule on
real files, with root mapped to this test's uid (as ToolTrustTest does) and
the directories above the fixture, which no test can own, taken as root's.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace

import host_steps as hs

HOST_STEPS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "host_steps.py")


class Fixture(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.d = os.path.realpath(t.name)
        os.chmod(self.d, 0o755)
        above = set()
        p = os.path.dirname(self.d)
        while True:
            st = os.lstat(p)
            above.add((st.st_dev, st.st_ino))
            if p == "/":
                break
            p = os.path.dirname(p)
        rule = hs._ancestor_ok
        self.addCleanup(setattr, hs, "_ancestor_ok", rule)
        hs._ancestor_ok = lambda st: (st.st_dev, st.st_ino) in above or rule(st)
        self.addCleanup(setattr, hs, "ROOT_UID", hs.ROOT_UID)
        hs.ROOT_UID = os.getuid()

    def judged(self, path):
        """_trusted_tool's answer: the path it trusts, or its refusal as text."""
        try:
            return hs._trusted_tool(path)
        except hs.Tooling as e:
            return f"refused: {e}"

    def file(self, rel, mode=0o755):
        p = os.path.join(self.d, rel)
        os.makedirs(os.path.dirname(p), mode=0o755, exist_ok=True)
        with open(p, "w") as f:
            f.write("#!/bin/sh\n")
        os.chmod(p, mode)
        return p


class TrustedToolRowsTest(Fixture):
    """The rule every root docker call now passes through."""

    def test_a_root_owned_chain_passes(self):
        tool = self.file("bin/docker")
        self.assertEqual(self.judged(tool), tool)

    def test_an_operator_owned_target_refuses(self):
        tool = self.file("bin/docker")
        hs.ROOT_UID = os.getuid() + 1          # the file's owner is now not root: the operator's
        with self.assertRaisesRegex(hs.Tooling, "not a root-owned executable"):
            hs._trusted_tool(tool)

    def test_a_group_writable_ancestor_refuses(self):
        tool = self.file("bin/docker")
        os.chmod(os.path.join(self.d, "bin"), 0o775)
        with self.assertRaisesRegex(hs.Tooling, "/bin, above .* is not root-owned, or is writable by others"):
            hs._trusted_tool(tool)

    def test_a_link_is_judged_by_its_resolved_target_and_that_chain(self):
        """The OrbStack shape: a link (anywhere) into a bundle. The target and
        the directories above IT decide; the link's own route is the startup
        closure's (closure_problems judges a spelled path link by link)."""
        target = self.file("app/xbin/docker-tools")
        link = os.path.join(self.d, "bin", "docker")
        os.makedirs(os.path.dirname(link), mode=0o755)
        os.symlink(target, link)
        self.assertEqual(self.judged(link), target, "the link resolves to a root-owned target under root's chain")
        os.chmod(os.path.join(self.d, "app"), 0o777)
        with self.assertRaisesRegex(hs.Tooling, "/app, above"):
            hs._trusted_tool(link)
        os.chmod(os.path.join(self.d, "app"), 0o755)
        os.chmod(target, 0o775)
        with self.assertRaisesRegex(hs.Tooling, "resolves to .*docker-tools"):
            hs._trusted_tool(link)


class ProbeToolsTest(unittest.TestCase):
    """probe-weekly's check: which paths, and that nothing runs without it."""

    def stub(self, **over):
        calls = {"trusted": [], "closure": []}
        fns = {"_trusted_tool": lambda p: calls["trusted"].append(p) or "/real" + p,
               "startup_closure": lambda *a: calls["closure"].append(a) or {},
               "closure_problems": lambda c: []}
        fns.update(over)
        for name, fn in fns.items():
            self.addCleanup(setattr, hs, name, getattr(hs, name))
            setattr(hs, name, fn)
        return calls

    def test_the_interpreter_the_client_and_the_program_are_each_checked_with_the_closure(self):
        calls = self.stub()
        hs._verify_probe_tools("/usr/bin/sudo", ["/usr/bin/docker"])
        self.assertEqual(calls["trusted"], [sys.executable, "/usr/bin/docker", "/usr/bin/sudo"])
        self.assertEqual(calls["closure"], [("/real" + sys.executable, "/real/usr/bin/docker",
                                             (sys.executable, "/usr/bin/docker", "/usr/bin/sudo"))])

    def test_without_docker_the_program_is_the_client(self):
        calls = self.stub()
        hs._verify_probe_tools("/usr/bin/docker", None)
        self.assertEqual(calls["trusted"][1:], ["/usr/bin/docker", "/usr/bin/docker"])

    def test_a_closure_problem_refuses(self):
        self.stub(closure_problems=lambda c: ["/usr/lib/x.so is not root-owned, or is writable by others"])
        with self.assertRaisesRegex(hs.Tooling, "startup closure"):
            hs._verify_probe_tools("/usr/bin/docker", ["/usr/bin/docker"])

    def test_an_untrusted_tool_refuses_the_step_and_nothing_runs_or_is_recorded(self):
        with tempfile.TemporaryDirectory() as t:
            ran, status = os.path.join(t, "ran"), os.path.join(t, "status.json")

            def untrusted(program, docker):
                raise hs.Tooling("not root's")
            for verify in (untrusted, None):
                with self.subTest(verify=verify):
                    if verify is None:
                        self.addCleanup(setattr, hs, "_verify_probe_tools", hs._verify_probe_tools)
                        hs._verify_probe_tools = untrusted       # the default the CLI uses
                    with self.assertRaises(hs.Refused) as e:
                        hs.probe_weekly(status, "w-1", [sys.executable, "-c", f"open({ran!r},'w')"], now=1,
                                        docker=["/usr/bin/docker"], verify=verify)
                    self.assertEqual(e.exception.rule, "tools")
                    self.assertFalse(os.path.exists(ran))
                    self.assertFalse(os.path.exists(status))

    @unittest.skipIf(os.geteuid() == 0, "as root, a file this test makes is root's")
    def test_the_cli_refuses_an_operator_owned_docker(self):
        with tempfile.TemporaryDirectory() as t:
            docker = os.path.join(t, "docker")
            with open(docker, "w") as f:
                f.write("#!/bin/sh\n")
            os.chmod(docker, 0o755)
            status = os.path.join(t, "status.json")
            done = subprocess.run([sys.executable, "-I", "-S", HOST_STEPS, "probe-weekly", status, "w-1",
                                   "--docker", docker, "--", docker, "run"], capture_output=True, timeout=120)
            self.assertEqual((done.returncode, done.stdout), (hs.REFUSED, b"refused: tools\n"))
            self.assertFalse(os.path.exists(status))


class SudoersRuleTest(unittest.TestCase):
    """Opus B5 at 184acedf: the narrow rule the sudo route needs is rendered,
    from the very prefix live_docker runs, never written by hand."""

    def setUp(self):
        import test_secret_setup as tss
        self.s = tss.spec(docker_via_sudo=True)

    @staticmethod
    def unescape(arg):
        out, i = "", 0
        while i < len(arg):
            if arg[i] == "\\":
                i += 1
            out += arg[i]
            i += 1
        return out

    def test_each_rule_is_exactly_the_live_prefix_and_then_dockers_own_arguments(self):
        import secret_setup as ss
        lines = ss.sudoers_lines(self.s, "unix:///var/run/docker.sock")
        rules = [l[2:] for l in lines if l.startswith("# #")]
        self.assertEqual(len(rules), 2, "the engine's (verify) and none (the activation verbs)")
        for rule, engine in zip(rules, ("unix:///var/run/docker.sock", None)):
            with self.subTest(engine=engine):
                head, cmd = rule.split(" NOPASSWD: ", 1)
                self.assertEqual(head, f"#{self.s.operator_uid} ALL=(root)")
                self.assertTrue(cmd.endswith(" *"))
                want = ss.sudo_route(self.s, engine)[2:]
                body = cmd[:-2]
                self.assertEqual(self.unescape(body), " ".join(want))
                bare = body.replace("\\\\", "").replace("\\,", "").replace("\\:", "").replace("\\=", "")
                for c in ",:=*?[]":
                    self.assertNotIn(c, bare.replace("\\" + c, ""), f"an unescaped {c!r}")

    def test_the_live_route_and_the_rule_share_one_builder(self):
        import secret_setup as ss
        with ss.trust_gate(self.s, engine="unix:///e.sock", closure=lambda s_: None, digest=lambda p: "b" * 64,
                           lstat=__import__("test_secret_setup").lstat_of(__import__("test_secret_setup").fs()),
                           realpath=lambda p: p):
            self.assertEqual(ss.live_docker(self.s), ss.sudo_route(self.s, "unix:///e.sock"))

    def test_the_plan_carries_the_rules_on_the_sudo_route_only(self):
        import host_setup as hs
        import test_secret_setup as tss
        for via, want in ((True, True), (False, False)):
            with self.subTest(via=via):
                spec = hs.load_spec(tss.full_doc(docker_via_sudo=via) if via else tss.full_doc())
                text = "\n".join(hs.render_plan(spec))
                self.assertEqual("NOPASSWD: /usr/bin/env -i" in text, want)
                self.assertNotIn("NOPASSWD: /usr/bin/env\n", text)


class LiveEngineGateTest(unittest.TestCase):
    """d3.3 §5(c), Codex B2 at 1c3f431c: no live engine call runs unless every
    prerequisite PASSes (the interpreter, docker and sudo by their tool rows,
    the writer by its pin, docker's startup closure computed as the operator),
    on the held and the lock-wrapped route alike. Every observation is then
    the refusal, as UNKNOWN, and rh.run is never reached. On the sudo route a
    call is `sudo -n` and the §3 grammar, with the document's engine."""

    PIN = "b" * 64

    def setUp(self):
        import test_secret_setup as tss
        self.tss = tss
        self.calls = []
        self.addCleanup(setattr, ss_rh(), "run", ss_rh().run)
        ss_rh().run = lambda argv, **kw: self.calls.append(list(argv)) or ss_rh().Proc(tuple(argv), 0, "{}", "")

    def table(self, **owned_by_op):
        f = self.tss.fs()
        for path in owned_by_op.values():
            f[path] = self.tss.fl(0o755, self.tss.OP)
        return self.tss.lstat_of(f)

    def gate(self, s, table=None, digest=None, closure=None, engine=None):
        import secret_setup as ss
        return ss.trust_gate(s, table or self.table(), lambda p: p, engine=engine,
                             digest=digest or (lambda p: self.PIN), closure=closure or (lambda s_: None))

    def refused(self, s, why, **gate):
        import secret_setup as ss
        for held in (True, False):
            with self.subTest(held=held, why=why):
                with self.gate(s, **gate):
                    got = ss.ask_volume(s, "r1", held=held)
                self.assertIsInstance(got, ss_rh().Unresolved)
                self.assertIn(why, got.reason)
                self.assertEqual(self.calls, [])

    def test_the_sudo_route_is_refused_when_docker_or_sudo_is_not_roots(self):
        s = self.tss.spec(docker_via_sudo=True)
        for name, path in (("docker", "/usr/local/bin/docker"), ("sudo", "/usr/bin/sudo")):
            self.refused(s, f"not run: {name} not root's alone", table=self.table(**{name: path}))

    def test_the_interpreter_is_a_prerequisite_on_both_routes(self):
        for via in (True, False):
            self.refused(self.tss.spec(docker_via_sudo=via), "not run: python3 not root's alone",
                         table=self.table(python3="/usr/bin/python3"))

    def test_a_writer_that_is_not_the_pinned_one_runs_no_engine(self):
        """Codex's witness at 1c3f431c: a writer-pin FAIL still dispatched."""
        for via in (True, False):
            self.refused(self.tss.spec(docker_via_sudo=via), "not the pinned one", digest=lambda p: "0" * 64)

    def test_a_closure_not_roots_alone_runs_no_engine(self):
        for via in (True, False):
            self.refused(self.tss.spec(docker_via_sudo=via), "startup closure is not root's alone: libz",
                         closure=lambda s_: "libz is the operator's")

    def test_a_closure_check_that_cannot_be_imported_refuses(self):
        """In a bundle without the writer's module, the gate refuses: it never
        passes a closure it could not compute."""
        import sys
        import secret_setup as ss
        had = "host_steps" in sys.modules
        before = sys.modules.get("host_steps")
        self.addCleanup(lambda: sys.modules.__setitem__("host_steps", before) if had
                        else sys.modules.pop("host_steps", None))
        sys.modules["host_steps"] = None
        why = ss._operator_closure(self.tss.spec())
        self.assertIsInstance(why, str, "an unimportable closure check passed")
        self.assertIn("not importable", why)

    def test_the_direct_route_runs_the_operators_own_docker_when_everything_passes(self):
        import secret_setup as ss
        s = self.tss.spec()
        with self.gate(s):
            ss.ask_volume(s, "r1", held=True)
        self.assertEqual(self.calls[0][:3], ["/usr/local/bin/docker", "run", "--rm"])

    def sudo_prefix(self, s, engine):
        """Built here from the spec, not from live_docker: §3's positional grammar under sudo."""
        tools = sorted(t for t in set(s.tools.values()) if not t.endswith("/sudo"))
        return ([s.tools["sudo"], "-n", "/usr/bin/env", "-i", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"]
                + ([f"DOCKER_HOST={engine}"] if engine else [])
                + ["/bin/sh", "-c", "command . /opt/ex/libexec/root-trust.sh && command -v root_exec >/dev/null "
                                    "|| exit 12; root_exec \"$@\"", "sh", self.PIN, s.tools["python3"],
                   "/opt/ex/libexec/host_steps.py", "trusted-exec"]
                + [x for t in tools for x in ("--tool", t)] + ["--", s.tools["docker"]])

    def test_the_sudo_route_is_the_section_3_grammar_with_the_documents_engine_on_both_routes(self):
        import secret_setup as ss
        s = self.tss.spec(docker_via_sudo=True)
        want = self.sudo_prefix(s, "unix:///var/run/docker.sock")
        with self.gate(s, engine="unix:///var/run/docker.sock"):
            ss.ask_volume(s, "r1", held=True)
            ss.ask_volume(s, "r2", held=False)
        held, locked = self.calls
        self.assertEqual(held[:len(want) + 2], want + ["run", "--rm"])
        self.assertEqual(locked[:7], [s.tools["python3"], "-I", "-S", s.writer, "lock", s.run_dir, "--"])
        self.assertEqual(locked[7:7 + len(want) + 2], want + ["run", "--rm"])
        self.assertNotIn("sudo", " ".join(held[2:]), "root's argv never holds sudo")

    def test_an_inner_gate_keeps_the_outer_gates_engine(self):
        import secret_setup as ss
        s = self.tss.spec(docker_via_sudo=True)
        with self.gate(s, engine="unix:///x.sock"):
            with self.gate(s):
                argv = ss.live_docker(s)
        self.assertIn("DOCKER_HOST=unix:///x.sock", argv)

    def test_host_setup_opens_the_gate_with_the_documents_engine(self):
        import host_setup as hs
        import secret_setup as ss
        got = []
        self.addCleanup(setattr, ss, "trust_gate", ss.trust_gate)
        ss.trust_gate = lambda s, lstat, realpath, engine=None, **k: got.append(engine)
        spec = SimpleNamespace(secrets=object(), supervision=SimpleNamespace(engine="unix:///e.sock"))
        hs._trust_gate(spec, lambda p: None, None)
        self.assertEqual(got, ["unix:///e.sock"])

    def test_the_exposure_sweep_asks_no_engine(self):
        import secret_exposure as se
        import test_secret_exposure as tse
        spec_x, sx = tse.specs()
        with self.gate(sx, table=self.table(docker=sx.tools["docker"])):
            found = se.checks(spec_x, sx, lstat_=lambda p: tse.Id(1, 1), stat_=tse.stat_of(), realpath=lambda p: p,
                              lock=tse.free_lock, platform="linux")
        self.assertEqual(self.calls, [])
        self.assertEqual([(c.result, c.reason) for c in found if c.result != ss_rh().PASS],
                         [(ss_rh().UNKNOWN, "not run: docker not root's alone")])

    def test_verify_dispatches_no_one_shot_after_a_writer_pin_fail(self):
        """Codex's aggregator witness: the REAL ss.checks, every tool root's,
        the closure passing; a wrong writer digest leaves the pin row FAIL and
        the volume one-shot is never dispatched. The control dispatches it."""
        import secret_setup as ss
        self.addCleanup(setattr, ss, "_operator_closure", ss._operator_closure)
        ss._operator_closure = lambda s_: None
        f = self.tss.fs()
        for digest, dispatched in (("0" * 64, False), (self.PIN, True)):
            with self.subTest(digest=digest[:1]):
                self.calls.clear()
                found = ss.checks(self.tss.spec(), lstat=self.tss.lstat_of(f), digest=lambda p, d=digest: d,
                                  read=self.tss.reader(self.tss.files()), platform="linux",
                                  listdir=lambda p: [], realpath=lambda p: p, now=self.tss.NOW, held=True,
                                  stat_=self.tss.identity_of(f), exists=lambda p: False)
                self.assertEqual(any("run" in c for c in self.calls), dispatched, self.calls)
                pin = [c for c in found if c.claim.endswith("hashes to its pin")]
                self.assertEqual(pin[0].result, ss_rh().PASS if dispatched else ss_rh().FAIL)

    def test_verify_with_its_real_tool_rows_runs_no_engine_after_a_docker_fail(self):
        """Codex's own_b2 shape: ss.checks with the REAL verify_tools, an
        operator-owned docker, and nothing injected for the volume."""
        import secret_setup as ss
        f = self.tss.fs()
        f["/usr/local/bin/docker"] = self.tss.fl(0o755, self.tss.OP)
        found = ss.checks(self.tss.spec(), lstat=self.tss.lstat_of(f), digest=lambda p: "b" * 64,
                          read=self.tss.reader(self.tss.files()), platform="linux",
                          listdir=lambda p: [], realpath=lambda p: p, now=self.tss.NOW, held=True,
                          stat_=self.tss.identity_of(f), exists=lambda p: False)
        self.assertFalse([c for c in self.calls if "run" in c], self.calls)
        rows = {c.claim: (c.result, c.reason) for c in found}
        self.assertEqual(rows["the docker tool /usr/local/bin/docker is a regular executable file owned by root"][0],
                         ss_rh().FAIL)
        vol = [v for k, v in rows.items() if k.startswith("the volume ")]
        self.assertTrue(vol and all(r == ss_rh().UNKNOWN and "not run: docker" in (why or "") for r, why in vol), vol)

    def test_outside_any_gate_live_docker_judges_the_real_files(self):
        import secret_setup as ss
        s = self.tss.spec(tools=dict(self.tss.sec()["tools"], docker="/nonexistent/amap-test/docker"))
        with self.assertRaises(ss_rh().CannotRun):
            ss.live_docker(s)


class RootExecToolListTest(unittest.TestCase):
    """Opus B1 at 3355eda0: the list is pinned by name, so dropping one fails a row."""

    def test_the_tools_root_executes_are_exactly_these(self):
        import secret_setup as ss
        self.assertEqual(ss.ROOT_EXEC_TOOLS, ("docker", "python3", "sudo", "install"))

    def test_an_operator_owned_sudo_fails(self):
        import test_secret_setup as tss
        f = tss.fs()
        f["/usr/bin/sudo"] = tss.fl(0o755, tss.OP)
        import secret_setup as ss
        rows = [c for c in ss.verify_tools(tss.spec(), tss.lstat_of(f), lambda p: p) if "the sudo tool" in c.claim]
        self.assertEqual([c.result for c in rows], [ss_rh().FAIL])


def ss_rh():
    import router_health
    return router_health


if __name__ == "__main__":
    unittest.main()
