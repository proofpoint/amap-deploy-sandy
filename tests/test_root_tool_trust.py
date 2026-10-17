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


class LiveEngineGateTest(unittest.TestCase):
    """Codex and Opus B2 at 3355eda0: no live engine call runs once the tool
    rows find docker (or sudo, or the lock route's python3) not root's alone.
    Every observation is the refusal, as UNKNOWN, and rh.run is never reached."""

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

    def test_the_sudo_route_is_refused_when_docker_or_sudo_is_not_roots(self):
        import secret_setup as ss
        s = self.tss.spec(docker_via_sudo=True)
        for bad in ({"docker": "/usr/local/bin/docker"}, {"sudo": "/usr/bin/sudo"}):
            with self.subTest(bad=bad):
                with ss.trust_gate(s, self.table(**bad)):
                    got = ss.ask_volume(s, "r1", held=True)
                self.assertIsInstance(got, ss_rh().Unresolved)
                self.assertIn(f"not run: {next(iter(bad))} not root's alone", got.reason)
                self.assertEqual(self.calls, [])

    def test_the_direct_route_is_refused_too_and_a_root_docker_runs(self):
        import secret_setup as ss
        s = self.tss.spec()
        with ss.trust_gate(s, self.table(docker="/usr/local/bin/docker")):
            self.assertIsInstance(ss.ask_volume(s, "r1", held=True), ss_rh().Unresolved)
        self.assertEqual(self.calls, [])
        with ss.trust_gate(s, self.table()):
            ss.ask_volume(s, "r1", held=True)
        self.assertEqual(self.calls[0][0], "/usr/local/bin/docker")

    def test_the_lock_route_also_needs_python3_roots(self):
        import secret_setup as ss
        s = self.tss.spec()
        with ss.trust_gate(s, self.table(python3="/usr/bin/python3")):
            self.assertIsInstance(ss.ask_volume(s, "r1", held=False), ss_rh().Unresolved)
            self.assertEqual(self.calls, [])
            ss.ask_volume(s, "r1", held=True)
        self.assertEqual(self.calls[0][0], "/usr/local/bin/docker", "the held route runs no python3")

    def test_the_exposure_sweep_asks_no_engine(self):
        import secret_exposure as se
        import secret_setup as ss
        import test_secret_exposure as tse
        spec_x, sx = tse.specs()
        with ss.trust_gate(sx, self.table(docker=sx.tools["docker"])):
            found = se.checks(spec_x, sx, lstat_=lambda p: tse.Id(1, 1), stat_=tse.stat_of(), realpath=lambda p: p,
                              lock=tse.free_lock, platform="linux")
        self.assertEqual(self.calls, [])
        self.assertEqual([(c.result, c.reason) for c in found if c.result != ss_rh().PASS],
                         [(ss_rh().UNKNOWN, "not run: docker not root's alone")])

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
