"""Root runs docker only when it is root's alone.

The hub's supervisor (systemd's ExecStartPre, launchd's wrapper) asks the
pinned writer's `trusted-tools` first; `probe-weekly` checks its own tools
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
        self.assertEqual(hs._trusted_tool(tool), tool)

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
        self.assertEqual(hs._trusted_tool(link), target)
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


class TrustedToolsStepTest(unittest.TestCase):
    """The writer's `trusted-tools PYTHON3 DOCKER`, which the supervisors run."""

    def test_it_is_the_partition_jobs_own_check(self):
        seen = []
        self.addCleanup(setattr, hs, "_verified_tools", hs._verified_tools)
        hs._verified_tools = lambda py, dk: seen.append((py, dk)) or (py, dk)
        self.assertEqual(hs.main(["trusted-tools", "/usr/bin/python3", "/usr/bin/docker"]), 0)
        self.assertEqual(seen, [("/usr/bin/python3", "/usr/bin/docker")])

        def refuse(py, dk):
            raise hs.Tooling(f"{dk} resolves to /x, which is not a root-owned executable no one else can write")
        hs._verified_tools = refuse
        self.assertEqual(hs.main(["trusted-tools", "/usr/bin/python3", "/usr/bin/docker"]), hs.EXIT_TOOLING)

    @unittest.skipIf(os.geteuid() == 0, "as root, a file this test makes is root's")
    def test_the_cli_refuses_an_operator_owned_docker(self):
        with tempfile.TemporaryDirectory() as t:
            docker = os.path.join(t, "docker")
            with open(docker, "w") as f:
                f.write("#!/bin/sh\n")
            os.chmod(docker, 0o755)
            done = subprocess.run([sys.executable, "-I", "-S", HOST_STEPS, "trusted-tools", sys.executable, docker],
                                  capture_output=True, text=True, timeout=120)
            self.assertEqual(done.returncode, hs.EXIT_TOOLING, done.stderr)


if __name__ == "__main__":
    unittest.main()
