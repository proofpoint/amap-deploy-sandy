"""host_steps.partition-judge and judge() (d3.3 §5(d) §2): the weekly job's
install-time check, judged exactly as trusted-exec judges, every problem
printed with its phase, the sentinel last and only when nothing was found.

What the host's real files cannot show (an operator-owned tool, a closure
problem, an ACL) is put in by replacing the one judge that finds it, as
FlowTest in test_trusted_exec does. The pin rows read real files."""

import os
import sys
import tempfile
import unittest

import host_steps as hs


class Judged(unittest.TestCase):
    DOCKER = "/usr/bin/docker"

    def stub(self, **over):
        self.calls = []
        fns = {"_trusted_tool": lambda p: p, "_bound": lambda argv: None,
               "exec_closure": lambda py, reals, spelled, platform=None: (self.calls.append("discover"),
                                                                          {hs.REQUIRED: [py], hs.LIBRARIES: [],
                                                                           hs.OPTIONAL: []})[1],
               "closure_problems": lambda c, platform=None, seen=None: [],
               "acl_problems": lambda paths, platform=None: [],
               "loader_dirs": lambda platform=None: []}
        fns.update(over)
        for name, fn in fns.items():
            self.addCleanup(setattr, hs, name, getattr(hs, name))
            setattr(hs, name, fn)

    def run_judge(self, docker=None, pin=None, platform="linux", python3=None):
        lines = []
        rc = hs.partition_judge(python3 or sys.executable, docker or self.DOCKER, pin, out=lines.append,
                                platform=platform)
        return rc, lines


class CleanRows(Judged):
    def test_a_clean_closure_prints_only_the_sentinel_on_each_system(self):
        for platform in ("linux", "darwin"):
            with self.subTest(platform=platform):
                self.stub()
                self.assertEqual(self.run_judge(platform=platform), (0, [hs.JUDGE_SENTINEL]))

    def test_the_sentinel_is_the_last_line_and_only_on_a_pass(self):
        self.stub(closure_problems=lambda c, platform=None, seen=None:
                  ["/usr/lib/x is writable by others"] if isinstance(c, dict) else [])
        rc, lines = self.run_judge()
        self.assertEqual(rc, hs.ROOT_TRUST_EXIT)
        self.assertNotIn(hs.JUDGE_SENTINEL, lines)
        self.assertEqual(lines[-1], "phase: closure")


class ProblemRows(Judged):
    def test_more_than_five_closure_problems_are_all_printed(self):
        many = [f"/usr/lib/lib{i}.so is writable by others" for i in range(7)]
        self.stub(closure_problems=lambda c, platform=None, seen=None: many if isinstance(c, dict) else [])
        rc, lines = self.run_judge()
        self.assertEqual([l for l in lines if l.startswith("untrusted: ")], [f"untrusted: {p}" for p in sorted(many)])
        self.assertEqual((rc, lines[-1]), (hs.ROOT_TRUST_EXIT, "phase: closure"))

    def test_both_tools_failing_their_file_rule_are_both_printed_and_nothing_is_discovered(self):
        def refuse(p):
            raise hs.Tooling(f"{p} is the operator's")
        self.stub(_trusted_tool=refuse)
        rc, lines = self.run_judge()
        self.assertEqual(lines, [f"untrusted: {p}" for p in sorted([f"{sys.executable} is the operator's",
                                                                    f"{self.DOCKER} is the operator's"])]
                         + ["phase: tools"])
        self.assertEqual((rc, self.calls), (hs.ROOT_TRUST_EXIT, []), "no list mode after a tools-phase problem")

    def test_an_unreadable_directory_and_a_writable_file_beside_it_are_both_kept(self):
        self.stub(closure_problems=lambda c, platform=None, seen=None:
                  ["/usr/lib/a cannot be listed", "/usr/lib/b is writable by others"] if isinstance(c, dict) else [])
        _, lines = self.run_judge()
        self.assertIn("untrusted: /usr/lib/a cannot be listed", lines)
        self.assertIn("untrusted: /usr/lib/b is writable by others", lines)

    def test_an_acl_and_the_loaders_directories_are_judged(self):
        seen = []
        self.stub(loader_dirs=lambda platform=None: ["/etc/ld.so.cache"],
                  closure_problems=lambda c, platform=None, seen_=None, **k: (
                      seen.append(list(c[hs.OPTIONAL])) if isinstance(c, dict) else None) or [],
                  acl_problems=lambda paths, platform=None: ["/usr/lib carries an ACL"])
        rc, lines = self.run_judge()
        self.assertEqual(seen, [["/etc/ld.so.cache"]])
        self.assertIn("untrusted: /usr/lib carries an ACL", lines)
        self.assertEqual(rc, hs.ROOT_TRUST_EXIT)

    def test_ld_so_preload_is_a_tools_phase_problem(self):
        with tempfile.NamedTemporaryFile() as f:
            self.addCleanup(setattr, hs, "LD_SO_PRELOAD", hs.LD_SO_PRELOAD)
            hs.LD_SO_PRELOAD = f.name
            self.stub()
            rc, lines = self.run_judge()
        self.assertEqual((rc, lines[-1]), (hs.ROOT_TRUST_EXIT, "phase: tools"))
        self.assertEqual(self.calls, [])

    def test_a_non_elf_docker_is_a_phase_closure_problem_with_no_traceback(self):
        def not_elf(py, reals, spelled, platform=None):
            raise hs.Tooling(f"{self.DOCKER}: not an ELF file")
        self.stub(exec_closure=not_elf)
        rc, lines = self.run_judge()
        self.assertEqual(lines, [f"untrusted: {self.DOCKER}: not an ELF file", "phase: closure"])
        self.assertEqual(rc, hs.ROOT_TRUST_EXIT)


class PinRows(Judged):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))

    def test_a_pin_mismatch_is_phase_tools(self):
        docker = os.path.join(self.d, "docker")
        with open(docker, "wb") as f:
            f.write(b"not the pinned client")
        self.stub()
        rc, lines = self.run_judge(docker=docker, pin="0" * 64)
        self.assertTrue(any("is not the client the document pins" in l for l in lines), lines)
        self.assertEqual((rc, lines[-1], self.calls), (hs.ROOT_TRUST_EXIT, "phase: tools", []))

    def test_a_matching_pin_passes(self):
        docker = os.path.join(self.d, "docker")
        with open(docker, "wb") as f:
            f.write(b"the client")
        self.stub()
        pin = __import__("hashlib").sha256(b"the client").hexdigest()
        self.assertEqual(self.run_judge(docker=docker, pin=pin), (0, [hs.JUDGE_SENTINEL]))

    def test_a_fifo_in_a_pinned_tools_place_never_hangs_and_its_pin_is_never_read(self):
        """Opus at v4 N4: the pin is read only for a tool that passed its file
        rule; the real _trusted_tool refuses a FIFO, so the pin read never
        happens. Were it read, the non-blocking open still would not hang."""
        fifo = os.path.join(self.d, "docker")
        os.mkfifo(fifo)
        read = []
        self.addCleanup(setattr, hs, "_pin_problem", hs._pin_problem)
        hs._pin_problem = lambda t, want: read.append(t)
        self.stub(_trusted_tool=hs._trusted_tool)
        rc, lines = self.run_judge(docker=fifo, pin="0" * 64)
        self.assertEqual((rc, lines[-1], read), (hs.ROOT_TRUST_EXIT, "phase: tools", []))

    def test_the_pin_reader_itself_refuses_a_fifo_without_blocking(self):
        fifo = os.path.join(self.d, "f")
        os.mkfifo(fifo)
        self.assertIn("is not a regular file", hs._pin_problem(fifo, "0" * 64))


class VerbRows(Judged):
    def test_python3_not_the_running_interpreter_is_refused(self):
        self.stub()
        rc, lines = self.run_judge(python3="/usr/bin/false")
        self.assertEqual(rc, hs.ROOT_TRUST_EXIT)
        self.assertIn("is not the interpreter running this check", lines[0])
        self.assertEqual(self.calls, [])

    def test_an_exception_mid_judging_prints_no_sentinel(self):
        def boom(py, reals, spelled, platform=None):
            raise ValueError("injected")
        self.stub(exec_closure=boom)
        lines = []
        self.addCleanup(setattr, hs, "partition_judge", hs.partition_judge)
        real = hs.partition_judge
        hs.partition_judge = lambda python3, docker, pin=None: real(python3, docker, pin, out=lines.append)
        rc = hs.main(["partition-judge", "--python3", sys.executable, "--docker", self.DOCKER])
        self.assertEqual(rc, 1)
        self.assertNotIn(hs.JUDGE_SENTINEL, lines)

    def test_the_verb_parses_only_its_own_options(self):
        for argv in (["partition-judge"], ["partition-judge", "--docker", "/usr/bin/docker"],
                     ["partition-judge", "--python3", sys.executable, "--docker", "docker"],
                     ["partition-judge", "--python3", sys.executable, "--docker", "/d", "--docker-sha256", "x"],
                     ["partition-judge", "--python3", sys.executable, "--docker", "/d", "--other", "y"]):
            with self.subTest(argv=argv):
                self.assertEqual(hs.main(argv), 1)


class TrustedExecParityRows(Judged):
    """judge() is trusted_exec's own judging: _bound keeps its place after
    the sudo refusal and before the recorded-set check, and the message is
    truncated to five problems only there."""

    def test_bound_runs_after_the_sudo_refusal_and_before_the_recorded_set(self):
        order = []
        self.stub(_bound=lambda argv: order.append("bound"))
        with self.assertRaisesRegex(hs.Tooling, "never holds sudo"):
            hs.trusted_exec(["/usr/bin/sudo", "x"], execv=lambda *a: None, platform="linux")
        self.assertEqual(order, [])
        with self.assertRaisesRegex(hs.Tooling, "is not a tool the document records"):
            hs.trusted_exec(["/usr/bin/docker", "ps"], execv=lambda *a: None, platform="linux", tools=[])
        self.assertEqual(order, ["bound"])

    def test_trusted_exec_truncates_to_five_and_judge_keeps_all(self):
        many = [f"/usr/lib/lib{i}.so is writable by others" for i in range(7)]
        self.stub(closure_problems=lambda c, platform=None, seen=None: many if isinstance(c, dict) else [])
        with self.assertRaises(hs.Tooling) as cm:
            hs.trusted_exec(["/usr/bin/docker", "ps"], execv=lambda *a: None, platform="linux",
                            tools=["/usr/bin/docker"])
        self.assertEqual(str(cm.exception).count("writable by others"), 5)
        j = hs.judge("/usr/bin/docker", recorded=["/usr/bin/docker"], platform="linux")
        self.assertEqual((j.phase, len(j.problems)), ("closure", 7))


if __name__ == "__main__":
    unittest.main()
