"""The mutant harness itself (tests/mutants.py), on a tiny repository of its own: each verdict it can give is reached
by the one cause that produces it. The real suite is never run here.

The fake repository has install/{target.py, tests/make_manifest.py, tests/test_t.py} and a root file the test reads
(root.txt), so a copy that left the root out would make the control red."""

import contextlib
import io
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import a2fix  # noqa: F401  (puts install/ on sys.path)
import mutants

TARGET = "VALUE = 1\n\n\ndef f():\n    return VALUE\n"
TEST = '''import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import target
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class T(unittest.TestCase):
    def test_value(self):
        self.assertEqual(target.f(), 1)

    def test_root_file(self):
        with open(os.path.join(ROOT, "root.txt")) as f:
            self.assertEqual(f.read(), "root\\n")
'''


class HarnessTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="a2harn-")
        self.addCleanup(shutil.rmtree, self.d, True)
        inst = os.path.join(self.d, "install")
        os.makedirs(os.path.join(inst, "tests"))
        for rel, text in (("target.py", TARGET), ("tests/make_manifest.py", "pass\n"), ("tests/test_t.py", TEST)):
            with open(os.path.join(inst, rel), "w") as f:
                f.write(text)
        with open(os.path.join(self.d, "root.txt"), "w") as f:
            f.write("root\n")
        os.makedirs(os.path.join(self.d, ".git"))
        p = mock.patch.object(mutants, "INSTALL", inst)
        p.start()
        self.addCleanup(p.stop)

    @staticmethod
    def quiet_run(labels):
        with contextlib.redirect_stdout(io.StringIO()):
            return mutants.run(labels)

    def one(self, old=None, new=None, fname="target.py", **kw):
        m = ("X", None, None, None) if old is None else ("X", fname, old, new)
        return mutants._one(m, **kw)[1:]

    def test_the_control_copies_the_root_and_counts_the_tests(self):
        verdict, ran, secs = self.one()
        self.assertEqual((verdict, ran), ("SURVIVED", 2))
        self.assertIsInstance(secs, float)

    def test_a_real_kill(self):
        v = self.one("VALUE = 1\n", "VALUE = 2\n", expect_ran=2)[0]
        self.assertTrue(v.startswith("KILLED by test_value (test_t.T"), v)

    def test_an_identity_edit_survives(self):
        self.assertEqual(self.one("VALUE = 1\n", "VALUE = 1\n", expect_ran=2)[0], "SURVIVED")

    def test_a_mutant_that_does_not_compile_is_bad_not_killed(self):
        self.assertTrue(self.one("VALUE = 1\n", "VALUE = (\n", expect_ran=2)[0].startswith("BAD-MUTANT (does not compile"))

    def test_a_mutant_under_which_a_test_module_does_not_import_is_bad(self):
        v = self.one("VALUE = 1\n", "VALUE = 1\nraise ImportError('x')\n", expect_ran=2)[0]
        self.assertEqual(v, "BAD-IMPORT (a test module did not import)")

    def test_another_test_count_is_bad(self):
        v = self.one("    def test_root_file(self):", "    def helper_root_file(self):", fname="tests/test_t.py",
                     expect_ran=2)[0]
        self.assertEqual(v, "BAD-MUTANT (ran 1 tests, the control ran 2)")

    def test_an_anchor_that_does_not_match_once_is_bad(self):
        self.assertTrue(self.one("NOT THERE", "x", expect_ran=2)[0].startswith("BAD-MUTANT (old string"))

    def test_a_timeout_is_its_own_outcome(self):
        v = self.one("    return VALUE\n", "    import time; time.sleep(30); return VALUE\n", expect_ran=2,
                     timeout_s=2)[0]
        self.assertEqual(v, "TIMEOUT (over 2 s)")

    def test_crlf_survives_an_identity_rewrite(self):
        p = os.path.join(mutants.INSTALL, "target.py")
        with open(p, "w", newline="") as f:
            f.write(TARGET.replace("\n", "\r\n"))
        self.assertEqual(self.one("VALUE = 1\r\n", "VALUE = 1\r\n")[0], "SURVIVED")

    def test_a_symlinked_file_is_bad_and_the_outside_target_is_untouched(self):
        outside = os.path.join(os.path.dirname(self.d), os.path.basename(self.d) + "-outside.py")
        with open(outside, "w") as f:
            f.write(TARGET)
        self.addCleanup(os.unlink, outside)
        os.symlink(outside, os.path.join(mutants.INSTALL, "linked.py"))
        v = self.one("VALUE = 1\n", "VALUE = 2\n", fname="linked.py", expect_ran=2)[0]
        self.assertEqual(v, "BAD-MUTANT (the file is a symlink or resolves outside the copy)")
        with open(outside) as f:
            self.assertEqual(f.read(), TARGET)

    def test_copies_that_disturb_each_other_turn_a_concurrent_control_red(self):
        """Gate B's NC-2/NC-3 shape: a test that claims one fixed path for a while. Two copies side by side collide.
        Whichever copies collide, the collision never becomes a kill: a red concurrent control refuses (exit 3),
        and a kill that does not repeat alone is UNSTABLE (exit 1)."""
        shared = os.path.join(os.path.dirname(self.d), os.path.basename(self.d) + "-shared")
        self.addCleanup(lambda: os.path.exists(shared) and os.rmdir(shared))
        with open(os.path.join(mutants.INSTALL, "tests", "test_shared.py"), "w") as f:
            f.write("import os, time, unittest\n"
                    "class S(unittest.TestCase):\n"
                    "    def test_claim(self):\n"
                    "        os.mkdir(%r)\n"
                    "        try:\n"
                    "            time.sleep(1.5)\n"
                    "        finally:\n"
                    "            os.rmdir(%r)\n" % (shared, shared))
        neutral = [("N1", "target.py", "VALUE = 1\n", "VALUE = 1\n"), ("N2", "target.py", "VALUE = 1\n", "VALUE = 1\n")]
        ident = ("IDENTITY", "target.py", "VALUE = 1\n", "VALUE = 1\n")
        with mock.patch.object(mutants, "M", neutral), mock.patch.object(mutants, "IDENTITY", ident):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = mutants.run(["N1", "N2"], jobs=2)
        self.assertIn(rc, (1, 3), out.getvalue())
        if rc == 3:
            self.assertIn("CONCURRENT CONTROL RED", out.getvalue())
        else:
            self.assertIn("UNSTABLE: N1 N2", out.getvalue())
            self.assertIn("killed=0", out.getvalue())

    def test_run_refuses_on_a_red_control_and_on_a_bad_identity(self):
        os.unlink(os.path.join(self.d, "root.txt"))
        with mock.patch.object(mutants, "M", [("K", "target.py", "VALUE = 1\n", "VALUE = 2\n")]):
            self.assertEqual(self.quiet_run(["K"]), 3)
        with open(os.path.join(self.d, "root.txt"), "w") as f:
            f.write("root\n")
        with mock.patch.object(mutants, "M", [("K", "target.py", "VALUE = 1\n", "VALUE = 2\n")]), \
                mock.patch.object(mutants, "IDENTITY", ("IDENTITY", "target.py", "VALUE = 1\n", "VALUE = 9\n")):
            self.assertEqual(self.quiet_run(["K"]), 3)

    def test_run_exits_1_on_bad_or_timeout_and_0_on_kills_only(self):
        ident = ("IDENTITY", "target.py", "VALUE = 1\n", "VALUE = 1\n")
        with mock.patch.object(mutants, "IDENTITY", ident):
            with mock.patch.object(mutants, "M", [("K", "target.py", "VALUE = 1\n", "VALUE = 2\n")]):
                self.assertEqual(self.quiet_run(["K"]), 0)
            with mock.patch.object(mutants, "M", [("B", "target.py", "VALUE = 1\n", "VALUE = (\n")]):
                self.assertEqual(self.quiet_run(["B"]), 1)


if __name__ == "__main__":
    unittest.main()
