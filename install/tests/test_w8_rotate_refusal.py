"""W8 r4.1: `--rotate-key` through the launcher refuses with RUNNER.ROTATE_UNSUPPORTED
before anything the launcher does after parsing its arguments (Dan
ALPHA2-W8-ROTATE-FALLBACK; Codex W8 r4).

Two surfaces:
- the real entry file as a real process (the pinned loader, the default site);
- a2_main.main in this process on a staged runner host (a2fix.World) that would
  otherwise admit, with a tripwire on every step after the parse: the private-file
  read, the locks, the arm gate, the handoff probe, the usage read, the broker, the
  run directory, the exec and S7's VM layer. A control run of `--verify` through the
  same harness must trip one, which shows the tripwires are live.
"""

import io
import os
import shutil
import unittest
from unittest import mock

import a2fix
import a2_admit
import a2_budget
import a2_locks
import a2_main
import a2_rundir
from test_a2_entry import copy_install, run_entry

CAUSE_LINE = "CAUSE=RUNNER.ROTATE_UNSUPPORTED"


def snapshot(root):
    """Every path under root with its size and mtime: any write shows."""
    out = {}
    for d, dirs, files in os.walk(root):
        for n in dirs + files:
            p = os.path.join(d, n)
            st = os.lstat(p)
            out[os.path.relpath(p, root)] = (st.st_mode, st.st_size, st.st_mtime_ns)
    return out


class Tripped(Exception):
    pass


class LauncherTripwireTest(unittest.TestCase):
    def setUp(self):
        self.base = a2fix.make_base()
        self.addCleanup(shutil.rmtree, self.base, True)
        self.world = a2fix.World(self.base)
        self.tripped = []

    def wire(self, name):
        def trip(*a, **k):
            self.tripped.append(name)
            raise Tripped(name)
        return trip

    def run_main(self, argv):
        site = self.world.site()
        for slot in ("arm_gate", "loop_tasks", "usage_read", "execve", "host_identity",
                     "vm_exec", "vm_write_secret", "vm_install_file"):
            setattr(site, slot, self.wire("site." + slot))
        for name in [n for n in dir(site) if n.startswith("probe_")]:
            setattr(site, name, self.wire("site." + name))
        patches = [mock.patch.object(a2_admit, "_read_private", self.wire("private read")),
                   mock.patch.object(a2_admit, "_handoff_and_usage", self.wire("handoff")),
                   mock.patch.object(a2_budget, "ask_broker", self.wire("broker"))]
        patches += [mock.patch.object(a2_locks, n, self.wire("locks." + n))
                    for n in dir(a2_locks) if callable(getattr(a2_locks, n)) and not n.startswith("_")
                    and getattr(getattr(a2_locks, n), "__module__", None) == "a2_locks"]
        patches += [mock.patch.object(a2_rundir, n, self.wire("rundir." + n))
                    for n in dir(a2_rundir) if callable(getattr(a2_rundir, n)) and not n.startswith("_")
                    and getattr(getattr(a2_rundir, n), "__module__", None) == "a2_rundir"]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        site.out = io.StringIO()
        before = snapshot(self.base)
        rc = a2_main.main(argv, "c" * 64, site.entry, site=site)
        return rc, site.out.getvalue(), snapshot(self.base) == before

    def test_rotate_key_refuses_before_any_launcher_step(self):
        rc, out, unchanged = self.run_main(["--rotate-key"])
        self.assertEqual((rc, out.splitlines()[0]), (2, CAUSE_LINE))
        self.assertEqual(self.tripped, [])
        self.assertTrue(unchanged)  # no run directory, no record, no lock file touched

    def test_control_verify_trips_the_first_wire(self):
        rc, out, unchanged = self.run_main(["--verify"])
        self.assertEqual(self.tripped[:1], ["private read"])
        self.assertNotIn(CAUSE_LINE, out)

    RUNNER = ["--runner", "--run-id", "20261120T190000Z-0123abcd"]

    def test_the_runner_route_refuses_before_any_admission_step(self):  # Opus r4.1 note
        """S0's admission (the runner the launcher would exec) parses before it reads,
        locks or creates the run directory."""
        rc, out, unchanged = self.run_main(self.RUNNER + ["--rotate-key"])
        self.assertEqual((rc, out.splitlines()[0]), (2, CAUSE_LINE))
        self.assertEqual(self.tripped, [])
        self.assertTrue(unchanged)

    def test_control_the_runner_route_with_verify_trips_the_first_wire(self):
        rc, out, unchanged = self.run_main(self.RUNNER + ["--verify"])
        self.assertEqual(self.tripped[:1], ["private read"])
        self.assertNotIn(CAUSE_LINE, out)


class RealEntryTest(unittest.TestCase):
    def test_rotate_key_through_the_entry_file_refuses_first(self):
        base = a2fix.make_base()
        self.addCleanup(shutil.rmtree, base, True)
        inst = os.path.join(base, "install")
        copy_install(inst)
        before = snapshot(base)
        r = run_entry(inst, ["--rotate-key"])
        self.assertEqual((r.returncode, r.stderr.splitlines()[0]), (2, CAUSE_LINE))
        # The same site refuses --verify at its first private read, so the
        # refusal above came before that read.
        self.assertEqual(run_entry(inst, ["--verify"]).stderr.splitlines()[0], "CAUSE=PREFLIGHT.PRIVATE_SOURCE")
        after = {k: v for k, v in snapshot(base).items() if "__pycache__" not in k}
        self.assertEqual(after, {k: v for k, v in before.items() if "__pycache__" not in k})


if __name__ == "__main__":
    unittest.main()
