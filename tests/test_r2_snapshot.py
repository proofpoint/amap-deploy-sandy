"""R2's state snapshot and its restore (TUTORIAL, R2 step 5 and back-out
R), executed: each row runs the runbook's OWN shell block, taken from the
TUTORIAL with only its value lines filled in, against a staged state_dir
and instance lanes, with a stub docker that answers whether the old router
runs. The staged tree has the shape the router's state_dir has (per
instance first-seen.json, results/, delivered/, quarantine/, pending/,
audit/; .router.lock and status.json at the top)."""

import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RUNBOOK = Path(__file__).absolute().parents[1] / "docs" / "TUTORIAL.md"
GNU = shutil.which("tar") and subprocess.run(["tar", "--version"], capture_output=True, text=True).stdout.startswith(
    "tar (GNU tar)")


def block(marker):
    """The fenced sh block of the runbook that names `marker`, de-indented."""
    text = RUNBOOK.read_text()
    for m in re.finditer(r"( *)```sh\n(.*?)\n *```", text, re.S):
        if marker in m.group(2):
            pad = len(m.group(1))
            return "\n".join(l[pad:] for l in m.group(2).split("\n"))
    raise AssertionError(f"no runbook block names {marker}")


def fill(text, **values):
    """Replace each `NAME='<…>'` assignment with the row's value."""
    for name, value in values.items():
        text, n = re.subn(rf"\b{name}='<[^>]*>'", f"{name}='{value}'", text)
        assert n == 1, (name, n)
    assert "'<" not in text, "a value left unfilled"
    return text


def tree(root):
    """Every entry under `root`: its relative path, type, mode and bytes."""
    out = {}
    for dirpath, dirs, files in os.walk(root):
        for name in dirs + files:
            p = os.path.join(dirpath, name)
            st = os.lstat(p)
            rel = os.path.relpath(p, root)
            data = open(p, "rb").read() if stat.S_ISREG(st.st_mode) else None
            out[rel] = (stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode), data)
    return out


@unittest.skipUnless(GNU, "the runbook's blocks are written for GNU tar and coreutils (a Linux host)")
class R2Snapshot(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.d = os.path.realpath(t.name)
        self.st = os.path.join(self.d, "state")
        self.inst = os.path.join(self.d, "instances")
        self.bk = os.path.join(self.d, "backup", "r2-snap")
        os.makedirs(os.path.join(self.d, "backup"))
        os.makedirs(self.st, 0o755)
        for name in ("alpha", "beta"):
            base = os.path.join(self.st, name)
            for sub in ("results", "delivered", "quarantine", "pending", "audit"):
                os.makedirs(os.path.join(base, sub))
            self.put(os.path.join(base, "first-seen.json"), b'{"first_seen": "2026-10-01T00:00:00Z"}\n')
            self.put(os.path.join(base, "results", "r1.json"), b'{"verdict": "accepted"}\n')
            self.put(os.path.join(base, "delivered", "n1.json"), b'{"notice": "n1"}\n')
            os.makedirs(os.path.join(self.inst, name, "outbox"))
            self.put(os.path.join(self.inst, name, "outbox", "req-0.json"), b'{"waiting": true}\n')
        self.put(os.path.join(self.st, ".router.lock"), b"")
        self.put(os.path.join(self.st, "status.json"), b'{"interval_s": 5}\n')
        self.bin = os.path.join(self.d, "bin")
        os.mkdir(self.bin)
        self.running("false")

    @staticmethod
    def put(path, data, mode=0o600):
        with open(path, "wb") as f:
            f.write(data)
        os.chmod(path, mode)

    def running(self, answer):
        self.put(os.path.join(self.bin, "docker"),
                 f"#!/bin/sh\n[ \"$1\" = inspect ] && {{ echo {answer}; exit 0; }}\nexit 9\n".encode(), 0o755)

    def sh(self, text):
        return subprocess.run(["/bin/sh", "-c", text], capture_output=True, text=True, timeout=60,
                              env={"PATH": f"{self.bin}:/usr/bin:/bin", "LC_ALL": "C"})

    def snapshot(self, bk=None):
        return self.sh(fill(block("r2-snapshot: STOP"), ST=self.st, INST=self.inst, BK=bk or self.bk,
                            OLD="0123abcd"))

    def restore(self, aside):
        return self.sh(fill(block("r2-restore: STOP"), ST=self.st, INST=self.inst, BK=self.bk, ASIDE=aside))

    def test_the_snapshot_is_the_whole_state_dir_private_and_read_back(self):
        p = self.snapshot()
        self.assertEqual(p.returncode, 0, p.stderr)
        tar = os.path.join(self.bk, "r2-state.tar")
        self.assertEqual(stat.S_IMODE(os.stat(self.bk).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(tar).st_mode), 0o600)
        data = open(tar, "rb").read()
        self.assertEqual(p.stdout.strip(),
                         f"r2-snapshot: OK {len(data)} bytes {hashlib.sha256(data).hexdigest()} {tar}")
        listed = subprocess.run(["tar", "-tf", tar], capture_output=True, text=True, check=True).stdout.split()
        for want in ("./.router.lock", "./status.json", "./alpha/first-seen.json", "./beta/delivered/n1.json"):
            self.assertIn(want, listed)
        self.assertFalse([e for e in listed if "outbox" in e], "the lanes are never in it")

    def test_an_existing_target_is_refused_and_never_added_to(self):
        os.mkdir(self.bk, 0o700)
        p = self.snapshot()
        self.assertEqual(p.returncode, 1)
        self.assertIn("already exists", p.stderr)
        self.assertEqual(os.listdir(self.bk), [])

    def test_a_target_under_state_dir_or_instances_dir_is_refused(self):
        for bk in (os.path.join(self.st, "snap"), os.path.join(self.inst, "snap")):
            with self.subTest(bk=bk):
                p = self.snapshot(bk)
                self.assertEqual(p.returncode, 1)
                self.assertIn("lies under state_dir or instances_dir", p.stderr)
                self.assertFalse(os.path.exists(bk))

    def test_a_running_old_router_is_refused_before_anything_is_made(self):
        self.running("true")
        p = self.snapshot()
        self.assertEqual(p.returncode, 1)
        self.assertIn("not shown stopped", p.stderr)
        self.assertFalse(os.path.exists(self.bk))

    def test_a_write_to_state_dir_during_the_tar_is_refused(self):
        real = shutil.which("tar")
        self.put(os.path.join(self.bin, "tar"),
                 (f"#!/bin/sh\ncase \"$1\" in --numeric-owner) printf x >> '{self.st}/status.json' ;; esac\n"
                  f"exec {real} \"$@\"\n").encode(), 0o755)
        p = self.snapshot()
        self.assertEqual(p.returncode, 1)
        self.assertIn("changed during the tar", p.stderr)

    def test_the_snapshot_comes_before_the_baseline_and_any_move(self):
        text = RUNBOOK.read_text()
        snap = text.index("**The state snapshot**")
        self.assertLess(text.index("5. **The window opens.**"), snap)
        self.assertLess(snap, text.index("python3 amap-sandy.py router-migrate baseline --preview"))
        self.assertLess(snap, text.index("7. **Move.**"))

    def test_the_restore_brings_back_the_stop_time_state_and_keeps_what_it_replaced(self):
        before = tree(self.st)
        self.assertEqual(self.snapshot().returncode, 0)
        lanes = tree(self.inst)
        # The migration as R2 makes it: alpha moved to its logical id and adopted, the router run.
        os.rename(os.path.join(self.st, "alpha"), os.path.join(self.st, "lid-alpha"))
        self.put(os.path.join(self.st, "lid-alpha", "migration.json"), b'{"gen": 1}\n')
        self.put(os.path.join(self.st, "status.json"), b'{"interval_s": 5, "new": true}\n')
        self.put(os.path.join(self.inst, "beta", "outbox", "req-1.json"), b'{"after": true}\n')
        lanes_now = tree(self.inst)
        aside = os.path.join(self.d, "backup", "aside")
        p = self.restore(aside)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(tree(self.st), before, "the stop-time state, byte for byte, with its modes")
        self.assertIn("lid-alpha", os.listdir(aside), "what it replaced is kept, outside state_dir")
        self.assertTrue(os.path.exists(os.path.join(aside, "lid-alpha", "migration.json")))
        self.assertEqual(tree(self.inst), lanes_now, "the lanes are never touched")
        self.assertNotEqual(lanes_now, lanes)

    def test_the_restore_refuses_a_changed_snapshot_and_an_existing_or_inner_aside(self):
        self.assertEqual(self.snapshot().returncode, 0)
        state = tree(self.st)
        for name, aside, words in (("existing", os.path.join(self.d, "backup"), "already exists"),
                                   ("inner", os.path.join(self.st, "aside"), "lies under state_dir")):
            with self.subTest(name=name):
                p = self.restore(aside)
                self.assertEqual(p.returncode, 1)
                self.assertIn(words, p.stderr)
                self.assertEqual(tree(self.st), state, "nothing moved")
        tar = os.path.join(self.bk, "r2-state.tar")
        os.chmod(tar, 0o600)
        with open(tar, "ab") as f:
            f.write(b"\0" * 512)
        p = self.restore(os.path.join(self.d, "backup", "aside"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("not the recorded one", p.stderr)
        self.assertEqual(tree(self.st), state)


if __name__ == "__main__":
    unittest.main()
