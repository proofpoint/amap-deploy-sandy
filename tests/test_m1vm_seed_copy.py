"""m1vm/seed_copy.py (m1-seed-copy): the copy, its idempotence, and each
refusal proven to fire on a seed built for it, run as the shipped program."""

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock

M1VM = Path(__file__).resolve().parent.parent / "m1vm"
PROGRAM = M1VM / "seed_copy.py"
sys.path.insert(0, str(M1VM))
import seed_copy  # noqa: E402

# The seed as `sandy --build-only` leaves it: hash dotfiles plus build files
# that must NOT move (the names follow REPORTED sandy a010af93; contents are
# stand-ins).
SEED_FILES = {
    ".base_build_hash": (b"base-1\n", 0o644),
    ".build_hash_claude": (b"claude-1\n", 0o644),
    ".skills_core_build_hash": (b"skills-1\n", 0o600),
    ".skill_version_core": (b"3\n", 0o644),
    "sandboxes/m1-one/.project_build_hash": (b"proj-1\n", 0o644),
}
NOT_HDOT = {"Dockerfile.base": b"FROM x\n", "sandboxes/m1-one/workspace.json": b"{}\n"}


@unittest.skipIf(os.geteuid() == 0, "m1-seed-copy refuses to run as root")
class SeedCopyCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.src = self.tmp / "sandy-seed"
        self.dst = self.tmp / "data/sandy"
        self.dst.mkdir(parents=True)
        (self.src / "sandboxes/m1-one").mkdir(parents=True)
        os.chmod(self.src / "sandboxes", 0o755)
        os.chmod(self.src / "sandboxes/m1-one", 0o775)  # wider than umask 022 allows
        for name, (data, mode) in SEED_FILES.items():
            p = self.src / name
            p.write_bytes(data)
            os.chmod(p, mode)
        for name, data in NOT_HDOT.items():
            (self.src / name).write_bytes(data)
        self.man = self.tmp / "MAN.json"
        self.write_man(self.hdot())

    def hdot(self):
        return [{"name": n, "mode": f"{m:04o}", "sha256": hashlib.sha256(d).hexdigest()}
                for n, (d, m) in sorted(SEED_FILES.items())]

    def write_man(self, hdot, **extra):
        doc = {"schema": "m1vm-man/1", "hdot": hdot, **extra}
        self.man.write_text(json.dumps(doc))

    def run_prog(self, *extra, args=None):
        argv = args if args is not None else ["--man", str(self.man), "--src", str(self.src), "--dst", str(self.dst)]
        return subprocess.run([sys.executable, "-I", "-S", "-B", str(PROGRAM), *argv, *extra],
                              capture_output=True, text=True)

    def assert_refused(self, needle):
        before = sorted(str(p.relative_to(self.dst)) for p in self.dst.rglob("*"))
        r = self.run_prog()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn(needle, r.stderr)
        self.assertNotIn("M1-SEED-COPY PASS", r.stdout)
        after = sorted(str(p.relative_to(self.dst)) for p in self.dst.rglob("*"))
        self.assertEqual(after, before, "a refusal wrote something")


class CopyTest(SeedCopyCase):
    def test_copies_exactly_hdot_with_modes(self):
        r = self.run_prog()
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = r.stdout.splitlines()
        man_sha = hashlib.sha256(self.man.read_bytes()).hexdigest()
        self.assertEqual(lines[-1], f"M1-SEED-COPY PASS n={len(SEED_FILES)} man={man_sha}")
        self.assertEqual(len(lines), len(SEED_FILES) + 1)
        for name, (data, mode) in SEED_FILES.items():
            p = self.dst / name
            self.assertEqual(p.read_bytes(), data)
            self.assertEqual(os.stat(p).st_mode & 0o7777, mode, name)
        for name in NOT_HDOT:
            self.assertFalse((self.dst / name).exists(), name)
        self.assertEqual(os.stat(self.dst / "sandboxes/m1-one").st_mode & 0o7777, 0o775)
        self.assertEqual(sorted(p.name for p in self.dst.rglob("*.tmp")), [])

    def test_second_run_is_present_not_copied(self):
        self.assertEqual(self.run_prog().returncode, 0)
        r = self.run_prog()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(all(l.endswith(" present") for l in r.stdout.splitlines()[:-1]))

    def test_line_form(self):
        r = self.run_prog()
        first = r.stdout.splitlines()[0]
        name = sorted(SEED_FILES)[0]
        data, mode = SEED_FILES[name]
        self.assertEqual(first, f"SEED {name} mode={mode:04o} sha256={hashlib.sha256(data).hexdigest()} copied")


class RefusalTest(SeedCopyCase):
    def test_missing_entry(self):
        (self.src / ".skill_version_core").unlink()
        self.assert_refused(".skill_version_core: absent from the seed")

    def test_extra_hash_dotfile_in_seed(self):
        (self.src / ".build_hash_codex").write_bytes(b"x\n")
        self.assert_refused("MAN does not list: '.build_hash_codex'")

    def test_extra_project_hash_in_seed(self):
        (self.src / "sandboxes/m1-two").mkdir()
        (self.src / "sandboxes/m1-two/.project_build_hash").write_bytes(b"x\n")
        self.assert_refused("sandboxes/m1-two/.project_build_hash")

    def test_sha_mismatch(self):
        (self.src / ".base_build_hash").write_bytes(b"tampered\n")
        self.assert_refused("sha256 differs from MAN's")

    def test_mode_mismatch(self):
        os.chmod(self.src / ".base_build_hash", 0o600)
        self.assert_refused("mode 0600 differs from MAN's 0644")

    def test_symlink_source(self):
        p = self.src / ".base_build_hash"
        real = self.tmp / "elsewhere"
        real.write_bytes(p.read_bytes())
        p.unlink()
        os.symlink(real, p)
        self.assert_refused(".base_build_hash: a symbolic link")

    def test_symlinked_sandbox_dir(self):
        moved = self.tmp / "moved"
        shutil.move(str(self.src / "sandboxes/m1-one"), moved)
        os.symlink(moved, self.src / "sandboxes/m1-one")
        self.assert_refused("not a plain directory")

    def test_hardlinked_source(self):
        os.link(self.src / ".base_build_hash", self.tmp / "second-name")
        self.assert_refused("2 links, not one")

    def test_different_destination_file(self):
        (self.dst / ".base_build_hash").write_bytes(b"other\n")
        self.assert_refused("already holds a different file")

    def test_missing_dst(self):
        shutil.rmtree(self.dst)
        r = self.run_prog()
        self.assertEqual(r.returncode, 1)
        self.assertIn("--dst", r.stderr)
        self.assertFalse(self.dst.exists())

    def test_dst_not_a_directory(self):
        shutil.rmtree(self.dst)
        self.dst.write_bytes(b"")
        r = self.run_prog()
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("--dst", r.stderr)

    def test_off_pattern_slug_holding_a_project_hash(self):
        (self.src / "sandboxes/_odd").mkdir()
        (self.src / "sandboxes/_odd/.project_build_hash").write_bytes(b"x\n")
        self.assert_refused("sandboxes/_odd/.project_build_hash")

    def test_symlinked_slug_dir(self):
        other = self.tmp / "other-slug"
        other.mkdir()
        (other / ".project_build_hash").write_bytes(b"x\n")
        os.symlink(other, self.src / "sandboxes/m1-two")
        self.assert_refused("sandboxes/'m1-two' is not a plain directory")

    def test_file_in_sandboxes(self):
        (self.src / "sandboxes/stray").write_bytes(b"")
        self.assert_refused("sandboxes/'stray' is not a plain directory")

    def test_fifo_and_dir_seed_entries(self):
        for make in (lambda p: os.mkfifo(p), lambda p: p.mkdir()):
            with self.subTest(make):
                self.setUp()
                p = self.src / ".base_build_hash"
                p.unlink()
                make(p)
                self.assert_refused(".base_build_hash: not a regular file")

    def test_extra_hash_dotfile_already_in_destination(self):
        (self.dst / ".build_hash_codex").write_bytes(b"x\n")
        self.assert_refused("the destination holds hash dotfiles MAN does not list")

    def test_extra_project_hash_already_in_destination(self):
        (self.dst / "sandboxes/m1-two").mkdir(parents=True)
        (self.dst / "sandboxes/m1-two/.project_build_hash").write_bytes(b"x\n")
        self.assert_refused("sandboxes/m1-two/.project_build_hash")

    def test_identical_bytes_other_mode_in_destination(self):
        name = ".base_build_hash"
        (self.dst / name).write_bytes(SEED_FILES[name][0])
        os.chmod(self.dst / name, 0o600)
        self.assert_refused("already holds a different file")

    def test_ancestor_symlinks_refused(self):
        for which in ("src", "dst", "man"):
            with self.subTest(which):
                self.setUp()
                target = {"src": self.src, "dst": self.dst, "man": self.man}[which]
                real_parent = self.tmp / f"real-{which}"
                link_parent = self.tmp / f"link-{which}"
                real_parent.mkdir()
                shutil.move(str(target), real_parent / target.name)
                os.symlink(real_parent, link_parent)
                path = str(link_parent / target.name)
                args = {"man": str(self.man), "src": str(self.src), "dst": str(self.dst)}
                args[which] = path
                r = self.run_prog(args=["--man", args["man"], "--src", args["src"], "--dst", args["dst"]])
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("is not a plain directory", r.stderr)
                self.assertNotIn("M1-SEED-COPY PASS", r.stdout)

    def test_absent_man_parent_is_refused_not_internal(self):
        r = self.run_prog(args=["--man", str(self.tmp / "nope/MAN.json"), "--src", str(self.src),
                                "--dst", str(self.dst)])
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("absent", r.stderr)

    def test_man_shapes(self):
        bad = {
            "schema": lambda: self.man.write_text(json.dumps({"schema": "m1vm-man/0", "hdot": self.hdot()})),
            "empty": lambda: self.write_man([]),
            "non-hdot name": lambda: self.write_man(self.hdot() + [{"name": "Dockerfile.base", "mode": "0644",
                                                                    "sha256": "0" * 64}]),
            "traversal": lambda: self.write_man([{"name": "sandboxes/../x/.project_build_hash", "mode": "0644",
                                                  "sha256": "0" * 64}]),
            "duplicate": lambda: self.write_man(self.hdot() + self.hdot()[:1]),
            "mode form": lambda: self.write_man([dict(self.hdot()[0], mode="644")]),
            "extra key": lambda: self.write_man([dict(self.hdot()[0], owner="x")]),
            "not json": lambda: self.man.write_text("{"),
            "duplicate key": lambda: self.man.write_text(
                '{"schema": "m1vm-man/1", "hdot": [], "hdot": ' + json.dumps(self.hdot()) + '}'),
            "newline name": lambda: self.write_man([dict(self.hdot()[0], name=".build_hash\nSEED x")]),
        }
        for name, brk in bad.items():
            with self.subTest(name):
                self.write_man(self.hdot())
                brk()
                self.assert_refused("REFUSE MAN:")


class InProcessCase(SeedCopyCase):
    def main(self):
        argv = ["--man", str(self.man), "--src", str(self.src), "--dst", str(self.dst)]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = seed_copy.main(argv)
        return rc, out.getvalue(), err.getvalue()


class OwnerTest(InProcessCase):
    def test_destination_root_owned_by_another_account(self):
        real = os.geteuid()
        with mock.patch.object(seed_copy, "_euid", lambda: real + 1):
            rc, out, err = self.main()
        self.assertEqual(rc, 1)
        self.assertIn("the destination: owned by uid", err)

    def test_identical_copy_owned_by_another_account(self):
        name = ".base_build_hash"
        (self.dst / name).write_bytes(SEED_FILES[name][0])
        os.chmod(self.dst / name, SEED_FILES[name][1])
        real_read = seed_copy._read_regular
        calls = {}

        def read(dir_fd, n, limit):
            got = real_read(dir_fd, n, limit)
            calls[n] = calls.get(n, 0) + 1
            if n == name and calls[n] == 2 and got is not None:  # the destination's copy
                return got[0], got[1], got[2] + 1
            return got
        with mock.patch.object(seed_copy, "_read_regular", read):
            rc, out, err = self.main()
        self.assertEqual(rc, 1)
        self.assertIn("copy is owned by uid", err)


    def test_destination_sandbox_dir_owned_by_another_account(self):
        (self.dst / "sandboxes/m1-one").mkdir(parents=True)
        ino = os.stat(self.dst / "sandboxes/m1-one").st_ino
        real_fstat = os.fstat

        def fstat(fd):
            st = real_fstat(fd)
            if st.st_ino == ino:
                return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid + 1,
                                       st.st_gid, st.st_size, 0, 0, 0))
            return st
        with mock.patch.object(seed_copy.os, "fstat", fstat):
            rc, out, err = self.main()
        self.assertEqual(rc, 1)
        self.assertIn("sandboxes/m1-one/ in the destination: owned by uid", err)


    def test_destination_sandboxes_dir_owned_by_another_account(self):
        (self.dst / "sandboxes").mkdir()
        ino = os.stat(self.dst / "sandboxes").st_ino
        real_fstat = os.fstat

        def fstat(fd):
            st = real_fstat(fd)
            if st.st_ino == ino:
                return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid + 1,
                                       st.st_gid, st.st_size, 0, 0, 0))
            return st
        with mock.patch.object(seed_copy.os, "fstat", fstat):
            rc, out, err = self.main()
        self.assertEqual(rc, 1)
        self.assertIn("sandboxes/ in the destination: owned by uid", err)


class FaultTest(InProcessCase):
    def test_failure_mid_write_leaves_a_prefix_and_reruns_clean(self):
        real_rename = os.rename
        count = {"n": 0}

        def rename(*a, **k):
            count["n"] += 1
            if count["n"] == 3:
                raise OSError(28, "No space left on device")
            return real_rename(*a, **k)
        with mock.patch.object(seed_copy.os, "rename", rename):
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                with self.assertRaises(OSError):
                    seed_copy.main(["--man", str(self.man), "--src", str(self.src), "--dst", str(self.dst)])
        self.assertNotIn("PASS", out.getvalue())
        self.assertEqual(out.getvalue(), "")
        done = [n for n in sorted(SEED_FILES) if (self.dst / n).exists()]
        self.assertEqual(done, sorted(SEED_FILES)[:2])
        rc, stdout, err = self.main()
        self.assertEqual(rc, 0, err)
        states = [l.rsplit(" ", 1)[1] for l in stdout.splitlines()[:-1]]
        self.assertEqual(states, ["present", "present", "copied", "copied", "copied"])
        self.assertEqual(sorted(p.name for p in self.dst.rglob("*.tmp")), [])


class UsageTest(SeedCopyCase):
    def test_usage_is_2(self):
        for args in ([], ["--man", "x"], ["--man", str(self.man), "--src", str(self.src), "--dst", str(self.dst),
                                          "--extra", "y"],
                     ["--man", str(self.man), "--man", str(self.man), "--src", str(self.src)]):
            with self.subTest(args):
                self.assertEqual(self.run_prog(args=args).returncode, 2)

    def test_relative_paths_are_usage(self):
        r = self.run_prog(args=["--man", str(self.man), "--src", "rel/seed", "--dst", str(self.dst)])
        self.assertEqual(r.returncode, 2)


class NameTest(unittest.TestCase):
    def test_closed_set(self):
        good = [".base_build_hash", ".build_hash", ".build_hash_x", ".skills_a_build_hash", ".skill_version_a",
                "sandboxes/s1/.project_build_hash"]
        bad = [".base_build_hash2", "x/.base_build_hash", "sandboxes/.project_build_hash",
               "sandboxes/../.project_build_hash", "sandboxes/s1/x/.project_build_hash", ".skills_build",
               "Dockerfile", "sandboxes/s1/.other_hash"]
        for n in good:
            self.assertTrue(seed_copy.is_hdot_name(n), n)
        for n in bad:
            self.assertFalse(seed_copy.is_hdot_name(n), n)


if __name__ == "__main__":
    unittest.main()
