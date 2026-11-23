"""vm_place: one root's files placed under the agent account's home, run in-process on the shipped module against a
temporary HOME (its real ancestors from / are walked too, as vm_dirs' tests do)."""

import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import a2fix  # noqa: F401  (puts install/ on sys.path)
import vm_place as vp

ME = os.geteuid()
D, F, X = 0o40755, 0o100644, 0o100755
SET = [("bin", D, None), ("bin/tool", X, b"#!/bin/sh\n"), ("a.json", F, b"{}\n"), ("bin/lib", D, None),
       ("bin/lib/m.py", F, b"x = 1\n")]


class PlaceTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="a2place-")
        self.addCleanup(shutil.rmtree, self.d, True)
        os.chmod(self.d, 0o755)
        self.home = os.path.join(self.d, "agent")
        os.mkdir(self.home, 0o750)

    def run_place(self, entries=SET, root=".r/sub", exact=True):
        try:
            return vp.place(self.home, root, vp.parse(vp.encode(entries)), ME, exact)
        except vp.Stop as e:
            return e.code

    def p(self, rel, root=".r/sub"):
        return os.path.join(self.home, root, rel)

    def test_places_each_with_its_mode_then_same(self):
        self.assertEqual(self.run_place(), [(p, "PLACED") for p, _, _ in SET])
        for path, mode, body in SET:
            st = os.lstat(self.p(path))
            self.assertEqual(st.st_mode, mode, path)
            if body is not None:
                with open(self.p(path), "rb") as f:
                    self.assertEqual(f.read(), body)
        for rel in (".r", ".r/sub"):
            self.assertEqual(stat.S_IMODE(os.lstat(os.path.join(self.home, rel)).st_mode), 0o755)
        self.assertEqual(self.run_place(), [(p, "SAME") for p, _, _ in SET])

    def test_a_partial_earlier_run_places_the_rest(self):
        self.run_place(SET[:2])
        self.assertEqual(self.run_place(), [("bin", "SAME"), ("bin/tool", "SAME"), ("a.json", "PLACED"),
                                            ("bin/lib", "PLACED"), ("bin/lib/m.py", "PLACED")])

    def test_different_bytes_refuse_and_nothing_is_written(self):
        self.run_place([("a.json", F, b"{}\n")])
        other = [("z.json", F, b"1\n"), ("a.json", F, b"[]\n")]
        self.assertEqual(self.run_place(other, exact=False), vp.DIFFERENT)
        self.assertFalse(os.path.lexists(self.p("z.json")))
        with open(self.p("a.json"), "rb") as f:
            self.assertEqual(f.read(), b"{}\n")

    def test_a_different_mode_refuses(self):
        self.run_place([("a.json", F, b"{}\n")])
        os.chmod(self.p("a.json"), 0o600)
        self.assertEqual(self.run_place([("a.json", F, b"{}\n")]), vp.DIFFERENT)

    def test_a_different_directory_mode_refuses(self):
        self.run_place(SET[:1])
        os.chmod(self.p("bin"), 0o700)
        self.assertEqual(self.run_place(SET[:1]), vp.DIFFERENT)

    def test_a_file_where_a_directory_belongs_refuses(self):
        os.makedirs(os.path.join(self.home, ".r/sub"))
        with open(self.p("bin"), "wb") as f:
            f.write(b"")
        self.assertEqual(self.run_place(exact=False), vp.DIFFERENT)

    def test_a_symlink_in_place_of_a_file_refuses(self):
        os.makedirs(os.path.join(self.home, ".r/sub"))
        with open(os.path.join(self.d, "elsewhere"), "wb") as f:
            f.write(b"{}\n")
        os.symlink(os.path.join(self.d, "elsewhere"), self.p("a.json"))
        self.assertEqual(self.run_place([("a.json", F, b"{}\n")], exact=False), vp.DIFFERENT)

    def test_an_extra_refuses_in_exact_and_is_left_in_subset(self):
        self.run_place([("a.json", F, b"{}\n")])
        with open(self.p("extra"), "wb") as f:
            f.write(b"x")
        self.assertEqual(self.run_place([("a.json", F, b"{}\n")], exact=True), vp.DIFFERENT)
        self.assertEqual(self.run_place([("a.json", F, b"{}\n")], exact=False), [("a.json", "SAME")])
        self.assertTrue(os.path.exists(self.p("extra")))

    def test_an_extra_inside_a_placed_directory_refuses_in_exact(self):
        self.run_place()
        with open(self.p("bin/lib/extra.py"), "wb") as f:
            f.write(b"")
        self.assertEqual(self.run_place(), vp.DIFFERENT)

    def test_a_leftover_temporary_refuses_in_either_mode(self):
        self.run_place([("a.json", F, b"{}\n")])
        with open(self.p(vp.TMP_PREFIX + "a.json"), "wb") as f:
            f.write(b"")
        for exact in (True, False):
            self.assertEqual(self.run_place([("a.json", F, b"{}\n")], exact=exact), vp.DIFFERENT)

    def test_a_root_not_owned_or_writable_by_others_refuses(self):
        os.makedirs(os.path.join(self.home, ".r/sub"))
        os.chmod(os.path.join(self.home, ".r"), 0o775)
        self.assertEqual(self.run_place(), vp.NOT_ALLOWED)
        self.assertFalse(os.path.lexists(self.p("a.json")))

    def test_a_present_root_owned_by_another_refuses(self):
        os.makedirs(os.path.join(self.home, ".r/sub"))
        real = os.stat

        def other(path, *a, **k):
            st = real(path, *a, **k)
            if path == "sub":
                return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, ME + 1) + tuple(st)[5:])
            return st
        with mock.patch.object(vp, "_stat", other):
            self.assertEqual(self.run_place(), vp.NOT_ALLOWED)

    def test_an_entry_owned_by_another_refuses(self):
        self.run_place([("a.json", F, b"{}\n")])
        real = os.stat

        def other(path, *a, **k):
            st = real(path, *a, **k)
            if path == "a.json":
                return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, ME + 1) + tuple(st)[5:])
            return st
        with mock.patch.object(vp, "_stat", other):
            self.assertEqual(self.run_place([("a.json", F, b"{}\n")]), vp.NOT_ALLOWED)

    def test_a_file_whose_open_shows_another_owner_refuses_not_allowed(self):
        self.run_place([("a.json", F, b"{}\n")])
        real = os.fstat

        def other(fd):
            st = real(fd)
            if stat.S_ISREG(st.st_mode):
                return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, ME + 1) + tuple(st)[5:])
            return st
        with mock.patch.object(vp, "_fstat", other):
            self.assertEqual(self.run_place([("a.json", F, b"{}\n")]), vp.NOT_ALLOWED)

    def test_the_two_codes_differ(self):
        self.assertEqual((vp.DIFFERENT, vp.NOT_ALLOWED), (3, 4))

    def test_an_untrusted_home_ancestor_refuses(self):
        os.chmod(self.d, 0o777)
        self.assertEqual(self.run_place(), vp.NOT_ALLOWED)

    def test_a_readback_mismatch_refuses(self):
        real = vp._read_at
        calls = []

        def lying(dfd, name):
            got, st = real(dfd, name)
            calls.append(name)
            return got + b"!", st
        with mock.patch.object(vp, "_read_at", lying):
            self.assertEqual(self.run_place([("a.json", F, b"{}\n")]), vp.READBACK)
        self.assertEqual(calls, ["a.json"])


class ParseTest(unittest.TestCase):
    def bad(self, data):
        with self.assertRaises(vp.Stop) as c:
            vp.parse(data)
        self.assertEqual(c.exception.code, vp.USAGE)

    def test_round_trip(self):
        got = vp.parse(vp.encode(SET))
        self.assertEqual([("/".join(p), m, b) for p, m, b in got], SET)

    def test_a_wrong_sha_refuses(self):
        data = bytearray(vp.encode([("a", F, b"abc")]))
        data[-1] ^= 1
        self.bad(bytes(data))

    def test_trailing_or_short_bytes_refuse(self):
        data = vp.encode([("a", F, b"abc")])
        self.bad(data + b"x")
        self.bad(data[:-1])
        self.bad(b"\0" * 4)

    def test_a_parent_must_come_first_and_be_a_directory(self):
        self.bad(vp.encode([("d/a", F, b"")]))
        self.bad(vp.encode([("d", F, b""), ("d/a", F, b"")]))

    def test_bad_paths_modes_and_duplicates_refuse(self):
        for path in ("", "..", "a/../b", "/a", "a//b", ".", "a/./b", vp.TMP_PREFIX + "x", "a b"):
            with self.subTest(path=path):
                self.bad(vp.encode([(path, F, b"")]))
        for mode in (0o100666, 0o100777, 0o40777, 0o120777, 0o644):
            with self.subTest(mode=mode):
                self.bad(vp.encode([("a", mode, b"" if mode != 0o40777 else None)]))
        self.bad(vp.encode([("a", F, b""), ("a", F, b"")]))

    def test_a_directory_with_bytes_refuses(self):
        h = b'[{"path":"d","mode":16877,"size":0,"sha256":"' + b"0" * 64 + b'"}]'
        self.bad(len(h).to_bytes(8, "big") + h)

    def test_extra_header_keys_refuse(self):
        h = b'[{"path":"d","mode":16877,"size":0,"sha256":null,"x":1}]'
        self.bad(len(h).to_bytes(8, "big") + h)


class MainTest(unittest.TestCase):
    def test_usage(self):
        for argv in ([], [".r"], [".r", "all"], ["../r", "exact"]):
            with self.subTest(argv=argv), mock.patch.object(vp, "_stdin", lambda: vp.encode(SET)):
                self.assertEqual(vp.main(argv), vp.USAGE)

    def test_runs_as_the_launcher_runs_it(self):
        d = tempfile.mkdtemp(prefix="a2place-")
        self.addCleanup(shutil.rmtree, d, True)
        os.chmod(d, 0o755)
        with open(vp.__file__, "rb") as f:
            src = f.read()
        p = subprocess.run([sys.executable, "-I", "-S", "-c", src, ".r", "exact"], input=vp.encode(SET),
                           capture_output=True, env={"HOME": d}, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.decode(), "".join("PLACED %s\n" % path for path, _, _ in SET))


if __name__ == "__main__":
    unittest.main()
