"""host_steps: the plan's root-run steps, run for real in a temporary tree.

The owner of the overlay and the markers is root; here it is the test's own
uid, so the steps run unprivileged. Every case that matters is a symbolic
link or a non-directory planted where the plan expects a directory: the step
must stop, and nothing beyond the link may change.
"""

import hashlib
import os
import stat
import tempfile
import unittest

import host_steps as st


class Tree(unittest.TestCase):

    def setUp(self):
        self.t = os.path.realpath(tempfile.mkdtemp())
        self.uid, self.gid = os.getuid(), os.getgid()
        orig = (st.OWNER_UID, st.OWNER_GID)
        st.OWNER_UID, st.OWNER_GID = self.uid, self.gid
        self.addCleanup(lambda: (setattr(st, "OWNER_UID", orig[0]), setattr(st, "OWNER_GID", orig[1])))

    def p(self, *parts):
        return os.path.join(self.t, *parts)

    def mode(self, path):
        return stat.S_IMODE(os.lstat(path).st_mode)


class RootTest(Tree):

    def test_a_root_is_created_with_its_mode(self):
        os.mkdir(self.p("a"))
        st.root(self.p("a", "b"), self.uid, self.gid, 0o2750)
        self.assertTrue(stat.S_ISDIR(os.lstat(self.p("a", "b")).st_mode))
        self.assertEqual(self.mode(self.p("a", "b")), 0o2750)

    def test_running_it_again_fixes_the_mode(self):
        os.mkdir(self.p("a"))
        os.mkdir(self.p("a", "b"), 0o777)
        os.chmod(self.p("a", "b"), 0o777)
        st.root(self.p("a", "b"), self.uid, self.gid, 0o750)
        self.assertEqual(self.mode(self.p("a", "b")), 0o750)

    def test_a_symlink_at_the_root_path_is_refused_and_its_target_untouched(self):
        os.mkdir(self.p("target"), 0o777)
        os.chmod(self.p("target"), 0o777)
        os.symlink(self.p("target"), self.p("root"))
        with self.assertRaises(st.StepError):
            st.root(self.p("root"), self.uid, self.gid, 0o700)
        self.assertEqual(self.mode(self.p("target")), 0o777)

    def test_a_symlinked_ancestor_is_refused_and_nothing_is_made_beneath_it(self):
        os.mkdir(self.p("elsewhere"))
        os.symlink(self.p("elsewhere"), self.p("a"))
        with self.assertRaises(st.StepError) as e:
            st.root(self.p("a", "b"), self.uid, self.gid, 0o700)
        self.assertIn(self.p("a"), str(e.exception))
        self.assertEqual(os.listdir(self.p("elsewhere")), [])

    def test_an_existing_file_at_the_root_path_is_refused(self):
        open(self.p("f"), "w").close()
        with self.assertRaises(st.StepError):
            st.root(self.p("f"), self.uid, self.gid, 0o700)
        self.assertTrue(stat.S_ISREG(os.lstat(self.p("f")).st_mode))

    def test_a_foreign_non_empty_root_is_not_re_owned(self):
        os.mkdir(self.p("r"))
        open(self.p("r", "f"), "w").close()
        os.chmod(self.p("r"), 0o777)
        with self.assertRaises(st.StepError) as e:
            st.root(self.p("r"), self.uid, self.gid + 1, 0o700)
        self.assertIn("not re-owned", str(e.exception))
        self.assertEqual(self.mode(self.p("r")), 0o777)

    def test_a_relative_or_unnormalised_path_is_refused(self):
        for bad in ("rel/x", self.t + "/a/../b", "//x"):
            with self.subTest(bad=bad), self.assertRaises(st.StepError):
                st.root(bad, self.uid, self.gid, 0o700)


class SyncTest(Tree):

    def test_directories_are_synced(self):
        os.mkdir(self.p("a"))
        st.sync(self.t, self.p("a"))

    def test_a_symlink_is_not_followed(self):
        os.mkdir(self.p("a"))
        os.symlink(self.p("a"), self.p("l"))
        with self.assertRaises(st.StepError):
            st.sync(self.p("l"))


class PlaceTest(Tree):

    def test_the_overlay_is_placed_read_only(self):
        src = self.p("src.py")
        with open(src, "w") as f:
            f.write("x = 1\n")
        os.mkdir(self.p("ov"))
        st.place(src, self.p("ov", "plugin.py"))
        self.assertEqual(open(self.p("ov", "plugin.py")).read(), "x = 1\n")
        self.assertEqual(self.mode(self.p("ov", "plugin.py")), 0o444)
        self.assertEqual(os.listdir(self.p("ov")), ["plugin.py"])

    def test_a_plist_mode_is_0644_and_no_other_mode_is_accepted(self):
        src = self.p("src.plist")
        with open(src, "w") as f:
            f.write("<plist/>\n")
        os.mkdir(self.p("ld"))
        rc = st.main(["place", src, self.p("ld", "x.plist"), "--sha256",
                      hashlib.sha256(b"<plist/>\n").hexdigest(), "--mode", "0644"])
        self.assertEqual(rc, 0)
        self.assertEqual(self.mode(self.p("ld", "x.plist")), 0o644)
        for bad in (0o666, 0o755, 0o600):
            with self.subTest(mode=oct(bad)):
                with self.assertRaises(st.StepError):
                    st.place(src, self.p("ld", "y.plist"), mode=bad)
                self.assertFalse(os.path.exists(self.p("ld", "y.plist")))

    def test_a_symlink_at_the_destination_is_replaced_not_written_through(self):
        src = self.p("src.py")
        with open(src, "w") as f:
            f.write("new\n")
        victim = self.p("victim")
        with open(victim, "w") as f:
            f.write("keep\n")
        os.mkdir(self.p("ov"))
        os.symlink(victim, self.p("ov", "plugin.py"))
        st.place(src, self.p("ov", "plugin.py"))
        self.assertEqual(open(victim).read(), "keep\n")
        self.assertFalse(os.path.islink(self.p("ov", "plugin.py")))
        self.assertEqual(open(self.p("ov", "plugin.py")).read(), "new\n")

    def test_a_symlinked_destination_directory_is_refused(self):
        src = self.p("src.py")
        open(src, "w").close()
        os.mkdir(self.p("elsewhere"))
        os.symlink(self.p("elsewhere"), self.p("ov"))
        with self.assertRaises(st.StepError):
            st.place(src, self.p("ov", "plugin.py"))
        self.assertEqual(os.listdir(self.p("elsewhere")), [])


class MarkerTest(Tree):

    def test_a_marker_is_random_hex_read_only(self):
        os.mkdir(self.p("r"))
        st.marker(self.p("r", ".root-id"))
        text = open(self.p("r", ".root-id")).read()
        self.assertRegex(text, r"\A[0-9a-f]{32}\Z")
        self.assertEqual(self.mode(self.p("r", ".root-id")), 0o444)

    def test_running_it_again_keeps_our_marker(self):
        os.mkdir(self.p("r"))
        st.marker(self.p("r", ".root-id"))
        first = open(self.p("r", ".root-id")).read()
        st.marker(self.p("r", ".root-id"))
        self.assertEqual(open(self.p("r", ".root-id")).read(), first)

    def test_a_symlink_at_the_marker_is_refused_and_its_target_untouched(self):
        os.mkdir(self.p("r"))
        victim = self.p("victim")
        with open(victim, "w") as f:
            f.write("keep\n")
        os.symlink(victim, self.p("r", ".root-id"))
        with self.assertRaises(st.StepError):
            st.marker(self.p("r", ".root-id"))
        self.assertEqual(open(victim).read(), "keep\n")

    def test_a_fifo_at_the_marker_is_refused_without_hanging(self):
        os.mkdir(self.p("r"))
        os.mkfifo(self.p("r", ".root-id"))
        with self.assertRaises(st.StepError):
            st.marker(self.p("r", ".root-id"))

    def test_a_hard_link_to_another_read_only_file_is_not_kept(self):
        os.mkdir(self.p("r"))
        with open(self.p("other"), "w") as f:
            f.write("0" * 32)
        os.chmod(self.p("other"), 0o444)
        os.link(self.p("other"), self.p("r", ".root-id"))
        with self.assertRaises(st.StepError):
            st.marker(self.p("r", ".root-id"))

    def test_a_file_that_is_not_ours_is_left_alone(self):
        os.mkdir(self.p("r"))
        with open(self.p("r", ".root-id"), "w") as f:
            f.write("planted")
        os.chmod(self.p("r", ".root-id"), 0o644)
        with self.assertRaises(st.StepError):
            st.marker(self.p("r", ".root-id"))
        self.assertEqual(open(self.p("r", ".root-id")).read(), "planted")


class MainTest(Tree):

    def test_an_error_exits_1_and_bad_usage_2(self):
        self.assertEqual(st.main(["sync", self.p("absent")]), 1)
        self.assertEqual(st.main(["frobnicate"]), 2)
        self.assertEqual(st.main(["root", self.p("x"), str(self.uid), str(self.gid), "0700"]), 0)
        self.assertEqual(self.mode(self.p("x")), 0o700)


if __name__ == "__main__":
    unittest.main()
