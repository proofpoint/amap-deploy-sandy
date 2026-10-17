"""root-trust.sh (root_trust.render) against the Python rules it transcribes,
row by row, on real files (ROOT-BOOTSTRAP d3 §3).

The sh route walk and file rule are held to host_steps.closure_problems over
the one path, plus the file rule on its target, plus a reference hop counter
(closure_problems' own readlink calls) bounded as the sh walk is. Both run with
root mapped to this test's uid and the directories above the fixture taken as
root's: the sh through its rendered `_rt_root` and `_rt_top`, the Python
through ROOT_UID and an lstat that answers for those directories. Each row
names the verdict it expects and requires both to give it."""

import hashlib
import os
import sys
import shutil
import stat
import subprocess
import tempfile
import unittest
from types import SimpleNamespace

import host_steps as hs
import root_trust as rt

ENV = {"PATH": rt.PATH, "LC_ALL": "C"}


def put_acl(test, path):
    """A POSIX access ACL on `path`, written as the kernel's
    system.posix_acl_access (version 2: user::rw-, user:<uid>:r--,
    group::r--, mask::r--, other::r--); `ls -ln` marks it with a trailing +.
    A filesystem that holds none skips the row."""
    import struct
    acl = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", t, p, i) for t, p, i in (
        (0x01, 6, 0xFFFFFFFF), (0x02, 4, os.getuid()), (0x04, 4, 0xFFFFFFFF), (0x10, 4, 0xFFFFFFFF),
        (0x20, 4, 0xFFFFFFFF)))
    try:
        os.setxattr(path, "system.posix_acl_access", acl)
    except OSError as e:
        test.skipTest(f"this filesystem holds no POSIX ACL: {e}")


class Fixture(unittest.TestCase):
    def setUp(self):
        t = tempfile.mkdtemp(prefix="rt")
        self.addCleanup(self._rm, t)
        self.d = os.path.realpath(t)
        os.chmod(self.d, 0o755)
        self.top = os.path.dirname(self.d)
        self.root = os.getuid()
        above, p = set(), self.top
        while True:
            st = os.lstat(p)
            above.add((st.st_dev, st.st_ino))
            if p == "/":
                break
            p = os.path.dirname(p)
        self.above = above
        self.addCleanup(setattr, hs, "ROOT_UID", hs.ROOT_UID)
        hs.ROOT_UID = self.root
        self.rtfile = os.path.join(self.d, "root-trust.sh")

    @staticmethod
    def _rm(t):
        for top, dirs, _ in os.walk(t):
            for n in dirs:
                try:
                    os.chmod(os.path.join(top, n), 0o755)
                except OSError:
                    pass
        shutil.rmtree(t, ignore_errors=True)

    def p(self, rel):
        return os.path.join(self.d, rel)

    def file(self, rel, mode=0o755, data="#!/bin/sh\n"):
        p = self.p(rel)
        os.makedirs(os.path.dirname(p), mode=0o755, exist_ok=True)
        with open(p, "w") as f:
            f.write(data)
        os.chmod(p, mode)
        return p

    def link(self, rel, target):
        p = self.p(rel)
        os.makedirs(os.path.dirname(p), mode=0o755, exist_ok=True)
        os.symlink(target, p)
        return p

    def sh(self, body, **render):
        with open(self.rtfile, "w") as f:
            f.write(rt.render(render.pop("kind", "systemd"), self.rtfile, self.root, self.top, **render))
        os.chmod(self.rtfile, 0o644)
        return subprocess.run(["/bin/sh", "-c", f". {self.rtfile} && {body}"], env=ENV, capture_output=True,
                              text=True, timeout=120)

    def lstat(self, p):
        st = os.lstat(p)
        if (st.st_dev, st.st_ino) in self.above:
            return SimpleNamespace(st_uid=self.root, st_mode=stat.S_IFDIR | 0o755, st_dev=st.st_dev, st_ino=st.st_ino)
        return st


class RouteDifferentialTest(Fixture):
    """`trusted PATH` against closure_problems([PATH]), the file rule on its
    target, and closure_problems' own hop count."""

    def python(self, path):
        hops = []

        def readlink(p):
            hops.append(p)
            return os.readlink(p)
        if path.endswith("/"):
            return False
        bad = hs.closure_problems([path], lstat=self.lstat, readlink=readlink, platform="linux")
        if bad or len(hops) > rt.MAX_HOPS:
            return False
        try:
            st = os.stat(path)
        except OSError:
            return False
        return stat.S_ISREG(st.st_mode) and st.st_uid == self.root and not st.st_mode & 0o022 \
            and bool(st.st_mode & 0o111)

    def shell(self, path):
        r = self.sh(f"trusted '{path}'")
        self.assertIn(r.returncode, (0, rt.EXIT), r.stderr)
        return r.returncode == 0

    def agree(self, path, expected):
        self.assertEqual((self.python(path), self.shell(path)), (expected, expected), path)

    def test_a_plain_file_passes(self):
        self.agree(self.file("bin/tool"), True)

    def test_a_relative_link_passes(self):
        self.file("bin/tool.real")
        self.agree(self.link("bin/tool", "tool.real"), True)

    def test_a_dotdot_link_passes(self):
        self.file("lib/x")
        self.agree(self.link("bin/tool", "../lib/x"), True)

    def test_dotdot_through_a_directory_link_passes(self):
        self.file("real/lib/x")
        self.link("via", "real/sub")
        os.makedirs(self.p("real/sub"), mode=0o755)
        self.agree(self.link("bin/tool", "../via/../lib/x"), True)

    def test_links_to_dot_and_dotdot_join_as_the_walk_does(self):
        self.file("a/b/tool")
        self.link("a/here", ".")
        self.link("a/b/up", "..")
        self.agree(self.p("a/here/b/tool"), True)
        self.agree(self.p("a/b/up/b/tool"), True)

    def test_absolute_file_and_directory_links_pass(self):
        """Codex d3.1 A2: the hop keeps the absolute-target branch."""
        real = self.file("abs/real/tool")
        self.agree(self.link("bin/abs-file", real), True)
        self.link("absdir", self.p("abs/real"))
        self.agree(self.p("absdir/tool"), True)
        os.chmod(self.p("abs"), 0o777)
        self.agree(self.p("bin/abs-file"), False)
        self.agree(self.p("absdir/tool"), False)

    def test_a_dangling_link_refuses(self):
        self.agree(self.link("bin/tool", "nowhere"), False)

    def test_a_two_link_cycle_refuses(self):
        self.link("bin/a", "b")
        self.link("bin/b", "a")
        self.agree(self.p("bin/a"), False)

    def test_a_link_to_a_non_executable_file_refuses(self):
        self.file("lib/data", 0o644)
        self.agree(self.link("bin/tool", "../lib/data"), False)

    def test_a_trailing_slash_refuses(self):
        self.file("bin/tool")
        self.assertFalse(self.shell(self.p("bin/tool") + "/"))

    def test_forty_hops_pass_and_forty_one_refuse(self):
        for n, expected in ((rt.MAX_HOPS, True), (rt.MAX_HOPS + 1, False)):
            with self.subTest(hops=n):
                d = f"chain{n}"
                self.file(f"{d}/t0")
                for i in range(1, n + 1):
                    self.link(f"{d}/t{i}", f"t{i - 1}")
                self.agree(self.p(f"{d}/t{n}"), expected)

    def test_a_multi_hop_route_through_a_writable_directory_refuses(self):
        """Opus: bin/hop -> op/mid -> lib/pyreal, with op o+w."""
        self.file("lib/pyreal")
        self.link("op/mid", "../lib/pyreal")
        os.chmod(self.p("op"), 0o757)
        self.agree(self.link("bin/hop", "../op/mid"), False)

    def test_a_directory_link_through_a_writable_directory_refuses(self):
        """Opus: bin2 -> op/dl -> bin, with op o+w."""
        self.file("bin/tool")
        self.link("op/dl", "../bin")
        os.chmod(self.p("op"), 0o757)
        self.link("bin2", "op/dl")
        self.agree(self.p("bin2/tool"), False)

    def test_front_mutable_bridge_safe_refuses(self):
        """Codex: front -> mutable/bridge -> safe, with mutable 0777."""
        self.file("safe/tool")
        self.link("mutable/bridge", "../safe")
        os.chmod(self.p("mutable"), 0o777)
        self.link("front", "mutable/bridge")
        self.agree(self.p("front/tool"), False)

    def test_a_target_with_a_trailing_newline_beside_the_good_one_refuses(self):
        self.file("bin/good")
        os.symlink("good\n", self.p("bin/tool"))
        self.agree(self.p("bin/tool"), False)

    def test_an_operator_owned_target_refuses(self):
        tool = self.file("bin/tool")
        self.root = self.root + 1
        hs.ROOT_UID = self.root
        self.agree(tool, False)


class TreeTest(Fixture):
    def tree(self):
        self.file("lib/python3.9/os.py", 0o644, "")
        self.file("lib/python3.9/json/__init__.py", 0o644, "")
        return self.p("lib/python3.9")

    def run_tree(self, root):
        r = self.sh(f"_rt_tree '{root}' && echo OK")
        self.assertIn(r.returncode, (0, rt.EXIT), r.stderr)
        return r.returncode == 0

    def test_a_clean_tree_passes_and_a_writable_entry_refuses(self):
        root = self.tree()
        self.assertTrue(self.run_tree(root))
        os.chmod(self.p("lib/python3.9/json/__init__.py"), 0o666)
        self.assertFalse(self.run_tree(root))

    def test_a_link_inside_is_hopped_and_judged(self):
        root = self.tree()
        self.file("shared/data.txt", 0o644, "")
        self.link("lib/python3.9/data.txt", "../../shared/data.txt")
        self.assertTrue(self.run_tree(root))
        os.chmod(self.p("shared"), 0o777)
        self.assertFalse(self.run_tree(root))

    def test_a_name_outside_printable_ascii_refuses(self):
        root = self.tree()
        self.file("lib/python3.9/bad\x01name.py", 0o644, "")
        self.assertFalse(self.run_tree(root))

    def test_an_acl_inside_refuses(self):
        root = self.tree()
        target = self.p("lib/python3.9/os.py")
        put_acl(self, target)
        self.assertFalse(self.run_tree(root))


class TreeDifferentialTest(Fixture):
    """`_rt_tree ROOT` against closure_problems([ROOT]): every entry under the
    root, every link hopped, a directory reached by a link visited whole."""

    def python(self, root):
        hops = []

        def readlink(p):
            hops.append(p)
            return os.readlink(p)
        return not hs.closure_problems([root], lstat=self.lstat, readlink=readlink, platform="linux") \
            and len(hops) <= rt.MAX_HOPS

    def shell(self, root):
        r = self.sh(f"_rt_tree '{root}'")
        self.assertIn(r.returncode, (0, rt.EXIT), r.stderr)
        return r.returncode == 0

    def agree(self, root, expected):
        self.assertEqual((self.python(root), self.shell(root)), (expected, expected), root)

    def stdlib(self):
        self.file("root/lib/os.py", 0o644, "")
        return self.p("root")

    def test_a_link_to_an_outside_tree_is_visited_whole(self):
        """Codex's witness: install-root/stdlib -> outside-stdlib, whose
        parents are clean, holding a group- and other-writable bad.py."""
        root = self.stdlib()
        self.file("outside-stdlib/ok.py", 0o644, "")
        self.link("root/stdlib", "../outside-stdlib")
        self.agree(root, True)
        self.file("outside-stdlib/bad.py", 0o666, "")
        self.agree(root, False)

    def test_a_link_nested_inside_a_linked_tree_is_followed(self):
        root = self.stdlib()
        self.file("far/x.py", 0o644, "")
        self.link("outer/inner", "../far")
        self.link("root/outer", "../outer")
        self.agree(root, True)
        os.chmod(self.p("far"), 0o777)
        self.agree(root, False)

    def test_a_directory_first_reached_as_a_chain_is_still_visited_whole(self):
        """`via` is a directory link on the route to x (a chain visit of its
        target), and is also linked from inside the tree (a tree visit)."""
        root = self.stdlib()
        self.file("shared/sub/a.py", 0o644, "")
        self.link("via", "shared")
        self.link("root/a.py", "../via/sub/a.py")
        self.link("root/whole", "../via")
        self.agree(root, True)
        self.file("shared/other/b.py", 0o666, "")
        self.agree(root, False)

    def test_a_cycle_inside_the_tree_ends(self):
        root = self.stdlib()
        self.link("root/up", "..")
        self.link("root/lib/back", "../..")
        self.agree(root, True)

    def test_the_install_root_itself_may_be_a_link(self):
        self.file("real-root/os.py", 0o644, "")
        self.link("root", "real-root")
        self.agree(self.p("root"), True)
        os.chmod(self.p("real-root/os.py"), 0o666)
        self.agree(self.p("root"), False)


class DotDotThroughALinkTest(Fixture):
    """Codex: jump -> branch/deep; jump/../tool is branch/tool to the kernel,
    not the sibling tool a lexical collapse would pick. The walk must judge
    the file the kernel opens."""

    def test_the_kernels_target_is_the_one_judged(self):
        self.file("branch/deep/.keep", 0o644, "")
        self.file("branch/tool")                 # what jump/../tool really is
        self.file("tool")                        # the lexical sibling, a decoy
        self.link("jump", "branch/deep")
        os.chmod(self.p("branch/tool"), 0o666)   # the real target is unsafe
        r = self.sh(f"trusted '{self.p('jump/../tool')}'")
        self.assertEqual(r.returncode, rt.EXIT, r.stderr)
        os.chmod(self.p("branch/tool"), 0o755)
        os.chmod(self.p("tool"), 0o666)          # now only the decoy is unsafe
        r = self.sh(f"trusted '{self.p('jump/../tool')}'")
        self.assertEqual(r.returncode, 0, r.stderr)


class RootExecTest(Fixture):
    """root_exec end to end, on a fixture interpreter and writer: nothing runs
    unless every check passes, proven by a sentinel the interpreter would write."""

    def setUp(self):
        super().setUp()
        self.sentinel = self.p("ran")
        self.py = self.file("usr/bin/python3.9", 0o755, f"#!/bin/sh\nprintf '%s\\n' \"$@\" > '{self.sentinel}'\n")
        self.link("usr/bin/python3", "python3.9")
        self.file("usr/lib/python3.9/os.py", 0o644, "")
        self.writer = self.file("libexec/host_steps.py", 0o644, "print('writer')\n")
        self.sha = hashlib.sha256(open(self.writer, "rb").read()).hexdigest()
        self.lib = self.file("lib/libpy.so", 0o644, "")
        # the loader in list mode, as glibc's prints it, naming one library
        # the loader in list mode, as glibc's prints it: one library, then itself as the interpreter
        ld = self.p("lib/ld.so")
        self.loader = self.file("lib/ld.so", 0o755,
                                f"#!/bin/sh\nprintf '\\tlibpy.so => {self.lib} (0x1)\\n\\t{ld} (0x2)\\n'\n")
        os.makedirs(self.p("etc"), mode=0o755)

    def go(self, sha=None, py=None):
        return self.sh(f"root_exec '{sha or self.sha}' '{py or self.p('usr/bin/python3')}' '{self.writer}' trusted-exec -- /bin/true",
                       python=self.p("usr/bin/python3"), bin_dir=self.p("usr/bin"), lib_dir=self.p("usr/lib"),
                       loader=self.loader, etc=self.p("etc"))

    def test_the_good_shape_execs_the_interpreter(self):
        r = self.go()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(self.sentinel))

    def test_a_non_root_interpreter_that_would_succeed_never_runs(self):
        """Codex's witness: the interpreter would answer success, but it is not root's."""
        self.root = self.root + 1
        r = self.go()
        self.assertEqual(r.returncode, rt.EXIT)
        self.assertFalse(os.path.exists(self.sentinel))

    def test_another_writer_never_runs(self):
        r = self.go(sha="0" * 64)
        self.assertEqual(r.returncode, rt.EXIT)
        self.assertIn("is not the writer the document pins", r.stderr)
        self.assertFalse(os.path.exists(self.sentinel))

    def test_another_interpreter_spelling_never_runs(self):
        r = self.go(py=self.py)
        self.assertEqual(r.returncode, rt.EXIT)
        self.assertFalse(os.path.exists(self.sentinel))

    def test_ld_so_preload_present_stops_it(self):
        self.file("etc/ld.so.preload", 0o644, "")
        r = self.go()
        self.assertEqual(r.returncode, rt.EXIT)
        self.assertIn("ld.so.preload", r.stderr)
        self.assertFalse(os.path.exists(self.sentinel))

    def test_a_linked_library_not_roots_alone_stops_it(self):
        os.chmod(self.lib, 0o666)
        r = self.go()
        self.assertEqual(r.returncode, rt.EXIT)
        self.assertFalse(os.path.exists(self.sentinel))

    def test_a_missing_empty_or_directory_root_trust_sh_exits_12_not_the_shells_own_code(self):
        os.makedirs(self.p("rtdir"), mode=0o755)
        empty = self.file("empty.sh", 0o644, "")
        for rtpath in (self.p("absent/root-trust.sh"), self.p("rtdir"), empty):
            line = rt.root_line(rtpath, self.sha, "/usr/bin/python3", self.writer, ["x"])
            for shell in (["/bin/sh"], ["bash", "--posix"]):
                with self.subTest(rt=os.path.basename(rtpath), shell=shell):
                    r = subprocess.run(shell + ["-c", line], env=ENV, capture_output=True, text=True, timeout=30)
                    self.assertEqual(r.returncode, rt.EXIT, r.stderr)

    def test_a_loader_line_mapping_a_path_onto_another_stops_it(self):
        """Opus d3.1 2(a): a patched PT_INTERP lists as `<pt> => <anchor>`."""
        with open(self.loader, "w") as f:
            f.write(f"#!/bin/sh\nprintf '\\t/tmp/patched-ld.so => {self.loader} (0x1)\\n'\n")
        r = self.go()
        self.assertEqual(r.returncode, rt.EXIT)
        self.assertIn("maps a path onto another", r.stderr)
        self.assertFalse(os.path.exists(self.sentinel))

    def test_the_line_grammar_is_root_exec_sha_python_writer_args(self):
        argv = rt.root_argv("/opt/ex/libexec/root-trust.sh", "a" * 64, "/usr/bin/python3",
                            "/opt/ex/libexec/host_steps.py", ["trusted-exec", "--also", "/usr/bin/docker", "--",
                                                              "/usr/bin/docker", "ps"], engine="unix:///x.sock")
        self.assertEqual(argv[:6], ["/usr/bin/env", "-i", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C",
                                    "DOCKER_HOST=unix:///x.sock", "/bin/sh"])
        self.assertEqual(argv[6], "-c")
        self.assertEqual(argv[7], "command . /opt/ex/libexec/root-trust.sh && command -v root_exec >/dev/null || exit 12; "
                         "root_exec " + "a" * 64 +
                         " /usr/bin/python3 /opt/ex/libexec/host_steps.py trusted-exec --also /usr/bin/docker -- "
                         "/usr/bin/docker ps")

    def refused(self, r, why):
        self.assertEqual(r.returncode, rt.EXIT, r.stderr)
        self.assertIn(why, r.stderr)
        self.assertFalse(os.path.exists(self.sentinel), "the interpreter ran")

    def test_the_interpreter_runs_as_I_S_B_writer_then_the_args(self):
        r = self.go()
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(self.sentinel) as f:
            self.assertEqual(f.read().splitlines(), ["-I", "-S", "-B", self.writer, "trusted-exec", "--", "/bin/true"])

    def test_an_interpreter_whose_route_is_not_roots_alone_never_runs(self):
        """Only the interpreter's own route passes through usr/bin."""
        os.chmod(self.p("usr/bin"), 0o777)
        self.refused(self.go(), "usr/bin")

    def test_an_interpreter_that_is_not_a_regular_file_never_runs(self):
        os.unlink(self.py)
        os.makedirs(self.py, mode=0o755)
        self.refused(self.go(), "is not a regular file")

    def test_an_interpreter_that_does_not_land_on_python3_N_never_runs(self):
        """With an install root for the name it lands on, so only the landing rule refuses it."""
        os.unlink(self.p("usr/bin/python3"))
        self.file("usr/bin/notpy", 0o755, f"#!/bin/sh\n: > '{self.sentinel}'\n")
        self.link("usr/bin/python3", "notpy")
        self.file("usr/lib/notpy/os.py", 0o644, "")
        self.refused(self.go(), "does not land on python3.N")

    def test_an_interpreter_that_lands_outside_the_bin_directory_never_runs(self):
        os.unlink(self.p("usr/bin/python3"))
        self.file("other/python3.9", 0o755, f"#!/bin/sh\n: > '{self.sentinel}'\n")
        self.link("usr/bin/python3", "../../other/python3.9")
        self.refused(self.go(), "does not land in")

    def test_a_writer_whose_route_is_not_roots_alone_never_runs(self):
        os.chmod(self.p("libexec"), 0o777)
        self.refused(self.go(), "libexec")

    def test_a_writer_path_outside_printable_ascii_never_runs(self):
        w = self.file("lib\x7fexec/host_steps.py", 0o644, "print('writer')\n")
        r = self.sh(f"root_exec '{self.sha}' '{self.p('usr/bin/python3')}' '{w}' trusted-exec -- /bin/true",
                    python=self.p("usr/bin/python3"), bin_dir=self.p("usr/bin"), lib_dir=self.p("usr/lib"),
                    loader=self.loader, etc=self.p("etc"))
        self.refused(r, "outside printable ASCII")

    def test_an_anchor_loader_not_roots_alone_never_lists_anything(self):
        os.chmod(self.loader, 0o777)
        self.refused(self.go(), "ld.so")

    def test_an_extension_modules_library_not_roots_alone_stops_it(self):
        bad = self.file("lib/libmod.so", 0o666, "")
        self.file("usr/lib/python3.9/lib-dynload/_x.so", 0o644, "")
        with open(self.loader, "w") as f:
            f.write(f"#!/bin/sh\ncase \"$2\" in *_x.so) printf '\\tlibmod.so => {bad} (0x1)\\n' ;; "
                    f"*) printf '\\tlibpy.so => {self.lib} (0x1)\\n\\t{self.loader} (0x2)\\n' ;; esac\n")
        self.refused(self.go(), "libmod.so")

    def test_a_library_the_loader_cannot_find_stops_it(self):
        with open(self.loader, "w") as f:
            f.write(f"#!/bin/sh\nprintf '\\tlibgone.so => not found\\n\\t{self.loader} (0x2)\\n'\n")
        self.refused(self.go(), "outside the list mode's forms")

    def test_more_than_40_links_in_all_stop_it_though_each_route_is_short(self):
        """The bound is on the whole run's hops (as closure_problems'), not per path:
        21 links to the writer and 21 to the loader, each well under 40 alone."""
        for name, target in (("w", self.writer), ("l", self.loader)):
            prev = target
            for i in range(21):
                prev = self.link(f"chain/{name}{i}", prev)
            setattr(self, name + "_end", prev)
        r = self.sh(f"root_exec '{self.sha}' '{self.p('usr/bin/python3')}' '{self.w_end}' trusted-exec -- /bin/true",
                    python=self.p("usr/bin/python3"), bin_dir=self.p("usr/bin"), lib_dir=self.p("usr/lib"),
                    loader=self.l_end, etc=self.p("etc"))
        self.refused(r, "more than 40 links")

    def test_a_posix_acl_on_the_writer_stops_it(self):
        put_acl(self, self.writer)
        self.refused(self.go(), "carries an ACL")

    def test_an_operator_writable_entry_in_the_install_root_stops_it(self):
        os.chmod(self.p("usr/lib/python3.9/os.py"), 0o666)
        r = self.go()
        self.assertEqual(r.returncode, rt.EXIT)
        self.assertFalse(os.path.exists(self.sentinel))


class ShellListModeTest(Fixture):
    """_rt_libs, d3.3 §3.6b's parser in the sh half, against a stub loader
    that prints exactly the stdout, stderr and rc each row gives it."""

    def setUp(self):
        super().setUp()
        self.lib = self.file("lib/libc.so.6", 0o644, "")
        self.ld = self.p("lib/ld.so")
        self.target = self.file("lib/target.so", 0o644, "")

    def libs(self, out, err="", rc=0, arg=""):
        with open(self.p("out"), "w") as f:
            f.write(out)
        with open(self.p("err"), "w") as f:
            f.write(err)
        self.file("lib/ld.so", 0o755, f"#!/bin/sh\ncat '{self.p('out')}'\ncat '{self.p('err')}' >&2\nexit {rc}\n")
        return self.sh(f"_rt_libs '{self.target}' {arg}", loader=self.ld)

    def ok(self, r):
        self.assertEqual(r.returncode, 0, r.stderr)

    def bad(self, r, why):
        self.assertEqual(r.returncode, rt.EXIT, r.stderr)
        self.assertIn(why, r.stderr)

    def test_the_three_forms_and_both_vdso_forms_pass(self):
        self.ok(self.libs(f"\tlinux-vdso.so.1 (0x0000ffff981db000)\n\tlibc.so.6 => {self.lib} (0x0000ffff97f70000)\n"
                          f"\t{self.ld} (0x0000ffff98190000)\n"))
        self.ok(self.libs(f"\tlinux-vdso.so.1 =>  (0x00007ffd)\n\tlibc.so.6 => {self.lib} (0x1)\n"))

    def test_a_lone_statically_linked_is_empty_and_only_alone(self):
        self.ok(self.libs("\tstatically linked\n"))
        self.bad(self.libs(f"\tstatically linked\n\tlibc.so.6 => {self.lib} (0x1)\n"), "outside the list mode's forms")

    def test_every_other_line_refuses(self):
        for line in ("\tlibx.so => not found", f"libc.so.6 => {self.lib} (0x1)", f"\tlibc.so.6 => {self.lib}",
                     f"\t{self.lib} (0xZZ)", f"\t/tmp/pt => {self.ld} (0x1)", f"\tlib c.so => {self.lib} (0x1)",
                     "\tsomething else", f" {self.lib} (0x1)"):
            with self.subTest(line=line):
                r = self.libs(f"\tlibc.so.6 => {self.lib} (0x1)\n{line}\n")
                self.assertEqual(r.returncode, rt.EXIT, r.stderr)
        self.bad(self.libs(""), "listed nothing")

    def test_the_shared_grammar_fixtures(self):
        """The same table test_trusted_exec holds the Python half to (Codex P2 at 1c3f431c)."""
        import _listmode
        for line, ok in _listmode.LINES:
            with self.subTest(line=line):
                r = self.libs(f"\tlibc.so.6 => {self.lib} (0x1)\n" + line.format(lib=self.lib) + "\n")
                self.assertEqual(r.returncode, 0 if ok else rt.EXIT, r.stderr)

    def test_stderr_or_a_non_zero_rc_refuses(self):
        good = f"\tlibc.so.6 => {self.lib} (0x1)\n"
        self.bad(self.libs(good, err="ld.so: warning\n"), "error stream")
        self.bad(self.libs(good, rc=127), "exit 127")

    def test_the_interpreter_line_is_found_by_its_text_anywhere(self):
        self.ok(self.libs(f"\t{self.ld} (0x2)\n\tlibc.so.6 => {self.lib} (0x1)\n", arg="interp"))
        self.bad(self.libs(f"\tlibc.so.6 => {self.lib} (0x1)\n", arg="interp"), "did not list itself")

    def test_sourcing_it_ends_with_status_0(self):
        r = subprocess.run(["/bin/sh", "-c", f". {self.write_rt()}; echo $?"], env=ENV, capture_output=True, text=True)
        self.assertEqual(r.stdout, "0\n")

    def write_rt(self):
        with open(self.rtfile, "w") as f:
            f.write(rt.render("systemd", self.rtfile, self.root, self.top, loader=self.ld))
        return self.rtfile

    @unittest.skipUnless(os.path.exists("/usr/bin/gcc") and sys.platform.startswith("linux"), "needs gcc on Linux")
    def test_a_missing_dependency_fails_under_each_form_on_the_real_loader(self):
        x = self.file("x.c", 0o644, "int x(void) { return 1; }\n")
        y = self.file("y.c", 0o644, "int x(void);\nint y(void) { return x(); }\n")
        libx, liby = self.p("libx.so"), self.p("liby.so")
        subprocess.run(["gcc", "-shared", "-fPIC", "-o", libx, x], check=True)
        subprocess.run(["gcc", "-shared", "-fPIC", "-o", liby, y, "-L" + self.d, "-lx"], check=True)
        os.unlink(libx)
        real = rt.elf_interpreter(rt.ANCHOR_SHELL)
        for trace, why in ((False, "cannot list its libraries (exit"), (True, "outside the list mode's forms")):
            with self.subTest(trace=trace):
                # the real system's libraries are root's: root is 0 here, not the fixture's mapped uid
                with open(self.rtfile, "w") as f:
                    f.write(rt.render("systemd", self.rtfile, 0, "", loader=real, trace=trace))
                r = subprocess.run(["/bin/sh", "-c", f". {self.rtfile} && _rt_libs '{liby}'"], env=ENV,
                                   capture_output=True, text=True, timeout=120)
                self.assertEqual(r.returncode, rt.EXIT, r.stderr)
                self.assertIn(why, r.stderr)

    def test_the_trace_form_is_rendered_below_glibc_2_33(self):
        for v, want in (("glibc 2.32", True), ("glibc 2.33", False), ("glibc 2.41", False), (None, False)):
            with self.subTest(v=v):
                self.assertIs(rt.trace_form(confstr=lambda name, v=v: v), want)
        self.addCleanup(setattr, rt, "trace_form", rt.trace_form)
        rt.trace_form = lambda: True
        self.assertIn("\n_rt_trace=1\n", rt.render("systemd", "/x/rt.sh", loader="/lib/ld.so"))
        rt.trace_form = lambda: False
        self.assertIn("\n_rt_trace=0\n", rt.render("systemd", "/x/rt.sh", loader="/lib/ld.so"))


class LoaderConfTest(Fixture):
    """d3.3 §3.0 in the sh half (Codex P2 at 1c3f431c): before any discovery,
    every directory ld.so.conf names, through every file it includes, is
    judged by the textual walk and the file rule; an entry it does not read
    refuses."""

    def setUp(self):
        super().setUp()
        self.libdir = self.p("lib/one")
        self.incdir = self.p("lib/two")
        os.makedirs(self.libdir, mode=0o755)
        os.makedirs(self.incdir, mode=0o755)
        self.file("etc/ld.so.conf.d/x.conf", 0o644, f"# included\n{self.incdir}\n")
        self.conf(f"include ld.so.conf.d/*.conf\n{self.libdir}   # a comment\n\n")

    def conf(self, text):
        self.file("etc/ld.so.conf", 0o644, text)

    def go(self):
        return self.sh("_rt_loader_config", etc=self.p("etc"), loader="/lib/ld.so")

    def test_every_named_directory_passes_when_roots_alone(self):
        r = self.go()
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_named_directory_writable_by_others_fails(self):
        os.chmod(self.libdir, 0o777)
        r = self.go()
        self.assertEqual(r.returncode, rt.EXIT, r.stderr)
        self.assertIn(self.libdir, r.stderr)

    def test_a_directory_named_by_an_included_file_is_judged_too(self):
        os.chmod(self.incdir, 0o777)
        r = self.go()
        self.assertEqual(r.returncode, rt.EXIT, r.stderr)
        self.assertIn(self.incdir, r.stderr)

    def test_an_absent_directory_is_judged_as_a_would_be_place(self):
        os.makedirs(self.p("open"), mode=0o755)
        os.chmod(self.p("open"), 0o777)
        self.conf(f"{self.p('open/later')}\n")
        r = self.go()
        self.assertEqual(r.returncode, rt.EXIT, r.stderr)
        self.assertIn(self.p("open"), r.stderr)

    def two_patterns(self):
        """`include one/*.conf two/*.conf`: glibc's ldconfig reads both, each
        relative to the conf's own directory (Opus B4, measured with ldconfig)."""
        self.one = self.p("lib/three")
        os.makedirs(self.one, mode=0o755)
        self.file("etc/one/x.conf", 0o644, f"{self.one}\n")
        self.file("etc/two/y.conf", 0o644, f"{self.incdir}\n")
        self.conf("include one/*.conf two/*.conf\n")

    def test_every_pattern_of_a_multi_pattern_include_is_followed(self):
        self.two_patterns()
        r = self.go()
        self.assertEqual(r.returncode, 0, r.stderr)
        for d in (self.one, self.incdir):
            with self.subTest(dir=d):
                os.chmod(d, 0o777)
                r = self.go()
                self.assertEqual(r.returncode, rt.EXIT, r.stderr)
                self.assertIn(d, r.stderr)
                os.chmod(d, 0o755)

    def test_an_unreadable_ld_so_conf_fails(self):
        """Opus N2: the file rule passes (mode 0400 kept from others' write),
        and reading it is what fails."""
        os.chmod(self.p("etc/ld.so.conf"), 0o000)
        r = self.go()
        self.assertEqual(r.returncode, rt.EXIT, r.stderr)
        self.assertIn("cannot be read", r.stderr)

    def test_a_writable_conf_file_fails_and_so_does_an_included_one_outside_conf_d(self):
        """Opus N2: each conf file by the file rule, not only the conf.d tree."""
        os.chmod(self.p("etc/ld.so.conf"), 0o666)
        r = self.go()
        self.assertEqual(r.returncode, rt.EXIT, r.stderr)
        self.assertIn(self.p("etc/ld.so.conf"), r.stderr)
        os.chmod(self.p("etc/ld.so.conf"), 0o644)
        self.two_patterns()
        os.chmod(self.p("etc/one/x.conf"), 0o666)
        r = self.go()
        self.assertEqual(r.returncode, rt.EXIT, r.stderr)
        self.assertIn(self.p("etc/one/x.conf"), r.stderr)

    def test_an_entry_this_check_does_not_read_refuses(self):
        for line in ("hwcap 1 nosegneg", "relative/lib", "include"):
            with self.subTest(line=line):
                self.conf(f"{self.libdir}\n{line}\n")
                r = self.go()
                self.assertEqual(r.returncode, rt.EXIT, r.stderr)
                self.assertIn("does not read", r.stderr)


class LaunchdRootExecTest(Fixture):
    """The launchd rendering of root_exec, run here: its two BSD `ls -e`
    calls replaced by a stand-in over GNU ls that drops -e and prints a BSD
    ACL entry line under each path named in acl.list. Every other line is
    the rendering's own."""

    def setUp(self):
        super().setUp()
        self.sentinel = self.p("ran")
        self.install = self.p("Py")
        self.py = self.file("Py/bin/python3.9", 0o755, f"#!/bin/sh\n: > '{self.sentinel}'\n")
        self.link("bin/python3", "../Py/bin/python3.9")
        self.writer = self.file("libexec/host_steps.py", 0o644, "print('writer')\n")
        self.sha = hashlib.sha256(open(self.writer, "rb").read()).hexdigest()
        self.acl = self.p("acl.list")
        open(self.acl, "w").close()
        self.ls = self.file("tools/ls", 0o755,
                            "#!/bin/bash\na=(); for x in \"$@\"; do case $x in -?*) x=${x//e/} ;; esac; a+=(\"$x\"); done\n"
                            "for x in \"$@\"; do case $x in -*) ;; *) /bin/ls \"${a[@]:0:1}\" -- \"$x\" || exit $?\n"
                            f"  grep -qxF -- \"$x\" '{self.acl}' && echo ' 0: group:everyone deny delete' || true ;; esac; done\n")

    def go(self):
        text = rt.render("launchd", self.rtfile, self.root, self.top, python=self.p("bin/python3"), install=self.install)
        self.assertEqual(text.count("/bin/ls -ledn"), 1)
        with open(self.rtfile, "w") as f:
            f.write(text.replace("/bin/ls -ledn", self.ls + " -ldn"))
        os.chmod(self.rtfile, 0o644)
        return subprocess.run(["/bin/sh", "-c", f". {self.rtfile} && root_exec '{self.sha}' '{self.p('bin/python3')}' "
                               f"'{self.writer}' trusted-exec -- /bin/true"], env=ENV, capture_output=True, text=True,
                              timeout=120)

    def test_the_good_shape_runs(self):
        r = self.go()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(self.sentinel))

    def test_an_interpreter_landing_outside_the_install_root_never_runs(self):
        os.unlink(self.p("bin/python3"))
        self.file("elsewhere/python3.9", 0o755, f"#!/bin/sh\n: > '{self.sentinel}'\n")
        self.link("bin/python3", "../elsewhere/python3.9")
        r = self.go()
        self.assertEqual(r.returncode, rt.EXIT, r.stderr)
        self.assertIn("lands outside", r.stderr)
        self.assertFalse(os.path.exists(self.sentinel))

    def test_an_acl_entry_line_on_the_writer_stops_it(self):
        with open(self.acl, "w") as f:
            f.write(self.writer + "\n")
        r = self.go()
        self.assertEqual(r.returncode, rt.EXIT, r.stderr)
        self.assertIn("carries an ACL", r.stderr)
        self.assertFalse(os.path.exists(self.sentinel))


class NoLddTest(unittest.TestCase):
    """Opus d3.1 3: ldd is a shell script; nothing root runs names it."""

    def test_no_root_code_names_ldd(self):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for name in ("host_steps.py", "root_trust.py", "hub_supervise.py", "partition_job.py"):
            with self.subTest(name=name):
                with open(os.path.join(here, name)) as f:
                    text = f.read()
                self.assertNotIn("/usr/bin/ldd", text)
                self.assertNotRegex(text, r"\bLDD\b")
        self.assertNotIn("ldd", rt.render("systemd", "/x"))


class WriterImportsTest(unittest.TestCase):
    """Root's writer (secrets.writer, host_steps.py) loads only the judged
    standard library: every import, anywhere in the file (ast.walk), is a
    standard-library module, and nothing writes sys.path."""

    def test_the_writer_imports_only_the_standard_library_and_never_sys_path(self):
        import ast
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(here, "host_steps.py")) as f:
            tree = ast.parse(f.read())
        stdlib = getattr(sys, "stdlib_module_names", None)
        if stdlib is None:
            self.skipTest("sys.stdlib_module_names needs 3.10")
        mods = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                mods.update(a.name.split(".")[0] for a in n.names)
            elif isinstance(n, ast.ImportFrom):
                self.assertEqual(n.level, 0)
                mods.add(n.module.split(".")[0])
            elif isinstance(n, ast.Attribute) and n.attr == "path" and isinstance(n.value, ast.Name) \
                    and n.value.id == "sys":
                self.fail("host_steps.py touches sys.path")
        self.assertEqual(sorted(m for m in mods if m not in stdlib), [])


class ConstantsTest(unittest.TestCase):
    def test_the_anchor_is_the_pinned_environment_and_carries_the_engine(self):
        self.assertEqual(rt.anchor(), ["/usr/bin/env", "-i", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"])
        self.assertEqual(rt.anchor("unix:///x.sock")[-1], "DOCKER_HOST=unix:///x.sock")

    def test_the_exit_means_nothing_else(self):
        self.assertEqual(rt.EXIT, hs.ROOT_TRUST_EXIT)
        self.assertNotIn(rt.EXIT, list(hs.PROBE_EXITS.values()) + [hs.REFUSED, hs.ENGINE_EXIT, 125, 126, 127, 143])
        self.assertFalse(0 <= rt.EXIT <= 11)

    def test_both_kinds_render_and_parse(self):
        for kind in ("systemd", "launchd"):
            with self.subTest(kind=kind):
                with tempfile.NamedTemporaryFile("w", suffix=".sh") as f:
                    f.write(rt.render(kind, f.name))
                    f.flush()
                    self.assertEqual(subprocess.run(["/bin/sh", "-n", f.name]).returncode, 0)


if __name__ == "__main__":
    unittest.main()
