"""The writer's per-run tripwire, closure_problems, follows a link to its
TEXTUAL target one hop at a time, judging every directory on the target's
own path first, as the install-time block does. Shapes are driven through a
fake filesystem (other owners, links in root's directories) and, where a test
user can make them, on real trees with root's uid mapped to the test's."""

import errno
import os
import stat
import tempfile
import types
import unittest

import host_steps as hs
from _fakefs import D, F, L, FakeFS, tree

W = stat.S_IFDIR | 0o777
WF = stat.S_IFREG | 0o666


def problems(fx, closure, **kw):
    return hs.closure_problems(closure, **fx.kw(**kw))


def named(bad):
    """The paths the problems name."""
    return {b.split(":")[0].split(" ")[0] for b in bad}


class AliasTest(unittest.TestCase):
    """Codex's alias fixture: second.py -> outside/alias/linked.py, with
    outside writable and outside/alias -> safe. realpath() alone resolves
    straight to safe/linked.py and never judges outside/."""

    def fixture(self, outside_mode):
        t = tree("/r1", "/r2", "/o/safe", **{"/o/outside": (0, outside_mode), "/o/safe/linked.py": (0, F)})
        links = {"/r1/first.py": "/o/safe/linked.py", "/r2/second.py": "/o/outside/alias/linked.py",
                 "/o/outside/alias": "/o/safe"}
        return FakeFS(t, links)

    def test_the_directories_on_a_targets_own_path_are_judged_in_either_order(self):
        for order in (["/r1", "/r2"], ["/r2", "/r1"]):
            with self.subTest(order=order):
                self.assertIn("/o/outside", named(problems(self.fixture(W), order)))
                self.assertEqual(problems(self.fixture(D), order), [], "the 0755 control")


class HopsTest(unittest.TestCase):
    def test_a_two_hop_tree_reaches_its_final_tree(self):
        t = tree("/r", "/mid", "/W/c", **{"/W/c/w": (0, WF)})
        fx = FakeFS(t, {"/r/a": "../mid/b", "/mid/b": "/W/c"})
        self.assertEqual(named(problems(fx, ["/r"])), {"/W/c/w"})

    def test_a_two_hop_parent_chain_judges_the_directories_its_targets_pass(self):
        t = tree("/q", "/mid2", "/W2", **{"/W2/marked": (0, W), "/W2/marked/real2": (0, D),
                                         "/W2/marked/real2/file": (0, F)})
        fx = FakeFS(t, {"/q/dirlink": "../mid2/p", "/mid2/p": "/W2/marked/real2"})
        self.assertEqual(named(problems(fx, ["/q/dirlink/file"])), {"/W2/marked"})

    def test_a_three_hop_chain_reaches_its_final_tree(self):
        t = tree("/r", "/m1", "/m2", "/end", **{"/end/w": (0, WF)})
        fx = FakeFS(t, {"/r/a": "/m1/b", "/m1/b": "../m2/c", "/m2/c": "/end"})
        self.assertEqual(named(problems(fx, ["/r"])), {"/end/w"})

    def test_a_chain_visit_never_stands_in_for_a_later_tree_visit_in_either_order(self):
        t = tree("/c1", "/c2", "/s/shared", "/o2", **{"/o2/outside": (0, W), "/o2/outside/linked.py": (0, F),
                                                      "/c1/y": (0, F)})
        links = {"/c1/parent": "/s/shared", "/c2/lnk": "/s/shared", "/s/shared/inner.py": "/o2/outside/linked.py"}
        for order in (["/c1/parent/x", "/c2"], ["/c2", "/c1/parent/x"]):
            with self.subTest(order=order):
                fx = FakeFS(dict(t, **{"/s/shared/x": (0, F)}), links)
                self.assertIn("/o2/outside", named(problems(fx, order)))

    def test_a_relative_target_is_joined_to_the_links_directory_never_the_working_directory(self):
        t = tree("/r", "/mid", "/W/c", **{"/W/c/w": (0, WF)})
        fx = FakeFS(t, {"/r/a": "../mid/b", "/mid/b": "/W/c"})
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            os.chdir(d)
            try:
                self.assertEqual(named(problems(fx, ["/r"])), {"/W/c/w"})
            finally:
                os.chdir(cwd)


class CycleTest(unittest.TestCase):
    """Each cycle ends within a bounded count of lstat calls, and a writable
    directory beyond it is still reported."""

    BOUND = 400

    def check(self, t, links, closure, beyond):
        fx = FakeFS(dict(t, **{beyond: (0, W)}), links)
        bad = problems(fx, closure)
        self.assertIn(beyond, named(bad))
        self.assertLess(fx.lstats, self.BOUND, "the walk ended")

    def test_every_cycle_ends(self):
        rows = {
            "d/l -> ../d/l": (tree("/c/d"), {"/c/d/l": "../d/l", "/c/d/out": "/w1"}, ["/c"], "/w1"),
            "bin/X11 -> .": (tree("/c/bin"), {"/c/bin/X11": ".", "/c/bin/out": "/w1"}, ["/c"], "/w1"),
            "bin/up -> ../bin": (tree("/c/bin"), {"/c/bin/up": "../bin", "/c/bin/out": "/w1"}, ["/c"], "/w1"),
            "A/sub -> ../B, B/back -> ../A": (tree("/c/A", "/c/B"), {"/c/A/sub": "../B", "/c/B/back": "../A",
                                                                      "/c/B/out": "/w1"}, ["/c"], "/w1"),
            "d/x -> loop/x through d/loop -> .": (tree("/c/d"), {"/c/d/x": "loop/x", "/c/d/loop": ".",
                                                                  "/c/d/out": "/w1"}, ["/c"], "/w1"),
        }
        for what, (t, links, closure, beyond) in rows.items():
            with self.subTest(what):
                self.check(t, links, closure, beyond)

    def test_an_entry_under_a_looping_parent_is_keyed_by_its_spelling(self):
        fx = FakeFS(tree("/c"), {"/c/p": "p"})
        self.assertEqual(hs._entry("/c/p/x", fx.stat, fx.realpath), "?/c/p/x")
        self.assertEqual(hs._entry("//c/./p/../p/x", fx.stat, fx.realpath), "?/c/p/x", "normalised as norm() does")
        self.assertEqual(hs._entry("/c/x", fx.stat, fx.realpath), "/c/x")
        fx = FakeFS(dict(tree("/c"), **{"/w": (0, W)}), {"/c/p": "p", "/c/q": "p/x", "/c/out": "/w"})
        bad = problems(fx, ["/c"])
        self.assertIn("/w", named(bad))
        self.assertLess(fx.lstats, self.BOUND)

    def test_a_chain_deeper_than_any_recursion_limit_completes(self):
        n = 5000
        t = tree("/c", "/deep", **{"/end": (0, W)})
        links = {f"/deep/l{i}": f"/deep/l{i + 1}" for i in range(n)}
        links[f"/deep/l{n}"] = "/end"
        links["/c/start"] = "/deep/l0"
        fx = FakeFS(t, links)
        self.assertIn("/end", named(problems(fx, ["/c"])))


class PartsTest(unittest.TestCase):
    def test_an_unlistable_directory_inside_a_tree_is_a_problem(self):
        fx = FakeFS(tree("/c/locked"), unreadable={"/c/locked"})
        self.assertEqual(problems(fx, ["/c"]), ["/c/locked: Permission denied"])

    def test_an_absent_zip_has_its_immediate_parent_judged_first(self):
        fx = FakeFS(tree("/opt", **{"/opt/pyzip": (501, D)}))
        closure = {hs.REQUIRED: [], hs.LIBRARIES: [], hs.OPTIONAL: ["/opt/pyzip/python313.zip"]}
        self.assertEqual(named(problems(fx, closure)), {"/opt/pyzip"})

    def test_an_absent_zips_parent_link_is_followed_as_a_chain(self):
        fx = FakeFS(tree("/opt", **{"/w": (0, W)}), {"/opt/pyzip": "/w"})
        closure = {hs.REQUIRED: [], hs.LIBRARIES: [], hs.OPTIONAL: ["/opt/pyzip/python313.zip"]}
        self.assertIn("/w", named(problems(fx, closure)))

    def test_a_spelled_tool_whose_route_crosses_a_writable_directory_is_reported(self):
        for tool in ("python3", "docker"):
            with self.subTest(tool):
                t = tree("/usr/bin", "/opt/real", **{"/opt/real/" + tool: (0, stat.S_IFREG | 0o755)})
                for mode, want in ((W, {"/etc/alternatives"}), (D, set())):
                    fx = FakeFS(dict(t, **{"/etc": (0, D), "/etc/alternatives": (0, mode)}),
                                {"/usr/bin/" + tool: "/etc/alternatives/" + tool,
                                 "/etc/alternatives/" + tool: "/opt/real/" + tool})
                    closure = {hs.REQUIRED: ["/opt/real/" + tool, "/usr/bin/" + tool], hs.LIBRARIES: [],
                               hs.OPTIONAL: []}
                    self.assertEqual(named(problems(fx, closure)), want)

    def test_on_macos_only_a_cache_member_is_excused_and_its_parents_are_still_judged(self):
        t = tree("/usr/lib", "/opt")
        lib = "/usr/lib/libcache-only.dylib"
        fx = FakeFS(t)
        closure = {hs.REQUIRED: [], hs.LIBRARIES: [lib], hs.OPTIONAL: []}
        self.assertEqual(problems(fx, closure, platform="darwin"), [])
        self.assertEqual(problems(fx, closure, platform="linux"), [f"{lib}: absent"])
        other = {hs.REQUIRED: [], hs.LIBRARIES: ["/opt/absent.dylib"], hs.OPTIONAL: []}
        self.assertEqual(problems(fx, other, platform="darwin"), ["/opt/absent.dylib: absent"])
        fx = FakeFS(dict(t, **{"/usr/lib": (501, D)}))
        self.assertEqual(named(problems(fx, closure, platform="darwin")), {"/usr/lib"})


class SpellingsTest(unittest.TestCase):
    def test_the_approved_spellings_are_closure_paths(self):
        calls = []
        for name, value in (("_trusted_tool", lambda p: "/real" + p),
                            ("startup_closure", lambda *a: calls.append(a) or {}),
                            ("closure_problems", lambda c: [])):
            self.addCleanup(setattr, hs, name, getattr(hs, name))
            setattr(hs, name, value)
        hs._verified_tools("/usr/bin/python3", "/usr/bin/docker")
        self.assertEqual(calls, [("/real/usr/bin/python3", "/real/usr/bin/docker",
                                  ("/usr/bin/python3", "/usr/bin/docker"))])

    def test_the_fallback_docker_closure_carries_the_spelling_when_known(self):
        self.addCleanup(setattr, hs, "_linked_libraries", hs._linked_libraries)
        hs._linked_libraries = lambda bs: []
        self.assertEqual(hs._docker_closure("/real/docker", "/usr/bin/docker")[hs.REQUIRED],
                         ["/real/docker", "/usr/bin/docker"])
        self.assertEqual(hs._docker_closure("/real/docker")[hs.REQUIRED], ["/real/docker"])

    def test_discovery_puts_the_spellings_in_required(self):
        import sys
        py, sh = os.path.realpath(sys.executable), os.path.realpath("/bin/sh")
        found = hs.startup_closure(py, sh, ("/spelled/python3", "/spelled/docker"))
        self.assertIn("/spelled/python3", found[hs.REQUIRED])
        self.assertIn("/spelled/docker", found[hs.REQUIRED])


class RealTreeTest(unittest.TestCase):
    """The same shapes on disk, with root's uid mapped to this test's user,
    run from a working directory outside the fixture; only findings inside
    the fixture are compared."""

    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.d = os.path.realpath(t.name)
        os.chmod(self.d, 0o755)
        self.addCleanup(setattr, hs, "ROOT_UID", hs.ROOT_UID)
        hs.ROOT_UID = os.getuid()
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir("/")

    def mk(self, rel, mode=0o755, link=None, file=False):
        p = os.path.join(self.d, rel)
        if link is not None:
            os.symlink(link, p)
        elif file:
            with open(p, "w") as f:
                f.write("x")
            os.chmod(p, mode)
        else:
            os.mkdir(p)
            os.chmod(p, mode)
        return p

    def found(self, closure):
        return {b for b in named(hs.closure_problems(closure)) if b.startswith(self.d + "/")}

    def test_the_alias_fixture_on_disk(self):
        for mode, want in ((0o777, {"o/outside"}), (0o755, set())):
            with self.subTest(mode=oct(mode)):
                with tempfile.TemporaryDirectory(dir=self.d) as sub:
                    os.chmod(sub, 0o755)
                    base = os.path.relpath(sub, self.d)
                    for rel in ("r1", "r2", "o", "o/safe"):
                        self.mk(f"{base}/{rel}")
                    self.mk(f"{base}/o/outside", mode)
                    self.mk(f"{base}/o/safe/linked.py", file=True, mode=0o644)
                    self.mk(f"{base}/o/outside/alias", link="../safe")
                    self.mk(f"{base}/r1/first.py", link=f"{sub}/o/safe/linked.py")
                    self.mk(f"{base}/r2/second.py", link="../o/outside/alias/linked.py")
                    for order in ([f"{sub}/r1", f"{sub}/r2"], [f"{sub}/r2", f"{sub}/r1"]):
                        got = {os.path.relpath(p, sub) for p in self.found(order)}
                        self.assertEqual(got, want, order)

    def test_bin_x11_on_disk_ends_and_judges_beyond(self):
        self.mk("c")
        self.mk("c/bin")
        self.mk("c/bin/X11", link=".")
        w = self.mk("w", 0o777)
        self.mk("c/bin/out", link=w)
        self.assertEqual(self.found([os.path.join(self.d, "c")]), {w})

    def test_an_entry_under_a_looping_parent_on_disk_is_keyed_by_its_spelling(self):
        self.mk("c")
        self.mk("c/p", link="p")
        self.assertEqual(hs._entry(os.path.join(self.d, "c/p/x")), "?" + os.path.join(self.d, "c/p/x"))
        self.assertEqual(hs._entry(os.path.join(self.d, "c/x")), os.path.join(self.d, "c/x"))

    def test_an_unreadable_directory_on_disk_is_named(self):
        if os.getuid() == 0:
            self.skipTest("root reads any directory")
        self.mk("c")
        locked = self.mk("c/locked", 0o755)
        os.chmod(locked, 0)
        self.addCleanup(os.chmod, locked, 0o755)
        bad = hs.closure_problems([os.path.join(self.d, "c")])
        self.assertIn(f"{locked}: Permission denied", bad)


if __name__ == "__main__":
    unittest.main()
