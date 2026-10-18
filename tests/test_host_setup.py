"""host_setup: the hop deployment's host plan, rendered and verified.

Every path, principal and group here is invented. The module knows no
runtime's directory names, and a real host's document is operator data. The
filesystem is a fake `lstat` over a dict, so each owner, mode and ancestor
can be broken one at a time. Docker is never run: each probe is a fake
built from what the real command prints (`docker inspect`'s JSON fields,
`/proc/<pid>/status` in kernel field order, `stat -c`, `openssl version`).
"""

import copy
import hashlib
import json
import os
import shlex
import stat
import tempfile
import posixpath
import unittest
from collections import namedtuple

import host_setup as hs
import router_health as rh

St = namedtuple("St", "st_mode st_uid st_gid st_ino", defaults=(0,))
UP, DOWN, GID = 2101, 2102, 2100
UPGRP = 2201


def doc():
    return {"schema": hs.SPEC_SCHEMA,
            "groups": {"hopgrp": GID, "upgrp": UPGRP, "downgrp": 2202},
            "principals": {"upstream": {"uid": UP, "groups": ["upgrp", "hopgrp"]},
                           "downstream": {"uid": DOWN, "groups": ["downgrp", "hopgrp"]}},
            "hops": [{"name": "h1", "upstream": "upstream", "downstream": "downstream", "peer_uid_env": "EX_PEER_UID"}],
            "roots": [{"path": "/srv/example/a/b", "owner": "upstream", "group": "hopgrp",
                       "mode": "2750", "readers": ["upstream", "downstream"], "purpose": "the shared root"},
                      {"path": "/srv/example/a/b/inner", "owner": "downstream", "group": "hopgrp",
                       "mode": "2750", "readers": ["downstream"], "purpose": "the inner root"},
                      {"path": "/srv/example/state/up", "owner": "upstream", "group": "upgrp",
                       "mode": "0700", "readers": ["upstream"], "purpose": "upstream state"}],
            "overlay": {"path": "/srv/example/overlay/plugin.py",
                        "pin": hs.stub_pin("/opt/example/plugin.py")},
            "agent_paths": ["/srv/example/agents"],
            "openssl": {"img-up": {"version": "3.0.13", "floor": "3.0", "source": "example base image"},
                        "img-down": {"version": "3.0.13", "floor": "3.0", "source": "example base image",
                                     "path": "/usr/bin/openssl"}},
            "runtimes": [{"principal": "upstream", "container": "ex-up", "image": "img-up", "umask": "0027",
                          "umasks": ["0027"]},
                         {"principal": "downstream", "container": "ex-down", "image": "img-down",
                          "umask": "0022", "umasks": ["0027", "0022"]}],
            "mounts": [{"principal": "downstream", "host": "/srv/example/a/b", "container": "/data/root"},
                       {"principal": "upstream", "host": "/srv/example/state/up", "container": "/state"},
                       {"principal": "upstream", "host": "/srv/example/a/b", "container": "/hop"}]}


def d(mode, uid=0, gid=0, ino=0):
    return St(stat.S_IFDIR | mode, uid, gid, ino)


def good_fs():
    return {"/": d(0o755), "/srv": d(0o755), "/srv/example": d(0o755), "/srv/example/a": d(0o755),
            "/srv/example/a/b": d(0o2750, UP, GID, 4242),
            "/srv/example/a/b/inner": d(0o2750, DOWN, GID),
            "/srv/example/state": d(0o755), "/srv/example/state/up": d(0o700, UP, UPGRP, 77),
            "/srv/example/overlay": d(0o755),
            "/srv/example/overlay/plugin.py": St(stat.S_IFREG | 0o444, 0, 0)}


def lstat_of(fs, denied=()):
    def lstat(p):
        if p in denied:
            raise PermissionError(13, "denied", p)
        if p not in fs:
            raise FileNotFoundError(p)
        return fs[p]
    return lstat


def good_containers():
    return {"ex-up": {"image": "img-up", "binds": [("/srv/example/state/up", "/state"),
                                                   ("/srv/example/a/b", "/hop")]},
            "ex-down": {"image": "img-down", "binds": [("/srv/example/a/b", "/data/root")]}}


def good_mount(container, path, marker):
    return {("ex-down", "/data/root"): ((4242, UP, GID, 0o2750), None),
            ("ex-up", "/state"): ((77, UP, UPGRP, 0o700), None),
            ("ex-up", "/hop"): ((4242, UP, GID, 0o2750), None)}[(container, path)]


def good_umasks(c):
    return [(UP, 0o027)] if c == "ex-up" else [(DOWN, 0o022)]


def good_groups(c):
    return [(UP, (UPGRP, (GID,)))] if c == "ex-up" else [(DOWN, (2202, (GID,)))]


def results(checks):
    return {c.claim: c.result for c in checks}


def fake_docker(test, answer):
    """Replace router_health.run with `answer(argv)` for one test; return the argv list seen."""
    seen = []

    def run(argv, **kw):
        seen.append(list(argv))
        return answer(argv)
    orig = rh.run
    rh.run = run
    test.addCleanup(setattr, rh, "run", orig)
    return seen


class SpecTest(unittest.TestCase):

    def test_a_good_document_loads(self):
        s = hs.load_spec(doc())
        self.assertEqual(s.principals["upstream"].gids, (UPGRP, GID))
        self.assertEqual(s.roots[0].mode, 0o2750)
        self.assertEqual(s.runtime_of("upstream")["umasks"], (0o027,))
        self.assertEqual(s.runtime_of("downstream")["umasks"], (0o027, 0o022))
        self.assertEqual(s.openssl["img-up"]["path"], "openssl")
        self.assertFalse(s.production)

    def refused(self, mutate, says):
        x = doc()
        mutate(x)
        with self.assertRaises(hs.SpecError) as e:
            hs.load_spec(x)
        self.assertIn(says, str(e.exception))

    def test_refusals(self):
        self.refused(lambda x: x["principals"]["downstream"].update(uid=UP), "needs its own uid")
        self.refused(lambda x: x["principals"]["upstream"].update(uid=0), "never runs as root")
        self.refused(lambda x: x.update(extra=1), "unknown member")
        self.refused(lambda x: x.update(production="yes"), "true or false")
        self.refused(lambda x: x["roots"][0].update(group="nogrp"), "not declared")
        self.refused(lambda x: x["roots"][0].update(mode="rwx"), "octal")
        self.refused(lambda x: x["roots"].append(dict(x["roots"][0])), "listed twice")
        self.refused(lambda x: x["roots"][0].update(path="/srv/example/../x"), "normalised")
        self.refused(lambda x: x["roots"][0].update(path="/"), "cannot be /")
        self.refused(lambda x: x["overlay"]["pin"].update(url="https://example.org"), "exactly sha256")
        self.refused(lambda x: x["roots"][0].update(readers=["nobody"]), "declared principals")
        self.refused(lambda x: x["openssl"]["img-up"].update(version="3"), "X.Y.Z")
        self.refused(lambda x: x["openssl"]["img-up"].update(floor="three"), "X.Y")
        self.refused(lambda x: x["openssl"]["img-up"].update(path="openssl"), "absolute")
        self.refused(lambda x: x["hops"][0].update(peer_uid_env="bad name"), "environment variable")
        self.refused(lambda x: x["mounts"][0].update(host="/srv/example/other"), "one of the roots")
        self.refused(lambda x: x["mounts"][0].update(principal="nobody"), "not declared")
        self.refused(lambda x: x["openssl"]["img-up"].update(floor="1.1", version="1.1.1"), "below 3.0")
        self.refused(lambda x: x["openssl"]["img-up"].update(floor="3.2"), "below its own floor")
        for bad in ("0077", "0002", "0000", "027", 23):
            self.refused(lambda x: x["runtimes"][1].update(umask=bad), "must be one of 0027, 0022")
            self.refused(lambda x: x["runtimes"][1].update(umasks=[bad]), "must be one of 0027, 0022")
        self.refused(lambda x: x["runtimes"][1].update(umasks=[]), "must list the umasks")
        self.refused(lambda x: x["runtimes"][0].update(principal="nobody"), "not declared")
        self.refused(lambda x: x["runtimes"][0].update(container="a b"), "container name")
        self.refused(lambda x: x["runtimes"][0].pop("umask"), "must have principal, container, image and umask")
        self.refused(lambda x: x["runtimes"][1].update(container="ex-up"), "listed twice")

    def test_without_umasks_a_runtime_may_run_only_under_0027(self):
        x = doc()
        del x["runtimes"][0]["umasks"]
        self.assertEqual(hs.load_spec(x).runtime_of("upstream")["umasks"], (0o027,))
        self.refused(lambda x: x["runtimes"][1].pop("umasks"), "is not one this runtime allows (0027)")

    def test_a_runtime_pinned_to_0027_cannot_declare_0022(self):
        self.refused(lambda x: x["runtimes"][0].update(umask="0022"), "is not one this runtime allows (0027)")

    def test_floor_3_0_is_accepted(self):
        self.assertEqual(hs.load_spec(doc()).openssl["img-up"]["floor"], (3, 0))

    def test_a_null_pin_is_no_plugin(self):
        x = doc()
        x["overlay"]["pin"] = None
        self.assertIsNone(hs.load_spec(x).overlay_pin)


class NothingIsLeftUncheckedTest(unittest.TestCase):
    """A document that leaves out what a check needs does not load, one
    omission at a time: a missing check must never read as a passing one."""

    def refused(self, mutate, says):
        x = doc()
        mutate(x)
        with self.assertRaises(hs.SpecError) as e:
            hs.load_spec(x)
        self.assertIn(says, str(e.exception))

    def test_a_schema_only_document(self):
        with self.assertRaises(hs.SpecError) as e:
            hs.load_spec({"schema": hs.SPEC_SCHEMA})
        self.assertIn("names no hop", str(e.exception))

    def test_no_hops(self):
        self.refused(lambda x: x.update(hops=[]), "names no hop")

    def test_a_hop_principal_without_a_runtime(self):
        self.refused(lambda x: (x["runtimes"].pop(1), x["mounts"].pop(0)), "downstream has 0 runtimes entries")
        self.refused(lambda x: x["runtimes"].pop(1), "downstream has no runtime to hold this mount")

    def test_a_hop_principal_with_two_runtimes(self):
        self.refused(lambda x: x["runtimes"].append(dict(x["runtimes"][1], container="ex-down-2")),
                     "downstream has 2 runtimes entries")

    def test_a_hop_principal_without_a_mount(self):
        self.refused(lambda x: (x["mounts"].pop(2), x["mounts"].pop(1)), "upstream has no mounts entry")

    def test_no_roots(self):
        self.refused(lambda x: x.update(roots=[]), "one of the roots")

    def test_a_runtime_image_without_openssl(self):
        self.refused(lambda x: x["openssl"].pop("img-down"), "image 'img-down' has no openssl record")

    def test_a_root_its_owner_reaches_through_no_mount(self):
        self.refused(lambda x: x["mounts"].pop(2), "root /srv/example/a/b: upstream owns or reads it, but "
                                                   "no mount of upstream's runtime holds it")

    def test_an_unrelated_mount_does_not_cover_a_root(self):
        def m(x):
            x["mounts"][2]["host"] = "/srv/example/state/up"
            x["mounts"][2]["container"] = "/other"
        self.refused(m, "root /srv/example/a/b: upstream owns or reads it")

    def test_a_reader_without_a_covering_mount(self):
        def m(x):
            x["roots"][2]["readers"] = ["upstream", "downstream"]
        self.refused(m, "root /srv/example/state/up: downstream owns or reads it")

    def test_an_owner_who_is_not_a_reader_still_needs_a_covering_mount(self):
        def m(x):
            x["roots"][0]["readers"] = ["downstream"]
            x["mounts"].pop(2)
        self.refused(m, "root /srv/example/a/b: upstream owns or reads it")

    def test_a_sibling_whose_name_extends_the_mount_is_not_covered(self):
        def m(x):
            x["roots"].append({"path": "/srv/example/a/bx", "owner": "downstream", "group": "hopgrp",
                               "mode": "2750", "readers": ["downstream"], "purpose": "a sibling"})
        self.refused(m, "root /srv/example/a/bx: downstream owns or reads it")

    def test_a_mount_above_the_root_covers_it(self):
        x = doc()
        x["mounts"][2]["host"] = "/srv/example/a/b"
        x["roots"][1]["readers"] = ["downstream", "upstream"]
        self.assertTrue(hs.load_spec(x))

    def test_a_mount_for_a_principal_with_no_runtime(self):
        def m(x):
            x["principals"]["third"] = {"uid": 2103, "groups": ["hopgrp"]}
            x["mounts"].append({"principal": "third", "host": "/srv/example/a/b", "container": "/x"})
        self.refused(m, "third has no runtime")

    def test_no_checks_never_pass(self):
        lines = []
        self.assertEqual(hs.report([], lines.append), 1)
        self.assertIn("UNKNOWN", lines[0])


class PlanTest(unittest.TestCase):

    def setUp(self):
        self.plan = hs.render_plan(hs.load_spec(doc()))
        self.steps = f"python3 {hs.HOST_STEPS}"

    def test_roots_are_created_parents_first_with_owner_group_and_mode(self):
        roots = [l for l in self.plan if l.startswith(f"{self.steps} root ")]
        self.assertEqual(roots[0], f"{self.steps} root /srv/example/a/b {UP} {GID} 2750  # the shared root")
        order = [l.split()[3] for l in roots]
        self.assertLess(order.index("/srv/example/a/b"), order.index("/srv/example/a/b/inner"))

    def test_the_barrier_fsyncs_every_root_and_ancestor_deepest_first(self):
        barrier = next(l for l in self.plan if l.startswith(f"{self.steps} sync "))
        args = barrier.split()[3:]
        for p in ("/", "/srv", "/srv/example", "/srv/example/a", "/srv/example/a/b/inner",
                  "/srv/example/state/up"):
            self.assertIn(p, args)
        self.assertLess(args.index("/srv/example/a/b/inner"), args.index("/srv/example/a"))

    def test_every_step_goes_through_the_no_follow_helper(self):
        for line in self.plan:
            if f" {hs.ROOT_SH} -c 'ok=1; m=0; " in line:
                # The one exception: root's directories' precheck, read-only (it tests and prints).
                import re
                self.assertIsNone(re.search(r"(^|[\s;{|&(])(mkdir|chmod|chown|rm|mv|install|tee)\s",
                                            line), line)
                self.assertNotIn(">", line.replace(">&2", ""), line)
                continue
            if not line.startswith("#"):
                self.assertTrue(line.startswith(self.steps), line)
        self.assertFalse(any(l.startswith(("install ", "sh -c", "chown", "chmod")) for l in self.plan))

    def test_each_side_gets_the_other_sides_uid(self):
        self.assertIn(f"# downstream's runtime environment: EX_PEER_UID={UP}", self.plan)
        self.assertIn(f"# upstream's runtime environment: EX_PEER_UID={DOWN}", self.plan)

    def test_roots_own_directories_are_made_before_anything_is_placed_in_them(self):
        """The plugin's directory and its parents below the first level are
        made by the helper, root's 0755, shallow first, before the place."""
        made = [l for l in self.plan if l.startswith(f"{self.steps} root ") and l.endswith(" 0 0 0755")]
        self.assertEqual(made, [f"{self.steps} root /srv/example 0 0 0755",
                                f"{self.steps} root /srv/example/overlay 0 0 0755"])
        place = next(i for i, l in enumerate(self.plan) if l.startswith(f"{self.steps} place "))
        self.assertLess(max(self.plan.index(l) for l in made), place)

    def test_the_plan_says_to_run_each_line_alone_and_stop_on_any_failure(self):
        self.assertIn("# Run each command line separately. Continue only after checking that its exit status is 0. "
                      "Any STOP or nonzero status ends this run; do not run the following steps.", self.plan[:3])

    def test_the_precheck_comes_before_roots_own_directories(self):
        made = [i for i, l in enumerate(self.plan) if l.startswith(f"{self.steps} root ") and l.endswith(" 0 0 0755")]
        pre = [i for i, l in enumerate(self.plan) if f" {hs.ROOT_SH} -c 'ok=1; m=0; " in l]
        self.assertEqual(len(pre), 1, self.plan)
        self.assertLess(pre[0], made[0])
        self.assertTrue(self.plan[pre[0]].endswith("' sh / /srv -- /srv/example /srv/example/overlay"),
                        self.plan[pre[0]])

    def test_the_precheck_runs_whole_in_roots_shell(self):
        """One line through sudo: `sudo /bin/sh -c '<script>' sh <parents> -- <dirs>`. The script holds no
        single quote, so the operator's shell passes it whole; a bare `sudo <line>` would elevate only its
        first command."""
        [line] = [l for l in self.plan if f" {hs.ROOT_SH} -c 'ok=1; m=0; " in l]
        self.assertTrue(line.startswith(f"/usr/bin/sudo {hs.ROOT_SH} -c '"), line)
        self.assertNotIn("'", hs.precheck_script())
        self.assertEqual(shlex.split(line)[3], hs.precheck_script())

    def test_a_missing_intermediate_is_made_too_shallow_first(self):
        x = doc()
        x["overlay"]["path"] = "/srv/example/one/two/plugin.py"
        dirs = hs.root_dirs(hs.load_spec(x))
        self.assertEqual(dirs, ["/srv/example", "/srv/example/one", "/srv/example/one/two"])

    def test_the_overlay_is_placed_and_names_its_digest(self):
        line = next(l for l in self.plan if l.startswith(f"{self.steps} place "))
        self.assertIn("/srv/example/overlay/plugin.py", line)
        self.assertIn(f" --sha256 {hs.STUB_SHA256}", line.split("#")[0],
                      "the pin is the place's own argument, so a wrong file is refused, not only commented")

    def test_the_marker_is_created_by_the_helper(self):
        x = doc()
        x["mounts"][0]["marker"] = ".root-id"
        line = next(l for l in hs.render_plan(hs.load_spec(x)) if "root marker" in l)
        self.assertTrue(line.startswith(f"{self.steps} marker /srv/example/a/b/.root-id"))

    def test_nothing_is_run(self):
        self.assertTrue(self.plan[0].startswith("# Run as root"))

    def test_each_runtime_is_told_its_umask_and_none_starts_before_the_steps(self):
        self.assertIn("# upstream's runtime (ex-up) starts under umask 0027: UMask=0027 in its service unit, "
                      "or `umask 0027` in its launcher before it execs", self.plan)
        self.assertIn("# downstream's runtime (ex-down) starts under umask 0022: UMask=0022 in its service "
                      "unit, or `umask 0022` in its launcher before it execs", self.plan)
        self.assertTrue(self.plan[-1].startswith("# Start no runtime until every step above has run"))


class RootsTest(unittest.TestCase):

    def verify(self, fs, denied=()):
        return results(hs.verify_roots(hs.load_spec(doc()), lstat_of(fs, denied)))

    def test_a_good_host_passes_every_check(self):
        r = self.verify(good_fs())
        self.assertTrue(r)
        self.assertEqual(set(r.values()), {rh.PASS})

    def assertFails(self, fs, needle, denied=()):
        r = self.verify(fs, denied)
        bad = {c: v for c, v in r.items() if v != rh.PASS}
        self.assertTrue(any(needle in c for c in bad), bad)
        return bad

    def test_wrong_mode(self):
        fs = good_fs()
        fs["/srv/example/a/b"] = d(0o2770, UP, GID)
        self.assertFails(fs, "/srv/example/a/b is a directory")

    def test_a_root_without_its_setgid_bit_fails(self):
        fs = good_fs()
        fs["/srv/example/a/b/inner"] = d(0o750, DOWN, GID)
        self.assertFails(fs, "/srv/example/a/b/inner is a directory")

    def test_wrong_owner(self):
        fs = good_fs()
        fs["/srv/example/a/b/inner"] = d(0o2750, UP, GID)
        self.assertFails(fs, "/srv/example/a/b/inner is a directory")

    def test_wrong_group(self):
        fs = good_fs()
        fs["/srv/example/state/up"] = d(0o700, UP, GID)
        self.assertFails(fs, "/srv/example/state/up is a directory")

    def test_a_symlink_is_not_the_root(self):
        fs = good_fs()
        fs["/srv/example/state/up"] = St(stat.S_IFLNK | 0o777, UP, UPGRP)
        self.assertFails(fs, "/srv/example/state/up is a directory")

    def test_a_symlinked_ancestor_fails_every_root_beneath_it(self):
        fs = good_fs()
        fs["/srv/example/a"] = St(stat.S_IFLNK | 0o777, 0, 0)
        bad = self.assertFails(fs, "every ancestor of /srv/example/a/b is a real directory")
        self.assertIn("every ancestor of /srv/example/a/b/inner is a real directory", bad)
        self.assertNotIn("every ancestor of /srv/example/state/up is a real directory", bad)

    def test_an_absent_ancestor_fails(self):
        fs = good_fs()
        del fs["/srv/example/state"]
        self.assertFails(fs, "every ancestor of /srv/example/state/up is a real directory")

    def test_absent(self):
        fs = good_fs()
        del fs["/srv/example/a/b/inner"]
        self.assertFails(fs, "inner is a directory")

    def test_an_execute_only_directory_fails_the_reader_it_blocks(self):
        fs = good_fs()
        fs["/srv/example/a/b"] = d(0o2710, UP, GID)
        bad = self.assertFails(fs, "downstream (uid 2102) can read and search every directory from "
                                   "/srv/example/a/b down to /srv/example/a/b/inner")
        self.assertNotIn("/srv/example/state/up is a directory owned by 2101:2201, mode 0700", bad)

    def test_an_ancestor_above_a_readers_mount_does_not_block_it(self):
        fs = good_fs()
        fs["/srv/example/a"] = d(0o700)
        r = self.verify(fs)
        self.assertEqual(r["downstream (uid 2102) can read and search every directory from /srv/example/a/b "
                           "down to /srv/example/a/b"], rh.PASS)
        self.assertEqual(r["downstream (uid 2102) can read and search every directory from /srv/example/a/b "
                           "down to /srv/example/a/b/inner"], rh.PASS)
        self.assertEqual(r["upstream (uid 2101) can read and search every directory from /srv/example/a/b "
                           "down to /srv/example/a/b"], rh.PASS)

    def test_an_owner_who_is_not_a_reader_is_checked_for_reach(self):
        x = doc()
        x["roots"][0].update(mode="0050", readers=["downstream"])
        fs = good_fs()
        fs["/srv/example/a/b"] = d(0o050, UP, GID, 4242)
        checks = hs.verify_roots(hs.load_spec(x), lstat_of(fs))
        r = results(checks)
        self.assertEqual(r["/srv/example/a/b is a directory owned by 2101:2100, mode 0050"], rh.PASS)
        self.assertEqual(r["upstream (uid 2101) can read and search every directory from /srv/example/a/b "
                           "down to /srv/example/a/b"], rh.FAIL)
        self.assertEqual(len(checks), len({c.claim for c in checks}), "each principal is checked once")
        by_claim = {c.claim: c for c in checks}
        reach = "can read and search every directory from /srv/example/a/b down to /srv/example/a/b"
        self.assertEqual(by_claim[f"upstream (uid 2101) {reach}"].expected.provenance,
                         "the host setup's root for the shared root: upstream owns it")
        self.assertEqual(by_claim[f"downstream (uid 2102) {reach}"].expected.provenance,
                         "the host setup's root for the shared root: downstream reads it")
        x["roots"][0]["readers"] = ["upstream", "downstream"]
        again = hs.verify_roots(hs.load_spec(x), lstat_of(fs))
        self.assertEqual(len(again), len({c.claim for c in again}), "an owner who reads is checked once")
        self.assertEqual({c.claim: c for c in again}[f"upstream (uid 2101) {reach}"].expected.provenance,
                         "the host setup's root for the shared root: upstream owns and reads it")

    def test_the_downstream_reader_needs_the_group_bit(self):
        fs = good_fs()
        fs["/srv/example/a/b"] = d(0o2700, UP, GID)
        self.assertFails(fs, "downstream (uid 2102) can read and search")

    def test_an_uninspectable_path_is_unknown_not_fail(self):
        r = self.verify(good_fs(), denied=("/srv/example/state/up",))
        self.assertEqual(r["/srv/example/state/up is a directory owned by 2101:2201, mode 0700"], rh.UNKNOWN)
        r = self.verify(good_fs(), denied=("/srv/example/state",))
        self.assertEqual(r["every ancestor of /srv/example/state/up is a real directory"], rh.UNKNOWN)


class OverlayTest(unittest.TestCase):

    def verify(self, fs=None, production=False, digest=hs.STUB_SHA256, mutate=None, denied=()):
        x = doc()
        if mutate:
            mutate(x)
        dg = (lambda p: digest)
        return results(hs.verify_overlay(hs.load_spec(x), production=production,
                                         lstat=lstat_of(fs or good_fs(), denied), digest=dg))

    def test_plumbing_with_the_stub_passes(self):
        r = self.verify()
        self.assertEqual(set(r.values()), {rh.PASS})
        self.assertFalse(any("not the stub" in c for c in r))

    def test_production_refuses_the_stub(self):
        r = self.verify(production=True)
        self.assertEqual(r["the overlay pins a reviewed plugin, not the stub"], rh.FAIL)

    def test_production_with_a_reviewed_pin_passes(self):
        real = "a" * 64
        r = self.verify(production=True, digest=real,
                        mutate=lambda x: x["overlay"]["pin"].update(sha256=real, commit="b" * 40))
        self.assertEqual(set(r.values()), {rh.PASS})

    def test_writable_or_not_root_owned(self):
        for st in (St(stat.S_IFREG | 0o644, 0, 0), St(stat.S_IFREG | 0o444, UP, 0)):
            fs = good_fs()
            fs["/srv/example/overlay/plugin.py"] = st
            self.assertEqual(self.verify(fs)["the overlay /srv/example/overlay/plugin.py is a regular "
                                             "file owned by root, mode 0444"], rh.FAIL)

    def test_inside_an_agent_path(self):
        fs = good_fs()
        fs["/srv/example/agents/plugin.py"] = St(stat.S_IFREG | 0o444, 0, 0)
        r = self.verify(fs, mutate=lambda x: x["overlay"].update(path="/srv/example/agents/plugin.py"))
        self.assertEqual(r["the overlay /srv/example/agents/plugin.py is outside every agent path"], rh.FAIL)

    def test_bytes_that_do_not_hash_to_the_pin(self):
        self.assertEqual(self.verify(digest="c" * 64)["the overlay's bytes hash to its pin"], rh.FAIL)

    def test_unreadable_is_unknown(self):
        r = self.verify(digest=rh.Unresolved("denied"))
        self.assertEqual(r["the overlay's bytes hash to its pin"], rh.UNKNOWN)

    def test_no_plugin_has_nothing_to_check(self):
        x = doc()
        x["overlay"]["pin"] = None
        self.assertEqual(hs.verify_overlay(hs.load_spec(x), production=True, lstat=lstat_of({})), [])

    def test_the_documents_production_flag_refuses_the_stub(self):
        x = doc()
        x["production"] = True
        r = results(hs.checks(hs.load_spec(x), production=False, lstat=lstat_of(good_fs()),
                              digest=lambda p: hs.STUB_SHA256, openssl={}, containers=good_containers().get,
                              mounts=good_mount, umasks=good_umasks, groups=good_groups))
        self.assertEqual(r["the overlay pins a reviewed plugin, not the stub"], rh.FAIL)


class StubTest(unittest.TestCase):

    def test_the_constant_is_the_files_digest(self):
        self.assertEqual(hashlib.sha256(hs.STUB_PLUGIN.read_bytes()).hexdigest(), hs.STUB_SHA256)

    def test_the_stub_cannot_be_imported_as_a_transport(self):
        with self.assertRaises(ImportError):
            exec(compile(hs.STUB_PLUGIN.read_text(), str(hs.STUB_PLUGIN), "exec"), {})

    def test_the_stub_is_outside_the_agent_payload(self):
        self.assertNotIn("payload", hs.STUB_PLUGIN.relative_to(hs.HERE).parts)

    def test_the_overlay_record_is_the_registrys_closed_shape(self):
        rec = json.loads(hs.overlay_record(hs.stub_pin("/opt/example/plugin.py"), "example.overlay/1"))
        self.assertEqual(set(rec), {"schema", "plugin"})
        self.assertEqual(rec["schema"], "example.overlay/1")
        self.assertEqual(set(rec["plugin"]), {"sha256", "commit", "path"})
        self.assertEqual(json.loads(hs.overlay_record(None, "example.overlay/1"))["plugin"], None)


class ContainerTest(unittest.TestCase):
    """The running container, from `docker inspect`: its image and its bind
    mounts, as the runtime was actually started."""

    INSPECT = ('true\t"img-down"\t[{"Type":"bind","Source":"/srv/example/a/b","Destination":"/data/root",'
               '"Mode":"","RW":true,"Propagation":"rprivate"},{"Type":"volume","Name":"v","Source":'
               '"/var/lib/docker/volumes/v/_data","Destination":"/cache","Driver":"local","Mode":"z",'
               '"RW":true,"Propagation":""}]\n')

    def test_inspect_is_read_into_image_and_binds(self):
        seen = fake_docker(self, lambda argv: rh.Proc(tuple(argv), 0, self.INSPECT, ""))
        self.assertEqual(hs.ask_container("ex-down"),
                         {"image": "img-down", "binds": [("/srv/example/a/b", "/data/root")]})
        self.assertEqual(seen[0][:3], ["docker", "inspect", "-f"])
        self.assertEqual(seen[0][-1], "ex-down")

    def test_a_stopped_container_is_unresolved(self):
        fake_docker(self, lambda argv: rh.Proc(tuple(argv), 0, self.INSPECT.replace("true", "false", 1), ""))
        self.assertIsInstance(hs.ask_container("ex-down"), rh.Unresolved)

    def test_an_absent_container_or_garbage_is_unresolved(self):
        fake_docker(self, lambda argv: rh.Proc(tuple(argv), 1, "", "Error: No such object: ex-down"))
        self.assertIsInstance(hs.ask_container("ex-down"), rh.Unresolved)
        fake_docker(self, lambda argv: rh.Proc(tuple(argv), 0, "nonsense\n", ""))
        self.assertIsInstance(hs.ask_container("ex-down"), rh.Unresolved)

    def test_the_declared_image(self):
        spec = hs.load_spec(doc())
        self.assertEqual(set(results(hs.verify_containers(spec, good_containers())).values()), {rh.PASS})
        seen = good_containers()
        seen["ex-up"]["image"] = "img-other"
        r = results(hs.verify_containers(spec, seen))
        self.assertEqual(r["upstream's running container ex-up is the image img-up"], rh.FAIL)
        seen["ex-up"] = rh.Unresolved("ex-up is not running")
        self.assertEqual(results(hs.verify_containers(spec, seen))[
            "upstream's running container ex-up is the image img-up"], rh.UNKNOWN)


class MountTopologyTest(unittest.TestCase):
    """Each declared mount on the RUNNING container: it binds the host root at
    the declared path, and that path, seen inside the running container, is
    the directory the plan created (inode, owner, group and mode, or the
    root's marker)."""

    BIND = "ex-down binds /srv/example/a/b at /data/root"
    CLAIM = "downstream's durable root /data/root in ex-down is the host directory /srv/example/a/b"
    SAME = (4242, UP, GID, 0o2750)
    OTHER = (9999, UP, GID, 0o2750)

    def verify(self, answer, fs=None, marker=None, host_marker="f00d", seen=None):
        asked = []
        x = doc()
        if marker:
            x["mounts"][0]["marker"] = marker

        def ask(container, path, mk):
            asked.append((container, path, mk))
            return answer if container == "ex-down" else good_mount(container, path, mk)
        checks = hs.verify_mounts(hs.load_spec(x), good_containers() if seen is None else seen,
                                  lstat_of(fs or good_fs()), ask, read_marker=lambda p: host_marker)
        return {c.claim: c for c in checks}, [a for a in asked if a[0] == "ex-down"]

    def test_the_same_directory_passes_by_inode_and_says_so(self):
        r, asked = self.verify((self.SAME, None))
        self.assertEqual(r[self.BIND].result, rh.PASS)
        self.assertEqual(r[self.CLAIM].result, rh.PASS)
        self.assertIn("matched by inode", r[self.CLAIM].expected.provenance)
        self.assertEqual(asked, [("ex-down", "/data/root", None)])

    def test_a_running_container_without_the_declared_bind_fails(self):
        for binds in ([], [("/srv/example/elsewhere", "/data/root")], [("/srv/example/a/b", "/data/other")],
                      [("/srv/example/a/b", "/data/root"), ("/srv/example/x", "/data/root")]):
            seen = good_containers()
            seen["ex-down"]["binds"] = binds
            with self.subTest(binds=binds):
                self.assertEqual(self.verify((self.SAME, None), seen=seen)[0][self.BIND].result, rh.FAIL)

    def test_a_container_not_running_is_unknown_and_nothing_is_asked(self):
        seen = good_containers()
        seen["ex-down"] = rh.Unresolved("ex-down is not running")
        r, asked = self.verify((self.SAME, None), seen=seen)
        self.assertEqual(r[self.BIND].result, rh.UNKNOWN)
        self.assertEqual(r[self.CLAIM].result, rh.UNKNOWN)
        self.assertEqual(asked, [])

    def test_another_directory_fails(self):
        for other in (self.OTHER, (4242, DOWN, GID, 0o2750), (4242, UP, GID, 0o2770)):
            with self.subTest(other=other):
                self.assertEqual(self.verify((other, None))[0][self.CLAIM].result, rh.FAIL)

    def test_an_inode_mismatch_passes_when_the_marker_matches_and_says_so(self):
        r, asked = self.verify((self.OTHER, "f00d"), marker=".root-id")
        self.assertEqual(r[self.CLAIM].result, rh.PASS)
        self.assertIn("matched by the root's marker", r[self.CLAIM].expected.provenance)
        self.assertEqual(asked[0][2], ".root-id")

    def test_neither_matching_fails(self):
        r, _ = self.verify((self.OTHER, "beef"), marker=".root-id")
        self.assertEqual(r[self.CLAIM].result, rh.FAIL)
        self.assertIn("neither", r[self.CLAIM].expected.provenance)

    def test_no_marker_on_the_host_never_matches_an_empty_one(self):
        r, _ = self.verify((self.OTHER, None), marker=".root-id", host_marker=None)
        self.assertEqual(r[self.CLAIM].result, rh.FAIL)

    def test_no_answer_is_unknown(self):
        self.assertEqual(self.verify(rh.Unresolved("docker absent"))[0][self.CLAIM].result, rh.UNKNOWN)

    def test_an_absent_host_directory_is_unknown_and_nothing_is_asked(self):
        fs = good_fs()
        del fs["/srv/example/a/b"]
        r, asked = self.verify((self.SAME, None), fs)
        self.assertEqual(r[self.CLAIM].result, rh.UNKNOWN)
        self.assertEqual(asked, [])

    def test_a_marker_must_be_one_name_inside_the_root(self):
        for bad in ("../x", "a/b", "..", ""):
            x = doc()
            x["mounts"][0]["marker"] = bad
            with self.subTest(bad=bad), self.assertRaises(hs.SpecError):
                hs.load_spec(x)

    def test_the_running_container_is_asked_read_only(self):
        seen = fake_docker(self, lambda argv: rh.Proc(tuple(argv), 0, "4242 2101 2100 2750\nf00d\n", ""))
        self.assertEqual(hs.ask_mount("ex-down", "/data/root", ".root-id"), ((4242, UP, GID, 0o2750), "f00d"))
        argv = seen[0]
        self.assertEqual(argv[:5], ["docker", "exec", "-u", "0", "ex-down"])
        self.assertEqual(argv[-2:], ["/data/root", ".root-id"])
        self.assertNotIn("run", argv)

    def test_garbled_stat_output_is_unknown(self):
        fake_docker(self, lambda argv: rh.Proc(tuple(argv), 0, "stat: not found\n", ""))
        self.assertIsInstance(hs.ask_mount("c", "/b"), rh.Unresolved)

    def test_the_device_number_is_not_compared(self):
        self.assertEqual(hs._identity(os.stat_result((stat.S_IFDIR | 0o750, 7, 99, 1, 5, 6, 0, 0, 0, 0))),
                         (7, 5, 6, 0o750))

    def test_a_fifo_at_the_host_marker_is_unresolved_not_a_hang(self):
        with tempfile.TemporaryDirectory() as t:
            os.mkfifo(os.path.join(t, "marker"))
            self.assertIsInstance(hs._read_marker(os.path.join(t, "marker")), rh.Unresolved)

    def test_the_host_marker_is_not_read_through_a_link(self):
        with tempfile.TemporaryDirectory() as t:
            real = os.path.join(t, "real")
            with open(real, "w") as f:
                f.write("f00d")
            os.symlink(real, os.path.join(t, "marker"))
            self.assertIsInstance(hs._read_marker(os.path.join(t, "marker")), rh.Unresolved)
            self.assertEqual(hs._read_marker(real), "f00d")
            self.assertIsNone(hs._read_marker(os.path.join(t, "absent")))


class OpensslTest(unittest.TestCase):

    def verify(self, out):
        r = results(hs.verify_openssl(hs.load_spec(doc()), {"img-up": out, "img-down": out}))
        return {c: v for c, v in r.items() if c.startswith("img-up")}

    def test_the_recorded_version(self):
        self.assertEqual(set(self.verify("OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13)").values()),
                         {rh.PASS})

    def test_below_the_floor_fails_both(self):
        r = self.verify("OpenSSL 1.1.1w  11 Sep 2023")
        self.assertEqual(set(r.values()), {rh.FAIL})

    def test_a_different_version_above_the_floor_fails_only_the_pin(self):
        r = self.verify("OpenSSL 3.3.1 4 Jun 2024")
        self.assertEqual(r["img-up's openssl is the recorded 3.0.13"], rh.FAIL)
        self.assertEqual(r["img-up's openssl is at least 3.0"], rh.PASS)

    def test_no_answer_is_unknown(self):
        self.assertEqual(set(self.verify(rh.Unresolved("docker absent")).values()), {rh.UNKNOWN})
        self.assertEqual(set(self.verify("LibreSSL 3.3.6").values()), {rh.UNKNOWN})

    def test_the_image_is_asked_offline_never_pulling_at_its_recorded_path(self):
        seen = fake_docker(self, lambda argv: rh.Proc(tuple(argv), 0, "OpenSSL 3.0.13 30 Jan 2024\n", ""))
        self.assertEqual(hs.ask_openssl({"img-down": "/usr/bin/openssl"}),
                         {"img-down": "OpenSSL 3.0.13 30 Jan 2024\n"})
        self.assertEqual(seen[0], ["docker", "run", "--rm", "--pull", "never", "--network", "none",
                                   "--entrypoint", "/usr/bin/openssl", "img-down", "version"])
        fake_docker(self, lambda argv: rh.Proc(tuple(argv), 1, "", "No such image"))
        self.assertIsInstance(hs.ask_openssl({"img-up": "openssl"})["img-up"], rh.Unresolved)

    def test_the_verb_asks_each_image_at_its_recorded_path(self):
        asked = []
        orig = hs.ask_openssl
        hs.ask_openssl = lambda images: asked.append(dict(images)) or {}
        self.addCleanup(setattr, hs, "ask_openssl", orig)
        hs.checks(hs.load_spec(doc()), production=False, lstat=lstat_of(good_fs()),
                  digest=lambda p: hs.STUB_SHA256, containers=good_containers().get,
                  mounts=good_mount, umasks=good_umasks)
        self.assertEqual(asked, [{"img-up": "openssl", "img-down": "/usr/bin/openssl"}])


def status(pid, uid, umask=None, name="python3"):
    """One /proc/<pid>/status as Linux prints it (fields trimmed to the
    ones read, in kernel order; Umask is present from Linux 4.7)."""
    s = f"Name:\t{name}\n"
    if umask is not None:
        s += f"Umask:\t{umask}\n"
    return s + (f"State:\tS (sleeping)\nTgid:\t{pid}\nNgid:\t0\nPid:\t{pid}\nPPid:\t1\n"
                f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{GID}\t{GID}\t{GID}\t{GID}\n")


def probe(pid, *rows):
    """The probe's output: its own pid, then the status files it read."""
    return f"probe {pid}\n" + "".join(rows)


class UmaskTest(unittest.TestCase):

    def verify(self, answers):
        return {c.claim.split(" (")[0]: c for c in
                hs.verify_umasks(hs.load_spec(doc()), lambda c: answers[c])}

    def good(self):
        return {"ex-up": hs.parse_proc_status(probe(90, status(1, UP, "0027"), status(7, UP, "0027", "sh"),
                                                    status(8, 0, "0022", "init"))),
                "ex-down": hs.parse_proc_status(probe(90, status(1, DOWN, "0022")))}

    def test_the_declared_umask_passes(self):
        self.assertEqual({c.result for c in self.verify(self.good()).values()}, {rh.PASS})

    def test_the_probes_own_shell_is_not_read_even_at_the_runtimes_uid(self):
        a = self.good()
        a["ex-up"] = hs.parse_proc_status(probe(90, status(1, UP, "0027"), status(90, UP, "0022", "sh")))
        self.assertEqual(a["ex-up"], [(UP, 0o027)])
        self.assertEqual(self.verify(a)["every process of upstream"].result, rh.PASS)

    def test_a_live_container_whose_runtime_is_gone_is_unknown(self):
        a = self.good()
        a["ex-up"] = hs.parse_proc_status(probe(90, status(1, 0, "0022", "tini"), status(90, UP, "0027", "sh")))
        c = self.verify(a)["every process of upstream"]
        self.assertEqual(c.result, rh.UNKNOWN)
        self.assertIn("no process running as uid", c.reason)

    def test_a_process_under_another_umask_fails_its_runtime_only(self):
        a = self.good()
        a["ex-up"] = hs.parse_proc_status(probe(90, status(1, UP, "0027"), status(5, UP, "0077", "worker")))
        r = self.verify(a)
        self.assertEqual(r["every process of upstream"].result, rh.FAIL)
        self.assertEqual(r["every process of upstream"].actual, [0o027, 0o077])
        self.assertEqual(r["every process of downstream"].result, rh.PASS)

    def test_0022_where_0027_is_declared_fails(self):
        a = self.good()
        a["ex-up"] = hs.parse_proc_status(probe(90, status(1, UP, "0022")))
        self.assertEqual(self.verify(a)["every process of upstream"].result, rh.FAIL)

    def test_only_the_runtimes_own_uid_is_read(self):
        a = self.good()
        a["ex-up"] = hs.parse_proc_status(probe(90, status(1, UP, "0027"), status(2, DOWN, "0077")))
        self.assertEqual(self.verify(a)["every process of upstream"].result, rh.PASS)

    def test_a_kernel_without_the_umask_field_is_unknown(self):
        a = self.good()
        a["ex-up"] = hs.parse_proc_status(probe(90, status(1, UP, "0027"), status(2, UP)))
        self.assertEqual(self.verify(a)["every process of upstream"].result, rh.UNKNOWN)

    def test_a_wrong_umask_beside_a_process_without_the_field_fails(self):
        a = self.good()
        a["ex-up"] = hs.parse_proc_status(probe(90, status(1, UP, "0077"), status(2, UP)))
        self.assertEqual(self.verify(a)["every process of upstream"].result, rh.FAIL)

    def test_no_answer_is_unknown(self):
        a = self.good()
        a["ex-down"] = rh.Unresolved("no such container")
        self.assertEqual(self.verify(a)["every process of downstream"].result, rh.UNKNOWN)

    def test_the_running_container_is_asked_read_only_as_a_uid_no_runtime_has(self):
        seen = fake_docker(self, lambda argv: rh.Proc(tuple(argv), 0, probe(90, status(1, UP, "0027")), ""))
        self.assertEqual(hs.ask_umasks("ex-up"), [(UP, 0o027)])
        argv = seen[0]
        self.assertEqual(argv[:7], ["docker", "exec", "-u", str(hs.PROBE_UID), "ex-up", "sh", "-c"])
        script = argv[7]
        self.assertTrue(script.startswith('echo "probe $$";'))
        self.assertIn('"/proc/$$/status") continue', script)
        self.assertNotIn(">", script.replace("2>/dev/null", ""))
        fake_docker(self, lambda argv: rh.Proc(tuple(argv), 1, "", "No such container: ex-up"))
        self.assertIsInstance(hs.ask_umasks("ex-up"), rh.Unresolved)

    def test_no_runtime_may_run_as_the_probes_uid(self):
        x = doc()
        x["principals"]["upstream"]["uid"] = hs.PROBE_UID
        with self.assertRaises(hs.SpecError):
            hs.load_spec(x)

    def test_the_effective_uid_is_the_one_read(self):
        text = f"probe 9\nName:\tx\nUmask:\t0027\nPid:\t3\nUid:\t0\t{UP}\t{UP}\t{UP}\n"
        self.assertEqual(hs.parse_proc_status(text), [(UP, 0o027)])


def gstatus(pid, uid, gid, groups, name="python3"):
    """One /proc/<pid>/status with the group fields, as Linux prints them:
    Gid's four tab-separated ids, and Groups as space-separated ids each
    followed by a space (an empty list prints nothing after the tab)."""
    return (f"Name:\t{name}\nUmask:\t0027\nState:\tS (sleeping)\nTgid:\t{pid}\nNgid:\t0\n"
            f"Pid:\t{pid}\nPPid:\t1\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
            f"Gid:\t{gid}\t{gid}\t{gid}\t{gid}\nFDSize:\t64\n"
            f"Groups:\t{''.join(f'{g} ' for g in groups)}\nNStgid:\t{pid}\n")


class GroupsTest(unittest.TestCase):

    def verify(self, answers):
        return {c.claim.split(" (")[0]: c for c in
                hs.verify_groups(hs.load_spec(doc()), lambda c: answers[c])}

    def good(self):
        return {"ex-up": hs.parse_proc_groups(probe(90, gstatus(1, UP, UPGRP, [GID]),
                                                    gstatus(8, 0, 0, [], "init"))),
                "ex-down": hs.parse_proc_groups(probe(90, gstatus(1, DOWN, 2202, [GID])))}

    def test_the_declared_groups_pass(self):
        self.assertEqual({c.result for c in self.verify(self.good()).values()}, {rh.PASS})

    def test_the_primary_group_listed_again_among_the_supplementary_passes(self):
        a = self.good()
        a["ex-up"] = hs.parse_proc_groups(probe(90, gstatus(1, UP, UPGRP, [UPGRP, GID])))
        self.assertEqual(self.verify(a)["every process of upstream"].result, rh.PASS)

    def test_a_runtime_without_the_hop_group_fails_its_runtime_only(self):
        a = self.good()
        a["ex-up"] = hs.parse_proc_groups(probe(90, gstatus(1, UP, UPGRP, [])))
        r = self.verify(a)
        self.assertEqual(r["every process of upstream"].result, rh.FAIL)
        self.assertEqual(r["every process of downstream"].result, rh.PASS)

    def test_another_principals_group_fails(self):
        a = self.good()
        a["ex-up"] = hs.parse_proc_groups(probe(90, gstatus(1, UP, UPGRP, [GID, 2202])))
        self.assertEqual(self.verify(a)["every process of upstream"].result, rh.FAIL)

    def test_the_wrong_primary_group_fails(self):
        a = self.good()
        a["ex-up"] = hs.parse_proc_groups(probe(90, gstatus(1, UP, GID, [UPGRP])))
        self.assertEqual(self.verify(a)["every process of upstream"].result, rh.FAIL)

    def test_one_process_without_the_group_fails(self):
        a = self.good()
        a["ex-up"] = hs.parse_proc_groups(probe(90, gstatus(1, UP, UPGRP, [GID]),
                                                gstatus(5, UP, UPGRP, [], "worker")))
        self.assertEqual(self.verify(a)["every process of upstream"].result, rh.FAIL)

    def test_the_probes_own_shell_is_not_read(self):
        a = self.good()
        a["ex-up"] = hs.parse_proc_groups(probe(90, gstatus(1, UP, UPGRP, [GID]),
                                                gstatus(90, UP, 0, [], "sh")))
        self.assertEqual(self.verify(a)["every process of upstream"].result, rh.PASS)

    def test_no_process_no_field_or_no_answer_is_unknown(self):
        for answer in (hs.parse_proc_groups(probe(90, gstatus(1, 0, 0, [], "tini"))),
                       hs.parse_proc_groups(probe(90, status(1, UP, "0027"))),
                       rh.Unresolved("no such container")):
            a = self.good()
            a["ex-up"] = answer
            self.assertEqual(self.verify(a)["every process of upstream"].result, rh.UNKNOWN, answer)

    def test_a_wrong_group_beside_a_process_without_the_fields_fails(self):
        a = self.good()
        a["ex-up"] = hs.parse_proc_groups(probe(90, gstatus(1, UP, UPGRP, []), status(2, UP, "0027")))
        self.assertEqual(self.verify(a)["every process of upstream"].result, rh.FAIL)

    def test_the_right_groups_beside_a_process_without_the_fields_is_unknown(self):
        a = self.good()
        a["ex-up"] = hs.parse_proc_groups(probe(90, gstatus(1, UP, UPGRP, [GID]), status(2, UP, "0027")))
        c = self.verify(a)["every process of upstream"]
        self.assertEqual(c.result, rh.UNKNOWN)
        self.assertIn("reports no groups", c.reason)

    def test_the_effective_ids_are_the_ones_read(self):
        text = (f"probe 9\nName:\tx\nPid:\t3\nUid:\t0\t{UP}\t{UP}\t{UP}\n"
                f"Gid:\t0\t{UPGRP}\t{UPGRP}\t{UPGRP}\nGroups:\t{GID} \n")
        self.assertEqual(hs.parse_proc_groups(text), [(UP, (UPGRP, (GID,)))])

    def test_the_verb_probes_each_container_once_for_both_umask_and_groups(self):
        procs = {"ex-up": probe(90, gstatus(1, UP, UPGRP, [GID])),
                 "ex-down": probe(90, gstatus(1, DOWN, 2202, [GID]).replace("Umask:\t0027", "Umask:\t0022"))}
        seen = fake_docker(self, lambda argv: rh.Proc(tuple(argv), 0, procs[argv[4]], ""))
        found = hs.checks(hs.load_spec(doc()), production=False, lstat=lstat_of(good_fs()),
                          digest=lambda p: hs.STUB_SHA256, openssl={}, containers=good_containers().get,
                          mounts=good_mount)
        for argv in seen:   # every other probe is injected, so each call is the /proc exec
            self.assertEqual(argv[:4], ["docker", "exec", "-u", str(hs.PROBE_UID)], argv)
            self.assertGreater(len(argv), 7, argv)
        self.assertEqual(sorted(a[4] for a in seen if a[7] == hs._PROC_SCRIPT), ["ex-down", "ex-up"])
        by = {c.claim.split(" (")[0] + c.claim.split(" runs ")[1][:4]: c.result for c in found
              if c.claim.startswith("every process of")}
        self.assertEqual(set(by.values()), {rh.PASS}, by)
        self.assertEqual(len(by), 4)

    def test_the_running_container_is_asked_with_the_same_read_only_probe(self):
        seen = fake_docker(self, lambda argv: rh.Proc(tuple(argv), 0,
                                                      probe(90, gstatus(1, UP, UPGRP, [GID])), ""))
        self.assertEqual(hs.ask_groups("ex-up"), [(UP, (UPGRP, (GID,)))])
        self.assertEqual(seen[0][:7], ["docker", "exec", "-u", str(hs.PROBE_UID), "ex-up", "sh", "-c"])
        self.assertEqual(seen[0][7], hs._PROC_SCRIPT)
        fake_docker(self, lambda argv: rh.Proc(tuple(argv), 1, "", "No such container: ex-up"))
        self.assertIsInstance(hs.ask_groups("ex-up"), rh.Unresolved)


class VerbTest(unittest.TestCase):
    """The verb: the plan, then the checks, and an exit status that counts an
    UNKNOWN as a problem. Docker is never reached: conftest refuses it, and
    each probe here is a fake."""

    def write(self, x):
        p = os.path.join(tempfile.mkdtemp(), "host-setup.json")
        with open(p, "w") as f:
            json.dump(x, f)
        return p

    def probes(self, **kw):
        kw.setdefault("digest", lambda p: hs.STUB_SHA256)
        kw.setdefault("containers", good_containers().get)
        kw.setdefault("mounts", good_mount)
        kw.setdefault("umasks", good_umasks)
        kw.setdefault("groups", good_groups)
        return kw

    def run_verb(self, x, fs, **kw):
        lines = []
        rc = hs.run(None if x is None else self.write(x), production=False, lstat=lstat_of(fs),
                    out=lines.append, **self.probes(**kw))
        return rc, "\n".join(lines)

    OPENSSL = {"img-up": "OpenSSL 3.0.13 x", "img-down": "OpenSSL 3.0.13 x"}

    def test_a_good_host_with_its_openssl_reported_exits_0(self):
        rc, out = self.run_verb(doc(), good_fs(), openssl=self.OPENSSL)
        self.assertEqual(rc, 0, out)
        self.assertIn("Nothing here has run", out)

    def test_unknown_is_a_problem(self):
        rc, out = self.run_verb(doc(), good_fs(), openssl={})
        self.assertEqual(rc, 1)
        self.assertIn("UNKNOWN", out)

    def test_a_failure_names_its_fix(self):
        fs = good_fs()
        fs["/srv/example/a/b"] = d(0o2777, UP, GID)
        rc, out = self.run_verb(doc(), fs, openssl=self.OPENSSL)
        self.assertEqual(rc, 1)
        self.assertIn("fix: run the plan's `root` step for /srv/example/a/b", out)

    def test_an_unusable_document_is_refused(self):
        for bad in ({"schema": "other"}, {"schema": hs.SPEC_SCHEMA}):
            rc, out = self.run_verb(bad, good_fs())
            self.assertEqual(rc, 2, out)

    def test_the_document_can_come_from_the_overlays_section(self):
        overlay = self.write({"registry": {}, "host_setup": doc()})
        rc, out = self.run_verb(None, good_fs(), openssl=self.OPENSSL, overlay=overlay)
        self.assertEqual(rc, 0, out)

    def test_spec_wins_over_the_overlay(self):
        overlay = self.write({"host_setup": {"schema": "other"}})
        rc, out = self.run_verb(doc(), good_fs(), openssl=self.OPENSSL, overlay=overlay)
        self.assertEqual(rc, 0, out)

    def test_neither_a_spec_nor_an_overlay_section_is_refused(self):
        rc, out = self.run_verb(None, good_fs())
        self.assertEqual(rc, 2)
        self.assertIn("no host-setup document", out)
        rc, out = self.run_verb(None, good_fs(), overlay=self.write({"registry": {}}))
        self.assertEqual(rc, 2)
        self.assertIn("has no 'host_setup' object", out)

    def test_a_missing_group_fails_the_verb(self):
        rc, out = self.run_verb(doc(), good_fs(), openssl=self.OPENSSL,
                                groups=lambda c: [(UP, (UPGRP, ()))] if c == "ex-up" else good_groups(c))
        self.assertEqual(rc, 1)
        self.assertIn(f"FAIL    every process of upstream (uid {UP}) in ex-up runs with gid {UPGRP}", out)

    def test_a_wrong_umask_fails_the_verb(self):
        rc, out = self.run_verb(doc(), good_fs(), openssl=self.OPENSSL,
                                umasks=lambda c: [(UP, 0o077)] if c == "ex-up" else [(DOWN, 0o022)])
        self.assertEqual(rc, 1)
        self.assertIn("FAIL    every process of upstream (uid 2101) in ex-up runs under umask 0027", out)
        self.assertIn("fix: set UMask=0027 in upstream's service unit", out)


class VerifySectionTest(unittest.TestCase):
    """verify's host-setup part: configured by the overlay's section."""

    def write(self, x):
        p = os.path.join(tempfile.mkdtemp(), "overlay.json")
        with open(p, "w") as f:
            json.dump(x, f)
        return p

    def section(self, overlay, **kw):
        lines = []
        kw.setdefault("lstat", lstat_of(good_fs()))
        kw.setdefault("digest", lambda p: hs.STUB_SHA256)
        kw.setdefault("containers", good_containers().get)
        kw.setdefault("mounts", good_mount)
        kw.setdefault("umasks", good_umasks)
        kw.setdefault("groups", good_groups)
        kw.setdefault("openssl", VerbTest.OPENSSL)
        rc = hs.verify_section(overlay, out=lines.append, **kw)
        return rc, "\n".join(lines)

    def test_no_overlay_is_not_configured(self):
        self.assertEqual(self.section(None), (0, ""))

    def test_an_overlay_without_the_section_says_so(self):
        rc, out = self.section(self.write({"registry": {}}))
        self.assertEqual(rc, 0)
        self.assertIn("not checked", out)

    def test_a_configured_good_host_passes(self):
        rc, out = self.section(self.write({"host_setup": doc()}))
        self.assertEqual(rc, 0, out)
        self.assertIn("PASS", out)

    def test_an_unknown_fails_verify(self):
        rc, out = self.section(self.write({"host_setup": doc()}), umasks=lambda c: rh.Unresolved("down"))
        self.assertEqual(rc, 1)

    def test_an_unusable_section_fails_verify(self):
        for bad in ({"host_setup": {"schema": hs.SPEC_SCHEMA}}, {"host_setup": []}):
            rc, out = self.section(self.write(bad))
            self.assertEqual(rc, 1, out)
            self.assertIn("UNKNOWN host setup", out)
        rc, out = self.section("/nonexistent/overlay.json")
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()


class VerifyRunsTheHostSetupTest(unittest.TestCase):
    """`verify` itself runs the configured host-setup checks: the install
    and fleet parts are made to pass, so the host setup is the only thing
    that can decide the exit status. Docker is refused by conftest, so
    every container probe is UNKNOWN."""

    def verify(self, overlay):
        import io
        from contextlib import redirect_stdout
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import patch
        import amap_sandy as prov
        args = SimpleNamespace(host_facts=None, servers=prov.DEFAULT_SERVERS, overlay=overlay)
        buf = io.StringIO()
        with patch.object(prov, "run_provision", lambda *a, **k: 0), \
                patch.object(prov, "run_verify", lambda *a, **k: 0), redirect_stdout(buf):
            rc = prov.run_verify_command(args, Path(tempfile.mkdtemp()), Path(tempfile.mkdtemp()))
        return rc, buf.getvalue()

    def write(self, x):
        p = os.path.join(tempfile.mkdtemp(), "overlay.json")
        with open(p, "w") as f:
            json.dump(x, f)
        return p

    def test_a_configured_host_setup_that_cannot_be_checked_fails_verify(self):
        rc, out = self.verify(self.write({"host_setup": doc()}))
        self.assertEqual(rc, 1, out)
        self.assertIn("verify: the hop deployment's host setup", out)
        self.assertIn("UNKNOWN", out)

    def test_without_the_section_or_an_overlay_verify_is_unchanged(self):
        self.assertEqual(self.verify(None), (0, "verify (1/2): is the install up to date?\n\n"
                                               "verify (2/2): the checks the install cannot make\n"))
        rc, out = self.verify(self.write({"registry": {}}))
        self.assertEqual(rc, 0, out)



class RootDirsPrecheckTest(unittest.TestCase):
    """The precheck line, executed by /bin/sh as printed. The fixture stands in
    for / and the first level (the suite never runs as root, so -O is the
    test's own uid)."""

    def setUp(self):
        import tempfile
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.top = os.path.join(os.path.realpath(d.name), "top")
        os.makedirs(os.path.join(self.top, "amap"))
        for p in (os.path.realpath(d.name), self.top, os.path.join(self.top, "amap")):
            os.chmod(p, 0o755)
        self.dirs = [os.path.join(self.top, "amap"), os.path.join(self.top, "amap", "plugin")]

    def run_line(self, parents=None, find=hs.FIND, dirs=None):
        import shlex
        import subprocess
        line = hs.root_dirs_precheck(dirs or self.dirs, shlex.quote, parents=parents or [self.top], find=find,
                                     sudo=None, uid=str(os.geteuid()), gid=str(os.stat(self.dirs[0]).st_gid))
        return subprocess.run(["/bin/sh", "-c", line], capture_output=True, text=True)

    def stub_find(self, body):
        stub = os.path.join(os.path.dirname(self.top), "find-stub")
        with open(stub, "w") as f:
            f.write("#!/bin/sh\n" + body + "\n")
        os.chmod(stub, 0o755)
        return stub

    def test_a_failing_find_is_never_an_empty_answer(self):
        """find's status is checked: a find that fails, printing nothing, STOPs
        even on a group-writable directory it would have named."""
        os.chmod(self.dirs[0], 0o775)
        self.addCleanup(os.chmod, self.dirs[0], 0o755)
        p = self.run_line(find=self.stub_find("exit 1"))
        self.assertEqual(p.returncode, 1, (p.stdout, p.stderr))
        self.assertIn("STOP:", p.stderr)

    def test_a_parent_not_owned_by_the_running_uid_stops(self):
        """/ is root's and the suite never runs as root, so -O refuses it."""
        if os.geteuid() == 0:
            self.skipTest("as root, / is the running uid's")
        p = self.run_line(parents=["/"])
        self.assertEqual(p.returncode, 1, (p.stdout, p.stderr))
        self.assertIn("STOP: / is not a real root directory", p.stderr)

    def test_find_is_named_by_its_absolute_path(self):
        import shlex
        line = hs.root_dirs_precheck(self.dirs, shlex.quote)
        self.assertIn("scan=$(/usr/bin/find ", line)
        self.assertNotIn("$(find ", line)

    def test_an_existing_safe_parent_and_an_absent_dir_pass(self):
        p = self.run_line()
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_each_unsafe_state_stops_with_status_1(self):
        amap, plugin = self.dirs
        cases = (("a group-writable existing dir", lambda: os.chmod(amap, 0o775), amap),
                 ("a world-writable parent", lambda: os.chmod(self.top, 0o757), self.top),
                 ("a symlink where a dir is to be made", lambda: os.symlink(amap, plugin), plugin),
                 ("a dangling symlink where a dir is to be made",
                  lambda: os.symlink(os.path.join(self.top, "nowhere"), plugin), plugin),
                 ("an existing dir of the right owner but mode 0700", lambda: os.mkdir(plugin, 0o700), plugin),
                 ("an existing dir of the right owner but mode 0750", lambda: (os.mkdir(plugin), os.chmod(plugin, 0o750)),
                  plugin),
                 ("an existing dir that is setgid 2755", lambda: (os.mkdir(plugin), os.chmod(plugin, 0o2755)), plugin),
                 ("a file where a dir is to be made", lambda: open(plugin, "w").close(), plugin))
        for name, make, where in cases:
            with self.subTest(name=name):
                make()
                try:
                    p = self.run_line()
                finally:
                    os.chmod(amap, 0o755)
                    os.chmod(self.top, 0o755)
                    if os.path.islink(plugin) or os.path.isfile(plugin):
                        os.unlink(plugin)
                    elif os.path.isdir(plugin):
                        os.rmdir(plugin)
                self.assertEqual(p.returncode, 1, (p.stdout, p.stderr))
                self.assertIn(f"STOP: {where}", p.stderr)

    def test_an_existing_dir_that_is_exactly_root_0755_passes(self):
        os.mkdir(self.dirs[1])
        os.chmod(self.dirs[1], 0o755)
        p = self.run_line()
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_a_link_is_never_a_safe_directory_even_when_find_says_nothing(self):
        """`[ ! -L ]` itself, not find, refuses a live link to a safe directory: a find stub that prints
        nothing and exits 0 would pass every find test."""
        link = os.path.join(os.path.dirname(self.top), "top-link")
        os.symlink(self.top, link)
        p = self.run_line(parents=[link], find=self.stub_find("exit 0"))
        self.assertEqual(p.returncode, 1, (p.stdout, p.stderr))
        self.assertIn(f"STOP: {link} is not a real root directory", p.stderr)

    def test_a_leaf_link_is_refused_where_install_d_would_follow_it(self):
        """A leaf a later `install -d` makes, as a link to a directory or a dangling link: STOP, never
        adopted (install -d follows the link and re-modes, as root re-owns, its target)."""
        leaf = os.path.join(self.dirs[0], "etc")
        target = os.path.join(self.top, "elsewhere")
        os.mkdir(target, 0o700)
        for name, dest in (("a link to a directory", target), ("a dangling link", target + "-gone")):
            with self.subTest(name=name):
                os.symlink(dest, leaf)
                p = self.run_line(dirs=self.dirs + [leaf])
                os.unlink(leaf)
                self.assertEqual(p.returncode, 1, (p.stdout, p.stderr))
                self.assertIn(f"STOP: {leaf} exists", p.stderr)
