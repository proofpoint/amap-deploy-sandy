"""host_setup: the hop deployment's host plan, rendered and verified.

Every path, principal and group here is invented. The module knows no
runtime's directory names, and a real host's document is operator data. The
filesystem is a fake `lstat` over a dict, so each owner, mode and ancestor
can be broken one at a time.
"""

import copy
import hashlib
import json
import os
import stat
import unittest
from collections import namedtuple

import host_setup as hs
import router_health as rh

St = namedtuple("St", "st_mode st_uid st_gid st_ino", defaults=(0,))
UP, DOWN, GID = 2101, 2102, 2100


def doc():
    return {"schema": hs.SPEC_SCHEMA,
            "groups": {"hopgrp": GID, "upgrp": 2201, "downgrp": 2202},
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
            "openssl": {"img-up": {"version": "3.0.13", "floor": "3.0", "source": "example base image"}},
            "mounts": [{"principal": "downstream", "image": "img-down", "host": "/srv/example/a/b",
                        "container": "/data/root"}],
            "runtimes": [{"principal": "upstream", "container": "ex-up", "umask": "0027"},
                         {"principal": "downstream", "container": "ex-down", "umask": "0022"}]}


def d(mode, uid=0, gid=0):
    return St(stat.S_IFDIR | mode, uid, gid)


def good_fs():
    return {"/": d(0o755), "/srv": d(0o755), "/srv/example": d(0o755), "/srv/example/a": d(0o755),
            "/srv/example/a/b": St(stat.S_IFDIR | 0o2750, UP, GID, 4242),
            "/srv/example/a/b/inner": d(0o2750, DOWN, GID),
            "/srv/example/state": d(0o755), "/srv/example/state/up": d(0o700, UP, 2201),
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


def results(checks):
    return {c.claim: c.result for c in checks}


class SpecTest(unittest.TestCase):

    def test_a_good_document_loads(self):
        s = hs.load_spec(doc())
        self.assertEqual(s.principals["upstream"].gids, (2201, GID))
        self.assertEqual(s.roots[0].mode, 0o2750)

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
        self.refused(lambda x: x["roots"][0].update(group="nogrp"), "not declared")
        self.refused(lambda x: x["roots"][0].update(mode="rwx"), "octal")
        self.refused(lambda x: x["roots"].append(dict(x["roots"][0])), "listed twice")
        self.refused(lambda x: x["roots"][0].update(path="/srv/example/../x"), "normalised")
        self.refused(lambda x: x["overlay"]["pin"].update(url="https://example.org"), "exactly sha256")
        self.refused(lambda x: x["roots"][0].update(readers=["nobody"]), "declared principals")
        self.refused(lambda x: x["openssl"]["img-up"].update(version="3"), "X.Y.Z")
        self.refused(lambda x: x["openssl"]["img-up"].update(floor="three"), "X.Y")
        self.refused(lambda x: x["hops"][0].update(peer_uid_env="bad name"), "environment variable")
        self.refused(lambda x: x["mounts"][0].update(host="/srv/example/other"), "one of the roots")
        self.refused(lambda x: x["mounts"][0].update(principal="nobody"), "not declared")
        self.refused(lambda x: x["openssl"]["img-up"].update(floor="1.1", version="1.1.1"), "below 3.0")
        self.refused(lambda x: x["openssl"]["img-up"].update(floor="3.2"), "below its own floor")
        for bad in ("0077", "0002", "0000", "027", 23):
            self.refused(lambda x: x["runtimes"][0].update(umask=bad), "must be one of 0027, 0022")
        self.refused(lambda x: x["runtimes"][0].update(principal="nobody"), "not declared")
        self.refused(lambda x: x["runtimes"][0].update(container="a b"), "container name")
        self.refused(lambda x: x["runtimes"][0].pop("umask"), "exactly principal, container and umask")
        self.refused(lambda x: x["runtimes"][1].update(container="ex-up"), "listed twice")

    def test_floor_3_0_is_accepted(self):
        self.assertEqual(hs.load_spec(doc()).openssl["img-up"]["floor"], (3, 0))

    def test_a_null_pin_is_no_plugin(self):
        x = doc()
        x["overlay"]["pin"] = None
        self.assertIsNone(hs.load_spec(x).overlay_pin)


class PlanTest(unittest.TestCase):

    def setUp(self):
        self.plan = hs.render_plan(hs.load_spec(doc()))

    def test_roots_are_created_parents_first_with_owner_group_and_mode(self):
        installs = [l for l in self.plan if l.startswith("install -d")]
        self.assertEqual(installs[0], f"install -d -o {UP} -g {GID} -m 2750 /srv/example/a/b  # the shared root")
        order = [l.split()[8] for l in installs]
        self.assertLess(order.index("/srv/example/a/b"), order.index("/srv/example/a/b/inner"))

    def test_the_barrier_fsyncs_every_root_and_ancestor_deepest_first(self):
        barrier = next(l for l in self.plan if l.startswith("python3 -c"))
        args = barrier.split("' ", 1)[1].split()
        for p in ("/srv", "/srv/example", "/srv/example/a", "/srv/example/a/b/inner",
                  "/srv/example/state/up"):
            self.assertIn(p, args)
        self.assertLess(args.index("/srv/example/a/b/inner"), args.index("/srv/example/a"))

    def test_each_side_gets_the_other_sides_uid(self):
        self.assertIn(f"# downstream's runtime environment: {"EX_PEER_UID"}={UP}", self.plan)
        self.assertIn(f"# upstream's runtime environment: {"EX_PEER_UID"}={DOWN}", self.plan)

    def test_the_overlay_is_installed_root_owned_0444_and_names_its_digest(self):
        line = next(l for l in self.plan if l.startswith("install -o 0"))
        self.assertIn("-m 0444", line)
        self.assertIn(hs.STUB_SHA256, line)

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
        fs["/srv/example/state/up"] = St(stat.S_IFLNK | 0o777, UP, 2201)
        self.assertFails(fs, "/srv/example/state/up is a directory")

    def test_absent(self):
        fs = good_fs()
        del fs["/srv/example/a/b/inner"]
        self.assertFails(fs, "inner is a directory")

    def test_an_execute_only_ancestor_fails_the_reader_it_blocks(self):
        fs = good_fs()
        fs["/srv/example/a"] = d(0o711)
        bad = self.assertFails(fs, "downstream (uid 2102) can read and search every directory down to "
                                   "/srv/example/a/b")
        self.assertNotIn("/srv/example/state/up is a directory", bad)

    def test_the_downstream_reader_needs_the_group_bit(self):
        fs = good_fs()
        fs["/srv/example/a/b"] = d(0o2700, UP, GID)
        self.assertFails(fs, "downstream (uid 2102) can read and search")

    def test_an_uninspectable_path_is_unknown_not_fail(self):
        r = self.verify(good_fs(), denied=("/srv/example/state/up",))
        self.assertEqual(r["/srv/example/state/up is a directory owned by 2101:2201, mode 0700"], rh.UNKNOWN)


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


class MountTopologyTest(unittest.TestCase):
    """The runtime's durable root, seen from a throwaway container with its
    own mount, is the directory the plan created: the inode, owner, group
    and mode match, OR the root's marker does."""

    CLAIM = "downstream's durable root /data/root in img-down is the host directory /srv/example/a/b"
    SAME = (4242, UP, GID, 0o2750)
    OTHER = (9999, UP, GID, 0o2750)

    def verify(self, answer, fs=None, marker=None, host_marker="f00d"):
        asked = []
        x = doc()
        if marker:
            x["mounts"][0]["marker"] = marker

        def ask(image, host, container, mk):
            asked.append((image, host, container, mk))
            return answer
        checks = hs.verify_mounts(hs.load_spec(x), lstat_of(fs or good_fs()), ask,
                                  read_marker=lambda p: host_marker)
        return {c.claim: c for c in checks}, asked

    def test_the_same_directory_passes_by_inode_and_says_so(self):
        r, asked = self.verify((self.SAME, None))
        self.assertEqual(r[self.CLAIM].result, rh.PASS)
        self.assertIn("matched by inode", r[self.CLAIM].expected.provenance)
        self.assertEqual(asked, [("img-down", "/srv/example/a/b", "/data/root", None)])

    def test_another_directory_fails(self):
        for other in (self.OTHER, (4242, DOWN, GID, 0o2750), (4242, UP, GID, 0o2770)):
            with self.subTest(other=other):
                self.assertEqual(self.verify((other, None))[0][self.CLAIM].result, rh.FAIL)

    def test_an_inode_mismatch_passes_when_the_marker_matches_and_says_so(self):
        r, asked = self.verify((self.OTHER, "f00d"), marker=".root-id")
        self.assertEqual(r[self.CLAIM].result, rh.PASS)
        self.assertIn("matched by the root's marker", r[self.CLAIM].expected.provenance)
        self.assertEqual(asked[0][3], ".root-id")

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

    def test_the_plan_writes_a_random_root_owned_read_only_marker(self):
        x = doc()
        x["mounts"][0]["marker"] = ".root-id"
        line = next(l for l in hs.render_plan(hs.load_spec(x)) if "root marker" in l)
        self.assertIn("/dev/urandom", line)
        self.assertIn("chown 0:0 /srv/example/a/b/.root-id && chmod 0444 /srv/example/a/b/.root-id", line)

    def test_a_marker_must_be_one_name_inside_the_root(self):
        for bad in ("../x", "a/b", "..", ""):
            x = doc()
            x["mounts"][0]["marker"] = bad
            with self.subTest(bad=bad), self.assertRaises(hs.SpecError):
                hs.load_spec(x)

    def test_the_throwaway_container_mounts_read_only_with_no_network(self):
        seen = []

        def fake_run(argv, **kw):
            seen.append(list(argv))
            return rh.Proc(tuple(argv), 0, "4242 2101 2100 2750\nf00d\n", "")
        orig = rh.run
        rh.run = fake_run
        self.addCleanup(setattr, rh, "run", orig)
        self.assertEqual(hs.ask_mount("img-down", "/srv/example/a/b", "/data/root", ".root-id"),
                         ((4242, UP, GID, 0o2750), "f00d"))
        self.assertEqual(seen[0][-2:], ["/data/root", ".root-id"])
        argv = seen[0]
        self.assertIn("/srv/example/a/b:/data/root:ro", argv)
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        self.assertIn("--rm", argv)

    def test_garbled_stat_output_is_unknown(self):
        orig = rh.run
        rh.run = lambda argv, **kw: rh.Proc(tuple(argv), 0, "stat: not found\n", "")
        self.addCleanup(setattr, rh, "run", orig)
        self.assertIsInstance(hs.ask_mount("i", "/a", "/b"), rh.Unresolved)

    def test_the_device_number_is_not_compared(self):
        self.assertEqual(hs._identity(os.stat_result((stat.S_IFDIR | 0o750, 7, 99, 1, 5, 6, 0, 0, 0, 0))),
                         (7, 5, 6, 0o750))


class OpensslTest(unittest.TestCase):

    def verify(self, out):
        return results(hs.verify_openssl(hs.load_spec(doc()), {"img-up": out}))

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

    def test_the_image_is_asked_in_a_throwaway_container(self):
        seen = []

        def fake_run(argv, **kw):
            seen.append(list(argv))
            return rh.Proc(tuple(argv), 0, "OpenSSL 3.0.13 30 Jan 2024\n", "") if argv[-1] == "version" \
                else rh.Proc(tuple(argv), 1, "", "boom")
        orig = rh.run
        rh.run = fake_run
        self.addCleanup(setattr, rh, "run", orig)
        self.assertEqual(hs.ask_openssl(["img-up"]), {"img-up": "OpenSSL 3.0.13 30 Jan 2024\n"})
        self.assertEqual(seen[0], ["docker", "run", "--rm", "--entrypoint", "openssl", "img-up", "version"])
        rh.run = lambda argv, **kw: rh.Proc(tuple(argv), 1, "", "no such image")
        self.assertIsInstance(hs.ask_openssl(["img-up"])["img-up"], rh.Unresolved)
        self.assertEqual(set(self.verify("LibreSSL 3.3.6").values()), {rh.UNKNOWN})


def status(uid, umask=None, name="python3"):
    """One /proc/<pid>/status as Linux prints it (fields trimmed to the
    ones read, in kernel order; Umask is present from Linux 4.7)."""
    s = f"Name:\t{name}\n"
    if umask is not None:
        s += f"Umask:\t{umask}\n"
    return s + f"State:\tS (sleeping)\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{GID}\t{GID}\t{GID}\t{GID}\n"


class UmaskTest(unittest.TestCase):

    def verify(self, answers):
        return {c.claim.split(" (")[0]: c for c in
                hs.verify_umasks(hs.load_spec(doc()), lambda c: answers[c])}

    def good(self):
        return {"ex-up": hs.parse_proc_status(status(UP, "0027") + status(UP, "0027", "sh")
                                              + status(0, "0022", "init")),
                "ex-down": hs.parse_proc_status(status(DOWN, "0022"))}

    def test_the_declared_umask_passes(self):
        self.assertEqual({c.result for c in self.verify(self.good()).values()}, {rh.PASS})

    def test_a_process_under_another_umask_fails_its_runtime_only(self):
        a = self.good()
        a["ex-up"] = hs.parse_proc_status(status(UP, "0027") + status(UP, "0077", "worker"))
        r = self.verify(a)
        self.assertEqual(r["every process of upstream"].result, rh.FAIL)
        self.assertEqual(r["every process of upstream"].actual, [0o027, 0o077])
        self.assertEqual(r["every process of downstream"].result, rh.PASS)

    def test_0022_where_0027_is_declared_fails(self):
        a = self.good()
        a["ex-up"] = hs.parse_proc_status(status(UP, "0022"))
        self.assertEqual(self.verify(a)["every process of upstream"].result, rh.FAIL)

    def test_only_the_runtimes_own_uid_is_read(self):
        a = self.good()
        a["ex-up"] = hs.parse_proc_status(status(UP, "0027") + status(DOWN, "0077"))
        self.assertEqual(self.verify(a)["every process of upstream"].result, rh.PASS)

    def test_no_process_of_its_uid_is_unknown(self):
        a = self.good()
        a["ex-up"] = hs.parse_proc_status(status(0, "0022"))
        c = self.verify(a)["every process of upstream"]
        self.assertEqual(c.result, rh.UNKNOWN)
        self.assertIn("no process running as uid", c.reason)

    def test_a_kernel_without_the_umask_field_is_unknown(self):
        a = self.good()
        a["ex-up"] = hs.parse_proc_status(status(UP, "0027") + status(UP))
        self.assertEqual(self.verify(a)["every process of upstream"].result, rh.UNKNOWN)

    def test_no_answer_is_unknown(self):
        a = self.good()
        a["ex-down"] = rh.Unresolved("no such container")
        self.assertEqual(self.verify(a)["every process of downstream"].result, rh.UNKNOWN)

    def test_the_running_container_is_asked_read_only(self):
        seen = []

        def fake_run(argv, **kw):
            seen.append(list(argv))
            return rh.Proc(tuple(argv), 0, status(UP, "0027"), "")
        orig = rh.run
        rh.run = fake_run
        self.addCleanup(setattr, rh, "run", orig)
        self.assertEqual(hs.ask_umasks("ex-up"), [(UP, 0o027)])
        self.assertEqual(seen[0][:5], ["docker", "exec", "ex-up", "sh", "-c"])
        self.assertIn("cat", seen[0][5])
        self.assertNotIn(">", seen[0][5].replace("2>/dev/null", ""))
        rh.run = lambda argv, **kw: rh.Proc(tuple(argv), 1, "", "No such container: ex-up")
        self.assertIsInstance(hs.ask_umasks("ex-up"), rh.Unresolved)

    def test_the_effective_uid_is_the_one_read(self):
        text = f"Name:\tx\nUmask:\t0027\nUid:\t0\t{UP}\t{UP}\t{UP}\n"
        self.assertEqual(hs.parse_proc_status(text), [(UP, 0o027)])


class VerbTest(unittest.TestCase):
    """The verb: the plan, then the checks, and an exit status that counts an
    UNKNOWN as a problem. Docker is never reached: conftest refuses it, and
    the openssl answer is UNKNOWN."""

    def write(self, x):
        import tempfile
        p = os.path.join(tempfile.mkdtemp(), "host-setup.json")
        with open(p, "w") as f:
            json.dump(x, f)
        return p

    def run_verb(self, x, fs, **kw):
        lines = []
        kw.setdefault("digest", lambda p: hs.STUB_SHA256)
        kw.setdefault("mounts", lambda image, host, container, marker: ((4242, UP, GID, 0o2750), None))
        kw.setdefault("umasks", lambda c: [(UP, 0o027)] if c == "ex-up" else [(DOWN, 0o022)])
        rc = hs.run(None if x is None else self.write(x), production=False, lstat=lstat_of(fs), out=lines.append, **kw)
        return rc, "\n".join(lines)

    def test_a_good_host_with_its_openssl_reported_exits_0(self):
        rc, out = self.run_verb(doc(), good_fs(), openssl={"img-up": "OpenSSL 3.0.13 x"})
        self.assertEqual(rc, 0, out)
        self.assertIn("Nothing here has run", out)

    def test_unknown_is_a_problem(self):
        rc, out = self.run_verb(doc(), good_fs())
        self.assertEqual(rc, 1)
        self.assertIn("UNKNOWN", out)

    def test_a_failure_names_its_fix(self):
        fs = good_fs()
        fs["/srv/example/a/b"] = d(0o2777, UP, GID)
        rc, out = self.run_verb(doc(), fs, openssl={"img-up": "OpenSSL 3.0.13 x"})
        self.assertEqual(rc, 1)
        self.assertIn("fix: run the plan's `install -d` line for /srv/example/a/b", out)

    def test_an_unusable_document_is_refused(self):
        rc, out = self.run_verb({"schema": "other"}, good_fs())
        self.assertEqual(rc, 2)

    def test_the_document_can_come_from_the_overlays_section(self):
        overlay = self.write({"registry": {}, "host_setup": doc()})
        rc, out = self.run_verb(None, good_fs(), openssl={"img-up": "OpenSSL 3.0.13 x"}, overlay=overlay)
        self.assertEqual(rc, 0, out)

    def test_spec_wins_over_the_overlay(self):
        overlay = self.write({"host_setup": {"schema": "other"}})
        rc, out = self.run_verb(doc(), good_fs(), openssl={"img-up": "OpenSSL 3.0.13 x"}, overlay=overlay)
        self.assertEqual(rc, 0, out)

    def test_neither_a_spec_nor_an_overlay_section_is_refused(self):
        rc, out = self.run_verb(None, good_fs())
        self.assertEqual(rc, 2)
        self.assertIn("no host-setup document", out)
        rc, out = self.run_verb(None, good_fs(), overlay=self.write({"registry": {}}))
        self.assertEqual(rc, 2)
        self.assertIn("has no 'host_setup' object", out)

    def test_a_wrong_umask_fails_the_verb(self):
        rc, out = self.run_verb(doc(), good_fs(), openssl={"img-up": "OpenSSL 3.0.13 x"},
                                umasks=lambda c: [(UP, 0o077)] if c == "ex-up" else [(DOWN, 0o022)])
        self.assertEqual(rc, 1)
        self.assertIn("FAIL    every process of upstream (uid 2101) in ex-up runs under umask 0027", out)
        self.assertIn("fix: set UMask=0027 in upstream's service unit", out)


if __name__ == "__main__":
    unittest.main()
