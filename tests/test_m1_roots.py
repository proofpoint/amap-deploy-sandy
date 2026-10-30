"""m1_roots (D-ROOTS) and host_steps' `install`, run for real in a temporary
tree. The roots' owner is the test's own uid and gid, so every step runs
unprivileged; the registry's uid in the spec is that same uid. Each refusal
the receipt names is planted one at a time, and the test requires that
problem, by its own wording, and a FAIL.
"""

import contextlib
import hashlib
import io
import json
import os
import stat
import tempfile
import unittest

import host_steps as st
import m1_roots as mr


class Fixture(unittest.TestCase):

    def setUp(self):
        self.t = os.path.realpath(tempfile.mkdtemp())
        self.uid, self.gid = os.getuid(), os.getgid()
        self.data = self.p("data")
        os.mkdir(self.data)
        self.hostj_src = self.p("host.json")
        with open(self.hostj_src, "wb") as f:
            f.write(b'{"adapters":{}}\n')
        self.hostj_sha = hashlib.sha256(b'{"adapters":{}}\n').hexdigest()
        self.spec = self.make_spec()
        self.mountinfo = (f"36 25 254:1 / {self.data} rw,relatime shared:1 - ext4 /dev/vdc rw\n")
        self.devices = {os.path.join(mr.BY_UUID, "1111-2222"): "/dev/vdc", "/dev/vdc": "/dev/vdc"}

    def p(self, *parts):
        return os.path.join(self.t, *parts)

    def realpath(self, path):
        return self.devices.get(path, path)

    def make_spec(self):
        d = self.data
        u, g = self.uid, self.gid
        roots = [
            {"path": d + "/sandy", "uid": u, "gid": g, "mode": "0700", "role": "sandy_home"},
            {"path": d + "/amap", "uid": u, "gid": g, "mode": "0755", "role": "dir"},
            {"path": d + "/amap/m1", "uid": u, "gid": g, "mode": "0700", "role": "run_dir"},
            {"path": d + "/amap/rl", "uid": u, "gid": g, "mode": "0750", "role": "dir"},
            {"path": d + "/amap/rl/state", "uid": u, "gid": g, "mode": "0700", "role": "state_dir"},
            {"path": d + "/amap/registry", "uid": u, "gid": g, "mode": "0700", "role": "registry"},
            {"path": d + "/identities", "uid": u, "gid": g, "mode": "0700", "role": "identities"},
            {"path": d + "/ws-a", "uid": u, "gid": g, "mode": "0700", "role": "workspace"},
        ]
        return {"schema": mr.SCHEMA, "data": d, "data_uuid": "1111-2222", "python3": "/usr/bin/python3",
                "writer": "/opt/amap/libexec/host_steps.py", "writer_sha256": "a" * 64, "roots": roots,
                "hostj": {"path": self.hostj_src, "sha256": self.hostj_sha},
                "seed_copy": {"path": "/opt/amap/m1-seed-copy", "sha256": "b" * 64, "uid": u,
                              "argv": ["/usr/bin/python3", "-I", "-S", "-B", "/opt/amap/m1-seed-copy", "--man",
                                       "/opt/amap/MAN.json", "--src", "/opt/amap/sandy-seed", "--dst", d + "/sandy"]}}

    def run_steps(self):
        """What the plan's root lines do, through the same writer functions."""
        for r in self.spec["roots"]:
            st.root(r["path"], r["uid"], r["gid"], int(r["mode"], 8))
        reg = mr.roles(self.spec)["registry"]
        st.install(self.hostj_src, mr.hostj_dest(self.spec), reg["uid"], reg["gid"], self.hostj_sha, 0o600)

    def receipt(self, acl=lambda paths: []):
        return mr.receipt(mr.load_spec(self.spec), self.mountinfo, realpath=self.realpath, acl=acl)


class SpecTest(Fixture):

    def refused(self, mutate, words):
        spec = json.loads(json.dumps(self.spec))
        mutate(spec)
        with self.assertRaises(mr.SpecError) as cm:
            mr.load_spec(spec)
        self.assertIn(words, str(cm.exception))

    def test_the_fixture_spec_loads(self):
        mr.load_spec(self.spec)

    def test_an_unknown_key_is_refused(self):
        self.refused(lambda s: s.update(extra=1), "must have exactly")

    def test_a_root_outside_data_is_refused(self):
        self.refused(lambda s: s["roots"][0].update(path=self.t + "/elsewhere"), "not under data")

    def test_a_root_before_its_parent_is_refused(self):
        def swap(s):
            s["roots"][1], s["roots"][2] = s["roots"][2], s["roots"][1]
        self.refused(swap, "parent is neither data nor an earlier root")

    def test_a_missing_role_is_refused(self):
        self.refused(lambda s: s["roots"].pop(6), "missing role(s) identities")

    def test_a_repeated_role_is_refused(self):
        self.refused(lambda s: s["roots"][7].update(role="sandy_home"), "appears twice")

    def test_a_private_root_other_than_0700_is_refused(self):
        self.refused(lambda s: s["roots"][5].update(mode="0755"), "0700 only")

    def test_registry_and_identities_owners_must_match(self):
        self.refused(lambda s: s["roots"][6].update(gid=self.gid + 1), "same owner")

    def test_root_as_owner_is_refused(self):
        self.refused(lambda s: s["roots"][0].update(uid=0), "never root")

    def test_the_seed_copy_argv_must_name_its_program(self):
        self.refused(lambda s: s["seed_copy"].update(argv=["/usr/bin/true"]), "naming seed_copy.path")

    def test_the_seed_copy_runs_as_sandy_homes_owner(self):
        self.refused(lambda s: s["seed_copy"].update(uid=self.uid + 1), "sandy_home's owner")

    def test_a_short_sha_is_refused(self):
        self.refused(lambda s: s["hostj"].update(sha256="abc"), "64 lowercase hex")


class PlanTest(Fixture):

    def test_the_seed_copy_line_stops_without_its_pass_line(self):
        import shlex
        import subprocess
        line = [ln for ln in mr.plan(mr.load_spec(self.spec), "/l", "/s") if "M1-SEED-COPY PASS" in ln][0]
        tail = line.split("&& out=$(", 1)[1].split(") && ", 1)[1]
        for out, want in (("SEED a present\nM1-SEED-COPY PASS n=1 man=x", 0), ("SEED a present", 1),
                          ("M1-SEED-COPY PASS n=1\nSEED late", 1)):
            with self.subTest(out=out):
                rc = subprocess.run(["/bin/sh", "-c", f"out={shlex.quote(out)}; " + tail],
                                    capture_output=True).returncode
                self.assertEqual(rc != 0, bool(want))

    def test_the_plan_checks_the_writer_first_and_ends_with_the_receipt(self):
        lines = mr.plan(mr.load_spec(self.spec), "/opt/amap/amap-m1-roots.py", "/opt/amap/roots.json")
        self.assertTrue(lines[1].startswith("printf '%s  %s\\n' " + "a" * 64))
        self.assertIn("sha256sum -c --strict -", lines[1])
        self.assertIn("check-mount --spec", lines[2])
        roots = [ln for ln in lines if " root " in ln]
        self.assertEqual([ln.split(" root ")[1].split()[0] for ln in roots],
                         [r["path"] for r in self.spec["roots"]])
        install = [ln for ln in lines if " install " in ln]
        self.assertEqual(len(install), 1)
        self.assertIn(f"{self.data}/amap/registry/host.json {self.uid} {self.gid} --sha256 {self.hostj_sha} "
                      f"--mode 0600", install[0])
        self.assertLess(lines.index(roots[-1]), lines.index(install[0]))
        seed = [ln for ln in lines if "m1-seed-copy" in ln and "sudo -u" in ln]
        self.assertEqual(len(seed), 1)
        self.assertIn("b" * 64, seed[0])
        self.assertIn(f"&& out=$(sudo -u '#{self.uid}' -- ", seed[0])
        self.assertTrue(seed[0].endswith("| tail -n 1 | grep -q '^M1-SEED-COPY PASS '"), seed[0])
        self.assertIn("receipt --spec", lines[-1])


class InstallTest(Fixture):

    def setUp(self):
        super().setUp()
        self.dir = self.p("reg")
        os.mkdir(self.dir, 0o700)
        os.chmod(self.dir, 0o700)

    def test_install_writes_the_owned_file_at_its_mode(self):
        st.install(self.hostj_src, self.dir + "/host.json", self.uid, self.gid, self.hostj_sha, 0o600)
        s = os.lstat(self.dir + "/host.json")
        self.assertEqual((s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)), (self.uid, self.gid, 0o600))
        with open(self.dir + "/host.json", "rb") as f:
            self.assertEqual(hashlib.sha256(f.read()).hexdigest(), self.hostj_sha)

    def test_install_refuses_another_sha(self):
        with self.assertRaisesRegex(st.StepError, "not the pinned"):
            st.install(self.hostj_src, self.dir + "/host.json", self.uid, self.gid, "c" * 64, 0o600)
        self.assertEqual(os.listdir(self.dir), [])

    def test_install_refuses_a_parent_that_is_not_the_owners_0700(self):
        os.chmod(self.dir, 0o755)
        with self.assertRaisesRegex(st.StepError, "not .* 0700"):
            st.install(self.hostj_src, self.dir + "/host.json", self.uid, self.gid, self.hostj_sha, 0o600)
        self.assertEqual(os.listdir(self.dir), [])

    def test_install_refuses_another_mode(self):
        with self.assertRaisesRegex(st.StepError, "not one of 0600, 0400"):
            st.install(self.hostj_src, self.dir + "/host.json", self.uid, self.gid, self.hostj_sha, 0o644)

    def test_install_refuses_a_linked_parent(self):
        os.symlink(self.dir, self.p("link"))
        with self.assertRaisesRegex(st.StepError, "not a real directory"):
            st.install(self.hostj_src, self.p("link") + "/host.json", self.uid, self.gid, self.hostj_sha, 0o600)

    def assert_nothing_written(self):
        self.assertEqual(os.listdir(self.dir), [])

    def install(self, **kw):
        args = dict(src=self.hostj_src, dest=self.dir + "/host.json", uid=self.uid, gid=self.gid,
                    sha256=self.hostj_sha, mode=0o600)
        args.update(kw)
        return st.install(**args)

    def test_an_access_acl_on_the_directory_is_refused_before_any_byte(self):
        with self.assertRaisesRegex(st.StepError, "carries an ACL; nothing installed"):
            self.install(listxattr=lambda fd: ["system.posix_acl_access"])
        self.assert_nothing_written()

    def test_a_default_acl_on_the_directory_is_refused_before_any_byte(self):
        with self.assertRaisesRegex(st.StepError, "carries an ACL; nothing installed"):
            self.install(listxattr=lambda fd: ["user.x", "system.posix_acl_default"])
        self.assert_nothing_written()

    def test_an_unreadable_acl_is_refused_before_any_byte(self):
        import errno

        def broken(fd):
            raise OSError(errno.EIO, "I/O error")
        with self.assertRaisesRegex(st.StepError, "ACL cannot be read"):
            self.install(listxattr=broken)
        self.assert_nothing_written()

    def test_the_acl_is_read_through_the_directory_descriptor(self):
        seen = []
        self.install(listxattr=lambda fd: seen.append(fd) or [])
        self.assertEqual(len(seen), 1)
        self.assertIsInstance(seen[0], int)

    def test_a_filesystem_without_xattrs_has_no_acl(self):
        import errno

        def unsupported(fd):
            raise OSError(errno.ENOTSUP, "not supported")
        self.install(listxattr=unsupported)
        self.assertEqual(os.listdir(self.dir), ["host.json"])

    def test_another_uid_argument_is_refused(self):
        with self.assertRaisesRegex(st.StepError, "0700; nothing installed"):
            self.install(uid=self.uid + 1)
        self.assert_nothing_written()

    def test_another_gid_argument_is_refused(self):
        with self.assertRaisesRegex(st.StepError, "0700; nothing installed"):
            self.install(gid=self.gid + 1)
        self.assert_nothing_written()

    def test_a_linked_source_is_refused(self):
        os.symlink(self.hostj_src, self.p("src-link"))
        with self.assertRaisesRegex(st.StepError, "nothing placed"):
            self.install(src=self.p("src-link"))
        self.assert_nothing_written()

    def test_a_malformed_sha_is_refused(self):
        with self.assertRaisesRegex(st.StepError, "64 hex characters"):
            self.install(sha256="abc")
        self.assert_nothing_written()

    def test_a_dest_that_is_a_link_is_refused_and_not_followed(self):
        target = self.p("elsewhere")
        with open(target, "w") as f:
            f.write("keep")
        os.symlink(target, self.dir + "/host.json")
        with self.assertRaisesRegex(st.StepError, "not a regular file with one link; not overwritten"):
            self.install()
        self.assertTrue(os.path.islink(self.dir + "/host.json"))
        with open(target) as f:
            self.assertEqual(f.read(), "keep")

    def test_an_existing_dest_with_other_bytes_is_refused(self):
        with open(self.dir + "/host.json", "w") as f:
            f.write("other")
        with self.assertRaisesRegex(st.StepError, "other bytes than the pin; not overwritten"):
            self.install()
        with open(self.dir + "/host.json") as f:
            self.assertEqual(f.read(), "other")
        self.assertEqual(sorted(os.listdir(self.dir)), ["host.json"])

    def test_an_existing_dest_with_the_pinned_bytes_is_installed_again(self):
        self.install()
        self.install()
        self.assertEqual(os.listdir(self.dir), ["host.json"])

    def test_the_command_line_reaches_install(self):
        rc = st.main(["install", self.hostj_src, self.dir + "/host.json", str(self.uid), str(self.gid),
                      "--sha256", self.hostj_sha, "--mode", "0600"])
        self.assertEqual(rc, 0)
        self.assertEqual(os.listdir(self.dir), ["host.json"])


class MountTest(Fixture):

    def test_the_state_disk_is_found_by_uuid(self):
        self.assertIsNone(mr.mount_problem(mr.load_spec(self.spec), self.mountinfo, self.realpath))

    def test_an_unmounted_data_is_a_problem(self):
        p = mr.mount_problem(mr.load_spec(self.spec), "", self.realpath)
        self.assertIn("is not a mountpoint", p)

    def test_another_device_is_a_problem(self):
        self.devices[os.path.join(mr.BY_UUID, "1111-2222")] = "/dev/vdb"
        p = mr.mount_problem(mr.load_spec(self.spec), self.mountinfo, self.realpath)
        self.assertIn("not the device with UUID", p)

    def test_the_last_mount_at_the_path_is_the_one_read(self):
        over = self.mountinfo + f"40 36 0:50 / {self.data} rw - tmpfs tmpfs rw\n"
        p = mr.mount_problem(mr.load_spec(self.spec), over, self.realpath)
        self.assertIn("mounted from tmpfs", p)


class ReceiptTest(Fixture):

    def setUp(self):
        super().setUp()
        self.run_steps()

    def fails_with(self, words, **kw):
        doc = self.receipt(**kw)
        self.assertEqual(doc["result"], "FAIL")
        self.assertTrue(any(words in p for p in doc["problems"]), doc["problems"])

    def test_the_planned_state_passes(self):
        doc = self.receipt()
        self.assertEqual(doc["result"], "PASS", doc["problems"])
        self.assertEqual(doc["hostj"]["sha256"], self.hostj_sha)
        reg = [r for r in doc["roots"] if r["role"] == "registry"][0]
        self.assertEqual(reg["entries"], ["host.json"])

    def test_an_extra_file_in_the_registry_fails(self):
        with open(self.data + "/amap/registry/journal", "w"):
            pass
        self.fails_with("not exactly ['host.json']")

    def test_a_missing_hostj_fails(self):
        os.unlink(mr.hostj_dest(self.spec))
        self.fails_with("holds [], not exactly")

    def test_another_hostj_sha_fails(self):
        path = mr.hostj_dest(self.spec)
        os.chmod(path, 0o600)
        with open(path, "ab") as f:
            f.write(b" ")
        self.fails_with("sha256 is")

    def test_hostj_at_another_mode_fails(self):
        os.chmod(mr.hostj_dest(self.spec), 0o644)
        self.fails_with("mode is '0644', not '0600'")

    def test_a_second_link_to_hostj_fails(self):
        os.link(mr.hostj_dest(self.spec), self.p("other-link"))
        self.fails_with("nlink is 2, not 1")

    def test_a_root_at_another_mode_fails(self):
        os.chmod(self.data + "/amap/registry", 0o750)
        self.fails_with(f"{self.data}/amap/registry: {self.uid}:{self.gid} 0750, not")

    def test_a_nonempty_state_dir_fails(self):
        os.mkdir(self.data + "/amap/rl/state/x")
        self.fails_with("the state_dir root is not empty")

    def test_a_nonempty_identities_dir_fails(self):
        os.mkdir(self.data + "/identities/abc")
        self.fails_with("the identities root is not empty")

    def test_a_linked_root_fails(self):
        os.rmdir(self.data + "/ws-a")
        os.symlink(self.data + "/sandy", self.data + "/ws-a")
        self.fails_with(f"{self.data}/ws-a: not a real directory")

    def test_an_acl_on_a_root_fails(self):
        ids = self.data + "/identities"
        self.fails_with(f"{ids} carries an ACL", acl=lambda paths: [f"{p} carries an ACL" for p in paths if p == ids])

    def test_an_acl_on_hostj_fails(self):
        dest = mr.hostj_dest(self.spec)
        self.fails_with(f"{dest} carries an ACL",
                        acl=lambda paths: [f"{p} carries an ACL" for p in paths if p == dest])

    def test_the_wrong_mount_fails(self):
        self.mountinfo = ""
        self.fails_with("is not a mountpoint")


class MainTest(Fixture):

    def write_spec(self):
        path = self.p("spec.json")
        with open(path, "w") as f:
            json.dump(self.spec, f)
        return path

    def test_a_bad_spec_exits_2(self):
        self.spec["schema"] = "other"
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(mr.main(["plan", "--spec", self.write_spec()]), mr.EXIT_SPEC)

    def test_plan_exits_0_and_prints_the_plan(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(mr.main(["plan", "--spec", self.write_spec()]), mr.EXIT_PASS)
        self.assertIn("receipt --spec", out.getvalue().splitlines()[-1])

    def test_bad_usage_exits_2(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(mr.main(["plan"]), mr.EXIT_SPEC)


if __name__ == "__main__":
    unittest.main()
