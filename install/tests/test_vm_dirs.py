"""vm_dirs: the S6 directories the agent account owns, run in-process on the shipped module against a temporary HOME
(its real ancestors from / are walked too, so the temporary directory's own parents must be trusted, as they are for
a home)."""

import grp
import os
import shutil
import subprocess
import sys
import stat
import tempfile
import types
import unittest
from unittest import mock

import a2fix  # noqa: F401  (puts install/ on sys.path)
import vm_dirs as vd

ME = os.geteuid()
G = os.getegid()


class LayoutTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="a2dirs-")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.home = os.path.join(self.d, "agent")
        os.mkdir(self.home, 0o750)
        os.chmod(self.d, 0o755)

    def run_layout(self, gid=G):
        try:
            return vd.layout(self.home, ME, gid)
        except vd.Stop as e:
            return e.code

    def p(self, rel):
        return os.path.join(self.home, rel)

    def made(self):
        return [rel for rel, _, _ in vd.DIRS if os.path.lexists(self.p(rel))]

    def test_creates_each_with_its_mode_and_group_then_existing(self):
        rows = self.run_layout()
        self.assertEqual(rows, [(rel, "CREATED") for rel, _, _ in vd.DIRS])
        for rel, mode, grouped in vd.DIRS:
            st = os.lstat(self.p(rel))
            self.assertTrue(stat.S_ISDIR(st.st_mode), rel)
            self.assertEqual(stat.S_IMODE(st.st_mode), mode, rel)
            self.assertEqual(st.st_uid, ME)
            if grouped:
                self.assertEqual(st.st_gid, G, rel)
        self.assertEqual(os.listdir(self.p(".amap-router/state")), [])
        self.assertEqual(self.run_layout(), [(rel, "EXISTING") for rel, _, _ in vd.DIRS])

    def test_the_layout_holds_the_design(self):
        modes = {rel: (mode, grouped) for rel, mode, grouped in vd.DIRS}
        self.assertEqual(modes[".amap-hop"], (0o2750, True))
        for rel in (".amap-hop/.disposed", ".amap-hop/.disposed/.unresolved", ".amap-hop/.disposed/.control"):
            self.assertEqual(modes[rel], (0o2750, True))
        self.assertNotIn(".amap-hop/.unresolved", modes)
        self.assertNotIn(".amap-hop/.control", modes)
        self.assertEqual(modes[".amap-router/state"], (0o700, False))
        self.assertEqual(modes[".amap-relay-config"], (0o755, False))
        rels = [rel for rel, _, _ in vd.DIRS]
        for rel in rels:
            parent = rel.rpartition("/")[0]
            if parent:
                self.assertLess(rels.index(parent), rels.index(rel), rel)

    def test_a_present_state_dir_need_not_be_empty(self):
        self.run_layout()
        open(self.p(".amap-router/state/peer-clock.json"), "w").close()
        self.assertEqual(self.run_layout()[1], (".amap-router/state", "EXISTING"))

    def test_some_present_others_made(self):
        os.mkdir(self.p(".amap-registry"), 0o755)
        os.chmod(self.p(".amap-registry"), 0o755)
        rows = dict(self.run_layout())
        self.assertEqual(rows[".amap-registry"], "EXISTING")
        self.assertEqual(rows[".amap-registry/instances"], "CREATED")

    def test_an_existing_path_that_breaks_a_rule_refuses_and_nothing_is_made(self):
        cases = [
            (".amap-relay-config", lambda p: (os.mkdir(p), os.chmod(p, 0o775))),
            (".amap-hop", lambda p: (os.mkdir(p), os.chmod(p, 0o2770))),
            (".amap-hop", lambda p: (os.mkdir(p), os.chmod(p, 0o0750))),
            (".amap-router", lambda p: (os.mkdir(p), os.chmod(p, 0o755))),
            (".a2-registry-code", lambda p: open(p, "w").close()),
            (".amap-registry", lambda p: (os.mkdir(p + "-real"), os.chmod(p + "-real", 0o755), os.symlink(p + "-real", p))),
        ]
        for rel, make in cases:
            with self.subTest(rel=rel):
                make(self.p(rel))
                self.assertEqual(self.run_layout(), vd.NOT_ALLOWED)
                self.assertEqual(self.made(), [rel])
                if os.path.islink(self.p(rel)) or not os.path.isdir(self.p(rel)):
                    os.unlink(self.p(rel))
                else:
                    os.rmdir(self.p(rel))
                if os.path.exists(self.p(rel) + "-real"):
                    os.rmdir(self.p(rel) + "-real")

    def test_a_late_entry_is_checked_before_an_early_one_is_made(self):
        os.mkdir(self.p(".amap-router-code"))
        os.chmod(self.p(".amap-router-code"), 0o700)
        self.assertEqual(self.run_layout(), vd.NOT_ALLOWED)
        self.assertEqual(self.made(), [".amap-router-code"])

    def test_a_hop_directory_in_another_group_refuses(self):
        self.run_layout()
        self.assertEqual(self.run_layout(gid=G + 1), vd.NOT_ALLOWED)

    def test_untrusted_ancestors_refuse(self):
        os.chmod(self.home, 0o770)
        self.assertEqual(self.run_layout(), vd.NOT_ALLOWED)
        os.chmod(self.home, 0o755)
        os.chmod(self.d, 0o757)
        self.assertEqual(self.run_layout(), vd.NOT_ALLOWED)
        os.chmod(self.d, 0o1777)
        self.assertEqual(self.run_layout(), [(rel, "CREATED") for rel, _, _ in vd.DIRS])

    def test_a_symlinked_home_or_a_bad_home_refuses(self):
        link = os.path.join(self.d, "link")
        os.symlink(self.home, link)
        self.home = link
        self.assertEqual(self.run_layout(), vd.NOT_ALLOWED)
        for bad in ("relative", "/", self.d + "/agent/", self.d + "/./agent", self.d + "//agent"):
            self.home = bad
            self.assertEqual(self.run_layout(), vd.NOT_ALLOWED, bad)

    def test_the_shipped_script_prints_one_line_per_directory(self):
        script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vm_dirs.py")
        with open(script) as f:
            src = f.read()
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": self.home}
        p = subprocess.run([sys.executable, "-I", "-S", "-c", src, grp.getgrgid(G).gr_name], env=env,
                           capture_output=True, stdin=subprocess.DEVNULL, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout, "".join("CREATED %s\n" % rel for rel, _, _ in vd.DIRS).encode())
        self.assertEqual(p.stderr, b"")

    def test_main(self):
        self.assertEqual(vd.main([]), vd.USAGE)
        self.assertEqual(vd.main(["a", "b"]), vd.USAGE)
        self.assertEqual(vd.main(["no-such-group-a2"]), vd.NOT_ALLOWED)



OTHER = 52003


class OwnershipTest(LayoutTest):
    """Owners and groups this uid cannot make without root, stood in through vm_dirs' ownership names (restored
    after each test): a table keyed by inode, real ids elsewhere."""

    def setUp(self):
        super().setUp()
        self.owners = {}
        for name in ("_stat", "_fstat", "_fchown"):
            self.addCleanup(setattr, vd, name, getattr(vd, name))
        real_stat, real_fstat = os.stat, os.fstat

        def fake(st):
            uid, gid = self.owners.get((st.st_dev, st.st_ino), (st.st_uid, st.st_gid))
            return types.SimpleNamespace(st_mode=st.st_mode, st_uid=uid, st_gid=gid)

        def fchown(fd, uid, gid):
            st = real_fstat(fd)
            old = self.owners.get((st.st_dev, st.st_ino), (st.st_uid, st.st_gid))
            self.owners[(st.st_dev, st.st_ino)] = (old[0] if uid == -1 else uid, old[1] if gid == -1 else gid)

        vd._stat = lambda *a, **kw: fake(real_stat(*a, **kw))
        vd._fstat = lambda fd: fake(real_fstat(fd))
        vd._fchown = fchown

    def own(self, path, uid, gid=G):
        st = os.lstat(path)
        self.owners[(st.st_dev, st.st_ino)] = (uid, gid)

    def test_an_existing_directory_owned_by_another_account_refuses(self):
        os.mkdir(self.p(".a2-registry-code"))
        os.chmod(self.p(".a2-registry-code"), 0o755)
        self.own(self.p(".a2-registry-code"), OTHER)
        self.assertEqual(self.run_layout(), vd.NOT_ALLOWED)
        self.assertEqual(self.made(), [".a2-registry-code"])

    def test_an_ancestor_owned_by_another_account_refuses_and_by_root_passes(self):
        self.own(self.d, OTHER)
        self.assertEqual(self.run_layout(), vd.NOT_ALLOWED)
        self.own(self.d, 0)
        self.assertEqual(self.run_layout(), [(rel, "CREATED") for rel, _, _ in vd.DIRS])

    def test_the_hop_directories_are_given_the_hop_group(self):
        g2 = G + 7
        self.assertEqual(self.run_layout(gid=g2), [(rel, "CREATED") for rel, _, _ in vd.DIRS])
        for rel, _, grouped in vd.DIRS:
            st = os.lstat(self.p(rel))
            got = self.owners.get((st.st_dev, st.st_ino), (st.st_uid, st.st_gid))[1]
            self.assertEqual(got, g2 if grouped else st.st_gid, rel)

    def test_main_refuses_a_group_this_account_is_not_in(self):
        root_group = grp.getgrgid(0).gr_name
        self.assertNotIn(0, os.getgroups())
        with mock.patch.dict(os.environ, {"HOME": self.home}):
            self.assertEqual(vd.main([root_group]), vd.NOT_ALLOWED)
        self.assertEqual(self.made(), [])


if __name__ == "__main__":
    unittest.main()


class RelaySetTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="a2dirs-r-")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.home = os.path.join(self.d, "relay")
        os.mkdir(self.home, 0o750)
        os.chmod(self.d, 0o755)

    def test_creates_each_private_then_existing_through_main(self):
        with mock.patch.dict(os.environ, {"HOME": self.home}):
            import io
            out = []
            with mock.patch.object(vd.os, "write", lambda fd, b: out.append(b) or len(b)):
                self.assertEqual(vd.main([vd.RELAY_FLAG]), vd.OK)
                self.assertEqual(vd.main([vd.RELAY_FLAG]), vd.OK)
        self.assertEqual(out[0].decode(), "".join("CREATED %s\n" % r for r, _, _ in vd.RELAY_DIRS))
        self.assertEqual(out[1].decode(), "".join("EXISTING %s\n" % r for r, _, _ in vd.RELAY_DIRS))
        for rel, mode, _ in vd.RELAY_DIRS:
            st = os.lstat(os.path.join(self.home, rel))
            self.assertEqual((stat.S_IMODE(st.st_mode), st.st_uid), (0o700, ME), rel)

    def test_the_relay_set_is_res_state(self):
        self.assertEqual([r for r, _, _ in vd.RELAY_DIRS], [".amap-relay", ".amap-relay/mailbox", ".amap-relay/ledger",
                                                           ".amap-relay/inbound", ".amap-relay/login"])
        self.assertTrue(all(m == 0o700 and not g for _, m, g in vd.RELAY_DIRS))

    def test_a_wrong_mode_refuses(self):
        os.mkdir(os.path.join(self.home, ".amap-relay"), 0o700)
        os.chmod(os.path.join(self.home, ".amap-relay"), 0o750)
        with mock.patch.dict(os.environ, {"HOME": self.home}):
            self.assertEqual(vd.main([vd.RELAY_FLAG]), vd.NOT_ALLOWED)
        self.assertEqual(os.listdir(os.path.join(self.home, ".amap-relay")), [])

    def test_a_flag_is_not_a_group_name(self):
        self.assertEqual(vd.main(["--other"]), vd.USAGE)
