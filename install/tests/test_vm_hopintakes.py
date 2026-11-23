"""vm_bootstrap's `hopintakes` op (ruling W7-HOPINTAKES, option R), run in-process on the shipped bytes.

Without root a test cannot own a directory as another uid, so the shipped text is loaded with ROOT rewritten to a
temporary VM root (as test_a2_vm does), and its two ownership names (`_fstat`, `_fchown`) are replaced by a table
that stands fake uids in for this one: a directory this uid really owns reads as AGENT's unless the table says
otherwise, and `_fchown` records into the table. Modes, setgid inheritance, symlinks, O_NOFOLLOW and the dir-fd
walk are the real filesystem's. The account and group lookups (`pwd`, `grp`) are fakes of the same shape.
"""

import os
import shutil
import stat
import tempfile
import types
import unittest

import a2fix  # noqa: F401  (puts install/ on sys.path)

INSTALL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHIPPED = os.path.join(INSTALL, "vm_bootstrap.py")
ME = os.getuid()
G = os.getgid()
AGENT, RELAY, OTHER = 52001, 52002, 52003
HOP = "/home/agent/.amap-hop"


class _Pwd:
    def __init__(self, table):
        self.table = table

    def getpwnam(self, name):
        if name not in self.table:
            raise KeyError(name)
        uid, gid = self.table[name]
        return types.SimpleNamespace(pw_uid=uid, pw_gid=gid)


class _Grp:
    def __init__(self, table):
        self.table = table

    def getgrnam(self, name):
        if name not in self.table:
            raise KeyError(name)
        gid, mem = self.table[name]
        return types.SimpleNamespace(gr_gid=gid, gr_mem=list(mem))


class HopIntakesTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="a2hi-")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.root = os.path.join(self.d, "vm")
        self.hop = self.root + HOP
        os.makedirs(self.hop)
        for p in (self.root, self.root + "/home", self.root + "/home/agent"):
            os.chmod(p, 0o755)
        os.chmod(self.hop, 0o2750)
        with open(SHIPPED) as f:
            text = f.read()
        assert text.count('ROOT = "/"\n') == 1
        self.mod = types.ModuleType("vm_bootstrap_hi")
        exec(compile(text.replace('ROOT = "/"\n', "ROOT = %r\n" % self.root), SHIPPED, "exec"), self.mod.__dict__)
        self.owners = {}
        self.mod._fstat = self.fstat
        self.mod._fchown = self.fchown
        self.mod.pwd = _Pwd({"relay": (RELAY, OTHER), "agent": (AGENT, G), "rootish": (0, G)})
        self.mod.grp = _Grp({"hop": (G, ("relay", "rootish")), "nothop": (OTHER + 1, ())})

    def fstat(self, fd):
        st = os.fstat(fd)
        uid, gid = self.owners.get((st.st_dev, st.st_ino), (AGENT if st.st_uid == ME else st.st_uid, st.st_gid))
        return types.SimpleNamespace(st_mode=st.st_mode, st_uid=uid, st_gid=gid)

    def fchown(self, fd, uid, gid):
        st = os.fstat(fd)
        self.owners[(st.st_dev, st.st_ino)] = (uid, gid)

    def own(self, path, uid, gid=G):
        st = os.lstat(path)
        self.owners[(st.st_dev, st.st_ino)] = (uid, gid)

    def owner_of(self, path):
        st = os.lstat(path)
        return self.owners.get((st.st_dev, st.st_ino), (AGENT, st.st_gid))

    def run_op(self, root=HOP, account="relay", group="hop"):
        try:
            return self.mod.hopintakes(root, account, group)
        except self.mod.Stop as e:
            return e.code

    def intake(self, name):
        return os.path.join(self.hop, name)

    def assert_none_made(self):
        self.assertEqual(sorted(os.listdir(self.hop)), [])

    # -- the good path

    def test_creates_both_as_relay_in_the_group_setgid_then_already(self):
        self.assertEqual(self.run_op(), self.mod.OK)
        for name in (".unresolved", ".control"):
            p = self.intake(name)
            st = os.lstat(p)
            self.assertTrue(stat.S_ISDIR(st.st_mode))
            self.assertEqual(stat.S_IMODE(st.st_mode), 0o2750)
            self.assertEqual(st.st_gid, G)
            self.assertEqual(self.owner_of(p), (RELAY, G))
        self.assertEqual(sorted(os.listdir(self.hop)), [".control", ".unresolved"])
        self.assertEqual(self.run_op(), self.mod.ALREADY)

    def test_one_in_place_one_absent_creates_only_the_absent(self):
        os.mkdir(self.intake(".unresolved"))
        os.chmod(self.intake(".unresolved"), 0o2750)
        self.own(self.intake(".unresolved"), RELAY)
        before = os.lstat(self.intake(".unresolved")).st_ino
        self.assertEqual(self.run_op(), self.mod.OK)
        self.assertEqual(os.lstat(self.intake(".unresolved")).st_ino, before)
        self.assertEqual(self.owner_of(self.intake(".control")), (RELAY, G))

    def test_a_sticky_world_writable_ancestor_is_trusted(self):
        os.chmod(self.root + "/home", 0o1777)
        self.assertEqual(self.run_op(), self.mod.OK)

    def test_main_routes_the_op(self):
        self.assertEqual(self.mod.main(["hopintakes", HOP, "relay", "hop"]), self.mod.OK)
        self.assertEqual(self.mod.main(["hopintakes", HOP, "relay"]), self.mod.USAGE)

    def test_a_chown_that_did_not_take_is_a_readback_failure(self):
        self.mod._fchown = lambda fd, uid, gid: None
        self.assertEqual(self.run_op(), self.mod.READBACK)

    # -- the hop root

    def test_root_mode_must_be_exactly_2750(self):
        for mode in (0o2770, 0o0750, 0o2755, 0o2700, 0o3750):
            os.chmod(self.hop, mode)
            self.assertEqual(self.run_op(), self.mod.NOT_ALLOWED, oct(mode))
            self.assert_none_made()

    def test_root_owned_by_root_or_the_relay_refuses(self):
        for uid in (0, RELAY):
            self.own(self.hop, uid)
            self.assertEqual(self.run_op(), self.mod.NOT_ALLOWED, uid)
            self.assert_none_made()

    def test_a_root_owned_hop_root_refuses_even_under_root_owned_ancestors(self):
        """Every ancestor root-owned, so the ancestor rule passes for owner 0: only the root-owner rule refuses."""
        for p in (self.root, self.root + "/home", self.root + "/home/agent"):
            self.own(p, 0)
        self.own(self.hop, 0)
        self.assertEqual(self.run_op(), self.mod.NOT_ALLOWED)
        self.assert_none_made()
        self.own(self.hop, AGENT)
        self.assertEqual(self.run_op(), self.mod.OK)

    def test_root_in_another_group_refuses(self):
        self.own(self.hop, AGENT, OTHER)
        self.assertEqual(self.run_op(), self.mod.NOT_ALLOWED)
        self.assert_none_made()

    def test_a_symlinked_root_or_a_missing_one_refuses(self):
        real = self.root + "/home/agent/real-hop"
        os.rename(self.hop, real)
        os.symlink(real, self.hop)
        self.assertEqual(self.run_op(), self.mod.NOT_ALLOWED)
        self.assertEqual(os.listdir(real), [])
        os.unlink(self.hop)
        self.assertEqual(self.run_op(), self.mod.NOT_ALLOWED)

    def test_a_symlinked_ancestor_refuses(self):
        os.rename(self.root + "/home/agent", self.root + "/home/agent-real")
        os.symlink("agent-real", self.root + "/home/agent")
        self.assertEqual(self.run_op(), self.mod.NOT_ALLOWED)

    def test_untrusted_ancestors_refuse(self):
        os.chmod(self.root + "/home/agent", 0o775)
        self.assertEqual(self.run_op(), self.mod.NOT_ALLOWED)
        os.chmod(self.root + "/home/agent", 0o757)
        self.assertEqual(self.run_op(), self.mod.NOT_ALLOWED)
        os.chmod(self.root + "/home/agent", 0o755)
        self.own(self.root + "/home", OTHER)
        self.assertEqual(self.run_op(), self.mod.NOT_ALLOWED)
        self.own(self.root + "/home", 0)
        self.own(self.root, RELAY)
        self.assertEqual(self.run_op(), self.mod.NOT_ALLOWED)
        self.assert_none_made()

    def test_an_ancestor_owned_by_root_is_trusted(self):
        self.own(self.root, 0)
        self.own(self.root + "/home", 0)
        self.assertEqual(self.run_op(), self.mod.OK)

    # -- existing intakes: never repaired

    def test_an_existing_intake_with_the_wrong_owner_or_mode_refuses_and_is_left(self):
        p = self.intake(".control")
        os.mkdir(p)
        for owner, mode in (((AGENT, G), 0o2750), ((RELAY, OTHER), 0o2750), ((RELAY, G), 0o2770),
                            ((RELAY, G), 0o0750), ((0, G), 0o2750)):
            os.chmod(p, mode)
            self.own(p, *owner)
            self.assertEqual(self.run_op(), self.mod.NOT_ALLOWED, (owner, oct(mode)))
            self.assertEqual(stat.S_IMODE(os.lstat(p).st_mode), mode)
            self.assertEqual(self.owner_of(p), owner)
            self.assertFalse(os.path.lexists(self.intake(".unresolved")))

    def test_a_symlinked_intake_refuses(self):
        target = self.root + "/home/agent/elsewhere"
        os.mkdir(target)
        os.chmod(target, 0o2750)
        self.own(target, RELAY)
        os.symlink(target, self.intake(".unresolved"))
        self.assertEqual(self.run_op(), self.mod.NOT_ALLOWED)
        self.assertFalse(os.path.lexists(self.intake(".control")))

    def test_an_intake_that_is_a_file_refuses(self):
        open(self.intake(".control"), "w").close()
        self.assertEqual(self.run_op(), self.mod.NOT_ALLOWED)
        self.assertFalse(os.path.lexists(self.intake(".unresolved")))

    def test_a_wrong_second_intake_refuses_before_the_first_is_made(self):
        os.mkdir(self.intake(".control"))
        os.chmod(self.intake(".control"), 0o2770)
        self.own(self.intake(".control"), RELAY)
        self.assertEqual(self.run_op(), self.mod.NOT_ALLOWED)
        self.assertFalse(os.path.lexists(self.intake(".unresolved")))

    # -- the account and group

    def test_account_and_group_rules(self):
        self.assertEqual(self.run_op(account="ghost"), self.mod.NOT_ALLOWED)
        self.assertEqual(self.run_op(group="ghost"), self.mod.NOT_ALLOWED)
        self.assertEqual(self.run_op(account="rootish"), self.mod.NOT_ALLOWED)
        self.mod.grp = _Grp({"hop": (G, ())})
        self.assertEqual(self.run_op(), self.mod.NOT_ALLOWED)
        self.assert_none_made()

    def test_the_account_by_primary_group_is_in_the_group(self):
        self.mod.pwd = _Pwd({"relay": (RELAY, G)})
        self.mod.grp = _Grp({"hop": (G, ())})
        self.assertEqual(self.run_op(), self.mod.OK)

    def test_the_hop_root_owner_is_not_the_relay_account(self):
        self.mod.pwd = _Pwd({"relay": (AGENT, G)})
        self.assertEqual(self.run_op(), self.mod.NOT_ALLOWED)
        self.assert_none_made()

    # -- usage

    def test_usage(self):
        for root in ("relative/hop", "/home/agent/../agent/.amap-hop", "/home/agent/./.amap-hop", "/home//agent",
                     "/", "/home/agent/.amap-hop/", "/home/a b"):
            self.assertEqual(self.run_op(root=root), self.mod.USAGE, root)
        for name in ("Relay", "", "1relay", "re lay"):
            self.assertEqual(self.run_op(account=name), self.mod.USAGE, name)
            self.assertEqual(self.run_op(group=name), self.mod.USAGE, name)
        self.assert_none_made()


if __name__ == "__main__":
    unittest.main()
