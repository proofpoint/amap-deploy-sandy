"""S6b's writer, vm_login_writer: its refusals one by one, and the REAL writer under the REAL bootstrap.

FAKED, and only these: the account database (LOOKUP) and the uid change (BECOME), because a test without root can
neither look up a relay account that does not exist here nor become another uid. The RealLayerTest replaces exactly
those two lines of the shipped writer by text (each counted once), pins the result in the lock's writers[] row, and
runs it through a2_vm.VmLayer.write_secret, the shipped vm_bootstrap.py (served the way test_a2_vm serves it), a
fake ssh and a fake sudo. Everything else, the file's path, checks, write, read-back, rename and fsync, is the real
filesystem's. _become_account itself is proved by the unit tests below, on stand-in os calls.
"""

import os
import pwd
import shutil
import stat
import tempfile
import unittest

import a2fix  # noqa: F401  (puts install/ on sys.path)
import test_a2_vm
import vm_login_writer as W
from a2_causes import Refusal

INSTALL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHIPPED = os.path.join(INSTALL, "vm_login_writer.py")
ME = (os.getuid(), os.getgid())
GOOD = bytearray(b"Tr0ub4dor&3-correct-horse!")


def relay_home(base):
    """A relay home laid out as S6's vm_dirs leaves it: .amap-relay and .amap-relay/login, 0700, this uid's."""
    home = os.path.join(base, "relayhome")
    os.makedirs(os.path.join(home, W.RELAY_DIR, W.LOGIN_DIR))
    for p in (W.RELAY_DIR, os.path.join(W.RELAY_DIR, W.LOGIN_DIR)):
        os.chmod(os.path.join(home, p), 0o700)
    return home


def pw_for(home):
    return pwd.struct_passwd(("relay", "x", ME[0], ME[1], "", home, "/bin/sh"))


class _Dir(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="a2lw-")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.home = relay_home(self.d)
        self.login = os.path.join(self.home, W.RELAY_DIR, W.LOGIN_DIR)
        self.pw = os.path.join(self.login, W.NAME)

    def patch(self, obj, name, value):
        old = getattr(obj, name)
        setattr(obj, name, value)
        self.addCleanup(setattr, obj, name, old)


class ValueAndAccountTest(_Dir):
    def test_value_is_res_rule(self):
        self.assertTrue(W.value_ok(bytearray(b"!")))
        self.assertTrue(W.value_ok(bytearray(b"~" * W.VALUE_MAX)))
        for v in (bytearray(), bytearray(b"x" * (W.VALUE_MAX + 1)), bytearray(b"a b"), bytearray(b"ab\n"),
                  bytearray(b"ab\r"), bytearray(b"\x7f"), bytearray(b"\x80"), b"bytes", "str", None):
            with self.subTest(v=v):
                self.assertFalse(W.value_ok(v))

    def test_account_root_unknown_or_odd_home_refuses(self):
        self.patch(W, "LOOKUP", lambda n: (_ for _ in ()).throw(KeyError(n)))
        with self.assertRaises(W.Refuse) as cm:
            W.account_of("relay")
        self.assertEqual(cm.exception.cause, "ACCOUNT")
        for uid, gid, home in ((0, 1001, "/home/relay"), (1001, 0, "/home/relay"), (1001, 1001, "rel"),
                               (1001, 1001, "//x"), (1001, 1001, "/a/../b"), (1001, 1001, "/a/"), (1001, 1001, "/a/./b")):
            with self.subTest(uid=uid, gid=gid, home=home):
                self.patch(W, "LOOKUP", lambda n, u=uid, g=gid, h=home: pwd.struct_passwd(("relay", "x", u, g, "", h, "/")))
                with self.assertRaises(W.Refuse) as cm:
                    W.account_of("relay")
                self.assertEqual(cm.exception.cause, "ACCOUNT")
        self.patch(W, "LOOKUP", lambda n: pwd.struct_passwd(("relay", "x", 1001, 1002, "", "/home/relay", "/")))
        self.assertEqual(W.account_of("relay"), (1001, 1002, "/home/relay"))

    def test_the_shipped_lookup_and_become_are_the_real_ones(self):
        with open(SHIPPED) as f:
            t = f.read()
        self.assertEqual(t.count("\nLOOKUP = pwd.getpwnam\n"), 1)
        self.assertEqual(t.count("\nBECOME = _become_account\n"), 1)
        self.assertIs(W.LOOKUP, pwd.getpwnam)
        self.assertIs(W.BECOME, W._become_account)


class BecomeTest(_Dir):
    """_become_account on stand-in os calls: the order, the exact ids, and the proof that root is gone."""

    def fake(self, ids, root_again=False, groups=None):
        calls = []
        state = {"uid": 0, "gid": 0}

        def setgroups(g):
            calls.append(("setgroups", list(g)))
            state["groups"] = list(g)

        def setgid(g):
            calls.append(("setgid", g))
            state["gid"] = g

        def setuid(u):
            calls.append(("setuid", u))
            if u == 0 and state["uid"] != 0 and not root_again:
                raise PermissionError(1, "EPERM")
            state["uid"] = u
        for name, fn in (("setgroups", setgroups), ("setgid", setgid), ("setuid", setuid),
                         ("getresuid", lambda: (state["uid"],) * 3), ("getresgid", lambda: (state["gid"],) * 3),
                         ("getgroups", lambda: groups if groups is not None else state.get("groups", []))):
            self.patch(os, name, fn)
        return calls

    def test_groups_then_gid_then_uid_then_root_must_fail(self):
        calls = self.fake((1001, 1002))
        W._become_account(1001, 1002)
        self.assertEqual(calls, [("setgroups", [1002]), ("setgid", 1002), ("setuid", 1001), ("setuid", 0)])

    def test_root_regained_refuses(self):
        self.fake((1001, 1002), root_again=True)
        with self.assertRaises(W.Refuse) as cm:
            W._become_account(1001, 1002)
        self.assertEqual(cm.exception.cause, "DROP")

    def test_a_saved_root_id_refuses(self):
        self.fake((1001, 1002))
        self.patch(os, "getresuid", lambda: (1001, 1001, 0))
        with self.assertRaises(W.Refuse) as cm:
            W._become_account(1001, 1002)
        self.assertEqual(cm.exception.cause, "DROP")
        self.patch(os, "getresuid", lambda: (1001, 1001, 1001))
        self.patch(os, "getresgid", lambda: (1002, 1002, 0))
        with self.assertRaises(W.Refuse) as cm:
            W._become_account(1001, 1002)
        self.assertEqual(cm.exception.cause, "DROP")

    def test_a_leftover_group_refuses(self):
        self.fake((1001, 1002), groups=[1002, 4242])
        with self.assertRaises(W.Refuse) as cm:
            W._become_account(1001, 1002)
        self.assertEqual(cm.exception.cause, "DROP")


class DumpableTest(unittest.TestCase):
    def test_set_and_read_back_and_core_limit(self):
        seen = []

        def prctl(op, *a):
            seen.append(op)
            return 0
        W.not_dumpable(prctl, lambda r: (0, 0))
        self.assertEqual(seen, [W.PR_SET_DUMPABLE, W.PR_GET_DUMPABLE])
        for prctl_, lim in ((lambda op, *a: -1, (0, 0)), (lambda op, *a: 1 if op == W.PR_GET_DUMPABLE else 0, (0, 0)),
                            (lambda op, *a: 0, (0, 1)), (lambda op, *a: 0, (1, 1))):
            with self.assertRaises(W.Refuse) as cm:
                W.not_dumpable(prctl_, lambda r, l=lim: l)
            self.assertEqual(cm.exception.cause, "CORE_LIMIT")

    def test_the_real_calls_pass_with_a_zero_limit(self):
        import resource
        old = resource.getrlimit(resource.RLIMIT_CORE)
        pid = os.fork()
        if pid == 0:
            try:
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                W.not_dumpable()
                os._exit(0)
            except BaseException:
                os._exit(9)
        self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]), 0)
        self.assertEqual(resource.getrlimit(resource.RLIMIT_CORE), old)


class FileTest(_Dir):
    def write(self, value=None):
        return W.write_as((ME[0], ME[1], self.home), bytearray(value or GOOD))

    def setUp(self):
        super().setUp()
        self.patch(W, "not_dumpable", lambda: None)

    def assert_file(self, value):
        st = os.lstat(self.pw)
        self.assertTrue(stat.S_ISREG(st.st_mode))
        self.assertEqual((stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid, st.st_nlink), (0o400, ME[0], ME[1], 1))
        with open(self.pw, "rb") as f:
            self.assertEqual(f.read(), bytes(value))
        self.assertEqual(sorted(os.listdir(self.login)), [W.NAME])

    def refuses(self, cause, rc=2, value=None):
        with self.assertRaises(W.Refuse) as cm:
            self.write(value)
        self.assertEqual((cm.exception.cause, cm.exception.rc), (cause, rc))

    def test_writes_exactly_the_value_0400_one_link(self):
        self.assertEqual(self.write(), 0)
        self.assert_file(GOOD)

    def test_an_existing_own_file_is_replaced(self):
        self.write(b"old-value-old-value-old!!")
        self.write()
        self.assert_file(GOOD)

    def test_login_dir_missing_linked_or_not_0700(self):
        os.rmdir(self.login)
        self.refuses("LOGIN_DIR")
        os.mkdir(self.login, 0o700)
        os.chmod(self.login, 0o750)
        self.refuses("LOGIN_DIR")
        os.chmod(self.login, 0o700)
        os.chmod(os.path.join(self.home, W.RELAY_DIR), 0o755)
        self.refuses("LOGIN_DIR")
        os.chmod(os.path.join(self.home, W.RELAY_DIR), 0o700)
        real = os.path.join(self.home, W.RELAY_DIR, "real")
        os.rename(self.login, real)
        os.symlink("real", self.login)
        self.refuses("LOGIN_DIR")
        self.assertFalse(os.path.exists(os.path.join(real, W.NAME)))

    def test_relay_dir_as_a_symlink_refuses(self):
        rd = os.path.join(self.home, W.RELAY_DIR)
        os.rename(rd, rd + "-real")
        os.symlink(W.RELAY_DIR + "-real", rd)
        self.refuses("LOGIN_DIR")

    def test_a_leftover_temporary_refuses_and_stays(self):
        p = os.path.join(self.login, W.TEMP_PREFIX + "99")
        open(p, "wb").close()
        self.refuses("TEMP_LEFTOVER")
        self.assertTrue(os.path.exists(p))
        self.assertFalse(os.path.exists(self.pw))

    def test_a_password_that_is_a_link_a_dir_or_hard_linked_refuses(self):
        os.symlink("/etc/passwd", self.pw)
        self.refuses("LOGIN_FILE")
        os.unlink(self.pw)
        os.mkdir(self.pw)
        self.refuses("LOGIN_FILE")
        os.rmdir(self.pw)
        open(self.pw, "wb").close()
        os.link(self.pw, os.path.join(self.home, "other"))
        self.refuses("LOGIN_FILE")
        self.assertEqual(os.path.getsize(self.pw), 0)

    def test_a_temporary_planted_after_the_check_is_never_written_through(self):
        """O_EXCL: a name planted at the temporary's path between check_present and the open (here a hard link to a
        file outside the login dir) refuses WRITE_FAILED, exit 2, and the plant keeps its bytes."""
        outside = os.path.join(self.d, "outside")
        with open(outside, "wb") as f:
            f.write(b"untouched")
        real = W.check_present

        def then_plant(lfd, uid):
            real(lfd, uid)
            os.link(outside, os.path.join(self.login, "%s%d" % (W.TEMP_PREFIX, os.getpid())))
        self.patch(W, "check_present", then_plant)
        self.refuses("WRITE_FAILED", rc=2)
        with open(outside, "rb") as f:
            self.assertEqual(f.read(), b"untouched")
        self.assertFalse(os.path.exists(self.pw))

    def test_a_temporary_that_cannot_be_removed_is_4_not_undone(self):
        """N-2: the write fails and so does the unlink of the temporary: the partial copy is still there, so the
        outcome is TEMP_LEFT, exit 4, never WRITE_FAILED's "undone"."""
        def boom(*a):
            raise OSError("disk")

        def no_unlink(*a, **kw):
            raise OSError("unlink")
        self.patch(os, "fsync", boom)
        self.patch(os, "unlink", no_unlink)
        self.refuses("TEMP_LEFT", rc=4)
        self.assertEqual([n for n in os.listdir(self.login) if n.startswith(W.TEMP_PREFIX)],
                         ["%s%d" % (W.TEMP_PREFIX, os.getpid())])

    def test_a_read_back_size_that_differs_is_undone(self):
        """The read-back holds the size to len(value): an fstat that reports one byte more refuses WRITE_FAILED,
        exit 3, with the temporary gone and no password file."""
        real = os.fstat

        def bigger(fd):
            st = real(fd)
            if stat.S_ISREG(st.st_mode):
                f = list(st)
                f[6] += 1
                return os.stat_result(f)
            return st
        self.patch(os, "fstat", bigger)
        self.refuses("WRITE_FAILED", rc=3)
        self.assertEqual(os.listdir(self.login), [])

    def test_a_failed_write_removes_the_temporary(self):
        def boom(*a):
            raise OSError("disk")
        self.patch(os, "fsync", boom)
        self.refuses("WRITE_FAILED", rc=3)
        self.assertEqual(os.listdir(self.login), [])

    def test_a_read_back_that_differs_is_undone(self):
        real = os.fchmod
        self.patch(os, "fchmod", lambda fd, m: real(fd, 0o440))
        self.refuses("WRITE_FAILED", rc=3)
        self.assertEqual(os.listdir(self.login), [])

    def test_a_failed_rename_is_undone_and_the_old_file_stays(self):
        self.write(b"old-value-old-value-old!!")

        def boom(*a, **kw):
            raise OSError("rename")
        self.patch(os, "rename", boom)
        self.refuses("WRITE_FAILED", rc=3)
        self.assert_file(b"old-value-old-value-old!!")

    def test_a_failed_directory_fsync_after_the_rename_is_4_and_the_file_stands(self):
        real = os.fsync
        n = []

        def second_fails(fd):
            n.append(fd)
            if len(n) == 2:
                raise OSError("dir fsync")
            return real(fd)
        self.patch(os, "fsync", second_fails)
        self.refuses("DURABILITY_UNCERTAIN", rc=4)
        self.assert_file(GOOD)


class MainTest(_Dir):
    def setUp(self):
        super().setUp()
        self.patch(W, "LOOKUP", lambda n: pw_for(self.home) if n == "relay" else (_ for _ in ()).throw(KeyError(n)))
        self.become = []
        self.patch(W, "BECOME", lambda u, g: self.become.append((u, g)))
        self.patch(W, "not_dumpable", lambda: None)
        r, w = os.pipe()
        self.err_r = r
        saved = os.dup(2)
        os.dup2(w, 2)
        os.close(w)

        def restore():
            os.dup2(saved, 2)
            os.close(saved)
        self.addCleanup(os.close, r)
        self.addCleanup(restore)

    def stderr(self):
        os.set_blocking(self.err_r, False)
        try:
            return os.read(self.err_r, 4096)
        except BlockingIOError:
            return b""

    def test_write_mode_in_a_child_as_the_account(self):
        self.assertEqual(W.main("write", bytearray(GOOD), "relay"), 0)
        with open(self.pw, "rb") as f:
            self.assertEqual(f.read(), bytes(GOOD))
        self.assertEqual(self.become, [], "BECOME ran in the child, not in the bootstrap's process")
        self.assertEqual(self.stderr(), b"")

    def test_refusals_before_the_fork_name_one_cause(self):
        for args, cause in ((("rotate", bytearray(GOOD), "relay"), b"MODE"),
                            (("finish", None, "relay"), b"MODE"),
                            (("write", bytearray(b"has space"), "relay"), b"VALUE_FORM"),
                            (("write", bytearray(GOOD), "nobody-here"), b"ACCOUNT")):
            with self.subTest(cause=cause):
                self.assertEqual(W.main(*args), 2)
                self.assertEqual(self.stderr(), b"CAUSE=" + cause + b"\n")
        self.assertFalse(os.path.exists(self.pw))

    def test_the_child_checks_dumpable_and_the_core_limit_after_the_drop_and_before_the_file(self):
        """Rule 1 of 3.7 in the child: not_dumpable runs after BECOME, and its refusal writes nothing. The order is
        recorded in a file, because both calls run in the forked child."""
        order = os.path.join(self.d, "order")

        def mark(word):
            with open(order, "a") as f:
                f.write(word + "\n")

        def no(*a, **k):
            mark("not_dumpable")
            raise W.Refuse("CORE_LIMIT")
        self.patch(W, "BECOME", lambda u, g: mark("become"))
        self.patch(W, "not_dumpable", no)
        self.assertEqual(W.main("write", bytearray(GOOD), "relay"), 2)
        self.assertEqual(self.stderr(), b"CAUSE=CORE_LIMIT\n")
        with open(order) as f:
            self.assertEqual(f.read().split(), ["become", "not_dumpable"])
        self.assertEqual(os.listdir(self.login), [])

    def test_a_failed_drop_is_2_and_writes_nothing(self):
        def drop(u, g):
            raise PermissionError(1, "EPERM")
        self.patch(W, "BECOME", drop)
        self.assertEqual(W.main("write", bytearray(GOOD), "relay"), 2)
        self.assertEqual(self.stderr(), b"CAUSE=DROP\n")
        self.assertFalse(os.path.exists(self.pw))

    def test_a_child_killed_is_4(self):
        import signal
        self.patch(W, "BECOME", lambda u, g: os.kill(os.getpid(), signal.SIGKILL))
        self.assertEqual(W.main("write", bytearray(GOOD), "relay"), 4)

    def test_the_value_never_reaches_stderr(self):
        os.chmod(self.login, 0o750)
        self.assertEqual(W.main("write", bytearray(GOOD), "relay"), 2)
        err = self.stderr()
        self.assertEqual(err, b"CAUSE=LOGIN_DIR\n")
        self.assertNotIn(bytes(GOOD[:6]), err)


class RealLayerTest(test_a2_vm.Base):
    """The REAL writer under the REAL bootstrap through a2_vm.VmLayer.write_secret("hub_login", "write").
    FAKED: LOOKUP (the relay account is this uid with a temporary home) and BECOME (no uid change without root)."""

    def setUp(self):
        super().setUp()
        self.home = relay_home(self.d)
        self.pw = os.path.join(self.home, W.RELAY_DIR, W.LOGIN_DIR, W.NAME)
        self.pin_writer()

    def writer_text(self):
        with open(SHIPPED) as f:
            t = f.read()
        fake_lookup = ("LOOKUP = (lambda n: pwd.struct_passwd(('relay', 'x', %d, %d, '', %r, '/bin/sh')) "
                       "if n == 'relay' else {}[n])\n" % (ME[0], ME[1], self.home))
        for old, new in (("LOOKUP = pwd.getpwnam\n", fake_lookup),
                         ("BECOME = _become_account\n", "BECOME = (lambda uid, gid: None)\n")):
            assert t.count("\n" + old) == 1, old
            t = t.replace("\n" + old, "\n" + new)
        return t

    def pin_writer(self, text=None):
        p = os.path.join(self.inst, "w", "login.py")
        with open(p, "w") as f:
            f.write(text if text is not None else self.writer_text())
        self.lock["writers"] = [r for r in self.lock["writers"] if r["use"] != "hub_login"] + [
            {"use": "hub_login", "path": "install/w/login.py", "sha256": self.sha_file(p)}]

    def write(self, value, account="relay"):
        return self.layer().write_secret("vm-a", "hub_login", "write", bytearray(value), account=account,
                                         stage="HUB-LOGIN")

    def test_the_file_is_res_after_one_session(self):
        self.assertEqual(self.write(GOOD), 0)
        st = os.lstat(self.pw)
        self.assertEqual((stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid, st.st_nlink), (0o400, ME[0], ME[1], 1))
        with open(self.pw, "rb") as f:
            self.assertEqual(f.read(), bytes(GOOD))
        log = "\n".join(self.logged())
        self.assertEqual(log.count("\nSUDO ") + log.startswith("SUDO "), 1)
        self.assertIn(" secret hub_login write %s relay\n" % self.lock["writers"][-1]["sha256"], log + "\n")

    def test_the_writers_codes_come_back_through_the_bootstrap(self):
        self.assertEqual(self.write(b"has space in it, not RE's form"), 2)
        self.assertEqual(self.write(GOOD, account="nobody"), 2)
        open(os.path.join(self.home, W.RELAY_DIR, W.LOGIN_DIR, W.TEMP_PREFIX + "1"), "wb").close()
        self.assertEqual(self.write(GOOD), 2)
        self.assertFalse(os.path.exists(self.pw))

    def test_one_byte_changed_on_the_way_gets_no_value(self):
        t = self.writer_text()
        self.pin_writer(t)
        p = os.path.join(self.inst, "w", "login.py")
        with open(p, "w") as f:
            f.write(t.replace("VALUE_MAX = 1024", "VALUE_MAX = 1025"))
        with self.assertRaises(Refusal) as cm:
            self.write(GOOD)
        self.assertEqual(cm.exception.cause, "HUB-LOGIN.PIN")
        self.assertFalse(os.path.exists(self.pw))

    def test_a_rerun_replaces_the_file(self):
        self.write(b"old-value-old-value-old!!")
        self.assertEqual(self.write(GOOD), 0)
        with open(self.pw, "rb") as f:
            self.assertEqual(f.read(), bytes(GOOD))


if __name__ == "__main__":
    unittest.main()
