"""W8: S7's token writer, run as the VM runs it: the REAL rule-7 bootstrap (vm_bootstrap.py
`secret api_key <mode> <sha> agent`, through tests/secret_session.py), plus in-process fault
injection on `apply`. Synthetic values only.

FAKED, and only these: the writer's LOOKUP (the agent account is this uid with a test home)
and BECOME (no uid change without root), by text in secret_session.faked_writer; every
other byte is the shipped writer, and the bootstrap is the shipped one."""

import collections
import hashlib
import inspect
import os
import signal
import stat
import unittest
from unittest import mock

import a2fix  # noqa: F401  (puts install/ on sys.path)
import secret_session
import vm_token_writer as W

WRITER = os.path.join(a2fix.INSTALL, "vm_token_writer.py")
TOKEN = b"sk-ant-oat01-SYNTHETIC-token-value-0001"
TOKEN2 = b"sk-ant-oat01-SYNTHETIC-token-value-0002"
Result = collections.namedtuple("Result", "returncode stdout stderr")


def writer_copy(home):
    """The shipped writer's text with LOOKUP and BECOME faked for the account "agent"."""
    return secret_session.faked_writer(WRITER, home, "agent")


class Base(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = os.path.join(self.tmp.name, "home")
        self.sandy = os.path.join(self.home, ".sandy")
        os.makedirs(self.sandy)
        os.chmod(self.sandy, 0o700)
        self.secrets = os.path.join(self.sandy, ".secrets")
        self.writer = writer_copy(self.home)

    def run_vm(self, mode, value=None, writer=None, want=None, account="agent"):
        """One real session. The bootstrap's exit code is the writer's on every path that
        reached the writer (it prints RC <n> and returns n)."""
        if value is None and mode in W.VALUE_MODES:
            value = b""
        rc, out, err = secret_session.run(writer or self.writer, "api_key", mode, value, account, want=want)
        if out.startswith(b"READY\n") and out != b"READY\nRC %d\n" % rc:
            raise AssertionError("the bootstrap's RC line does not match its exit code: %r" % out)
        return Result(rc, out, err)

    def put(self, data, mode=0o600, path=None):
        p = path or self.secrets
        with open(p, "wb") as f:
            f.write(data)
        os.chmod(p, mode)

    def read(self, path=None):
        with open(path or self.secrets, "rb") as f:
            return f.read()

    def listing(self):
        return sorted(os.listdir(self.sandy))

    def inproc(self, mode, value=b""):
        """apply() in this process, as the child would run it, against the test home."""
        v = bytearray(value) if mode in W.VALUE_MODES else None
        return W.apply(mode, v, os.getuid(), self.home)


class WriteTest(Base):
    def test_fresh_file_one_line_0600(self):
        p = self.run_vm("write", TOKEN)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.read(), W.KEY + b"=" + TOKEN + b"\n")
        self.assertEqual(stat.S_IMODE(os.stat(self.secrets).st_mode), 0o600)
        self.assertEqual(self.listing(), [".secrets"])

    def test_other_lines_kept_byte_for_byte_and_token_lines_collapse(self):
        self.put(b"A=1\nCLAUDE_CODE_OAUTH_TOKEN=old1\n# note\nB=2\r\nCLAUDE_CODE_OAUTH_TOKEN=old2\n"
                 b"export CLAUDE_CODE_OAUTH_TOKEN=x\n CLAUDE_CODE_OAUTH_TOKEN=y\nC=a\rb\n")
        p = self.run_vm("write", TOKEN)
        self.assertEqual(p.returncode, 0, p.stderr)
        # sandy's key is exactly the text before the first '=': `export K` and ` K` are
        # other keys, kept; a lone CR is not a line break (F1, L1).
        self.assertEqual(self.read(), b"A=1\n# note\nB=2\r\nexport CLAUDE_CODE_OAUTH_TOKEN=x\n"
                                      b" CLAUDE_CODE_OAUTH_TOKEN=y\nC=a\rb\n" + W.KEY + b"=" + TOKEN + b"\n")

    def test_a_file_without_a_final_lf_is_refused_unchanged(self):
        self.put(b"A=1\nB=2")  # sandy never reads B; appending would make it read it
        p = self.run_vm("write", TOKEN)
        self.assertEqual((p.returncode, p.stderr), (2, b"CAUSE=SECRETS_FILE_SHAPE\n"))
        self.assertEqual(self.read(), b"A=1\nB=2")

    def test_nothing_printed_and_no_value_in_output(self):
        p = self.run_vm("write", TOKEN)
        self.assertEqual((p.stdout, p.stderr), (b"READY\nRC 0\n", b""))
        p = self.run_vm("write", b"bad value with spaces")
        self.assertNotIn(b"bad value", p.stdout + p.stderr)
        self.assertEqual(p.stderr, b"CAUSE=VALUE_FORM\n")

    def test_bad_values_refused_file_unchanged(self):
        self.put(b"A=1\n")
        for v in (b"", b"\n", b"a\nb", b"a b", b"x" * (W.VALUE_MAX + 1), b"caf\xc3\xa9",
                  b'"quoted', b"quoted'", b"'x'", b"a\rb"):
            with self.subTest(v=v[:12]):
                p = self.run_vm("write", v)
                self.assertEqual(p.returncode, 2)
                self.assertEqual(self.read(), b"A=1\n")

    def test_a_symlinked_secrets_file_is_refused(self):
        target = os.path.join(self.tmp.name, "elsewhere")
        self.put(b"KEEP\n", path=target)
        os.symlink(target, self.secrets)
        p = self.run_vm("write", TOKEN)
        self.assertEqual((p.returncode, p.stderr), (2, b"CAUSE=SECRETS_FILE\n"))
        self.assertEqual(self.read(target), b"KEEP\n")

    def test_group_readable_file_or_open_dir_refused(self):
        self.put(b"A=1\n", 0o640)
        self.assertEqual(self.run_vm("write", TOKEN).stderr, b"CAUSE=SECRETS_FILE\n")
        os.chmod(self.secrets, 0o600)
        os.chmod(self.sandy, 0o750)
        self.assertEqual(self.run_vm("write", TOKEN).stderr, b"CAUSE=SECRETS_DIR\n")
        self.assertEqual(self.read(), b"A=1\n")


class TargetPinTest(Base):  # Opus 5; DS 5d428598: no path is passed
    def test_no_path_reaches_the_writer(self):
        """The bootstrap's entry takes the mode, the value and the account, nothing else; the
        path is derived from the account database alone."""
        self.assertEqual(list(inspect.signature(W.main).parameters), ["mode", "value", "account"])
        self.assertEqual(list(inspect.signature(W.apply).parameters), ["mode", "value", "uid", "home"])

    def test_a_symlinked_sandy_directory_is_refused(self):
        real = os.path.join(self.tmp.name, "elsewhere")
        os.rename(self.sandy, real)
        os.symlink(real, self.sandy)
        p = self.run_vm("write", TOKEN)
        self.assertEqual((p.returncode, p.stderr), (2, b"CAUSE=TARGET\n"))
        self.assertEqual(os.listdir(real), [])

    def test_the_shipped_pin_is_the_account_databases_home(self):
        import pwd
        self.assertIs(W.LOOKUP, pwd.getpwnam)
        self.assertIs(W.BECOME, W._become_account)
        self.assertEqual(W.pinned_path("/home/agent"), "/home/agent/.sandy/.secrets")
        self.assertEqual(W.account_of(pwd.getpwuid(os.getuid()).pw_name)[2], pwd.getpwuid(os.getuid()).pw_dir)

    def test_a_primary_group_of_root_refuses(self):
        rootgrp = secret_session.faked_writer(WRITER, self.home, "agent", gid=0)
        p = self.run_vm("write", TOKEN, writer=rootgrp)
        self.assertEqual((p.returncode, p.stderr), (2, b"CAUSE=ACCOUNT\n"))
        self.assertFalse(os.path.exists(self.secrets))

    def test_an_unknown_account_or_root_refuses(self):
        p = self.run_vm("write", TOKEN, account="nobody")
        self.assertEqual((p.returncode, p.stderr), (2, b"CAUSE=ACCOUNT\n"))
        root = secret_session.faked_writer(WRITER, self.home, "agent", uid=0)
        p = self.run_vm("write", TOKEN, writer=root)
        self.assertEqual((p.returncode, p.stderr), (2, b"CAUSE=ACCOUNT\n"))
        self.assertFalse(os.path.exists(self.secrets))


class RuleOneTest(Base):  # Opus 3
    def in_child(self, **patches):
        """main() in this process: LOOKUP, BECOME and not_dumpable stood in (this test
        process's core limit is not zero; the real sessions above run not_dumpable for
        real), plus `patches` on W; the child's stderr captured."""
        import pwd
        base = dict(LOOKUP=lambda n: pwd.struct_passwd(("agent", "x", os.getuid(), os.getgid(), "", self.home, "/")),
                    BECOME=lambda u, g: None, not_dumpable=lambda: None)
        base.update(patches)
        for k, v in base.items():
            mock.patch.object(W, k, v).start()
        self.addCleanup(mock.patch.stopall)
        r, w = os.pipe()
        saved = os.dup(2)
        os.dup2(w, 2)
        os.close(w)
        try:
            rc = W.main("write", bytearray(TOKEN), "agent")
        finally:
            os.dup2(saved, 2)
            os.close(saved)
        err = os.read(r, 4096)
        os.close(r)
        return rc, err

    def test_a_core_limit_or_dumpable_failure_after_the_drop_writes_nothing(self):
        def no(*a, **k):
            raise W.Refuse("CORE_LIMIT")
        self.assertEqual(self.in_child(not_dumpable=no), (2, b"CAUSE=CORE_LIMIT\n"))
        self.assertFalse(os.path.exists(self.secrets))

    def test_not_dumpable_refuses_when_the_limit_or_the_flag_does_not_hold(self):
        for prctl, lim in ((lambda op, *a: 0, (1, 1)), (lambda op, *a: -1, (0, 0)),
                           (lambda op, *a: 1 if op == W.PR_GET_DUMPABLE else 0, (0, 0))):
            with self.assertRaises(W.Refuse) as cm:
                W.not_dumpable(prctl, lambda r, l=lim: l)
            self.assertEqual(cm.exception.cause, "CORE_LIMIT")
        W.not_dumpable(lambda op, *a: 0, lambda r: (0, 0))

    def test_a_failed_drop_writes_nothing(self):
        def drop(u, g):
            raise PermissionError(1, "EPERM")
        self.assertEqual(self.in_child(BECOME=drop), (2, b"CAUSE=DROP\n"))
        self.assertFalse(os.path.exists(self.secrets))

    def test_an_unexpected_error_in_the_child_is_rc4_with_one_cause_line(self):  # Opus W8 r2, 3 (X11)
        def odd(*a, **k):
            raise RuntimeError("anything")
        rc, err = self.in_child(apply=odd)
        self.assertEqual((rc, err), (4, b"CAUSE=UNCLASSIFIED\n"))  # unknown: S7 must not read it as "nothing changed"

    def test_a_child_killed_is_rc4(self):
        rc, err = self.in_child(BECOME=lambda u, g: os.kill(os.getpid(), signal.SIGKILL))
        self.assertEqual((rc, err), (4, b"CAUSE=UNCLASSIFIED\n"))

    def test_the_drop_is_groups_gid_uid_then_root_must_fail(self):
        calls = []
        ids = {"uid": 0, "gid": 0, "groups": []}

        def setuid(u):
            calls.append(("setuid", u))
            if u == 0 and ids["uid"] != 0:
                raise PermissionError(1, "EPERM")
            ids["uid"] = u
        fakes = dict(setgroups=lambda g: calls.append(("setgroups", list(g))) or ids.update(groups=list(g)),
                     setgid=lambda g: calls.append(("setgid", g)) or ids.update(gid=g), setuid=setuid,
                     getresuid=lambda: (ids["uid"],) * 3, getresgid=lambda: (ids["gid"],) * 3,
                     getgroups=lambda: ids["groups"])
        with mock.patch.multiple(W.os, **fakes):
            W._become_account(1001, 1002)
        self.assertEqual(calls, [("setgroups", [1002]), ("setgid", 1002), ("setuid", 1001), ("setuid", 0)])

    def test_a_saved_root_id_refuses(self):
        for resuid, resgid in (((1001, 1001, 0), (1002,) * 3), ((1001,) * 3, (1002, 1002, 0))):
            fakes = dict(setgroups=lambda g: None, setgid=lambda g: None,
                         setuid=lambda u: (_ for _ in ()).throw(PermissionError(1, "EPERM")) if u == 0 else None,
                         getresuid=lambda r=resuid: r, getresgid=lambda r=resgid: r, getgroups=lambda: [1002])
            with mock.patch.multiple(W.os, **fakes):
                with self.assertRaises(W.Refuse) as cm:
                    W._become_account(1001, 1002)
            self.assertEqual(cm.exception.cause, "DROP")

    def test_regaining_root_refuses(self):
        fakes = dict(setgroups=lambda g: None, setgid=lambda g: None, setuid=lambda u: None,
                     getresuid=lambda: (1001,) * 3, getresgid=lambda: (1002,) * 3, getgroups=lambda: [1002])
        with mock.patch.multiple(W.os, **fakes):
            with self.assertRaises(W.Refuse) as cm:
                W._become_account(1001, 1002)
        self.assertEqual(cm.exception.cause, "DROP")


class FaultTest(Base):  # Opus 2, monitor M1, MB
    def setUp(self):
        super().setUp()
        self.put(W.KEY + b"=" + TOKEN + b"\n")
        self.old = self.read()

    def fail(self, name, after=0):
        real = getattr(W.os, name)
        calls = {"n": 0}

        def f(*a, **k):
            calls["n"] += 1
            if calls["n"] > after:
                raise OSError("injected")
            return real(*a, **k)
        return mock.patch.object(W.os, name, side_effect=f)

    def rotate(self):
        with self.assertRaises(W.Refuse) as cm:
            self.inproc("rotate", TOKEN2)
        return cm.exception

    def test_a_failed_rename_leaves_the_file_and_no_prev(self):
        with self.fail("rename"):
            e = self.rotate()
        self.assertEqual((e.cause, e.rc), ("WRITE_FAILED", 3))
        self.assertEqual(self.read(), self.old)
        self.assertEqual(self.listing(), [".secrets"])  # MB: no linked .prev left behind

    def test_a_failed_temp_fsync_leaves_the_file_and_no_temp(self):
        with self.fail("fsync"):
            e = self.rotate()
        self.assertEqual((e.cause, e.rc), ("WRITE_FAILED", 3))
        self.assertEqual(self.read(), self.old)
        self.assertEqual(self.listing(), [".secrets"])

    def test_a_failed_directory_fsync_after_the_rename_keeps_prev_rc4(self):
        with self.fail("fsync", after=1):  # the temp fsync passes, the directory's fails
            e = self.rotate()
        self.assertEqual((e.cause, e.rc), ("DURABILITY_UNCERTAIN", 4))
        self.assertEqual(self.read(), W.KEY + b"=" + TOKEN2 + b"\n")  # the change stands
        self.assertEqual(self.read(self.secrets + ".prev"), self.old)  # and can be restored
        W.apply("restore", None, os.getuid(), self.home)
        self.assertEqual(self.read(), self.old)

    def test_a_failed_directory_open_after_the_rename_keeps_prev_rc4(self):
        real_open = W.os.open

        def f(path, flags, *a, **k):
            if flags & os.O_DIRECTORY:
                raise OSError("injected")
            return real_open(path, flags, *a, **k)
        with mock.patch.object(W.os, "open", side_effect=f):
            e = self.rotate()
        self.assertEqual((e.cause, e.rc), ("DURABILITY_UNCERTAIN", 4))
        self.assertTrue(os.path.exists(self.secrets + ".prev"))


class LeftoverTest(Base):  # monitor M2, L2
    def test_a_leftover_temporary_refuses_before_anything(self):
        self.put(b"CLAUDE_CODE_OAUTH_TOKEN=leftover-copy\n", path=os.path.join(self.sandy, ".secrets.tmp-4242"))
        for mode in ("write", "rotate"):
            with self.subTest(mode=mode):
                p = self.run_vm(mode, TOKEN)
                self.assertEqual((p.returncode, p.stderr), (2, b"CAUSE=TEMP_LEFTOVER\n"))
                self.assertFalse(os.path.exists(self.secrets))

    def test_a_previous_file_refuses_rc2_before_a_temp_exists(self):
        self.put(W.KEY + b"=" + TOKEN + b"\n")
        self.put(b"OLD\n", path=self.secrets + ".prev")
        for mode in ("write", "rotate"):
            with self.subTest(mode=mode):
                p = self.run_vm(mode, TOKEN2)
                self.assertEqual((p.returncode, p.stderr), (2, b"CAUSE=PREVIOUS_EXISTS\n"))
                self.assertEqual(self.listing(), [".secrets", ".secrets.prev"])


class RotateTest(Base):
    def test_rotate_keeps_previous_then_finish_removes_it(self):
        self.run_vm("write", TOKEN)
        old = self.read()
        p = self.run_vm("rotate", TOKEN2)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.read(self.secrets + ".prev"), old)
        self.assertEqual(self.read(), W.KEY + b"=" + TOKEN2 + b"\n")
        self.assertEqual(self.run_vm("finish").returncode, 0)
        self.assertEqual(self.listing(), [".secrets"])

    def test_rotate_then_restore_brings_the_old_file_back(self):
        self.run_vm("write", TOKEN)
        old = self.read()
        self.run_vm("rotate", TOKEN2)
        self.assertEqual(self.run_vm("restore").returncode, 0)
        self.assertEqual(self.read(), old)
        self.assertEqual(self.listing(), [".secrets"])

    def test_rotating_to_the_value_sandy_reads_is_refused(self):
        # MC: sandy reads the LAST token line; equal to it is unchanged, equal only to an
        # earlier line is a real change.
        self.put(W.KEY + b"=" + TOKEN2 + b"\n" + W.KEY + b"=\"" + TOKEN + b"\"\n")
        p = self.run_vm("rotate", TOKEN)
        self.assertEqual((p.returncode, p.stderr), (2, b"CAUSE=VALUE_UNCHANGED\n"))
        self.assertEqual(self.listing(), [".secrets"])
        p = self.run_vm("rotate", TOKEN2)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_restore_without_previous_refuses(self):
        self.run_vm("write", TOKEN)
        p = self.run_vm("restore")
        self.assertEqual((p.returncode, p.stderr), (2, b"CAUSE=NO_PREVIOUS\n"))


class FinishRestoreFaultTest(Base):  # Opus W8 r2, 3 (X3, X4); monitor L3
    def setUp(self):
        super().setUp()
        self.run_vm("write", TOKEN)
        self.old = self.read()
        self.assertEqual(self.run_vm("rotate", TOKEN2).returncode, 0)

    def test_restore_fsyncs_the_directory_and_a_failure_is_rc4(self):  # X3
        with mock.patch.object(W, "_fsync_dir", side_effect=OSError("injected")) as f:
            with self.assertRaises(W.Refuse) as cm:
                W.restore(self.secrets)
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("DURABILITY_UNCERTAIN", 4))
        f.assert_called_once_with(self.sandy)
        self.assertEqual(self.read(), self.old)  # the rename took; durability is what is unknown

    def test_a_finish_whose_directory_fsync_fails_is_rc4(self):  # X4
        with mock.patch.object(W, "_fsync_dir", side_effect=OSError("injected")):
            with self.assertRaises(W.Refuse) as cm:
                W.finish(self.secrets)
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("FINISH_FAILED", 4))

    def test_a_finish_whose_unlink_fails_is_rc4_and_keeps_prev(self):  # X4
        with mock.patch.object(W.os, "unlink", side_effect=PermissionError("injected")):
            with self.assertRaises(W.Refuse) as cm:
                W.finish(self.secrets)
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("FINISH_FAILED", 4))
        self.assertTrue(os.path.exists(self.secrets + ".prev"))


class BootstrapTest(Base):
    def test_a_writer_changed_by_one_byte_gets_no_value(self):
        data = bytearray(self.writer.encode())
        data[-2] ^= 0x01
        p = self.run_vm("write", TOKEN, writer=bytes(data), want=hashlib.sha256(self.writer.encode()).hexdigest())
        self.assertEqual((p.returncode, p.stdout), (3, b""))  # the bootstrap's PIN, no READY
        self.assertFalse(os.path.exists(self.secrets))

    def test_mode_and_value_pairing_is_the_writers_own_too(self):
        for mode, value in (("bogus", None), ("finish", bytearray(TOKEN)), ("write", None), ("rotate", b"bytes")):
            with self.subTest(mode=mode):
                with mock.patch.object(W.os, "fork", side_effect=AssertionError("forked")):
                    r, w = os.pipe()
                    saved = os.dup(2)
                    os.dup2(w, 2)
                    os.close(w)
                    try:
                        rc = W.main(mode, value, "agent")
                    finally:
                        os.dup2(saved, 2)
                        os.close(saved)
                    err = os.read(r, 4096)
                    os.close(r)
                self.assertEqual(rc, 2)
                self.assertIn(err, (b"CAUSE=MODE\n", b"CAUSE=VALUE_FORM\n"))


if __name__ == "__main__":
    unittest.main()
