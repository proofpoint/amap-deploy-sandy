"""W8: S7's token writer, run as the VM would run it (`env -i /usr/bin/python3 -I -S -B
<bootstrap> <writer> <sha> <mode> <path>`; the bootstrap here is the TEST stand-in for
DS's), plus in-process fault injection. Synthetic values only.

The writer pins its target to <the account's home>/.sandy/.secrets from the account
database. The subprocess tests therefore run a scratch COPY of the writer in which that one
expression names a test home; every other byte is the shipped file (`writer_copy`)."""

import hashlib
import os
import resource
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

import a2fix  # noqa: F401  (puts install/ on sys.path)
import vm_token_writer as W

BOOT = os.path.join(a2fix.INSTALL, "tests", "standin_bootstrap.py")
WRITER = os.path.join(a2fix.INSTALL, "vm_token_writer.py")
TOKEN = b"sk-ant-oat01-SYNTHETIC-token-value-0001"
TOKEN2 = b"sk-ant-oat01-SYNTHETIC-token-value-0002"
PIN_EXPR = "(home if home is not None else pwd.getpwuid(uid).pw_dir)"


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def writer_copy(dest_dir, home):
    """The shipped writer with only its pinned-home expression replaced."""
    with open(WRITER, encoding="utf-8") as f:
        src = f.read()
    assert src.count(PIN_EXPR) == 1
    path = os.path.join(dest_dir, "vm_token_writer.py")
    with open(path, "w", encoding="utf-8") as f:
        f.write(src.replace(PIN_EXPR, "(home if home is not None else %r)" % home))
    return path


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = os.path.join(self.tmp.name, "home")
        self.sandy = os.path.join(self.home, ".sandy")
        os.makedirs(self.sandy)
        os.chmod(self.sandy, 0o700)
        self.secrets = os.path.join(self.sandy, ".secrets")
        tools = os.path.join(self.tmp.name, "tools")
        os.mkdir(tools)
        self.writer = writer_copy(tools, self.home)

    def run_vm(self, mode, value=None, extra=(), writer=None, want=None):
        w = writer or self.writer
        return subprocess.run(["/usr/bin/env", "-i", "/usr/bin/python3", "-I", "-S", "-B", BOOT, w,
                               want or sha(w), mode] + list(extra),
                              input=value if value is not None else b"", capture_output=True, timeout=60)

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
        """main() in this process against the test home, stdin from a pipe."""
        r, w = os.pipe()
        os.write(w, value)
        os.close(w)
        self.addCleanup(os.close, r)
        W.main(["w", mode], stdin_fd=r, home=self.home)
        return r


class WriteTest(Base):
    def test_fresh_file_one_line_0600(self):
        p = self.run_vm("write", TOKEN + b"\n")
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
        self.assertEqual(p.stdout + p.stderr, b"")
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
    def test_no_path_argument_is_accepted(self):
        ws = os.path.join(self.home, "dev", "agent-a", ".sandy")
        os.makedirs(ws)
        os.chmod(ws, 0o700)
        p = self.run_vm("write", TOKEN, extra=[os.path.join(ws, ".secrets")])
        self.assertEqual((p.returncode, p.stderr), (2, b"CAUSE=ARGS\n"))
        self.assertFalse(os.path.exists(os.path.join(ws, ".secrets")))
        self.assertFalse(os.path.exists(self.secrets))

    def test_a_symlinked_sandy_directory_is_refused(self):
        real = os.path.join(self.tmp.name, "elsewhere")
        os.rename(self.sandy, real)
        os.symlink(real, self.sandy)
        p = self.run_vm("write", TOKEN)
        self.assertEqual((p.returncode, p.stderr), (2, b"CAUSE=TARGET\n"))
        self.assertEqual(os.listdir(real), [])

    def test_the_shipped_pin_is_the_account_databases_home(self):
        import pwd
        self.assertEqual(W.pinned_path(os.getuid()), pwd.getpwuid(os.getuid()).pw_dir + "/.sandy/.secrets")


class RuleOneTest(Base):  # Opus 3
    def test_a_core_limit_failure_reads_nothing(self):
        with mock.patch.object(W.resource, "setrlimit", side_effect=OSError("no")):
            with self.assertRaises(W.Refuse) as cm:
                r = None
                rd, wr = os.pipe()
                os.write(wr, TOKEN)
                os.close(wr)
                self.addCleanup(os.close, rd)
                W.main(["w", "write"], stdin_fd=rd, home=self.home)
        self.assertEqual(cm.exception.cause, "CORE_LIMIT")
        self.assertEqual(os.read(rd, 100), TOKEN)  # stdin untouched
        self.assertFalse(os.path.exists(self.secrets))

    def test_core_zero_refuses_when_the_limit_does_not_hold(self):
        with self.assertRaises(W.Refuse):
            W.core_zero(setrlimit=lambda *a: None, getrlimit=lambda r: (1, 1))


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
        W.main(["w", "restore"], home=self.home)
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

    def test_any_unexpected_error_prints_one_cause_line(self):
        p = subprocess.run(["/usr/bin/env", "-i", "/usr/bin/python3", "-I", "-S", "-B", BOOT, self.writer,
                            sha(self.writer), "write"], stdin=subprocess.DEVNULL,
                           capture_output=True, timeout=60)
        self.assertEqual(p.stderr.count(b"CAUSE="), 1)
        self.assertNotIn(b"Traceback", p.stderr)


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


class CatchAllTest(unittest.TestCase):  # Opus W8 r2, 3 (X11)
    def test_an_unclassified_error_is_rc4_with_one_cause_line(self):
        written = []
        with mock.patch.object(W, "main", side_effect=RuntimeError("anything")), \
                mock.patch.object(W.os, "write", side_effect=lambda fd, b: written.append((fd, b)) or len(b)):
            rc = W.run(["w", "write"])
        self.assertEqual(rc, 4)  # unknown: S7 must not read it as "nothing changed"
        self.assertEqual(written, [(2, b"CAUSE=UNCLASSIFIED\n")])


class BootstrapTest(Base):
    def test_a_writer_changed_by_one_byte_gets_no_value(self):
        changed = os.path.join(self.tmp.name, "w.py")
        with open(self.writer, "rb") as f:
            data = bytearray(f.read())
        data[-2] ^= 0x01
        with open(changed, "wb") as f:
            f.write(data)
        r, w = os.pipe()
        os.write(w, TOKEN)
        os.close(w)
        p = subprocess.run(["/usr/bin/env", "-i", "/usr/bin/python3", "-I", "-S", "-B", BOOT, changed,
                            sha(self.writer), "write"], stdin=r, capture_output=True, timeout=60)
        unread = os.read(r, 100)
        os.close(r)
        self.assertEqual((p.returncode, p.stderr), (2, b"CAUSE=PIN\n"))
        self.assertEqual(unread, TOKEN)
        self.assertFalse(os.path.exists(self.secrets))

    def test_symlinked_writer_and_bad_sha_refused(self):
        link = os.path.join(self.tmp.name, "link.py")
        os.symlink(self.writer, link)
        self.assertEqual(self.run_vm("write", TOKEN, writer=link, want=sha(self.writer)).stderr, b"CAUSE=PIN\n")
        self.assertEqual(self.run_vm("write", TOKEN, want="z" * 64).stderr, b"CAUSE=PIN\n")
        self.assertFalse(os.path.exists(self.secrets))


if __name__ == "__main__":
    unittest.main()
