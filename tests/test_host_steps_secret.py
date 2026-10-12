"""host_steps' secret steps, run for real as a subprocess in a temporary tree.

Every value here is synthetic. The steps run as the test's own uid, which
stands in for the runtime's: the directory is made 0700 and owned by it.
Each case runs the program the way the runbook does (`python3 -I -S`), with a
real pipe on stdin, because a refusal ends in os._exit and the stdin checks
are about what kind of file descriptor 0 is.
"""

import fcntl
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest

import host_steps as st

HOST_STEPS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "host_steps.py")
VALUE = b"synthetic-not-a-secret-0123"


def run(*args, stdin=b"", pipe=True, timeout=30):
    """host_steps with `args`; stdin is a pipe carrying `stdin`, or, with
    pipe=False, the open file `stdin`."""
    cmd = [sys.executable, "-I", "-S", HOST_STEPS, *args]
    if pipe:
        return subprocess.run(cmd, input=stdin, capture_output=True, timeout=timeout)
    return subprocess.run(cmd, stdin=stdin, capture_output=True, timeout=timeout)


class Secret(unittest.TestCase):

    def setUp(self):
        self.t = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(self._cleanup)
        self.uid, self.gid = os.getuid(), os.getgid()
        self.d = os.path.join(self.t, "secrets")
        os.mkdir(self.d, 0o700)
        os.chmod(self.d, 0o700)
        self.path = os.path.join(self.d, "hub-password")
        self.tmp = os.path.join(self.d, ".hub-password.tmp")

    def _cleanup(self):
        for root, dirs, files in os.walk(self.t, topdown=False):
            for n in dirs + files:
                p = os.path.join(root, n)
                if not os.path.islink(p):
                    os.chmod(p, 0o700)
        subprocess.run(["rm", "-rf", self.t], check=False)

    def write(self, data=VALUE + b"\n", **kw):
        return run("secret", self.path, str(self.uid), str(self.gid), stdin=data, **kw)

    def assertRefused(self, done, rule):
        self.assertEqual(done.returncode, st.REFUSED, done)
        self.assertEqual(done.stdout, f"refused: {rule}\n".encode())
        self.assertEqual(done.stderr, b"")

    def assertNoValue(self, done, value=VALUE):
        self.assertNotIn(value, done.stdout + done.stderr)

    def content(self):
        with open(self.path, "rb") as f:
            return f.read()


class WriteTest(Secret):

    def test_the_value_is_written_0400_without_its_newline(self):
        done = self.write()
        self.assertEqual(done.returncode, 0, done)
        self.assertEqual(done.stdout, f"wrote {self.path} (0400 {self.uid}:{self.gid})\n".encode())
        self.assertNoValue(done)
        s = os.lstat(self.path)
        self.assertEqual(stat.S_IMODE(s.st_mode), 0o400)
        self.assertEqual((s.st_uid, s.st_gid, s.st_nlink), (self.uid, self.gid, 1))
        os.chmod(self.path, 0o600)
        self.assertEqual(self.content(), VALUE)
        self.assertEqual(os.listdir(self.d), ["hub-password"])

    def test_a_second_write_replaces_the_file_and_no_old_inode_remains(self):
        self.assertEqual(self.write().returncode, 0)
        old = os.lstat(self.path).st_ino
        self.assertEqual(self.write(b"synthetic-other-value\n").returncode, 0)
        inodes = {os.lstat(os.path.join(self.d, n)).st_ino for n in os.listdir(self.d)}
        self.assertNotIn(old, inodes)
        os.chmod(self.path, 0o600)
        self.assertEqual(self.content(), b"synthetic-other-value")

    def test_the_length_bound_is_on_the_value_after_its_newline(self):
        for n, ok in ((4095, True), (4096, True), (4097, False)):
            with self.subTest(n=n):
                done = self.write(b"a" * n + b"\n")
                if ok:
                    self.assertEqual(done.returncode, 0, done)
                else:
                    self.assertRefused(done, "too long")

    def test_a_value_far_past_the_bound_is_refused_without_reading_it_all(self):
        self.assertRefused(self.write(b"a" * 100000 + b"\n"), "too long")

    def test_a_line_past_the_bound_is_refused_as_it_arrives_newline_or_not(self):
        self.assertRefused(self.write(b"a" * (st.MAX_LINE + 1)), "too long")

    def test_a_missing_newline_is_an_incomplete_line(self):
        self.assertRefused(self.write(b"a" * 4096), "incomplete line")
        self.assertRefused(self.write(VALUE), "incomplete line")
        self.assertFalse(os.path.exists(self.path))

    def test_an_empty_value_is_refused(self):
        self.assertRefused(self.write(b"\n"), "empty")
        self.assertRefused(self.write(b""), "incomplete line")

    def test_a_byte_outside_the_alphabet_is_refused_and_not_echoed(self):
        for bad in (b"synthetic value", b"synthetic\x7f", b"synthetic\xc3\xa9", b"two\nlines",
                    b"tab\there", b"cr\r"):
            with self.subTest(bad=bad):
                done = self.write(bad + b"\n")
                self.assertRefused(done, "alphabet")
                self.assertNoValue(done, bad)
        self.assertFalse(os.path.exists(self.path))

    def test_a_terminal_or_a_regular_file_on_stdin_is_refused(self):
        src = os.path.join(self.t, "value")
        with open(src, "wb") as f:
            f.write(VALUE + b"\n")
        with open(src, "rb") as f:
            self.assertRefused(self.write(f, pipe=False), "stdin")
        with open("/dev/null", "rb") as f:
            self.assertRefused(self.write(f, pipe=False), "stdin")
        self.assertFalse(os.path.exists(self.path))

    def test_a_socket_on_stdin_is_accepted(self):
        import socket
        a, b = socket.socketpair()
        b.sendall(VALUE + b"\n")
        b.close()
        try:
            done = self.write(a, pipe=False)
        finally:
            a.close()
        self.assertEqual(done.returncode, 0, done)


class WrittenFileTest(Secret):

    def test_a_file_whose_mode_did_not_take_is_refused_and_not_renamed_into_place(self):
        """The fstat of the written temp is the last guard before the rename;
        here fchmod is made to leave group bits, which nothing else catches."""
        repo = os.path.dirname(HOST_STEPS)
        prog = ("import os,sys;sys.path.insert(0,%r);import host_steps as st;"
                "real=os.fchmod;os.fchmod=lambda fd,m:real(fd,0o440);"
                "sys.exit(st.main(['secret',%r,%r,%r]))"
                % (repo, self.path, str(self.uid), str(self.gid)))
        done = subprocess.run([sys.executable, "-I", "-S", "-c", prog], input=VALUE + b"\n",
                              capture_output=True, timeout=30)
        self.assertRefused(done, "written file")
        self.assertEqual(os.listdir(self.d), [])


class DirectoryTest(Secret):

    def test_a_directory_with_group_or_world_bits_is_refused(self):
        os.chmod(self.d, 0o750)
        self.assertRefused(self.write(), "directory")
        self.assertEqual(os.listdir(self.d), [])

    def test_a_directory_owned_by_another_uid_is_refused(self):
        done = run("secret", self.path, str(self.uid + 1), str(self.gid), stdin=VALUE + b"\n")
        self.assertRefused(done, "directory")

    def test_a_symlinked_directory_is_refused_and_its_target_untouched(self):
        real = os.path.join(self.t, "real")
        os.mkdir(real, 0o700)
        os.chmod(real, 0o700)
        link = os.path.join(self.t, "link")
        os.symlink(real, link)
        done = run("secret", os.path.join(link, "hub-password"), str(self.uid), str(self.gid),
                   stdin=VALUE + b"\n")
        self.assertRefused(done, "directory")
        self.assertEqual(os.listdir(real), [])


class EntryTest(Secret):

    def test_an_unexpected_entry_is_refused_and_nothing_written(self):
        open(os.path.join(self.d, "other"), "w").close()
        self.assertRefused(self.write(), "unexpected entry")
        self.assertEqual(sorted(os.listdir(self.d)), ["other"])

    def test_a_directory_or_a_symlink_at_the_target_is_refused(self):
        os.mkdir(self.path)
        self.assertRefused(self.write(), "entry type")
        os.rmdir(self.path)
        victim = os.path.join(self.t, "victim")
        open(victim, "w").close()
        os.symlink(victim, self.path)
        self.assertRefused(self.write(), "entry type")
        self.assertEqual(os.path.getsize(victim), 0)

    def test_a_hard_linked_target_is_refused(self):
        self.assertEqual(self.write().returncode, 0)
        os.link(self.path, os.path.join(self.t, "second-name"))
        self.assertRefused(self.write(), "entry type")

    def test_a_target_with_the_wrong_mode_is_refused(self):
        with open(self.path, "wb") as f:
            f.write(VALUE)
        os.chmod(self.path, 0o644)
        self.assertRefused(self.write(), "entry owner or mode")

    def test_a_valid_crash_temp_is_removed_and_the_write_goes_on(self):
        with open(self.tmp, "wb") as f:
            f.write(b"synthetic-left")
        os.chmod(self.tmp, 0o400)
        done = self.write()
        self.assertEqual(done.returncode, 0, done)
        self.assertEqual(os.listdir(self.d), ["hub-password"])

    def test_a_crash_temp_with_group_bits_is_refused(self):
        with open(self.tmp, "wb") as f:
            f.write(b"synthetic-left")
        os.chmod(self.tmp, 0o440)
        self.assertRefused(self.write(), "entry owner or mode")
        self.assertTrue(os.path.exists(self.tmp))


class WriterLockTest(Secret):

    def hold(self):
        fd = os.open(self.d, os.O_RDONLY | os.O_DIRECTORY)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.addCleanup(os.close, fd)
        return fd

    def test_a_second_writer_refuses_before_touching_anything(self):
        with open(self.tmp, "wb") as f:
            f.write(b"synthetic-left")
        os.chmod(self.tmp, 0o400)
        self.hold()
        self.assertRefused(self.write(), "concurrent writer")
        self.assertEqual(os.listdir(self.d), [".hub-password.tmp"])

    def test_two_concurrent_writers_exactly_one_succeeds(self):
        slow = (f"import os,sys,time;sys.stdout.buffer.write(b'{VALUE.decode()}');"
                f"sys.stdout.flush();time.sleep(2);sys.stdout.buffer.write(b'\\n')")
        feeder = subprocess.Popen([sys.executable, "-c", slow], stdout=subprocess.PIPE)
        first = subprocess.Popen([sys.executable, "-I", "-S", HOST_STEPS, "secret", self.path,
                                  str(self.uid), str(self.gid)], stdin=feeder.stdout,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        feeder.stdout.close()
        time.sleep(0.5)
        second = self.write(b"synthetic-second\n")
        out, err = first.communicate(timeout=30)
        feeder.wait(timeout=30)
        self.assertEqual(first.returncode, 0, (out, err))
        self.assertRefused(second, "concurrent writer")
        os.chmod(self.path, 0o600)
        self.assertEqual(self.content(), VALUE)

    def test_remove_takes_the_same_lock(self):
        self.assertEqual(self.write().returncode, 0)
        self.hold()
        self.assertRefused(run("secret-remove", self.path), "concurrent writer")
        self.assertTrue(os.path.exists(self.path))


class CheckTest(Secret):

    def check(self, **kw):
        return run("secret", "--check", self.path, str(self.uid), str(self.gid), **kw)

    def test_check_reports_absent_then_present_and_writes_nothing(self):
        done = self.check(stdin=VALUE + b"\n")
        self.assertEqual(done.returncode, 0, done)
        self.assertEqual(done.stdout, f"ok: {self.path} absent\n".encode())
        self.assertEqual(os.listdir(self.d), [])
        self.assertEqual(self.write().returncode, 0)
        self.assertEqual(self.check().stdout, f"ok: {self.path} present\n".encode())

    def test_check_fails_on_the_wrong_stdin_kind(self):
        with open("/dev/null", "rb") as f:
            self.assertRefused(self.check(stdin=f, pipe=False), "stdin")

    def test_check_fails_on_an_entry_the_writer_would_refuse(self):
        os.mkdir(self.path)
        self.assertRefused(self.check(), "entry type")
        os.rmdir(self.path)
        with open(self.tmp, "wb") as f:
            f.write(b"x")
        os.chmod(self.tmp, 0o644)
        self.assertRefused(self.check(), "entry owner or mode")

    def test_check_takes_no_writer_lock(self):
        fd = os.open(self.d, os.O_RDONLY | os.O_DIRECTORY)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.addCleanup(os.close, fd)
        self.assertEqual(self.check().returncode, 0)


class RemoveAndStatTest(Secret):

    def test_remove_takes_the_file_and_the_crash_temp(self):
        self.assertEqual(self.write().returncode, 0)
        with open(self.tmp, "wb") as f:
            f.write(b"synthetic-left")
        os.chmod(self.tmp, 0o400)
        done = run("secret-remove", self.path)
        self.assertEqual(done.returncode, 0, done)
        self.assertEqual(os.listdir(self.d), [])

    def test_remove_refuses_an_unexpected_entry_and_removes_nothing(self):
        self.assertEqual(self.write().returncode, 0)
        open(os.path.join(self.d, "other"), "w").close()
        self.assertRefused(run("secret-remove", self.path), "unexpected entry")
        self.assertEqual(sorted(os.listdir(self.d)), ["hub-password", "other"])

    def test_stat_reports_metadata_without_opening_any_file(self):
        self.assertEqual(self.write().returncode, 0)
        os.chmod(self.path, 0o000)
        done = run("stat-secret", self.d)
        self.assertEqual(done.returncode, 0, done)
        doc = json.loads(done.stdout)
        self.assertEqual((doc["uid"], doc["mode"]), (self.uid, "0700"))
        self.assertEqual(doc["entries"], [{
            "name": "hub-password", "regular": True, "uid": self.uid, "gid": self.gid,
            "mode": "0000", "nlink": 1, "nonempty": True}])
        self.assertNoValue(done)


class LockTest(Secret):

    def setUp(self):
        super().setUp()
        self.run_dir = os.path.join(self.t, "run")
        os.mkdir(self.run_dir, 0o700)
        self.lockfile = os.path.join(self.run_dir, st.LOCK_FILE)
        open(self.lockfile, "w").close()
        os.chmod(self.lockfile, 0o600)

    def wrap(self, *argv, **kw):
        return run("lock", self.run_dir, "--", *argv, **kw)

    def free(self):
        fd = os.open(self.lockfile, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            return False
        finally:
            os.close(fd)

    def test_the_child_gets_the_bytes_intact_and_the_wrapper_prints_nothing(self):
        out = os.path.join(self.t, "copied")
        copy = f"import sys;open({out!r},'wb').write(sys.stdin.buffer.read())"
        done = self.wrap(sys.executable, "-c", copy, stdin=VALUE + b"\n")
        self.assertEqual(done.returncode, 0, done)
        self.assertEqual((done.stdout, done.stderr), (b"", b""))
        with open(out, "rb") as f:
            self.assertEqual(f.read(), VALUE + b"\n")

    def test_the_childs_status_passes_through_and_a_signal_death_is_128_plus_n(self):
        self.assertEqual(self.wrap(sys.executable, "-c", "raise SystemExit(7)").returncode, 7)
        kill = "import os,signal;os.kill(os.getpid(),signal.SIGTERM)"
        self.assertEqual(self.wrap(sys.executable, "-c", kill).returncode, 128 + signal.SIGTERM)

    def test_a_relative_command_or_a_missing_or_symlinked_lock_file_is_refused(self):
        self.assertRefused(self.wrap("python3", "-c", "pass"), "lock")
        os.unlink(self.lockfile)
        self.assertRefused(self.wrap(sys.executable, "-c", "pass"), "lock")
        os.symlink(os.path.join(self.t, "elsewhere"), self.lockfile)
        open(os.path.join(self.t, "elsewhere"), "w").close()
        self.assertRefused(self.wrap(sys.executable, "-c", "pass"), "lock")

    def test_a_lock_path_that_is_not_a_regular_file_is_refused(self):
        os.unlink(self.lockfile)
        os.mkdir(self.lockfile)
        self.assertRefused(self.wrap(sys.executable, "-c", "pass"), "lock")
        os.rmdir(self.lockfile)
        os.mkfifo(self.lockfile)
        self.assertRefused(self.wrap(sys.executable, "-c", "pass"), "lock")

    def test_a_held_lock_is_waited_for_then_refused(self):
        orig = st.LOCK_WAIT_S
        fd = os.open(self.lockfile, os.O_RDONLY)
        fcntl.flock(fd, fcntl.LOCK_EX)
        self.addCleanup(os.close, fd)
        try:
            st.LOCK_WAIT_S = 0.5
            with self.assertRaises(st.Refused):
                st._take(os.open(self.lockfile, os.O_RDONLY), st.LOCK_WAIT_S)
        finally:
            st.LOCK_WAIT_S = orig

    def _sleeper(self, wrapper_argv):
        """A wrapped child that records its pid and sleeps; returns the
        wrapper process and the child's pid."""
        pidfile = os.path.join(self.t, "child.pid")
        sleep = f"import os,time;open({pidfile!r},'w').write(str(os.getpid()));time.sleep(60)"
        wrapper = subprocess.Popen([sys.executable, "-I", "-S", HOST_STEPS, "lock", self.run_dir,
                                    "--", *wrapper_argv, sys.executable, "-c", sleep])
        for _ in range(200):
            if os.path.exists(pidfile) and os.path.getsize(pidfile):
                break
            time.sleep(0.05)
        with open(pidfile) as f:
            return wrapper, int(f.read())

    def test_the_lock_outlives_a_killed_wrapper_until_the_child_exits(self):
        wrapper, child = self._sleeper([])
        os.kill(wrapper.pid, signal.SIGKILL)
        wrapper.wait(timeout=10)
        self.assertFalse(self.free())
        os.kill(child, signal.SIGKILL)
        for _ in range(200):
            if self.free():
                break
            time.sleep(0.05)
        self.assertTrue(self.free())

    def test_via_a_sudo_that_closes_fds_only_the_wrapper_holds_it(self):
        stub = os.path.join(self.t, "stub-sudo")
        with open(stub, "w") as f:
            f.write(f"#!{sys.executable}\nimport os,sys\nos.closerange(3, 65536)\n"
                    f"os.execv(sys.argv[1], sys.argv[1:])\n")
        os.chmod(stub, 0o700)
        wrapper, child = self._sleeper([stub])
        self.addCleanup(lambda: os.kill(child, signal.SIGKILL))
        self.assertFalse(self.free())
        os.kill(wrapper.pid, signal.SIGKILL)
        wrapper.wait(timeout=10)
        self.assertTrue(self.free())


class ProbeWeeklyTest(Secret):

    def setUp(self):
        super().setUp()
        self.status = os.path.join(self.t, "hub-probe.json")

    def probe(self, line, rc=0, now=1000):
        prog = f"import sys;sys.stdout.write({line!r});raise SystemExit({rc})"
        return st.probe_weekly(self.status, [sys.executable, "-c", prog], now=now)

    def doc(self):
        with open(self.status) as f:
            return json.load(f)

    def test_the_class_and_code_are_kept_with_when_it_last_passed(self):
        self.assertEqual(self.probe("ok 235\n", now=1000), 0)
        self.assertEqual(self.doc(), {"class": "ok", "smtp_code": "235", "at": 1000,
                                      "previous_class": None, "last_ok_at": 1000})
        self.assertEqual(self.probe("tls_failed -\n", rc=8, now=2000), 8)
        self.assertEqual(self.doc(), {"class": "tls_failed", "smtp_code": "-", "at": 2000,
                                      "previous_class": "ok", "last_ok_at": 1000})

    def test_anything_else_on_stdout_is_a_protocol_error(self):
        self.probe("garbage line with words\n", rc=0)
        self.assertEqual(self.doc()["class"], "protocol_error")

    def test_a_command_that_cannot_start_is_engine_unavailable(self):
        rc = st.probe_weekly(self.status, [os.path.join(self.t, "absent")], now=5)
        self.assertEqual(rc, st.REFUSED)
        self.assertEqual(self.doc()["class"], "engine_unavailable")


class PlaceShaTest(Secret):

    def test_a_mismatched_sha_places_nothing(self):
        src = os.path.join(self.t, "w.py")
        with open(src, "w") as f:
            f.write("x = 1\n")
        dest_dir = os.path.join(self.t, "libexec")
        os.mkdir(dest_dir)
        orig = (st.OWNER_UID, st.OWNER_GID)
        st.OWNER_UID, st.OWNER_GID = self.uid, self.gid
        self.addCleanup(lambda: (setattr(st, "OWNER_UID", orig[0]),
                                 setattr(st, "OWNER_GID", orig[1])))
        with self.assertRaises(st.StepError):
            st.place(src, os.path.join(dest_dir, "w.py"), sha256="0" * 64)
        self.assertEqual(os.listdir(dest_dir), [])
        import hashlib
        st.place(src, os.path.join(dest_dir, "w.py"),
                 sha256=hashlib.sha256(b"x = 1\n").hexdigest())
        self.assertEqual(os.listdir(dest_dir), ["w.py"])


if __name__ == "__main__":
    unittest.main()
