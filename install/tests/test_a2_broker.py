"""The budget broker (a2_broker) on a staged lock root.

The broker runs here as the test uid, which stands for root (`root_uid`), and the test uid is also the caller: the
config maps it to one runner account. Records are read back with a2_budget's own strict read, so the broker and
every reader agree on what was written.
"""

import json
import os
import shutil
import socket
import threading
import time
import unittest

import a2fix
import a2_args
import a2_broker
import a2_budget
from a2_causes import Refusal

ME = os.getuid()
SHA = "a" * 64
NOW = 1795132800          # 2026-11-20T00:00:00Z


def req(command="install", loop="L2", **over):
    d = {"command": command, "loop": loop, "lock_sha256": SHA, "hosts_sha256": SHA, "installer_sha256": SHA}
    d.update(over)
    return json.dumps(d).encode() + b"\n"


def utc(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def fail_dir_fsync(test):
    """The directory's fsync, which follows the rename, fails: the record is under its final name."""
    import stat as st
    real = a2_broker.os.fsync

    def fsync(fd):
        if st.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("injected")
        return real(fd)
    a2_broker.os.fsync = fsync
    test.addCleanup(setattr, a2_broker.os, "fsync", real)


class Base(unittest.TestCase):
    def setUp(self):
        self.base = a2fix.make_base()
        self.addCleanup(shutil.rmtree, self.base, True)
        self.w = a2fix.World(self.base)
        self.root = self.w.root
        self.now = NOW + 3600
        self.tokens = iter("%08x" % i for i in range(1, 10000))

    def cfg(self, account="loop", usage="a", **kw):
        c = a2_broker.Config(self.root, {ME: account}, usage, root_uid=ME, now=lambda: self.now,
                             token=lambda n: next(self.tokens))
        for k, v in kw.items():
            setattr(c, k, v)
        return c

    def admit(self, raw=None, account="loop", usage="a", uid=ME):
        return a2_broker.admit(raw if raw is not None else req(), uid, self.cfg(account, usage))

    def refused(self, *a, **kw):
        with self.assertRaises(a2_broker.Refused):
            self.admit(*a, **kw)

    def records(self):
        return a2_budget.read_budget(os.path.join(self.root, "budget.d"), ME)

    def names(self, sub="loop"):
        return sorted(os.listdir(os.path.join(self.root, "budget.d", sub)))

    def write_permit(self, permit_id="b" * 32, pct=10, observed=None, expires=None, name="permit.json", **over):
        observed = self.now - 60 if observed is None else observed
        expires = observed + 1800 if expires is None else expires
        p = {"kind": "permit", "permit_id": permit_id, "observed_percent": pct,
             "observed_at": utc(observed), "expires_at": utc(expires)}
        p.update(over)
        path = os.path.join(self.root, "stop.d", "monitor", name)
        with open(path, "w") as f:
            json.dump(p, f)
        return path

    def set_aside(self, at, files):
        """A budget.d.<utc> with {(sub, name): bytes}."""
        top = os.path.join(self.root, "budget.d." + utc(at))
        for sub in ("loop", "l3"):
            os.makedirs(os.path.join(top, sub), exist_ok=True)
        for (sub, name), raw in files.items():
            p = os.path.join(top, sub, name)
            with open(p, "wb") as f:
                f.write(raw)
            os.chmod(p, 0o644)
        return top


def record(rid, loop="L2", started=None, permit="-", command="install"):
    started = started or "%s-%s-%sT%s:%s:%sZ" % (rid[0:4], rid[4:6], rid[6:8], rid[9:11], rid[11:13], rid[13:15])
    return json.dumps({"kind": "start", "run_id": rid, "command": command, "loop": loop, "started_at": started,
                       "lock_sha256": SHA, "hosts_sha256": SHA, "installer_sha256": SHA,
                       "permit_id": permit}).encode()


class RequestTest(Base):
    def test_the_request_is_closed_and_matched_in_full(self):
        bad = [b"", b"[]", b"{}", req(extra="x"), req()[:-3], req(lock_sha256="A" * 64),
               req(command="build"), req(loop="L4"), req(hosts_sha256=1),
               b'{"command":"install","command":"install"}', req(lock_sha256=SHA[:-1])]
        for raw in bad:
            with self.subTest(raw=raw[:40]):
                self.refused(raw)
        self.assertEqual(self.names(), [])

    def test_only_commands_that_write_a_target_and_are_enabled(self):
        for command in a2_args.NON_WRITING + a2_broker.DISABLED:
            with self.subTest(command=command):
                self.refused(req(command=command, loop="-"))

    def test_a_loop_only_on_install(self):
        self.refused(req(command="canary", loop="L2"))
        self.assertEqual(self.admit(req(command="canary", loop="-"))[0][:8], time.strftime("%Y%m%d", time.gmtime(self.now)))

    def test_the_callers_account_must_be_the_one_the_command_needs(self):
        for account, raw in (("loop", req(loop="L3")), ("loop", req(loop="-")), ("loop", req(command="destroy", loop="-")),
                             ("l3", req(loop="L2")), ("l3", req(loop="L2-leak")), ("l3", req(loop="L1"))):
            with self.subTest(account=account, raw=raw[:48]):
                self.refused(raw, account=account)
        self.admit(req(loop="L3"), account="l3")
        self.assertEqual(len(self.names("l3")), 1)

    def test_an_unknown_caller_is_refused(self):
        self.refused(uid=ME + 1)
        self.refused(req(command="canary", loop="-"), uid=ME + 1)
        self.assertEqual(self.names("loop") + self.names("l3"), [])


class AdmitTest(Base):
    def test_the_record_is_published_and_reads_back(self):
        rid, sha = self.admit()
        self.assertEqual(rid, time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(self.now)) + "-00000001")
        self.assertEqual(self.names(), ["start-%s.json" % rid])
        sub, rec, got_sha = self.records()[rid]
        self.assertEqual((sub, got_sha), ("loop", sha))
        self.assertEqual(rec["started_at"], utc(self.now))
        self.assertEqual((rec["kind"], rec["command"], rec["loop"], rec["permit_id"]), ("start", "install", "L2", "-"))
        st = os.stat(os.path.join(self.root, "budget.d", "loop", "start-%s.json" % rid))
        self.assertEqual((st.st_mode & 0o7777, st.st_nlink), (0o644, 1))

    def test_twelve_l2_starts_a_day_then_refused_but_other_runs_go_on(self):
        for i in range(12):
            self.admit(req(loop="L2" if i % 2 else "L2-leak"))
        self.refused(req(loop="L2"))
        self.refused(req(loop="L2-leak"))
        self.admit(req(loop="L1"))
        self.now += 86400
        self.admit(req(loop="L2"))

    def test_set_aside_records_count_and_a_bad_entry_counts_as_one_l2(self):
        """Nine good L2 records, one bad record under a good name (counted on its run_id's day) and one name that
        does not parse (counted on the set-aside's day): eleven, so one more L2 starts and the next refuses."""
        day = time.strftime("%Y%m%d", time.gmtime(self.now))
        files = {("loop", "start-%sT000100Z-%08x.json" % (day, i)): record("%sT000100Z-%08x" % (day, i))
                 for i in range(9)}
        files[("loop", "start-%sT000200Z-0000ffff.json" % day)] = b"not json"
        files[("l3", "junk-name")] = b"x"
        self.set_aside(self.now - 600, files)
        self.admit(req(loop="L2"))
        self.refused(req(loop="L2"))

    def test_a_set_aside_name_that_is_not_utc_refuses(self):
        os.makedirs(os.path.join(self.root, "budget.d.yesterday", "loop"))
        self.refused()

    def test_an_unobserved_budget_d_refuses(self):
        open(os.path.join(self.root, "budget.d", "stray"), "w").close()
        self.refused()

    def test_the_account_ceiling(self):
        old = a2_broker.ACCOUNT_CEILING
        a2_broker.ACCOUNT_CEILING = 2
        self.addCleanup(setattr, a2_broker, "ACCOUNT_CEILING", old)
        self.admit(req(loop="L1"))
        self.admit(req(loop="L1"))
        self.refused(req(loop="L1"))
        self.admit(req(loop="L3"), account="l3")

    def test_a_minted_run_id_already_named_refuses(self):
        rid = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(self.now)) + "-00000001"
        self.set_aside(self.now - 600, {("l3", "start-%s.json" % rid): record(rid, loop="L3")})
        self.refused()
        self.assertEqual(self.names(), [])

    def test_the_final_name_is_never_replaced(self):
        rid = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(self.now)) + "-00000001"
        d = os.path.join(self.root, "budget.d", "loop")
        # An existing name that a2_budget's read does not see (the broker's link alone must refuse it).
        os.symlink("elsewhere", os.path.join(d, "start-%s.json" % rid))
        orig = a2_budget.read_budget
        a2_budget.read_budget = lambda *a, **k: {}
        self.addCleanup(setattr, a2_budget, "read_budget", orig)
        self.refused()
        self.assertEqual(sorted(os.listdir(d)), ["start-%s.json" % rid])
        self.assertTrue(os.path.islink(os.path.join(d, "start-%s.json" % rid)))

    def test_admission_holds_an_exclusive_lock_on_budget_d(self):
        import fcntl
        seen = []
        real = a2_broker._admit_locked

        def probe(*a):
            fd = os.open(os.path.join(self.root, "budget.d"), os.O_RDONLY | os.O_DIRECTORY)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                seen.append("free")
            except BlockingIOError:
                seen.append("held")
            finally:
                os.close(fd)
            return real(*a)
        a2_broker._admit_locked = probe
        self.addCleanup(setattr, a2_broker, "_admit_locked", real)
        self.admit()
        self.assertEqual(seen, ["held"])

    def test_a_failed_close_after_publication_is_unknown(self):
        """Either close that follows the rename (the subdirectory's, then budget.d's) failing is Unknown, never a
        refusal: the record is published."""
        for which in (1, 2):
            with self.subTest(close=which):
                real = a2_broker._close
                calls = []

                def close(fd, n=which):
                    calls.append(fd)
                    real(fd)
                    if len(calls) == n:
                        raise OSError("injected")
                a2_broker._close = close
                try:
                    with self.assertRaises(a2_broker.Unknown):
                        self.admit(req(loop="L1"))
                finally:
                    a2_broker._close = real
        self.assertEqual(len([n for n in self.names() if n.startswith("start-")]), 2)

    def test_the_fsyncs_come_in_order(self):
        """fsync of the record before the rename, fsync of the directory after it."""
        import stat as st
        seen = []
        real_fsync, real_rename = a2_broker.os.fsync, a2_broker._renameat2_noreplace

        def fsync(fd):
            seen.append("dir" if st.S_ISDIR(os.fstat(fd).st_mode) else "file")
            return real_fsync(fd)

        def rename(*a):
            seen.append("rename")
            return real_rename(*a)
        a2_broker.os.fsync, a2_broker._renameat2_noreplace = fsync, rename
        self.addCleanup(setattr, a2_broker.os, "fsync", real_fsync)
        self.addCleanup(setattr, a2_broker, "_renameat2_noreplace", real_rename)
        self.admit()
        self.assertEqual(seen, ["file", "rename", "dir"])

    def test_a_caller_that_hung_up_gets_no_record(self):
        with self.assertRaises(a2_broker.Refused):
            a2_broker.admit(req(), ME, self.cfg(), alive=lambda: False)
        self.assertEqual(self.names(), [])

    def test_a_set_aside_with_an_impossible_date_or_odd_shape_refuses_or_counts(self):
        os.makedirs(os.path.join(self.root, "budget.d.2026-02-30T00:00:00Z", "loop"))
        self.refused()
        shutil.rmtree(os.path.join(self.root, "budget.d.2026-02-30T00:00:00Z"))
        top = self.set_aside(self.now - 600, {})
        shutil.rmtree(os.path.join(top, "l3"))
        os.symlink(os.path.join(top, "loop"), os.path.join(top, "l3"))
        self.refused()
        os.unlink(os.path.join(top, "l3"))
        # Twelve stray names at the top of the set-aside: twelve L2 starts on its day.
        for i in range(12):
            open(os.path.join(top, "stray%d" % i), "w").close()
        self.refused(req(loop="L2"))
        self.admit(req(loop="L1"))

    def test_a_failure_after_the_link_is_unknown_and_the_record_stays(self):
        fail_dir_fsync(self)
        with self.assertRaises(a2_broker.Unknown):
            self.admit()
        self.assertEqual(len([n for n in self.names() if n.startswith("start-")]), 1)


class PermitTest(Base):
    def test_path_b_needs_a_current_permit_and_records_it(self):
        self.refused(usage="b")
        self.write_permit()
        rid, _ = self.admit(usage="b")
        self.assertEqual(self.records()[rid][1]["permit_id"], "b" * 32)

    def test_a_permit_grants_one_launch(self):
        self.write_permit()
        self.admit(usage="b")
        self.refused(usage="b")

    def test_a_permit_spent_in_a_set_aside_grants_nothing(self):
        self.write_permit()
        rid = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(self.now - 30)) + "-0000aaaa"
        # Set aside before the permit was observed, so the "current at <utc>" rule cannot be what refuses.
        self.set_aside(self.now - 3000, {("loop", "start-%s.json" % rid): record(rid, loop="L1", permit="b" * 32)})
        self.refused(usage="b")

    def test_a_permit_observed_in_the_set_asides_own_second_grants_nothing(self):
        self.write_permit(observed=self.now - 600, expires=self.now + 600)
        self.set_aside(self.now - 600, {})
        self.refused(usage="b")

    def test_a_permit_current_when_budget_d_was_set_aside_grants_nothing(self):
        self.write_permit(observed=self.now - 600, expires=self.now + 600)
        self.set_aside(self.now - 300, {})
        self.refused(usage="b")

    def test_permits_that_are_not_current_or_not_well_formed(self):
        cases = (dict(observed=NOW + 3700), dict(observed=NOW, expires=NOW + 1800),
                 dict(pct=80), dict(pct=-1), dict(pct=True), dict(pct=10.0),
                 dict(observed=NOW + 3000, expires=NOW + 3000 + 3601), dict(kind="stop"),
                 dict(permit_id="B" * 32), dict(extra=1), dict(expires_at="soon"))
        for over in cases:
            with self.subTest(over=sorted(over)):
                self.write_permit(**over)
                self.refused(usage="b")

    def test_a_permit_that_is_not_a_regular_file(self):
        target = self.write_permit(name="real.json")
        p = os.path.join(self.root, "stop.d", "monitor", "permit.json")
        os.symlink(target, p)
        self.refused(usage="b")
        os.unlink(p)
        os.mkfifo(p)
        self.refused(usage="b")
        os.unlink(p)
        # A valid permit padded to exactly one byte past the bound: only the bound refuses it.
        os.unlink(target)
        self.write_permit(name="real.json")
        with open(target) as f:
            body = f.read()
        with open(p, "w") as f:
            f.write(" " * (a2_broker.PERMIT_MAX + 1 - len(body)) + body)
        self.refused(usage="b")

    def test_path_a_reads_no_permit(self):
        rid, _ = self.admit(usage="a")
        self.assertEqual(self.records()[rid][1]["permit_id"], "-")


class SocketTest(Base):
    def serve(self, cfg):
        sock = a2_broker.bind_socket(self.root, ME)
        t = threading.Thread(target=a2_broker.serve, args=(sock, cfg), daemon=True)
        t.start()

        def stop():
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            t.join(timeout=10)
            sock.close()
        self.addCleanup(stop)

    def ask(self, argv=("--loop", "L2")):
        return a2_budget.ask_broker(self.root, a2_args.parse(list(argv)), SHA, SHA, SHA, root_uid=ME)

    def test_end_to_end_the_launcher_gets_a_record_s0_accepts(self):
        self.now = time.time()
        self.serve(self.cfg())
        rid, sha = self.ask()
        got = a2_budget.check_start_record(os.path.join(self.root, "budget.d"), "loop", rid,
                                           a2_args.parse(["--loop", "L2"]), SHA, SHA, SHA, root_uid=ME)
        self.assertEqual(got, sha)
        st = os.lstat(os.path.join(self.root, a2_budget.SOCKET_NAME))
        self.assertEqual(st.st_mode & 0o777, 0o666)

    def test_a_refusal_is_preflight_budget_and_an_unknown_is_not_started(self):
        self.serve(self.cfg(account="l3"))
        with self.assertRaises(Refusal) as cm:
            self.ask()
        self.assertEqual(cm.exception.cause, "PREFLIGHT.BUDGET")
        fail_dir_fsync(self)
        with self.assertRaises(Refusal) as cm:
            self.ask(("--loop", "L3"))
        self.assertEqual(cm.exception.cause, "RUNNER.NOT_STARTED")

    def test_an_oversized_or_slow_request_is_refused(self):
        self.serve(self.cfg())
        path = os.path.join(self.root, a2_budget.SOCKET_NAME)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(path)
            # A valid request padded past the bound: only the bound refuses it.
            s.sendall(req() + b" " * a2_broker.REQUEST_MAX)
            s.shutdown(socket.SHUT_WR)
            self.assertEqual(s.recv(100), a2_broker.REFUSAL)
        old = a2_broker.REQUEST_BOUND_S
        a2_broker.REQUEST_BOUND_S = 0.3
        self.addCleanup(setattr, a2_broker, "REQUEST_BOUND_S", old)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(path)
            s.sendall(req()[:10])
            self.assertEqual(s.recv(100), a2_broker.REFUSAL)
        self.assertEqual(self.names(), [])

    def serve_with_peers(self, cfg, uids):
        """A Server whose callers present the given uids, in connection order."""
        sock = a2_broker.bind_socket(self.root, ME)
        order = list(uids)
        server = a2_broker.Server(sock, cfg, peer=lambda conn: order.pop(0))
        t = threading.Thread(target=server.serve, daemon=True)
        t.start()

        def stop():
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            t.join(timeout=10)
            sock.close()
        self.addCleanup(stop)
        return server

    def silent(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(os.path.join(self.root, a2_budget.SOCKET_NAME))
        self.addCleanup(s.close)
        return s

    def test_a_caller_of_neither_account_is_closed_unread_and_delays_no_one(self):
        self.now = time.time()
        cfg = a2_broker.Config(self.root, {ME: "loop", ME + 1: "l3"}, "a", root_uid=ME, now=time.time)
        self.serve_with_peers(cfg, [ME + 7, ME + 7, ME])
        for _ in range(2):
            s = self.silent()
            s.settimeout(2)
            self.assertEqual(s.recv(10), b"")
        t0 = time.monotonic()
        self.ask()
        self.assertLess(time.monotonic() - t0, 2)

    def test_one_accounts_silent_callers_do_not_delay_the_other_account(self):
        cfg = a2_broker.Config(self.root, {ME + 1: "loop", ME: "l3"}, "a", root_uid=ME, now=time.time)
        self.serve_with_peers(cfg, [ME + 1, ME + 1, ME + 1, ME])
        held = [self.silent(), self.silent()]
        third = self.silent()
        third.settimeout(2)
        self.assertEqual(third.recv(10), b"")
        t0 = time.monotonic()
        self.ask(("--loop", "L3"))
        self.assertLess(time.monotonic() - t0, 2)
        self.assertEqual(len(held), 2)

    def test_a_caller_that_hangs_up_before_admission_gets_no_record(self):
        """The admission waits on budget.d's flock (held here); the caller sends its request and closes; when the
        flock is released, the broker sees the hang-up and publishes nothing."""
        import fcntl
        self.now = time.time()
        self.serve(self.cfg())
        bfd = os.open(os.path.join(self.root, "budget.d"), os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, bfd)
        fcntl.flock(bfd, fcntl.LOCK_EX)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(os.path.join(self.root, a2_budget.SOCKET_NAME))
        s.sendall(req())
        s.shutdown(socket.SHUT_WR)
        time.sleep(0.3)
        s.close()
        time.sleep(0.2)
        fcntl.flock(bfd, fcntl.LOCK_UN)
        time.sleep(0.5)
        self.assertEqual(self.names(), [])

    def test_bind_replaces_only_its_own_stale_socket(self):
        path = os.path.join(self.root, a2_budget.SOCKET_NAME)
        with open(path, "w"):
            pass
        with self.assertRaises(SystemExit):
            a2_broker.bind_socket(self.root, ME)
        os.unlink(path)
        stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale.bind(path)
        stale.close()
        a2_broker.bind_socket(self.root, ME).close()


class ClosureTest(unittest.TestCase):
    """The broker runs from a root-owned copy of exactly six installer files (MAP section 7): it imports from a
    directory holding only those, with the standard library and nothing else."""

    FILES = ("a2_broker.py", "a2_budget.py", "a2_args.py", "a2_host.py", "a2_private.py", "a2_causes.py")

    def test_the_shipped_execstart_form_imports(self):
        """`/usr/bin/python3 -I -B <dir>/a2_broker.py` from a directory of exactly the six files: a bad argv is
        main's rc 2, with nothing on stderr (an import failure would be rc 1 and a traceback)."""
        import subprocess
        import tempfile
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        d = tempfile.mkdtemp(prefix="a2brk-")
        self.addCleanup(shutil.rmtree, d, True)
        for f in self.FILES:
            shutil.copy(os.path.join(here, f), d)
        p = subprocess.run(["/usr/bin/python3", "-I", "-B", os.path.join(d, "a2_broker.py"), "--bad"],
                           capture_output=True, text=True, cwd="/", stdin=subprocess.DEVNULL)
        self.assertEqual((p.returncode, p.stderr), (2, ""))

    def test_six_files_suffice(self):
        import subprocess
        import tempfile
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        d = tempfile.mkdtemp(prefix="a2brk-")
        self.addCleanup(shutil.rmtree, d, True)
        for f in self.FILES:
            shutil.copy(os.path.join(here, f), d)
        p = subprocess.run(["/usr/bin/python3", "-I", "-B", "-c",
                            "import sys; sys.path.insert(0, %r); import a2_broker; "
                            "print(sorted(m for m in sys.modules if m.startswith('a2_')))" % d],
                           capture_output=True, text=True, cwd=d)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.strip(), str(sorted(f[:-3] for f in self.FILES)))


class AccountsTest(unittest.TestCase):
    def test_two_distinct_non_root_accounts(self):
        import types
        uids = {"lp": 1001, "l3": 1002, "same": 1001, "root": 0, "nobody": 65534}

        def getpwnam(n):
            if n not in uids:
                raise KeyError(n)
            return types.SimpleNamespace(pw_uid=uids[n])
        self.assertEqual(a2_broker.accounts_of("lp", "l3", getpwnam), {1001: "loop", 1002: "l3"})
        for pair in (("lp", "same"), ("lp", "root"), ("root", "l3"), ("lp", "nobody-here"), ("lp", "nobody"),
                     ("nobody", "l3")):
            with self.subTest(pair=pair):
                self.assertIsNone(a2_broker.accounts_of(*pair, getpwnam))


class CleanTest(Base):
    def test_start_up_removes_temporaries_and_nothing_else(self):
        d = os.path.join(self.root, "budget.d", "loop")
        rid, _ = self.admit()
        open(os.path.join(d, ".tmp-20261120T000000Z-00000000"), "w").close()
        a2_broker.clean_temporaries(self.root)
        self.assertEqual(sorted(os.listdir(d)), ["start-%s.json" % rid])


class ServeExitTest(unittest.TestCase):
    def test_an_accept_failure_returns_false(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.close()
        self.assertFalse(a2_broker.Server(s, None).serve())


class MainTest(unittest.TestCase):
    def test_argv_root_and_namespace(self):
        good = ["--lock-root", "/srv/locks", "--loop-account", "a", "--l3-account", "b", "--usage-path", "a"]
        for argv in ([], good[:-2], good + ["--x", "y"], ["--lock-root", "rel"] + good[2:]):
            with self.subTest(argv=argv):
                self.assertEqual(a2_broker.main(argv), 2)
        self.assertEqual(a2_broker.main(good[:-1] + ["c"]), 2)
        self.assertTrue(a2_broker.may_serve(lambda: 0, lambda: True))
        self.assertFalse(a2_broker.may_serve(lambda: 1000, lambda: True))
        self.assertFalse(a2_broker.may_serve(lambda: 0, lambda: False))
        self.assertTrue(a2_broker.initial_user_namespace(lambda p: "user:[1]"))
        self.assertFalse(a2_broker.initial_user_namespace(
            lambda p: "user:[1]" if p == "/proc/1/ns/user" else "user:[2]"))

        def gone(p):
            raise OSError(p)
        self.assertFalse(a2_broker.initial_user_namespace(gone))


if __name__ == "__main__":
    unittest.main()
