"""S1 CREDENTIALS (3.7): the no-echo prompt on a real pseudo-terminal, the
core limit, the form and live-check slots, L5, and S1 through the runner."""

import copy
import os
import resource
import shutil
import termios
import threading
import unittest

import a2fix
import a2_args
import a2_guard
import a2_s1
from a2_causes import Refusal


class Pty:
    """A pseudo-terminal whose far side answers each prompt with the next
    value, and records every byte the prompt side wrote."""

    def __init__(self, answers):
        self.master, self.slave = os.openpty()
        self.path = os.ttyname(self.slave)
        self.answers = list(answers)
        self.seen = b""
        self.t = threading.Thread(target=self._serve, daemon=True)
        self.t.start()

    def _serve(self):
        """Answer each prompt; asked for more than it was given, hang up
        (close the far side), so the prompt side reads EOF instead of
        waiting forever."""
        while True:
            try:
                b = os.read(self.master, 4096)
            except OSError:
                return
            if not b:
                return
            self.seen += b
            while b"(not echoed): " in self.seen:
                if not self.answers:
                    self.hung_up = True
                    os.close(self.master)
                    return
                head, _, self.seen_tail = self.seen.partition(b"(not echoed): ")
                self.seen = self.seen_tail
                self.consumed = getattr(self, "consumed", b"") + head + b"(not echoed): "
                answer = self.answers.pop(0)
                if isinstance(answer, tuple):
                    # ("signal", signum, partial bytes typed first)
                    _, signum, partial = answer
                    if partial:
                        os.write(self.master, partial)
                        import time
                        time.sleep(0.2)
                    os.kill(os.getpid(), signum)
                    continue
                os.write(self.master, answer + b"\n")

    def transcript(self):
        """Everything the prompt side wrote, as the far side saw it: with
        echo on, typed values would appear here."""
        self.t.join(timeout=5)
        if getattr(self, "hung_up", False):
            return getattr(self, "consumed", b"") + self.seen
        try:
            os.set_blocking(self.master, False)
            while True:
                b = os.read(self.master, 4096)
                if not b:
                    break
                self.seen += b
        except (BlockingIOError, OSError):
            pass
        return getattr(self, "consumed", b"") + self.seen

    def close(self):
        """The slave first, so the far side's read ends (EIO) and its thread
        returns; only then the master. Closing the master under a thread
        still reading it would let that thread read whatever pty a later
        test opens on the same descriptor number."""
        try:
            os.close(self.slave)
        except OSError:
            pass
        self.t.join(timeout=10)
        if self.t.is_alive():
            raise AssertionError("the pty's far side did not stop")
        if not getattr(self, "hung_up", False):
            try:
                os.close(self.master)
            except OSError:
                pass


class Forgetful(a2_guard.OutputGuard):
    """A guard whose release forgets its values without overwriting them,
    so only the prompt's own clear can zero them."""

    def release_all(self):
        self._held = []


class _KeepsMask(unittest.TestCase):
    """Each test ends with the signal mask it started with. A prompt that
    left the stop signals blocked would otherwise carry the block into a
    later test, whose signal another thread then takes, and that test's
    read would wait for ever instead of failing."""

    def setUp(self):
        import signal
        self.addCleanup(signal.pthread_sigmask, signal.SIG_SETMASK, signal.pthread_sigmask(signal.SIG_BLOCK, ()))


class PromptTest(_KeepsMask):
    def pty(self, answers):
        p = Pty(answers)
        self.addCleanup(p.close)
        return p

    def test_reads_each_value_without_echo_and_restores_the_terminal(self):
        p = self.pty([b"key-value-1", b"mbx-value-2"])
        before = termios.tcgetattr(p.slave)
        got = a2_s1.prompt(["api_key", "mailbox:vm-a"], a2_guard.OutputGuard(), p.path, p.slave)
        self.assertEqual(got, {"api_key": bytearray(b"key-value-1"), "mailbox:vm-a": bytearray(b"mbx-value-2")})
        self.assertTrue(all(isinstance(v, bytearray) for v in got.values()))
        self.assertEqual(termios.tcgetattr(p.slave), before)
        seen = p.transcript()
        self.assertIn(b"Enter api_key (not echoed): ", seen)
        self.assertNotIn(b"key-value-1", seen)
        self.assertNotIn(b"mbx-value-2", seen)

    def test_stdin_not_a_terminal_refuses_before_any_read(self):
        r, w = os.pipe()
        self.addCleanup(os.close, r)
        self.addCleanup(os.close, w)
        opened = []
        with self.assertRaises(Refusal) as cm:
            a2_s1.prompt(["api_key"], a2_guard.OutputGuard(), "/dev/tty", r,
                         open_fn=lambda *a: opened.append(a) or 0 / 0)
        self.assertEqual(cm.exception.cause, "CREDENTIALS.NO_ECHO")
        self.assertEqual(opened, [])

    def test_no_controlling_terminal_refuses(self):
        p = self.pty([])
        with self.assertRaises(Refusal) as cm:
            a2_s1.prompt(["api_key"], a2_guard.OutputGuard(), "/nonexistent-tty", p.slave)
        self.assertEqual(cm.exception.cause, "CREDENTIALS.NO_ECHO")

    def test_echo_that_cannot_be_turned_off_refuses_and_reads_nothing(self):
        from unittest import mock
        p = self.pty([b"never-read"])
        with mock.patch.object(a2_s1.termios, "tcsetattr", lambda *a: None):
            with self.assertRaises(Refusal) as cm:
                a2_s1.prompt(["api_key"], a2_guard.OutputGuard(), p.path, p.slave)
        self.assertEqual(cm.exception.cause, "CREDENTIALS.NO_ECHO")
        self.assertNotIn(b"Enter", p.transcript())

    def test_a_hung_up_terminal_refuses_and_restores(self):
        """The line is gone, so its attributes can no longer be read back; the
        point is that the prompt refuses instead of waiting."""
        p = self.pty([b"only-one"])
        with self.assertRaises(Refusal) as cm:
            a2_s1.prompt(["api_key", "mailbox:vm-a"], a2_guard.OutputGuard(), p.path, p.slave)
        self.assertEqual(cm.exception.cause, "CREDENTIALS.NO_ECHO")

    def test_end_of_file_at_the_prompt_refuses(self):
        """Ctrl-D at the start of a line: the read returns no bytes, which is
        not a value."""
        p = self.pty([b"\x04"])
        before = termios.tcgetattr(p.slave)
        with self.assertRaises(Refusal) as cm:
            a2_s1.prompt(["api_key"], a2_guard.OutputGuard(), p.path, p.slave)
        self.assertEqual(cm.exception.cause, "CREDENTIALS.NO_ECHO")
        self.assertEqual(termios.tcgetattr(p.slave), before)

    def test_echonl_that_cannot_be_turned_off_refuses(self):
        """ECHONL is checked off too, before any prompt."""
        from unittest import mock
        p = self.pty([b"never-read"])
        real_get = termios.tcgetattr
        calls = []

        def get(fd):
            a = real_get(fd)
            calls.append(1)
            if len(calls) == 2:          # the read-back after turning echo off
                a[3] |= termios.ECHONL
            return a
        with mock.patch.object(a2_s1.termios, "tcgetattr", get):
            with self.assertRaises(Refusal) as cm:
                a2_s1.prompt(["api_key"], a2_guard.OutputGuard(), p.path, p.slave)
        self.assertEqual(cm.exception.cause, "CREDENTIALS.NO_ECHO")
        self.assertNotIn(b"Enter", p.transcript())

    def test_a_failed_restore_is_a_refusal(self):
        from unittest import mock
        p = self.pty([b"value-1-x9"])
        real_set = termios.tcsetattr
        calls = []

        def setattr_(fd, when, attrs):
            calls.append(1)
            if len(calls) == 2:          # the restore
                raise termios.error(5, "restore failed")
            return real_set(fd, when, attrs)
        g = a2_guard.OutputGuard()
        with mock.patch.object(a2_s1.termios, "tcsetattr", setattr_):
            with self.assertRaises(Refusal) as cm:
                a2_s1.prompt(["api_key"], g, p.path, p.slave)
        self.assertEqual((cm.exception.cause, cm.exception.detail),
                         ("CREDENTIALS.NO_ECHO", "terminal state not restored"))
        real_set(p.slave, termios.TCSANOW, termios.tcgetattr(p.slave))

    def test_partial_value_is_zeroed_on_eof(self):
        """A value cut off by a hang-up is overwritten before the refusal."""
        seen = []
        real = a2_s1._zero

        def spy(buf):
            seen.append(bytes(buf))
            real(buf)
            seen.append(bytes(buf))
        from unittest import mock
        r, w = os.pipe()
        os.write(w, b"partial-secret")
        os.close(w)
        with mock.patch.object(a2_s1, "_zero", spy):
            with self.assertRaises(Refusal):
                a2_s1._read_line(r)
        os.close(r)
        self.assertEqual(seen, [b"partial-secret", b"\x00" * 14])

    def test_signals_at_the_prompt_restore_and_refuse(self):
        import signal
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
            with self.subTest(sig=sig):
                p = self.pty([("signal", sig, b"partial-sec")])
                before = termios.tcgetattr(p.slave)

                def own(signum, frame):
                    raise AssertionError("the prompt did not take this signal")
                prior = signal.signal(sig, own)
                self.addCleanup(signal.signal, sig, prior)
                old = own
                with self.assertRaises(Refusal) as cm:
                    a2_s1.prompt(["api_key"], a2_guard.OutputGuard(), p.path, p.slave)
                self.assertEqual((cm.exception.cause, cm.exception.detail),
                                 ("CREDENTIALS.NO_ECHO", "interrupted"))
                self.assertEqual(termios.tcgetattr(p.slave), before)
                self.assertIs(signal.getsignal(sig), old)

    def test_stop_is_ignored_during_the_prompt_and_restored_after(self):
        """SIGTSTP is ignored while echo is off (a stopped prompt would
        leave it off), and every handler is put back when the session ends
        normally."""
        import signal
        seen = []
        real = a2_s1._read_line

        def read(fd, *a):
            seen.append(signal.getsignal(signal.SIGTSTP))
            return real(fd, *a)
        from unittest import mock
        olds = {}
        for s in (signal.SIGTSTP,) + a2_s1.STOP_SIGNALS:
            def own(signum, frame):
                pass
            self.addCleanup(signal.signal, s, signal.signal(s, own))
            olds[s] = own
        p = self.pty([b"value-1-x9"])
        with mock.patch.object(a2_s1, "_read_line", read):
            a2_s1.prompt(["api_key"], a2_guard.OutputGuard(), p.path, p.slave)
        self.assertEqual(seen, [signal.SIG_IGN])
        for s, old in olds.items():
            self.assertIs(signal.getsignal(s), old)

    def _own_handlers(self):
        import signal

        def own(signum, frame):
            raise AssertionError("the prompt did not take this signal")
        for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT, signal.SIGTSTP):
            self.addCleanup(signal.signal, s, signal.signal(s, own))
        return own


    def test_the_restores_run_with_the_stop_signals_blocked(self):
        """The terminal restore and the handler restore both run with INT,
        TERM, HUP, QUIT and TSTP blocked, and the caller's mask is back
        afterwards."""
        import signal
        from unittest import mock
        want = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT, signal.SIGTSTP}
        self._own_handlers()
        before = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        p = self.pty([b"value-1-x9"])
        real_set = termios.tcsetattr
        real_restore = a2_s1._Signals._restore
        seen = {}

        def setattr_(fd, when, attrs):
            seen.setdefault("calls", []).append(signal.pthread_sigmask(signal.SIG_BLOCK, ()))
            return real_set(fd, when, attrs)

        def restore(self_):
            seen["handlers"] = signal.pthread_sigmask(signal.SIG_BLOCK, ())
            return real_restore(self_)
        with mock.patch.object(a2_s1.termios, "tcsetattr", setattr_), \
                mock.patch.object(a2_s1._Signals, "_restore", restore):
            a2_s1.prompt(["api_key"], a2_guard.OutputGuard(), p.path, p.slave)
        self.assertLessEqual(want, seen["calls"][-1])          # the terminal restore
        self.assertLessEqual(want, seen["handlers"])
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, ()), before)

    def test_a_signal_during_the_terminal_restore_waits_for_it(self):
        """A stop raised while the terminal is being put back is held until
        the restore is done; then it refuses, with the terminal, the
        handlers and the mask all back."""
        import signal
        from unittest import mock
        own = self._own_handlers()
        before_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        p = self.pty([b"value-1-x9"])
        before = termios.tcgetattr(p.slave)
        real_set = termios.tcsetattr
        calls = []

        def setattr_(fd, when, attrs):
            calls.append(1)
            if len(calls) == 2:          # the restore
                signal.raise_signal(signal.SIGTERM)
            return real_set(fd, when, attrs)
        with mock.patch.object(a2_s1.termios, "tcsetattr", setattr_):
            with self.assertRaises(Refusal) as cm:
                a2_s1.prompt(["api_key"], a2_guard.OutputGuard(), p.path, p.slave)
        self.assertEqual((cm.exception.cause, cm.exception.detail), ("CREDENTIALS.NO_ECHO", "interrupted"))
        self.assertEqual(termios.tcgetattr(p.slave), before)
        self.assertIs(signal.getsignal(signal.SIGTERM), own)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, ()), before_mask)

    def test_a_stop_taken_just_before_the_block_reruns_the_restore(self):
        """`_uninterrupted`'s own rerun: an `_Interrupted` raised as the
        block goes up (S1's handlers raise one only during a read, so this
        models a raise from elsewhere) runs the restore again under the
        block, then refuses, and the mask is back."""
        import signal
        from unittest import mock
        self._own_handlers()
        before_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        p = self.pty([b"value-1-x9"])
        before = termios.tcgetattr(p.slave)
        real_mask = a2_s1._mask
        fired = []

        def mask(how, sigs):
            old = real_mask(how, sigs)
            if how == signal.SIG_BLOCK and sigs and not fired:
                fired.append(1)
                raise a2_s1._Interrupted()
            return old
        with mock.patch.object(a2_s1, "_mask", mask):
            with self.assertRaises(Refusal) as cm:
                a2_s1.prompt(["api_key"], a2_guard.OutputGuard(), p.path, p.slave)
        self.assertEqual(fired, [1])
        self.assertEqual((cm.exception.cause, cm.exception.detail), ("CREDENTIALS.NO_ECHO", "interrupted"))
        self.assertEqual(termios.tcgetattr(p.slave), before)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, ()), before_mask)

    def test_a_second_stop_during_the_reads_own_clear_does_not_cut_it(self):
        """A TERM during the read raises; an INT on the read's own clear of
        the partial value is recorded, not raised (the handler leaves the
        read state as it raises), so that clear runs to its end. The
        prompt still refuses as for a stop at the read."""
        import signal
        from unittest import mock
        self._own_handlers()
        p = self.pty([("signal", signal.SIGTERM, b"partial-sec")])
        real = a2_s1._zero
        calls = []

        def zero(buf):
            calls.append(None)
            n = len(calls)
            if n == 1:
                signal.raise_signal(signal.SIGINT)
            real(buf)
            calls[n - 1] = (len(buf), bytes(buf) == bytes(len(buf)))
        with mock.patch.object(a2_s1, "_zero", zero):
            with self.assertRaises(Refusal) as cm:
                a2_s1.prompt(["api_key"], a2_guard.OutputGuard(), p.path, p.slave)
        # the read's own clear ran to its end (in canonical mode the partial
        # bytes are not delivered before a newline, so the buffer may be empty)
        self.assertIsNotNone(calls[0])
        self.assertTrue(calls[0][1])
        self.assertEqual((cm.exception.cause, cm.exception.detail), ("CREDENTIALS.NO_ECHO", "interrupted"))

    def test_a_hand_back_cut_after_two_restores_ends_with_every_handler_back(self):
        """The prompt's hand-back can run again with the same result: one cut
        after its second handler is put back (modelled by an
        `_Interrupted` there) runs again from the start, and every handler
        is the caller's afterwards."""
        import signal
        import sys
        from unittest import mock
        own = self._own_handlers()
        p = self.pty([b"value-1-x9"])
        real = signal.signal
        code = a2_s1._Signals._restore.__code__
        n = []

        def put(sig, handler):
            old = real(sig, handler)
            if sys._getframe(1).f_code is code:
                n.append(sig)
                if len(n) == 2:
                    raise a2_s1._Interrupted()
            return old
        with mock.patch.object(a2_s1.signal, "signal", put):
            with self.assertRaises(Refusal) as cm:
                a2_s1.prompt(["api_key"], a2_guard.OutputGuard(), p.path, p.slave)
        self.assertEqual(len(n), 2 + 5)
        self.assertEqual((cm.exception.cause, cm.exception.detail), ("CREDENTIALS.NO_ECHO", "interrupted"))
        for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT, signal.SIGTSTP):
            self.assertIs(signal.getsignal(s), own)

    def test_an_empty_value_is_a_form_refusal_and_earlier_values_are_zeroed(self):
        seen = []
        real = a2_s1._zero

        def spy(buf):
            real(buf)
            seen.append(bytes(buf))
        from unittest import mock
        p = self.pty([b"first-value", b""])
        g = a2_guard.OutputGuard()
        with mock.patch.object(a2_s1, "_zero", spy):
            with self.assertRaises(Refusal) as cm:
                a2_s1.prompt(["api_key", "mailbox:vm-a"], g, p.path, p.slave)
        self.assertEqual((cm.exception.cause, cm.exception.detail), ("CREDENTIALS.FORM", "form rule: empty"))
        self.assertIn(b"\x00" * len(b"first-value"), seen)

    def test_terminal_restored_when_a_value_is_too_long(self):
        p = self.pty([b"x" * (a2_s1.VALUE_MAX + 1)])
        before = termios.tcgetattr(p.slave)
        with self.assertRaises(Refusal) as cm:
            a2_s1.prompt(["api_key"], a2_guard.OutputGuard(), p.path, p.slave)
        self.assertEqual(cm.exception.cause, "CREDENTIALS.FORM")
        self.assertNotIn(b"x" * 10, cm.exception.detail.encode())
        self.assertEqual(termios.tcgetattr(p.slave), before)


class RulesTest(_KeepsMask):
    def test_core_limit_set_and_refused_when_it_cannot_be(self):
        calls = []
        a2_s1.set_core_limit(lambda r, v: calls.append(v), lambda r: (0, 0))
        self.assertEqual(calls, [(0, 0)])
        for setr, getr in ((lambda r, v: (_ for _ in ()).throw(OSError()), lambda r: (0, 0)),
                           (lambda r, v: None, lambda r: (0, 1024))):
            with self.assertRaises(Refusal) as cm:
                a2_s1.set_core_limit(setr, getr)
            self.assertEqual(cm.exception.cause, "CREDENTIALS.CORE_LIMIT")

    def test_core_limit_really_applies(self):
        old = resource.getrlimit(resource.RLIMIT_CORE)
        self.addCleanup(lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))
        a2_s1.set_core_limit()
        self.assertEqual(resource.getrlimit(resource.RLIMIT_CORE), (0, 0))
        self.assertTrue(old[0] >= 0 or old[0] == resource.RLIM_INFINITY)

    def test_form_rules_slot_and_failures_name_only_the_rule(self):
        values = {"api_key": bytearray(b"secret-k"), "mailbox:vm-a": bytearray(b"secret-m")}
        for rules, rule in ((None, "not supplied"), ({"api_key": lambda v: True}, "mailbox"),
                            ({"api_key": lambda v: False, "mailbox": lambda v: True}, "api_key"),
                            ({"api_key": lambda v: 1, "mailbox": lambda v: True}, "api_key")):
            with self.subTest(rule=rule):
                with self.assertRaises(Refusal) as cm:
                    a2_s1.check_forms(values, rules)
                self.assertEqual((cm.exception.cause, cm.exception.detail),
                                 ("CREDENTIALS.FORM", "form rule: " + rule))
        a2_s1.check_forms(values, {"api_key": lambda v: True, "mailbox": lambda v: True})
        with self.assertRaises(Refusal):
            a2_s1.check_forms({"api_key": bytearray()}, {"api_key": lambda v: True})

    def test_live_check_slot_and_the_leak_run_stub(self):
        I = a2_args.Invocation
        v = {"api_key": bytearray(b"k")}
        for check in (None, lambda k: False, lambda k: 1 / 0, lambda k: "yes"):
            with self.assertRaises(Refusal) as cm:
                a2_s1.check_live(v, I("install", "L2", {}), check)
            self.assertEqual(cm.exception.cause, "CREDENTIALS.KEY_NOT_LIVE")
        self.assertEqual(a2_s1.check_live(v, I("install", "L2", {}), lambda k: True), "pass")
        self.assertEqual(a2_s1.check_live(v, I("install", "L2-leak", {}), None), "stub")

    def test_l5_raw_and_parsed(self):
        class C:
            pass
        c = C()
        c.lock = copy.deepcopy(a2fix.LOCK)
        c.lock_raw = a2fix.dumps(c.lock)
        c.hosts = a2fix.hosts_doc("/srv/locks")
        c.hosts_raw = a2fix.dumps(c.hosts)
        a2_s1.check_l5({"api_key": bytearray(b"not-in-either-file")}, c)
        for value, cause in ((b"tmpl", "CREDENTIALS.LEAK_LOCK"), (b"hub.example.org", "CREDENTIALS.LEAK_HOSTS")):
            with self.subTest(value=value):
                with self.assertRaises(Refusal) as cm:
                    a2_s1.check_l5({"api_key": bytearray(value)}, c)
                self.assertEqual(cm.exception.cause, cause)
        # Only in the raw bytes: a sequence that spans JSON syntax is in no
        # parsed string.
        with self.assertRaises(Refusal) as cm:
            a2_s1.check_l5({"api_key": bytearray(b'"name": "tmpl')}, c)
        self.assertEqual(cm.exception.cause, "CREDENTIALS.LEAK_LOCK")
        # Only in the parsed form: an escaped value in the raw bytes.
        c.hosts["hub"]["domain"] = "zz.example.org"
        c.hosts_raw = a2fix.dumps(c.hosts).replace(b"zz.example.org", b"\\u007az.example.org")
        with self.assertRaises(Refusal) as cm:
            a2_s1.check_l5({"api_key": bytearray(b"zz.example")}, c)
        self.assertEqual(cm.exception.cause, "CREDENTIALS.LEAK_HOSTS")

    def test_clear_zeroes_the_values_itself(self):
        """Held.clear overwrites the bytearrays, whatever the guard does."""
        class InertGuard:
            def hold(self, v):
                pass

            def release_all(self):
                pass
        v = bytearray(b"s3cret")
        a2_s1.Held({"api_key": v}, InertGuard()).clear()
        self.assertEqual(v, bytearray(6))

    def test_a_dry_run_never_prompts(self):
        """Rule 2: --dry-run never prompts; S1 records its plan."""
        p = Pty([])
        self.addCleanup(p.close)

        class C:
            pass
        c = C()
        c.inv = a2_args.Invocation("dry-run", None, {})
        c.hosts = a2fix.hosts_doc("/srv/locks")
        c.account = "loop"

        class Site:
            tty_path = p.path
            stdin_fd = p.slave

        class Run:
            started = "2026-11-16T00:00:00Z"
            written = []

            def write_receipt(self, *a, **kw):
                self.written.append((a, kw))
        run = Run()
        self.assertIsNone(a2_s1.run_s1(c, Site(), run, a2_guard.OutputGuard()))
        (args, kw), = run.written
        self.assertEqual(args[:4], ("S1", None, "2026-11-16T00:00:00Z", "PLANNED"))
        self.assertNotIn(b"Enter", p.transcript())

    def test_run_s1_clears_what_it_read_on_an_unnamed_failure(self):
        """run_s1 itself zeroes and releases the values when a failure it
        does not name leaves it, before any caller's cleanup runs."""
        p = Pty([b"api-secret-1x", b"mbx-secret-ax", b"mbx-secret-bx", b"mbx-secret-cx"])
        self.addCleanup(p.close)
        seen = []

        def broken(v):
            seen.append(v)
            raise KeyError("predicate broke")

        class C:
            pass
        c = C()
        c.inv = a2_args.Invocation("install", "L2", {})
        c.hosts = a2fix.hosts_doc("/srv/locks")
        c.account = "loop"

        class Site:
            tty_path = p.path
            stdin_fd = p.slave
            form_rules = {"api_key": broken, "mailbox": broken}
            live_check = None

            @staticmethod
            def setrlimit(r, v):
                pass

            @staticmethod
            def getrlimit(r):
                return (0, 0)

        class Run:
            started = "2026-11-16T00:00:00Z"

            def write_receipt(self, *a, **kw):
                raise AssertionError("no receipt for an unnamed failure")
        g = a2_guard.OutputGuard()
        with self.assertRaises(KeyError):
            a2_s1.run_s1(c, Site(), Run(), g)
        self.assertFalse(g.holding)
        self.assertTrue(seen)
        for v in seen:
            self.assertEqual(v, bytearray(len(v)))

    def test_held_values_are_guarded_then_cleared(self):
        g = a2_guard.OutputGuard()
        v = bytearray(b"s3cret")
        h = a2_s1.Held({"api_key": v}, g)
        with self.assertRaises(Refusal):
            g.check("..s3cret..")
        h.clear()
        self.assertEqual(v, bytearray(6))
        g.check("..s3cret..")


class RunnerS1Test(_KeepsMask):
    """S1 through the runner, after a passing S0 (a2fix.GitWorld)."""

    def setUp(self):
        super().setUp()
        import a2_budget
        import a2_locks
        self.base = a2fix.make_base()
        self.addCleanup(shutil.rmtree, self.base, True)
        self.w = a2fix.World(self.base)
        self.gw = a2fix.GitWorld(self.w)
        self.held = []
        self.addCleanup(lambda: [a2_locks.release(h) for h in self.held])
        inv = a2_args.parse(["--loop", "L2"])
        vms = a2_locks.run_vms(self.w.hosts, inv, "loop")
        order = a2_locks.lock_order(self.w.root, a2_locks.targets(self.w.hosts, vms), True)
        self.held.append(a2_locks.acquire(order, os.getuid()))
        b = a2fix.FakeBroker(self.w)
        try:
            import hashlib
            shas = []
            for n in ("alpha2.lock", "alpha2.hosts"):
                with open(os.path.join(self.w.private, n), "rb") as f:
                    shas.append(hashlib.sha256(f.read()).hexdigest())
            self.rid, _ = a2_budget.ask_broker(self.w.root, inv, shas[0], shas[1], "c" * 64,
                                               root_uid=os.getuid())
        finally:
            b.close()

    def site_for(self, answers, **over):
        """The run's site, answering the prompt with `answers`; kept as
        self.site_now, so a check made while the run is going can read it."""
        p = Pty(answers)
        self.addCleanup(p.close)
        o = self.gw.site_over()
        o.update(dict(tty_path=p.path, stdin_fd=p.slave,
                      setrlimit=lambda r, v: None, getrlimit=lambda r: (0, 0),
                      form_rules={"api_key": lambda v: True, "mailbox": lambda v: True},
                      live_check=lambda k: True))
        o.update(over)
        import io
        site = self.w.site(**o)
        site.out = io.StringIO()
        self.site_now = site
        return site, p

    def run_with(self, answers, stops=None, **over):
        import a2_main
        site, p = self.site_for(answers, **over)
        with self.assertRaises(Refusal) as cm:
            a2_main.run(self.rid, ["--loop", "L2"], site, stops)
        return cm.exception, site, p

    def read(self, *parts):
        with open(os.path.join(self.w.home, "alpha2-work", "runs", self.rid, *parts), "rb") as f:
            return f.read()

    def rc_of(self, name):
        """A receipt's rc, from its parsed end line."""
        import a2_record
        return a2_record.parse_receipt(self.read("receipts", name))[3]

    def finished(self, site):
        """The record is finished (3.4, 5.4): S10's receipt, the final
        manifest, the summary last in SUMS, and the verified SUMS sha as
        the terminal's last line."""
        import json
        import a2_record
        self.read("receipts", "S10--.txt")
        self.assertEqual(json.loads(self.read("manifest.json"))["state"], "final")
        self.assertTrue(self.read("summary.txt").rstrip(b"\n").splitlines()[-1].startswith(b"NOT ELIGIBLE: "))
        self.assertEqual(self.read("SUMS").rstrip(b"\n").splitlines()[-1].split(b" ")[-1], b"summary.txt")
        fd = os.open(os.path.join(self.w.home, "alpha2-work", "runs", self.rid), a2_record.DIR_FLAGS)
        try:
            self.assertEqual("SUMS sha256 " + a2_record.verify_sums(fd), site.out.getvalue().splitlines()[-1])
        finally:
            os.close(fd)

    def own_stop_handlers(self):
        """A raising handler of the test's own on each stop signal, so a
        stop nothing took fails the test instead of ending the process;
        returns it, to check the run gave it back. Each call is recorded
        in self.stray, because the runner turns any exception into an
        UNCLASSIFIED cause and would otherwise hide that it ran."""
        import signal
        self.stray = []
        self.addCleanup(lambda: self.assertEqual(self.stray, [], "a stop reached the test's own handler"))

        def own(signum, frame):
            self.stray.append(signum)
            raise AssertionError("the runner did not take signal %d" % signum)
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
            self.addCleanup(signal.signal, sig, signal.signal(sig, own))
        return own

    def test_s1_passes_binds_by_vm_name_and_never_records_a_value(self):
        e, site, p = self.run_with([b"api-secret-1", b"mbx-secret-a", b"mbx-secret-b"])
        self.assertEqual((e.cause, e.rc), ("RUNNER.UNCLASSIFIED", 3))     # S2 is not built yet
        s1 = self.read("receipts", "S1--.txt")
        self.assertIn(b"RESULT=PASS", s1)
        self.assertIn(b"BINDING=api_key mailbox:vm-a-t mailbox:vm-b-t", s1)
        self.assertIn(b"KEY_LIVE=pass", s1)
        for secret in (b"api-secret-1", b"mbx-secret-a", b"mbx-secret-b"):
            for name in os.listdir(os.path.join(self.w.home, "alpha2-work", "runs", self.rid, "receipts")):
                self.assertNotIn(secret, self.read("receipts", name))
            self.assertNotIn(secret, self.read("manifest.json"))
            self.assertNotIn(secret, self.read("summary.txt"))
            self.assertNotIn(secret.decode(), site.out.getvalue())
        self.assertIn("SUMS sha256 ", site.out.getvalue())

    def test_a_value_present_in_hosts_refuses_l5_and_no_writer_runs(self):
        e, site, p = self.run_with([b"api-secret-1", b"hub.example.org", b"mbx-secret-b"])
        self.assertEqual((e.cause, e.rc), ("CREDENTIALS.LEAK_HOSTS", 2))
        self.assertIn(b"CAUSE=CREDENTIALS.LEAK_HOSTS", self.read("receipts", "S1--.txt"))

    def test_form_slot_unset_refuses(self):
        e, site, p = self.run_with([b"val-one-x9", b"val-two-x9", b"val-thr-x9"], form_rules=None)
        self.assertEqual(e.cause, "CREDENTIALS.FORM")

    def test_live_slot_unset_refuses(self):
        e, site, p = self.run_with([b"val-one-x9", b"val-two-x9", b"val-thr-x9"], live_check=None)
        self.assertEqual(e.cause, "CREDENTIALS.KEY_NOT_LIVE")

    def test_a_value_is_guarded_as_soon_as_it_is_read(self):
        """The first value is in the guard before the second prompt is
        written: a first value that the second prompt's text contains stops
        the prompt there (fail closed), before anything else is printed."""
        e, site, p = self.run_with([b"mailbox", b"never-asked", b"never-asked-2"])
        self.assertEqual(e.cause, "RUNNER.OUTPUT_GUARD")
        self.assertNotIn(b"Enter mailbox:", p.transcript())

    def test_an_unexpected_failure_in_s1_is_s1s_unclassified(self):
        """A form predicate that raises: S1's own receipt carries
        CREDENTIALS.UNCLASSIFIED with rc 3, and nothing stays held."""
        import a2_guard
        g = a2_guard.OutputGuard()

        def broken(v):
            raise KeyError("predicate broke")
        e, site, p = self.run_with([b"val-one-x9", b"val-two-x9", b"val-thr-x9"], guard=g,
                                   form_rules={"api_key": broken, "mailbox": broken})
        self.assertEqual((e.cause, e.rc), ("CREDENTIALS.UNCLASSIFIED", 3))
        self.assertIn(b"CAUSE=CREDENTIALS.UNCLASSIFIED", self.read("receipts", "S1--.txt"))
        self.assertIn(b"STAGE-END S1 - rc=3", self.read("receipts", "S1--.txt"))
        self.assertFalse(g.holding)

    SECRETS = (b"api-secret-1x", b"mbx-secret-ax", b"mbx-secret-bx")

    def test_s1_receipt_facts_are_exactly_the_allowed_ones(self):
        e, site, p = self.run_with(list(self.SECRETS))
        import a2_record
        facts, _sid, _host, rc = a2_record.parse_receipt(self.read("receipts", "S1--.txt"))
        base = {"RUN_ID", "COMMAND", "LOOP", "INSTALLER_SHA", "LOCK_SHA", "HOSTS_SHA", "STAGE", "HOST",
                "STARTED", "ENDED", "RESULT"}
        self.assertEqual(set(facts) - base, {"CUSTODY_LOCKS", "CUSTODY_PLACEMENT", "CUSTODY_STOP",
                                             "CORE_LIMIT", "NO_ECHO", "BINDING", "FORM", "KEY_LIVE",
                                             "LEAK_CHECK", "HOLD"})
        # 5.3b: the custody read-back taken before S1, as S1's facts.
        self.assertEqual({k: facts[k] for k in ("CUSTODY_LOCKS", "CUSTODY_PLACEMENT", "CUSTODY_STOP")},
                         {"CUSTODY_LOCKS": "held", "CUSTODY_PLACEMENT": "match", "CUSTODY_STOP": "unset"})
        self.assertEqual({k: facts[k] for k in ("CORE_LIMIT", "NO_ECHO", "FORM", "KEY_LIVE", "LEAK_CHECK")},
                         {"CORE_LIMIT": "0", "NO_ECHO": "verified", "FORM": "pass", "KEY_LIVE": "pass",
                          "LEAK_CHECK": "L5 pass"})

    def test_no_part_hash_or_length_of_a_value_reaches_any_file_or_the_terminal(self):
        """3.3 forbids a value, its hash, length, prefix or any part: every
        6-byte substring and the sha256 of each value are searched for."""
        import hashlib
        e, site, p = self.run_with(list(self.SECRETS))
        run_dir = os.path.join(self.w.home, "alpha2-work", "runs", self.rid)
        blobs = [site.out.getvalue().encode()]
        for root, _dirs, files in os.walk(run_dir):
            for n in files:
                with open(os.path.join(root, n), "rb") as f:
                    blobs.append(f.read())
        for secret in self.SECRETS:
            needles = {secret[i:i + 6] for i in range(len(secret) - 5)}
            needles.add(hashlib.sha256(secret).hexdigest().encode())
            for blob in blobs:
                for nd in needles:
                    self.assertNotIn(nd, blob)

    def test_an_interrupt_at_the_prompt_finishes_the_record(self):
        """SIGINT during the runner's prompt: S1 receipt NO_ECHO, S10 and the
        summary written, the manifest final, a contract rc."""
        import json
        import signal
        e, site, p = self.run_with([("signal", signal.SIGINT, b"")])
        self.assertEqual((e.cause, e.rc), ("CREDENTIALS.NO_ECHO", 2))
        self.assertIn(b"CAUSE=CREDENTIALS.NO_ECHO", self.read("receipts", "S1--.txt"))
        self.assertEqual(json.loads(self.read("manifest.json"))["state"], "final")
        self.assertTrue(self.read("summary.txt").startswith(b"RESULT FAIL\n"))

    def test_a_quit_at_the_prompt_finishes_the_record(self):
        """SIGQUIT (Ctrl-\\) during the runner's prompt is a stop like
        SIGINT: S1 receipt NO_ECHO, the record finished, the terminal back."""
        import json
        import signal

        def own(signum, frame):
            raise AssertionError("the prompt did not take SIGQUIT")
        self.addCleanup(signal.signal, signal.SIGQUIT, signal.signal(signal.SIGQUIT, own))
        e, site, p = self.run_with([("signal", signal.SIGQUIT, b"")])
        self.assertEqual((e.cause, e.rc), ("CREDENTIALS.NO_ECHO", 2))
        self.assertIn(b"CAUSE=CREDENTIALS.NO_ECHO", self.read("receipts", "S1--.txt"))
        self.assertEqual(json.loads(self.read("manifest.json"))["state"], "final")
        self.assertTrue(self.read("summary.txt").startswith(b"RESULT FAIL\n"))
        self.assertIs(signal.getsignal(signal.SIGQUIT), own)

    def test_a_keyboardinterrupt_outside_the_prompt_is_unclassified_and_finished(self):
        import json

        def interrupting(v):
            raise KeyboardInterrupt
        e, site, p = self.run_with(list(self.SECRETS), live_check=interrupting)
        self.assertEqual((e.cause, e.rc), ("CREDENTIALS.UNCLASSIFIED", 3))
        self.assertEqual(json.loads(self.read("manifest.json"))["state"], "final")

    def test_custody_mismatch_at_s10_fails_s10_and_is_not_eligible(self):
        calls = []

        def placement(h):
            calls.append(1)
            return "differs" if len(calls) >= 3 else "match"
        e, site, p = self.run_with(list(self.SECRETS), probe_placement=placement)
        s10 = self.read("receipts", "S10--.txt")
        self.assertIn(b"CAUSE=RUNNER.CUSTODY", s10)
        self.assertIn(b"CUSTODY_PLACEMENT=differs", s10)
        self.assertTrue(self.read("summary.txt").rstrip(b"\n").splitlines()[-1].startswith(b"NOT ELIGIBLE: "))

    def test_an_unexpected_failure_in_s1_zeroes_the_values_s1_read(self):
        """Through the runner: the values S1 read are overwritten when a
        failure no cause names ends the run."""
        seen = []

        def broken(v):
            seen.append(v)
            raise KeyError("predicate broke")
        e, site, p = self.run_with(list(self.SECRETS), form_rules={"api_key": broken, "mailbox": broken})
        self.assertEqual(e.cause, "CREDENTIALS.UNCLASSIFIED")
        self.assertTrue(seen)
        for v in seen:
            self.assertEqual(v, bytearray(len(v)))

    def test_the_runner_releases_what_a_stage_left_held(self):
        """Whatever a stage leaves in the guard, the runner releases it on the
        way out. The stand-in takes run_s1's own parameters and records that
        it held a value, so the release is of a value the stage really left."""
        import inspect
        import a2_guard
        g = a2_guard.OutputGuard()
        real = a2_s1.run_s1
        left = []

        def leaving(c, site, run, guard, custody=()):
            guard.hold(bytearray(b"left-held-x9"))
            left.append(guard.holding)
            raise RuntimeError("stage broke")
        self.assertEqual(inspect.signature(leaving), inspect.signature(real))
        a2_s1.run_s1 = leaving
        self.addCleanup(setattr, a2_s1, "run_s1", real)
        e, site, p = self.run_with([], guard=g)
        self.assertEqual((e.cause, e.rc), ("CREDENTIALS.UNCLASSIFIED", 3))
        self.assertEqual(left, [True])
        self.assertFalse(g.holding)

    def test_a_chain_broken_before_the_summary_stops_s10_without_one(self):
        """S10 verifies the chain once the final manifest is on it; a chain
        that no longer verifies there gets no summary."""
        import a2_record
        real = a2_record.Run.write_manifest
        rd = os.path.join(self.w.home, "alpha2-work", "runs", self.rid)

        def then_break(run, final=False):
            real(run, final=final)
            if final:
                q = os.path.join(rd, "receipts", "S0--.txt")
                os.chmod(q, 0o600)
                with open(q, "ab") as f:
                    f.write(b"X")
        a2_record.Run.write_manifest = then_break
        self.addCleanup(setattr, a2_record.Run, "write_manifest", real)
        e, site, p = self.run_with(list(self.SECRETS))
        self.assertEqual(e.rc, 3)
        self.assertFalse(os.path.exists(os.path.join(rd, "summary.txt")))

    def test_the_round_trip_nonce_is_fresh_from_the_system_source(self):
        """5.5: the round-trip line carries a fresh nonce: S10 draws it from
        secrets.token_hex, and it matches the --check-roundtrip pattern."""
        import re
        import secrets
        import a2_s10
        drawn = []

        class Source:
            @staticmethod
            def token_hex(n):
                drawn.append(secrets.token_hex(n))
                return drawn[-1]
        real = a2_s10.secrets
        a2_s10.secrets = Source
        self.addCleanup(setattr, a2_s10, "secrets", real)
        e, site, p = self.run_with(list(self.SECRETS))
        self.assertEqual(len(drawn), 1)
        self.assertRegex(drawn[0], r"^[A-Za-z0-9]{8,64}$")
        lines = self.read("summary.txt").decode("ascii").splitlines()
        self.assertIn("round trip: alpha2_install.py --check-roundtrip " + drawn[0], lines)

    def test_the_runner_clears_the_values_s1_returned(self):
        """The values S1 hands back are overwritten by the runner's own
        clear when the run ends, whatever the guard does on release."""
        import a2_guard

        class Forgetful(a2_guard.OutputGuard):
            def release_all(self):
                self._held = []
        seen = []

        def rule(v):
            seen.append(v)
            return True
        e, site, p = self.run_with(list(self.SECRETS), guard=Forgetful(),
                                   form_rules={"api_key": rule, "mailbox": rule})
        self.assertEqual((e.cause, e.rc), ("RUNNER.UNCLASSIFIED", 3))
        self.assertTrue(seen)
        for v in seen:
            self.assertEqual(v, bytearray(len(v)))

    def test_values_are_released_when_the_run_ends(self):
        import a2_guard
        g = a2_guard.OutputGuard()
        e, site, p = self.run_with([b"api-secret-1", b"mbx-secret-a", b"mbx-secret-b"], guard=g)
        self.assertFalse(g.holding)

    def test_custody_is_read_before_s1(self):
        """Placement matches at S0 and differs before S1: S1 does not run,
        its receipt carries RUNNER.CUSTODY, and nothing is prompted."""
        calls = []

        def placement(h):
            calls.append(1)
            return "match" if len(calls) == 1 else "differs"
        e, site, p = self.run_with([b"never"], probe_placement=placement)
        self.assertEqual(e.cause, "RUNNER.CUSTODY")
        self.assertIn(b"CAUSE=RUNNER.CUSTODY", self.read("receipts", "S1--.txt"))
        self.assertNotIn(b"Enter", p.transcript())

    def test_a_custody_read_that_raises_after_s0_is_s1s_and_s10_still_finishes(self):
        """The probe of the 2b r2.1 review: placement matches at S0, then
        every later read raises. The read after S0 is S1's (its receipt,
        CREDENTIALS.UNCLASSIFIED, rc 3); S10's read raises too, and S10
        still writes its FAIL receipt with every custody fact UNOBSERVED,
        the final manifest and a NOT ELIGIBLE summary, and SUMS verifies."""
        import json
        import a2_record
        calls = []

        def placement(h):
            calls.append(1)
            if len(calls) == 1:
                return "match"
            raise RuntimeError("placement probe broke")
        e, site, p = self.run_with([b"never"], probe_placement=placement)
        self.assertEqual((e.cause, e.rc), ("CREDENTIALS.UNCLASSIFIED", 3))
        self.assertEqual(len(calls), 3)
        s1 = self.read("receipts", "S1--.txt")
        self.assertIn(b"CAUSE=CREDENTIALS.UNCLASSIFIED", s1)
        self.assertEqual(self.rc_of("S1--.txt"), 3)
        for k in (b"CUSTODY_LOCKS", b"CUSTODY_PLACEMENT", b"CUSTODY_STOP"):
            self.assertIn(k + b"=UNOBSERVED", s1)        # 5.3b: the read-back S1 could not make
        s10 = self.read("receipts", "S10--.txt")
        self.assertIn(b"RESULT=FAIL", s10)
        self.assertIn(b"CAUSE=SUMMARY.UNCLASSIFIED", s10)
        self.assertEqual(self.rc_of("S10--.txt"), 3)
        for k in (b"CUSTODY_LOCKS", b"CUSTODY_PLACEMENT", b"CUSTODY_STOP"):
            self.assertIn(k + b"=UNOBSERVED", s10)
        self.assertEqual(json.loads(self.read("manifest.json"))["state"], "final")
        self.assertTrue(self.read("summary.txt").rstrip(b"\n").splitlines()[-1].startswith(b"NOT ELIGIBLE: "))
        self.assertNotIn(b"Enter", p.transcript())
        fd = os.open(os.path.join(self.w.home, "alpha2-work", "runs", self.rid), a2_record.DIR_FLAGS)
        try:
            self.assertEqual("SUMS sha256 " + a2_record.verify_sums(fd), site.out.getvalue().splitlines()[-1])
        finally:
            os.close(fd)

    def test_a_custody_read_that_raises_only_at_s10_makes_an_rc_2_stop_rc_3(self):
        """S1 refuses with rc 2, then S10's read raises: S10's FAIL receipt
        carries SUMMARY.UNCLASSIFIED and the run's rc becomes 3 (3.4)."""
        calls = []

        def placement(h):
            calls.append(1)
            if len(calls) <= 2:
                return "match"
            raise RuntimeError("placement probe broke")
        e, site, p = self.run_with([b"val-one-x9", b"val-two-x9", b"val-thr-x9"], form_rules=None,
                                   probe_placement=placement)
        self.assertEqual((e.cause, e.rc), ("SUMMARY.UNCLASSIFIED", 3))
        self.assertIn(b"CAUSE=CREDENTIALS.FORM", self.read("receipts", "S1--.txt"))
        s10 = self.read("receipts", "S10--.txt")
        self.assertIn(b"CAUSE=SUMMARY.UNCLASSIFIED", s10)
        self.assertIn(b"CUSTODY_PLACEMENT=UNOBSERVED", s10)
        self.assertTrue(self.read("summary.txt").rstrip(b"\n").splitlines()[-1].startswith(b"NOT ELIGIBLE: "))

    def test_an_interrupt_in_the_s10_custody_read_still_finishes_the_record(self):
        """The probe of the 2b r2.2 review: S0 and the read after S0 pass,
        S1 refuses with rc 2, then S10's custody read raises
        KeyboardInterrupt. S10 still writes its FAIL receipt
        (SUMMARY.UNCLASSIFIED, rc 3, every custody fact UNOBSERVED), the
        final manifest and the summary; SUMS ends at summary.txt, and the
        terminal's last line is the verified SUMS sha."""
        import json
        import a2_record
        calls = []

        def placement(h):
            calls.append(1)
            if len(calls) <= 2:
                return "match"
            raise KeyboardInterrupt
        e, site, p = self.run_with([b"val-one-x9", b"val-two-x9", b"val-thr-x9"], form_rules=None,
                                   probe_placement=placement)
        self.assertEqual((e.cause, e.rc), ("SUMMARY.UNCLASSIFIED", 3))
        self.assertEqual(len(calls), 3)
        self.assertIn(b"CAUSE=CREDENTIALS.FORM", self.read("receipts", "S1--.txt"))
        s10 = self.read("receipts", "S10--.txt")
        self.assertIn(b"RESULT=FAIL", s10)
        self.assertIn(b"CAUSE=SUMMARY.UNCLASSIFIED", s10)
        self.assertEqual(self.rc_of("S10--.txt"), 3)
        for k in (b"CUSTODY_LOCKS", b"CUSTODY_PLACEMENT", b"CUSTODY_STOP"):
            self.assertIn(k + b"=UNOBSERVED", s10)
        self.assertEqual(json.loads(self.read("manifest.json"))["state"], "final")
        self.assertTrue(self.read("summary.txt").rstrip(b"\n").splitlines()[-1].startswith(b"NOT ELIGIBLE: "))
        self.assertEqual(self.read("SUMS").rstrip(b"\n").splitlines()[-1].split(b" ")[-1], b"summary.txt")
        fd = os.open(os.path.join(self.w.home, "alpha2-work", "runs", self.rid), a2_record.DIR_FLAGS)
        try:
            self.assertEqual("SUMS sha256 " + a2_record.verify_sums(fd), site.out.getvalue().splitlines()[-1])
        finally:
            os.close(fd)

    def _stop_in_s1(self, sig):
        """A stop signal in S1, outside the prompt (during the live check):
        S1's UNCLASSIFIED with its custody facts, then a finished record,
        and the test's own handler back after the run."""
        import signal
        own = self.own_stop_handlers()
        e, site, p = self.run_with(list(self.SECRETS), live_check=lambda k: signal.raise_signal(sig))
        self.assertEqual((e.cause, e.rc), ("CREDENTIALS.UNCLASSIFIED", 3))
        self.assertIn(b"CAUSE=CREDENTIALS.UNCLASSIFIED", self.read("receipts", "S1--.txt"))
        self.assertIn(b"CUSTODY_PLACEMENT=match", self.read("receipts", "S1--.txt"))
        self.assertEqual(self.rc_of("S1--.txt"), 3)
        self.finished(site)
        self.assertIs(signal.getsignal(sig), own)

    def test_sigterm_outside_the_prompt_finishes_the_record(self):
        import signal
        self._stop_in_s1(signal.SIGTERM)

    def test_sighup_outside_the_prompt_finishes_the_record(self):
        import signal
        self._stop_in_s1(signal.SIGHUP)

    def test_sigquit_outside_the_prompt_finishes_the_record(self):
        import signal
        self._stop_in_s1(signal.SIGQUIT)

    def test_sigint_outside_the_prompt_finishes_the_record(self):
        import signal
        self._stop_in_s1(signal.SIGINT)

    def test_a_stop_in_s0_is_s0s_unclassified_and_finishes_the_record(self):
        import signal
        own = self.own_stop_handlers()
        e, site, p = self.run_with([b"never"], probe_tools=lambda *a: signal.raise_signal(signal.SIGTERM))
        self.assertEqual((e.cause, e.rc), ("PREFLIGHT.UNCLASSIFIED", 3))
        self.assertEqual(self.rc_of("S0--.txt"), 3)
        self.finished(site)
        self.assertNotIn(b"Enter", p.transcript())
        self.assertIs(signal.getsignal(signal.SIGTERM), own)

    def _stop_in_s10(self, **over):
        """A stop signal raised as S10 starts: held, so S10 still finishes."""
        import signal
        from unittest import mock
        import a2_s10
        self.own_stop_handlers()
        real = a2_s10.run_s10

        def s10(*a, **k):
            signal.raise_signal(signal.SIGTERM)
            return real(*a, **k)
        with mock.patch.object(a2_s10, "run_s10", s10):
            e, site, p = self.run_with(**over)
        self.finished(site)
        return e

    def test_a_stop_during_s10_is_held_and_the_run_keeps_its_own_rc(self):
        """S1 refuses with rc 2, then a stop lands as S10 starts. S10
        finishes, and the run ends with S1's cause and rc 2: a stop held
        once the closeout has begun keeps the run's own cause and rc, so
        the exit code agrees with the sealed record (the operator's
        ruling)."""
        e = self._stop_in_s10(answers=[b"val-one-x9", b"val-two-x9", b"val-thr-x9"], form_rules=None)
        self.assertEqual((e.cause, e.rc), ("CREDENTIALS.FORM", 2))
        self.assertIn(b"RESULT=PASS", self.read("receipts", "S10--.txt"))

    def test_a_stop_during_s10_after_a_passing_s1_is_held(self):
        e = self._stop_in_s10(answers=list(self.SECRETS))
        self.assertEqual((e.cause, e.rc), ("RUNNER.UNCLASSIFIED", 3))     # S2 is not built
        self.assertIn(b"RESULT=PASS", self.read("receipts", "S1--.txt"))

    def test_a_second_stop_while_s1_clears_its_values_is_held(self):
        """The first stop raises; a second one, landing while S1 zeroes the
        values it read, is held, so the zeroing completes."""
        import signal
        from unittest import mock
        self.own_stop_handlers()
        real = a2_s1.Held.clear
        done = []

        def clear(self_):
            signal.raise_signal(signal.SIGHUP)
            real(self_)
            done.append(1)
        with mock.patch.object(a2_s1.Held, "clear", clear):
            e, site, p = self.run_with(list(self.SECRETS),
                                       live_check=lambda k: signal.raise_signal(signal.SIGTERM))
        self.assertTrue(done)
        self.assertEqual((e.cause, e.rc), ("CREDENTIALS.UNCLASSIFIED", 3))
        self.finished(site)

    def test_a_stop_while_s1_gives_back_the_handlers_finishes_the_record(self):
        """Opus's r2.2 window: a TERM that lands while the prompt gives the
        handlers back. It is held under the mask, then taken by the
        runner's handler (not the default action, which would end the
        process): S1's UNCLASSIFIED, then a finished record."""
        import signal
        from unittest import mock
        own = self.own_stop_handlers()
        real = a2_s1._Signals._restore
        sent = []

        def restore(self_):
            if not sent:
                sent.append(1)
                signal.raise_signal(signal.SIGTERM)
            return real(self_)
        with mock.patch.object(a2_s1._Signals, "_restore", restore):
            e, site, p = self.run_with(list(self.SECRETS))
        self.assertEqual(sent, [1])
        self.assertEqual((e.cause, e.rc), ("CREDENTIALS.UNCLASSIFIED", 3))
        self.finished(site)
        self.assertIs(signal.getsignal(signal.SIGTERM), own)

    def hand_back_hooks(self, before_block=None, after_block=None, after_restore=None):
        """Hooks in the runner's hand-back (`_Stops.__exit__`) and nowhere
        else: `before_block()` and `after_block()` run just before and just
        after its block of the stop signals, `after_restore(n)` just after
        the nth caller handler is given back. Returns the signals given
        back, in order."""
        import signal
        import sys
        import a2_main
        code = a2_main._Stops.__exit__.__code__
        real_mask, real_signal = signal.pthread_sigmask, signal.signal
        restores = []

        def mask(how, sigs):
            hit = (sys._getframe(1).f_code is code and how == signal.SIG_BLOCK
                   and set(sigs) == set(a2_s1.MASKED))
            if hit and before_block:
                before_block()
            old = real_mask(how, sigs)
            if hit and after_block:
                after_block()
            return old

        def put(sig, handler):
            old = real_signal(sig, handler)
            if sys._getframe(1).f_code is code:
                restores.append(sig)
                if after_restore:
                    after_restore(len(restores))
            return old
        signal.pthread_sigmask, signal.signal = mask, put
        self.addCleanup(setattr, signal, "pthread_sigmask", real_mask)
        self.addCleanup(setattr, signal, "signal", real_signal)
        return restores

    def caller_handlers(self):
        """The test as the runner's caller: its own handler on each stop
        signal, which records each call in self.calls and, inside the call,
        checks what the caller sees by then: all four of its handlers back,
        its own mask, and a finished record. Returns the handler and the
        mask."""
        import signal
        self.calls = []
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())

        def caller(signum, frame):
            self.calls.append(signum)
            for s in a2_s1.STOP_SIGNALS:
                self.assertIs(signal.getsignal(s), caller)
            self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, ()), mask)
            self.finished(self.site_now)
        for sig in a2_s1.STOP_SIGNALS:
            self.addCleanup(signal.signal, sig, signal.signal(sig, caller))
        return caller, mask

    FORM_FAILS = [b"val-one-x9", b"val-two-x9", b"val-thr-x9"]

    def _stop_in_the_hand_back(self, at, sig):
        """Option B: the run hands stop ownership to its caller at the
        hand-back's block. A stop raised before the block (`at` "before")
        is the run's and is held. One raised just after it ("block"), or
        after the nth caller handler is given back (`at` 1 to 4), is the
        caller's: its handler runs once, with all four handlers and its
        mask back and the record finished. Either way the run ends with
        its own cause and rc."""
        import signal
        import a2_main
        caller, mask = self.caller_handlers()
        send = lambda: signal.raise_signal(sig)
        hooks = {"before": dict(before_block=send), "block": dict(after_block=send)}.get(
            at, dict(after_restore=lambda n: n == at and send()))
        back = self.hand_back_hooks(**hooks)
        stops = a2_main._Stops()
        e, site, p = self.run_with(self.FORM_FAILS, stops=stops, form_rules=None)
        self.assertEqual(sorted(back), sorted(a2_s1.STOP_SIGNALS))
        for s in a2_s1.STOP_SIGNALS:
            self.assertIs(signal.getsignal(s), caller)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, ()), mask)
        if at == "before":
            self.assertEqual((self.calls, stops.pending), ([], sig))
        else:
            self.assertEqual((self.calls, stops.pending), ([sig], None))
        self.assertEqual((e.cause, e.rc), ("CREDENTIALS.FORM", 2))
        self.finished(site)

    def _hand_back_fails(self, **hooks):
        """A hand-back that fails inside: the failure is raised from run(),
        the caller's mask is back, no stop reached the caller, and the
        record, finished before the hand-back, stays finished."""
        import signal
        import a2_main
        caller, mask = self.caller_handlers()
        self.hand_back_hooks(**hooks)
        site, p = self.site_for(self.FORM_FAILS, form_rules=None)
        with self.assertRaises(RuntimeError):
            a2_main.run(self.rid, ["--loop", "L2"], site)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, ()), mask)
        self.assertEqual(self.calls, [])
        self.finished(site)

    def test_a_restore_that_fails_still_gives_back_the_callers_mask(self):
        def fail(n):
            if n == 2:
                raise RuntimeError("restore failed")
        self._hand_back_fails(after_restore=fail)

    def test_a_block_that_fails_once_in_effect_still_gives_back_the_callers_mask(self):
        def fail():
            raise RuntimeError("block failed")
        self._hand_back_fails(after_block=fail)

    def _main_with_a_sigint(self, **hooks):
        """main() as the process runs it: SIGINT is Python's
        default_int_handler. Returns main()'s exit code and the site."""
        import signal
        import a2_main
        self.addCleanup(signal.signal, signal.SIGINT, signal.signal(signal.SIGINT, signal.default_int_handler))
        self.hand_back_hooks(**hooks)
        site, p = self.site_for(self.FORM_FAILS, form_rules=None)
        rc = a2_main.main(["--runner", "--run-id", self.rid, "--loop", "L2"], site.installer_sha, site.entry, site)
        self.assertIs(signal.getsignal(signal.SIGINT), signal.default_int_handler)
        return rc, site

    def test_a_sigint_after_the_hand_back_ends_main_as_an_interrupt(self):
        """Opus's condition b1: the SIGINT is the process's own, after a
        finished record. main() exits 130 and prints nothing after the
        SUMS line (finished() checks the terminal's last line)."""
        import signal
        rc, site = self._main_with_a_sigint(after_block=lambda: signal.raise_signal(signal.SIGINT))
        self.assertEqual(rc, 128 + signal.SIGINT)
        self.finished(site)

    def test_a_sigint_before_the_hand_back_is_held_and_main_reports_the_run(self):
        import signal
        rc, site = self._main_with_a_sigint(before_block=lambda: signal.raise_signal(signal.SIGINT))
        lines = site.out.getvalue().splitlines()
        at = max(i for i, ln in enumerate(lines) if ln.startswith("SUMS sha256 "))
        self.assertEqual((rc, lines[at + 1]), (2, "CAUSE=CREDENTIALS.FORM"))

    def test_a_second_stop_at_the_prompts_clear_after_a_stop_before_the_hold(self):
        """Opus's p2c r2 probe, with the real guard: a TERM after the
        second value is read and before the session holds it, then an INT
        at the entry of the prompt's clear (`_zero_all`). The session's
        hand-back has already zeroed every value read, under the same
        mask that gives S1's handlers back, so the INT finds nothing left
        to cut. The mask is the caller's, and the record is finished."""
        import signal
        from unittest import mock
        self.own_stop_handlers()
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        reads, entered = [], []
        real_read, real_zero_all = a2_s1._read_line, a2_s1._zero_all

        def read(fd, *a):
            v = real_read(fd, *a)
            reads.append(v)
            if len(reads) == 2:
                signal.raise_signal(signal.SIGTERM)
            return v

        def zero_all(values):
            entered.append(1)
            if len(entered) == 1:
                signal.raise_signal(signal.SIGINT)
            return real_zero_all(values)
        with mock.patch.object(a2_s1, "_read_line", read), mock.patch.object(a2_s1, "_zero_all", zero_all):
            e, site, p = self.run_with(list(self.SECRETS))
        self.assertEqual((len(reads), entered), (2, [1]))
        for v in reads:
            self.assertTrue(v)
            self.assertEqual(v, bytearray(len(v)))
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, ()), mask)
        self.assertEqual((e.cause, e.rc), ("CREDENTIALS.UNCLASSIFIED", 3))
        self.finished(site)

    def _stops_as_a_read_prompt_ends(self, first):
        """All three values are read and held by a guard that forgets them
        on release, so only the prompt's own clear can zero them. `first`
        places the first stop as the session's hand-back starts. Every
        value read ends zero, and the record is finished."""
        import signal
        from unittest import mock
        self.own_stop_handlers()
        reads = []
        real_read = a2_s1._read_line

        def read(fd, *a):
            v = real_read(fd, *a)
            reads.append(v)
            return v
        with mock.patch.object(a2_s1, "_read_line", read), first():
            e, site, p = self.run_with(list(self.SECRETS), guard=Forgetful())
        self.assertEqual(len(reads), 3)
        for v in reads:
            self.assertTrue(v)
            self.assertEqual(v, bytearray(len(v)))
        self.assertEqual((e.cause, e.rc), ("CREDENTIALS.UNCLASSIFIED", 3))
        self.finished(site)

    def test_a_stop_as_a_read_prompt_gives_back_the_handlers_is_taken_after_the_clear(self):
        """A TERM while the session gives S1's handlers back (masked): it
        reaches the runner's handler once they are back, and the prompt's
        clear still zeroes every value."""
        import signal
        from unittest import mock
        real = a2_s1._Signals._restore

        def restore(self_):
            signal.raise_signal(signal.SIGTERM)
            return real(self_)
        self._stops_as_a_read_prompt_ends(lambda: mock.patch.object(a2_s1._Signals, "_restore", restore))

    def test_a_second_stop_while_a_read_prompt_clears_is_taken_after_the_clear(self):
        """A TERM taken by S1's own handler just before the session's
        hand-back blocks the stops (the session itself had ended well), so
        recorded, then an INT on the clear's first overwrite: the clear
        runs with the stops blocked, so every value is zero before the INT
        is taken."""
        import signal
        from unittest import mock
        real_exit, real_mask, real_zero = a2_s1._Signals.__exit__, a2_s1._mask, a2_s1._zero
        armed, zeros = [], []

        def exit_(self_, *exc):
            armed.append(1)
            return real_exit(self_, *exc)

        def mask(how, sigs):
            if armed == [1] and how == signal.SIG_BLOCK and set(sigs) == set(a2_s1.MASKED):
                armed.append(2)
                signal.raise_signal(signal.SIGTERM)
            return real_mask(how, sigs)

        def zero(buf):
            zeros.append(1)
            if len(zeros) == 1:
                signal.raise_signal(signal.SIGINT)
            real_zero(buf)

        import contextlib

        @contextlib.contextmanager
        def first():
            with mock.patch.object(a2_s1._Signals, "__exit__", exit_), \
                    mock.patch.object(a2_s1, "_mask", mask), mock.patch.object(a2_s1, "_zero", zero):
                yield
        self._stops_as_a_read_prompt_ends(first)
        self.assertEqual(armed, [1, 2])

    def test_a_block_that_fails_in_the_prompts_hand_back_leaves_the_callers_mask(self):
        """Opus's condition b3 for `_uninterrupted`: its block of MASKED
        takes effect and then the call fails. The caller's mask is put back,
        the failure is S1's UNCLASSIFIED, the prompt's own clear zeroes
        every value read, and the record is finished. S1's handlers are not
        given back (the step that would have done it never ran): the
        runner then gives the caller's four stop handlers back."""
        import signal
        from unittest import mock
        self.own_stop_handlers()
        self.addCleanup(signal.signal, signal.SIGTSTP, signal.getsignal(signal.SIGTSTP))
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        real_exit, real_mask, real_read = a2_s1._Signals.__exit__, a2_s1._mask, a2_s1._read_line
        armed, reads = [], []

        def exit_(self_, *exc):
            armed.append(1)
            return real_exit(self_, *exc)

        def mask_(how, sigs):
            old = real_mask(how, sigs)
            if armed == [1] and how == signal.SIG_BLOCK and set(sigs) == set(a2_s1.MASKED):
                armed.append(2)
                raise RuntimeError("block failed")
            return old

        def read(fd, *a):
            v = real_read(fd, *a)
            reads.append(v)
            return v
        with mock.patch.object(a2_s1._Signals, "__exit__", exit_), mock.patch.object(a2_s1, "_mask", mask_), \
                mock.patch.object(a2_s1, "_read_line", read):
            e, site, p = self.run_with(list(self.SECRETS), guard=Forgetful())
        self.assertEqual((armed, len(reads)), ([1, 2], 3))
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, ()), mask)
        for v in reads:
            self.assertEqual(v, bytearray(len(v)))
        self.assertEqual((e.cause, e.rc), ("CREDENTIALS.UNCLASSIFIED", 3))
        self.finished(site)

    # -- option A: S1's handlers raise only during a read; elsewhere a stop is recorded

    def _watch_the_prompt(self):
        """Records, as the prompt returns or raises, the handler on each
        signal S1 takes over; returns the patch and the list."""
        import signal
        from unittest import mock
        real = a2_s1.prompt
        after = []

        def prompt(*a, **k):
            try:
                return real(*a, **k)
            finally:
                after.append({s: signal.getsignal(s) for s in a2_s1.MASKED})
        return mock.patch.object(a2_s1, "prompt", prompt), after

    def _at_entry(self, owner, name, sig, armed=None, times=1):
        """A patch that raises `sig` on entry to owner.name, the first
        `times` calls made while `armed()` holds (always, without it)."""
        import signal
        from unittest import mock
        real = getattr(owner, name)
        sent = []

        def entry(*a, **k):
            if len(sent) < times and (armed is None or armed()):
                sent.append(sig)
                signal.raise_signal(sig)
            return real(*a, **k)
        return mock.patch.object(owner, name, entry), sent

    def _reads(self):
        from unittest import mock
        real = a2_s1._read_line
        reads = []

        def read(fd, *a):
            v = real(fd, *a)
            reads.append(v)
            return v
        return mock.patch.object(a2_s1, "_read_line", read), reads

    def _after_s10s_receipt(self, sig):
        """A patch raising `sig` just after S10's receipt line is in SUMS."""
        import signal
        from unittest import mock
        import a2_record
        real = a2_record.Run._append_sums
        sent = []

        def append(run, at, data):
            real(run, at, data)
            if at == "receipts/S10--.txt" and not sent:
                sent.append(sig)
                signal.raise_signal(sig)
        return mock.patch.object(a2_record.Run, "_append_sums", append), sent

    def test_a_stop_at_the_prompts_hand_back_then_one_in_the_closeout(self):
        """Opus's r3 blocker, two stops with the real guard: an INT as the
        prompt's hand-back (`_Signals.__exit__`) is entered, then a TERM
        just after S10's receipt is in SUMS. The INT is recorded, not
        raised, so the hand-back completes: after the prompt every stop
        handler is the runner's again, and TSTP the caller's. The prompt
        then refuses for the recorded stop (as a stop at the read does),
        the TERM is held by the runner, and the record is finished."""
        import contextlib
        import signal
        import a2_main
        own = self.own_stop_handlers()
        tstp = signal.getsignal(signal.SIGTSTP)
        stops = a2_main._Stops()
        watch, after = self._watch_the_prompt()
        at_exit, sent = self._at_entry(a2_s1._Signals, "__exit__", signal.SIGINT)
        late, sent2 = self._after_s10s_receipt(signal.SIGTERM)
        with contextlib.ExitStack() as st:
            for p_ in (watch, at_exit, late):
                st.enter_context(p_)
            e, site, p = self.run_with(list(self.SECRETS), stops=stops)
        self.assertEqual((sent, sent2), ([signal.SIGINT], [signal.SIGTERM]))
        self.assertEqual(len(after), 1)
        for s in a2_s1.STOP_SIGNALS:
            self.assertEqual(after[0][s], stops._handler)
        self.assertEqual(after[0][signal.SIGTSTP], tstp)
        self.assertEqual(stops.pending, signal.SIGTERM)
        self.assertEqual((e.cause, e.rc), ("CREDENTIALS.NO_ECHO", 2))
        self.assertIn(b"CAUSE=CREDENTIALS.NO_ECHO", self.read("receipts", "S1--.txt"))
        self.finished(site)
        for s in a2_s1.STOP_SIGNALS:
            self.assertIs(signal.getsignal(s), own)

    def _three_stops(self, guard):
        """Opus's r3 secret-clearing sequence: a TERM after the second value
        is read and before it is held (outside the read), an INT as the
        prompt's hand-back is entered, then a HUP as the prompt's own
        clear (`_zero_all`) is entered."""
        import contextlib
        import signal
        from unittest import mock
        self.own_stop_handlers()
        watch, reads = self._reads()
        at_exit, sent = self._at_entry(a2_s1._Signals, "__exit__", signal.SIGINT)
        at_zero, sent2 = self._at_entry(a2_s1, "_zero_all", signal.SIGHUP)
        real_hold = type(guard).hold
        holds = []

        def hold(self_, v):
            holds.append(1)
            if len(holds) == 2:
                signal.raise_signal(signal.SIGTERM)
            return real_hold(self_, v)
        with contextlib.ExitStack() as st:
            for p_ in (watch, at_exit, at_zero, mock.patch.object(type(guard), "hold", hold)):
                st.enter_context(p_)
            e, site, p = self.run_with(list(self.SECRETS), guard=guard)
        self.assertEqual((sent, sent2), ([signal.SIGINT], [signal.SIGHUP]))
        # the recorded TERM ends the session before its next read: the
        # third value is neither asked for nor read
        self.assertEqual(len(reads), 2)
        self.assertEqual(p.transcript().count(b"(not echoed): "), 2)
        for v in reads:
            self.assertTrue(v)
            self.assertEqual(v, bytearray(len(v)))
        # the HUP reaches the runner's handler, back by then: S1's UNCLASSIFIED
        self.assertEqual((e.cause, e.rc), ("CREDENTIALS.UNCLASSIFIED", 3))
        self.finished(site)

    def test_three_stops_around_the_prompts_hand_back_leave_every_value_zero(self):
        self._three_stops(a2_guard.OutputGuard())

    def test_three_stops_leave_every_value_zero_by_the_prompts_own_clear(self):
        """The same with a guard that forgets its values on release, so only
        the prompt's clear can zero them: the hand-back's masked clear does,
        before the HUP cuts `_zero_all` at its entry."""
        self._three_stops(Forgetful())

    def test_a_stop_at_the_hand_back_and_one_at_the_clear_leave_every_value_zero(self):
        """The session ends well (all three values read and held), an INT
        is recorded as the hand-back is entered, and a HUP lands as the
        prompt's clear is entered. The hand-back's masked step zeroes every
        value for the recorded stop, so the HUP, taken by the runner, finds
        nothing left set."""
        import contextlib
        import signal
        self.own_stop_handlers()
        watch, reads = self._reads()
        at_exit, sent = self._at_entry(a2_s1._Signals, "__exit__", signal.SIGINT)
        at_zero, sent2 = self._at_entry(a2_s1, "_zero_all", signal.SIGHUP)
        with contextlib.ExitStack() as st:
            for p_ in (watch, at_exit, at_zero):
                st.enter_context(p_)
            e, site, p = self.run_with(list(self.SECRETS), guard=Forgetful())
        self.assertEqual((sent, sent2, len(reads)), ([signal.SIGINT], [signal.SIGHUP], 3))
        for v in reads:
            self.assertEqual(v, bytearray(len(v)))
        self.assertEqual((e.cause, e.rc), ("CREDENTIALS.UNCLASSIFIED", 3))
        self.finished(site)

    def test_a_failed_hand_back_then_a_stop_in_the_prompts_clear_leaves_every_value_zero(self):
        """The session ends well, so the hand-back clears nothing, and its
        `_restore` puts the runner's handlers back and then fails. The
        prompt's own clear (`_zero_all`) is then the only thing that zeroes
        the values, and the run's first stop, an INT on its first
        overwrite, goes to the runner's handler, which raises. The clear's
        mask holds the INT until every value is zero (a guard that forgets
        on release, so no other clear can do it)."""
        import contextlib
        import signal
        from unittest import mock
        self.own_stop_handlers()
        watch, reads = self._reads()
        real_restore, real_zero_all = a2_s1._Signals._restore, a2_s1._zero_all
        failed, clearing = [], []

        def restore(self_):
            real_restore(self_)
            if not failed:
                failed.append(1)
                raise OSError("restore")

        def zero_all(values):
            clearing.append(1)
            return real_zero_all(values)
        at_zero, sent = self._at_entry(a2_s1, "_zero", signal.SIGINT, lambda: clearing == [1])
        with contextlib.ExitStack() as st:
            for p_ in (mock.patch.object(a2_s1._Signals, "_restore", restore),
                       mock.patch.object(a2_s1, "_zero_all", zero_all), at_zero, watch):
                st.enter_context(p_)
            e, site, p = self.run_with(list(self.SECRETS), guard=Forgetful())
        self.assertEqual((failed, sent, len(reads), clearing), ([1], [signal.SIGINT], 3, [1]))
        for v in reads:
            self.assertTrue(v)
            self.assertEqual(v, bytearray(len(v)))
        self.assertEqual((e.cause, e.rc), ("CREDENTIALS.UNCLASSIFIED", 3))
        self.finished(site)

    #: Each function of the prompt's hand-back, with whether a stop on its
    #: entry comes before the hand-back's block (recorded by S1's handler,
    #: then refused as a stop at the read is) or after it (pending until
    #: the runner's handlers are back, then taken by the runner).
    HAND_BACK = (("__exit__", "before"), ("_uninterrupted", "before"), ("_mask", "before"),
                 ("_clear", "after"), ("_restore", "after"))

    def _stop_at_a_hand_back_entry(self, name, when, answers):
        """A TERM on entry to one function of the prompt's hand-back, the
        first time it is called inside `_Signals.__exit__`. Whichever side
        of the block it lands on, the hand-back completes: after the prompt
        every stop handler is the runner's and TSTP the caller's, every
        value read is zero (a guard that forgets on release, so the
        prompt's own clear did it), the mask is back, and the record is
        finished."""
        import contextlib
        import signal
        from unittest import mock
        import a2_main
        own = self.own_stop_handlers()
        tstp = signal.getsignal(signal.SIGTSTP)
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        stops = a2_main._Stops()
        watch, after = self._watch_the_prompt()
        reads_patch, reads = self._reads()
        real_exit = a2_s1._Signals.__exit__
        inside = []

        def exit_(self_, *exc):
            inside.append(1)
            try:
                return real_exit(self_, *exc)
            finally:
                inside.append(0)
        owner = a2_s1._Signals if name in ("__exit__", "_restore") else a2_s1
        with contextlib.ExitStack() as st:
            if name == "__exit__":
                hook, sent = self._at_entry(owner, name, signal.SIGTERM)
            else:
                st.enter_context(mock.patch.object(a2_s1._Signals, "__exit__", exit_))
                hook, sent = self._at_entry(owner, name, signal.SIGTERM, lambda: inside[-1:] == [1])
            for p_ in (hook, watch, reads_patch):
                st.enter_context(p_)
            e, site, p = self.run_with(answers, stops=stops, guard=Forgetful())
        self.assertEqual(sent, [signal.SIGTERM])
        self.assertEqual(len(after), 1)
        for s in a2_s1.STOP_SIGNALS:
            self.assertEqual(after[0][s], stops._handler)
        self.assertEqual(after[0][signal.SIGTSTP], tstp)
        for v in reads:
            self.assertEqual(v, bytearray(len(v)))
        want = ("CREDENTIALS.NO_ECHO", 2) if when == "before" else ("CREDENTIALS.UNCLASSIFIED", 3)
        self.assertEqual((e.cause, e.rc), want)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, ()), mask)
        self.finished(site)
        for s in a2_s1.STOP_SIGNALS:
            self.assertIs(signal.getsignal(s), own)


    def test_a_stop_as_a_value_is_asked_for_ends_the_session_before_its_read(self):
        """A TERM while the third value's prompt is being checked and shown
        (after the session's check for a recorded stop, before the read):
        it is recorded, and the read refuses on entry, so the third value
        is never read. The run refuses as for a stop at the read."""
        import signal
        from unittest import mock
        self.own_stop_handlers()
        watch, reads = self._reads()
        real_check = a2_guard.OutputGuard.check
        asked = []

        def check(self_, text):
            if isinstance(text, str) and text.startswith("Enter "):
                asked.append(1)
                if len(asked) == 3:
                    signal.raise_signal(signal.SIGTERM)
            return real_check(self_, text)
        with watch, mock.patch.object(a2_guard.OutputGuard, "check", check):
            e, site, p = self.run_with(list(self.SECRETS))
        self.assertEqual((len(asked), len(reads)), (3, 2))
        for v in reads:
            self.assertEqual(v, bytearray(len(v)))
        self.assertEqual((e.cause, e.rc), ("CREDENTIALS.NO_ECHO", 2))
        self.finished(site)

    def test_a_stop_the_caller_blocks_stays_pending_for_the_caller(self):
        """The design note's T4 (Opus's note a): the caller blocks TERM, and
        a TERM is raised just after the runner's hand-back blocks the stops.
        It stays pending after run(): the caller's handler is not called,
        the mask is the caller's, and the record is finished."""
        import signal
        import a2_main
        caller, _ = self.caller_handlers()
        signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGTERM])
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        self.hand_back_hooks(after_block=lambda: signal.raise_signal(signal.SIGTERM))
        stops = a2_main._Stops()
        e, site, p = self.run_with(self.FORM_FAILS, stops=stops, form_rules=None)
        pending = signal.sigpending()
        # discard the pending TERM before the mask goes back: a pending
        # signal whose action is set to ignore is discarded
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, caller)
        self.assertIn(signal.SIGTERM, pending)
        self.assertEqual(self.calls, [])
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, ()), mask)
        for s in a2_s1.STOP_SIGNALS:
            self.assertIs(signal.getsignal(s), caller)
        self.assertEqual((e.cause, e.rc, stops.pending), ("CREDENTIALS.FORM", 2, None))
        self.finished(site)
        self.assertNotIn(signal.SIGTERM, signal.sigpending())

    def _stop_after_the_sums_line(self, path, **over):
        """Opus's p2c window: a TERM raised inside the receipt write, just
        after the SUMS line for `path`. The stop is taken once the whole
        write is complete, so the receipt is in SUMS and in the manifest,
        and the record is finished."""
        import json
        import signal
        from unittest import mock
        import a2_record
        self.own_stop_handlers()
        real = a2_record.Run._append_sums
        sent = []

        def append(run, at, data):
            real(run, at, data)
            if at == path and not sent:
                sent.append(1)
                signal.raise_signal(signal.SIGTERM)
        with mock.patch.object(a2_record.Run, "_append_sums", append):
            e, site, p = self.run_with(**over)
        self.assertEqual(sent, [1])
        self.finished(site)
        self.assertIn(path, [st["receipt"] for st in json.loads(self.read("manifest.json"))["stages"]])
        return e

    def test_a_stop_inside_s0s_receipt_write_finishes_the_record(self):
        e = self._stop_after_the_sums_line("receipts/S0--.txt", answers=list(self.SECRETS))
        self.assertEqual((e.cause, e.rc), ("PREFLIGHT.UNCLASSIFIED", 3))
        self.assertEqual(self.rc_of("S0--.txt"), 0)

    def test_a_stop_inside_s1s_pass_receipt_write_finishes_the_record(self):
        e = self._stop_after_the_sums_line("receipts/S1--.txt", answers=list(self.SECRETS))
        self.assertEqual((e.cause, e.rc), ("CREDENTIALS.UNCLASSIFIED", 3))
        self.assertIn(b"RESULT=PASS", self.read("receipts", "S1--.txt"))

    def test_a_stop_inside_s1s_fail_receipt_write_finishes_the_record(self):
        e = self._stop_after_the_sums_line("receipts/S1--.txt",
                                           answers=[b"val-one-x9", b"val-two-x9", b"val-thr-x9"], form_rules=None)
        self.assertEqual((e.cause, e.rc), ("CREDENTIALS.UNCLASSIFIED", 3))
        self.assertIn(b"CAUSE=CREDENTIALS.FORM", self.read("receipts", "S1--.txt"))

    def _two_stops_while_s1_reads(self, before_hold):
        """Opus's p2c probe: a TERM in the prompt session once the second
        value is read, then an INT on the first overwrite. Every value read
        is zero, by the prompt's own clear: this guard forgets its values on
        release, so the guard's overwrite is not what clears them. With
        `before_hold`, the TERM lands before the session has held the
        value."""
        import signal
        from unittest import mock
        import a2_guard
        self.own_stop_handlers()
        reads, zeros = [], []
        real_read, real_zero = a2_s1._read_line, a2_s1._zero

        def read(fd, *a):
            v = real_read(fd, *a)
            reads.append(v)
            if before_hold and len(reads) == 2:
                signal.raise_signal(signal.SIGTERM)
            return v

        def zero(buf):
            zeros.append(1)
            if len(zeros) == 1:
                signal.raise_signal(signal.SIGINT)
            real_zero(buf)

        class Forgetful(a2_guard.OutputGuard):
            def hold(self_, v):
                super().hold(v)
                if not before_hold and len(reads) == 2:
                    signal.raise_signal(signal.SIGTERM)

            def release_all(self_):
                self_._held = []
        with mock.patch.object(a2_s1, "_read_line", read), mock.patch.object(a2_s1, "_zero", zero):
            e, site, p = self.run_with(list(self.SECRETS), guard=Forgetful())
        self.assertEqual(len(reads), 2)
        for v in reads:
            self.assertTrue(v)
            self.assertEqual(v, bytearray(len(v)))
        self.assertEqual((e.cause, e.rc), ("CREDENTIALS.UNCLASSIFIED", 3))
        self.finished(site)

    def test_a_second_stop_while_the_prompt_clears_is_taken_after_the_clear(self):
        self._two_stops_while_s1_reads(before_hold=False)

    def test_a_stop_before_the_session_holds_a_value_still_clears_it(self):
        self._two_stops_while_s1_reads(before_hold=True)

    def test_a_stop_while_the_unclassified_receipt_is_written_is_held(self):
        """A failure no cause names, then a stop while the runner writes
        S1's UNCLASSIFIED receipt: the stop is held, the receipt is
        written, and S10 finishes."""
        import signal
        from unittest import mock
        import a2_record
        self.own_stop_handlers()
        real = a2_record.Run.write_receipt

        def write(self_, stage, *a, **k):
            if stage == "S1" and k.get("cause") == "CREDENTIALS.UNCLASSIFIED":
                signal.raise_signal(signal.SIGTERM)
            return real(self_, stage, *a, **k)

        def broken(v):
            raise KeyError("predicate broke")
        with mock.patch.object(a2_record.Run, "write_receipt", write):
            e, site, p = self.run_with(list(self.SECRETS), form_rules={"api_key": broken, "mailbox": broken})
        self.assertEqual((e.cause, e.rc), ("CREDENTIALS.UNCLASSIFIED", 3))
        self.assertIn(b"CAUSE=CREDENTIALS.UNCLASSIFIED", self.read("receipts", "S1--.txt"))
        self.finished(site)

    def test_core_limit_refusal_reads_nothing(self):
        e, site, p = self.run_with([b"never"], setrlimit=lambda r, v: (_ for _ in ()).throw(OSError()))
        self.assertEqual(e.cause, "CREDENTIALS.CORE_LIMIT")
        self.assertNotIn(b"Enter", p.transcript())


for _at, _where in (("before", "before_the_hand_back_blocks_is_the_runs"),
                   ("block", "just_after_the_hand_back_blocks_is_the_callers"),
                   (1, "after_the_first_handler_is_given_back_is_the_callers"),
                   (2, "after_the_second_handler_is_given_back_is_the_callers"),
                   (3, "after_the_third_handler_is_given_back_is_the_callers"),
                   (4, "after_the_last_handler_is_given_back_is_the_callers")):
    for _name in ("SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"):
        setattr(RunnerS1Test, "test_a_%s_%s" % (_name[3:].lower(), _where),
                (lambda at, name: lambda self: self._stop_in_the_hand_back(at, getattr(__import__("signal"), name)))(
                    _at, _name))



def _hand_back_entry_test(name, when, good):
    def test(self):
        answers = list(self.SECRETS) if good else [b"api-secret-1x", b""]
        self._stop_at_a_hand_back_entry(name, when, answers)
    test.__doc__ = ("A stop on entry to %s (%s the block), after %s." % (
        name, when, "a session that read every value" if good else "a session's empty-value form refusal"))
    return test


for _name, _when in RunnerS1Test.HAND_BACK:
    for _good in (True, False):
        if _good and _name == "_clear":
            continue     # a session that ended well with no stop recorded has nothing to clear
        setattr(RunnerS1Test, "test_a_stop_on_entry_to_%s_%s" % (_name.strip("_"), "after_a_good_session" if _good
                                                                    else "after_a_form_refusal"),
                _hand_back_entry_test(_name, _when, _good))


if __name__ == "__main__":
    unittest.main()
