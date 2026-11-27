"""S1 CREDENTIALS (section 3.7, rules 1 to 4 and 3a; section 8 L5).

S1 reads the API key and one mailbox credential per VM of the run at one
no-echo prompt on the controlling terminal, checks each value's form, checks
the key live (or, in the L2-leak run only, by the stub), runs L5 on the
private files' in-memory bytes, and holds the values in memory until their
writers run (S6b, S7). It writes nothing on any target. Its receipt carries
facts only, never a value.

Every input another review fixes is a slot that refuses until filled: the
form rules ([OPEN: the shapes], the S1 review) and the live check
([OPEN: endpoint]).
"""

import hmac
import os
import resource
import signal
import termios
import threading

import a2_locks
from a2_causes import Refusal

TTY = "/dev/tty"
#: The longest value S1 reads. A terminal in canonical mode delivers at most
#: about 4095 bytes in one line, so the bound sits well inside that. Submitted
#: to the S1 review with the form rules.
VALUE_MAX = 1024
API_KEY = "api_key"


def mailbox_label(vm_name):
    return "mailbox:" + vm_name


# ------------------------------------------------------------ rule 1


def set_core_limit(setrlimit=resource.setrlimit, getrlimit=resource.getrlimit):
    """Rule 1: the core-dump limit is zero for S1 and every child it starts,
    or S1 refuses."""
    try:
        setrlimit(resource.RLIMIT_CORE, (0, 0))
        if getrlimit(resource.RLIMIT_CORE) != (0, 0):
            raise OSError("limit not zero")
    except (OSError, ValueError):
        raise Refusal("CREDENTIALS.CORE_LIMIT")


# ------------------------------------------------------------ rule 2


def _zero(buf):
    for i in range(len(buf)):
        buf[i] = 0


def _read_line(fd, limit=VALUE_MAX, buf=None):
    """One line from fd into a bytearray, never a str: into `buf` when the
    caller passes one, so the caller can track it before the first byte is
    read. The LF ends it and is not kept. Longer than `limit` is a form
    failure. On every failure the partial buffer is overwritten before the
    refusal leaves."""
    if buf is None:
        buf = bytearray()
    try:
        while True:
            try:
                b = os.read(fd, 1)
            except OSError:
                # The terminal went away (EIO on a hung-up line).
                raise Refusal("CREDENTIALS.NO_ECHO")
            if not b:
                raise Refusal("CREDENTIALS.NO_ECHO")
            if b == b"\n":
                break
            if b == b"\r":
                continue
            buf += b
            if len(buf) > limit:
                raise Refusal("CREDENTIALS.FORM", "form rule: length")
    except BaseException:
        _zero(buf)
        raise
    return buf


ECHO_BITS = termios.ECHO | termios.ECHONL
#: Signals that end the prompt: each restores the terminal and refuses.
#: SIGQUIT is one: its default action ends the process with echo off.
STOP_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)
#: Held back while the terminal or the handlers are being put back.
MASKED = STOP_SIGNALS + (signal.SIGTSTP,)


class _Interrupted(Exception):
    pass


def _mask(how, sigs):
    return signal.pthread_sigmask(how, sigs)


def _uninterrupted(fn):
    """Run fn with MASKED blocked, so a second signal cannot cut a restore
    short. An `_Interrupted` raised anyway (S1's handlers raise it only
    during a read, so none of the prompt's own calls meets one) runs fn
    again from the start, and is raised once fn has completed. fn must be
    safe to repeat. The
    caller's mask is read before anything is blocked, and the block is
    inside the try that puts it back, so a stop or a failure at any point
    after that read leaves the caller's mask in place."""
    pending = None
    old = None
    while True:
        try:
            if old is None:
                old = _mask(signal.SIG_BLOCK, ())
            try:
                _mask(signal.SIG_BLOCK, MASKED)
                result = fn()
            finally:
                _mask(signal.SIG_SETMASK, old)
            break
        except _Interrupted as e:
            pending = e
    if pending is not None:
        raise pending
    return result


class _Signals:
    """For the prompt session: INT, TERM, HUP and QUIT, and TSTP ignored (a
    stopped prompt would leave echo off). Installed only in the main
    thread, the only one Python delivers signals to.

    A stop raises `_Interrupted` only while a read is in progress
    (`reading`), so the read's own clear and the session's finally run.
    Anywhere else in the session, the hand-back included, the stop is
    recorded in `pending` and nothing is raised, so no stop can cut the
    hand-back short. A recorded stop ends the session before its next
    read, and the prompt raises it once the caller's handlers are back.

    The hand-back puts the old handlers back with MASKED blocked, and can
    be run again with the same result. When the session ends with an
    exception or a recorded stop, the values read are overwritten in that
    same masked step, before the handlers go back, so no stop reaches the
    caller's handler while a value read is still set."""

    def __init__(self, values):
        self.values = values
        self.reading = False
        self.pending = None

    def _handler(self, signum, frame):
        if self.reading:
            self.reading = False
            raise _Interrupted()
        if self.pending is None:
            self.pending = signum

    def begin_read(self):
        """Enter the read: a stop recorded before it ends the session here."""
        self.reading = True
        if self.pending is not None:
            self.reading = False
            raise _Interrupted()

    def __enter__(self):
        self.saved = {}
        if threading.current_thread() is threading.main_thread():
            for sig in STOP_SIGNALS:
                self.saved[sig] = signal.signal(sig, self._handler)
            self.saved[signal.SIGTSTP] = signal.signal(signal.SIGTSTP, signal.SIG_IGN)
        return self

    def __exit__(self, exc_type, exc, tb):
        def back():
            if exc_type is not None or self.pending is not None:
                _clear(self.values)
            self._restore()
        _uninterrupted(back)
        return False

    def _restore(self):
        for sig, old in self.saved.items():
            signal.signal(sig, old)


def prompt(labels, guard, tty_path=TTY, stdin_fd=0, open_fn=os.open):
    """Rule 2: one prompt session, no echo. The values are read from the
    controlling terminal with echo off (ECHO and ECHONL), checked off before
    any prompt or read; if stdin is not a terminal, or echo cannot be turned
    off, S1 refuses before reading. Each value is held in the output guard
    the moment it is read, before anything else is written. The terminal
    state is restored on every exit path, and a restore that fails is
    itself a refusal. Returns {label: bytearray}, already held."""
    if not os.isatty(stdin_fd):
        raise Refusal("CREDENTIALS.NO_ECHO")
    try:
        fd = open_fn(tty_path, os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
    except OSError:
        raise Refusal("CREDENTIALS.NO_ECHO")
    values = {}
    sigs = _Signals(values)
    try:
        with sigs:
            _session(fd, labels, guard, values, sigs)
        if sigs.pending is not None:
            raise _Interrupted()
    except (_Interrupted, Refusal) as e:
        # A stop the session recorded is raised here, with the caller's
        # handlers back, as the refusal a stop at the read gives.
        _zero_all(values)
        if isinstance(e, _Interrupted) or sigs.pending is not None:
            raise Refusal("CREDENTIALS.NO_ECHO", "interrupted")
        raise
    except BaseException:
        _zero_all(values)
        raise
    finally:
        os.close(fd)
    return values


def _clear(values):
    for v in values.values():
        _zero(v)


def _zero_all(values):
    """Overwrite every value read, with MASKED blocked, so a stop cannot cut
    the loop short; one that lands is raised once every value is zero."""
    _uninterrupted(lambda: _clear(values))


def _session(fd, labels, guard, values, sigs):
    """The prompt session proper, inside the signal handlers. Only the read
    itself is open to a stop's `_Interrupted` (`sigs.reading`)."""
    if not os.isatty(fd):
        raise Refusal("CREDENTIALS.NO_ECHO")
    try:
        saved = termios.tcgetattr(fd)
    except termios.error:
        raise Refusal("CREDENTIALS.NO_ECHO")
    failed = True
    try:
        quiet = list(saved)
        quiet[3] = quiet[3] & ~ECHO_BITS
        try:
            termios.tcsetattr(fd, termios.TCSAFLUSH, quiet)
            now = termios.tcgetattr(fd)
        except termios.error:
            raise Refusal("CREDENTIALS.NO_ECHO")
        if now[3] & ECHO_BITS:
            raise Refusal("CREDENTIALS.NO_ECHO")
        for label in labels:
            if sigs.pending is not None:
                raise _Interrupted()
            text = "Enter " + label + " (not echoed): "
            guard.check(text)
            os.write(fd, text.encode("ascii"))
            # In `values` before the first byte is read, so the prompt's
            # clear reaches a value a stop interrupts at any point.
            value = values[label] = bytearray()
            sigs.begin_read()
            try:
                _read_line(fd, VALUE_MAX, value)
            finally:
                sigs.reading = False
            if not value:
                raise Refusal("CREDENTIALS.FORM", "form rule: empty")
            guard.hold(value)
            os.write(fd, b"\n")
        failed = False
    finally:
        restored = _uninterrupted(lambda: _restore_terminal(fd, saved))
        if not restored and not failed:
            raise Refusal("CREDENTIALS.NO_ECHO", "terminal state not restored")


def _restore_terminal(fd, saved):
    """Put the saved state back and read it back; True if it took."""
    try:
        termios.tcsetattr(fd, termios.TCSAFLUSH, saved)
        return termios.tcgetattr(fd)[3] == saved[3]
    except termios.error:
        return False


# ------------------------------------------------------- rules 3, 3a


def check_forms(values, form_rules):
    """Rule 3: each value's form. A failure names only the rule, never the
    value, its length or any part of it. The rules are the S1 review's
    ([OPEN: the shapes]); a value with no rule refuses."""
    if form_rules is None:
        raise Refusal("CREDENTIALS.FORM", "form rule: not supplied")
    for label, v in values.items():
        kind = API_KEY if label == API_KEY else "mailbox"
        rule = form_rules.get(kind)
        if rule is None:
            raise Refusal("CREDENTIALS.FORM", "form rule: " + kind)
        if not v or rule(v) is not True:
            raise Refusal("CREDENTIALS.FORM", "form rule: " + kind)


def check_distinct(values):
    """Rule 4: no two VMs' mailbox values are equal. Each pair is compared
    in constant time, on the held bytearrays; the refusal names only the
    rule, never which VMs."""
    boxes = [v for label, v in values.items() if label != API_KEY]
    for i in range(len(boxes)):
        for j in range(i + 1, len(boxes)):
            if hmac.compare_digest(boxes[i], boxes[j]):
                raise Refusal("CREDENTIALS.MAILBOX_REUSED", "form rule: mailbox values distinct")


def check_live(values, inv, live_check):
    """Rule 3: one authenticated request for the API key, made by the
    installer's own process ([OPEN: endpoint]; unset refuses). Rule 3a: in
    the L2-leak run only, the stub accepts and nothing leaves the host.
    Returns the KEY_LIVE fact."""
    if inv.loop == "L2-leak":
        return "stub"
    if live_check is None:
        raise Refusal("CREDENTIALS.KEY_NOT_LIVE")
    try:
        ok = live_check(values[API_KEY])
    except Exception:
        raise Refusal("CREDENTIALS.KEY_NOT_LIVE")
    if ok is not True:
        raise Refusal("CREDENTIALS.KEY_NOT_LIVE")
    return "pass"


# ------------------------------------------------------------- L5


def _strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield k
            yield from _strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _strings(v)


def check_l5(values, c):
    """Section 8 L5: no string and no raw byte sequence of either private
    file equals or contains a value S1 holds, compared in memory only, on
    the bytes S0 checked."""
    for raw, doc, cause in ((c.lock_raw, c.lock, "CREDENTIALS.LEAK_LOCK"),
                            (c.hosts_raw, c.hosts, "CREDENTIALS.LEAK_HOSTS")):
        strings = [s.encode("utf-8") for s in _strings(doc)]
        for v in values.values():
            needle = bytes(v)
            if needle in raw or any(needle in s for s in strings):
                raise Refusal(cause)


# ------------------------------------------------------------- S1


def labels_for(c):
    """The API key, then one mailbox credential per VM of the run, bound by
    `vms[].name` (rule 4)."""
    vms = a2_locks.run_vms(c.hosts, c.inv, c.account)
    return [API_KEY] + [mailbox_label(v["name"]) for v in vms]


class Held:
    """The values S1 holds for the writers (rule 4): bytearrays, never
    converted to str, cleared after the last writer. The prompt has already
    put each one in the guard; `already_held=False` holds them here."""

    def __init__(self, values, guard, already_held=False):
        self.values = values
        self.guard = guard
        if not already_held:
            for v in values.values():
                if v:
                    guard.hold(v)

    def clear(self):
        for v in self.values.values():
            for i in range(len(v)):
                v[i] = 0
        self.values = {}
        self.guard.release_all()


def run_s1(c, site, run, guard, custody=()):
    """S1's plan (dry-run: no prompt) or apply. Returns the Held values, or
    None for a dry-run. Writes S1's receipt, which carries first the
    custody read-back the runner took before S1 (5.3b)."""
    started = run.started
    facts = list(custody)
    labels = labels_for(c)
    if c.inv.command == "dry-run":
        run.write_receipt("S1", None, started, "PLANNED",
                          facts + [("BINDING", " ".join(labels)), ("PROMPT", "not shown in a dry-run")])
        return None
    held = None
    try:
        set_core_limit(site.setrlimit, site.getrlimit)
        facts.append(("CORE_LIMIT", "0"))
        values = prompt(labels, guard, site.tty_path, site.stdin_fd)
        held = Held(values, guard, already_held=True)
        facts.append(("NO_ECHO", "verified"))
        facts.append(("BINDING", " ".join(labels)))
        check_forms(values, site.form_rules)
        facts.append(("FORM", "pass"))
        check_distinct(values)
        facts.append(("DISTINCT", "pass"))
        facts.append(("KEY_LIVE", check_live(values, c.inv, site.live_check)))
        check_l5(values, c)
        facts.append(("LEAK_CHECK", "L5 pass"))
        hold = "the values are held in memory until the last writer (S6b, S7) has run"
        facts.append(("HOLD", hold))
        guard.emit(site.out, "S1: " + hold + ".")
    except Refusal as r:
        if held is not None:
            held.clear()
        else:
            guard.release_all()
        run.write_receipt("S1", None, started, "FAIL", facts, rc=r.rc, cause=r.cause)
        raise
    except BaseException:
        # Not a named cause: the values go first; the runner records
        # CREDENTIALS.UNCLASSIFIED for S1 (3.4).
        if held is not None:
            held.clear()
        guard.release_all()
        raise
    run.write_receipt("S1", None, started, "PASS", facts)
    return held
