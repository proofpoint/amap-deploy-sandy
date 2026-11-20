"""The run's record: receipts (section 3.3), the run manifest (6.3) and the
SUMS chain (5.4).

Every file is written relative to the run directory's descriptor that S0
pinned (5.2), never through a path resolved again: to a temporary name,
fsynced, renamed into place, and the directory fsynced. Every line passes
through the output guard first (3.3).
"""

import hashlib
import json
import os
import re
import signal
import stat
import time

import a2_causes
from a2_causes import Refusal
from a2_private import matches

STAGES = (("S0", "PREFLIGHT"), ("S1", "CREDENTIALS"), ("S2", "VMS"), ("S3", "HUB-CHECK"),
          ("S4", "IMAGES"), ("S5", "KEYS"), ("S6", "CONFIG"), ("S6b", "HUB-LOGIN"),
          ("S7", "AGENTS"), ("S8", "START"), ("S9", "VERIFY"), ("S10", "SUMMARY"))
STAGE_NAME = dict(STAGES)
KEY = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
VALUE = re.compile(r"[\x20-\x7e]*")
CAUSE = re.compile(r"(RUNNER|[A-Z][A-Z0-9-]*)\.[A-Z][A-Z0-9_]{1,82}")
REQUIRED = ("RUN_ID", "COMMAND", "LOOP", "INSTALLER_SHA", "LOCK_SHA", "HOSTS_SHA", "STAGE",
            "HOST", "STARTED", "ENDED", "RESULT")
PASS_RESULTS = ("CHANGED", "ALREADY", "PLANNED", "PASS")
RECEIPT_MAX = 1 << 20
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
RECEIPTS = "receipts"
MANIFEST = "manifest.json"
SUMS = "SUMS"
SUMMARY = "summary.txt"
ENV_NAMES = ["HOME", "PATH", "SSH_AUTH_SOCK", "TERM"]
ZERO = "0" * 64
#: Held back for the whole of one record write: the stop signals.
WRITE_MASK = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)


def utc_now(now=None):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() if now is None else now))


def receipt_name(stage_id, host):
    return stage_id + "-" + (host or "-") + ".txt"


def _whole(fn):
    """Run one record write with WRITE_MASK blocked, so a stop cannot leave
    a file on disk outside SUMS or the manifest. A stop that lands during
    the write is taken when the caller's mask is put back, once the write
    is complete. The caller's mask is read before anything is blocked."""
    old = signal.pthread_sigmask(signal.SIG_BLOCK, ())
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, WRITE_MASK)
        return fn()
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, old)


# ------------------------------------------------------------ files


def _write_atomic(dir_fd, name, data):
    """temp, fsync, rename, directory fsync (3.3, 5.4)."""
    tmp = ".tmp-" + name
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=dir_fd)
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    os.fsync(dir_fd)


def _read_at(dir_fd, name, limit=RECEIPT_MAX):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("not a regular file")
        chunks, n = [], 0
        while n <= limit:
            b = os.read(fd, limit + 1 - n)
            if not b:
                break
            chunks.append(b)
            n += len(b)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if len(data) > limit:
        raise OSError("too large")
    return data


# ---------------------------------------------------------- receipts


def render_receipt(facts, stage_id, host, rc):
    """The receipt's bytes, checked against every rule of 3.3 before any
    byte is written. `facts` is an ordered list of (KEY, VALUE)."""
    lines = []
    for k, v in facts:
        if not KEY.fullmatch(k) or not isinstance(v, str) or not VALUE.fullmatch(v):
            raise ValueError("bad fact")
        lines.append(k + "=" + v + "\n")
    lines.append("STAGE-END " + stage_id + " " + (host or "-") + " rc=" + str(rc) + "\n")
    data = "".join(lines).encode("ascii")
    check_receipt(data, stage_id, host, None)
    return data


def parse_receipt(data):
    """(facts dict, stage_id, host, rc) or ValueError."""
    if not data.endswith(b"\n"):
        raise ValueError("no final LF")
    try:
        text = data.decode("ascii", "strict")
    except UnicodeDecodeError:
        raise ValueError("not ascii")
    lines = text.split("\n")[:-1]
    if not lines:
        raise ValueError("empty")
    end = lines[-1].split(" ")
    if (len(end) != 4 or end[0] != "STAGE-END" or end[1] not in STAGE_NAME
            or not (end[2] == "-" or matches("name", end[2])) or end[3] not in ("rc=0", "rc=2", "rc=3", "rc=4")):
        raise ValueError("bad end line")
    facts = {}
    for ln in lines[:-1]:
        k, sep, v = ln.partition("=")
        if not sep or not KEY.fullmatch(k) or not VALUE.fullmatch(v) or k in facts:
            raise ValueError("bad fact line")
        facts[k] = v
    host = None if end[2] == "-" else end[2]
    return facts, end[1], host, int(end[3][3:])


def check_receipt(data, stage_id, host, name):
    """Every rule of 3.3 on one receipt. Returns (facts, rc)."""
    facts, sid, h, rc = parse_receipt(data)
    if sid != stage_id or h != host:
        raise ValueError("end line names another stage or host")
    if name is not None and name != receipt_name(stage_id, host):
        raise ValueError("file name disagrees")
    for k in REQUIRED:
        if k not in facts:
            raise ValueError("missing " + k)
    if facts["STAGE"] != STAGE_NAME[stage_id] or facts["HOST"] != (host or "-"):
        raise ValueError("STAGE or HOST disagrees")
    for k in ("INSTALLER_SHA", "LOCK_SHA", "HOSTS_SHA"):
        if not matches("sha256", facts[k]):
            raise ValueError("bad sha " + k)
    for k in ("STARTED", "ENDED"):
        if not matches("utc", facts[k]):
            raise ValueError("bad time " + k)
    if not matches("run_id", facts["RUN_ID"]):
        raise ValueError("bad run id")
    has_cause = "CAUSE" in facts or "CAUSE_TEXT" in facts
    if rc == 0:
        if facts["RESULT"] not in PASS_RESULTS or has_cause:
            raise ValueError("rc 0 rules")
    else:
        if facts["RESULT"] != "FAIL" or "CAUSE" not in facts or "CAUSE_TEXT" not in facts:
            raise ValueError("failure rules")
        if not CAUSE.fullmatch(facts["CAUSE"]):
            raise ValueError("bad cause")
        stage_part = facts["CAUSE"].split(".", 1)[0]
        if stage_part != "RUNNER" and stage_part != STAGE_NAME[stage_id]:
            raise ValueError("cause names another stage")
        want = a2_causes.sentence(facts["CAUSE"])
        if want is None or facts["CAUSE_TEXT"] != want:
            raise ValueError("cause text is not the fixed sentence")
    return facts, rc


class Run:
    """One run's record, anchored at the run directory's descriptor."""

    def __init__(self, run_fd, guard, run_id, command, loop, installer_sha, lock_sha, hosts_sha,
                 source_run=None, now=None):
        self.run_fd = run_fd
        self.guard = guard
        self.run_id = run_id
        self.command = command
        self.loop = loop
        self.installer_sha = installer_sha
        self.lock_sha = lock_sha
        self.hosts_sha = hosts_sha
        self.source_run = source_run
        self.started = utc_now(now)
        self.stages = []
        self.causes = {}
        self.receipts_fd = os.open(RECEIPTS, DIR_FLAGS, dir_fd=run_fd)
        self.sums_prev = ZERO
        self.sums_n = 0
        self.final = False

    # -- manifest (6.3)

    def manifest_doc(self, final, now=None):
        doc = {"schema": "alpha2.run/1", "state": "final" if final else "active",
               "run_id": self.run_id, "command": self.command, "loop": self.loop,
               "source_run": self.source_run, "installer_sha256": self.installer_sha,
               "lock_sha256": self.lock_sha, "hosts_sha256": self.hosts_sha,
               "started": self.started}
        if final:
            doc["ended"] = utc_now(now)
        doc["env_names"] = list(ENV_NAMES)
        doc["stages"] = [dict(s) for s in self.stages]
        return doc

    def write_manifest(self, final=False, now=None):
        """Rewrite the manifest; a final one is also appended to SUMS. The
        whole write is one record write (`_whole`)."""
        return _whole(lambda: self._write_manifest(final, now))

    def _write_manifest(self, final, now):
        if self.final:
            raise ValueError("the manifest is final")
        data = (json.dumps(self.manifest_doc(final, now), indent=1, sort_keys=False) + "\n").encode()
        self.guard.check(data)
        _write_atomic(self.run_fd, MANIFEST, data)
        if final:
            self.final = True
            self._append_sums(MANIFEST, data)

    # -- receipts

    def base_facts(self, stage_id, host, started):
        return [("RUN_ID", self.run_id), ("COMMAND", self.command),
                ("LOOP", "-" if self.loop is None else self.loop),
                ("INSTALLER_SHA", self.installer_sha), ("LOCK_SHA", self.lock_sha),
                ("HOSTS_SHA", self.hosts_sha), ("STAGE", STAGE_NAME[stage_id]),
                ("HOST", host or "-"), ("STARTED", started)]

    def write_receipt(self, stage_id, host, started, result, facts, rc=0, cause=None, now=None):
        """Finalize one receipt atomically, then append its SUMS line and
        rewrite the active manifest (6.3 lifecycle), all as one record write
        (`_whole`)."""
        return _whole(lambda: self._write_receipt(stage_id, host, started, result, facts, rc, cause, now))

    def _write_receipt(self, stage_id, host, started, result, facts, rc, cause, now):
        if self.final:
            raise ValueError("the manifest is final")
        allf = self.base_facts(stage_id, host, started) + list(facts)
        allf.append(("ENDED", utc_now(now)))
        allf.append(("RESULT", result))
        if cause is not None:
            allf.append(("CAUSE", cause))
            allf.append(("CAUSE_TEXT", a2_causes.sentence(cause)))
        data = render_receipt(allf, stage_id, host, rc)
        self.guard.check(data)
        name = receipt_name(stage_id, host)
        try:
            os.stat(name, dir_fd=self.receipts_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("receipt exists")
        _write_atomic(self.receipts_fd, name, data)
        path = RECEIPTS + "/" + name
        self._append_sums(path, data)
        self.stages.append({"stage": stage_id, "host": host or "-", "receipt": path,
                            "sha256": hashlib.sha256(data).hexdigest(), "rc": rc})
        if cause is not None:
            self.causes[(stage_id, host or "-")] = cause
        self.write_manifest(final=False)
        return path

    def read_receipt(self, stage_id, host):
        """A predecessor's receipt from this run, by every 3.3 reader rule.
        Returns its facts; refuses with the reader's cause otherwise."""
        stage_name = STAGE_NAME[stage_id]
        name = receipt_name(stage_id, host)
        try:
            data = _read_at(self.receipts_fd, name)
        except FileNotFoundError:
            raise Refusal(stage_name + ".PREDECESSOR_MISSING")
        except OSError:
            raise Refusal(stage_name + ".PREDECESSOR_INCOMPLETE")
        try:
            facts, rc = check_receipt(data, stage_id, host, name)
        except ValueError:
            raise Refusal(stage_name + ".PREDECESSOR_INCOMPLETE")
        if (facts["LOCK_SHA"] != self.lock_sha or facts["HOSTS_SHA"] != self.hosts_sha
                or facts["RUN_ID"] != self.run_id or facts["COMMAND"] != self.command
                or facts["LOOP"] != ("-" if self.loop is None else self.loop)):
            raise Refusal(stage_name + ".PREDECESSOR_INCOMPLETE")
        if facts["INSTALLER_SHA"] != self.installer_sha:
            raise Refusal(stage_name + ".PREDECESSOR_INSTALLER")
        if rc != 0:
            raise Refusal(stage_name + ".PREDECESSOR_FAILED")
        return facts

    # -- SUMS (5.4)

    def _append_sums(self, path, data):
        self.sums_n += 1
        line = "%d %s %s %s\n" % (self.sums_n, hashlib.sha256(data).hexdigest(), self.sums_prev, path)
        self.guard.check(line)
        fd = os.open(SUMS, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.run_fd)
        try:
            raw = line.encode("ascii")
            view = memoryview(raw)
            while view:
                n = os.write(fd, view)
                view = view[n:]
            os.fsync(fd)
        finally:
            os.close(fd)
        self.sums_prev = hashlib.sha256(raw).hexdigest()

    def close(self):
        os.close(self.receipts_fd)


SUMS_LINE = re.compile(r"([1-9][0-9]*) ([0-9a-f]{64}) ([0-9a-f]{64}) (\S+)\n")
RECEIPT_PATH = re.compile(r"receipts/(S0|S1|S2|S3|S4|S5|S6|S6b|S7|S8|S9|S10)-(-|[a-z][a-z0-9-]{0,62})\.txt")


def verify_sums(run_fd):
    """5.4: every line parses and recomputes, numbers are consecutive, no
    path repeats, every listed file exists, and no file in the run
    directory is unlisted. Returns the SUMS sha256. `RUNNER.SUMS` (rc 4)."""
    try:
        raw = _read_at(run_fd, SUMS, 1 << 24)
        text = raw.decode("ascii", "strict")
    except (OSError, UnicodeDecodeError):
        raise Refusal("RUNNER.SUMS")
    prev = ZERO
    seen = set()
    for i, ln in enumerate(text.splitlines(True), 1):
        m = SUMS_LINE.fullmatch(ln)
        if m is None or int(m.group(1)) != i or m.group(3) != prev:
            raise Refusal("RUNNER.SUMS")
        path = m.group(4)
        if path in seen or not (path in (MANIFEST, SUMMARY) or RECEIPT_PATH.fullmatch(path)):
            raise Refusal("RUNNER.SUMS")
        seen.add(path)
        try:
            if path.startswith(RECEIPTS + "/"):
                rfd = os.open(RECEIPTS, DIR_FLAGS, dir_fd=run_fd)
                try:
                    data = _read_at(rfd, path.split("/", 1)[1])
                finally:
                    os.close(rfd)
            else:
                data = _read_at(run_fd, path, 1 << 24)
        except OSError:
            raise Refusal("RUNNER.SUMS")
        if hashlib.sha256(data).hexdigest() != m.group(2):
            raise Refusal("RUNNER.SUMS")
        prev = hashlib.sha256(ln.encode("ascii")).hexdigest()
    present = set()
    for name in os.listdir(run_fd):
        if name == RECEIPTS:
            rfd = os.open(RECEIPTS, DIR_FLAGS, dir_fd=run_fd)
            try:
                present.update(RECEIPTS + "/" + n for n in os.listdir(rfd))
            finally:
                os.close(rfd)
        elif name != SUMS:
            present.add(name)
    if present - seen:
        raise Refusal("RUNNER.SUMS")
    return hashlib.sha256(raw).hexdigest()
