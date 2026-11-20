"""The loop's budget (section 5.3c), runner side: the broker client the
launcher uses, and the read of `budget.d` that S0 checks its start record
with. The broker itself is [OPEN: budget broker, DS].

`root_uid` is the owner every `budget.d` object must have (0 on a runner
host); the tests pass their own uid.
"""

import calendar
import errno
import hashlib
import json
import os
import re
import socket
import stat
import struct
import time

from a2_causes import Refusal
from a2_private import matches

SUBDIRS = ("loop", "l3")
RECORD_KEYS = ("kind", "run_id", "command", "loop", "started_at", "lock_sha256",
               "hosts_sha256", "installer_sha256", "permit_id")
COMMANDS = ("install", "dry-run", "verify", "canary", "add-agent", "rotate-key",
            "check-roundtrip", "destroy")
LOOPS = ("L1", "L2", "L2-leak", "L3", "-")
PERMIT_ID = re.compile(r"[0-9a-f]{32}")
NAME = re.compile(r"start-([0-9]{8}T[0-9]{6}Z-[0-9a-f]{8})\.json")
STALE_S = 60
ACL_XATTRS = ("system.posix_acl_access", "system.posix_acl_default")

#: The broker's socket name in the lock root, its answer bound and the
#: largest answer read. The broker review states the bound
#: ([OPEN: budget broker, DS]); these are the values submitted to it.
SOCKET_NAME = "budget.sock"
ANSWER_BOUND_S = 10
ANSWER_MAX = 4096
RECORD_MAX = 4096


class Unobserved(Exception):
    pass


def loop_token(loop):
    return "-" if loop is None else loop


# ------------------------------------------------------- the record


def _strict(raw):
    def pairs(ps):
        seen = set()
        for k, _ in ps:
            if k in seen:
                raise ValueError("dup")
            seen.add(k)
        return dict(ps)

    def const(_):
        raise ValueError("const")

    return json.loads(raw.decode("utf-8", errors="strict"),
                      object_pairs_hook=pairs, parse_constant=const)


def check_record(rec, run_id_from_name):
    """The closed record schema of 5.3c."""
    if not isinstance(rec, dict) or set(rec) != set(RECORD_KEYS):
        return False
    if rec["kind"] != "start" or rec["run_id"] != run_id_from_name:
        return False
    if not matches("run_id", rec["run_id"]):
        return False
    if rec["command"] not in COMMANDS or rec["loop"] not in LOOPS:
        return False
    if not matches("utc", rec["started_at"]):
        return False
    try:
        time.strptime(rec["started_at"], "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    for k in ("lock_sha256", "hosts_sha256", "installer_sha256"):
        if not matches("sha256", rec[k]):
            return False
    p = rec["permit_id"]
    if not (p == "-" or (isinstance(p, str) and PERMIT_ID.fullmatch(p))):
        return False
    return True


def _has_acl(path):
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError as e:
        return e.errno not in (errno.ENOTSUP, errno.EOPNOTSUPP)
    return any(n in names for n in ACL_XATTRS)


def _check_dir(path, root_uid):
    try:
        st = os.lstat(path)
    except OSError:
        raise Unobserved()
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != root_uid
            or stat.S_IMODE(st.st_mode) != 0o755 or _has_acl(path)):
        raise Unobserved()
    try:
        return os.listdir(path)
    except OSError:
        raise Unobserved()


def _read_record(path, root_uid):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise Unobserved()
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != root_uid
                or stat.S_IMODE(st.st_mode) != 0o644 or st.st_nlink != 1
                or st.st_size > RECORD_MAX):
            raise Unobserved()
        chunks, n = [], 0
        while n <= RECORD_MAX:
            b = os.read(fd, RECORD_MAX + 1 - n)
            if not b:
                break
            chunks.append(b)
            n += len(b)
        raw = b"".join(chunks)
    except OSError:
        raise Unobserved()
    finally:
        os.close(fd)
    if len(raw) > RECORD_MAX:
        raise Unobserved()
    return raw


def read_budget(budget_dir, root_uid=0):
    """A read of `budget.d` (5.3c): {run_id: (subdir, record, sha256)}.
    Any rule broken is `Unobserved`."""
    top = _check_dir(budget_dir, root_uid)
    if set(top) != set(SUBDIRS):
        raise Unobserved()
    out = {}
    for sub in SUBDIRS:
        d = os.path.join(budget_dir, sub)
        for name in _check_dir(d, root_uid):
            if name.startswith(".tmp-"):
                continue
            m = NAME.fullmatch(name)
            if m is None:
                raise Unobserved()
            raw = _read_record(os.path.join(d, name), root_uid)
            try:
                rec = _strict(raw)
            except (ValueError, UnicodeDecodeError, RecursionError):
                raise Unobserved()
            if not check_record(rec, m.group(1)):
                raise Unobserved()
            if rec["run_id"] in out:
                raise Unobserved()
            out[rec["run_id"]] = (sub, rec, hashlib.sha256(raw).hexdigest())
    return out


def _utc_seconds(s):
    return calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))


def check_start_record(budget_dir, account, run_id, inv, lock_sha, hosts_sha,
                       installer_sha, now=None, root_uid=0):
    """S0's check of its own start record (5.1a). Returns the record's
    sha256 (`ADMISSION_SHA`). A read that breaks the rules refuses
    `PREFLIGHT.BUDGET`; a record that does not bind this run refuses
    `RUNNER.ADMISSION`."""
    try:
        records = read_budget(budget_dir, root_uid)
    except Unobserved:
        raise Refusal("PREFLIGHT.BUDGET")
    got = records.get(run_id)
    if got is None:
        raise Refusal("RUNNER.ADMISSION")
    sub, rec, sha = got
    if sub != account:
        raise Refusal("RUNNER.ADMISSION")
    if rec["command"] != inv.command or rec["loop"] != loop_token(inv.loop):
        raise Refusal("RUNNER.ADMISSION")
    if rec["lock_sha256"] != lock_sha or rec["hosts_sha256"] != hosts_sha:
        raise Refusal("RUNNER.ADMISSION")
    if rec["installer_sha256"] != installer_sha:
        raise Refusal("RUNNER.ADMISSION")
    t_now = int(time.time() if now is None else now)
    started = _utc_seconds(rec["started_at"])
    if started > t_now or t_now - started > STALE_S:
        raise Refusal("RUNNER.ADMISSION")
    return sha


# ---------------------------------------------------- broker client


def socket_owner_ok(st, root_uid):
    """The broker socket is a socket owned by root (5.3c)."""
    return stat.S_ISSOCK(st.st_mode) and st.st_uid == root_uid


def peer_ok(cred, root_uid):
    """The peer's `SO_PEERCRED` uid is root (5.3c)."""
    _pid, peer_uid, _gid = struct.unpack("iII", cred)
    return peer_uid == root_uid


#: The broker's explicit refusal, which the broker sends only before any
#: record is under its final name (5.3c). Its shape is submitted to the
#: broker review ([OPEN: budget broker, DS]).
REFUSAL = {"refused": True}


def ask_broker(lock_root, inv, lock_sha, hosts_sha, installer_sha, root_uid=0,
               bound_s=ANSWER_BOUND_S):
    """One request to the budget broker. Returns (run_id, record sha256).

    The boundary between the two refusals is whether any byte of the
    request was sent (5.3c). Before that, and on the broker's explicit
    refusal, it is PREFLIGHT.BUDGET: no record was published. After it,
    any timeout and any lost, late or malformed answer has an unknown
    outcome: RUNNER.NOT_STARTED."""
    path = os.path.join(lock_root, SOCKET_NAME)
    try:
        st = os.lstat(path)
    except OSError:
        raise Refusal("PREFLIGHT.BUDGET")
    if not socket_owner_ok(st, root_uid):
        raise Refusal("PREFLIGHT.BUDGET")
    req = json.dumps({"command": inv.command, "loop": loop_token(inv.loop),
                      "lock_sha256": lock_sha, "hosts_sha256": hosts_sha,
                      "installer_sha256": installer_sha},
                     sort_keys=True, separators=(",", ":")).encode() + b"\n"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    sent = 0
    try:
        try:
            s.settimeout(bound_s)
            s.connect(path)
            if not peer_ok(s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                        struct.calcsize("iII")), root_uid):
                raise Refusal("PREFLIGHT.BUDGET")
            while sent < len(req):
                n = s.send(req[sent:])
                if n <= 0:
                    raise OSError("send made no progress")
                sent += n
            s.shutdown(socket.SHUT_WR)
            buf = b""
            deadline = time.monotonic() + bound_s
            while len(buf) <= ANSWER_MAX:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise Refusal("RUNNER.NOT_STARTED")
                s.settimeout(left)
                chunk = s.recv(ANSWER_MAX + 1 - len(buf))
                if not chunk:
                    break
                buf += chunk
        except (OSError, socket.timeout):
            raise Refusal("PREFLIGHT.BUDGET" if sent == 0 else "RUNNER.NOT_STARTED")
    finally:
        s.close()
    if len(buf) > ANSWER_MAX:
        raise Refusal("RUNNER.NOT_STARTED")
    try:
        ans = _strict(buf)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise Refusal("RUNNER.NOT_STARTED")
    if ans == REFUSAL and type(ans.get("refused")) is bool:
        raise Refusal("PREFLIGHT.BUDGET")
    if (not isinstance(ans, dict) or set(ans) != {"run_id", "sha256"}
            or not matches("run_id", ans["run_id"]) or not matches("sha256", ans["sha256"])):
        raise Refusal("RUNNER.NOT_STARTED")
    return ans["run_id"], ans["sha256"]
