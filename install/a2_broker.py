"""The budget broker (stage contract 5.3c): the only writer of start records.

A root-owned program on the runner host. It serves one request per connection on `<lock_root>/budget.sock`,
identifies its caller by the uid of SO_PEERCRED (captured at connect; never the pid, never SCM_CREDENTIALS), and
for each request, under an exclusive flock on `budget.d` itself:

1. reads every record in `budget.d` (the strict read of a2_budget) and in every `budget.d.<utc>` set aside (the
   lenient read below), and refuses if a count cannot be made;
2. refuses an `install` with loop `L2` or `L2-leak` once the UTC day's count of L2 starts is DAILY_L2;
3. refuses once the caller's own records for the UTC day reach ACCOUNT_CEILING;
4. under usage path (b), reads `stop.d/monitor/permit.json` itself and refuses unless it is current, its id is in no
   record, and no set-aside makes it spent;
5. mints the run_id from its own clock, builds the record, validates it against the record schema, and publishes it
   in the caller's own subdirectory: a `.tmp-` file, fsync, renameat2(RENAME_NOREPLACE) to `start-<run_id>.json`
   (which fails if the name exists, and never leaves two links), fsync of the directory.

It answers `{"run_id", "sha256"}`, or the explicit refusal `{"refused": true}` only while no record is under its
final name. Any failure after the rename, a close included, closes the connection with no answer: the launcher maps
that to RUNNER.NOT_STARTED, and the record, if published, counts.

Each connection is served in its own thread, after its uid is checked at accept: a caller of neither account is
closed unread, and each account holds at most PER_ACCOUNT_SLOTS connections at once, so no caller can delay the other
account's request. Admissions themselves run one at a time (a process lock and the flock). Before publishing, the
broker checks that its caller is still connected; a caller that has hung up gets no record.

Usage: python3 -I -B a2_broker.py --lock-root PATH --loop-account NAME --l3-account NAME --usage-path a|b
"""

import calendar
import fcntl
import select
import hashlib
import json
import os
import pwd
import re
import secrets
import socket
import stat
import struct
import sys
import threading
import time

# The broker runs as `python3 -I -B <dir>/a2_broker.py` from a root-owned directory holding exactly its six files
# (MAP section 7). -I leaves the script's directory off sys.path, so the broker puts it there itself, before its own
# imports: nothing a runner account can write is ever on the path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import a2_budget  # noqa: E402
from a2_args import Invocation, NON_WRITING  # noqa: E402
from a2_host import required_account  # noqa: E402

SOCKET_NAME = a2_budget.SOCKET_NAME
REQUEST_KEYS = ("command", "loop", "lock_sha256", "hosts_sha256", "installer_sha256")
REQUEST_MAX = 1024
REQUEST_BOUND_S = 5
DAILY_L2 = 12
#: The per-account ceiling of start records per UTC day (5.3c "that the broker review states"). It bounds what
#: direct calls can add to budget.d; the L2 count above is the budget itself.
ACCOUNT_CEILING = 32
PERMIT_MAX = 4096
PERMIT_KEYS = ("kind", "permit_id", "observed_percent", "observed_at", "expires_at")
PERMIT_SPAN_S = 3600
L2_LOOPS = ("L2", "L2-leak")
#: Commands the broker admits for no account. --rotate-key is disabled (the operator's go A, W8 r4): PROPOSED with
#: W8's contract rows.
DISABLED = ("rotate-key",)
PER_ACCOUNT_SLOTS = 2
RENAME_NOREPLACE = 1
NOBODY = 65534
SET_ASIDE = re.compile(r"budget\.d\.([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)")
REFUSAL = json.dumps(a2_budget.REFUSAL, separators=(",", ":")).encode()


class Refused(Exception):
    """An explicit refusal: no record is under its final name."""


class Unknown(Exception):
    """A failure after the link: the connection closes with no answer."""


def _utc(s):
    return calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))


def _day(t):
    return time.strftime("%Y-%m-%d", time.gmtime(t))


def _rid_time(rid):
    return calendar.timegm(time.strptime(rid[:16], "%Y%m%dT%H%M%SZ"))


class Config:
    def __init__(self, lock_root, accounts, usage_path, root_uid=0, now=time.time, token=secrets.token_hex):
        if usage_path not in ("a", "b"):
            raise ValueError("usage path")
        self.lock_root = lock_root
        self.accounts = dict(accounts)          # {uid: "loop" | "l3"}
        self.usage_path = usage_path
        self.root_uid = root_uid
        self.now = now
        self.token = token


# ------------------------------------------------------------------ the request


def parse_request(raw):
    """The closed request of 5.3c, each value matched in full; anything else refuses."""
    try:
        req = a2_budget._strict(raw.rstrip(b"\n"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise Refused()
    if not isinstance(req, dict) or set(req) != set(REQUEST_KEYS):
        raise Refused()
    if req["command"] not in a2_budget.COMMANDS or req["loop"] not in a2_budget.LOOPS:
        raise Refused()
    for k in ("lock_sha256", "hosts_sha256", "installer_sha256"):
        if not a2_budget.matches("sha256", req[k]):
            raise Refused()
    return req


def authorise(req, account):
    """The command must write a target, be enabled, carry a loop only for `install`, and be one the caller's account
    may run (5.3b, a2_host.required_account)."""
    if account is None or req["command"] in NON_WRITING or req["command"] in DISABLED:
        raise Refused()
    if req["command"] != "install" and req["loop"] != "-":
        raise Refused()
    inv = Invocation(req["command"], None if req["loop"] == "-" else req["loop"], {})
    need = required_account(inv)
    if need is not None and need != account:
        raise Refused()


# ------------------------------------------------------------------ the reads


def read_set_asides(lock_root, root_uid):
    """Every `budget.d.<utc>` (5.3c, section 9): [(utc seconds, [entry])], an entry being (run_id or None, loop,
    started_at seconds, permit_id or None). An entry that fails the record rules counts as one L2 start on the day of
    its name's run_id, or of <utc>; it is never UNOBSERVED. A set-aside whose name is not `budget.d.<utc>`, or whose
    directories cannot be listed, refuses: its count cannot be made."""
    out = []
    try:
        names = os.listdir(lock_root)
    except OSError:
        raise Refused()
    for name in names:
        if not name.startswith("budget.d."):
            continue
        m = SET_ASIDE.fullmatch(name)
        if m is None:
            raise Refused()
        try:
            at = _utc(m.group(1))
        except ValueError:
            raise Refused()
        top = os.path.join(lock_root, name)
        entries = []
        try:
            extra = [n for n in os.listdir(top) if n not in a2_budget.SUBDIRS]
        except OSError:
            raise Refused()
        # A name other than the two subdirectories counts as one L2 start on the set-aside's day.
        entries += [(None, "L2", at, None) for _ in extra]
        for sub in a2_budget.SUBDIRS:
            d = os.path.join(top, sub)
            try:
                st = os.lstat(d)
            except FileNotFoundError:
                continue
            except OSError:
                raise Refused()
            if not stat.S_ISDIR(st.st_mode):
                raise Refused()
            try:
                listing = os.listdir(d)
            except OSError:
                raise Refused()
            for entry in listing:
                if entry.startswith(".tmp-"):
                    continue
                nm = a2_budget.NAME.fullmatch(entry)
                rid = nm.group(1) if nm else None
                rec = None
                if nm is not None:
                    try:
                        raw = a2_budget._read_record(os.path.join(d, entry), root_uid)
                        cand = a2_budget._strict(raw)
                        if a2_budget.check_record(cand, rid):
                            rec = cand
                    except (a2_budget.Unobserved, ValueError, UnicodeDecodeError, RecursionError):
                        rec = None
                if rec is not None:
                    pid = None if rec["permit_id"] == "-" else rec["permit_id"]
                    entries.append((rid, rec["loop"], _utc(rec["started_at"]), pid))
                else:
                    t = at
                    if rid is not None:
                        try:
                            t = _rid_time(rid)
                        except ValueError:
                            t = at
                    entries.append((rid, "L2", t, None))
        out.append((at, entries))
    return out


def read_permit(lock_root):
    """`stop.d/monitor/permit.json`, opened O_NOFOLLOW|O_NONBLOCK: a regular file of at most PERMIT_MAX bytes holding
    the closed permit record, or None (not current)."""
    path = os.path.join(lock_root, "stop.d", "monitor", "permit.json")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        raw = os.read(fd, PERMIT_MAX + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    if len(raw) > PERMIT_MAX:
        return None
    try:
        p = a2_budget._strict(raw)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    if not isinstance(p, dict) or set(p) != set(PERMIT_KEYS) or p["kind"] != "permit":
        return None
    if not isinstance(p["permit_id"], str) or not a2_budget.PERMIT_ID.fullmatch(p["permit_id"]):
        return None
    pct = p["observed_percent"]
    if type(pct) is not int or not 0 <= pct <= 79:
        return None
    try:
        if not (a2_budget.matches("utc", p["observed_at"]) and a2_budget.matches("utc", p["expires_at"])):
            return None
        obs, exp = _utc(p["observed_at"]), _utc(p["expires_at"])
    except (TypeError, ValueError):
        return None
    if not obs < exp <= obs + PERMIT_SPAN_S:
        return None
    return {"permit_id": p["permit_id"], "observed_at": obs, "expires_at": exp}


# ------------------------------------------------------------------ one admission


def _close(fd):
    os.close(fd)


def admit(raw, peer_uid, cfg, alive=lambda: True):
    """One request: (run_id, record sha256), or Refused before any publication, or Unknown after it. `alive` says
    whether the caller is still connected; it is asked just before publication."""
    req = parse_request(raw)
    account = cfg.accounts.get(peer_uid)
    authorise(req, account)
    budget = os.path.join(cfg.lock_root, "budget.d")
    try:
        bfd = os.open(budget, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise Refused()
    try:
        fcntl.flock(bfd, fcntl.LOCK_EX)
        result = _admit_locked(req, account, cfg, budget, alive)
    except BaseException:
        try:
            _close(bfd)
        except OSError:
            pass
        raise
    try:
        _close(bfd)
    except OSError:
        # The record is published: never a refusal.
        raise Unknown()
    return result


def _admit_locked(req, account, cfg, budget, alive):
    try:
        records = a2_budget.read_budget(budget, cfg.root_uid)
    except a2_budget.Unobserved:
        raise Refused()
    asides = read_set_asides(cfg.lock_root, cfg.root_uid)
    now = int(cfg.now())
    today = _day(now)

    starts = [(rid, rec["loop"], _utc(rec["started_at"]), None if rec["permit_id"] == "-" else rec["permit_id"], sub)
              for rid, (sub, rec, _sha) in records.items()]
    aside_entries = [e for _at, entries in asides for e in entries]
    l2_today = sum(1 for _r, loop, t, _p, _s in starts if loop in L2_LOOPS and _day(t) == today)
    l2_today += sum(1 for _r, loop, t, _p in aside_entries if loop in L2_LOOPS and _day(t) == today)
    if req["command"] == "install" and req["loop"] in L2_LOOPS and l2_today >= DAILY_L2:
        raise Refused()
    mine_today = sum(1 for _r, _l, t, _p, sub in starts if sub == account and _day(t) == today)
    if mine_today >= ACCOUNT_CEILING:
        raise Refused()

    permit_id = "-"
    if cfg.usage_path == "b":
        permit = read_permit(cfg.lock_root)
        if permit is None or not permit["observed_at"] <= now < permit["expires_at"]:
            raise Refused()
        used = {p for _r, _l, _t, p, _s in starts if p} | {p for _r, _l, _t, p in aside_entries if p}
        if permit["permit_id"] in used:
            raise Refused()
        for at, _entries in asides:
            if permit["observed_at"] <= at < permit["expires_at"]:
                raise Refused()
        permit_id = permit["permit_id"]

    rid = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now)) + "-" + cfg.token(4)
    taken = set(records) | {r for r, _l, _t, _p in aside_entries if r}
    if rid in taken:
        raise Refused()
    rec = {"kind": "start", "run_id": rid, "command": req["command"], "loop": req["loop"],
           "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
           "lock_sha256": req["lock_sha256"], "hosts_sha256": req["hosts_sha256"],
           "installer_sha256": req["installer_sha256"], "permit_id": permit_id}
    if not a2_budget.check_record(rec, rid):
        raise Refused()
    raw = json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > a2_budget.RECORD_MAX:
        raise Refused()
    if not alive():
        raise Refused()
    publish(os.path.join(budget, account), rid, raw)
    return rid, hashlib.sha256(raw).hexdigest()


def _renameat2_noreplace(src, dst, dfd):
    """renameat2(dfd, src, dfd, dst, RENAME_NOREPLACE): fails with EEXIST if `dst` exists, and the record never has
    two names."""
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.renameat2(dfd, src.encode(), dfd, dst.encode(), RENAME_NOREPLACE) != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))


def publish(subdir, rid, raw):
    """The publication rule of 5.3c. Before the rename: Refused (the temporary is removed). From the rename on,
    whatever fails, the directory's fsync or a close included: Unknown."""
    tmp, final = ".tmp-" + rid, "start-" + rid + ".json"
    try:
        dfd = os.open(subdir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise Refused()
    linked = False
    try:
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                         dir_fd=dfd)
        except OSError:
            raise Refused()
        try:
            view = memoryview(raw)
            while view:
                view = view[os.write(fd, view):]
            os.fchmod(fd, 0o644)
            os.fsync(fd)
        except OSError:
            os.close(fd)
            _unlink(tmp, dfd)
            raise Refused()
        os.close(fd)
        try:
            _renameat2_noreplace(tmp, final, dfd)
        except OSError:
            _unlink(tmp, dfd)
            raise Refused()
        linked = True
        os.fsync(dfd)
    except Refused:
        _close_quietly(dfd)
        raise
    except BaseException:
        _close_quietly(dfd)
        if linked:
            raise Unknown()
        raise Refused()
    try:
        _close(dfd)
    except OSError:
        raise Unknown()


def _close_quietly(fd):
    try:
        _close(fd)
    except OSError:
        pass


def _unlink(name, dfd):
    try:
        os.unlink(name, dir_fd=dfd)
    except OSError:
        pass


# ------------------------------------------------------------------ the socket


def peer_uid(conn):
    _pid, uid, _gid = struct.unpack("iII", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                           struct.calcsize("iII")))
    return uid


def read_request(conn):
    """The request: everything up to the caller's shutdown, at most REQUEST_MAX bytes, within REQUEST_BOUND_S."""
    deadline = time.monotonic() + REQUEST_BOUND_S
    buf = b""
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            raise Refused()
        conn.settimeout(left)
        chunk = conn.recv(REQUEST_MAX + 1 - len(buf))
        if not chunk:
            return buf
        buf += chunk
        if len(buf) > REQUEST_MAX:
            raise Refused()


def alive(conn):
    """The caller has not hung up: poll shows no HUP or error on the connection."""
    p = select.poll()
    p.register(conn.fileno(), select.POLLIN)
    return not any(ev & (select.POLLHUP | select.POLLERR) for _fd, ev in p.poll(0))


def serve_one(conn, cfg, uid, admission=None):
    """One connection, one request, for a caller whose uid was checked at accept. An explicit refusal is sent only
    for a refusal before publication; anything else that goes wrong during admission gets no answer."""
    try:
        raw = read_request(conn)
    except (Refused, OSError, socket.timeout):
        _send(conn, REFUSAL)
        return
    try:
        with admission or threading.Lock():
            rid, sha = admit(raw, uid, cfg, alive=lambda: alive(conn))
    except Refused:
        _send(conn, REFUSAL)
        return
    except BaseException:
        return
    _send(conn, json.dumps({"run_id": rid, "sha256": sha}, separators=(",", ":")).encode())


def _send(conn, answer):
    try:
        conn.settimeout(REQUEST_BOUND_S)
        conn.sendall(answer)
    except OSError:
        pass


class Server:
    """Accepts, checks the caller's uid at once, and serves each admitted caller in its own thread."""

    def __init__(self, sock, cfg, peer=peer_uid):
        self.sock = sock
        self.cfg = cfg
        self.peer = peer
        self.slots = {}
        self.mu = threading.Lock()
        self.admission = threading.Lock()

    def serve(self, stop=lambda: False):
        """Returns False when accept fails (the caller exits non-zero), True when stopped."""
        while not stop():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return False
            try:
                uid = self.peer(conn)
            except OSError:
                conn.close()
                continue
            if self.cfg.accounts.get(uid) is None:
                conn.close()
                continue
            with self.mu:
                if self.slots.get(uid, 0) >= PER_ACCOUNT_SLOTS:
                    conn.close()
                    continue
                self.slots[uid] = self.slots.get(uid, 0) + 1
            threading.Thread(target=self._one, args=(conn, uid), daemon=True).start()
        return True

    def _one(self, conn, uid):
        try:
            with conn:
                serve_one(conn, self.cfg, uid, self.admission)
        finally:
            with self.mu:
                self.slots[uid] -= 1


def bind_socket(lock_root, root_uid):
    """`<lock_root>/budget.sock`: a stale socket of the broker's own uid is replaced; anything else at that name
    stops the broker. Mode 0666: who may ask is decided by SO_PEERCRED, not by the file mode."""
    path = os.path.join(lock_root, SOCKET_NAME)
    try:
        st = os.lstat(path)
        if not stat.S_ISSOCK(st.st_mode) or st.st_uid != root_uid:
            raise SystemExit(2)
        os.unlink(path)
    except FileNotFoundError:
        pass
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    s.bind(path)
    os.chmod(path, 0o666)
    s.listen(8)
    return s


def serve(sock, cfg, stop=lambda: False):
    return Server(sock, cfg).serve(stop)


def clean_temporaries(lock_root):
    """At start, under the budget.d flock: remove `.tmp-` names left by a crash. A temporary is never a record (the
    rename moves it), and readers ignore the name; this only keeps the directory tidy."""
    budget = os.path.join(lock_root, "budget.d")
    bfd = os.open(budget, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fcntl.flock(bfd, fcntl.LOCK_EX)
        for sub in a2_budget.SUBDIRS:
            dfd = os.open(os.path.join(budget, sub), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                for name in os.listdir(dfd):
                    if name.startswith(".tmp-"):
                        _unlink(name, dfd)
            finally:
                os.close(dfd)
    finally:
        os.close(bfd)


def initial_user_namespace(read=os.readlink):
    try:
        return read("/proc/self/ns/user") == read("/proc/1/ns/user")
    except OSError:
        return False


def may_serve(geteuid=os.geteuid, namespace=initial_user_namespace):
    """Root, in the runner host's initial user namespace."""
    return geteuid() == 0 and namespace()


def accounts_of(loop_name, l3_name, getpwnam=pwd.getpwnam):
    """{uid: "loop" | "l3"} for two distinct accounts, neither of them root; None otherwise."""
    try:
        accounts = {getpwnam(loop_name).pw_uid: "loop", getpwnam(l3_name).pw_uid: "l3"}
    except KeyError:
        return None
    if len(accounts) != 2 or 0 in accounts or NOBODY in accounts:
        return None
    return accounts


def main(argv):
    args = dict(zip(argv[0::2], argv[1::2]))
    if (len(argv) != 8 or set(args) != {"--lock-root", "--loop-account", "--l3-account", "--usage-path"}
            or not os.path.isabs(args["--lock-root"]) or args["--usage-path"] not in ("a", "b")):
        return 2
    if not may_serve():
        return 2
    accounts = accounts_of(args["--loop-account"], args["--l3-account"])
    if accounts is None:
        return 2
    cfg = Config(args["--lock-root"], accounts, args["--usage-path"])
    os.umask(0o022)
    clean_temporaries(cfg.lock_root)
    return 0 if serve(bind_socket(cfg.lock_root, 0), cfg) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
