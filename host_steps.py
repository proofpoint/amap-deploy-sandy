"""The root-run steps of a hop deployment's host plan, as one small program
the operator runs, so that no step follows a symbolic link. `host-setup`
prints the calls; this module is what they run. Standard library only.

  python3 host_steps.py root  PATH UID GID MODE [--exclusive]
                                                  a root directory, created or fixed;
                                                  --exclusive: under the secret writer's lock
  python3 host_steps.py sync  DIR...              fsync each directory
  python3 host_steps.py place SRC DEST            the overlay, root-owned 0444
  python3 host_steps.py marker PATH               a random root marker, root-owned 0444
  python3 host_steps.py place SRC DEST --sha256 HEX
                                                  the same, refused unless SRC has that sha256
  python3 host_steps.py place SRC DEST --sha256 HEX --mode 0644
                                                  the same, root-owned 0644 (a LaunchDaemon's plist);
                                                  the mode is 0444 or 0644, nothing else

A runtime's secret file, in a directory that only that runtime's uid can open:

  python3 -I -S host_steps.py secret PATH UID GID          one line from a pipe, written 0400
  python3 -I -S host_steps.py secret --check PATH UID GID  the same checks, no value read
  python3 -I -S host_steps.py secret-remove PATH           the file and any crash temp removed
  python3 -I -S host_steps.py stat-secret DIR              its entries' metadata, as one JSON line
  python3 -I -S host_steps.py lock RUN_DIR -- ARGV...      ARGV run under RUN_DIR/oneshot.lock
  python3 -I -S host_steps.py probe-weekly STATUS RUN_ID [--engine unix:///SOCK] [--docker ABS] -- ARGV...
                                                  ARGV's one-line result kept in STATUS, refused
                                                  unless this interpreter, the docker client and
                                                  ARGV's program are root's alone

The weekly partition job's root half (see its section below):

  python3 -I -S -B host_steps.py partition-weekly --exec-root DIR --host NAME --document PATH --document-sha256 HEX
                                                  one run of the provisioned bundle, under the job's lock
  python3 -I -S -B host_steps.py partition-provision DIR
                                                  DIR/bundle.new swapped in as the bundle, under the lock

A supervisor's own check before it runs docker as root:

  python3 -I -S host_steps.py trusted-tools PYTHON3 DOCKER
                                                  exit 0 when both, and their startup closure, are
                                                  root's alone; 4 (and why, on stderr) otherwise

Every path is walked from `/` one component at a time, each opened with
O_NOFOLLOW | O_DIRECTORY, so a symbolic link anywhere on the way, or a
non-directory where a directory belongs, stops the step with an error and
changes nothing beneath it. A step is safe to run again: an existing root
is re-owned and re-moded through its own descriptor (unless it is owned by
someone else and not empty, which stops the step), an existing marker is
kept only if it is already a root-owned 0444 regular file with one link,
and the overlay replaces its destination by rename, never by writing
through it.

The secret steps hold a value no output may carry. Each refusal is a fixed
rule name, printed as `refused: <rule>` with exit 2; nothing printed is built
from the value, its length or where it differs. The value is kept as bytes
and never decoded. `secret` accepts stdin only from a pipe or a socket, takes
a lock on the directory so a second writer refuses rather than interleaves,
and replaces the file by rename from a temporary name in the same directory.
`lock` hands the command its own descriptor on the lock, so the lock lasts
until the command exits even when the wrapper is killed; it never reads
stdin.
"""

import calendar
import fcntl
import hashlib
import json
import os
import re
import resource
import signal
import stat
import struct
import subprocess
import sys
import time

_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
MARKER_MODE = 0o444
OVERLAY_MODE = 0o444
#: The modes `place` may set: read-only, or root-writable and world-readable.
PLACE_MODES = (0o444, 0o644)
#: Who owns the overlay and the markers: root.
OWNER_UID, OWNER_GID = 0, 0


class StepError(Exception):
    pass


def _parts(path):
    if not path.startswith("/") or os.path.normpath(path) != path or path.startswith("//"):
        raise StepError(f"{path}: not an absolute, normalised path")
    return [p for p in path.split("/") if p]


def open_dir(path, create=None, exclusive=False):
    """A descriptor for directory `path`, reached from / without following
    any link. With `create=(uid, gid, mode)`, the last component is made if
    absent, and owner and mode are set through its descriptor. With
    `exclusive`, the directory is flock'd first (as the secret writer locks
    it), and a held lock stops the step before anything changes."""
    parts = _parts(path)
    fd = os.open("/", _DIR)
    try:
        for i, name in enumerate(parts):
            last = i == len(parts) - 1
            existed = False
            if last and create is not None:
                try:
                    os.mkdir(name, 0o700, dir_fd=fd)
                except FileExistsError:
                    existed = True
            try:
                nxt = os.open(name, _DIR, dir_fd=fd)
            except OSError as e:
                where = "/" + "/".join(parts[:i + 1])
                raise StepError(f"{where}: not a real directory ({e.strerror}); nothing beneath it "
                                f"was touched") from None
            os.close(fd)
            fd = nxt
        if exclusive:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise StepError(f"{path}: concurrent writer; nothing changed") from None
        if create is not None:
            uid, gid, mode = create
            st = os.fstat(fd)
            if existed and (st.st_uid, st.st_gid) != (uid, gid) and os.listdir(fd):
                raise StepError(f"{path}: already exists, owned by {st.st_uid}:{st.st_gid} and not "
                                f"empty; not re-owned. Find out whose it is before running this again")
            os.fchown(fd, uid, gid)
            os.fchmod(fd, mode)
        return fd
    except BaseException:
        os.close(fd)
        raise


def root(path, uid, gid, mode, exclusive=False):
    fd = open_dir(path, create=(uid, gid, mode), exclusive=exclusive)
    os.close(fd)


def sync(*dirs):
    for d in dirs:
        fd = open_dir(d)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _split(path):
    parent, name = os.path.split(path)
    if not name or name in (".", ".."):
        raise StepError(f"{path}: names no file")
    return parent, name


def _read_source(src):
    """A place source's bytes: the file itself, never through a link, never
    a FIFO or device (opened without blocking, then held to a regular file
    with one link), and at most DOC_MAX bytes, read to one more so a larger
    file is seen and refused rather than truncated."""
    try:
        fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except OSError as e:
        raise StepError(f"{src}: {e.strerror}; nothing placed") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise StepError(f"{src} is not a regular file with one link; nothing placed")
        chunks, total = [], 0
        while total <= DOC_MAX:
            chunk = os.read(fd, DOC_MAX + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        os.close(fd)
    if total > DOC_MAX:
        raise StepError(f"{src} is larger than {DOC_MAX} bytes; nothing placed")
    return b"".join(chunks)


def place(src, dest, sha256=None, mode=OVERLAY_MODE):
    """Copy `src` to `dest` as a root-owned file, 0444 unless `mode` is the
    one other mode allowed (0644): written under a fresh
    temporary name in dest's directory (O_EXCL, O_NOFOLLOW), then renamed
    over dest, so a link at dest is replaced, never written through. With
    `sha256`, the bytes read are checked against it before anything is
    written, so the route `src` arrived by does not have to be trusted."""
    if mode not in PLACE_MODES:
        raise StepError(f"mode {mode:04o} is not one of " + ", ".join(f"{m:04o}" for m in PLACE_MODES))
    parent, name = _split(dest)
    data = _read_source(src)
    if sha256 is not None and hashlib.sha256(data).hexdigest() != sha256.lower():
        raise StepError(f"{src}: sha256 is not the pinned {sha256}; nothing placed")
    dfd = open_dir(parent)
    tmp = f".{name}.{os.getpid()}.tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
        try:
            os.write(fd, data)
            os.fchown(fd, OWNER_UID, OWNER_GID)
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        os.fsync(dfd)
    finally:
        os.close(dfd)


def marker(path):
    """16 random bytes as hex, in a new root-owned 0444 file. An existing
    marker is kept only if it is already a root-owned 0444 regular file."""
    parent, name = _split(path)
    dfd = open_dir(parent)
    try:
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
        except FileExistsError:
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
            except OSError as e:
                raise StepError(f"{path}: exists and is not a regular file ({e.strerror})") from None
            try:
                st = os.fstat(fd)
            finally:
                os.close(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != OWNER_UID or st.st_nlink != 1 \
                    or stat.S_IMODE(st.st_mode) != MARKER_MODE:
                raise StepError(f"{path}: exists, but is not a root-owned 0444 file with one link; "
                                f"not ours, left alone")
            print(f"{path}: kept")
            return
        try:
            os.write(fd, os.urandom(16).hex().encode("ascii"))
            os.fchown(fd, OWNER_UID, OWNER_GID)
            os.fchmod(fd, MARKER_MODE)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(dfd)
    finally:
        os.close(dfd)


# ---- a runtime's secret file ------------------------------------------------

#: The most a valid line can take: the value's 4096 bytes plus its newline.
MAX_VALUE = 4096
MAX_LINE = MAX_VALUE + 1
SECRET_MODE = 0o400
SECRET_DIR_MODE = 0o700
#: The value's alphabet, shared with the reader: printable ASCII, no space.
ALPHABET = frozenset(range(0x21, 0x7F))
PR_SET_DUMPABLE = 4
LOCK_FILE = "oneshot.lock"
#: How long `lock` waits for another holder before it refuses.
LOCK_WAIT_S = 60
LOCK_POLL_S = 0.25
#: The exit for every refusal of the secret steps.
REFUSED = 2


class Refused(Exception):
    """A secret step's refusal. Its only text is a fixed rule name."""

    def __init__(self, rule):
        super().__init__(rule)
        self.rule = rule


def no_dumps():
    """No core file and no same-uid ptrace for this process, before any value
    is read. RLIMIT_CORE alone is ignored by a piped core handler;
    PR_SET_DUMPABLE is Linux's, where the writer runs, and a failing prctl
    refuses."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if sys.platform.startswith("linux"):
        import ctypes   # here, so the other steps never depend on it
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise Refused("dumpable")


def _names(path):
    parent, name = _split(path)
    return parent, name, f".{name}.tmp"


def _stdin_is_a_pipe():
    try:
        mode = os.fstat(0).st_mode
    except OSError:
        raise Refused("stdin") from None
    if not (stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)):
        raise Refused("stdin")


def _secret_dir(parent, uid, gid):
    """The directory's descriptor, reached without following a link, and
    owned uid:gid with mode 0700."""
    try:
        dfd = open_dir(parent)
    except StepError:
        raise Refused("directory") from None
    st = os.fstat(dfd)
    if (st.st_uid, st.st_gid) != (uid, gid) or stat.S_IMODE(st.st_mode) != SECRET_DIR_MODE:
        os.close(dfd)
        raise Refused("directory")
    return dfd


def _writer_lock(dfd):
    """The writer's own lock, on the directory: a second writer in another
    container sees the same inode and refuses instead of interleaving. The
    descriptor is open_dir's (O_RDONLY | O_DIRECTORY), never O_PATH, on
    which flock fails."""
    try:
        fcntl.flock(dfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise Refused("concurrent writer") from None


def _entries(dfd, name, tmp, uid):
    """Every entry, checked without opening any: only the file and its crash
    temp may be there. Returns which of the two exist."""
    found = set()
    for entry in os.listdir(dfd):
        if entry not in (name, tmp):
            raise Refused("unexpected entry")
        st = os.stat(entry, dir_fd=dfd, follow_symlinks=False)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise Refused("entry type")
        if entry == name and (st.st_uid != uid or stat.S_IMODE(st.st_mode) != SECRET_MODE):
            raise Refused("entry owner or mode")
        if entry == tmp and (st.st_uid not in (0, uid) or st.st_mode & 0o077):
            raise Refused("entry owner or mode")
        found.add(entry)
    return found


def _read_line():
    """The value from stdin: read to EOF, refused past MAX_LINE bytes, and
    required to end in exactly one newline, which marks a complete line, so
    a producer that died mid-write leaves nothing that passes."""
    buf = bytearray()
    while True:
        chunk = os.read(0, MAX_LINE + 1 - len(buf))
        if not chunk:
            break
        buf += chunk
        if len(buf) > MAX_LINE:
            raise Refused("too long")
    if not buf.endswith(b"\n"):
        raise Refused("incomplete line")
    # MAX_LINE and the required newline together bound the value at MAX_VALUE.
    value = bytes(buf[:-1])
    if not value:
        raise Refused("empty")
    if any(b not in ALPHABET for b in value):
        raise Refused("alphabet")
    return value


def secret(path, uid, gid):
    """One value from a pipe into `path`, owner uid:gid, mode 0400, replaced by
    rename from a temporary name in the same directory."""
    no_dumps()
    _stdin_is_a_pipe()
    parent, name, tmp = _names(path)
    dfd = _secret_dir(parent, uid, gid)
    try:
        _writer_lock(dfd)
        if tmp in _entries(dfd, name, tmp, uid):
            os.unlink(tmp, dir_fd=dfd)
            os.fsync(dfd)
        value = _read_line()
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     SECRET_MODE, dir_fd=dfd)
        try:
            try:
                os.fchown(fd, uid, gid)
                os.fchmod(fd, SECRET_MODE)
                view = memoryview(value)
                while view:
                    view = view[os.write(fd, view):]
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or (st.st_uid, st.st_gid) != (uid, gid) \
                        or stat.S_IMODE(st.st_mode) != SECRET_MODE or st.st_nlink != 1 \
                        or st.st_size != len(value):
                    raise Refused("written file")
                os.fsync(fd)
            finally:
                os.close(fd)
            os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        except BaseException:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except OSError:
                pass
            raise
        os.fsync(dfd)
    finally:
        os.close(dfd)
    print(f"wrote {path} (0400 {uid}:{gid})")


def secret_check(path, uid, gid):
    """Every check `secret` makes before it reads, with no value read and
    nothing changed: proof, through the same route, that the write would be
    accepted."""
    no_dumps()
    _stdin_is_a_pipe()
    parent, name, tmp = _names(path)
    dfd = _secret_dir(parent, uid, gid)
    try:
        found = _entries(dfd, name, tmp, uid)
    finally:
        os.close(dfd)
    print(f"ok: {path} {'present' if name in found else 'absent'}")


def secret_remove(path):
    """The file and any crash temp gone, under the writer's lock. The expected
    owner is the directory's."""
    parent, name, tmp = _names(path)
    try:
        dfd = open_dir(parent)
    except StepError:
        raise Refused("directory") from None
    try:
        st = os.fstat(dfd)
        if stat.S_IMODE(st.st_mode) != SECRET_DIR_MODE:
            raise Refused("directory")
        _writer_lock(dfd)
        for entry in sorted(_entries(dfd, name, tmp, st.st_uid)):
            os.unlink(entry, dir_fd=dfd)
        os.fsync(dfd)
    finally:
        os.close(dfd)
    print(f"removed {path}")


def stat_secret(directory):
    """The directory's and each entry's metadata, by lstat alone: no file is
    opened, so nothing here can read a value."""
    try:
        dfd = open_dir(directory)
    except StepError:
        raise Refused("directory") from None
    try:
        st = os.fstat(dfd)
        doc = {"uid": st.st_uid, "gid": st.st_gid, "mode": f"{stat.S_IMODE(st.st_mode):04o}",
               "entries": []}
        for entry in sorted(os.listdir(dfd)):
            e = os.stat(entry, dir_fd=dfd, follow_symlinks=False)
            doc["entries"].append({
                "name": entry, "regular": stat.S_ISREG(e.st_mode), "uid": e.st_uid,
                "gid": e.st_gid, "mode": f"{stat.S_IMODE(e.st_mode):04o}", "nlink": e.st_nlink,
                "nonempty": e.st_size > 0})
    finally:
        os.close(dfd)
    print(json.dumps(doc, sort_keys=True))


def _open_lock(run_dir):
    """RUN_DIR/oneshot.lock, made by host-setup: opened read-only, never
    created here, and only if it is a regular file."""
    try:
        dfd = open_dir(run_dir)
    except StepError:
        raise Refused("lock") from None
    try:
        fd = os.open(LOCK_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=dfd)
    except OSError:
        raise Refused("lock") from None
    finally:
        os.close(dfd)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise Refused("lock")
    return fd


def _take(fd, wait_s):
    deadline = time.monotonic() + wait_s
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise Refused("lock") from None
            time.sleep(LOCK_POLL_S)


def _exit_status(returncode):
    """A signal death (-n) as 128+n, as a shell reports it, so it survives
    the wrapper and ssh."""
    return 128 - returncode if returncode < 0 else returncode


def lock(run_dir, argv):
    """`argv` run under the exclusive lock. The child gets its own duplicate
    of the lock descriptor, so the lock outlives this wrapper. stdin, stdout
    and stderr pass straight through; this process never reads stdin."""
    if not argv or not os.path.isabs(argv[0]):
        raise Refused("lock")
    fd = _open_lock(run_dir)
    _take(fd, LOCK_WAIT_S)
    child_fd = os.dup(fd)
    try:
        child = subprocess.Popen(argv, shell=False, close_fds=True, pass_fds=(child_fd,),
                                 restore_signals=True)
    except OSError:
        raise Refused("lock") from None
    finally:
        os.close(child_fd)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    return _exit_status(child.wait())


#: RE's probe contract: each class with the one exit code it comes with.
#: A line and an exit that disagree are a protocol error, never a pass.
PROBE_OK = "ok"
PROBE_EXITS = {"ok": 0, "secret_unavailable": 5, "auth_failed": 6, "hub_unreachable": 7,
               "tls_failed": 8, "connect_failed": 9, "protocol_error": 10, "temporary": 11}
#: The container engine's own "could not run the container" exit.
ENGINE_EXIT = 125
RUN_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")


#: An SMTP reply code, or "-" when none was reached.
SMTP_CODE = re.compile(r"\d{3}|-")
#: The most of the probe's stdout that is ever read: one short line.
PROBE_OUT_MAX = 4096


def probe_class(stdout, returncode):
    """(class, code) from the probe's one line and its exit: the line's class
    only when its exit is exactly the contract's for that class and its code
    is an SMTP code or "-". engine_unavailable is never the probe's to say."""
    if returncode == ENGINE_EXIT:
        return "engine_unavailable", "-"
    if len(stdout) > PROBE_OUT_MAX:
        return "protocol_error", "-"
    words = stdout.decode("ascii", "replace").split()
    if len(words) == 2 and PROBE_EXITS.get(words[0]) == returncode and SMTP_CODE.fullmatch(words[1]):
        return words[0], words[1]
    return "protocol_error", "-"


def engine_answers(endpoint):
    """Whether the engine at `unix:///abs/path` is there to ask: the path is
    a socket and accepts a connection. Anything else is a stopped engine."""
    import socket
    if not endpoint.startswith("unix:///"):
        raise Refused("probe")
    path = endpoint[len("unix://"):]
    try:
        if not stat.S_ISSOCK(os.stat(path).st_mode):
            return False
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect(path)
        return True
    except OSError:
        return False


#: How long the probe may run. Its own phase budgets keep it well inside.
PROBE_TIMEOUT_S = 300
RUN_LABEL = "org.amap.run"


def _remove_run(docker, run_id):
    """Remove every container labelled with this run: a timeout kills the
    docker client, not the container, which would go on holding the secret
    volume. Best effort; the sweep reports any that remain."""
    try:
        ids = subprocess.run(docker + ["ps", "--all", "--quiet", "--filter", f"label={RUN_LABEL}={run_id}"],
                             shell=False, close_fds=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=60).stdout.decode("ascii", "replace").split()
        if ids:
            subprocess.run(docker + ["rm", "--force"] + ids, shell=False, close_fds=True,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        pass


def probe_weekly(status_path, run_id, argv, now=None, engine=None, docker=None, verify=None):
    """Run the probe command and keep its result in `status_path`: the class,
    its SMTP code, the time, this run's id, the previous run's class, and
    when the probe last passed. With `engine`, a stopped engine is recorded
    as engine_unavailable without running anything. With `docker` (the
    engine's client argv), a probe that outruns its timeout has its
    containers removed by this run's label, and is recorded as timeout.
    Exits with the probe's
    status. Run it under `lock`, never the reverse: a busy lock is the
    wrapper's refusal, not a probe result. Root runs it, so before anything
    runs, `verify` (by default `_verify_probe_tools`) must find this
    interpreter, the docker client and ARGV's program root's alone; when it
    does not, the step is refused and nothing is run or recorded."""
    if not argv or not os.path.isabs(argv[0]) or not RUN_ID.fullmatch(run_id) \
            or (docker is not None and not (docker and os.path.isabs(docker[0]))):
        raise Refused("probe")
    try:
        (verify or _verify_probe_tools)(argv[0], docker)
    except Tooling:
        raise Refused("tools") from None
    at = int(now if now is not None else time.time())
    if engine is not None and not engine_answers(engine):
        cls, code, rc = "engine_unavailable", "-", REFUSED
    else:
        try:
            done = subprocess.run(argv, shell=False, close_fds=True, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  restore_signals=True, timeout=PROBE_TIMEOUT_S)
            rc = _exit_status(done.returncode)
            cls, code = probe_class(done.stdout, rc)
        except subprocess.TimeoutExpired:
            if docker is not None:
                _remove_run(docker, run_id)
            cls, code, rc = "timeout", "-", REFUSED
        except OSError:
            cls, code, rc = "engine_unavailable", "-", REFUSED
    parent, name = _split(status_path)
    previous = {}
    dfd = open_dir(parent)
    try:
        try:
            pfd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
            with os.fdopen(pfd, "rb") as f:
                previous = json.loads(f.read(65536) or b"{}")
        except (OSError, ValueError):
            previous = {}
        if not isinstance(previous, dict):
            previous = {}
        doc = {"class": cls, "smtp_code": code, "at": at, "run_id": run_id,
               "previous_class": previous.get("class"),
               "last_ok_at": at if cls == PROBE_OK else previous.get("last_ok_at")}
        tmp = f".{name}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644,
                     dir_fd=dfd)
        try:
            try:
                os.write(fd, (json.dumps(doc, sort_keys=True) + "\n").encode("ascii"))
                os.fchmod(fd, 0o644)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        except BaseException:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except OSError:
                pass
            raise
        os.fsync(dfd)
    finally:
        os.close(dfd)
    return rc


def _verify_probe_tools(program, docker):
    """What probe-weekly will run as root, as partition-weekly verifies its
    own: the interpreter running this step, the docker client (`docker`, else
    the program), and the program, each a root-owned executable under
    root-owned directories, with the startup closure root's alone. Tooling
    otherwise."""
    python = sys.executable
    if not python or not os.path.isabs(python):
        raise Tooling("the running interpreter has no absolute path")
    client = docker[0] if docker else program
    py, dock = _trusted_tool(python), _trusted_tool(client)
    _trusted_tool(program)
    bad = closure_problems(startup_closure(py, dock, (python, client, program)))
    if bad:
        raise Tooling("the startup closure is not root's alone: " + "; ".join(bad[:5]))


def _probe_weekly_main(argv):
    """probe-weekly STATUS RUN_ID [--engine unix:///SOCK] [--docker ABS] -- ARGV"""
    cut = argv.index("--", 3)
    opts, rest = argv[3:cut], argv[cut + 1:]
    engine = docker = None
    while opts:
        if opts[0] == "--engine" and len(opts) > 1 and engine is None:
            engine, opts = opts[1], opts[2:]
        elif opts[0] == "--docker" and len(opts) > 1 and docker is None:
            docker, opts = [opts[1]], opts[2:]
        else:
            raise Refused("usage")
    return probe_weekly(argv[1], argv[2], rest, engine=engine, docker=docker)


# --- The weekly partition job: its root half -------------------------------------------
#
# `partition-weekly` runs the partition probes from the provisioned bundle as
# root, and `partition-provision` swaps a newly provisioned bundle in. Both hold
# `<exec_root>/lock`. The job's lock descriptor is passed to its child, so the
# lock is held until every process of the run is gone, even when this process
# dies first. What the job trusts: this file, the unit's argv (the exec root,
# the host, the approved document's path and sha256), the document's exact
# bytes once they match that sha256, the bundle only root provisioned, and the
# root-owned tools and their startup closure. It never runs git, and never
# reads the operator's clones.
#
# Everything the job will run, and every root it will write under, is verified
# BEFORE its first engine call: the tools and their startup closure, the engine
# socket, the bundle, the evidence directory and the live config's directory,
# and the recovery description. Only then is any abandoned run decided.
#
# This file imports nothing of the library. The records it reads (each run's
# context, expectation and outcome, the evidence document, the incident) are
# read by their own exact grammars here, the evidence and the incident grammars
# being copies of partition_evidence's and partition_incident's that a test
# holds equal to them.

CONTEXT_SCHEMA = "amap-deploy.partition-context/2"
#: The context before the run mode was recorded: read as a weekly run's.
CONTEXT_SCHEMA_V1 = "amap-deploy.partition-context/1"
EXPECT_SCHEMA = "amap-deploy.partition-expect/1"
OUTCOME_SCHEMA = "amap-deploy.partition-outcome/1"
RECOVERY_SCHEMA = "amap-deploy.partition-recovery/1"
EVIDENCE_SCHEMA = "amap-deploy.partition-evidence/1"
#: The job's exits: passed; a fail-stop incident handled; refused (usage);
#: a handoff (could not complete, nothing stopped); tooling not verified.
EXIT_PASS, EXIT_INCIDENT, EXIT_HANDOFF, EXIT_TOOLING = 0, 1, 3, 4
#: How long the child may run before its group is killed: the probes' own
#: budgets keep it well inside.
CHILD_TIMEOUT_S = 3600
#: The bundle's bounds, checked before anything is read.
BUNDLE_MAX_FILES, BUNDLE_FILE_MAX, BUNDLE_MAX_BYTES = 64, 1 << 20, 8 << 20
BUNDLE, CLOSURE, PIN, LAUNCHER = "bundle", "partition_weekly.closure", "PIN", "partition_weekly.py"
RUN_PREFIX = "run-"
RUN_NAME = re.compile(r"run-([A-Za-z0-9._-]{1,64})")
DOC_MAX = 1 << 20
#: `docker stop -t` for the local router, as its supervision renders it.
STOP_TIMEOUT_S = 100
#: One engine call's bound (`_Engine.run`'s).
ENGINE_CALL_S = STOP_TIMEOUT_S + 60
#: The most engine calls the parent makes after its child ends: remove_run's
#: ps and rm, then on a fail-stop _act's running (an inspect, then a ps),
#: stop, and running again (a test counts them on that trace).
POST_CHILD_ENGINE_CALLS = 7
#: The filesystem work, the publications and the wait after a kill.
STALE_MARGIN_S = 600
#: How long a run may be recorded as running before verify reads it as
#: overdue: the child's bound, the parent's calls after it, and the margin.
#: A conservative threshold, never a proof that anything stopped.
STALE_AFTER_S = CHILD_TIMEOUT_S + POST_CHILD_ENGINE_CALLS * ENGINE_CALL_S + STALE_MARGIN_S
INCIDENT_PREFIX = "incident-"
#: Who must own what the job trusts: root.
ROOT_UID, ROOT_GID = 0, 0
#: The evidence directory's mode, as host-setup makes it.
EVIDENCE_DIR_MODE = 0o755
#: How far a placed file's time may precede the run's start (clock grain).
PLACED_SLACK_S = 2
#: The operating system's own tools that list a binary's linked libraries.
LDD, OTOOL, XCODE_SELECT = "/usr/bin/ldd", "/usr/bin/otool", "/usr/bin/xcode-select"
#: ELF: the program header naming the interpreter (a dynamic binary's loader),
#: the dynamic section's, and its entries naming a needed library and its end.
PT_INTERP, PT_DYNAMIC, DT_NEEDED, DT_NULL = 3, 2, 1, 0
#: Where macOS keeps system libraries in the dyld shared cache, on the sealed system volume, not on disk.
SEALED_PREFIXES = ("/usr/lib/", "/System/Library/")

_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_AT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")

# The evidence document's grammar: a copy of partition_evidence's.
EVIDENCE_MEMBERS = frozenset({"schema", "host", "run_id", "at", "script_sha256", "bindings", "probes", "fail_stop",
                              "delegation_partition_verified"})
PROBE_MEMBERS = frozenset({"id", "vantage", "operation", "target_role", "outcome", "witness", "verdict"})
PROBE_IDS = ("P01", "P02", "P03", "P04")
FAIL_STOP = ("P03", "P04")
VERDICTS = ("PASS", "FAIL", "UNKNOWN")
TOKEN_MEMBER = "delegation_partition_verified"
VANTAGE_MEMBERS = frozenset({"container", "image", "uid", "gids"})
WITNESS_MEMBERS = frozenset({"operation", "outcome"})
REQUIRED_ROLES = {"P03": frozenset({"key:signing", "key:dir"})}
_RUN_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_ROLE = re.compile(r"(key:(signing|dir)|mount:[A-Za-z0-9._/-]{1,128}|peer:[A-Za-z0-9._-]{1,64}"
                   r"|marker:(up|down)/[A-Za-z0-9._-]{1,64}|runtime:[A-Za-z0-9._-]{1,64})")
_OUTCOME = re.compile(r"E[A-Z0-9]{1,15}|ok|unresolved")

# The incident record's grammar: a copy of partition_incident's.
ACTIONS = ("rewrite", "stop")
EVENT_GRAMMAR = {
    "rewrite_ok": ({}, {"observed": "text"}),
    "rewrite_failed": ({"reason": "text"}, {}),
    "stop_ok": ({"id": "text"}, {"observed": "text"}),
    "stop_failed": ({"reason": "text"}, {"id": "text"}),
    "stop_not_attempted": ({"reason": "text"}, {}),
    "stop_not_required": ({"reason": "text"}, {}),
    "resolved": ({"evidence": "text", "reason": "text"}, {}),
}
_COMMON = ({"at": "text"}, {"completion": "bool", "by": "text"})
DETECTED_REQUIRED = {"run_id": str, "at": str, "failing": list, "pending": list}
DETECTED_OPTIONAL = {"token": (str, type(None)), "identity": (str, type(None)), "failing_evidence_persisted": bool,
                     "recorded_late": bool, "taken_without_record": bool, "recorded_by": str, "mode": str}
MODES = ("weekly", "prospective")
NO_DELEGATION = "the live config carries no delegation"

# Each run record's members and types, exactly.
_OPT_STR = (str, type(None))
CONTEXT_MEMBERS_V1 = {"schema": str, "run_id": str, "host": str, "started_at": str, "evidence_dir": str,
                      "live_config_path": str, "router_container_id": _OPT_STR, "engine": str, "docker": str}
CONTEXT_MEMBERS = dict(CONTEXT_MEMBERS_V1, mode=str)
EXPECT_MEMBERS = {"schema": str, "run_id": str, "host": str, "bindings": dict}
OUTCOME_MEMBERS = {"schema": str, "run_id": str, "code": int, "incident": bool, "router_seen": _OPT_STR, "why": str,
                   "config_sha256": _OPT_STR, "evidence_run_id": _OPT_STR, "evidence_sha256": _OPT_STR,
                   "inspect_digest": _OPT_STR}
RECOVERY_MEMBERS = {"schema": str, "host": str, "run_id": str, "at": str, "evidence_dir": str, "live_config_path": str,
                    "engine": str, "docker": str, "router_container_id": str, "config_sha256": str,
                    "evidence_run_id": str, "evidence_sha256": str, "inspect_digest": str, "activation_sha256": str}
#: The stop target's copy in the evidence directory, for verify only: the job
#: never reads it, and the library's store cannot write it (it is outside
#: partition_setup.EVIDENCE_NAME).
STOP_TARGET = "stop-target.json"
#: The weekly job's record of the runs it has not finished deciding, beside
#: the stop target: a writer-only name, outside EVIDENCE_NAME, so the child's
#: store can neither create nor replace it.
WEEKLY_RUNS = "weekly-runs.json"
RUNS_SCHEMA = "amap-deploy.partition-runs/1"
RUNNING, KEPT, UNDECIDED = "running", "kept", "undecided"
#: A1's approved record, placed by the operator, read only under the unit's digest.
ACTIVATION = "activation.json"


def _ancestor_ok(st):
    """A directory above a trusted path: root's, and no one else can write it."""
    return st.st_uid == ROOT_UID and not st.st_mode & 0o022


class Handoff(Exception):
    """The run cannot proceed, and nothing is stopped: the reason is reported."""


class Tooling(Exception):
    """What root would run is not as provisioned: tamper or misconfiguration."""


def _strict_json(raw):
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise ValueError(f"duplicate key {k!r}")
            out[k] = v
        return out

    def no_constant(name):
        raise ValueError(f"non-finite number {name}")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=no_constant)


def _canonical(doc):
    """partition_evidence's canonical form, exactly."""
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _typed(doc, members, schema):
    """`doc` exactly `members`, each of its type (a bool is never an int), and
    the given schema."""
    if not isinstance(doc, dict) or set(doc) != set(members) or doc.get("schema") != schema:
        return False
    for k, t in members.items():
        v = doc[k]
        if t is int:
            if not _int(v):
                return False
        elif isinstance(v, bool) and t is not bool:
            return False
        elif not isinstance(v, t):
            return False
    return True


def _at_seconds(at):
    return calendar.timegm(time.strptime(at, "%Y-%m-%dT%H:%M:%SZ"))


def _read_at(dfd, name, limit, want=None):
    """A regular file in `dfd`, opened without following a link, checked on
    the descriptor it is read from (`want`: (uid, gid, mode, nlink) it must
    have), and read up to `limit` bytes. Returns (bytes, its stat)."""
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"{name} is not a regular file")
        if want is not None and (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_nlink) != want:
            raise ValueError(f"{name} is not {want[0]}:{want[1]} {oct(want[2])} with {want[3]} link(s)")
        if st.st_size > limit:
            raise ValueError(f"{name} is over {limit} bytes")
        chunks, total = [], 0
        while total <= limit:
            b = os.read(fd, limit + 1 - total)
            if not b:
                break
            chunks.append(b)
            total += len(b)
        if total > limit:
            raise ValueError(f"{name} is over {limit} bytes")
        return b"".join(chunks), st
    finally:
        os.close(fd)


def _record(dfd, name, members, schema):
    """A run record by its exact grammar, or None: absent, truncated,
    malformed and mistyped are all "not there", never repaired."""
    try:
        doc = _strict_json(_read_at(dfd, name, DOC_MAX)[0])
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    return doc if _typed(doc, members, schema) else None


def _write_at(dfd, name, data, mode, exclusive=False, keep=False):
    """`name` in `dfd`: written under a fresh temporary name (O_EXCL), then
    linked into place when `exclusive` (it must not exist) or renamed over it;
    with `keep`, the existing file's owner and mode are kept."""
    owner = None
    if keep:
        old = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        if not stat.S_ISREG(old.st_mode):
            raise ValueError(f"{name} is not a regular file")
        owner, mode = (old.st_uid, old.st_gid), stat.S_IMODE(old.st_mode)
    tmp = f".{name}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
    try:
        try:
            os.write(fd, data)
            if owner is not None:
                os.fchown(fd, *owner)
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        if exclusive:
            os.link(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
            os.unlink(tmp, dir_fd=dfd)
        else:
            os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
    except BaseException:
        try:
            os.unlink(tmp, dir_fd=dfd)
        except OSError:
            pass
        raise
    os.fsync(dfd)


def _remove_tree(dfd, name):
    """`name` under `dfd` and everything in it, never following a link."""
    st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    if not stat.S_ISDIR(st.st_mode):
        os.unlink(name, dir_fd=dfd)
        return
    sub = os.open(name, _DIR, dir_fd=dfd)
    try:
        os.fchmod(sub, 0o700)  # a read-only tree (a bundle) is being removed whole
        for n in os.listdir(sub):
            _remove_tree(sub, n)
    finally:
        os.close(sub)
    os.rmdir(name, dir_fd=dfd)


def _walk(path, ok_ancestor, ok_last, what):
    """A descriptor for directory `path`, reached from / without following a
    link, each directory above it passing `ok_ancestor` and the last
    `ok_last` (each given its stat); Tooling naming the first that fails."""
    parts = _parts(path)
    fd = os.open("/", _DIR)
    try:
        for i, name in enumerate(parts):
            if not ok_ancestor(os.fstat(fd)):
                raise Tooling(f"{what}: {'/' + '/'.join(parts[:i])} is not root-owned, or is writable by others")
            nxt = os.open(name, _DIR, dir_fd=fd)
            os.close(fd)
            fd = nxt
        if not ok_last(os.fstat(fd)):
            raise Tooling(f"{what}: {path} is not as the job requires (owner or mode)")
        return fd
    except OSError as e:
        os.close(fd)
        raise Tooling(f"{what}: {path}: not a real directory ({e.strerror})") from None
    except BaseException:
        os.close(fd)
        raise


def _root_dir(path, mode):
    """`path`, root:root with exactly `mode`, under root-owned parents that
    no one else can write."""
    return _walk(path, _ancestor_ok,
                 lambda st: (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) == (ROOT_UID, ROOT_GID, mode),
                 f"the job's directory (root:root {oct(mode)})")


def _evidence_dir(path):
    """The evidence directory, as host-setup makes it: root:root 0755 under
    root-owned parents that no one else can write."""
    return _walk(path, _ancestor_ok,
                 lambda st: (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) == (ROOT_UID, ROOT_GID, EVIDENCE_DIR_MODE),
                 "the evidence directory (root:root 0755)")


def _config_dir(path):
    """The local router's live config's directory, and the config in it: the
    directory and every one above it owned by root or by the config's own
    owner, and writable by no one else; the config a regular file, not a
    link, that no one but its owner can write."""
    parent, name = _split(path)
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError as e:
        raise Tooling(f"the live config {path}: {e.strerror}") from None
    if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o022:
        raise Tooling(f"the live config {path} is not a regular file only its owner can write")
    owners = {ROOT_UID, st.st_uid}

    def ok(s):
        return s.st_uid in owners and not s.st_mode & 0o022
    return _walk(parent, lambda s: _ancestor_ok(s) or ok(s), ok, "the live config's directory"), name


def _related(a, b):
    a, b = a.rstrip("/"), b.rstrip("/")
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


def _take_partition_lock(efd):
    fd = os.open("lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=efd)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != ROOT_UID:
        os.close(fd)
        raise Tooling("the lock is not a root-owned regular file")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise Handoff("another run holds the lock") from None
    return fd


def _document(path, sha256):
    """The approved document's exact bytes and its host-setup section. A
    document that is not the one the unit approved is a handoff."""
    parent, name = _split(path)
    try:
        dfd = open_dir(parent)
        try:
            raw = _read_at(dfd, name, DOC_MAX)[0]
        finally:
            os.close(dfd)
    except (OSError, ValueError, StepError) as e:
        raise Handoff(f"the approved document cannot be read: {e}") from None
    if hashlib.sha256(raw).hexdigest() != sha256:
        raise Handoff("the document is not the one the unit approved: re-render the unit after an overlay change")
    try:
        doc = _strict_json(raw)
    except (ValueError, UnicodeDecodeError) as e:
        raise Handoff(f"the approved document does not parse: {e}") from None
    sec = doc.get("host_setup", doc) if isinstance(doc, dict) else None
    if not isinstance(sec, dict):
        raise Handoff("the approved document has no host_setup object")
    return raw, sec


def _activation(evidence_dir, path, sha256):
    """A1's approved record's exact bytes, at its one place, only when they
    hash to the unit's digest; a handoff otherwise."""
    if path != os.path.join(evidence_dir, ACTIVATION):
        raise Handoff(f"the unit's activation record is not {os.path.join(evidence_dir, ACTIVATION)}")
    try:
        evfd = _evidence_dir(evidence_dir)
        try:
            raw = _read_at(evfd, ACTIVATION, DOC_MAX, want=(ROOT_UID, ROOT_GID, 0o444, 1))[0]
        finally:
            os.close(evfd)
    except (OSError, ValueError) as e:
        raise Handoff(f"the approved activation record cannot be read: {e}") from None
    if hashlib.sha256(raw).hexdigest() != sha256:
        raise Handoff("the activation record is not the one the unit approved: re-render the unit after A1")
    return raw


def _authority(sec, exec_root):
    """What the approved document selects, held to the unit's exec root, with
    no root of the job's inside another."""
    try:
        part = sec["partition"]
        values = {"evidence_dir": part["evidence_dir"], "exec_root": part["exec_root"],
                  "python3": part["tools"]["python3"], "docker": part["tools"]["docker"],
                  "engine": sec["supervision"]["engine"], "live_config": sec["keys"]["local_config"],
                  "pin": sec["secrets"]["clones"]["deploy"]["sha"]}
    except (KeyError, TypeError):
        raise Handoff("the approved document lacks what the weekly job needs") from None
    if values["exec_root"] != exec_root:
        raise Handoff("the approved document's exec_root is not the unit's")
    for k in ("evidence_dir", "python3", "docker", "live_config"):
        if not isinstance(values[k], str):
            raise Handoff(f"the approved document's {k} is not a path")
        _parts(values[k])
    if not isinstance(values["pin"], str) or not _HEX40.fullmatch(values["pin"]):
        raise Handoff("the approved document's deploy pin is not a commit sha")
    roots = [("evidence_dir", values["evidence_dir"]), ("exec_root", exec_root),
             ("the live config's directory", os.path.dirname(values["live_config"]))]
    for i, (a, pa) in enumerate(roots):
        for b, pb in roots[i + 1:]:
            if _related(pa, pb):
                raise Handoff(f"the approved document's {a} and {b} overlap")
    return values


def _verify_bundle(efd, pin):
    """The provisioned bundle: root's, flat, only regular files no one else
    can write, exactly the closure list plus the list and PIN, each valid
    UTF-8 holding no NUL, within the bounds; PIN equal to the deploy pin."""
    try:
        bfd = os.open(BUNDLE, _DIR, dir_fd=efd)
    except OSError as e:
        raise Tooling(f"no bundle: {e.strerror}") from None
    try:
        st = os.fstat(bfd)
        if st.st_uid != ROOT_UID or st.st_mode & 0o222:
            raise Tooling("the bundle directory is not root's and read-only")
        names = os.listdir(bfd)
        if len(names) > BUNDLE_MAX_FILES:
            raise Tooling("the bundle holds too many files")
        total, contents = 0, {}
        for n in names:
            try:
                data, fst = _read_at(bfd, n, BUNDLE_FILE_MAX)
            except (OSError, ValueError) as e:
                raise Tooling(f"bundle file {n!r}: {e}") from None
            if fst.st_uid != ROOT_UID or fst.st_mode & 0o222:
                raise Tooling(f"bundle file {n!r} is not root's and read-only")
            total += len(data)
            if total > BUNDLE_MAX_BYTES:
                raise Tooling("the bundle is over its size bound")
            if b"\0" in data:
                raise Tooling(f"bundle file {n!r} holds a NUL")
            try:
                contents[n] = data.decode("utf-8")
            except UnicodeDecodeError:
                raise Tooling(f"bundle file {n!r} is not UTF-8") from None
        if CLOSURE not in contents or PIN not in contents:
            raise Tooling("the bundle has no closure list or no PIN")
        closure = [l for l in contents[CLOSURE].splitlines() if l]
        if LAUNCHER not in closure or set(names) != set(closure) | {CLOSURE, PIN} or len(set(closure)) != len(closure):
            raise Tooling("the bundle's files are not exactly its closure list")
        if contents[PIN].strip() != pin:
            raise Handoff("the bundle is not the deploy pin: provision it again after the pin move")
    finally:
        os.close(bfd)


def _trusted_tool(path):
    """`path`'s realpath, a root-owned executable no one else can write,
    under root-owned directories no one else can write."""
    real = os.path.realpath(path)
    try:
        st = os.lstat(real)
    except OSError as e:
        raise Tooling(f"{path}: {e.strerror}") from None
    if not stat.S_ISREG(st.st_mode) or st.st_uid != ROOT_UID or st.st_mode & 0o022 or not st.st_mode & 0o111:
        raise Tooling(f"{path} resolves to {real}, which is not a root-owned executable no one else can write")
    d = os.path.dirname(real)
    while True:
        if not _ancestor_ok(os.lstat(d)):
            raise Tooling(f"{d}, above {real}, is not root-owned, or is writable by others")
        if d == "/":
            return real
        d = os.path.dirname(d)


def _links_nothing(path):
    """True only when `path` is PROVEN to load no shared library: an ELF with
    no program interpreter AND no DT_NEEDED entry in its dynamic section (a
    static executable, or a static-PIE). False when it names an interpreter
    or a needed library (a dynamic executable, or a shared object such as an
    extension module with dependencies). None when it is not an ELF that can
    be read completely: never proof."""
    try:
        with open(path, "rb") as f:
            head = f.read(64)
            if len(head) < 52 or head[:4] != b"\x7fELF" or head[4] not in (1, 2) or head[5] not in (1, 2):
                return None
            end, wide = ("<" if head[5] == 1 else ">"), head[4] == 2
            if wide:
                phoff, = struct.unpack(end + "Q", head[32:40])
                phentsize, phnum = struct.unpack(end + "HH", head[54:58])
                ph, dyn = end + "IIQQQQQQ", end + "qQ"
            else:
                phoff, = struct.unpack(end + "I", head[28:32])
                phentsize, phnum = struct.unpack(end + "HH", head[42:46])
                ph, dyn = end + "IIIIIIII", end + "iI"
            if phnum == 0xFFFF or phentsize < struct.calcsize(ph):
                return None
            segments = []
            for i in range(phnum):
                f.seek(phoff + i * phentsize)
                entry = f.read(struct.calcsize(ph))
                if len(entry) != struct.calcsize(ph):
                    return None
                v = struct.unpack(ph, entry)
                # (type, offset, file size): the field order differs by class
                segments.append((v[0], v[2], v[5]) if wide else (v[0], v[1], v[4]))
            if any(t == PT_INTERP for t, _, _ in segments):
                return False
            for t, off, size in segments:
                if t != PT_DYNAMIC:
                    continue
                f.seek(off)
                table = f.read(size)
                if len(table) != size:
                    return None
                step = struct.calcsize(dyn)
                for at in range(0, size - step + 1, step):
                    tag, _ = struct.unpack(dyn, table[at:at + step])
                    if tag == DT_NEEDED:
                        return False
                    if tag == DT_NULL:
                        break
            return True
    except (OSError, struct.error):
        return None


def _ldd_libraries(b, out, err, rc):
    """The libraries and the loader ldd named for `b`; Tooling unless ldd
    named them completely, or `b` is a static ELF, which links none."""
    text = out.decode("utf-8", "replace")
    if rc != 0:
        if _links_nothing(b) is True:
            return []
        raise Tooling(f"ldd could not list {b}'s libraries (exit {rc}), and it is not proven to link nothing")
    libs = []
    for line in text.splitlines():
        line = line.strip()
        if "=>" in line:
            target = line.split("=>", 1)[1].split()
            if not target or not target[0].startswith("/"):
                raise Tooling(f"ldd could not resolve a library of {b}: {line}")
            libs.append(target[0])
        elif line.startswith("/"):
            libs.append(line.split()[0])   # the program interpreter, the loader itself
        elif "statically linked" in line and _links_nothing(b) is True:
            return []
        elif line and not line.startswith("linux-vdso") and not line.startswith("linux-gate"):
            raise Tooling(f"ldd printed what is not a library of {b}: {line}")
    if not libs and _links_nothing(b) is not True:
        raise Tooling(f"ldd named no library for {b}, which is not proven to link nothing")
    return libs


def _otool_libraries(b, out, err, rc):
    """The libraries otool -L named for `b`; Tooling unless it named them."""
    lines = out.decode("utf-8", "replace").splitlines()
    libs = [l.split()[0] for l in lines[1:] if l.startswith(("\t", " ")) and l.split()]
    if rc != 0 or not libs or not all(x.startswith("/") for x in libs):
        raise Tooling(f"otool could not list {b}'s libraries (exit {rc})")
    return libs


def _linked_libraries(binaries):
    """The shared libraries `binaries` link, and the loader, as the operating
    system's own tool names them, completely; Tooling when neither tool is
    there or discovery is incomplete for any binary."""
    if os.path.exists(LDD):
        argv, parse = [LDD], _ldd_libraries
    elif os.path.exists(OTOOL):
        argv, parse = [OTOOL, "-L"], _otool_libraries
    else:
        raise Tooling("no ldd and no otool: the startup closure's libraries cannot be listed")
    out = set()
    for b in binaries:
        try:
            p = subprocess.run(argv + [b], shell=False, close_fds=True, stdin=subprocess.DEVNULL, env={},
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise Tooling(f"cannot list {b}'s libraries: {e}") from None
        out.update(parse(b, p.stdout, p.stderr, p.returncode))
    return sorted(out)


#: Asks the interpreter, under an empty environment, where its startup closure is.
_CLOSURE_QUERY = ("import json,os,sys,sysconfig\n"
                  "p=sysconfig.get_paths()\n"
                  "d=sysconfig.get_config_var('DESTSHARED') or os.path.join(p['platstdlib'],'lib-dynload')\n"
                  "print(json.dumps({'paths':[p['stdlib'],p['platstdlib'],d],"
                  "'zips':[x for x in sys.path if x.endswith('.zip')]}))\n")
#: The parts of a startup closure: paths that must exist; libraries the
#: operating system's tool named (on macOS possibly only in the shared
#: cache); and optional paths the interpreter would load if present (a zip on
#: its path), whose would-be place is protected when they are absent.
REQUIRED, LIBRARIES, OPTIONAL = "required", "libraries", "optional"


def startup_closure(python, docker, spelled=()):
    """Every path root's runs of `python` and `docker` load from, by part:
    REQUIRED, the binaries (their realpaths, and `spelled`, the approved
    document's spellings, whose routes the unit execs), the interpreter's standard library and its
    extension modules, and on macOS the developer directory xcode-select
    chose; LIBRARIES, what both binaries and every extension module link;
    OPTIONAL, each zip on the interpreter's path."""
    try:
        p = subprocess.run([python, "-I", "-S", "-B", "-c", _CLOSURE_QUERY], shell=False, close_fds=True,
                           stdin=subprocess.DEVNULL, env={}, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=60)
        found = json.loads(p.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError) as e:
        raise Tooling(f"the interpreter cannot say where its library is: {e}") from None
    def absolute(xs):
        if not isinstance(xs, list) or not all(isinstance(x, str) and x.startswith("/") for x in xs):
            raise Tooling("the interpreter named its library in a form that is not absolute paths")
        return xs
    paths = absolute(found.get("paths")) + [python, docker] + list(spelled)
    optional = absolute(found.get("zips"))
    if len(found["paths"]) != 3:
        raise Tooling("the interpreter did not name its library, platform library and extension modules")
    dynload = found["paths"][2]
    modules = []
    if os.path.isdir(dynload):
        modules = [os.path.join(dynload, n) for n in os.listdir(dynload) if n.endswith(".so")]
    libraries = _linked_libraries([python, docker] + modules)
    if sys.platform == "darwin" and os.path.exists(XCODE_SELECT):
        try:
            dev = subprocess.run([XCODE_SELECT, "-p"], shell=False, close_fds=True, stdin=subprocess.DEVNULL, env={},
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30).stdout.decode().strip()
        except (OSError, subprocess.TimeoutExpired) as e:
            raise Tooling(f"xcode-select cannot say which developer directory is chosen: {e}") from None
        if dev.startswith("/"):
            paths.append(dev)
    return {REQUIRED: sorted(set(paths)), LIBRARIES: libraries, OPTIONAL: sorted(set(optional))}


def _norm(x):
    """The shell's textual collapse of "." and ".." (the install block's
    norm()): a leading "//" becomes "/", which os.path.normpath keeps."""
    out = []
    for c in x.split("/"):
        if c in ("", "."):
            continue
        if c == "..":
            if out:
                out.pop()
            continue
        out.append(c)
    return "/" + "/".join(out)


def _entry(t, stat_=os.stat, realpath=os.path.realpath):
    """The directory entry `t` names, as the install block's ent() keys it:
    its directory's realpath and its own name; "?" and its normalised
    spelling exactly when os.stat of its directory raises, which follows
    links, so an absent directory and a looping one alike (an lstat would
    succeed on a looping link)."""
    try:
        stat_(os.path.dirname(t))
    except OSError:
        return "?" + _norm(t)
    return realpath(os.path.dirname(t)) + "/" + os.path.basename(t)


def closure_problems(closure, lstat=os.lstat, walk=os.walk, realpath=os.path.realpath, platform=None,
                     readlink=os.readlink, stat_=os.stat):
    """Every path in the startup closure, every directory above it and
    everything under it, root-owned and writable by no one else, exactly as
    the install-time block judges it. A link is judged itself, then followed
    one hop at a time to its TEXTUAL target (never its realpath alone): every
    directory on the target's own path is judged first, then the target, and
    for a link inside the closure everything under the target (a tree
    visit); a link among those directories has only its target and the
    directories above it judged (a chain visit). A visit is known by the
    directory entry its target names, so each link along a chain is visited
    once and every cycle ends; a chain visit never stands in for a later
    tree visit. A directory above a path is known by its spelling and its
    realpath. `closure`: a startup closure by part, or a list of required
    paths. A required path must exist. A library must exist, except on macOS
    a system library its tool named that is absent from disk, which is in
    the dyld shared cache on the sealed system volume. An optional path is
    judged whole when present; when absent, the directories its would-be
    place is under are judged instead. A directory the walk cannot list is
    a problem. The problems, empty when there are none."""
    if not isinstance(closure, dict):
        closure = {REQUIRED: list(closure), LIBRARIES: [], OPTIONAL: []}
    bad, trees, chains, ups = [], set(), set(), set()
    cached = frozenset(p for p in closure[LIBRARIES] if p.startswith(SEALED_PREFIXES)) \
        if (platform or sys.platform) == "darwin" else frozenset()

    def meta(p):
        try:
            st = lstat(p)
        except FileNotFoundError:
            if p not in cached:
                bad.append(f"{p}: absent")
            return None
        except OSError as e:
            bad.append(f"{p}: {e.strerror}")
            return None
        if st.st_uid != ROOT_UID or st.st_mode & 0o022 and not stat.S_ISLNK(st.st_mode):
            bad.append(f"{p} is not root-owned, or is writable by others")
        return st

    def unlisted(e):
        bad.append(f"{e.filename}: {e.strerror}")

    def under(t):
        """Judge `t`, and everything under it when it is a directory; the
        links found, `t` itself when it is one."""
        st = meta(t)
        if st is None:
            return []
        if stat.S_ISLNK(st.st_mode):
            return [t]
        found = []
        if stat.S_ISDIR(st.st_mode):
            for top, dirs, files in walk(t, onerror=unlisted):
                for n in dirs + files:
                    e = os.path.join(top, n)
                    est = meta(e)
                    if est is not None and stat.S_ISLNK(est.st_mode):
                        found.append(e)
        return found

    # The walk is iterative, so no input can exhaust the interpreter's stack:
    # ("up", x) judges the next directory above x; ("hop", link, mode)
    # follows a link one step; ("visit", t, mode) visits a reached target
    # after the directories above it.
    work = []

    def run():
        while work:
            task = work.pop()
            if task[0] == "up":
                x = task[1]
                if x in ("/", "."):
                    continue
                x = os.path.dirname(x)
                k = (_norm(x), realpath(x))
                if k in ups:
                    continue
                ups.add(k)
                work.append(("up", x))
                st = meta(x)
                if st is not None and stat.S_ISLNK(st.st_mode):
                    work.append(("hop", x, "chain"))
            elif task[0] == "hop":
                _, link, mode = task
                try:
                    r = readlink(link)
                except OSError as e:
                    bad.append(f"{link}: {e.strerror}")
                    continue
                t = r if r.startswith("/") else os.path.dirname(link) + "/" + r
                work.append(("visit", t, mode))
                work.append(("up", t))
            else:
                _, t, mode = task
                k = _entry(t, stat_, realpath)
                if mode == "tree":
                    if k in trees:
                        continue
                    trees.add(k)
                    for link in reversed(under(t)):
                        work.append(("hop", link, "tree"))
                else:
                    if k in trees or k in chains:
                        continue
                    chains.add(k)
                    st = meta(t)
                    if st is not None and stat.S_ISLNK(st.st_mode):
                        work.append(("hop", t, "chain"))

    def cover(p):
        """A closure path: the directories above it, then it and everything
        under it, each link found followed as a tree visit."""
        work.append(("up", p))
        run()
        for link in reversed(under(p)):
            work.append(("hop", link, "tree"))
        run()

    try:
        for path in closure[REQUIRED] + closure[LIBRARIES]:
            cover(path)
        for path in closure[OPTIONAL]:
            try:
                lstat(path)
            except FileNotFoundError:
                # Its would-be place: up() starts at its immediate parent, so
                # whoever can write there, or above, could plant it.
                work.append(("up", path))
                run()
                continue
            except OSError:
                pass
            cover(path)
    except RecursionError:
        raise Tooling("the closure's links are too deep to judge") from None
    return sorted(set(bad))


def _docker_closure(docker, spelled=None):
    """What root's run of `docker` alone loads: the binary (and the approved
    document's spelling of it, when the document could be read), and every
    library and the loader it links."""
    return {REQUIRED: [docker] + ([spelled] if spelled else []), LIBRARIES: _linked_libraries([docker]),
            OPTIONAL: []}


def _verified_tools(python3, docker):
    """The interpreter's and docker's realpaths once they and their startup
    closure are root's alone; Tooling otherwise."""
    python, dock = _trusted_tool(python3), _trusted_tool(docker)
    bad = closure_problems(startup_closure(python, dock, (python3, docker)))
    if bad:
        raise Tooling("the startup closure is not root's alone: " + "; ".join(bad[:5]))
    return python, dock


def _engine_socket(endpoint):
    if not isinstance(endpoint, str) or not endpoint.startswith("unix:///"):
        raise Tooling("the engine is not a unix socket")
    try:
        st = os.lstat(endpoint[len("unix://"):])
    except OSError as e:
        raise Tooling(f"the engine socket: {e.strerror}") from None
    if not stat.S_ISSOCK(st.st_mode):
        raise Tooling("the engine socket is not a socket")
    return st.st_uid


class _Engine:
    """docker, as root: the verified CLI against the verified engine, with an
    empty configuration and home of the run's own, so no context, helper or
    plugin is read."""

    def __init__(self, docker, engine, run_dir):
        self.docker, self.env = docker, {"DOCKER_HOST": engine, "DOCKER_CONFIG": os.path.join(run_dir, "docker"),
                                         "HOME": os.path.join(run_dir, "home"), "LC_ALL": "C"}

    def run(self, args, timeout=ENGINE_CALL_S):
        try:
            return subprocess.run([self.docker] + args, shell=False, close_fds=True, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=self.env, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            return None

    def running(self, cid):
        """True when the engine affirms the container runs (paused or
        restarting included), False when it affirms it does not, or that no
        such container exists; None whenever it cannot say."""
        p = self.run(["inspect", "--type", "container", "--format", "{{json .State}}", cid])
        if p is None:
            return None
        if p.returncode == 0:
            try:
                state = json.loads(p.stdout)
            except ValueError:
                return None
            if not isinstance(state, dict) or not isinstance(state.get("Running"), bool):
                return None
            return state["Running"] or state.get("Paused") is True or state.get("Restarting") is True
        q = self.run(["ps", "--all", "--quiet", "--no-trunc", "--filter", f"id={cid}"])
        if q is not None and q.returncode == 0 and not q.stdout.strip():
            return False
        return None

    def running_by_name(self, name):
        """As `running`, for the container holding `name`: a guard read only,
        never a stop target. Absence is a successful listing by exact name
        that lists nothing."""
        p = self.run(["inspect", "--type", "container", "--format", "{{json .State}}", name])
        if p is None:
            return None
        if p.returncode == 0:
            try:
                state = json.loads(p.stdout)
            except ValueError:
                return None
            if not isinstance(state, dict) or not isinstance(state.get("Running"), bool):
                return None
            return state["Running"] or state.get("Paused") is True or state.get("Restarting") is True
        q = self.run(["ps", "--all", "--quiet", "--no-trunc", "--filter", f"name=^/{name}$"])
        if q is not None and q.returncode == 0 and not q.stdout.strip():
            return False
        return None

    def identity(self, cid):
        """The container `cid` names, inspected BY ID: its document, or None
        whenever the engine does not answer with one."""
        p = self.run(["inspect", "--type", "container", "--format", "{{json .}}", cid])
        if p is None or p.returncode != 0:
            return None
        try:
            doc = json.loads(p.stdout)
        except ValueError:
            return None
        return doc if isinstance(doc, dict) else None

    def remove_run(self, run_id):
        p = self.run(["ps", "--all", "--quiet", "--filter", f"label={RUN_LABEL}={run_id}"])
        ids = p.stdout.decode("ascii", "replace").split() if p is not None and p.returncode == 0 else []
        if ids:
            self.run(["rm", "--force"] + ids)


def _evidence_problem(raw, host):
    """Why `raw` is not partition evidence for `host`, or None: a copy of
    partition_evidence.parse, judged exactly as it judges."""
    try:
        doc = _strict_json(raw)
    except (ValueError, UnicodeDecodeError):
        return "not JSON", None
    if not isinstance(doc, dict) or set(doc) != EVIDENCE_MEMBERS:
        return "not exactly the document's members", None
    try:
        if _canonical(doc) != raw:
            return "not in canonical form", None
    except ValueError:
        return "not in canonical form", None
    if doc["schema"] != EVIDENCE_SCHEMA or doc["host"] != host:
        return "not this host's partition evidence", None
    if not isinstance(doc["run_id"], str) or not _RUN_ID_RE.fullmatch(doc["run_id"]):
        return "run_id is malformed", None
    if not isinstance(doc["at"], str) or not _AT.fullmatch(doc["at"]):
        return "at is malformed", None
    try:
        _at_seconds(doc["at"])
    except ValueError:
        return "at is not a real time", None
    for what in ("script_sha256", "bindings"):
        v = doc[what]
        if not isinstance(v, dict) or not v or not all(
                isinstance(k, str) and _NAME.fullmatch(k) and isinstance(h, str) and _HEX64.fullmatch(h)
                for k, h in v.items()):
            return f"{what} is malformed", None
    probes = doc["probes"]
    if not isinstance(probes, list) or [p.get("id") if isinstance(p, dict) else None for p in probes] != list(PROBE_IDS):
        return "probes are not exactly P01-P04", None
    for p in probes:
        why = _probe_problem(p)
        if why:
            return why, None
    verdicts = {p["id"]: p["verdict"] for p in probes}
    if doc["fail_stop"] != {i: verdicts.get(i) for i in FAIL_STOP}:
        return "fail_stop does not repeat the verdicts", None
    token = doc[TOKEN_MEMBER]
    if all(verdicts.get(i) == "PASS" for i in FAIL_STOP):
        unsigned = dict(doc, **{TOKEN_MEMBER: None})
        if token != f"{doc['run_id']}:{hashlib.sha256(_canonical(unsigned)).hexdigest()}":
            return "the token is not this document's", None
    elif token is not None:
        return "a token although a fail-stop probe did not pass", None
    return None, doc


def _probe_problem(p):
    pid = p["id"]
    if set(p) != PROBE_MEMBERS:
        return f"{pid} is not exactly the probe's members"
    if p["verdict"] not in VERDICTS:
        return f"{pid}'s verdict is not a verdict"
    v = p["vantage"]
    if not isinstance(v, list) or not v or not all(
            isinstance(x, dict) and set(x) == VANTAGE_MEMBERS and isinstance(x["container"], str) and x["container"]
            and isinstance(x["image"], str) and x["image"] and _int(x["uid"])
            and isinstance(x["gids"], list) and all(_int(g) for g in x["gids"]) for x in v):
        return f"{pid}'s vantage is malformed"
    if not isinstance(p["operation"], str) or not p["operation"]:
        return f"{pid}'s operation is malformed"
    roles = p["target_role"]
    if not isinstance(roles, list) or not roles or not all(isinstance(r, str) and _ROLE.fullmatch(r) for r in roles) \
            or len(set(roles)) != len(roles):
        return f"{pid}'s target_role is malformed"
    if not isinstance(p["outcome"], str) or not _OUTCOME.fullmatch(p["outcome"]):
        return f"{pid}'s outcome is malformed"
    w = p["witness"]
    if not isinstance(w, dict) or set(w) != WITNESS_MEMBERS or not isinstance(w["operation"], str) \
            or not w["operation"] or not isinstance(w["outcome"], str) or not _OUTCOME.fullmatch(w["outcome"]):
        return f"{pid}'s witness is malformed"
    if pid in FAIL_STOP:
        if not REQUIRED_ROLES.get(pid, frozenset()) <= set(roles):
            return f"{pid}'s roles do not cover its required roles"
        if pid == "P04" and not all(r.startswith("peer:") for r in roles):
            return "P04's roles are not the agents' lanes"
        if p["verdict"] == "PASS" and (p["outcome"] != "ENOENT" or w["outcome"] != "ok"):
            return f"{pid} passes only with ENOENT and its witness ok"
    return None


def _evidence_failing(evfd, rid, context, expect):
    """This run's fail-stop failures, read from its own evidence document
    only when it is trustworthy: root:root 0444 with one link, partition
    evidence by its whole grammar, this run's and this host's, placed and
    dated after the run started, under the bindings the child recorded before
    its first one-shot. Otherwise none, and why: a FAIL is never invented."""
    if expect is None:
        return [], "no expectation recorded, so no evidence of this run is used"
    try:
        raw, st = _read_at(evfd, f"partition-{rid}.json", DOC_MAX, want=(ROOT_UID, ROOT_GID, 0o444, 1))
    except FileNotFoundError:
        return [], "no evidence placed"
    except (OSError, ValueError) as e:
        return [], f"the evidence is not trustworthy: {e}"
    why, doc = _evidence_problem(raw, context["host"])
    if why:
        return [], f"the evidence is not partition evidence: {why}"
    try:
        started = _at_seconds(context["started_at"])
    except ValueError:
        return [], "the run's start time cannot be read"
    if doc["run_id"] != rid or expect["run_id"] != rid or doc["bindings"] != expect["bindings"]:
        return [], "the evidence is not this run's, or not under its expected bindings"
    if _at_seconds(doc["at"]) < started or st.st_mtime < started - PLACED_SLACK_S:
        return [], "the evidence was not placed after this run started"
    return sorted(p["id"] for p in doc["probes"] if p["id"] in FAIL_STOP and p["verdict"] == "FAIL"), ""


def _text_ok(v, kind):
    if kind == "bool":
        return isinstance(v, bool)
    return isinstance(v, str) and bool(v.strip())


def event_problem(e):
    """Why `e` is not a well-formed incident event, or None: partition_incident's grammar."""
    if not isinstance(e, dict) or not isinstance(e.get("event"), str):
        return "not an event"
    kind = e["event"]
    if kind not in EVENT_GRAMMAR:
        return f"{kind!r} is outside the vocabulary"
    required = dict(EVENT_GRAMMAR[kind][0], **_COMMON[0])
    allowed = dict(required, **EVENT_GRAMMAR[kind][1], **_COMMON[1])
    if any(k not in e for k in required) or set(e) - set(allowed) - {"event"}:
        return f"{kind} is not its grammar"
    if any(k in e and not _text_ok(e[k], allowed[k]) for k in allowed):
        return f"{kind} has a member of the wrong type"
    return None


def detected_problem(doc, rid):
    """Why `doc` is not a well-formed detected.json for `rid`, or None."""
    if not isinstance(doc, dict):
        return "not an object"
    if set(DETECTED_REQUIRED) - set(doc) or set(doc) - set(DETECTED_REQUIRED) - set(DETECTED_OPTIONAL):
        return "not exactly its members"
    for k, t in list(DETECTED_REQUIRED.items()) + list(DETECTED_OPTIONAL.items()):
        if k in doc and (isinstance(doc[k], bool) and t is not bool or not isinstance(doc[k], t)):
            return f"{k} has the wrong type"
    if doc["run_id"] != rid or not doc["failing"] or not all(isinstance(f, str) and f for f in doc["failing"]):
        return "not this run's, or names no failing probe"
    if "mode" in doc and doc["mode"] != MODES[1]:
        return "its mode is not prospective (a weekly run records none)"
    pending = doc["pending"]
    if not all(isinstance(a, str) and a in ACTIONS for a in pending) or len(set(pending)) != len(pending):
        return "its pending actions are malformed"
    return None


def _incident(evfd, rid):
    """This run's incident: None when there is none, else (its detected
    record or None when absent or malformed, its well-formed events or None
    when the history is malformed or unreadable). An incident that cannot
    be opened is one whose records are unknown."""
    try:
        ifd = os.open(INCIDENT_PREFIX + rid, _DIR, dir_fd=evfd)
    except FileNotFoundError:
        return None
    except OSError:
        return None, None
    try:
        try:
            det = _strict_json(_read_at(ifd, "detected.json", DOC_MAX)[0])
            if detected_problem(det, rid):
                det = None
        except FileNotFoundError:
            det = None
        except (OSError, ValueError, UnicodeDecodeError):
            det = None
        try:
            raw = _read_at(ifd, "events.jsonl", DOC_MAX)[0]
            if raw and not raw.endswith(b"\n"):
                return det, None
            events = [_strict_json(l.encode("utf-8")) for l in raw.decode("utf-8").splitlines() if l.strip()]
            if any(event_problem(e) for e in events):
                return det, None
        except FileNotFoundError:
            events = []
        except (OSError, ValueError, UnicodeDecodeError):
            return det, None
        return det, events
    finally:
        os.close(ifd)


def _act(evidence_dir, live_config, target, rid, at, failing, engine, said, mode=MODES[0], router_running=None):
    """The fail-stop actions, in order, each attempted whatever the earlier
    did: the incident record if absent (an existing well-formed one keeps its
    cause), the live config without delegation if it still carries it, and
    the stop of `target`, only if the engine affirms it runs, recorded as
    done only when the engine affirms it no longer does. Nothing is ever
    stopped by name. A well-formed resolved incident is left alone; a
    malformed history is completed, never trusted to say it is done. No
    record, history or diagnostic failure can block the stop. A PROSPECTIVE
    run's stop is not required only when every rewrite in the incident's
    history and this one observed no delegation, the target does not run,
    and `router_running()` affirms the local router's name runs nothing.
    Returns whether every effect is done."""
    def say(text):
        try:
            said.append(text)
        except Exception:  # a diagnostic is never an action
            pass
    ifd = None
    try:
        evfd = _evidence_dir(evidence_dir)
        try:
            det, events = _incident(evfd, rid) or (None, [])
            prior = events
            if events and any(e["event"] == "resolved" for e in events):
                say(f"incident {rid} is resolved; nothing to complete")
                return True
            try:
                os.mkdir(INCIDENT_PREFIX + rid, 0o755, dir_fd=evfd)
            except FileExistsError:
                pass
            ifd = os.open(INCIDENT_PREFIX + rid, _DIR, dir_fd=evfd)
            if det is None:
                try:
                    _write_at(ifd, "detected.json", _canonical(dict(
                        {"run_id": rid, "at": at, "failing": failing, "identity": target,
                         "pending": list(ACTIONS), "recorded_by": "writer"},
                        **({"mode": mode} if mode == MODES[1] else {}))), 0o444, exclusive=True)
                except FileExistsError:
                    say(f"incident {rid}: an existing record is kept as it is")
        finally:
            os.close(evfd)
    except (OSError, ValueError, StepError, Tooling) as e:
        say(f"incident NOT recorded: {e}")
        ifd = None
        prior = None

    def event(ev):
        if ifd is not None:
            try:
                fd = os.open("events.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o644, dir_fd=ifd)
                try:
                    os.write(fd, (json.dumps(dict(ev, at=at, by="writer"), sort_keys=True,
                                             separators=(",", ":")) + "\n").encode("utf-8"))
                    os.fsync(fd)
                finally:
                    os.close(fd)
            except OSError as e:
                say(f"could not record {ev['event']}: {e.strerror}")
        say(ev["event"])
    rewritten = observed = False
    try:
        cfd, cname = _config_dir(live_config)
        try:
            doc = _strict_json(_read_at(cfd, cname, DOC_MAX)[0])
            if not isinstance(doc, dict):
                raise ValueError("the live config is not an object")
            if "delegation" in doc:
                doc.pop("delegation")
                _write_at(cfd, cname, (json.dumps(doc, indent=2) + "\n").encode("utf-8"), 0o644, keep=True)
                event({"event": "rewrite_ok"})
            else:
                event({"event": "rewrite_ok", "observed": NO_DELEGATION})
                observed = True
            rewritten = True
        finally:
            os.close(cfd)
    except (OSError, ValueError, UnicodeDecodeError, StepError, Tooling) as e:
        event({"event": "rewrite_failed", "reason": str(e) or type(e).__name__})
    stopped = False
    eligible = mode == MODES[1] and observed and isinstance(prior, list) and _only_observed(prior)

    def not_needed(why):
        named = router_running() if router_running is not None else None
        if named is False:
            event({"event": "stop_not_required", "reason": f"prospective: {NO_DELEGATION} throughout, {why}, "
                                                           "and the local router is stopped"})
            return True
        event({"event": "stop_not_attempted",
               "reason": "a router may be signing that no record names (" + (
                   "a container under the local router's name runs" if named else
                   "the engine cannot say whether the local router runs") + "); " + _remedy(True)})
        return False
    if not isinstance(target, str) or not _HEX64.fullmatch(target):
        if eligible:
            stopped = not_needed("no certified target")
        else:
            event({"event": "stop_not_attempted", "reason": "no verified full container id to stop"})
    else:
        up = engine.running(target)
        if up is False and eligible:
            stopped = not_needed(f"the certified {target} does not run")
        elif up is False:
            # Not [1]'s running container: never certified stopped, since a
            # stale id leaves the router that replaced it running.
            event({"event": "stop_not_attempted", "reason": f"{target} is not running: the target may be stale"})
        elif up is None:
            event({"event": "stop_not_attempted", "reason": "the engine cannot say whether it runs"})
        else:
            engine.run(["stop", "-t", str(STOP_TIMEOUT_S), target])
            after = engine.running(target)
            if after is False:
                event({"event": "stop_ok", "id": target})
                stopped = True
            else:
                event({"event": "stop_failed", "id": target,
                       "reason": "still running" if after else "the engine cannot say whether it stopped"})
    if mode == MODES[1] and not stopped and not eligible:
        say(_remedy(False))
    if ifd is not None:
        os.close(ifd)
    return rewritten and stopped


def _context(rfd):
    """A run's context with its mode: a /2 record whose mode is one of
    MODES, or a /1 record read as a weekly run's; None otherwise."""
    doc = _record(rfd, "context.json", CONTEXT_MEMBERS, CONTEXT_SCHEMA)
    if doc is not None:
        return doc if doc["mode"] in MODES else None
    doc = _record(rfd, "context.json", CONTEXT_MEMBERS_V1, CONTEXT_SCHEMA_V1)
    return dict(doc, mode=MODES[0]) if doc is not None else None


def _remedy(all_observed):
    """partition_incident.remedy, exactly."""
    if all_observed:
        return "remedy: stop the local router, then run the ordinary partition-weekly"
    return ("remedy: stop the local router, check it, and record resolved; a delegation was live during this "
            "incident, so no ordinary run can close it")


def _only_observed(events):
    """partition_incident.only_observed, exactly: every rewrite in the
    history found no delegation to remove."""
    return all(e["event"] == "rewrite_ok" and e.get("observed") == NO_DELEGATION
               for e in events if e["event"] in ("rewrite_ok", "rewrite_failed"))


def _approved_name(rfd):
    """The local router's container name in the run's copy of A1's record
    (spec.name), or None when it cannot be read: a guard's name, never a
    stop target."""
    try:
        doc = _strict_json(_read_at(rfd, ACTIVATION, DOC_MAX)[0])
        name = doc["spec"]["name"]
    except (OSError, ValueError, UnicodeDecodeError, KeyError, TypeError):
        return None
    return name if isinstance(name, str) and _NAME.fullmatch(name) else None


def _decide(efd, run_name, current, said):
    """The parent's decision for one run, from its own records, with ITS
    context's engine and docker, re-verified, and never an old id on another
    engine. A fail-stop failure in the run's trustworthy evidence, or its own
    open incident, is completed with the ORIGINAL cause and the context's
    target only. Returns (exit, the run's passing outcome or None, whether
    its directory must be kept because an effect is not yet shown done)."""
    rid = RUN_NAME.fullmatch(run_name).group(1)
    rfd = os.open(run_name, _DIR, dir_fd=efd)
    try:
        context = _context(rfd)
        expect = _record(rfd, "expect.json", EXPECT_MEMBERS, EXPECT_SCHEMA)
        outcome = _record(rfd, "outcome.json", OUTCOME_MEMBERS, OUTCOME_SCHEMA)
        router_name = _approved_name(rfd)
    finally:
        os.close(rfd)
    if context is None or context["run_id"] != rid:
        said.append(f"{rid}: no usable context; nothing is decided or stopped")
        return EXIT_HANDOFF, None, False
    if context["engine"] != current["engine"] or context["docker"] != current["docker"]:
        said.append(f"{rid}: its engine or docker is not the job's verified one now; never an old id on another "
                    "engine: kept")
        return EXIT_HANDOFF, None, True
    engine = _Engine(context["docker"], context["engine"], os.path.join(current["exec_root"], run_name))
    engine.remove_run(rid)
    try:
        evfd = _evidence_dir(context["evidence_dir"])
    except Tooling as e:
        said.append(f"{rid}: {e}: kept")
        return EXIT_HANDOFF, None, True
    try:
        failing, why = _evidence_failing(evfd, rid, context, expect)
        incident = _incident(evfd, rid)
    finally:
        os.close(evfd)
    prospective = context["mode"] == MODES[1]
    done, events = set(), None
    if incident is not None:
        det, events = incident
        done = {e["event"] for e in events} if events is not None else set()

    def effects_done():
        return "resolved" in done or {"rewrite_ok", "stop_ok"} <= done or (
            prospective and events is not None and {"rewrite_ok", "stop_not_required"} <= done
            and _only_observed(events))
    if incident is not None:
        if not failing and not effects_done():
            # Its own open incident, completed with its ORIGINAL cause; a
            # record that cannot be read is completed too, never trusted done.
            failing, why = (list(det["failing"]) if det else ["cause_unrecorded"]), ""
    if failing:
        if effects_done():
            said.append(f"{rid}: its incident's history already shows every effect done; none is repeated")
            return EXIT_INCIDENT, None, False
        complete = _act(context["evidence_dir"], context["live_config_path"], context["router_container_id"], rid,
                        context["started_at"], failing, engine, said, mode=context["mode"],
                        router_running=(lambda: engine.running_by_name(router_name)) if router_name else None)
        return EXIT_INCIDENT, None, not complete
    if outcome is not None and outcome["run_id"] == rid and outcome["code"] == 0 and not why:
        return EXIT_PASS, outcome, False
    said.append(f"{rid}: could not complete: {why or (outcome or {}).get('why') or 'the child did not finish'}")
    return EXIT_HANDOFF, None, False


def inspect_projection(live):
    """partition_activation.inspect_projection, exactly (a test holds the
    two equal): what of `docker inspect` the stop target's record binds."""
    cfg, hc = live.get("Config") or {}, live.get("HostConfig") or {}
    return {"Id": live.get("Id"), "Created": live.get("Created"), "Image": live.get("Image"),
            "User": cfg.get("User"), "Env": sorted(str(e) for e in cfg.get("Env") or []),
            "NetworkMode": hc.get("NetworkMode"), "RestartPolicy": (hc.get("RestartPolicy") or {}).get("Name"),
            "Mounts": sorted([str(m.get("Type")), str(m.get("Source")), str(m.get("Destination")), bool(m.get("RW"))]
                             for m in live.get("Mounts") or [] if isinstance(m, dict))}


def _verified_target(engine, passed, values):
    """Why the passing run's reported router is NOT a stop target to record,
    or "" when it is. The child's snapshot must be whole; the router is
    re-inspected BY ID and must be that very container, running, with the
    live config as its identity read-only bind and its ROUTER_CONFIG, and
    hash to the child's projection; the live config and the cited evidence,
    read now, must be the bytes the child judged. Never a name, and never an
    id from a name."""
    seen, digest = passed.get("router_seen"), passed.get("inspect_digest")
    erid, live = passed.get("evidence_run_id"), values["live_config"]
    if not all(isinstance(passed.get(k), str) and _HEX64.fullmatch(passed[k])
               for k in ("router_seen", "config_sha256", "evidence_sha256", "inspect_digest")) \
            or not isinstance(erid, str) or not _RUN_ID_RE.fullmatch(erid):
        return "the run reported no whole snapshot of the approved activation"
    doc = engine.identity(seen)
    if doc is None or doc.get("Id") != seen:
        return f"the engine does not answer for {seen} by its id"
    state = doc.get("State")
    if not isinstance(state, dict) or state.get("Running") is not True or state.get("Paused") is not False \
            or state.get("Restarting") is not False:
        return f"the engine does not state that {seen} is running"
    if not any(isinstance(m, dict) and m.get("Type") == "bind" and m.get("Source") == live
               and m.get("Destination") == live and m.get("RW") is False for m in doc.get("Mounts") or []):
        return f"{seen} does not bind the live config {live} read-only at its own path"
    if f"ROUTER_CONFIG={live}" not in ((doc.get("Config") or {}).get("Env") or []):
        return f"{seen} does not run with ROUTER_CONFIG={live}"
    if hashlib.sha256(_canonical(inspect_projection(doc))).hexdigest() != digest:
        return f"{seen} has changed since the run judged it"
    try:
        cfd, cname = _config_dir(live)
        try:
            config = _read_at(cfd, cname, DOC_MAX)[0]
        finally:
            os.close(cfd)
        evfd = _evidence_dir(values["evidence_dir"])
        try:
            evidence = _read_at(evfd, f"partition-{erid}.json", DOC_MAX, want=(ROOT_UID, ROOT_GID, 0o444, 1))[0]
        finally:
            os.close(evfd)
    except (OSError, ValueError, Tooling) as e:
        return f"the live config or the token's evidence cannot be read again: {e}"
    if hashlib.sha256(config).hexdigest() != passed["config_sha256"]:
        return "the live config has changed since the run judged it"
    if hashlib.sha256(evidence).hexdigest() != passed["evidence_sha256"]:
        return "the token's evidence has changed since the run judged it"
    return ""


def _stage_write(dfd, name, data, fs):
    """`name` in `dfd` atomically: a temporary file (O_EXCL), written and
    fsynced, renamed into place, then the directory fsynced. Returns None,
    ("before", why) when the rename did not happen (the temporary file is
    removed), or ("after", why) when it did and only the directory fsync
    failed."""
    tmp = f".{name}.{os.getpid()}.tmp"
    try:
        fd = fs.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
        try:
            if fs.write(fd, data) != len(data):
                raise OSError("a short write")
            fs.fchmod(fd, 0o444)
            fs.fsync(fd)
        finally:
            fs.close(fd)
        fs.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
    except OSError as e:
        try:
            os.unlink(tmp, dir_fd=dfd)
        except OSError:
            pass
        return "before", str(e)
    try:
        fs.fsync(dfd)
    except OSError as e:
        return "after", str(e)
    return None


def _publish_target(efd, evidence_dir, data, fs=os):
    """The stop target, under the lock, in three steps, each failure a
    stated state and never success: (1) invalidate the old verify copy,
    (2) recovery.json, (3) the byte-identical copy. Returns why it is not
    published, or "" when it is."""
    try:
        evfd = _evidence_dir(evidence_dir)
    except Tooling as e:
        return f"stop target not published: the old copy could not be invalidated: {e}"
    try:
        try:
            try:
                fs.unlink(STOP_TARGET, dir_fd=evfd)
            except FileNotFoundError:
                pass
            fs.fsync(evfd)
        except OSError as e:
            return f"stop target not published: the old copy could not be invalidated: {e}"
        got = _stage_write(efd, "recovery.json", data, fs)
        if got and got[0] == "before":
            return f"stop target not published: recovery.json not written: {got[1]}"
        if got:
            return f"recovery.json written, its durability uncertain ({got[1]}); stop target not published"
        got = _stage_write(evfd, STOP_TARGET, data, fs)
        if got and got[0] == "before":
            return f"stop target not published: {got[1]}"
        if got:
            return f"stop target published, its durability uncertain ({got[1]})"
        return ""
    finally:
        os.close(evfd)


def _recovery(efd):
    """The recovery description, root's alone, or None."""
    try:
        doc = _strict_json(_read_at(efd, "recovery.json", DOC_MAX, want=(ROOT_UID, ROOT_GID, 0o444, 1))[0])
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    if not _typed(doc, RECOVERY_MEMBERS, RECOVERY_SCHEMA) or not _HEX64.fullmatch(doc["router_container_id"]):
        return None
    return doc


def _runs_fs(phase):
    """The filesystem the run record goes through in `phase` (W2, W5 or
    W7): the real one; a test faults a single phase."""
    return os


def _invalidate_runs(evfd, fs):
    """W2: the old record removed, durably, before any run directory is
    made. Raises OSError: on the unlink (the old record may remain) or on
    the directory fsync (it is gone now, not durably)."""
    try:
        fs.unlink(WEEKLY_RUNS, dir_fd=evfd)
    except FileNotFoundError:
        pass
    fs.fsync(evfd)


def _runs_record(efd, host, at, kept, running=None):
    """The record from a fresh listing of the exec root: every run directory
    present now, `running` as running, one whose decision kept it as kept,
    and any other (unreadable, a failed removal, not decided here) as
    undecided. Empty only when no run directory remains."""
    runs = []
    for n in sorted(os.listdir(efd)):
        m = RUN_NAME.fullmatch(n)
        if m:
            state = RUNNING if m.group(1) == running else KEPT if n in kept else UNDECIDED
            runs.append({"run_id": m.group(1), "state": state, "since": at})
    return _canonical({"schema": RUNS_SCHEMA, "host": host, "at": at, "runs": runs})


def _launch(argv, **kw):
    """The child's start (a test faults it)."""
    return subprocess.Popen(argv, **kw)


def _status(code):
    """A status failure (a run record or a run directory the writer could not
    settle) maps the exit once: a pass becomes a handoff; an incident, a
    handoff and a tooling exit stay as they are."""
    return EXIT_HANDOFF if code == EXIT_PASS else code


def _approved_name_of(raw):
    """The local router's container name in A1's record's bytes, or None."""
    try:
        name = _strict_json(raw)["spec"]["name"]
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        return None
    return name if isinstance(name, str) and _NAME.fullmatch(name) else None


#: The post-place back-out, in order: the start is gated on the HOST file
#: carrying no delegation, never on its sha256 alone.
POST_PLACE_BACK_OUT = ("install (read its diff); install --apply, which must exit 0; the host's live config file, "
                       "not the container's view, must parse as a JSON object with no delegation member (if it "
                       "carries one, or cannot be read or parsed, stop: the activated config may still be in "
                       "place); compare its sha256 with the pre-activation one; then docker stop and docker start "
                       "the local router")


def _back_out(name, kept, pre_sha=None, live_delegation=False):
    """What brings the local router back after a prospective run that did
    not pass. A start is named only when THIS run's G1 read the live config
    and found no delegation (`pre_sha` set): it was stopped for A2 on that
    config. G1 finding a delegation is the state after A3's place, whose
    back-out is install's, never a start; a run that did not show the
    config pre-activation (refused before G1, or G1 found no object) names
    no start either. A kept run's remedy comes first."""
    if live_delegation:
        return ("back-out: the live config carries delegation, so do not start the local router on it; this is "
                f"the state after A3's place, and its back-out is, in order: {POST_PLACE_BACK_OUT}")
    if not pre_sha:
        return ("back-out: this run did not show the live config is pre-activation, so it names no start; before "
                "starting the "
                "local router, read the host's live config: it must parse as a JSON object with no delegation "
                f"member, else back out in order: {POST_PLACE_BACK_OUT}")
    start = f"docker start {name}" if name else "docker start <the local router's container>"
    if kept:
        return (f"back-out: first follow the remedy printed for {', '.join(kept)} (kept: an effect is not shown "
                f"done), then {start}")
    return f"back-out: the local router was stopped for A2 and its live config is unchanged (its sha256 {pre_sha}): {start}"


def _prospective_refusal(efd, host, values, approved, recovery, docker, exec_root, seen):
    """Why a prospective run (A2) may not start, or "": every read here is a
    guard, made before W2 and any effect. G1: the live config carries no
    delegation. G2: no router a weekly pass certified (recovery.json's, for
    this host, config, engine and evidence) runs. G3: no run awaits a
    decision; that is the ordinary run's to complete. G4': no container
    under the approved record's local router name runs: A2 runs with it
    stopped, since nothing the writer can read shows which config a running
    one adopted. Also A1's record must be this host's, for this config.
    Returns (why, whether the local router was found running or could not
    be said not to run): its back-out is then not to start it. `seen`
    receives the pre-activation live config's sha256, from G1's own read."""
    try:
        record = _strict_json(approved)
        name, rec_host, final = record["spec"]["name"], record["host"], record["final_config_path"]
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        return "A1's record cannot be read", False
    if rec_host != host or final != values["live_config"]:
        return "A1's record is another host's or another config path's", False
    try:
        cfd, cname = _config_dir(values["live_config"])
        try:
            raw = _read_at(cfd, cname, DOC_MAX)[0]
            doc = _strict_json(raw)
        finally:
            os.close(cfd)
    except (OSError, ValueError, UnicodeDecodeError, Tooling) as e:
        return f"the live config cannot be read: {e}", False
    if not isinstance(doc, dict):
        return "the live config is not a JSON object", False
    if "delegation" in doc:
        seen["live_delegation"] = True
        return "A2 is pre-activation: the live config already carries delegation", False
    seen["pre_activation_sha256"] = hashlib.sha256(raw).hexdigest()
    engine = _Engine(docker, values["engine"], exec_root)
    if recovery and recovery["host"] == host and recovery["live_config_path"] == values["live_config"] \
            and recovery["engine"] == values["engine"] and recovery["evidence_dir"] == values["evidence_dir"]:
        up = engine.running(recovery["router_container_id"])
        if up is not False:
            return (f"a router the weekly job certified ({recovery['router_container_id']}) is running: de-activate "
                    "it (A4 recreates it) or run the ordinary partition-weekly" if up else
                    "the engine cannot say whether the certified router runs"), True
    pending = [n for n in os.listdir(efd) if RUN_NAME.fullmatch(n)]
    if pending:
        return f"{', '.join(sorted(pending))} awaits a decision: run the ordinary partition-weekly, which completes it", False
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        return "A1's record names no local router container", False
    up = engine.running_by_name(name)
    if up is not False:
        return (f"A2 runs with the local router stopped: stop {name} (docker stop {name}), then run A2; A3 and A4 "
                "start it on the activated config" if up else
                f"the engine cannot say whether {name} runs"), True
    return "", False


def partition_weekly(exec_root, host, document, sha256, activation, activation_sha256, now=None, child_timeout=None,
                     emit=print, prospective=False):
    """One weekly partition run (see the section comment). Returns its exit.

    Its run record, under the lock: W2 removes the old one, durably, before
    any run directory is made (else no run starts); W5 publishes every run
    directory with this run as running, durably, before the child starts
    (else the child never starts); W7 publishes what remains, from a fresh
    listing, on every path once W2 succeeded, before the lock is released.
    So whenever a run directory exists, the record is absent or lists it.
    A record or a run directory the writer cannot settle never reads as a
    pass, and never hides an incident or a stop."""
    child_timeout = CHILD_TIMEOUT_S if child_timeout is None else child_timeout
    if not RUN_ID.fullmatch(host) or not _HEX64.fullmatch(sha256) or not _HEX64.fullmatch(activation_sha256):
        raise Refused("usage")
    at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now if now is not None else time.time()))
    rid = time.strftime("w%Y%m%dT%H%M%SZ", time.gmtime(now if now is not None else time.time()))

    def stamp():
        return at if now is not None else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time()))
    said = []
    try:
        efd = _root_dir(exec_root, 0o700)
    except Tooling as e:
        emit(f"partition-weekly: tooling_unverified: {e}; no recovery context can be trusted without the exec root")
        return EXIT_TOOLING
    lock_fd = values = None
    # The record's state: the evidence directory once W2 removed the old
    # record, the runs a decision kept, whether any status failed, whether an
    # abandoned run's decision was an incident, this run's directory once
    # made, whether its child started, and this run's decided exit.
    rec = {"evfd": None, "kept": set(), "status": False, "incident": False, "made": None, "started": False,
           "code": None}

    def remove(name):
        try:
            _remove_tree(efd, name)
        except OSError as e:
            said.append(f"{name}: cannot be removed ({e.strerror or e}); kept, undecided")
            rec["status"] = True

    def body():
        nonlocal lock_fd, values
        try:
            lock_fd = _take_partition_lock(efd)
            raw, sec = _document(document, sha256)
            values = _authority(sec, exec_root)
            # Everything root will run or write under, verified before any engine call.
            python, docker = _verified_tools(values["python3"], values["docker"])
            _engine_socket(values["engine"])
            _verify_bundle(efd, values["pin"])
            os.close(_evidence_dir(values["evidence_dir"]))
            cfd, _ = _config_dir(values["live_config"])
            os.close(cfd)
            approved = _activation(values["evidence_dir"], activation, activation_sha256)
            recovery = _recovery(efd)
            mode = MODES[1] if prospective else MODES[0]
            if prospective:
                rec["router_name"] = _approved_name_of(approved)
                refused, rec["router_up"] = _prospective_refusal(efd, host, values, approved, recovery, docker,
                                                                 exec_root, rec)
                if refused:
                    said.append(f"refused, nothing written: {refused}")
                    return EXIT_HANDOFF
            current = {"engine": values["engine"], "docker": docker, "exec_root": exec_root}
            # W2: no run directory is made unless the old record is durably gone.
            evfd = _evidence_dir(values["evidence_dir"])
            try:
                _invalidate_runs(evfd, _runs_fs("W2"))
                rec["evfd"] = evfd
            except OSError as e:
                os.close(evfd)
                said.append(f"the run record cannot be invalidated ({e.strerror or e}); no run is started")
            for n in sorted(os.listdir(efd)):
                if RUN_NAME.fullmatch(n):
                    said.append(f"{n}: abandoned; completing its decision before removing it")
                    try:
                        code, _, keep = _decide(efd, n, current, said)
                    except OSError as e:
                        said.append(f"{n}: cannot be read ({e.strerror}); kept, undecided, for the operator")
                        continue
                    rec["incident"] = rec["incident"] or code == EXIT_INCIDENT
                    if keep:
                        said.append(f"{n}: kept, since an effect is not yet shown done")
                        rec["kept"].add(n)
                    else:
                        remove(n)
            # With no child, an abandoned run's incident is the exit; a status failure never hides it.
            no_child = EXIT_INCIDENT if rec["incident"] else EXIT_HANDOFF
            if rec["evfd"] is None:
                return no_child
            target = recovery["router_container_id"] if recovery and recovery["host"] == host \
                and recovery["live_config_path"] == values["live_config"] and recovery["engine"] == values["engine"] \
                and recovery["evidence_dir"] == values["evidence_dir"] else None
            run_name = RUN_PREFIX + rid
            os.mkdir(run_name, 0o700, dir_fd=efd)
            rec["made"] = run_name
            rfd = os.open(run_name, _DIR, dir_fd=efd)
            try:
                for d in ("docker", "home"):
                    os.mkdir(d, 0o700, dir_fd=rfd)
                _write_at(rfd, "document.json", raw, 0o400, exclusive=True)
                _write_at(rfd, ACTIVATION, approved, 0o400, exclusive=True)
                _write_at(rfd, "context.json", _canonical(
                    {"schema": CONTEXT_SCHEMA, "run_id": rid, "host": host, "started_at": at,
                     "evidence_dir": values["evidence_dir"], "live_config_path": values["live_config"],
                     "router_container_id": target, "engine": values["engine"], "docker": docker, "mode": mode}), 0o400,
                    exclusive=True)
            finally:
                os.close(rfd)
            # W5: no child starts unless this run is durably published as running.
            got = _stage_write(rec["evfd"], WEEKLY_RUNS, _runs_record(efd, host, stamp(), rec["kept"], rid),
                               _runs_fs("W5"))
            if got:
                said.append(f"the run record cannot be published ({got[0]} its rename: {got[1]}); nothing is run")
                remove(run_name)
                return no_child
            run_dir = os.path.join(exec_root, run_name)
            child_fd = os.dup(lock_fd)
            try:
                child = _launch(
                    [python, "-I", "-S", "-B", os.path.join(exec_root, BUNDLE, LAUNCHER), "--run-dir", run_dir,
                     "--lock-fd", str(child_fd), "--docker", docker],
                    shell=False, close_fds=True, pass_fds=(child_fd,), stdin=subprocess.DEVNULL, cwd=run_dir,
                    env={"DOCKER_HOST": values["engine"], "DOCKER_CONFIG": os.path.join(run_dir, "docker"),
                         "HOME": os.path.join(run_dir, "home"), "LC_ALL": "C"}, start_new_session=True)
                rec["started"] = True
            finally:
                os.close(child_fd)
            try:
                child.wait(timeout=child_timeout)
            except subprocess.TimeoutExpired:
                said.append(f"{rid}: the child outran {child_timeout} s; its group is killed")
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except OSError:
                    pass
                child.wait()
            code, passed, keep = _decide(efd, run_name, current, said)
            rec["code"] = code
            if code == EXIT_PASS and prospective:
                said.append(f"{rid}: A2 passed; its evidence carries the token for A3 "
                            f"({passed['why']}); no stop target is recorded before activation")
                said.append(f"pre-activation live config sha256 {rec['pre_activation_sha256']}: keep it beside A3's "
                            f"place. After that place the back-out is, in order: {POST_PLACE_BACK_OUT}")
            elif code == EXIT_PASS:
                why = _verified_target(_Engine(docker, values["engine"], run_dir), passed, values)
                if why:
                    said.append(f"{rid}: passed; no stop target recorded: {why}")
                    code = EXIT_HANDOFF
                else:
                    record = {k: passed[k] for k in ("config_sha256", "evidence_run_id", "evidence_sha256",
                                                     "inspect_digest")}
                    record.update(schema=RECOVERY_SCHEMA, host=host, run_id=rid, at=at,
                                  evidence_dir=values["evidence_dir"], live_config_path=values["live_config"],
                                  engine=values["engine"], docker=docker, router_container_id=passed["router_seen"],
                                  activation_sha256=activation_sha256)
                    why = _publish_target(efd, values["evidence_dir"], _canonical(record))
                    if why:
                        said.append(f"{rid}: passed; {why}")
                        code = EXIT_HANDOFF
                    else:
                        said.append(f"{rid}: passed; stop target {passed['router_seen']} recorded")
            if keep:
                said.append(f"{run_name}: kept, since an effect is not yet shown done")
                rec["kept"].add(run_name)
            else:
                remove(run_name)
            return code
        except Handoff as e:
            said.append(f"handoff: {e}")
            return EXIT_HANDOFF
        except OSError as e:
            # Setting up, listing or launching failed. A run whose child never
            # started has no effect, and its directory goes; a decided run
            # keeps its exit; otherwise it is a handoff, never an incident.
            said.append(f"handoff: {e.strerror or e}" + (f" ({e.filename})" if e.filename else ""))
            if rec["made"] is not None and not rec["started"]:
                remove(rec["made"])
            if rec["code"] is not None:
                return rec["code"] if rec["code"] in (EXIT_INCIDENT, EXIT_TOOLING) else EXIT_HANDOFF
            return EXIT_INCIDENT if rec["incident"] else EXIT_HANDOFF
        except Tooling as e:
            said.append(f"tooling_unverified: {e}")
            if lock_fd is None:
                said.append("the lock is not held: nothing is acted on")
                return EXIT_TOOLING
            recovery = _recovery(efd)
            if recovery is None:
                said.append("no recovery description: no target, nothing stopped")
                return EXIT_TOOLING
            try:
                docker = _trusted_tool(recovery["docker"])
                bad = closure_problems(_docker_closure(docker, values["docker"] if values else None))
                if bad:
                    raise Tooling("its own startup closure is not root's alone: " + "; ".join(bad[:5]))
                _engine_socket(recovery["engine"])
            except Tooling as e2:
                said.append(f"handoff: the recovery description's docker is not verified either ({e2}): "
                            "it is not run, and nothing is stopped")
                return EXIT_TOOLING
            _act(recovery["evidence_dir"], recovery["live_config_path"], recovery["router_container_id"],
                 "tooling-" + rid, at, ["tooling_unverified"], _Engine(docker, recovery["engine"], exec_root), said)
            return EXIT_TOOLING

    def publish():
        """W7, after every effect and before the lock is released, on every
        path once W2 succeeded: what remains, from a fresh listing. Visible is
        never taken for durable."""
        if rec["evfd"] is None:
            return
        try:
            data = _runs_record(efd, host, stamp(), rec["kept"])
        except OSError as e:
            said.append(f"the run record cannot be listed ({e.strerror or e}); the last one stays")
            rec["status"] = True
            return
        got = _stage_write(rec["evfd"], WEEKLY_RUNS, data, _runs_fs("W7"))
        if got:
            said.append(f"the run record cannot be published durably ({got[0]} its rename: {got[1]})")
            rec["status"] = True

    try:
        try:
            code = body()
        finally:
            publish()
        final = _status(code) if rec["status"] else code
        if prospective and final != EXIT_PASS and not rec.get("router_up"):
            said.append(_back_out(rec.get("router_name"), sorted(rec["kept"]), rec.get("pre_activation_sha256"),
                                  rec.get("live_delegation", False)))
        return final
    finally:
        for s in said:
            try:
                emit(f"partition-weekly: {s}")
            except Exception:  # a diagnostic is never an action
                pass
        if rec["evfd"] is not None:
            os.close(rec["evfd"])
        if lock_fd is not None:
            os.close(lock_fd)
        os.close(efd)


def partition_provision(exec_root):
    """Swap `<exec_root>/bundle.new` in as the bundle, under the job's lock,
    once it verifies (its own PIN is the one it carries). The operator runs
    this after the printed provisioning commands fill bundle.new."""
    efd = _root_dir(exec_root, 0o700)
    lock_fd = None
    try:
        lock_fd = _take_partition_lock(efd)
        nfd = os.open("bundle.new", _DIR, dir_fd=efd)
        try:
            pin = _read_at(nfd, PIN, 64)[0].decode("ascii").strip()
        finally:
            os.close(nfd)
        os.rename("bundle.new", "bundle.check", src_dir_fd=efd, dst_dir_fd=efd)
        try:
            os.rename("bundle", "bundle.old", src_dir_fd=efd, dst_dir_fd=efd)
        except FileNotFoundError:
            pass
        os.rename("bundle.check", BUNDLE, src_dir_fd=efd, dst_dir_fd=efd)
        try:
            _verify_bundle(efd, pin)
        except (Tooling, Handoff):
            os.rename(BUNDLE, "bundle.new", src_dir_fd=efd, dst_dir_fd=efd)
            try:
                os.rename("bundle.old", BUNDLE, src_dir_fd=efd, dst_dir_fd=efd)
            except FileNotFoundError:
                pass
            raise
        try:
            _remove_tree(efd, "bundle.old")
        except FileNotFoundError:
            pass
        os.fsync(efd)
        return 0
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
        os.close(efd)


def _secret_main(argv):
    """The secret steps' dispatch. Any exception at all becomes one fixed
    line and exit 2 through os._exit, so no traceback, repr or message can
    carry the value."""
    try:
        if len(argv) == 4 and argv[0] == "secret":
            secret(argv[1], int(argv[2]), int(argv[3]))
        elif len(argv) == 5 and argv[:2] == ["secret", "--check"]:
            secret_check(argv[2], int(argv[3]), int(argv[4]))
        elif len(argv) == 2 and argv[0] == "secret-remove":
            secret_remove(argv[1])
        elif len(argv) == 2 and argv[0] == "stat-secret":
            stat_secret(argv[1])
        elif len(argv) >= 4 and argv[0] == "lock" and argv[2] == "--":
            return lock(argv[1], argv[3:])
        elif len(argv) >= 5 and argv[0] == "probe-weekly" and "--" in argv[3:]:
            return _probe_weekly_main(argv)
        else:
            raise Refused("usage")
        sys.stdout.flush()
        return 0
    except Refused as e:
        rule = e.rule
    except BaseException:
        rule = argv[0] if argv and argv[0] in SECRET_STEPS else "usage"
    try:
        sys.stdout.write(f"refused: {rule}\n")
        sys.stdout.flush()
    except BaseException:
        pass
    os._exit(REFUSED)


SECRET_STEPS = frozenset({"secret", "secret-remove", "stat-secret", "lock", "probe-weekly"})


def main(argv):
    if argv and argv[0] in SECRET_STEPS:
        return _secret_main(argv)
    try:
        if len(argv) == 5 and argv[0] == "root":
            root(argv[1], int(argv[2]), int(argv[3]), int(argv[4], 8))
        elif len(argv) == 6 and argv[0] == "root" and argv[5] == "--exclusive":
            root(argv[1], int(argv[2]), int(argv[3]), int(argv[4], 8), exclusive=True)
        elif len(argv) >= 2 and argv[0] == "sync":
            sync(*argv[1:])
        elif len(argv) == 3 and argv[0] == "place":
            place(argv[1], argv[2])
        elif len(argv) == 5 and argv[0] == "place" and argv[3] == "--sha256":
            place(argv[1], argv[2], sha256=argv[4])
        elif len(argv) == 7 and argv[0] == "place" and argv[3] == "--sha256" and argv[5] == "--mode":
            if not re.fullmatch(r"0?[0-7]{3}", argv[6]):
                raise StepError(f"--mode {argv[6]!r} is not an octal mode; 0444 or 0644")
            place(argv[1], argv[2], sha256=argv[4], mode=int(argv[6], 8))
        elif len(argv) == 2 and argv[0] == "marker":
            marker(argv[1])
        elif len(argv) in (13, 14) and argv[0] == "partition-weekly" and (len(argv) == 13 or argv[13] == "--prospective"):
            opts = dict(zip(argv[1:13:2], argv[2:13:2]))
            if set(opts) != {"--exec-root", "--host", "--document", "--document-sha256", "--activation",
                             "--activation-sha256"}:
                raise StepError("partition-weekly --exec-root DIR --host NAME --document PATH --document-sha256 HEX "
                                "--activation PATH --activation-sha256 HEX [--prospective]")
            return partition_weekly(opts["--exec-root"], opts["--host"], opts["--document"], opts["--document-sha256"],
                                    opts["--activation"], opts["--activation-sha256"], prospective=len(argv) == 14)
        elif len(argv) == 2 and argv[0] == "partition-provision":
            return partition_provision(argv[1])
        elif len(argv) == 3 and argv[0] == "trusted-tools":
            _verified_tools(argv[1], argv[2])
            return 0
        else:
            print(__doc__.split("\n\n")[1], file=sys.stderr)
            return 2
    except (Tooling, Handoff) as e:
        print(f"host_steps: {e}", file=sys.stderr)
        return EXIT_TOOLING if isinstance(e, Tooling) else EXIT_HANDOFF
    except Refused:
        print("host_steps: refused: usage", file=sys.stderr)
        return REFUSED
    except (StepError, OSError, ValueError) as e:
        print(f"host_steps: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
