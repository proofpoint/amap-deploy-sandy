"""S6b's writer (stage contract 3.7; lock `writers[]` use `hub_login`): RE's password file on a VM.

DS's rule-7 bootstrap (vm_bootstrap.py `secret hub_login write <sha> <relay account>`) runs as root, sets the core
limit to zero and the process not dumpable, checks these bytes against their pin, says READY, reads the value, and
calls `main(mode, value, account)` in its own process. This writer never writes as root: it forks, and the child
becomes the relay account (its own primary group only, every other group dropped), proves it cannot become root
again, sets itself not dumpable and reads that back (a uid change sets the flag to the kernel's fs.suid_dumpable,
0 by default; the child does not rely on that setting), and only then touches the file.

The file is RE's (hub_secret.py at RE's pin, as relayed): `<relay home>/.amap-relay/login/password`, a regular file,
one link, owned by the relay account's uid AND its primary gid (the user S8 runs RE as), mode 0400, holding exactly
the value: 1 to VALUE_MAX bytes, each 0x21 to 0x7E, no newline. The directory `.amap-relay/login` is S6's (vm_dirs
RELAY_DIRS), the relay account's own, 0700; this writer never creates or repairs it.

    write      the value becomes the file's whole content (the only mode: S6b has no rotation)

Rules (3.7):
- 1: the core limit is zero, checked again in the child, before the value is used;
- 6: every return code is checked, and a full-write loop writes a 0600 temporary in the same 0700 directory, which
  is fsynced, made 0400, checked, renamed into place, and the directory fsynced. A temporary that cannot be removed
  after a failed write is exit 4 (TEMP_LEFT), never "undone".
The value, its length and any part of it are never printed. The only output is one fixed `CAUSE=` line on stderr,
on refusal.

Exit codes (returned to the bootstrap, which prints `RC <n>`):
- 0: done;
- 2: refused, and nothing changed;
- 3: a change was attempted and undone, so the file is as it was;
- 4: the new file STANDS but is not known durable (DURABILITY_UNCERTAIN), or a failed write's temporary could not be
  removed (TEMP_LEFT: no new file, a partial temporary left), or the child ended without an answer.
"""

import ctypes
import os
import pwd
import resource
import stat

MODES = ("write",)
VALUE_MAX = 1024
RELAY_DIR = ".amap-relay"
LOGIN_DIR = "login"
NAME = "password"
TEMP_PREFIX = ".password.tmp-"
FILE_MODE = 0o400
TEMP_MODE = 0o600
DIR_MODE = 0o700
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
PR_SET_DUMPABLE, PR_GET_DUMPABLE = 4, 3


class Refuse(Exception):
    def __init__(self, cause, rc=2):
        super().__init__(cause)
        self.cause, self.rc = cause, rc


def _cause(name):
    try:
        os.write(2, ("CAUSE=%s\n" % name).encode("ascii"))
    except OSError:
        pass


def value_ok(value):
    """RE's own rule for the file's bytes: a bytearray of 1 to VALUE_MAX bytes, each 0x21 to 0x7E."""
    if type(value) is not bytearray or not 0 < len(value) <= VALUE_MAX:
        return False
    for b in value:
        if not 0x21 <= b <= 0x7E:
            return False
    return True


def account_of(name):
    """(uid, gid, home) of the relay account, from the account database. Root, a primary group of root, or a home
    that is not a plain absolute path, refuses."""
    try:
        pw = LOOKUP(name)
    except (KeyError, TypeError, ValueError):
        raise Refuse("ACCOUNT")
    home = pw.pw_dir
    if (pw.pw_uid == 0 or pw.pw_gid == 0 or not isinstance(home, str) or not home.startswith("/") or home.startswith("//")
            or any(s in (".", "..") for s in home.split("/")) or home.rstrip("/") != home):
        raise Refuse("ACCOUNT")
    return pw.pw_uid, pw.pw_gid, home


def _become_account(uid, gid):
    """Root to exactly `uid`:`gid`, no supplementary group but `gid`; then becoming root again must fail."""
    os.setgroups([gid])
    os.setgid(gid)
    os.setuid(uid)
    if (os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid)
            or os.getgroups() not in ([], [gid])):
        raise Refuse("DROP")
    try:
        os.setuid(0)
    except PermissionError:
        return
    raise Refuse("DROP")


#: The account database and the uid change: the only two names the RealLayerTest stands in for (by text, without
#: root), each named in its NOTE as FAKED.
LOOKUP = pwd.getpwnam
BECOME = _become_account


def not_dumpable(prctl=None, getrlimit=resource.getrlimit):
    """After the uid change: not dumpable (set and read back) and the core limit still zero, or refuse."""
    try:
        if prctl is None:
            prctl = ctypes.CDLL(None, use_errno=True).prctl
        if prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 or prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise OSError("dumpable")
        if getrlimit(resource.RLIMIT_CORE) != (0, 0):
            raise OSError("core limit")
    except (OSError, AttributeError, ValueError):
        raise Refuse("CORE_LIMIT")


def _own_dir(fd, uid):
    st = os.fstat(fd)
    return stat.S_ISDIR(st.st_mode) and st.st_uid == uid and stat.S_IMODE(st.st_mode) == DIR_MODE


def open_login_dir(home, uid):
    """<home>/.amap-relay/login, each step opened without following a symlink, both the account's own 0700
    directories. Returns its descriptor."""
    fds = []
    try:
        try:
            hfd = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            fds.append(hfd)
            rfd = os.open(RELAY_DIR, DIR_FLAGS, dir_fd=hfd)
            fds.append(rfd)
            lfd = os.open(LOGIN_DIR, DIR_FLAGS, dir_fd=rfd)
        except OSError:
            raise Refuse("LOGIN_DIR")
        if not _own_dir(rfd, uid) or not _own_dir(lfd, uid):
            os.close(lfd)
            raise Refuse("LOGIN_DIR")
        return lfd
    finally:
        for fd in fds:
            os.close(fd)


def check_present(lfd, uid):
    """Before anything is created: no leftover temporary (a crashed run's copy of a value), and a password file
    already there is the account's own regular file with one link."""
    try:
        names = os.listdir(lfd)
    except OSError:
        raise Refuse("LOGIN_DIR")
    if any(n.startswith(TEMP_PREFIX) for n in names):
        raise Refuse("TEMP_LEFTOVER")
    try:
        st = os.stat(NAME, dir_fd=lfd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError:
        raise Refuse("LOGIN_FILE")
    if not stat.S_ISREG(st.st_mode) or st.st_uid != uid or st.st_nlink != 1:
        raise Refuse("LOGIN_FILE")


def _write_all(fd, data):
    view = memoryview(data)
    try:
        while view:
            n = os.write(fd, view)
            if n <= 0:
                raise OSError("short write")
            view = view[n:]
    finally:
        view.release()


def place(lfd, value, uid, gid):
    """The temporary, written, fsynced, made 0400 and checked; then renamed over the file and the directory
    fsynced. Before the rename any failure removes the temporary (3); after it, the new file stands (4)."""
    tmp = "%s%d" % (TEMP_PREFIX, os.getpid())
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, TEMP_MODE, dir_fd=lfd)
    except OSError:
        raise Refuse("WRITE_FAILED")
    renamed = False
    try:
        try:
            _write_all(fd, value)
            os.fsync(fd)
            os.fchmod(fd, FILE_MODE)
            st = os.fstat(fd)
        finally:
            os.close(fd)
        if (not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != FILE_MODE or (st.st_uid, st.st_gid) != (uid, gid)
                or st.st_nlink != 1 or st.st_size != len(value)):
            raise OSError("read-back")
        os.rename(tmp, NAME, src_dir_fd=lfd, dst_dir_fd=lfd)
        renamed = True
        os.fsync(lfd)
    except OSError:
        if renamed:
            raise Refuse("DURABILITY_UNCERTAIN", rc=4)
        try:
            os.unlink(tmp, dir_fd=lfd)
        except OSError:
            # The temporary (a partial copy of the value) is still there: not "undone". The next run refuses
            # TEMP_LEFTOVER until it is removed.
            raise Refuse("TEMP_LEFT", rc=4)
        raise Refuse("WRITE_FAILED", rc=3)


def write_as(account_ids, value):
    """The child's whole job, already as the account. Returns 0 or raises Refuse."""
    uid, gid, home = account_ids
    not_dumpable()
    lfd = open_login_dir(home, uid)
    try:
        check_present(lfd, uid)
        place(lfd, value, uid, gid)
    finally:
        os.close(lfd)
    return 0


def _child(ids, value):
    rc = 4
    try:
        try:
            BECOME(ids[0], ids[1])
        except OSError:
            raise Refuse("DROP")
        rc = write_as(ids, value)
    except Refuse as e:
        _cause(e.cause)
        rc = e.rc
    except BaseException:
        _cause("UNCLASSIFIED")
        rc = 4
    finally:
        value[:] = b"\x00" * len(value)
    os._exit(rc)


def main(mode, value, account):
    """The bootstrap's entry. Every check that needs no account runs here, before the fork; the file is touched only
    by the child, as the account."""
    try:
        if mode not in MODES:
            raise Refuse("MODE")
        if not value_ok(value):
            raise Refuse("VALUE_FORM")
        ids = account_of(account)
    except Refuse as e:
        _cause(e.cause)
        return e.rc
    pid = os.fork()
    if pid == 0:
        _child(ids, value)
    try:
        _, status = os.waitpid(pid, 0)
    except OSError:
        _cause("UNCLASSIFIED")
        return 4
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    _cause("UNCLASSIFIED")
    return 4
