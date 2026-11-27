"""S7's writer (stage contract 3.7; lock `writers[]` use `api_key`), run on a VM by DS's
rule-7 bootstrap (vm_bootstrap.py `secret api_key <mode> <sha> <agent account>`), which runs as root and calls
`main(mode, value, account)` in its own process. This writer never writes as root: it forks, and the child becomes
the agent account (its own primary group only), proves it cannot become root again and sets itself not dumpable
and reads that back (a uid change sets the flag to the kernel's fs.suid_dumpable, 0 by default;
the child does not rely on that setting) before it touches a file. For ALPHA-2 the Claude credential is the setup
token, `CLAUDE_CODE_OAUTH_TOKEN`, written to sandy's privileged secrets file. That file is
derived here and nowhere else: exactly `<the account's home>/.sandy/.secrets`, with the
home from the account database, never a workspace `.sandy/.secrets` (sandy a.12 answers,
section 4; DS 5d428598: vm_write_secret passes NO path). Its directory must resolve to
itself (no symlink on the way).

    write      the value becomes the file's one token line
    rotate     the same, keeping the old file as .secrets.prev; a value equal to the
               one sandy reads today is refused (VALUE_UNCHANGED)
    finish     rotation succeeded: remove .secrets.prev
    restore    rotation failed: .secrets.prev back in place of .secrets

The value arrives from the bootstrap, which read it from stdin, never as an argument or a variable
(rule 9): a bytearray for write and rotate, None for finish and restore. The bootstrap runs in a
closed environment: PATH=/usr/bin:/bin and LC_ALL=C only.

How the file is read is sandy's own rule (`_load_sandy_config`, sandy 15522+ at 924fa5b6):
- lines are split on LF only, and a final line without an LF is never read;
- a line's key is exactly the text before its first `=`, with no trimming, so a line
  `export KEY=...` or ` KEY=...` is not KEY;
- the value has one trailing CR removed, then one leading and trailing `"`, then one `'`;
- the last line of a key wins.
So the writer removes exactly the lines whose key is KEY, keeps every other line byte for
byte, and appends one `KEY=<value>` line. It refuses a non-empty file that does not end in
LF, because appending would make sandy read a line it ignores today. It also refuses a
value with a leading or trailing quote, which sandy would strip. S7's rule-10 count
(`grep -c '^KEY='`) is the same predicate.

Rules (3.7):
- 1: the bootstrap sets the core-dump limit to zero before it reads the value; the child
  checks it again, and sets itself not dumpable, after the uid change and before any file;
- 6: every return code is checked, and a full-write loop writes a 0600 temporary in the
  same 0700 directory, which is fsynced and renamed into place;
- 8: the result holds exactly one token line.
The value, its length and any part of it are never printed. The only output is one fixed
`CAUSE=` line on stderr, on refusal.

Exit codes:
- 0: done;
- 2: refused, and nothing changed;
- 3: a change was attempted and undone, so the file is as it was;
- 4: the change STANDS but is not known durable (DURABILITY_UNCERTAIN), a finish or
  restore step failed half way, or the child ended without an answer. S7 treats 4 as
  "restore needed".
The writer keeps the value's bytes in bytearrays and zeroes those it owns. Immutable
copies made by Python on the way are not zeroed; with core dumps off, that is defence in
depth only.
"""

import ctypes
import os
import pwd
import resource
import stat

MODES = ("write", "rotate", "finish", "restore")
VALUE_MODES = ("write", "rotate")
KEY = b"CLAUDE_CODE_OAUTH_TOKEN"
VALUE_MAX = 4096
FILE_MAX = 1 << 20
PREV = ".prev"
TEMP_PREFIX = ".secrets.tmp-"
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
    """Printable ASCII only, 1 to VALUE_MAX bytes, in a bytearray, and no leading or trailing
    quote (sandy would strip it)."""
    if type(value) is not bytearray or not 0 < len(value) <= VALUE_MAX:
        return False
    for c in value:
        if not 0x21 <= c <= 0x7e:
            return False
    return value[:1] not in (b'"', b"'") and value[-1:] not in (b'"', b"'")


def account_of(name):
    """(uid, gid, home) of the agent account, from the account database. Root, a primary group of root, or a
    home that is not a plain absolute path, refuses."""
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
    """Root to exactly `uid`:`gid`, no supplementary group but `gid`; then becoming root
    again must fail."""
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


#: The account database and the uid change: the only two names the RealLayerTest stands in
#: for (by text, without root), each named in its NOTE as FAKED.
LOOKUP = pwd.getpwnam
BECOME = _become_account


def not_dumpable(prctl=None, getrlimit=resource.getrlimit):
    """After the uid change: not dumpable (set and read back) and the core limit still zero,
    or refuse."""
    try:
        if prctl is None:
            prctl = ctypes.CDLL(None, use_errno=True).prctl
        if prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 or prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise OSError("dumpable")
        if getrlimit(resource.RLIMIT_CORE) != (0, 0):
            raise OSError("core limit")
    except (OSError, AttributeError, ValueError):
        raise Refuse("CORE_LIMIT")


def pinned_path(home):
    """<the account's home>/.sandy/.secrets, the home from the account database."""
    return home + "/.sandy/.secrets"


def check_target(path, uid):
    """The derived path has no `.` or `..` and no symlink anywhere on it, and its
    directory is the account's own 0700 directory."""
    d = os.path.dirname(path)
    if ("/./" in path or "/../" in path or not os.path.isabs(path)
            or os.path.realpath(d) != d):
        raise Refuse("TARGET")
    try:
        st = os.stat(d, follow_symlinks=False)
    except OSError:
        raise Refuse("SECRETS_DIR")
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != uid or stat.S_IMODE(st.st_mode) != 0o700:
        raise Refuse("SECRETS_DIR")


def no_leftovers(d, path, rotating):
    """Refuse before anything is created: a leftover temporary (a crashed run's full
    token copy) or, for rotate and write, a previous file."""
    try:
        names = os.listdir(d)
    except OSError:
        raise Refuse("SECRETS_DIR")
    if any(n.startswith(TEMP_PREFIX) for n in names):
        raise Refuse("TEMP_LEFTOVER")
    if os.path.lexists(path + PREV):
        raise Refuse("PREVIOUS_EXISTS")


def _read_existing(path, uid):
    """The current file's bytes, b"" if absent. A symlink, a non-regular file, a foreign
    owner, group or other access, or a non-empty file without a final LF refuses."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return b""
    except OSError:
        raise Refuse("SECRETS_FILE")
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != uid or stat.S_IMODE(st.st_mode) & 0o077
                or st.st_size > FILE_MAX):
            raise Refuse("SECRETS_FILE")
        out = bytearray()
        while True:
            b = os.read(fd, 65536)
            if not b:
                break
            out += b
            if len(out) > FILE_MAX:
                raise Refuse("SECRETS_FILE")
    finally:
        os.close(fd)
    if out and not out.endswith(b"\n"):
        raise Refuse("SECRETS_FILE_SHAPE")
    return bytes(out)


def _lines(existing):
    return existing.split(b"\n")[:-1] if existing else []  # LF only; the file ends in LF


def _is_key(line):
    return line.split(b"=", 1)[0] == KEY and b"=" in line


def sandy_value(line):
    v = line.split(b"=", 1)[1]
    if v.endswith(b"\r"):
        v = v[:-1]
    for q in (b'"', b"'"):
        if v.startswith(q):
            v = v[1:]
        if v.endswith(q):
            v = v[:-1]
    return v


def current_value_equals(existing, value):
    """True when the value sandy reads today (the LAST token line) is `value`. Compared
    here on the VM and never reported."""
    lines = [l for l in _lines(existing) if _is_key(l)]
    return bool(lines) and sandy_value(lines[-1]) == bytes(value)


def merged(existing, value):
    """`existing` without its token lines, then one token line. A bytearray, so the
    caller can zero it."""
    out = bytearray()
    for line in _lines(existing):
        if not _is_key(line):
            out += line + b"\n"
    out += KEY + b"=" + value + b"\n"
    return out


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        if n <= 0:
            raise OSError("short write")
        view = view[n:]


def _fsync_dir(d):
    dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def replace(path, data, keep_previous=False):
    """Write `data` to a 0600 temporary beside `path` and fsync it, link the old file as
    path.prev if asked, rename over `path`, then fsync the directory.
    - Before the rename, any failure removes the temporary and any link this run made:
      the file is as it was (WRITE_FAILED, 3).
    - After the rename, the new file stands, and path.prev is NEVER removed. A failure
      there is DURABILITY_UNCERTAIN (4), never "undone"."""
    d = os.path.dirname(path)
    tmp = os.path.join(d, "%s%d" % (TEMP_PREFIX, os.getpid()))
    prev = path + PREV
    linked = renamed = False
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError:
        raise Refuse("WRITE_FAILED")
    try:
        try:
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        if keep_previous and os.path.lexists(path):
            os.link(path, prev, follow_symlinks=False)
            linked = True
        os.rename(tmp, path)
        renamed = True
        _fsync_dir(d)
    except OSError:
        if renamed:
            raise Refuse("DURABILITY_UNCERTAIN", rc=4)
        _unlink(tmp)
        if linked:
            _unlink(prev)
        raise Refuse("WRITE_FAILED", rc=3)


def _unlink(p):
    try:
        os.unlink(p)
    except OSError:
        pass


def finish(path):
    try:
        os.unlink(path + PREV)
        _fsync_dir(os.path.dirname(path))
    except FileNotFoundError:
        pass
    except OSError:
        raise Refuse("FINISH_FAILED", rc=4)


def restore(path):
    prev = path + PREV
    try:
        st = os.stat(prev, follow_symlinks=False)
    except OSError:
        raise Refuse("NO_PREVIOUS")
    if not stat.S_ISREG(st.st_mode):
        raise Refuse("NO_PREVIOUS")
    try:
        os.rename(prev, path)
    except OSError:
        raise Refuse("RESTORE_FAILED", rc=4)
    try:
        _fsync_dir(os.path.dirname(path))
    except OSError:
        raise Refuse("DURABILITY_UNCERTAIN", rc=4)


def apply(mode, value, uid, home):
    """One mode, already as the account. Returns 0 or raises Refuse."""
    path = pinned_path(home)
    check_target(path, uid)
    if mode == "finish":
        return finish(path)
    if mode == "restore":
        return restore(path)
    no_leftovers(os.path.dirname(path), path, mode == "rotate")
    existing = _read_existing(path, uid)
    data = bytearray()
    try:
        if mode == "rotate" and current_value_equals(existing, value):
            raise Refuse("VALUE_UNCHANGED")
        data = merged(existing, value)
        replace(path, data, keep_previous=(mode == "rotate"))
    finally:
        data[:] = b"\0" * len(data)
    return 0


def _child(ids, mode, value):
    rc = 4
    try:
        try:
            BECOME(ids[0], ids[1])
        except OSError:
            raise Refuse("DROP")
        not_dumpable()
        rc = apply(mode, value, ids[0], ids[2]) or 0
    except Refuse as e:
        _cause(e.cause)
        rc = e.rc
    except BaseException:
        _cause("UNCLASSIFIED")
        rc = 4
    finally:
        if value is not None:
            value[:] = b"\0" * len(value)
    os._exit(rc)


def main(mode, value, account):
    """The bootstrap's entry. Every check that needs no account runs here, before the fork;
    the file is touched only by the child, as the account."""
    try:
        if mode not in MODES:
            raise Refuse("MODE")
        if mode in VALUE_MODES:
            if not value_ok(value):
                raise Refuse("VALUE_FORM")
        elif value is not None:
            raise Refuse("VALUE_FORM")
        ids = account_of(account)
    except Refuse as e:
        _cause(e.cause)
        return e.rc
    pid = os.fork()
    if pid == 0:
        _child(ids, mode, value)
    try:
        _, status = os.waitpid(pid, 0)
    except OSError:
        _cause("UNCLASSIFIED")
        return 4
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    _cause("UNCLASSIFIED")
    return 4
