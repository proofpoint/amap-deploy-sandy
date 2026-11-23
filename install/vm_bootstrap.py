"""The one bootstrap the runner runs on a VM as root (stage contract 3.7 rule 7).

It is never a file on the VM. The runner reads these bytes from its own checkout, checks them against
install/MANIFEST, and runs them as `sudo -n -- /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/python3 -I -S -c
<these bytes> <op> <args>`, so the bytes hashed are the bytes the VM's interpreter executes.

  install <relpath> <mode> <sha256>              data on stdin; places one allowlisted file, root-owned
  secret <use> <mode> <writer_sha256> <account>  stdin: 8-byte length, the writer's bytes, then the value
  hopintakes <hop root> <relay account> <group>  the hop root's two intakes, owned by the relay account

Exit codes: 0 done, 10 already in place, 2 usage, 3 pin mismatch, 4 not allowed, 5 OS error, 6 read-back mismatch,
7 core limit or dumpable flag not set, 8 a never-replaced file is present and differs (left untouched). `secret` prints two lines and nothing else: `READY`, after the writer's bytes
matched their pin (the caller sends the value only after it, so a mismatched writer never receives the value), and
`RC <n>`, after the writer returned n. A `secret` that exits without `RC` failed in the bootstrap, whatever its code.
"""

import grp
import hashlib
import os
import pwd
import re
import resource
import stat
import sys

ROOT = "/"
OWNER = (0, 0)
BIN = "usr/local/bin"
SANDY = BIN + "/sandy"
PROXY = BIN + "/proxy"
#: The HOP transport plugin, which RL and RE both load from a root-owned path (W7-PLUGIN-ROOT-PATH).
PLUGIN = "opt/amap-plugin/amap_hop_plugin.py"
_PROXY_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_SHA = re.compile(r"[0-9a-f]{64}")
_NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
MAX_FILE = 32 << 20
MAX_WRITER = 1 << 20
MAX_VALUE = 64 << 10
USES = ("api_key", "hub_login")
#: The hop root's two host intakes (HOP's layout): owned by RE's account, in the hop group, setgid, read by RL
#: through the group. The agent account makes the root itself; only these need root to give to another uid.
INTAKES = (".unresolved", ".control")
INTAKE_MODE = 0o2750
HOP_ROOT_MODE = 0o2750
_ABS = re.compile(r"(/[A-Za-z0-9._-]+)+")
#: hopintakes reads ownership and gives it away only through these two names, so a test without root can stand
#: another uid in for the real one; everything else it does is the real filesystem's.
_fstat = os.fstat
_fchown = os.fchown
SECRET_MODES = ("write", "rotate", "finish", "restore")

OK, ALREADY, USAGE, PIN, NOT_ALLOWED, OS_ERROR, READBACK, CORE = 0, 10, 2, 3, 4, 5, 6, 7
DIFFERENT = 8
#: Files placed only where absent: a present one with other bytes, owner or mode refuses DIFFERENT and is never
#: replaced. The sandy binary and the proxy files are replaced by design (S7 moves them to the lock's pin).
NEVER_REPLACED = (PLUGIN,)
PR_SET_DUMPABLE = 4


class Stop(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _allowed(relpath, mode):
    """The compiled allowlist: the sandy file at 0755, flat files under proxy/ at 0644, and the plugin at 0444."""
    if relpath == SANDY:
        return mode == 0o755
    if relpath == PLUGIN:
        return mode == 0o444
    head, _, name = relpath.rpartition("/")
    return head == PROXY and name not in (".", "..") and bool(_PROXY_NAME.fullmatch(name)) and mode == 0o644


def _checked_dir(fd):
    """A directory descriptor owned by OWNER and writable by no group or other; refused otherwise."""
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode) or (st.st_uid, st.st_gid) != OWNER or st.st_mode & 0o022:
        raise Stop(NOT_ALLOWED)


def _open_dir(parts, create_last=False):
    """Walk from ROOT one component at a time, never following a symlink, checking each directory. The last one is
    created 0755 if asked and absent. Returns the last directory's descriptor: every later open, rename and fsync
    goes through it, so no path is resolved twice."""
    fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _checked_dir(fd)
        for i, part in enumerate(parts):
            try:
                nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if not (create_last and i == len(parts) - 1):
                    raise Stop(NOT_ALLOWED)
                os.mkdir(part, 0o700, dir_fd=fd)
                nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.fchown(nfd, *OWNER)
                os.fchmod(nfd, 0o755)
            except OSError:
                raise Stop(NOT_ALLOWED)
            os.close(fd)
            fd = nfd
            _checked_dir(fd)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_all(fd, limit):
    chunks, size = [], 0
    while True:
        b = os.read(fd, min(1 << 16, limit + 1 - size))
        if not b:
            return b"".join(chunks)
        chunks.append(b)
        size += len(b)
        if size > limit:
            raise Stop(NOT_ALLOWED)


def _read_exact(fd, n):
    chunks, size = [], 0
    while size < n:
        b = os.read(fd, n - size)
        if not b:
            raise Stop(USAGE)
        chunks.append(b)
        size += len(b)
    return b"".join(chunks)


def _in_place(dfd, name, sha, mode):
    """The file `name` in directory `dfd` has the wanted bytes, owner and mode: True; absent: False; a symlink or a
    non-file: refused."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    except FileNotFoundError:
        return False
    except OSError:
        raise Stop(NOT_ALLOWED)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Stop(NOT_ALLOWED)
        same = (hashlib.sha256(_read_all(fd, MAX_FILE)).hexdigest() == sha
                and (st.st_uid, st.st_gid) == OWNER and stat.S_IMODE(st.st_mode) == mode)
    finally:
        os.close(fd)
    return same


def _present(dfd, name):
    """Whether `name` exists in `dfd`, whatever its type (a symlink is not followed)."""
    try:
        os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError:
        raise Stop(NOT_ALLOWED)
    return True


def install(relpath, mode_s, sha, data):
    if not re.fullmatch(r"0[0-7]{3}", mode_s) or not _SHA.fullmatch(sha):
        raise Stop(USAGE)
    mode = int(mode_s, 8)
    if not _allowed(relpath, mode):
        raise Stop(NOT_ALLOWED)
    if len(data) > MAX_FILE:
        raise Stop(NOT_ALLOWED)
    if hashlib.sha256(data).hexdigest() != sha:
        raise Stop(PIN)
    *dirs, name = relpath.split("/")
    dfd = _open_dir(dirs, create_last=(relpath != SANDY))
    try:
        if _in_place(dfd, name, sha, mode):
            return ALREADY
        keep = relpath in NEVER_REPLACED
        if keep and _present(dfd, name):
            raise Stop(DIFFERENT)
        tmp = ".a2-install-%d" % os.getpid()
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
        try:
            view = memoryview(data)
            while view:
                n = os.write(fd, view)
                view = view[n:]
            os.fsync(fd)
            os.fchown(fd, *OWNER)
            os.fchmod(fd, mode)
            os.close(fd)
            fd = None
            if keep:
                # link(2) never replaces: a file that appeared since the check refuses, and the target is untouched.
                try:
                    os.link(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=False)
                except FileExistsError:
                    os.unlink(tmp, dir_fd=dfd)
                    raise Stop(DIFFERENT)
                os.unlink(tmp, dir_fd=dfd)
            else:
                os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        except OSError:
            if fd is not None:
                os.close(fd)
            try:
                os.unlink(tmp, dir_fd=dfd)
            except OSError:
                pass
            raise
        os.fsync(dfd)
        if not _in_place(dfd, name, sha, mode):
            raise Stop(READBACK)
        return OK
    finally:
        os.close(dfd)


def _trusted_ancestor(fd, owner_uid):
    """An ancestor of the hop root: a directory owned by root or the hop root's owner, writable by no group or
    other unless sticky."""
    st = _fstat(fd)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, owner_uid):
        raise Stop(NOT_ALLOWED)
    if st.st_mode & 0o022 and not st.st_mode & stat.S_ISVTX:
        raise Stop(NOT_ALLOWED)


def _intake_ok(st, uid, gid):
    return stat.S_ISDIR(st.st_mode) and (st.st_uid, st.st_gid) == (uid, gid) and stat.S_IMODE(st.st_mode) == INTAKE_MODE


def hopintakes(root, account, group):
    """Create the absent intakes of `root` as account:group 2750; never repair one that exists. The root must be a
    directory owned by a uid that is neither root nor the account's, with gid `group` and mode exactly 2750, reached
    from / through trusted directories without a symlink. OK if one was created, ALREADY if both were in place."""
    if (not _ABS.fullmatch(root) or any(p in (".", "..") for p in root.split("/")) or not _NAME.fullmatch(account)
            or not _NAME.fullmatch(group)):
        raise Stop(USAGE)
    try:
        pw = pwd.getpwnam(account)
        gr = grp.getgrnam(group)
    except KeyError:
        raise Stop(NOT_ALLOWED)
    uid, gid = pw.pw_uid, gr.gr_gid
    if uid == 0 or not (pw.pw_gid == gid or account in gr.gr_mem):
        raise Stop(NOT_ALLOWED)
    parts = root.strip("/").split("/")
    fds = []
    try:
        fds.append(os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        for part in parts:
            try:
                fds.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1]))
            except OSError:
                raise Stop(NOT_ALLOWED)
        rst = _fstat(fds[-1])
        owner = rst.st_uid
        if (owner in (0, uid) or rst.st_gid != gid or stat.S_IMODE(rst.st_mode) != HOP_ROOT_MODE):
            raise Stop(NOT_ALLOWED)
        for fd in fds[:-1]:
            _trusted_ancestor(fd, owner)
        rfd = fds[-1]
        # Every existing intake is checked before any is made, so a refusal means nothing was written.
        absent = []
        for name in INTAKES:
            try:
                ifd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=rfd)
            except FileNotFoundError:
                absent.append(name)
                continue
            except OSError:
                raise Stop(NOT_ALLOWED)
            try:
                if not _intake_ok(_fstat(ifd), uid, gid):
                    raise Stop(NOT_ALLOWED)
            finally:
                os.close(ifd)
        for name in absent:
            os.mkdir(name, 0o700, dir_fd=rfd)
            ifd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=rfd)
            try:
                _fchown(ifd, uid, gid)
                os.fchmod(ifd, INTAKE_MODE)
                os.fsync(ifd)
                if not _intake_ok(_fstat(ifd), uid, gid):
                    raise Stop(READBACK)
            finally:
                os.close(ifd)
        created = bool(absent)
        if created:
            os.fsync(rfd)
        return OK if created else ALREADY
    finally:
        for fd in fds:
            os.close(fd)


def _not_dumpable():
    """prctl(PR_SET_DUMPABLE, 0): no core through a pipe core_pattern helper either, and no ptrace by the same uid."""
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl")


def _read_value(fd, limit):
    """The value, read straight into one preallocated bytearray (no intermediate bytes), at most `limit` bytes."""
    buf = bytearray(limit + 1)
    view = memoryview(buf)
    n = 0
    try:
        while True:
            got = os.readv(fd, [view[n:]])
            if not got:
                break
            n += got
            if n > limit:
                buf[:] = b"\x00" * len(buf)
                raise Stop(NOT_ALLOWED)
    finally:
        view.release()
    del buf[n:]
    return buf


def secret(use, mode, writer_sha, account):
    if use not in USES or mode not in SECRET_MODES or not _SHA.fullmatch(writer_sha) or not _NAME.fullmatch(account):
        raise Stop(USAGE)
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        _not_dumpable()
    except (OSError, ValueError, AttributeError):
        raise Stop(CORE)
    n = int.from_bytes(_read_exact(0, 8), "big")
    if n > MAX_WRITER:
        raise Stop(NOT_ALLOWED)
    writer = _read_exact(0, n)
    if hashlib.sha256(writer).hexdigest() != writer_sha:
        raise Stop(PIN)
    os.write(1, b"READY\n")
    value = None
    if mode in ("write", "rotate"):
        value = _read_value(0, MAX_VALUE)
    namespace = {"__name__": "a2_writer"}
    try:
        exec(compile(writer, "<writer " + use + ">", "exec"), namespace)
        rc = namespace["main"](mode, value, account)
    finally:
        if value is not None:
            value[:] = b"\x00" * len(value)
    if type(rc) is not int or not 0 <= rc <= 255:
        return OS_ERROR
    os.write(1, b"RC %d\n" % rc)
    return rc


def main(argv):
    try:
        if len(argv) == 4 and argv[0] == "install":
            data = _read_all(0, MAX_FILE)
            return install(argv[1], argv[2], argv[3], data)
        if len(argv) == 4 and argv[0] == "hopintakes":
            return hopintakes(argv[1], argv[2], argv[3])
        if len(argv) == 5 and argv[0] == "secret":
            return secret(argv[1], argv[2], argv[3], argv[4])
        return USAGE
    except Stop as e:
        return e.code
    except OSError:
        return OS_ERROR


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
