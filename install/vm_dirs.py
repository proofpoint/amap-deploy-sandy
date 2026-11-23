"""S6 CONFIG on one VM: the directories the agent account owns (design S6 section 2; HOP 30eedfbb).

It is never a file on the VM. The runner reads these bytes from its own checkout, checks them against
install/MANIFEST, and runs them through the VM layer's launcher as `/usr/bin/python3 -I -S -c <these bytes>
<hop group>`, as the agent account, with HOME that account's home; or with the one argument `--relay`, as the relay
account, for RELAY_DIRS (no group) under that account's home.

- Every directory from / down to HOME is a real directory owned by root or this account, not group- or
  other-writable unless sticky (RL's rule for the seed's ancestors, condition (b)).
- Each directory of DIRS, in order, under HOME: absent, it is made with its exact mode (and the hop group where it
  has one); present, it must be a real directory owned by this account with that exact mode and group, or the run
  refuses. Nothing is ever repaired. Every present one is checked before any is made, so a refusal means this run
  made nothing.
- The router's state directory is made EMPTY; RL fills it. A present one is not required to be empty.
- The hop root's two intakes are not here: they belong to the relay account and the bootstrap's hopintakes makes
  them, after this.

Output: one line per directory, `CREATED <relpath>` or `EXISTING <relpath>`, in DIRS order.
Exit codes: 0 done, 2 usage, 4 a rule broken (an existing path's owner, group, mode or type, or an ancestor), 5 an OS
error.
"""

import grp
import os
import stat
import sys

#: (path under HOME, mode, in the hop group). Parents come before their children.
DIRS = (
    (".amap-router", 0o700, False),
    (".amap-router/state", 0o700, False),
    (".amap-hop", 0o2750, True),
    (".amap-hop/.disposed", 0o2750, True),
    (".amap-hop/.disposed/.unresolved", 0o2750, True),
    (".amap-hop/.disposed/.control", 0o2750, True),
    (".amap-registry", 0o755, False),
    (".amap-registry/instances", 0o755, False),
    (".amap-relay-env", 0o700, False),
    (".amap-relay-config", 0o755, False),
    (".a2-registry-code", 0o755, False),
    (".amap-router-code", 0o755, False),
)

#: The relay account's set (`--relay`, run as the relay account): RE's state, all VM-local and private to it (RE's
#: answer to E1): the mailbox root (with its send log), the ledger, the inbound state, and the directory S6b's writer
#: puts the password file in. RE creates nothing above these and refuses group or other access.
RELAY_DIRS = (
    (".amap-relay", 0o700, False),
    (".amap-relay/mailbox", 0o700, False),
    (".amap-relay/ledger", 0o700, False),
    (".amap-relay/inbound", 0o700, False),
    (".amap-relay/login", 0o700, False),
)
RELAY_FLAG = "--relay"

OK, USAGE, NOT_ALLOWED, OS_ERROR = 0, 2, 4, 5
#: Ownership is read and given only through these names, so a test without root can stand other ids in.
_stat = os.stat
_fstat = os.fstat
_fchown = os.fchown


class Stop(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _trusted_ancestor(fd, euid):
    st = _fstat(fd)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, euid):
        raise Stop(NOT_ALLOWED)
    if st.st_mode & 0o022 and not st.st_mode & stat.S_ISVTX:
        raise Stop(NOT_ALLOWED)


def _open_home(home, euid):
    """HOME's descriptor, reached from / one component at a time without following a symlink, each one trusted."""
    if not home.startswith("/") or os.path.normpath(home) != home or home == "/" or "//" in home:
        raise Stop(NOT_ALLOWED)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _trusted_ancestor(fd, euid)
        for part in home.strip("/").split("/"):
            try:
                nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except OSError:
                raise Stop(NOT_ALLOWED)
            os.close(fd)
            fd = nfd
            _trusted_ancestor(fd, euid)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _right(st, euid, gid, mode):
    return (stat.S_ISDIR(st.st_mode) and st.st_uid == euid and stat.S_IMODE(st.st_mode) == mode
            and (gid is None or st.st_gid == gid))


def layout(home, euid, gid, dirs=DIRS):
    """[(relpath, "CREATED" | "EXISTING")] in `dirs` order, or Stop."""
    hfd = _open_home(home, euid)
    try:
        present = {}
        for rel, mode, grouped in dirs:
            try:
                st = _stat(rel, dir_fd=hfd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError:
                raise Stop(NOT_ALLOWED)
            if not _right(st, euid, gid if grouped else None, mode):
                raise Stop(NOT_ALLOWED)
            present[rel] = True
        out = []
        for rel, mode, grouped in dirs:
            if rel in present:
                out.append((rel, "EXISTING"))
                continue
            parent, _, name = rel.rpartition("/")
            pfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=hfd) if parent else hfd
            try:
                os.mkdir(name, 0o700, dir_fd=pfd)
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=pfd)
                try:
                    if grouped:
                        _fchown(fd, -1, gid)
                    os.fchmod(fd, mode)
                    if not _right(_fstat(fd), euid, gid if grouped else None, mode):
                        raise Stop(NOT_ALLOWED)
                finally:
                    os.close(fd)
                os.fsync(pfd)
            finally:
                if parent:
                    os.close(pfd)
            out.append((rel, "CREATED"))
        return out
    finally:
        os.close(hfd)


def main(argv):
    if argv == [RELAY_FLAG]:
        try:
            rows = layout(os.environ.get("HOME", ""), os.geteuid(), None, RELAY_DIRS)
        except Stop as e:
            return e.code
        except OSError:
            return OS_ERROR
        os.write(1, "".join("%s %s\n" % (what, rel) for rel, what in rows).encode())
        return OK
    if len(argv) != 1 or argv[0].startswith("-"):
        return USAGE
    try:
        gid = grp.getgrnam(argv[0]).gr_gid
    except (KeyError, ValueError):
        return NOT_ALLOWED
    euid = os.geteuid()
    if gid not in os.getgroups() and gid != os.getegid():
        return NOT_ALLOWED
    try:
        rows = layout(os.environ.get("HOME", ""), euid, gid)
    except Stop as e:
        return e.code
    except OSError:
        return OS_ERROR
    os.write(1, "".join("%s %s\n" % (what, rel) for rel, what in rows).encode())
    return OK


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
