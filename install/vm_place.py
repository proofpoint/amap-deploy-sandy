"""S6 CONFIG on one VM: place a set of files under one root in the agent account's home, each one re-hashed.

It is never a file on the VM. The runner reads these bytes from its own checkout, checks them against
install/MANIFEST, and runs them through the VM layer's launcher as `/usr/bin/python3 -I -S -c <these bytes> <root>
<exact|subset>`, as the agent account, with HOME that account's home. The set arrives on stdin:

  8 bytes   big-endian length N of the header
  N bytes   the header: UTF-8 JSON, a list of entries {"path", "mode", "size", "sha256"} in order
  then      every file entry's bytes, concatenated in header order (a directory entry has none)

An entry's path is relative to <root>, which is relative to HOME. A directory entry has mode 0o40755 or 0o40700,
size 0 and sha256 null; a file entry's mode is one of FILE_MODES. Every parent of an entry is itself an entry
earlier in the list, or <root>.

- Every directory from / down to HOME is a real directory owned by root or this account, not group- or
  other-writable unless sticky (vm_dirs' rule). <root> and its missing ancestors under HOME are made 0755; a present
  one must be a real directory owned by this account and not group- or other-writable.
- Everything is checked before anything is written. A present entry must be the same type, mode and (for a file)
  bytes, owned by this account, or the run refuses (DIFFERENT; another owner is NOT_ALLOWED). Nothing is ever repaired or replaced.
- In `exact`, <root> may hold nothing that is not an entry (EXTRA). In `subset`, other names are left alone (the
  feature root, where sandy and the router keep their own files beside the placed ones).
- A missing file is written to a temporary name in its directory, given its mode, synced and renamed into place,
  then opened again and re-hashed (READBACK). A temporary name left by an earlier run is an EXTRA in either mode.

Output: one line per entry, `PLACED <path>` or `SAME <path>`, in header order.
Exit codes: 0 done, 2 usage or a malformed set (including a sha256 the bytes do not match), 3 DIFFERENT (a present
entry of another type, mode or bytes, an EXTRA, or a leftover temporary), 4 NOT_ALLOWED (an owner, an ancestor, the
root), 5 an OS error, 6 READBACK.
"""

import hashlib
import json
import os
import re
import stat
import sys

OK, USAGE, DIFFERENT, NOT_ALLOWED, OS_ERROR, READBACK = 0, 2, 3, 4, 5, 6
MODES = ("exact", "subset")
FILE_MODES = (0o100644, 0o100755, 0o100600, 0o100444)
DIR_MODES = (0o40755, 0o40700)
ROOT_MODE = 0o755
TMP_PREFIX = ".a2-place-"
#: The whole set's bound on stdin.
MAX_BYTES = 64 * 1024 * 1024
_SEG = re.compile(r"[A-Za-z0-9_.][A-Za-z0-9._+-]*")
#: Ownership is read only through these names, so a test without root can stand other ids in.
_stat = os.stat
_fstat = os.fstat


class Stop(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _rel(p):
    if not isinstance(p, str) or not p:
        raise Stop(USAGE)
    parts = p.split("/")
    if any(not _SEG.fullmatch(s) or s in (".", "..") or s.startswith(TMP_PREFIX) for s in parts):
        raise Stop(USAGE)
    return parts


def parse(data):
    """[(parts, mode, bytes | None)] in order, or Stop(USAGE)."""
    if len(data) < 8:
        raise Stop(USAGE)
    n = int.from_bytes(data[:8], "big")
    if n > len(data) - 8:
        raise Stop(USAGE)
    try:
        head = json.loads(data[8:8 + n].decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Stop(USAGE)
    if not isinstance(head, list) or not head:
        raise Stop(USAGE)
    off, out, seen = 8 + n, [], set()
    for e in head:
        if not isinstance(e, dict) or set(e) != {"path", "mode", "size", "sha256"}:
            raise Stop(USAGE)
        parts, mode, size, digest = _rel(e["path"]), e["mode"], e["size"], e["sha256"]
        if type(mode) is not int or type(size) is not int or size < 0 or tuple(parts) in seen:
            raise Stop(USAGE)
        if len(parts) > 1 and tuple(parts[:-1]) not in seen:
            raise Stop(USAGE)
        if mode in DIR_MODES:
            if size != 0 or digest is not None:
                raise Stop(USAGE)
            body = None
        elif mode in FILE_MODES:
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise Stop(USAGE)
            body = data[off:off + size]
            off += size
            if len(body) != size or hashlib.sha256(body).hexdigest() != digest:
                raise Stop(USAGE)
        else:
            raise Stop(USAGE)
        if len(parts) > 1 and dict((tuple(p), m) for p, m, _ in out)[tuple(parts[:-1])] not in DIR_MODES:
            raise Stop(USAGE)
        seen.add(tuple(parts))
        out.append((parts, mode, body))
    if off != len(data):
        raise Stop(USAGE)
    return out


def encode(entries):
    """The runner's side: [(path, mode, bytes | None)] to the stdin bytes `parse` reads."""
    head, bodies = [], []
    for path, mode, body in entries:
        if body is None:
            head.append({"path": path, "mode": mode, "size": 0, "sha256": None})
        else:
            head.append({"path": path, "mode": mode, "size": len(body), "sha256": hashlib.sha256(body).hexdigest()})
            bodies.append(bytes(body))
    h = json.dumps(head, separators=(",", ":")).encode("utf-8")
    return len(h).to_bytes(8, "big") + h + b"".join(bodies)


def _trusted_ancestor(fd, euid):
    st = _fstat(fd)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, euid):
        raise Stop(NOT_ALLOWED)
    if st.st_mode & 0o022 and not st.st_mode & stat.S_ISVTX:
        raise Stop(NOT_ALLOWED)


def _open_home(home, euid):
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


def _own_dir(st, euid):
    return stat.S_ISDIR(st.st_mode) and st.st_uid == euid and not st.st_mode & 0o022


def _open_root(hfd, parts, euid):
    """<root>'s descriptor, its missing components made ROOT_MODE. Checks before it makes: a present component that
    breaks the rule refuses with nothing made."""
    fd, made = os.dup(hfd), False
    try:
        for part in parts:
            try:
                st = _stat(part, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                os.mkdir(part, 0o700, dir_fd=fd)
                nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.fchmod(nfd, ROOT_MODE)
                os.fsync(fd)
                os.close(fd)
                fd, made = nfd, True
                continue
            if made or not _own_dir(st, euid):
                raise Stop(NOT_ALLOWED)
            nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nfd
            if not _own_dir(_fstat(fd), euid):
                raise Stop(NOT_ALLOWED)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_at(dfd, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
    try:
        chunks = []
        while True:
            b = os.read(fd, 1 << 20)
            if not b:
                return b"".join(chunks), _fstat(fd)
            chunks.append(b)
    finally:
        os.close(fd)


def _walk_names(rfd, prefix=()):
    """Every name under <root>, as tuples of parts, never following a symlink."""
    out = []
    for name in sorted(os.listdir(rfd)):
        p = prefix + (name,)
        out.append(p)
        st = _stat(name, dir_fd=rfd, follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            sfd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=rfd)
            try:
                out += _walk_names(sfd, p)
            finally:
                os.close(sfd)
    return out


def _check(rfd, entries, euid, exact):
    """{path tuple: True} for each entry present and right; Stop on anything else. Writes nothing."""
    want = {tuple(p): (m, b) for p, m, b in entries}
    present = {}
    for p, mode, body in entries:
        parent = p[:-1]
        if parent and tuple(parent) not in present:
            continue
        dfd = os.open("/".join(parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=rfd) if parent \
            else os.dup(rfd)
        try:
            try:
                st = _stat(p[-1], dir_fd=dfd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if st.st_uid != euid:
                raise Stop(NOT_ALLOWED)
            if st.st_mode != mode:
                raise Stop(DIFFERENT)
            if body is not None:
                got, fst = _read_at(dfd, p[-1])
                if fst.st_uid != euid:
                    raise Stop(NOT_ALLOWED)
                if got != body or fst.st_mode != mode:
                    raise Stop(DIFFERENT)
            present[tuple(p)] = True
        finally:
            os.close(dfd)
    for p in _walk_names(rfd):
        if p[-1].startswith(TMP_PREFIX) or (exact and p not in want):
            raise Stop(DIFFERENT)
    return present


def place(home, root, entries, euid, exact):
    """[(path, "PLACED" | "SAME")] in entry order, or Stop."""
    hfd = _open_home(home, euid)
    try:
        rfd = _open_root(hfd, _rel(root), euid)
    finally:
        os.close(hfd)
    try:
        present = _check(rfd, entries, euid, exact)
        out = []
        for p, mode, body in entries:
            path = "/".join(p)
            if tuple(p) in present:
                out.append((path, "SAME"))
                continue
            parent = p[:-1]
            dfd = os.open("/".join(parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=rfd) if parent \
                else os.dup(rfd)
            try:
                if body is None:
                    os.mkdir(p[-1], 0o700, dir_fd=dfd)
                    fd = os.open(p[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dfd)
                    try:
                        os.fchmod(fd, stat.S_IMODE(mode))
                        if _fstat(fd).st_mode != mode:
                            raise Stop(READBACK)
                    finally:
                        os.close(fd)
                else:
                    tmp = TMP_PREFIX + p[-1]
                    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
                    try:
                        view = memoryview(body)
                        while view:
                            view = view[os.write(fd, view):]
                        os.fchmod(fd, stat.S_IMODE(mode))
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    os.rename(tmp, p[-1], src_dir_fd=dfd, dst_dir_fd=dfd)
                    got, fst = _read_at(dfd, p[-1])
                    if got != body or fst.st_mode != mode or fst.st_uid != euid:
                        raise Stop(READBACK)
                os.fsync(dfd)
            finally:
                os.close(dfd)
            out.append((path, "PLACED"))
        return out
    finally:
        os.close(rfd)


def _stdin():
    chunks, total = [], 0
    while True:
        b = os.read(0, 1 << 20)
        if not b:
            return b"".join(chunks)
        total += len(b)
        if total > MAX_BYTES:
            raise Stop(USAGE)
        chunks.append(b)


def main(argv):
    if len(argv) != 2 or argv[1] not in MODES:
        return USAGE
    try:
        _rel(argv[0])
        entries = parse(_stdin())
        rows = place(os.environ.get("HOME", ""), argv[0], entries, os.geteuid(), argv[1] == "exact")
    except Stop as e:
        return e.code
    except OSError:
        return OS_ERROR
    os.write(1, "".join("%s %s\n" % (what, path) for path, what in rows).encode())
    return OK


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
