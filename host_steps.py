"""The root-run steps of a hop deployment's host plan, as one small program
the operator runs, so that no step follows a symbolic link. `host-setup`
prints the calls; this module is what they run. Standard library only.

  python3 host_steps.py root  PATH UID GID MODE   a root directory, created or fixed
  python3 host_steps.py sync  DIR...              fsync each directory
  python3 host_steps.py place SRC DEST            the overlay, root-owned 0444
  python3 host_steps.py marker PATH               a random root marker, root-owned 0444

Every path is walked from `/` one component at a time, each opened with
O_NOFOLLOW | O_DIRECTORY, so a symbolic link anywhere on the way, or a
non-directory where a directory belongs, stops the step with an error and
changes nothing beneath it. A step is safe to run again: an existing root
is re-owned and re-moded through its own descriptor (unless it is owned by
someone else and not empty, which stops the step), an existing marker is
kept only if it is already a root-owned 0444 regular file with one link,
and the overlay replaces its destination by rename, never by writing
through it.
"""

import os
import stat
import sys

_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
MARKER_MODE = 0o444
OVERLAY_MODE = 0o444
#: Who owns the overlay and the markers: root.
OWNER_UID, OWNER_GID = 0, 0


class StepError(Exception):
    pass


def _parts(path):
    if not path.startswith("/") or os.path.normpath(path) != path or path.startswith("//"):
        raise StepError(f"{path}: not an absolute, normalised path")
    return [p for p in path.split("/") if p]


def open_dir(path, create=None):
    """A descriptor for directory `path`, reached from / without following
    any link. With `create=(uid, gid, mode)`, the last component is made if
    absent, and owner and mode are set through its descriptor."""
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


def root(path, uid, gid, mode):
    fd = open_dir(path, create=(uid, gid, mode))
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


def place(src, dest):
    """Copy `src` to `dest` as a root-owned 0444 file: written under a fresh
    temporary name in dest's directory (O_EXCL, O_NOFOLLOW), then renamed
    over dest, so a link at dest is replaced, never written through."""
    parent, name = _split(dest)
    with open(src, "rb") as f:
        data = f.read()
    dfd = open_dir(parent)
    tmp = f".{name}.{os.getpid()}.tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
        try:
            os.write(fd, data)
            os.fchown(fd, OWNER_UID, OWNER_GID)
            os.fchmod(fd, OVERLAY_MODE)
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


def main(argv):
    try:
        if len(argv) == 5 and argv[0] == "root":
            root(argv[1], int(argv[2]), int(argv[3]), int(argv[4], 8))
        elif len(argv) >= 2 and argv[0] == "sync":
            sync(*argv[1:])
        elif len(argv) == 3 and argv[0] == "place":
            place(argv[1], argv[2])
        elif len(argv) == 2 and argv[0] == "marker":
            marker(argv[1])
        else:
            print(__doc__.split("\n\n")[1], file=sys.stderr)
            return 2
    except (StepError, OSError, ValueError) as e:
        print(f"host_steps: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
