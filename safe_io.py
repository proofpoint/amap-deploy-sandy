"""Reading and writing the deployment's own files without following a link.

Every file `install`, `fleet-domain` and the activation verbs read or write
is reached through this module. A path is walked from a descriptor for the
physical `/`, each directory component opened relative to the one already
verified with `O_DIRECTORY | O_NOFOLLOW`, so a symbolic link at ANY
component refuses, dangling or not. Everything after the walk (the leaf's
read, a `mkdir`, the temporary file, the rename) is relative to the
verified descriptor, never a pathname reopened. A refusal names the path
and never prints a byte of the file.

A path whose real location is reached through a link (`/var` and `/tmp`
on macOS) must be given by its physical spelling.

Standard library only. `fleet_policy` keeps its own copy of the guarded
read, because another repository and the weekly job's pinned closure import
that module alone.
"""

from __future__ import annotations

import os
import secrets
import stat
from typing import List, Tuple, Union

PathLike = Union[str, "os.PathLike[str]"]

DEFAULT_BOUND = 32 * 1024 * 1024  # far past any file the deployment owns

_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_ROOT = os.O_RDONLY | os.O_DIRECTORY | _CLOEXEC
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | _CLOEXEC
_LEAF = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | _CLOEXEC
_TMP = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | _CLOEXEC


class SafeIOError(OSError):
    """A refusal. An `OSError`, so a caller's `except OSError` reports it;
    never a `FileNotFoundError`, so it is never read as absence."""


def _parts(path: PathLike) -> List[str]:
    return [p for p in os.path.abspath(path).split(os.sep) if p]


def open_dir(path: PathLike, *, create: bool = False) -> int:
    """A descriptor for directory `path`, walked from `/` with every
    component opened relative to its verified parent and without following
    a link. With `create`, a missing component is made (mode 0777 less the
    umask, as `mkdir -p` would) relative to that parent, then opened the
    same way. A missing component without `create` is `FileNotFoundError`;
    a link or a non-directory is a `SafeIOError` naming it."""
    fd = os.open("/", _ROOT)
    try:
        where = ""
        for name in _parts(path):
            where = f"{where}/{name}"
            if create:
                try:
                    os.mkdir(name, 0o777, dir_fd=fd)
                except FileExistsError:
                    pass
            try:
                nxt = os.open(name, _DIR, dir_fd=fd)
            except FileNotFoundError:
                raise FileNotFoundError(f"{where} is absent") from None
            except OSError as e:
                raise SafeIOError(f"{where} is a symlink or not a directory ({e.strerror}); "
                                  f"it is not followed, and nothing beneath it was touched") from None
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_child_dir(dfd: int, name: str, where: str) -> int:
    """Directory `name` inside verified directory `dfd`, opened without
    following a link; `where` is its path, for the refusal."""
    try:
        return os.open(name, _DIR, dir_fd=dfd)
    except FileNotFoundError:
        raise FileNotFoundError(f"{where} is absent") from None
    except OSError as e:
        raise SafeIOError(f"{where} is a symlink or not a directory ({e.strerror}); "
                          f"it is not followed") from None


def lstat_child(dfd: int, name: str) -> "os.stat_result | None":
    """`lstat` of `name` inside verified directory `dfd`; None when absent."""
    try:
        return os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def child_names(dfd: int) -> List[str]:
    """The names in verified directory `dfd`, sorted, listed through a
    duplicate of the descriptor so `dfd` itself stays usable."""
    dup = os.dup(dfd)
    try:
        return sorted(e.name for e in os.scandir(dup))
    finally:
        os.close(dup)


def _parent_fd(path: PathLike, create: bool) -> Tuple[int, str]:
    parent, name = os.path.split(os.path.abspath(path))
    if not name:
        raise SafeIOError(f"{path} names no file")
    return open_dir(parent, create=create), name


def read_leaf_stat(path: PathLike, *, bound: int = DEFAULT_BOUND) -> Tuple[bytes, os.stat_result]:
    """The bytes of regular file `path` and the `fstat` of the descriptor
    they were read from: opened relative to its verified directory, without
    following a link and without blocking, required to be a regular file
    with exactly one link, and read to at most `bound` bytes. Absent (the
    file or any directory above it) is `FileNotFoundError`."""
    dfd, name = _parent_fd(path, create=False)
    try:
        try:
            fd = os.open(name, _LEAF, dir_fd=dfd)
        except FileNotFoundError:
            raise FileNotFoundError(f"{path} is absent") from None
        except OSError as e:
            raise SafeIOError(f"{path} cannot be opened without following a link "
                              f"({e.strerror}); it is not followed") from None
    finally:
        os.close(dfd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SafeIOError(f"{path} is not a regular file")
        if st.st_nlink != 1:
            raise SafeIOError(f"{path} has {st.st_nlink} links; it must have exactly one")
        chunks, n = [], 0
        while n <= bound:
            b = os.read(fd, bound + 1 - n)
            if not b:
                break
            chunks.append(b)
            n += len(b)
        if n > bound:
            raise SafeIOError(f"{path} is larger than {bound} bytes")
        return b"".join(chunks), st
    finally:
        os.close(fd)


def read_leaf(path: PathLike, *, bound: int = DEFAULT_BOUND) -> bytes:
    """`read_leaf_stat`'s bytes."""
    return read_leaf_stat(path, bound=bound)[0]


def decode(data: bytes, path: PathLike) -> str:
    """`data` as UTF-8. A failure names the file and nothing else: the
    exception Python raises carries the offending byte and its offset, and
    the file may be a secret's."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise SafeIOError(f"{path} is not UTF-8 text") from None


def read_text(path: PathLike, *, bound: int = DEFAULT_BOUND) -> str:
    """`read_leaf`, decoded by `decode`."""
    return decode(read_leaf(path, bound=bound), path)


def write_leaf(path: PathLike, data: bytes, *, executable: bool = False) -> None:
    """Replace regular file `path` with `data`, atomically, every step
    relative to the leaf's verified directory: a link or a non-regular file
    at the leaf is refused, never replaced; the temporary file has a name no
    earlier run used and is created exclusively without following a link,
    so any object already there refuses; it is written, given its mode,
    fsynced and renamed over the leaf, and the directory fsynced. Missing
    directories are created. The mode is exactly 0755 for an executable,
    whatever the umask, and 0666 less the umask otherwise, as `write_text`
    then `chmod(0o755)` gave."""
    dfd, name = _parent_fd(path, create=True)
    try:
        try:
            st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            st = None
        if st is not None and not stat.S_ISREG(st.st_mode):
            raise SafeIOError(f"{path} is a symlink or not a regular file; it is not replaced")
        tmp = f".{name}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
        try:
            fd = os.open(tmp, _TMP, 0o600, dir_fd=dfd)
        except FileExistsError:
            raise SafeIOError(f"{path}: something already holds the temporary name {tmp}; "
                              f"nothing was written") from None
        try:
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view):]
                umask = os.umask(0)
                os.umask(umask)
                os.fchmod(fd, 0o755 if executable else 0o666 & ~umask)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        except BaseException:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except FileNotFoundError:
                pass
            raise
        os.fsync(dfd)
    finally:
        os.close(dfd)
