"""The weekly job's one write choke point: every file the partition library
writes as root goes through a RootedStore, which refuses any path outside its
roots before anything is opened.

The roots, fixed when the store is made:
- `evidence_dir`: only the evidence writer's own names (partition_setup's
  EVIDENCE_NAME: the evidence and control documents, the risk record, and
  each incident's two files), never the gate record;
- the run's work directory: only its three records (`context.json`,
  `expect.json`, `outcome.json`), each created once;
- the local router's live config: exactly that path, replaced by rename with
  the existing file's owner and mode kept.

Every path is reached from `/` one component at a time, each opened with
O_NOFOLLOW | O_DIRECTORY, so a symbolic link anywhere on the way stops the
write. Files are created under a temporary name with O_EXCL and renamed into
place; directories are fsynced after each change.
"""

import json
import os
import posixpath
import stat
from typing import Any, Dict, List

import partition_incident as pi
import partition_setup as ps

#: The run directory's records, each created once by its one writer.
RUN_RECORDS = frozenset({"context.json", "expect.json", "outcome.json"})
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
#: The most any record or config read here may hold.
MAX_BYTES = 1 << 20


class Refused(ValueError):
    """A write outside the store's roots; nothing was opened."""


def _abs(p: str) -> str:
    if not isinstance(p, str) or not p.startswith("/") or posixpath.normpath(p) != p or p.startswith("//"):
        raise Refused(f"{p!r} is not an absolute, normalised path")
    return p


def open_dir(path: str) -> int:
    """A descriptor for directory `path`, reached from / without following
    any link."""
    fd = os.open("/", _DIR)
    try:
        for name in [c for c in _abs(path).split("/") if c]:
            nxt = os.open(name, _DIR, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_fd(fd: int) -> bytes:
    chunks, total = [], 0
    while total <= MAX_BYTES:
        b = os.read(fd, MAX_BYTES + 1 - total)
        if not b:
            return b"".join(chunks)
        chunks.append(b)
        total += len(b)
    raise ValueError(f"more than {MAX_BYTES} bytes")


class RootedStore(pi.Store):
    """partition_incident's Store, held to the weekly job's write roots."""

    def __init__(self, *, evidence_dir: str, run_dir: str, live_config: str):
        self.evidence_dir, self.run_dir, self.live_config = _abs(evidence_dir), _abs(run_dir), _abs(live_config)

    # Which writes are allowed, decided before anything is opened.
    def _evidence_name(self, path: str) -> str:
        if not path.startswith(self.evidence_dir.rstrip("/") + "/"):
            return ""
        return path[len(self.evidence_dir.rstrip("/")) + 1:]

    def _may_write(self, path: str) -> None:
        path = _abs(path)
        if path == self.live_config:
            return
        if posixpath.dirname(path) == self.run_dir and posixpath.basename(path) in RUN_RECORDS:
            return
        if ps.evidence_name_ok(self._evidence_name(path)):
            return
        raise Refused(f"{path} is outside the weekly job's write roots")

    def _may_mkdir(self, path: str) -> None:
        rel = self._evidence_name(_abs(path))
        if not (rel.startswith(pi.PREFIX) and ps.evidence_name_ok(f"{rel}/{pi.DETECTED}")):
            raise Refused(f"{path} is not an incident directory under {self.evidence_dir}")

    def _may_read(self, path: str) -> None:
        path = _abs(path)
        if path == self.live_config or posixpath.dirname(path) == self.run_dir or self._evidence_name(path) \
                or path in (self.evidence_dir, self.run_dir):
            return
        raise Refused(f"{path} is outside the weekly job's roots")

    # The Store's operations, each through the checks above.
    def mkdir(self, path: str) -> None:
        self._may_mkdir(path)
        dfd = open_dir(posixpath.dirname(path))
        try:
            os.mkdir(posixpath.basename(path), 0o755, dir_fd=dfd)
            os.fsync(dfd)
        finally:
            os.close(dfd)

    def new_file(self, path: str, data: bytes) -> None:
        self._may_write(path)
        record = posixpath.dirname(path) == self.run_dir
        self._replace(path, data, keep=False, exclusive=record, mode=0o400 if record else 0o444)

    def append(self, path: str, line: bytes) -> None:
        self._may_write(path)
        if posixpath.basename(path) != pi.EVENTS:
            raise Refused(f"{path}: only an incident's events are appended to")
        dfd = open_dir(posixpath.dirname(path))
        try:
            fd = os.open(posixpath.basename(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o644,
                         dir_fd=dfd)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise Refused(f"{path} is not a regular file")
                os.write(fd, line)
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            os.close(dfd)

    def read(self, path: str) -> bytes:
        self._may_read(path)
        dfd = open_dir(posixpath.dirname(path))
        try:
            fd = os.open(posixpath.basename(path), _READ, dir_fd=dfd)
        finally:
            os.close(dfd)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError(f"{path} is not a regular file")
            return _read_fd(fd)
        finally:
            os.close(fd)

    def listdir(self, path: str) -> List[str]:
        self._may_read(path)
        fd = open_dir(path)
        try:
            return os.listdir(fd)
        finally:
            os.close(fd)

    def replace_live_config(self, data: bytes) -> None:
        """The local router's live config replaced by `data`, keeping the
        existing file's owner and mode."""
        self._replace(self.live_config, data, keep=True, exclusive=False, mode=0o644)

    def _replace(self, path: str, data: bytes, *, keep: bool, exclusive: bool, mode: int) -> None:
        dfd = open_dir(posixpath.dirname(path))
        name = posixpath.basename(path)
        try:
            owner = None
            try:
                old = os.stat(name, dir_fd=dfd, follow_symlinks=False)
                if exclusive:
                    raise Refused(f"{path} exists; a run's record is created once")
                if not stat.S_ISREG(old.st_mode):
                    raise Refused(f"{path} is not a regular file")
                if keep:
                    owner, mode = (old.st_uid, old.st_gid), stat.S_IMODE(old.st_mode)
            except FileNotFoundError:
                if keep:
                    raise Refused(f"{path} does not exist; the live config is replaced, never created") from None
            tmp = f".{name}.{os.getpid()}.tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
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
        finally:
            os.close(dfd)


def strict_object(raw: bytes) -> Dict[str, Any]:
    """`raw` as one JSON object: UTF-8, no duplicate key, no non-finite
    number; ValueError otherwise. A truncated record fails here and is never
    repaired."""
    def pairs(items: List[Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k, v in items:
            if k in out:
                raise ValueError(f"duplicate key {k!r}")
            out[k] = v
        return out

    def no_constant(name: str) -> Any:
        raise ValueError(f"non-finite number {name}")
    doc = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=no_constant)
    if not isinstance(doc, dict):
        raise ValueError("not a JSON object")
    return doc


def read_bounded(path: str) -> bytes:
    """A regular file's bytes, reached from / without following any link and
    read from the descriptor it was checked on: for inputs outside the write
    roots, which are read and never written."""
    dfd = open_dir(posixpath.dirname(_abs(path)))
    try:
        fd = os.open(posixpath.basename(path), _READ, dir_fd=dfd)
    finally:
        os.close(dfd)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(f"{path} is not a regular file")
        return _read_fd(fd)
    finally:
        os.close(fd)


def without_delegation(raw: bytes) -> bytes:
    """The live config without its `delegation` member, in install's own
    serialisation; ValueError when it is not one strict JSON object."""
    doc = strict_object(raw)
    doc.pop("delegation", None)
    return (json.dumps(doc, indent=2) + "\n").encode("utf-8")
