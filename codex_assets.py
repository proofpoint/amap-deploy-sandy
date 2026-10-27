"""Versioned Codex policy assets, retaining original-path fingerprint inputs.

This module uses only the host's standard library. Installing assets never
reads a native home, starts a connector or changes an instance configuration.

The host's install and verify (`install`, `findings`, `sources`,
`legacy_record`, `read_path`) reach every file through a directory
descriptor walked from the physical `/`, each component opened relative to
the one already verified without following a link, and act relative to the
held descriptor afterwards, never by a pathname reopened. This is
`safe_io`'s walk, kept here because this module is also copied into the
Codex payload, where `safe_io` is not. The path-based helpers (`regular`,
`directory`, `place`) serve the in-sandbox callers.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile

ASSETS = ("operator-instructions.md", "mcp.toml")
LEGACY_RECORD = "legacy-protected.json"
SELECTED_RECORD = "protected-assets.json"
LIMIT = 1024 * 1024

_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_ROOT = os.O_RDONLY | os.O_DIRECTORY | _CLOEXEC
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | _CLOEXEC
_LEAF = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | _CLOEXEC
_TMP = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | _CLOEXEC


class AssetError(ValueError):
    pass


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def regular(path):
    """Read one bounded, unlinked regular file without following its leaf."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > LIMIT:
            raise AssetError("protected asset must be a bounded regular file with one link: %s" % path)
        if info.st_mode & 0o022:
            raise AssetError("protected asset is group/world writable: %s" % path)
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise AssetError("protected asset exceeded its read bound: %s" % path)
        return raw
    finally:
        os.close(fd)


def directory(path, *, create=False):
    """Refuse symlinks in the directory chain, including the payload root."""
    path = Path(path).absolute()
    for part in reversed((path,) + tuple(path.parents)):
        try:
            info = part.lstat()
        except FileNotFoundError:
            if create:
                part.mkdir()
                sync_directory(part.parent)
            continue
        if not stat.S_ISDIR(info.st_mode):
            raise AssetError("protected asset parent must be a real directory: %s" % part)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def place(path, raw, *, replace=False, mode=0o644):
    """Durable same-directory placement; immutable files are never replaced."""
    directory(path.parent)
    if os.path.lexists(path):
        if regular(path) == raw:
            return
        if not replace:
            raise AssetError("immutable protected asset differs: %s" % path)
    directory(path.parent, create=True)
    fd, temporary = tempfile.mkstemp(prefix=".asset-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            try:
                os.link(temporary, path)
            except FileExistsError:
                # Unlink our temporary name before enforcing single-link custody.
                os.unlink(temporary)
                temporary = None
                if regular(path) != raw:
                    raise AssetError("immutable protected asset differs: %s" % path)
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)
            temporary = None
        sync_directory(path.parent)
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)


def child_dir(dfd, name, where, *, create=False):
    """Directory `name` inside verified directory `dfd`, opened without
    following a link. With `create`, a missing one is made relative to `dfd`
    and `dfd` fsynced. A missing one without `create` is FileNotFoundError."""
    if create:
        try:
            os.mkdir(name, 0o777, dir_fd=dfd)
        except FileExistsError:
            pass
        else:
            os.fsync(dfd)
    try:
        return os.open(name, _DIR, dir_fd=dfd)
    except FileNotFoundError:
        raise
    except OSError:
        raise AssetError("protected asset parent must be a real directory: %s" % where) from None


def open_dir(path, *, create=False):
    """A descriptor for directory `path`, walked from the physical `/` with
    every component opened by `child_dir` relative to its verified parent."""
    fd = os.open("/", _ROOT)
    try:
        where = ""
        for name in [part for part in os.path.abspath(path).split(os.sep) if part]:
            where = "%s/%s" % (where, name)
            nxt = child_dir(fd, name, where, create=create)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def exists_at(dfd, name):
    """Whether `name` is present inside `dfd`, a link counting as present."""
    try:
        os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def read_at(dfd, name, where):
    """`regular`'s checks and bound, for `name` opened relative to `dfd`."""
    fd = os.open(name, _LEAF, dir_fd=dfd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > LIMIT:
            raise AssetError("protected asset must be a bounded regular file with one link: %s" % where)
        if info.st_mode & 0o022:
            raise AssetError("protected asset is group/world writable: %s" % where)
        chunks, size = [], 0
        while size <= LIMIT:
            chunk = os.read(fd, LIMIT + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size > LIMIT:
            raise AssetError("protected asset exceeded its read bound: %s" % where)
        return b"".join(chunks)
    finally:
        os.close(fd)


def read_path(path):
    """`read_at` for the file at `path`, its directory walked by `open_dir`."""
    path = Path(path).absolute()
    dfd = open_dir(path.parent)
    try:
        return read_at(dfd, path.name, path)
    finally:
        os.close(dfd)


def place_at(dfd, name, raw, where, *, replace=False, mode=0o644):
    """`place`, relative to verified directory `dfd`: an existing equal file
    is kept, an immutable one that differs refuses, and the new bytes go to
    an exclusive temporary name, fsynced, then are linked (immutable) or
    renamed (replaceable) into place and `dfd` is fsynced."""
    if exists_at(dfd, name):
        if read_at(dfd, name, where) == raw:
            return
        if not replace:
            raise AssetError("immutable protected asset differs: %s" % where)
    temporary = ".asset-%d-%s" % (os.getpid(), secrets.token_hex(8))
    fd = os.open(temporary, _TMP, 0o600, dir_fd=dfd)
    try:
        try:
            view = memoryview(raw)
            while view:
                view = view[os.write(fd, view):]
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        if replace:
            os.replace(temporary, name, src_dir_fd=dfd, dst_dir_fd=dfd)
            temporary = None
        else:
            try:
                os.link(temporary, name, src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=False)
            except FileExistsError:
                # Unlink our temporary name before enforcing single-link custody.
                os.unlink(temporary, dir_fd=dfd)
                temporary = None
                if read_at(dfd, name, where) != raw:
                    raise AssetError("immutable protected asset differs: %s" % where)
            if temporary is not None:
                os.unlink(temporary, dir_fd=dfd)
                temporary = None
        os.fsync(dfd)
    finally:
        if temporary is not None and exists_at(dfd, temporary):
            os.unlink(temporary, dir_fd=dfd)


def sources(policy, mcp):
    raw = {ASSETS[0]: read_path(policy), ASSETS[1]: read_path(mcp)}
    hashes = {name: digest(value) for name, value in raw.items()}
    version = digest(encoded(hashes))
    record = {"schema": 1, "version": version, "sha256": hashes}
    return raw, record


def _legacy_at(pfd, payload, raw):
    if exists_at(pfd, LEGACY_RECORD):
        value = json.loads(read_at(pfd, LEGACY_RECORD, payload / LEGACY_RECORD))
        if (not isinstance(value, dict) or type(value.get("schema")) is not int or value.get("schema") != 1
                or set(value) != {"schema", "sha256"}
                or not isinstance(value["sha256"], dict)
                or set(value["sha256"]) != set(ASSETS)):
            raise AssetError("invalid legacy protected asset record")
        for name in ASSETS:
            if digest(read_at(pfd, name, payload / name)) != value["sha256"][name]:
                raise AssetError("retained legacy protected asset differs: %s" % (payload / name))
        return value
    hashes = {}
    for name in ASSETS:
        hashes[name] = digest(read_at(pfd, name, payload / name) if exists_at(pfd, name) else raw[name])
    return {"schema": 1, "sha256": hashes}


def legacy_record(payload, raw):
    payload = Path(payload).absolute()
    pfd = open_dir(payload)
    try:
        return _legacy_at(pfd, payload, raw)
    finally:
        os.close(pfd)


def install(payload, policy, mcp, *, dry_run=True):
    """Preserve legacy bytes and append immutable versions before selection.

    Preflight every existing destination before changing anything. A restart
    after a partial append reuses identical files. Selection changes only after
    the complete version and the legacy record are durable. This selection is
    an asset choice, never an instance mode or adoption receipt.
    """
    payload = Path(payload).absolute()
    raw, selected = sources(policy, mcp)
    would = "would preserve legacy Codex assets and select protected version " + selected["version"]
    try:
        pfd = open_dir(payload)
    except FileNotFoundError:
        if dry_run:
            return would
        pfd = open_dir(payload, create=True)
    fds = [pfd]
    try:
        legacy = _legacy_at(pfd, payload, raw)
        protected = payload / "protected"
        version_dir = protected / selected["version"]
        vfd = None
        try:
            qfd = child_dir(pfd, "protected", protected)
            fds.append(qfd)
            vfd = child_dir(qfd, selected["version"], version_dir)
            fds.append(vfd)
        except FileNotFoundError:
            pass
        for name in ASSETS:
            if vfd is not None and exists_at(vfd, name) and read_at(vfd, name, version_dir / name) != raw[name]:
                raise AssetError("immutable protected asset differs: %s" % (version_dir / name))
        previous = (read_at(pfd, SELECTED_RECORD, payload / SELECTED_RECORD)
                    if exists_at(pfd, SELECTED_RECORD) else None)
        settled = (exists_at(pfd, LEGACY_RECORD) and previous == encoded(selected)
                   and vfd is not None and all(exists_at(vfd, name) for name in ASSETS))
        if settled:
            return "Codex protected assets present"
        if dry_run:
            return would
        for name in ASSETS:
            if not exists_at(pfd, name):
                place_at(pfd, name, raw[name], payload / name)
        place_at(pfd, LEGACY_RECORD, encoded(legacy), payload / LEGACY_RECORD)
        if vfd is None:
            qfd = child_dir(pfd, "protected", protected, create=True)
            fds.append(qfd)
            vfd = child_dir(qfd, selected["version"], version_dir, create=True)
            fds.append(vfd)
        for name in ASSETS:
            place_at(vfd, name, raw[name], version_dir / name)
        if previous != encoded(selected):
            place_at(pfd, SELECTED_RECORD, encoded(selected), payload / SELECTED_RECORD, replace=True)
        return "installed Codex protected version " + selected["version"] + " (legacy bytes retained)"
    finally:
        for fd in reversed(fds):
            os.close(fd)


def findings(payload, policy, mcp):
    """Compare selected assets to source and retained assets to their record."""
    payload = Path(payload).absolute()
    fds = []
    try:
        raw, selected = sources(policy, mcp)
        try:
            pfd = open_dir(payload)
        except FileNotFoundError:
            raise AssetError("no retained legacy protected asset record") from None
        fds.append(pfd)
        if not exists_at(pfd, LEGACY_RECORD):
            raise AssetError("no retained legacy protected asset record")
        _legacy_at(pfd, payload, raw)
        if read_at(pfd, SELECTED_RECORD, payload / SELECTED_RECORD) != encoded(selected):
            raise AssetError("selected protected asset version differs from source")
        version_dir = payload / "protected" / selected["version"]
        qfd = child_dir(pfd, "protected", payload / "protected")
        fds.append(qfd)
        vfd = child_dir(qfd, selected["version"], version_dir)
        fds.append(vfd)
        for name in ASSETS:
            if read_at(vfd, name, version_dir / name) != raw[name]:
                raise AssetError("selected protected asset differs: %s" % (version_dir / name))
    except (OSError, ValueError, RuntimeError) as exc:
        return ["Codex protected assets: %s" % exc]
    finally:
        for fd in reversed(fds):
            os.close(fd)
    return []
