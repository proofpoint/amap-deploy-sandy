"""Versioned Codex policy assets, retaining original-path fingerprint inputs.

This module uses only the host's standard library. Installing assets never
reads a native home, starts a connector or changes an instance configuration.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

ASSETS = ("operator-instructions.md", "mcp.toml")
LEGACY_RECORD = "legacy-protected.json"
SELECTED_RECORD = "protected-assets.json"
LIMIT = 1024 * 1024


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


def sources(policy, mcp):
    raw = {ASSETS[0]: regular(Path(policy)), ASSETS[1]: regular(Path(mcp))}
    hashes = {name: digest(value) for name, value in raw.items()}
    version = digest(encoded(hashes))
    record = {"schema": 1, "version": version, "sha256": hashes}
    return raw, record


def legacy_record(payload, raw):
    path = payload / LEGACY_RECORD
    if os.path.lexists(path):
        value = json.loads(regular(path))
        if (not isinstance(value, dict) or type(value.get("schema")) is not int or value.get("schema") != 1
                or set(value) != {"schema", "sha256"}
                or not isinstance(value["sha256"], dict)
                or set(value["sha256"]) != set(ASSETS)):
            raise AssetError("invalid legacy protected asset record")
        for name in ASSETS:
            if digest(regular(payload / name)) != value["sha256"][name]:
                raise AssetError("retained legacy protected asset differs: %s" % (payload / name))
        return value
    hashes = {}
    for name in ASSETS:
        path = payload / name
        hashes[name] = digest(regular(path) if os.path.lexists(path) else raw[name])
    return {"schema": 1, "sha256": hashes}


def install(payload, policy, mcp, *, dry_run=True):
    """Preserve legacy bytes and append immutable versions before selection.

    Preflight every existing destination before changing anything. A restart
    after a partial append reuses identical files. Selection changes only after
    the complete version and the legacy record are durable. This selection is
    an asset choice, never an instance mode or adoption receipt.
    """
    payload = Path(payload)
    directory(payload)
    raw, selected = sources(policy, mcp)
    legacy = legacy_record(payload, raw)
    version_dir = payload / "protected" / selected["version"]
    directory(version_dir)
    for name in ASSETS:
        path = version_dir / name
        if os.path.lexists(path) and regular(path) != raw[name]:
            raise AssetError("immutable protected asset differs: %s" % path)
    pointer = payload / SELECTED_RECORD
    previous = regular(pointer) if os.path.lexists(pointer) else None
    settled = (os.path.lexists(payload / LEGACY_RECORD) and previous == encoded(selected)
               and all(os.path.lexists(version_dir / name) for name in ASSETS))
    if settled:
        return "Codex protected assets present"
    if dry_run:
        return "would preserve legacy Codex assets and select protected version " + selected["version"]
    for name in ASSETS:
        if not os.path.lexists(payload / name):
            place(payload / name, raw[name])
    place(payload / LEGACY_RECORD, encoded(legacy))
    for name in ASSETS:
        place(version_dir / name, raw[name])
    if previous != encoded(selected):
        place(pointer, encoded(selected), replace=True)
    return "installed Codex protected version " + selected["version"] + " (legacy bytes retained)"


def findings(payload, policy, mcp):
    """Compare selected assets to source and retained assets to their record."""
    payload = Path(payload)
    try:
        directory(payload)
        raw, selected = sources(policy, mcp)
        if not os.path.lexists(payload / LEGACY_RECORD):
            raise AssetError("no retained legacy protected asset record")
        legacy_record(payload, raw)
        if regular(payload / SELECTED_RECORD) != encoded(selected):
            raise AssetError("selected protected asset version differs from source")
        version_dir = payload / "protected" / selected["version"]
        directory(version_dir)
        for name in ASSETS:
            if regular(version_dir / name) != raw[name]:
                raise AssetError("selected protected asset differs: %s" % (version_dir / name))
    except (OSError, ValueError) as exc:
        return ["Codex protected assets: %s" % exc]
    return []
