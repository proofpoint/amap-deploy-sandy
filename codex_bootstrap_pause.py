"""Standalone stdlib first-upgrade input capture and pause; stops nothing.

The reviewed file can run with python -I -S -c before new adapter modules are
installed. It writes only the existing instance's private feature state.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

RECORD = "bootstrap-inputs.json"
LIMIT = 1024 * 1024


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_size > LIMIT or info.st_mode & 0o022):
            raise ValueError("bootstrap input must be a bounded protected regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise ValueError("bootstrap input exceeds bound")
        return raw
    finally:
        os.close(fd)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def private_state(state):
    if not state.is_absolute():
        raise ValueError("bootstrap state must be absolute")
    for part in (state,) + tuple(state.parents):
        if not stat.S_ISDIR(part.lstat().st_mode):
            raise ValueError("bootstrap state ancestry must contain real directories")
    info = state.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("bootstrap requires the existing owned private state directory")


def inputs(state, controller=None):
    import tomllib
    private_state(state)
    raw = read(state / "controller.toml") if controller is None else controller
    doc = tomllib.loads(raw.decode())
    if doc.get("state_dir") != str(state):
        raise ValueError("controller names another state directory")
    protected = {}
    for key in ("operator_instructions", "trusted_config_file"):
        path = doc.get(key)
        if not isinstance(path, str) or not Path(path).is_absolute():
            raise ValueError("bootstrap requires explicit original protected-file references")
        protected[key] = {"path": path, "sha256": digest(read(Path(path)))}
    value = {"schema": 1, "state_dir": str(state), "controller_sha256": digest(raw),
             "snapshot": "controller-history/" + digest(raw) + ".toml", "protected": protected}
    return raw, value


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def immutable(path, raw):
    if os.path.lexists(path.parent) and not stat.S_ISDIR(path.parent.lstat().st_mode):
        raise ValueError("bootstrap evidence parent is not a real directory")
    if os.path.lexists(path):
        if read(path) != raw:
            raise ValueError("bootstrap immutable evidence differs: " + path.name)
        return
    if not path.parent.exists():
        path.parent.mkdir(mode=0o700)
        sync(path.parent.parent)
    if not stat.S_ISDIR(path.parent.lstat().st_mode):
        raise ValueError("bootstrap evidence parent is not a real directory")
    fd, temporary = tempfile.mkstemp(prefix=".bootstrap-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            os.unlink(temporary)
            temporary = None
            if read(path) != raw:
                raise ValueError("bootstrap evidence changed during placement")
        if temporary is not None:
            os.unlink(temporary)
            temporary = None
        sync(path.parent)
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)


def verify(state, controller=None):
    raw, expected = inputs(state, controller)
    recorded = json.loads(read(state / RECORD))
    history = state / "controller-history"
    if not stat.S_ISDIR(history.lstat().st_mode):
        raise ValueError("bootstrap snapshot parent is not a real directory")
    if recorded != expected or read(state / expected["snapshot"]) != raw:
        raise ValueError("bootstrap controller/protected inputs changed; retain pause and inspect")
    return expected


def pause(state, note, *, apply=False):
    if not note.strip() or len(note) > 500:
        raise ValueError("bootstrap pause requires a note of 1 to 500 characters")
    raw, record = inputs(state)
    if os.path.lexists(state / RECORD):
        verify(state)
    marker = {"schema": 1, "state": "paused", "note": note}
    if os.path.lexists(state / "adapter-pause.json") and json.loads(read(state / "adapter-pause.json")) != marker:
        raise ValueError("another pause record exists; retain it for inspection")
    if apply:
        immutable(state / record["snapshot"], raw)
        immutable(state / RECORD, encoded(record))
        verify(state)
        immutable(state / "adapter-pause.json", encoded(marker))
    return {"apply": apply, "controller_sha256": record["controller_sha256"],
            "pause": marker, "service_stopped": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=Path("/opt/sandy/feature-state/amap/codex"))
    parser.add_argument("--note", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(pause(args.state, args.note, apply=args.apply), indent=2))
        return 0
    except (OSError, ValueError) as exc:
        print("codex bootstrap pause: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
