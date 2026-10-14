"""`install` refuses a connector checkout that is not at its siblings.json pin.

The payload's connector files are copied from the checkout `install` finds
(`--connector-src`, `$AMAP_CONNECTOR_REPO`, or the nearest
amap-connector-claude), at whatever that checkout's HEAD is. siblings.json
names the commit CI tested, so a checkout anywhere else deploys bytes no
test ran. Before anything is written, the checkout that holds the source
directory must have the pinned commit as its HEAD and no change to a tracked
file. Every file HEAD tracks in the source directory, and every file install
copies from it, is compared byte for byte with its HEAD blob, because an index
flag (assume-unchanged, skip-worktree) hides a change from `git status`.
Otherwise `install` and `install --apply` refuse, naming both commits.

`--allow-unpinned-connector REASON` lets an unpinned or dirty checkout
through. Every use is recorded under `--apply` as one JSON line in the
install log beside the manifest: the time, the pinned and found commits,
whether the checkout was dirty, the checkout's path and the reason as given.
The line is appended without following a symbolic link and fsynced. It
records an ATTEMPT: it is written before the install, which can still fail.
A dry run says what it would record.

install.sh puts the checkout at its pin first (amap-siblings.py --apply), so
its path passes this check unchanged.
"""

import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Sequence

import siblings

CONNECTOR = "amap-connector-claude"
OVERRIDE_FLAG = "--allow-unpinned-connector"
LOG_NAME = "install.log"


class PinRefused(Exception):
    """The connector checkout is not at its pin, and no override was given."""


@dataclass(frozen=True)
class PinCheck:
    pinned: str
    found: Optional[str]          # the checkout's HEAD, or None when it is not a git checkout
    dirty: bool
    checkout: Path
    why: str                      # empty when the checkout is at its pin and clean

    @property
    def ok(self) -> bool:
        return not self.why


def _git(args: List[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, timeout=60)


def pinned_commit(pins_path: Path = siblings.PINS_FILE) -> str:
    return next(s["commit"] for s in siblings.load_pins(pins_path) if s["name"] == CONNECTOR)


def changed_files(checkout: Path, src: Path, files: Sequence[str],
                  git: Callable[[List[str], Path], subprocess.CompletedProcess] = _git) -> List[str]:
    """The files under `src` whose bytes on disk are not their HEAD blob's:
    every file HEAD tracks there, and each of `files`, which must be one of
    them. Compared by blob id, `git hash-object --no-filters` against
    `HEAD:<path>`, so an index flag (assume-unchanged, skip-worktree) that
    hides a change from `git status` does not hide it here."""
    rel = src.resolve().relative_to(checkout.resolve())
    prefix = "" if str(rel) == "." else f"{rel.as_posix()}/"
    tree = git(["ls-tree", "-r", "--name-only", "HEAD", "--", prefix or "."], checkout)
    tracked = [n for n in tree.stdout.splitlines() if n] if tree.returncode == 0 else []
    out = [f"{prefix}{f} (not in HEAD)" for f in files if f"{prefix}{f}" not in tracked]
    for path in tracked:
        want = git(["rev-parse", f"HEAD:{path}"], checkout)
        have = git(["hash-object", "--no-filters", "--", path], checkout)
        if have.returncode != 0 or want.returncode != 0 or have.stdout.strip() != want.stdout.strip():
            out.append(path)
    if tree.returncode != 0:
        out.append(f"{prefix or '.'} (git ls-tree failed)")
    return out


def check(connector_src: Path, *, pins_path: Path = siblings.PINS_FILE, files: Sequence[str] = (),
          git: Callable[[List[str], Path], subprocess.CompletedProcess] = _git) -> PinCheck:
    """The checkout holding `connector_src` (its `bin/`) against the pin.
    `files` are the names install copies from it."""
    pinned = pinned_commit(pins_path)
    src = Path(connector_src).absolute()
    if not src.is_dir():
        return PinCheck(pinned, None, False, src, f"{src} is not a directory")
    top = git(["rev-parse", "--show-toplevel"], src)
    if top.returncode != 0 or not top.stdout.strip():
        return PinCheck(pinned, None, False, src,
                        f"{src} is not inside a git checkout, so its commit cannot be known")
    checkout = Path(top.stdout.strip())
    head = git(["rev-parse", "HEAD"], checkout)
    found = head.stdout.strip() if head.returncode == 0 else None
    status = git(["status", "--porcelain", "--untracked-files=no"], checkout)
    if status.returncode != 0:
        return PinCheck(pinned, found, False, checkout, f"git status failed in {checkout}")
    changed = changed_files(checkout, src, files, git)
    dirty = bool(status.stdout.strip()) or bool(changed)
    if found != pinned:
        return PinCheck(pinned, found, dirty, checkout,
                        f"{checkout} is at {found or 'no commit'}, not the pinned {pinned}")
    if changed:
        return PinCheck(pinned, found, dirty, checkout,
                        f"{checkout} is at the pinned {pinned} but the bytes of "
                        f"{', '.join(changed)} are not the pinned commit's (an index flag can hide "
                        f"this from git status)")
    if dirty:
        return PinCheck(pinned, found, dirty, checkout,
                        f"{checkout} is at the pinned {pinned} but has changes to tracked files")
    return PinCheck(pinned, found, dirty, checkout, "")


def guard(connector_src: Path, *, override: Optional[str], apply: bool, log_dir: Path, out=print,
          pins_path: Path = siblings.PINS_FILE, files: Sequence[str] = (), git=_git,
          now: Callable[[], float] = time.time) -> PinCheck:
    """Check the connector checkout before `install` writes anything.
    Raises PinRefused when it is not at its pin and `override` is not a
    reason; with a reason, records the use in the install log (`--apply`)
    or says it would (dry run)."""
    c = check(connector_src, pins_path=pins_path, files=files, git=git)
    if c.ok:
        out(f"  connector {c.checkout}: at its pin {c.pinned[:12]}")
        return c
    if override is None or not override.strip():
        raise PinRefused(
            f"the connector checkout is not at its siblings.json pin: {c.why}. Pinned "
            f"{c.pinned}, found {c.found or 'none'}. Put it at the pin (amap-siblings.py --apply), "
            f"or pass {OVERRIDE_FLAG} REASON to install from it anyway; that use is logged")
    record = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now())), "event": "unpinned_connector",
              "pinned": c.pinned, "found": c.found, "dirty": c.dirty, "checkout": str(c.checkout),
              "reason": override}
    log = Path(log_dir) / LOG_NAME
    out(f"  WARN  connector {c.checkout}: {c.why}; installing anyway under {OVERRIDE_FLAG} "
        f"({override!r})")
    if apply:
        log.parent.mkdir(parents=True, exist_ok=True)
        append_line(log, json.dumps(record, sort_keys=True) + "\n")
        out(f"  recorded in {log}")
    else:
        out(f"  would record in {log}: {json.dumps(record, sort_keys=True)}")
    return c


def append_line(path: Path, line: str) -> None:
    """Append one line and make it durable: never through a symbolic link at
    `path`, and fsynced before returning."""
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o644)
    try:
        data = line.encode("utf-8")
        while data:
            data = data[os.write(fd, data):]
        os.fsync(fd)
    finally:
        os.close(fd)
