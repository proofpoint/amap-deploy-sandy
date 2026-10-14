"""`install` refuses a connector checkout that is not at its siblings.json pin.

The payload's connector files are copied from the checkout `install` finds
(`--connector-src`, `$AMAP_CONNECTOR_REPO`, or the nearest
amap-connector-claude), at whatever that checkout's HEAD is. siblings.json
names the commit CI tested, so a checkout anywhere else deploys bytes no
test ran. Before anything is written, the checkout that holds the source
directory must have the pinned commit as its HEAD and no change to a tracked
file. Otherwise `install` and `install --apply` refuse, naming both commits.

`--allow-unpinned-connector REASON` lets an unpinned or dirty checkout
through. Every use is recorded under `--apply` as one JSON line in the
install log beside the manifest: the time, the pinned and found commits,
whether the checkout was dirty, the checkout's path and the reason. A dry
run says what it would record.

install.sh puts the checkout at its pin first (amap-siblings.py --apply), so
its path passes this check unchanged.
"""

import json
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

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


def check(connector_src: Path, *, pins_path: Path = siblings.PINS_FILE,
          git: Callable[[List[str], Path], subprocess.CompletedProcess] = _git) -> PinCheck:
    """The checkout holding `connector_src` (its `bin/`) against the pin."""
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
    dirty = bool(status.stdout.strip())
    if found != pinned:
        return PinCheck(pinned, found, dirty, checkout,
                        f"{checkout} is at {found or 'no commit'}, not the pinned {pinned}")
    if dirty:
        return PinCheck(pinned, found, dirty, checkout,
                        f"{checkout} is at the pinned {pinned} but has changes to tracked files")
    return PinCheck(pinned, found, dirty, checkout, "")


def guard(connector_src: Path, *, override: Optional[str], apply: bool, log_dir: Path, out=print,
          pins_path: Path = siblings.PINS_FILE, git=_git,
          now: Callable[[], float] = time.time) -> PinCheck:
    """Check the connector checkout before `install` writes anything.
    Raises PinRefused when it is not at its pin and `override` is not a
    reason; with a reason, records the use in the install log (`--apply`)
    or says it would (dry run)."""
    c = check(connector_src, pins_path=pins_path, git=git)
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
              "reason": override.strip()}
    log = Path(log_dir) / LOG_NAME
    out(f"  WARN  connector {c.checkout}: {c.why}; installing anyway under {OVERRIDE_FLAG} "
        f"({override.strip()!r})")
    if apply:
        log.parent.mkdir(parents=True, exist_ok=True)
        with open(log, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")
        out(f"  recorded in {log}")
    else:
        out(f"  would record in {log}: {json.dumps(record, sort_keys=True)}")
    return c
