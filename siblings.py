"""siblings.py — put the router and connector checkouts at the commits this
repo is built and tested against.

`siblings.json` pins each sibling repository to one full commit. A host runs
what `install --apply` copies from the connector checkout, and the router
image `docker/build.sh` builds from the router checkout, so an unpinned
checkout makes a host's code depend on the day it was cloned. This step
clones each sibling beside this repository, or fetches into the checkout
already there, and checks out the pinned commit, detached. CI and the
installer run it, and so does an operator by hand.

A dry run unless `--apply`. Standard library only, and it imports nothing
that loads a sibling, because it runs before they exist. It refuses, per
sibling, a path that is not a git checkout and a checkout with uncommitted
changes to tracked files. A sibling whose override variable is set
($AMAP_ROUTER_REPO, $AMAP_CONNECTOR_REPO) is the operator's own checkout
and is left alone. $AMAP_REPO_BASE replaces the base of every clone URL,
for a mirror.

Exit 0 when every sibling is at its pin or would be put there; 1 when any
was refused or failed.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
PINS_FILE = HERE / "siblings.json"
PINS_SCHEMA = 1
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
REPO_BASE_ENV = "AMAP_REPO_BASE"


class SiblingError(Exception):
    """A sibling that cannot be put at its pin, with the reason."""


def load_pins(path: Path = PINS_FILE) -> List[Dict[str, str]]:
    """The pinned siblings, validated: a name, a clone URL, a full 40-character
    commit, and the variable that overrides the checkout's location."""
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise SiblingError(f"{path}: cannot read the pins: {e}")
    if not isinstance(doc, dict) or doc.get("schema") != PINS_SCHEMA:
        raise SiblingError(f"{path}: expected schema {PINS_SCHEMA}")
    out = []
    for i, s in enumerate(doc.get("siblings") or []):
        where = f"{path}: siblings[{i}]"
        if not isinstance(s, dict):
            raise SiblingError(f"{where} is not an object")
        for key in ("name", "url", "commit", "override"):
            if not isinstance(s.get(key), str) or not s[key]:
                raise SiblingError(f"{where} has no {key!r}")
        if not NAME_RE.match(s["name"]):
            raise SiblingError(f"{where}: name {s['name']!r} is not a directory name")
        if not COMMIT_RE.match(s["commit"]):
            raise SiblingError(f"{where}: commit {s['commit']!r} is not a full 40-character sha")
        out.append({k: s[k] for k in ("name", "url", "commit", "override")})
    if not out:
        raise SiblingError(f"{path}: no siblings listed")
    return out


def clone_url(sibling: Dict[str, str]) -> str:
    """The sibling's URL, or `$AMAP_REPO_BASE/<name>` when that is set."""
    base = os.environ.get(REPO_BASE_ENV) or ""
    return f"{base.rstrip('/')}/{sibling['name']}" if base else sibling["url"]


def _git(args: List[str], cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=str(cwd) if cwd else None,
                          capture_output=True, text=True, timeout=600)


def _head(dest: Path) -> Optional[str]:
    r = _git(["rev-parse", "HEAD"], dest)
    return r.stdout.strip() if r.returncode == 0 else None


def plan(sibling: Dict[str, str], base: Path) -> Tuple[str, str]:
    """`(action, detail)`: one of `skip` (override set), `present` (at its
    pin), `clone` or `checkout`. Raises SiblingError for a refusal."""
    var = sibling["override"]
    if os.environ.get(var):
        return "skip", (f"${var} names {os.environ[var]}; that checkout is the operator's "
                        f"and is left alone")
    dest = base / sibling["name"]
    if not dest.exists():
        return "clone", f"{clone_url(sibling)} into {dest} at {sibling['commit'][:12]}"
    if not (dest / ".git").exists():
        raise SiblingError(f"{dest} exists and is not a git checkout; move it aside, then re-run")
    head = _head(dest)
    if head == sibling["commit"]:
        return "present", f"{dest} at {head[:12]}"
    dirty = _git(["status", "--porcelain", "--untracked-files=no"], dest)
    if dirty.returncode != 0:
        raise SiblingError(f"{dest}: git status failed: {dirty.stderr.strip()}")
    if dirty.stdout.strip():
        raise SiblingError(f"{dest} has uncommitted changes; commit or stash them, then re-run")
    return "checkout", f"{dest} from {(head or 'nothing')[:12]} to {sibling['commit'][:12]}"


def apply(sibling: Dict[str, str], base: Path, action: str) -> None:
    """Carry out `plan`'s action. Raises SiblingError if git fails or the pin
    is not on the remote."""
    dest = base / sibling["name"]
    commit = sibling["commit"]
    if action == "clone":
        r = _git(["clone", "--quiet", clone_url(sibling), str(dest)])
        if r.returncode != 0:
            raise SiblingError(f"clone of {clone_url(sibling)} failed: {r.stderr.strip()}")
    if _git(["cat-file", "-e", f"{commit}^{{commit}}"], dest).returncode != 0:
        r = _git(["fetch", "--quiet", "origin"], dest)
        if r.returncode != 0:
            raise SiblingError(f"{dest}: fetch failed: {r.stderr.strip()}")
        if _git(["cat-file", "-e", f"{commit}^{{commit}}"], dest).returncode != 0:
            raise SiblingError(f"{dest}: the pinned commit {commit} is not on its remote")
    r = _git(["checkout", "--quiet", "--detach", commit], dest)
    if r.returncode != 0 or _head(dest) != commit:
        raise SiblingError(f"{dest}: checkout of {commit} failed: {r.stderr.strip()}")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="amap-siblings.py",
        description="Put the router and connector checkouts at the commits pinned in "
                    "siblings.json. A dry run unless --apply.")
    ap.add_argument("--apply", action="store_true", help="clone, fetch and check out")
    ap.add_argument("--base", default=str(HERE.parent),
                    help="the directory the siblings sit in (default: this repo's parent)")
    args = ap.parse_args(argv)
    base = Path(args.base).expanduser()
    try:
        pins = load_pins()
    except SiblingError as e:
        print(f"siblings: {e}", file=sys.stderr)
        return 1
    rc = 0
    for s in pins:
        try:
            action, detail = plan(s, base)
            if args.apply and action in ("clone", "checkout"):
                apply(s, base, action)
                print(f"  {s['name']}: {action}d {detail}" if action == "clone"
                      else f"  {s['name']}: checked out {detail}")
            else:
                verb = {"skip": "skipped", "present": "present",
                        "clone": "would clone", "checkout": "would check out"}[action]
                print(f"  {s['name']}: {verb} {detail}")
        except SiblingError as e:
            print(f"  {s['name']}: REFUSED — {e}", file=sys.stderr)
            rc = 1
    return rc
