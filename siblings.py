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
and is left alone. A sibling with an `opt_in` variable ($AMAP_CODEX for
the Codex connector) is put at its pin only when that variable is `1`, and
skipped otherwise. $AMAP_REPO_BASE replaces the base of every clone URL,
for a mirror.

A repository may be pinned twice. The second entry names its own checkout
directory (`dir`) and override, and says why it exists and when it goes
(`temporary`): the hop renderer's router pin, at a commit of the router's
integration branch, sits beside the main router pin until that branch
merges. Every lookup by repository name (`primary`) reads the entry
without a `dir`.

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
KEYS = ("name", "url", "commit", "override", "opt_in", "dir", "temporary")
REPO_BASE_ENV = "AMAP_REPO_BASE"


class SiblingError(Exception):
    """A sibling that cannot be put at its pin, with the reason."""


def load_pins(path: Path = PINS_FILE) -> List[Dict[str, str]]:
    """The pinned siblings, validated: a name, a clone URL, a full 40-character
    commit, the variable that overrides the checkout's location, and,
    optionally, the variable that opts in to it."""
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
        unknown = sorted(set(s) - set(KEYS))
        if unknown:
            raise SiblingError(f"{where} has unknown key(s) {unknown}")
        if "opt_in" in s and (not isinstance(s["opt_in"], str) or not s["opt_in"]):
            raise SiblingError(f"{where}: opt_in must name a variable")
        if ("dir" in s) != ("temporary" in s):
            raise SiblingError(f"{where}: dir and temporary go together: a second pin of a "
                               f"repository says where it is checked out and when it goes")
        if "dir" in s and (not isinstance(s["dir"], str) or not NAME_RE.match(s["dir"])):
            raise SiblingError(f"{where}: dir {s['dir']!r} is not a directory name")
        if "temporary" in s and (not isinstance(s["temporary"], str) or not s["temporary"].strip()):
            raise SiblingError(f"{where}: temporary must say when the pin is removed")
        out.append({k: s[k] for k in KEYS if k in s})
    if not out:
        raise SiblingError(f"{path}: no siblings listed")
    dirs = [checkout_dir(s) for s in out]
    if len(set(dirs)) != len(dirs):
        raise SiblingError(f"{path}: two siblings share a checkout directory")
    names = [s["name"] for s in out if "dir" not in s]
    if any(s["name"] not in names for s in out if "dir" in s):
        raise SiblingError(f"{path}: a second pin needs its repository's primary pin")
    overrides = [s["override"] for s in out]
    if len(set(overrides)) != len(overrides):
        raise SiblingError(f"{path}: two siblings share an override variable")
    return out


def checkout_dir(sibling: Dict[str, str]) -> str:
    """The directory the sibling is checked out into, beside the others."""
    return sibling.get("dir", sibling["name"])


def primary(pins: List[Dict[str, str]], name: str) -> Dict[str, str]:
    """The repository's main pin: the entry with no `dir`."""
    return next(s for s in pins if s["name"] == name and "dir" not in s)


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
    opt_in = sibling.get("opt_in")
    if opt_in and os.environ.get(opt_in) != "1":
        return "skip", f"optional; set {opt_in}=1 to put it at its pin"
    var = sibling["override"]
    if os.environ.get(var):
        return "skip", (f"${var} names {os.environ[var]}; that checkout is the operator's "
                        f"and is left alone")
    dest = base / checkout_dir(sibling)
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
    dest = base / checkout_dir(sibling)
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
                print(f"  {checkout_dir(s)}: {action}d {detail}" if action == "clone"
                      else f"  {checkout_dir(s)}: checked out {detail}")
            else:
                verb = {"skip": "skipped", "present": "present",
                        "clone": "would clone", "checkout": "would check out"}[action]
                print(f"  {checkout_dir(s)}: {verb} {detail}")
        except SiblingError as e:
            print(f"  {checkout_dir(s)}: REFUSED — {e}", file=sys.stderr)
            rc = 1
    return rc
