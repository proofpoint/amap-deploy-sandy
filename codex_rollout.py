"""The rollout of a reviewed Codex connector pin, and its interactive pane, on
a host whose checkouts already sit side by side under one directory
(`AMAP_ROOT`, default ~/amap). Host-side, as the operator; standard library
only, so it runs the same on Linux and Darwin.

    AMAP_EXPECT_DS_COMMIT=<full sha> python3 amap-codex-rollout.py check
    AMAP_EXPECT_DS_COMMIT=<full sha> python3 amap-codex-rollout.py apply
    python3 amap-codex-rollout.py rollback <backup directory printed by apply>

`check` (the default) writes nothing. It refuses unless:

- this deployment's checkout is at AMAP_EXPECT_DS_COMMIT, and every tracked
  file holds exactly its committed bytes and mode, hashed against the commit
  itself so that an index flag (assume-unchanged, skip-worktree) cannot hide
  an edit;
- every sibling siblings.json names is a checkout at its pinned commit, in the
  directory siblings.json gives it, held to the same check;
- every file install will copy out of the Codex connector checkout is one of
  those committed files, so no untracked extra is deployed (untracked files
  install does not copy are left alone);
- no source override install would honour (the `override` variable
  siblings.json names for each sibling, such as AMAP_CODEX_CONNECTOR_REPO)
  points anywhere but the checkout this check holds, so install reads exactly
  what was checked;
- the sandy named by SANDY_BIN (default `sandy`) lists `agent_wrapper` in
  --print-schema's manifest.top_level_keys.

It then prints install's own dry run, run with that same sandy.

`apply` runs the same checks, then copies the feature's payload, feature.json
and router.json into a new backup directory under AMAP_ROOT/rollout-backups
and compares the copy with the
live files entry by entry (type, mode, link target and content). Only then
does it run `install --apply` and `verify`, both with the same sandy, and a
problem from either is a nonzero exit naming the backup. The backup's
inventory is written beside it as INVENTORY.json.

`rollback` compares a backup with its INVENTORY.json, moves the current
payload, feature.json and router.json aside into another new directory
(nothing is deleted), copies the backup back, and compares the restored files
with the inventory.

Backups never live in sandy's features directory: sandy reads every
directory there as a feature, and one it refuses mounts no feature at all.
Every verb refuses while a directory of this tool's backups is still there.

Every step checks its own result: a failed copy, hash, listing or command
stops the run with a nonzero exit, and no later step runs. Nothing here
fetches, moves a checkout, a branch or a tag, and nothing reads or writes a
sandbox's feature state (the supervisor's journal and claims) or a Codex home
(its authentication).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

PARTS = ("payload", "feature.json", "router.json")
INVENTORY = "INVENTORY.json"
CODEX_SIBLING = "amap-connector-codex"
# What install copies out of the Codex connector checkout, as relative path
# globs (amap_sandy.codex_payload_sources; a test holds the two equal).
CODEX_DEPLOYED = ("src/amap_codex/*.py", "bin/inbox-mcp-vol", "bin/inbox-submit", "bin/_inboxlib.py",
                  "config/operator-instructions.md")
SHA_RE = re.compile(r"[0-9a-f]{40}")
DIR_RE = re.compile(r"[A-Za-z0-9._-]+")


class Refused(Exception):
    pass


def say(line: str) -> None:
    print(line, flush=True)


def _run(argv: Sequence[str], **kw) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(list(argv), capture_output=True, **kw)
    except OSError as e:
        raise Refused(f"cannot run {argv[0]}: {e.strerror}")


def git(top: Path, *args: str) -> bytes:
    r = _run(["git", "-C", str(top), *args])
    if r.returncode != 0:
        raise Refused(f"git {' '.join(args)} failed in {top}: {r.stderr.decode(errors='replace').strip()}")
    return r.stdout


def committed(top: Path) -> Dict[str, Tuple[bytes, bytes]]:
    """Every blob HEAD tracks: path -> (mode, sha1)."""
    out = {}
    for entry in git(top, "ls-tree", "-r", "-z", "--full-tree", "HEAD").split(b"\0"):
        if not entry:
            continue
        meta, path = entry.split(b"\t", 1)
        mode, kind, sha = meta.split()
        if kind == b"blob":
            out[path.decode()] = (mode, sha)
    return out


def blob_sha(path: Path, mode: bytes) -> Optional[bytes]:
    """The git blob id of `path` as it stands, or None when it is not the kind `mode` names."""
    try:
        if mode == b"120000":
            if not path.is_symlink():
                return None
            data = os.fsencode(os.readlink(path))
        else:
            if path.is_symlink() or not path.is_file():
                return None
            if bool(path.stat().st_mode & stat.S_IXUSR) != (mode == b"100755"):
                return None
            data = path.read_bytes()
    except OSError:
        return None
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest().encode()


def exact_at(top: Path, commit: str, label: str) -> Dict[str, Tuple[bytes, bytes]]:
    if not (top / ".git").exists():
        raise Refused(f"{label}: no checkout at {top}")
    head = git(top, "rev-parse", "HEAD").decode().strip()
    if head != commit:
        raise Refused(f"{label}: {top} is at {head}, not the reviewed {commit}")
    tracked = committed(top)
    bad = [p for p, (mode, sha) in sorted(tracked.items()) if blob_sha(top / p, mode) != sha]
    if bad:
        more = f" and {len(bad) - 5} more" if len(bad) > 5 else ""
        raise Refused(f"{label}: {top} is not the committed bytes and modes: {', '.join(bad[:5])}{more}")
    say(f"  ok  {label} {top} at {commit}, every tracked file as committed")
    return tracked


def sibling_pins(ds: Path) -> List[Tuple[str, str, Optional[str]]]:
    """(directory, commit, override variable or None) for every sibling."""
    try:
        doc = json.loads((ds / "siblings.json").read_text())
        rows = [(s.get("dir", s["name"]), s["commit"], s.get("override")) for s in doc["siblings"]]
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        raise Refused(f"cannot read the sibling pins from {ds / 'siblings.json'}: {e}")
    if not rows:
        raise Refused(f"{ds / 'siblings.json'} names no sibling")
    for d, c, o in rows:
        if not isinstance(d, str) or not DIR_RE.fullmatch(d) or not isinstance(c, str) or not SHA_RE.fullmatch(c) \
                or not (o is None or isinstance(o, str)):
            raise Refused(f"{ds / 'siblings.json'}: bad sibling entry {d!r} {c!r}")
    return rows


def override_agrees(var: Optional[str], checked: Path) -> None:
    """An override install would follow names the checked checkout, or is unset."""
    value = os.environ.get(var) if var else None
    if value and Path(value).resolve() != checked.resolve():
        raise Refused(f"{var} is set to {value}, so install would read that checkout instead of the "
                      f"checked {checked}; unset it for the rollout")


def deployed_closure(top: Path, tracked: Dict[str, Tuple[bytes, bytes]]) -> None:
    """Every file install copies from the Codex checkout is a committed file."""
    found = set()
    for pattern in CODEX_DEPLOYED:
        found.update(str(p.relative_to(top)) for p in top.glob(pattern))
    extra = sorted(p for p in found if p not in tracked)
    if extra:
        raise Refused(f"{CODEX_SIBLING}: install would deploy files the reviewed commit does not hold: "
                      f"{', '.join(extra)}")
    say(f"  ok  {CODEX_SIBLING}: every deployed file is committed")


def sandy_ok(sandy: str) -> None:
    r = _run([sandy, "--print-schema"])
    try:
        keys = json.loads(r.stdout)["manifest"]["top_level_keys"] if r.returncode == 0 else None
    except (ValueError, KeyError, TypeError):
        keys = None
    if not isinstance(keys, list) or "agent_wrapper" not in keys:
        raise Refused(f"{sandy} does not list agent_wrapper in --print-schema; install the sandy that does first")
    say(f"  ok  {sandy} lists agent_wrapper")


def checks(root: Path, ds: Path, sandy: str) -> None:
    expect = os.environ.get("AMAP_EXPECT_DS_COMMIT", "")
    if not expect:
        raise Refused("set AMAP_EXPECT_DS_COMMIT to the reviewed amap-deploy-sandy commit (full sha)")
    if not SHA_RE.fullmatch(expect):
        raise Refused("AMAP_EXPECT_DS_COMMIT is not a full commit sha")
    exact_at(ds, expect, "amap-deploy-sandy")
    seen_codex = False
    for d, commit, override in sibling_pins(ds):
        tracked = exact_at(root / d, commit, d)
        override_agrees(override, root / d)
        if d == CODEX_SIBLING:
            deployed_closure(root / d, tracked)
            seen_codex = True
    if not seen_codex:
        raise Refused(f"{ds / 'siblings.json'} pins no {CODEX_SIBLING}")
    sandy_ok(sandy)


def inventory(base: Path, names: Sequence[str]) -> Dict[str, List]:
    """Every entry under each present name: relative path -> [type, mode, link target or sha256].
    A link's own mode is not recorded: it controls nothing, and platforms differ on it."""
    out: Dict[str, List] = {}

    def one(path: Path, rel: str) -> None:
        st = os.lstat(path)
        mode = stat.S_IMODE(st.st_mode)
        if stat.S_ISLNK(st.st_mode):
            out[rel] = ["l", None, os.readlink(path)]
        elif stat.S_ISDIR(st.st_mode):
            out[rel] = ["d", mode, None]
            for child in sorted(os.listdir(path)):
                one(path / child, f"{rel}/{child}")
        elif stat.S_ISREG(st.st_mode):
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for block in iter(lambda: f.read(1 << 20), b""):
                    h.update(block)
            out[rel] = ["f", mode, h.hexdigest()]
        else:
            raise Refused(f"{path} is neither a file, a directory nor a link")

    for name in names:
        if os.path.lexists(base / name):
            one(base / name, name)
    return out


def copy_entry(src: Path, dest: Path) -> None:
    """Copy one entry exactly: a link as a link (no metadata call that could
    follow it, so its target may not exist yet), a file with its mode and
    times, a directory's contents before its own mode (so a directory that is
    not writable is still filled)."""
    st = os.lstat(src)
    if stat.S_ISLNK(st.st_mode):
        os.symlink(os.readlink(src), dest)
    elif stat.S_ISDIR(st.st_mode):
        os.mkdir(dest)
        for child in sorted(os.listdir(src)):
            copy_entry(src / child, dest / child)
        os.chmod(dest, stat.S_IMODE(st.st_mode))
    elif stat.S_ISREG(st.st_mode):
        shutil.copy2(src, dest)
    else:
        raise Refused(f"{src} is neither a file, a directory nor a link")


def new_dir(path: Path) -> Path:
    try:
        path.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        raise Refused(f"{path} exists; run again in a second")
    return path


def stamp() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


BACKUPS_DIR = "rollout-backups"


def features_clear(feature: Path, backups: Path) -> None:
    """Nothing of this tool's in sandy's features directory, and no backup
    root inside it: sandy reads each directory there as a feature and, on
    one it refuses, mounts no feature in any sandbox it launches."""
    features = feature.parent
    stray = features / f"{feature.name}.{BACKUPS_DIR}"
    if os.path.lexists(stray):
        raise Refused(f"{stray} is in sandy's features directory, so sandy mounts no feature "
                      f"at launch; move its contents to {backups} and remove it")
    try:
        inside = backups.resolve().is_relative_to(features.resolve())
    except OSError as e:
        raise Refused(f"cannot resolve {backups} ({e})")
    if inside:
        raise Refused(f"{backups} is inside sandy's features directory {features}; "
                      f"set AMAP_ROOT to a directory outside it")


def backup(feature: Path, backups: Path) -> Path:
    dest = new_dir(backups / stamp())
    present = [n for n in PARTS if os.path.lexists(feature / n)]
    try:
        for name in present:
            copy_entry(feature / name, dest / name)
        live, copied = inventory(feature, present), inventory(dest, present)
    except OSError as e:
        raise Refused(f"the backup in {dest} failed ({e}); nothing was installed")
    if copied != live:
        differ = sorted(k for k in set(live) | set(copied) if live.get(k) != copied.get(k))
        raise Refused(f"the backup in {dest} does not match the live files ({', '.join(differ[:5])}); "
                      f"nothing was installed")
    tmp = dest / f".{INVENTORY}.tmp"
    tmp.write_text(json.dumps({"parts": present, "entries": live}, indent=1, sort_keys=True))
    os.replace(tmp, dest / INVENTORY)
    return dest


def deployment(ds: Path, sandy: str, *args: str) -> int:
    return subprocess.run([sys.executable, str(ds / "amap-sandy.py"), "--sandy", sandy, *args]).returncode


def rollback(feature: Path, backups: Path, b: Path) -> Path:
    try:
        doc = json.loads((b / INVENTORY).read_text())
        parts, want = list(doc["parts"]), doc["entries"]
        if not set(parts) <= set(PARTS):
            raise ValueError("unknown part")
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise Refused(f"{b} holds no readable {INVENTORY}: not a backup this tool made ({e})")
    try:
        have = inventory(b, parts)
    except OSError as e:
        raise Refused(f"{b} cannot be read ({e}); restore it by hand")
    if have != want:
        raise Refused(f"{b} does not match its {INVENTORY}; restore it by hand")
    aside = new_dir(backups / f"{stamp()}-replaced")
    try:
        for name in PARTS:
            if os.path.lexists(feature / name):
                os.rename(feature / name, aside / name)
        for name in parts:
            copy_entry(b / name, feature / name)
        restored = inventory(feature, parts)
    except OSError as e:
        raise Refused(f"the restore failed ({e}); the replaced files are in {aside}")
    if restored != want:
        raise Refused(f"the restored files do not match {b / INVENTORY}; the replaced files are in {aside}")
    return aside


def main(argv: Sequence[str]) -> int:
    mode = argv[0] if argv else "check"
    root = Path(os.environ.get("AMAP_ROOT") or Path.home() / "amap")
    ds = root / "amap-deploy-sandy"
    sandy = os.environ.get("SANDY_BIN") or "sandy"
    feature = Path(os.environ.get("SANDY_HOME") or Path.home() / ".sandy") / "features" / "amap"
    backups = root / BACKUPS_DIR
    try:
        features_clear(feature, backups)
        if mode == "check":
            checks(root, ds, sandy)
            return deployment(ds, sandy, "install")
        if mode == "apply":
            checks(root, ds, sandy)
            b = backup(feature, backups)
            say(f"  ok  backup {b}, matching the live files")
            if deployment(ds, sandy, "install", "--apply") != 0:
                raise Refused(f"install --apply failed (above); to roll back: amap-codex-rollout.py rollback {b}")
            if deployment(ds, sandy, "verify") != 0:
                raise Refused(f"verify reported problems (above) after install --apply; "
                              f"to roll back: amap-codex-rollout.py rollback {b}")
            say(f"Applied. Relaunch each Codex sandbox (its interactive pane: sandy --new). "
                f"Roll back with: amap-codex-rollout.py rollback {b}")
            return 0
        if mode == "rollback" and len(argv) == 2:
            aside = rollback(feature, backups, Path(argv[1]))
            say(f"Restored {argv[1]}; the replaced files are in {aside}. Relaunch each Codex sandbox.")
            say("The checkouts are unchanged: an install from them renders the newer payload again.")
            return 0
        raise Refused("usage: amap-codex-rollout.py check | apply | rollback BACKUP")
    except Refused as e:
        print(f"amap-codex-rollout: {e}", file=sys.stderr)
        return 1
