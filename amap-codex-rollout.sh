#!/usr/bin/env bash
# amap-codex-rollout.sh — adopt a reviewed Codex connector pin, and its
# interactive pane, on a host whose checkouts already exist side by side
# under one directory (AMAP_ROOT, default ~/amap). Host-side, as the operator.
#
#   AMAP_EXPECT_DS_COMMIT=<full sha> ./amap-codex-rollout.sh check
#   AMAP_EXPECT_DS_COMMIT=<full sha> ./amap-codex-rollout.sh apply
#   ./amap-codex-rollout.sh rollback <backup directory printed by apply>
#
# check (the default) writes nothing. It refuses unless:
# - this deployment's checkout is at AMAP_EXPECT_DS_COMMIT, and every tracked
#   file in it holds exactly the committed bytes and mode (hashed against the
#   commit itself, so an index flag cannot hide an edit);
# - every sibling siblings.json names (the Codex connector included) is a
#   checkout at its pinned commit, in the directory siblings.json gives it,
#   held to the same byte check;
# - this host's sandy lists `agent_wrapper` in --print-schema's
#   manifest.top_level_keys.
# It then prints install's own dry run.
#
# apply runs the same checks, copies the feature's payload, feature.json and
# router.json into a new backup directory (cp -a: modes, links and times kept)
# with two lists: SHA256SUMS for every regular file and TREE for every entry's
# type, mode and link target. It then runs `install --apply` and `verify`, and
# exits nonzero, naming the backup, when verify reports a problem. rollback
# checks a backup against both lists, moves the current payload, feature.json
# and router.json aside into another new directory (nothing is deleted),
# restores the backup, and checks the restored tree against TREE.
#
# Nothing here fetches, moves a checkout, a branch or a tag, and nothing reads
# or writes a sandbox's feature state (the supervisor's journal and claims) or
# a Codex home (its authentication). A running Codex sandbox picks up the new
# payload when it is next launched; its interactive pane starts with
# `sandy --new`.
set -euo pipefail

MODE=${1:-check}
ROOT=${AMAP_ROOT:-$HOME/amap}
DS=$ROOT/amap-deploy-sandy
SANDY=${SANDY_BIN:-sandy}
FEATURE=${SANDY_HOME:-$HOME/.sandy}/features/amap
BACKUPS=$FEATURE.rollout-backups
PARTS=(payload feature.json router.json)

die() { echo "amap-codex-rollout: $*" >&2; exit 1; }
stamp() { date -u +%Y%m%dT%H%M%SZ; }

exact_at() {   # exact_at DIR COMMIT LABEL
    [ -d "$1/.git" ] || [ -f "$1/.git" ] || die "$3: no checkout at $1"
    local head
    head=$(git -C "$1" rev-parse HEAD) || die "$3: cannot read HEAD at $1"
    [ "$head" = "$2" ] || die "$3: $1 is at $head, not the reviewed $2"
    python3 - "$1" "$3" <<'PY' || exit 1
import hashlib, os, subprocess, sys
top, label = sys.argv[1], sys.argv[2]
out = subprocess.run(["git", "-C", top, "ls-tree", "-r", "-z", "--full-tree", "HEAD"],
                     capture_output=True, check=True).stdout
bad = []
for entry in out.split(b"\0"):
    if not entry:
        continue
    meta, path = entry.split(b"\t", 1)
    mode, kind, sha = meta.split()
    if kind != b"blob":
        continue
    full = os.path.join(os.fsencode(top), path)
    try:
        if mode == b"120000":
            data = os.readlink(full)
            same_mode = os.path.islink(full)
        else:
            if os.path.islink(full) or not os.path.isfile(full):
                raise OSError("not a regular file")
            data = open(full, "rb").read()
            same_mode = bool(os.stat(full).st_mode & 0o100) == (mode == b"100755")
    except OSError:
        bad.append(path.decode(errors="replace") + " (missing or wrong type)")
        continue
    got = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest().encode()
    if got != sha:
        bad.append(path.decode(errors="replace"))
    elif not same_mode:
        bad.append(path.decode(errors="replace") + " (mode)")
if bad:
    sys.exit("amap-codex-rollout: %s: %s is not the committed bytes: %s"
             % (label, top, ", ".join(bad[:5]) + (" and %d more" % (len(bad) - 5) if len(bad) > 5 else "")))
PY
    echo "  ok  $3 $1 at $2, every tracked file as committed"
}

checks() {
    : "${AMAP_EXPECT_DS_COMMIT:?set AMAP_EXPECT_DS_COMMIT to the reviewed amap-deploy-sandy commit (full sha)}"
    [[ $AMAP_EXPECT_DS_COMMIT =~ ^[0-9a-f]{40}$ ]] || die "AMAP_EXPECT_DS_COMMIT is not a full commit sha"
    exact_at "$DS" "$AMAP_EXPECT_DS_COMMIT" amap-deploy-sandy
    local pins dir commit
    pins=$(python3 -c '
import json, re, sys
doc = json.load(open(sys.argv[1]))
rows = []
for s in doc["siblings"]:
    d, c = s.get("dir", s["name"]), s["commit"]
    if not re.fullmatch(r"[A-Za-z0-9._-]+", d) or not re.fullmatch(r"[0-9a-f]{40}", c):
        sys.exit("bad sibling entry: %r" % (s,))
    rows.append(d + " " + c)
if not rows:
    sys.exit("siblings.json names no sibling")
print("\n".join(rows))' "$DS/siblings.json") || die "cannot read the sibling pins from $DS/siblings.json"
    [ -n "$pins" ] || die "no sibling pins read from $DS/siblings.json"
    while IFS=' ' read -r dir commit; do
        exact_at "$ROOT/$dir" "$commit" "$dir"
    done <<< "$pins"
    "$SANDY" --print-schema | python3 -c '
import json, sys
keys = json.load(sys.stdin).get("manifest", {}).get("top_level_keys")
sys.exit(0 if isinstance(keys, list) and "agent_wrapper" in keys else 1)' \
        || die "this sandy does not list agent_wrapper in --print-schema; install the sandy that does first"
    echo "  ok  sandy lists agent_wrapper"
}

tree_list() {   # tree_list DIR: every entry's type, mode and link target, sorted
    (cd "$1" && find . ! -name SHA256SUMS ! -name TREE ! -path . -printf '%y %m %p %l\n' | LC_ALL=C sort)
}

parts_list() {   # parts_list: the same list for the feature's live payload, feature.json and router.json
    local present=() f
    for f in "${PARTS[@]}"; do
        if [ -e "$FEATURE/$f" ] || [ -L "$FEATURE/$f" ]; then present+=("$f"); fi
    done
    [ "${#present[@]}" -gt 0 ] || return 0
    (cd "$FEATURE" && find "${present[@]}" -printf '%y %m ./%p %l\n' | LC_ALL=C sort)
}

backup() {
    local dest
    dest=$BACKUPS/$(stamp)
    [ ! -e "$dest" ] || die "$dest exists; run again in a second"
    mkdir -p "$dest"
    local f
    for f in "${PARTS[@]}"; do
        if [ -e "$FEATURE/$f" ] || [ -L "$FEATURE/$f" ]; then cp -a "$FEATURE/$f" "$dest/$f"; fi
    done
    (cd "$dest" && find . -type f ! -name SHA256SUMS ! -name TREE -print0 | LC_ALL=C sort -z \
        | xargs -0 -r sha256sum > SHA256SUMS)
    tree_list "$dest" > "$dest/TREE"
    [ "$(cat "$dest/TREE")" = "$(parts_list)" ] \
        || die "the backup in $dest does not match the live files (a type, mode or link differs); nothing was installed"
    echo "$dest"
}

case "$MODE" in
check)
    checks
    python3 "$DS/amap-sandy.py" install ;;
apply)
    checks
    b=$(backup)
    echo "  ok  backup $b"
    python3 "$DS/amap-sandy.py" install --apply
    if ! python3 "$DS/amap-sandy.py" verify; then
        die "verify reported problems (above) after install --apply; to roll back: $0 rollback $b"
    fi
    echo "Applied. Relaunch each Codex sandbox (its interactive pane: sandy --new). Roll back with: $0 rollback $b" ;;
rollback)
    b=${2:?rollback needs the backup directory apply printed}
    [ -f "$b/SHA256SUMS" ] && [ -f "$b/TREE" ] || die "$b holds no SHA256SUMS and TREE: not a backup this script made"
    (cd "$b" && sha256sum --quiet --strict -c SHA256SUMS) || die "$b does not match its SHA256SUMS; restore it by hand"
    [ "$(tree_list "$b")" = "$(cat "$b/TREE")" ] || die "$b does not match its TREE (a type, mode or link changed); restore it by hand"
    aside=$BACKUPS/$(stamp)-replaced
    [ ! -e "$aside" ] || die "$aside exists; run again in a second"
    mkdir -p "$aside"
    for f in "${PARTS[@]}"; do
        if [ -e "$FEATURE/$f" ] || [ -L "$FEATURE/$f" ]; then mv "$FEATURE/$f" "$aside/$f"; fi
        if [ -e "$b/$f" ] || [ -L "$b/$f" ]; then cp -a "$b/$f" "$FEATURE/$f"; fi
    done
    [ "$(parts_list)" = "$(cat "$b/TREE")" ] || die "the restored files do not match $b/TREE; the replaced ones are in $aside"
    echo "Restored $b; the replaced files are in $aside. Relaunch each Codex sandbox."
    echo "The checkouts are unchanged: an install from them renders the newer payload again." ;;
*) die "usage: $0 check|apply|rollback BACKUP" ;;
esac
