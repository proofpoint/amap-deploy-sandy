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
# - this deployment's checkout is at AMAP_EXPECT_DS_COMMIT, with no tracked
#   change;
# - every sibling siblings.json names (the Codex connector included) is a
#   checkout at its pinned commit beside it, with no tracked change;
# - this host's sandy lists `agent_wrapper` in --print-schema's
#   manifest.top_level_keys.
# It then prints install's own dry run.
#
# apply runs the same checks, copies the feature's payload, feature.json and
# router.json into a new backup directory with a sha256 list, then runs
# `install --apply` and `verify`. rollback checks a backup against its list,
# moves the current payload, feature.json and router.json aside into another
# new directory (nothing is deleted), and restores the backup.
#
# Nothing here moves a checkout, a branch or a tag, and nothing reads or
# writes a sandbox's feature state (the supervisor's journal and claims) or a
# Codex home (its authentication). A running Codex sandbox picks up the new
# payload when it is next launched; its interactive pane starts with
# `sandy --new`.
set -euo pipefail

MODE=${1:-check}
ROOT=${AMAP_ROOT:-$HOME/amap}
DS=$ROOT/amap-deploy-sandy
SANDY=${SANDY_BIN:-sandy}
FEATURE=${SANDY_HOME:-$HOME/.sandy}/features/amap
BACKUPS=$FEATURE.rollout-backups

die() { echo "amap-codex-rollout: $*" >&2; exit 1; }
stamp() { date -u +%Y%m%dT%H%M%SZ; }

clean_at() {   # clean_at DIR COMMIT LABEL
    [ -d "$1/.git" ] || [ -f "$1/.git" ] || die "$3: no checkout at $1"
    local head
    head=$(git -C "$1" rev-parse HEAD) || die "$3: cannot read HEAD at $1"
    [ "$head" = "$2" ] || die "$3: $1 is at $head, not the reviewed $2"
    [ -z "$(git -C "$1" status --porcelain --untracked-files=no)" ] \
        || die "$3: $1 has tracked changes; commit or set them aside before a rollout"
    echo "  ok  $3 $1 at $2, clean"
}

checks() {
    : "${AMAP_EXPECT_DS_COMMIT:?set AMAP_EXPECT_DS_COMMIT to the reviewed amap-deploy-sandy commit (full sha)}"
    [[ $AMAP_EXPECT_DS_COMMIT =~ ^[0-9a-f]{40}$ ]] || die "AMAP_EXPECT_DS_COMMIT is not a full commit sha"
    clean_at "$DS" "$AMAP_EXPECT_DS_COMMIT" amap-deploy-sandy
    local name commit
    while IFS=' ' read -r name commit; do
        clean_at "$ROOT/$name" "$commit" "$name"
    done < <(python3 -c '
import json, sys
for s in json.load(open(sys.argv[1]))["siblings"]:
    print(s["name"], s["commit"])' "$DS/siblings.json")
    "$SANDY" --print-schema | python3 -c '
import json, sys
keys = json.load(sys.stdin).get("manifest", {}).get("top_level_keys")
sys.exit(0 if isinstance(keys, list) and "agent_wrapper" in keys else 1)' \
        || die "this sandy does not list agent_wrapper in --print-schema; install the sandy that does first"
    echo "  ok  sandy lists agent_wrapper"
}

backup() {
    local dest=$BACKUPS/$(stamp)
    [ ! -e "$dest" ] || die "$dest exists; run again in a second"
    mkdir -p "$dest"
    local f
    for f in payload feature.json router.json; do
        [ -e "$FEATURE/$f" ] && cp -a "$FEATURE/$f" "$dest/$f"
    done
    (cd "$dest" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
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
    python3 "$DS/amap-sandy.py" verify || echo "amap-codex-rollout: verify reported problems (above); the backup to roll back to is $b" >&2
    echo "Applied. Relaunch each Codex sandbox (its interactive pane: sandy --new). Roll back with: $0 rollback $b" ;;
rollback)
    b=${2:?rollback needs the backup directory apply printed}
    [ -f "$b/SHA256SUMS" ] || die "$b holds no SHA256SUMS: not a backup this script made"
    (cd "$b" && sha256sum --quiet -c SHA256SUMS) || die "$b does not match its SHA256SUMS; restore it by hand"
    aside=$BACKUPS/$(stamp)-replaced
    [ ! -e "$aside" ] || die "$aside exists; run again in a second"
    mkdir -p "$aside"
    for f in payload feature.json router.json; do
        [ -e "$FEATURE/$f" ] && mv "$FEATURE/$f" "$aside/$f"
        [ -e "$b/$f" ] && cp -a "$b/$f" "$FEATURE/$f"
    done
    echo "Restored $b; the replaced files are in $aside. Relaunch each Codex sandbox."
    echo "The checkouts are unchanged: an install from them renders the newer payload again." ;;
*) die "usage: $0 check|apply|rollback BACKUP" ;;
esac
