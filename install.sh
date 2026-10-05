#!/usr/bin/env bash
# install.sh — AMAP on this sandy host, in one command:
#
#   curl -fsSL https://raw.githubusercontent.com/proofpoint/amap-deploy-sandy/main/install.sh | bash
#
# It clones (or fast-forwards) amap-deploy-sandy, puts the router and the
# connector beside it at the commits pinned in its siblings.json, runs
# `amap-sandy.py install --apply`, which writes the default policy (every
# sandbox launched with claude may task every other), the payload and the
# router's config, then builds the router's image and starts it. Agents are
# started afterwards, whenever and in any order, with `sandy --start`.
#
# Safe to run again: the checkouts are brought up to date, install is
# idempotent, and a router container that already exists is left running.
#
# It needs no root and no credentials, and installs nothing outside $AMAP_DIR
# and $SANDY_HOME/features/amap (plus the router's state directory).
#
#   AMAP_DIR        where the checkouts go           (default: ~/amap)
#   SANDY_HOME      sandy's home                     (default: ~/.sandy)
#   AMAP_REPO_BASE  where the repositories come from (default: GitHub)
#   AMAP_FLEET_DOMAIN_BASE  a fresh host's fleet domain is sandy.<host>.<this>
#                   (default: internal, non-routable)
set -euo pipefail

AMAP_DIR="${AMAP_DIR:-$HOME/amap}"
SANDY_HOME="${SANDY_HOME:-$HOME/.sandy}"
AMAP_REPO_BASE="${AMAP_REPO_BASE:-https://github.com/proofpoint}"
ROUTER_CONTAINER=amap-router-local
# The checkouts are the ones under $AMAP_DIR: an override pointing elsewhere
# would install and build from a tree this script did not put at its pin.
unset AMAP_ROUTER_REPO AMAP_CONNECTOR_REPO

say() { printf '[amap] %s\n' "$*"; }
die() { printf '[amap] error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is not on PATH. $2"; }

# --- what this host needs, checked before anything is written ------------
need git "Install git, then re-run."
need python3 "Install Python 3.9 or later, then re-run."
python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' \
  || die "Python 3.9 or later is required; python3 is $(python3 -V 2>&1)."
need docker "Install Docker (Docker Desktop, Rancher Desktop, Colima or Lima), then re-run."
docker info >/dev/null 2>&1 || die "docker is installed but not answering. Start it, then re-run."
need sandy "Install sandy first: curl -fsSL https://raw.githubusercontent.com/rappdw/sandy/main/install.sh | bash"

# --- the three checkouts, side by side ------------------------------------
mkdir -p "$AMAP_DIR"
dest="$AMAP_DIR/amap-deploy-sandy"
if [ -d "$dest/.git" ]; then
  say "updating $dest"
  git -C "$dest" pull --ff-only --quiet \
    || die "$dest cannot be fast-forwarded (local changes or a diverged branch). Resolve it, then re-run."
elif [ -e "$dest" ]; then
  die "$dest exists and is not a git checkout. Move it aside, then re-run."
else
  say "cloning amap-deploy-sandy into $dest"
  git clone --quiet "$AMAP_REPO_BASE/amap-deploy-sandy.git" "$dest"
fi
say "putting the router and the connector at their pinned commits"
AMAP_REPO_BASE="$AMAP_REPO_BASE" python3 "$dest/amap-siblings.py" --apply --base "$AMAP_DIR" \
  || die "a sibling checkout could not be put at its pin; see above."

# --- the manifest, the payload, the router's config and its directories ---
say "installing the AMAP feature into $SANDY_HOME/features/amap"
SANDY_HOME="$SANDY_HOME" python3 "$AMAP_DIR/amap-deploy-sandy/amap-sandy.py" install --apply \
  ${AMAP_FLEET_DOMAIN_BASE:+--fleet-domain-base "$AMAP_FLEET_DOMAIN_BASE"}
CONFIG="$SANDY_HOME/features/amap/router.json"
[ -f "$CONFIG" ] || die "install did not write $CONFIG; see its output above."

# --- the router -------------------------------------------------------------
say "building the router image"
"$AMAP_DIR/amap-router-local/docker/build.sh" --quiet >/dev/null
if docker container inspect "$ROUTER_CONTAINER" >/dev/null 2>&1; then
  say "a router container named $ROUTER_CONTAINER already exists; it was left running."
  say "  It re-reads its config on every poll. To run the image just built:"
  say "  docker rm -f $ROUTER_CONTAINER, then re-run this script."
else
  say "starting the router"
  "$AMAP_DIR/amap-router-local/docker/run.sh" --config "$CONFIG" --detach >/dev/null
fi

cat <<EOF

[amap] Done. The router is running, and the policy lets every agent task every other.
[amap] Start agents whenever you need them, in any order:
[amap]   cd <a workspace> && sandy --start
[amap] A sandbox that was already running must be relaunched once
[amap] (sandy --stop, then sandy --start) to pick up the feature.
[amap] Check everything:  python3 $AMAP_DIR/amap-deploy-sandy/amap-sandy.py verify
[amap] Narrow the policy: edit $SANDY_HOME/features/amap/feature.json, then
[amap]   python3 $AMAP_DIR/amap-deploy-sandy/amap-sandy.py install --apply
EOF
