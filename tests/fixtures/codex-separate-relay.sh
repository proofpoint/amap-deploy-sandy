#!/bin/sh
# payload/codex/relay — shipped by amap-deploy-sandy and copied VERBATIM onto
# the feature payload. payload/relay execs it when the sandbox's agent is
# codex. Edit it HERE, then re-run install --apply; an edit to a deployed
# copy is drift.
#
# It starts the Codex connector's supervisor (amap-connector-codex,
# `amap_codex.cli run`), which drives one persistent `codex app-server`
# thread from this sandbox's AMAP notices. Like payload/relay, it is a
# constant: every value comes from sandy's exports, sandy's session file or
# the agent's own Codex configuration, and is written into a supervisor
# configuration under this entry's own state directory on every start.
#
# Two conditions HOLD the entry rather than fail it: Codex is not logged in
# yet (`sandy --login codex` starts entries too), or the image's Codex build
# is not one the connector has reviewed. Exiting would fail the launch
# inside sandy's startup window, or crash-loop after it. Instead the reason
# is written to $STATE/hold.json, which verify reports, and the entry waits.
# Every other gap is fatal, as in payload/relay: a guessed value is a wrong
# value used silently.
#
# This file and everything it execs sit behind the read-only payload mount.
set -e

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)

: "${AMAP_INBOX_DIR:?codex relay: sandy exported no AMAP_INBOX_DIR; the inbox lane is not mounted}"
: "${AMAP_OUTBOX_DIR:?codex relay: sandy exported no AMAP_OUTBOX_DIR; the outbox lane is not mounted}"
: "${AMAP_PEER_DIR:?codex relay: sandy exported no AMAP_PEER_DIR; the peer lane is not mounted}"
: "${SANDY_FEATURE_STATE:?codex relay: sandy exported no SANDY_FEATURE_STATE; this sandy predates per-entry state}"

STATE="$SANDY_FEATURE_STATE/codex"
mkdir -p "$STATE"
chmod 700 "$STATE"
HOLD="$STATE/hold.json"

# hold REASON: record why the supervisor is not running, then wait until
# CHECK (a shell command) succeeds, re-checking every 30 seconds.
hold_until() {
    reason=$1; check=$2
    while ! sh -c "$check" >/dev/null 2>&1; do
        if [ ! -f "$HOLD" ] || ! grep -qF "\"$reason\"" "$HOLD"; then
            python3 -c 'import json, sys, time; print(json.dumps({"reason": sys.argv[1], "since": int(time.time())}))' "$reason" > "$HOLD.tmp"
            mv "$HOLD.tmp" "$HOLD"
            echo "codex relay: holding: $reason" >&2
        fi
        sleep 30
    done
    rm -f "$HOLD"
}

hold_until "codex is not logged in; run sandy --login codex" "codex login status"

# Any Codex build runs; the supervisor reports whether the connector has
# reviewed it. A build that cannot state its version (a broken install)
# holds, since the supervisor checks the launched app-server against it.
export PYTHONPATH="$SELF_DIR/src"
AMAP_CODEX_BUILD='import subprocess, sys
from amap_codex.config import CODEX_VERSION
try:
    out = subprocess.run(["codex", "--version"], capture_output=True, text=True, timeout=30).stdout
except (OSError, subprocess.SubprocessError):
    out = ""
build = out.split("\n")[0].strip()
if not CODEX_VERSION.fullmatch(build):
    sys.exit(1)
print(build)'
export AMAP_CODEX_BUILD
hold_until "codex --version reports no build; the image's Codex install is broken (rebuild it)" 'python3 -c "$AMAP_CODEX_BUILD"'
CODEX_VERSION=$(python3 -c "$AMAP_CODEX_BUILD")

# The model is the one the agent's own Codex uses: `model` in its
# config.toml, as a Claude agent's model is its pane's. None there leaves the
# choice to Codex's own default, as it does for the pane. It takes effect
# when the supervisor starts.
MODEL=$(python3 -c '
import sys, tomllib
try:
    model = tomllib.load(open(sys.argv[1], "rb")).get("model")
except (OSError, ValueError):
    model = None
print(model if isinstance(model, str) else "")' "${CODEX_HOME:-$HOME/.codex}/config.toml")

SANDY_SESSION_FILE=/etc/sandy-session.json
if [ ! -r "$SANDY_SESSION_FILE" ]; then
    echo "codex relay: $SANDY_SESSION_FILE is missing or unreadable; sandy composes it before launch" >&2
    exit 1
fi
read_session() {
    python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get(sys.argv[2]) or "")' "$SANDY_SESSION_FILE" "$1"
}
sandbox_name=$(read_session sandbox_name)
: "${sandbox_name:?codex relay: $SANDY_SESSION_FILE carries no sandbox_name}"
workspace=$(read_session workspace)
: "${workspace:?codex relay: $SANDY_SESSION_FILE carries no workspace}"

# The peer lane needs the agent's own address; a fleet without a domain has
# none, and the router places no peer notices there. Mail only, then.
self_address=""
if [ -n "${AMAP_FLEET_DOMAIN+x}" ]; then
    : "${AMAP_FLEET_DOMAIN:?codex relay: AMAP_FLEET_DOMAIN is exported but empty; re-run amap-sandy.py install --apply}"
    self_address="$sandbox_name@$AMAP_FLEET_DOMAIN"
fi

# The connector's outcome directory sits in its own extension space; it
# creates the leaf, and its parent must exist.
mkdir -p "$AMAP_OUTBOX_DIR/ext/codex"
mkdir -p "$STATE/claims"

python3 - "$STATE/controller.toml" "$sandbox_name" "$self_address" "$MODEL" "$CODEX_VERSION" "$workspace" "$STATE" "$SELF_DIR" <<'PY'
import json, os, sys
path, name, address, model, version, workspace, state, payload = sys.argv[1:]
env = os.environ
q = json.dumps  # a JSON string is a valid TOML basic string
lines = [
    f"instance_id = {q(name)}",
    f"launch_argv = {q(['codex', 'app-server', '--listen', 'stdio://'])}",
    f"state_dir = {q(state)}",
    f"codex_version = {q(version)}",
    f"cwd = {q(workspace)}",
    'sandbox = "danger-full-access"',
    'approval_policy = "never"',
    f"operator_instructions = {q(payload + '/operator-instructions.md')}",
    f"trusted_config_file = {q(payload + '/mcp.toml')}",
    f"outcome_dir = {q(env['AMAP_OUTBOX_DIR'] + '/ext/codex/outcomes')}",
    "operator_kickoff_enabled = true",
]
if address:
    lines.insert(1, f"self_address = {q(address)}")
if model:
    lines.append(f"codex_model = {q(model)}")
lanes = [("mail", env["AMAP_INBOX_DIR"])]
if address:
    lanes.append(("peer", env["AMAP_PEER_DIR"]))
for lane, root in lanes:
    lines += ["", f"[lanes.{lane}]",
              f"notice_dir = {q(root + '/notices')}",
              f"message_dir = {q(root + '/messages')}",
              f"claim_path = {q(state + '/claims/' + lane + '.amap-consumer.json')}"]
tmp = path + ".tmp"
with open(tmp, "w") as f:
    f.write("\n".join(lines) + "\n")
os.chmod(tmp, 0o600)
os.replace(tmp, path)
PY

# The supervisor runs as a child, never exec'd: a supervisor that fails to
# start (an app-server that will not come up, an MCP registry that is not
# exactly the trusted one) is a hold with its exit status, retried with
# backoff, never an exit that fails the agent's launch. Its own output is
# in this entry's log. A stop request reaches it, and ends the loop.
supervisor=""
trap 'stopping=1; [ -n "$supervisor" ] && kill -TERM "$supervisor" 2>/dev/null' TERM INT
stopping=""
backoff=30
while :; do
    rm -f "$HOLD"
    python3 -m amap_codex.cli --config "$STATE/controller.toml" run &
    supervisor=$!
    rc=0
    wait "$supervisor" || rc=$?
    # A trapped signal interrupts the first wait; the second reaps the child.
    [ -n "$stopping" ] && { wait "$supervisor" 2>/dev/null || true; exit 0; }
    [ "$rc" -eq 0 ] && exit 0
    python3 -c 'import json, sys, time; print(json.dumps({"reason": sys.argv[1], "since": int(time.time())}))' \
        "codex supervisor exited $rc; its output is in /opt/sandy/feature-state/amap/supervisor.log; retrying in ${backoff}s" > "$HOLD.tmp"
    mv "$HOLD.tmp" "$HOLD"
    echo "codex relay: supervisor exited $rc; retrying in ${backoff}s" >&2
    sleep "$backoff" &
    wait $! || true
    [ -n "$stopping" ] && exit 0
    [ "$backoff" -lt 600 ] && backoff=$((backoff * 2))
done
