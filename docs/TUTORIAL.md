# AMAP on sandy: the runbook

This is the hands-on half. It sets up two Claude Code agents, each in its own
sandy sandbox, sends a real delegation between them through amap-router-local,
and then breaks each guarantee on purpose so you can see where it is enforced.

**New to AMAP?** Start with the [explainer](https://proofpoint.github.io/amap-deploy-sandy/), which covers what the
protocol guarantees, why agents run isolated, and how the pieces fit, with
animated flows. This page assumes that background and sticks to commands.

1. [What you need](#1-what-you-need)
2. [Get the pieces](#2-get-the-pieces)
3. [Make two workspaces](#3-make-two-workspaces)
4. [Install](#4-install)
5. [Start the router, then the agents](#5-start-the-router-then-the-agents)
6. [Verify](#6-verify)
7. [Send your first delegation](#7-send-your-first-delegation)
8. [Break it on purpose](#8-break-it-on-purpose)

## 1. What you need

- macOS or Linux, with Docker (Docker Desktop, Rancher Desktop, Colima or
  Lima)
- Python 3.9 or later, and `jq`
- a Claude account that sandy can use (see sandy's README)
- **sandy 2.2.0 or later**. Install it and check the host:

```sh
curl -fsSL https://raw.githubusercontent.com/rappdw/sandy/main/install.sh | bash
curl -fsSL https://raw.githubusercontent.com/rappdw/sandy/main/doctor.sh | bash
sandy --print-schema | jq '.schema_version'   # must print 3 or 4
```

## 2. Get the pieces

Clone amap-deploy-sandy, then put the router and the connector beside it, at
the commits this repo is tested against:

```sh
mkdir -p ~/amap && cd ~/amap
git clone https://github.com/proofpoint/amap-deploy-sandy
python3 amap-deploy-sandy/amap-siblings.py --apply
```

`amap-siblings.py` clones `amap-router-local` and `amap-connector-claude`
into `~/amap` and checks out the commits pinned in `siblings.json`. Run it
without `--apply` to see what it would do. It refuses a checkout with
uncommitted changes. `amap-deploy-sandy` finds the other two by looking
beside itself; `$AMAP_ROUTER_REPO` and `$AMAP_CONNECTOR_REPO` override that,
and `amap-siblings.py` leaves an overridden checkout alone. You do not build
the connector: `install` copies its binaries onto the read-only payload.

**Or, in one command:**

```sh
curl -fsSL https://raw.githubusercontent.com/proofpoint/amap-deploy-sandy/main/install.sh | bash
```

This clones (or updates) the three repos side by side in `~/amap`, with the
router and the connector at their pinned commits, runs
step 4's `install --apply`, and builds and starts the router: the first half
of step 5. Then make your workspaces (step 3), start agents as in the second
half of step 5, and verify (step 6). It is safe to run again: it leaves a
running router alone and starts a stopped one. It never changes an existing
host's fleet domain. When that domain differs from the one this host would
derive, it says so; `AMAP_MOVE_FLEET_DOMAIN=1` moves it (then relaunch every
agent). `AMAP_DIR` and `SANDY_HOME` override where it puts things.

## 3. Make two workspaces

```sh
mkdir -p ~/amap-demo/alpha ~/amap-demo/beta
```

That is all for now. Sandy creates a workspace's sandbox at its **first
launch** (step 5) and names it with the **slug**, which looks like
`alpha-1a2b3c4d`. The slug is also the agent's name to the router and the
local part of its address. Never create a sandbox directory by hand.

Launch only after step 4 has written the manifest. Sandy decides at each
launch whether the feature selects a sandbox, against the manifest on disk,
so a sandbox launched before step 4 has to be relaunched (`sandy --stop`,
then `sandy --start`) to join.

## 4. Install

```sh
cd ~/amap/amap-deploy-sandy
python3 amap-sandy.py install --apply
```

Every verb is a dry run without `--apply`, so drop it to preview. On a fresh
host this writes the manifest at `~/.sandy/features/amap/feature.json` from
a template that **works as written**, installs the payload beside it,
renders the router's config, and creates the empty directories the router
mounts.

The manifest *is* the policy. Its `feature` section, as the template writes
it:

```json
"feature": {
  "version": 1,
  "groups": {},
  "default_peers": [],
  "peers": {},
  "task_graph": "ALL",
  "task_deny": [],
  "fleet_domain": "sandy.<this host>.internal",
  "container_recreate_interval_hours": 24
}
```

- **`task_graph: "ALL"`** lets every selected agent task every other. The
  directed form, `{"<recipient>": ["<sender>", ...]}`, appears in step 8.
- **`default_peers`, `peers` and `groups` are empty:** they are the mail
  lane, and an ordered pair may not appear on both lanes.
- **`fleet_domain`** is the right-hand side of every address, and names this
  host's router: `<slug>@sandy.<this host>.internal`. `install` derives it
  from the host's short name, once, so two hosts never share one. It is a
  name, not a real domain: `.internal` is reserved for private use, which is
  allowed for a fleet on one host. Routing between hosts or runtimes is
  mail, so for that pass a base you control:
  `install --apply --fleet-domain-base <your domain>` on a fresh host, or
  `fleet-domain --base <your domain> --apply` to move an existing one (every
  address changes, so relaunch the agents after).
- **`container_recreate_interval_hours`** is how often the agent containers
  are rebuilt, once you load the job `python3 amap-sandy.py cadence` prints.
- The top-level **`sandboxes`/`agents`** blocks are the selection rule: every
  sandbox launched with claude, none excluded.

**To narrow it**, edit the file in place and run `install --apply` again. Add
a glob to `sandboxes.exclude` to keep a sandbox out, or replace `"ALL"` with
explicit edges. A policy that names slugs (explicit `task_graph` edges,
`peers` or `groups`) needs those sandboxes to exist first, because `install`
refuses a slug sandy does not report: start them once, edit, install, and
relaunch them. `examples/feature.json` is a complete edited manifest.

## 5. Start the router, then the agents

```sh
cd ~/amap/amap-router-local
docker/build.sh
docker/run.sh --config ~/.sandy/features/amap/router.json \
  --detach
```

The router needs no agent to be running. Its container has no network, and
its mounts are computed from its config. It re-reads the config and looks
for new agents on every poll, so later policy changes need only
`install --apply`, and an agent launched later is picked up with no restart.

```sh
cd ~/amap-demo/alpha && sandy --start
cd ~/amap-demo/beta  && sandy --start
```

Start agents whenever you need them, in any order. The first `--start` in a
workspace creates its sandbox. At each launch sandy evaluates the selection
rule, creates the agent's lanes under
`~/.sandy/features/amap/instances/<slug>/`, mounts the payload read-only at
`/opt/sandy/features/amap`, starts the relay, and passes Claude Code its MCP
config and its system-prompt policy. Agents can delegate to each other as
they come online.

**Starting the router is the approval.** Its first poll of each agent is
*first sight*: it snapshots that agent's outbox, and never delivers anything
staged before then. With the router already running, that is a few seconds
after the agent's launch, before it has anything to say. Keep the router's
state directory on persistent storage, because a fresh one is a fresh first
sight.

## 6. Verify

```sh
cd ~/amap/amap-deploy-sandy
python3 amap-sandy.py list     # both: selected
python3 amap-sandy.py verify   # exit 0 before going on
```

`verify` checks the manifest against the policy, the payload byte for byte,
each agent's lanes, relay and mounts, and last the router's container and
health. Every check is PASS, FAIL or **UNKNOWN**, and UNKNOWN counts as a
problem: it exits 1. Continue once it exits 0.

## 7. Send your first delegation

Attach to both agents, in two terminals:

```sh
cd ~/amap-demo/alpha && sandy --attach   # terminal 1
cd ~/amap-demo/beta  && sandy --attach   # terminal 2: watch it arrive
```

Ask alpha, in plain words:

> Ask beta to list the files in its workspace and report back.

Alpha needs no more than that. The policy text in its system prompt tells it
that the fleet roster is at `$AMAP_ROSTER_DIR/roster.json`, that addresses
are `<slug>@<domain>`, and that `inbox-submit`'s `submit` is how to ask. If
two workspaces share a name, it may need the slug.

Alpha finds beta in the roster and calls `submit`, which writes an inert
request into its outbox. The router checks its graph, binds the sender to
alpha's outbox, and places a notice in beta's read-only peer lane. beta's
`inbox-delivery` injects the request into beta's session, where it arrives as
a turn from the runtime-asserted sender. beta replies with `submit`; the
router binds the reply to alpha, and it arrives in alpha's session the same
way. Alpha can check the router's verdict with `submit_result`.

A delegation that is **delivered and answered** is the only proof that the
whole chain works. A started relay proves only that the daemon runs.

## 8. Break it on purpose

Each experiment breaks one property and shows you where it is enforced. None
of them damages the setup.

### The agent cannot rewrite its own tools

Open a shell in alpha's sandbox and try to change the relay:

```sh
cd ~/amap-demo/alpha && sandy --exec
touch /opt/sandy/features/amap/relay
```

The write fails with **`Read-only file system`** (`EROFS`), even though you
own the file. The same holds for the connector's binaries, the MCP config and
the policy text, and for the inbound lanes under `$AMAP_INBOX_DIR` and
`$AMAP_PEER_DIR`. Only `$AMAP_OUTBOX_DIR` is writable, and anything written
there is just a request.

### A delegation edge is directed

Change the policy so that only alpha may task beta. In the `feature` section,
using the two slugs:

```json
"task_graph": { "<beta-slug>": ["<alpha-slug>"] }
```

Run `python3 amap-sandy.py install --apply`; no restart is needed. Now ask
**beta** to start a new task for alpha, rather than reply to one. The
connector writes the request, because it holds no allowlist. The **router**
does not deliver it: beta was never granted that edge, and `submit_result`
reports the router's decision. A reply is different: a reply to a delegation
from alpha still reaches alpha, because a reply is bound to the sender.

Put `"task_graph": "ALL"` back when you are done.

### Nothing an agent does can select it

The selection rule matches the slug sandy reports, and nothing read from
inside the workspace. A repository cannot add itself to the fleet, and an
agent cannot write `~/.sandy/features/amap/` at all. To take beta out, add
its slug to `sandboxes.exclude` in the manifest, run `install --apply`, and
relaunch beta: sandy drops it from `selected.json` at that launch.

### "Could not tell" is not "fine"

```sh
docker stop amap-router-local
python3 amap-sandy.py verify; echo "exit $?"
```

The router checks report the container as not running, the health checks
report **UNKNOWN** with the reason, and `verify` exits 1. No check rounds a
question it could not answer up to a pass. Start the router again with the
`docker/run.sh` command from step 5.

## 9. Add a Codex agent

A sandbox launched with **codex** as its only agent is served by the Codex
connector (`amap-connector-codex`). Its supervisor runs inside the sandbox,
as this feature's entry, and drives one persistent Codex thread from the
sandbox's AMAP notices. The thread is separate from the Codex pane you type
in; you give it work with `kickoff` below.

**Get the connector.** It is an optional sibling: run the installer with
`AMAP_CODEX=1` (your git must be able to reach the repository), or put a
checkout beside this one and pass nothing.

```sh
curl -fsSL https://raw.githubusercontent.com/proofpoint/amap-deploy-sandy/main/install.sh | AMAP_CODEX=1 bash
```

**Select Codex sandboxes.** In `$SANDY_HOME/features/amap/feature.json`, add
`"codex"` to `agents.include`:

```json
"agents": {"include": ["claude", "codex"], "exclude": []},
```

Then `python3 amap-sandy.py install --apply`.

**Make a Codex workspace.** Sandy reads the agent from the workspace's
config, which holds through restarts:

```sh
mkdir -p ~/amap-demo/gamma/.sandy
echo SANDY_AGENT=codex > ~/amap-demo/gamma/.sandy/config
cd ~/amap-demo/gamma && sandy --start
```

Log Codex in inside the sandbox if it is not already. Until it is, the
supervisor waits, and `verify` reports it as holding with the reason. Any
Codex build runs; `verify` notes one the connector has not reviewed.

The default separate supervisor uses `model` in the native
`CODEX_HOME/config.toml` (normally `~/.codex/config.toml`), then Codex's default.
`CODEX_MODEL` reaches the pane without changing that separate-supervisor
selection. The policy and manifest carry no model. A separate supervisor picks
up native config changes when its entry next renders.

Explicit unified preparation and entry propose sharing the pane selection:
nonempty `CODEX_MODEL` first, then the native config model, then Codex's default.
This is an explicit operator decision for review: `CODEX_MODEL`, when nonempty,
overrides the native config model for the unified supervisor. It does not change
default separate mode. The forwarding contract rests on Sandy source excerpts,
not a measurement of the current host. An established unified instance holds
conflicting settings for an explicit transition.

**Talk to Codex yourself.** Where your sandy lists `agent_wrapper` in
`sandy --print-schema`'s `manifest.top_level_keys`, `install` renders
`"agent_wrapper": {"codex": "payload/codex/interactive-launch"}`, and a Codex
pane starts through the connector's `interactive`. That pane is a NEW
conversation with the AMAP tools (`inbox_submit.peers` finds fleet peers,
`submit` sends, `amap_fleet.activity` shows the supervisor). It is separate
from the supervisor's thread, which still owns everything incoming. Launch it
fresh, because a resumed or forked session is refused:

```sh
cd ~/amap-demo/gamma && sandy --new
```

The pane waits up to `AMAP_CODEX_LAUNCH_WAIT_SECONDS` (60) for the supervisor
to be ready (a fresh heartbeat, a bound thread, live lane claims, nothing
uncertain, no hold), and otherwise shows why and does not start Codex. Watch
the supervisor beside it, from a second terminal:

```sh
sandy --exec --workspace ~/amap-demo/gamma -- /opt/sandy/features/amap/codex/activity
```

Confirm the pane was wrapped (`{}` means this launch was not, `null` that the
sandbox's marker predates the field):

```sh
sandy --print-state | jq -e '.sandboxes[] | select(.workspace_path=="'"$HOME"'/amap-demo/gamma") | .agent_wrappers.codex.feature == "amap"'
```

**Verify.** `python3 amap-sandy.py verify` checks the Codex sandbox through
the supervisor's own status: both lanes claimed, a thread bound, nothing
UNCERTAIN, no hold.

**Delegate from Codex.** Give the supervisor's thread a task, from the
workspace, with a run id of your choosing (a repeated one is refused, never
sent twice):

```sh
cd ~/amap-demo/gamma && sandy --exec -- /opt/sandy/features/amap/codex/kickoff R1 'Ask <alpha address> to list the files in its workspace, and report the reply.'
```

The thread submits the delegation and finishes its turn. alpha's reply
arrives as a later turn on the same thread. **Delegate to Codex** the same
way as to any agent: ask alpha to task gamma's address.

### Experimental unified conversation: existing-instance transition

The Codex pin names merged connector main commit
`e10eb2cf22a1056d1506938ef0669bfde582ff75`. Before end-to-end execution,
require the approved deployment commit for the host's line, full exact-pin
suite and canary evidence, the operator's unified-model precedence decision,
and actual-host acceptance of the paused-restart procedure below.
The default remains separate. Installing new payload files selects no instance
for unified mode. No command here merges two saved conversations.

Use the deployment checkout under the existing `AMAP_ROOT` (normally `~/amap`),
on the approved adapter commit for the host's line. The development base is
`7c4b766fcb9947fe39fc2c78b9a58ff43a55207c`; the deployed release branch
`release/amap-2026-10-10` starts at
`8346e9d7beb030bff5a7fd1b8f52830f77e3a972`. These are bases, not the unified
installation commits. No Git tag is assumed. Keep the router and Claude pins
on that line. The Codex pin must name the corrected, independently reviewed
source reachable from its forge; the supplied experimental source is not a
deployment approval.

Before installation, retain a verified copy of the entire feature payload,
feature manifest and router configuration, and separately preserve each selected
instance's entry state and native Codex home. Preserve permissions, original
paths, the delivery journal and native history; do not copy credentials into
reports or source control. Do not run an ordinary rollout rollback after any
instance has a transition record. The rollout tool and this transition are
separate operations.

Set `WORKSPACE` to one existing absolute workspace path and `THREAD` to the
explicit saved native UUID the operator selected. Inspect unresolved AMAP and
operator work before stopping anything. Select one history, retaining the other.
Resolve unfinished delivery/publication through its existing audited workflow.
Do not infer completion from queue admission, a smaller queue, or a submit
receipt.

The installation order is: preserve existing inputs; quiesce the service and
native clients; install reviewed code without restarting the entry; prepare;
adopt; confirm; explicitly release the pause; attach and verify. The installer
retains `codex/operator-instructions.md` and `codex/mcp.toml` byte for byte at
their original paths, records their hashes in `legacy-protected.json`, and
appends immutable files under `codex/protected/<content-sha256>/`. It refuses
later changes to recorded legacy bytes or an existing immutable version.
Before each separate-mode entry replaces a controller, it durably retains its
exact bytes at `controller-history/<content-sha256>.toml` in the private state.
These snapshots preserve the original protected-file references; no snapshot is
automatically selected or restored for adoption.

For a separate instance already running the pause-aware adapter, its pause
command can replace the bootstrap pause below. It stops no process; the first
command is a dry run:

```sh
sandy --exec --workspace "$WORKSPACE" -- python3 /opt/sandy/features/amap/codex/transition pause --note 'Operator selected stopped-service maintenance'
sandy --exec --workspace "$WORKSPACE" -- python3 /opt/sandy/features/amap/codex/transition pause --note 'Operator selected stopped-service maintenance' --apply
```

**First-upgrade candidate, source-supported; host acceptance OWED.** Maintenance
can use a new paused environment rather than keep the old environment running.
Before stopping the old environment, capture its controller and original
protected inputs and persist a pause using the reviewed standalone stdlib writer.
It requires no new adapter imports and stops nothing. Its private immutable
`bootstrap-inputs.json` records controller/protected hashes, and preparation
compares them again before changing the controller. A re-render race or changed
protected file refuses, even if the connector fingerprint happens to be equal.

The supplied launcher excerpts preserve command arguments and stdin and leave
the interactive pane shell waiting after wrapper refusal. These are source
facts; current-host custody, old-container absence and held restart remain
operator acceptance. Run the candidate from the reviewed adapter checkout,
with the existing absolute `WORKSPACE`:

```sh
(
  set -e
  BOOTSTRAP_SHA256=b48b6f9222937f5c2da3b220bf08e7fdb19401d5ed7939474e525dd4b84b63d6
  BOOTSTRAP_STATE=/opt/sandy/feature-state/amap/codex
  BOOTSTRAP_SOURCE=$(
    python3 -I -S - "$BOOTSTRAP_SHA256" <<'PY'
import hashlib, pathlib, sys
raw = pathlib.Path("codex_bootstrap_pause.py").read_bytes()
if not raw or hashlib.sha256(raw).hexdigest() != sys.argv[1]:
    sys.exit("HOLD: bootstrap source is empty or differs from the reviewed bytes")
sys.stdout.write(raw.decode("utf-8"))
PY
  ) || { echo 'HOLD: bootstrap source capture failed' >&2; exit 1; }
  : "${BOOTSTRAP_SOURCE:?HOLD: bootstrap source is empty}"
  sandy --exec --workspace "$WORKSPACE" -- python3 -I -S -c "$BOOTSTRAP_SOURCE" --state "$BOOTSTRAP_STATE" --note 'Operator selected stopped-service maintenance'
  sandy --exec --workspace "$WORKSPACE" -- python3 -I -S -c "$BOOTSTRAP_SOURCE" --state "$BOOTSTRAP_STATE" --note 'Operator selected stopped-service maintenance' --apply
  sandy --exec --workspace "$WORKSPACE" -- python3 -I -S -c "$BOOTSTRAP_SOURCE" --state "$BOOTSTRAP_STATE" --note 'Operator selected stopped-service maintenance' --verify
)
```

This block captures the checked, nonempty reviewed source once and reuses those
exact bytes. Its final read-only verification requires both the immutable input
receipt and the expected pause note. A missing, empty, changed or unreadable
source, failed exec or absent receipt stops the block. Do not continue to stop
or install after any failure; retain partial evidence for inspection. The hash
names this adapter candidate and must match the separately reviewed artifact.

The old relay does not honor the new marker. Identify whether the old session
is daemon or foreground. `sandy --stop` targets daemon-labelled sessions only:

```sh
(cd "$WORKSPACE" && sandy --stop)
```

Exit 4 means no daemon session; it does not establish that a foreground session
is gone. Exit a foreground session through its normal session exit instead.
Establish actual old-container absence from a successful read of the launcher's
container state, including both daemon-labelled and exact foreground identity;
an unavailable Docker/state read is UNKNOWN. The new-container `--exec -- true`
preflight below is not an absence check for the old one. Keep the procedure held
if the matching old container is still present or cannot be checked. Do not
guess process-tree kill commands. The normal stop/exit must establish that the
service/backend and every native client have stopped. Identify and record the
exact full `OLD_CONTAINER_ID` before stopping, using the existing workspace
resolution and read-only inventory:

```sh
sandy --exec --workspace "$WORKSPACE" --dry-run -- true
docker ps --no-trunc --format '{{.ID}} {{.Names}}'
```

Use one matching old environment, identified by the dry-run container ID and
its workspace/name/daemon labels; ambiguous inventory holds the procedure. Keep
the verified Docker context/daemon unchanged throughout. After normal daemon
stop or foreground exit, require successful all-container enumeration and
absence of that full ID; no daemon exit code substitutes for this check:

```sh
(
  set -e
  : "${OLD_CONTAINER_ID:?Set the exact full old container ID from preflight}"
  old_ids=$(docker ps --all --quiet --no-trunc) || { echo 'UNKNOWN: container enumeration failed' >&2; exit 1; }
  python3 -c 'import re, sys
old, listing = sys.argv[1:]
ids = listing.splitlines()
if not re.fullmatch("[0-9a-f]{64}", old) or any(not re.fullmatch("[0-9a-f]{64}", v) for v in ids):
    sys.exit("UNKNOWN: full container identity is unavailable")
if old in ids:
    sys.exit("HOLD: old container still exists")
print("Old container absent on the enumerated daemon")' "$OLD_CONTAINER_ID" "$old_ids"
)
```

A failed read, switched daemon/context or surviving old container holds the
procedure. This is a source-derived operator check, not an already measured
host result. Preserve all
mounts/native history. Install reviewed payload while stopped, retaining legacy
protected bytes. From the reviewed adapter checkout, check the sibling pin and
preview/apply the installation before restarting anything:

```sh
AMAP_CODEX=1 python3 amap-siblings.py
python3 amap-sandy.py install
python3 amap-sandy.py install --apply
```

Keep `adapter-pause.json` present in retained private state. Start the new
environment only after the installation completes:

```sh
(cd "$WORKSPACE" && sandy --start)
sandy --exec --workspace "$WORKSPACE" -- true
```

The new relay checks pause before rendering or running a service, and its pane
wrapper refuses native startup. Source inspection suggests a refused wrapper
leaves a waiting pane shell; this must be verified on the target. Successful
`--exec -- true` establishes exec availability, not service quiescence or
adoption success. If that preflight or absence of old/new native clients is
unknown, retain the pause and stop the procedure. No process-tree kill or
service-stop API is assumed. The shipped old/new relay controls prove marker
and controller preservation in fixtures, not Sandy lifecycle acceptance.

The sibling check must report the approved source, and the installation must
complete without restarting any selected service. The installed baseline
connector lacks `unified-adopt`; adoption therefore follows code installation.
Do not substitute adopt-before-install or change old protected paths to copies.

Explicit unified preparation and entry resolve the same model: nonempty forwarded
`CODEX_MODEL`, native config model, then native default. The retained previous
controller keeps its original model bytes; the target records the selected
model and its source. Supported unified permissions require explicit
`SANDY_SKIP_PERMISSIONS=true` and the retained `danger-full-access`/`never`
profile. Missing, false or other choices refuse; no alternate permission mapping
is assumed. The pane wrapper checks the environment selection again, and a
different explicit model/permission argv flag refuses at attachment. An
established unified instance holds changed model/build selections; its controller
is never automatically re-rendered. Settings transitions beyond this first
adoption require their own reviewed procedure.

The relay writes `entry-settings.json` with entry-environment scope, the selected
model/source and permission choice, bound to the controller bytes. Host verify
names that source and reports unknown, foreign or mismatched entry evidence as
a problem. The receipt is not proof of arbitrary later native argv, nor current
host acceptance. The operator still verifies the target environment and pane.

Before a unified incoming service starts, the relay publishes a config-bound
`pane-startup.json` for its private entry generation. The protected pane wrapper
checks its complete native argv, including explicit model/approval/sandbox
choices, then writes matching `pane-selection.json`. A conflicting `-a
on-request` refuses even with `SANDY_SKIP_PERMISSIONS=true`; unsupported profiles,
provider/config/effort overrides and foreign resume choices also refuse before
incoming execution. Environment evidence alone never releases this startup gate.

Prepare the selected instance while stopped. The first command previews only:

```sh
sandy --exec --workspace "$WORKSPACE" -- python3 /opt/sandy/features/amap/codex/transition prepare --thread "$THREAD"
sandy --exec --workspace "$WORKSPACE" -- python3 /opt/sandy/features/amap/codex/transition prepare --thread "$THREAD" --apply
```

Preparation takes the connector's controller and lane ownership, preserves
`adapter-previous.toml`, durably records `adapter-transition.json` as `prepared`,
then writes the target at its final `controller.toml` pathname. Original
protected references in the previous snapshot remain unchanged. The target
renders unified mode, the owned native argv and kickoff disabled. An interrupted
prepare can be repeated for the same thread and unchanged assets. A different
target, foreign controller or changed snapshot refuses. The prepared record
blocks automatic entry startup even if the native adoption has already happened.

Validate and adopt at that exact final pathname, in the same execution
environment. `doctor` below is static; do not add `--probe`:

```sh
sandy --exec --workspace "$WORKSPACE" -- sh -c 'export PYTHONPATH=/opt/sandy/features/amap/codex/src; python3 -m amap_codex.cli --config /opt/sandy/feature-state/amap/codex/controller.toml doctor'
sandy --exec --workspace "$WORKSPACE" -- sh -c 'export PYTHONPATH=/opt/sandy/features/amap/codex/src; python3 -m amap_codex.cli --config /opt/sandy/feature-state/amap/codex/controller.toml unified-adopt --previous-config /opt/sandy/feature-state/amap/codex/adapter-previous.toml --thread "$1" --note "Operator selected this saved conversation for unified delivery"' sh "$THREAD"
sandy --exec --workspace "$WORKSPACE" -- python3 /opt/sandy/features/amap/codex/transition confirm
sandy --exec --workspace "$WORKSPACE" -- python3 /opt/sandy/features/amap/codex/transition confirm --apply
```

The connector's protected activity tool includes the configuration pathname in
its policy binding. Do not adopt through a temporary pathname and then rename
it. Confirmation requires the committed native adoption, retained-history hash,
matching previous/target fingerprints and selected thread, matching protected
policy hashes and effective model. It releases no pause and starts nothing.
If acknowledgement was lost after native adoption committed, run confirmation;
do not create another history or replay model input. If native maintenance is
still planned, retain the hold and follow its explicit same-command recovery.

Only after confirmation, release the adapter pause, with the service still
stopped:

```sh
sandy --exec --workspace "$WORKSPACE" -- python3 /opt/sandy/features/amap/codex/transition unpause
sandy --exec --workspace "$WORKSPACE" -- python3 /opt/sandy/features/amap/codex/transition unpause --apply
```

After unpause, incoming work remains held until a protected native wrapper
launch records the complete matching argv for that entry generation. The exact
host terminal launch after paused restart remains part of launcher acceptance.
First check that the current selection request is available (this does not
claim backend readiness):

```sh
sandy --exec --workspace "$WORKSPACE" -- python3 /opt/sandy/features/amap/codex/transition selection-ready
```

Once that succeeds, the operator can launch the actual protected wrapper from a
real terminal with the explicitly reviewed full-access/never profile. The exec
source keeps a TTY only when the calling stdin is a TTY. This command selects
its complete native argv; it does not fabricate a receipt or copy an ambient
profile/per-agent argument string:

```sh
sandy --exec --workspace "$WORKSPACE" -- sh -c 'if [ -n "${CODEX_MODEL:-}" ]; then set -- --model "$CODEX_MODEL"; else set --; fi; exec /opt/sandy/features/amap/codex/interactive-launch codex --sandbox danger-full-access --ask-for-approval never "$@"'
```

The wrapper then delegates
directly to the connector's single bounded wait. It targets the registered
canonical thread and private generation; it
never starts a substitute conversation. Detaching the terminal leaves the
service running. Retries within that same adapter entry generation retain the
selection proof. Relay-process and backend retries in the same execution
environment retain proof without requiring a terminal relaunch. The Sandy
adapter derives environment identity from kernel boot UUID, PID namespace and
PID1 start identity; unavailable facts hold unified startup. A different
execution environment, controller or validator code requires fresh wrapper
selection. `kickoff` is disabled; human work enters through the native pane.

`verify` requires matching fresh status and descriptor evidence, the current
configuration and durable canonical/policy binding, all named readiness checks,
matching model/permissions and known scheduler/queue/client facts. Missing,
stale, foreign and malformed evidence is UNKNOWN and exits nonzero. Protected
tool validation is a generation-bound startup fact, not continuous tool health.
The operator must additionally measure both directions of a Codex/Claude round
trip with accepted-send correlation, busy-human queueing, detach/reattach and a
safe restart in the actual unified pane. Synthetic source controls establish
none of these host acceptance results.

At any failed or uncertain step, preserve the pause, transition record, logs,
previous configuration, journal and native history. A `prepared` record can
cover an uncertain native side effect. After any native adoption, restoring an
old payload/configuration is not a valid rollback; remain stopped for an audited
reverse transition. No reset, deletion, implicit cancellation or automatic
replay is part of this procedure.
