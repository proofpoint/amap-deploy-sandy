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
into `~/amap` and checks out the commits pinned in `siblings.json`. It also
checks out the router a second time, as `amap-router-local-hop`, at the
temporary pin the hop deployment's renderer is tested against. Run it
without `--apply` to see what it would do. It refuses a checkout with
uncommitted changes. `amap-deploy-sandy` finds the other two by looking
beside itself; `$AMAP_ROUTER_REPO` and `$AMAP_CONNECTOR_REPO` override that,
and `amap-siblings.py` leaves an overridden checkout alone. You do not build
the connector: `install` copies its binaries onto the read-only payload.
`install` refuses a connector checkout that is not at its pin or has changed
files, so an overridden checkout must be at the pin too. To install from one
that is not, say why; the attempt is logged in `install.log` beside the
manifest:

```sh
python3 amap-deploy-sandy/amap-sandy.py --allow-unpinned-connector "testing a connector fix" install --apply
```

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

The supervisor uses the agent's own model, `model` in the sandbox's
`~/.codex/config.toml`, or Codex's default where that names none. Change it
there, not with sandy's `CODEX_MODEL`, which reaches only the pane; the
supervisor picks it up on its next start.

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

This procedure is an engineering draft. Source approval, an immutable reviewed
Codex connector pin, the launcher model/permission facts and the service-only
stop procedure are still required before an operator can execute it end to end.
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

**Stop step OWED:** obtain the isolation launcher's supported procedure to stop
the feature entry's service/backend and every native client while keeping the
execution environment available for maintenance. Neither `sandy --stop` followed
by `sandy --exec`, nor killing only the supervisor, is an established procedure.
The old relay retries failed children. A newly installed relay file does not
replace an already-running old relay process. The operator must establish that
the old service/backend and clients have exited and their controller/lane
ownership is released. Do not install or transition while that fact is unknown.

For an instance already running the pause-aware adapter, the following commands
write an explicit pause; they stop no process. The first command is a dry run:

```sh
sandy --exec --workspace "$WORKSPACE" -- python3 /opt/sandy/features/amap/codex/transition pause --note 'Operator selected stopped-service maintenance'
sandy --exec --workspace "$WORKSPACE" -- python3 /opt/sandy/features/amap/codex/transition pause --note 'Operator selected stopped-service maintenance' --apply
```

`adapter-pause.json` lives in the private entry state, alongside the controller.
The relay checks its presence before rendering and before every child retry,
including after a relay restart. The terminal wrapper refuses attachment while
paused. Establish quiescence separately, then run the approved installation from
the correct adapter checkout:

```sh
AMAP_CODEX=1 python3 amap-siblings.py
python3 amap-sandy.py install
python3 amap-sandy.py install --apply
```

The sibling check must report the approved source, and the installation must
complete without restarting any selected service. The installed baseline
connector lacks `unified-adopt`; adoption therefore follows code installation.
Do not substitute adopt-before-install or change old protected paths to copies.

The target inherits the previous explicit model and permission settings. Until
the generic launcher exports its resolved model, `CODEX_MODEL` must be unset or
equal to the model in the native Codex configuration. That condition is an
operator preflight obligation, not a measured host fact. A different explicit
pane model/permission flag refuses at attachment. A changed native configuration
model or build holds the relay; automatic re-rendering is disabled in unified
mode. Settings transitions beyond this first separate-to-unified adoption
require their own reviewed procedure.

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

The pause-aware relay may resume at its next poll. If the entry was stopped,
use the isolation launcher's reviewed service-start procedure (still OWED).
Unified attachment then delegates directly to the connector's single bounded
wait. It targets the registered canonical thread and private generation; it
never starts a substitute conversation. Detaching the terminal leaves the
service running. `kickoff` is disabled; human work enters through the native pane.

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

## 10. A hop deployment's host setup

A hop deployment runs each side of a hop as its own uid, against roots the
operator creates as root. Its host is described by a host-setup document
(operator data, kept outside this repository: the deployment overlay's
`host_setup` section, or a file given with `--spec`), and one verb prints the
plan and checks the host against it. It runs none of the plan:

```sh
python3 amap-sandy.py --overlay <deployment overlay> host-setup
```

**Which directories are roots.** Every directory a hop runtime opens as the
top of a tree it writes is a root in the document, with that runtime's
principal among its readers: its hop root and private roots, its state
directory, its lock directory (unless that is on tmpfs), any archive
directory it is configured with, and the directory that holds any state file
it is configured with (a file's parent is the root, not the file). The
private overlay's documentation lists them for each runtime. A directory left
out is one the plan never creates, syncs or checks.

**Nothing under a hop root's per-link directory is a root.**
`<hop_root>/<logical_id>/` and everything under it are created by the
runtimes; a deployment must not pre-create or chown them. Each level is
checked by the runtime that makes it and never repaired, so one made or
re-owned by anyone else stops that runtime's admission of the link.

Run the printed steps as root, in order, **before any hop runtime starts**,
from a checkout that no sandbox mounts read-write: a fresh clone at the
recorded deploy commit, never an agent's workspace checkout. The steps run
that checkout's `host_steps.py` as root.
Each step goes through `host_steps.py`, which reaches every path from `/`
without following a symbolic link and stops at one. Every root is created
with its owner, group and mode, then it and every ancestor are fsynced, so a
runtime never opens a root that is not durable. The steps are safe to run
again.

Start each hop runtime under the umask the plan names for it: `UMask=0027`
in its service unit, or `umask 0027` in its launcher before it execs. 0027
is the only umask a runtime record accepts unless it lists 0022 in
`umasks`. Never list it for a runtime whose paths create directories under
the umask alone: under 0022 those directories are readable by every uid on
the host.

Start each hop runtime with exactly its principal's groups: its uid and
primary group as the container's user (`--user <uid>:<gid>`), and
`--group-add` for each of its other groups and no more. `verify` reads
every process's groups and fails a runtime that is missing one or holds
another principal's, because the reach checks assume them.

With the stub plugin pinned, the router refuses to start (`exec_failed`):
that is the expected outcome while the plumbing is checked, and it ends
when the reviewed plugin's digest is pinned.

Then run the verb again; `verify` runs the same checks whenever the
overlay has a `host_setup` section. Each exits non-zero unless every check
passes, and an UNKNOWN (a runtime not running, a container that could not be
asked, a runtime outside a container) is a problem, not a pass. No check can
see whether the barrier ran: durability rests on the steps having run before
the runtimes started.

### A refused leftover item or `.stage` directory

A hop runtime never repairs a directory it finds already there. If a crash
left one behind that is not exactly what the runtime would have made, the
runtime refuses it with an ERROR that names the path, and its replay stops
there.

1. **Stop the runtime.**
2. **Check the named directory.** `ls -lnd <path> <path>/..` shows the type,
   the mode, and the owner's uid of it and of its parent. Every one of these
   must hold:
   - it is a **real directory**: its line starts with `d`, not `l`;
   - it is **empty**: `ls -A <path>` prints nothing;
   - it is **owned by the writer's uid**, the runtime that refused it;
   - its permission bits are **a subset of the requested ones**: 0770
     (`rwxrwx---`) for an inbound item directory (a notice's attachments or
     a candidate, under a generation's `inbound/`), 0750 (`rwxr-x---`) for
     any other item directory (a request's attachments, a host intake's
     item), 0700 (`rwx------`) for a `.stage` directory;
   - it has **no setuid and no sticky bit**: no `s` in the owner's execute
     place, and no `t` or `T` at the end;
   - its **setgid bit** (`s` or `S` in the group's execute place) is the
     same as its parent's.
3. **If all hold, remove it** with `rmdir <path>`, never `rm -r`, and
   **start the runtime**. The replay creates it again. That is safe: the
   directory is empty and its owner is the writer, and nothing is committed
   there before the runtime's checks pass.

**Two mismatches have a known cause.** Each is a directory that passes every
check above and differs from the request in one way only:
- **An inbound item directory without group write** (`rwxr-s---` where
  `rwxrws---` was asked). Every accepted umask strips group write from
  0770, so the runtime restores it with an `fchmod` after the `mkdir`, and a
  crash between the two leaves exactly this. `rmdir` it and start the
  runtime.
- **Any directory without the setgid bit its parent has.** A umask that
  strips a requested bit leaves this when the parent's group is not one of
  the writer's groups. It is a deployment error, not a plant: fix the
  runtime's umask and its groups (the umask and group checks above name
  each), then `rmdir` it and start the runtime.

**Any other mismatch: do not remove it.** A directory that is not a real
directory, not empty, owned by someone else, or carrying bits the runtime
never asks for may have been planted. Leave it in place, keep the runtime
stopped, and escalate.

### A runtime's secret file

A runtime that needs a credential reads it from a file in a directory only
its own uid can open: the directory 0700, the file 0400, both owned by the
runtime's uid, mounted read-only into that runtime alone. `host_steps.py`
writes and removes it. Run it with `python3 -I -S`, from a root-owned copy
whose sha256 you have checked, never from a working checkout:

```sh
<producer> | python3 -I -S host_steps.py secret <dir>/<name> <uid> <gid>
printf '' | python3 -I -S host_steps.py secret --check <dir>/<name> <uid> <gid>
python3 -I -S host_steps.py secret-remove <dir>/<name>
python3 -I -S host_steps.py stat-secret <dir>
```

- **The value arrives on a pipe, and nowhere else.** `secret` refuses a
  terminal, a regular file or a device on stdin, so it cannot be typed,
  pasted or read from a saved copy. Never put the value in an argument or
  an environment variable: both show in `ps` and `docker inspect`.
- **One line, ending in a newline.** The newline marks the line complete,
  so a producer that dies mid-write leaves nothing that passes. The value
  is at most 4096 bytes, printable ASCII without spaces, and is stored
  without its newline.
- **Nothing it prints carries the value.** A refusal is one line,
  `refused: <rule>`, exit 2. On success it prints only the path, mode and
  owner.
- **It replaces the file whole:** written under `.<name>.tmp` in the same
  directory, checked by fstat, fsynced, renamed over the file, and the
  directory fsynced. A temp left by a crash is removed by the next run.
  Any other entry in the directory is refused, and nothing is written.
- **One writer at a time.** `secret` and `secret-remove` lock the
  directory; a second one refuses with `refused: concurrent writer` before
  changing anything.
- `secret --check` makes every check `secret` makes before it reads, reads
  nothing, and changes nothing: run it through the same route first, with a
  pipe carrying no value on stdin. `stat-secret` reports the directory's and
  each entry's owner, mode and link count from `lstat` alone, without
  opening any file.

**The host-setup document's `secrets` section** describes such a file on a
host whose runtime keeps it in a container-engine volume: the volume and the
principal that owns it, the runtime image by digest, the pinned writer, a
root-owned anchor holding the reviewed overlay's sha, a root-owned state
file (`pending_b5`, `active` or `retired`), the fresh clones the tooling
runs from, and the absolute path of every tool. `host-setup` then prints the
steps that create the anchor, install the writer, create the volume and its
root, the lock file and the state, and checks, without reading the secret:
- the document itself was read from the anchored overlay clone, as a file
  that clone tracks, never from a copy or a working checkout;
- the writer, the anchor and the state file are root-owned 0444 with one
  link under root-owned directories, and the writer hashes to its pin;
- each clone is the operator's 0700, at its recorded commit, with no hook
  that can run and no changed or ignored file, asked with system and user
  git configuration ignored;
- each tool is a regular executable whose real path, and every directory
  above it, is owned by root or the operator and not group- or
  world-writable. docker, python3, sudo and install, which root executes, must be
  root's alone: the real path, every directory above it, and every
  directory above the recorded path, so no one else can repoint a link.
  A docker inside an operator-owned application bundle (OrbStack's), or a
  python3 under the operator's home, fails here: record root-owned ones;
- the hub ssh key is pinned in a 0400 known_hosts, and ssh's effective
  host-key checking is strict in the producer's own option order;
- the volume holds exactly what the state says, read by `stat-secret` in a
  one-shot container under the lock;
- the host keeps no core file (Linux: every core to systemd-coredump with
  `Storage=none`, and apport absent or disabled; macOS: `kern.coredump=0`);
- the lock files: `oneshot.lock` and each name in `pipeline_locks`, each the
  operator's, 0600, created by the plan, never later;
- in the `active` state, the weekly probe has run within 8 days, passed
  within 15, and not failed TLS twice in a row.

**Who else could reach it.** With the section, `host-setup` and `verify`
also check every container on every engine of this host (each `docker
context` with a `unix://` endpoint, running or stopped; a remote context is
swept by its own host's verify and named in the notes), holding the
one-shots' lock so nothing starts meanwhile. Each of these is a failure:
- a mount of the secret's volume by anything but the runtime's own
  container, on the engine that holds the volume, as rendered: the pinned
  image's resolved ID, its user, one read-only mount at its directory,
  every capability dropped and none added, no new privileges; a one-shot
  container still there (a crash, or one running while the lock is held);
- a bind that overlaps a secret path (the volume's backing directory, an
  engine socket's directory, ssh's directory, a core directory, any listed
  in `exposure.secret_roots`) in either direction, or that is writable over
  the tooling, or sits above it. Paths are compared by device and inode up
  each ancestor chain, the resolved path's and the literal one's, so an
  alias, a case variant, a firmlink or a symlink matches; a bind source
  that cannot be stat'ed is UNKNOWN, whatever its name suggests. An engine
  socket is protected as itself, so a bind of it or of a directory above
  it fails and its siblings do not;
- a privileged container, a capability not in `caps_allow` (or one no
  allowlist admits: those that reach another process's memory or the
  host's files), a host or shared namespace, a device, an unconfined
  profile, or volumes taken from the runtime's container; the runtime
  itself adds no capability and runs with `no-new-privileges`;
- an engine socket bound, or `DOCKER_HOST` or `SSH_AUTH_SOCK` set;
- an engine socket no context names, or an OrbStack machine.

It then prints, for you to confirm: the attestations the section records;
the fingerprints of the listed `authorized_keys` files; `sshd -T`'s
password, keyboard-interactive, CA and authorized-keys-command lines; any
agent CLI running on the host outside a container; `tmutil isexcluded` for
each path in `exposure.backup_excluded`; and the remote contexts it left to
their own hosts.

`place <src> <dest> --sha256 <hex>` installs a file root-owned 0444 only if
its bytes have the given sha256, so the route the file arrived by need not be
trusted.

`lock <run_dir> -- <command>` runs a command under `<run_dir>/oneshot.lock`,
which host-setup creates. The command gets its own descriptor on the lock,
so the lock lasts until the command exits even if the wrapper is killed. The
wrapper never reads stdin. A command killed by signal n exits 128+n.

The weekly probe job runs `lock <run_dir> -- python3 -I -S host_steps.py
probe-weekly <status> <run_id> --engine unix://<socket> --docker <docker> --
<probe command>`: `lock` outside, never inside, so a busy lock is the
wrapper's refusal rather than a probe result. `probe-weekly` keeps a class
only when the probe's exit is that class's own; a stopped engine is
recorded as `engine_unavailable` without running anything, and a probe that
outruns its time has its containers removed by the run's label and is
recorded as `timeout`. Before anything runs, `probe-weekly` checks that its
interpreter, the docker client and the probe's program are root's alone,
with their startup closure, as the weekly partition job checks its own; when
they are not it refuses (`refused: tools`), runs nothing and records nothing.

### The hub-link router's files

A document with a `hub` section (which needs the `secrets` section and its
`probe` settings) renders two files for the email router on a hub link, and
`host-setup` prints the steps that place them:

- **The delivered-domain (D7) file**, from the network's generated D7
  document in the `secrets` section's producer clone. Only this host's link
  is taken, and only when the document says it is attested; otherwise
  nothing is rendered, the plan says the router must not start, and a file
  already placed stays until you stop the router. The render refuses
  anything the stricter of the two routers would refuse (a domain not
  already one lower-case `<label>.internal`, the host's own domain, an
  excluded domain, a hash that is not the domains' own, a reworded
  statement, a set that differs from `fleet_hosts`, duplicate JSON keys).
  It never writes an attestation; it copies the source's.
- **The environment file**, one `KEY=VALUE` per line, used by every mode
  of the router. `own_domain` is the one source for the router's own
  domain, its SMTP and IMAP logins and the D7 exclusion. Keys the router
  refuses when present at all, even empty, are never written: the
  passwords, the TLS key log, the raw archive, the optional templates, the
  file log sink, the drop-box and every `OAUTH2_*`.

Render them as the operator, into the `secrets` section's run directory:

```sh
python3 amap-sandy.py hub-render            # says what it would write
python3 amap-sandy.py hub-render --apply    # writes hub-d7.json and hub.env
```

then run the plan's two `place ... --sha256 <hex>` steps as root. The D7
file goes alone into its own root-owned 0755 directory, which both routers
mount read-only as a directory: `place` replaces the file by rename, so a
single-file mount would keep the old one.

`host-setup` and `verify` then check: the D7 directory holds only the file
(a `place` temp file there is a note: re-run the step), the file is
root:root 0444 and byte-identical to a fresh render, and it carries the
source link's domains, hash and attestation, compared field by field with
the hash recomputed; a source that no longer attests the link fails. The
environment file is root:root 0444 under root-owned directories and
byte-identical to a fresh render. The rendering itself, and the running
container when there is one, must meet the router's rules: the refused
keys absent, `RELAY_LINK_ROLE=hub` once, password auth, the runtime's uid,
gid and exactly its other groups, a read-only root, core 0:0, no new
privileges, every capability dropped, restart `no`, the secret volume once,
read-only, without copy, and the D7, overlay and registry directories
read-only. A running container must also match the rendering: the same
variables (beyond the image's own) and mounts. In the `pending_b5` and
`retired` states the router must not exist at all.

### The local router's signing key

A `keys` section (it needs the `hub` section) places the local router's
signing key and keeps it out of the email router's reach. The key is
generated on the host by you, as the local router's uid, into its own 0700
directory, mode 0400; nothing in this repository generates, reads or
copies it. The directory must be listed in the `secrets` section's
`exposure.secret_roots`, so the exposure sweep fails any container whose
bind overlaps it, in either direction, the local router's included, and
the probe's evidence directory in `exposure.integrity_roots`.

The key-read probe runs the email router's own rendered run spec (its
user, groups, capabilities, security options, read-only root and mounts)
with only its name, labels, network (none), restart, entrypoint and
command changed, and without the secret volume, which no other container
may mount. It only `lstat`s the key's paths and passes only when every one
is absent (ENOENT): a key that is there but unreadable (EACCES) is a key
that is reachable.

```sh
python3 amap-sandy.py hub-keyprobe            # shows the probe
python3 amap-sandy.py hub-keyprobe --apply    # runs it; writes keyprobe.json into the run directory
```

Then place the record with the plan's `place ... --sha256 <hex>` step. The
record is bound to the email router's run-spec hash, the key's path, the
candidate paths and the probe's image and command: change any of them and
the record is stale, and the email router may not start until the probe
passes again. The environment file's contents are not bound: a variable
cannot add a mount, a capability or a user.

The evidence directory must be root-owned 0755 under root-owned
directories, and no container may bind it, or anything above it, at all,
read-only included.

`host-setup` and `verify` also check the local router's config for a
`delegation` block: one present, in any form, fails (no live peer signing
until the full signed-case harness passes). Its absence passes only when
the running local router reads `keys.local_config`, byte for byte: they
ask the router's container which file its `ROUTER_CONFIG` names and hash
it there. On a hop host `install` refuses a `keys.local_config` other than
the router.json it renders, so start the local router with `--config`
naming that file. They also check that each running router sees the D7
file the host holds, and that the email router's inbound recovery window
(`HUB_INBOUND_RECOVERY_MAX_DAYS`, rendered into its environment file) stays
below the local router's `ingress_dedup_horizon_days`.

### The local router's hop link

On a host with a hop link, the local router carries the link's keys in the
router.json `install` renders. Two inputs turn them on, and both are needed:

- the policy names the link, in the manifest's `feature` section:
  `"hop_link": {"link": "<the hub section's hop link name>",
  "trusted_fleet_hosts": [...], "egress": true}`. Every member is required;
  the trusted hosts are a subset of the hub section's `fleet_hosts`;
- the host-setup document is complete: the `hub` section, the overlay pin,
  and a `router` section naming the local router's image (`name`, `digest`,
  `commit`) and its `container` name.

Build the local router's image from the hop checkout (`siblings.json`'s
`amap-router-local-hop` entry), under a name other than the factory
default. Build the image from a clean export of the pinned commit (`git -c
core.attributesFile=/dev/null archive <pin> | tar -x -C <an empty
directory>`, from a clone with no `$GIT_DIR/info/attributes`), never from a
tree in which Python or the tests have run. The build copies router/ whole,
so a stale `__pycache__` would be copied and could run in place of the
source. Then, before A1:

```sh
python3 amap-sandy.py router-fingerprint --image <the image> --apply
python3 amap-sandy.py router-fingerprint --verify-image <the file it wrote> --commit <the pin>
```

The check must print `EXACT`. Record its image ID as the `digest` (`docker
image inspect --format '{{.Id}}' <name>`, the engine's content-addressed
image Id: the config digest on the classic image store, the manifest (list)
digest on the containerd store), and
the commit it was built from. Then:

```sh
python3 amap-sandy.py install --apply
```

renders the hop keys and validates them with the hop checkout's own loader.
Start, or restart, the router from the hop checkout's `docker/run.sh`, with
`--name` the `router` section's container name, run by the local router's
principal (the hub's hop's other end in the host-setup document): the
router runs as the uid and gid of whoever runs `run.sh`, and `verify`
checks they are that principal's. A change to the hop keys or the plugin
needs that restart; the router refuses a reload that changes them.
`verify` reports a refused reload from the router's own `status.json`: the
router keeps running on its last good config and says so there, and only a
recent document from a router with its hop transport loaded can show that
no reload was refused.

Three changes are refused rather than rendered:

- `hop.root` against the generations recorded in `state_dir`: it is fixed
  for the life of `state_dir`;
- the link name: run `router generation new <name> --reason <text>` for
  each hop identity first;
- removing `hop_link` while `state_dir` holds hop state: run
  `python3 amap-sandy.py install --decommission-hop --apply`, then restart
  the router.

### The registry without a hop link

A host whose local router resolves its instances through the registry, but
has no hop link yet, names it in the policy: `"router_registry": true` in the
manifest's `feature` section. Only `true` is accepted. `install` then renders
`registry_dir`, and no hop key, from the overlay's `registry.directory`.
That value is never defaulted: it must be an existing directory, named by
its own physical spelling. Only the hop checkout's router reads
`registry_dir`, so the hop checkout's loader validates the rendering, and
`--render-to` takes it as it takes a hop host's. Run that router as the hop
section says. With a hop link as well, the link's `registry_dir` must be the
same directory. Without the key, the rendering is unchanged.

### The local router's migration to the generation layout (R2)

A local router whose state is keyed by instance name (any router that ran
without `registry_dir`) cannot be upgraded to the pinned router
transparently. On a configuration that sets `registry_dir`, the pinned
router holds each such instance (`state_not_migrated`, then
`legacy_state_unadopted`). It places nothing for it and loses nothing,
until the instance's state is moved to its logical id and adopted. R2 does
that as its own window, before any activation. It ends with the pinned
router running under the host-setup document's `router.container`, with
every instance's state in the generation layout under the registry, and
fingerprinting `MEASURED`, which is what activation's step 2 requires. R2
is never part of an activation window.

R2 needs:
- the hop link above: the policy's `hop_link`, so that `install` renders
  `registry_dir`;
- the hop checkout at its pin;
- the local router's image, built and checked;
- every configured instance enrolled in the host registry. Step 3 STOPs
  otherwise, before anything has changed.

A router that ever had a transport route is out of R2's scope: step 4
STOPs on any transport history.

Run every step as the operator: the router runs as the operator's uid,
and its `state_dir` is the operator's.

Each `router-migrate` step:
- runs the pinned router's own code through the hop checkout's
  `docker/run.sh`, on the document's `router.image`;
- writes its record into the run directory;
- exits 0 when it is done, 1 on a STOP and 2 when it cannot run. Any
  non-zero exit stops R2 at that point, and the back-out for that point
  (below) applies.

Step 4's preview is the plan, and every later step is bound to it: the
config's sha256, the state directory and its identity, the registry, the
hop checkout, the image, and each instance's binding and state directory.
Each later step re-reads the registry through the pinned code, and refuses
before it changes anything unless all of these are still the plan's.

**The stable window.** From step 5's stop until step 11's acceptance has
passed, no instance root may be recreated. Only after step 11 passes do
sandbox lifecycle actions, host changes and the scheduled recreation
resume.
- An instance root is `$SANDY_HOME/features/amap/instances/<slug>` on the
  host. The router's config names `$SANDY_HOME/features/amap/instances` as
  its `instances_dir`, and the pinned router takes each `<slug>` under it as
  that instance's `handoff_dir`, its root. Sandy creates the directory when
  it launches a selected sandbox, and removes it with the sandbox
  (`--remove-sandbox`).
- The manifest this repository renders mounts into a sandbox only that
  directory's lanes, never the directory itself or any ancestor of it, so
  an agent in a sandbox cannot recreate a root, and running agents stay up.
  That covers this feature's own mounts, not every container on the host.
  So, before step 5, check that no other container (anything but the local
  router's containers: its own, stopped here, and R2's one-shot steps) has
  a writable bind of an instance root or of any ancestor of one, and stop
  any that does for the window. If that is the hub-link router, stop and
  start it through its supervisor (`systemctl stop` and `start` of its
  unit, or launchd's `bootout system/<label>` and then `bootstrap system
  <its plist path>`), never with a bare `docker stop`: its default 10 s
  timeout is shorter than the router's own stop budget, so it can kill the
  router in the middle of a send, and the supervisor then restarts it (exit
  137). The supervisor's stop waits for the router's own clean exit.
- For every instance being migrated, until step 11 passes:
  - no sandbox lifecycle action (launch, relaunch, remove or recreate);
  - no host-side change under its `instances/<slug>`;
  - no registry change for it: a rebind makes the router begin a new
    generation, as a recreated root does, and a retirement, removal,
    rename, collision, unreadable snapshot or rollback holds the instance,
    so its first poll would not drain it;
  - no `reset` and no `generation new` of it, each of which begins a new
    generation;
  - no edit of the live config.
- Before step 5, pause the scheduled container recreation, the job the
  policy's `container_recreate_interval_hours` drives.
- Steps 8, 9 and 10 detect a change of an instance root, of the registry
  binding, of the config, or of an instance's state directory, and stop R2
  before step 10's start, on the back-out for that point: D once any
  migrated directory holds an adopt's files (`migration.json` or
  `generations.json`), and C then B before that. The premise covers every
  other change. The one gap left is between step 10's verify and the
  router's first poll, which only this premise covers. A root recreated there would make the router
  begin a new generation, with a fresh first sight that quarantines that
  instance's waiting requests.

While R2's window is open, everything waits on disk and nothing is lost:
- agents' outbox requests stay in their outboxes;
- the router's state stays where step 7 moves it.
After step 9's adopt and step 10's start, each instance's first-sight
marker and reply ledger carry over, and it drains on the first poll.

1. **Fingerprint.** `python3 amap-sandy.py router-fingerprint --step 0
   --label r2 --apply`, then `python3 amap-sandy.py router-fingerprint
   --match <the file it wrote>`, each with `--container <its current name>`
   while the router's container is not yet `router.container`. `--label r2`
   keeps R2's capture files apart from an activation's. The match must print
   `MIGRATE` and exit 3 (`pre_registry_base` or `migration_required`).
   `MEASURED` means no migration is needed. Any other result names its own
   remedy, and R2 does not start. A `state_layout` refusal naming a file
   that is a temporary of the router's own (it writes its status by
   rename) clears when you fingerprint again.
2. **Render.** `python3 amap-sandy.py install --render-to <run_dir>/r2-config.json
   --apply`.
   - This path renders and nothing else: the manifest, the payload, the
     roster, the registry and the live config are not written. It writes
     the pinned router's configuration to that new file and prints its
     sha256, and its exit code is the rendering's.
   - The live config is not written yet: the running router's loader
     refuses the hop keys.
   - The rendering is held to the pinned router's own loader, which refuses
     a `hop.root` or a `registry_dir` nested with `state_dir` in either
     direction. So the hub-link router's hop tree and registry, which come
     from the same document fields, never lie under a state directory that
     step 7 moves.
3. **Map.** `python3 amap-sandy.py router-migrate map --config
   <run_dir>/r2-config.json --apply`. It records each instance's logical id
   and registry binding. It STOPs when the registry is not `ok`, or when a
   configured instance is not resolved.
4. **Preview.** `python3 amap-sandy.py router-migrate preview --config
   <run_dir>/r2-config.json --reason "<text>" --apply`.
   - It plans every instance whose state is pre-generation: under its name
     (to be moved, then adopted), or already under its logical id (adopted
     where it is). State holding no pre-generation entry (results,
     inflight, transport, pending, quarantine, held, first-seen.json or
     approval.json) needs no adopt: the pinned router begins its first
     generation there on its own first poll, unless it also holds a
     generation directory (`gen-*`) with no generations.json, which the
     pinned router holds as `state_layout_conflict`; step 4 STOPs on that. Under a name it is moved and
     not adopted; under a logical id it is left as it is. Such state has no
     first-sight marker, so that first poll takes a fresh first sight and
     quarantines the instance's waiting requests, as the old router would
     have done too: the migration does not cause it.
   - It STOPs unless the plan covers exactly what the state directory's
     layout needs: a name-keyed directory of an instance that is not
     configured, a logical id the registry does not map, or a file named
     like an instance's state each stop it.
   - It copies each planned state directory to a scratch state directory
     under its logical id, runs `generation adopt --dry-run` there, and
     removes the copy.
   - A copy of a running router's state is only a preview: the binding dry
     run is step 8's.
5. **The window opens.** Fingerprint and match again, as in step 1, with
   `--step 2 --label r2`. It must print `MIGRATE` with the same reason. Then, at once,
   with no other step between them:
   - `sha256sum <the live config>`, recorded;
   - `cp -p <the live config> <run_dir>/r2-pre-migration-config.json`;
   - `docker inspect -f '{{.Name}} {{.HostConfig.RestartPolicy.Name}}
     {{.HostConfig.RestartPolicy.MaximumRetryCount}}' <the container Id the
     file records>`, recorded: the old container's name (without its leading
     `/`) and its whole restart policy, which back-out B restores exactly;
   - `docker stop <that Id>`;
   - `docker update --restart no <that Id>`, so that a daemon restart cannot
     start it beside the new router;
   - `docker rename <that Id> <router.container>-pre-registry`, so that
     step 10 can start the new router under `router.container`. The rename
     fails if that name is taken, and then R2 stops here (back-out B).

   Then `python3 amap-sandy.py router-migrate baseline --preview <step 4's
   file> --apply`. It is read-only and takes the drain lock. For each
   instance to be adopted it records, in `<run_dir>/router-migrate-baseline-
   <at>.json`, the sha256 of its legacy `first-seen.json` and the private
   results that already record a first sight's rejection
   (`quarantined_pre_approval`). Step 11 compares against this file.
   It STOPs unless the state directory and each instance's directory are
   still the ones step 4 recorded, so it runs only here, before any move.
   R2 does not migrate approval-only state: an instance to be adopted whose
   legacy state has no `first-seen.json` STOPs the baseline, before
   anything has moved. Take back-out B, and then, by the layout the
   baseline names:
   - under the instance's name, with an `approval.json` that carries a
     valid `approved_ts`: let the old router poll that instance once (an
     ordinary drain; its first sight writes `first-seen.json` from the
     approval), and run R2 again from step 1;
   - under the instance's name, with no valid `approved_ts`: R2 cannot
     adopt it; it is the maintainers' call (fence-legacy);
   - under its logical id: R2 does not support it, and it is the
     maintainers' call. Start nothing for it: a name-keyed old router never
     reads the logical-id directory, so a poll would take a fresh first
     sight beside it.
6. **The live config.** `python3 amap-sandy.py install --apply`. Then
   `sha256sum <the live config>` must equal the sha256 step 2 printed.
   Every later step refuses a config whose sha256 is not the plan's.
7. **Move.** `python3 amap-sandy.py router-migrate move --config <the live
   config> --preview <step 4's file> --apply`.
   - It takes the router's drain lock first (`state_dir/.router.lock`), and
     STOPs if a router holds it. On a host whose Docker engine runs in a VM,
     the lock does not reach the container, and step 5's stop is the only
     guard.
   - It STOPs before any move unless the layout is still exactly the
     plan's, so a name-keyed directory that appeared since step 4 stops it.
   - For each planned name, it moves `<state_dir>/<name>` to
     `<state_dir>/<logical_id>` by an atomic rename that never replaces an
     entry, and only when the name's entry is the directory the plan
     recorded. `state_dir` is the same path on the host and in the
     container: `run.sh` mounts it at its own path.
   - Each move is journaled and published durably before it is made, and
     marked done after. The first failure stops the step and names the
     journal.
8. **Check.** `python3 amap-sandy.py router-migrate check --config <the live
   config> --preview <step 4's file> --reason "<text>" --apply`.
   - It STOPs unless every planned instance's state is now under its
     logical id, with no name-keyed state left.
   - It STOPs when the binding (logical id, adapter, stable key and binding
     sequence), the root or the verb differs from the preview's, or when
     any instance shows transport history: a counter, in-flight entries,
     transport verdicts or malformed anchors.
   - The count of local anchors may differ from the preview's, because the
     running router went on delivering. `--no-transport-history=N` attests
     that an instance never had a transport route, covering the N local
     anchors that remain at this dry run. The check takes N only from this
     dry run's own refusal text, and records it.
9. **Adopt.** `python3 amap-sandy.py router-migrate adopt --config <the live
   config> --check <step 8's file> --reason "<text>" --apply`. Once its
   first adopt has written its files, R2 only goes forward (back-out D); a
   STOP before that, at the fresh plan or the state check, still has C then
   B.
   - Before each adopt it takes a fresh read-only plan, which must name the
     checked root, and it checks each instance's state is the recorded one.
   - After the adopts, four records of each root must be one (path,
     device and inode): the adopt's own journal (`migration.json`), the
     generation it made (`generations.json`), the root recorded at step 8,
     and the root as the router opens it now, read inside the router's
     image. On a mismatch it STOPs: do not start the router.
10. **Start.** First, `python3 amap-sandy.py router-migrate verify --config
    <the live config> --check <step 8's file> --apply`, which repeats step
    9's four-way root check and the context, binding and state checks, and
    changes nothing. Then
    at once, with no other step between them, `docker/run.sh --config <the
    live config> --image <router.image.digest> --name <router.container>
    --detach`, from the hop checkout.
11. **Accept.** Wait for a poll at least 3 s after the start. Then:
    - `python3 amap-sandy.py router-fingerprint --step 0 --label r2 --apply`
      and its `--match` must print `MEASURED` (`measured`): the pinned
      router, on its registry configuration, with every instance's state in
      the generation layout under the registry;
    - `python3 amap-sandy.py router-migrate accept --config <the live
      config> --check <step 8's file> --baseline <step 5's baseline file>
      --apply` must exit 0 and print `router-migrate accept: ACCEPT: <its
      record>`. It is read-only. It re-reads the registry, which must still
      resolve every instance R2 moved or adopted, and for each adopted
      instance it checks, under `state_dir/<logical_id>/`:
      - the generation the adopt made (`migration.json`'s `gen`) is still
        `generations.json`'s current and last one. A fresh first sight,
        which quarantines waiting requests, needs a new generation;
      - `gen-<current>/first-seen.json` has the sha256 the baseline
        recorded for the legacy marker: the adopt moved it, byte for byte;
      - `gen-<current>/results/` holds no private result recording a first
        sight's rejection (`quarantined_pre_approval`) beyond those the
        baseline recorded, which the adopt carried over. The private result
        is the record: `gen-<current>/quarantine/` is written best-effort,
        and the agent may delete a result in its outbox once read, so
        neither proves an absence. The accept record lists the quarantine
        directory's entries as corroboration only;
    - as corroboration only (logs are not durable), `docker logs
      <router.container> 2>&1 | grep -F "': FIRST SIGHT"` prints nothing;
    - for each migrated instance, `docker/run.sh --config <the live config>
      --image <router.image.digest> --name amap-router-migrate -- shell
      python3 -m router --config <the live config> quarantine list <name> >
      <run_dir>/r2-ingress-<name>.txt`, from the hop checkout, as
      corroboration only: it must exit 0 with nothing on stderr (the read
      worked), and its listing is kept, not judged. It reads the INGRESS
      quarantine (inbound cross-host items a first poll may legitimately
      quarantine), plus the host's own intakes whatever the name, so an
      entry there is not an R2 failure, and it says nothing about the
      waiting outbox requests. It is read-only and takes no lock, so the
      listing is a snapshot, not a barrier;
    - `python3 amap-sandy.py verify` must pass.
12. **Only then**, `docker rm <the old container's Id>`, by the Id step 5's
    file records.

**R2's back-outs**, by the point reached. After step 7's first move, the
old container is never started except through back-out C, then B.

- A. Before step 5's stop: nothing has changed. The run directory's files
  are inert.
- B. After the stop, before step 7's first move:
  1. If step 6 ran, `cp -p <run_dir>/r2-pre-migration-config.json <the live
     config>`, and check that `sha256sum` equals step 5's record.
  2. `docker rename <that Id> <its old name, as step 5 recorded it>`.
  3. `docker update --restart <its restart policy, as step 5 recorded it>
     <that Id>`: the policy's name, or `on-failure:<count>` when step 5
     recorded `on-failure` with a count above 0.
  4. `docker start <that Id>`.
- C. After a move, before step 9:
  1. `python3 amap-sandy.py router-migrate move --config <the live config>
     --reverse <step 7's journal> --apply`. It moves each journaled
     directory back, newest first; an entry never moved, or already moved
     back, is left as it is, so the reverse can be run again until it
     completes. It refuses, and moves nothing, once any journaled directory
     holds a migration.json or a generations.json: an adopt has begun, and
     back-out D applies.
  2. Then back-out B.
- D. Once any migrated directory holds a `migration.json` or a
  `generations.json` (an adopt has begun): forward only. The adopted state is in the
  generation layout under the registry, which the old router never reads.
  Starting the old container now would take a fresh first sight and
  quarantine every waiting request, and leave state under both the name
  and the logical id, which the pinned router then holds as
  `state_conflict`.
  - Re-running step 9 resumes an interrupted adopt: until it completes, the
    router holds the instance as `state_layout_conflict`.
  - If the pinned router cannot start, keep the old container stopped and
    stop: the window stays open, and the router's maintainers decide the
    next step. `generation fence-legacy` exists only for an origin that
    cannot be vouched for.

### The local router's fresh start (FS), instead of R2

A fresh start is the other way onto the pinned router, for a host whose
operator chose it over R2's migration. The pinned router starts on a NEW,
empty `state_dir`. The old router's `state_dir` (OLD) is never written: it
is archived while the old router is stopped and kept in place, untouched,
as the back-out's state. Nothing is mapped, moved or adopted.

Every instance takes a fresh first sight on the new router's first poll,
and a fresh first sight quarantines whatever request is waiting. So a fresh
start runs only while every outbox is quiet (F3 and F4b below).

FS needs what R2 needs (the hop link, the hop root, the hop checkout at its
pin, the router's image, and every configured instance enrolled in the host
registry), plus:
- **a router config at its default place.** This section is written for a
  host whose live config is `install`'s default,
  `$SANDY_HOME/features/amap/router.json`, with no `--router-config-path`.
  A host that names its router config elsewhere follows its own reviewed
  fresh-start plan, which uses this section's blocks, because there the
  first install that names the path must be a plain `install --apply` (a
  `--render-to` with an unrecorded path is refused), and its start line is
  the one its host setup names.
- **two distinct state directories.** OLD is the `state_dir` the live config
  names now. NEW is the one the new configuration names
  (`install --state-dir <NEW>`). They must be physically distinct: their
  real paths and their (device, inode) pairs differ, neither contains the
  other, neither lies inside `instances_dir` (resolved physically, so a
  symlinked parent cannot hide it) nor contains it, and no bind source of
  the old router or the hub-link router contains both. The separation block
  below checks this at F2 and again at F5. A shared `state_dir` is not a
  fresh start, and FS refuses it. Make NEW before F2 as the router's
  account, `mkdir -m 0700 <NEW>`, refusing an existing path: `install`
  leaves an existing directory's mode alone, and the EMPTY witness at F5
  requires that account's own 0700.
- **an old router with no in-flight state.** The quiet block below checks
  both halves: every outbox holds only `results/` and `processed/`, and OLD
  holds no file under a `pending/`, `inflight/`, `dsn-pending/` or
  `reuse-pending/` directory (a pre-registry router keeps no other
  work-bearing set). An old router that holds such state is out of FS's
  scope.

**The quiet predicate.** For every configured instance,
`instances/<slug>/outbox/` holds, at its top level, only the directories
`results/` and `processed/`. Any other entry means NOT quiet: a
`req-*.json`, a `req-*.attachments/`, a connector's temporary file, or
anything unexpected. Every listing must succeed: an outbox that cannot be
listed is NOT quiet. Producers, the operator's own traffic included, hold
from F3 until F7's acceptance passes. That is a coordination premise, not a
lock: F4b's repeat is what catches a request that arrives after the stop.
The same block checks FS's scope: OLD holds no file under a `pending/`,
`inflight/`, `dsn-pending/` or `reuse-pending/` directory: any entry below
one that is not a directory (a file, a symlink, a socket) is work. It also
refuses an empty SLUGS, and an outbox under `instances_dir` whose instance
SLUGS does not name. A search that fails is not an empty one.

```sh
( OST='<OLD: the state_dir the live config names>'
  INST='<instances_dir>'; SLUGS='<every configured instance, space separated>'
  stop() { printf 'fs-quiet: STOP: %s\n' "$1" >&2; exit 1; }
  [ -n "$SLUGS" ] || stop "no instance named: nothing would be checked"
  for o in "$INST"/*/outbox; do
    [ -e "$o" ] || [ -h "$o" ] || continue
    s=${o%/outbox}; s=${s##*/}
    case " $SLUGS " in *" $s "*) ;; *) stop "$s has an outbox and is not in SLUGS: it would not be checked" ;; esac
  done
  set -f
  for s in $SLUGS; do
    o="$INST/$s/outbox"
    [ -d "$o" ] && [ ! -h "$o" ] || stop "$s: no outbox directory $o"
    e=$(find "$o" -mindepth 1 -maxdepth 1 ! -name results ! -name processed -print -quit) \
      || stop "$s: the outbox cannot be listed: not quiet"
    [ -z "$e" ] || stop "$s: ${e##*/} is waiting: not quiet"
    e=$(find "$o" -mindepth 1 -maxdepth 1 \( -name results -o -name processed \) ! -type d -print -quit) \
      || stop "$s: the outbox cannot be listed: not quiet"
    [ -z "$e" ] || stop "$s: ${e##*/} is not a directory: not quiet"
  done
  OP=$(cd -P -- "$OST" && pwd -P) || stop "OLD $OST cannot be resolved: its in-flight state is not established"
  w=$(find "$OP" ! -type d \( -path '*/pending/*' -o -path '*/inflight/*' -o -path '*/dsn-pending/*' \
        -o -path '*/reuse-pending/*' \) -print -quit) || stop "OLD cannot be searched: its in-flight state is not established"
  [ -z "$w" ] || stop "OLD holds in-flight state ($w): outside a fresh start's scope"
  printf 'fs-quiet: OK every outbox holds only results/ and processed/, and OLD holds no in-flight state\n' )
```

**The separation check.** It reads NEW by `lstat` alone, so NEW itself
needs no search permission for the operator: only its parent is resolved.
It refuses a NEW that is a symlink. NEW is also kept apart from the hop
root: never the hop root itself, nor inside it, nor containing it, so the
hop tree holds only the hub-link router's own top-level names. The hop root
may not exist yet (a host whose hop leg comes later): it is then resolved
through its parent, the path-wise checks still apply, and only the (device,
inode) comparison is skipped. The snapshot block and the OLD check resolve
it the same way.

```sh
( OST='<OLD: the state_dir the live config names>'; NST='<NEW: the state_dir the new configuration names>'
  INST='<instances_dir>'; HOP='<the hop root: its host path>'; OLD='<the old container Id>'
  HUB='<the hub-link router container>'
  stop() { printf 'fs-separate: STOP: %s\n' "$1" >&2; exit 1; }
  case "$NST" in /*) ;; *) stop "NEW $NST is not an absolute path" ;; esac
  case "$NST/" in //|*/./*|*/../*|*//*) stop "NEW $NST is not a normalised path, or is the root directory" ;; esac
  OP=$(cd -P -- "$OST" && pwd -P) || stop "no OLD $OST"
  ND=$(cd -P -- "$(dirname -- "$NST")" && pwd -P) || stop "no parent for NEW $NST"
  NP=$ND/$(basename -- "$NST")
  [ -d "$NP" ] && [ ! -h "$NP" ] || stop "NEW $NST is not a directory, or is a symlink"
  [ "$OP" != "$NP" ] || stop "OLD and NEW are the same path: a fresh start needs two"
  oi=$(stat -c '%d:%i' -- "$OP") || stop "OLD cannot be stat'ed"
  ni=$(stat -c '%d:%i' -- "$NP") || stop "NEW cannot be stat'ed"
  [ "$oi" != "$ni" ] || stop "OLD and NEW are one directory under two names"
  case "$NP/" in "$OP"/*) stop "NEW lies under OLD" ;; esac
  case "$OP/" in "$NP"/*) stop "OLD lies under NEW" ;; esac
  INP=$(cd -P -- "$INST" && pwd -P) || stop "no instances_dir $INST"
  case "$NP/" in "$INP"/*) stop "NEW lies under instances_dir" ;; esac
  case "$INP/" in "$NP"/*) stop "instances_dir lies under NEW" ;; esac
  case "$HOP" in /*) ;; *) stop "the hop root $HOP is not an absolute path" ;; esac
  case "$HOP/" in //|*/./*|*/../*|*//*) stop "the hop root $HOP is not a normalised path, or is the root directory" ;; esac
  HD=$(cd -P -- "$(dirname -- "$HOP")" && pwd -P) || stop "no parent for the hop root $HOP"
  HP=$HD/$(basename -- "$HOP"); HPM=
  if [ -e "$HP" ] || [ -h "$HP" ]; then
    [ -d "$HP" ] && [ ! -h "$HP" ] || stop "the hop root $HOP is not a directory, or is a symlink"
    HPM=$HP
  fi
  [ "$NP" != "$HP" ] || stop "NEW is the hop root"
  if [ -n "$HPM" ]; then
    hi=$(stat -c '%d:%i' -- "$HP") || stop "the hop root cannot be stat'ed"
    [ "$ni" != "$hi" ] || stop "NEW and the hop root are one directory under two names"
  fi
  case "$NP/" in "$HP"/*) stop "NEW lies under the hop root" ;; esac
  case "$HP/" in "$NP"/*) stop "the hop root lies under NEW" ;; esac
  MNT=$(docker inspect -f '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}{{"\n"}}{{end}}{{end}}' "$OLD") \
    || stop "the old router's mounts cannot be read"
  hub=$(docker ps -a -q --no-trunc --filter "name=^/$HUB\$") || stop "docker cannot list containers"
  if [ -n "$hub" ]; then
    HM=$(docker inspect -f '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}{{"\n"}}{{end}}{{end}}' "$HUB") \
      || stop "the hub-link router's mounts cannot be read"
    MNT=$(printf '%s\n%s' "$MNT" "$HM")
  fi
  IFS=$(printf '\n.'); IFS=${IFS%.}; set -f
  for m in $MNT; do
    [ -d "$m" ] || continue
    mp=$(cd -P -- "$m" && pwd -P) || stop "the mount source $m cannot be resolved"
    case "$OP/" in "$mp"/*) case "$NP/" in "$mp"/*) stop "the mount source $m contains both OLD and NEW" ;; esac ;; esac
  done
  printf 'fs-separate: OK OLD %s (%s) and NEW %s (%s) are distinct\n' "$OP" "$oi" "$NP" "$ni" )
```

Run every step as the operator, except where a step names the account that
runs the router. Each step's STOP ends FS at that point, and the back-out
for that point (below) applies.

**The ledger's two kinds of line.** Each `printf … >> <run_dir>/fs-ledger.txt`
below is written in its checked form, `printf … >> <run_dir>/fs-ledger.txt
|| echo 'STOP: the ledger write failed: run nothing further' >&2`. On that STOP, run nothing further. The form only echoes and never `exit`s, so a line pasted into an interactive shell does not close it.
- An INTENT line (`F4c started`, `F5 started`, `F6 attempted`) is written
  BEFORE the action it records. A failed write stops FS before that
  action, so no action runs unrecorded. Above all, F6's start runs only
  after `F6 attempted` is written: a start the ledger does not show could
  otherwise be taken for one that never happened, and offered OLD's
  back-out.
- A COMPLETION line (`F4 stopped`, `F4c ok`) is written only AFTER the step
  it records has succeeded and been checked: `F4 stopped` after the
  rename, and `F4c ok` after the snapshot block's `fs-snapshot: OK` and
  `fs-lanes: OK` lines. It is never written early. A missing completion
  line sends back-out B to the branch before it.

- **F1 Fingerprint.** `python3 amap-sandy.py router-fingerprint --step 0
  --label fs --apply`, then `python3 amap-sandy.py router-fingerprint
  --match <the file it wrote>`, each with `--container <its current name>`.
  The match must print `MIGRATE` and exit 3, as R2's step 1. `MEASURED`
  means the router is already the pinned one. Any other result names its
  own remedy, and FS does not start.
- **F2 Render.** `python3 amap-sandy.py --state-dir <NEW> install --render-to
  <run_dir>/fs-config.json --apply`, with the sha256 it prints recorded, as
  R2's step 2. Then the separation block.
- **F3 Quiet**, with the old router still running: the quiet block. If an
  outbox is not quiet, wait for the old router's polls and run it again.
  An outbox that will not settle, or any in-flight state in OLD, stops FS
  here (back-out A).
- **F4 Stop.** Fingerprint and match again, with `--step 2 --label fs`. It
  must print `MIGRATE` with the same reason. Then R2's step 5 stop, at
  once, with no other step between them: the live config's `sha256sum`,
  recorded; `cp -p <the live config> <run_dir>/fs-pre-start-config.json`;
  the recorded `docker inspect` of the old container's name and restart
  policy; the recorded `docker inspect -f '{{json .Config.Env}} {{json
  .Mounts}}'` of it, which names its `ROUTER_CONFIG` and the bind source
  mounted there (the config it was started with); `docker stop`; `docker update --restart no`; and
  `docker rename <that Id> <router.container>-pre-registry`. Then the
  ledger's first line, written to a ledger that must not exist yet (each FS
  attempt uses a new run_dir), `( set -C; printf 'F4 stopped %s %s %s\n'
  <that Id> <its recorded name> <its recorded policy> > <run_dir>/fs-ledger.txt )
  || echo 'STOP: the ledger write failed: run nothing further' >&2`. `set -C` refuses an existing ledger rather than truncating it.
- **F4b Quiet again**, after the stop: the quiet block once more. Not quiet
  means a request arrived after F3, or OLD holds in-flight state. Clear nothing, start nothing: take
  back-out B (the old router drains it), then start FS again from F1.
- **F4c The snapshot**: `printf 'F4c started\n' >> <run_dir>/fs-ledger.txt
  || echo 'STOP: the ledger write failed: run nothing further' >&2`, then the snapshot block below, of OLD, then, only after its
  `fs-snapshot: OK` and `fs-lanes: OK` lines, `printf 'F4c ok %s\n' <BK> >>
  <run_dir>/fs-ledger.txt || echo 'STOP: the ledger write failed: run nothing further' >&2`.
- **F5 The live config.** `printf 'F5 started\n' >> <run_dir>/fs-ledger.txt
  || echo 'STOP: the ledger write failed: run nothing further' >&2`, then `python3 amap-sandy.py --state-dir <NEW> install --apply`. Its live config's `sha256sum` must equal F2's. A mismatch stops
  FS before any start: back-out B. Then the separation block again, and the
  EMPTY witness: as the account that runs the router,
  ```sh
  ( NST='<NEW>'
    stop() { printf 'fs-empty: STOP: %s\n' "$1" >&2; exit 1; }
    [ -d "$NST" ] && [ ! -h "$NST" ] || stop "NEW is not a directory, or is a symlink"
    me=$(id -u) || stop "the account cannot be read"
    o=$(stat -c '%u %a' -- "$NST") || stop "NEW cannot be stat'ed"
    [ "$o" = "$me 700" ] || stop "NEW is not private to the router's account ($o, not $me 700)"
    left=$(ls -A -- "$NST") || stop "NEW cannot be listed: its emptiness is not established"
    [ -z "$left" ] || stop "NEW is not empty"
    printf 'fs-empty: OK %s is empty at %s\n' "$NST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" )
  ```
  NEW must be the router account's own 0700 directory, not a symlink, and
  empty. A listing that fails is never proof of emptiness.
- **F6 Start.** `printf 'F6 attempted\n' >> <run_dir>/fs-ledger.txt
  || echo 'STOP: the ledger write failed: run nothing further' >&2`, then
  `docker/run.sh --config <the live config> --image
  <router.image.digest> --name <router.container> --detach`, from the hop
  checkout, as the account that runs the router. After this start there is
  no automatic back-out (below).
- **F7 Accept.** Wait for a poll at least 3 s after the start. Then, each
  read from durable state; a read that fails stops FS:
  - `router-fingerprint --step 0 --label fs --apply` and its `--match` print
    `MEASURED` (`measured`);
  - the router's `status.json`: `registry.state` is `ok`, `registry.held` is
    `{}`, and every configured instance has a `generations` entry;
  - each instance's `<logical_id>/generations.json` holds exactly one
    generation, its reason `first`, and it is the current one;
  - its `gen-<current>/first-seen.json` has an empty `outbox_snapshot`, and
    `gen-<current>/results/` holds no `quarantined_pre_approval` result:
    F3 and F4b proved nothing was waiting;
  - `python3 amap-sandy.py verify` passes.

  As corroboration only (logs are not durable): `docker logs
  <router.container> 2>&1 | grep -F "FIRST SIGHT"` shows each instance's
  first sight with 0 requests.
- **F8 The old container stays**, stopped, named
  `<router.container>-pre-registry` with restart policy `no`, through the
  retention below.

**The snapshot** (F4c). It is OLD whole, taken while the old router is
stopped, as R2's step 5 snapshot: per instance `first-seen.json`,
`results/`, `delivered/`, `quarantine/`, `pending/` and `audit/`, plus
`.router.lock` and `status.json`. It is the record of OLD for back-out B's
check. The instance lanes are archived beside it into `fs-lanes.tar`, a
best-effort, non-atomic live archive that is an ARCHIVE ONLY and never
restore input. Both hold message content, so they stay the operator's
alone: mode 0600 in a new 0700 directory outside OLD, NEW,
`instances_dir`, the hop root and every path a container mounts. They never
leave the host and are never attached to a message. Run it as the operator,
in one POSIX shell with GNU coreutils and GNU tar (a Linux host), filling in
the seven values.
- Choosing `BK`, a new directory private to the operator on the host's own
  disk, which no container mounts, is the operator's precondition. The block
  supports it but cannot prove it: it refuses a target under OLD, NEW,
  `instances_dir`, the hop root, or any bind source of the old router or
  the hub-link router (an absent hub-link router adds none), but it cannot
  see every other container's mounts. A bind source that is the root
  directory, or that is neither a resolvable directory nor an existing
  file, stops it.
- Its before-and-after listing of OLD is a change detector, not proof that
  the content is unchanged. The snapshot is consistent because the old
  router is stopped and nothing else writes OLD. `tar -d` then proves the
  archive equals the tree.
- Every observation is checked by its own exit status before its output is
  believed.
- It assumes the router's one operator uid owns the whole of OLD (its 0600
  files and 0755 directories), so the operator's tar records bytes and
  modes. State owned by another uid is outside it.

```sh
( ST='<OLD>'; NST='<NEW>'; INST='<instances_dir>'; HOP='<the hop root: its host path>'
  BK='<a new, operator-private, host-only directory for the snapshot>'
  OLD='<the old container Id, as F4 records it>'; HUB='<the hub-link router container>'
  umask 077
  stop() { printf 'fs-snapshot: STOP: %s\n' "$1" >&2; exit 1; }
  manifest() {  # every entry: type, mode, owner, size (link target for a link; none for a directory), name; NUL-ended, sorted
    ( cd -- "$1" && find . \( -type d -printf '%y %m %U %G - %p\0' \) -o \( -type l -printf '%y %m %U %G %l %p\0' \) \
        -o -printf '%y %m %U %G %s %p\0' ) > "$2.unsorted" || return 1
    LC_ALL=C sort -z -o "$2" -- "$2.unsorted" && rm -- "$2.unsorted"
  }
  s=$(docker inspect -f '{{.State.Running}} {{.HostConfig.RestartPolicy.Name}}' "$OLD") \
    || stop "the old router cannot be inspected"
  [ "$s" = "false no" ] || stop "the old router is not shown stopped with restart policy no"
  STP=$(cd -P -- "$ST" && pwd -P) || stop "no state_dir $ST"
  case "$NST" in /*) ;; *) stop "NEW $NST is not an absolute path" ;; esac
  case "$NST/" in //|*/./*|*/../*|*//*) stop "NEW $NST is not a normalised path, or is the root directory" ;; esac
  ND=$(cd -P -- "$(dirname -- "$NST")" && pwd -P) || stop "no parent for NEW $NST"
  NP=$ND/$(basename -- "$NST")
  INP=$(cd -P -- "$INST" && pwd -P) || stop "no instances_dir $INST"
  case "$HOP" in /*) ;; *) stop "the hop root $HOP is not an absolute path" ;; esac
  case "$HOP/" in //|*/./*|*/../*|*//*) stop "the hop root $HOP is not a normalised path, or is the root directory" ;; esac
  HD=$(cd -P -- "$(dirname -- "$HOP")" && pwd -P) || stop "no parent for the hop root $HOP"
  HP=$HD/$(basename -- "$HOP"); HPM=
  if [ -e "$HP" ] || [ -h "$HP" ]; then
    [ -d "$HP" ] && [ ! -h "$HP" ] || stop "the hop root $HOP is not a directory, or is a symlink"
    HPM=$HP
  fi
  [ "$STP" != / ] || stop "state_dir is the root directory"
  case "$HP/" in "$STP"/*) stop "the hop root lies under state_dir" ;; esac
  case "$STP/" in "$HP"/*) stop "state_dir lies under the hop root" ;; esac
  MNT=$(docker inspect -f '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}{{"\n"}}{{end}}{{end}}' "$OLD") \
    || stop "the old router's mounts cannot be read"
  hub=$(docker ps -a -q --no-trunc --filter "name=^/$HUB\$") || stop "docker cannot list containers"
  if [ -n "$hub" ]; then
    HM=$(docker inspect -f '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}{{"\n"}}{{end}}{{end}}' "$HUB") \
      || stop "the hub-link router's mounts cannot be read"
    MNT=$(printf '%s\n%s' "$MNT" "$HM")
  else
    printf 'fs-snapshot: no container %s: it adds no mounts\n' "$HUB"
  fi
  BKD=$(cd -P -- "$(dirname -- "$BK")" && pwd -P) || stop "no parent for $BK"
  BKP=$BKD/$(basename -- "$BK")
  case "$BKP/" in "$NP"/*) stop "$BK lies under NEW" ;; esac
  IFS=$(printf '\n.'); IFS=${IFS%.}; set -f
  case "$BKP/" in "$HP"/*) stop "$BK lies under the hop root" ;; esac
  for m in $STP $INP $HPM $MNT; do
    if [ -d "$m" ]; then mp=$(cd -P -- "$m" && pwd -P) || stop "the mount source $m cannot be resolved"
    elif [ -f "$m" ]; then mp=$m
    else stop "the mount source $m is neither a directory nor a file"; fi
    [ "$mp" != / ] || stop "a mount source is the root directory: nothing can lie outside it"
    case "$BKP/" in "$mp"/*) stop "$BK lies under $m" ;; esac
  done
  IFS=$(printf ' \t\n.'); IFS=${IFS%.}; set +f
  mkdir -m 0700 -- "$BKP" || stop "$BK already exists, or cannot be made"
  before=$(cd -- "$STP" && ls -lnAR --full-time .) || stop "state_dir cannot be listed"
  tar --numeric-owner -cpf "$BKP/fs-state.tar" -C "$STP" . || stop "tar failed"
  after=$(cd -- "$STP" && ls -lnAR --full-time .) || stop "state_dir cannot be listed"
  [ "$before" = "$after" ] || stop "state_dir changed during the tar: something else writes it"
  tar --numeric-owner -dpf "$BKP/fs-state.tar" -C "$STP" > /dev/null || stop "the snapshot is not the tree"
  manifest "$STP" "$BKP/fs-state.manifest" || stop "the state's manifest cannot be written"
  ( cd -- "$BKP" && sha256sum fs-state.manifest > fs-state.manifest.sha256 ) || stop "sha256sum failed"
  chmod 0600 -- "$BKP/fs-state.tar" "$BKP/fs-state.manifest" || stop "chmod failed"
  ( cd -- "$BKP" && sha256sum fs-state.tar > fs-state.tar.sha256 ) || stop "sha256sum failed"
  ( cd -- "$BKP" && sha256sum -c --strict --status fs-state.tar.sha256 ) || stop "the snapshot does not read back"
  n=$(wc -c < "$BKP/fs-state.tar") || stop "the snapshot cannot be measured"
  case $n in ""|*[!0-9]*) stop "the snapshot cannot be measured" ;; esac
  h=$(cut -d' ' -f1 "$BKP/fs-state.tar.sha256") || stop "the snapshot's sha256 cannot be read"
  case $h in ""|*[!0-9a-f]*) stop "the snapshot's sha256 cannot be read" ;; esac
  [ ${#h} -eq 64 ] || stop "the snapshot's sha256 cannot be read"
  printf 'fs-snapshot: OK %s bytes %s %s\n' "$n" "$h" "$BKP/fs-state.tar"
  lanes=$(cd -- "$INP" || exit 1; for d in */inbox */peer */outbox; do [ -d "$d" ] && printf '%s\n' "$d"; done; exit 0) \
    || stop "instances_dir cannot be read"
  [ -n "$lanes" ] || stop "instances_dir holds no lane"
  printf '%s\n' "$lanes" > "$BKP/fs-lanes.list" || stop "the lane list cannot be written"
  ( cd -- "$INP" && tar --numeric-owner -cpf "$BKP/fs-lanes.tar" -T "$BKP/fs-lanes.list" ) 2> "$BKP/fs-lanes.tar.log"
  rc=$?
  cat -- "$BKP/fs-lanes.tar.log" >&2 || stop "tar's warnings cannot be read back"
  [ "$rc" -le 1 ] || stop "the lane archive failed"
  rm -- "$BKP/fs-lanes.list" || stop "the lane list cannot be removed"
  chmod 0600 -- "$BKP/fs-lanes.tar" || stop "chmod failed"
  ( cd -- "$BKP" && sha256sum fs-lanes.tar > fs-lanes.tar.sha256 ) || stop "sha256sum failed"
  ( cd -- "$BKP" && sha256sum -c --strict --status fs-lanes.tar.sha256 ) || stop "the lane archive does not read back"
  n=$(wc -c < "$BKP/fs-lanes.tar") || stop "the lane archive cannot be measured"
  case $n in ""|*[!0-9]*) stop "the lane archive cannot be measured" ;; esac
  h=$(cut -d' ' -f1 "$BKP/fs-lanes.tar.sha256") || stop "the lane archive's sha256 cannot be read"
  case $h in ""|*[!0-9a-f]*) stop "the lane archive's sha256 cannot be read" ;; esac
  [ ${#h} -eq 64 ] || stop "the lane archive's sha256 cannot be read"
  printf 'fs-lanes: OK %s bytes %s %s (best-effort, non-atomic live archive: entries may be omitted or contain changing data; tar exit %s; its warnings in fs-lanes.tar.log)\n' \
    "$n" "$h" "$BKP/fs-lanes.tar" "$rc" )
```

The lane archive is taken with agents running: entries may be omitted or
contain changing data, and its sha256 proves the archive file's integrity,
not complete lane coverage. GNU tar's exit 1 (a file changed, or was
removed, as it was read) is recorded, not refused, and tar's warnings are
kept in `fs-lanes.tar.log` and shown. Record the `fs-snapshot: OK` and
`fs-lanes: OK` lines (each byte count, sha256 and path), tar's exit code and
any warnings it showed, in the run log. Any `STOP` line ends FS here: take
back-out B. The block refuses a directory that already exists, so a
snapshot is never added to or replaced.

**FS's back-outs**, by the point reached:
- **A. Before F4's stop:** nothing has changed. The run directory's files
  are inert.
- **B. After the stop, before F6's start:**
  1. The phase block, below. It reads the ledger and names the branch:
     - `BEFORE-VALID-SNAPSHOT` (F4b found work, or F4c did not complete):
       OLD was never written and no archive is needed. Skip the OLD check.
     - `AFTER-SNAPSHOT`: the OLD check, below. OLD must still be the
       snapshot, entry for entry; it restores OLD from the snapshot only
       when it is not.
     Any other ledger, an attempted F6, or an old container that is not
     exactly as F4 left it STOPs for reconciliation.
  2. If the ledger has `F5 started`, `cp -p <run_dir>/fs-pre-start-config.json
     <the old container's config: the bind source F4 recorded at its
     ROUTER_CONFIG>`, and check that `sha256sum` equals F4's record.
  3. R2's back-out B steps 2-4: `docker rename` the old container to its
     recorded name, `docker update --restart` its recorded policy, and
     `docker start` it by its Id.

  NEW is left as it is. Nothing in the lanes is touched.
- **After F6's start: no automatic back-out.** The pinned router admits
  every resolved instance on its first poll, and may write the hop root from
  then on. Stop it, set its restart policy to `no`, rename it
  `<router.container>-fs-failed`, and keep it with its `docker inspect` and
  logs. Leave its state, the hop tree and the lanes in place: nothing is
  wiped, restored or replayed. Any return to the old router is the router's
  and the hop tree's maintainers' decision, recording what the new router
  admitted.

**The phase block**, back-out B's step 1:

```sh
( LEDGER='<fs-ledger.txt in the run directory>'; OLD='<the old container Id, as F4 records it>'; NEW='<router.container>'
  stop() { printf 'fs-phase: STOP: %s\n' "$1" >&2; exit 1; }
  absent() { ids=$(docker ps -a -q --no-trunc --filter "name=^/$1\$") || stop "docker cannot list containers"; [ -z "$ids" ]; }
  [ -f "$LEDGER" ] && [ ! -h "$LEDGER" ] || stop "no ledger $LEDGER: reconcile by hand"
  seq=$(cut -d' ' -f1,2 -- "$LEDGER") || stop "the ledger cannot be read"
  seq=$(printf '%s' "$seq" | tr '\n' ';')
  case $seq in
    *"F6 attempted"*) stop "F6 was attempted: FS has no automatic back-out" ;;
    "F4 stopped"|"F4 stopped;F4c started") branch=BEFORE-VALID-SNAPSHOT; cfg=no ;;
    "F4 stopped;F4c started;F4c ok") branch=AFTER-SNAPSHOT; cfg=no ;;
    "F4 stopped;F4c started;F4c ok;F5 started") branch=AFTER-SNAPSHOT; cfg=yes ;;
    *) stop "the ledger is not a recognised phase sequence ($seq): reconcile" ;;
  esac
  rid=$(sed -n '1s/^F4 stopped \([^ ]*\) .*/\1/p' -- "$LEDGER") || stop "the ledger cannot be read"
  [ "$rid" = "$OLD" ] || stop "the ledger names the old container $rid, not $OLD"
  absent "$NEW" || stop "a container is named $NEW: the new router may have started"
  absent "$NEW-fs-failed" || stop "a container is named $NEW-fs-failed: the new router started"
  s=$(docker inspect -f '{{.Name}} {{.State.Running}} {{.HostConfig.RestartPolicy.Name}}' "$OLD") \
    || stop "the old container cannot be inspected"
  [ "$s" = "/$NEW-pre-registry false no" ] || stop "the old container is not exactly as F4 left it ($s)"
  bk=$(sed -n 's/^F4c ok //p' -- "$LEDGER") || stop "the ledger cannot be read"
  printf 'fs-phase: %s; restore the config: %s%s\n' "$branch" "$cfg" "${bk:+; the OLD check takes BK=$bk}" )
```

**The OLD check**, back-out B's step 1 on the `AFTER-SNAPSHOT` branch, as the operator in one POSIX shell
with GNU coreutils and GNU tar. It runs only while no container is named
`<router.container>` or `<router.container>-fs-failed`: `docker/run.sh`
creates and starts the router in one step, so either name means F6 ran, and
the block refuses. A container's absence is a `docker ps -a` that succeeds
and lists nothing. When OLD still equals the snapshot, entry for entry
(the snapshot's recorded manifest of every entry's type, mode, owner, size
and name, and `tar -d` for the contents), it changes nothing. An extra
entry is a change.
Otherwise every entry OLD holds now goes into `ASIDE` (a NEW directory,
private to the operator, on the host's own disk, which no container mounts;
kept, never deleted, and never left inside OLD) and the snapshot is
extracted in its place.

```sh
( ST='<OLD>'; NST='<NEW>'; INST='<instances_dir>'; HOP='<the hop root: its host path>'
  BK='<the snapshot directory F4c recorded>'
  ASIDE='<a new, operator-private, host-only directory for what it replaces>'
  OLD='<the old container Id, as F4 records it>'; NEW='<router.container>'
  HUB='<the hub-link router container>'
  umask 077
  stop() { printf 'fs-restore: STOP: %s\n' "$1" >&2; exit 1; }
  manifest() {  # every entry: type, mode, owner, size (link target for a link; none for a directory), name; NUL-ended, sorted
    ( cd -- "$1" && find . \( -type d -printf '%y %m %U %G - %p\0' \) -o \( -type l -printf '%y %m %U %G %l %p\0' \) \
        -o -printf '%y %m %U %G %s %p\0' ) > "$2.unsorted" || return 1
    LC_ALL=C sort -z -o "$2" -- "$2.unsorted" && rm -- "$2.unsorted"
  }
  absent() { ids=$(docker ps -a -q --no-trunc --filter "name=^/$1\$") || stop "docker cannot list containers"; [ -z "$ids" ]; }
  absent "$NEW" || stop "a container is named $NEW: the new router started, and FS has no automatic back-out"
  absent "$NEW-fs-failed" || stop "a container is named $NEW-fs-failed: the new router started, and FS has no automatic back-out"
  s=$(docker inspect -f '{{.State.Running}} {{.HostConfig.RestartPolicy.Name}}' "$OLD") \
    || stop "the old container cannot be inspected"
  [ "$s" = "false no" ] || stop "the old container is not shown stopped with restart policy no"
  STP=$(cd -P -- "$ST" && pwd -P) || stop "no state_dir $ST"
  [ "$STP" != / ] || stop "state_dir is the root directory"
  ( cd -- "$BK" && sha256sum -c --strict --status fs-state.tar.sha256 ) || stop "the snapshot is not the recorded one"
  ( cd -- "$BK" && sha256sum -c --strict --status fs-state.manifest.sha256 ) || stop "the snapshot's manifest is not the recorded one"
  NOW=$(mktemp -- "$BK/fs-check.XXXXXX") || stop "no scratch file for the current manifest"
  manifest "$STP" "$NOW" || stop "the current state's manifest cannot be written"
  if cmp -s -- "$NOW" "$BK/fs-state.manifest" && tar --numeric-owner -dpf "$BK/fs-state.tar" -C "$STP" > /dev/null 2>&1; then
    printf 'fs-restore: OK %s is the snapshot, entry for entry; nothing restored\n' "$STP"; exit 0
  fi
  INP=$(cd -P -- "$INST" && pwd -P) || stop "no instances_dir $INST"
  case "$HOP" in /*) ;; *) stop "the hop root $HOP is not an absolute path" ;; esac
  case "$HOP/" in //|*/./*|*/../*|*//*) stop "the hop root $HOP is not a normalised path, or is the root directory" ;; esac
  HD=$(cd -P -- "$(dirname -- "$HOP")" && pwd -P) || stop "no parent for the hop root $HOP"
  HP=$HD/$(basename -- "$HOP"); HPM=
  if [ -e "$HP" ] || [ -h "$HP" ]; then
    [ -d "$HP" ] && [ ! -h "$HP" ] || stop "the hop root $HOP is not a directory, or is a symlink"
    HPM=$HP
  fi
  case "$HP/" in "$STP"/*) stop "the hop root lies under state_dir" ;; esac
  case "$STP/" in "$HP"/*) stop "state_dir lies under the hop root" ;; esac
  MNT=$(docker inspect -f '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}{{"\n"}}{{end}}{{end}}' "$OLD") \
    || stop "the old container's mounts cannot be read"
  if ! absent "$HUB"; then
    HM=$(docker inspect -f '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}{{"\n"}}{{end}}{{end}}' "$HUB") \
      || stop "the hub-link router's mounts cannot be read"
    MNT=$(printf '%s\n%s' "$MNT" "$HM")
  fi
  ADD=$(cd -P -- "$(dirname -- "$ASIDE")" && pwd -P) || stop "no parent for $ASIDE"
  ASP=$ADD/$(basename -- "$ASIDE")
  IFS=$(printf '\n.'); IFS=${IFS%.}; set -f
  case "$ASP/" in "$HP"/*) stop "$ASIDE lies under the hop root" ;; esac
  ND=$(cd -P -- "$(dirname -- "$NST")" && pwd -P) || stop "no parent for NEW $NST"
  NP=$ND/$(basename -- "$NST")
  case "$ASP/" in "$NP"/*) stop "$ASIDE lies under NEW" ;; esac
  for m in $STP $INP $HPM $MNT; do
    if [ -d "$m" ]; then mp=$(cd -P -- "$m" && pwd -P) || stop "the mount source $m cannot be resolved"
    elif [ -f "$m" ]; then mp=$m
    else stop "the mount source $m is neither a directory nor a file"; fi
    [ "$mp" != / ] || stop "a mount source is the root directory: nothing can lie outside it"
    case "$ASP/" in "$mp"/*) stop "$ASIDE lies under $m" ;; esac
  done
  IFS=$(printf ' \t\n.'); IFS=${IFS%.}; set +f
  mkdir -m 0700 -- "$ASP" || stop "$ASIDE already exists, or cannot be made"
  for e in "$STP"/* "$STP"/.[!.]* "$STP"/..?*; do
    [ -e "$e" ] || [ -h "$e" ] || continue
    mv -- "$e" "$ASP"/ || stop "cannot move $e aside"
  done
  left=$(ls -A -- "$STP") || stop "state_dir cannot be listed"
  [ -z "$left" ] || stop "state_dir is not empty after the move aside"
  tar --numeric-owner -xpf "$BK/fs-state.tar" -C "$STP" || stop "the extract failed"
  tar --numeric-owner -dpf "$BK/fs-state.tar" -C "$STP" > /dev/null || stop "the restored tree is not the snapshot"
  manifest "$STP" "$NOW" || stop "the restored state's manifest cannot be written"
  cmp -s -- "$NOW" "$BK/fs-state.manifest" || stop "the restored tree does not hold exactly the snapshot's entries"
  printf 'fs-restore: OK restored %s; what it replaced is kept in %s\n' "$STP" "$ASP" )
```

**FS's retention**, as the operator decided it:
- OLD, the state snapshot (`fs-state.tar` and its `.sha256`, `fs-state.manifest`
  and its `.sha256`, and any `fs-check.*` scratch manifest an OLD check left), any `ASIDE`
  the OLD check made, the old container (stopped,
  `<router.container>-pre-registry`, restart policy `no`) and any
  `<router.container>-fs-failed` are kept until 7 days after the canary
  passes. Then they are removed on the operator's go, by literal paths and
  Ids, never a glob or a variable: `docker rm <the old container's Id>`;
  `rm -- <the snapshot directory>/fs-state.tar <the snapshot directory>/fs-state.tar.sha256`;
  and OLD by its literal path.
- The lane archive (`fs-lanes.tar`, `fs-lanes.tar.sha256` and
  `fs-lanes.tar.log`) is kept indefinitely, in the snapshot directory, which
  therefore stays.
- NEW, the new router's state, and every container are never removed
  implicitly.
- Record each removal in the run log, with `date -u`, the path or Id, and
  the sha256 the archive had.

### The local router's delegation: fleet keys and activation

Signed delegation between hosts needs three inputs, and it stays off until
all three hold and the activation steps have run:

- the policy turns it on for this host: `hop_link` gains
  `"delegation": {"inbound": false}` (or `true` to verify inbound signed
  delegations too). Without the member, no `delegation` block is rendered;
- the host-setup document pins the fleet's public keys:
  `"fleet_keys": {"path": "<the inventory file>", "sha256": "<its sha256>"}`.
  The inventory is one canonical JSON file listing every host's `name`,
  `domains`, `runtime` (`amap.router@<one of its domains>`), `public_key`
  (the raw 32-byte key, 64 hex) and `key_id` (the sha256 of that key, as the
  key step printed it). This host is the entry listing its fleet domain;
  every other entry must lie within `hop_link.trusted_fleet_hosts`;
- the harness gate holds (`delegation_gate`).

Nothing here reads the signing key. Each rendering is held to the hop
checkout's loader and its plugin's key gate in a separate process that
refuses to open the key; the key pair itself is proved only by the router,
when it starts.

Activation is A1 to A5, then the weekly job's first manual run. Each step
is required before the next, and each command prints the next step.

Every Docker call the activation verbs make goes through the document's
docker client, with no `-H`. That client is `docker` itself, or, where
`docker_via_sudo` is set, `sudo -n` followed by the root barrier line
(`/usr/bin/env -i …`, then root-trust.sh's root_exec and trusted-exec, then
docker). Outside `verify`'s own run that line names no `DOCKER_HOST`, so
docker reaches its default engine. The local router and the hub-link router
must therefore run on that one engine, and `supervision.engine` must name
it. If the engines differ, the checks fail closed: a router on another
engine reads as not running.

0. **Before A1, on each host, in this order.** A2's evidence, the
   post-activation document and the key probe's record bind the approved
   document and the hub-link router's run spec. Anything that changes either
   after activation makes them stale. The local router's image is the clean,
   checked build above (the local router's hop link).
   1. Generate the signing key as the operator (below). The one root command
      installs the 32-byte seed. If keys.dir does not exist yet, create it
      first with the plan's own step (`install -d -o <uid> -g <gid> -m 0700
      <keys.dir>`), from the document as it stands. That run is not the
      approval in step 5.
   2. Add this host's entry (its `public_key` and `key_id`) to the fleet
      inventory, and pin the inventory in this host's document:
      `fleet_keys {path, sha256}`. The pin is part of the host-setup
      document, so it changes the document. Every host's entry must be in
      the inventory before any host pins it. A1 refuses without the pin.
   3. Move the deployment to its final deploy commit
      (`secrets.clones.deploy.sha`).
   4. Build the hub-link router's image and update `secrets.image`.
   5. Approve and anchor the host-setup document, and render the unit, ONCE,
      now: steps 2, 3 and 4 all change the document.
   6. Run the hub key probe, and start the hub-link router on that image.
   7. Provision the weekly job's bundle once, at that deploy commit (its PIN
      is that commit, so the weekly job hands off until it is provisioned).
   8. Take an early fingerprint of the running local router and match it (the
      two commands in step 2, with `--step 0`), so that an unmeasured base
      shows before the window. If it prints `MIGRATE` (exit 3), the router's
      state must be migrated first: run R2 (the local router's migration,
      above), which ends with this match printing `MEASURED`, then take this
      step again.
   9. Make the operator a member of the hop tree's group before A1, and check
      it with `id -Gn` after a fresh login: step 7's P02 reads the hop tree as
      the operator. Never chmod the hop tree.
   10. Only then begin A1.

   `secrets.writer.commit` stays at its reviewed commit. The writer's pin is
   the sha256 of `host_steps.py`, not the deploy commit: a deploy commit that
   leaves `host_steps.py` unchanged leaves the writer as it is, so do not
   "update" `secrets.writer.commit` to the deploy commit.

   The key, step 1. Every check stops the block before the root install,
   and its exit status says whether the seed was installed:

   ```sh
   (
     set -eu
     umask 077
     if [ -d /dev/shm ]; then T=$(mktemp -d /dev/shm/amap-key.XXXXXX); else T=$(mktemp -d "$HOME/amap-key.XXXXXX"); fi
     trap 'rm -rf "$T"' EXIT
     "$OPENSSL" genpkey -algorithm ed25519 -outform DER -out "$T/k.der"
     test "$(wc -c < "$T/k.der")" -eq 48
     tail -c 32 "$T/k.der" > "$T/seed"
     test "$(wc -c < "$T/seed")" -eq 32
     "$OPENSSL" pkey -inform DER -in "$T/k.der" -pubout -outform DER > "$T/pub.der"
     test "$(wc -c < "$T/pub.der")" -eq 44
     tail -c 32 "$T/pub.der" > "$T/pub.raw"
     printf 'public_key '; od -An -tx1 "$T/pub.raw" | tr -d ' \n'; echo
     printf 'key_id     '; "$OPENSSL" dgst -sha256 -r "$T/pub.raw" | cut -c1-64
     /usr/bin/sudo /usr/bin/install -o <the local router's uid> -g <its gid> -m 0400 "$T/seed" <keys.dir>/<keys.file>
   ); echo "exit $? (anything but 0: STOP, nothing was installed)"
   ```

   - It is written for a POSIX shell and was run under bash and dash. On
     macOS, whose interactive shell is zsh, run it under `/bin/sh` or
     `bash` (paste it into `bash`), not zsh.

   - Run it as shown, never as the left side of `||` or `&&`: there the
     shell ignores `set -e` inside the parentheses, and a failed check no
     longer stops the install.
   - `$OPENSSL` is OpenSSL 3, run as the operator only. On macOS, the system
     `openssl` is LibreSSL; use an OpenSSL 3 build. An unset `$OPENSSL` stops
     the block.
   - `install -o` names the local router's in-container uid. Every directory on
     the key's path is owned by root or that uid, and is not group- or
     other-writable.
   - `$T` is on tmpfs where the host has `/dev/shm` (Linux). A host without
     it (macOS) uses a private directory in the operator's home instead,
     which is on disk: `rm -rf` does not scrub it. A RAM disk there is
     optional.
1. **A1.** `python3 amap-sandy.py partition-activate --apply` renders the
   staged config from install's rendering, after every hop-host check install
   makes, and writes A1's record into the run directory. It prints the root
   `place` of the record, the record's sha256 (A3 takes it), and the two
   weekly argv, 7b and 7d. Run the place as root. If the live config already
   carries delegation, de-activate first (the back-out after the place,
   below).
2. **The outage window opens.** First, before recording the live config's
   sha256 and before `docker stop`, fingerprint the running local router and
   match it:

   ```sh
   python3 amap-sandy.py router-fingerprint --step 2 --apply
   python3 amap-sandy.py router-fingerprint --match <the file it wrote>
   ```

   If the running router's container does not yet have the host-setup
   document's `router.container` name (a router started before activation),
   add `--container <its current name>` to both commands. Whatever its name,
   the stop below is by the Id the file records.

   - The match must print `MEASURED` and exit 0. That means:
     - the running router's source, its process and its transport plugin are
       what the upgrade to the pinned router was measured from
       (`router-upgrade-bases.json`);
     - its live config is unchanged since it started (under the clock
       premises the tool documents);
     - its state directory holds no peer-lane state.
   - Then record `sha256sum <the live config>`, and stop exactly the
     container the file names: `docker stop <its container Id>` (never a
     restart-policy change). Do this at once: a restart in between is not
     detected.
   - On `UNMEASURED` or `UNKNOWN`, do not stop the router, and do not
     continue the activation. A1's record stays inert until A3.
     - If the reason is that the status is not yet this process's
       (`stale_status`), wait until the router has written a poll at least
       3 s after it started (at most 3 s plus one poll interval), then
       fingerprint again.
     - If the reason is that the live config changed since the router
       started (`config_changed`), restart the router (before activation
       that loses nothing), wait as above, and fingerprint again.
     - If the host and the router disagree on the time (`clock_skew`), wait
       until their clocks agree and fingerprint again. A router restart does
       not help, because the skew is not the router's.
     - If the router's start and the clock disagree (`pid1_age`), let the
       host clock settle, restart the router, wait as above, and fingerprint
       again. A healthy router whose interpreter took more than 5 s to start
       is also refused here, and the same restart is its remedy.
     - If the live config is not one regular file at its own path
       (`config_identity`), relaunch the router with the config bound at its
       own real path, as `docker/run.sh` does.
     - Only for `no_match`, `unmeasured`, `pre_registry_unchecked`, `mixed`
       or `peer_lane` does the
       upgrade wait until its base is measured and recorded in
       `router-upgrade-bases.json` in a reviewed change. That moves the
       deploy commit, so the activation starts again at step 0. Every other
       refusal names its own remedy.
   - On `MIGRATE` (exit 3, reason `pre_registry_base` or
     `migration_required`), do not stop the router, and do not continue the
     activation either: this window never migrates state. The router's state
     is keyed by instance name, so run R2 (the local router's migration,
     above) as its own window first, then start again at step 0's item 8.
   - A router that is not running is `UNKNOWN`.
   - An image capture never satisfies this step.
3. **A2.** Immediately, as root, the printed 7b argv
   (`partition-weekly ... --prospective`). Never interrupt it: wait for its
   process to EXIT. It passes only when both fail-stop probes pass, the
   evidence is placed and P02 passes, and it names the run whose token A3
   takes. Copy its printed pre-activation line into
   `<run_dir>/a2-pre-activation.sha256`, labelled with this host and A2's run
   id, under the header line
   `# operator-copied from A2's and A3's output; not evidence`. That file is
   your convenience, never evidence. A2's line must equal the `sha256sum`
   recorded at step 2. If it differs, something moved the live config during
   the window: stop, take the back-out before the place, and find what
   changed before trying again. On a non-zero exit, take the back-out before
   the place.
4. **A3.** `python3 amap-sandy.py install --apply --activate <A2's run id>
   --activation-sha256 <A1's printed digest>`, then the root place it prints.
   Add A3's printed sha256 line to the same file, labelled.
5. **A4.** `docker/run.sh --config <the live config> --detach`.
6. **A5, preliminary.** `python3 amap-sandy.py partition-check --document <the
   unit argv's document> --document-sha256 <its sha256>`. Only V1 and V2 must
   PASS here. T1 FAILs until step 8 records a stop target (its remedy, "run
   the weekly job once now", is step 8). E1 and E2 are UNKNOWN until then.
7. **The post-activation document.** `python3 amap-sandy.py partition-probe
   --post-activation <A2's run id> --document <...> --document-sha256 <...>
   --apply`, then the root place it prints. It writes the document whatever
   its verdicts, and it is placed whatever they are: it records what P01 and
   P02 saw against the final router. Exit 1 means one of them did not PASS.
   A FAIL means the partition does not hold against that router: after
   placing the document, take the back-out after the place. An UNKNOWN means
   a probe could not tell (for P02, the operator's access to the hop tree):
   read its reason, and run the step again once it can be measured; the
   host is not ready until a run of this step exits 0. Each run has its own
   `pa-<UTC time>` run id, so a re-run never replaces an earlier document:
   the one that counts is the newest (by the UTC time in its run id) placed
   post-activation document whose `names_token` is A2's token. If P02
   stays UNKNOWN because the operator is outside the hop directories' group,
   it never becomes measurable: that is the host operator's decision, to add
   the operator to the group or to back out. Never chmod the hop tree. No
   check reads this document as a pass by its presence: its verdicts are
   what it records. A refusal (exit 2) writes no document, and there is
   nothing to place.

   Step 7 is its own gate. Neither `partition-check --ready` nor `verify`
   reads P01 or P02 from this document, so a host can show six PASS at
   step 9 while step 7's P02 is FAIL or UNKNOWN. A2 leaves P01 for the
   final router to this step, so an UNKNOWN here is a measurement still
   missing, not a neutral one. Step 7 is complete only when this verb exits
   0 (P01 and P02 PASS) and that newest document is placed.
   While P01 or P02 is UNKNOWN, activation is incomplete: the host is not
   ready, and no collection that depends on it starts, until it resolves or
   the host operator decides as above.
8. **The weekly job's first run (7d).** As root, the printed 7d argv, in the
   foreground. It must end with exit 0, `weekly-runs.json` `runs: []` and
   `stop-target.json` present. Run it once, before any collection that reads
   E1 (a canary's, for example), and never during that collection: a re-run
   renews the stop target and moves E1's subject under it. Plan the
   collection so that this run's `at` (E1's `key_observed.at`) plus
   `FRESH_FOR_S` (691200 s, eight days) is at or after the collection's
   planned end plus its collection budget.
9. **A5, final.** `python3 amap-sandy.py partition-check ... --ready` exits 0
   only when all six claims PASS. `partition-check`'s exit 0 without `--ready`
   means only that its object was written, so read all six cells. Then
   `python3 amap-sandy.py verify` (on a launchd host,
   `python3 amap-sandy.py verify --a5`) must pass, and step 7 must be
   complete (above): the newest placed post-activation document for A2's
   token has P01 and P02 PASS. `--ready` cannot discharge it. Only then is
   the host ready. E1's claim names the step-8 run and time it rests on: the key
   identity is root's observation in that run.

**The back-out before the place.** After a non-zero A2, or an A3 refusal,
follow a kept incident's printed remedy first, then
`docker start <the local router's container>`: its live config is unchanged.

**The back-out after the place.** If a step after A3's place fails, back out
in this order. Stopping the router first shortens the time it may sign.

1. `python3 amap-sandy.py install`, and read the diff it prints;
2. `python3 amap-sandy.py install --apply`, which must exit 0. Plain install
   never renders a `delegation` member;
3. read the live config on the HOST, not through the container: a running
   router binds the file it started with. It must parse as a JSON object
   with no `delegation` member. If it carries one, or cannot be read or
   parsed, stop: the activated config may still be in place;
4. compare its sha256 with A2's line, of the SAME run id, in
   `<run_dir>/a2-pre-activation.sha256`: equal, or a difference that
   install's diff explains. A missing file, or another host's or run's line,
   stops you until install's diff has been read;
5. `docker stop` the local router if it runs, then `docker start` it.

Backing out refuses signed work the router has begun but not yet handed
over, at its next publication check, rather than holding it. Work already
handed over settles as usual, and the router's peer state stays on disk for
a later activation. After activation, every change to the local router's
config goes through A1 to A5 again: a plain `install --apply` renders no
delegation, so it de-activates the host, and `verify` reports it. A planned
restart of the hub-link router after activation goes through
`hub-start-check`, which needs A2's evidence still current: do it within that
window, or after the weekly run renews it.

**What the outage window does to the local router.** In the local router's
own words, with only these changes to its text: "the local router" where it
named itself or this router by a label; "(above)" for the back-out it cited;
and two parentheses that named this deployment's internal plan reworded or
removed.

> While the local router is stopped (docker stop, then A4's restart):
>
> WAITS ON DISK, nothing lost:
> - agents' outbox requests, which stay in their outboxes, unconsumed;
> - in-flight records and handed markers (state_dir/.../inflight/), held local deliveries (pending/), and pending DSNs;
> - the peer ledger, the candidate and receive journals, the replay store and the peer clock;
> - hop items, in the hop root: hand-overs not yet written, handed requests awaiting the downstream result, and inbound candidates;
> - the first-sight marker.
> Every one of these is written durably (atomic write plus fsync) and is read again on the next poll.
>
> LOST OR DROPPED BY THE STOP ITSELF: nothing.
> C1: The local router installs no SIGTERM handler, so `docker stop` ends PID 1 at once, mid-poll if one is running. It is the same as a crash, and SIGKILL after docker's grace period is the same again. The router is built for this: every side effect is atomic and durable and passes through one crash seam, and recovery from a crash after any single write is a tested property. On restart the interrupted poll's work is redone or settled EXACTLY ONCE (idempotency anchors; a handed request is never re-handed under a new id).
>
> If the local router's state is keyed by instance name (a router that ran without `registry_dir`), a restart on a configuration that sets `registry_dir` does not drain that instance by itself: the router holds it, places nothing for it, and loses nothing. Such a router never reaches this window: step 2 refuses it (`MIGRATE`), and R2 migrates it in its own window first.
>
> DRAINS ON RESTART WITH NO OPERATOR STEP: yes, for a router whose state is in the generation layout under the registry, which is the only router this window stops.
> - The kernel releases the drain lock when the process dies.
> - First sight is a persisted marker, so a restart never re-snapshots or quarantines waiting requests.
> - A restart never begins a generation (the binding and root are unchanged).
> - Peer admission stays open: it closes only when the clock file is missing, unreadable or uninitialised, or when an operator-declared restore happens, never on a restart.
> - Delivery resumes on the first poll after start.
>
> C2, TIME WINDOWS. These are the only effects of the stop's DURATION, and none applies to a stop shorter than the peer window P (delegation.windows.p, default 3600 s):
> - Inbound signed tasks (only where delegation.inbound is true): when evaluated after the restart, a statement whose ts is now older than now - P is DEMOTED, not dropped. It is quarantined as "demoted"/ts_window, and the sender gets a "demoted" control notice. It is not placed as a signed task.
> - Outbound: a signed task this router had SIGNED but not yet HANDED OVER when it stopped, and handed after ts + P + F, will be demoted by the receiver in the same way. `python3 -m router --config C peer-request show <id>` shows its window end.
> - Reverse-edge replies (no forward edge) must be drained within peer_reply_window_seconds of the record (default 604800 s, 7 days), and mail replies within mail_reply_window_seconds (default 7 days). Irrelevant for a planned outage of minutes.
>
> C3 (revised). For the FIRST activation of a router (before activation, the live config carries no delegation):
> - C2's OUTBOUND clause cannot apply. A router without delegation never signed anything, so no signed task is waiting to be handed over.
> - C2's INBOUND clause applies only where this host's rendering turns `inbound` on, and only to signed statements that peers address to this router during the window.
>   - While the router has no delegation (or inbound is off) it takes no signed candidates at all: they wait in the hop intake untouched (peerjournal.poll returns before reading them).
>   - After A4 starts it with delegation and inbound, each waiting statement is judged against the window: ts below (now - P) is DEMOTED (quarantined, plus a "demoted" control notice to its sender), never dropped.
> - A2 is NEVER interrupted. The operator starts A2 immediately after `docker stop <router>`, with no other step between them, and waits until A2's process is OBSERVED to exit. Neither number below replaces that observation: CHILD_TIMEOUT_S (3600 s) bounds only A2's wait for its child, and the writer treats a run older than STALE_AFTER_S (5320 s) as overdue, a conservative threshold and not proof that the run stopped. The local router is not started while A2's process lives. On a non-zero exit the operator takes the before-place back-out (above), after any kept incident's remedy.
> - Plan target, NOT a cancellation point: the whole window, from `docker stop <router>` to A4's start of the router on the activated config (or the back-out's start on the unchanged config), is planned to close within 30 minutes. That is half of P's default 3600 s, leaving margin for clock skew and the first poll. Missing the target cancels nothing.
> - Worst case: the window lasts until A2 exits plus the steps after it. No figure here caps it, and it can exceed P (P's default is 3600 s). However long it lasts, the only effect on the local router past P is the inbound clause above: waiting signed statements older than now - P are demoted, each with a notice to its sender, and none is dropped. Local delivery and hand-over simply wait, as C1 says. Nothing on disk is lost, and the restart drains with no operator step. The 7-day reply windows are the only later limit, and only an outage measured in days would reach them.
> - If no peer signs tasks to this router before its own activation, the inbound clause has nothing to act on, and the window only bounds the local-delivery and hand-over outage C1 describes, however long A2 runs.

`verify` passes the signing check only when the router
signs exactly as the policy and the gate allow, under the token of current
evidence, and has adopted the host's config: it watches two of the router's
polls while the file it reads stays unchanged. That witness holds only where
the router reads its config through a bind of the same file the host holds
(native Linux Docker) on ext4, xfs or btrfs; through a VM's file share
(Docker on macOS) the signing check is UNKNOWN by design, and says so. Read
the filesystem type with `findmnt -T <the live config> -o FSTYPE`; `stat -f`
names ext2, ext3 and ext4 alike.

After activation, the hub-link router's start check (`hub-start-check`, and
on launchd `verify`'s enablement check) admits the local router's
delegation block only when it is exactly A1's approved block and the policy,
the harness gate and the token's current evidence all hold; any other block
refuses the start, and an input that cannot be read refuses it too. It does
not ask the adoption witness: the hub-link router's start changes nothing
the local router signs. A crash or boot restart of the hub-link router is
its supervisor's (systemd `Restart=on-failure`, launchd `KeepAlive`) and is
not gated: the check governs the start step it prints and launchd's
enablement.

Every command root runs for the hub-link router goes through one barrier:
an empty environment, then `root_exec` from `root-trust.sh`, placed root
0444 beside the writer. It judges the operating system's own python3 and the
pinned writer before either runs, and the writer's `trusted-exec` then
judges the command and everything it loads before it executes it. Every
start, the gated one and each restart, first runs that barrier over docker:
systemd's first `ExecStartPre`, whose failure fails the start, and the
launchd wrapper, which then records `untrusted_tools` and exits 0, so
launchd does not restart it. Root runs no docker that is not root's alone.

A stop goes through the barrier too, so a refused stop never reaches
`docker stop`. On macOS the wrapper says "the stop was refused or failed",
and when launchd's `ExitTimeOut` ends the wrapper, the container is still
running. On Linux, systemd then sends its own TERM to the docker client.
The client is attached, so it should forward that TERM to the container,
but this has not been measured. On either system, if `docker ps` still
names the hub-link router after a stop, find out why the barrier refused
before you stop the container by hand.

On macOS the wrapper's error stream goes to `hub-link-run.err`, beside its
status in the root-owned status directory. It holds only the wrapper's own
lines: the router's output goes to the engine's log (`docker logs`).
`verify` reads both files. Two consequences follow from where the router's
output goes:
- With `hub.log_driver` set to `none`, the hub-link router's observation
  lines are not kept anywhere on macOS.
- The `json-file` driver does not rotate unless the daemon sets `log-opts`;
  the `local` driver does.

If a start ends in exit 125 (docker never started the container), the
wrapper says what the engine reports about the image and about a container
of that name before passing the code on. A missing
status is a failure, not "never started", because a refusal that cannot
record itself removes the last one. A refusal is a failure whether or not it
was recorded.

`verify`'s own live engine calls go through the same barrier. Each runs
only when the interpreter, the pinned writer, docker's startup closure
(computed as you) and sudo all pass. On the sudo route each call is
`sudo -n /usr/bin/env -i PATH=… LC_ALL=C DOCKER_HOST=<engine> /bin/sh -c
'<the fixed source line> root_exec "$@"' sh <writer sha256> <python3> <writer>
trusted-exec --tool … -- <docker> …`.

No sudoers rule is safe for that invocation yet, so the sudo route is
unavailable. sudoers compares the arguments as one space-joined string, so
it cannot keep `env`'s assignments apart from the command it runs. The
arguments `-i`, then one `PATH=<everything else>`, then any program join
to the same string as the intended ones, and `env` would run that program
as root, skipping `/bin/sh`, `root_exec` and `trusted-exec`. Do NOT install
a `NOPASSWD` rule for `/usr/bin/env`, however narrow it looks. Without one,
`sudo -n` refuses, and no live check on that route can read the engine.
The route needs a fixed-purpose, root-owned entry point that enforces the
argument boundary before running anything the caller chose. Any grant that
lets this invocation run without one is root-equivalent, the same class as
the old docker grant (root through the engine's socket). That entry point is
a separate, reviewed change, not part of this setup.


### The weekly partition job's tools

The weekly partition job runs the host's interpreter and docker as root, so
when the document has a partition section, the plan's first steps check them
and everything they load at startup. Run these steps at install AND again after any
operating-system, interpreter or docker update, before the next weekly run.
Those updates change the startup closure the per-run tripwire holds to the
install-time state.

Root makes a directory only root can open, and writes two scripts into it
from the plan's text before anything that is being checked runs:
`discover.sh`, which runs the interpreter, `ldd` (or `otool`) and
`xcode-select` to list the closure, and `judge.sh`, which judges that list
with the operating system's own `find` and executes nothing it judges. The
plan prints both scripts and their sha256 digests:

```sh
R=$(sudo mktemp -d /tmp/amap-judge.XXXXXXXX)
sudo chmod 0400 "$R/judge.sh" "$R/discover.sh"
```

Then one root invocation checks the digests, runs discovery as `nobody`
(no terminal, an empty environment, its output cut at 1 MiB and one byte)
and judges what it wrote. On Linux:

```sh
sudo sh -c 'sha256sum --status -c "$1/judge.sha256" || { echo "discovery failed: the judging scripts do not match their digests; nothing is run"; exit 1; }; ( cd / && setsid -w runuser -u nobody -- env -i PATH=/usr/bin:/bin HOME=/ LC_ALL=C sh -c "$(cat "$1/discover.sh")" </dev/null 2>/dev/null ) | head -c 1048577 > "$1/closure.env"; chmod 0400 "$1/closure.env" && sh "$1/judge.sh" "$1/closure.env"' sh "$R"
```

On macOS:

```sh
sudo sh -c 'shasum -a 256 --status -c "$1/judge.sha256" || { echo "discovery failed: the judging scripts do not match their digests; nothing is run"; exit 1; }; ( cd / && /usr/bin/perl -MPOSIX -e "POSIX::setsid() >= 0 or exit 1; exec @ARGV" /usr/bin/sudo -u nobody -g nobody /usr/bin/env -i PATH=/usr/bin:/bin HOME=/var/empty LC_ALL=C /bin/sh -c "$(cat "$1/discover.sh")" </dev/null 2>/dev/null ) | head -c 1048577 > "$1/closure.env"; chmod 0400 "$1/closure.env" && sh "$1/judge.sh" "$1/closure.env"' sh "$R"
```

Go on only when it printed exactly `END-OF-BLOCK` and exited 0. The plan
prints this check first, before every step that runs an interpreter as root,
and the bundle's provisioning
(`partition-provision`, under the job's lock) comes after it. `nobody` must
hold no sudoers rule and own nothing in the closure, and sudo's default
`closefrom` must hold. The check trusts, as given, the completeness of the
lists discovery writes beyond the tools themselves and its self-checks, and
only as far as no hostile process runs as `nobody`. The interpreter
names its own library paths from its standard library, so whoever can already
write that library can make it misreport them: a known limit, the same for
the per-run tripwire. A process discovery leaves behind that holds the pipe
makes the step hang visibly; interrupt it, and run nothing after it.
