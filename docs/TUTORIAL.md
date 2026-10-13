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

The supervisor uses the agent's own model, `model` in the sandbox's
`~/.codex/config.toml`, or Codex's default where that names none. Change it
there, not with sandy's `CODEX_MODEL`, which reaches only the pane; the
supervisor picks it up on its next start.

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

Run the printed steps as root, in order, **before any hop runtime starts**.
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
   - its permission bits are **a subset of the requested ones**: 0750
     (`rwxr-x---`) for an item directory, 0700 (`rwx------`) for a `.stage`
     directory;
   - it has **no setuid and no sticky bit**: no `s` in the owner's execute
     place, and no `t` or `T` at the end;
   - its **setgid bit** (`s` or `S` in the group's execute place) is the
     same as its parent's.
3. **If all hold, remove it** with `rmdir <path>`, never `rm -r`, and
   **start the runtime**. The replay creates it again. That is safe: a
   writer-owned 0700 or 0750 directory can hold only the writer's own
   entries, and nothing is committed there before the runtime's checks pass.

**One mismatch has a known cause.** An empty, writer-owned directory whose
only difference is a missing setgid bit is what a umask that strips a
requested bit leaves behind when the parent's group is not one of the
writer's groups. It is a deployment error, not a plant: fix the runtime's
umask (the check above names it), then `rmdir` it and start the runtime.

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
  world-writable;
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
recorded as `timeout`.
