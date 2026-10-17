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
recorded as `timeout`.

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

The check must print `EXACT`. Record the image ID as the `digest` (`docker
image inspect --format '{{.Id}}' <name>`: a local build has no registry
digest), and the commit it was built from. Then:

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

### The local router's migration to the registry layout (R2)

A local router whose state is keyed by instance name (any router that ran
without `registry_dir`) cannot be upgraded to the pinned router
transparently. On a configuration that sets `registry_dir`, the pinned
router holds each such instance (`state_not_migrated`, then
`legacy_state_unadopted`). It places nothing for it and loses nothing,
until the instance's state directory is moved to its logical id and
adopted. R2 does that as its own window, before any activation. It ends
with the pinned router running under the host-setup document's
`router.container`, on its registry configuration, and fingerprinting
`MEASURED`, which is what activation's step 2 requires. R2 is never part of
an activation window.

R2 needs the hop link above (the policy's `hop_link`, so that `install`
renders `registry_dir`), the hop checkout at its pin, and the local
router's image built and checked. Run every step as the operator: the
router runs as the operator's uid, and its `state_dir` is the operator's.
Each `router-migrate` step runs the pinned router's own code through the
hop checkout's `docker/run.sh`, on the document's `router.image`, and
writes its record into the run directory. Each exits 0 when it is done,
1 on a STOP, and 2 when it cannot run. Any non-zero exit stops R2 at that
point, and the back-out for that point (below) applies.

1. **Fingerprint.** `python3 amap-sandy.py router-fingerprint --step 0
   --apply`, then `python3 amap-sandy.py router-fingerprint --match <the
   file it wrote>`, each with `--container <its current name>` while the
   router's container is not yet `router.container`. The match must print
   `MIGRATE` and exit 3 (`pre_registry_base` or `migration_required`).
   `MEASURED` means no migration is needed. Any other result names its own
   remedy, and R2 does not start.
2. **Render.** `python3 amap-sandy.py install --render-to <run_dir>/r2-config.json
   --apply`. It writes the pinned router's configuration to that new file
   only, and prints its sha256. The live config is not written yet: the
   running router's loader refuses the hop keys.
3. **Map.** `python3 amap-sandy.py router-migrate map --config
   <run_dir>/r2-config.json --apply`. It records each instance's logical id
   and registry binding. It STOPs when the registry is not `ok`, or when a
   configured instance is not resolved.
4. **Preview.** `python3 amap-sandy.py router-migrate preview --config
   <run_dir>/r2-config.json --map <step 3's file> --reason "<text>" --apply`.
   It copies each name-keyed state directory to a scratch state directory
   under its logical id, runs `generation adopt --dry-run` there, and removes
   the copy. A copy of a running router's state is only a preview: the
   binding dry run is step 9's.
5. **The window opens.** Fingerprint and match again, as in step 1, with
   `--step 2`. It must print `MIGRATE` with the same reason. Then, at once,
   with no other step between them:
   - `sha256sum <the live config>`, recorded;
   - `cp -p <the live config> <run_dir>/r2-pre-migration-config.json`;
   - `docker stop <the container Id the file records>`;
   - `docker update --restart no <that Id>`, so that a daemon restart cannot
     start it beside the new router;
   - `docker rename <that Id> <router.container>-pre-registry`, so that
     step 11 can start the new router under `router.container`.
6. **The live config.** `python3 amap-sandy.py install --apply`. Then
   `sha256sum <the live config>` must equal the sha256 step 2 printed.
7. **Map again.** `python3 amap-sandy.py router-migrate map --config <the
   live config> --apply`.
8. **Move.** `python3 amap-sandy.py router-migrate move --config <the live
   config> --map <step 7's file> --apply`. For each instance, it moves
   `<state_dir>/<name>` to `<state_dir>/<logical_id>`, and only when the
   name's entry is a real directory (never a link) and the logical id has no
   entry of any type, a dangling link included. `state_dir` is the same
   path on the host and in the container: `run.sh` mounts it at its own
   path. Each move is journaled before it is made, and the first failure
   stops the step.
9. **Check.** `python3 amap-sandy.py router-migrate check --config <the live
   config> --preview <step 4's file> --map <step 7's file> --reason "<text>"
   --apply`. It STOPs when the binding (logical id, adapter, stable key and
   binding sequence), the root or the verb differs from the preview's, or
   when any instance shows transport history: a counter, in-flight entries,
   transport verdicts or malformed anchors. The count of local anchors may
   differ from the preview's, because the running router went on delivering.
   `--no-transport-history=N` attests that an instance never had a transport
   route, and N is its exact count of local anchors. The check takes N only
   from this dry run's own refusal text, and records it.
10. **Adopt.** `python3 amap-sandy.py router-migrate adopt --config <the live
    config> --check <step 9's file> --reason "<text>" --apply`. From here
    R2 only goes forward (back-out D).
11. **Start.** `docker/run.sh --config <the live config> --image
    <router.image.digest> --name <router.container> --detach`, from the hop
    checkout.
12. **Accept.** Wait for a poll at least 3 s after the start. Then
    `python3 amap-sandy.py router-fingerprint --step 0 --apply` and its
    `--match` must print `MEASURED` (`measured`): the pinned router, on its
    registry configuration, with every instance's state in the generation
    layout. `python3 amap-sandy.py verify` must pass.
13. **Only then**, `docker rm <the old container's Id>`, by the Id step 5's
    file records.

**R2's back-outs**, by the point reached:

- A. Before step 5's stop: nothing has changed. The run directory's files
  are inert.
- B. After the stop, before step 8's first move:
  1. If step 6 ran, `cp -p <run_dir>/r2-pre-migration-config.json <the live
     config>`, and check that `sha256sum` equals step 5's record.
  2. `docker rename <that Id> <its old name>`.
  3. `docker update --restart unless-stopped <that Id>`.
  4. `docker start <that Id>`.
- C. After a move, before step 10:
  1. `python3 amap-sandy.py router-migrate move --config <the live config>
     --reverse <step 8's journal> --apply`, which moves each journaled
     directory back, newest first.
  2. Then back-out B.
- D. Once step 10 has begun: forward only. The adopted state is in the
  generation layout under the logical id, which the old router never reads.
  - Re-running step 10 resumes an interrupted adopt: until it completes, the
    router holds the instance as `state_layout_conflict`.
  - If the pinned router cannot start, keep the old container stopped and
    stop: the window stays open, and the router's maintainers decide the
    next step. `generation fence-legacy` exists only for an origin that
    cannot be vouched for.

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
docker client (`docker`, or `sudo -n docker` where `docker_via_sudo` is
set), with no `-H`. So the local router and the hub-link router must run on
the one engine that client reaches, and `supervision.engine` must name that
engine. Under sudo's default environment reset, `sudo -n` drops `DOCKER_HOST`. If
the engines differ, the checks fail closed: a router on another engine
reads as not running.

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
> DRAINS ON RESTART WITH NO OPERATOR STEP: yes, for a router whose state is in the registry layout, which is the only router this window stops.
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
