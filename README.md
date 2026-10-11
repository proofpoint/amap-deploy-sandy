# amap-deploy-sandy

This repo deploys AMAP (the Agent Mailbox Access Protocol, specified in [amap-spec](https://github.com/proofpoint/amap-spec)) on a
**sandy** host. The result is a fleet of Claude Code agents, each in its own
sandy sandbox, that can task one another and reply through a local router.

It installs the per-agent connector as a sandy feature, and renders the
router's config from the operator's policy. Its parts:

- the **router**: [amap-router-local](https://github.com/proofpoint/amap-router-local),
  which runs in its own container
- the **connector**: [amap-connector-claude](https://github.com/proofpoint/amap-connector-claude).
  It provides the delivery daemon and the MCP servers the agent uses.
- **sandy**: the sandbox host. It selects sandboxes, mounts the feature, and
  supervises the relay.

**Quick start.** With [sandy](https://github.com/rappdw/sandy) installed and
Docker running, one command clones the three repos into `~/amap`, installs
the default policy (every agent may task every other) and starts the router:

```sh
curl -fsSL https://raw.githubusercontent.com/proofpoint/amap-deploy-sandy/main/install.sh | bash
```

Then start agents whenever you need them, with `sandy --start` in each
workspace. They can delegate to each other as they come online.

**New to AMAP?** Start with [the explainer](https://proofpoint.github.io/amap-deploy-sandy/) (`docs/index.html`, served by GitHub Pages), which walks through the concepts with animated flows. Then follow [the runbook](docs/TUTORIAL.md), which gets two agents talking
and then breaks each guarantee on purpose so you can see where it is enforced.

sandy is one isolation choice, not a requirement of AMAP. Any isolation method
that implements at a minimum credential, network and file-system isolation can
take its place, with a deployment of its own in place of this repo; the
explainer's "Why sandy" screen lists what that deployment must supply.

Everything here runs **host-side, as the operator**. Nothing in this repo
runs inside a sandbox, and nothing here can send or receive a message.

## Requirements

- **sandy 2.2.0 or later** (`--print-schema` reports `schema_version` 3 or 4).
  `install` refuses an older sandy, because on one every later step would
  report success while sandy read none of it.
  On sandy 2.4.0 or later, `install` also declares `receives:
  ["cross_session"]` in the manifest, so sandy accepts cross-session delivery
  for amap's sandboxes because the feature asks for it. On an older sandy, the
  key is left out and sandy's legacy rule does the same job.
- **amap-router-local** and **amap-connector-claude**, each checked out beside
  this repo (a sibling directory of an ancestor), or named by
  `$AMAP_ROUTER_REPO` / `$AMAP_CONNECTOR_REPO`. **They are pinned:**
  `siblings.json` names the commit of each that this repo is tested against,
  and `python3 amap-siblings.py --apply` clones or checks out exactly those
  (a dry run without `--apply`; an overridden checkout is left alone). The
  one-command installer does this for you.
- Python 3 (standard library only; the tests use pytest) and Docker for the router.

## What gets installed

Everything lives once per host, under `$SANDY_HOME/features/amap/`:

| Path | What it is | Whose |
|---|---|---|
| `feature.json` | sandy's feature **manifest**. Its `feature` section is the fleet **policy**, and `sandboxes`/`agents` hold the selection rule | yours to edit; `install` owns the `schema`/`create`/`mounts`/`entry`/`expose`/`agent_args`/`receives` blocks |
| `payload/` | the relay wrapper, the session lister, the submit server's wrapper, the connector's binaries, `mcp-servers.json` and `INBOX-POLICY.md`. Mounted **read-only** at `/opt/sandy/features/amap` in every selected sandbox | `install` |
| `router.json` | the router's config, **generated** from the policy | `install`; never hand-edit |
| `roster/` | the fleet roster the router writes, mounted read-only into every selected sandbox | created empty by `install`, written by the router |
| `selected.json` | **sandy's** verdict: which sandboxes the rule selected at their last launch | sandy |
| `instances/` | the root of every instance's lanes, mounted whole by the router | created empty by `install` |
| `instances/<slug>/` | each instance's lanes (inbox, peer, outbox), created by sandy at launch | sandy |
| `by-slug/<slug>` | a symlink to the identity directory the host registry names for that sandbox, mounted read-only when the policy's `identity` is `registry` | `install --apply` (identity on) or `link-identity --apply` |

Beside it, `$SANDY_HOME/router-state/` is the router's `state_dir`: first-sight
markers, the reply ledger, held requests. `install` creates it empty, and
everything in it is the router's.

**Nothing is written into a sandbox.** Sandy applies the manifest to each
sandbox at its launch. The manifest's `agent_args` pass Claude Code the MCP
config and the system-prompt policy, both from the read-only payload.

## Bring-up

With sandy installed and Docker running, one command clones (or updates) the
three repos into `~/amap`, runs `install --apply` and starts the router:

```sh
curl -fsSL https://raw.githubusercontent.com/proofpoint/amap-deploy-sandy/main/install.sh | bash
```

Then start agents whenever you need them (`sandy --start` in each workspace)
and run `verify`. The same steps by hand:

```sh
# 1. Install. On a fresh host this writes the manifest from a TEMPLATE that works
#    as written: every sandbox launched with claude selected, every one may
#    task every other (task_graph "ALL", no mail lane), addresses
#    <slug>@sandy.<this host>.internal, a 24h recreation cadence. Also renders
#    router.json.
python3 amap-sandy.py install            # preview (every verb is a dry run without --apply)
python3 amap-sandy.py install --apply

# 2. Optional: narrow the policy in $SANDY_HOME/features/amap/feature.json
#    (a glob in sandboxes.exclude, explicit task_graph edges, your own
#    fleet_domain; examples/feature.json is a complete edited one), then
#    install again.
python3 amap-sandy.py install --apply

# 3. Start the router from the amap-router-local checkout. It needs no sandbox
#    to have launched yet.
docker/build.sh && docker/run.sh --config "$SANDY_HOME/features/amap/router.json"

# 4. Launch agents whenever you like, in any order. The first launch creates a
#    workspace's sandbox, and every launch selects it against the rule,
#    creates its lanes and mounts the payload; the router admits it on its
#    next poll. A sandbox already running from before step 1 must be
#    relaunched (sandy --stop, then sandy --start) to pick up the manifest.
sandy --start                            # in each workspace

# 5. Check everything, the router process included.
python3 amap-sandy.py verify
```

**There is no approve step.** The first time the router polls an instance,
it takes a snapshot of that instance's outbox. It never delivers anything
staged before that snapshot. With the router already running, that snapshot
comes at its first poll after an agent's launch, before the agent has
anything to say. Keep the router's `state_dir` on persistent storage: a
fresh `state_dir` means a fresh first sight.

## Verbs

Host-wide options (`--sandy-home`, `--sandy`, `--servers`, `--connector-src`,
`--state-dir`, `--overlay`) go **before** the verb.

`--overlay PATH` (default `$AMAP_DEPLOY_OVERLAY`) names the **deployment
overlay**: a private JSON file whose `registry` section holds the host
registry's identifiers (its interface token, its CLI and operator-verb
modules, and the name.json schema id) and, optionally, its checkout and its
directory. Its optional `host_setup` section is the host-setup document
`host-setup` reads when no `--spec` is given. This repository names none of
them. Only the registry verbs, `host-setup` without `--spec`, and a policy
whose `identity` is `registry`, need it; without it they refuse by
name and nothing else changes. With `identity` on, `verify` also asks the
registry (read-only `show`) about every running sandbox and compares the
name.json that sandbox's container reads; any gap is a problem for that
sandbox alone. With `identity` on, `install --apply` also registers every
selected sandbox the registry has not seen (with the workspace sandy
reports) and makes its `by-slug/` link, so a new agent needs no import:
after its first launch, `install --apply` and a relaunch. It registers
nothing until the registry exists: import today's slugs first with
`migrate-registry`, so no existing agent is given a new name. That guard is
for the registry as a whole, not per agent: an existing agent the import
missed (one sandy had not yet selected when the batch was written) is
registered by a later `install --apply` under a new name. Check the
import's plan against `list` before turning `identity` on. The relay reads name.json once, when it starts: a name the
registry changes later (an operator override) takes effect when the sandbox
relaunches, and `verify`, which reads the file, does not see the
difference.

| Verb | Does |
|---|---|
| `install [--apply]` | the whole install, once per host: the manifest, the payload, the roster directory and the router's config |
| `verify [--only SLUG] [--match SUBSTR] [--host-facts PATH]` | read-only. It checks the install, every selected sandbox (lanes, relay, the mounts, what sandy applied at its last launch) and, last, the router process: its container, mount set and health. It exits 1 on any problem |
| `router-config [--apply]` | only the router's config. Without `--apply` it compares the file with the rendering and exits 1 on drift |
| `list` | every sandbox sandy reports, with sandy's verdict for this feature: `selected`, `not selected` (with the reason) or `unknown` (not launched since the manifest changed) |
| `fleet-domain [--base BASE] [--apply]` | this host's derived fleet domain, `sandy.<host>.<base>` (base: `internal`), beside the manifest's; `--apply` writes it into `feature.fleet_domain`. Every agent's address changes, so relaunch them after |
| `cadence [--apply]` | the container-recreation job (macOS launchd), rendered from the policy's cadence. It prints the `launchctl` line and never runs it |
| `migrate-registry --registry DIR --batch FILE [--registry-repo DIR] [--apply]` | the host registry's import of every selected sandbox, prepared: writes the batch (slug and workspace) and prints the registry's two operator commands, `plan` and `apply`. It runs neither |
| `link-identity --registry DIR [--registry-repo DIR] [--apply]` | one `by-slug/<slug>` link per selected, registered sandbox, to the identity directory the registry names. It removes nothing and refuses a path that is not a link; a sandbox gains or changes the mount when it relaunches |
| `teardown [--apply] [--force]` | takes the host back to before `install`: removes the payload, the router's config and its state. It keeps the manifest and `instances/`. `--force` also empties every lane |
| `host-setup [--spec FILE] [--production]` | a hop deployment's host plan, from a host-setup document (operator data: `--spec`, else the overlay's `host_setup` section): prints the root-run steps (each root created with owner and mode, a barrier syncing each one and its ancestors, the overlay root-owned 0444, each runtime's umask), all through `host_steps.py`, which follows no symbolic link, and runs none of them. Then checks the host against them: every root and ancestor a real directory with its owner and mode; each runtime's running container its declared image, binding each declared root, which is the directory the plan made; each image's openssl (3.0 or later, at its recorded version, asked offline with `--pull never`); and each running hop runtime's umask. A document that leaves a hop principal without its runtime or mounts, or an image without its openssl record, does not load. `verify` runs the same checks when the overlay has the section. No runtime starts before the plan has run; the [runbook](docs/TUTORIAL.md#10-a-hop-deployments-host-setup) has the steps and what to do with a refused leftover directory. The checks read each runtime's running container, so a hop runtime outside a container is not verified: it is reported UNKNOWN, and the verb exits 1. `--production` (or `"production": true` in the document) refuses the stub plugin's pin |

`verify` has three outcomes: PASS, FAIL and **UNKNOWN**. UNKNOWN is reported
as a problem, never as a pass: a router that cannot be read is not a router
that is fine. `--host-facts PATH` writes the router sections as JSON for the
router's operator console, on every exit.

## Everyday tasks

**A sandbox should join.** If the rule already admits it, launch it once and
sandy selects it at that launch. The router re-reads its config on every
poll, so no restart is needed once `install --apply` has re-rendered it.

**A sandbox should leave.** Add its slug to `sandboxes.exclude` in the
manifest, run `install --apply`, and relaunch the sandbox. Sandy drops it
from `selected.json` at that launch.

**Who may task whom should change.** Edit the manifest's `feature` section,
never `router.json`, then run `install --apply`.

## Rules that do not change

- **Selection is sandy's.** The include and exclude globs go into the
  manifest verbatim, and sandy evaluates them at each launch, against the
  slug and the launching agent. Exclusion wins. Nothing here predicts sandy's
  verdict, and nothing read from inside a workspace can influence it.
- **One name.** A sandy slug names the sandbox, the router instance and the
  local part of the agent's address.
- **The boundary is the read-only mount.** The agent owns the payload's
  files, yet a write to them fails with `EROFS`. Permission bits bind
  nothing there.
- **Authorisation is the router's.** Nothing on the agent's side names whom
  the agent may task. The roster lists who exists, never who may task whom.
- **Never `mkdir` a sandbox directory or a lane tree.** Sandy creates both at
  launch.
- **Dry run is the default** for every verb that writes.

`POLICY.md` explains the text every agent receives as its system prompt.
`CLAUDE.md` holds the contributor's conventions.

## Tests

```sh
python3 -m pytest tests -q
```

The suite needs the **router and connector checked out as siblings**, at
their pins (`python3 amap-siblings.py --apply`). It
imports the router's package to agree with its layout, and it reads the
connector's daemon to agree with its variables. Without them the run fails;
it does not pass as a smaller green. The suite never runs Docker, the router
or sandy.

## License

Apache License 2.0. See `LICENSE`.
