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
  `$AMAP_ROUTER_REPO` / `$AMAP_CONNECTOR_REPO`.
- Python 3 (standard library only; the tests use pytest) and Docker for the router.

## What gets installed

Everything lives once per host, under `$SANDY_HOME/features/amap/`:

| Path | What it is | Whose |
|---|---|---|
| `feature.json` | sandy's feature **manifest**. Its `feature` section is the fleet **policy**, and `sandboxes`/`agents` hold the selection rule | yours to edit; `install` owns the `schema`/`create`/`mounts`/`entry`/`expose`/`agent_args`/`receives` blocks |
| `payload/` | the relay wrapper, the session lister, the connector's binaries, `mcp-servers.json` and `INBOX-POLICY.md`. Mounted **read-only** at `/opt/sandy/features/amap` in every selected sandbox | `install` |
| `router.json` | the router's config, **generated** from the policy | `install`; never hand-edit |
| `roster/` | the fleet roster the router writes, mounted read-only into every selected sandbox | created empty by `install`, written by the router |
| `selected.json` | **sandy's** verdict: which sandboxes the rule selected at their last launch | sandy |
| `instances/` | the root of every instance's lanes, mounted whole by the router | created empty by `install` |
| `instances/<slug>/` | each instance's lanes (inbox, peer, outbox), created by sandy at launch | sandy |

Beside it, `$SANDY_HOME/router-state/` is the router's `state_dir`: first-sight
markers, the reply ledger, held requests. `install` creates it empty, and
everything in it is the router's.

**Nothing is written into a sandbox.** Sandy applies the manifest to each
sandbox at its launch. The manifest's `agent_args` pass Claude Code the MCP
config and the system-prompt policy, both from the read-only payload.

## Bring-up

```sh
# 1. Install. On a fresh host this writes the manifest from a TEMPLATE that works
#    as written: every sandbox launched with claude selected, every one may
#    task every other (task_graph "ALL", no mail lane), addresses
#    <slug>@agents.internal, a 24h recreation cadence. Also renders router.json.
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
`--state-dir`) go **before** the verb.

| Verb | Does |
|---|---|
| `install [--apply]` | the whole install, once per host: the manifest, the payload, the roster directory and the router's config |
| `verify [--only SLUG] [--match SUBSTR] [--host-facts PATH]` | read-only. It checks the install, every selected sandbox (lanes, relay, the mounts, what sandy applied at its last launch) and, last, the router process: its container, mount set and health. It exits 1 on any problem |
| `router-config [--apply]` | only the router's config. Without `--apply` it compares the file with the rendering and exits 1 on drift |
| `list` | every sandbox sandy reports, with sandy's verdict for this feature: `selected`, `not selected` (with the reason) or `unknown` (not launched since the manifest changed) |
| `cadence [--apply]` | the container-recreation job (macOS launchd), rendered from the policy's cadence. It prints the `launchctl` line and never runs it |
| `teardown [--apply] [--force]` | takes the host back to before `install`: removes the payload, the router's config and its state. It keeps the manifest and `instances/`. `--force` also empties every lane |

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

The suite needs the **router and connector checked out as siblings**. It
imports the router's package to agree with its layout, and it reads the
connector's daemon to agree with its variables. Without them the run fails;
it does not pass as a smaller green. The suite never runs Docker, the router
or sandy.

## License

Apache License 2.0. See `LICENSE`.
