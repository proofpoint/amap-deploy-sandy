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
  router is pinned twice for now: a second, temporary pin at a commit of its
  `hop-integration` branch is checked out as `amap-router-local-hop`
  (`$AMAP_HOP_ROUTER_REPO`) for the hop deployment's renderer, and is removed
  when that branch merges to the router's main. The
  one-command installer does this for you. `install` refuses, before it
  writes anything, a connector checkout whose HEAD is not that pin or that
  has changes to tracked files (compared byte for byte with HEAD, so an index
  flag cannot hide one), naming both commits; `--allow-unpinned-connector
  REASON` installs from it anyway, and under `--apply` records the use, both
  commits and the reason as a line in `install.log` beside the manifest. A
  line records an install ATTEMPT: it is written before the install runs,
  which can still fail.
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
`migrate-registry`, so no existing agent is given a new name. Per agent,
the first `install --apply` with `identity` on records the router's roster
as it stands at that moment (`pre-identity.json`, beside `roster/`; no
roster, an empty record), and never rewrites it: an agent in that record
that the registry has not bound is refused, by name, and pointed at
`migrate-registry`, while an agent launched later registers with no import.
A record that cannot be read registers nothing. An agent that existed but
was not in the roster when the record was made (not launched since the
manifest, so not admitted) is not protected: a later `install --apply`
registers it under a new name. Check the import's plan against `list`
before turning `identity` on. The record is written whole or not at all. If
one cannot be read (damaged by hand, for example), **do not just delete it**:
a new record lists only the roster at that moment, so an agent the old
record protected that is not admitted now (a stopped sandbox) would then be
registered under a new name. Replace it with a superset instead: every slug
in the old record (from a backup, if the file is lost), every slug the
roster lists now, and every sandbox that existed before `identity` was
turned on. Write it as `{"schema": "amap-deploy-sandy.pre-identity/1",
"slugs": [...]}`, then run `install --apply`. A slug wrongly kept there is
refused until it is imported; a slug wrongly left out can be renamed.

A forced retire is not undone by `install` unnoticed. After the registry's
`retire --force` of a sandbox whose workspace still exists:
- if its slug is **not** in the pre-identity record, the next
  `install --apply` registers it again as a NEW identity, with a new
  logical_id and a new name, and prints `registered as <address>`;
- if its slug **is** in the record, the registry no longer has an active
  entry for it, so `install` refuses it like an agent never imported, and
  nothing is registered.

The old name is never reused either way. To bring a recorded agent back as
a new identity, remove its slug from the `slugs` list in
`pre-identity.json` (a JSON edit that leaves the file valid; a damaged file
registers nothing), then run `install --apply`. In both cases, run it only
when the agent is meant to come back; then relaunch the agent, so its relay
reads the new name, and give its peers the new address.

The relay reads name.json once, when it starts: a name the
registry changes later (an operator override) takes effect when the sandbox
relaunches, and `verify`, which reads the file, does not see the
difference.

| Verb | Does |
|---|---|
| `install [--apply]` | the whole install, once per host: the manifest, the payload, the roster directory and the router's config. First, the connector checkout the payload is copied from must be at its `siblings.json` pin and clean, or the install refuses; `--allow-unpinned-connector REASON` overrides it and is logged in `install.log` (one line per attempt). On a host whose policy has `hop_link`, router.json also carries the local router's hop keys, from the host-setup document (which must then be complete, its `router` section included); they are validated by the hop pin's loader, a plugin nested in another mount or a hop path at the container's system paths refuses, and a change to `hop.root`, the link or the hop version against state_dir's records refuses. `--decommission-hop` renders router.json without the hop keys although state_dir holds hop state: the explicit removal of a link (then restart the router) |
| `verify [--only SLUG] [--match SUBSTR] [--host-facts PATH]` | read-only. It checks the install, the payload daemon's connector build against its siblings.json pin, every selected sandbox (lanes, relay, the mounts, what sandy applied at its last launch, whether the session lister can serve its sessions and, for named sessions, their posture as sandy reports it, and the peer notices its daemon has not handled) and, last, the router process: its container, mount set and health. It exits 1 on any problem |
| `router-config [--apply]` | only the router's config. Without `--apply` it compares the file with the rendering and exits 1 on drift |
| `list` | every sandbox sandy reports, with sandy's verdict for this feature: `selected`, `not selected` (with the reason) or `unknown` (not launched since the manifest changed) |
| `fleet-domain [--base BASE] [--apply]` | this host's derived fleet domain, `sandy.<host>.<base>` (base: `internal`), beside the manifest's; `--apply` writes it into `feature.fleet_domain`. Every agent's address changes, so relaunch them after |
| `cadence [--apply]` | the container-recreation job (macOS launchd), rendered from the policy's cadence. It prints the `launchctl` line and never runs it |
| `migrate-registry --registry DIR --batch FILE [--registry-repo DIR] [--apply]` | the host registry's import of every selected sandbox, prepared: writes the batch (slug and workspace) and prints the registry's two operator commands, `plan` and `apply`. It runs neither |
| `link-identity --registry DIR [--registry-repo DIR] [--apply]` | one `by-slug/<slug>` link per selected, registered sandbox, to the identity directory the registry names. It removes nothing and refuses a path that is not a link; a sandbox gains or changes the mount when it relaunches |
| `teardown [--apply] [--force]` | takes the host back to before `install`: removes the payload, the router's config and its state. It keeps the manifest and `instances/`. `--force` also empties every lane |
| `host-setup [--spec FILE] [--production]` | a hop deployment's host plan, from a host-setup document (operator data: `--spec`, else the overlay's `host_setup` section): prints the root-run steps (each root created with owner and mode, a barrier syncing each one and its ancestors, the overlay root-owned 0444, each runtime's umask), all through `host_steps.py`, which follows no symbolic link, and runs none of them. Then checks the host against them: every root and ancestor a real directory with its owner and mode; each runtime's running container its declared image, binding each declared root, which is the directory the plan made; each image's openssl (3.0 or later, at its recorded version, asked offline with `--pull never`); and each running hop runtime's umask (0027, or 0022 only where its record lists it). Inside a container, the checks run `docker exec` as root and only read, with `stat`, `cat` and a loop over `/proc`. A document that leaves a hop principal without its runtime or mounts, or an image without its openssl record, does not load. `verify` runs the same checks when the overlay has the section. No runtime starts before the plan has run; the [runbook](docs/TUTORIAL.md#10-a-hop-deployments-host-setup) has the steps and what to do with a refused leftover directory. The checks read each runtime's running container, so a hop runtime outside a container is not verified: it is reported UNKNOWN, and the verb exits 1. `--production` (or `"production": true` in the document) refuses the stub plugin's pin |
| `hub-render [--spec FILE] [--apply]` | the hub-link email router's two files, from the host-setup document's `hub` section: the delivered-domain (D7) file rendered from the network's attested D7 document (nothing when it does not attest this host's link) and the router's environment file, written into the `secrets` section's run directory only with `--apply`. Placing them is the plan's root step; `host-setup` and `verify` check the placed files and the router's rendering ([runbook](docs/TUTORIAL.md#the-hub-link-routers-files)) |
| `hub-keyprobe [--spec FILE] [--apply]` | the key-read probe: the hub-link email router's own rendered run spec, without its secret volume, `lstat`-ing the local router's key paths; PASS only when none exists inside it. Runs only with `--apply`, and writes its record (bound to the run spec, the key path, the candidates and the probe) into the run directory for the plan to place ([runbook](docs/TUTORIAL.md#the-local-routers-signing-key)) |
| `hub-supervise [--spec FILE] [--apply]` | the hub-link email router's supervisor and the weekly login probe's job, from the host-setup document's `supervision` section: on Linux a systemd unit (`RestartPreventExitStatus=2 3 4 5 6 7 8 9 10 11`, `SuccessExitStatus=143`, `docker stop -t 100` under `TimeoutStopSec=120`) and a service and timer; on macOS a wrapper, run by its LaunchDaemon as `/bin/sh <wrapper>`, that maps the router's exit codes the same way, and a LaunchDaemon for the probe. Written into the run directory only with `--apply`; placing them is the plan's root step, and nothing is enabled: on macOS, where launchd loads every plist in `/Library/LaunchDaemons` at boot, the plan runs `launchctl disable system/<label>` for both labels before placing them, and `verify` FAILs a label that is not disabled unless every start check passes. Exit 143 differs by platform: on Linux it is a success and is not restarted; on macOS the wrapper passes it on and launchd restarts it |
| `hub-start-check [--spec FILE]` | every check that must pass before the hub-link email router starts: the secret's state is active, its files and rendering, the production overlay pin, the key probe's current evidence, the supervision's placed files, and that the router image's reviewed commit contains each required merge commit (`git merge-base --is-ancestor` in the runtime clone, and the image's revision label where it has one). On a pass, and only then, it prints the start step (`systemctl enable --now …`, or `launchctl enable system/<label>` then `launchctl bootstrap system …`) for the operator; it runs nothing |

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

## The hygiene gate

`amap-hygiene.py` finds private names and private fixture content in what a
public repository holds or is about to publish. The code is here; the lists
are private and are never in this repository. A writer's sandbox sees them
read-only at `~/.amap-hygiene`; the gate prints their sha256, so a stale
copy shows.

Before every push, PR, PR edit or comment to a public repository:

```sh
python3 amap-hygiene.py --lists ~/.amap-hygiene --repo <repo> \
    --range origin/<the PR's base>..HEAD --tree HEAD --refs --text <the PR body or comment>
```

`amap-hygiene.py install-hook --lists ~/.amap-hygiene --repo <repo>` installs
a `pre-push` hook that runs the same scan and blocks on a finding (exit 1)
and when the gate cannot run (exit 2), so a missing list never passes. A
finding names the location and the list entry's line number, never the
entry's text. Names are matched in text files only: a file with a NUL in
its first 8000 bytes (git's own test, which also classes UTF-16 text as
binary) is checked against the fixture file hashes but not read for names.

`amap-hygiene.py ci` is the scheduled run, in the private repository's CI:
every public fleet repository's refs, history and trees, and the text
GitHub holds beside them (pull requests, issues, comments, releases and
their assets, Actions logs and artifacts, the wiki), every read bounded. Its
`--verdicts` hand-over gives `success` or `failure` for each default-branch
and open pull-request head, decided ONLY by the git content that commit
fixes: its tree and every commit reachable from it. Branch and tag names
and everything GitHub holds as editable text can change without a new
commit, so they turn the scheduled run red but never fail a commit's
status.

A surface with a finding is never remembered as read: while it stays
public, every scheduled run reports it again. The incremental cache
(`--cache`) is used only for the same lists and the same gate commit, so a
change to either rescans everything. The token named by `--token-env` is
required in practice: the retained body revisions of an edited issue or
pull request are read through GraphQL, which answers no anonymous request,
so without it each such object is a LIMIT on every run.

What `ci` does not read, each a known limit:

- pull request review summaries (the body of an approval or a change
  request), as distinct from review comments;
- the edit history of a comment (issue, review or commit comment), only its
  current text;
- discussions (a repository with them enabled is a named LIMIT).

What it reads but cannot match:

- a streamed line over 1 MiB, which is scanned for names in overlapping
  pieces but never as a fixture line;
- an `allow` entry's span cut by a piece boundary on such a line, so the
  name it allows can be reported (a false positive, never a miss).

`fingerprint` refuses a fixture line that a public repository already
holds, but not a fixture file already public whole whose lines are all too
short or too regular to fingerprint. Under `--no-fingerprints` no fixture
content is matched at all, and every report says so.

A squash merge, and the default merge-commit message, copy the pull
request's title and body into a NEW commit on the default branch. A name in
a PR body therefore passes the pull request's own check and then lands on
main, where only the next scheduled run finds it. Set each public
repository's merge-message defaults so the PR body is not included.

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
