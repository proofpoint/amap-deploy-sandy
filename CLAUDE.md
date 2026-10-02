# CLAUDE.md: amap-deploy-sandy

`README.md` is the operator's map. This file is for **contributors**: the
conventions that are load-bearing, and what breaks if you violate them.

This repo deploys AMAP on a sandy host. It sits on the **connector side** of
the trust boundary: it installs a per-agent connector (as a sandy feature)
and renders the config for a router that runs elsewhere. Everything here runs
**host-side, as the operator**. Nothing runs inside a sandbox, and nothing
here can send or receive a message.

## Guardrails

- Keep shipped text **identifier-clean**: no absolute host paths, no personal
  names, no real addresses or domains. Use repo-relative paths, the
  `<SANDBOX_DIR>` / `$SANDY_HOME` placeholders, and `example.org` domains.
- **No credentials, ever.** This repo holds none and must acquire none.
- **Comments describe the present.** A comment that records history (revision
  ids, dates, "used to", "until") belongs in the commit message.

## Tests

```sh
python3 -m pytest tests -q
```

`tests/_workspace.py` finds the router by walking up for `amap-router-local`
(or through `$AMAP_ROUTER_REPO`) and confirms it by the presence of
`router/reset.py`. The connector is found the same way (`amap-connector-claude`,
`$AMAP_CONNECTOR_REPO`). **Without the router beside this repo the run fails;
it does not pass as a smaller green.** `amap_sandy` imports `router.config`
at module scope. `router_health.py` imports without the router.

`conftest.py` puts `tests/` on `sys.path` as a plain directory, so test
modules `import _workspace` and `_wrapper` directly. The modules are shared
within one test process, so a test that replaces a module attribute must
restore it (`addCleanup`).

**The suite never runs Docker, the router or sandy.** `conftest.py` replaces
`router_health.run` for the whole session with a refusal that every caller
reports as UNKNOWN. A test that reached them unpatched
would read the operator's live router. Sandy is stubbed with a fake
`--print-schema` / `--print-state`, and the fixtures write sandy's
`selected.json` under a temporary `$SANDY_HOME`.

**No pass/fail total goes in this file or any other.** A total asserts an
expected value with no derivation, goes stale on the next commit, and hides
per-platform failures. A proof is a specific input reaching a specific
assertion, and a total shows neither.

## The discipline behind `verify`

### Three outcomes, never two

`PASS` / `FAIL` / **`UNKNOWN`**. `Unresolved` is the value of a fact that
could not be computed. It is deliberately **not `None` and not an empty
collection**: its `__eq__` returns `False` against everything, including
itself, and `__hash__` is `None`, so comparing anything to it yields UNKNOWN,
never PASS.

**UNKNOWN never rounds to PASS, and `verify` reports it as a problem** and
exits 1 for it. One missing container is ONE failure: every property of a
container that is not there is UNKNOWN, not FALSE. Absence is decided by a
`docker ps` that succeeds and lists nothing, never by matching a daemon's
error prose.

Absent and empty are different answers. In the host-facts document,
`not_enrolled` is **omitted** when the lookup could not be made, and `[]`
only when sandy genuinely excluded nothing. Merging the two turns a failed
lookup into a clean bill of health.

### The literal budget

`tests/test_no_hardcoded_expectations.py` walks the AST. Inside every
`verify_*` **and any helper that calls `check()`/`unknown()`**, it enforces:

1. **No int literal** other than `0`, `1`, `2`.
2. **No string literal** that is not a key of `WIRE_NAMES` (a name another
   program emits or reads), a key of `FACT_SOURCES`, argv, or prose
   (`claim`/`remedy`/`do_not`/`reason`/`provenance`).

`Check.expected` is typed as a `Fact`, and `ctx.fact()` is the only way to
build one. So **every expected value comes from a Fact carrying a
provenance**, and a failure report can say *why* it expected that value. When
the budget refuses a string, ask what it is. If it is a name another program
chose, add it to `WIRE_NAMES` **with the reason**. If it is an expected
value, derive it. A count never belongs in `WIRE_NAMES`.

A non-passing `Check` **owes the operator a remedy**: `__post_init__` raises
without one. `do_not` is where you name the tempting wrong fix.

### A guard not proven to fire is not a guard

Break the world one way at a time, and require that the check *whose claim
names that thing* goes FAIL, not merely that something went red
(`HealthAssertionsActuallyFireTest`, `MountSetFollowsTheConfigTest`). Do the
same by hand when you add a check. A mutant that comes back **green** means
no test covered that guard.

**The inverse: a check that cannot PASS** teaches an operator to scroll past
it. The usual cause is a **fixture that invents a field the real producer
never emits**. Build fixtures from what the producer actually prints, and say
in the docstring where it was measured.

**To pin that A causes B, assert B on a surface where A is the only thing
that could have produced it.** Pick that surface by asking which producers
can reach the observable, and do it when you choose the surface, not when
you read a green result.

**When a mechanism is replaced, grep the suite for its names the same
hour.** A faithful assertion of a retired mechanism passes its own mutation
perfectly: it is green, mutation-proven, and about nothing. Delete the half of
each check that can no longer fire, and keep the half that still bites.

### The router's facts come from its own document

`router_health` reads the router's view of the fleet (`admitted`) and its
poll interval (`interval_s`) from the router's `status.json`, never from its
logs and never from an option. A field the router omitted is UNKNOWN, never
defaulted. The freshness bound is `FRESHNESS_MULTIPLE` × `interval_s`.

### `--host-facts` is a consumed contract

amap-router-local's operator console reads `verify --host-facts PATH` and
refuses a `schema` it does not recognise. **A shape change is a
`HOST_FACTS_SCHEMA` bump and a word to the router**, never a silent edit.

The document carries these fields:

- `generated_ts`
- `exit_meaning`: `ok`, `failed` or `cannot_run`. `cannot_run` is neither
  success nor failure.
- `phases[]`: the two router sections, each with `checks[]` of
  `claim`/`result`/`remedy`, plus `reason` on an UNKNOWN
- `not_enrolled`

`expected`/`actual` values are omitted, because they hold host paths and the
document ends up on a web page. It is **written on every exit** of `verify`,
including an early `ProvisionError`, as `cannot_run` with no phases. When
you prove the contract, capture the degenerate document first.

## The deployment's shape

**The manifest is the policy.** `$SANDY_HOME/features/amap/feature.json` is
authored. Its `sandboxes`/`agents` blocks are the selection rule, and its
`feature` section is the fleet policy, which `fleet_policy.load_policy` reads
directly. Its `schema`, `create`, `mounts`, `entry`, `expose`, `agent_args`
and `receives` blocks belong to this repo: `install` rewrites them and
`verify` reports a hand edit as drift. **`receives: ["cross_session"]` is
rendered only where this host's sandy lists the key in `--print-schema`'s
`manifest.top_level_keys` and the value in `manifest.receives_values`**
(`sandy_accepts_receives`), because an unknown key or value refuses the whole
manifest. Where the schema cannot be read, the key is left as it is.
`router.json` beside it is **generated** in the router's exact vocabulary
and nothing else, because the router refuses an unknown key.

**Selection is sandy's, at launch.** The policy's include and exclude globs
go into the manifest verbatim. `fleet_policy.selection()` copies the rule and
never evaluates it. The selected set is what sandy reports, intersected with
what its verdict names. A sandbox not launched since the manifest was
written is `unknown`, and is never rounded to either answer.

**Two lanes, disjoint per ordered pair.** Mail (`peers`) is mutual.
Delegation (`task_graph`, rendered as the router's `peer_senders`) is
directed. A sender that could reach the same recipient on either lane would
get to choose which one, and the lanes carry different trust.
`policy_checks` refuses the overlap; the renderer never repairs it.

**The capability gate is membership, never a version.**
`sandy_manifest_capable` requires `--print-schema`'s `schema_version` to be
a token this repo has reviewed (`SANDY_SCHEMA_VERSIONS`). Tokens are opaque:
they are compared by membership and never parsed. When sandy bumps the token,
the gate goes FALSE; read what changed, then add the new token.

**The boundary is the read-only mount flag, not permission bits.** The agent
runs as the host uid and owns the payload's files, yet both a write and a
`chmod` return **`EROFS`**. Expect and assert `EROFS`, never `EACCES`.
**Verify the mount, never the host directory**: `verify_feature_mount` reads
the container's mount table.

**Nothing is written into a sandbox.** The install is the manifest and the
payload, once per host. The manifest's `agent_args` carry `--mcp-config` and
`--append-system-prompt-file`, both pointing at the read-only payload. What
sandy applied is recorded in the sandbox's `sandy-session.json` from its
**last** launch, so a disagreement with the manifest is LAG (relaunch), never
drift. A different path is a note; **a last launch that did not apply both
flags is a problem**, because that agent is delivered delegations it cannot
answer through the router. **Read it through `--print-state`** where sandy reports `marker`
(2.7.0+): `agent_args` and `cross_session_inbound` come from the record, and
a null there is read against `marker.state`. Sandy's host path contract makes
the host copy of the marker and the two settings files private, so reading
them directly is only the fallback for an older sandy.

**The cross-session verdict names what it covers** (`CROSS_SESSION_COVERAGE`).
Claude Code also reads `crossSessionInbound` from the workspace's committed
`.claude/settings.json` (tighten-only, which sandy neither writes nor
reports, so `verify` reads it with sandy's symlink, FIFO and size guards)
and from a `--settings` flag (last-wins, named where `agent_args` shows one).

**Two frames in one object.** In `--print-state`, `relay.path` is a
CONTAINER path and `relay.state_dir` is a HOST path.

### The daemon's contract is explicit variables

The connector's delivery daemon reads **explicit `AMAP_DELIVERY_*`
variables**, none of them defaulted, and refuses to start if a required one is
missing. `AMAP_DELIVERY_SELF`, its own address, is **optional by design**.
With no `fleet_domain` there is no address, and the daemon fails closed per
notice, loudly, rather than guessing. **Do not make a missing
`AMAP_FLEET_DOMAIN` fatal in the wrapper.** Once it is set, though, every gap
on the way to the address is fatal: the daemon must never start under an
address nobody named.

The address is `<sandbox_name>@<fleet_domain>`. `sandbox_name` is read in
the container from `/etc/sandy-session.json`, and the domain arrives as the
manifest's one `expose` entry. Translating sandy's facts into those
variables is **this repo's** job; the daemon stays host-agnostic.

**`payload/relay` is a checked-in file**, because nothing in it differs
between two sandboxes or two hosts. Edit it here, then run
`install --apply`; an edit to a deployed copy is drift. `tests/_wrapper.py`
executes the **shipped file** under `/bin/sh`, and there is no Python mirror
of it.

**`payload/handoff-sessions` is checked in the same way.** It is the session
lister the daemon runs as `AMAP_DELIVERY_SESSION_SOURCE`, and it reads pane
identity only through sandy's published pane-identity contract: the tmux
session `sandy`, the `@sandy_pane_agent` option, and `$SANDY_AGENT` as spawn
order. When any pane carries the option, only the options identify; a pane
without one is a user split or a teammate. **Never identify a pane by
`pane_index`**; in the four-agent grid it is not spawn order. `tests/test_handoff_sessions.py`
executes the shipped file against a fake `tmux` and a staged `/proc`.

### Authorisation is the router's

The daemon holds **no allowlist**, and nothing on the agent's side names whom
it may task. The router holds the graph and decides at submit time, and the
result is the only report of what happened. Do not reintroduce an
agent-side list.

**The fleet roster is not an allowlist.** The router writes `roster.json`
into `$SANDY_HOME/features/amap/roster/`, which the manifest mounts
read-only **as a directory** at `$AMAP_ROSTER_DIR`. It lists who exists,
never who may task whom.

- **Mount the directory.** The router replaces the file by rename, and a
  single-file bind would pin the old inode forever.
- **`install` creates the directory, never the router.** The router finds it
  at `dirname(selected_json)/roster`, never through a new `router.json` key.
- **The pointer and the mount travel together.** `verify` checks "pointer
  present ⇒ read-only mount declared".
- **Freshness is one number.** The agents are told "more than three intervals
  old", `verify` applies `FRESHNESS_MULTIPLE` × `interval_s`, and a test pins
  the prose to the constant. A missing `interval_s` is UNKNOWN, never
  defaulted.

### Payload text

- **`payload/INBOX-POLICY.md` is calibration, not enforcement.** Every agent
  receives it as part of its system prompt and pays for it on every turn, so
  it carries rules and no reasoning (the reasoning is in `POLICY.md`). **Never
  add a rule there that only works if the agent obeys it.** If a property
  matters, it belongs in the router.
- **`payload/mcp-servers.json` is one constant file**, rooted at the
  manifest's lane exports (`${AMAP_INBOX_DIR}`, `${AMAP_PEER_DIR}`,
  `${AMAP_OUTBOX_DIR}`). Never write `~` there (Claude Code does not expand
  it), never write a mount destination, and never a per-sandbox value. It
  grants MCP access; it is not delivery approval.

## Conventions

- **Dry run is the default** for every verb that writes; `--apply` is
  always explicit.
- **Nothing here writes under the router's `state_dir`.** The router takes
  an instance's first-sight snapshot on its own first poll, and a marker
  written by anything else would be a snapshot taken at the wrong moment.
  `install` creates the directory itself, empty, because `docker/run.sh`
  refuses a missing bind source rather than let Docker create it as root.
- **Never `mkdir` a sandbox directory or a lane tree.** Sandy creates both
  at launch. `install` creates only the empty `instances/` root, which the
  router mounts whole, so the router can start before any sandbox has
  launched.
- **The slug is the instance name.** One string names the sandbox, the
  router instance and the local part of the address. Nothing derives a
  second name, and nothing case-folds it.
- `fleet_policy.py` is a **library, not a CLI**, and **its pure core is a
  shared interface.** amap-deploy-openshell imports it from a sibling
  checkout rather than copying it. The functions, parameter names and key
  constants it may rely on are pinned in `tests/test_shared_policy_surface.py`,
  which also requires the module to import with the standard library alone.
  Changing one of them is a word to that repository first. `policy_checks.py`
  is not shared.
- **`router_health.py` shares only its three-outcome discipline** with the
  same consumer: the verdicts, `Unresolved`, `Fact`, `Check`, `check()`,
  `unknown()`, `same_set()` and `CannotRun`, and the behaviour that makes
  them the discipline. `tests/test_shared_router_health_core.py` pins them
  and that the module imports no router or sandy code. Everything else in
  it, including `Ctx`, `FACT_SOURCES`, `WIRE_NAMES`, `run_sections` and the
  two router sections, is internal: their facts reach this repo's sandy
  layout through `provisioner()`.
- **Scripts are launchers over modules.** `amap-sandy.py` is a ten-line
  launcher and the code is in `amap_sandy.py`: a hyphen means "run me", an
  underscore means "import me".
- **`docs/` is two documents with one job each.** `index.html` is the
  explainer (concepts and animated flows, one self-contained file served by
  GitHub Pages); `TUTORIAL.md` is the runbook. Concepts live only in the
  explainer. The setup commands appear in both, and
  `tests/test_docs_agree.py` fails if the explainer shows a command the
  runbook does not have word for word: change the runbook first.
- **Before renaming or moving a file, ask the consumers "do you name
  this?"**, not just "do you import this?". A marker filename or a spelled
  path is a dependency too.
