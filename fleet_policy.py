"""fleet_policy.py — the fleet policy: its schema, its validation, and the
pure operations over it.

THE POLICY LIVES IN THE MANIFEST. `$SANDY_HOME/features/amap/feature.json`
is the authored document; its reserved `feature` key IS this schema, and
`load_policy` reads it from there. There is no separate policy file, so
every message here names the manifest's `feature` section — a remedy that
names a file the operator does not have points away from the fix at the
moment someone is least able to tell the two apart.

The policy answers two questions: which sandboxes are agents (the selection
rule, which sandy evaluates), and who may reach whom (the mail matrix and
the delegation graph, which the router enforces). This module is the pure,
I/O-light core both consumers of those answers share. It performs exactly
one piece of I/O itself (`load_policy` reads the manifest); everything else
is pure functions over already-loaded data.

THE SCHEMA (the manifest's `feature` section), pinned:

    {
      "version": 1,
      "sandboxes":     { "include": ["*"], "exclude": ["*redteam*"] },
      "agents":        { "include": ["claude"], "exclude": [] },
      "groups":        { "team": ["alpha-11111111", "bravo-22222222"] },
      "default_peers": [],
      "peers":         { "alpha-11111111": ["@team", "charlie-33333333"],
                         "some-hub":       ["ALLOW_ANY"] },
      "fleet_domain":  "agents.example.org",
      "task_graph":    { "bravo-22222222": ["alpha-11111111"] },
      "container_recreate_interval_hours": 24
    }

SEMANTICS:

  - Keys and values in `peers`/`groups`/`task_graph` are ROUTER INSTANCE
    NAMES — which are the sandy slugs, verbatim: the router accepts the slug
    alphabet, so the instance name is what the router config is keyed on,
    what `state_dir/<name>/` is called, and what sandy calls the sandbox.
  - `@name` references a group. `@` cannot occur in an instance name
    (alphabet `[A-Za-z0-9._-]`), so the sigil is unambiguous. Groups do not
    nest — a `@` inside a group's own member list is a load-time error.
  - `@all` is a built-in group meaning every selected instance — the
    built-in name `all` is reserved and cannot be redefined in `groups`.
  - `ALLOW_ANY` is the router's own sentinel; passed through untouched to
    the rendered config, never expanded.
  - An instance absent from `peers` gets `default_peers`.
  - `sandboxes` and `agents` are the SELECTION RULE (sandy's feature
    manifest): each is an `include` list and an `exclude` list of globs in
    sandy's own selector syntax. `sandboxes` patterns match the slug;
    `agents` patterns match the agent the launch runs. A sandbox is selected
    iff it matches an include in BOTH blocks and an exclude in NEITHER —
    exclude wins. An exact slug is a pattern with no wildcard and `"*"` is
    everyone. The rule is rendered VERBATIM into the manifest's
    `sandboxes`/`agents` blocks and EVALUATED BY SANDY at every launch; this
    module never evaluates it (one matcher, sandy's, and `selected.json` is
    its verdict). Selection IS enrolment: there is no enrol list, no marker,
    and no enrol command.
  - No policy -> `default_policy()` below: `default_peers: ["@all"]`, a full
    mail mesh over the selected set. `load_policy` marks the returned dict so
    a caller can print a one-line "here is how to create one" notice without
    re-deriving "was this file present" itself.

`ALLOW_ANY` MIXED WITH EXPLICIT NAMES IN ONE LIST IS A HARD VALIDATION
ERROR, not a silent "ALLOW_ANY wins" or a silent "the explicit names win".
Two readings are both plausible on sight — "ALLOW_ANY plus some names" could
mean "open to everyone" (the names are then dead weight) or "open only to
these, ALLOW_ANY was a leftover typo" (ALLOW_ANY is then silently discarded)
— and they describe materially different security postures for the instance
in question. Either silent resolution discards half of what the operator
apparently intended, and the whole point of this policy layer (see
`one_sided`, below) is refusing to guess at intent from something that
merely parses. So `load_policy` refuses outright, naming the field and the
offending entries, and the operator picks one explicitly. This applies to
every place a peer LIST appears — `peers.*` and `default_peers` — but never
inside a `groups` entry, because a group is a set of instance names by
definition and `ALLOW_ANY` appearing there is refused as a different error
(a group is not a peers list).

MUTUALITY IS REPORTED, NEVER SILENTLY REPAIRED (`one_sided`, below). A cold
send on the mail lane needs BOTH sides to list the other (amap-router-local,
`router/binding.py:check_cold`). `resolve_peers` emits exactly what the
policy declares and never auto-symmetrizes — silently adding the reverse
edge would grant reach the operator never expressed. In JSON a one-sided
entry looks entirely correct and is inert; `one_sided` is the thing that
makes that visible.

SELECTION NEVER READS THE WORKSPACE. A workspace's own config — including
one COMMITTED TO A REPOSITORY — is passive-tier: it can enable behaviour
with no operator prompt ever shown. The `sandboxes` patterns are matched by
sandy against the slug only — never a file inside the workspace — and this
module never matches them at all.

THE RULE IS THE HUMAN ACT. Editing `sandboxes`/`agents` is a policy edit an
operator makes; `install --apply` renders it into the feature manifest, and
sandy evaluates it at every launch, so a new sandbox that matches is an
agent from its first launch, and the router admits it by sandy's verdict.
There is no later `approve`: the router snapshots the instance's outbox on
FIRST SIGHT — the first poll that reaches its root, before it drains
anything — and never delivers what was staged before then
(amap-router-local, `router/firstsight.py`). So the moment that matters is
the render-and-start, and a policy that selects sandboxes is a REVIEWABLE
PLAN whose consequence is exactly that. Membership is read back from sandy
(`selected.json`, `--print-state`'s `features`), never predicted here: one
matcher, and it is sandy's.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

# ---------------------------------------------------------------- constants

# There is no separate policy file: the policy lives in the feature manifest
# (`$SANDY_HOME/features/amap/feature.json`, `feature` section) and
# `load_policy` reads it there. `amap_sandy.feature_manifest_path`
# is where a caller finds it.
SCHEMA_VERSION = 1

ALLOW_ANY = "ALLOW_ANY"          # the router's own sentinel; passed through, never expanded
GROUP_SIGIL = "@"
ALL_GROUP = "all"                # the reserved, built-in "every enrolled instance" group
# The selection rule, sandy's `sandboxes`/`agents` manifest blocks,
# carried in the policy under the same names and rendered verbatim. Each is
# `{"include": [globs], "exclude": [globs]}`; exclude wins; sandy evaluates it
# at every launch.
SANDBOXES_KEY = "sandboxes"
AGENTS_KEY = "agents"
SELECTION_INCLUDE = "include"
SELECTION_EXCLUDE = "exclude"
# Everyone, in sandy's selector syntax: a bare `*`. Not a keyword.
SELECT_ALL = "*"
# This feature's artefacts (the MCP registration, the policy prompt) are
# Claude-specific, so the default agent selection names claude alone.
DEFAULT_AGENT = "claude"


def default_selection() -> Dict[str, Dict[str, List[str]]]:
    """The selection an absent policy is treated as: every sandbox, launched
    with claude. A fresh copy each call — callers mutate nothing, but a
    shared dict is a shared bug."""
    return {SANDBOXES_KEY: {SELECTION_INCLUDE: [SELECT_ALL], SELECTION_EXCLUDE: []},
            AGENTS_KEY: {SELECTION_INCLUDE: [DEFAULT_AGENT], SELECTION_EXCLUDE: []}}

# ---- the delegation lane -----------------------------------------------------
#
# THREE OPERATOR VALUES. They are declared here, in the same document as the
# mail matrix, because the two declarations are checked AGAINST EACH OTHER:
# an ordered pair may appear on one lane or the other, never both (a sender
# that could reach a recipient on either lane gets to choose, and the lanes
# carry different trust). Splitting them across two files would make that
# check a cross-file concern and, eventually, an unchecked one.
#
#   fleet_domain                        the domain half of every agent address.
#                                       `<instance>@<fleet_domain>` on BOTH
#                                       lanes; an agent has exactly one
#                                       address.
#                                       Required for any peer edge.
#   task_graph                          the DIRECTED delegation graph,
#                                       {recipient: [sender, ...]} BY INSTANCE
#                                       NAME. Declared on the receiver, exactly
#                                       as the router's `peer_senders` is,
#                                       because the receiver is the party the
#                                       edge exposes. No wildcard, no group
#                                       reference, no mutuality ("ALL" is
#                                       the one wildcard; see TASK_GRAPH_ALL).
#   container_recreate_interval_hours   the recreation cadence the launchd job
#                                       runs at. No default anywhere:
#                                       `install` refuses to provision under a
#                                       policy that omits it, which is what
#                                       makes writing it in the operator's
#                                       ratification of the number.
#
# `peers`/`groups`/`default_peers` are the MAIL matrix.


# ---- the environment --------------------------------------------------------
#
# The variables these tools share are `$AMAP_<suffix>` — `$AMAP_ROUTER_REPO`,
# `$AMAP_CONNECTOR_REPO` — and every read goes through here.
def amap_env_named(suffix: str) -> Tuple[Optional[str], Optional[str]]:
    """`(VARIABLE_NAME, value)` for `$AMAP_<suffix>`, else `(None, None)`.

    The NAME is returned, not just the value, so that an error can say which
    variable led where: an operator told to check a variable they did not set
    concludes the discovery is broken rather than that their own path is.

    A set-but-empty value is treated as unset on purpose: `AMAP_ROUTER_REPO=`
    in a shell profile is how an operator disables an override, and returning
    `""` would make `Path("")` resolve to the cwd — a wrong checkout, found
    silently."""
    name = "AMAP_" + suffix
    value = os.environ.get(name)
    return (name, value) if value else (None, None)


def amap_env(suffix: str) -> Optional[str]:
    """`$AMAP_<suffix>`, or None when unset or empty."""
    return amap_env_named(suffix)[1]


def router_not_found_message(confirm_file: str) -> str:
    """Why the router checkout was not found, in the operator's own terms.

    ONE builder for every site that reports this, and two cases, because the
    distinction is the whole point:
      * a variable SUPPLIED a path — then that path is the only thing that was
        searched, and the message names the variable, its value, and what was
        missing inside it. Nothing else was looked at, so suggesting anything
        else would be a lie.
      * nothing was set — then the walk-up ran and found no checkout, and the
        remedy is to check one out or set the variable."""
    name, value = amap_env_named("ROUTER_REPO")
    if name:
        return (f"${name}={value} does not contain {confirm_file} — that is the "
                "only checkout that was searched, because the variable names it. "
                "Point it at the router checkout, or unset it to search for "
                f"{ROUTER_REPO_NAME} beside this checkout.")
    return (f"cannot locate the router checkout ({ROUTER_REPO_NAME}, identified by "
            f"{confirm_file}). Check it out beside this repository, or set "
            "$AMAP_ROUTER_REPO to its path.")


# The router checkout's directory name, for every walk-up that looks for it
# beside this one (`amap_sandy`, `tests/_workspace`).
ROUTER_REPO_NAME = "amap-router-local"


FLEET_DOMAIN_KEY = "fleet_domain"
TASK_GRAPH_KEY = "task_graph"
# The wildcard form of `task_graph`. "Every enrolled instance may task every
# other" — the common case on a single-host fleet, where adding an agent
# should not mean editing an edge list. EXPANDED HERE, never passed through:
# the router refuses a wildcard in `peer_senders` ("the task graph names
# instances, never a wildcard") so that the stored graph, `peers --json` and
# `derive_matrix` all keep enumerating who may task whom. Expanding in the
# renderer keeps that audit surface intact and needs no router change.
TASK_GRAPH_ALL = "ALL"
# Ordered pairs subtracted from whatever `task_graph` resolves to, wildcard
# or explicit. Deny always wins, so a block reads the same either way.
TASK_DENY_KEY = "task_deny"
RECREATE_INTERVAL_KEY = "container_recreate_interval_hours"

# The router's own local part (amap-router-local, `router/config.py:
# ROUTER_LOCAL_PART`). It is NEVER rendered into `may_task`/`tasked_by`: the
# router's DSNs arrive as mail, on the mail lane, and accepting `amap.router@`
# as a peer sender would be accepting the transport as a principal.
ROUTER_LOCAL_PART = "amap.router"

# A bare, lowercase domain label sequence -- the same shape the router's own
# loader enforces (`config.py`, `fleet_domain`). Deliberately NOT a general
# hostname validator: this value ends up as the right-hand side of every
# address an agent memorises, so an odd one is a flag day, and a narrow rule
# catches the typo at install time rather than at the first delegation.
FLEET_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")

ALL_GROUP_REF = GROUP_SIGIL + ALL_GROUP

# Marks a `load_policy()` return value that was SYNTHESIZED because no file
# existed at the given path, distinct from an on-disk policy that happens to
# have identical content — the caller (a CLI `main()`) uses this to decide
# whether to print the "no policy file, here is how to create one" notice.
# Not part of the pinned on-disk schema: nothing may write this key back into
# the manifest.
SOURCE_KEY = "_source"
SOURCE_DEFAULT = "default"


class PolicyError(Exception):
    """Operator-facing failure. Never includes a secret. Every raise here
    names the offending field and, where useful, the offending value — the
    same discipline `ProvisionError` follows in `amap_sandy`, so a policy mistake reads like a config mistake, not a
    traceback."""


# ------------------------------------------------------------------ loading

def default_policy() -> Dict[str, Any]:
    """The policy an absent `feature` section is treated as: full mail mesh,
    every sandbox launched with claude selected. `default_peers: ["@all"]`
    with no per-instance `peers` overrides makes `resolve_peers` hand every
    instance the full set of every OTHER selected instance, so "no policy"
    and "a policy that spells out the full mesh" are the same code path
    rather than two. (`install` still refuses to PROVISION under a manifest that
    omits the ratified fields; a default is what an absent file MEANS, not
    what an operator is allowed to leave unsaid.)"""
    return {
        "version": SCHEMA_VERSION,
        **default_selection(),
        "groups": {},
        "default_peers": [ALL_GROUP_REF],
        "peers": {},
        # Empty, not absent: "no delegation edges" is a real, renderable
        # answer, and every consumer may read `policy[TASK_GRAPH_KEY]`
        # without a `.get`. `fleet_domain` and
        # `container_recreate_interval_hours` are the opposite case and are
        # deliberately ABSENT here -- they have no defensible default, they
        # are operator decisions, and `install` refuses to provision under a
        # policy that omits the second one. Synthesising either would make
        # "the operator chose this" and "nobody chose anything"
        # indistinguishable, which is the exact confusion the
        # ratification step exists to remove.
        TASK_GRAPH_KEY: {},
    }


def _require_str_list(value: Any, where: str) -> List[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise PolicyError(f"{where}: expected an array of strings, got {value!r}")
    return value


MANIFEST_ONLY_KEYS = ("create", "mounts", "expose", "entry", "schema")


def is_manifest(raw: Dict[str, Any]) -> bool:
    """A feature manifest as opposed to a bare policy: a `feature` object
    beside at least one key only a manifest carries."""
    return isinstance(raw.get("feature"), dict) and any(k in raw for k in MANIFEST_ONLY_KEYS)


def load_policy(path: Path) -> Dict[str, Any]:
    """Load and validate `path`. Missing file -> `default_policy()`, marked
    with `SOURCE_KEY = SOURCE_DEFAULT` so a caller can emit the "no policy
    file, here is how to make one" notice without a second existence check
    that could disagree with this one under a race. A present-but-malformed
    file FAILS LOUD, naming the offending field — silently falling back to
    the default here would be indistinguishable from "operator has no
    opinion" when the truth is "operator's opinion doesn't parse", and the
    two need very different responses.

    Validates everything checkable from the file's own content alone:
    shape/types, group nesting (`@` inside a group), `ALLOW_ANY` mixed with
    other entries in one peers list (see the module docstring for why this
    is a hard error rather than a silent pick), and that every `@group`
    reference in a peers-shaped list resolves to a real group or the
    built-in `@all`. What it CANNOT validate — whether a group or peer names
    a currently enrolled instance — needs the enrolled set, which this
    function deliberately never reads (`load_policy` is I/O-limited to the
    policy file itself); that half of validation lives in `resolve_peers`.
    """
    path = Path(path)
    if not path.is_file():
        default = default_policy()
        default[SOURCE_KEY] = SOURCE_DEFAULT
        return default

    try:
        text = path.read_text()
    except OSError as e:
        raise PolicyError(f"cannot read {path}: {e}")
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as e:
        raise PolicyError(f"{path} is not valid JSON: {e}")
    if not isinstance(raw, dict):
        raise PolicyError(f"{path}: expected a JSON object at the top level")

    # THE MANIFEST IS THE POLICY. `$SANDY_HOME/features/amap/feature.json`
    # carries the selection rule at top level (sandy reads those) and the
    # rest of the policy under its reserved `feature` section (sandy carries
    # it untouched and never reads it). Recognised by shape — a `feature`
    # object beside the mechanical blocks only a manifest has — and folded
    # into the one policy document every rule below validates. A bare policy
    # document (no manifest blocks) loads by the same rules.
    if is_manifest(raw):
        feature = raw["feature"]
        if not isinstance(feature, dict):
            raise PolicyError(f"{path}: `feature` must be an object — it is where the policy "
                              f"lives in the manifest")
        folded: Dict[str, Any] = {}
        for key in (SANDBOXES_KEY, AGENTS_KEY):
            if key in raw:
                folded[key] = raw[key]
        for key, value in feature.items():
            if key in (SANDBOXES_KEY, AGENTS_KEY):
                raise PolicyError(f"{path}: `feature.{key}` — the selection rule lives at the "
                                  f"manifest's top level, where sandy reads it, not in `feature`")
            folded[key] = value
        raw = folded

    if SOURCE_KEY in raw:
        raise PolicyError(
            f"{path}: '{SOURCE_KEY}' is reserved — this loader sets it to record "
            "whether a policy file existed, so a value written here is overwritten "
            "and lost rather than round-tripped. Rename it (a leading 'x-' is safe; "
            "unknown keys are preserved verbatim).")

    version = raw.get("version", SCHEMA_VERSION)
    if version != SCHEMA_VERSION:
        raise PolicyError(
            f"{path}: 'version' is {version!r} — this build only understands "
            f"{SCHEMA_VERSION}. Written by a newer or older tool than this one?"
        )

    selection = {}
    for block_key in (SANDBOXES_KEY, AGENTS_KEY):
        block = raw.get(block_key, default_selection()[block_key])
        if not isinstance(block, dict):
            raise PolicyError(f"{path}: {block_key!r} must be an object with "
                              f"{SELECTION_INCLUDE!r} and {SELECTION_EXCLUDE!r} lists")
        unknown = sorted(set(block) - {SELECTION_INCLUDE, SELECTION_EXCLUDE})
        if unknown:
            raise PolicyError(f"{path}: {block_key}: unknown key(s) {unknown} — only "
                              f"{SELECTION_INCLUDE!r} and {SELECTION_EXCLUDE!r}, which is "
                              f"also all sandy's manifest reader accepts")
        selection[block_key] = {
            SELECTION_INCLUDE: list(_require_str_list(
                block.get(SELECTION_INCLUDE, []), f"{path}: {block_key}.{SELECTION_INCLUDE}")),
            SELECTION_EXCLUDE: list(_require_str_list(
                block.get(SELECTION_EXCLUDE, []), f"{path}: {block_key}.{SELECTION_EXCLUDE}")),
        }
        for pattern in selection[block_key][SELECTION_INCLUDE] + selection[block_key][SELECTION_EXCLUDE]:
            if not pattern:
                raise PolicyError(f"{path}: {block_key}: an empty pattern matches nothing "
                                  f"and reads as a mistake — delete it")
            # Sandy matches these as shell `case` patterns and refuses none: a
            # broken pattern simply never matches, and the sandbox lands in
            # `not_selected` with a reason that reads as intentional ("no
            # sandboxes include matched"). The one shape that is never a
            # pattern anyone meant is refused here, where the file was
            # edited: a bracket expression that does not close, or whitespace
            # (a slug never carries any).
            if pattern.count("[") != pattern.count("]"):
                raise PolicyError(f"{path}: {block_key}: pattern {pattern!r} has an unclosed "
                                  f"bracket expression — sandy would match it against "
                                  f"nothing and report the sandbox as excluded, not the "
                                  f"pattern as broken")
            if any(c.isspace() for c in pattern):
                raise PolicyError(f"{path}: {block_key}: pattern {pattern!r} contains "
                                  f"whitespace, which no slug or agent name carries — it "
                                  f"would match nothing, silently")

    groups_raw = raw.get("groups", {})
    if not isinstance(groups_raw, dict):
        raise PolicyError(f"{path}: 'groups' must be an object of {{name: [instance names]}}")
    if ALL_GROUP in groups_raw:
        raise PolicyError(
            f"{path}: groups.{ALL_GROUP!r} is reserved for the built-in full-mesh group "
            f"(every enrolled instance, referenced as {ALL_GROUP_REF!r}) — rename this group"
        )
    for gname, members in groups_raw.items():
        _require_str_list(members, f"{path}: groups.{gname}")
        for m in members:
            if GROUP_SIGIL in m:
                raise PolicyError(
                    f"{path}: groups.{gname} lists {m!r} — groups do not nest, a {GROUP_SIGIL!r} "
                    "inside a group's own member list is not allowed (name a router instance here, "
                    "not another group)"
                )
            if m == ALLOW_ANY:
                raise PolicyError(
                    f"{path}: groups.{gname} lists the literal {ALLOW_ANY!r} — a group is a set of "
                    "instance names; ALLOW_ANY belongs directly in a peers/default_peers list, not "
                    "inside a group"
                )

    known_group_refs = {GROUP_SIGIL + g for g in groups_raw} | {ALL_GROUP_REF}

    def _check_peer_list(value: Any, where: str) -> List[str]:
        lst = _require_str_list(value, where)
        if ALLOW_ANY in lst and len(lst) > 1:
            others = sorted(set(lst) - {ALLOW_ANY})
            raise PolicyError(
                f"{where}: {ALLOW_ANY!r} cannot be mixed with other entries in the same list "
                f"(also has {others}) — see the module docstring's 'THE DECISION' section: this "
                "reads as two different, incompatible intents (open to everyone vs. open only to "
                "these), and picking one silently would discard the other. State one explicitly: "
                f"either {ALLOW_ANY!r} alone, or the explicit list without it."
            )
        for entry in lst:
            if entry == ALLOW_ANY:
                continue
            if entry.startswith(GROUP_SIGIL) and entry not in known_group_refs:
                raise PolicyError(
                    f"{where}: {entry!r} references no group in 'groups' and is not the "
                    f"built-in {ALL_GROUP_REF!r}"
                )
        return lst

    default_peers = _check_peer_list(raw.get("default_peers", []), f"{path}: 'default_peers'")

    peers_raw = raw.get("peers", {})
    if not isinstance(peers_raw, dict):
        raise PolicyError(f"{path}: 'peers' must be an object of {{instance name: [peer entries]}}")
    for name, lst in peers_raw.items():
        _check_peer_list(lst, f"{path}: peers.{name}")

    # ---- the peer lane -------------------------------------------------
    # Shape only. Whether a name in `task_graph` is an ENROLLED instance
    # needs the enrolled set, which this function never reads (same
    # division of labour the mail matrix already has: shape here,
    # membership in `resolve_peers`/`resolve_task_graph`). Whether the two
    # declarations overlap needs the RESOLVED matrix, so it lives in
    # `overlapping_pairs`, called by `policy_checks` on the write path.
    fleet_domain = raw.get(FLEET_DOMAIN_KEY)
    if fleet_domain is not None:
        if not isinstance(fleet_domain, str) or not FLEET_DOMAIN_RE.match(fleet_domain):
            raise PolicyError(
                f"{path}: {FLEET_DOMAIN_KEY!r} is {fleet_domain!r} — expected a bare, "
                "lowercase domain label sequence such as 'agents.example.org' (no scheme, "
                "no port, no trailing dot, no uppercase). This value is the right-hand "
                "side of every address an agent memorises; changing it later is a flag "
                "day, so it is checked narrowly here rather than at the first delegation."
            )

    graph_raw = raw.get(TASK_GRAPH_KEY, {})
    _check_task_deny_shape(raw.get(TASK_DENY_KEY) or [],
                           f"{path}: {TASK_DENY_KEY!r}")
    # The wildcard form. Accepted HERE; expanded in `resolve_task_graph` for
    # this repo's own checks (the lane-overlap check), and RENDERED AS THE
    # ROUTER'S OWN TOP-LEVEL WORD (`task_graph: "all"`) into the router's
    # config. The per-edge checks below police an edge LIST, and `ALL`
    # declares no edges to police.
    graph_is_wildcard = graph_raw == TASK_GRAPH_ALL
    if isinstance(graph_raw, str) and not graph_is_wildcard:
        raise PolicyError(
            f"{path}: {TASK_GRAPH_KEY!r}: the only string form is {TASK_GRAPH_ALL!r}; "
            f"got {graph_raw!r}. Anything else must be an explicit "
            "{recipient: [sender, ...]} map.")
    if not graph_is_wildcard and not isinstance(graph_raw, dict):
        raise PolicyError(
            f"{path}: {TASK_GRAPH_KEY!r} must be an object of "
            "{recipient instance name: [sender instance name, ...]} — the graph is "
            "DIRECTED and declared on the RECEIVER, the same way the router's "
            "per-instance `peer_senders` is — or the literal "
            f"{TASK_GRAPH_ALL!r}")
    # The per-edge checks below police an edge LIST; the wildcard declares no
    # edges to police. `graph_raw` is NOT flattened to {} here — doing that
    # rebuilt the returned policy with an empty graph, silently turning
    # "everyone may task everyone" into "nobody may task anyone" with no error
    # anywhere. Caught by `test_load_policy_accepts_the_wildcard`.
    for recipient, senders in ({} if graph_is_wildcard else graph_raw).items():
        where = f"{path}: {TASK_GRAPH_KEY}.{recipient}"
        _require_str_list(senders, where)
        if len(set(senders)) != len(senders):
            raise PolicyError(f"{where}: duplicate entries in {senders!r}")
        for sender in senders:
            if sender == ALLOW_ANY:
                raise PolicyError(
                    f"{where}: {ALLOW_ANY!r} is not permitted — the task graph names "
                    "instances, never a wildcard. A delegation edge is a named grant to "
                    "a named agent; there is no 'anyone may task me'.")
            if sender.startswith(GROUP_SIGIL):
                raise PolicyError(
                    f"{where}: {sender!r} is a group reference — the task graph names "
                    "instances directly. Groups expand to MUTUAL mail edges; a directed "
                    "delegation edge expanded from a group would grant N edges from one "
                    "line, which is exactly the review property this graph exists to keep.")
            if sender == recipient:
                raise PolicyError(f"{where}: an instance cannot task itself")

    interval = raw.get(RECREATE_INTERVAL_KEY)
    if interval is not None:
        if isinstance(interval, bool) or not isinstance(interval, int) or interval <= 0:
            raise PolicyError(
                f"{path}: {RECREATE_INTERVAL_KEY!r} is {interval!r} — expected a positive "
                "whole number of hours. Absent is also an answer here, and a different "
                "one: `install` refuses to provision under a manifest that omits "
                "this field, because installing it is what ratifies the cadence.")

    out = {
        "version": version,
        **selection,
        "groups": {k: list(v) for k, v in groups_raw.items()},
        "default_peers": list(default_peers),
        "peers": {k: list(v) for k, v in peers_raw.items()},
        TASK_GRAPH_KEY: (TASK_GRAPH_ALL if graph_is_wildcard
                         else {k: list(v) for k, v in graph_raw.items()}),
        TASK_DENY_KEY: [list(pair) for pair in (raw.get(TASK_DENY_KEY) or [])],
    }
    # Absent stays ABSENT, never `None` — a caller asking "did the operator
    # declare a fleet domain?" must get the same answer from the loaded
    # policy as from the file, and `{"fleet_domain": None}` is a third state
    # that means neither.
    if fleet_domain is not None:
        out[FLEET_DOMAIN_KEY] = fleet_domain
    if interval is not None:
        out[RECREATE_INTERVAL_KEY] = interval

    # Carry through anything we do not recognise, unchanged. Reconstructing
    # the policy from only the known keys would silently discard everything
    # else — `_comment` is the concrete case: JSON has no comments, and an
    # operator who documents their policy that way would lose the
    # documentation to whatever next writes the loaded policy back.
    #
    # Unknown keys are not validated — we do not know what they mean — but
    # preserving something we do not understand is strictly safer than
    # deleting it.
    for key, value in raw.items():
        if key not in out:
            out[key] = value

    return out


# --------------------------------------------------------------- selection

def selection(policy: Dict[str, Any]) -> Dict[str, Dict[str, List[str]]]:
    """The rule as the manifest carries it: `{sandboxes: {include, exclude},
    agents: {include, exclude}}`, copied so a caller can render it without
    aliasing the loaded policy. Never EVALUATED here — see the module
    docstring; sandy's `selected.json` is the verdict."""
    return {key: {SELECTION_INCLUDE: list(policy[key][SELECTION_INCLUDE]),
                  SELECTION_EXCLUDE: list(policy[key][SELECTION_EXCLUDE])}
            for key in (SANDBOXES_KEY, AGENTS_KEY)}


# --------------------------------------------------------------- resolving

def _expand_entries(
    entries: Iterable[str], owner: str, groups: Dict[str, List[str]], names: Set[str], where: str,
) -> List[str]:
    """One raw peers-shaped list (already load-time-validated for shape and
    the mixed-ALLOW_ANY case) -> the final, concrete peer list for `owner`:
    groups expanded, `@all` expanded to every currently enrolled instance,
    self-references dropped, sorted, deduped. `ALLOW_ANY` alone (never mixed
    — `load_policy` already refused that) short-circuits to `[ALLOW_ANY]`,
    since expanding groups underneath a sentinel that already means "every
    peer" would be pure waste.

    Every concrete name is checked against `names` (the CURRENTLY ENROLLED
    set) here, not only at load time, because `load_policy` never sees the
    enrolled set at all — a peers list naming an instance that is no longer
    selected must fail loud here rather than render a config
    with a dangling peer, which would silently block cold contact instead of
    erroring where an operator would see it."""
    entries = list(entries)
    if ALLOW_ANY in entries:
        return [ALLOW_ANY]
    out: Set[str] = set()
    for entry in entries:
        if entry == ALL_GROUP_REF:
            out |= names
        elif entry.startswith(GROUP_SIGIL):
            gname = entry[len(GROUP_SIGIL):]
            members = groups.get(gname)
            if members is None:
                # Reachable only if `resolve_peers` is called with a
                # hand-built policy dict that skipped `load_policy` (e.g. a
                # unit test) — `load_policy` itself already refuses an
                # unknown group reference before this ever runs on a
                # real policy file.
                raise PolicyError(f"{where}: {entry!r} references no group in 'groups'")
            unknown = [m for m in members if m not in names]
            if unknown:
                raise PolicyError(
                    f"the manifest's `feature` section: groups.{gname} names instance(s) not currently "
                    f"enrolled: {', '.join(sorted(unknown))} — a stale group member would "
                    "silently omit a peer edge (or, used the other direction, silently block "
                    "cold contact) rather than error where an operator would see it. Fix the "
                    "group, or widen the selection rule."
                )
            out |= set(members)
        else:
            if entry not in names:
                raise PolicyError(
                    f"{where}: peer {entry!r} is not a currently enrolled instance — rendering "
                    "this would produce a peer edge that dangles (silently blocking cold contact "
                    "rather than erroring, since the far side can never list a name that names "
                    "nothing). Enroll the instance, or remove it from the policy."
                )
            out.add(entry)
    out.discard(owner)  # self is never a peer
    return sorted(out)


def resolve_peers(
    policy: Dict[str, Any],
    instance_names: Iterable[str],
    enrolled_record: Optional[Dict[str, Any]] = None,
) -> Dict[str, List[str]]:
    """`{instance name: [resolved peer entries]}` for every name in
    `instance_names` (router instance names, NOT slugs — see the module
    docstring). Expands `@group` and `@all` references, drops self-
    references, sorts and dedupes; passes `ALLOW_ANY` through untouched.

    An instance ABSENT from `policy['peers']` gets the top-level
    `policy['default_peers']`.

    `enrolled_record` is accepted and unused: every caller passes the
    selected set, and nothing in the schema varies by it.
    """

    # A peers KEY naming no enrolled instance is a typo, and it fails OPEN:
    # the instance the operator meant to constrain silently keeps
    # `default_peers`, so asking for isolation yields the full mesh with no
    # diagnostic. Peer VALUES are already validated; the key case was not, and
    # it is the more dangerous of the two because the value case fails closed
    # (an edge that does not exist) while this one grants more reach than was
    # declared.
    _declared = policy.get("peers") or {}
    _known = set(instance_names) if not isinstance(instance_names, (list, tuple, set)) else set(instance_names)
    _stray = sorted(set(_declared) - set(_known))
    if _stray:
        raise PolicyError(
            "policy 'peers' names instance(s) that are not enrolled: "
            + ", ".join(_stray)
            + ". These entries do nothing, and the instances you meant to "
              "constrain silently keep their default peers — which is MORE "
              "reach than you declared, not less. Fix the spelling, or widen "
              "the selection rule. (Instance names are the sandy slugs, verbatim — "
              "`amap-sandy.py list` prints them with sandy's "
              "verdict.)")

    names: Set[str] = set(instance_names)
    groups = policy.get("groups", {})

    # Every GROUP is validated against the enrolled set up front, whether or
    # not it is actually referenced by any peers list — a stale member is
    # worth catching proactively on a fleet ops tool, not only the moment
    # someone happens to reference the group.
    for gname, members in groups.items():
        unknown = [m for m in members if m not in names]
        if unknown:
            raise PolicyError(
                f"the manifest's `feature` section: groups.{gname} names instance(s) not currently selected: "
                f"{', '.join(sorted(unknown))} — fix the group, or widen the selection rule."
            )

    raw_peers = policy.get("peers", {})
    top_default = policy.get("default_peers", [])

    resolved: Dict[str, List[str]] = {}
    for name in sorted(names):
        if name in raw_peers:
            entries, where = raw_peers[name], f"the manifest's `feature` section: peers.{name}"
        else:
            entries, where = top_default, "the manifest's `feature` section: default_peers"
        resolved[name] = _expand_entries(entries, name, groups, names, where)
    return resolved


def one_sided(resolved: Dict[str, List[str]]) -> List[str]:
    """The mutuality report: one line per ordered pair `(a, b)` where `a`'s
    resolved peers name `b` but `b`'s do not name `a` back (and `b` has not
    separately opened itself with `ALLOW_ANY`). A cold send `a -> b` needs
    BOTH sides (`router/binding.py:check_cold`), so every entry here is a
    peer edge that LOOKS present in the JSON and does nothing.

    An instance that declares `ALLOW_ANY` itself is skipped as the "a" side:
    `ALLOW_ANY` expresses no specific intent about any particular peer, so
    there is nothing pair-specific to warn about on its behalf — its
    inbound reachability from a given `b` still depends on whether `b` lists
    it (or `b` also declares `ALLOW_ANY`), and that IS reported, from `b`'s
    side, if `b` lists real names elsewhere.

    Never repairs anything — see the module docstring's MUTUALITY section.
    This is read-only over `resolved`; nothing here writes back a symmetric
    edge, which would grant reach the operator never actually expressed."""
    warnings: List[str] = []
    for a in sorted(resolved):
        peers_a = resolved[a]
        if ALLOW_ANY in peers_a:
            continue
        for b in peers_a:
            if b == ALLOW_ANY:
                continue
            peers_b = resolved.get(b, [])
            if a in peers_b or ALLOW_ANY in peers_b:
                continue
            warnings.append(
                f"one-sided peer entry — {a!r} lists {b!r} but {b!r} does not list {a!r}; "
                f"a cold send {a} -> {b} will be refused. Add {a!r} to {b!r} or remove {b!r} "
                f"from {a!r}."
            )
    return warnings


# ------------------------------------------------------- the peer lane
#
# Read-only functions over an already-`load_policy`-validated policy: the
# SINGLE derivation of the delegation graph this repo checks, so nothing
# here can disagree with itself about who may task whom. The router holds
# the graph and enforces it; nothing on the agent's side names it.


def address_for(name: str, fleet_domain: Optional[str]) -> str:
    """`<instance-name>@<fleet_domain>` — the one address an agent has, on
    both lanes. Mirrors amap-router-local's `router/config.py:address_for`
    exactly, including its behaviour without a domain (the bare name), so
    this repo and the router cannot disagree about what an agent is
    called."""
    if fleet_domain:
        return f"{name}@{fleet_domain}"
    return name


def router_address(fleet_domain: Optional[str]) -> Optional[str]:
    """`amap.router@<fleet_domain>`, or `None` without a domain. Rendered
    NEVER into `may_task`/`tasked_by`: the router's DSNs arrive as mail,
    and a daemon that admitted
    `amap.router@` as a peer sender would be treating the transport as a
    principal."""
    if not fleet_domain:
        return None
    return f"{ROUTER_LOCAL_PART}@{fleet_domain}"


def _check_task_deny_shape(raw: Any, where: str) -> None:
    """Shape of `task_deny`, checked identically at load time and at render
    time. One function because two copies drift: the loader would accept a
    policy the renderer later refuses, with the error naming a file the
    operator did not edit — the same failure `resolve_task_graph`'s stray-sender
    message already describes."""
    if not isinstance(raw, list):
        raise PolicyError(
            f"{where}: expected an array of [sender, recipient] pairs, got "
            f"{type(raw).__name__}")
    for entry in raw:
        if (not isinstance(entry, list) or len(entry) != 2
                or not all(isinstance(x, str) for x in entry)):
            raise PolicyError(
                f"{where}: every entry must be a two-element array "
                f"[sender, recipient] of instance names; got {entry!r}")
        if entry[0] == entry[1]:
            raise PolicyError(
                f"{where}: {entry[0]!r} -> {entry[1]!r} denies a self-edge, which is "
                "never granted in the first place")


def resolve_task_deny(
    policy: Dict[str, Any], instance_names: Iterable[str],
) -> Set[Tuple[str, str]]:
    """The denied ordered pairs, as `{(sender, recipient)}`.

    ORDERED, because the lane is. `["a", "b"]` blocks `a -> b` and says
    nothing about `b -> a`. A directed grant needs a directed block, or the
    deny list cannot express "a may task b but not the reverse" — which is
    most of why anyone writes one.

    A name that is not enrolled RAISES, and this is the stricter half of the
    rule `resolve_task_graph` already applies to stray keys. An inert deny is
    harmless in itself — it blocks a pair nothing granted. But the way one
    arises in practice is a TYPO in a pair the operator meant to block, and
    that fails OPEN: the block silently does not happen and the edge stays
    live. A stray edge grants nothing and is merely useless; a stray deny
    blocks nothing while looking exactly like a control."""
    names = set(instance_names)
    raw = policy.get(TASK_DENY_KEY) or []
    _check_task_deny_shape(raw, f"policy {TASK_DENY_KEY!r}")

    denied: Set[Tuple[str, str]] = set()
    for entry in raw:
        sender, recipient = entry
        unknown = sorted({sender, recipient} - names)
        if unknown:
            raise PolicyError(
                f"policy {TASK_DENY_KEY!r}: the pair {sender!r} -> {recipient!r} names "
                "instance(s) that are not enrolled: " + ", ".join(unknown)
                + ". A deny that names nothing blocks nothing, and it looks exactly "
                  "like a control that is working. Fix the name, or remove the entry. "
                  "(Instance names are the sandy slugs, verbatim — "
                  "`amap-sandy.py list` prints them.)")
        denied.add((sender, recipient))
    return denied


def resolve_task_graph(
    policy: Dict[str, Any], instance_names: Iterable[str],
) -> Dict[str, List[str]]:
    """`{recipient: [sender, ...]}` by INSTANCE NAME for every name in
    `instance_names`, sorted, with an instance nobody may task mapping to
    `[]`.

    `task_graph` is either an explicit `{recipient: [sender, ...]}` map or
    the literal `TASK_GRAPH_ALL`, which expands to every enrolled instance
    tasking every other. `task_deny` is subtracted from EITHER, so a block
    reads the same whichever form the graph takes.

    THE WILDCARD IS EXPANDED HERE FOR THIS REPO'S OWN CHECKS — the lane
    overlap check — and is NOT what the router is sent: the router's config
    carries its own top-level `task_graph: "all"`, which the router expands
    at load into exactly the sets this function produces, so `peers --json`
    and this agree. `router/config.py` refuses a wildcard INSIDE
    `peer_senders`, so a per-instance list always names instances.

    SELF IS EXCLUDED from the expansion. An instance tasking itself is
    meaningless, `derive_matrix` already special-cases `a == b`, and the
    router's disjointness check would be asked a question about a pair that
    cannot exist.

    Every instance this repo renders is a discovered, directory-per-slug
    instance, so the expansion cannot produce the namespace-mode peer target
    the router refuses. A renderer that grows namespace-mode support must
    filter here.

    Total over the enrolled set on purpose — the same shape the router's
    `peers --json` emits, for the same reason it gives: an ABSENT edge must
    be visible as an empty list rather than as a missing key, so
    `verify`'s element-for-element comparison covers every instance
    instead of only the ones that happen to have an edge. `[]` and "not in
    the document" are the same fact here, and only one of them can be
    diffed.

    Sorted for the same reason: `router/config.py:derive_peer_graph` sorts,
    so anything compared against it must sort too or the comparison reports
    drift on a reordering that changes nothing. The policy file's own order
    is not meaningful — the router stores `peer_senders` as a frozenset.

    Both a KEY and every VALUE must name a currently enrolled instance, and
    the two failures are different in kind. A stray VALUE is an edge that
    dangles: the sender does not exist, so the grant is inert. A stray KEY
    is worse in the same way `resolve_peers`'s stray key is worse — the
    instance the operator meant to expose keeps NO edges silently, so a
    delegation that was declared never happens and nothing says why. Both
    raise."""
    names = set(instance_names)
    denied = resolve_task_deny(policy, names)
    graph = policy.get(TASK_GRAPH_KEY) or {}

    if isinstance(graph, str):
        if graph != TASK_GRAPH_ALL:
            raise PolicyError(
                f"policy {TASK_GRAPH_KEY!r}: the only string form is "
                f"{TASK_GRAPH_ALL!r}; got {graph!r}. Anything else must be an explicit "
                f"{{recipient: [sender, ...]}} map.")
        return {
            recipient: sorted(s for s in names
                              if s != recipient and (s, recipient) not in denied)
            for recipient in sorted(names)
        }

    if not isinstance(graph, dict):
        raise PolicyError(
            f"policy {TASK_GRAPH_KEY!r}: expected a {{recipient: [sender, ...]}} map "
            f"or the literal {TASK_GRAPH_ALL!r}, got {type(graph).__name__}")

    stray = sorted(set(graph) - names)
    if stray:
        raise PolicyError(
            f"policy {TASK_GRAPH_KEY!r} names recipient instance(s) that are not "
            "enrolled: " + ", ".join(stray)
            + ". Those entries do nothing: the delegation edges you declared for them "
              "are never rendered, into the router's config or into any agent's "
              "peers.json, and the first symptom is a submit refused at run "
              "time with no trace of the declaration. (Instance names are the sandy "
              "slugs, verbatim — `amap-sandy.py list` prints "
              "them.)")

    out: Dict[str, List[str]] = {}
    for recipient in sorted(names):
        senders = graph.get(recipient, [])
        unknown = sorted(set(senders) - names)
        if unknown:
            raise PolicyError(
                f"the manifest's `feature` section: {TASK_GRAPH_KEY}.{recipient} names sender(s) that "
                "are not enrolled: " + ", ".join(unknown)
                + ". The router refuses a config whose `peer_senders` names no "
                  "configured instance, so this would be caught at render time as a "
                  "loader error naming a file the operator did not write. Enroll the "
                  "instance, or remove it from the graph.")
        out[recipient] = sorted(s for s in senders if (s, recipient) not in denied)
    return out


def transpose_task_graph(graph: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """`{sender: [recipient, ...]}` — every instance whose `peer_senders`
    names this one. Total over the same key set as `graph`, sorted.

    Whom each agent may address. Informational — the router holds anything
    off-graph regardless, so widening it locally buys nothing. Reply binding
    is the router's too (it sets `in_reply_to` iff it resolved the key from
    its own ledger); the daemon holds no copy of this list."""
    out: Dict[str, List[str]] = {name: [] for name in graph}
    for recipient, senders in graph.items():
        for sender in senders:
            out.setdefault(sender, []).append(recipient)
    return {name: sorted(rs) for name, rs in sorted(out.items())}


def overlapping_pairs(
    policy: Dict[str, Any], resolved_peers: Dict[str, List[str]],
    graph: Dict[str, List[str]],
) -> List[str]:
    """Every ordered pair `(sender -> recipient)` declared in the task graph
    that the RESOLVED mail matrix also declares, in either direction. One
    human-readable line each; empty means disjoint.

    WHY THE RESOLVED MATRIX AND NOT THE RAW KEYS. A policy may declare its
    mail pairs through `@group` references and `default_peers`; a raw-key
    comparison against `policy['peers']` would see the strings `"@team"`
    and `"@all"` and find no overlap with anything, every time. The check has to run on what those expand to.

    WHY EITHER DIRECTION, WHICH IS STRICTER THAN THE ROUTER. The router's
    own loader refuses only a MUTUAL mail pair that is also a peer edge (it
    asks `binding.check_cold`, which needs both sides). A one-sided mail
    entry is inert there. But a one-sided mail entry is an operator mistake
    by construction — `one_sided()` already reports it as present-but-inert
    — and refusing it here buys a property worth more than the strictness
    costs: the router's `ConfigError` becomes UNREACHABLE from any policy
    `install` accepted. An operator who fixes the one-sided entry the
    obvious way (adding the reverse) would otherwise turn a policy that
    installed cleanly into a config the router rejects, at render time, with
    an error naming a file they did not edit.

    `ALLOW_ANY` on an instance counts as every pair INTO it: the sentinel
    means "any enrolled instance may cold-contact me on the mail lane",
    which necessarily includes the one holding the delegation edge.

    Read-only. Never repairs, never drops an edge, never zeroes a matrix —
    the adapter renders what the policy says (round 3's correction) and this
    function only reports."""
    lines: List[str] = []
    for recipient in sorted(graph):
        for sender in graph[recipient]:
            mail_in = resolved_peers.get(recipient) or []
            mail_out = resolved_peers.get(sender) or []
            reasons = []
            if ALLOW_ANY in mail_in:
                reasons.append(f"peers.{recipient} is {ALLOW_ANY} (every instance, "
                               f"including {sender})")
            elif sender in mail_in:
                reasons.append(f"peers.{recipient} lists {sender}")
            if ALLOW_ANY in mail_out:
                reasons.append(f"peers.{sender} is {ALLOW_ANY} (every instance, "
                               f"including {recipient})")
            elif recipient in mail_out:
                reasons.append(f"peers.{sender} lists {recipient}")
            if reasons:
                lines.append(
                    f"{sender} -> {recipient} is declared on BOTH lanes: "
                    f"{TASK_GRAPH_KEY}.{recipient} lists {sender}, and " + "; ".join(reasons)
                    + ". The two declarations must be disjoint per ordered pair — a "
                      "sender that could reach the same recipient on either lane gets "
                      "to choose which one, and the lanes carry different trust. Remove "
                      "the pair from one of them.")
    return lines
