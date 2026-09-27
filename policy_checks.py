#!/usr/bin/env python3
"""policy_checks.py — what the authored manifest's policy must satisfy before
any sandbox is provisioned under it. A library, not a CLI.

The policy is authored IN the feature manifest (`$SANDY_HOME/features/amap/
feature.json`, `feature` section; `fleet_policy.load_policy` reads it there).
The operator edits the file in place, and `amap-sandy.py install` validates
it on the write path with the checks below, refusing to provision until they
pass and naming what to edit:

  - `check_ratification`: pure functions of the file. The recreation cadence
    must be present (writing it into the manifest is the operator's
    ratification of it), and a task graph with edges must have a
    `fleet_domain` to address them with.
  - `check_resolve_peers` / `check_disjoint`: against the PROJECTED
    membership (`projected_membership`) — what sandy reports at all plus what
    it has selected — because on a fresh fleet nothing is selected yet and a
    `peers` key naming a real sandbox would otherwise be refused for no
    reason. The disjointness rule is `fleet_policy.overlapping_pairs`.
  - `selection_report`: the rule beside sandy's CURRENT verdicts, never a
    prediction.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

import fleet_policy as fp

def selection_report(policy: Dict[str, Any], boxes: List[Dict[str, Any]],
                     states: Dict[str, Tuple[str, str]]) -> str:
    """What this candidate's selection rule IS, beside what sandy CURRENTLY
    reports for every sandbox — never a prediction of what sandy will
    decide. The rule is rendered verbatim into the manifest and evaluated
    by sandy at each launch (one matcher, sandy's); the verdicts shown are
    from each sandbox's LAST launch and change at its next one, which is
    exactly why they are labelled as such rather than bucketed as
    "would select"."""
    sel = fp.selection(policy)
    lines = ["this candidate's selection rule (rendered into the manifest; sandy applies it at "
             "every launch):"]
    for key in (fp.SANDBOXES_KEY, fp.AGENTS_KEY):
        lines.append(f"  {key}: include {sel[key][fp.SELECTION_INCLUDE]!r}, "
                     f"exclude {sel[key][fp.SELECTION_EXCLUDE]!r}")
    lines.append("sandy's CURRENT verdict per sandbox (its last launch; the next launch re-decides "
                 "under this candidate):")
    if not boxes:
        lines.append("  sandy reports no sandboxes")
    for box in boxes:
        slug = box.get("name") or ""
        if not slug:
            continue
        state, detail = states.get(slug, ("unknown", "no verdict"))
        lines.append(f"  {slug}: {state} — {detail}")
    return "\n".join(lines)


def projected_membership(membership: Dict[str, dict],
                         boxes: List[Dict[str, Any]]) -> Dict[str, dict]:
    """The membership `resolve_peers` must be checked against: what sandy
    reports as selected now, plus EVERY sandbox sandy reports at all.

    These checks run before the launches at which sandy evaluates the
    candidate's rule, so on a fresh fleet nothing is
    selected yet and a `peers` key naming a real sandbox would be refused
    for no reason. Every sandbox sandy reports is a candidate for
    selection, so the projection is the reported set — and a name in
    `peers`/`groups` that sandy does not report AT ALL is still a ghost and
    still refused. The added entries are empty records: the instance name
    is the slug."""
    projected = dict(membership)
    for box in boxes:
        slug = box.get("name")
        if slug:
            projected.setdefault(slug, {})
    return projected


def check_resolve_peers(policy: Dict[str, Any], enrolled_record: Dict[str, dict], prov: Any) -> None:
    """Runs `fleet_policy.resolve_peers` against the membership passed in —
    see `projected_membership` for which one that must be and why. This is
    the same resolution the router-config render makes. `load_policy`
    validates the candidate's SHAPE; `resolve_peers` additionally refuses a
    `peers` key naming an instance that is not selected and a `groups`
    member the fleet does not currently select.

    Raises `fleet_policy.PolicyError` unmodified on a refusal — this
    function adds no rules of its own, it just also runs the ONE MORE check
    the render does that the loader alone does not."""
    names_by_slug = prov.instance_names(enrolled_record)
    fp.resolve_peers(policy, list(names_by_slug.values()), enrolled_record)


def check_ratification(policy: Dict[str, Any]) -> List[str]:
    """The refusals that need NOTHING but the candidate itself: the
    recreation cadence must be present, and a task graph with edges must
    have a `fleet_domain` to address them with. Returns one line per
    failure; empty means it passed.

    These are hard refusals, not `--apply` gates like the
    `resolve_peers`/overlap checks below, and the difference is real rather
    than stylistic: those two depend on what sandy currently reports, so
    "the check could not run" is a state they have to distinguish and be
    polite about. These two are pure functions of the file, so there is no
    such state — a candidate that fails one is wrong on every fleet, on
    every host, forever, and printing it as a warning on a dry run would
    only teach an operator to scroll past it.

    WHY THE CADENCE IS REQUIRED RATHER THAN DEFAULTED. Writing it in IS the
    operator's ratification of the number. A default would mean this repo
    carries a recreation cadence nobody typed, and the
    launchd job would then run on a schedule that appears in no reviewed
    artifact. `fleet_policy.load_policy` validates the field's SHAPE when it
    is present and says nothing about its absence, precisely so that this
    is the one place absence is decided.

    WHY A DOMAIN IS REQUIRED FOR EDGES. Every peer address is
    `<instance>@<fleet_domain>`; without a domain no edge has an address
    at either end, and the router's own loader refuses `peer_senders`
    without one. Refusing here means that error never
    reaches the operator from a file they did not edit."""
    problems: List[str] = []
    if fp.RECREATE_INTERVAL_KEY not in policy:
        problems.append(
            f"{fp.RECREATE_INTERVAL_KEY!r} is missing. It has no default: writing it "
            "into the policy is what ratifies the container recreation cadence the "
            "launchd job runs at, and a cadence nobody typed is not a decision. Add "
            "it, in hours (for example 24).")
    graph = policy.get(fp.TASK_GRAPH_KEY) or {}
    # The wildcard declares an edge for every ordered pair of selected
    # instances, so it needs a domain for exactly the reason an explicit edge
    # does. The selected set is not readable here, so the edges cannot be
    # named — which does not weaken the refusal, only its message.
    wildcard = graph == fp.TASK_GRAPH_ALL
    has_edges = wildcard or any(senders for senders in graph.values())
    if has_edges and fp.FLEET_DOMAIN_KEY not in policy:
        edges = ("every ordered pair of selected instances" if wildcard else
                 ", ".join(f"{s} -> {r}" for r in sorted(graph) for s in sorted(graph[r])))
        problems.append(
            f"{fp.TASK_GRAPH_KEY!r} declares edge(s) ({edges}) but the policy has no "
            f"{fp.FLEET_DOMAIN_KEY!r}. Every peer address is "
            "'<instance>@<fleet_domain>', so without one no edge has an address, and "
            "the router's own loader would refuse the config. Add it (a bare "
            "lowercase domain, for example 'agents.example.org').")
    return problems


def check_disjoint(policy: Dict[str, Any], enrolled_record: Dict[str, dict],
                   prov: Any) -> List[str]:
    """The disjointness refusal: no ordered pair may be declared on both
    lanes. Runs against the PROJECTED membership, for the same reason
    `check_resolve_peers` does (see `projected_membership`) — the mail
    matrix has to be resolved against the fleet this candidate would
    produce, not the one that exists now.

    The comparison itself, and why it is deliberately stricter than the
    router's own loader, is `fleet_policy.overlapping_pairs`."""
    names_by_slug = prov.instance_names(enrolled_record)
    names = list(names_by_slug.values())
    resolved = fp.resolve_peers(policy, names, enrolled_record)
    graph = fp.resolve_task_graph(policy, names)
    return fp.overlapping_pairs(policy, resolved, graph)
