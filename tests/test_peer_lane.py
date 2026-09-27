"""The peer lane, end to end on this side of the seam.

One file because the renderings of the peer lane come from ONE declaration
and are checked against each other: splitting these across
`test_fleet_policy.py` and `test_provision_sandboxes.py` would put each half
of every agreement in a different place, which is how the halves drift.

WHAT IS PINNED HERE, AND WHAT IS NOT. Everything below is host-side: what
this repo renders, what it refuses, and what `verify` catches. The DAEMON's
behaviour (claims, injection, outcomes) belongs to amap-connector-claude and
is tested there. What can only be observed in a live container is a
documented manual check, named in `ManualCheckRegistryTest` so it cannot be
quietly forgotten.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import unittest

import _wrapper
import unittest.mock
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

import _workspace  # noqa: E402

_workspace.skip_if_incomplete()
_ROUTER_ROOT = _workspace.ROUTER_ROOT
if str(_ROUTER_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROUTER_ROOT))

_HERE = Path(__file__).absolute().parents[1]
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import fleet_policy as fp  # noqa: E402
import launchd_job as lj   # noqa: E402


import amap_sandy as prov  # noqa: E402

# The connector's state directory as the delivery daemon sees it INSIDE a
# container: every claim path it publishes is rooted here. A fixture value,
# spelled out because the module under test does not name it.
CONTAINER_CONNECTOR = "/home/claude/.claude/connector"

DOMAIN = "agents.example.org"


def _policy(**over):
    """A minimal ratifiable policy: a domain, a cadence, one directed edge,
    and a closed mail lane. Every refusal test below damages exactly one
    thing in it."""
    base = {
        "version": 1, **fp.default_selection(), "groups": {},
        "default_peers": [], "peers": {},
        fp.FLEET_DOMAIN_KEY: DOMAIN,
        fp.RECREATE_INTERVAL_KEY: 24,
        fp.TASK_GRAPH_KEY: {"bravo": ["alpha"]},
    }
    base.update(over)
    return base


def _write(d: Path, policy: dict, name: str = "candidate.json") -> Path:
    path = d / name
    path.write_text(json.dumps(policy, indent=2) + "\n")
    return path


# ============================================================ the declaration


class FleetDomainTest(unittest.TestCase):
    def test_a_bare_lowercase_domain_loads(self):
        with TemporaryDirectory() as d:
            policy = fp.load_policy(_write(Path(d), _policy()))
        self.assertEqual(policy[fp.FLEET_DOMAIN_KEY], DOMAIN)

    def test_absent_stays_absent_never_none(self):
        """`{"fleet_domain": None}` is a third state that means neither
        'declared' nor 'not declared', and every consumer asks the
        `is None` question."""
        with TemporaryDirectory() as d:
            raw = _policy()
            del raw[fp.FLEET_DOMAIN_KEY]
            raw[fp.TASK_GRAPH_KEY] = {}
            policy = fp.load_policy(_write(Path(d), raw))
        self.assertNotIn(fp.FLEET_DOMAIN_KEY, policy)

    def test_a_scheme_or_port_or_uppercase_is_refused(self):
        for bad in ("https://agents.example.org", "agents.example.org:25", "Agents.Example.Org",
                    "agents.example.org.", "agents..example.org", "", 25):
            with self.subTest(value=bad), TemporaryDirectory() as d:
                with self.assertRaises(fp.PolicyError) as ctx:
                    fp.load_policy(_write(Path(d), _policy(**{fp.FLEET_DOMAIN_KEY: bad})))
                self.assertIn(fp.FLEET_DOMAIN_KEY, str(ctx.exception))


class TaskGraphShapeTest(unittest.TestCase):
    def test_a_wildcard_sender_is_refused(self):
        with TemporaryDirectory() as d:
            with self.assertRaises(fp.PolicyError) as ctx:
                fp.load_policy(_write(Path(d), _policy(
                    **{fp.TASK_GRAPH_KEY: {"bravo": [fp.ALLOW_ANY]}})))
            self.assertIn(fp.ALLOW_ANY, str(ctx.exception))

    def test_a_group_reference_is_refused(self):
        """Groups expand to MUTUAL mail edges. A directed delegation edge
        expanded from a group would grant N edges from one reviewed line."""
        with TemporaryDirectory() as d:
            with self.assertRaises(fp.PolicyError) as ctx:
                fp.load_policy(_write(Path(d), _policy(
                    **{fp.TASK_GRAPH_KEY: {"bravo": ["@team"]}})))
            self.assertIn("group", str(ctx.exception))

    def test_a_self_edge_is_refused(self):
        with TemporaryDirectory() as d:
            with self.assertRaises(fp.PolicyError):
                fp.load_policy(_write(Path(d), _policy(
                    **{fp.TASK_GRAPH_KEY: {"bravo": ["bravo"]}})))

    def test_duplicate_senders_are_refused(self):
        with TemporaryDirectory() as d:
            with self.assertRaises(fp.PolicyError):
                fp.load_policy(_write(Path(d), _policy(
                    **{fp.TASK_GRAPH_KEY: {"bravo": ["alpha", "alpha"]}})))

    def test_a_non_object_graph_is_refused(self):
        with TemporaryDirectory() as d:
            with self.assertRaises(fp.PolicyError):
                fp.load_policy(_write(Path(d), _policy(**{fp.TASK_GRAPH_KEY: ["alpha"]})))


class RecreateIntervalShapeTest(unittest.TestCase):
    def test_a_positive_integer_loads(self):
        with TemporaryDirectory() as d:
            self.assertEqual(
                fp.load_policy(_write(Path(d), _policy()))[fp.RECREATE_INTERVAL_KEY], 24)

    def test_zero_negative_float_and_bool_are_refused(self):
        for bad in (0, -1, 24.5, True, "24"):
            with self.subTest(value=bad), TemporaryDirectory() as d:
                with self.assertRaises(fp.PolicyError):
                    fp.load_policy(_write(Path(d), _policy(
                        **{fp.RECREATE_INTERVAL_KEY: bad})))


class ResolveTaskGraphTest(unittest.TestCase):
    NAMES = ["alpha", "bravo", "charlie"]

    def test_every_instance_appears_even_with_no_edge(self):
        """`[]` and 'not in the document' are the same fact, and only one of
        them can be diffed element for element."""
        graph = fp.resolve_task_graph(_policy(), self.NAMES)
        self.assertEqual(sorted(graph), self.NAMES)
        self.assertEqual(graph["charlie"], [])

    def test_senders_are_sorted_to_match_the_routers_own_derivation(self):
        graph = fp.resolve_task_graph(
            _policy(**{fp.TASK_GRAPH_KEY: {"charlie": ["bravo", "alpha"]}}), self.NAMES)
        self.assertEqual(graph["charlie"], ["alpha", "bravo"])

    def test_a_stray_recipient_is_refused(self):
        with self.assertRaises(fp.PolicyError) as ctx:
            fp.resolve_task_graph(
                _policy(**{fp.TASK_GRAPH_KEY: {"ghost": ["alpha"]}}), self.NAMES)
        self.assertIn("ghost", str(ctx.exception))

    def test_a_stray_sender_is_refused(self):
        with self.assertRaises(fp.PolicyError) as ctx:
            fp.resolve_task_graph(
                _policy(**{fp.TASK_GRAPH_KEY: {"bravo": ["ghost"]}}), self.NAMES)
        self.assertIn("ghost", str(ctx.exception))

    # --- the wildcard form and its deny list ---------------------------

    def test_ALL_expands_to_every_pair_but_never_self(self):
        """An instance tasking itself is meaningless; derive_matrix already
        special-cases a == b, and the router's disjointness check would be
        asked about a pair that cannot exist."""
        graph = fp.resolve_task_graph(
            _policy(**{fp.TASK_GRAPH_KEY: fp.TASK_GRAPH_ALL}), self.NAMES)
        self.assertEqual(sorted(graph), self.NAMES)
        self.assertEqual(graph["alpha"], ["bravo", "charlie"])
        self.assertEqual(graph["charlie"], ["alpha", "bravo"])
        for name in self.NAMES:
            self.assertNotIn(name, graph[name])

    def test_a_deny_subtracts_one_DIRECTION_only(self):
        """The lane is directed, so the block must be. A deny list that blocked
        both ways could not express 'a may task b but not the reverse'."""
        graph = fp.resolve_task_graph(
            _policy(**{fp.TASK_GRAPH_KEY: fp.TASK_GRAPH_ALL,
                       fp.TASK_DENY_KEY: [["alpha", "bravo"]]}), self.NAMES)
        self.assertNotIn("alpha", graph["bravo"])
        self.assertIn("bravo", graph["alpha"])

    def test_a_deny_applies_to_an_EXPLICIT_graph_too(self):
        """Deny wins either way, so a block reads the same whichever form the
        graph takes."""
        graph = fp.resolve_task_graph(
            _policy(**{fp.TASK_GRAPH_KEY: {"bravo": ["alpha", "charlie"]},
                       fp.TASK_DENY_KEY: [["alpha", "bravo"]]}), self.NAMES)
        self.assertEqual(graph["bravo"], ["charlie"])

    def test_a_deny_naming_an_unselected_instance_is_refused(self):
        """The dangerous case. A stray EDGE grants nothing and is merely
        useless; a stray DENY blocks nothing while looking like a control, so
        a typo fails OPEN."""
        with self.assertRaises(fp.PolicyError) as ctx:
            fp.resolve_task_graph(
                _policy(**{fp.TASK_GRAPH_KEY: fp.TASK_GRAPH_ALL,
                           fp.TASK_DENY_KEY: [["alpha", "ghost"]]}), self.NAMES)
        self.assertIn("ghost", str(ctx.exception))
        self.assertIn("blocks nothing", str(ctx.exception))

    def test_a_malformed_deny_entry_is_refused(self):
        for bad in (["alpha"], "alpha", ["alpha", "bravo", "charlie"], [1, 2]):
            with self.subTest(entry=bad):
                with self.assertRaises(fp.PolicyError):
                    fp.resolve_task_graph(
                        _policy(**{fp.TASK_GRAPH_KEY: fp.TASK_GRAPH_ALL,
                                   fp.TASK_DENY_KEY: [bad]}), self.NAMES)

    def test_a_self_deny_is_refused_rather_than_silently_inert(self):
        with self.assertRaises(fp.PolicyError):
            fp.resolve_task_graph(
                _policy(**{fp.TASK_GRAPH_KEY: fp.TASK_GRAPH_ALL,
                           fp.TASK_DENY_KEY: [["alpha", "alpha"]]}), self.NAMES)

    def test_an_unknown_string_form_is_refused(self):
        """`ALL` is the only wildcard. A typo must not read as an empty graph."""
        with self.assertRaises(fp.PolicyError) as ctx:
            fp.resolve_task_graph(
                _policy(**{fp.TASK_GRAPH_KEY: "all"}), self.NAMES)
        self.assertIn("ALL", str(ctx.exception))

    def test_ALL_still_renders_an_enumerated_graph_not_a_wildcard(self):
        """The router refuses a wildcard in peer_senders so that the stored
        graph keeps naming instances. Expanding here is what lets an operator
        have zero-configuration defaults without costing that."""
        graph = fp.resolve_task_graph(
            _policy(**{fp.TASK_GRAPH_KEY: fp.TASK_GRAPH_ALL}), self.NAMES)
        for senders in graph.values():
            self.assertNotIn(fp.TASK_GRAPH_ALL, senders)
            self.assertTrue(all(s in self.NAMES for s in senders))

    def test_load_policy_accepts_the_wildcard(self):
        """The installer validates separately from the renderer. Teaching only
        one of them the wildcard means the installer accepts a policy the
        renderer refuses, or the reverse — an error naming a file the operator
        did not edit."""
        with TemporaryDirectory() as d:
            path = Path(d) / "p.json"
            path.write_text(json.dumps(
                {"version": 1, "fleet_domain": "x.example.org",
                 fp.TASK_GRAPH_KEY: fp.TASK_GRAPH_ALL, fp.TASK_DENY_KEY: []}))
            pol = fp.load_policy(path)
            self.assertEqual(pol[fp.TASK_GRAPH_KEY], fp.TASK_GRAPH_ALL)

    def test_load_policy_refuses_a_near_miss_wildcard(self):
        with TemporaryDirectory() as d:
            path = Path(d) / "p.json"
            path.write_text(json.dumps(
                {"version": 1, "fleet_domain": "x.example.org",
                 fp.TASK_GRAPH_KEY: "all"}))
            with self.assertRaises(fp.PolicyError) as ctx:
                fp.load_policy(path)
            # Pinned to THIS branch. The map-or-wildcard fallback below also
            # names ALL, so asserting only that would pass with this guard
            # removed — the same too-loose assertion this suite caught once
            # already.
            self.assertIn("the only string form is", str(ctx.exception))

    def test_load_policy_refuses_a_malformed_deny_at_INSTALL_time(self):
        """Shape is checked by the same helper the renderer uses, so the two
        cannot disagree about what a deny list looks like."""
        with TemporaryDirectory() as d:
            path = Path(d) / "p.json"
            path.write_text(json.dumps(
                {"version": 1, "fleet_domain": "x.example.org",
                 fp.TASK_GRAPH_KEY: fp.TASK_GRAPH_ALL,
                 fp.TASK_DENY_KEY: [["only-one"]]}))
            with self.assertRaises(fp.PolicyError):
                fp.load_policy(path)

    def test_the_transposition_is_total_and_sorted(self):
        graph = fp.resolve_task_graph(
            _policy(**{fp.TASK_GRAPH_KEY: {"charlie": ["bravo", "alpha"],
                                           "bravo": ["alpha"]}}), self.NAMES)
        t = fp.transpose_task_graph(graph)
        self.assertEqual(t["alpha"], ["bravo", "charlie"])
        self.assertEqual(t["bravo"], ["charlie"])
        self.assertEqual(t["charlie"], [])


class AddressingTest(unittest.TestCase):
    def test_an_agent_has_one_address_on_both_lanes(self):
        self.assertEqual(fp.address_for("alpha", DOMAIN), "alpha@agents.example.org")

    def test_the_routers_address_is_derived_never_declared(self):
        self.assertEqual(fp.router_address(DOMAIN), "amap.router@agents.example.org")

    def test_no_domain_means_no_router_address(self):
        self.assertIsNone(fp.router_address(None))

    def test_the_adapter_agrees_with_the_router_on_both(self):
        """Two repositories, one address. The router derives these itself and
        never reads ours, so nothing but this comparison keeps them equal."""
        from router.config import address_for as router_address_for, router_address
        for name in ("alpha", "bravo-lab-2b2b2b2b"):
            with self.subTest(name=name):
                self.assertEqual(fp.address_for(name, DOMAIN),
                                 router_address_for(name, DOMAIN))
        self.assertEqual(fp.router_address(DOMAIN), router_address(DOMAIN))


class DisjointnessTest(unittest.TestCase):
    """The disjointness refusal, and the two ways it is stricter than the router's."""

    NAMES = ["alpha", "bravo"]

    def _overlap(self, mail):
        policy = _policy(peers=mail)
        resolved = fp.resolve_peers(policy, self.NAMES)
        graph = fp.resolve_task_graph(policy, self.NAMES)
        return fp.overlapping_pairs(policy, resolved, graph)

    def test_a_closed_mail_lane_is_disjoint(self):
        self.assertEqual(self._overlap({}), [])

    def test_a_mutual_mail_pair_over_a_delegation_edge_is_refused(self):
        self.assertTrue(self._overlap({"alpha": ["bravo"], "bravo": ["alpha"]}))

    def test_a_ONE_SIDED_mail_entry_in_either_direction_is_refused(self):
        """Stricter than the router's loader on purpose: it refuses only a
        MUTUAL pair, so a one-sided entry installs cleanly here and becomes a
        router ConfigError the moment an operator 'fixes' it by adding the
        reverse — an error naming a file they did not edit."""
        self.assertTrue(self._overlap({"bravo": ["alpha"]}))     # recipient's side
        self.assertTrue(self._overlap({"alpha": ["bravo"]}))     # sender's side

    def test_ALLOW_ANY_counts_as_every_pair_into_that_instance(self):
        self.assertTrue(self._overlap({"bravo": [fp.ALLOW_ANY]}))

    def test_an_unrelated_mail_pair_is_not_an_overlap(self):
        """The check is per ORDERED PAIR, not per instance: a mail edge that
        does not touch the delegation pair must not be swept up."""
        names = self.NAMES + ["charlie", "delta"]
        policy = _policy(peers={"charlie": ["delta"], "delta": ["charlie"]})
        resolved = fp.resolve_peers(policy, names)
        graph = fp.resolve_task_graph(policy, names)
        self.assertEqual(fp.overlapping_pairs(policy, resolved, graph), [])

    def test_the_routers_own_loader_accepts_everything_this_check_passes(self):
        """THE PROPERTY the strictness buys: the router's ConfigError is
        unreachable from any policy the installer accepted. Driven through
        the router's REAL loader, not a restatement of its rule."""
        from router.config import load_obj
        with TemporaryDirectory() as d:
            root = Path(d)
            paths = {}
            for name in self.NAMES:
                (root / name).mkdir(parents=True)
                paths[name] = root / name
            policy = _policy()
            self.assertEqual(self._overlap({}), [], "precondition: disjoint")
            doc = prov.render_router_sibling(policy, {n: {} for n in self.NAMES}, root,
                                             root / "state", paths)["_doc"]
            load_obj(json.loads(json.dumps(doc)))       # must not raise


# ================================================== the write path's refusals
#
# On the authored manifest: a policy with an overlapping pair, or edges
# without a domain, is refused BEFORE the router ever sees it. The operator
# edits `feature.json` in place, and `install` refuses to provision under a
# policy that fails these checks (`policy_checks`), on the write path —
# reporting them on a dry run, exit 3 on `--apply`.


class SyncRefusalTest(unittest.TestCase):
    def _run(self, policy, *, apply=False, fleet=()):
        with TemporaryDirectory() as d:
            root = Path(d)
            home = root / "sandy-home"
            (home / "sandboxes").mkdir(parents=True)
            src = root / "bin"
            src.mkdir()
            for name in prov.CONNECTOR_BINARIES + prov.RELAY_CHAIN_COPIED:
                (src / name).write_text("#!/bin/sh\n")
                (src / name).chmod(0o755)
            for n in fleet:
                (home / "sandboxes" / n).mkdir()
            if fleet:
                _select(home, *fleet)
            fake = root / "sandy"
            schema = json.dumps({"schema_version": 3, "config": {},
                                 "manifest": {"top_level_keys": ["schema", "sandboxes", "agents",
                                                                 "create", "mounts", "entry", "expose",
                                                                 "feature", "agent_args"]},
                                 "agents": [{"name": "claude"}]})
            fake.write_text("#!/bin/sh\ncase \"$1\" in --print-schema) cat <<'EOF'\n" + schema
                            + "\nEOF\n;; --print-version) echo '{\"full_version\": \"2.2.0\"}';; "
                            "*) cat <<'EOF'\n" + json.dumps({"sandboxes": [
                {"name": n, "path": str(home / "sandboxes" / n),
                 "workspace_path": f"/ws/{n}", "features": [prov.FEATURE_NAME],
                 "agents": ["claude"]}
                for n in fleet]}) + "\nEOF\n;; esac\n")
            fake.chmod(0o755)
            manifest = prov.feature_manifest_path(home)
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_text(prov.manifest_text(policy))
            out, err = io.StringIO(), io.StringIO()
            argv = ["--sandy-home", str(home), "--sandy", str(fake),
                    "--connector-src", str(src), "install"]
            if apply:
                argv.append("--apply")
            with redirect_stdout(out), redirect_stderr(err):
                rc = prov.main(argv)
            # "Provisioned" is the HOST install: the payload landed. Nothing
            # per sandbox exists to look for.
            provisioned = prov.payload_entry_path(home).is_file()
            return rc, out.getvalue() + err.getvalue(), provisioned

    def test_a_ratifiable_policy_provisions(self):
        rc, out, provisioned = self._run(_policy(**{fp.TASK_GRAPH_KEY: {}}), apply=True,
                                         fleet=("alpha", "bravo"))
        self.assertEqual(rc, 0, out)
        self.assertTrue(provisioned)

    def test_a_policy_without_the_cadence_is_reported_dry_and_refused_on_apply(self):
        raw = _policy()
        del raw[fp.RECREATE_INTERVAL_KEY]
        rc, out, provisioned = self._run(raw, fleet=("alpha", "bravo"))
        self.assertEqual(rc, 0, "a dry run reports; it refuses nothing")
        self.assertIn(fp.RECREATE_INTERVAL_KEY, out)
        self.assertFalse(provisioned)
        rc, out, provisioned = self._run(raw, apply=True, fleet=("alpha", "bravo"))
        self.assertEqual(rc, prov.EXIT_POLICY_UNRATIFIED, out)
        self.assertIn(fp.RECREATE_INTERVAL_KEY, out)
        self.assertIn("feature.json", out)
        # The template and the payload land BEFORE the refusal, deliberately:
        # a fresh host gets its template and is told what to edit in it.
        # There is no per-sandbox write left for the refusal to withhold.
        self.assertTrue(provisioned, "the host install lands; the refusal is the policy's")

    def test_edges_without_a_domain_are_refused(self):
        raw = _policy()
        del raw[fp.FLEET_DOMAIN_KEY]
        rc, out, provisioned = self._run(raw, apply=True, fleet=("alpha", "bravo"))
        self.assertEqual(rc, prov.EXIT_POLICY_UNRATIFIED, out)
        self.assertIn(fp.FLEET_DOMAIN_KEY, out)
        self.assertTrue(provisioned, "the host install lands before the policy refusal; "
                                     "there is no per-sandbox write to withhold")

    def test_an_EMPTY_graph_without_a_domain_is_fine(self):
        """A fleet with no delegation needs no domain: refusing it would make
        the peer lane mandatory, which it is not."""
        raw = _policy(**{fp.TASK_GRAPH_KEY: {}})
        del raw[fp.FLEET_DOMAIN_KEY]
        rc, out, _ = self._run(raw, apply=True, fleet=("alpha", "bravo"))
        self.assertEqual(rc, 0, out)

    def test_an_empty_LIST_is_not_an_edge(self):
        """`{"bravo": []}` declares no edge, so it needs no domain either.
        The check is on edges, not on the key's presence."""
        raw = _policy(**{fp.TASK_GRAPH_KEY: {"bravo": []}})
        del raw[fp.FLEET_DOMAIN_KEY]
        rc, out, _ = self._run(raw, apply=True, fleet=("alpha", "bravo"))
        self.assertEqual(rc, 0, out)

    def test_both_content_problems_are_reported_in_one_run(self):
        """A policy missing both takes one round trip to fix, not two."""
        raw = _policy()
        del raw[fp.RECREATE_INTERVAL_KEY]
        del raw[fp.FLEET_DOMAIN_KEY]
        rc, out, _ = self._run(raw, apply=True, fleet=("alpha", "bravo"))
        self.assertEqual(rc, prov.EXIT_POLICY_UNRATIFIED)
        self.assertIn(fp.RECREATE_INTERVAL_KEY, out)
        self.assertIn(fp.FLEET_DOMAIN_KEY, out)

    def test_an_overlapping_pair_is_refused_on_apply_and_reported_dry(self):
        """No ordered pair on both lanes. Against the PROJECTED
        membership, so a fresh fleet is judged by what sandy reports."""
        overlapping = _policy(peers={"alpha": ["bravo"], "bravo": ["alpha"]})
        rc, out, provisioned = self._run(overlapping, apply=True, fleet=("alpha", "bravo"))
        self.assertEqual(rc, prov.EXIT_POLICY_UNRATIFIED, out)
        self.assertIn("BOTH lanes", out)
        self.assertTrue(provisioned, "the host install lands before the policy refusal; "
                                     "there is no per-sandbox write to withhold")
        rc, out, _ = self._run(overlapping, fleet=("alpha", "bravo"))
        self.assertEqual(rc, 0)
        self.assertIn("BOTH lanes", out)


# ================================================ what install --apply renders


class RouterSiblingRenderTest(unittest.TestCase):
    """The router's config, rendered as a SIBLING of the manifest: three
    absolute roots, the domain, and the two graphs in the router's exact
    tokens — and nothing else, because the router refuses an unknown key.
    There is no instance table:
    the router discovers instances under `instances_dir` and admits each by
    `selected_json`, so the graphs are total over the SELECTED set and an
    edge naming a slug not yet discovered is inert, never a refusal."""
    NAMES = ["alpha", "bravo"]

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.paths = {n: self.root / "sandboxes" / n for n in self.NAMES}
        for path in self.paths.values():
            path.mkdir(parents=True)

    def _render(self, policy=None, members=None, state=None):
        return prov.render_router_sibling(
            policy if policy is not None else _policy(),
            {n: {} for n in (self.NAMES if members is None else members)},
            self.root, state if state is not None else self.root / "state", self.paths)

    def test_the_renderers_vocabulary_is_a_subset_of_the_routers_whole_one(self):
        """The renderer's keys are pinned inside the router's complete
        `_TOP_KEYS`, and
        the keys it reads that this side never writes are named — so a
        rendering with a domain, a wildcard task graph and a mail map
        carries none of them, and the authored `instances` table least of
        all (a sibling that carried one would be an authored config wearing
        discovery's name)."""
        self.assertLessEqual(set(prov.SIBLING_KEYS), set(prov.ROUTER_TOP_KEYS))
        self.assertEqual(sorted(prov.SIBLING_KEYS_NEVER_RENDERED),
                         sorted(set(prov.ROUTER_TOP_KEYS) - set(prov.SIBLING_KEYS)))
        self.assertIn("instances", prov.SIBLING_KEYS_NEVER_RENDERED)
        self.assertIn("intake_dir", prov.SIBLING_KEYS_NEVER_RENDERED)
        doc = self._render(_policy(**{fp.TASK_GRAPH_KEY: fp.TASK_GRAPH_ALL,
                                      "peers": {"alpha": ["bravo"], "bravo": ["alpha"]}}))["_doc"]
        self.assertLessEqual(set(doc), set(prov.SIBLING_KEYS), sorted(doc))
        self.assertEqual(set(doc) & set(prov.SIBLING_KEYS_NEVER_RENDERED), set(), sorted(doc))

    def test_no_rendered_path_carries_a_dot_or_dot_dot_segment(self):
        """A `state_dir` spelled `<HOME>/features/amap/../router-state` names
        the same directory as the plain spelling on disk, and an unnormalised
        rendering makes `verify` report byte-for-byte drift between two
        names of one place. Every path the sibling carries is normalised;
        the mutation is dropping `normpath` from `_sibling_path`."""
        doc = self._render(state=self.root / "features" / "amap" / ".." / "router-state")["_doc"]
        for key in (prov.SIBLING_STATE_DIR, prov.SIBLING_INSTANCES_DIR,
                    prov.SIBLING_SELECTED_JSON):
            with self.subTest(key=key):
                parts = Path(doc[key]).parts
                self.assertNotIn("..", parts, doc[key])
                self.assertNotIn(".", parts, doc[key])
                self.assertTrue(Path(doc[key]).is_absolute(), doc[key])
        # `amap/..` cancels `amap` and nothing else: the one directory this
        # spelling names is `<root>/features/router-state`.
        self.assertEqual(doc[prov.SIBLING_STATE_DIR], str(self.root / "features" / "router-state"))

    def test_the_state_dir_in_force_wins_over_the_default_when_none_is_given(self):
        """`verify` and a re-render without `--state-dir` keep the sibling's
        own state_dir (the operator's choice, which the router refuses to
        change on reload) rather than drifting against the
        conventional default; `--state-dir` still wins over both."""
        home = self.root
        chosen = self.root / "elsewhere-state"
        self.assertEqual(prov.sibling_state_dir(home, None), home / prov.ROUTER_STATE_SUBDIR)
        doc = self._render(state=chosen)["_doc"]
        prov.router_sibling_path(home).parent.mkdir(parents=True, exist_ok=True)
        prov.router_sibling_path(home).write_text(prov.sibling_text(doc))
        self.assertEqual(prov.sibling_state_dir(home, None), chosen)
        self.assertEqual(prov.sibling_state_dir(home, str(self.root / "x")), self.root / "x")

    def test_no_mail_edge_renders_neither_mail_key(self):
        """Zero of the pair is the router's spelling of "no mail lane"
        not `peers: {}`, not a wildcard, nothing."""
        doc = self._render(_policy(peers={}))["_doc"]
        self.assertNotIn(prov.SIBLING_MAIL_GRAPH, doc)
        self.assertNotIn(prov.SIBLING_PEERS, doc)

    def test_the_document_carries_only_keys_the_router_reads(self):
        doc = self._render()["_doc"]
        self.assertLessEqual(set(doc), set(prov.SIBLING_KEYS), sorted(doc))
        for key in (prov.SIBLING_STATE_DIR, prov.SIBLING_INSTANCES_DIR,
                    prov.SIBLING_SELECTED_JSON):
            with self.subTest(key=key):
                self.assertTrue(Path(doc[key]).is_absolute(), doc[key])
        self.assertEqual(doc[prov.SIBLING_INSTANCES_DIR],
                         str(prov.feature_instances_dir(self.root).absolute()))
        self.assertEqual(doc[prov.SIBLING_SELECTED_JSON],
                         str(prov.feature_selected_path(self.root).absolute()))
        self.assertEqual(doc[fp.FLEET_DOMAIN_KEY], DOMAIN)

    def test_peer_senders_is_total_and_the_mail_key_is_absent(self):
        doc = self._render()["_doc"]
        self.assertEqual(doc[prov.SIBLING_PEER_SENDERS], {"alpha": [], "bravo": ["alpha"]},
                         "an instance nobody may task must map to [], not vanish")
        self.assertNotIn(prov.SIBLING_TASK_GRAPH, doc, "the word and the map are different keys")
        # A closed mail lane is NOT rendered as `peers: {}`: a fleet that
        # declares no mail edge carries no mail key.
        self.assertNotIn(prov.SIBLING_PEERS, doc)
        self.assertNotIn(prov.SIBLING_MAIL_GRAPH, doc)

    def test_the_wildcard_renders_the_routers_word_and_no_map(self):
        doc = self._render(policy=_policy(**{fp.TASK_GRAPH_KEY: fp.TASK_GRAPH_ALL}))["_doc"]
        self.assertEqual(doc[prov.SIBLING_TASK_GRAPH], prov.ROUTER_TASK_GRAPH_ALL)
        self.assertNotIn(prov.SIBLING_PEER_SENDERS, doc)
        self.assertNotEqual(prov.ROUTER_TASK_GRAPH_ALL, fp.TASK_GRAPH_ALL,
                            "the policy's spelling and the router's differ on purpose")

    def test_a_mutual_mail_pair_renders_the_peers_map(self):
        policy = _policy(**{fp.TASK_GRAPH_KEY: {}, "peers": {"alpha": ["bravo"], "bravo": ["alpha"]}})
        doc = self._render(policy=policy)["_doc"]
        self.assertEqual(doc[prov.SIBLING_PEERS], {"alpha": ["bravo"], "bravo": ["alpha"]})

    def test_no_domain_renders_no_lane_key_at_all(self):
        """The router's loader refuses `peer_senders` without a domain, so a
        half-rendered lane would be a config it rejects."""
        raw = _policy(**{fp.TASK_GRAPH_KEY: {}})
        del raw[fp.FLEET_DOMAIN_KEY]
        doc = self._render(policy=raw)["_doc"]
        self.assertEqual(sorted(doc), sorted([prov.SIBLING_STATE_DIR, prov.SIBLING_INSTANCES_DIR,
                                              prov.SIBLING_SELECTED_JSON]))

    def test_an_empty_selected_set_renders_rather_than_refusing(self):
        """Discovery's point: the document can exist before the first launch,
        and the router admits instances as sandy selects them."""
        doc = self._render(policy=_policy(**{fp.TASK_GRAPH_KEY: {}}), members=[])["_doc"]
        self.assertEqual(doc[prov.SIBLING_PEER_SENDERS], {})

    def test_the_routers_own_address_is_NEVER_rendered(self):
        self.assertNotIn(fp.ROUTER_LOCAL_PART, json.dumps(self._render()["_doc"]))

    def test_state_dir_inside_a_sandbox_root_or_the_instances_tree_is_refused(self):
        for where in (self.paths["alpha"] / "rs",
                      prov.feature_instances_dir(self.root) / "rs",
                      prov.feature_instances_dir(self.root)):
            with self.subTest(where=str(where)):
                with self.assertRaises(prov.ProvisionError) as ctx:
                    self._render(state=where)
                self.assertIn("router-private", str(ctx.exception))

    def test_the_routers_real_loader_accepts_it(self):
        try:
            from router.config import load_obj
        except ImportError:
            self.skipTest("the router's loader is not importable here (a stub router)")
        for policy in (_policy(), _policy(**{fp.TASK_GRAPH_KEY: fp.TASK_GRAPH_ALL})):
            load_obj(json.loads(json.dumps(self._render(policy=policy)["_doc"])))
        self.assertIsNone(prov.validate_with_router(self._render()["_doc"]))

    def test_a_reordered_peer_senders_is_DRIFT_unlike_a_reordered_peers(self):
        """`peers` is mutual and compared per slug as a set; `peer_senders`
        is what `verify` diffs positionally against two other files, so a
        REORDERING there really is a disagreement."""
        want = self._render()["_doc"]
        want[prov.SIBLING_PEER_SENDERS]["bravo"] = ["alpha", "charlie"]
        want[prov.SIBLING_PEERS] = {"bravo": ["alpha", "charlie"]}
        same = json.loads(json.dumps(want))
        self.assertEqual(prov.sibling_diff(same, want), [])
        reordered_peers = json.loads(json.dumps(want))
        reordered_peers[prov.SIBLING_PEERS]["bravo"] = ["charlie", "alpha"]
        self.assertEqual(prov.sibling_diff(reordered_peers, want), [])
        reordered_senders = json.loads(json.dumps(want))
        reordered_senders[prov.SIBLING_PEER_SENDERS]["bravo"] = ["charlie", "alpha"]
        changes = prov.sibling_diff(reordered_senders, want)
        self.assertTrue(any("peer_senders[bravo]" in c for c in changes), changes)
        dropped = json.loads(json.dumps(want))
        dropped[prov.SIBLING_PEER_SENDERS]["bravo"] = []
        self.assertTrue(any("peer_senders[bravo]" in c for c in prov.sibling_diff(dropped, want)))

    def test_a_changed_domain_and_an_unknown_key_are_reported_by_name(self):
        want = self._render()["_doc"]
        have = json.loads(json.dumps(want))
        have[fp.FLEET_DOMAIN_KEY] = "somewhere.else"
        have["rendered_at"] = "x"
        changes = prov.sibling_diff(have, want)
        self.assertTrue(any(fp.FLEET_DOMAIN_KEY in c for c in changes), changes)
        self.assertTrue(any("rendered_at" in c and "refuses" in c for c in changes), changes)

    def test_the_text_is_stable_and_ends_with_a_newline(self):
        a, b = (prov.sibling_text(self._render()["_doc"]) for _ in range(2))
        self.assertEqual(a, b)
        self.assertTrue(a.endswith("\n"))


# ============================================ what the provisioner writes


class SandboxFixture(unittest.TestCase):
    """Two selected, launched sandboxes and the host install, built by the
    INSTALLER'S OWN writer rather than by a hand-built imitation of it — a
    fixture that imitates the artefacts asserts only that the tests agree
    with the tests. Everything a sandbox gets is the payload installed once
    per host, plus what sandy applies at launch from the manifest; nothing
    is written per sandbox."""

    SLUG = "alpha-1111aaaa"
    OTHER = "bravo-2222bbbb"

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.home = self.root / "sandy-home"
        self.boxes = self.home / "sandboxes"
        self.src = self.root / "connector-bin"
        self.src.mkdir(parents=True)
        # The relay chain's two copied files come from the same source tree.
        for name in prov.CONNECTOR_BINARIES + prov.RELAY_CHAIN_COPIED:
            f = self.src / name
            f.write_text(f"#!/bin/sh\necho {name}\n")
            f.chmod(0o755)
        for slug in (self.SLUG, self.OTHER):
            d = self.boxes / slug
            # The sandbox directory sandy made at its launch, with the
            # agent's rw `claude/` tree the connector's state lives under.
            (d / "claude").mkdir(parents=True)
        # SELECTED, the way sandy records it: `selected.json` beside the
        # manifest, plus `features` on each reported sandbox (`_boxes`).
        _select(self.home, self.SLUG, self.OTHER)
        self.policy = _policy(**{fp.TASK_GRAPH_KEY: {self.OTHER: [self.SLUG]}})
        # The payload, ONCE, where sandy mounts it from: `$SANDY_HOME/features/
        # amap/payload/`.
        prov.install_feature_payload(self.home, self.src, dry_run=False)
        self.payload = prov.feature_payload_dir(self.home)

    def wrapper(self):
        """The relay WRAPPER, on the payload: the manifest's `entry`."""
        return self.payload / prov.RELAY_WRAPPER_NAME

    def sandbox(self, slug=None):
        return self.boxes / (slug or self.SLUG)

    def claude_json(self, slug=None):
        return self.boxes / f"{slug or self.SLUG}.claude.json"

    def connector(self, slug=None):
        return prov.connector_state_dir(self.sandbox(slug))


def _select(home, *slugs, rejected=(), at=None):
    """`selected.json` as SANDY writes it: the verdict of each
    sandbox's last launch. Built from sandy's pasted shape, never from what
    this repo wishes it wrote. `rejected` is `((slug, why), ...)`."""
    root = prov.feature_root(Path(home))
    root.mkdir(parents=True, exist_ok=True)
    # `at` is the launch that took the verdict. Default: the installed
    # manifest's own rendering stamp when there is one (a fixture sandbox
    # launched under the current rule), else a fixed time — a test that
    # wants an OLDER verdict passes `at` itself.
    at = at or prov.manifest_changed_at(Path(home)) or "2026-09-18T18:28:47Z"
    doc = {"schema": 1,
           "note": "Written by sandy at each launch and removal (fixture copy).",
           "selected": [{"slug": s, "at": at} for s in slugs],
           "not_selected": [{"slug": s, "why": why, "at": at} for s, why in rejected]}
    (root / prov.FEATURE_SELECTED_NAME).write_text(json.dumps(doc, indent=2) + "\n")
    return doc


def _daemon_path():
    """Where `install` would copy the daemon from: the same resolver, so the
    daemon this test reads is the one that ships."""
    return prov._default_connector_src() / "inbox-delivery"


def _daemon_source():
    path = _daemon_path()
    return path.read_text() if path.is_file() else None


def _daemon_required_vars(source: str):
    """The daemon's own `ENV_KEYS`, parsed out of its source.

    Parsed rather than imported: the daemon is a hyphenated executable in
    another repository with its own imports, and loading it here would couple
    this suite to whether that repo's dependencies are installed.

    A source this cannot parse RAISES rather than returning something
    comparable — a cross-repo agreement check that silently answers "nothing
    to compare" is indistinguishable in the output from one that passed."""
    import ast
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "ENV_KEYS":
                    return list(ast.literal_eval(node.value))
    raise AssertionError("the daemon declares no ENV_KEYS tuple")


def _wrapper_daemon_disagreements(daemon_source: str) -> list:
    """Every way the shipped wrapper and a daemon SOURCE disagree, collected.

    1. A name the daemon requires that the wrapper does not export — the
       daemon refuses to start. A daemon that still requires
       `AMAP_DELIVERY_PEERS` is below the connector floor: the wrapper does
       not export it.
    2. A name the wrapper exports that the daemon neither requires nor
       reads — it misleads the next reader. `AMAP_DELIVERY_SELF` is the one
       name allowed to be exported without being required, because the
       daemon keeps it optional by design (a mail-only fleet has none).
    3. If `AMAP_DELIVERY_SELF` is not required, the daemon must at least READ
       it: it is the daemon's only source of its own address, and a daemon
       that does not read it has none. This check never becomes implied,
       because the name never joins `ENV_KEYS`.

    Collected, not first-wins: a source with two faults must report two, or
    the second is an assertion that cannot be reached."""
    required = set(_daemon_required_vars(daemon_source))
    exported = set(_wrapper.exported_names())
    out = []
    missing = sorted(required - exported)
    if missing:
        out.append(f"required by the daemon, not exported: {', '.join(missing)} — a daemon "
                   f"that requires AMAP_DELIVERY_PEERS is below the connector floor; the "
                   f"wrapper does not set it")
    stray = sorted((exported - required) - {_wrapper.SELF_VAR})
    if stray:
        out.append(f"exported, and the daemon neither requires nor tolerates it: "
                   f"{', '.join(stray)}")
    if _wrapper.SELF_VAR not in required and _wrapper.SELF_VAR not in daemon_source:
        out.append(f"the daemon neither requires nor reads {_wrapper.SELF_VAR}: this connector "
                   f"is below the floor, and its daemon has no address at all")
    return out


class McpRegistrationIsOneConstantFileTest(unittest.TestCase):
    """`payload/mcp-servers.json` is JSON read by Claude Code, not by a shell. Claude
    Code expands `${VAR}` in an MCP `command` and `env` before spawning, and
    does NOT expand `~` — a `~/...` command is posix_spawn'd literally and
    fails ENOENT. So the file is one constant, rooted at the lane exports,
    with no container home in it and nothing to substitute per sandbox at
    all: `inbox-submit` omits `agent_id` when `MAILBOX_AGENT_ID` is unset,
    so there is no agent id to stamp either. This class keeps it that way."""

    def _servers(self):
        return prov.load_servers(_HERE / "payload" / "mcp-servers.json")

    def _env_paths(self):
        for name, spec in self._servers().items():
            for var, val in (spec.get("env") or {}).items():
                if var != "INBOX_LANE":
                    yield f"{name}.env.{var}", val

    def test_every_env_path_is_a_lane_export_and_none_uses_tilde(self):
        """Every path is rooted at one of the manifest's lane exports
        (`${AMAP_INBOX_DIR}` and the rest, feature.json `mounts[].export`),
        which sandy passes into the container environment and Claude Code
        expands — the one spelling that names no mount point and no home.
        The lane each server reads is the lane its export names."""
        exports = {"inbox": "inbox", "delegation": "peer", "inbox-submit": "outbox"}
        for where, val in self._env_paths():
            with self.subTest(where=where):
                server = where.split(".")[0]
                lane = exports[server]
                self.assertTrue(val.startswith("${" + prov.EXPORT_LANE_DIR[lane] + "}"), val)
                self.assertNotIn("~", val, "Claude Code spawns a literal ~ — ENOENT")
                self.assertNotIn("${HOME}", val,
                                 "a mount has a name, never a destination: the path under "
                                 "the home is sandy's to choose and its export to state")

    def test_every_command_is_on_the_feature_mount(self):
        """Two claims, not one loosened: the binaries live on sandy's read-only
        feature mount at a FIXED path, which is not under the home
        and does not move with it, so `${HOME}` would be the wrong root."""
        for name, spec in self._servers().items():
            with self.subTest(server=name):
                self.assertTrue(spec["command"].startswith(prov.CONTAINER_FEATURE_BIN + "/"),
                                spec["command"])
                self.assertNotIn("~", spec["command"])
                self.assertNotIn("${", spec["command"], "a fixed mount path expands nothing")

    def test_no_container_home_and_no_placeholder_survives_in_the_shipped_block(self):
        """Scoped to the `mcpServers` object, not the raw file, so the guard
        reads what Claude Code loads rather than any prose around it."""
        block = json.dumps(self._servers())
        self.assertNotIn("/home/", block)
        self.assertNotIn("__", block, "no placeholder of any kind: nothing is substituted")

    def test_the_two_readers_declare_their_lane(self):
        """Same binary, two trees, two instruction sets: without INBOX_LANE
        the delegation server serves mail-framed instructions that tell the
        agent to treat a delegation as suspicious mail."""
        servers = self._servers()
        self.assertEqual(servers["delegation"]["env"]["INBOX_LANE"], "peer")
        self.assertEqual(servers["inbox"]["env"]["INBOX_LANE"], "mail")

    def test_no_agent_id_is_stamped_and_nothing_varies_per_sandbox(self):
        """`MAILBOX_AGENT_ID` must not reappear: an unset variable means the
        connector omits `agent_id` and the router binds by
        drop-box; a set one re-enables a cross-check this fleet does not
        want, and a WRONG one rejects every submit as agent_id_mismatch."""
        block = json.dumps(self._servers())
        self.assertNotIn("MAILBOX_AGENT_ID", block)
        self.assertNotIn("__REPLACE_WITH", block)


class ClaimPathSurvivesARenamedHomeTest(unittest.TestCase):
    """`_claim_host_path` maps a path the DAEMON published, from inside the
    container, onto this host. The container user's home is sandy's to
    choose, so the daemon may publish `/home/<other>/.claude/connector/...`
    — and a mapping anchored on a whole absolute prefix would report every
    healthy claim as unresolvable the day the home moves."""

    SANDBOX = Path("/fake/sandboxes/alpha-a1b2c3d4")

    def test_any_container_home_resolves(self):
        for home in ("/home/claude", "/home/agent", "/var/lib/sandy/u1000"):
            with self.subTest(home=home):
                published = f"{home}/{prov.CONNECTOR_REL}/claims/mail.amap-consumer.json"
                self.assertEqual(
                    prov._claim_host_path(self.SANDBOX, published),
                    prov.connector_state_dir(self.SANDBOX) / "claims"
                    / "mail.amap-consumer.json")

    def test_a_path_with_no_connector_component_is_unresolvable(self):
        for bad in ("/tmp/elsewhere.json", "/home/agent/claims/mail.json", "", 17):
            with self.subTest(published=bad):
                self.assertIsNone(prov._claim_host_path(self.SANDBOX, bad))


class ShippedWrapperTest(unittest.TestCase):
    """`payload/relay` is a checked-in file, not a rendered one, so there is
    no Python mirror to keep faithful — the artifact itself is executed."""

    def test_it_exports_the_daemons_eight_paths_and_resolves_any_layout(self):
        """With no `AMAP_FLEET_DOMAIN` in the environment: the eight path variables,
        and nothing else — the address is the peer lane's, and a fleet without
        a domain has none. The session file is not even opened then (none
        is staged here, and the run succeeds)."""
        rc, err, env = _wrapper.run_wrapper(_wrapper.FOREIGN_LAYOUT)
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(env), 8)
        self.assertNotIn(_wrapper.SELF_VAR, env)
        # Every one of the eight must carry a VALUE. An exported-but-unset
        # variable still appears on the export line, so counting names would
        # pass over a wrapper whose daemon refuses to start.
        empty = sorted(n for n, v in env.items() if not v)
        self.assertEqual(empty, [], f"exported with no value: {empty}")
        self.assertEqual(env["AMAP_DELIVERY_MAIL_NOTICE_DIR"], "/mnt/h/inbox/notices")
        self.assertEqual(env["AMAP_DELIVERY_STATE_DIR"],
                         "/home/agent/.claude/connector/delivery-state")
        self.assertEqual(env["AMAP_DELIVERY_OUTCOME_DIR"],
                         "/mnt/h/outbox/ext/claude-code/outcomes")

    def test_the_address_is_the_slug_at_the_fleet_domain_in_the_adapters_own_address_form(self):
        """`AMAP_DELIVERY_SELF` is what the router expects this instance to
        call itself, so it is asserted against `fp.address_for` — the one
        function the router config is rendered with — not against a string
        restated here. `sandbox_name` comes from sandy's session file and the
        domain from `AMAP_FLEET_DOMAIN`, the manifest's `expose`; nothing
        else."""
        slug = "alpha-1111aaaa"
        rc, err, env = _wrapper.run_wrapper(
            _wrapper.FOREIGN_LAYOUT, fleet_domain=DOMAIN,
            session={"schema": 1, "sandbox_name": slug, "workspace": "/w"})
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(env), 9)
        self.assertEqual(env[_wrapper.SELF_VAR], fp.address_for(slug, DOMAIN))

    def test_the_address_is_never_guessed(self):
        """Once `AMAP_FLEET_DOMAIN` is set, every gap on the way to the
        address is fatal: the daemon would otherwise start under an address
        nobody named — the failure mode of a typo, not of an omission. Each
        refusal names the thing that is missing."""
        cases = {
            "empty domain": dict(fleet_domain="", session={"sandbox_name": "x"}),
            "no session file": dict(fleet_domain=DOMAIN, session=None),
            "session without a name": dict(fleet_domain=DOMAIN, session={"schema": 1}),
        }
        for what, kw in cases.items():
            with self.subTest(what=what):
                rc, err, env = _wrapper.run_wrapper(_wrapper.FOREIGN_LAYOUT, **kw)
                self.assertNotEqual(rc, 0, what)
                self.assertEqual(env, {})
                self.assertIn("relay:", err)
        self.assertIn("sandbox_name", _wrapper.run_wrapper(
            _wrapper.FOREIGN_LAYOUT, **cases["session without a name"])[1])
        self.assertIn("empty", _wrapper.run_wrapper(
            _wrapper.FOREIGN_LAYOUT, **cases["empty domain"])[1])

    def test_it_REFUSES_to_start_without_the_lane_exports(self):
        """A guessed path is a wrong path used silently — the daemon's own rule,
        applied to the three values the manifest's mounts export and sandy
        owns. The supervisor records the exit and the message, which is how
        an operator learns of it."""
        for missing in sorted(_wrapper.LANE_EXPORT.values()):
            with self.subTest(missing=missing):
                rc, err, _ = _wrapper.run_wrapper(_wrapper.FOREIGN_LAYOUT, drop=missing)
                self.assertNotEqual(rc, 0)
                self.assertIn(missing, err)

    def test_no_container_home_is_baked_into_the_shipped_wrapper(self):
        """The regression guard for the derivation: the container user's
        home is sandy's to choose, and a path under a named home would point
        at nothing the day it moves."""
        self.assertNotIn("/home/claude", _wrapper.WRAPPER.read_text())

    def test_the_provisioner_copies_the_shipped_file_verbatim(self):
        self.assertEqual(prov.relay_wrapper_source(), _wrapper.WRAPPER)


def _relay_env(**over):
    """The environment sandy gives the relay. The wrapper REFUSES to start
    without the three lane exports (`${VAR:?}`), so a probe that inherits a
    bare test environment produces no output at all — which reads as a broken
    assertion rather than as the guard doing its job.

    Every inherited `AMAP_*` is dropped first: run inside a sandbox (or a
    shell that exported one), an inherited `AMAP_FLEET_DOMAIN` would turn
    the no-domain case into a domain case while the test believed otherwise."""
    inherited = {k: v for k, v in os.environ.items() if not k.startswith("AMAP_")}
    env = {**inherited, "HOME": _wrapper.FOREIGN_LAYOUT["home"],
           _wrapper.LANE_EXPORT["inbox"]: _wrapper.FOREIGN_LAYOUT["inbox"],
           _wrapper.LANE_EXPORT["outbox"]: _wrapper.FOREIGN_LAYOUT["outbox"],
           _wrapper.LANE_EXPORT["peer"]: _wrapper.FOREIGN_LAYOUT["peer"]}
    env.update(over)
    return env


class DeliveryWrapperTest(SandboxFixture):
    """The wrapper present, byte-identical to the shipped file, exporting
    all nine `AMAP_DELIVERY_*` variables (the
    `PEER_*` names, and `SELF`), none defaulted, and none the daemon does not
    read."""

    def _session(self, name=None):
        """A session file the way sandy composes it, staged in the
        fixture root; the probes point the wrapper's hardcoded path at it."""
        path = self.root / "sandy-session.json"
        path.write_text(json.dumps({"schema": 1, "sandbox_name": name or self.SLUG}))
        return path

    def test_all_nine_variables_are_exported_and_none_is_defaulted(self):
        text = self.wrapper().read_text()
        # The deployed copy (on the payload) IS the shipped file: same names,
        # same order.
        self.assertEqual(_wrapper.exported_names(text), _wrapper.exported_names())
        self.assertEqual(len(_wrapper.exported_names(text)), 9)
        self.assertEqual(_wrapper.exported_names(text)[-1], _wrapper.SELF_VAR)
        # No `${VAR:-default}` on any AMAP_DELIVERY assignment: the daemon
        # refuses to start on a missing variable, and a default here would
        # substitute a path for that refusal. The `${VAR:?}` guards on sandy's
        # three exports are the opposite thing — they supply no value and make
        # absence fatal, which is the same rule pointed at sandy's half.
        for line in text.splitlines():
            if line.startswith("AMAP_DELIVERY_"):
                self.assertNotIn(":-", line)

    def test_the_exports_are_exactly_the_daemons_required_set(self):
        """Read from the DAEMON's own source, not restated here. The two live
        in different repositories and nothing else keeps them equal. The
        comparison is `_wrapper_daemon_disagreements`, which COLLECTS every
        disagreement rather than returning at the first — see the synthetic
        test below for why that matters and for the proof that each of its
        three conditions can fail.

        THIS IS THE CONNECTOR FLOOR: a daemon that reads `AMAP_DELIVERY_SELF`
        and does not require `AMAP_DELIVERY_PEERS`. Anything older fails
        here, by name."""
        daemon = _daemon_source()
        if daemon is None:
            self.skipTest(f"{_daemon_path()} not checked out")
        self.assertEqual(_wrapper_daemon_disagreements(daemon), [])

    def test_each_disagreement_is_reachable_on_a_daemon_this_test_controls(self):
        """The mutation proof for `_wrapper_daemon_disagreements`, against
        daemon sources built here rather than real connector revisions.

        WHY SYNTHETIC. Not every failing shape exists as a real connector
        (requires no PEERS, reads no SELF has never shipped), so a real
        daemon cannot prove the read check fires, and it would otherwise be
        an assertion nobody has seen fail. The seam is
        `_daemon_required_vars(source)`, which parses an `ENV_KEYS` tuple out
        of text; the sources here carry exactly that assignment, the way the
        daemon spells it.

        WHY COLLECT. A daemon that requires PEERS and never reads SELF
        carries BOTH faults, and a comparison that stops at the first one
        reports the floor and hides the address.
        """
        eight = ("AMAP_DELIVERY_MAIL_NOTICE_DIR", "AMAP_DELIVERY_MAIL_CLAIM",
                 "AMAP_DELIVERY_PEER_NOTICE_DIR", "AMAP_DELIVERY_PEER_MESSAGE_DIR",
                 "AMAP_DELIVERY_PEER_CLAIM", "AMAP_DELIVERY_STATE_DIR",
                 "AMAP_DELIVERY_OUTCOME_DIR", "AMAP_DELIVERY_SESSION_SOURCE")
        peers = ("AMAP_DELIVERY_PEERS",)

        def daemon(required, *, reads_self):
            src = f"ENV_KEYS = {tuple(required)!r}\n"
            if reads_self:
                src += 'self_addr = os.environ.get("AMAP_DELIVERY_SELF")\n'
            return src

        # One row per shape, each its own subTest: a broken row names the
        # SHAPE, and a first-wins assertion over all six would hide later
        # rows. `expect` is the
        # set of substrings each disagreement must carry, one entry per
        # disagreement expected — so the count is asserted too.
        rows = (
            ("at the floor: eight required, SELF read — the control",
             daemon(eight, reads_self=True), ()),
            ("PEERS still required — the floor, and only it",
             daemon(eight + peers, reads_self=True),
             (("AMAP_DELIVERY_PEERS", "floor"),)),
            ("PEERS required AND SELF never read — both, collected",
             daemon(eight + peers, reads_self=False),
             (("AMAP_DELIVERY_PEERS",), ("reads", "AMAP_DELIVERY_SELF"))),
            ("eight required, SELF never read — the read check alone",
             daemon(eight, reads_self=False),
             (("reads", "AMAP_DELIVERY_SELF"),)),
            ("SELF required: the read check is skipped, required-and-exported covers it",
             daemon(eight + ("AMAP_DELIVERY_SELF",), reads_self=False), ()),
            ("one path gone from ENV_KEYS: a stray the daemon neither requires nor reads",
             daemon(eight[:-1], reads_self=True),
             (("AMAP_DELIVERY_SESSION_SOURCE",),)),
        )
        for shape, source, expect in rows:
            with self.subTest(shape=shape):
                got = _wrapper_daemon_disagreements(source)
                self.assertEqual(len(got), len(expect), got)
                for needles in expect:
                    self.assertTrue(any(all(n in d for n in needles) for d in got),
                                    f"no disagreement carries {needles}: {got}")

    def test_the_optional_tenth_is_deliberately_not_rendered(self):
        """`AMAP_DELIVERY_RECEIPT_WINDOW_SECONDS` has a daemon-side default;
        rendering it would put a number in every sandbox that no policy
        records."""
        self.assertNotIn(prov.DELIVERY_RECEIPT_WINDOW_ENV, self.wrapper().read_text())

    def test_it_execs_the_daemon_and_forwards_arguments(self):
        text = self.wrapper().read_text()
        self.assertIn(f'exec "$SELF_DIR/{prov.DELIVERY_DAEMON_NAME}" "$@"', text)

    def test_it_execs_ONLY_out_of_its_own_directory(self):
        """The invariant, read off the wrapper. A path that escaped
        `$SELF_DIR` would leave the `:ro` mount, and the agent-writable copy
        under `claude/connector/bin/` is exactly what it would escape TO."""
        text = self.wrapper().read_text()
        execs = [ln for ln in text.splitlines() if ln.startswith("exec ")]
        self.assertEqual(len(execs), 1, execs)
        self.assertTrue(execs[0].startswith('exec "$SELF_DIR/'), execs[0])
        # The env values legitimately name `claude/connector/` — that is
        # where the daemon's STATE lives, and state is writable by design. It
        # is the connector's BIN directory that must never be reached.
        self.assertNotIn(f"{CONTAINER_CONNECTOR}/bin", text)

    def test_SELF_DIR_resolves_to_the_directory_the_wrapper_IS_in(self):
        """Run it, do not read it: `$0`-relative resolution is the mechanism
        the whole read-only claim rests on, and a `dirname` that came out
        relative would send the exec somewhere the cwd decided."""
        path = self.wrapper()
        probe = path.parent / "probe-selfdir.sh"
        # The probe sits on the payload beside the wrapper; it gets a session
        # file so the address branch has one to read if the domain is set.
        probe.write_text(_wrapper.with_session_file(path.read_text(), self._session()).replace(
            f'exec "$SELF_DIR/{prov.DELIVERY_DAEMON_NAME}" "$@"', 'echo "$SELF_DIR"'))
        for cwd in (self.root, path.parent):
            with self.subTest(cwd=str(cwd)):
                r = subprocess.run(["sh", str(probe)], capture_output=True,
                                   text=True, cwd=str(cwd), env=_relay_env())
                self.assertEqual(r.stdout.strip(), str(path.parent.resolve()))
        # ...and by a relative path, from the payload's own parent. Sandy
        # invokes it by its absolute path on the mount, but `$0`-relative
        # resolution must survive a relative invocation too or the exec
        # follows the cwd.
        r = subprocess.run(["sh", f"{prov.FEATURE_PAYLOAD_SUBDIR}/{probe.name}"],
                           capture_output=True, text=True, cwd=str(self.payload.parent),
                           env=_relay_env())
        self.assertEqual(r.stdout.strip(), str(path.parent.resolve()))

    def test_the_whole_chain_lands_on_the_payload(self):
        """Every link on ONE read-only mount. A wrapper on a `:ro` mount that
        execs a daemon on a writable one accomplishes nothing — the agent
        rewrites the daemon instead — and a daemon that imports a writable
        `_inboxlib.py` is the same failure one link further down.

        The chain and both MCP binaries live once at
        `$SANDY_HOME/features/amap/payload/`, mounted `:ro` at `/opt/sandy/
        features/amap`, and the manifest's `entry` names the wrapper there
        directly. Sandy's documented limit — it guarantees the FIRST
        executable — is met by the entry, and the rest is on a mount the
        agent cannot write either."""
        for rel, _src, _x in prov.payload_sources(self.src):
            with self.subTest(name=rel):
                path = self.payload / rel
                self.assertTrue(path.is_file(), path)
                self.assertFalse(path.is_symlink(),
                                 "a symlink resolves back out of the :ro mount")
        self.assertEqual(prov.render_manifest(self.policy)["entry"], prov.MANIFEST_ENTRY)

    def test_nothing_of_ours_is_left_in_the_agent_writable_bin(self):
        """A second, writable copy of an executable that lives on the `:ro`
        mount is a second answer to `which inbox-submit runs`."""
        bin_dir = self.sandbox() / "claude" / "connector" / "bin"
        for name in prov.CONNECTOR_BINARIES + prov.RELAY_CHAIN_COPIED:
            self.assertFalse((bin_dir / name).exists(), name)
        self.assertNotIn(prov.DELIVERY_DAEMON_NAME, prov.CONNECTOR_BINARIES)

    def test_it_is_valid_sh_and_exports_nine_with_a_domain_and_eight_without(self):
        """Run, not read: a wrapper that parses in a reviewer's head and not
        in `/bin/sh` is a relay that crash-loops. Nine exports when sandy
        hands the container AMAP_FLEET_DOMAIN (the manifest's `expose`),
        eight when it does not — and the SAME answer from the payload and
        from anywhere else, because nothing beside the wrapper is read."""
        path = self.wrapper()
        self.assertEqual(subprocess.run(["sh", "-n", str(path)]).returncode, 0)
        text = _wrapper.with_session_file(path.read_text(), self._session()).replace(
            f'exec "$SELF_DIR/{prov.DELIVERY_DAEMON_NAME}" "$@"',
            'env | grep -c "^AMAP_DELIVERY_"')
        for where in (self.payload, self.root):
            for env, want in ((_relay_env(**{_wrapper.FLEET_DOMAIN_VAR: "agents.example.org"}), "9"),
                              (_relay_env(), "8")):
                probe = where / "probe.sh"
                probe.write_text(text)
                r = subprocess.run(["sh", str(probe)], capture_output=True, text=True, env=env)
                with self.subTest(where=str(where), domain=_wrapper.FLEET_DOMAIN_VAR in env):
                    self.assertEqual(r.stdout.strip(), want, r.stderr)


class ClaimsTest(unittest.TestCase):
    """The daemon's single-consumer claims, as the wrapper places them."""

    def test_the_two_lanes_take_two_DIFFERENT_claims(self):
        """One claim for both lanes would make a single stuck lane look like
        a dead daemon, and would let a second consumer take the mail claim
        while the daemon held only the peer one."""
        env = _wrapper.run_wrapper(_wrapper.FOREIGN_LAYOUT)[2]
        self.assertNotEqual(env["AMAP_DELIVERY_MAIL_CLAIM"], env["AMAP_DELIVERY_PEER_CLAIM"])


# ================================================================== verify
#
# `verify` exits 1 on wrapper drift, relay not alive (heartbeat stale OR
# kill -0 fails), peer graph drift, peer host directory absent.
#
# Every test below is a MUTATION PROOF by construction: the fixture is a
# healthy sandbox, one thing is broken, and the check whose message names
# that thing must be the one that fires. `test_a_healthy_sandbox_has_no_
# problems` is the control that keeps them honest — without it a function
# that returned a problem unconditionally would pass every one.


class VerifyUnitTest(SandboxFixture):
    def setUp(self):
        super().setUp()

    # The start time the fake `/proc` reports and the claims record. They
    # agree unless a test deliberately parts them.
    CLAIM_START = "101128298"

    def _claim_path(self, lane):
        return self.connector() / "claims" / f"{lane}.amap-consumer.json"

    def _claims_on_disk(self, *, pid=None, proc_start=None, lanes=("mail", "peer")):
        """The claim files as `bin/inbox-delivery` actually writes them.

        Shape taken from a live daemon, not from what the verifier wishes it
        wrote: that mismatch is the bug these tests exist to prevent coming
        back. See `_heartbeat` for the other half of it."""
        for lane in lanes:
            path = self._claim_path(lane)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({
                "consumer": "inbox-delivery",
                "pid": os.getpid() if pid is None else pid,
                "proc_start": self.CLAIM_START if proc_start is None else proc_start,
                "notice_dir": f"/lanes/{lane}/notices",
                "started_at": "2026-09-10T00:00:00Z"}))

    def _heartbeat(self, *, claims_on_disk=True, **over):
        """`delivery-state/daemon.json` exactly as the daemon writes it.

        `claims` maps each lane to the claim file's CONTAINER path — NOT to
        the string "held". The verifier believed the latter for as long as
        these tests did, so it reported every healthy daemon as dead."""
        doc = {"pid": os.getpid(), "started_at": "2026-09-10T00:00:00Z",
               "claims": {lane: f"{CONTAINER_CONNECTOR}/claims/{lane}.amap-consumer.json"
                          for lane in ("mail", "peer")},
               "heartbeat_at": datetime.now(timezone.utc).isoformat()}
        doc.update(over)
        path = self.connector() / "delivery-state" / "daemon.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(doc))
        if claims_on_disk:
            self._claims_on_disk()
        return path

    # --- the relay's configuration ---------------------------------------


    # --- the payload -------------------------------------------------------

    def test_a_healthy_payload_has_no_problems(self):
        self.assertEqual(prov.verify_feature_payload(self.home, self.src), [])

    def test_a_missing_DAEMON_fails_even_with_a_perfect_wrapper(self):
        """The wrapper being byte-perfect says nothing about the two files
        beside it that it actually runs — and a `:ro` wrapper that execs
        nothing is a relay sandy restarts forever."""
        (self.payload / prov.DELIVERY_DAEMON_NAME).unlink()
        problems = prov.verify_feature_payload(self.home, self.src)
        self.assertTrue(any(p.startswith("payload drift") and prov.DELIVERY_DAEMON_NAME in p
                            for p in problems), problems)

    def test_a_missing_SUPPORT_MODULE_fails(self):
        """`inbox-delivery` loads `_inboxlib.py` by path from beside itself,
        so an absent module is a daemon that dies at import."""
        (self.payload / prov.DELIVERY_SUPPORT_NAME).unlink()
        problems = prov.verify_feature_payload(self.home, self.src)
        self.assertTrue(any(prov.DELIVERY_SUPPORT_NAME in p for p in problems), problems)

    def test_a_daemon_that_is_not_the_connector_source_is_drift(self):
        (self.payload / prov.DELIVERY_DAEMON_NAME).write_text("#!/bin/sh\nexit 0\n")
        problems = prov.verify_feature_payload(self.home, self.src)
        self.assertTrue(any("differs" in p for p in problems), problems)

    def test_a_non_executable_daemon_is_drift(self):
        (self.payload / prov.DELIVERY_DAEMON_NAME).chmod(0o644)
        problems = prov.verify_feature_payload(self.home, self.src)
        self.assertTrue(any("not executable" in p for p in problems), problems)

    def test_a_symlinked_payload_file_is_drift(self):
        """A symlink resolves back out of the `:ro` mount — to wherever the
        agent, or anyone, pointed it."""
        target = self.root / "elsewhere"
        target.write_text("#!/bin/sh\nexit 0\n")
        (self.payload / prov.DELIVERY_DAEMON_NAME).unlink()
        (self.payload / prov.DELIVERY_DAEMON_NAME).symlink_to(target)
        problems = prov.verify_feature_payload(self.home, self.src)
        self.assertTrue(any("symlink" in p for p in problems), problems)

    def test_a_wrapper_missing_ONE_variable_fails(self):
        """The failure existence alone cannot catch: a file that is there,
        is executable, and produces a daemon that refuses to start."""
        path = self.wrapper()
        path.write_text(path.read_text().replace(
            'AMAP_DELIVERY_STATE_DIR="', '#AMAP_DELIVERY_STATE_DIR="'))
        problems = prov.verify_feature_payload(self.home, self.src)
        self.assertTrue(any(p.startswith("payload drift") and prov.RELAY_WRAPPER_NAME in p
                            for p in problems), problems)

    def test_a_hand_set_receipt_window_must_be_a_positive_number(self):
        path = self.wrapper()
        good = path.read_text().replace(
            "set -e", f'set -e\n{prov.DELIVERY_RECEIPT_WINDOW_ENV}="45"')
        path.write_text(good)
        # It is drift either way (the wrapper is byte-compared), but the
        # window check must not ALSO fire on a legal value.
        problems = prov.verify_feature_payload(self.home, self.src)
        self.assertFalse(any(prov.DELIVERY_RECEIPT_WINDOW_ENV in p for p in problems))
        path.write_text(good.replace('="45"', '="0"'))
        problems = prov.verify_feature_payload(self.home, self.src)
        self.assertTrue(any(prov.DELIVERY_RECEIPT_WINDOW_ENV in p for p in problems))

    # --- sandy's selection verdict ------------------------------------------

    def _box(self, **over):
        box = {"name": self.SLUG, "path": str(self.sandbox()), "features": [prov.FEATURE_NAME],
               "feature_problems": []}
        box.update(over)
        return box

    def test_a_selected_sandbox_has_no_selection_problems(self):
        self.assertEqual(prov.verify_selection(self.SLUG, self._box()), [])

    def test_a_sandbox_sandy_did_not_select_is_named_with_sandys_reason(self):
        """Sandy's `features` is its last launch's verdict; `feature_problems`
        carries why. A check that read only this repo's own files would call
        this healthy."""
        problems = prov.verify_selection(
            self.SLUG, self._box(features=[], feature_problems=[f"{prov.FEATURE_NAME}: no agents "
                                                                 f"include matched"]))
        self.assertTrue(any(p.startswith("not selected") and "last launch" in p
                            for p in problems), problems)
        self.assertTrue(any("no agents include matched" in p for p in problems), problems)

    def test_a_sandy_without_the_field_or_the_sandbox_is_unverifiable_not_a_pass(self):
        problems = prov.verify_selection(self.SLUG, self._box(features=None))
        self.assertTrue(any("unverifiable" in p for p in problems), problems)
        problems = prov.verify_selection(self.SLUG, None)
        self.assertTrue(any("unverifiable" in p for p in problems), problems)

    # --- sandy's supervisor log -------------------------------------------

    def _relay_state(self):
        """Where sandy keeps the supervisor's state for this sandbox —
        named to this tool by the record's `relay.state_dir`, never built."""
        return self.sandbox() / "relay-state"

    def _record(self):
        return {"name": self.SLUG, "relay": {"path": prov.CONTAINER_ENTRY_PATH,
                                              "state_dir": str(self._relay_state())}}

    def _supervisor(self, *lines):
        path = self._relay_state() / prov.SUPERVISOR_LOG_NAME
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n")
        return path

    @staticmethod
    def _ts(seconds_ago):
        return (datetime.now(timezone.utc)
                - timedelta(seconds=seconds_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def test_no_supervisor_log_is_no_signal_not_a_problem(self):
        """A sandbox that never launched has no log, and that is not a fault."""
        self.assertEqual(prov.verify_relay_supervisor(self.sandbox(), self.SLUG, record=self._record()), [])

    def test_the_log_is_opened_where_sandy_NAMES_it_and_the_report_says_where(self):
        """`--print-state` carries `relay.state_dir`, the HOST path of the
        supervisor's state. A constructed path would read nothing if sandy
        moved it, silently. The record names
        the directory and this opens what it names; a record that names none
        has no log location at all."""
        named = self.root / "elsewhere" / "relay-state"
        named.mkdir(parents=True)
        (named / prov.SUPERVISOR_LOG_NAME).write_text(
            "(header)\n"
            f"[sandy-relay] {self._ts(120)} start /opt/sandy/features/amap/relay\n"
            "inbox-delivery: fatal: something\n"
            f"[sandy-relay] {self._ts(119)} exit rc=2 uptime=0s; restart in 60s\n")
        record = {"name": self.SLUG, "relay": {"path": prov.CONTAINER_ENTRY_PATH,
                                                "state_dir": str(named)}}
        problems = prov.verify_relay_supervisor(self.sandbox(), self.SLUG, record=record)
        self.assertTrue(any(p.startswith("relay is down") for p in problems), problems)
        self.assertIn(str(named / prov.SUPERVISOR_LOG_NAME), problems[0])
        # A record with no state_dir names no location, and none is guessed:
        # verify reports it as relaunch lag.
        self.assertIsNone(prov.supervisor_log_path({"relay": {"path": "x"}}))
        self.assertIsNone(prov.supervisor_log_path(None))
        self.assertEqual(prov.verify_relay_supervisor(self.sandbox(), self.SLUG,
                                                      record={"relay": {"path": "x"}}), [])

    def test_a_relay_disabled_at_its_last_launch_is_reported_off_the_record(self):
        """For a STOPPED sandbox too: the marker read needs a container, the
        `--print-state` record does not."""
        self.assertEqual(prov.verify_relay_disabled_record(self.SLUG, {"relay": {"path": "x"}}), [])
        self.assertEqual(prov.verify_relay_disabled_record(self.SLUG, None), [])
        problems = prov.verify_relay_disabled_record(
            self.SLUG, {"relay": {"path": None, "disabled_by": "workspace"}})
        self.assertTrue(any(p.startswith("relay disabled") for p in problems), problems)
        self.assertIn("workspace tier", problems[0])


    # --- `feature_entries` in the `--print-state` record. Shape as the sandy
    # workspace reported it from sandy's unmerged amap-decouple branch
    # (rappdw/sandy#381): state_dir is a HOST path, $SANDBOX_DIR/relay-state
    # for the designated entry and $SANDBOX_DIR/feature-state/<feature> for
    # any other. Re-measure against a released sandy 2.4.0 before relying on it.

    def _entries_record(self, state_dir, *, disabled_by=None, relay_state_dir=None):
        return {"name": self.SLUG,
                "relay": {"path": f"{prov.CONTAINER_FEATURES_ROOT}/aaa-other/run",
                          "state_dir": str(relay_state_dir or self._relay_state()),
                          "disabled_by": disabled_by},
                "feature_entries": {prov.FEATURE_NAME: {
                    "path": prov.CONTAINER_ENTRY_PATH, "state_dir": str(state_dir),
                    "relay_alias": False, "disabled_by": disabled_by}}}

    def test_the_log_is_read_from_our_entrys_state_dir_not_the_relays(self):
        """relay{} names the designated entry's state; ours is elsewhere. A
        healthy log under relay.state_dir must not hide ours being down."""
        self._supervisor(
            "(header)",
            f"[sandy-relay] {self._ts(300)} start /opt/sandy/features/aaa-other/run")
        ours = self.sandbox() / "feature-state" / prov.FEATURE_NAME
        ours.mkdir(parents=True)
        (ours / prov.SUPERVISOR_LOG_NAME).write_text(
            "(header)\n"
            f"[sandy-entry {prov.FEATURE_NAME}] {self._ts(120)} start {prov.CONTAINER_ENTRY_PATH}\n"
            "inbox-delivery: fatal: something\n"
            f"[sandy-entry {prov.FEATURE_NAME}] {self._ts(119)} exit rc=2 uptime=0s; "
            "restart in 60s\n")
        problems = prov.verify_relay_supervisor(self.sandbox(), self.SLUG,
                                                record=self._entries_record(ours))
        self.assertTrue(any(p.startswith("relay is down") for p in problems), problems)
        self.assertIn(str(ours / prov.SUPERVISOR_LOG_NAME), problems[0])
        self.assertIn("fatal: something", problems[0])

    def test_entries_reported_without_ours_names_no_log(self):
        record = {"name": self.SLUG,
                  "relay": {"path": "x", "state_dir": str(self._relay_state())},
                  "feature_entries": {"aaa-other": {"path": "x", "state_dir": "/y"}}}
        self.assertIsNone(prov.supervisor_log_path(record))
        self.assertEqual(prov.supervisor_log_path({**record, "feature_entries": None}),
                         self._relay_state() / prov.SUPERVISOR_LOG_NAME)

    def test_the_lock_held_line_is_not_the_relays_last_words(self):
        """The supervisor refusing a second copy of itself writes its own
        line; the diagnosis is still the relay's stderr before it."""
        self._supervisor(
            "(header)",
            f"[sandy-relay] {self._ts(120)} start /opt/sandy/features/amap/relay",
            "inbox-delivery: fatal: the real cause",
            f"[sandy-relay] {self._ts(119)} supervisor already running (lock held); "
            "not starting a second",
            f"[sandy-relay] {self._ts(118)} exit rc=2 uptime=0s; restart in 60s")
        problems = prov.verify_relay_supervisor(self.sandbox(), self.SLUG, record=self._record())
        self.assertTrue(any(p.startswith("relay is down") for p in problems), problems)
        self.assertIn("the real cause", problems[0])
        self.assertNotIn("lock held", problems[0])

    def test_an_entry_declared_but_never_started_is_reported(self):
        """sandy's report (rappdw/sandy#381, unmerged): with an agent image
        older than sandy, the container starts only the designated entry, and
        `--print-state` shows ours as state "absent", disabled_by null. The
        daemon heartbeat check fails too; this names the cause."""
        record = self._entries_record(self.sandbox() / "feature-state" / prov.FEATURE_NAME)
        record["feature_entries"][prov.FEATURE_NAME]["state"] = "absent"
        problems = prov.verify_entry_started_record(self.SLUG, record)
        self.assertTrue(any(p.startswith("entry not started") for p in problems), problems)
        self.assertIn("sandy --rebuild", problems[0])
        self.assertIn("re-run verify", problems[0])
        for state in ("started", "failed", "looping"):
            with self.subTest(state=state):
                record["feature_entries"][prov.FEATURE_NAME]["state"] = state
                self.assertEqual(prov.verify_entry_started_record(self.SLUG, record), [])

    def test_absent_state_is_not_raised_where_other_checks_own_the_answer(self):
        """Disabled (sandy reports "absent" and a tier), not adopted, and not
        reported: each has its own check, so this one stays silent."""
        ours = self.sandbox() / "feature-state" / prov.FEATURE_NAME
        disabled = self._entries_record(ours, disabled_by="env")
        disabled["feature_entries"][prov.FEATURE_NAME]["state"] = "absent"
        not_adopted = {"feature_entries": {"aaa-other": {"state": "absent"}}}
        unreported = {"feature_entries": None, "relay": {"state": "absent"}}
        for name, record in (("disabled", disabled), ("not adopted", not_adopted),
                             ("unreported", unreported), ("no record", None)):
            with self.subTest(name):
                self.assertEqual(prov.verify_entry_started_record(self.SLUG, record), [])

    def test_own_entry_disabled_at_its_last_launch_is_reported_off_the_record(self):
        """Without `relay{}` at all, the shape once a later sandy major removes
        it (rappdw/sandy#382): the entry's own disabled_by is the only signal."""
        record = self._entries_record(self.sandbox() / "feature-state" / prov.FEATURE_NAME,
                                      disabled_by="host")
        del record["relay"]
        problems = prov.verify_relay_disabled_record(self.SLUG, record)
        self.assertTrue(any(p.startswith("relay disabled") for p in problems), problems)
        self.assertIn("host tier", problems[0])

    def test_a_healthy_relay_passes(self):
        self._supervisor(
            "(header line the tail may have cut)",
            f"[sandy-relay] {self._ts(300)} start /opt/sandy/features/amap/relay",
            "inbox-delivery: started pid 4242; mail=/x peer=/y")
        self.assertEqual(prov.verify_relay_supervisor(self.sandbox(), self.SLUG, record=self._record()), [])

    def test_a_relay_that_is_DOWN_is_reported_with_its_own_last_words(self):
        """The diagnosis is in the relay's stderr, not the supervisor's line.
        An operator who has to go and find the log has already lost most of
        the value of it being written."""
        self._supervisor(
            "(header)",
            f"[sandy-relay] {self._ts(120)} start /opt/sandy/features/amap/relay",
            "inbox-delivery: fatal: mail notice dir /lanes/inbox/notices "
            "is not a directory",
            f"[sandy-relay] {self._ts(119)} exit rc=2 uptime=0s; restart in 60s")
        problems = prov.verify_relay_supervisor(self.sandbox(), self.SLUG, record=self._record())
        self.assertTrue(any(p.startswith("relay is down") for p in problems), problems)
        self.assertIn("is not a directory", problems[0])

    def test_a_LOOPING_relay_is_caught_even_when_the_last_event_is_a_start(self):
        """The failure a single sample cannot see. A relay the supervisor
        restarts every 60 s is `started` whenever you look just after a
        restart; only the COUNT separates it from a healthy one. This is the
        shape of the 1,630-restart loop that ran unnoticed for 37 hours."""
        lines = ["(header)"]
        for n in (400, 340, 280, 220, 160, 100):
            lines.append(f"[sandy-relay] {self._ts(n)} start /opt/sandy/features/amap/relay")
            lines.append("inbox-delivery: fatal: peer notice dir /x is not a directory")
            lines.append(f"[sandy-relay] {self._ts(n - 1)} exit rc=2 uptime=0s; "
                         "restart in 60s")
        lines.append(f"[sandy-relay] {self._ts(40)} start /opt/sandy/features/amap/relay")
        self._supervisor(*lines)
        problems = prov.verify_relay_supervisor(self.sandbox(), self.SLUG, record=self._record())
        self.assertTrue(any(p.startswith("relay is looping") for p in problems), problems)
        self.assertIn("is not a directory", problems[0])

    def test_old_failures_that_have_since_recovered_do_not_fail(self):
        """The real log holds 1,630 failures AND the success that ended them.
        A check that counted all of history would call a working relay broken
        forever."""
        lines = ["(header)"]
        for n in (90000, 89000, 88000):
            lines.append(f"[sandy-relay] {self._ts(n)} start /opt/sandy/features/amap/relay")
            lines.append(f"[sandy-relay] {self._ts(n - 1)} exit rc=2 uptime=0s; "
                         "restart in 60s")
        lines.append(f"[sandy-relay] {self._ts(60)} start /opt/sandy/features/amap/relay")
        self._supervisor(*lines)
        self.assertEqual(prov.verify_relay_supervisor(self.sandbox(), self.SLUG, record=self._record()), [])

    def test_a_clean_exit_is_not_a_failure(self):
        """ENOUGH clean exits to cross the loop threshold, deliberately. One
        rc=0 proves nothing here: it sits below the threshold either way, so a
        check that wrongly counted clean exits would still pass. Two is the
        smallest number that can tell the difference."""
        self._supervisor(
            "(header)",
            f"[sandy-relay] {self._ts(300)} start /opt/sandy/features/amap/relay",
            f"[sandy-relay] {self._ts(250)} exit rc=0 uptime=50s; restart in 60s",
            f"[sandy-relay] {self._ts(200)} start /opt/sandy/features/amap/relay",
            f"[sandy-relay] {self._ts(150)} exit rc=0 uptime=50s; restart in 60s",
            f"[sandy-relay] {self._ts(90)} start /opt/sandy/features/amap/relay")
        self.assertEqual(prov.verify_relay_supervisor(self.sandbox(), self.SLUG, record=self._record()), [])

    def test_a_clean_exit_as_the_LAST_event_is_not_reported_as_down(self):
        """`down` means failed, not stopped. A relay that exited 0 is covered
        by the heartbeat check; calling it a fault here would fail `verify` on
        a sandbox that was deliberately shut down."""
        self._supervisor(
            "(header)",
            f"[sandy-relay] {self._ts(200)} start /opt/sandy/features/amap/relay",
            f"[sandy-relay] {self._ts(150)} exit rc=0 uptime=50s; restart in 60s")
        self.assertEqual(prov.verify_relay_supervisor(self.sandbox(), self.SLUG, record=self._record()), [])

    # --- the peer mount ---------------------------------------------------


    # --- liveness ---------------------------------------------------------

    def test_a_live_daemon_passes_both_signals(self):
        self._heartbeat()
        self.assertEqual(
            prov.verify_relay_alive(self.sandbox(), self.SLUG,
                                    container="c", docker_bin=self._fake_docker(0)), [])

    def test_a_missing_heartbeat_fails(self):
        problems = prov.verify_relay_alive(self.sandbox(), self.SLUG, container="c",
                                           docker_bin=self._fake_docker(0))
        self.assertTrue(any(p.startswith("relay not alive") for p in problems))

    def test_a_stale_heartbeat_fails(self):
        self._heartbeat(heartbeat_at=(datetime.now(timezone.utc)
                                      - timedelta(seconds=120)).isoformat())
        problems = prov.verify_relay_alive(self.sandbox(), self.SLUG, container="c",
                                           docker_bin=self._fake_docker(0))
        self.assertTrue(any("heartbeat is" in p for p in problems))

    def test_a_claim_held_by_another_pid_fails_and_names_the_lane(self):
        """The second-consumer case the claim lock exists to catch."""
        self._heartbeat()
        self._claims_on_disk(pid=os.getpid() + 1, lanes=("peer",))
        problems = prov.verify_relay_alive(self.sandbox(), self.SLUG, container="c",
                                           docker_bin=self._fake_docker(0))
        self.assertTrue(any("peer claim is held by pid" in p for p in problems))
        self.assertFalse(any("mail claim is held by pid" in p for p in problems))

    def test_a_missing_claim_file_fails_as_ABSENT(self):
        """ABSENT IS NOT EMPTY, and it is not malformed either. Asserting only
        that some problem mentions the lane would pass whichever branch fired,
        so this pins the one that should."""
        self._heartbeat()
        self._claim_path("mail").unlink()
        problems = prov.verify_relay_alive(self.sandbox(), self.SLUG, container="c",
                                           docker_bin=self._fake_docker(0))
        self.assertTrue(any("mail claim absent" in p for p in problems), problems)

    def test_a_claim_that_is_not_an_object_fails_as_MALFORMED(self):
        """The other branch, pinned separately for the same reason."""
        self._heartbeat()
        self._claim_path("mail").write_text("[1, 2, 3]")
        problems = prov.verify_relay_alive(self.sandbox(), self.SLUG, container="c",
                                           docker_bin=self._fake_docker(0))
        self.assertTrue(any("mail claim is not an object" in p for p in problems), problems)

    def test_a_claim_path_outside_the_connector_mount_fails(self):
        """An unverifiable claim is not a held one. A daemon that published a
        path this host cannot resolve would otherwise be waved through."""
        self._heartbeat(claims={"mail": "/tmp/elsewhere.json",
                                "peer": f"{CONTAINER_CONNECTOR}/claims/peer.amap-consumer.json"})
        problems = prov.verify_relay_alive(self.sandbox(), self.SLUG, container="c",
                                           docker_bin=self._fake_docker(0))
        self.assertTrue(any("has no" in p and prov.CONNECTOR_REL in p
                            for p in problems))

    def test_a_stale_proc_start_fails(self):
        """A pid is only a name. The claim was written by an EARLIER process
        that happened to hold the same number; the start time says so."""
        self._heartbeat()
        self._claims_on_disk(proc_start="99999999")
        problems = prov.verify_relay_alive(self.sandbox(), self.SLUG, container="c",
                                           docker_bin=self._fake_docker(0))
        self.assertTrue(any("belongs to an earlier process" in p for p in problems))

    def test_a_pid_that_is_not_the_daemon_fails(self):
        """Stops the agent pointing a hand-written claim at a shell it owns:
        the pid must be shown to be running the daemon, not merely alive."""
        self._heartbeat()
        problems = prov.verify_relay_alive(
            self.sandbox(), self.SLUG, container="c",
            docker_bin=self._fake_docker(0, cmdline="/bin/sh -i"))
        self.assertTrue(any("not inbox-delivery" in p for p in problems))

    def test_the_probe_never_uses_kill(self):
        """Regression guard for the bug this replaced. sandy drops CAP_KILL
        from the container's bounding set, which caps root too, so `kill -0`
        returns EPERM for a LIVE process and the check read that as dead."""
        self.assertNotIn("kill", prov._PROC_PROBE)

    def test_a_FRESH_heartbeat_with_a_DEAD_pid_still_fails(self):
        """The point of the second signal. The heartbeat file is same-uid and
        forgeable; `kill -0` in the container is not. A check that trusted
        the file alone would be green over a fleet where the agent wrote it."""
        self._heartbeat()
        problems = prov.verify_relay_alive(self.sandbox(), self.SLUG, container="c",
                                           docker_bin=self._fake_docker(1))
        self.assertTrue(any("is not running in" in p for p in problems))

    def test_a_missing_container_is_a_failure_not_a_pass(self):
        """Falling back to 'the heartbeat looks fine' would make the
        forgeable signal sufficient whenever docker is unavailable."""
        self._heartbeat()
        problems = prov.verify_relay_alive(self.sandbox(), self.SLUG, container=None)
        self.assertTrue(any("could not be checked" in p for p in problems))

    def test_a_naive_timestamp_is_read_as_UTC(self):
        """The daemon writes inside a container whose timezone this host has
        no reason to share; guessing local would make a fresh heartbeat look
        hours stale, or a stale one look fresh."""
        now = datetime.now(timezone.utc)
        self.assertLess(
            abs(prov._heartbeat_age_seconds(now.replace(tzinfo=None).isoformat())), 5)

    def test_an_unparsable_timestamp_is_None_never_zero(self):
        self.assertIsNone(prov._heartbeat_age_seconds("yesterday"))
        self.assertIsNone(prov._heartbeat_age_seconds(None))

    def _fake_docker(self, rc, *, starttime=None, cmdline=None):
        """A docker whose `exec` answers the /proc probe.

        `rc` non-zero stands for "the pid is not running in the container".
        On success it emits a `/proc/<pid>/stat` line and a command line in
        the probe's two-part shape, so the tests exercise the real parsing
        rather than a bare exit code — which is what let `kill -0` sit here
        broken: a fake that only ever returned a status could not tell the
        difference between the two commands."""
        starttime = self.CLAIM_START if starttime is None else starttime
        cmdline = ("python3 /opt/sandy/features/amap/inbox-delivery" if cmdline is None else cmdline)
        # Field 22 is the start time. After the closing paren of field 2 the
        # fields run 3..N, so the start time must land at index 19 there:
        # one token for field 3 plus eighteen fillers puts it in place.
        stat = "7 (python3) S " + " ".join(["0"] * 18) + " " + starttime
        path = self.root / f"docker-{rc}-{abs(hash((starttime, cmdline))) % 99999}"
        path.write_text("#!/bin/sh\n"
                        + (f"exit {rc}\n" if rc else
                           f"printf '%s\\n' '{stat}'\n"
                           f"printf '%s\\n' '{prov._PROBE_SEP}'\n"
                           f"printf '%s' '{cmdline}'\n"))
        path.chmod(0o755)
        return str(path)


class VerifyEndToEndTest(SandboxFixture):
    """`verify` through `main()`, exit codes included — the wiring, not the
    helpers. A first cut of these called the check functions directly, which
    would have stayed green over a `main()` that never called them."""

    def _run(self, selected=(None,)):
        """`selected` is the slugs whose last launch selected the feature —
        both, by default."""
        chosen = list(selected) if selected != (None,) else [self.SLUG, self.OTHER]
        fake = self.root / "sandy"
        state = json.dumps({"sandboxes": [
            {"name": s, "path": str(self.sandbox(s)), "workspace_path": f"/ws/{s}",
             "agents": ["claude"],
             "features": [prov.FEATURE_NAME] if s in chosen else [],
             "feature_problems": [] if s in chosen else [f"{prov.FEATURE_NAME}: excluded"]}
            for s in (self.SLUG, self.OTHER)]})
        schema = json.dumps({"schema_version": 3, "config": {"privileged_keys": []},
                             "manifest": {"top_level_keys": ["schema", "sandboxes", "agents", "create",
                                                             "mounts", "entry", "expose", "feature",
                                                             "agent_args"]},
                             "agents": [{"name": "claude"}]})
        fake.write_text("#!/bin/sh\ncase \"$1\" in\n  --print-schema) cat <<'EOF'\n"
                        + schema + "\nEOF\n;;\n  *) cat <<'EOF'\n" + state + "\nEOF\n;;\nesac\n")
        fake.chmod(0o755)
        _select(self.home, *chosen)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = prov.main(["--sandy", str(fake),
                            "--sandy-home", str(self.home),
                            "--connector-src", str(self.src),
                            "verify"])
        return rc, out.getvalue() + err.getvalue()

    def setUp(self):
        super().setUp()
        self.policy_file = _write(self.root, self.policy, "policy.json")
        # The manifest, rendered from the policy the run will load — `verify`
        # checks the file on disk against that rendering byte for byte. It is
        # written by the installer's own writer, so the fixture is what the
        # tool produces rather than what the test thinks it produces.
        prov.install_manifest(self.home, fp.load_policy(self.policy_file), dry_run=False)

    def test_a_healthy_unstarted_fleet_reports_only_what_needs_a_container(self):
        rc, out = self._run()
        # No container is running, so the peer-graph check needs a rendered
        # router config that does not exist yet; liveness is not asked at all.
        self.assertIn("verify (1/2)", out)
        self.assertIn("verify (2/2)", out)
        self.assertNotIn("relay not alive", out)

    def test_the_router_process_is_read_last_and_an_unanswerable_read_is_a_problem_by_name(self):
        """The wiring: `verify` reaches router_health's two sections through
        main(). The suite never runs docker (conftest refuses it), so what
        this run can see is the UNKNOWN that refusal produces — reported,
        with its reason, and exit 1: "could not tell" is not a clean bill."""
        rc, out = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("router: UNKNOWN whether the router container is running", out)
        self.assertIn("never runs docker", out)
        self.assertIn("router-container, router-health", out)


    def test_payload_drift_exits_1(self):
        """The chain is on the payload; a hand-edited wrapper there is drift,
        reported once for the host."""
        self.wrapper().write_text("#!/bin/sh\nexit 0\n")
        rc, out = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("payload drift", out)

    def test_manifest_drift_exits_1(self):
        path = prov.feature_manifest_path(self.home)
        doc = json.loads(path.read_text())
        doc["create"] = []
        path.write_text(json.dumps(doc, indent=2) + "\n")
        rc, out = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("manifest drift", out)

    def test_a_fleet_where_sandy_selected_nothing_says_so(self):
        # The operator's edit lands IN the manifest (the policy lives there);
        # `install_manifest` over an existing file repairs only the adapter's
        # blocks, so a policy change is written the way an operator makes it.
        prov.feature_manifest_path(self.home).write_text(
            prov.manifest_text({**self.policy, fp.TASK_GRAPH_KEY: {}}))
        rc, out = self._run(selected=())
        self.assertIn("no sandbox selected", out)

    def test_a_policy_naming_UNSELECTED_instances_is_reported_and_exits_1(self):
        """It fails loud. A graph naming a slug sandy has not selected is the
        policy check's, reported on the read path as a POLICY line and
        refused on the write path. Exit 1 here: `verify` answered, and the
        answer names the slug."""
        rc, out = self._run(selected=())
        self.assertEqual(rc, 1, out)
        self.assertIn("POLICY", out)
        self.assertIn(self.OTHER, out)


# ================================ the invariant: a :ro exec chain, and WHOSE
# signal says the relay ran
#
# The two failure shapes these tests exist to stop:
#
#   1. A green `verify` resting on a file sandy never reads. Every check
#      whose inputs are all our own writes can only prove we are consistent
#      with ourselves. The relay record in sandy's session marker is sandy's,
#      and nothing this repo writes can make it true.
#   2. A `:ro` wrapper that execs a writable daemon. The agent simply
#      rewrites the daemon instead, and the hijack still reports a started
#      relay and a green wrapper byte-comparison.
#
# The docker calls are faked, but the WRITE PROBE is real: the fake runs the
# probe's shell locally against a real directory, so `READONLY` is produced by
# an actual EACCES rather than by the fake agreeing with the test.

FAKE_DOCKER = """#!/usr/bin/env python3
import json, os, subprocess, sys
cfg = json.load(open(os.environ["FAKE_DOCKER_CFG"]))
a = sys.argv[1:]
if a and a[0] == "inspect":
    if cfg.get("inspect_fails"):
        sys.exit(1)
    for m in cfg["mounts"]:
        print("%s|%s|%s" % (m["Source"], m["Destination"], m["RW"]))
    sys.exit(0)
if a and a[0] == "exec":
    i, env = 1, dict(os.environ)
    while i < len(a) and a[i] == "-e":
        k, _, v = a[i + 1].partition("=")
        env[k] = v
        i += 2
    i += 1  # the container name
    rest = a[i:]
    if rest[:1] == ["cat"]:
        if "session" not in cfg:
            sys.stderr.write("no such file\\n")
            sys.exit(1)
        sys.stdout.write(cfg["session"] if isinstance(cfg["session"], str)
                         else json.dumps(cfg["session"]))
        sys.exit(0)
    if rest[:2] == ["sh", "-c"]:
        sys.exit(subprocess.run(["sh", "-c", rest[2]], env=env).returncode)
sys.exit(1)
"""


class SettledReportTest(unittest.TestCase):
    """`_part_is_settled` decides whether `verify`'s staleness pass calls a
    part of the install up to date. A writer whose "nothing to do" phrase is not
    listed there is counted as a change forever; one that ends in " present"
    by accident would have a real change counted as settled."""

    def test_every_settled_phrase_the_writers_produce_is_recognised(self):
        for part in ("relay present",
                     "roster directory present",
                     "relay present; inbox-delivery present; _inboxlib.py present"):
            with self.subTest(part=part):
                self.assertTrue(prov._part_is_settled(part), part)

    def test_a_changed_part_is_not_settled_even_beside_settled_ones(self):
        for part in ("created relay", "would create roster directory",
                     "removed inbox-delivery",
                     "relay present; created inbox-delivery; _inboxlib.py present"):
            with self.subTest(part=part):
                self.assertFalse(prov._part_is_settled(part), part)


# ================================================ the recreation cadence
#
# `container_recreate_interval_hours` present in the policy (`install`
# refuses without it — `SyncRefusalTest`), the launchd job loaded, and
# `--check` seeing it ran within the interval plus slack.


class LaunchdJobTest(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = Path(self._tmp.name)

    def test_the_daily_case_is_a_wall_clock_schedule(self):
        """A calendar entry is what 'daily at 04:00' means, and launchd runs
        a missed one on wake; a missed StartInterval simply slips."""
        plist = lj.render_plist("/usr/local/bin/sandy", self.home, 24)
        self.assertIn("StartCalendarInterval", plist)
        self.assertIn(f"<key>Hour</key><integer>{lj.RUN_HOUR}</integer>", plist)
        self.assertNotIn("StartInterval", plist)

    def test_a_non_daily_interval_becomes_seconds_rather_than_a_wrong_hour(self):
        """A calendar entry cannot express 'every 7 hours', and pretending
        otherwise would silently run the fleet on a cadence the policy did
        not ask for."""
        plist = lj.render_plist("/usr/local/bin/sandy", self.home, 7)
        self.assertIn("<key>StartInterval</key>", plist)
        self.assertIn(str(7 * 3600), plist)
        self.assertNotIn("StartCalendarInterval", plist)

    def test_it_never_runs_at_load(self):
        """Bootstrapping the agent must not recreate every container on the
        box during whatever the operator was doing when they ran it."""
        plist = lj.render_plist("/usr/local/bin/sandy", self.home, 24)
        self.assertIn("<key>RunAtLoad</key>\n    <false/>", plist)

    def test_a_non_positive_interval_is_refused(self):
        for bad in (0, -1):
            with self.subTest(hours=bad), self.assertRaises(ValueError):
                lj.render_plist("/usr/local/bin/sandy", self.home, bad)

    def test_a_path_with_spaces_survives_into_the_shell_command(self):
        cmd = lj.job_command("/Applications/My Tools/sandy", self.home)
        self.assertIn("'/Applications/My Tools/sandy'", cmd)

    def test_the_plist_is_well_formed_xml(self):
        import xml.dom.minidom
        xml.dom.minidom.parseString(
            lj.render_plist("/usr/local/bin/sand&y", self.home, 24))

    def test_the_job_command_really_writes_a_parsable_stamp(self):
        """Run, not read. A stamp format that only the test's own writer
        produces proves nothing about what launchd will leave behind."""
        cmd = lj.job_command(shutil.which("true"), self.home)
        subprocess.run(["sh", "-c", cmd], check=True)
        record = lj.last_run(self.home)
        self.assertEqual(record["status"], 0)
        self.assertIsNotNone(record["at"])
        self.assertIsNone(lj.overdue_reason(self.home, 24))

    def test_a_FAILING_job_leaves_a_record_and_is_reported_as_failed(self):
        """The third state, and the one a plain age check calls healthy: it
        ran, on time, and the containers were not recreated. `;` and not
        `&&` in the job command is what keeps this distinguishable from
        'never ran'."""
        subprocess.run(["sh", "-c", lj.job_command(shutil.which("false"), self.home)], check=True)
        record = lj.last_run(self.home)
        self.assertNotEqual(record["status"], 0)
        reason = lj.overdue_reason(self.home, 24)
        self.assertIn("NOT recreated", reason)

    def test_never_run_is_distinguishable_from_overdue(self):
        never = lj.overdue_reason(self.home, 24)
        self.assertIn("never run", never)
        subprocess.run(["sh", "-c", lj.job_command(shutil.which("true"), self.home)], check=True)
        late = lj.overdue_reason(
            self.home, 24, now=datetime.now(timezone.utc) + timedelta(hours=40))
        self.assertIn("past the ratified", late)
        self.assertNotIn("never run", late)

    def test_the_slack_is_actually_applied(self):
        subprocess.run(["sh", "-c", lj.job_command(shutil.which("true"), self.home)], check=True)
        just_inside = datetime.now(timezone.utc) + timedelta(
            hours=24 + lj.SLACK_HOURS - 1)
        self.assertIsNone(lj.overdue_reason(self.home, 24, now=just_inside))

    def test_a_corrupt_stamp_is_a_reason_never_a_crash(self):
        """This is read from a `--check` that may run from cron, where a
        traceback is a mail nobody reads."""
        lj.stamp_path(self.home).write_text("garbage\n")
        self.assertIn("does not hold", lj.overdue_reason(self.home, 24))
        lj.stamp_path(self.home).write_text("not-a-date 0\n")
        self.assertIn("unparsable timestamp", lj.overdue_reason(self.home, 24))

    def test_the_stamp_is_outside_every_sandbox(self):
        """An agent must not be able to forge evidence that the cadence is
        being kept."""
        self.assertEqual(lj.stamp_path(self.home).parent, self.home)
        self.assertNotIn("sandboxes", lj.stamp_path(self.home).parts)

    def test_the_install_command_is_handed_over_never_run(self):
        cmd = lj.install_command(self.home)
        self.assertIn("launchctl bootstrap", cmd)
        self.assertIn(lj.LABEL, cmd)
        self.assertFalse(lj.plist_path(self.home).exists(),
                         "rendering must not install anything")


class ManualCheckRegistryTest(unittest.TestCase):
    """The properties that CANNOT be a test here, named so they are not
    quietly forgotten.

    Each entry says what has to be observed and why no host-side test can
    stand in for it. This is deliberately a test rather than a comment: a
    check that moves from 'manual' to 'covered' should require deleting a
    line here, in the same change that adds the coverage."""

    MANUAL = {
        "ambiguous-target": (
            "With two `claude` panes live, a delegation yields an "
            "`ambiguous_target` outcome and remains in the spool; with one, it is "
            "delivered. Needs a live container with two panes and the payload's "
            "`handoff-sessions`; the daemon's own suite in "
            "amap-connector-claude covers the counting logic."),
        "launchd-live": (
            "The launchd job LOADED, and the relay present after a real "
            "recreation. `LaunchdJobTest` proves the plist, the stamp and the "
            "three states; whether launchd honoured it is observable only on "
            "the Mac host, by hand."),
        "email-router-partition": (
            "When an email router is added: its `touch` probe writes the mail "
            "trees and the intake spool and fails on every peer lane. There is "
            "no email router in this deployment, so the partition is prospective — "
            "the design commits to 'the email router is a container' so nobody "
            "later runs it as a host process and satisfies the rule on paper."),
    }

    def test_every_manual_check_says_why_it_is_manual(self):
        for key, reason in self.MANUAL.items():
            with self.subTest(check=key):
                self.assertGreater(len(reason), 120,
                                   "a manual check needs the reason, in sentences")


class RelayStartedAndMountsTest(unittest.TestCase):
    """Sandy's own signals about a running sandbox: which relay it started
    at launch (`relay` in the session marker — `path`, `source`,
    `disabled_by`), and what the container's mount table holds for the
    feature payload and the roster."""

    SLUG = "alpha-a1b2c3d4"
    CONTAINER = "sandy-alpha-a1b2c3d4"

    def setUp(self):
        self._td = TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.dir = Path(self._td.name)
        self.sandbox = self.dir / "sandboxes" / self.SLUG
        self.sandbox.mkdir(parents=True)

    def _docker_marker(self, doc, rc=0):
        path = self.dir / f"docker-m-{abs(hash(json.dumps(doc, sort_keys=True))) % 99999}"
        path.write_text("#!/bin/sh\n" + (f"exit {rc}\n" if rc else
                                         f"cat <<'EOF'\n{json.dumps(doc)}\nEOF\n"))
        path.chmod(0o755)
        return str(path)

    def _started(self, doc, rc=0):
        return prov.verify_relay_started(self.SLUG, self.CONTAINER,
                                         docker_bin=self._docker_marker(doc, rc))


    # --- the relay marker: `path`, `source`, `disabled_by`

    def test_a_marker_on_the_ENTRY_passes(self):
        self.assertEqual(self._started(
            {"relay": {"path": prov.CONTAINER_ENTRY_PATH, "source": "manifest",
                       "disabled_by": None}}), [])

    def test_a_marker_with_no_path_is_no_relay_at_all(self):
        problems = self._started({"relay": {"path": None, "source": "none", "disabled_by": None}})
        self.assertTrue(any(p.startswith("relay not configured") for p in problems), problems)
        self.assertIn("install --apply", problems[0])

    def test_another_features_entry_pinned_as_the_relay_names_that_feature(self):
        """sandy 2.2.0+ records only `source` "manifest" or "none", and pins ONE
        selected feature's entry as the relay: a foreign path under "manifest"
        is another feature's entry, never an override (sandy refuses one)."""
        other = f"{prov.CONTAINER_FEATURES_ROOT}/zzz-other/run"
        problems = self._started({"relay": {"path": other, "source": "manifest",
                                            "disabled_by": None}})
        self.assertTrue(any(p.startswith("relay elsewhere") for p in problems), problems)
        self.assertIn(other, problems[0])
        self.assertIn("'zzz-other' feature's entry", problems[0])
        self.assertIn("no relay override to clear", problems[0])

    def test_a_pre_floor_marker_with_a_foreign_path_asks_for_a_relaunch(self):
        """"explicit" (and "slot") appear only in a marker a sandy older than
        the floor wrote; a relaunch under the floor rewrites it."""
        other = "/opt/elsewhere/my-relay"
        problems = self._started({"relay": {"path": other, "source": "explicit"}})
        self.assertTrue(any(p.startswith("relay elsewhere") for p in problems), problems)
        self.assertIn(other, problems[0])
        self.assertIn("relay.source='explicit'", problems[0])
        self.assertIn(f"Relaunch it under sandy {prov.SANDY_FLOOR}", problems[0])


    # --- sandy's per-feature entries (`feature_entries`) in the marker.
    # Shape as the sandy workspace reported it from sandy's unmerged
    # amap-decouple branch (rappdw/sandy#381): per feature, exactly
    # {path, relay_alias, disabled_by}. Re-measure against a released
    # sandy 2.4.0 marker before relying on it.

    @staticmethod
    def _entry(path=None, relay_alias=True, disabled_by=None):
        return {"path": prov.CONTAINER_ENTRY_PATH if path is None else path,
                "relay_alias": relay_alias, "disabled_by": disabled_by}

    def test_own_entry_running_passes_while_relay_describes_another_feature(self):
        """sandy runs every selected feature's entry; `relay{}` describes the
        one it designated. With `feature_entries` reported, ours is read and
        `relay{}` is not, so another feature's designation is no fault."""
        other = f"{prov.CONTAINER_FEATURES_ROOT}/aaa-other/run"
        doc = {"relay": {"path": other, "source": "manifest", "disabled_by": None},
               "feature_entries": {"aaa-other": self._entry(other, True),
                                   prov.FEATURE_NAME: self._entry(relay_alias=False)}}
        self.assertEqual(self._started(doc), [])

    def test_own_entry_disabled_is_reported_before_anything_else(self):
        """relay_alias is false on a disabled entry even when it would have
        been designated, so disabled_by is read first."""
        doc = {"relay": {"path": None, "source": "none", "disabled_by": "env"},
               "feature_entries": {prov.FEATURE_NAME: self._entry(relay_alias=False,
                                                                  disabled_by="env")}}
        problems = self._started(doc)
        self.assertTrue(any(p.startswith("relay disabled") for p in problems), problems)
        self.assertIn("env tier", problems[0])

    def test_entries_reported_without_ours_is_an_entry_not_adopted(self):
        other = f"{prov.CONTAINER_FEATURES_ROOT}/aaa-other/run"
        doc = {"relay": {"path": other, "source": "manifest", "disabled_by": None},
               "feature_entries": {"aaa-other": self._entry(other, True)}}
        problems = self._started(doc)
        self.assertTrue(any(p.startswith("relay not configured") for p in problems), problems)
        self.assertIn(f"adopted no {prov.FEATURE_NAME} entry", problems[0])

    def test_own_entry_at_another_path_is_a_manifest_mismatch(self):
        doc = {"feature_entries": {prov.FEATURE_NAME: self._entry(
            path=f"{prov.CONTAINER_FEATURE_DIR}/old-relay")}}
        problems = self._started(doc)
        self.assertTrue(any(p.startswith("relay elsewhere") for p in problems), problems)
        self.assertIn("install --apply", problems[0])

    def test_null_or_absent_entries_fall_back_to_the_relay_record(self):
        """Null (a launch before the upgrade) and absent (an older sandy) are
        UNKNOWN for `feature_entries`, never an empty answer: the relay{}
        reading applies, including its failures."""
        other = f"{prov.CONTAINER_FEATURES_ROOT}/aaa-other/run"
        for entries in ({"feature_entries": None}, {}):
            with self.subTest(entries=entries):
                ours = {"relay": {"path": prov.CONTAINER_ENTRY_PATH, "source": "manifest",
                                  "disabled_by": None}, **entries}
                self.assertEqual(self._started(ours), [])
                theirs = {"relay": {"path": other, "source": "manifest",
                                    "disabled_by": None}, **entries}
                problems = self._started(theirs)
                self.assertTrue(any(p.startswith("relay elsewhere") for p in problems),
                                problems)

    def test_a_marker_disabled_by_a_tier_is_reported_off_disabled_by(self):
        """`disabled_by` is the only host-side signal that a cloned repo
        shipping SANDY_RELAY=0 disabled a connector — which stops a manifest
        entry too."""
        problems = self._started({"relay": {"path": None, "source": "none", "disabled_by": "host"}})
        self.assertTrue(any(p.startswith("relay disabled") for p in problems), problems)
        self.assertIn("host tier", problems[0])


    def test_a_marker_with_no_relay_object_is_a_launch_by_an_unsupported_sandy(self):
        problems = self._started({"sandbox_name": self.SLUG})
        self.assertTrue(any(p.startswith("relay not configured") and "RELAUNCH" in p
                            for p in problems), problems)

    def test_an_unreadable_marker_is_a_failure_not_a_pass(self):
        self.assertTrue(self._started({}, rc=1))

    def _docker_mounts(self, *rows):
        lines = "".join(f"{os.path.realpath(h)}|{c}|{rw}\n" for h, c, rw in rows)
        path = self.dir / f"docker-i-{abs(hash(lines)) % 99999}"
        path.write_text("#!/bin/sh\ncat <<'EOF'\n" + lines + "EOF\n")
        path.chmod(0o755)
        return str(path)


    # --- the feature mount ---------------------------------------------------
    #
    # Asked of the mount table, never of the host directory: it can be right
    # while sandy did not select the sandbox and mounted nothing.

    def _fdir(self):
        """The SANDY HOME; the payload sits at its fixed place beneath it."""
        prov.feature_payload_dir(self.dir).mkdir(parents=True, exist_ok=True)
        return self.dir

    def test_a_read_only_feature_mount_at_the_right_path_passes(self):
        fdir = self._fdir()
        docker = self._docker_mounts(
            (prov.feature_payload_dir(fdir), prov.CONTAINER_FEATURE_DIR, "false"))
        self.assertEqual(prov.verify_feature_mount(fdir, self.SLUG, self.CONTAINER,
                                                   docker_bin=docker), [])

    def test_a_WRITABLE_feature_mount_fails(self):
        fdir = self._fdir()
        docker = self._docker_mounts(
            (prov.feature_payload_dir(fdir), prov.CONTAINER_FEATURE_DIR, "true"))
        problems = prov.verify_feature_mount(fdir, self.SLUG, self.CONTAINER, docker_bin=docker)
        self.assertTrue(any("WRITABLE" in p for p in problems), problems)

    def test_a_payload_covered_by_NO_MOUNT_names_the_two_causes(self):
        """The directory and sandy's verdict can both be right while the
        running container predates the manifest, or its launch skipped the
        mount: nothing is mounted, and both causes are named."""
        fdir = self._fdir()
        docker = self._docker_mounts(("/somewhere/else", "/opt/other", "false"))
        problems = prov.verify_feature_mount(fdir, self.SLUG, self.CONTAINER, docker_bin=docker)
        self.assertTrue(any("not mounted" in p and "relaunched" in p and "skip" in p
                            for p in problems), problems)

    def test_a_payload_mounted_at_the_WRONG_path_fails(self):
        """The manifest's entry and the registration name the payload at its
        fixed container path; a payload mounted anywhere else is an entry
        that execs nothing."""
        fdir = self._fdir()
        docker = self._docker_mounts(
            (prov.feature_payload_dir(fdir), "/opt/sandy/features/other", "false"))
        problems = prov.verify_feature_mount(fdir, self.SLUG, self.CONTAINER, docker_bin=docker)
        self.assertTrue(any("mounted elsewhere" in p for p in problems), problems)


    # --- the roster mount ---------------------------------------------------
    #
    # A missing mount is a PROBLEM, not a relaunch note: the payload is live,
    # so an agent restarted inside an older container reads the pointer with
    # no mount behind it.

    def _rdir(self):
        prov.feature_roster_dir(self.dir).mkdir(parents=True, exist_ok=True)
        return self.dir

    def test_a_read_only_roster_mount_passes(self):
        home = self._rdir()
        docker = self._docker_mounts((prov.feature_roster_dir(home), "/opt/amap/roster", "false"))
        self.assertEqual(prov.verify_roster_mount(home, self.SLUG, self.CONTAINER,
                                                  docker_bin=docker), [])

    def test_a_WRITABLE_roster_mount_fails(self):
        home = self._rdir()
        docker = self._docker_mounts((prov.feature_roster_dir(home), "/opt/amap/roster", "true"))
        problems = prov.verify_roster_mount(home, self.SLUG, self.CONTAINER, docker_bin=docker)
        self.assertTrue(any("roster WRITABLE" in p for p in problems), problems)

    def test_no_roster_mount_is_a_problem_with_relaunch_as_the_remedy(self):
        home = self._rdir()
        docker = self._docker_mounts(("/somewhere/else", "/opt/other", "false"))
        problems = prov.verify_roster_mount(home, self.SLUG, self.CONTAINER, docker_bin=docker)
        self.assertTrue(any("roster not mounted" in p and "Relaunch" in p for p in problems),
                        problems)

