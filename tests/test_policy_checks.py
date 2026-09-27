"""tests/test_policy_checks.py — the checks the write path applies to the
authored manifest's policy before any sandbox is provisioned under it:
ratification, `resolve_peers` and lane disjointness over the PROJECTED
membership, and the selection report (the rule beside sandy's verdicts,
never a prediction). The operator edits `feature.json` in place and
`install` validates it with these.
"""
import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

import _workspace  # noqa: E402

_workspace.skip_if_incomplete()
_ROUTER_ROOT = _workspace.ROUTER_ROOT
if str(_ROUTER_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROUTER_ROOT))

_HERE = Path(__file__).resolve().parents[1]

import fleet_policy as fp  # noqa: E402


def _load():
    """The checks module and the provisioner, both importable; a test that
    replaces one of the provisioner's functions must put it back — see the
    `addCleanup` beside every such assignment."""
    if str(_HERE) not in sys.path:
        sys.path.insert(0, str(_HERE))
    import policy_checks
    return policy_checks


def _prov_module():
    if str(_HERE) not in sys.path:
        sys.path.insert(0, str(_HERE))
    import amap_sandy
    return amap_sandy


ifp = _load()

_POLICY = {
    "version": 1, "sandboxes": {"include": ["*"], "exclude": ["*redteam*"]},
    "agents": {"include": ["claude"], "exclude": []},
    "groups": {}, "default_peers": [], "peers": {},
    # Required: `install` refuses a policy that omits it, because writing it
    # in IS the operator's ratification of the recreation cadence. Every
    # fixture here carries it for the same reason every real policy must.
    "container_recreate_interval_hours": 24,
}


# The same policy with nothing excluded: a DIFFERENT installed file, so a
# run against `_POLICY` is a real change and not a no-op.
_VARIANT = {**_POLICY, "sandboxes": {"include": ["*"], "exclude": []}}


def _box(slug, workspace_path):
    return {"name": slug, "path": f"/boxes/{slug}", "workspace_path": workspace_path}


class SelectionReportTest(unittest.TestCase):
    """The preview is the candidate's RULE beside sandy's CURRENT verdicts —
    never a prediction. One matcher, sandy's; this tool prints what it will
    render and what sandy last decided."""

    def test_the_rule_and_the_verdicts_are_both_printed(self):
        boxes = [_box("alice", "/ws/dev/alice"), _box("bob", "/ws/other/bob")]
        states = {"alice": ("selected", "at 2026-09-18T18:28:47Z"),
                  "bob": ("not selected", "excluded by *bob*")}
        out = ifp.selection_report(_POLICY, boxes, states)
        self.assertIn("include ['*'], exclude ['*redteam*']", out)
        self.assertIn("include ['claude'], exclude []", out)
        self.assertIn("alice: selected — at 2026-09-18T18:28:47Z", out)
        self.assertIn("bob: not selected — excluded by *bob*", out)
        self.assertIn("next launch re-decides", out)

    def test_a_sandbox_with_no_verdict_is_unknown_never_predicted(self):
        out = ifp.selection_report(_POLICY, [_box("carol", "/w/carol")], {})
        self.assertIn("carol: unknown", out)
        self.assertNotIn("would", out)


class CheckResolvePeersTest(unittest.TestCase):
    """`load_policy` accepts a `peers` key naming an instance that is not
    selected (it is a shape check only); the router-config render refuses it
    via `resolve_peers`. The write path runs the SAME check, so the refusal
    arrives before anything is written rather than at the render."""

    def _prov(self, enrolled_record):
        prov = _prov_module()
        self.addCleanup(setattr, prov, "load_membership", prov.load_membership)
        prov.load_membership = staticmethod(lambda home, boxes: enrolled_record)
        return prov

    def test_a_peer_naming_an_unenrolled_instance_is_refused(self):
        policy = {**_POLICY, "peers": {"nobody-enrolled": []}}
        prov = self._prov({})  # nothing enrolled at all
        with self.assertRaises(fp.PolicyError) as ctx:
            ifp.check_resolve_peers(policy, {}, prov)
        self.assertIn("nobody-enrolled", str(ctx.exception))

    def test_a_known_good_policy_is_not_refused(self):
        """A known-good policy must NOT trip this — a false positive here
        would gate every `--apply` for no reason. `_POLICY`'s `peers`/`groups` are both empty, exactly the
        shape a policy with nothing scoped yet has."""
        prov = self._prov({"alice": {"instance_name": "alice"}})
        ifp.check_resolve_peers(_POLICY, {"alice": {"instance_name": "alice"}}, prov)  # does not raise

class ProjectedMembershipTest(unittest.TestCase):
    """The checks run BEFORE the launches at which sandy evaluates the
    candidate's rule, so on a fresh fleet nothing is selected yet and a
    `peers` key naming a real sandbox would be refused for no reason. The
    projection is every sandbox sandy reports — and a name sandy does not
    report at all is still a ghost."""

    # A deployed policy's shape, loaded through `load_policy` from a file:
    # a tasking fleet (task_graph ALL, no mail edges), as a live host has it.
    HOST_POLICY = {**_POLICY, "task_graph": "ALL", "task_deny": [],
                   "fleet_domain": "agents.example.org"}
    FLEET = ["alpha-11111111", "bravo-22222222", "charlie-33333333"]

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.REAL = Path(tmp.name) / "feature.json"
        self.REAL.write_text(json.dumps(self.HOST_POLICY))

    def _fleet(self):
        return [{"name": s, "workspace_path": f"/ws/{s}"} for s in self.FLEET]

    def _check(self, policy, membership, boxes=None):
        checks = _load()
        projected = checks.projected_membership(membership, self._fleet() if boxes is None else boxes)
        checks.check_resolve_peers(policy, projected, _prov_module())

    def test_the_real_policy_installs_on_a_completely_empty_fleet(self):
        """THE regression. Nothing selected, nothing reported, a deployed
        policy, must not raise."""
        self._check(fp.load_policy(self.REAL), {}, boxes=[])

    def test_the_real_policy_installs_when_reported_but_not_yet_selected(self):
        self._check(fp.load_policy(self.REAL), {})

    def test_the_real_policy_still_installs_when_fully_selected(self):
        self._check(fp.load_policy(self.REAL), {s: {} for s in self.FLEET})

    def test_a_peers_key_sandy_does_not_report_is_still_refused(self):
        policy = dict(fp.load_policy(self.REAL))
        policy["peers"] = {**policy["peers"], "ghost-instance-9999": []}
        with self.assertRaises(fp.PolicyError) as ctx:
            self._check(policy, {})
        self.assertIn("ghost-instance-9999", str(ctx.exception))

    def test_a_group_member_sandy_does_not_report_is_still_refused(self):
        policy = dict(fp.load_policy(self.REAL))
        policy["groups"] = {**policy["groups"], "team": self.FLEET[:2] + ["ghost-member-9999"]}
        with self.assertRaises(fp.PolicyError) as ctx:
            self._check(policy, {})
        self.assertIn("ghost-member-9999", str(ctx.exception))

    def test_projection_does_not_overwrite_an_existing_record(self):
        checks = _load()
        membership = {"delta_lab-44444444": {"selected_at": "2000-01-01T00:00:00Z"}}
        projected = checks.projected_membership(
            membership, [{"name": "delta_lab-44444444"}, {"name": "brand-new-slug"}])
        self.assertEqual(projected["delta_lab-44444444"], {"selected_at": "2000-01-01T00:00:00Z"})
        self.assertEqual(projected["brand-new-slug"], {})
