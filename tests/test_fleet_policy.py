"""tests/test_fleet_policy.py — the peer-policy schema, groups/@all/ALLOW_ANY
expansion, the selection rule's shape, and the mutuality report.

The property under test throughout is that a policy file that PARSES but is
semantically wrong (an unknown group, a dangling peer, ALLOW_ANY mixed with
names) is refused loudly at load or resolve time, never silently
reinterpreted — see `fleet_policy.py`'s module docstring for why each of
these is a hard error rather than a guess.
"""
import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import fleet_policy as fp


class DefaultPolicyTest(unittest.TestCase):
    def test_missing_file_is_marked_default(self):
        with TemporaryDirectory() as d:
            policy = fp.load_policy(Path(d) / "feature.json")
        self.assertEqual(policy.get(fp.SOURCE_KEY), fp.SOURCE_DEFAULT)

    def test_the_default_selection_is_everyone_launched_with_claude(self):
        """What an ABSENT policy means: every sandbox, launched with claude,
        nothing excluded. A fresh copy each call, so a caller's edit cannot
        leak into the next default."""
        d = fp.default_policy()
        self.assertEqual(d[fp.SANDBOXES_KEY], {"include": ["*"], "exclude": []})
        self.assertEqual(d[fp.AGENTS_KEY], {"include": ["claude"], "exclude": []})
        d[fp.SANDBOXES_KEY]["include"].append("x")
        self.assertEqual(fp.default_policy()[fp.SANDBOXES_KEY]["include"], ["*"])

    def test_default_policy_resolves_to_full_mesh(self):
        names = {"alice", "bob", "carol"}
        resolved = fp.resolve_peers(fp.default_policy(), names)
        self.assertEqual(resolved["alice"], ["bob", "carol"])
        self.assertEqual(resolved["bob"], ["alice", "carol"])
        self.assertEqual(resolved["carol"], ["alice", "bob"])

class LoadPolicyValidationTest(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "feature.json"

    def _write(self, doc):
        self.path.write_text(json.dumps(doc))

    def test_malformed_json_fails_loud(self):
        self.path.write_text("{not json")
        with self.assertRaises(fp.PolicyError) as cm:
            fp.load_policy(self.path)
        self.assertIn("not valid JSON", str(cm.exception))

    def test_unsupported_version_fails_loud(self):
        self._write({"version": 2})
        with self.assertRaises(fp.PolicyError) as cm:
            fp.load_policy(self.path)
        self.assertIn("version", str(cm.exception))

    def test_groups_named_all_is_reserved(self):
        self._write({"groups": {"all": ["alice"]}})
        with self.assertRaises(fp.PolicyError) as cm:
            fp.load_policy(self.path)
        self.assertIn("reserved", str(cm.exception))

    def test_group_nesting_is_refused(self):
        self._write({"groups": {"amp": ["@other"]}})
        with self.assertRaises(fp.PolicyError) as cm:
            fp.load_policy(self.path)
        self.assertIn("do not nest", str(cm.exception))

    def test_allow_any_inside_a_group_is_refused(self):
        self._write({"groups": {"amp": ["ALLOW_ANY"]}})
        with self.assertRaises(fp.PolicyError) as cm:
            fp.load_policy(self.path)
        self.assertIn("ALLOW_ANY", str(cm.exception))

    def test_allow_any_mixed_with_names_is_refused_in_peers(self):
        """THE recorded decision (module docstring): mixing is a hard
        error, not a silent pick of one interpretation over the other."""
        self._write({"peers": {"alice": ["ALLOW_ANY", "bob"]}})
        with self.assertRaises(fp.PolicyError) as cm:
            fp.load_policy(self.path)
        self.assertIn("cannot be mixed", str(cm.exception))

    def test_allow_any_mixed_in_default_peers_is_refused(self):
        self._write({"default_peers": ["ALLOW_ANY", "bob"]})
        with self.assertRaises(fp.PolicyError):
            fp.load_policy(self.path)

    def test_allow_any_alone_is_fine(self):
        self._write({"peers": {"hub": ["ALLOW_ANY"]}})
        policy = fp.load_policy(self.path)
        self.assertEqual(policy["peers"]["hub"], ["ALLOW_ANY"])

    def test_unknown_group_reference_fails_loud(self):
        self._write({"peers": {"alice": ["@nosuch"]}})
        with self.assertRaises(fp.PolicyError) as cm:
            fp.load_policy(self.path)
        self.assertIn("references no group", str(cm.exception))

    def test_at_all_is_always_a_valid_reference(self):
        self._write({"default_peers": ["@all"]})
        policy = fp.load_policy(self.path)
        self.assertEqual(policy["default_peers"], ["@all"])

    def test_selection_lists_must_be_string_lists(self):
        for bad in ({"sandboxes": {"include": [1, 2]}},
                    {"agents": {"exclude": "codex"}},
                    {"sandboxes": ["*"]}):
            with self.subTest(bad=bad):
                self._write(bad)
                with self.assertRaises(fp.PolicyError):
                    fp.load_policy(self.path)

    def test_an_unknown_selection_key_is_refused_like_sandy_would(self):
        """Sandy's manifest reader refuses `<block>: unknown key`, so the
        policy refuses it first, naming the two keys that exist."""
        self._write({"sandboxes": {"include": ["*"], "only": ["x"]}})
        with self.assertRaises(fp.PolicyError) as cm:
            fp.load_policy(self.path)
        self.assertIn("unknown key", str(cm.exception))

    def test_a_broken_glob_is_refused_where_it_was_typed(self):
        """Sandy matches selection patterns as shell `case` patterns and
        refuses none: a broken one matches nothing and the sandbox lands in
        `not_selected` with a reason that reads as intentional. The two
        shapes nobody means are refused here, by name."""
        for bad in ("alpha-[abc", "alpha 1"):
            with self.subTest(pattern=bad):
                self._write({"sandboxes": {"include": [bad], "exclude": []}})
                with self.assertRaises(fp.PolicyError) as cm:
                    fp.load_policy(self.path)
                self.assertIn(repr(bad), str(cm.exception))
        # A pattern that is merely unusual is not refused: matching nothing
        # today may be intentional.
        self._write({"sandboxes": {"include": ["nothing-matches-this-*"], "exclude": []}})
        fp.load_policy(self.path)

    def test_an_empty_pattern_is_refused(self):
        self._write({"agents": {"include": [""]}})
        with self.assertRaises(fp.PolicyError) as cm:
            fp.load_policy(self.path)
        self.assertIn("empty pattern", str(cm.exception))


    def test_selection_defaults_when_absent_and_round_trips_when_present(self):
        self._write({"version": 1})
        policy = fp.load_policy(self.path)
        self.assertEqual(policy[fp.SANDBOXES_KEY], {"include": ["*"], "exclude": []})
        self.assertEqual(policy[fp.AGENTS_KEY], {"include": ["claude"], "exclude": []})
        self._write({"sandboxes": {"include": ["proj-*"], "exclude": ["*redteam*"]},
                     "agents": {"include": ["claude", "codex"]}})
        policy = fp.load_policy(self.path)
        self.assertEqual(policy[fp.SANDBOXES_KEY],
                         {"include": ["proj-*"], "exclude": ["*redteam*"]})
        self.assertEqual(policy[fp.AGENTS_KEY], {"include": ["claude", "codex"], "exclude": []})

    def test_round_trips_the_pinned_schema_example(self):
        """The exact schema from the module docstring, byte-for-byte, must
        load clean."""
        doc = {
            "version": 1,
            "sandboxes": {"include": ["*"], "exclude": ["*redteam*"]},
            "agents": {"include": ["claude"], "exclude": []},
            "groups": {"team": ["alpha-11111111", "bravo-22222222"]},
            "default_peers": [],
            "peers": {"alpha-11111111": ["@team", "charlie-33333333"],
                      "some-hub": ["ALLOW_ANY"]},
            "fleet_domain": "agents.example.org",
            "task_graph": {"bravo-22222222": ["alpha-11111111"]},
            "container_recreate_interval_hours": 24,
        }
        self._write(doc)
        policy = fp.load_policy(self.path)
        for key in doc:
            self.assertEqual(policy[key], doc[key])


class ResolvePeersTest(unittest.TestCase):
    def test_group_expansion(self):
        policy = {"groups": {"amp": ["alice", "bob"]}, "default_peers": [],
                  "peers": {"carol": ["@amp"]}}
        resolved = fp.resolve_peers(policy, {"alice", "bob", "carol"})
        self.assertEqual(resolved["carol"], ["alice", "bob"])

    def test_at_all_expands_to_every_enrolled_instance_minus_self(self):
        policy = {"default_peers": ["@all"], "peers": {}}
        resolved = fp.resolve_peers(policy, {"alice", "bob", "carol"})
        self.assertEqual(resolved["alice"], ["bob", "carol"])

    def test_self_reference_is_dropped(self):
        policy = {"default_peers": [], "peers": {"alice": ["alice", "bob"]}}
        resolved = fp.resolve_peers(policy, {"alice", "bob"})
        self.assertEqual(resolved["alice"], ["bob"])

    def test_sorted_and_deduped(self):
        policy = {"default_peers": [], "peers": {"alice": ["carol", "bob", "bob"]}}
        resolved = fp.resolve_peers(policy, {"alice", "bob", "carol"})
        self.assertEqual(resolved["alice"], ["bob", "carol"])

    def test_allow_any_passes_through_untouched(self):
        policy = {"default_peers": [], "peers": {"hub": ["ALLOW_ANY"]}}
        resolved = fp.resolve_peers(policy, {"hub", "alice"})
        self.assertEqual(resolved["hub"], ["ALLOW_ANY"])

    def test_peer_naming_an_unenrolled_instance_fails_loud(self):
        """The evaluator's own probe: a dangling peer must error, not
        silently render (which would silently block cold contact instead)."""
        policy = {"default_peers": [], "peers": {"alice": ["ghost"]}}
        with self.assertRaises(fp.PolicyError) as cm:
            fp.resolve_peers(policy, {"alice", "bob"})
        self.assertIn("ghost", str(cm.exception))
        self.assertIn("not a currently enrolled instance", str(cm.exception))

    def test_group_naming_an_unenrolled_instance_fails_loud(self):
        policy = {"groups": {"amp": ["alice", "ghost"]}, "default_peers": ["@amp"], "peers": {}}
        with self.assertRaises(fp.PolicyError) as cm:
            fp.resolve_peers(policy, {"alice", "bob"})
        self.assertIn("ghost", str(cm.exception))

    def test_instance_absent_from_peers_gets_top_level_default(self):
        policy = {"default_peers": ["bob"], "peers": {}}
        resolved = fp.resolve_peers(policy, {"alice", "bob"})
        self.assertEqual(resolved["alice"], ["bob"])

class OneSidedTest(unittest.TestCase):
    def test_detects_one_sided_pair_naming_both_sides(self):
        resolved = {"a": ["b"], "b": []}
        warnings = fp.one_sided(resolved)
        self.assertEqual(len(warnings), 1)
        self.assertIn("'a'", warnings[0])
        self.assertIn("'b'", warnings[0])
        self.assertIn("a -> b", warnings[0])

    def test_mutual_pair_has_no_warning(self):
        resolved = {"a": ["b"], "b": ["a"]}
        self.assertEqual(fp.one_sided(resolved), [])

    def test_never_auto_symmetrizes(self):
        """The generator must emit exactly what the policy declares — this
        function is read-only and must never mutate its input."""
        resolved = {"a": ["b"], "b": []}
        fp.one_sided(resolved)
        self.assertEqual(resolved["b"], [])

    def test_allow_any_declarer_is_not_reported_as_the_one_sided_side(self):
        """ALLOW_ANY expresses no specific pairwise intent, so it is
        skipped as the 'a' side — but a peer that lists ALLOW_ANY-declarer
        by name is still checked from ITS side."""
        resolved = {"a": ["ALLOW_ANY"], "b": ["c"], "c": []}
        warnings = fp.one_sided(resolved)
        self.assertTrue(any("'b'" in w and "'c'" in w for w in warnings))
        self.assertFalse(any(w.startswith("one-sided peer entry — 'a'") for w in warnings))

    def test_allow_any_recipient_satisfies_the_other_side(self):
        resolved = {"a": ["b"], "b": ["ALLOW_ANY"]}
        self.assertEqual(fp.one_sided(resolved), [])


class SelectionIsNeverEvaluatedHereTest(unittest.TestCase):
    """One matcher, and it is sandy's. This module carries the rule and
    renders it; it must never grow a second evaluator whose case-folding or
    path-matching could drift from the one that decides at launch."""

    def test_selection_returns_the_rule_as_a_copy(self):
        policy = fp.default_policy()
        sel = fp.selection(policy)
        sel[fp.SANDBOXES_KEY]["include"].append("x")
        self.assertEqual(policy[fp.SANDBOXES_KEY]["include"], ["*"])

    def test_no_glob_evaluation_here(self):
        source = Path(fp.__file__).read_text()
        self.assertNotIn("fnmatch", source, "no glob evaluation in this module")


if __name__ == "__main__":
    unittest.main()


class EvaluatorFindingsTests(unittest.TestCase):
    """Regressions for defects an independent evaluation of the policy
    loader found. Each looked right and was wrong, and several failed OPEN —
    granting more reach than the operator declared.
    """

    def test_stray_peers_key_fails_loud_finding_c(self):
        """A typo'd key left the instance on `default_peers`: the operator asked
        for isolation and silently got the full mesh. Fails open, so it must
        raise rather than warn."""
        with self.assertRaises(fp.PolicyError) as cm:
            fp.resolve_peers(
                {"version": 1, "default_peers": ["@all"],
                 "peers": {"alpha-1111111": []}},          # one '1' short
                ["alpha-11111111", "bravo-22222222"])
        self.assertIn("alpha-1111111", str(cm.exception))
        self.assertIn("not enrolled", str(cm.exception))

    def test_unknown_top_level_keys_survive_finding_d(self):
        """Anything `load_policy` dropped would be lost from the operator's
        file by whatever next writes the loaded policy back. JSON has no
        comments, so `_comment` keys are how an operator documents one."""
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "feature.json"
            path.write_text(json.dumps({
                "version": 1,
                "_comment": "why these are denied",
                "x-operator-note": {"nested": True},
                "sandboxes": {"include": ["*"], "exclude": ["*redteam*"]},
                "peers": {},
            }))
            pol = fp.load_policy(path)
        self.assertEqual(pol.get("_comment"), "why these are denied")
        self.assertEqual(pol.get("x-operator-note"), {"nested": True})


class AmapEnvTest(unittest.TestCase):
    """`amap_env` and the one router-not-found message builder."""

    def setUp(self):
        old = os.environ.get("AMAP_ROUTER_REPO")
        self.addCleanup(lambda: os.environ.__setitem__("AMAP_ROUTER_REPO", old)
                        if old is not None else os.environ.pop("AMAP_ROUTER_REPO", None))
        os.environ.pop("AMAP_ROUTER_REPO", None)

    def test_unset_is_none(self):
        self.assertIsNone(fp.amap_env("ROUTER_REPO"))
        self.assertEqual(fp.amap_env_named("ROUTER_REPO"), (None, None))

    def test_a_set_value_is_returned_with_its_name(self):
        os.environ["AMAP_ROUTER_REPO"] = "/somewhere"
        self.assertEqual(fp.amap_env_named("ROUTER_REPO"), ("AMAP_ROUTER_REPO", "/somewhere"))
        self.assertEqual(fp.amap_env("ROUTER_REPO"), "/somewhere")

    def test_an_empty_value_counts_as_unset(self):
        """`AMAP_ROUTER_REPO=` is how a profile disables an override. Honouring
        it would make `Path("")` the cwd — a wrong checkout, found silently."""
        os.environ["AMAP_ROUTER_REPO"] = ""
        self.assertIsNone(fp.amap_env("ROUTER_REPO"))

    def test_the_message_names_the_variable_and_the_path_it_set(self):
        os.environ["AMAP_ROUTER_REPO"] = "/wrong/path"
        msg = fp.router_not_found_message("router/reset.py")
        self.assertIn("AMAP_ROUTER_REPO", msg)
        self.assertIn("/wrong/path", msg)
        self.assertIn("router/reset.py", msg)
        self.assertIn("only checkout that was searched", msg)

    def test_with_nothing_set_the_message_names_the_variable_and_the_directory(self):
        msg = fp.router_not_found_message("router/reset.py")
        self.assertIn("$AMAP_ROUTER_REPO", msg)
        self.assertIn(fp.ROUTER_REPO_NAME, msg)
        self.assertEqual(fp.ROUTER_REPO_NAME, "amap-router-local")


