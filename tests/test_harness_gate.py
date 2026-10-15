"""harness_gate: the full-run gate record's one shape and its checks G1-G7.
The healthy record is the design's example with real-length values; every
refusal row breaks it one way and requires the gate that names that thing.
The refusal rows pin a small mutant list for themselves and restore the
module after; RealPinTest judges records against the module's own pinned
list, untouched."""

import copy
import hashlib
import json
import unittest

import harness_gate as hg

RL = "1" * 40
HOP = "2" * 40
PLUGIN = "3" * 64
IDS = ["m01", "m02", "m03"]
#: The harness's frozen mutant list for the deploy's gate run, as relayed.
FROZEN_IDS = ("A2-drop-wrapper A3-no-registry A3-precreate-state A4-no-first-sight A6-write-during-read "
              "A7-old-target A8-control-on-null A8-widened M1 M10 M11 M12 M12b M12c M13 M14 M15a M15b M16 "
              "M17a M17b M17c M17d M17e M2 M20 M21 M26-carry-clock M27 M3 M4 M4b M6 M7 M8 RT-double-send "
              "RT-drop-send RT-wrong-tree").split()
#: Stand-ins for the record's schema and unit values, which the module pins by
#: hash alone; the tests pin these the same way.
SCHEMA = "example.gate/1"
UNIT = "EXAMPLE-UNIT"


def healthy():
    return {
        "schema": SCHEMA, "unit": UNIT,
        "harness_sha": "4" * 40, "rl_sha": RL, "hop_sha": HOP, "hop_plugin_api": [3, 0],
        "hop_artifact_sha256": PLUGIN, "rl_registry_fixture_sha256": "5" * 64,
        "s5r4": {"commit": "6" * 40, "profile_sha256": "7" * 64},
        "exit_status": 0, "verdict": "PASS",
        "cases_expected": {"count": hg.CASE_COUNT, "set_sha256": hg.CASES_SET_SHA256},
        "cases_seen": {"count": hg.CASE_COUNT, "set_sha256": hg.CASES_SET_SHA256},
        "case_outcomes": {"pass": hg.CASE_COUNT - 2, "declared_difference": 1, "spec_question": 1},
        "mutants_expected": {"count": len(IDS), "ids": list(IDS)},
        "mutants": [{"id": i, "outcome": "killed", "by": "verdict"} for i in IDS],
        "synthetic_expected": ["S1", "S2", "S3"],
        "synthetic": {s: {"verdict": "pass", "sender_never_installed": True} for s in ("S1", "S2", "S3")},
        "o1": "holds", "o2": {"total": 0, "hold": 0, "accepted": 0}, "o3_placed": 0,
        "inbound_mode": "delegation.inbound",
        "profiles": {"cases": "conformance", "config_cases": "production_startup", "o2_points": "production"},
        "overrides": [], "results_sha256": "8" * 64}


def raw_of(r):
    return hg.canonical(r)


class GateTest(unittest.TestCase):
    def setUp(self):
        for name, value in (("MUTANT_IDS_SHA256", hg.set_sha256(IDS)), ("MUTANT_COUNT", len(IDS)),
                            ("SCHEMA_SHA256", hashlib.sha256(SCHEMA.encode()).hexdigest()),
                            ("UNIT_SHA256", hashlib.sha256(UNIT.encode()).hexdigest())):
            self.addCleanup(setattr, hg, name, getattr(hg, name))
            setattr(hg, name, value)

    def check(self, r=None, raw=None, **over):
        raw = raw if raw is not None else raw_of(r if r is not None else healthy())
        args = dict(record_sha256=hashlib.sha256(raw).hexdigest(), rl_sha=RL, hop_sha=HOP, plugin_sha256=PLUGIN)
        args.update(over)
        return hg.problems(raw, **args)

    def gates(self, r=None, **over):
        return sorted({g for g, _ in self.check(r, **over)})

    def broken(self, edit):
        r = healthy()
        edit(r)
        return r

    def test_the_healthy_record_passes_every_gate_at_once(self):
        self.assertEqual(self.check(), [])

    def test_the_healthy_record_is_its_own_canonical_form_with_the_shapes_members(self):
        r = healthy()
        self.assertEqual(set(r), hg.RECORD_MEMBERS)
        self.assertEqual(hg.parse(raw_of(r)), r)

    # G1
    def test_bytes_that_do_not_hash_to_the_overlays_sha256_refuse(self):
        self.assertEqual(self.gates(record_sha256="0" * 64), ["G1"])

    def test_a_non_canonical_record_refuses(self):
        raw = json.dumps(healthy(), indent=1).encode()
        self.assertIn("G1", {g for g, _ in self.check(raw=raw)})

    def test_an_old_shape_record_refuses(self):
        for edit in (lambda r: r.update(cases={"total": 112, "blocking": 0}),
                     lambda r: r.update(mutants={"total": 3, "red": 3, "survived": 0}),
                     lambda r: r.update(synthetic={"S1": "pass", "S2": "pass", "S3": "pass"})):
            with self.subTest():
                self.assertEqual(self.gates(self.broken(edit)), ["G1"])

    def test_a_missing_member_or_a_wrong_type_refuses(self):
        self.assertEqual(self.gates(self.broken(lambda r: r.pop("o2"))), ["G1"])
        self.assertEqual(self.gates(self.broken(lambda r: r.update(exit_status="0"))), ["G1"])
        self.assertEqual(self.gates(self.broken(lambda r: r.update(rl_sha=RL[:-1]))), ["G1"])

    def test_another_schema_or_unit_refuses(self):
        self.assertEqual(self.gates(self.broken(lambda r: r.update(schema="x/1"))), ["G1"])
        self.assertEqual(self.gates(self.broken(lambda r: r.update(unit="OTHER"))), ["G1"])

    def test_duplicate_keys_refuse(self):
        raw = raw_of(healthy())
        raw = raw[:-1] + b',"o1":"holds"}'
        self.assertEqual({g for g, _ in self.check(raw=raw)}, {"G1"})

    # G2
    def test_a_failing_run_refuses(self):
        self.assertEqual(self.gates(self.broken(lambda r: r.update(exit_status=2))), ["G2"])
        self.assertEqual(self.gates(self.broken(lambda r: r.update(verdict="FAIL"))), ["G2"])

    # G3
    def test_a_record_for_another_local_router_commit_hop_pin_or_plugin_refuses(self):
        self.assertEqual(self.gates(rl_sha="9" * 40), ["G3"])
        self.assertEqual(self.gates(hop_sha="9" * 40), ["G3"])
        self.assertEqual(self.gates(plugin_sha256="9" * 64), ["G3"])

    # G4
    def test_another_inbound_mode_or_the_override_refuses(self):
        self.assertEqual(self.gates(self.broken(lambda r: r.update(inbound_mode="build_constant"))), ["G4"])
        self.assertEqual(self.gates(self.broken(lambda r: r.update(overrides=["INBOUND_AVAILABLE=1"]))), ["G4"])

    # G5
    def test_a_zero_case_pass_refuses(self):
        def edit(r):
            r["cases_expected"] = r["cases_seen"] = {"count": 0, "set_sha256": hg.set_sha256([])}
            r["case_outcomes"] = {}
        self.assertEqual(self.gates(self.broken(edit)), ["G5"])

    def test_a_self_consistent_record_with_another_112_case_set_refuses(self):
        def edit(r):
            r["cases_expected"] = r["cases_seen"] = {"count": hg.CASE_COUNT, "set_sha256": "a" * 64}
        why = self.check(self.broken(edit))
        self.assertEqual(why, [("G5", "the expected cases are not the pinned set")])

    def test_a_missing_or_skipped_case_refuses(self):
        def edit(r):
            r["cases_seen"] = {"count": hg.CASE_COUNT - 1, "set_sha256": "b" * 64}
            r["case_outcomes"]["pass"] -= 1
        self.assertEqual(self.gates(self.broken(edit)), ["G5"])

    def test_outcomes_that_do_not_sum_to_the_count_refuse(self):
        self.assertEqual(self.gates(self.broken(lambda r: r["case_outcomes"].update(spec_question=2))), ["G5"])

    def test_each_blocking_kind_refuses(self):
        for kind in hg.BLOCKING_KINDS:
            with self.subTest(kind=kind):
                def edit(r, kind=kind):
                    r["case_outcomes"]["pass"] -= 1
                    r["case_outcomes"][kind] = 1
                self.assertEqual(self.gates(self.broken(edit)), ["G5"])

    def test_an_outcome_kind_outside_the_vocabulary_refuses(self):
        for kind in ("skipped", "stale"):
            with self.subTest(kind=kind):
                def edit(r, kind=kind):
                    r["case_outcomes"]["pass"] -= 1
                    r["case_outcomes"][kind] = 1
                why = self.check(self.broken(edit))
                self.assertEqual(why, [("G5", f"outcome kinds outside the vocabulary: {kind}")])

    # G6
    def test_no_pinned_mutant_list_refuses_even_a_healthy_record(self):
        hg.MUTANT_IDS_SHA256 = None
        why = self.check()
        self.assertEqual(why, [("G6", "no mutant list is pinned yet: the harness's design has not frozen it")])

    def test_a_mutant_pin_of_zero_refuses(self):
        hg.MUTANT_IDS_SHA256, hg.MUTANT_COUNT = hg.set_sha256([]), 0
        def edit(r):
            r["mutants_expected"] = {"count": 0, "ids": []}
            r["mutants"] = []
        why = self.check(self.broken(edit))
        self.assertEqual(why, [("G6", "no mutant list is pinned yet: the harness's design has not frozen it")])

    def test_the_module_ships_with_the_frozen_list_pinned(self):
        """Read from the source, since this class pins a list for its own tests."""
        import ast
        with open(hg.__file__, encoding="utf-8") as f:
            tree = ast.parse(f.read())
        pinned = {n.target.id: n.value.value for n in tree.body if isinstance(n, ast.AnnAssign)
                  and isinstance(n.value, ast.Constant)}
        self.assertEqual((pinned["MUTANT_IDS_SHA256"], pinned["MUTANT_COUNT"]),
                         (hg.set_sha256(FROZEN_IDS), len(FROZEN_IDS)))
        self.assertEqual(len(FROZEN_IDS), len(set(FROZEN_IDS)))

    def test_the_module_ships_with_the_deploy_runs_unit_pinned(self):
        """The unit is pinned by its sha256 alone: the record's unit names
        are not written in this repository."""
        import ast
        with open(hg.__file__, encoding="utf-8") as f:
            tree = ast.parse(f.read())
        pinned = {n.targets[0].id: n.value.value for n in tree.body if isinstance(n, ast.Assign)
                  and isinstance(n.value, ast.Constant) and isinstance(n.targets[0], ast.Name)}
        self.assertEqual(pinned["UNIT_SHA256"], "0b576199029d7b0d5bc6c156ab5ef62dd57f95fa431c9e4c9c7607f41b5bcc53")
        self.assertNotEqual(pinned["UNIT_SHA256"], "6310dd4912a80935203600f1d24922f49744b9324b494c6310b12479608995d5",
                            "not the earlier unit's")

    def test_a_self_consistent_record_with_other_mutant_ids_refuses(self):
        def edit(r):
            r["mutants_expected"] = {"count": 3, "ids": ["x1", "x2", "x3"]}
            r["mutants"] = [{"id": i, "outcome": "killed", "by": "verdict"} for i in ("x1", "x2", "x3")]
        self.assertEqual(self.check(self.broken(edit)), [("G6", "the expected mutants are not the pinned list")])

    def test_zero_or_incomplete_mutants_refuse(self):
        self.assertEqual(self.gates(self.broken(lambda r: r.update(mutants=[]))), ["G6"])
        self.assertEqual(self.gates(self.broken(lambda r: r["mutants"].pop())), ["G6"])

    def test_a_not_run_or_survived_mutant_refuses(self):
        for outcome in ("not_run", "survived"):
            with self.subTest(outcome=outcome):
                self.assertEqual(self.gates(self.broken(lambda r: r["mutants"][0].update(outcome=outcome))),
                                 ["G6"])

    def test_a_duplicate_mutant_refuses(self):
        self.assertEqual(self.gates(self.broken(lambda r: r["mutants"].append(dict(r["mutants"][0])))), ["G6"])

    def test_an_outcome_outside_the_vocabulary_refuses(self):
        why = self.check(self.broken(lambda r: r["mutants"][0].update(outcome="errored")))
        self.assertEqual(why, [("G6", "mutant m01's outcome 'errored' is outside the vocabulary")])

    # G7
    def test_empty_or_missing_synthetics_refuse(self):
        self.assertEqual(self.gates(self.broken(lambda r: r.update(synthetic={}))), ["G7"])
        self.assertEqual(self.gates(self.broken(lambda r: r["synthetic"].pop("S3"))), ["G7"])
        self.assertEqual(self.gates(self.broken(lambda r: r.update(synthetic_expected=[]))), ["G7"])

    def test_a_failing_synthetic_or_an_installed_sender_refuses(self):
        self.assertEqual(self.gates(self.broken(lambda r: r["synthetic"]["S2"].update(verdict="fail"))), ["G7"])
        self.assertEqual(self.gates(self.broken(lambda r: r["synthetic"]["S1"].update(sender_never_installed=False))),
                         ["G7"])


class PinsTest(unittest.TestCase):
    def test_the_case_set_pin_is_the_harnesss_value(self):
        self.assertEqual((hg.CASE_COUNT, hg.CASES_SET_SHA256),
                         (112, "10e1401b725739d050686d92bb6e642cb4d85dc0e61c898e451e6fe565576f43"))

    def test_the_set_hash_is_over_the_sorted_ids_joined_by_newline(self):
        self.assertEqual(hg.set_sha256(["b", "a"]), hashlib.sha256(b"a\nb").hexdigest())

    def test_the_vocabulary_is_the_harness_gates_ten_kinds(self):
        self.assertEqual(set(hg.BLOCKING_KINDS),
                         {"pending", "overlay_pending", "fail", "fail_stale_label", "known_erratum_unratified"})
        self.assertEqual(hg.OUTCOME_KINDS - set(hg.BLOCKING_KINDS),
                         {"pass", "overlay_mapped", "known_erratum", "declared_difference", "spec_question"})



class RealPinTest(unittest.TestCase):
    """G6 against the module's OWN mutant pins, which nothing here patches.
    Only the schema and unit hashes are pinned to the test record's
    stand-ins, as GateTest does; G1-G5 and G7 are not under test here."""

    def setUp(self):
        for name, value in (("SCHEMA_SHA256", hashlib.sha256(SCHEMA.encode()).hexdigest()),
                            ("UNIT_SHA256", hashlib.sha256(UNIT.encode()).hexdigest())):
            self.addCleanup(setattr, hg, name, getattr(hg, name))
            setattr(hg, name, value)

    def g6(self, expected, judged=None):
        r = healthy()
        judged = list(expected) if judged is None else judged
        r["mutants_expected"] = {"count": len(expected), "ids": list(expected)}
        r["mutants"] = [{"id": i, "outcome": "killed", "by": "verdict"} for i in judged]
        raw = raw_of(r)
        return [why for gate, why in hg.problems(raw, record_sha256=hashlib.sha256(raw).hexdigest(), rl_sha=RL,
                                                 hop_sha=HOP, plugin_sha256=PLUGIN) if gate == "G6"]

    def test_the_frozen_list_all_killed_holds(self):
        self.assertEqual(self.g6(FROZEN_IDS), [])

    def test_any_other_list_is_not_the_pin(self):
        historical = [i for i in FROZEN_IDS if not i.startswith("RT-")]
        renamed = FROZEN_IDS[:-1] + ["RT-wrong-tree2"]
        for name, ids in (("one dropped", FROZEN_IDS[:-1]), ("the earlier 35", historical),
                          ("one renamed", renamed)):
            with self.subTest(name=name):
                self.assertEqual(self.g6(ids), ["the expected mutants are not the pinned list"])

    def test_the_frozen_list_with_a_mutant_not_judged_refuses(self):
        self.assertTrue(self.g6(FROZEN_IDS, judged=FROZEN_IDS[:-1]))


if __name__ == "__main__":
    unittest.main()
