"""The part of `router_health` another repository imports: the three-outcome
discipline, and nothing else.

amap-deploy-openshell loads `router_health` from a sibling amap-deploy-sandy
checkout. The names below, their parameters, and the behaviour that makes
them the discipline (UNKNOWN never rounds to PASS, an Unresolved equals
nothing, a non-passing Check owes a remedy) are what it may rely on. A change
to any of them fails here first, and is a word to that repository before it
is a commit here.

Everything else in the module is internal, including `Ctx`, `FACT_SOURCES`,
`WIRE_NAMES`, `run_sections` and the two router sections: their facts reach
this repo's sandy layout through `provisioner()`.
"""
from __future__ import annotations

import inspect
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import router_health as rh  # noqa: E402

SHARED_SIGNATURES = {
    "check": ["claim", "expected", "actual", "remedy", "do_not", "ok"],
    "unknown": ["claim", "expected", "reason", "remedy", "do_not"],
    "same_set": ["expected_seq", "actual_seq"],
    "Fact": ["name", "value", "provenance"],
    "Check": ["claim", "expected", "actual", "result", "remedy", "do_not"],
}


def _fact(value, name="x"):
    return rh.Fact(name, value, "a test's own derivation")


class SharedRouterHealthCoreTest(unittest.TestCase):

    def test_names_and_parameters(self):
        for name, params in SHARED_SIGNATURES.items():
            with self.subTest(name):
                obj = getattr(rh, name, None)
                self.assertTrue(callable(obj), f"router_health.{name} is gone")
                self.assertEqual(list(inspect.signature(obj).parameters), params)

    def test_the_three_verdicts(self):
        self.assertEqual((rh.PASS, rh.FAIL, rh.UNKNOWN), ("PASS", "FAIL", "UNKNOWN"))
        self.assertEqual((rh.Verdict.PASS, rh.Verdict.FAIL, rh.Verdict.UNKNOWN),
                         (rh.PASS, rh.FAIL, rh.UNKNOWN))
        self.assertTrue(issubclass(rh.CannotRun, Exception))

    def test_an_unresolved_equals_nothing_and_cannot_be_hashed(self):
        u = rh.Unresolved("why")
        self.assertEqual(u.reason, "why")
        self.assertFalse(u == u)
        self.assertFalse(u == None)  # noqa: E711
        with self.assertRaises(TypeError):
            hash(u)
        self.assertFalse(_fact(u).known)
        self.assertTrue(_fact(0).known)

    def test_check_is_three_valued_and_unknown_never_rounds_to_pass(self):
        self.assertEqual(rh.check("c", _fact(1), 1, "r").result, rh.PASS)
        self.assertEqual(rh.check("c", _fact(1), 2, "r").result, rh.FAIL)
        self.assertEqual(rh.check("c", _fact(1), rh.Unresolved("no"), "r").result, rh.UNKNOWN)
        self.assertEqual(rh.check("c", _fact(rh.Unresolved("no")), 1, "r").result, rh.UNKNOWN)
        self.assertEqual(rh.check("c", _fact(3), 5, "r", ok=lambda e, a: a > e).result, rh.PASS)
        u = rh.unknown("c", _fact(1), "could not ask", "r")
        self.assertEqual((u.result, u.reason), (rh.UNKNOWN, "could not ask"))

    def test_a_non_passing_check_owes_a_remedy_and_expected_must_be_a_fact(self):
        with self.assertRaises(ValueError):
            rh.check("c", _fact(1), 2, "  ")
        with self.assertRaises(TypeError):
            rh.Check("c", 1, 1, rh.PASS, "r")

    def test_same_set(self):
        self.assertTrue(rh.same_set(["a", "b"], ["b", "a"]))
        self.assertFalse(rh.same_set(["a"], ["a", "b"]))

    def test_importing_it_pulls_in_no_router_and_no_sandy_code(self):
        probe = ("import sys; sys.path.insert(0, sys.argv[1]); import router_health; "
                 "print(sorted(m for m in ('router', 'amap_sandy', 'fleet_policy') "
                 "if m in sys.modules))")
        r = subprocess.run([sys.executable, "-I", "-c", probe, str(HERE)],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "[]")


if __name__ == "__main__":
    unittest.main()
