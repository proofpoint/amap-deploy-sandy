"""A green run that tested nothing must not be reportable as green.

The principle, borrowed from sandy's own integration suite:

    skipping is correct when nothing was intended, and a false green when
    something was — only the operator can say which.

The instance this repo has is the host-facts document's `not_enrolled`
field, below: a lookup that could not be made must not read as an empty
answer.
"""
import sys
from pathlib import Path
import os
import shutil
import unittest


if __name__ == "__main__":
    unittest.main()



class NotEnrolledIsDataAndAbsenceIsNotZeroTest(unittest.TestCase):
    """`not_enrolled` in the --host-facts document: `[]` and ABSENT are
    different answers, and the boundary must not blur them.

    The operator console renders an absent field as "unanswered" and an empty
    list as "none excluded". So a failed lookup that emitted `[]` would
    manufacture a clean bill of health — the same false green this module
    exists for, in a new place: a question that could not be asked reported as
    a question with a reassuring answer.
    """

    class _Ctx:
        """Minimal stand-in: `_f_not_enrolled` uses value() and fact().provenance.
        `home` is what `_f_sandy_home` reads; the stub never reaches it."""

        home = None

        def __init__(self, **values):
            self._v = values

        def value(self, key):
            # Derived facts resolve through FACT_SOURCES on the real Ctx; the
            # stub does the same for the one this class is about, so the test
            # exercises the real derivation rather than a value it planted.
            if key not in self._v:
                sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
                import router_health
                return router_health.FACT_SOURCES[key](self)[0]
            return self._v[key]

        def fact(self, key):
            class _F:
                provenance = f"stub:{key}"
            return _F()

    @staticmethod
    def _rh():
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        import router_health
        return router_health

    def _states(self):
        """Sandy's verdicts, as `selection_states` reports them: one member,
        one sandy kept out (with its reason), one with no verdict yet."""
        return {
            "keeper-1111": ("selected", "at 2026-09-18T18:28:47Z"),
            "redteam-2222": ("not selected", "excluded by *redteam*"),
            "pending-3333": ("unknown", "not launched since the manifest was written"),
        }

    def test_it_names_what_sandy_did_not_select_and_nothing_pending(self):
        """`not selected` is sandy's verdict and the excluded sense; a
        sandbox with NO verdict yet is pending, not excluded, and naming it
        here would tell the console it was kept out."""
        b = self._rh()
        got, provenance = b._f_not_enrolled(self._Ctx(selection_states=self._states()))
        self.assertEqual(got, ["redteam-2222"])
        self.assertIn("selection_states", provenance)

    def test_an_unresolvable_input_yields_Unresolved_not_an_empty_list(self):
        b = self._rh()
        got, _ = b._f_not_enrolled(
            self._Ctx(selection_states=b._unresolved("sandy has not written a verdict")))
        self.assertIsInstance(got, b.Unresolved)

    def test_the_document_OMITS_the_field_rather_than_emitting_empty(self):
        """The mutation that matters: emitting `[]` here reads as 'none
        excluded' on a page, off a lookup that failed."""
        b = self._rh()
        ctx = self._Ctx(selection_states=b._unresolved("no verdict file"))
        doc = b.host_facts_doc([], b.EXIT_OK, ctx)
        self.assertNotIn("not_enrolled", doc)

    def test_a_genuinely_empty_fleet_exclusion_IS_emitted_as_empty(self):
        """The inverse, so the omission above cannot be implemented as 'never
        emit it'. A check that can only ever be absent is not a check."""
        b = self._rh()
        ctx = self._Ctx(selection_states={"keeper-1111": ("selected", "at 2026-01-01")})
        doc = b.host_facts_doc([], b.EXIT_OK, ctx)
        self.assertIn("not_enrolled", doc)
        self.assertEqual(doc["not_enrolled"], [])
