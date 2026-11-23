"""W8 carries one DS-owned fix, for DS's review: <STAGE>.NOT_RESTORED exiting 3 (contract
4.2). Agents unique per (vm, id) (E9) is W7's, with DS's tests/test_a2_agents_unique.py."""

import unittest

import a2fix  # noqa: F401 - puts install/ on sys.path
from a2_causes import Refusal


class NotRestoredExitTest(unittest.TestCase):
    def test_not_restored_exits_3_for_any_stage(self):
        """A writing stage's NOT_RESTORED exits 3 and names it at the raise site (a2_causes.AFTER_WRITE_ONLY)."""
        for stage in ("AGENTS",):
            with self.subTest(stage=stage):
                self.assertEqual(Refusal(stage + ".NOT_RESTORED", rc=3).rc, 3)
                with self.assertRaises(ValueError):
                    Refusal(stage + ".NOT_RESTORED")

    def test_a_stage_that_never_writes_has_no_not_restored(self):
        """CREDENTIALS and PREFLIGHT write nothing, so they cannot fail to restore: NOT_RESTORED cannot be built for
        them, with or without rc=3 (ruling W13-W8-NOT-RESTORED A)."""
        for stage in ("CREDENTIALS", "PREFLIGHT"):
            for rc in (None, 3):
                with self.subTest(stage=stage, rc=rc), self.assertRaises(ValueError):
                    Refusal(stage + ".NOT_RESTORED", rc=rc)


if __name__ == "__main__":
    unittest.main()
