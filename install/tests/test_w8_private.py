"""W8 carries one DS-owned fix, for DS's review: <STAGE>.NOT_RESTORED exiting 3 (contract
4.2). Agents unique per (vm, id) (E9) is W7's, with DS's tests/test_a2_agents_unique.py."""

import unittest

import a2fix  # noqa: F401 - puts install/ on sys.path
from a2_causes import Refusal


class NotRestoredExitTest(unittest.TestCase):
    def test_not_restored_exits_3_for_any_stage(self):
        for stage in ("AGENTS", "CREDENTIALS", "PREFLIGHT"):
            with self.subTest(stage=stage):
                self.assertEqual(Refusal(stage + ".NOT_RESTORED").rc, 3)


if __name__ == "__main__":
    unittest.main()
