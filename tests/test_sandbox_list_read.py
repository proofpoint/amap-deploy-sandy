"""One `--print-state` read per verb: the workspace map and the shared read."""
import unittest
from pathlib import Path

import amap_sandy as prov


class WorkspacesOfTest(unittest.TestCase):
    def test_the_map_names_every_sandbox_sandy_reports_a_workspace_for(self):
        boxes = [{"name": "alpha-1", "path": "/s/a", "workspace_path": "/ws/alpha"},
                 {"name": "bravo-2", "path": "/s/b", "workspace_path": ""},
                 {"name": "charlie-3", "path": "/s/c"},
                 {"name": "delta-4", "path": "/s/d", "workspace_path": "/ws/delta"}]
        self.assertEqual(prov.workspaces_of(boxes),
                         {"alpha-1": Path("/ws/alpha"), "delta-4": Path("/ws/delta")})


class ReadOnceTest(unittest.TestCase):
    def test_one_read_serves_every_caller_with_its_own_copy(self):
        reads = []
        once = prov.ReadOnce(lambda: reads.append(1) or [{"name": "alpha-1", "agents": ["claude"]}])
        first = once()
        first[0]["agents"].append("mutated")
        self.assertEqual(once(), [{"name": "alpha-1", "agents": ["claude"]}])
        self.assertEqual(len(reads), 1)

    def test_a_failed_read_fails_every_caller_without_asking_again(self):
        reads = []

        def read():
            reads.append(1)
            raise prov.ProvisionError("did not answer")

        once = prov.ReadOnce(read)
        for _ in range(2):
            with self.assertRaisesRegex(prov.ProvisionError, "did not answer"):
                once()
        self.assertEqual(len(reads), 1)


if __name__ == "__main__":
    unittest.main()
