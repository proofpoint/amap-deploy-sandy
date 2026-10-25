"""First-upgrade stdlib evidence and stale-input refusal, without lifecycle."""
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import codex_bootstrap_pause as bootstrap


@unittest.skipUnless(sys.version_info >= (3, 11), "native configuration requires Python 3.11")
class BootstrapPauseTest(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory(prefix=".bp-", dir=HERE)
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.policy = self.root / "operator-instructions.md"
        self.mcp = self.root / "mcp.toml"
        self.policy.write_text("protected operator policy")
        self.mcp.write_text("protected tools")
        import json
        self.raw = ('state_dir = '+json.dumps(str(self.state))+'\noperator_instructions = '+json.dumps(str(self.policy))+
                    '\ntrusted_config_file = '+json.dumps(str(self.mcp))+'\n').encode()
        (self.state / "controller.toml").write_bytes(self.raw)

    def test_dry_run_writes_nothing_and_repeated_pause_preserves_evidence(self):
        before = set(self.state.iterdir())
        bootstrap.pause(self.state, "maintenance")
        self.assertEqual(set(self.state.iterdir()), before)
        bootstrap.pause(self.state, "maintenance", apply=True)
        record = bootstrap.verify(self.state)
        self.assertEqual((self.state / record["snapshot"]).read_bytes(), self.raw)
        files = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.state.rglob("*") if p.is_file()}
        bootstrap.pause(self.state, "maintenance", apply=True)
        self.assertEqual(files, {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.state.rglob("*") if p.is_file()})

    def test_changed_controller_or_original_protected_bytes_refuse(self):
        bootstrap.pause(self.state, "maintenance", apply=True)
        self.policy.write_text("changed policy")
        with self.assertRaisesRegex(ValueError, "inputs changed"):
            bootstrap.verify(self.state)
        self.policy.write_text("protected operator policy")
        (self.state / "controller.toml").write_bytes(self.raw+b'instance_id = "different"\n')
        with self.assertRaisesRegex(ValueError, "inputs changed"):
            bootstrap.verify(self.state)

    def test_history_symlink_refuses_without_writing_its_target(self):
        other = self.root / "other"
        other.mkdir()
        (self.state / "controller-history").symlink_to(other, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "parent is not a real directory"):
            bootstrap.pause(self.state, "maintenance", apply=True)
        self.assertEqual(list(other.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
