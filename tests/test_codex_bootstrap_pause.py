"""First-upgrade stdlib evidence and stale-input refusal, without lifecycle."""
import os
import shlex
import shutil
import subprocess
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

    def test_verify_requires_capture_and_the_exact_pause_without_writes(self):
        with self.assertRaises(OSError):
            bootstrap.verify_pause(self.state, "maintenance")
        bootstrap.pause(self.state, "maintenance", apply=True)
        before = {p: p.read_bytes() for p in self.state.rglob("*") if p.is_file()}
        self.assertTrue(bootstrap.verify_pause(self.state, "maintenance")["verified"])
        with self.assertRaisesRegex(ValueError, "pause is absent or differs"):
            bootstrap.verify_pause(self.state, "other note")
        (self.state / "adapter-pause.json").unlink()
        with self.assertRaises(OSError):
            bootstrap.verify_pause(self.state, "maintenance")
        self.assertEqual({p: p.read_bytes() for p in self.state.rglob("*") if p.is_file()},
                         {p: raw for p, raw in before.items() if p.name != "adapter-pause.json"})

    def test_shipped_bootstrap_block_refuses_missing_empty_or_changed_source(self):
        tutorial = (HERE / "docs/TUTORIAL.md").read_text()
        start = tutorial.index("(\n  set -e\n  BOOTSTRAP_SHA256=")
        script = tutorial[start:tutorial.index("\n```", start)]
        script = script.replace("BOOTSTRAP_STATE=/opt/sandy/feature-state/amap/codex",
                                "BOOTSTRAP_STATE=" + shlex.quote(str(self.state)))
        source = self.root / "codex_bootstrap_pause.py"
        bindir = self.root / "bin"
        bindir.mkdir()
        sandy = bindir / "sandy"
        sandy.write_text('#!/bin/sh\nprintf invoked >> "$EXEC_CALLS"\nwhile [ "$1" != -- ]; do shift; done\nshift\nexec "$@"\n')
        sandy.chmod(0o755)
        calls = self.root / "exec-calls"
        env = {**os.environ, "PATH": str(bindir) + os.pathsep + os.environ["PATH"],
               "EXEC_CALLS": str(calls), "WORKSPACE": str(self.root)}
        for data in (None, b"", b"raise SystemExit(0)\n"):
            with self.subTest(source=data):
                if data is not None:
                    source.write_bytes(data)
                result = subprocess.run(["/bin/sh", "-c", script], cwd=self.root, env=env,
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(calls.exists(), "unverified source reached the exec boundary")
                self.assertFalse((self.state / bootstrap.RECORD).exists())
                self.assertFalse((self.state / "adapter-pause.json").exists())
        shutil.copyfile(HERE / "codex_bootstrap_pause.py", source)
        command = sandy.read_text()
        sandy.write_text(command.replace('exec "$@"', 'for arg do [ "$arg" != --apply ] || exit 0; done\nexec "$@"'))
        result = subprocess.run(["/bin/sh", "-c", script], cwd=self.root, env=env,
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0, "missing capture must fail the final verification")
        self.assertFalse((self.state / bootstrap.RECORD).exists())
        self.assertFalse((self.state / "adapter-pause.json").exists())
        calls.unlink()
        sandy.write_text(command)
        result = subprocess.run(["/bin/sh", "-c", script], cwd=self.root, env=env,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls.read_text(), "invoked" * 3)
        self.assertTrue(bootstrap.verify_pause(self.state, "Operator selected stopped-service maintenance")["verified"])

    def test_history_symlink_refuses_without_writing_its_target(self):
        other = self.root / "other"
        other.mkdir()
        (self.state / "controller-history").symlink_to(other, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "parent is not a real directory"):
            bootstrap.pause(self.state, "maintenance", apply=True)
        self.assertEqual(list(other.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
