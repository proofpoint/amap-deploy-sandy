"""Protected versions preserve original-path bytes across an interrupted upgrade."""
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import codex_assets as assets


class ProtectedAssetsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory(prefix=".codex-assets-test-", dir=HERE)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.payload = self.root / "payload"
        self.policy = self.root / "policy"
        self.mcp = self.root / "mcp"
        self.policy.write_bytes(b"first policy\n")
        self.mcp.write_bytes(b"first tool registry\n")

    def install(self, **kwargs):
        return assets.install(self.payload, self.policy, self.mcp, **kwargs)

    def selected(self):
        return json.loads((self.payload / assets.SELECTED_RECORD).read_bytes())

    def snapshot(self):
        return {str(p.relative_to(self.root)): (p.read_bytes(), p.stat().st_mtime_ns)
                for p in self.root.rglob("*") if p.is_file()}

    def test_dry_run_creates_nothing_and_apply_is_idempotent(self):
        before = self.snapshot()
        self.assertIn("would preserve", self.install())
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.payload.exists())
        self.install(dry_run=False)
        self.assertEqual(assets.findings(self.payload, self.policy, self.mcp), [])
        before = self.snapshot()
        directories = {str(p): p.stat().st_mtime_ns for p in self.root.rglob("*") if p.is_dir()}
        self.install(dry_run=False)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual({str(p): p.stat().st_mtime_ns for p in self.root.rglob("*") if p.is_dir()}, directories)

    def test_upgrade_keeps_original_paths_and_old_versions_byte_stable(self):
        self.install(dry_run=False)
        previous = self.selected()
        before = self.snapshot()
        self.policy.write_bytes(b"second policy\n")
        self.mcp.write_bytes(b"second tool registry\n")
        self.install(dry_run=False)
        current = self.selected()
        self.assertNotEqual(previous["version"], current["version"])
        for name in assets.ASSETS:
            self.assertEqual(self.snapshot()["payload/" + name], before["payload/" + name])
            retained = "payload/protected/" + previous["version"] + "/" + name
            self.assertEqual(self.snapshot()[retained], before[retained])
        self.assertEqual(assets.findings(self.payload, self.policy, self.mcp), [])

    def test_first_upgrade_preserves_preexisting_legacy_bytes(self):
        self.payload.mkdir()
        for name in assets.ASSETS:
            (self.payload / name).write_bytes(b"operator installed legacy\n")
        before = self.snapshot()
        self.install(dry_run=False)
        for name in assets.ASSETS:
            self.assertEqual(self.snapshot()["payload/" + name], before["payload/" + name])
        self.assertEqual(assets.findings(self.payload, self.policy, self.mcp), [])

    def test_legacy_tampering_refuses_before_new_version_or_pointer_write(self):
        self.install(dry_run=False)
        (self.payload / "mcp.toml").write_bytes(b"tampered")
        self.policy.write_bytes(b"new policy")
        before = self.snapshot()
        with self.assertRaisesRegex(assets.AssetError, "retained legacy"):
            self.install(dry_run=False)
        self.assertEqual(self.snapshot(), before)
        self.assertIn("retained legacy", assets.findings(self.payload, self.policy, self.mcp)[0])

    def test_corrupted_immutable_version_is_never_overwritten(self):
        self.install(dry_run=False)
        version = self.payload / "protected" / self.selected()["version"]
        (version / "mcp.toml").write_bytes(b"tampered")
        before = self.snapshot()
        with self.assertRaisesRegex(assets.AssetError, "immutable protected"):
            self.install(dry_run=False)
        self.assertEqual(self.snapshot(), before)

    def test_interrupted_version_append_keeps_previous_selection_and_reruns(self):
        self.install(dry_run=False)
        previous = (self.payload / assets.SELECTED_RECORD).read_bytes()
        self.policy.write_bytes(b"next policy")
        real_place = assets.place

        def interrupt(path, raw, **kwargs):
            if path.name == assets.SELECTED_RECORD:
                raise OSError("interrupted before selection")
            return real_place(path, raw, **kwargs)

        with mock.patch.object(assets, "place", side_effect=interrupt):
            with self.assertRaisesRegex(OSError, "interrupted"):
                self.install(dry_run=False)
        self.assertEqual((self.payload / assets.SELECTED_RECORD).read_bytes(), previous)
        self.install(dry_run=False)
        self.assertEqual(assets.findings(self.payload, self.policy, self.mcp), [])
        self.assertNotEqual((self.payload / assets.SELECTED_RECORD).read_bytes(), previous)

    def test_symlinked_parent_and_leaf_are_refused_without_writes(self):
        target = self.root / "target"
        target.mkdir()
        self.payload.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(assets.AssetError, "real directory"):
            self.install(dry_run=False)
        self.assertEqual(list(target.iterdir()), [])
        self.payload.unlink()
        self.payload.mkdir()
        (self.payload / "mcp.toml").symlink_to(self.mcp)
        with self.assertRaises(OSError):
            self.install(dry_run=False)
        self.assertEqual(self.mcp.read_bytes(), b"first tool registry\n")
        self.assertFalse((self.payload / assets.LEGACY_RECORD).exists())

    def test_hardlink_and_writable_file_are_refused(self):
        self.payload.mkdir()
        path = self.payload / "mcp.toml"
        os.link(self.mcp, path)
        with self.assertRaisesRegex(assets.AssetError, "one link"):
            self.install(dry_run=False)
        path.unlink()
        path.write_bytes(b"unsafe")
        path.chmod(0o666)
        with self.assertRaisesRegex(assets.AssetError, "writable"):
            self.install(dry_run=False)

    def test_verify_reports_missing_records_and_selected_source_mismatch(self):
        self.assertIn("no retained", assets.findings(self.payload, self.policy, self.mcp)[0])
        self.install(dry_run=False)
        self.policy.write_bytes(b"different source")
        self.assertIn("differs from source", assets.findings(self.payload, self.policy, self.mcp)[0])


if __name__ == "__main__":
    unittest.main()
