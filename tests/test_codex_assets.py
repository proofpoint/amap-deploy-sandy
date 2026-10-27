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
        self.assertIn("present", self.install(dry_run=False))
        self.assertEqual(self.snapshot(), before)
        self.assertEqual({str(p): p.stat().st_mtime_ns for p in self.root.rglob("*") if p.is_dir()}, directories)
        self.assertIn("present", self.install())

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
        real_place = assets.place_at

        def interrupt(dfd, name, raw, where, **kwargs):
            if name == assets.SELECTED_RECORD:
                raise OSError("interrupted before selection")
            return real_place(dfd, name, raw, where, **kwargs)

        with mock.patch.object(assets, "place_at", side_effect=interrupt):
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


class DescriptorAnchoredInstallTest(unittest.TestCase):
    """The host install and verify reach every file through a descriptor
    walked from `/`: a link at ANY component refuses, and what happens after
    the walk lands in the verified directory, never by a pathname reopened."""

    def setUp(self):
        self.tmp = TemporaryDirectory(prefix=".codex-assets-anchor-", dir=HERE)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.policy = self.root / "policy"
        self.mcp = self.root / "mcp"
        self.policy.write_bytes(b"first policy\n")
        self.mcp.write_bytes(b"first tool registry\n")
        self.decoy = self.root / "decoy"
        self.decoy.mkdir()

    def test_a_link_above_the_payload_refuses_and_writes_nothing(self):
        (self.root / "real").mkdir()
        (self.root / "via").symlink_to(self.root / "real", target_is_directory=True)
        with self.assertRaisesRegex(assets.AssetError, "real directory: .*/via$"):
            assets.install(self.root / "via" / "payload", self.policy, self.mcp, dry_run=False)
        self.assertEqual(list((self.root / "real").iterdir()), [])

    def test_a_link_above_a_source_refuses(self):
        (self.root / "src").mkdir()
        (self.root / "src" / "mcp").write_bytes(b"registry\n")
        (self.root / "srclink").symlink_to(self.root / "src", target_is_directory=True)
        with self.assertRaisesRegex(assets.AssetError, "real directory: .*/srclink$"):
            assets.install(self.root / "payload", self.policy, self.root / "srclink" / "mcp", dry_run=False)
        self.assertFalse((self.root / "payload").exists())

    def test_a_payload_swapped_for_a_link_mid_install_is_not_followed(self):
        payload = self.root / "payload"
        real = assets.place_at
        swapped = []

        def swap_then_place(dfd, name, raw, where, **kwargs):
            if not swapped:
                payload.rename(self.root / "moved")
                payload.symlink_to(self.decoy, target_is_directory=True)
                swapped.append(True)
            return real(dfd, name, raw, where, **kwargs)

        with mock.patch.object(assets, "place_at", side_effect=swap_then_place):
            assets.install(payload, self.policy, self.mcp, dry_run=False)
        self.assertEqual(list(self.decoy.iterdir()), [])
        self.assertTrue((self.root / "moved" / assets.SELECTED_RECORD).is_file())

    def test_an_object_at_the_temporary_name_refuses(self):
        payload = self.root / "payload"
        payload.mkdir()
        (payload / (".asset-%d-%s" % (os.getpid(), "f" * 16))).symlink_to(self.decoy / "planted")
        with mock.patch.object(assets.secrets, "token_hex", return_value="f" * 16):
            with self.assertRaises(FileExistsError):
                assets.install(payload, self.policy, self.mcp, dry_run=False)
        self.assertEqual(list(self.decoy.iterdir()), [])

    def test_verify_read_refuses_a_link_above_the_file(self):
        (self.root / "state").mkdir()
        (self.root / "state" / "fresh-birth.json").write_bytes(b"{}")
        (self.root / "statelink").symlink_to(self.root / "state", target_is_directory=True)
        self.assertEqual(assets.read_path(self.root / "state" / "fresh-birth.json"), b"{}")
        with self.assertRaisesRegex(assets.AssetError, "real directory: .*/statelink$"):
            assets.read_path(self.root / "statelink" / "fresh-birth.json")

    def test_verify_read_uses_the_walked_directory_not_a_reopened_path(self):
        state = self.root / "state"
        state.mkdir()
        (state / "fresh-birth.json").write_bytes(b"{\"walked\": true}")
        (self.decoy / "fresh-birth.json").write_bytes(b"{\"decoy\": true}")
        real = assets.open_dir

        def walk_then_swap(path, **kwargs):
            fd = real(path, **kwargs)
            state.rename(self.root / "moved")
            state.symlink_to(self.decoy, target_is_directory=True)
            return fd

        with mock.patch.object(assets, "open_dir", side_effect=walk_then_swap):
            self.assertEqual(assets.read_path(state / "fresh-birth.json"), b"{\"walked\": true}")

    def test_findings_refuses_a_link_above_the_payload(self):
        assets.install(self.root / "payload", self.policy, self.mcp, dry_run=False)
        (self.root / "paylink").symlink_to(self.root / "payload", target_is_directory=True)
        self.assertEqual(assets.findings(self.root / "payload", self.policy, self.mcp), [])
        self.assertRegex(assets.findings(self.root / "paylink", self.policy, self.mcp)[0],
                         "real directory: .*/paylink$")


if __name__ == "__main__":
    unittest.main()
