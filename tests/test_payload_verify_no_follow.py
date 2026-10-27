"""verify's payload check reads every payload and source file through safe_io.

Each test builds a real payload with install, then plants one thing a
pathname read would follow or accept: a link at the payload directory to a
byte-identical copy, a second hard link to a payload file, or a leaf linked
to an identical file. A read that followed it would find equal bytes and
report nothing, so a reported problem naming the file can only come from
the read refusing it.
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

import amap_sandy as prov


class PayloadVerifyNoFollowTest(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.d = Path(td.name).resolve()
        self.home = self.d / "sandy-home"
        prov.feature_root(self.home).mkdir(parents=True)
        prov.install_feature_payload(self.home, prov.DEFAULT_CONNECTOR_SRC, dry_run=False)
        self.dest = prov.feature_payload_dir(self.home)

    def verify(self):
        return prov.verify_feature_payload(self.home, prov.DEFAULT_CONNECTOR_SRC)

    def test_an_installed_payload_verifies_clean(self):
        self.assertEqual(self.verify(), [])

    def test_a_payload_directory_linked_to_an_identical_copy_is_not_read_through(self):
        copy = self.d / "copy"
        shutil.copytree(self.dest, copy)
        shutil.rmtree(self.dest)
        os.symlink(copy, self.dest)
        problems = self.verify()
        relay = f"payload drift: {self.dest / prov.RELAY_WRAPPER_NAME} is missing or unreadable"
        self.assertIn(relay, problems)

    def test_a_second_hard_link_to_a_payload_file_is_reported(self):
        os.link(self.dest / prov.RELAY_WRAPPER_NAME, self.d / "extra-link")
        self.assertIn(f"payload drift: {self.dest / prov.RELAY_WRAPPER_NAME} is missing or unreadable",
                      self.verify())

    def test_a_leaf_linked_to_an_identical_file_is_reported_as_a_link(self):
        leaf = self.dest / prov.RELAY_WRAPPER_NAME
        twin = self.d / "twin"
        shutil.copy2(leaf, twin)
        leaf.unlink()
        os.symlink(twin, leaf)
        self.assertIn(f"payload drift: {leaf} is a symlink — real files only", self.verify())

    def test_the_executable_bit_comes_from_the_file_that_was_read(self):
        leaf = self.dest / prov.RELAY_WRAPPER_NAME
        leaf.chmod(0o644)
        self.assertIn(f"payload drift: {leaf} is not executable", self.verify())


if __name__ == "__main__":
    unittest.main()
