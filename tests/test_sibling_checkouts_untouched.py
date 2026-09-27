"""The session guard in conftest.py fingerprints the router checkout before
and after the suite. This proves the fingerprint SEES a write — an
untracked file, a modified tracked file — so the guard is a guard and not a
comparison of two empty strings.
"""
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import _workspace


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.org",
                        "PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": str(root)})


class CheckoutFingerprintTest(unittest.TestCase):
    def _repo(self, tmp):
        root = Path(tmp) / "repo"
        root.mkdir()
        _git(root, "init", "-q")
        (root / "docker").mkdir()
        (root / "docker" / "derive-mounts.py").write_text("# the emitter\n" * 40)
        _git(root, "add", "-A")
        _git(root, "commit", "-q", "-m", "emitter")
        return root

    def test_a_clean_checkout_fingerprints_the_same_twice(self):
        with TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            self.assertEqual(_workspace.checkout_fingerprint(root),
                             _workspace.checkout_fingerprint(root))

    def test_overwriting_a_tracked_file_changes_the_fingerprint(self):
        """The shape the guard exists for: the committed emitter replaced by
        a short stand-in."""
        with TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            before = _workspace.checkout_fingerprint(root)
            (root / "docker" / "derive-mounts.py").write_text("# stand-in; the test patches `run`\n")
            after = _workspace.checkout_fingerprint(root)
            self.assertNotEqual(before, after)
            self.assertIn("derive-mounts.py", after)

    def test_an_untracked_file_changes_the_fingerprint(self):
        with TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            before = _workspace.checkout_fingerprint(root)
            (root / "stray").write_text("x")
            self.assertNotEqual(before, _workspace.checkout_fingerprint(root))

    def test_a_non_checkout_is_None_never_a_match(self):
        with TemporaryDirectory() as tmp:
            self.assertIsNone(_workspace.checkout_fingerprint(Path(tmp)))
