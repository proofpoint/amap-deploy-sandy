"""`siblings.py`: the router and connector checkouts, put at their pins.

Real git, against throwaway local repositories: a "remote" with two commits,
pinned to the OLDER one, so a checkout that merely followed the remote's
branch tip would be caught.
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

HERE = Path(__file__).resolve().parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import siblings  # noqa: E402

GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.org"}


def git(*args, cwd):
    r = subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True,
                       env={**os.environ, **GIT_ENV})
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


class SiblingsTest(unittest.TestCase):

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.remotes = root / "remotes"
        self.base = root / "work"
        self.base.mkdir()
        src = self.remotes / "demo"
        src.mkdir(parents=True)
        git("init", "--quiet", "-b", "main", cwd=src)
        (src / "f").write_text("one\n")
        git("add", "f", cwd=src)
        git("commit", "--quiet", "-m", "one", cwd=src)
        self.old = git("rev-parse", "HEAD", cwd=src)
        (src / "f").write_text("two\n")
        git("commit", "--quiet", "-am", "two", cwd=src)
        self.new = git("rev-parse", "HEAD", cwd=src)
        self.sib = {"name": "demo", "url": str(src), "commit": self.old,
                    "override": "AMAP_TEST_DEMO_REPO"}
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        for var in ("AMAP_TEST_DEMO_REPO", siblings.REPO_BASE_ENV):
            os.environ.pop(var, None)

    def _put(self):
        action, _ = siblings.plan(self.sib, self.base)
        if action in ("clone", "checkout"):
            siblings.apply(self.sib, self.base, action)
        return action

    def _head(self):
        return git("rev-parse", "HEAD", cwd=self.base / "demo")

    def test_a_missing_checkout_is_cloned_and_put_at_the_pin_not_the_tip(self):
        self.assertEqual(self._put(), "clone")
        self.assertEqual(self._head(), self.old)
        self.assertEqual(self._put(), "present")

    def test_an_existing_checkout_is_moved_to_the_pin(self):
        git("clone", "--quiet", self.sib["url"], str(self.base / "demo"), cwd=self.base)
        self.assertEqual(self._head(), self.new)
        self.assertEqual(self._put(), "checkout")
        self.assertEqual(self._head(), self.old)

    def test_uncommitted_changes_to_tracked_files_refuse_and_untracked_files_do_not(self):
        self._put()
        dest = self.base / "demo"
        (dest / "scratch").write_text("mine\n")
        self.sib["commit"] = self.new
        self.assertEqual(siblings.plan(self.sib, self.base)[0], "checkout")
        (dest / "f").write_text("edited\n")
        with self.assertRaises(siblings.SiblingError) as cm:
            siblings.plan(self.sib, self.base)
        self.assertIn("uncommitted changes", str(cm.exception))

    def test_a_path_that_is_not_a_checkout_is_refused(self):
        (self.base / "demo").mkdir()
        with self.assertRaises(siblings.SiblingError) as cm:
            siblings.plan(self.sib, self.base)
        self.assertIn("not a git checkout", str(cm.exception))

    def test_an_override_leaves_the_operators_checkout_alone(self):
        os.environ["AMAP_TEST_DEMO_REPO"] = "/somewhere/else"
        action, detail = siblings.plan(self.sib, self.base)
        self.assertEqual(action, "skip")
        self.assertIn("/somewhere/else", detail)
        self.assertFalse((self.base / "demo").exists())

    def test_a_pin_the_remote_does_not_have_fails_loudly(self):
        self.sib["commit"] = "0" * 40
        with self.assertRaises(siblings.SiblingError) as cm:
            self._put()
        self.assertIn("not on its remote", str(cm.exception))

    def test_the_repo_base_replaces_the_url_for_a_mirror(self):
        os.environ[siblings.REPO_BASE_ENV] = str(self.remotes) + "/"
        self.sib["url"] = "https://example.org/unreachable/demo"
        self.assertEqual(siblings.clone_url(self.sib), f"{self.remotes}/demo")
        self.assertEqual(self._put(), "clone")
        self.assertEqual(self._head(), self.old)

    def test_a_dry_run_writes_nothing(self):
        out = io.StringIO()
        with mock.patch.object(siblings, "load_pins", return_value=[self.sib]), \
                redirect_stdout(out), redirect_stderr(io.StringIO()):
            rc = siblings.main(["--base", str(self.base)])
        self.assertEqual(rc, 0)
        self.assertIn("would clone", out.getvalue())
        self.assertFalse((self.base / "demo").exists())


class ShippedPinsTest(unittest.TestCase):

    def test_the_shipped_pins_load_and_name_both_siblings_with_their_overrides(self):
        pins = {p["name"]: p for p in siblings.load_pins()}
        self.assertEqual(set(pins), {"amap-router-local", "amap-connector-claude"})
        self.assertEqual(pins["amap-router-local"]["override"], "AMAP_ROUTER_REPO")
        self.assertEqual(pins["amap-connector-claude"]["override"], "AMAP_CONNECTOR_REPO")

    def test_a_short_or_missing_commit_is_refused(self):
        with TemporaryDirectory() as d:
            for commit in ("abc1234", "", None):
                with self.subTest(commit=commit):
                    p = Path(d) / "pins.json"
                    p.write_text(json.dumps({"schema": 1, "siblings": [
                        {"name": "x", "url": "u", "commit": commit, "override": "V"}]}))
                    with self.assertRaises(siblings.SiblingError):
                        siblings.load_pins(p)


if __name__ == "__main__":
    unittest.main()
