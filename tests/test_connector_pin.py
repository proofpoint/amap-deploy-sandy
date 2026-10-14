"""connector_pin: install refuses a connector checkout that is not at its
siblings.json pin.

Every checkout here is a scratch git repository made in a temporary
directory, with a `bin/` holding a stand-in file; the pins file is a scratch
copy naming the commit under test. Nothing touches a real checkout or a host:
the install verb runs only against a temporary $SANDY_HOME, and the refusal
is checked to come before anything is written there.
"""

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import connector_pin as cp

GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.org",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}


def git(*args, cwd):
    r = subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True,
                       env={**os.environ, **GIT_ENV}, timeout=60)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


class Scratch(unittest.TestCase):
    """A scratch connector checkout with two commits, and a pins file."""

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = Path(td.name)
        self.repo = self.root / "amap-connector-claude"
        (self.repo / "bin").mkdir(parents=True)
        git("init", "--quiet", "-b", "main", cwd=self.repo)
        (self.repo / "bin" / "inbox-delivery").write_text("one\n")
        git("add", "-A", cwd=self.repo)
        git("commit", "--quiet", "-m", "one", cwd=self.repo)
        self.first = git("rev-parse", "HEAD", cwd=self.repo)
        (self.repo / "bin" / "inbox-delivery").write_text("two\n")
        git("commit", "--quiet", "-am", "two", cwd=self.repo)
        self.second = git("rev-parse", "HEAD", cwd=self.repo)
        self.pins = self.root / "siblings.json"
        self.pin(self.second)
        self.log_dir = self.root / "feature"
        self.said = []

    def pin(self, commit):
        self.pins.write_text(json.dumps({"schema": 1, "siblings": [
            {"name": "amap-router-local", "url": "https://example.org/r", "commit": "0" * 40,
             "override": "AMAP_ROUTER_REPO"},
            {"name": "amap-connector-claude", "url": "https://example.org/c", "commit": commit,
             "override": "AMAP_CONNECTOR_REPO"}]}))

    def guard(self, override=None, apply=False):
        return cp.guard(self.repo / "bin", override=override, apply=apply, log_dir=self.log_dir,
                        out=self.said.append, pins_path=self.pins)

    def log_lines(self):
        log = self.log_dir / cp.LOG_NAME
        return [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []


class MatchTest(Scratch):
    def test_a_checkout_at_its_pin_passes(self):
        c = self.guard()
        self.assertTrue(c.ok)
        self.assertEqual(c.found, self.second)
        self.assertIn("at its pin", self.said[0])

    def test_an_untracked_file_is_not_a_change_to_the_pinned_bytes(self):
        (self.repo / "bin" / "scratch.txt").write_text("x")
        self.assertTrue(self.guard().ok)


class MismatchTest(Scratch):
    def test_a_checkout_past_its_pin_is_refused_naming_both_commits(self):
        self.pin(self.first)
        with self.assertRaises(cp.PinRefused) as e:
            self.guard()
        self.assertIn(self.first, str(e.exception))
        self.assertIn(self.second, str(e.exception))
        self.assertIn(cp.OVERRIDE_FLAG, str(e.exception))

    def test_a_refusal_writes_no_log(self):
        self.pin(self.first)
        with self.assertRaises(cp.PinRefused):
            self.guard(apply=True)
        self.assertFalse((self.log_dir / cp.LOG_NAME).exists())

    def test_a_source_outside_any_checkout_is_refused(self):
        plain = self.root / "plain" / "bin"
        plain.mkdir(parents=True)
        with self.assertRaises(cp.PinRefused) as e:
            cp.guard(plain, override=None, apply=False, log_dir=self.log_dir, out=self.said.append,
                     pins_path=self.pins)
        self.assertIn("not inside a git checkout", str(e.exception))
        self.assertIn(self.second, str(e.exception), "the refusal names the pinned commit")


class DirtyTest(Scratch):
    def test_a_changed_tracked_file_at_the_pin_is_refused(self):
        (self.repo / "bin" / "inbox-delivery").write_text("edited\n")
        with self.assertRaises(cp.PinRefused) as e:
            self.guard()
        self.assertIn("changes to tracked files", str(e.exception))

    def test_a_staged_change_at_the_pin_is_refused(self):
        (self.repo / "bin" / "inbox-delivery").write_text("edited\n")
        git("add", "-A", cwd=self.repo)
        with self.assertRaises(cp.PinRefused):
            self.guard()


class OverrideTest(Scratch):
    def setUp(self):
        super().setUp()
        self.pin(self.first)

    def test_an_override_with_apply_is_recorded_with_both_commits_and_the_reason(self):
        c = self.guard(override="testing a fix", apply=True)
        self.assertFalse(c.ok)
        [rec] = self.log_lines()
        self.assertEqual((rec["event"], rec["pinned"], rec["found"], rec["reason"], rec["dirty"]),
                         ("unpinned_connector", self.first, self.second, "testing a fix", False))
        self.assertEqual(rec["checkout"], str(self.repo))

    def test_each_use_appends_one_line(self):
        self.guard(override="one", apply=True)
        self.guard(override="two", apply=True)
        self.assertEqual([r["reason"] for r in self.log_lines()], ["one", "two"])

    def test_a_dry_run_override_writes_nothing_and_says_what_it_would_record(self):
        self.guard(override="testing", apply=False)
        self.assertEqual(self.log_lines(), [])
        self.assertTrue(any("would record" in s for s in self.said))

    def test_a_dirty_checkout_override_records_dirty(self):
        self.pin(self.second)
        (self.repo / "bin" / "inbox-delivery").write_text("edited\n")
        self.guard(override="local patch", apply=True)
        self.assertTrue(self.log_lines()[0]["dirty"])

    def test_a_blank_reason_is_no_override(self):
        with self.assertRaises(cp.PinRefused):
            self.guard(override="   ", apply=True)


class InstallVerbTest(Scratch):
    """The verb, end to end, against a temporary $SANDY_HOME: the refusal
    comes before anything is written."""

    def run_install(self, *extra):
        import amap_sandy as prov
        home = self.root / "sandy-home"
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = prov.main(["--sandy-home", str(home), "--connector-src", str(self.repo / "bin"),
                            *extra, "install", "--apply"])
        return rc, home, out.getvalue() + err.getvalue()

    def test_install_apply_refuses_an_unpinned_checkout_before_writing(self):
        # The scratch checkout is not at this repo's real pin.
        rc, home, said = self.run_install()
        self.assertEqual(rc, 2, said)
        self.assertIn("not at its siblings.json pin", said)
        self.assertFalse((home / "features").exists(), "install wrote before refusing")


if __name__ == "__main__":
    unittest.main()
