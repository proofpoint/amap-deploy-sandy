"""The SHIPPED amap-codex-rollout.sh, against throwaway checkouts.

AMAP_ROOT holds four git repositories made here: a stand-in deployment
checkout (its own siblings.json and a stub amap-sandy.py that records its
arguments and, for `install --apply`, rewrites the payload) and three
siblings at the commits that siblings.json names. `sandy` is a stub whose
--print-schema the test sets. Nothing here reads a real checkout, sandy or
SANDY_HOME.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

HERE = Path(__file__).resolve().parents[1]
SCRIPT = HERE / "amap-codex-rollout.sh"

STUB_INSTALL = """import sys, os, pathlib
open(os.environ["STUB_CALLS"], "a").write(" ".join(sys.argv[1:]) + "\\n")
if sys.argv[1:] == ["verify"]:
    sys.exit(int(os.environ.get("STUB_VERIFY_RC", "0")))
if sys.argv[1:] == ["install", "--apply"]:
    p = pathlib.Path(os.environ["SANDY_HOME"]) / "features/amap/payload/codex/interactive-launch"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("new launcher\\n")
"""

STUB_SANDY = """#!/bin/sh
[ "$1" = "--print-schema" ] || exit 9
printf '%s\\n' "$STUB_SCHEMA"
"""

SIBLINGS = ("amap-router-local", "amap-connector-claude", "amap-connector-codex")
HOP_DIR = "amap-router-local-hop"  # a sibling whose checkout siblings.json puts in its own `dir`


def git(cwd, *args):
    return subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True,
                          text=True, env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org",
                                          "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.org"}).stdout.strip()


def repo(path, files):
    path.mkdir(parents=True)
    git(path, "init", "-q")
    for name, text in files.items():
        (path / name).write_text(text)
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", "x")
    return git(path, "rev-parse", "HEAD")


class RolloutTest(unittest.TestCase):

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        amap = self.root / "amap"
        pins = {name: repo(amap / name, {"README": name}) for name in SIBLINGS}
        hop = repo(amap / HOP_DIR, {"README": "hop"})
        siblings = {"schema": 1, "siblings": [{"name": n, "commit": c} for n, c in pins.items()]
                    + [{"name": "amap-router-local", "commit": hop, "dir": HOP_DIR}]}
        self.ds_commit = repo(amap / "amap-deploy-sandy", {"siblings.json": json.dumps(siblings),
                                                          "amap-sandy.py": STUB_INSTALL})
        self.amap = amap
        home = self.root / "sandy-home"
        self.feature = home / "features" / "amap"
        (self.feature / "payload" / "codex").mkdir(parents=True)
        launcher = self.feature / "payload" / "codex" / "interactive-launch"
        launcher.write_text("old launcher\n")
        launcher.chmod(0o755)
        (self.feature / "payload" / "codex" / "relay-link").symlink_to("interactive-launch")
        (self.feature / "feature.json").write_text('{"schema": 1}\n')
        (self.feature / "router.json").write_text('{"instances": {}}\n')
        bindir = self.root / "bin"
        bindir.mkdir()
        (bindir / "sandy").write_text(STUB_SANDY)
        (bindir / "sandy").chmod(0o755)
        self.calls = self.root / "calls"
        self.env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "AMAP_ROOT": str(amap),
                    "SANDY_HOME": str(home), "STUB_CALLS": str(self.calls),
                    "AMAP_EXPECT_DS_COMMIT": self.ds_commit,
                    "STUB_SCHEMA": json.dumps({"manifest": {"top_level_keys": ["schema", "agent_wrapper"]}})}

    def run_(self, *args, **env):
        return subprocess.run(["bash", str(SCRIPT), *args], env={**self.env, **env},
                              capture_output=True, text=True, timeout=60)

    def installs(self):
        return self.calls.read_text().splitlines() if self.calls.exists() else []

    def test_check_passes_on_exact_clean_checkouts_and_only_dry_runs(self):
        r = self.run_("check")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.installs(), ["install"])
        self.assertFalse((self.feature.parent / "amap.rollout-backups").exists())

    def _refused(self, must, *args, **env):
        r = self.run_(*(args or ("apply",)), **env)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(must, r.stderr)
        self.assertEqual(self.installs(), [], "install ran after a refused check")
        self.assertEqual((self.feature / "payload/codex/interactive-launch").read_text(), "old launcher\n")
        return r

    def test_another_deployment_commit_refuses(self):
        self._refused("not the reviewed", AMAP_EXPECT_DS_COMMIT="0" * 40)

    def test_no_expected_commit_refuses(self):
        env = {k: v for k, v in self.env.items() if k != "AMAP_EXPECT_DS_COMMIT"}
        r = subprocess.run(["bash", str(SCRIPT), "apply"], env=env, capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("set AMAP_EXPECT_DS_COMMIT", r.stderr)
        self.assertEqual(self.installs(), [])

    def test_a_tracked_change_in_a_sibling_refuses(self):
        (self.amap / "amap-connector-codex" / "README").write_text("edited\n")
        self._refused("amap-connector-codex is not the committed bytes: README")

    def test_a_sibling_at_another_commit_refuses(self):
        git(self.amap / "amap-router-local", "commit", "-q", "--allow-empty", "-m", "y")
        self._refused("not the reviewed")

    def test_a_missing_sibling_refuses(self):
        shutil.rmtree(self.amap / "amap-connector-codex")
        self._refused("amap-connector-codex: no checkout")

    def test_a_sibling_is_checked_in_the_directory_siblings_json_gives_it(self):
        r = self.run_("check")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"ok  {HOP_DIR} ", r.stdout)
        self.calls.unlink()
        shutil.rmtree(self.amap / HOP_DIR)
        self._refused(f"{HOP_DIR}: no checkout")

    def _ds_siblings(self, text):
        """A deployment checkout whose own committed siblings.json is `text`."""
        ds = self.amap / "amap-deploy-sandy"
        (ds / "siblings.json").write_text(text)
        git(ds, "commit", "-q", "-am", "siblings")
        return git(ds, "rev-parse", "HEAD")

    def test_siblings_json_that_does_not_parse_refuses_rather_than_checking_nothing(self):
        commit = self._ds_siblings("{not json")
        self._refused("cannot read the sibling pins", AMAP_EXPECT_DS_COMMIT=commit)

    def test_siblings_json_naming_no_sibling_refuses(self):
        commit = self._ds_siblings(json.dumps({"schema": 1, "siblings": []}))
        self._refused("cannot read the sibling pins", AMAP_EXPECT_DS_COMMIT=commit)

    def test_an_edit_hidden_by_assume_unchanged_refuses(self):
        d = self.amap / "amap-connector-claude"
        git(d, "update-index", "--assume-unchanged", "README")
        (d / "README").write_text("edited\n")
        self.assertEqual(git(d, "status", "--porcelain"), "", "git status is meant to hide this edit")
        self._refused("amap-connector-claude is not the committed bytes: README")

    def test_an_edit_hidden_by_skip_worktree_refuses(self):
        d = self.amap / "amap-router-local"
        git(d, "update-index", "--skip-worktree", "README")
        (d / "README").write_text("edited\n")
        self.assertEqual(git(d, "status", "--porcelain"), "")
        self._refused("amap-router-local is not the committed bytes: README")

    def test_a_mode_change_refuses(self):
        (self.amap / "amap-connector-codex" / "README").chmod(0o755)
        self._refused("README (mode)")

    def test_a_sandy_without_agent_wrapper_refuses(self):
        self._refused("does not list agent_wrapper",
                      STUB_SCHEMA=json.dumps({"manifest": {"top_level_keys": ["schema"]}}))

    def test_apply_backs_up_then_installs_and_rollback_restores_without_deleting(self):
        r = self.run_("apply")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.installs(), ["install --apply", "verify"])
        launcher = self.feature / "payload/codex/interactive-launch"
        link = self.feature / "payload/codex/relay-link"
        self.assertEqual(launcher.read_text(), "new launcher\n")
        backups = sorted((self.feature.parent / "amap.rollout-backups").iterdir())
        self.assertEqual(len(backups), 1)
        b = backups[0]
        self.assertEqual((b / "payload/codex/interactive-launch").read_text(), "old launcher\n")
        self.assertTrue((b / "SHA256SUMS").is_file())
        self.assertEqual(os.readlink(b / "payload/codex/relay-link"), "interactive-launch")
        self.assertEqual(stat.S_IMODE((b / "payload/codex/interactive-launch").stat().st_mode), 0o755)
        launcher.chmod(0o644)
        r = self.run_("rollback", str(b))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(launcher.read_text(), "old launcher\n")
        self.assertEqual(stat.S_IMODE(launcher.stat().st_mode), 0o755, "the mode was not restored")
        self.assertEqual(os.readlink(link), "interactive-launch", "the link was not restored as a link")
        aside = [p for p in (self.feature.parent / "amap.rollout-backups").iterdir() if p.name.endswith("-replaced")]
        self.assertEqual(len(aside), 1)
        self.assertEqual((aside[0] / "payload/codex/interactive-launch").read_text(), "new launcher\n")
        self.assertEqual((self.feature / "feature.json").read_text(), '{"schema": 1}\n')

    def _backup(self):
        r = self.run_("apply")
        self.assertEqual(r.returncode, 0, r.stderr)
        return next((self.feature.parent / "amap.rollout-backups").iterdir())

    def _rollback_refused(self, b, must):
        r = self.run_("rollback", str(b))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(must, r.stderr)
        self.assertEqual((self.feature / "payload/codex/interactive-launch").read_text(), "new launcher\n")
        self.assertEqual([p.name for p in (self.feature.parent / "amap.rollout-backups").iterdir()
                          if p.name.endswith("-replaced")], [], "files were moved aside after a refusal")

    def test_rollback_refuses_a_backup_whose_bytes_changed(self):
        b = self._backup()
        (b / "feature.json").write_text("tampered\n")
        self._rollback_refused(b, "does not match its SHA256SUMS")

    def test_rollback_refuses_a_backup_whose_mode_changed(self):
        b = self._backup()
        (b / "payload/codex/interactive-launch").chmod(0o644)
        self._rollback_refused(b, "does not match its TREE")

    def test_rollback_refuses_a_backup_whose_link_changed(self):
        b = self._backup()
        os.remove(b / "payload/codex/relay-link")
        os.symlink("/etc/passwd", b / "payload/codex/relay-link")
        self._rollback_refused(b, "does not match its TREE")

    def test_rollback_refuses_a_directory_without_both_lists(self):
        b = self._backup()
        os.remove(b / "TREE")
        self._rollback_refused(b, "holds no SHA256SUMS and TREE")

    def test_the_backup_keeps_modes_under_a_restrictive_umask(self):
        """A copy that does not preserve modes would turn 0755 into 0700 under umask 077."""
        r = subprocess.run(["bash", "-c", 'umask 077 && exec bash "$0" apply', str(SCRIPT)],
                           env=self.env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        b = next((self.feature.parent / "amap.rollout-backups").iterdir())
        self.assertEqual(stat.S_IMODE((b / "payload/codex/interactive-launch").stat().st_mode), 0o755)

    def test_a_backup_that_differs_from_the_live_files_stops_before_install(self):
        """The fidelity check, isolated: a backup copier that drops a link is refused."""
        script = SCRIPT.read_text().replace('cp -a "$FEATURE/$f" "$dest/$f"', 'cp -rL "$FEATURE/$f" "$dest/$f"')
        self.assertNotEqual(script, SCRIPT.read_text())
        patched = self.root / "rollout-patched.sh"
        patched.write_text(script)
        r = subprocess.run(["bash", str(patched), "apply"], env=self.env, capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("does not match the live files", r.stderr)
        self.assertEqual(self.installs(), [], "install ran after a backup that does not match")

    def test_a_restore_that_does_not_match_the_backup_is_reported(self):
        """The post-restore check, isolated: a restore that drops a link is a failure."""
        b = self._backup()
        script = SCRIPT.read_text().replace('then cp -a "$b/$f" "$FEATURE/$f"', 'then cp -rL "$b/$f" "$FEATURE/$f"')
        self.assertNotEqual(script, SCRIPT.read_text())
        patched = self.root / "rollout-patched.sh"
        patched.write_text(script)
        r = subprocess.run(["bash", str(patched), "rollback", str(b)], env=self.env,
                           capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("the restored files do not match", r.stderr)

    def test_a_verify_failure_after_apply_is_a_failure_that_names_the_backup(self):
        r = self.run_("apply", STUB_VERIFY_RC="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("verify reported problems", r.stderr)
        b = next((self.feature.parent / "amap.rollout-backups").iterdir())
        self.assertIn(f"rollback {b}", r.stderr)
        self.assertNotIn("Applied.", r.stdout)
