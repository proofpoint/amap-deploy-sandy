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
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

HERE = Path(__file__).resolve().parents[1]
SCRIPT = HERE / "amap-codex-rollout.sh"

STUB_INSTALL = """import sys, os, pathlib
open(os.environ["STUB_CALLS"], "a").write(" ".join(sys.argv[1:]) + "\\n")
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
        siblings = {"schema": 1, "siblings": [{"name": n, "commit": c} for n, c in pins.items()]}
        self.ds_commit = repo(amap / "amap-deploy-sandy", {"siblings.json": json.dumps(siblings),
                                                          "amap-sandy.py": STUB_INSTALL})
        self.amap = amap
        home = self.root / "sandy-home"
        self.feature = home / "features" / "amap"
        (self.feature / "payload" / "codex").mkdir(parents=True)
        (self.feature / "payload" / "codex" / "interactive-launch").write_text("old launcher\n")
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
        self._refused("amap-connector-codex has tracked changes")

    def test_a_sibling_at_another_commit_refuses(self):
        git(self.amap / "amap-router-local", "commit", "-q", "--allow-empty", "-m", "y")
        self._refused("not the reviewed")

    def test_a_missing_sibling_refuses(self):
        shutil.rmtree(self.amap / "amap-connector-codex")
        self._refused("amap-connector-codex: no checkout")

    def test_a_sandy_without_agent_wrapper_refuses(self):
        self._refused("does not list agent_wrapper",
                      STUB_SCHEMA=json.dumps({"manifest": {"top_level_keys": ["schema"]}}))

    def test_apply_backs_up_then_installs_and_rollback_restores_without_deleting(self):
        r = self.run_("apply")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.installs(), ["install --apply", "verify"])
        launcher = self.feature / "payload/codex/interactive-launch"
        self.assertEqual(launcher.read_text(), "new launcher\n")
        backups = sorted((self.feature.parent / "amap.rollout-backups").iterdir())
        self.assertEqual(len(backups), 1)
        b = backups[0]
        self.assertEqual((b / "payload/codex/interactive-launch").read_text(), "old launcher\n")
        self.assertTrue((b / "SHA256SUMS").is_file())
        r = self.run_("rollback", str(b))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(launcher.read_text(), "old launcher\n")
        aside = [p for p in (self.feature.parent / "amap.rollout-backups").iterdir() if p.name.endswith("-replaced")]
        self.assertEqual(len(aside), 1)
        self.assertEqual((aside[0] / "payload/codex/interactive-launch").read_text(), "new launcher\n")
        self.assertEqual((self.feature / "feature.json").read_text(), '{"schema": 1}\n')

    def test_rollback_refuses_a_backup_that_does_not_match_its_list(self):
        r = self.run_("apply")
        self.assertEqual(r.returncode, 0, r.stderr)
        b = next((self.feature.parent / "amap.rollout-backups").iterdir())
        (b / "feature.json").write_text("tampered\n")
        r = self.run_("rollback", str(b))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("does not match its SHA256SUMS", r.stderr)
        self.assertEqual((self.feature / "payload/codex/interactive-launch").read_text(), "new launcher\n")
