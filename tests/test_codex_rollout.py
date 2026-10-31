"""The SHIPPED amap-codex-rollout.py (codex_rollout), against throwaway checkouts.

AMAP_ROOT holds git repositories made here: a stand-in deployment checkout
(its own siblings.json and a stub amap-sandy.py that records its arguments
and, for `install --apply`, rewrites the payload) and siblings at the commits
that siblings.json names, one of them in its own `dir`. `sandy` is a stub
whose --print-schema the test sets. Nothing here reads a real checkout,
sandy or SANDY_HOME.

End to end, the launcher runs as the operator runs it. The failure paths a
shell cannot show are driven in process through `codex_rollout.main`, with
one step of the real code broken at a time: a copy that fails, a copy that
truncates without failing, a hash that fails, a restore copy that fails.
Each must stop the run before the installer is called, or name where the
replaced files went.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

HERE = Path(__file__).resolve().parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import codex_rollout as cr  # noqa: E402

LAUNCHER = HERE / "amap-codex-rollout.py"

STUB_INSTALL = """import sys, os, pathlib
open(os.environ["STUB_CALLS"], "a").write(" ".join(sys.argv[1:]) + "\\n")
if sys.argv[-1] == "verify":
    sys.exit(int(os.environ.get("STUB_VERIFY_RC", "0")))
if sys.argv[-2:] == ["install", "--apply"]:
    if os.environ.get("STUB_INSTALL_RC"):
        sys.exit(int(os.environ["STUB_INSTALL_RC"]))
    p = pathlib.Path(os.environ["SANDY_HOME"]) / "features/amap/payload/codex/interactive-launch"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("new launcher\\n")
"""

STUB_SANDY = """#!/bin/sh
[ "$1" = "--print-schema" ] || exit 9
printf '%s\\n' "$STUB_SCHEMA"
"""

GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.org"}
HOP_DIR = "amap-router-local-hop"


def git(cwd, *args):
    return subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True,
                          env={**os.environ, **GIT_ENV}).stdout.strip()


def repo(path, files):
    path.mkdir(parents=True)
    git(path, "init", "-q")
    for name, text in files.items():
        (path / name).parent.mkdir(parents=True, exist_ok=True)
        (path / name).write_text(text)
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", "x")
    return git(path, "rev-parse", "HEAD")


CODEX_FILES = {"src/amap_codex/__init__.py": "", "src/amap_codex/interactive.py": "x = 1\n",
               "bin/inbox-mcp-vol": "#!/bin/sh\n", "bin/inbox-submit": "#!/bin/sh\n",
               "bin/_inboxlib.py": "", "config/operator-instructions.md": "policy\n", "README": "codex\n"}


class RolloutTest(unittest.TestCase):

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        amap = self.amap = self.root / "amap"
        pins = {"amap-router-local": repo(amap / "amap-router-local", {"README": "r"}),
                "amap-connector-claude": repo(amap / "amap-connector-claude", {"README": "c"}),
                "amap-connector-codex": repo(amap / "amap-connector-codex", CODEX_FILES)}
        hop = repo(amap / HOP_DIR, {"README": "hop"})
        overrides = {"amap-router-local": "AMAP_ROUTER_REPO", "amap-connector-claude": "AMAP_CONNECTOR_REPO",
                     "amap-connector-codex": "AMAP_CODEX_CONNECTOR_REPO"}
        siblings = {"schema": 1, "siblings": [{"name": n, "commit": c, "override": overrides[n]}
                                               for n, c in pins.items()]
                    + [{"name": "amap-router-local", "commit": hop, "dir": HOP_DIR,
                        "override": "AMAP_HOP_ROUTER_REPO"}]}
        self.ds_commit = repo(amap / "amap-deploy-sandy", {"siblings.json": json.dumps(siblings),
                                                          "amap-sandy.py": STUB_INSTALL})
        self.home = self.root / "sandy-home"
        self.feature = self.home / "features" / "amap"
        (self.feature / "payload" / "codex").mkdir(parents=True)
        launcher = self.feature / "payload" / "codex" / "interactive-launch"
        launcher.write_text("old launcher\n")
        launcher.chmod(0o755)
        # The link sorts before nothing it needs, and points at a sibling copied after it
        # ("a-link" < "interactive-launch"), so a copier that follows links fails here.
        (self.feature / "payload" / "codex" / "relay-link").symlink_to("interactive-launch")
        (self.feature / "payload" / "codex" / "a-link").symlink_to("interactive-launch")
        (self.feature / "payload" / "codex").chmod(0o750)
        (self.feature / "feature.json").write_text('{"schema": 1}\n')
        (self.feature / "router.json").write_text('{"instances": {}}\n')
        bindir = self.root / "bin"
        bindir.mkdir()
        self.sandy = bindir / "sandy"
        self.sandy.write_text(STUB_SANDY)
        self.sandy.chmod(0o755)
        self.calls = self.root / "calls"
        self.env = {**{v: "" for v in (*overrides.values(), "AMAP_HOP_ROUTER_REPO")},
                    "AMAP_ROOT": str(amap), "SANDY_HOME": str(self.home), "STUB_CALLS": str(self.calls),
                    "SANDY_BIN": str(self.sandy), "AMAP_EXPECT_DS_COMMIT": self.ds_commit,
                    "STUB_SCHEMA": json.dumps({"manifest": {"top_level_keys": ["schema", "agent_wrapper"]}})}

    # ---- helpers

    def run_(self, *args, **env):
        return subprocess.run([sys.executable, str(LAUNCHER), *args], env={**os.environ, **self.env, **env},
                              capture_output=True, text=True, timeout=60)

    def main_(self, *args, **env):
        """codex_rollout.main in process, with this test's environment."""
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {**self.env, **env}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cr.main(list(args))
        return rc, out.getvalue(), err.getvalue()

    def installs(self):
        return self.calls.read_text().splitlines() if self.calls.exists() else []

    def backups(self):
        d = self.amap / "rollout-backups"
        return sorted(d.iterdir()) if d.exists() else []

    def launcher_text(self):
        return (self.feature / "payload/codex/interactive-launch").read_text()

    def _refused(self, must, *args, **env):
        r = self.run_(*(args or ("apply",)), **env)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(must, r.stderr)
        self.assertEqual(self.installs(), [], "the installer ran after a refused check")
        self.assertEqual(self.launcher_text(), "old launcher\n")
        return r

    # ---- check

    def test_check_passes_on_exact_checkouts_and_only_dry_runs_with_the_same_sandy(self):
        r = self.run_("check")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.installs(), [f"--sandy {self.sandy} install"])
        self.assertIn(f"ok  {HOP_DIR} ", r.stdout)
        self.assertEqual(self.backups(), [])

    def test_another_deployment_commit_refuses(self):
        self._refused("not the reviewed", AMAP_EXPECT_DS_COMMIT="0" * 40)

    def test_no_expected_commit_refuses(self):
        self._refused("set AMAP_EXPECT_DS_COMMIT", AMAP_EXPECT_DS_COMMIT="")

    def test_a_sibling_at_another_commit_refuses(self):
        git(self.amap / "amap-router-local", "commit", "-q", "--allow-empty", "-m", "y")
        self._refused("not the reviewed")

    def test_a_missing_sibling_refuses(self):
        shutil.rmtree(self.amap / HOP_DIR)
        self._refused(f"{HOP_DIR}: no checkout")

    def test_an_edited_tracked_file_refuses(self):
        (self.amap / "amap-connector-codex" / "README").write_text("edited\n")
        self._refused("amap-connector-codex: ")

    def test_an_edit_hidden_by_assume_unchanged_refuses(self):
        d = self.amap / "amap-connector-claude"
        git(d, "update-index", "--assume-unchanged", "README")
        (d / "README").write_text("edited\n")
        self.assertEqual(git(d, "status", "--porcelain"), "", "git status is meant to hide this edit")
        self._refused("is not the committed bytes and modes: README")

    def test_an_edit_hidden_by_skip_worktree_refuses(self):
        d = self.amap / "amap-router-local"
        git(d, "update-index", "--skip-worktree", "README")
        (d / "README").write_text("edited\n")
        self.assertEqual(git(d, "status", "--porcelain"), "")
        self._refused("is not the committed bytes and modes: README")

    def test_a_mode_change_refuses(self):
        (self.amap / "amap-connector-codex" / "README").chmod(0o755)
        self._refused("is not the committed bytes and modes: README")

    def test_an_untracked_module_install_would_deploy_refuses(self):
        (self.amap / "amap-connector-codex" / "src/amap_codex/extra.py").write_text("print('unreviewed')\n")
        self._refused("install would deploy files the reviewed commit does not hold: src/amap_codex/extra.py")

    def test_an_untracked_file_install_does_not_copy_is_left_alone(self):
        (self.amap / "amap-connector-codex" / "NOTES.local").write_text("mine\n")
        r = self.run_("check")
        self.assertEqual(r.returncode, 0, r.stderr)

    def _ds_siblings(self, text):
        ds = self.amap / "amap-deploy-sandy"
        (ds / "siblings.json").write_text(text)
        git(ds, "commit", "-q", "-am", "siblings")
        return git(ds, "rev-parse", "HEAD")

    def test_siblings_json_that_does_not_parse_refuses_rather_than_checking_nothing(self):
        self._refused("cannot read the sibling pins", AMAP_EXPECT_DS_COMMIT=self._ds_siblings("{not json"))

    def test_siblings_json_naming_no_sibling_refuses(self):
        commit = self._ds_siblings(json.dumps({"schema": 1, "siblings": []}))
        self._refused("names no sibling", AMAP_EXPECT_DS_COMMIT=commit)

    def test_siblings_json_without_the_codex_connector_refuses(self):
        doc = json.loads((self.amap / "amap-deploy-sandy" / "siblings.json").read_text())
        doc["siblings"] = [s for s in doc["siblings"] if s["name"] != cr.CODEX_SIBLING]
        self._refused("pins no amap-connector-codex", AMAP_EXPECT_DS_COMMIT=self._ds_siblings(json.dumps(doc)))

    def test_a_source_override_pointing_elsewhere_refuses(self):
        """install honours AMAP_CODEX_CONNECTOR_REPO; it must name the checked checkout or be unset."""
        other = self.root / "other-codex"
        other.mkdir()
        self._refused("AMAP_CODEX_CONNECTOR_REPO is set to", AMAP_CODEX_CONNECTOR_REPO=str(other))

    def test_a_source_override_naming_the_checked_checkout_is_accepted(self):
        r = self.run_("check", AMAP_CODEX_CONNECTOR_REPO=str(self.amap / "amap-connector-codex"))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_sandy_without_agent_wrapper_refuses(self):
        self._refused("does not list agent_wrapper",
                      STUB_SCHEMA=json.dumps({"manifest": {"top_level_keys": ["schema"]}}))

    def test_a_sandy_that_cannot_be_run_refuses(self):
        self._refused("cannot run", SANDY_BIN=str(self.root / "no-such-sandy"))

    def test_a_sandy_that_is_not_executable_refuses_cleanly(self):
        """Any OSError from starting a command is a refusal, not a traceback."""
        self.sandy.chmod(0o644)
        r = self._refused("cannot run")
        self.assertNotIn("Traceback", r.stderr)

    def test_a_host_without_git_refuses(self):
        r = self.run_("apply", PATH=str(self.root / "empty-path"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("cannot run git", r.stderr)
        self.assertEqual(self.installs(), [])

    # ---- apply and rollback, end to end

    def test_apply_backs_up_then_installs_with_the_same_sandy_and_rollback_restores(self):
        r = self.run_("apply")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.installs(), [f"--sandy {self.sandy} install --apply", f"--sandy {self.sandy} verify"])
        self.assertEqual(self.launcher_text(), "new launcher\n")
        b, = self.backups()
        self.assertEqual((b / "payload/codex/interactive-launch").read_text(), "old launcher\n")
        self.assertEqual(os.readlink(b / "payload/codex/relay-link"), "interactive-launch")
        (self.feature / "payload/codex/interactive-launch").chmod(0o644)
        r = self.run_("rollback", str(b))
        self.assertEqual(r.returncode, 0, r.stderr)
        launcher = self.feature / "payload/codex/interactive-launch"
        self.assertEqual(launcher.read_text(), "old launcher\n")
        self.assertEqual(stat.S_IMODE(launcher.stat().st_mode), 0o755)
        self.assertEqual(os.readlink(self.feature / "payload/codex/relay-link"), "interactive-launch")
        aside = [p for p in self.backups() if p.name.endswith("-replaced")]
        self.assertEqual(len(aside), 1)
        self.assertEqual((aside[0] / "payload/codex/interactive-launch").read_text(), "new launcher\n")

    # ---- sandy's features directory holds the feature and nothing of this tool's

    def test_apply_and_rollback_leave_nothing_beside_the_feature_in_sandys_features_directory(self):
        # Sandy reads each directory under features/ as a feature, and on one it refuses
        # mounts none: only the backup's location can put a second entry there.
        r = self.run_("apply")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sorted(os.listdir(self.feature.parent)), ["amap"])
        b, = self.backups()
        r = self.run_("rollback", str(b))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sorted(os.listdir(self.feature.parent)), ["amap"])
        self.assertEqual(len(self.backups()), 2)

    def test_a_backup_directory_left_in_sandys_features_directory_refuses_every_verb(self):
        stray = self.feature.parent / "amap.rollout-backups"
        (stray / "20261024T161750Z").mkdir(parents=True)
        for args in (("check",), ("apply",), ("rollback", str(stray / "20261024T161750Z"))):
            r = self.run_(*args)
            self.assertEqual(r.returncode, 1, args)
            self.assertIn(f"{stray} is in sandy's features directory, so sandy mounts no feature "
                          f"at launch; move its contents to {self.amap / 'rollout-backups'}", r.stderr)
        self.assertEqual(self.installs(), [])
        self.assertEqual(self.launcher_text(), "old launcher\n")

    def test_a_backup_root_inside_sandys_features_directory_refuses(self):
        with self.assertRaises(cr.Refused) as e:
            cr.features_clear(self.feature, self.feature.parent / "elsewhere" / "rollout-backups")
        self.assertIn("is inside sandy's features directory", str(e.exception))
        cr.features_clear(self.feature, self.amap / "rollout-backups")

    def test_a_link_copied_before_its_target_and_a_directory_mode_survive_the_round_trip(self):
        # Copying a link's own metadata is not portable: in a reviewer's confined workspace
        # it resolved the link, so a link copied before its target raised ENOENT. Which
        # entry a directory walk reaches first is not fixed, so here every such call
        # fails, and the copy must make none.
        real = shutil.copystat

        def strict(src, dst, *, follow_symlinks=True):
            if not follow_symlinks and os.path.islink(dst):
                raise FileNotFoundError(2, "No such file or directory", str(dst))
            return real(src, dst, follow_symlinks=follow_symlinks)
        with mock.patch("shutil.copystat", strict):
            rc, out, err = self.main_("apply")
            self.assertEqual(rc, 0, err)
            b, = self.backups()
            self.assertEqual(os.readlink(b / "payload/codex/a-link"), "interactive-launch")
            self.assertEqual(stat.S_IMODE((b / "payload/codex").stat().st_mode), 0o750)
            rc, out, err = self.main_("rollback", str(b))
            self.assertEqual(rc, 0, err)
        self.assertEqual(os.readlink(self.feature / "payload/codex/a-link"), "interactive-launch")
        self.assertEqual(stat.S_IMODE((self.feature / "payload/codex").stat().st_mode), 0o750)

    def test_the_backup_keeps_modes_under_a_restrictive_umask(self):
        r = subprocess.run(["sh", "-c", f'umask 077 && exec "{sys.executable}" "{LAUNCHER}" apply'],
                           env={**os.environ, **self.env}, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        b, = self.backups()
        self.assertEqual(stat.S_IMODE((b / "payload/codex/interactive-launch").stat().st_mode), 0o755)

    def test_an_install_failure_is_a_failure_that_names_the_backup(self):
        r = self.run_("apply", STUB_INSTALL_RC="3")
        self.assertNotEqual(r.returncode, 0)
        b, = self.backups()
        self.assertIn(f"install --apply failed (above); to roll back: amap-codex-rollout.py rollback {b}", r.stderr)
        self.assertNotIn("verify", " ".join(self.installs()))

    def test_a_verify_failure_after_apply_is_a_failure_that_names_the_backup(self):
        r = self.run_("apply", STUB_VERIFY_RC="1")
        self.assertNotEqual(r.returncode, 0)
        b, = self.backups()
        self.assertIn(f"verify reported problems (above) after install --apply; "
                      f"to roll back: amap-codex-rollout.py rollback {b}", r.stderr)
        self.assertNotIn("Applied.", r.stdout)

    # ---- the backup's failure paths, in process: each must stop before the installer runs

    def _backup_refused(self, must, **patches):
        with contextlib.ExitStack() as stack:
            for target, new in patches.items():
                stack.enter_context(mock.patch(target, new))
            rc, out, err = self.main_("apply")
        self.assertEqual(rc, 1)
        self.assertIn(must, err)
        self.assertIn("nothing was installed", err)
        self.assertEqual(self.installs(), [], "the installer ran after a failed backup")
        self.assertEqual(self.launcher_text(), "old launcher\n")

    def test_a_copy_that_fails_stops_before_install(self):
        def failing(src, dst, **kw):
            raise OSError(28, "No space left on device")
        self._backup_refused("No space left on device", **{"codex_rollout.shutil.copy2": failing})

    def test_a_copy_that_truncates_without_failing_stops_before_install(self):
        real = shutil.copy2

        def truncating(src, dst, **kw):
            real(src, dst, **kw)
            if os.path.basename(str(dst)) == "interactive-launch":
                with open(dst, "r+b") as f:
                    f.truncate(3)
            return dst
        self._backup_refused("does not match the live files (payload/codex/interactive-launch)",
                             **{"codex_rollout.shutil.copy2": truncating})

    def test_a_copy_that_drops_a_link_stops_before_install(self):
        def dereferencing(src, dest):
            shutil.copytree(src, dest, symlinks=False) if Path(src).is_dir() else shutil.copy2(src, dest)
        self._backup_refused("does not match the live files (payload/codex/a-link, payload/codex/relay-link)",
                             **{"codex_rollout.copy_entry": dereferencing})

    def test_a_hash_that_fails_stops_before_install(self):
        real = open

        def failing_open(path, *a, **kw):
            if "rollout-backups" in str(path) and str(path).endswith("feature.json"):
                raise OSError(5, "Input/output error")
            return real(path, *a, **kw)
        self._backup_refused("Input/output error", **{"builtins.open": failing_open})

    # ---- rollback's failure paths

    def _backup(self):
        rc, out, err = self.main_("apply")
        self.assertEqual(rc, 0, err)
        b, = self.backups()
        self.calls.unlink()
        return b

    def _rollback_refused(self, b, must):
        rc, out, err = self.main_("rollback", str(b))
        self.assertEqual(rc, 1)
        self.assertIn(must, err)
        self.assertEqual(self.launcher_text(), "new launcher\n")
        self.assertEqual([p for p in self.backups() if p.name.endswith("-replaced")], [],
                         "files were moved aside after a refusal")

    def test_rollback_refuses_a_backup_whose_bytes_changed(self):
        b = self._backup()
        (b / "feature.json").write_text("tampered\n")
        self._rollback_refused(b, "does not match its INVENTORY.json")

    def test_rollback_refuses_a_backup_whose_mode_changed(self):
        b = self._backup()
        (b / "payload/codex/interactive-launch").chmod(0o644)
        self._rollback_refused(b, "does not match its INVENTORY.json")

    def test_rollback_refuses_a_backup_whose_link_changed(self):
        b = self._backup()
        os.remove(b / "payload/codex/relay-link")
        os.symlink("/etc/passwd", b / "payload/codex/relay-link")
        self._rollback_refused(b, "does not match its INVENTORY.json")

    def test_rollback_refuses_a_directory_without_an_inventory(self):
        b = self._backup()
        os.remove(b / cr.INVENTORY)
        self._rollback_refused(b, "holds no readable INVENTORY.json")

    def test_a_restore_copy_that_fails_names_where_the_replaced_files_are(self):
        b = self._backup()

        def failing(src, dest):
            raise OSError(28, "No space left on device")
        with mock.patch("codex_rollout.copy_entry", failing):
            rc, out, err = self.main_("rollback", str(b))
        self.assertEqual(rc, 1)
        aside, = [p for p in self.backups() if p.name.endswith("-replaced")]
        self.assertIn(f"the restore failed ([Errno 28] No space left on device); the replaced files are in {aside}", err)
        self.assertEqual((aside / "payload/codex/interactive-launch").read_text(), "new launcher\n")

    def test_a_restore_that_does_not_match_the_inventory_is_reported(self):
        b = self._backup()
        real = cr.copy_entry

        def truncating(src, dest):
            real(src, dest)
            if Path(dest).name == "feature.json":
                Path(dest).write_text("")
        with mock.patch("codex_rollout.copy_entry", truncating):
            rc, out, err = self.main_("rollback", str(b))
        self.assertEqual(rc, 1)
        self.assertIn("the restored files do not match", err)


class DeployedSetTest(unittest.TestCase):
    """CODEX_DEPLOYED names exactly the files install copies out of the Codex checkout."""

    def test_the_globs_match_codex_payload_sources(self):
        import _workspace
        _workspace.skip_if_incomplete()
        import amap_sandy as prov
        root = _workspace.CODEX_CONNECTOR_ROOT
        sources = {str(src.relative_to(root)) for _, src, _ in prov.codex_payload_sources(root)
                   if root in src.parents}
        globbed = {str(p.relative_to(root)) for pattern in cr.CODEX_DEPLOYED for p in root.glob(pattern)}
        self.assertTrue(sources)
        self.assertEqual(globbed, sources)
