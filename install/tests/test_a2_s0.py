"""S0 after admission (a2_s0), through the runner (a2_main.run) on a staged
runner host with real git repositories: annotated tags on local bare
remotes, the overlay checkout as the private directory, an installer
checkout. Each case breaks one rule and requires that S0 refuse with the
cause that rule names, write a FAIL receipt carrying it, and finish the
manifest so that SUMS verifies."""

import copy
import hashlib
import json
import os
import shutil
import unittest

import a2fix
from a2fix import git
import a2_budget
import a2_args
import a2_locks
import a2_main
import a2_record
from a2_causes import Refusal

NOT_BUILT = a2_main.NOT_BUILT


class Base(unittest.TestCase):
    def setUp(self):
        self.base = a2fix.make_base()
        self.addCleanup(shutil.rmtree, self.base, True)
        self.w = a2fix.World(self.base)
        self.gw = a2fix.GitWorld(self.w)
        self.held = []
        self.addCleanup(lambda: [a2_locks.release(h) for h in self.held])

    def site(self, **over):
        o = self.gw.site_over()
        o.update(over)
        return self.w.site(**o)

    def direct(self, argv=("--loop", "L2"), account="loop", sub="loop"):
        """Locks and a broker record, as an admitting process would leave
        them, for the files as they are on disk now."""
        inv = a2_args.parse(list(argv))
        vms = a2_locks.run_vms(self.w.hosts, inv, account)
        order = a2_locks.lock_order(self.w.root, a2_locks.targets(self.w.hosts, vms), inv.writes_target)
        self.held.append(a2_locks.acquire(order, os.getuid()))
        if not inv.writes_target:
            return "20261116T000000Z-0000aaaa", list(argv)
        b = a2fix.FakeBroker(self.w, sub=sub)
        try:
            shas = []
            for name in ("alpha2.lock", "alpha2.hosts"):
                with open(os.path.join(self.w.private, name), "rb") as f:
                    shas.append(hashlib.sha256(f.read()).hexdigest())
            rid, _ = a2_budget.ask_broker(self.w.root, inv, shas[0], shas[1], "c" * 64, root_uid=os.getuid())
        finally:
            b.close()
        return rid, list(argv)

    def run_s0(self, argv=("--loop", "L2"), **over):
        rid, argv = self.direct(argv)
        site = self.site(**over)
        with self.assertRaises(Refusal) as cm:
            a2_main.run(rid, argv, site)
        self.rid = rid
        return cm.exception

    def run_dir(self):
        return os.path.join(self.w.home, "alpha2-work", "runs", self.rid)

    def receipt(self):
        with open(os.path.join(self.run_dir(), "receipts", "S0--.txt"), "rb") as f:
            facts, _sid, _host, rc = a2_record.parse_receipt(f.read())
        return facts, rc

    def assert_s0_fail(self, cause, **kw):
        e = self.run_s0(**kw)
        self.assertEqual(e.cause, cause)
        facts, rc = self.receipt()
        self.assertEqual((facts["RESULT"], facts["CAUSE"], rc), ("FAIL", cause, e.rc))
        # The manifest is final and the record verifies.
        with open(os.path.join(self.run_dir(), "manifest.json")) as f:
            self.assertEqual(json.load(f)["state"], "final")
        fd = os.open(self.run_dir(), os.O_RDONLY | os.O_DIRECTORY)
        try:
            a2_record.verify_sums(fd)
        finally:
            os.close(fd)
        return e


def _assert_s0_pass(self, e):
    """S0 passed: its receipt is PASS, and the run went on to S1 (which,
    with no terminal in a test, refuses CREDENTIALS.NO_ECHO)."""
    facts, rc = self.receipt()
    self.assertEqual((facts["RESULT"], rc), ("PASS", 0))
    self.assertEqual(e.cause, "CREDENTIALS.NO_ECHO")


Base.assert_s0_pass = _assert_s0_pass


class PassTest(Base):
    def test_s0_passes_then_s1_and_s10_finish_the_record(self):
        e = self.run_s0()
        # S1 refuses here (the test has no terminal: a named cause, rc 2), and
        # S10 still writes its receipt, the final manifest and the summary.
        self.assertEqual((e.cause, e.rc), ("CREDENTIALS.NO_ECHO", 2))
        facts, rc = self.receipt()
        self.assertEqual((facts["RESULT"], rc), ("PASS", 0))
        self.assertEqual(facts["PRIVATE_COMMIT"], git(self.w.private, "rev-parse", "HEAD"))
        self.assertEqual((facts["CUSTODY_LOCKS"], facts["CUSTODY_PLACEMENT"], facts["CUSTODY_STOP"]),
                         ("held", "match", "unset"))
        self.assertEqual(len(facts["ADMISSION_SHA"]), 64)
        with open(os.path.join(self.run_dir(), "manifest.json")) as f:
            man = json.load(f)
        self.assertEqual((man["state"], [s["stage"] for s in man["stages"]]), ("final", ["S0", "S1", "S10"]))
        with open(os.path.join(self.run_dir(), "summary.txt")) as f:
            summary = f.read()
        self.assertTrue(summary.startswith("RESULT FAIL\n"))
        self.assertIn("stage S1 host - rc 2 cause CREDENTIALS.NO_ECHO", summary)
        self.assertTrue(summary.rstrip("\n").splitlines()[-1].startswith("NOT ELIGIBLE: "))
        fd = os.open(self.run_dir(), os.O_RDONLY | os.O_DIRECTORY)
        try:
            a2_record.verify_sums(fd)
        finally:
            os.close(fd)
        # The fetched commits are in the work directory, in the installer's own bare repos.
        for name in ("overlay", "c-router", "c-connector"):
            self.assertTrue(os.path.isdir(os.path.join(self.w.home, "alpha2-work", "fetched", self.rid,
                                                       name + ".git")))


class UnclassifiedTest(Base):
    def test_a_raising_probe_leaves_a_finished_record_and_rc3(self):
        def boom(h):
            raise ValueError("probe broke")
        e = self.assert_s0_fail("PREFLIGHT.UNCLASSIFIED", probe_hub_read=boom)
        self.assertEqual(e.rc, 3)
        facts, rc = self.receipt()
        self.assertEqual(rc, 3)
        # The facts S0 had gathered are kept as the final observed state.
        self.assertEqual(facts["PRIVATE_COMMIT"], git(self.w.private, "rev-parse", "HEAD"))
        self.assertIn("LEAK_CHECK", facts)

    def test_a_failing_s10_still_makes_the_manifest_final(self):
        """If S10 itself fails, the runner makes the manifest final and the
        stop is rc 3 (SUMMARY.UNCLASSIFIED over a named rc-2 cause)."""
        import a2_s10
        orig = a2_s10.run_s10

        def broken(*a, **kw):
            raise ValueError("S10 broke")
        a2_s10.run_s10 = broken
        self.addCleanup(setattr, a2_s10, "run_s10", orig)
        e = self.run_s0()
        self.assertEqual((e.cause, e.rc), ("SUMMARY.UNCLASSIFIED", 3))
        with open(os.path.join(self.run_dir(), "manifest.json")) as f:
            self.assertEqual(json.load(f)["state"], "final")

    def test_a_failure_writing_the_receipt_still_finishes_the_record(self):
        """If S0's own FAIL receipt cannot be written, the runner writes one
        with no facts, makes the manifest final, and exits 3."""
        import a2_record
        orig = a2_record.Run.write_receipt
        calls = []

        def flaky(self_, *a, **kw):
            calls.append(1)
            if len(calls) == 1:
                raise ValueError("render failed")
            return orig(self_, *a, **kw)
        a2_record.Run.write_receipt = flaky
        self.addCleanup(setattr, a2_record.Run, "write_receipt", orig)

        def boom(h):
            raise ValueError("probe broke")
        e = self.assert_s0_fail("PREFLIGHT.UNCLASSIFIED", probe_hub_read=boom)
        self.assertEqual(e.rc, 3)

    def test_garbled_git_output_is_unclassified_free(self):
        """A parse error in git's output inside the overlay checks is caught
        as PRIVATE_SOURCE, not left to escape."""
        import a2_git

        class Garbled(a2_git.Git):
            def diff_tree(self, repo, a, b):
                raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")
        o = self.gw.site_over()
        g = Garbled(o["git"].env, protocols=("file",))
        self.assert_s0_fail("PREFLIGHT.PRIVATE_SOURCE", git=g)


class GitSafetyTest(Base):
    def test_replace_refs_cannot_change_what_s0_reads(self):
        """Replace overlay.commit and HEAD with commits whose trees
        carry a changed alpha2.hosts; HEAD's id is still the tag's."""
        priv = self.w.private
        h = copy.deepcopy(self.w.hosts)
        h["hub"]["domain"] = "elsewhere.example.org"
        p = os.path.join(priv, "alpha2.hosts")
        with open(p, "wb") as f:
            f.write(a2fix.dumps(h))
        blob = git(priv, "hash-object", "-w", "alpha2.hosts")
        for rev in (self.gw.overlay_commit, git(priv, "rev-parse", "HEAD")):
            tree = git(priv, "rev-parse", rev + "^{tree}")
            lines = git(priv, "ls-tree", tree).splitlines()
            new_lines = [ln if not ln.endswith("\talpha2.hosts") else "100644 blob %s\talpha2.hosts" % blob
                         for ln in lines]
            import subprocess
            r = subprocess.run(["/usr/bin/git", "-C", priv, "mktree"], input="\n".join(new_lines) + "\n",
                               env=a2fix.GIT_ENV, capture_output=True, text=True, check=True)
            new_tree = r.stdout.strip()
            parents = git(priv, "rev-list", "--parents", "-n", "1", rev).split()[1:]
            args = []
            for par in parents:
                args += ["-p", par]
            new_commit = git(priv, "commit-tree", new_tree, *args, "-m", "replaced")
            git(priv, "replace", "-f", rev, new_commit)
        git(priv, "read-tree", "HEAD")
        self.assertEqual(git(priv, "status", "--porcelain"), "")
        self.assert_s0_fail("PREFLIGHT.PRIVATE_SOURCE")

    def test_s0_does_not_write_the_checkouts_index(self):
        """git status must not refresh a checkout's index."""
        import time
        idx = {}
        for repo in (self.w.private, self.gw.inst):
            p = os.path.join(repo, ".git", "index")
            os.utime(os.path.join(repo, "alpha2.hosts" if repo == self.w.private else "install/alpha2_install.py"),
                     (time.time() + 5, time.time() + 5))
            with open(p, "rb") as f:
                idx[p] = (f.read(), os.stat(p).st_mtime_ns)
        self.assert_s0_pass(self.run_s0())
        for p, (data, mtime) in idx.items():
            with open(p, "rb") as f:
                self.assertEqual((f.read(), os.stat(p).st_mtime_ns), (data, mtime))

    def test_a_checkouts_fsmonitor_never_runs(self):
        marker = os.path.join(self.base, "fsmonitor-ran")
        script = os.path.join(self.base, "fsmon.sh")
        with open(script, "w") as f:
            f.write("#!/bin/sh\ntouch %s\nexit 1\n" % marker)
        os.chmod(script, 0o755)
        git(self.w.private, "config", "core.fsmonitor", script)
        self.assert_s0_pass(self.run_s0())
        self.assertFalse(os.path.exists(marker))

    def test_a_global_config_in_home_has_no_effect(self):
        """GIT_CONFIG_GLOBAL=/dev/null: a redirect in the run's HOME is not read."""
        attacker = os.path.join(self.base, "attacker.git")
        git(self.base, "init", "-q", "--bare", attacker)
        with open(os.path.join(self.w.home, ".gitconfig"), "w") as f:
            f.write("[url \"%s\"]\n\tinsteadOf = %s\n" % (attacker, self.gw.url_map[self.gw.URLS["router"]]))
        self.assert_s0_pass(self.run_s0())

    def test_the_runner_builds_git_with_the_explicit_env(self):
        import a2_git
        seen = []

        class Recording(a2_git.Git):
            def __init__(self, env, **kw):
                seen.append(dict(env))
                kw["protocols"] = ("file",)
                super().__init__(env, **kw)
        orig = a2_main.a2_git.Git
        a2_main.a2_git.Git = Recording
        self.addCleanup(setattr, a2_main.a2_git, "Git", orig)
        self.assert_s0_pass(self.run_s0(git=None))
        # The fixture builds one Git too; the runner's is the last, and every
        # one is exactly env_for(): nothing from os.environ.
        self.assertTrue(len(seen) >= 2)
        self.assertEqual(seen[-1], a2_git.env_for(self.w.home, ""))
        self.assertNotIn("LC_CTYPE", seen[-1])

    def test_bytes_admitted_not_reread(self):
        """S0 checks the bytes admission read. A change to the file after
        admission (hidden from status by skip-worktree) is not what L6 hashes."""
        import a2_git
        priv = self.w.private
        p = os.path.join(priv, "alpha2.hosts")
        git(priv, "update-index", "--skip-worktree", "alpha2.hosts")

        class Changing(a2_git.Git):
            done = []

            def head(self, repo):
                if repo == priv and not self.done:
                    self.done.append(1)
                    with open(p, "ab") as f:
                        f.write(b"\n")
                return super().head(repo)
        o = self.gw.site_over()
        self.assert_s0_pass(self.run_s0(git=Changing(o["git"].env, protocols=("file",))))


class InterpreterTest(Base):
    def test_version_hash_and_resolved_path(self):
        self.assert_s0_fail("PREFLIGHT.INTERPRETER", version_info=(3, 0, 0))
        for i, key in enumerate(("sha256", "resolved_sha256", "resolved_path")):
            with self.subTest(key=key):
                lock = copy.deepcopy(self.gw.lock)
                lock["interpreter"][key] = "/usr/bin/python9" if key == "resolved_path" else "d" * 64
                self.gw.commit_lock(lock, tag="alpha2-rc1")
                for h in self.held:
                    a2_locks.release(h)
                self.held = []
                self.assert_s0_fail("PREFLIGHT.INTERPRETER")

    def test_manifest_sha_differs_from_the_lock(self):
        lock = copy.deepcopy(self.gw.lock)
        lock["installer"]["sha256"] = "e" * 64
        self.gw.commit_lock(lock)
        self.assert_s0_fail("PREFLIGHT.INTERPRETER")

    def test_installer_checkout_dirty_or_elsewhere(self):
        with open(os.path.join(self.gw.inst, "stray"), "w") as f:
            f.write("x")
        self.assert_s0_fail("PREFLIGHT.INTERPRETER")

    def test_installer_checkout_at_another_commit(self):
        with open(os.path.join(self.gw.inst, "install", "alpha2_install.py"), "a") as f:
            f.write("# more\n")
        git(self.gw.inst, "commit", "-q", "-am", "more")
        self.assert_s0_fail("PREFLIGHT.INTERPRETER")


class PrivateSourceTest(Base):
    def test_untracked_file_makes_it_unclean(self):
        open(os.path.join(self.w.private, "stray"), "w").close()
        self.assert_s0_fail("PREFLIGHT.PRIVATE_SOURCE")

    def test_skip_worktree_cannot_hide_a_changed_hosts(self):
        """The L6 hole: git status reports clean, but the bytes S0 read are
        not HEAD's blob."""
        git(self.w.private, "update-index", "--skip-worktree", "alpha2.hosts")
        h = copy.deepcopy(self.w.hosts)
        h["hub"]["domain"] = "other.example.org"
        p = os.path.join(self.w.private, "alpha2.hosts")
        os.chmod(p, 0o600)
        with open(p, "wb") as f:
            f.write(a2fix.dumps(h))
        self.assertEqual(git(self.w.private, "status", "--porcelain"), "")
        self.assert_s0_fail("PREFLIGHT.PRIVATE_SOURCE")

    def test_assume_unchanged_cannot_hide_a_changed_lock(self):
        git(self.w.private, "update-index", "--assume-unchanged", "alpha2.lock")
        p = os.path.join(self.w.private, "alpha2.lock")
        with open(p, "ab") as f:
            f.write(b"\n")
        self.assert_s0_fail("PREFLIGHT.PRIVATE_SOURCE")

    def test_head_not_descended_from_overlay_commit(self):
        lock = copy.deepcopy(self.gw.lock)
        lock["overlay"]["commit"] = lock["components"][0]["commit"]
        self.gw.commit_lock(lock)
        self.assert_s0_fail("PREFLIGHT.PRIVATE_SOURCE")

    def test_pinned_commit_present_but_not_an_ancestor(self):
        """A side commit with overlay.commit's exact tree: the tree rule
        alone would pass, so only the descent rule can refuse."""
        priv = self.w.private
        tree = git(priv, "rev-parse", self.gw.overlay_commit + "^{tree}")
        side = git(priv, "commit-tree", tree, "-m", "side")
        lock = copy.deepcopy(self.gw.lock)
        lock["overlay"]["commit"] = side
        self.gw.commit_lock(lock)
        self.assertEqual(git(priv, "diff-tree", "--no-renames", "-r", "--name-only", side, "HEAD"), "alpha2.lock")
        # A graft in the checkout forges the ancestry there (GIT_NO_REPLACE_OBJECTS
        # does not disable grafts); S0 reads ancestry only in the fetched bare
        # repository, so the forgery is never seen.
        head = git(priv, "rev-parse", "HEAD")
        with open(os.path.join(priv, ".git", "info", "grafts"), "w") as f:
            f.write("%s %s\n" % (head, side))
        env = dict(a2fix.GIT_ENV, GIT_NO_REPLACE_OBJECTS="1")
        import subprocess
        # Captured: this git warns on stderr that grafts are deprecated.
        r = subprocess.run(["/usr/bin/git", "-C", priv, "merge-base", "--is-ancestor", side, head], env=env,
                           capture_output=True)
        self.assertEqual(r.returncode, 0)          # the checkout believes the forgery
        self.assert_s0_fail("PREFLIGHT.PRIVATE_SOURCE")

    def test_another_path_changed_since_overlay_commit(self):
        with open(os.path.join(self.w.private, "notes.txt"), "w") as f:
            f.write("n\n")
        git(self.w.private, "add", "notes.txt")
        self.gw.commit_lock(self.gw.lock)
        self.assert_s0_fail("PREFLIGHT.PRIVATE_SOURCE")

    def test_a_rename_into_alpha2_lock_is_two_changes(self):
        """With renames on, 'notes.txt -> alpha2.lock' would list one path."""
        priv = self.w.private
        git(priv, "rm", "-q", "alpha2.lock")
        git(priv, "commit", "-q", "-m", "drop lock")
        lock_bytes = a2fix.dumps(self.gw.lock)
        with open(os.path.join(priv, "notes.txt"), "wb") as f:
            f.write(lock_bytes)
        git(priv, "add", "notes.txt")
        git(priv, "commit", "-q", "-m", "notes")
        lock = copy.deepcopy(self.gw.lock)
        lock["overlay"]["commit"] = git(priv, "rev-parse", "HEAD")
        git(priv, "mv", "notes.txt", "alpha2.lock")
        with open(os.path.join(priv, "alpha2.lock"), "wb") as f:
            f.write(a2fix.dumps(lock))
        os.chmod(os.path.join(priv, "alpha2.lock"), 0o600)
        git(priv, "add", "alpha2.lock")
        git(priv, "commit", "-q", "-m", "rename")
        git(priv, "tag", "-f", "-a", "alpha2-rc1", "-m", "t")
        git(priv, "push", "-q", "-f", self.gw.url_map[self.gw.URLS["overlay"]], "HEAD:refs/heads/main",
            "+refs/tags/alpha2-rc1")
        self.assert_s0_fail("PREFLIGHT.PRIVATE_SOURCE")

    def test_mode_only_change_to_hosts(self):
        p = os.path.join(self.w.private, "alpha2.hosts")
        git(self.w.private, "update-index", "--chmod=+x", "alpha2.hosts")
        os.chmod(p, 0o700)
        git(self.w.private, "commit", "-q", "-m", "mode")
        os.chmod(p, 0o700)
        lock = copy.deepcopy(self.gw.lock)
        self.gw.commit_lock(lock)
        os.chmod(p, 0o600)
        git(self.w.private, "update-index", "--chmod=+x", "alpha2.hosts")
        self.assert_s0_fail("PREFLIGHT.PRIVATE_SOURCE")

    def test_tag_on_overlay_commit_not_on_head(self):
        priv = self.w.private
        git(priv, "tag", "-f", "-a", "alpha2-rc1", "-m", "t", self.gw.overlay_commit)
        git(priv, "push", "-q", "-f", self.gw.url_map[self.gw.URLS["overlay"]], "+refs/tags/alpha2-rc1")
        self.assert_s0_fail("PREFLIGHT.PRIVATE_SOURCE")

    def test_tag_on_a_same_tree_commit_that_is_not_head(self):
        """The tag peels to a commit with HEAD's exact tree and parent but a
        different id: every tree, blob and ancestry rule would pass, so only
        rule 1 (the tag peels to HEAD) can refuse."""
        priv = self.w.private
        tree = git(priv, "rev-parse", "HEAD^{tree}")
        parent = git(priv, "rev-parse", "HEAD^")
        other = git(priv, "commit-tree", tree, "-p", parent, "-m", "same tree, other commit")
        git(priv, "tag", "-f", "-a", "alpha2-rc1", "-m", "t", other)
        git(priv, "push", "-q", "-f", self.gw.url_map[self.gw.URLS["overlay"]], other + ":refs/heads/other",
            "+refs/tags/alpha2-rc1")
        self.assert_s0_fail("PREFLIGHT.PRIVATE_SOURCE")

    def test_lightweight_tag_refused(self):
        priv = self.w.private
        git(priv, "tag", "-d", "alpha2-rc1")
        git(priv, "tag", "alpha2-rc1")
        git(priv, "push", "-q", "-f", self.gw.url_map[self.gw.URLS["overlay"]], "+refs/tags/alpha2-rc1")
        self.assert_s0_fail("PREFLIGHT.PRIVATE_SOURCE")

    def test_a_tail_matching_ref_is_not_the_tag(self):
        """refs/tags/x/refs/tags/<tag> is not refs/tags/<tag>."""
        bare = self.gw.url_map[self.gw.URLS["overlay"]]
        oid = git(bare, "rev-parse", "refs/tags/alpha2-rc1")
        git(bare, "update-ref", "refs/tags/x/refs/tags/alpha2-rc1", oid)
        git(bare, "tag", "-d", "alpha2-rc1")
        self.assert_s0_fail("PREFLIGHT.PRIVATE_SOURCE")

    def test_local_tag_only_is_not_the_remote_s(self):
        lock = copy.deepcopy(self.gw.lock)
        lock["overlay"]["tag"] = "alpha2-rc2"
        for c in lock["components"]:
            c["tag"] = "alpha2-rc2"
        self.gw.commit_lock(lock, push_tag=False)
        git(self.w.private, "tag", "-a", "alpha2-rc2", "-m", "local only")
        self.assert_s0_fail("PREFLIGHT.PRIVATE_SOURCE")

    def test_overlay_remote_unreachable_is_repo_access(self):
        over = self.gw.site_over()["repo_url_map"]
        over[self.gw.URLS["overlay"]] = os.path.join(self.base, "no-such-remote.git")
        e = self.assert_s0_fail("PREFLIGHT.REPO_ACCESS", repo_url_map=over)
        self.assertEqual(e.detail, "repository: overlay")


class L7Test(Base):
    def test_mode_allows_others(self):
        os.chmod(os.path.join(self.w.private, "alpha2.hosts"), 0o604)
        e = self.assert_s0_fail("PREFLIGHT.LEAK_HOSTS")
        self.assertEqual(e.detail, "check L7 at $")

    def test_under_a_sandbox_mount_root(self):
        e = self.assert_s0_fail("PREFLIGHT.LEAK_LOCK", sandbox_mount_roots=(self.base,))
        self.assertEqual(e.detail, "check L7 at $")

    def test_a_symlinked_deny_root_still_covers(self):
        link = os.path.join(self.base, "link-to-base")
        os.symlink(self.base, link)
        self.assert_s0_fail("PREFLIGHT.LEAK_LOCK", sandbox_mount_roots=(link,))

    def test_a_symlinked_private_dir_is_resolved(self):
        """The file's own path is resolved: reached through a symlink, it is
        still under the deny root that holds the real directory."""
        link = os.path.join(self.base, "private-link")
        os.symlink(self.w.private, link)
        self.assert_s0_fail("PREFLIGHT.LEAK_LOCK", private_dir=link,
                            sandbox_mount_roots=(self.w.private,))

    def test_unset_deny_list_refuses(self):
        self.assert_s0_fail("PREFLIGHT.LEAK_LOCK", sandbox_mount_roots=None)


class LiveDeployTest(Base):
    def test_work_dir_is_or_contains_the_live_deploy(self):
        work = os.path.join(self.w.home, "alpha2-work")
        for live in (work, os.path.join(work, "x"), self.w.home):
            with self.subTest(live=live):
                for h in self.held:
                    a2_locks.release(h)
                self.held = []
                self.assert_s0_fail("PREFLIGHT.LIVE_DEPLOY", live_deploy_paths=(live,))

    def test_unset_refuses(self):
        self.assert_s0_fail("PREFLIGHT.LIVE_DEPLOY", live_deploy_paths=None)


class FetchTest(Base):
    def push_tag(self, name, *tag_args):
        work = os.path.join(self.base, "work-" + name)
        git(work, "tag", "-d", "alpha2-rc1")
        git(work, *tag_args)
        git(work, "push", "-q", "-f", self.gw.url_map[self.gw.URLS[name]], "+refs/tags/alpha2-rc1")

    def test_component_tag_absent(self):
        git(self.gw.url_map[self.gw.URLS["router"]], "tag", "-d", "alpha2-rc1")
        self.assert_s0_fail("PREFLIGHT.FETCH")

    def test_component_tag_on_another_commit(self):
        work = os.path.join(self.base, "work-router")
        git(work, "commit", "-q", "--allow-empty", "-m", "later")
        self.push_tag("router", "tag", "-a", "alpha2-rc1", "-m", "moved")
        e = self.assert_s0_fail("PREFLIGHT.FETCH")
        self.assertEqual(e.detail, "repository: router")

    def test_component_lightweight_tag(self):
        self.push_tag("router", "tag", "alpha2-rc1")
        self.assert_s0_fail("PREFLIGHT.FETCH")

    def test_component_remote_unreachable(self):
        over = self.gw.site_over()["repo_url_map"]
        over[self.gw.URLS["connector"]] = os.path.join(self.base, "gone.git")
        e = self.assert_s0_fail("PREFLIGHT.REPO_ACCESS", repo_url_map=over)
        self.assertEqual(e.detail, "repository: connector")

    def run_prepared(self, prep):
        """direct(), then prep(rid) before the runner starts."""
        rid, argv = self.direct()
        prep(rid)
        with self.assertRaises(Refusal) as cm:
            a2_main.run(rid, argv, self.site())
        self.rid = rid
        return cm.exception

    def seed_redirect(self, path):
        """A bare repository whose local config redirects the router's
        pinned URL to an attacker remote carrying a tag on another commit."""
        attacker = os.path.join(self.base, "attacker.git")
        git(self.base, "init", "-q", "--bare", attacker)
        work = os.path.join(self.base, "work-router")
        git(work, "commit", "-q", "--allow-empty", "-m", "evil")
        git(work, "tag", "-f", "-a", "alpha2-rc1", "-m", "evil")
        git(work, "push", "-q", attacker, "HEAD:refs/heads/main", "+refs/tags/alpha2-rc1")
        git(work, "reset", "-q", "--hard", "HEAD~1")
        git(work, "tag", "-f", "-a", "alpha2-rc1", "-m", "good")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        git(self.base, "init", "-q", "--bare", path)
        git(path, "config", "url." + attacker + ".insteadOf", self.gw.url_map[self.gw.URLS["router"]])

    def test_preseeded_repo_in_this_runs_fetch_dir_refuses(self):
        work = os.path.join(self.w.home, "alpha2-work")
        e = self.run_prepared(lambda rid: self.seed_redirect(os.path.join(work, "fetched", rid, "router.git")))
        self.assertEqual(e.cause, "PREFLIGHT.FETCH")

    def test_a_shared_repo_with_a_redirect_is_never_used(self):
        """A repository left at the old shared path, with a local insteadOf,
        has no effect: every run fetches into a fresh directory."""
        work = os.path.join(self.w.home, "alpha2-work")
        os.makedirs(os.path.join(work, "fetched"), 0o700)
        self.seed_redirect(os.path.join(work, "fetched", "router.git"))
        e = self.run_prepared(lambda rid: None)
        self.assert_s0_pass(e)

    def test_fetched_with_a_loose_mode_refuses(self):
        work = os.path.join(self.w.home, "alpha2-work")
        for mode in (0o755, 0o777):
            with self.subTest(mode=oct(mode)):
                for h in self.held:
                    a2_locks.release(h)
                self.held = []
                p = os.path.join(work, "fetched")
                if not os.path.isdir(p):
                    os.mkdir(p)
                os.chmod(p, mode)
                e = self.run_prepared(lambda rid: None)
                self.assertEqual(e.cause, "PREFLIGHT.FETCH")

    def test_symlinked_fetched_or_run_dir_refuses(self):
        work = os.path.join(self.w.home, "alpha2-work")
        elsewhere = os.path.join(self.base, "elsewhere")
        os.mkdir(elsewhere, 0o700)
        os.symlink(elsewhere, os.path.join(work, "fetched"))
        e = self.run_prepared(lambda rid: None)
        self.assertEqual(e.cause, "PREFLIGHT.FETCH")
        self.assertEqual(os.listdir(elsewhere), [])
        os.unlink(os.path.join(work, "fetched"))
        for h in self.held:
            a2_locks.release(h)
        self.held = []
        os.mkdir(os.path.join(work, "fetched"), 0o700)
        e = self.run_prepared(lambda rid: os.symlink(elsewhere, os.path.join(work, "fetched", rid)))
        self.assertEqual(e.cause, "PREFLIGHT.FETCH")
        self.assertEqual(os.listdir(elsewhere), [])

    def test_file_transport_refused_by_the_installers_git(self):
        """The runner's own Git allows ssh and https only."""
        import a2_git
        g = a2_git.Git(a2_git.env_for(self.w.home))
        self.assert_s0_fail("PREFLIGHT.REPO_ACCESS", git=g)


class ProbeAndCustodyTest(Base):
    def test_each_probe(self):
        for cause, slot in (("PREFLIGHT.MAC_TOOLS", "probe_tools"),
                            ("PREFLIGHT.NET_RUNTIME", "probe_net_runtime"),
                            ("PREFLIGHT.KEEP_AWAKE", "probe_keep_awake"),
                            ("PREFLIGHT.TARGET_ACCESS", "probe_target_access"),
                            ("PREFLIGHT.HUB_READ", "probe_hub_read"),
                            ("PREFLIGHT.OPERATOR_ROUTE", "probe_operator_route")):
            with self.subTest(slot=slot):
                for h in self.held:
                    a2_locks.release(h)
                self.held = []
                self.assert_s0_fail(cause, **{slot: lambda h: "UNOBSERVED"})

    def test_survey_only_for_l3_or_bare(self):
        self.assert_s0_pass(self.run_s0(probe_survey=lambda h: "UNOBSERVED"))

    def test_placement_differs_or_unobserved_is_custody(self):
        for ans in ("differs", "UNOBSERVED", "weird"):
            with self.subTest(ans=ans):
                for h in self.held:
                    a2_locks.release(h)
                self.held = []
                self.assert_s0_fail("RUNNER.CUSTODY", probe_placement=lambda h, a=ans: a)

    def test_stop_set_during_s0_is_handoff(self):
        stop = os.path.join(self.w.root, "stop.d", "monitor", "stop")

        def setting_probe(h):
            open(stop, "w").close()
            return "ok"
        self.assert_s0_fail("PREFLIGHT.HANDOFF", probe_hub_read=setting_probe)


if __name__ == "__main__":
    unittest.main()
