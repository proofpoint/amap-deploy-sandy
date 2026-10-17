"""host_steps.partition-fetch (d3.3 §5(d) §1): the weekly job's bundle from
the pinned commit, as root, under git_env and the -c set, through a private
git-exec holding exactly two links to the judged targets; four commands,
each a capped child in its own process group, proven empty before release.

Root is mapped to this test's uid. The stub git is a real executable at a
recorded path that logs its argv, environment and git-exec as it sees them
and answers from stub.json beside it, since the profile leaves it nothing
else to read. Phase A's judge is replaced where the row is not about it;
the image-rule rows run the real one. The real-git rows clone a local
fixture with the two accommodations §1.7 names, which are outside the https
closure and prove nothing about it."""

import fcntl
import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest

import host_steps as hs

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
PIN = "c" * 40
URL = "https://github.com/proofpoint/amap-deploy-sandy"
REAL_GIT = shutil.which("git")
REAL_HELPER = "/usr/lib/git-core/git-remote-https"
REAL_UPLOAD = "/usr/lib/git-core/git-upload-pack"

STUB = r'''#!{py} -I
import json, os, sys, time
here = os.path.dirname(os.path.realpath(__file__))
cfg = json.load(open(os.path.join(here, "stub.json")))
args, i = [], 1
while i < len(sys.argv):
    if sys.argv[i] == "-c":
        i += 2
        continue
    args.append(sys.argv[i])
    i += 1
src = None
if args[0] == "-C":
    src, args = args[1], args[2:]
cmd = args[0]
key = cmd
if cmd == "cat-file":
    key = "cat-file -t" if args[1] == "-t" else "blob:" + args[2].split(":", 1)[1]
gx = os.environ.get("GIT_EXEC_PATH", "")
try:
    st = os.lstat(gx)
    seen = {{"entries": sorted(os.listdir(gx)), "mode": st.st_mode & 0o7777, "uid": st.st_uid,
             "links": {{n: os.readlink(os.path.join(gx, n)) for n in os.listdir(gx)}}}}
except OSError:
    seen = None
with open(os.path.join(here, "log.jsonl"), "a") as f:
    f.write(json.dumps({{"argv0": sys.argv[0], "argv": sys.argv[1:], "key": key, "env": dict(os.environ),
                        "cwd": os.getcwd(), "git_exec": seen, "pgid": os.getpgid(0), "pid": os.getpid()}}) + "\n")
act = cfg.get("act", {{}}).get(key, {{}})
if act.get("late_write"):
    if os.fork() == 0:
        time.sleep(act["late_write"])
        with open(os.path.join(cfg["src"], "LATE"), "w") as f:
            f.write("late")
        os._exit(0)
if act.get("close_and_hang"):
    os.close(1)
    os.close(2)
    time.sleep(3600)
if act.get("hang"):
    time.sleep(3600)
if act.get("stderr"):
    sys.stderr.buffer.write(b"e" * act["stderr"])
    sys.stderr.flush()
if act.get("fail"):
    sys.stderr.write("stub refuses\n")
    sys.exit(1)
if "stdout" in act:
    out = act["stdout"].encode("latin-1")
elif cmd == "clone":
    os.mkdir(args[-1])
    out = b""
elif key == "cat-file -t":
    out = b"commit\n"
elif key.startswith("blob:"):
    out = cfg["files"][key[5:]].encode("utf-8")
elif cmd == "ls-tree":
    names = args[args.index("--") + 1:]
    out = b"".join(("%s %s %s\t%s" % (cfg.get("modes", {{}}).get(n, "100644"), cfg.get("kinds", {{}}).get(n, "blob"),
                                      "0" * 40, n)).encode() + b"\0" for n in names if n in cfg["files"])
else:
    out = b""
sys.stdout.buffer.write(out)
sys.stdout.flush()
'''

FILES = {hs.LAUNCHER: "print('weekly')\n", "root_trust.py": "X = 1\n",
         hs.CLOSURE: f"{hs.LAUNCHER}\nroot_trust.py\n"}


class Fetch(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.d = os.path.realpath(t.name)
        self.exec = os.path.join(self.d, "exec")
        os.mkdir(self.exec, 0o700)
        os.chmod(self.exec, 0o700)
        self.tools = os.path.join(self.d, "tools")
        os.mkdir(self.tools)
        self.git = os.path.join(self.tools, "git")
        self.helper = os.path.join(self.tools, "git-remote-https")
        with open(self.git, "w") as f:
            f.write(STUB.format(py=sys.executable))
        os.chmod(self.git, 0o755)
        with open(self.helper, "w") as f:
            f.write("not used\n")
        os.chmod(self.helper, 0o755)
        self.patch("ROOT_UID", os.getuid())
        self.patch("ROOT_GID", os.getgid())
        self.patch("_ancestor_ok", lambda st: True)
        self.judged = []
        self.patch("judge", lambda argv0, also=(), recorded=(), **k: (self.judged.append((argv0, list(also),
                                                                                           list(recorded))),
                                                                       hs.Judgment([], "clean"))[1])
        self.stub()

    def patch(self, name, value):
        self.addCleanup(setattr, hs, name, getattr(hs, name))
        setattr(hs, name, value)

    def stub(self, files=None, **cfg):
        cfg.setdefault("files", dict(FILES if files is None else files))
        cfg.setdefault("src", os.path.join(self.exec, hs.SRC_NEW))
        with open(os.path.join(self.tools, "stub.json"), "w") as f:
            json.dump(cfg, f)

    def calls(self):
        try:
            with open(os.path.join(self.tools, "log.jsonl")) as f:
                return [json.loads(l) for l in f]
        except FileNotFoundError:
            return []

    def fetch(self, pin=PIN, popen=subprocess.Popen, git=None, helper=None):
        return hs.partition_fetch(self.exec, pin, URL, git or self.git, helper or self.helper, popen=popen)

    def refused(self, exc, fn, words=""):
        """`fn` refuses with `exc` naming `words`; anything else, raised or
        returned, fails the row rather than erroring it."""
        try:
            got = fn()
        except exc as e:
            self.assertIn(words, str(e))
            return
        except Exception as e:  # a mutant's other path is a failure of this row, not an error
            self.fail(f"refused with {e!r}, not {exc.__name__}")
        self.fail(f"accepted ({got!r})")

    def bundle(self):
        b = os.path.join(self.exec, hs.BUNDLE)
        out = {}
        for n in sorted(os.listdir(b)):
            with open(os.path.join(b, n), "rb") as f:
                out[n] = f.read()
        return out

    def live_bundle(self):
        """A verified bundle already in place, as a previous fetch left it."""
        self.fetch()
        os.unlink(os.path.join(self.tools, "log.jsonl"))
        return self.bundle()

    def staging(self):
        return sorted(n for n in os.listdir(self.exec) if n not in (hs.BUNDLE, "lock", hs.EMPTY_HOME))


class PositiveRows(Fetch):
    def test_a_fresh_install_writes_exactly_the_closure_the_manifest_and_pin_and_leaves_no_staging(self):
        self.assertEqual(self.fetch(), 0)
        want = {n: d.encode() for n, d in FILES.items()}
        want[hs.PIN] = f"{PIN}\n".encode()
        self.assertEqual(self.bundle(), want)
        self.assertEqual(self.staging(), [], "src.new, git-exec and git.pgid are gone")
        self.assertEqual(os.listdir(os.path.join(self.exec, hs.EMPTY_HOME)), [])
        fd = os.open(os.path.join(self.exec, "lock"), os.O_RDWR)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_every_call_runs_under_exactly_git_env_with_git_exec_root_only_and_two_links(self):
        self.fetch()
        calls = self.calls()
        self.assertTrue(calls)
        for c in calls:
            with self.subTest(key=c["key"]):
                self.assertEqual(c["env"], hs.git_env(self.exec))
                self.assertEqual(c["cwd"], os.path.join(self.exec, hs.EMPTY_HOME))
                self.assertEqual(c["git_exec"], {"entries": ["git", "git-remote-https"], "mode": 0o700,
                                                 "uid": os.getuid(),
                                                 "links": {"git": self.git, "git-remote-https": self.helper}})
                self.assertEqual(c["pgid"], c["pid"], "each child leads its own process group")

    def test_the_argvs_are_exactly_the_four_commands(self):
        self.fetch()
        g = [os.path.join(self.exec, hs.GIT_EXEC, "git")]
        src = os.path.join(self.exec, hs.SRC_NEW)
        names = [hs.LAUNCHER, "root_trust.py"]
        want = [["clone", "--no-checkout", "--quiet", "--template=", "--", URL, src],
                ["-C", src, "cat-file", "-t", PIN],
                ["-C", src, "cat-file", "blob", f"{PIN}:{hs.CLOSURE}"],
                ["-C", src, "ls-tree", "-z", PIN, "--", *names]] + \
            [["-C", src, "cat-file", "blob", f"{PIN}:{n}"] for n in names]
        self.assertEqual([[c["argv0"]] + c["argv"] for c in self.calls()], [g + list(hs.GIT_CONFIG) + w for w in want])

    def test_git_env_is_built_from_nothing_inherited(self):
        os.environ["AMAP_FETCH_PROBE"] = "1"
        self.addCleanup(os.environ.pop, "AMAP_FETCH_PROBE")
        env = hs.git_env("/opt/ex/exec")
        self.assertEqual(env, {"PATH": "/opt/ex/exec/git-exec", "GIT_EXEC_PATH": "/opt/ex/exec/git-exec", "LC_ALL": "C",
                               "HOME": "/opt/ex/exec/empty-home", "XDG_CONFIG_HOME": "/opt/ex/exec/empty-home",
                               "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_ATTR_NOSYSTEM": "1",
                               "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_EDITOR": ":"})

    def test_the_config_set_pins_the_protocols_hooks_and_templates(self):
        c = dict(a.split("=", 1) for a in hs.GIT_CONFIG[1::2])
        self.assertEqual(hs.GIT_CONFIG[0::2], ("-c",) * len(c))
        self.assertEqual(c, {"core.hooksPath": "/dev/null", "core.fsmonitor": "false",
                             "core.attributesFile": "/dev/null", "core.pager": "cat", "core.askPass": "",
                             "core.sshCommand": "", "credential.helper": "", "init.templateDir": "",
                             "protocol.allow": "never", "protocol.https.allow": "always",
                             "uploadpack.packObjectsHook": ""})

    def test_a_stale_git_exec_with_wrong_links_is_replaced_and_passes(self):
        gx = os.path.join(self.exec, hs.GIT_EXEC)
        os.mkdir(gx)
        os.symlink("/usr/bin/git", os.path.join(gx, "git"))
        os.symlink("/bin/sh", os.path.join(gx, "sh"))
        for n in (hs.SRC_NEW, hs.BUNDLE_NEW):
            os.mkdir(os.path.join(self.exec, n))
        self.assertEqual(self.fetch(), 0)
        self.assertEqual(self.calls()[0]["git_exec"]["links"], {"git": self.git, "git-remote-https": self.helper})

    def test_the_lock_is_taken_once(self):
        taken = []
        real = hs._take_partition_lock
        self.patch("_take_partition_lock", lambda efd: (taken.append(1), real(efd))[1])
        self.assertEqual(self.fetch(), 0)
        self.assertEqual(taken, [1])


class PhaseRows(Fetch):
    def test_phase_a_judges_exactly_the_two_targets_before_any_staging_change(self):
        stale = os.path.join(self.exec, hs.SRC_NEW)
        os.mkdir(stale)
        self.patch("judge", lambda argv0, also=(), recorded=(), **k: (self.judged.append(list(also)),
                                                                       hs.Judgment(["x is the operator's"], "tools"))[1])
        with self.assertRaisesRegex(hs.Untrusted, "operator's"):
            self.fetch()
        self.assertEqual((self.judged, self.calls()), ([[self.git, self.helper]], []))
        self.assertTrue(os.path.isdir(stale), "Phase A refuses before step 4 touches staging")
        self.assertFalse(os.path.exists(os.path.join(self.exec, hs.GIT_EXEC)))

    def tamper(self, how):
        real = hs._phase_b

        def tampered(efd, made, git, helper):
            how(os.path.join(self.exec, hs.GIT_EXEC))
            return real(efd, made, git, helper)
        self.patch("_phase_b", tampered)
        with self.assertRaises(hs.Untrusted):
            self.fetch()
        self.assertEqual(self.calls(), [], "Phase B refuses before the first git call")
        self.assertEqual(self.staging(), [], "the scaffolding Phase B checked is removed")

    def test_a_link_naming_another_git_is_refused(self):
        def relink(gx):
            os.unlink(os.path.join(gx, "git"))
            os.symlink("/usr/bin/git", os.path.join(gx, "git"))
        self.tamper(relink)

    def test_a_helper_link_naming_another_file_is_refused(self):
        def relink(gx):
            os.unlink(os.path.join(gx, "git-remote-https"))
            os.symlink(self.git, os.path.join(gx, "git-remote-https"))
        self.tamper(relink)

    def test_a_third_entry_is_refused(self):
        self.tamper(lambda gx: os.symlink("/bin/sh", os.path.join(gx, "sh")))

    def test_a_git_exec_swapped_after_its_mkdir_is_refused(self):
        def swap(gx):
            os.rename(gx, gx + ".old")
            os.mkdir(gx, 0o700)
            os.symlink(self.git, os.path.join(gx, "git"))
            os.symlink(self.helper, os.path.join(gx, "git-remote-https"))
            shutil.rmtree(gx + ".old")
        self.tamper(swap)

    def test_a_git_exec_others_can_enter_is_refused(self):
        self.tamper(lambda gx: os.chmod(gx, 0o755))

    def test_trusted_exec_never_admits_the_alias_spelling(self):
        """The allowlist does not widen: the private alias is not a tool the
        document records, so trusted-exec refuses it as argv[0] and as --also."""
        alias = os.path.join(self.exec, hs.GIT_EXEC, "git")
        self.patch("judge", JUDGE)
        self.patch("_bound", lambda argv: None)
        for argv, also in (([alias, "--version"], []), ([sys.executable, "-I", "-S", "-B", "w"], [alias])):
            with self.subTest(argv=argv[0], also=also):
                with self.assertRaisesRegex(hs.Tooling, "is not a tool the document records"):
                    hs.trusted_exec(argv, execv=lambda *a: self.fail("exec"), platform="linux",
                                    tools=[self.git, self.helper, sys.executable], also=also)

    def test_the_verb_takes_its_targets_from_its_own_arguments_and_judges_a_same_basename_other(self):
        """A --git (or helper) of the right basename that is not the recorded
        file is judged in Phase A like any other: refused, no git call."""
        recorded = {self.git, self.helper, sys.executable}

        def tool(p):
            if p not in recorded:
                raise hs.Tooling(f"{p} is not root's alone")
            return p
        for which in ("git", "helper"):
            with self.subTest(which=which):
                other = os.path.join(self.d, "other", "git" if which == "git" else "git-remote-https")
                os.makedirs(os.path.dirname(other), exist_ok=True)
                shutil.copy(self.git if which == "git" else self.helper, other)
                self.patch("judge", JUDGE)
                self.patch("_trusted_tool", tool)
                self.patch("_bound", lambda argv: None)
                kw = {"git": other} if which == "git" else {"helper": other}
                with self.assertRaises(hs.Untrusted):
                    self.fetch(**kw)
                self.assertEqual(self.calls(), [])


JUDGE = hs.judge


class ImageRuleRows(Fetch):
    """Phase A's real judge: a helper that is not a native image is refused
    before any git call, which is what closes git's ENOEXEC retry through
    its SHELL_PATH (d3.3 §5(d) §1.3)."""

    def test_a_text_or_shebang_helper_is_refused_in_phase_a(self):
        self.patch("judge", JUDGE)
        self.patch("_trusted_tool", lambda p: p)
        self.patch("_bound", lambda argv: None)
        self.patch("closure_problems", lambda c, platform=None, seen=None: [])
        self.patch("acl_problems", lambda paths, platform=None: [])
        self.patch("loader_dirs", lambda platform=None: [])
        for body in ("echo hi\n", "#!/bin/sh\necho hi\n"):
            with self.subTest(body=body[:9]):
                with open(self.helper, "w") as f:
                    f.write(body)
                with self.assertRaisesRegex(hs.Untrusted, "ELF|Mach-O"):
                    self.fetch(git=REAL_GIT)
                self.assertEqual(self.calls(), [])


class ArgumentRows(Fetch):
    def test_only_a_40_hex_lowercase_pin_is_accepted(self):
        self.assertEqual(self.fetch(pin="0123456789abcdef0123456789abcdef01234567"), 0)
        for pin in ("a" * 64, "a" * 39, "A" * 40, "g" * 40, "a" * 40 + "\n"):
            with self.subTest(pin=pin):
                self.refused(hs.Tooling, lambda: self.fetch(pin=pin), "40-hex")

    def test_the_repo_must_be_a_plain_https_url(self):
        for repo in ("http://example.org/x", "https://u@example.org/x", "file:///tmp/x", "-https://example.org/x",
                     "https://example.org/x y", "ext::sh"):
            with self.subTest(repo=repo):
                with self.assertRaisesRegex(hs.Tooling, "https"):
                    hs.partition_fetch(self.exec, PIN, repo, self.git, self.helper)
        self.assertEqual(self.judged, [])

    def test_the_targets_are_absolute_with_their_own_basenames(self):
        for git, helper in (("git", self.helper), (self.helper, self.helper), (self.git, self.git)):
            with self.subTest(git=git, helper=helper):
                with self.assertRaises(hs.Tooling):
                    hs.partition_fetch(self.exec, PIN, URL, git, helper)

    def test_the_verb_parses_only_its_own_options_and_maps_each_refusal_to_its_exit(self):
        good = ["partition-fetch", "--git", self.git, "--git-remote-https", self.helper, "--exec-root", self.exec,
                "--pin", PIN, "--repo", URL]
        self.assertEqual(hs.main(good), 0)
        self.assertEqual(hs.main(good[:-2]), hs.EXIT_TOOLING)
        self.assertEqual(hs.main(good[:-2] + ["--other", URL]), hs.EXIT_TOOLING)
        self.patch("judge", lambda *a, **k: hs.Judgment(["x"], "closure"))
        self.assertEqual(hs.main(good), hs.ROOT_TRUST_EXIT)


class ManifestRows(Fetch):
    def test_each_manifest_outside_the_grammar_is_refused_before_ls_tree(self):
        for name, manifest in (("dotdot", "../x\n"), ("dash", "-x\n"), ("slash", "a/b\n"), ("dup", "x.py\nx.py\n"),
                               ("nul", "x\0y\n"), ("long", "a" * 256 + "\n"), ("dot", ".x\n"),
                               ("pin", "PIN\n"), ("closure", f"{hs.CLOSURE}\n")):
            with self.subTest(name=name):
                files = dict(FILES)
                files[hs.CLOSURE] = (manifest if name in ("dup",) else f"{hs.LAUNCHER}\n" + manifest)
                self.stub(files=files)
                with self.assertRaises(hs.Tooling):
                    self.fetch()
                self.assertNotIn("ls-tree", [c["key"] for c in self.calls()])
                os.unlink(os.path.join(self.tools, "log.jsonl"))
        files = dict(FILES)
        files[hs.CLOSURE] = "root_trust.py\n"
        self.stub(files=files)
        with self.assertRaisesRegex(hs.Tooling, "does not name"):
            self.fetch()

    def test_a_link_a_gitlink_a_tree_or_a_missing_name_in_the_pinned_tree_is_refused(self):
        for name, cfg in (("symlink", {"modes": {"root_trust.py": "120000"}}),
                          ("gitlink", {"modes": {"root_trust.py": "160000"}, "kinds": {"root_trust.py": "commit"}}),
                          ("tree", {"modes": {"root_trust.py": "040000"}, "kinds": {"root_trust.py": "tree"}})):
            with self.subTest(name=name):
                self.stub(**cfg)
                with self.assertRaisesRegex(hs.Tooling, "not a regular blob"):
                    self.fetch()
                self.assertFalse(os.path.exists(os.path.join(self.exec, hs.BUNDLE)))
        files = dict(FILES)
        files[hs.CLOSURE] = f"{hs.LAUNCHER}\nroot_trust.py\nmissing.py\n"
        self.stub(files=files)
        with self.assertRaisesRegex(hs.Tooling, "not exactly the closure list"):
            self.fetch()

    def test_an_annotated_tag_or_anything_but_commit_is_refused(self):
        for out in ("tag\n", "commit", "blob\n"):
            with self.subTest(out=out):
                self.stub(act={"cat-file -t": {"stdout": out}})
                with self.assertRaisesRegex(hs.Tooling, "does not name a commit"):
                    self.fetch()


class LockRows(Fetch):
    def test_a_competing_holder_hands_off_and_touches_nothing(self):
        stale = os.path.join(self.exec, hs.SRC_NEW)
        os.mkdir(stale)
        fd = os.open(os.path.join(self.exec, "lock"), os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        rc = hs.main(["partition-fetch", "--git", self.git, "--git-remote-https", self.helper, "--exec-root",
                      self.exec, "--pin", PIN, "--repo", URL])
        self.assertEqual(rc, hs.EXIT_HANDOFF)
        self.assertEqual((self.judged, self.calls(), os.path.isdir(stale)), ([], [], True))

    def test_git_failing_at_each_call_exits_4_with_the_live_bundle_unchanged(self):
        live = self.live_bundle()
        for key in ("clone", "cat-file -t", f"blob:{hs.CLOSURE}", "ls-tree", "blob:root_trust.py"):
            with self.subTest(key=key):
                self.stub(act={key: {"fail": True}})
                rc = hs.main(["partition-fetch", "--git", self.git, "--git-remote-https", self.helper,
                              "--exec-root", self.exec, "--pin", PIN, "--repo", URL])
                self.assertEqual(rc, hs.EXIT_TOOLING)
                self.assertEqual(self.bundle(), live)
                self.assertNotIn(hs.PGID_FILE, os.listdir(self.exec))
                self.assertFalse({hs.SRC_NEW, hs.GIT_EXEC} & set(os.listdir(self.exec)))

    def test_a_refused_swap_restores_the_live_bundle(self):
        live = self.live_bundle()
        self.patch("_verify_bundle", lambda efd, pin: (_ for _ in ()).throw(hs.Tooling("refused")))
        with self.assertRaisesRegex(hs.Tooling, "refused"):
            self.fetch()
        self.patch("_verify_bundle", JUDGE_VERIFY)
        self.assertEqual(self.bundle(), live)

    def test_standalone_provision_swaps_the_core_in_under_its_own_lock(self):
        live = self.live_bundle()
        new = os.path.join(self.exec, hs.BUNDLE_NEW)
        shutil.copytree(os.path.join(self.exec, hs.BUNDLE), new)
        self.assertEqual(hs.partition_provision(self.exec), 0)
        self.assertEqual(self.bundle(), live)
        self.assertFalse(os.path.exists(new))

    def test_the_core_never_takes_the_lock(self):
        self.live_bundle()
        shutil.copytree(os.path.join(self.exec, hs.BUNDLE), os.path.join(self.exec, hs.BUNDLE_NEW))
        self.patch("_take_partition_lock", lambda efd: self.fail("the core re-took the lock"))
        efd = os.open(self.exec, hs._DIR)
        self.addCleanup(os.close, efd)
        self.assertEqual(hs._provision_core(efd, -1), 0)

    def test_every_write_into_bundle_new_is_exclusive(self):
        """Were the grammar ever to let a name through twice, the second
        write refuses rather than replacing the first."""
        self.patch("_manifest_names", lambda raw: [hs.LAUNCHER, hs.LAUNCHER])
        self.patch("_tree_entries", lambda raw, names: None)
        self.refused(FileExistsError, self.fetch)

    def test_the_bundle_without_its_manifest_fails_verification(self):
        self.live_bundle()
        new = os.path.join(self.exec, hs.BUNDLE_NEW)
        shutil.copytree(os.path.join(self.exec, hs.BUNDLE), new)
        os.chmod(new, 0o755)
        os.unlink(os.path.join(new, hs.CLOSURE))
        os.chmod(new, 0o555)
        with self.assertRaisesRegex(hs.Tooling, "no closure list"):
            hs.partition_provision(self.exec)


JUDGE_VERIFY = hs._verify_bundle


class CapRows(Fetch):
    """§1.6: stdout over its cap kills the group; stderr past STDERR_MAX is
    counted and dropped and never kills."""

    def git_once(self, act, cap, deadline=10):
        self.stub(act={"probe": act})
        efd = os.open(self.exec, hs._DIR)
        self.addCleanup(os.close, efd)
        return hs._git(efd, [self.git, "probe"], {"PATH": "/nonexistent"}, self.d, cap, deadline)

    def test_each_cap_passes_at_the_cap_and_kills_one_byte_over(self):
        for name, cap in (("clone", 0), ("cat-file -t", len(hs.COMMIT_TYPE)), ("ls-tree", hs.LSTREE_MAX),
                          ("blob", hs.BUNDLE_FILE_MAX)):
            with self.subTest(name=name):
                self.assertEqual(len(self.git_once({"stdout": "x" * cap}, cap)[0]), cap)
                with self.assertRaisesRegex(hs.Tooling, f"more than {cap} bytes"):
                    self.git_once({"stdout": "x" * (cap + 1)}, cap)
                self.assertNotIn(hs.PGID_FILE, os.listdir(self.exec))

    def test_a_clone_writing_one_byte_is_killed(self):
        self.stub(act={"clone": {"stdout": "x"}})
        with self.assertRaisesRegex(hs.Tooling, "more than 0 bytes"):
            self.fetch()

    def test_stderr_over_its_bound_is_dropped_and_the_child_runs_on(self):
        try:
            out, err, dropped = self.git_once({"stderr": hs.STDERR_MAX + 4096, "stdout": "ok"}, 2)
        except hs.Tooling as e:
            self.fail(f"stderr ended the child: {e}")
        self.assertEqual((out, len(err), dropped), (b"ok", hs.STDERR_MAX, 4096))


class FollowRows(Fetch):
    def test_a_failure_after_the_child_started_still_kills_and_reaps_its_group(self):
        """git.pgid cannot be written: the child is not left running."""
        started = []

        def popen(argv, **kw):
            p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(3600)"], **kw)
            started.append(p)
            return p
        self.patch("_write_at", lambda *a, **k: (_ for _ in ()).throw(OSError(28, "No space left on device")))
        efd = os.open(self.exec, hs._DIR)
        self.addCleanup(os.close, efd)
        with self.assertRaisesRegex(hs.Tooling, "could not be followed"):
            hs._git(efd, ["git"], {}, self.d, 0, 30, popen=popen)
        self.assertIsNotNone(started[0].returncode)
        self.assertTrue(hs._group_gone(started[0].pid))


class SurvivorRows(Fetch):
    """Once a child exists, any failure to show its group empty is the
    survivor path: staging and git.pgid are kept, and the next entry's guard
    refuses with nothing changed."""

    def assertSurvivor(self):
        try:
            self.fetch()
        except hs.Survivor:
            return
        except BaseException as e:  # any other exit is this row's failure, not an error
            self.fail(f"not the survivor path: {e!r}")
        self.fail("the fetch passed")

    def kill_recorded(self):
        try:
            with open(os.path.join(self.exec, hs.PGID_FILE)) as f:
                pgid = int(f.read())
        except (OSError, ValueError):
            return
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def test_a_kill_refused_with_eperm_is_a_survivor(self):
        real = os.killpg

        def killpg(pgid, sig):
            if sig == signal.SIGKILL:
                raise PermissionError(1, "Operation not permitted")
            return real(pgid, sig)
        self.addCleanup(setattr, os, "killpg", real)
        os.killpg = killpg
        self.patch("GIT_LOCAL_TIMEOUT_S", 1)
        self.patch("DRAIN_S", 0.5)
        self.stub(act={"cat-file -t": {"hang": True}})
        self.assertSurvivor()
        os.killpg = real
        self.addCleanup(self.kill_recorded)
        left = sorted(os.listdir(self.exec))
        for name in (hs.PGID_FILE, hs.SRC_NEW, hs.GIT_EXEC):
            self.assertIn(name, left)
        before = {n: os.lstat(os.path.join(self.exec, n)).st_ino for n in left}
        os.unlink(os.path.join(self.tools, "log.jsonl"))
        with self.assertRaises(hs.Survivor):
            self.fetch()
        self.assertEqual({n: os.lstat(os.path.join(self.exec, n)).st_ino for n in sorted(os.listdir(self.exec))},
                         before)
        self.assertEqual(self.calls(), [])

    def test_a_cleanup_error_or_interrupt_is_a_survivor(self):
        for name, exc in (("error", OSError(5, "Input/output error")), ("interrupt", KeyboardInterrupt())):
            with self.subTest(name=name):
                for n in list(os.listdir(self.exec)):
                    if n in (hs.SRC_NEW, hs.GIT_EXEC, hs.BUNDLE_NEW, hs.PGID_FILE):
                        self.kill_recorded()
                        p = os.path.join(self.exec, n)
                        shutil.rmtree(p) if os.path.isdir(p) and not os.path.islink(p) else os.unlink(p)
                self.patch("GIT_LOCAL_TIMEOUT_S", 1)
                self.stub(act={"cat-file -t": {"hang": True}})
                real = hs._cleanup_group

                def broken(child, pgid, exc=exc):
                    raise exc
                hs._cleanup_group = broken
                try:
                    self.assertSurvivor()
                finally:
                    hs._cleanup_group = real
                self.addCleanup(self.kill_recorded)
                left = sorted(os.listdir(self.exec))
                for n in (hs.PGID_FILE, hs.SRC_NEW, hs.GIT_EXEC):
                    self.assertIn(n, left)
                before = {n: os.lstat(os.path.join(self.exec, n)).st_ino for n in left}
                with self.assertRaises(hs.Survivor):
                    self.fetch()
                self.assertEqual({n: os.lstat(os.path.join(self.exec, n)).st_ino
                                  for n in sorted(os.listdir(self.exec))}, before)
                self.kill_recorded()

    def test_a_dropped_stderr_is_reported(self):
        import contextlib
        import io
        self.stub(act={"cat-file -t": {"stderr": hs.STDERR_MAX + 10}})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.fetch(), 0)
        self.assertIn(f"git cat-file wrote 10 stderr bytes past {hs.STDERR_MAX}; they were dropped", err.getvalue())


class TreeRows(Fetch):
    """§1.6's process tree, on real processes."""

    def test_a_descendant_holding_stdout_is_killed_with_its_group_and_never_writes_late(self):
        self.patch("GIT_LOCAL_TIMEOUT_S", 1)
        self.stub(act={"cat-file -t": {"late_write": 2, "hang": True}})
        t0 = time.monotonic()
        with self.assertRaisesRegex(hs.Tooling, "did not finish"):
            self.fetch()
        self.assertLess(time.monotonic() - t0, 1 + hs.DRAIN_S + 2)
        time.sleep(2.5)
        self.assertFalse(os.path.exists(os.path.join(self.exec, hs.SRC_NEW)), "no write after release")
        self.assertNotIn(hs.PGID_FILE, os.listdir(self.exec))

    def test_pipes_closed_with_the_child_alive_still_meet_the_deadline(self):
        self.patch("GIT_LOCAL_TIMEOUT_S", 1)
        self.stub(act={"cat-file -t": {"close_and_hang": True}})
        t0 = time.monotonic()
        with self.assertRaisesRegex(hs.Tooling, "did not finish"):
            self.fetch()
        self.assertLess(time.monotonic() - t0, 1 + hs.DRAIN_S + 2)

    def test_cleanup_returns_by_its_deadline_and_never_waits_unbounded(self):
        self.patch("DRAIN_S", 0.5)
        waits = []

        class Stuck:
            returncode = None
            stdout = stderr = None

            def wait(self, timeout=None):
                waits.append(timeout)
                if timeout is None:
                    raise AssertionError("wait() without a timeout")
                time.sleep(timeout)
                raise subprocess.TimeoutExpired("git", timeout)
        sent = []
        self.addCleanup(setattr, os, "killpg", os.killpg)
        os.killpg = lambda pgid, sig: sent.append(sig)
        t0 = time.monotonic()
        self.assertFalse(hs._cleanup_group(Stuck(), 999999))
        self.assertLess(time.monotonic() - t0, 1.5)
        self.assertTrue(waits and all(w is not None for w in waits))
        self.assertIn(signal.SIGKILL, sent)

    def test_an_already_empty_group_is_success(self):
        class Gone:
            returncode = None
            stdout = stderr = None

            def wait(self, timeout=None):
                self.returncode = -9

        def killpg(pgid, sig):
            raise ProcessLookupError
        self.addCleanup(setattr, os, "killpg", os.killpg)
        os.killpg = killpg
        self.assertTrue(hs._cleanup_group(Gone(), 999999))

    def test_no_destructive_signal_once_the_leader_is_reaped(self):
        sent = []

        class Reaped:
            returncode = 0
            stdout = stderr = None

            def wait(self, timeout=None):
                return 0
        self.patch("DRAIN_S", 0.2)
        self.addCleanup(setattr, os, "killpg", os.killpg)
        os.killpg = lambda pgid, sig: sent.append(sig)
        self.assertFalse(hs._cleanup_group(Reaped(), 999999), "a live answer is a survivor, never a kill")
        self.assertEqual(set(sent), {0})


class GuardRows(Fetch):
    """A recorded group here may be this test's own: only signal 0 is ever
    passed through, and every other signal is recorded, never sent."""

    def setUp(self):
        super().setUp()
        self.sent = []
        real = os.killpg
        self.addCleanup(setattr, os, "killpg", real)
        os.killpg = lambda pgid, sig: (self.sent.append(sig), real(pgid, 0) if sig == 0 else None)[1]

    def record(self, pgid):
        with open(os.path.join(self.exec, hs.PGID_FILE), "w") as f:
            f.write(f"{pgid}\n")

    def dead_group(self):
        p = subprocess.Popen([sys.executable, "-c", "pass"], start_new_session=True)
        p.wait()
        return p.pid

    def test_a_survivor_exits_4_and_keeps_its_staging_and_git_pgid_and_the_next_run_refuses(self):
        self.patch("_await_empty", lambda pgid: False)
        rc = hs.main(["partition-fetch", "--git", self.git, "--git-remote-https", self.helper, "--exec-root",
                      self.exec, "--pin", PIN, "--repo", URL])
        self.assertEqual(rc, hs.EXIT_TOOLING)
        left = sorted(os.listdir(self.exec))
        self.assertIn(hs.PGID_FILE, left)
        self.assertIn(hs.SRC_NEW, left)
        self.assertIn(hs.GIT_EXEC, left)
        self.record(os.getpgid(0))                     # the recorded group now lives
        os.unlink(os.path.join(self.tools, "log.jsonl"))
        self.sent.clear()
        with self.assertRaisesRegex(hs.Survivor, "still exists"):
            self.fetch()
        self.assertEqual((sorted(os.listdir(self.exec)), self.calls(), set(self.sent)), (left, [], {0}))
        self.assertFalse(os.path.exists(os.path.join(self.exec, hs.BUNDLE)), "nothing is published")

    def test_a_stale_record_whose_group_is_gone_is_cleared_and_the_fetch_proceeds(self):
        self.record(self.dead_group())
        self.assertEqual(self.fetch(), 0)
        self.assertNotIn(hs.PGID_FILE, os.listdir(self.exec))

    def test_a_record_naming_a_live_unrelated_group_refuses_and_sends_no_signal(self):
        self.record(os.getpgid(0))
        os.mkdir(os.path.join(self.exec, hs.SRC_NEW))
        with self.assertRaises(hs.Survivor):
            self.fetch()
        self.assertEqual(set(self.sent), {0})
        self.assertTrue(os.path.isdir(os.path.join(self.exec, hs.SRC_NEW)), "the guard runs before any removal")

    def test_partition_provision_refuses_on_a_live_recorded_group(self):
        self.live_bundle()
        shutil.copytree(os.path.join(self.exec, hs.BUNDLE), os.path.join(self.exec, hs.BUNDLE_NEW))
        self.record(os.getpgid(0))
        with self.assertRaises(hs.Survivor):
            hs.partition_provision(self.exec)
        self.assertTrue(os.path.isdir(os.path.join(self.exec, hs.BUNDLE_NEW)))
        self.assertEqual(set(self.sent), {0})

    def test_only_the_writer_names_the_staging(self):
        names = (hs.SRC_NEW, hs.BUNDLE_NEW, hs.GIT_EXEC, hs.PGID_FILE)
        found = []
        for n in sorted(os.listdir(REPO)):
            if n.endswith(".py") and n != "host_steps.py":
                with open(os.path.join(REPO, n)) as f:
                    text = f.read()
                found += [(n, s) for s in names if s in text]
        self.assertEqual(found, [])


@unittest.skipUnless(REAL_GIT and os.path.exists(REAL_HELPER) and os.path.exists(REAL_UPLOAD),
                     "real-git rows need git with git-core beside it")
class RealGitRows(Fetch):
    """Real git under the production env and -c set. A local clone needs
    git-upload-pack, which the https profile never runs, so ONLY the clone
    gets -c protocol.file.allow=always and --upload-pack (§1.7)."""

    def fixture(self, files, attributes=None, extra=None):
        src = os.path.join(self.d, "fixture")
        os.mkdir(src)
        env = {"PATH": "/usr/bin:/bin", "HOME": self.d, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
               "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org", "GIT_COMMITTER_NAME": "t",
               "GIT_COMMITTER_EMAIL": "t@example.org", "LC_ALL": "C"}

        def git(*a):
            return subprocess.run([REAL_GIT, "-C", src, *a], env=env, check=True, capture_output=True).stdout
        git("init", "-q", "-b", "main")
        for n, data in files.items():
            with open(os.path.join(src, n), "wb") as f:
                f.write(data)
        if attributes is not None:
            with open(os.path.join(src, ".gitattributes"), "w") as f:
                f.write(attributes)
        git("add", "-A")
        if extra:
            extra(git, src)
        git("commit", "-q", "-m", "fixture")
        return src, git("rev-parse", "HEAD").decode().strip(), git

    def local(self, src):
        def popen(argv, **kw):
            if "clone" in argv:
                i = argv.index("clone")
                argv = argv[:i] + ["-c", "protocol.file.allow=always", "clone", f"--upload-pack={REAL_UPLOAD}"] + \
                    [src if a == URL else a for a in argv[i + 1:]]
            return subprocess.Popen(argv, **kw)
        return popen

    def test_the_written_bytes_are_the_pinned_blobs_whatever_the_trees_attributes_say(self):
        files = {hs.LAUNCHER: b"# $Format:%H$\r\nline\n", "root_trust.py": b"a\nb\n",
                 hs.CLOSURE: f"{hs.LAUNCHER}\nroot_trust.py\n".encode()}
        src, pin, git = self.fixture(files, attributes="* export-subst\n* text eol=crlf\n")
        self.assertEqual(hs.partition_fetch(self.exec, pin, URL, REAL_GIT, REAL_HELPER, popen=self.local(src)), 0)
        got = self.bundle()
        for n in files:
            self.assertEqual(got[n], git("cat-file", "blob", f"{pin}:{n}"), n)
        self.assertEqual(got[hs.PIN], f"{pin}\n".encode())

    def test_a_symlink_or_a_gitlink_entry_is_refused(self):
        for kind in ("symlink", "gitlink"):
            with self.subTest(kind=kind):
                shutil.rmtree(os.path.join(self.d, "fixture"), ignore_errors=True)
                files = {hs.LAUNCHER: b"x\n", hs.CLOSURE: f"{hs.LAUNCHER}\nlinked.py\n".encode()}

                def extra(git, src, kind=kind):
                    if kind == "symlink":
                        os.symlink(hs.LAUNCHER, os.path.join(src, "linked.py"))
                        git("add", "linked.py")
                    else:
                        git("update-index", "--add", "--cacheinfo", f"160000,{'1' * 40},linked.py")
                src, pin, _ = self.fixture(files, extra=extra)
                with self.assertRaisesRegex(hs.Tooling, "not a regular blob"):
                    hs.partition_fetch(self.exec, pin, URL, REAL_GIT, REAL_HELPER, popen=self.local(src))

    def test_the_real_closure_list_goes_through_the_core_and_verifies(self):
        with open(os.path.join(REPO, hs.CLOSURE), "rb") as f:
            manifest = f.read()
        files = {hs.CLOSURE: manifest}
        for n in manifest.decode().split():
            with open(os.path.join(REPO, n), "rb") as f:
                files[n] = f.read()
        src, pin, _ = self.fixture(files)
        self.assertEqual(hs.partition_fetch(self.exec, pin, URL, REAL_GIT, REAL_HELPER, popen=self.local(src)), 0)
        self.assertEqual(set(self.bundle()), set(files) | {hs.PIN})

    def test_the_clones_own_config_holds_only_command_scope_and_clones_known_keys(self):
        src, pin, _ = self.fixture({"a.txt": b"a\n"})
        gx = os.path.join(self.exec, hs.GIT_EXEC)
        home = os.path.join(self.exec, hs.EMPTY_HOME)
        os.mkdir(gx, 0o700)
        os.mkdir(home, 0o700)
        os.symlink(REAL_GIT, os.path.join(gx, "git"))
        os.symlink(REAL_HELPER, os.path.join(gx, "git-remote-https"))
        env = hs.git_env(self.exec)
        dest = os.path.join(self.exec, hs.SRC_NEW)
        g = [os.path.join(gx, "git"), *hs.GIT_CONFIG]
        p = subprocess.run(g + ["-c", "protocol.file.allow=always", "clone", "--no-checkout", "--quiet", "--template=",
                                f"--upload-pack={REAL_UPLOAD}", "--", src, dest], env=env, cwd=home,
                           capture_output=True, stdin=subprocess.DEVNULL)
        self.assertEqual(p.returncode, 0, p.stderr)
        listed = subprocess.run(g + ["-C", dest, "config", "--list", "--show-origin", "--show-scope"], env=env,
                                cwd=home, capture_output=True, check=True).stdout.decode().splitlines()
        known = {"core.repositoryformatversion", "core.filemode", "core.bare", "core.logallrefupdates",
                 "core.ignorecase", "core.precomposeunicode", "remote.origin.url", "remote.origin.fetch",
                 "branch.main.remote", "branch.main.merge"}
        local = {}
        for line in listed:
            scope, _origin, kv = line.split("\t", 2)
            key, _, value = kv.partition("=")
            if scope == "command":
                continue
            self.assertEqual(scope, "local", line)
            self.assertIn(key, known, line)
            local[key] = value
        self.assertEqual((local["remote.origin.url"], local["remote.origin.fetch"]),
                         (src, "+refs/heads/*:refs/remotes/origin/*"))
        self.assertEqual((local.get("branch.main.remote", "origin"), local.get("branch.main.merge", "refs/heads/main")),
                         ("origin", "refs/heads/main"))
        self.assertFalse([l for l in listed if "include" in l.split("\t")[-1].split("=")[0]])


if __name__ == "__main__":
    unittest.main()
