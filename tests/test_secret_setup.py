"""secret_setup: a runtime's secret file, its plan steps and its checks.

Every path, name, uid and sha here is invented; a real host's section is
operator data. The filesystem is a fake `lstat` over a dict, small files are
a fake `read`, and every command goes through router_health.run, replaced
per test by answers built from what the real tool prints: `git rev-parse`'s
sha, `git status --porcelain`'s empty output, `ssh-keygen -F`'s "# Host ...
found" line, `ssh -G`'s lower-case "key value" lines, `systemd-analyze
cat-config`'s file dump, `sysctl -n`'s bare value. Docker is never run: the
volume's metadata is the dict `host_steps.py stat-secret` prints. A good host
passes every check; each fact is then broken alone, and the check whose
claim names it must stop passing.
"""

import copy
import json
import stat
import unittest
from collections import namedtuple

import host_setup as hs
import router_health as rh
import secret_setup as ss
from test_host_setup import doc as host_doc, good_fs, lstat_of

St = namedtuple("St", "st_mode st_uid st_gid st_ino st_nlink", defaults=(0, 1))
Ident = namedtuple("Ident", "st_dev st_ino")
OP = 501
DOWN, DOWNGRP = 2102, 2202
ANCHOR = "d" * 40
NOW = 2_000_000_000
STATUS = "/var/ex/status/" + ss.STATUS_FILE
OVERLAY = "/srv/op/clones/overlay/overlay.json"


def sec():
    return {"volume": "ex-secret", "label": "org.example.role=secret", "principal": "downstream",
            "file": "credential", "container_dir": "/run/secrets/ex",
            "image": "ex/runtime@sha256:" + "a" * 64,
            "writer": {"dir": "/opt/ex/libexec", "sha256": "b" * 64, "commit": "c" * 40},
            "anchor": "/opt/ex/etc/overlay.sha", "state_file": "/opt/ex/etc/state",
            "clones": {"deploy": {"path": "/srv/op/clones/deploy", "sha": "1" * 40},
                       "overlay": {"path": "/srv/op/clones/overlay"},
                       "producer": {"path": "/srv/op/clones/producer", "sha": "2" * 40},
                       "runtime": {"path": "/srv/op/clones/runtime", "sha": "3" * 40}},
            "tools": {"git": "/usr/bin/git", "docker": "/usr/local/bin/docker",
                      "python3": "/usr/bin/python3", "ssh": "/usr/bin/ssh",
                      "ssh-keygen": "/usr/bin/ssh-keygen", "sudo": "/usr/bin/sudo",
                      "install": "/usr/bin/install", "sha256sum": "/usr/bin/sha256sum",
                      "systemd-analyze": "/usr/bin/systemd-analyze"},
            "uv": {"binary": "/usr/local/bin/uv", "cache_dir": "/srv/op/uv-cache",
                   "python_dir": "/srv/op/uv-python"},
            "status_dir": "/var/ex/status", "run_dir": "/srv/op/run",
            "ssh": {"config": "/srv/op/ssh/config", "known_hosts": "/srv/op/ssh/known_hosts",
                    "alias": "exhub"},
            "operator_uid": OP}


def full_doc(**over):
    d = host_doc()
    d[ss.SECTION] = sec()
    d[ss.SECTION].update(over)
    return d


def spec(**over):
    return hs.load_spec(full_doc(**over)).secrets


def dr(mode, uid=0):
    return St(stat.S_IFDIR | mode, uid, 0)


def fl(mode, uid=0, gid=0, nlink=1):
    return St(stat.S_IFREG | mode, uid, gid, 0, nlink)


def fs():
    f = good_fs()
    f.update({"/opt": dr(0o755), "/opt/ex": dr(0o755), "/opt/ex/libexec": dr(0o755),
              "/opt/ex/etc": dr(0o755),
              "/opt/ex/libexec/host_steps.py": fl(0o444), "/opt/ex/etc/overlay.sha": fl(0o444),
              "/opt/ex/etc/state": fl(0o444),
              "/usr": dr(0o755), "/usr/bin": dr(0o755), "/usr/local": dr(0o755),
              "/usr/local/bin": dr(0o755, OP),
              "/srv/op": dr(0o700, OP), "/srv/op/clones": dr(0o700, OP),
              "/srv/op/uv-cache": dr(0o700, OP), "/srv/op/uv-python": dr(0o700, OP),
              "/srv/op/run": dr(0o700, OP), "/srv/op/run/oneshot.lock": fl(0o600, OP),
              "/srv/op/ssh": dr(0o700, OP), "/srv/op/ssh/known_hosts": fl(0o400, OP),
              "/srv/op/ssh/config": fl(0o600, OP), OVERLAY: fl(0o644, OP), STATUS: fl(0o644),
              "/var": dr(0o755), "/var/ex": dr(0o755), "/var/ex/status": dr(0o755)})
    for role in ss.CLONE_ROLES:
        f[f"/srv/op/clones/{role}"] = dr(0o700, OP)
    for t in sec()["tools"].values():
        f[t] = fl(0o755)
    f["/usr/local/bin/uv"] = fl(0o755, OP)
    return f


def files(state="active", **over):
    status = {"class": "ok", "smtp_code": "235", "at": NOW - 3600, "run_id": "w-41",
              "previous_class": "ok", "last_ok_at": NOW - 3600}
    status.update(over)
    return {"/opt/ex/etc/overlay.sha": ANCHOR + "\n", "/opt/ex/etc/state": state + "\n",
            "/proc/sys/kernel/core_pattern": "|/usr/lib/systemd/systemd-coredump %P %u\n",
            STATUS: json.dumps(status)}


def reader(f):
    def read(p):
        if p not in f:
            raise FileNotFoundError(p)
        return f[p]
    return read


def identity_of(table):
    """A fake os.stat: each path in the table has its own identity."""
    ids = {p: i for i, p in enumerate(sorted(table), 1)}

    def st(p):
        if p not in ids:
            raise FileNotFoundError(p)
        return Ident(1, ids[p])
    return st


def volume_of(names=("credential",), mode="0400", root=(DOWN, DOWNGRP, "0700")):
    entries = [{"name": n, "regular": True, "uid": DOWN, "gid": DOWNGRP, "mode": mode, "nlink": 1,
                "nonempty": True} for n in names]
    doc = {"uid": root[0], "gid": root[1], "mode": root[2], "entries": entries}
    return lambda s, run_id: doc


SHAS = {"/srv/op/clones/deploy": "1" * 40, "/srv/op/clones/overlay": ANCHOR,
        "/srv/op/clones/producer": "2" * 40, "/srv/op/clones/runtime": "3" * 40}


def tools_answer(over=None):
    """What each tool prints on a good host; `over` maps a predicate on argv
    to a replacement answer."""
    def answer(argv, **kw):
        for pred, ans in (over or {}).items():
            if pred(argv):
                return rh.Proc(tuple(argv), *ans)
        if argv[0].endswith("git") and "rev-parse" in argv:
            return rh.Proc(tuple(argv), 0, SHAS[argv[2]] + "\n", "")
        if argv[0].endswith("git") and "status" in argv:
            return rh.Proc(tuple(argv), 0, "", "")
        if argv[0].endswith("git") and "ls-files" in argv:
            return rh.Proc(tuple(argv), 0, argv[-1] + "\n", "")
        if argv[0].endswith("ssh-keygen"):
            return rh.Proc(tuple(argv), 0, "# Host exhub found: line 1 \nexhub ssh-ed25519 AAAA\n", "")
        if argv[0].endswith("/ssh"):
            return rh.Proc(tuple(argv), 0, "user op\nhostname exhub\nstricthostkeychecking true\n", "")
        if argv[0].endswith("systemd-analyze"):
            return rh.Proc(tuple(argv), 0, "# /etc/systemd/coredump.conf\n[Coredump]\n#Storage=external\n"
                                           "# /etc/systemd/coredump.conf.d/x.conf\n[Coredump]\nStorage=none\n",
                           "")
        if argv[0].endswith("sysctl"):
            return rh.Proc(tuple(argv), 0, "0\n", "")
        raise AssertionError(f"unexpected command {argv}")
    return answer


class Base(unittest.TestCase):

    def run_checks(self, s=None, *, f=None, files_=None, volume=None, answer=None, platform="linux",
                   hooks=("pre-commit.sample",), digest="b" * 64, realpath=lambda p: p, overlay=OVERLAY,
                   exists=lambda p: False):
        seen = []

        def run(argv, **kw):
            seen.append((list(argv), kw))
            return (answer or tools_answer())(argv, **kw)
        orig = rh.run
        rh.run = run
        self.addCleanup(setattr, rh, "run", orig)
        self.seen = seen
        table = f if f is not None else fs()
        return ss.checks(s or spec(), lstat=lstat_of(table),
                         digest=lambda p: digest, read=reader(files_ if files_ is not None else files()),
                         platform=platform, volume=volume or volume_of(),
                         listdir=lambda p: list(hooks), realpath=realpath, now=NOW, overlay=overlay,
                         stat_=identity_of(table), exists=exists)

    def results(self, found):
        return {c.claim: c.result for c in found}

    def assertOnly(self, found, fragment, result=rh.FAIL):
        """Exactly the checks whose claim contains `fragment` are `result`;
        every other check passes."""
        bad = {c.claim: c.result for c in found if c.result != rh.PASS}
        self.assertTrue(bad, "nothing stopped passing")
        for claim, r in bad.items():
            self.assertIn(fragment, claim)
            self.assertEqual(r, result, claim)


class GoodHostTest(Base):

    def test_a_good_host_passes_every_check(self):
        found = self.run_checks()
        self.assertGreater(len(found), 20)
        self.assertEqual([c.claim for c in found if c.result != rh.PASS], [])

    def test_retired_and_pending_states_pass_on_an_empty_volume(self):
        for state in ("pending_b5", "retired"):
            with self.subTest(state=state):
                found = self.run_checks(files_=files(state), volume=volume_of(names=()))
                self.assertEqual([c.claim for c in found if c.result != rh.PASS], [])

    def test_git_runs_with_system_and_user_config_ignored_and_no_hooks(self):
        self.run_checks()
        gits = [(a, kw) for a, kw in self.seen if a[0] == "/usr/bin/git"]
        self.assertTrue(gits)
        for argv, kw in gits:
            self.assertIn("core.hooksPath=/dev/null", argv)
            self.assertIn("core.fsmonitor=false", argv)
            repo = argv[argv.index("-C") + 1]
            self.assertEqual(kw["extra_env"], {
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_DIR": repo + "/.git",
                "GIT_WORK_TREE": repo, "GIT_COMMON_DIR": repo + "/.git", "GIT_CONFIG_COUNT": "0",
                "GIT_CONFIG_PARAMETERS": ""})

    def test_ssh_is_asked_in_the_producers_option_order(self):
        self.run_checks()
        ssh = next(a for a, _ in self.seen if a[0] == "/usr/bin/ssh")
        self.assertEqual(ssh[ssh.index("-G"):], [
            "-G", "-F", "/srv/op/ssh/config", "-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new", "exhub"])


class PinsTest(Base):

    def test_a_writable_writer_fails(self):
        f = fs()
        f["/opt/ex/libexec/host_steps.py"] = fl(0o644)
        self.assertOnly(self.run_checks(f=f), "the writer /opt/ex/libexec/host_steps.py is root:root 0444")

    def test_a_writer_owned_by_the_operator_fails(self):
        f = fs()
        f["/opt/ex/libexec/host_steps.py"] = fl(0o444, OP)
        self.assertOnly(self.run_checks(f=f), "the writer")

    def test_a_writer_with_a_second_link_fails(self):
        f = fs()
        f["/opt/ex/libexec/host_steps.py"] = fl(0o444, nlink=2)
        self.assertOnly(self.run_checks(f=f), "the writer")

    def test_a_group_writable_directory_above_the_writer_fails(self):
        f = fs()
        f["/opt/ex/libexec"] = dr(0o775)
        self.assertOnly(self.run_checks(f=f), "every directory above /opt/ex/libexec/host_steps.py")

    def test_a_writer_that_does_not_hash_to_its_pin_fails(self):
        self.assertOnly(self.run_checks(digest="e" * 64), "hashes to its pin")

    def test_an_unreadable_writer_is_unknown(self):
        found = self.run_checks(digest=rh.Unresolved("denied"))
        self.assertOnly(found, "hashes to its pin", rh.UNKNOWN)

    def test_an_anchor_or_state_file_writable_by_anyone_but_root_fails(self):
        for path, frag in (("/opt/ex/etc/overlay.sha", "the anchor"), ("/opt/ex/etc/state", "the state file")):
            with self.subTest(path=path):
                f = fs()
                f[path] = fl(0o644)
                self.assertOnly(self.run_checks(f=f), frag)

    def test_an_operator_owned_etc_directory_fails(self):
        f = fs()
        f["/opt/ex/etc"] = dr(0o755, OP)
        found = self.run_checks(f=f)
        bad = [c.claim for c in found if c.result != rh.PASS]
        self.assertEqual(bad, ["every directory above /opt/ex/etc/overlay.sha is root-owned and not "
                               "group- or world-writable",
                               "every directory above /opt/ex/etc/state is root-owned and not "
                               "group- or world-writable"])

    def test_an_unknown_state_is_unknown_never_guessed(self):
        found = self.run_checks(files_=files("halfway"))
        unknowns = {c.claim for c in found if c.result == rh.UNKNOWN}
        self.assertIn("/opt/ex/etc/state holds one of pending_b5, active, retired", unknowns)
        self.assertIn("the volume ex-secret holds what the state says", unknowns)
        self.assertFalse([c for c in found if c.result == rh.FAIL])

    def test_an_anchor_that_is_not_a_sha_leaves_the_overlay_clone_unknown(self):
        f = files()
        f["/opt/ex/etc/overlay.sha"] = "main\n"
        found = self.run_checks(files_=f)
        unknowns = {c.claim for c in found if c.result == rh.UNKNOWN}
        self.assertEqual(unknowns, {"/opt/ex/etc/overlay.sha holds the reviewed overlay's commit sha",
                                    "the overlay clone's HEAD is its reviewed commit"})


class ClonesTest(Base):

    def test_a_clone_at_another_commit_fails(self):
        def other(argv):
            return argv[0].endswith("git") and "rev-parse" in argv and argv[2].endswith("producer")
        found = self.run_checks(answer=tools_answer({other: (0, "9" * 40 + "\n", "")}))
        self.assertOnly(found, "the producer clone's HEAD")

    def test_the_overlay_clone_is_held_to_the_anchor(self):
        f = files()
        f["/opt/ex/etc/overlay.sha"] = "f" * 40 + "\n"
        self.assertOnly(self.run_checks(files_=f), "the overlay clone's HEAD")

    def test_a_dirty_or_ignored_file_fails(self):
        def dirty(argv):
            return argv[0].endswith("git") and "status" in argv and argv[2].endswith("deploy")
        found = self.run_checks(answer=tools_answer({dirty: (0, "!! planted.pyc\n", "")}))
        self.assertOnly(found, "the deploy clone has no change")

    def test_an_ignored_file_is_seen_only_because_ignored_files_are_asked_for(self):
        """git status hides an ignored file unless --ignored is given; this
        fake is faithful to that, so the check must ask for them."""
        def status(argv):
            return argv[0].endswith("git") and "status" in argv and argv[2].endswith("runtime")

        def answer(argv, **kw):
            if status(argv):
                out = "!! host/__pycache__/planted.pyc\n" if "--ignored" in argv else ""
                return rh.Proc(tuple(argv), 0, out, "")
            return tools_answer()(argv, **kw)
        self.assertOnly(self.run_checks(answer=answer), "the runtime clone has no change")

    def test_a_hook_that_could_run_fails(self):
        found = self.run_checks(hooks=("pre-commit.sample", "post-checkout"))
        bad = {c.claim for c in found if c.result != rh.PASS}
        self.assertEqual(bad, {f"the {r} clone holds no hook that could run" for r in ss.CLONE_ROLES})

    def test_a_clone_open_to_the_group_fails(self):
        f = fs()
        f["/srv/op/clones/runtime"] = dr(0o750, OP)
        self.assertOnly(self.run_checks(f=f), "the runtime clone /srv/op/clones/runtime is a directory")

    def test_a_host_without_the_producer_clone_checks_only_the_clones_it_has(self):
        """A host that pins the D7 source as one file holds no producer tree:
        no producer claim is made, and the other clones are checked as ever."""
        no_producer = {k: v for k, v in sec()["clones"].items() if k != "producer"}
        host = hs.load_spec(full_doc())
        s = ss.load(dict(sec(), clones=no_producer), host.principals, host.runtimes)
        found = self.run_checks(s=s)
        self.assertFalse([c.claim for c in found if "producer clone" in c.claim])
        self.assertEqual([(c.claim, c.actual) for c in found if c.result != rh.PASS], [])
        self.assertTrue([c for c in found if "the deploy clone's HEAD" in c.claim])

    def test_only_the_producer_clone_may_be_left_out(self):
        """At the section, only the producer may be absent; whether THIS host
        may leave it out is the document's rule (a hub pinning the file)."""
        host = hs.load_spec(full_doc())
        for role in ss.CLONE_ROLES:
            with self.subTest(role=role):
                clones = {k: v for k, v in sec()["clones"].items() if k != role}
                if role == ss.OPTIONAL_CLONE_ROLE:
                    self.assertNotIn(role, ss.load(dict(sec(), clones=clones), host.principals, host.runtimes).clones)
                    with self.assertRaises(hs.SpecError):
                        spec(clones=clones)
                else:
                    with self.assertRaises(ss.SecretSpecError):
                        ss.load(dict(sec(), clones=clones), host.principals, host.runtimes)

    def test_git_that_cannot_answer_is_unknown(self):
        def broken(argv):
            return argv[0].endswith("git") and "rev-parse" in argv and argv[2].endswith("deploy")
        found = self.run_checks(answer=tools_answer({broken: (128, "", "fatal: not a git repository")}))
        self.assertOnly(found, "the deploy clone's HEAD", rh.UNKNOWN)


class ToolsTest(Base):

    def test_a_tool_writable_by_the_group_fails(self):
        f = fs()
        f["/usr/bin/ssh"] = fl(0o775)
        self.assertOnly(self.run_checks(f=f), "the ssh tool")

    def test_a_tool_that_cannot_execute_fails(self):
        f = fs()
        f["/usr/bin/git"] = fl(0o644)
        self.assertOnly(self.run_checks(f=f), "the git tool")

    def test_a_tool_owned_by_another_user_fails(self):
        f = fs()
        f["/usr/bin/install"] = fl(0o755, 777)
        self.assertOnly(self.run_checks(f=f), "the install tool")

    def test_a_tools_real_path_is_what_is_checked(self):
        f = fs()
        f["/srv/agent-writable/bin/python3"] = fl(0o755, 777)
        f["/srv/agent-writable"] = dr(0o755, 777)
        f["/srv/agent-writable/bin"] = dr(0o755, 777)
        found = self.run_checks(f=f, realpath=lambda p: "/srv/agent-writable/bin/python3"
                                if p == "/usr/bin/python3" else p)
        bad = {c.claim for c in found if c.result != rh.PASS}
        self.assertIn("the python3 tool /usr/bin/python3 is a regular executable file owned by root or "
                      "the operator", bad)
        self.assertIn("every directory above /srv/agent-writable/bin/python3 is owned by root or the operator and "
                      "not group- or world-writable", bad)

    def test_a_world_writable_directory_above_a_tool_fails(self):
        f = fs()
        f["/usr/local/bin"] = dr(0o777, OP)
        found = self.run_checks(f=f)
        bad = {c.claim for c in found if c.result != rh.PASS}
        self.assertEqual(bad, {
            "every directory above /usr/local/bin/docker is owned by root or the operator and not "
            "group- or world-writable",
            "every directory above /usr/local/bin/uv is owned by root or the operator and not "
            "group- or world-writable"})


class DirsAndSshTest(Base):

    def test_a_missing_lock_file_fails(self):
        f = fs()
        del f["/srv/op/run/oneshot.lock"]
        self.assertOnly(self.run_checks(f=f), "the lock file")

    def test_a_lock_file_others_can_open_fails(self):
        f = fs()
        f["/srv/op/run/oneshot.lock"] = fl(0o644, OP)
        self.assertOnly(self.run_checks(f=f), "the lock file")

    def test_an_open_uv_cache_fails(self):
        f = fs()
        f["/srv/op/uv-cache"] = dr(0o755, OP)
        self.assertOnly(self.run_checks(f=f), "uv's cache")

    def test_a_known_hosts_that_can_be_appended_to_fails(self):
        f = fs()
        f["/srv/op/ssh/known_hosts"] = fl(0o600, OP)
        self.assertOnly(self.run_checks(f=f), "the pinned known_hosts")

    def test_a_hub_key_that_is_not_pinned_fails(self):
        found = self.run_checks(answer=tools_answer({lambda a: a[0].endswith("ssh-keygen"): (1, "", "")}))
        self.assertOnly(found, "the hub's host key is pinned")

    def test_accept_new_winning_fails(self):
        found = self.run_checks(answer=tools_answer({
            lambda a: a[0].endswith("/ssh"): (0, "stricthostkeychecking accept-new\n", "")}))
        self.assertOnly(found, "host-key checking is strict")


class VolumeTest(Base):

    def test_an_active_volume_without_the_file_fails(self):
        self.assertOnly(self.run_checks(volume=volume_of(names=())), "the volume holds exactly credential")

    def test_a_stray_entry_fails(self):
        found = self.run_checks(volume=volume_of(names=("credential", ".credential.tmp")))
        self.assertOnly(found, "the volume holds exactly credential")

    def test_a_file_with_group_bits_fails(self):
        self.assertOnly(self.run_checks(volume=volume_of(mode="0440")), "credential is a regular file")

    def test_a_file_present_while_pending_fails(self):
        found = self.run_checks(files_=files("pending_b5"))
        self.assertOnly(found, "the volume holds nothing in the pending_b5 state")

    def test_a_file_left_after_retiring_fails(self):
        self.assertOnly(self.run_checks(files_=files("retired")), "the volume holds nothing in the retired")

    def test_a_root_not_owned_by_the_runtime_fails(self):
        found = self.run_checks(volume=volume_of(root=(0, 0, "0755")))
        self.assertOnly(found, "the volume ex-secret's root")

    def test_an_engine_that_cannot_be_asked_is_unknown(self):
        found = self.run_checks(volume=lambda s, r: rh.Unresolved("the engine is not running"))
        self.assertOnly(found, "the volume ex-secret holds what the state says", rh.UNKNOWN)

    def test_the_stat_one_shot_is_in_the_reviewed_shape_under_the_lock(self):
        s = spec()
        out = json.dumps({"uid": DOWN, "gid": DOWNGRP, "mode": "0700", "entries": []})
        seen = []

        def run(argv, **kw):
            seen.append(list(argv))
            return rh.Proc(tuple(argv), 0, out, "")
        orig = rh.run
        rh.run = run
        self.addCleanup(setattr, rh, "run", orig)
        got = ss.ask_volume(s, "r1")
        self.assertEqual(got["entries"], [])
        argv = seen[0]
        self.assertEqual(argv[:8], ["/usr/bin/python3", "-I", "-S", "/opt/ex/libexec/host_steps.py",
                                    "lock", "/srv/op/run", "--", "/usr/local/bin/docker"])
        for flag in (["--pull", "never"], ["--network", "none"], ["--log-driver", "none"],
                     ["--cap-drop", "ALL"], ["--user", f"{DOWN}:{DOWNGRP}"]):
            i = argv.index(flag[0])
            self.assertEqual(argv[i:i + 2], flag)
        self.assertNotIn("--cap-add", argv)
        self.assertIn("type=volume,src=ex-secret,dst=/v,volume-nocopy,readonly", argv)
        self.assertEqual(argv[-2:], ["stat-secret", "/v"])

    def test_docker_through_sudo_where_recorded(self):
        s = spec(docker_via_sudo=True)
        self.assertEqual(ss.docker(s), ["/usr/bin/sudo", "-n", "/usr/local/bin/docker"])


class CoreAndStatusTest(Base):

    def test_cores_handed_to_another_handler_fail(self):
        f = files()
        f["/proc/sys/kernel/core_pattern"] = "|/usr/share/apport/apport %p %s\n"
        self.assertOnly(self.run_checks(files_=f), "hands every core to systemd-coredump")

    def test_stored_cores_fail(self):
        found = self.run_checks(answer=tools_answer({
            lambda a: a[0].endswith("systemd-analyze"): (0, "[Coredump]\nStorage=external\n", "")}))
        self.assertOnly(found, "systemd-coredump stores nothing")

    def test_the_last_storage_line_wins(self):
        found = self.run_checks(answer=tools_answer({
            lambda a: a[0].endswith("systemd-analyze"):
                (0, "[Coredump]\nStorage=none\n# drop-in\n[Coredump]\nStorage=journal\n", "")}))
        self.assertOnly(found, "systemd-coredump stores nothing")

    def test_macos_cores_on_fail(self):
        s = spec(tools=dict(sec()["tools"], sysctl="/usr/sbin/sysctl"))
        f = fs()
        f["/usr/sbin"] = dr(0o755)
        f["/usr/sbin/sysctl"] = fl(0o755)
        found = self.run_checks(s, f=f, platform="darwin", answer=tools_answer({
            lambda a: a[0].endswith("sysctl"): (0, "1\n", "")}))
        self.assertOnly(found, "kern.coredump=0")

    def test_an_old_status_fails(self):
        found = self.run_checks(files_=files(at=NOW - 9 * 86400, last_ok_at=NOW - 9 * 86400))
        self.assertOnly(found, "the weekly probe has run within 8 days")

    def test_no_pass_for_15_days_fails_whatever_the_last_class(self):
        found = self.run_checks(files_=files(**{"class": "hub_unreachable", "smtp_code": "-",
                                                "last_ok_at": NOW - 16 * 86400}))
        self.assertOnly(found, "passed within 15 days")

    def test_an_auth_failure_fails(self):
        found = self.run_checks(files_=files(**{"class": "auth_failed", "smtp_code": "535"}))
        self.assertOnly(found, "the weekly probe has run")

    def test_two_tls_failures_in_a_row_fail(self):
        found = self.run_checks(files_=files(**{"class": "tls_failed", "smtp_code": "-",
                                                "previous_class": "tls_failed"}))
        self.assertOnly(found, "failed TLS twice")

    def test_a_status_without_a_valid_run_id_or_a_member_is_unknown(self):
        for over in ({"run_id": ""}, {"run_id": "has space"}, {"run_id": 7}, {"smtp_code": "2x5"}, {"smtp_code": "\u0662\u0663\u0665"},
                     {"smtp_code": 235}, {"previous_class": "fine"}, {"class": "great"}, {"at": "yesterday"},
                     {"last_ok_at": "yesterday"}):
            with self.subTest(over=over):
                found = self.run_checks(files_=files(**over))
                self.assertOnly(found, "the weekly probe has run within 8 days", rh.UNKNOWN)
        for member in ("run_id", "previous_class", "last_ok_at", "smtp_code", "class", "at"):
            with self.subTest(member=member):
                f = files()
                doc = json.loads(f[STATUS])
                del doc[member]
                f[STATUS] = json.dumps(doc)
                self.assertOnly(self.run_checks(files_=f), "the weekly probe has run within 8 days",
                                rh.UNKNOWN)

    def test_no_status_is_asked_for_before_the_secret_exists(self):
        f = files("pending_b5")
        del f[STATUS]
        found = self.run_checks(files_=f, volume=volume_of(names=()))
        self.assertEqual([c.claim for c in found if c.result != rh.PASS], [])


class OverlaySourceTest(Base):

    def test_a_document_from_outside_the_anchored_clone_fails(self):
        f = fs()
        f["/srv/op/copy.json"] = fl(0o644, OP)
        self.assertOnly(self.run_checks(f=f, overlay="/srv/op/copy.json"), "read from the anchored overlay clone")

    def test_a_document_given_by_spec_fails(self):
        self.assertOnly(self.run_checks(overlay=None), "read from the anchored overlay clone")

    def test_a_symlink_into_the_clone_passes_only_by_its_target(self):
        f = fs()
        f["/srv/op/link.json"] = fl(0o644, OP)
        found = self.run_checks(f=f, overlay="/srv/op/link.json",
                                realpath=lambda p: OVERLAY if p == "/srv/op/link.json" else p)
        self.assertEqual([c.claim for c in found if c.result != rh.PASS], [])

    def test_an_untracked_document_fails(self):
        found = self.run_checks(answer=tools_answer({
            lambda a: a[0].endswith("git") and "ls-files" in a: (1, "", "error: pathspec did not match")}))
        self.assertOnly(found, "is a tracked file of the anchored overlay clone")


class ApportTest(Base):

    def apport(self, default, units=None, exists=True):
        f = files()
        if default is not None:
            f[ss.APPORT_DEFAULT] = default
        s = spec(tools=dict(sec()["tools"], systemctl="/usr/bin/systemctl"))
        table = fs()
        table["/usr/bin/systemctl"] = fl(0o755)
        units = units or {}

        def unit(argv):
            return argv[0].endswith("systemctl")

        def answer(argv, **kw):
            if unit(argv):
                state = units.get(argv[-1], "disabled")
                return rh.Proc(tuple(argv), 0 if state == "enabled" else 1, state + "\n", "")
            return tools_answer()(argv, **kw)
        return self.run_checks(s, f=table, files_=f, answer=answer, exists=lambda p: exists)

    def test_absent_apport_passes(self):
        self.assertEqual([c.claim for c in self.apport(None, exists=False) if c.result != rh.PASS], [])

    def test_disabled_in_defaults_and_units_passes(self):
        self.assertEqual([c.claim for c in self.apport("enabled=0\n") if c.result != rh.PASS], [])

    def test_enabled_in_defaults_fails(self):
        self.assertOnly(self.apport("# comment\nenabled=1\n"), "apport is absent or disabled")

    def test_disabled_in_defaults_but_a_unit_enabled_fails(self):
        self.assertOnly(self.apport("enabled=0\n", {"apport.service": "enabled"}), "apport is absent or disabled")

    def test_an_unreadable_default_is_unknown(self):
        def read(p):
            if p == ss.APPORT_DEFAULT:
                raise PermissionError(13, "denied", p)
            return files()[p]
        s = spec(tools=dict(sec()["tools"], systemctl="/usr/bin/systemctl"))
        table = fs()
        table["/usr/bin/systemctl"] = fl(0o755)
        orig = rh.run
        rh.run = tools_answer()
        self.addCleanup(setattr, rh, "run", orig)
        found = ss.checks(s, lstat=lstat_of(table), digest=lambda p: "b" * 64, read=read, platform="linux",
                          volume=volume_of(), listdir=lambda p: [], realpath=lambda p: p, now=NOW,
                          overlay=OVERLAY, stat_=identity_of(table), exists=lambda p: True)
        bad = {c.claim: c.result for c in found if c.result != rh.PASS}
        self.assertEqual(bad, {"apport is absent or disabled": rh.UNKNOWN})


class PipelineLocksTest(Base):

    def test_a_missing_or_open_pipeline_lock_fails(self):
        s = spec(pipeline_locks=["b5-one.lock"])
        found = self.run_checks(s)
        self.assertOnly(found, "the lock file /srv/op/run/b5-one.lock")
        f = fs()
        f["/srv/op/run/b5-one.lock"] = fl(0o644, OP)
        self.assertOnly(self.run_checks(s, f=f), "the lock file /srv/op/run/b5-one.lock")
        f["/srv/op/run/b5-one.lock"] = fl(0o600, OP)
        self.assertEqual([c.claim for c in self.run_checks(s, f=f) if c.result != rh.PASS], [])

    def test_the_plan_creates_every_pipeline_lock(self):
        lines = hs.render_plan(hs.load_spec(full_doc(pipeline_locks=["b5-one.lock", "b5-two.lock"])))
        for name in ("oneshot.lock", "b5-one.lock", "b5-two.lock"):
            self.assertTrue(any(line.endswith(f"/srv/op/run/{name}") and "-m 0600 /dev/null" in line
                                for line in lines), name)


class ZshAndFilesTest(Base):

    def zsh(self, out, module_dir_mode=0o755):
        s = spec(tools=dict(sec()["tools"], zsh="/bin/zsh"),
                 zsh={"version": "5.9", "module_path": "/usr/lib/zsh/5.9"})
        f = fs()
        f.update({"/bin": dr(0o755), "/bin/zsh": fl(0o755), "/usr/lib": dr(0o755),
                  "/usr/lib/zsh": dr(0o755), "/usr/lib/zsh/5.9": dr(module_dir_mode)})
        return self.run_checks(s, f=f, answer=tools_answer({lambda a: a[0] == "/bin/zsh": (0, out, "")}))

    def test_the_recorded_zsh_passes(self):
        self.assertEqual([c.claim for c in self.zsh("5.9\n/usr/lib/zsh/5.9\n") if c.result != rh.PASS], [])

    def test_another_zsh_fails(self):
        self.assertOnly(self.zsh("5.8\n/opt/homebrew/lib/zsh/5.8\n"), "the recorded zsh is its recorded version")

    def test_a_writable_module_directory_fails(self):
        self.assertOnly(self.zsh("5.9\n/usr/lib/zsh/5.9\n", 0o775), "the zsh module directory")

    def test_an_open_hub_ssh_config_fails(self):
        f = fs()
        f["/srv/op/ssh/config"] = fl(0o644, OP)
        self.assertOnly(self.run_checks(f=f), "the hub ssh config")

    def test_a_status_file_not_roots_fails(self):
        f = fs()
        f[STATUS] = fl(0o666)
        self.assertOnly(self.run_checks(f=f), "the weekly probe's status file is root's")


class RemedyAndProbeTest(Base):

    def remedy(self, found, fragment):
        return next(c.remedy for c in found if fragment in c.claim and c.result != rh.PASS)

    def test_a_foreign_stray_is_escalated_and_a_crash_temp_removed(self):
        foreign = self.run_checks(volume=volume_of(names=("credential", "planted")))
        self.assertIn("escalate", self.remedy(foreign, "the volume holds exactly"))
        temp = self.run_checks(volume=volume_of(names=("credential", ".credential.tmp")))
        self.assertIn("remove the crash temp with `secret-remove`", self.remedy(temp, "the volume holds exactly"))

    def test_the_probe_runs_probe_login_with_its_budgets(self):
        s = spec(probe={"network": "ex-net", "smtp_host": "hub.example.org", "smtp_port": 587,
                        "username": "probe-user@ex.example.org"})
        argv = ss.probe(s, "w-1")
        self.assertEqual(argv[-2:], ["ex/runtime@sha256:" + "a" * 64, "probe-login"])
        for env in ("SMTP_PASSWORD_FILE=/run/secrets/ex/credential", "SMTP_AUTH_METHOD=password",
                    "SMTP_PORT=587", "RELAY_SMTP_CONNECT_TIMEOUT=30", "RELAY_SMTP_COMMAND_TIMEOUT=30",
                    "RELAY_SMTP_DATA_TIMEOUT=30", "RELAY_SMTP_DOT_TIMEOUT=30"):
            self.assertEqual(argv[argv.index(env) - 1], "-e")
        self.assertIn("type=volume,src=ex-secret,dst=/run/secrets/ex,readonly,volume-nocopy", argv)
        self.assertEqual(argv[argv.index("--user") + 1], f"{DOWN}:{DOWNGRP}")
        self.assertNotIn("--cap-add", argv)

    def test_held_runs_the_stat_one_shot_without_the_wrapper(self):
        s = spec()
        seen = []

        def run(argv, **kw):
            seen.append(list(argv))
            return rh.Proc(tuple(argv), 0, json.dumps({"uid": DOWN, "gid": DOWNGRP, "mode": "0700",
                                                       "entries": []}), "")
        orig = rh.run
        rh.run = run
        self.addCleanup(setattr, rh, "run", orig)
        ss.ask_volume(s, "r1", held=True)
        self.assertEqual(seen[0][0], "/usr/local/bin/docker")
        self.assertNotIn("lock", seen[0][:6])


class HostSetupLockTest(unittest.TestCase):

    def test_a_busy_lock_is_one_unknown_and_no_secret_check_runs(self):
        import contextlib

        @contextlib.contextmanager
        def busy(s):
            yield rh.Unresolved("held for 60s")
        spec_ = hs.load_spec(full_doc())
        called = []
        orig = ss.checks
        ss.checks = lambda *a, **k: called.append(k) or []
        self.addCleanup(setattr, ss, "checks", orig)
        found = hs.checks(spec_, production=False, lstat=lstat_of(fs()), digest=lambda p: "x",
                          openssl={}, containers=lambda c: rh.Unresolved("n/a"), umasks=lambda c: [],
                          secret_lock=busy)
        self.assertEqual(called, [])
        self.assertIn("the secret's checks ran under the one-shots' lock",
                      [c.claim for c in found if c.result == rh.UNKNOWN])

    def test_a_free_lock_runs_the_secret_checks_as_held_with_the_overlay(self):
        import contextlib

        @contextlib.contextmanager
        def free(s):
            yield None
        spec_ = hs.load_spec(full_doc())
        called = []
        orig = ss.checks
        ss.checks = lambda *a, **k: called.append(k) or []
        self.addCleanup(setattr, ss, "checks", orig)
        hs.checks(spec_, production=False, lstat=lstat_of(fs()), digest=lambda p: "x", openssl={},
                  containers=lambda c: rh.Unresolved("n/a"), umasks=lambda c: [], secret_lock=free,
                  overlay="/srv/op/clones/overlay/overlay.json")
        self.assertEqual((called[0]["held"], called[0]["overlay"]), (True, "/srv/op/clones/overlay/overlay.json"))


class LoadTest(unittest.TestCase):

    def test_bad_sections_do_not_load(self):
        cases = {
            "an unknown member": dict(sec(), extra=1),
            "a tag where a digest belongs": dict(sec(), image="ex/runtime:latest"),
            "a principal with no runtime": dict(sec(), principal="nobody"),
            "a missing tool": dict(sec(), tools={k: v for k, v in sec()["tools"].items() if k != "git"}),
            "a relative tool": dict(sec(), tools=dict(sec()["tools"], git="git")),
            "a clone without its sha": dict(sec(), clones=dict(sec()["clones"],
                                                               deploy={"path": "/srv/op/clones/deploy"})),
            "a missing clone": dict(sec(), clones={k: v for k, v in sec()["clones"].items()
                                                   if k != "runtime"}),
            "sudo without its tool": dict(sec(), docker_via_sudo=True,
                                          tools={k: v for k, v in sec()["tools"].items() if k != "sudo"}),
            "root as the operator": dict(sec(), operator_uid=0),
            "a short writer pin": dict(sec(), writer=dict(sec()["writer"], sha256="b" * 63)),
            "a pipeline lock that is a path": dict(sec(), pipeline_locks=["../x.lock"]),
            "the one-shots' lock as a pipeline lock": dict(sec(), pipeline_locks=["oneshot.lock"]),
            "a probe without its port": dict(sec(), probe={"network": "n", "smtp_host": "h", "username": "u"}),
            "a zsh without its tool": dict(sec(), zsh={"version": "5.9", "module_path": "/usr/lib/zsh/5.9"}),
            "a short image commit": dict(sec(), image_commit="c" * 12),
            "an upper-case image commit": dict(sec(), image_commit="C" * 40),
            "an image commit that is not a string": dict(sec(), image_commit=1),
        }
        for what, s in cases.items():
            with self.subTest(what=what):
                d = host_doc()
                d[ss.SECTION] = s
                with self.assertRaises(hs.SpecError):
                    hs.load_spec(d)

    def test_a_document_without_the_section_has_none(self):
        self.assertIsNone(hs.load_spec(host_doc()).secrets)

    def test_the_image_commit_is_optional_and_kept_when_recorded(self):
        """The commit the runtime image was built from (verify's runtime
        builds phase); absent, the build claim is UNKNOWN, never refused."""
        self.assertIsNone(hs.load_spec(full_doc()).secrets.image_commit)
        self.assertEqual(hs.load_spec(full_doc(image_commit="c" * 40)).secrets.image_commit, "c" * 40)


class PlanTest(unittest.TestCase):

    def test_the_plan_creates_the_volume_root_lock_and_state_in_order(self):
        lines = hs.render_plan(hs.load_spec(full_doc()))
        text = "\n".join(lines)
        order = ["/opt/ex/etc/overlay.sha", "/opt/ex/libexec/host_steps.py", "/srv/op/run/oneshot.lock",
                 "volume create --label org.example.role=secret ex-secret",
                 f"root /v {DOWN} {DOWNGRP} 0700 --exclusive", "pending_b5"]
        at = [text.index(x) for x in order]
        self.assertEqual(at, sorted(at))
        root = next(line for line in lines if line.endswith(f"root /v {DOWN} {DOWNGRP} 0700 --exclusive"))
        self.assertTrue(root.startswith("/usr/bin/python3 -I -S /opt/ex/libexec/host_steps.py lock /srv/op/run --"))
        self.assertNotIn("/dev/stdin", text)
        for flag in ("--pull never", "--network none", "--cap-drop ALL", "--cap-add CHOWN",
                     "volume-nocopy", "/w,readonly"):
            self.assertIn(flag, root)
        self.assertLess(text.index("Start no runtime"), len(text))
        self.assertEqual(lines[-1][:17], "# Start no runtim")


if __name__ == "__main__":
    unittest.main()
