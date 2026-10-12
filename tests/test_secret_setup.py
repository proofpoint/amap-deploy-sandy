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
OP = 501
DOWN, DOWNGRP = 2102, 2202
ANCHOR = "d" * 40
NOW = 2_000_000_000
STATUS = "/var/ex/status/" + ss.STATUS_FILE


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
                   hooks=("pre-commit.sample",), digest="b" * 64, realpath=lambda p: p):
        seen = []

        def run(argv, **kw):
            seen.append((list(argv), kw))
            return (answer or tools_answer())(argv, **kw)
        orig = rh.run
        rh.run = run
        self.addCleanup(setattr, rh, "run", orig)
        self.seen = seen
        return ss.checks(s or spec(), lstat=lstat_of(f if f is not None else fs()),
                         digest=lambda p: digest, read=reader(files_ if files_ is not None else files()),
                         platform=platform, volume=volume or volume_of(),
                         listdir=lambda p: list(hooks), realpath=realpath, now=NOW)

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
            self.assertEqual(kw["extra_env"], {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"})

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
        for over in ({"run_id": ""}, {"run_id": "has space"}, {"run_id": 7}):
            with self.subTest(over=over):
                found = self.run_checks(files_=files(**over))
                self.assertOnly(found, "the weekly probe has run within 8 days", rh.UNKNOWN)
        for member in ("run_id", "previous_class", "last_ok_at"):
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
        }
        for what, s in cases.items():
            with self.subTest(what=what):
                d = host_doc()
                d[ss.SECTION] = s
                with self.assertRaises(hs.SpecError):
                    hs.load_spec(d)

    def test_a_document_without_the_section_has_none(self):
        self.assertIsNone(hs.load_spec(host_doc()).secrets)


class PlanTest(unittest.TestCase):

    def test_the_plan_creates_the_volume_root_lock_and_state_in_order(self):
        lines = hs.render_plan(hs.load_spec(full_doc()))
        text = "\n".join(lines)
        order = ["/opt/ex/etc/overlay.sha", "/opt/ex/libexec/host_steps.py",
                 "volume create --label org.example.role=secret ex-secret",
                 f"root /v {DOWN} {DOWNGRP} 0700", "/srv/op/run/oneshot.lock",
                 "pending_b5"]
        at = [text.index(x) for x in order]
        self.assertEqual(at, sorted(at))
        root = next(line for line in lines if line.endswith(f"root /v {DOWN} {DOWNGRP} 0700"))
        for flag in ("--pull never", "--network none", "--cap-drop ALL", "--cap-add CHOWN",
                     "volume-nocopy", "/w,readonly"):
            self.assertIn(flag, root)
        self.assertLess(text.index("Start no runtime"), len(text))
        self.assertEqual(lines[-1][:17], "# Start no runtim")


if __name__ == "__main__":
    unittest.main()
