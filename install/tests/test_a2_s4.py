"""S4 IMAGES (a2_s4) on a fake layer: the lock's two images by role, the runtime users, and the checks on an image
already present (inspect and revision, readback as root and as the runtime user, openssl, the RL fingerprint).

The docker outputs here are FAKED in the shapes docker and the vm-build r2 programs print: `image inspect --format
'{{json .}}'` is one JSON object with Id and Config (Labels, WorkingDir); the readback walk prints vm-build r2's
FIRSTPY and ENTRIES lines; `openssl version` prints "OpenSSL x.y.z <date> (Library: ...)". vm_measure's line is the
real script's shape (test_a2_s6 runs it). obtain's presence list is FAKED as `docker image ls --no-trunc --quiet`
prints it, one full Id per line (PENDING CAPTURE on a VM); `docker load`'s output is never read, only its exit
status. The archives are real files in a temporary lock root."""

import copy
import grp
import hashlib
import json
import os
import pwd
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock

import a2fix
import a2_s4 as S
import a2_s8_re
import test_a2_vm
from a2_causes import Refusal

C_RL, C_RE, C_INST = "1a" * 20, "2b" * 20, a2fix.H40
RL_ID, RE_ID = "sha256:" + "a" * 64, "sha256:" + "e" * 64
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
#: The two archives' bytes, as written into a test lock root; the lock's archive_sha256 rows are their shas.
ARCHIVE = {"rl-img": b"rl archive bytes\n" * 3, "re-img": b"re archive bytes\n" * 5}


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def s4_lock():
    """a2fix's lock with the RL and RE components, their two images, and the installer's fingerprint files."""
    d = copy.deepcopy(a2fix.LOCK)
    d["components"] += [
        {"name": S.RL_COMPONENT, "repo": "https://git.example.org/amap/amap-router-local", "commit": C_RL,
         "tag": "alpha2-rc1"},
        {"name": "re-component", "repo": "ssh://git@git.example.org/amap/re", "commit": C_RE, "tag": "alpha2-rc1"},
        {"name": S.INSTALLER_COMPONENT, "repo": d["installer"]["repo"], "commit": C_INST, "tag": "alpha2-rc1"}]
    d["images"] = [{"name": "rl-img", "built_from": S.RL_COMPONENT, "image_id": RL_ID,
                    "archive_sha256": _sha(ARCHIVE["rl-img"])},
                   {"name": "re-img", "built_from": "re-component", "image_id": RE_ID,
                    "archive_sha256": _sha(ARCHIVE["re-img"])}]
    for fname in S.FINGERPRINT_FILES:
        with open(os.path.join(REPO_ROOT, fname), "rb") as f:
            d["files"].append({"path": fname, "component": S.INSTALLER_COMPONENT,
                               "sha256": hashlib.sha256(f.read()).hexdigest()})
    return d


V = {"name": "vm-a", "agent_account": "agent", "relay_account": "relay", "hop_group": "hop"}
MEASURE = {"home": "/home/agent", "uid": 1000, "gid": 1000, "relay_uid": 2102, "relay_gid": 2102,
           "relay_home": "/home/relay", "hop_gid": 2100, "agent_in_hop": True, "relay_in_hop": True,
           "python": [3, 11]}
RE_TREE = {"docker": {"Dockerfile": b"FROM x\n", "entrypoint.sh": b"#!/bin/sh\n"},
           "host": {"both_loop.py": b"", "relay.py": b"", "imap_notify.py": b""}}
OPENSSL_OUT = b"/usr/bin/openssl\nOpenSSL 3.0.15 3 Sep 2024 (Library: OpenSSL 3.0.15 3 Sep 2024)\n"


#: The owner the archive checks expect here: this test's own uid stands for root (a2_locks' root_uid, a2_site.Site).
UID = os.getuid()


def lock_root(test):
    """A temporary lock root holding both archives as S4 expects them installed: images/ 0755 and each .tar 0644,
    owned by UID; removed at the test's end."""
    d = tempfile.mkdtemp(prefix="a2s4-")
    test.addCleanup(shutil.rmtree, d, True)
    os.mkdir(os.path.join(d, S.ARCHIVE_DIR))
    os.chmod(os.path.join(d, S.ARCHIVE_DIR), 0o755)
    for name, data in ARCHIVE.items():
        with open(os.path.join(d, S.ARCHIVE_DIR, name + ".tar"), "wb") as f:
            f.write(data)
        os.chmod(os.path.join(d, S.ARCHIVE_DIR, name + ".tar"), 0o644)
    return d


def ls_out(*ids):
    return "".join(i + "\n" for i in ids).encode()


def inspect_doc(iid, commit, wd="/app"):
    return (json.dumps({"Id": iid, "Config": {"Labels": {S.REVISION_LABEL: commit}, "WorkingDir": wd}}) + "\n").encode()


#: `docker version --format '{{.Server.Version}}'` as the CLI prints it: the version and a newline (INFERRED shape;
#: PENDING CAPTURE on a VM).
DOCKER_VERSION_OUT = b"27.5.1\n"
#: `docker image inspect <Id>` as router_fingerprint.capture_image reads it: a list of one object with Config.Env.
RFP_INSPECT = json.dumps([{"Id": RL_ID, "Config": {"Env": ["PATH=/usr/local/bin:/usr/bin:/bin"]}}]).encode()


class FakeLayer:
    """The VM layer's surface S4 uses. `answers` maps a kind of call to (rc, out), or to a list of them taken in
    order; every exec is recorded with its stdin and timeout. Like the real layer, a writing exec makes every later
    cause of the stage exit 3."""

    def __init__(self, lock=None, prior=False, **answers):
        self.lock = lock or s4_lock()
        self.prior = prior
        self.calls = []
        self.installer_dir = os.path.join(REPO_ROOT, "install")
        self.fetched = {"c-" + S.RL_COMPONENT: "/runner/work/c-rl.git"}
        self.git = type("G", (), {"git": "/usr/bin/git"})()
        self.re_tree = copy.deepcopy(RE_TREE)
        self.answers = dict(measure=(0, (json.dumps(MEASURE, sort_keys=True) + "\n").encode()),
                            inspect_rl=(0, inspect_doc(RL_ID, C_RL)), inspect_re=(0, inspect_doc(RE_ID, C_RE)),
                            walk=(0, b"FIRSTPY /app/router/__init__.py\nENTRIES 42 OFF-MODE 0\n"),
                            read=(0, b""), openssl=(0, OPENSSL_OUT), ls=(0, ls_out(RL_ID, RE_ID)), load=(0, b""),
                            testx=(0, b""), version=(0, DOCKER_VERSION_OUT), rfp_inspect=(0, RFP_INSPECT),
                            rfp_run=(1, b""))
        self.answers.update(answers)

    def wrote(self, stage):
        assert stage == S.STAGE
        return self.prior or any(c[4] for c in self.calls)

    def pinned_installer_file(self, name, stage):
        assert (name, stage) == ("vm_measure.py", S.STAGE)
        return b"# measure"

    def component_tree(self, component, prefix, *, stage):
        assert (component, stage) == ("re-component", S.STAGE)
        if prefix not in self.re_tree:
            raise Refusal(S.STAGE + ".PIN", "component tree not pinned or not fetched")
        return "tree", [(n, 0o644, b) for n, b in sorted(self.re_tree[prefix].items())]

    def kind(self, argv):
        if argv[0] == S.PYTHON:
            return "measure"
        if argv[0] == S.TEST:
            assert argv == [S.TEST, "-x", S.DOCKER]
            return "testx"
        if argv[1:2] == ["version"]:
            assert argv == [S.DOCKER, "version", "--format", "{{.Server.Version}}"]
            return "version"
        if argv[1:3] == ["image", "ls"]:
            return "ls"
        if argv[1:3] == ["image", "inspect"] and len(argv) == 4:
            return "rfp_inspect"
        if argv[-1:] == ["image"] and "-c" in argv:
            return "rfp_run"
        if argv[1:] == ["load"]:
            return "load"
        if argv[1:3] == ["image", "inspect"]:
            return "inspect_rl" if argv[-1] == RL_ID else "inspect_re"
        if "-c" in argv and argv[argv.index("-c") + 1] == S.WALK:
            return "walk"
        if S.READ_TEST in argv:
            return "read"
        return "openssl"

    def exec(self, vm, argv, *, account, stage, writes, stdin=None, timeout_s=None):
        self.calls.append((vm, list(argv), account, stage, writes, stdin, timeout_s))
        a = self.answers[self.kind(argv)]
        if isinstance(a, list):
            a = a.pop(0)
        return a + (b"",)


class Refuses(unittest.TestCase):
    def refuses(self, cause, rc, fn, *a, **kw):
        with self.assertRaises(Refusal) as cm:
            fn(*a, **kw)
        self.assertEqual((cm.exception.cause, cm.exception.rc), (cause, rc))


class ImageRowsTest(Refuses):
    def test_two_roles_by_the_rl_component_with_their_commits(self):
        rows = S.image_rows(s4_lock())
        self.assertEqual({r: (rows[r]["component"], rows[r]["commit"], rows[r]["image_id"]) for r in rows},
                         {S.RL: (S.RL_COMPONENT, C_RL, RL_ID), S.RE: ("re-component", C_RE, RE_ID)})
        self.assertEqual(S.plan_facts(rows), [("RL_BUILT_FROM", C_RL), ("RE_BUILT_FROM", C_RE)])

    def test_anything_but_one_rl_and_one_other_image_refuses_lock(self):
        def mut(f):
            d = s4_lock()
            f(d)
            return d
        for name, d in (
                ("one image", mut(lambda d: d["images"].pop())),
                ("three images", mut(lambda d: d["images"].append(dict(d["images"][1], name="x")))),
                ("two RL", mut(lambda d: d["images"][1].__setitem__("built_from", S.RL_COMPONENT))),
                ("no RL", mut(lambda d: d["images"][0].__setitem__("built_from", "re-component"))),
                ("no component", mut(lambda d: d["images"][1].__setitem__("built_from", "nope"))),
                ("short commit", mut(lambda d: d["components"][-2].__setitem__("commit", "2" * 39))),
                ("upper commit", mut(lambda d: d["components"][-2].__setitem__("commit", C_RE.upper()))),
                ("bad id", mut(lambda d: d["images"][0].__setitem__("image_id", "sha256:" + "A" * 64))),
                ("not a list", mut(lambda d: d.__setitem__("images", {}))),
                ("duplicate component", mut(lambda d: d["components"].append(dict(d["components"][-2]))))):
            with self.subTest(name):
                self.refuses("IMAGES.LOCK", 2, S.image_rows, d)


class RuntimeUsersTest(Refuses):
    def test_rl_as_the_agent_and_re_as_the_relay_both_with_the_hop_group(self):
        L = FakeLayer()
        self.assertEqual(S.runtime_users(L, "vm-a", V), {S.RL: "1000:2100", S.RE: "2102:2100"})
        self.assertEqual(L.calls, [("vm-a", [S.PYTHON, "-I", "-S", "-c", "# measure", "relay", "hop"], "agent",
                                    "IMAGES", False, None, None)])

    def test_missing_accounts_root_or_shared_uids_refuse_hosts_and_a_bad_line_unclassified(self):
        self.refuses("IMAGES.HOSTS", 2, S.runtime_users, FakeLayer(measure=(4, b"")), "vm-a", V)
        for k, val in (("uid", 0), ("relay_uid", 0), ("relay_uid", 1000)):
            with self.subTest(k=k, val=val):
                out = (json.dumps(dict(MEASURE, **{k: val}), sort_keys=True) + "\n").encode()
                self.refuses("IMAGES.HOSTS", 2, S.runtime_users, FakeLayer(measure=(0, out)), "vm-a", V)
        for out in (b"", b"{}\n", (json.dumps(dict(MEASURE, uid=True)) + "\n").encode(),
                    json.dumps(MEASURE).encode()):
            with self.subTest(out=out[:20]):
                self.refuses("IMAGES.UNCLASSIFIED", 2, S.runtime_users, FakeLayer(measure=(0, out)), "vm-a", V)

    def test_after_an_obtain_that_wrote_each_cause_exits_3(self):
        self.refuses("IMAGES.HOSTS", 3, S.runtime_users, FakeLayer(prior=True, measure=(4, b"")), "vm-a", V)


class InspectTest(Refuses):
    def test_the_id_and_working_dir_when_the_revision_label_is_the_commit(self):
        L = FakeLayer()
        self.assertEqual(S.inspect(L, "vm-a", V, RL_ID, C_RL), (RL_ID, "/app"))
        self.assertEqual(L.calls[0][1], [S.DOCKER, "image", "inspect", "--format", "{{json .}}", RL_ID])
        self.assertEqual((L.calls[0][2], L.calls[0][4]), ("agent", False))

    def test_an_image_without_a_working_dir_reads_as_app(self):
        doc = json.loads(inspect_doc(RL_ID, C_RL))
        doc["Config"]["WorkingDir"] = ""
        L = FakeLayer(inspect_rl=(0, json.dumps(doc).encode()))
        self.assertEqual(S.inspect(L, "vm-a", V, RL_ID, C_RL), (RL_ID, S.DEFAULT_WORKDIR))

    def test_another_revision_label_refuses_revision(self):
        for label in (C_RE, "", None, C_RL.upper()):
            doc = json.loads(inspect_doc(RL_ID, C_RL))
            doc["Config"]["Labels"] = {S.REVISION_LABEL: label} if label is not None else None
            with self.subTest(label=label):
                self.refuses("IMAGES.REVISION", 2, S.inspect, FakeLayer(inspect_rl=(0, json.dumps(doc).encode())),
                             "vm-a", V, RL_ID, C_RL)

    def test_a_failed_or_malformed_inspect_is_unclassified_and_a_bad_working_dir_readback(self):
        for rc, out in ((1, b""), (0, b"[]"), (0, b"not json"), (0, b'{"Id": "sha256:x", "Config": {}}'),
                        (0, b'{"Id": "' + RL_ID.encode() + b'"}')):
            with self.subTest(rc=rc, out=out[:20]):
                self.refuses("IMAGES.UNCLASSIFIED", 2, S.inspect, FakeLayer(inspect_rl=(rc, out)), "vm-a", V,
                             RL_ID, C_RL)
        for wd in ("app", "/app/../etc", "/app/", "/a b"):
            with self.subTest(wd=wd):
                self.refuses("IMAGES.READBACK", 2, S.inspect, FakeLayer(inspect_rl=(0, inspect_doc(RL_ID, C_RL, wd))),
                             "vm-a", V, RL_ID, C_RL)


class ReadbackTest(Refuses):
    def test_the_walk_as_root_then_each_needed_file_and_the_first_py_as_the_runtime_user(self):
        L = FakeLayer()
        self.assertEqual(S.readback(L, "vm-a", V, RE_ID, "/app", "2102:2100", S.RE_NEEDED), 42)
        walk, reads = L.calls[0][1], [c[1] for c in L.calls[1:]]
        self.assertEqual(walk, [S.DOCKER] + S.ONE_SHOT + ["--user", "0:0", "--entrypoint", S.IMAGE_PYTHON, RE_ID,
                                                          "-I", "-S", "-c", S.WALK, "/app"] + list(S.RE_NEEDED))
        self.assertEqual([r[-1] for r in reads], ["/app/" + p for p in S.RE_NEEDED] + ["/app/router/__init__.py"])
        for r in reads:
            self.assertEqual(r[:len(S.ONE_SHOT) + 1], [S.DOCKER] + S.ONE_SHOT)
            self.assertEqual(r[r.index("--user") + 1], "2102:2100")
            self.assertEqual(r[r.index("--entrypoint") + 1], "/bin/sh")
        self.assertTrue(all(c[4] is False for c in L.calls))

    def test_an_off_mode_entry_or_an_unreadable_file_refuses_readback(self):
        for out in (b"FIRSTPY /app/x.py\nENTRIES 42 OFF-MODE 1\n", b"FIRSTPY -\nENTRIES 42 OFF-MODE 0\n",
                    b"FIRSTPY /app/x.py\nENTRIES 42 OFF-MODE 0\nOFF 0666 0:0 /app/x\n", b""):
            with self.subTest(out=out):
                self.refuses("IMAGES.READBACK", 2, S.readback, FakeLayer(walk=(0, out)), "vm-a", V, RE_ID, "/app",
                             "2102:2100", S.RE_NEEDED)
        self.refuses("IMAGES.READBACK", 2, S.readback, FakeLayer(walk=(1, b"FIRSTPY /app/x.py\nENTRIES 42 OFF-MODE 0\n")),
                     "vm-a", V, RE_ID, "/app", "2102:2100", S.RE_NEEDED)
        self.refuses("IMAGES.READBACK", 2, S.readback, FakeLayer(read=(1, b"")), "vm-a", V, RE_ID, "/app",
                     "2102:2100", S.RE_NEEDED)


class OneShotAndWalkTest(unittest.TestCase):
    def test_the_one_shot_flags_are_vm_build_r2s(self):
        self.assertEqual(S.ONE_SHOT, ["run", "--rm", "--pull", "never", "--log-driver", "none", "--network", "none",
                                      "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges"])

    def test_the_walk_counts_every_entry_and_finds_one_not_root_owned_here(self):
        """WALK, run here as this (non-root) uid on a staged tree: every entry and the root count as off-mode, so it
        exits 1; it names the first .py and counts the entries (symlinks skipped)."""
        import subprocess
        import tempfile
        d = tempfile.mkdtemp(prefix="a2s4-")
        self.addCleanup(shutil.rmtree, d, True)
        os.makedirs(os.path.join(d, "app", "router"))
        for rel in ("router/__init__.py", "router/b.py", "README"):
            with open(os.path.join(d, "app", rel), "w") as f:
                f.write("x")
        os.symlink("README", os.path.join(d, "app", "link"))
        p = subprocess.run([sys.executable, "-I", "-S", "-c", S.WALK, os.path.join(d, "app")], capture_output=True,
                           stdin=subprocess.DEVNULL)
        self.assertEqual(p.returncode, 0 if os.getuid() == 0 else 1)
        self.assertEqual(p.stdout.decode().split("\n")[:2],
                         ["FIRSTPY " + os.path.join(d, "app", "router", "__init__.py"),
                          "ENTRIES 4 OFF-MODE %d" % (0 if os.getuid() == 0 else 5)])


#: Runs WALK (argv[1]) with os.lstat reporting every non-link entry as root-owned, directories 0755 and other files
#: 0644, except where argv[2] (a JSON map, keyed by basename) overrides an entry's "mode", "uid" or "gid". WALK's own
#: `import os` gets this module, so its lstat is the patched one; argv[3:] are WALK's own arguments.
ROOT_LSTAT = r'''import json, os, stat, sys
walk, over, real = sys.argv[1], json.loads(sys.argv[2]), os.lstat
def lstat(p, *a, **kw):
    st = real(p, *a, **kw)
    if stat.S_ISLNK(st.st_mode):
        return st
    o = over.get(os.path.basename(p), {})
    t = list(st)
    t[0] = stat.S_IFMT(st.st_mode) | o.get("mode", 0o755 if stat.S_ISDIR(st.st_mode) else 0o644)
    t[4], t[5] = o.get("uid", 0), o.get("gid", 0)
    return os.stat_result(t)
os.lstat = lstat
sys.argv = ["walk"] + sys.argv[3:]
exec(compile(walk, "walk", "exec"), {"__name__": "__main__"})
'''


class WalkAsRootTest(unittest.TestCase):
    """The real WALK, its owner and mode rules deciding (ROOT_LSTAT stands for an image's root-owned tree), on a staged
    tree: app/ holds a.py/ (a directory named like a module), README, router/__init__.py, `linked` (a symlink to
    router/) and `link` (a symlink to README). Each case asserts the exit status, both lines and FIRSTPY."""

    def setUp(self):
        d = tempfile.mkdtemp(prefix="a2s4-")
        self.addCleanup(shutil.rmtree, d, True)
        self.app = os.path.join(d, "app")
        os.makedirs(os.path.join(self.app, "router"))
        os.mkdir(os.path.join(self.app, "a.py"))
        for rel in ("router/__init__.py", "README"):
            with open(os.path.join(self.app, rel), "w") as f:
                f.write("x")
        os.symlink("router", os.path.join(self.app, "linked"))
        os.symlink("README", os.path.join(self.app, "link"))

    def walk(self, over=None, need=()):
        import subprocess
        p = subprocess.run([sys.executable, "-I", "-S", "-c", ROOT_LSTAT, S.WALK, json.dumps(over or {}), self.app]
                           + list(need), capture_output=True, stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout.decode().split("\n")[:2]

    def test_a_root_owned_tree_passes_with_its_first_module_a_file_not_the_directory_named_a_py(self):
        self.assertEqual(self.walk(), (0, ["FIRSTPY " + os.path.join(self.app, "router", "__init__.py"),
                                           "ENTRIES 4 OFF-MODE 0"]))

    def test_each_owner_or_mode_off_by_one_rule_is_one_off_entry(self):
        first = "FIRSTPY " + os.path.join(self.app, "router", "__init__.py")
        for over in ({"app": {"mode": 0o750}}, {"app": {"gid": 1000}}, {"README": {"gid": 1000}},
                     {"README": {"uid": 1000}}, {"README": {"mode": 0o664}}, {"__init__.py": {"mode": 0o600}},
                     {"router": {"mode": 0o775}}, {"a.py": {"mode": 0o700}}):
            with self.subTest(over=over):
                self.assertEqual(self.walk(over), (1, [first, "ENTRIES 4 OFF-MODE 1"]))
        self.assertEqual(self.walk({"README": {"mode": 0o755}}), (0, [first, "ENTRIES 4 OFF-MODE 0"]))

    def test_each_needed_path_must_be_a_regular_file_the_walk_reached(self):
        """A needed path under a symlinked directory, a needed symlink, a needed directory and a missing one are each
        one off entry; one the walk reached as a regular file is not (gate A N1, gate B N7)."""
        first = "FIRSTPY " + os.path.join(self.app, "router", "__init__.py")
        self.assertEqual(self.walk(need=["router/__init__.py", "README"]), (0, [first, "ENTRIES 4 OFF-MODE 0"]))
        for need in (["linked/__init__.py"], ["link"], ["a.py"], ["router/b.py"], ["README", "linked/__init__.py"]):
            with self.subTest(need=need):
                self.assertEqual(self.walk(need=need), (1, [first, "ENTRIES 4 OFF-MODE 1"]))


class ImagePythonTest(unittest.TestCase):
    def test_every_in_image_entrypoint_is_the_images_python_and_the_vm_host_keeps_its_own(self):
        """Through the real check_vm: each one-shot whose entrypoint is a python3 names IMAGE_PYTHON, the path inside
        python:3.11-slim (INFERRED, PENDING CAPTURE); the VM host's measure runs PYTHON."""
        self.assertEqual((S.PYTHON, S.IMAGE_PYTHON), ("/usr/bin/python3", "/usr/local/bin/python3"))
        L = FakeLayer(rfp_run=(1, b""))
        rfp = S.fingerprint_modules(FakeLayer())
        with self.assertRaises(Refusal):
            S.check_vm(L, "vm-a", V, S.image_rows(L.lock), {S.RL: RL_ID, S.RE: RE_ID}, "0", rfp, S.RE_NEEDED)
        entry = [c[1][c[1].index("--entrypoint") + 1] for c in L.calls if "--entrypoint" in c[1]]
        self.assertIn(S.IMAGE_PYTHON, entry)
        self.assertNotIn(S.PYTHON, entry)
        self.assertEqual([c[1][0] for c in L.calls if c[1][0] != S.DOCKER], [S.PYTHON])


class ReadTestTest(unittest.TestCase):
    def test_the_per_file_test_passes_a_readable_regular_file_only(self):
        """READ_TEST run by the real /bin/sh: a regular readable file passes; a symlink (even to a readable file), a
        directory, a missing path and an unreadable file do not."""
        import subprocess
        d = tempfile.mkdtemp(prefix="a2s4rt-")
        self.addCleanup(shutil.rmtree, d, True)
        f, link, sub, closed = (os.path.join(d, n) for n in ("f", "link", "sub", "closed"))
        for p in (f, closed):
            with open(p, "w") as h:
                h.write("x")
        os.chmod(closed, 0)
        os.symlink(f, link)
        os.mkdir(sub)
        want = {f: 0, link: 1, sub: 1, os.path.join(d, "absent"): 1}
        if os.getuid() != 0:
            want[closed] = 1
        for path, rc in want.items():
            with self.subTest(path=os.path.basename(path)):
                p = subprocess.run(["/bin/sh", "-c", S.READ_TEST, "readback", path], stdin=subprocess.DEVNULL)
                self.assertEqual(p.returncode, rc)


class OpensslTest(Refuses):
    def test_an_absolute_openssl_at_or_above_3_0(self):
        L = FakeLayer()
        self.assertEqual(S.openssl(L, "vm-a", V, RL_ID), "version=3.0.15|path=/usr/bin/openssl")
        argv = L.calls[0][1]
        self.assertEqual(argv[argv.index("--entrypoint") + 1], "/bin/sh")

    def test_no_cli_an_old_version_or_a_relative_path_refuses_openssl(self):
        for rc, out in ((9, b""), (0, b"/usr/bin/openssl\nOpenSSL 1.1.1w 11 Sep 2023\n"),
                        (0, b"openssl\nOpenSSL 3.0.15 3 Sep 2024\n"), (0, b"/usr/bin/openssl\nLibreSSL 3.8.2\n"),
                        (0, b"/usr/bin/openssl\n"), (0, OPENSSL_OUT + b"extra\n")):
            with self.subTest(rc=rc, out=out):
                self.refuses("IMAGES.OPENSSL", 2, S.openssl, FakeLayer(openssl=(rc, out)), "vm-a", V, RL_ID)

    def test_a_version_group_past_nine_digits_refuses_openssl_not_an_unnamed_error(self):
        for v in (b"3.0." + b"1" * 10, b"3." + b"0" * 5000 + b".1", b"3" * 5000 + b".0.1"):
            with self.subTest(v=v[:20]):
                self.refuses("IMAGES.OPENSSL", 2, S.openssl, FakeLayer(openssl=(0, b"/usr/bin/openssl\nOpenSSL " + v
                                                                                   + b" 3 Sep 2024\n")), "vm-a", V, RL_ID)
        self.assertEqual(S.openssl(FakeLayer(openssl=(0, b"/usr/bin/openssl\nOpenSSL 3.0.123456789 x\n")), "vm-a", V,
                                   RL_ID), "version=3.0.123456789|path=/usr/bin/openssl")


class ReNeededTest(Refuses):
    def setUp(self):
        # The derivation pins, met by the fake tree: S4 compares the bytes' sha256 with RE_DERIVATION_PINS.
        self.addCleanup(setattr, S, "RE_DERIVATION_PINS", S.RE_DERIVATION_PINS)
        S.RE_DERIVATION_PINS = {p: hashlib.sha256(RE_TREE[p.split("/")[0]][p.split("/")[1]]).hexdigest()
                                for p in S.RE_DERIVATION_PINS}

    def test_the_mode_s8_runs_gives_the_exec_chain_of_both(self):
        self.assertEqual(S.re_needed(FakeLayer()), ("docker/entrypoint.sh", "host/both_loop.py", "host/relay.py",
                                                     "host/imap_notify.py"))

    def test_another_dockerfile_or_entrypoint_or_a_missing_file_refuses_pin(self):
        for prefix, name, data in (("docker", "Dockerfile", b"FROM y\n"), ("docker", "entrypoint.sh", b"#!/bin/bash\n")):
            L = FakeLayer()
            L.re_tree[prefix][name] = data
            with self.subTest(name):
                self.refuses("IMAGES.PIN", 2, S.re_needed, L)
        for prefix, name in (("host", "imap_notify.py"), ("docker", "Dockerfile")):
            L = FakeLayer()
            del L.re_tree[prefix][name]
            with self.subTest(missing=name):
                self.refuses("IMAGES.PIN", 2, S.re_needed, L)
        L = FakeLayer()
        del L.re_tree["host"]
        self.refuses("IMAGES.PIN", 2, S.re_needed, L)


class ReModeTest(unittest.TestCase):
    def test_re_mode_is_the_mode_s8_starts_re_in(self):
        """RE_MODE is S8's start argv's last word: the two cannot drift."""
        env = {k: "/x/" + k.lower() for k in a2_s8_re.RW_KNOBS + a2_s8_re.RO_KNOBS}
        argv = a2_s8_re.start_argv(env, "/e", RE_ID, 2102, 2102, 2100)
        self.assertEqual((argv[-2], argv[-1]), (RE_ID, S.RE_MODE))
        self.assertIn(S.RE_MODE, S.RE_NEEDED_BY_MODE)


class StubRfp:
    """router_fingerprint's surface S4 calls, recording its arguments; `outcome` is verify_image's."""
    EXACT = "exact"
    CaptureError = type("CaptureError", (Exception,), {})
    HistoryReadError = type("HistoryReadError", (Exception,), {})
    PROGRAM = "print('stub program')"

    def __init__(self, outcome="exact", code=0, fail=None, captured_id=RL_ID):
        self.outcome, self.code, self.fail, self.captured_id, self.log = outcome, code, fail, captured_id, []

    def capture_image(self, docker, ref, run):
        self.log.append(("capture", docker, ref))
        p = run([S.DOCKER, "image", "inspect", ref], capture_output=True, timeout=300)
        self.log.append(("ran", p.args, p.returncode))
        if self.fail == "capture":
            raise self.CaptureError("x")
        return {"image": {"ref": ref, "id": self.captured_id}}

    def read_history(self, repo, target, measured_from, git):
        self.log.append(("history", repo, target, measured_from, git))
        if self.fail == "history":
            raise self.HistoryReadError("x")
        return {"h": 1}

    def canonical(self, doc):
        return json.dumps(doc, sort_keys=True).encode()

    def verify_image(self, capture, history, commit):
        self.log.append(("verify", json.loads(capture), history, commit))
        return self.outcome, self.code, "r", "t"


class FingerprintTest(Refuses):
    def test_exact_with_the_docker_call_carried_by_the_layer_and_the_history_from_s0s_fetch(self):
        L, rfp = FakeLayer(), StubRfp()
        self.assertEqual(S.fingerprint(L, "vm-a", V, RL_ID, C_RL, rfp), "EXACT")
        self.assertEqual(rfp.log[0], ("capture", [S.DOCKER], RL_ID))
        self.assertEqual(rfp.log[1][1:], ([S.DOCKER, "image", "inspect", RL_ID], 0))
        self.assertEqual(L.calls,
                         [("vm-a", [S.DOCKER, "image", "inspect", RL_ID], "agent", "IMAGES", False, None, 300)])
        self.assertEqual(rfp.log[2], ("history", "/runner/work/c-rl.git", C_RL, C_RL, "/usr/bin/git"))
        self.assertEqual(rfp.log[3][3], C_RL)

    def test_not_exact_a_capture_or_history_failure_or_another_image_refuses_fingerprint(self):
        for rfp in (StubRfp(outcome="differs", code=1), StubRfp(code=1), StubRfp(fail="capture"),
                    StubRfp(fail="history"), StubRfp(captured_id=RE_ID)):
            with self.subTest(outcome=rfp.outcome, code=rfp.code, fail=rfp.fail, id=rfp.captured_id):
                self.refuses("IMAGES.FINGERPRINT", 2, S.fingerprint, FakeLayer(), "vm-a", V, RL_ID, C_RL, rfp)

    def test_an_unfetched_rl_repository_refuses_pin(self):
        L = FakeLayer()
        L.fetched = {}
        self.refuses("IMAGES.PIN", 2, S.fingerprint, L, "vm-a", V, RL_ID, C_RL, StubRfp())

    def test_the_layer_runner_admits_only_capture_images_two_argvs_for_the_locks_id(self):
        L = FakeLayer()
        run = S.layer_runner(L, "vm-a", V, RL_ID, "P")
        one = [S.DOCKER, "run", "--rm", "--network", "none", "--entrypoint", "python3", RL_ID, "-I", "-S", "-c", "P",
               "image"]
        for argv in (["/bin/sh", "-c", "x"], [S.DOCKER, "image", "inspect", RE_ID], [S.DOCKER, "image", "rm", RL_ID],
                     [S.DOCKER, "image", "inspect", "--format", "{{json .}}", RL_ID], one[:7] + [RE_ID] + one[8:],
                     one[:-2] + ["Q", "image"], one + ["x"], [S.DOCKER, "run", "--privileged"] + one[2:]):
            with self.subTest(argv=argv):
                with self.assertRaises(OSError):
                    run(argv)
        self.assertEqual(L.calls, [])

    def test_the_layer_runner_refuses_any_keyword_but_capture_output_and_timeout(self):
        L = FakeLayer()
        run = S.layer_runner(L, "vm-a", V, RL_ID, "P")
        for kw in ({"input": b"x"}, {"env": {}}, {"cwd": "/"}, {"check": True}):
            with self.subTest(kw=kw):
                with self.assertRaises(OSError):
                    run([S.DOCKER, "image", "inspect", RL_ID], **kw)
        self.assertEqual(L.calls, [])
        run([S.DOCKER, "image", "inspect", RL_ID], capture_output=True, timeout=7)
        self.assertEqual([c[6] for c in L.calls], [7])

    def test_the_real_modules_capture_reaches_the_vm_as_s4s_one_shot_with_its_timeout(self):
        """router_fingerprint.capture_image itself (the pinned module, loaded as S4 loads it), through layer_runner:
        its inspect is sent as it is, and its run becomes ONE_SHOT with the absolute entrypoint. The fake run exits 1,
        so the capture fails: FINGERPRINT."""
        rfp = S.fingerprint_modules(FakeLayer())
        L = FakeLayer()
        self.refuses("IMAGES.FINGERPRINT", 2, S.fingerprint, L, "vm-a", V, RL_ID, C_RL, rfp)
        self.assertEqual([c[1:] for c in L.calls], [
            ([S.DOCKER, "image", "inspect", RL_ID], "agent", "IMAGES", False, None, 300),
            ([S.DOCKER] + S.ONE_SHOT + ["--entrypoint", S.IMAGE_PYTHON, RL_ID, "-I", "-S", "-c", rfp.PROGRAM, "image"],
             "agent", "IMAGES", False, None, 300)])


class FingerprintModulesTest(Refuses):
    def test_the_repository_roots_files_load_when_their_rows_pin_them(self):
        before = sys.modules.get("hygiene_gate")
        rfp = S.fingerprint_modules(FakeLayer())
        for name in ("capture_image", "read_history", "verify_image", "canonical", "EXACT", "CaptureError"):
            self.assertTrue(hasattr(rfp, name), name)
        self.assertEqual(rfp.__file__, os.path.join(REPO_ROOT, "router_fingerprint.py"))
        self.assertIs(sys.modules.get("hygiene_gate"), before)

    def test_another_sha_or_a_missing_or_doubled_row_refuses_pin(self):
        for fname in S.FINGERPRINT_FILES:
            for how in ("sha", "missing", "double"):
                lock = s4_lock()
                rows = [f for f in lock["files"] if f["path"] == fname]
                if how == "sha":
                    rows[0]["sha256"] = "0" * 64
                elif how == "missing":
                    lock["files"].remove(rows[0])
                else:
                    lock["files"].append(dict(rows[0]))
                with self.subTest(fname=fname, how=how):
                    self.refuses("IMAGES.PIN", 2, S.fingerprint_modules, FakeLayer(lock=lock))


class ReFixTest(Refuses):
    """re_fix on a real git repository and the real a2_git.Git: the fix commit an ancestor, the built-from commit
    itself, on a side branch, or absent."""

    def setUp(self):
        import a2_git
        import tempfile
        self.d = tempfile.mkdtemp(prefix="a2s4git-")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.work = os.path.join(self.d, "re")
        os.mkdir(self.work)
        a2fix.git(self.work, "init", "-q")
        self.c = {}
        for name in ("base", "fix", "after"):
            with open(os.path.join(self.work, "f"), "w") as f:
                f.write(name)
            a2fix.git(self.work, "add", "-A")
            a2fix.git(self.work, "-c", "user.name=t", "-c", "user.email=t@example.org", "commit", "-q", "-m", name)
            self.c[name] = a2fix.git(self.work, "rev-parse", "HEAD")
        a2fix.git(self.work, "checkout", "-q", "-b", "side", self.c["base"])
        with open(os.path.join(self.work, "f"), "w") as f:
            f.write("side")
        a2fix.git(self.work, "-c", "user.name=t", "-c", "user.email=t@example.org", "commit", "-q", "-am", "side")
        self.c["side"] = a2fix.git(self.work, "rev-parse", "HEAD")
        self.bare = os.path.join(self.d, "re.git")
        a2fix.git(self.d, "clone", "-q", "--bare", self.work, self.bare)
        self.git = a2_git.Git(a2_git.env_for(self.d))
        self.addCleanup(setattr, S, "RE_FIX_COMMIT", S.RE_FIX_COMMIT)
        S.RE_FIX_COMMIT = self.c["fix"]

    def layer(self, built_from):
        lock = s4_lock()
        [c for c in lock["components"] if c["name"] == "re-component"][0]["commit"] = built_from
        L = FakeLayer(lock=lock)
        L.git, L.fetched = self.git, {"c-re-component": self.bare}
        return L

    def test_the_fix_or_a_descendant_gives_0(self):
        for built in ("fix", "after"):
            with self.subTest(built=built):
                L = self.layer(self.c[built])
                self.assertEqual(S.re_fix(L, S.image_rows(L.lock)), "0")
                self.assertEqual(L.calls, [], "read on the runner: no VM contact")

    def test_a_side_branch_an_older_commit_or_an_absent_fix_refuses_re_fix_and_no_fetch_pin(self):
        for built in ("side", "base"):
            with self.subTest(built=built):
                L = self.layer(self.c[built])
                self.refuses("IMAGES.RE_FIX", 2, S.re_fix, L, S.image_rows(L.lock))
        S.RE_FIX_COMMIT = "f" * 40
        L = self.layer(self.c["after"])
        self.refuses("IMAGES.RE_FIX", 2, S.re_fix, L, S.image_rows(L.lock))
        L.fetched = {}
        self.refuses("IMAGES.PIN", 2, S.re_fix, L, S.image_rows(L.lock))

    def test_the_fix_commit_is_w12s(self):
        """The constant as shipped (setUp replaces it for the history tests)."""
        with open(S.__file__) as f:
            self.assertEqual(f.read().count('\nRE_FIX_COMMIT = "fc542edc9f829c89c6378755b87acd26681571d8"\n'), 1)


class CheckVmTest(Refuses):
    def test_the_facts_of_one_vm(self):
        L = FakeLayer()
        facts = S.check_vm(L, "vm-a", V, S.image_rows(L.lock), {S.RL: RL_ID, S.RE: RE_ID}, "0", rfp=StubRfp(),
                           needed=S.RE_NEEDED)
        self.assertEqual(facts, [
            ("RE_FIX_ANCESTOR", "0"),
            ("RL_IMAGE", RL_ID), ("RL_BUILT_FROM", C_RL), ("RL_READBACK", "PASS entries=42"),
            ("RL_OPENSSL", "version=3.0.15|path=/usr/bin/openssl"), ("RL_FINGERPRINT", "EXACT"),
            ("RE_IMAGE", RE_ID), ("RE_BUILT_FROM", C_RE), ("RE_READBACK", "PASS entries=42"),
            ("RE_OPENSSL", "version=3.0.15|path=/usr/bin/openssl")])
        self.assertTrue(all(c[4] is False for c in L.calls), "S4's checks write nothing")
        for c in L.calls:
            if c[1][1:2] == ["run"]:
                self.assertIn("--entrypoint", c[1], "every one-shot sets its entrypoint (3.5 K2)")
                self.assertEqual(c[1][1:len(S.ONE_SHOT) + 1], S.ONE_SHOT)

    def test_the_re_image_is_read_as_the_relay_and_rl_as_the_agent(self):
        L = FakeLayer()
        S.check_vm(L, "vm-a", V, S.image_rows(L.lock), {S.RL: RL_ID, S.RE: RE_ID}, "0", rfp=StubRfp(), needed=S.RE_NEEDED)
        users = {(c[1][c[1].index("--user") + 1], c[1][c[1].index("--entrypoint") + 2])
                 for c in L.calls if S.READ_TEST in c[1]}
        self.assertEqual(users, {("1000:2100", RL_ID), ("2102:2100", RE_ID)})


class CheckVmIdTest(Refuses):
    def test_an_inspected_id_that_is_not_the_locks_refuses_for_each_role(self):
        other = "sha256:" + "b" * 64
        for role, kind, commit in ((S.RL, "inspect_rl", C_RL), (S.RE, "inspect_re", C_RE)):
            for prior, rc in ((False, 2), (True, 3)):
                with self.subTest(role=role, prior=prior):
                    L = FakeLayer(prior=prior, **{kind: (0, inspect_doc(other, commit))})
                    self.refuses("IMAGES.UNCLASSIFIED", rc, S.check_vm, L, "vm-a", V, S.image_rows(L.lock),
                                 {S.RL: RL_ID, S.RE: RE_ID}, "0", StubRfp(), S.RE_NEEDED)
                    self.assertFalse([c for c in L.calls if c[1][1:2] == ["run"] and other in c[1]],
                                     "no check runs on an Id the lock does not pin")


class RealLayerTest(test_a2_vm.Base):
    """S4's VM calls on a real VmLayer, over test_a2_vm's fake ssh: the real vm_measure.py through the real
    launcher (REAL-PROBED, as this uid), and the docker argv as the layer sends it."""

    def setUp(self):
        super().setUp()
        shutil.copyfile(os.path.join(test_a2_vm.INSTALL, "vm_measure.py"), os.path.join(self.inst, "vm_measure.py"))
        with open(os.path.join(self.inst, "MANIFEST"), "w") as f:
            for name in ("vm_bootstrap.py", "vm_launch.py", "vm_measure.py"):
                f.write("%s  %s\n" % (self.sha_file(os.path.join(self.inst, name)), name))
        self.lock["installer"]["sha256"] = self.manifest_sha()
        me = pwd.getpwuid(os.getuid())
        self.v = {"name": "vm-a", "agent_account": me.pw_name, "relay_account": "nobody",
                  "hop_group": grp.getgrgid(os.getgid()).gr_name}

    def test_the_runtime_users_from_the_real_measure_script(self):
        L = self.layer()
        got = S.runtime_users(L, "vm-a", self.v)
        hop = grp.getgrgid(os.getgid()).gr_gid
        self.assertEqual(got, {S.RL: "%d:%d" % (os.getuid(), hop), S.RE: "%d:%d" % (pwd.getpwnam("nobody").pw_uid, hop)})
        self.assertEqual(L._wrote, set(), "the measure is a read")

    def test_the_relay_as_the_agent_refuses_hosts(self):
        self.v["relay_account"] = self.v["agent_account"]
        with self.assertRaises(Refusal) as cm:
            S.runtime_users(self.layer(), "vm-a", self.v)
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("IMAGES.HOSTS", 2))

    def test_the_inspect_argv_reaches_the_vm_word_for_word(self):
        L = self.layer()
        with self.assertRaises(Refusal):
            S.inspect(L, "vm-a", self.v, RL_ID, C_RL)
        log = "\n".join(self.logged())
        # The ssh line carries the remote string, each word shell-quoted; sudo's line, the words as the VM parsed them.
        self.assertIn(" /usr/bin/docker image inspect --format '{{json .}}' " + RL_ID + "\n", log + "\n")
        self.assertTrue(log.endswith(" /usr/bin/docker image inspect --format {{json .}} " + RL_ID), log[-200:])
        self.assertEqual(L._wrote, set())

    def test_the_load_reaches_the_vm_with_the_archive_on_its_stdin_and_is_a_write(self):
        """The fake ssh records every stdin byte (`tee`). The docker it runs is a stand-in that reads its stdin to EOF
        and exits 1, as a refused load does, so no real docker is ever reached: LOAD, 3."""
        open(os.path.join(self.fake, "tee"), "w").close()
        docker = os.path.join(self.fake, "docker")
        with open(docker, "w") as f:
            f.write('#!/bin/sh\n[ "$*" = load ] || exit 9\ncat > %s.stdin\nexit 1\n' % docker)
        os.chmod(docker, 0o755)
        L = self.layer()
        with mock.patch.object(S, "image_ids", lambda layer, vm, v: set()), mock.patch.object(S, "DOCKER", docker):
            with self.assertRaises(Refusal) as cm:
                S.obtain(L, "vm-a", self.v, S.image_rows(s4_lock()), lock_root(self), UID)
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("IMAGES.LOAD", 3))
        for got in ("stdin.bytes", "docker.stdin"):
            with open(os.path.join(self.fake, got), "rb") as f:
                self.assertEqual(f.read(), ARCHIVE["rl-img"], got)
        self.assertTrue("\n".join(self.logged()).endswith(" " + docker + " load"))
        self.assertEqual(L._wrote, {S.STAGE})

    def test_a_load_that_times_out_is_target_access_3_and_the_stage_is_written(self):
        """The real VmLayer, its ssh call timing out during `docker load`: the layer's TARGET_ACCESS, exit 3 (4.2's
        LOAD row), and the stage counted as written."""
        import a2_vm
        import subprocess
        L = self.layer()

        def timeout(*a, **kw):
            raise subprocess.TimeoutExpired(a[0] if a else "ssh", 1)
        with mock.patch.object(S, "image_ids", lambda layer, vm, v: set()), \
                mock.patch.object(a2_vm.subprocess, "run", timeout):
            with self.assertRaises(Refusal) as cm:
                S.obtain(L, "vm-a", self.v, S.image_rows(s4_lock()), lock_root(self), UID)
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("IMAGES.TARGET_ACCESS", 3))
        self.assertEqual(L._wrote, {S.STAGE})


class Rec:
    def __init__(self):
        self.receipts = []

    def write_receipt(self, stage_id, host, started, result, facts, rc=0, cause=None):
        self.receipts.append((stage_id, host, result, list(facts), rc, cause))


def run_args(command="install", layer=None, root=None, extra=()):
    inv = type("Inv", (), {"command": command, "loop": "L2"})()
    c = type("C", (), {"lock": s4_lock(), "inv": inv, "lock_root": root,
                       "hosts": {"vms": [dict(V, scope="loop"), dict(V, name="vm-b", scope="loop")] + list(extra)}})()
    site = type("Site", (), {"vm_layer": layer, "now": 0, "root_uid": UID})()
    return c, site, Rec()


def pin_fake_tree(test):
    """RE_DERIVATION_PINS set to the fake RE tree's bytes, restored at the test's end."""
    test.addCleanup(setattr, S, "RE_DERIVATION_PINS", S.RE_DERIVATION_PINS)
    S.RE_DERIVATION_PINS = {p: hashlib.sha256(RE_TREE[p.split("/")[0]][p.split("/")[1]]).hexdigest()
                            for p in S.RE_DERIVATION_PINS}


class RunS4Test(unittest.TestCase):
    def setUp(self):
        pin_fake_tree(self)
    def test_a_dry_run_plans_each_vms_built_from_commits_and_touches_no_vm(self):
        c, site, rec = run_args("dry-run", FakeLayer())
        S.run_s4(c, site, rec)
        self.assertEqual(rec.receipts, [("S4", n, "PLANNED", [("RL_BUILT_FROM", C_RL), ("RE_BUILT_FROM", C_RE)], 0,
                                         None) for n in ("vm-a", "vm-b")])
        self.assertEqual(site.vm_layer.calls, [])

    def test_the_re_fix_is_read_before_any_vm_and_its_refusal_is_the_first_vms_exit_2(self):
        L = FakeLayer()
        L.fetched = {}
        c, site, rec = run_args("install", L, lock_root(self))
        with self.assertRaises(Refusal) as cm:
            S.run_s4(c, site, rec)
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("IMAGES.PIN", 2))
        self.assertEqual(rec.receipts, [("S4", "vm-a", "FAIL", [], 2, "IMAGES.PIN")])
        self.assertEqual(L.calls, [])

    def run_stubbed(self, L, root):
        """run_s4 with re_fix and check_vm stood in (each has its own tests): the obtain step and RESULT."""
        for name, fn in (("re_fix", lambda layer, rows: "0"),
                         ("check_vm", lambda layer, vm, v, rows, refs, fix, rfp, needed:
                          [("CHECKED", refs[S.RL] + refs[S.RE])])):
            p = mock.patch.object(S, name, fn)
            p.start()
            self.addCleanup(p.stop)
        c, site, rec = run_args("install", L, root)
        S.run_s4(c, site, rec)
        return rec

    def test_a_load_on_one_vm_is_changed_and_a_vm_holding_both_is_already(self):
        L = FakeLayer(ls=[(0, ls_out(RE_ID)), (0, ls_out(RL_ID, RE_ID)), (0, ls_out(RE_ID, RL_ID))])
        rec = self.run_stubbed(L, lock_root(self))
        self.assertEqual(rec.receipts, [
            ("S4", "vm-a", "CHANGED", [("DOCKER_VERSION", "27.5.1"), ("RL_LOADED", "yes"), ("RE_LOADED", "no"),
                                       ("CHECKED", RL_ID + RE_ID)], 0, None),
            ("S4", "vm-b", "ALREADY", [("DOCKER_VERSION", "27.5.1"), ("RL_LOADED", "no"), ("RE_LOADED", "no"),
                                       ("CHECKED", RL_ID + RE_ID)], 0, None)])
        self.assertEqual([(c[0], c[5]) for c in L.calls if c[4]], [("vm-a", ARCHIVE["rl-img"])])

    def test_docker_is_checked_on_each_vm_before_its_image_list_and_its_version_is_a_receipt_fact(self):
        L = FakeLayer(version=[(0, b"27.5.1\n"), (0, b"28.0.4\n")])
        rec = self.run_stubbed(L, lock_root(self))
        self.assertEqual([r[3][0] for r in rec.receipts], [("DOCKER_VERSION", "27.5.1"), ("DOCKER_VERSION", "28.0.4")])
        for vm in ("vm-a", "vm-b"):
            kinds = [L.kind(c[1]) for c in L.calls if c[0] == vm]
            self.assertEqual(kinds[:3], ["testx", "version", "ls"], vm)
        self.assertTrue(all(c[2] == V["agent_account"] and not c[4] for c in L.calls
                            if L.kind(c[1]) in ("testx", "version")))

    def test_docker_absent_or_unreachable_is_images_docker_with_no_other_docker_call_on_that_vm(self):
        for answers in (dict(testx=(1, b"")), dict(testx=(2, b"")), dict(version=(1, b"27.5.1\n")),
                        dict(version=(125, b""))):
            with self.subTest(answers=answers):
                L = FakeLayer(**answers)
                c, site, rec = run_args("install", L, lock_root(self))
                with mock.patch.object(S, "re_fix", lambda layer, rows: "0"):
                    with self.assertRaises(Refusal) as cm:
                        S.run_s4(c, site, rec)
                self.assertEqual((cm.exception.cause, cm.exception.rc), ("IMAGES.DOCKER", 2))
                self.assertEqual(rec.receipts, [("S4", "vm-a", "FAIL", [], 2, "IMAGES.DOCKER")])
                self.assertNotIn("ls", [L.kind(c[1]) for c in L.calls])
                self.assertFalse(any(c[4] for c in L.calls))

    def test_docker_on_a_later_vm_after_an_earlier_vms_load_is_exit_3(self):
        L = FakeLayer(ls=[(0, ls_out(RE_ID)), (0, ls_out(RL_ID, RE_ID))], testx=[(0, b""), (1, b"")])
        with self.assertRaises(Refusal) as cm:
            self.run_stubbed(L, lock_root(self))
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("IMAGES.DOCKER", 3))

    def test_the_version_is_recorded_only_when_version_shaped_and_its_text_never_decides(self):
        for out, want in ((b"27.5.1\n", "27.5.1"), (b"24.0.7-0ubuntu4\n", "24.0.7-0ubuntu4"), (b"27.5.1", "UNOBSERVED"),
                          (b"", "UNOBSERVED"), (b"\n", "UNOBSERVED"), (b"27.5.1\nx\n", "UNOBSERVED"),
                          (b"permission denied\n", "UNOBSERVED"), (b"\xff\n", "UNOBSERVED"),
                          (b"1" * 65 + b"\n", "UNOBSERVED"), (b"1" * 64 + b"\n", "1" * 64)):
            with self.subTest(out=out):
                self.assertEqual(S.docker_ready(FakeLayer(version=(0, out)), "vm-a", V), want)

    def test_each_runner_only_pin_refuses_before_any_vm(self):
        """RE's Dockerfile off its pin, a needed file missing, router_fingerprint.py's files[] row missing, and the RL
        repository not fetched: each is IMAGES.PIN exit 2, the first VM's FAIL receipt, and no VM call."""
        def dockerfile(L):
            L.re_tree["docker"]["Dockerfile"] = b"FROM y\n"

        def needed(L):
            del L.re_tree["host"]["relay.py"]

        def rfp_row(L):
            L.lock["files"] = [f for f in L.lock["files"] if f["path"] != "router_fingerprint.py"]

        def rl_fetch(L):
            L.fetched = {}
        for name, breaks in (("dockerfile", dockerfile), ("needed", needed), ("rfp_row", rfp_row),
                             ("rl_fetch", rl_fetch)):
            with self.subTest(name):
                L = FakeLayer(ls=[(0, ls_out(RE_ID)), (0, ls_out(RL_ID, RE_ID))])
                breaks(L)
                c, site, rec = run_args("install", L, lock_root(self))
                c.lock = L.lock
                with mock.patch.object(S, "re_fix", lambda layer, rows: "0"):
                    with self.assertRaises(Refusal) as cm:
                        S.run_s4(c, site, rec)
                self.assertEqual((cm.exception.cause, cm.exception.rc), ("IMAGES.PIN", 2))
                self.assertEqual(rec.receipts, [("S4", "vm-a", "FAIL", [], 2, "IMAGES.PIN")])
                self.assertEqual(L.calls, [])

    def test_run_s4_through_the_real_check_vm_and_only_the_run_scopes_vms(self):
        """No stand-in for check_vm: pre_vm's RE needed files and fingerprint modules reach it (StubRfp only through
        fingerprint_modules). A VM in another scope is never contacted."""
        L = FakeLayer()
        rfp = StubRfp()
        c, site, rec = run_args("install", L, lock_root(self), extra=[dict(V, name="vm-c", scope="l3")])
        with mock.patch.object(S, "re_fix", lambda layer, rows: "0"), \
                mock.patch.object(S, "fingerprint_modules", lambda layer: rfp):
            S.run_s4(c, site, rec)
        self.assertEqual([r[1] for r in rec.receipts], ["vm-a", "vm-b"])
        self.assertNotIn("vm-c", {c[0] for c in L.calls})
        for vm in ("vm-a", "vm-b"):
            reads = [c[1][-1] for c in L.calls if c[0] == vm and S.READ_TEST in c[1] and RE_ID in c[1]]
            self.assertEqual(reads, ["/app/" + p for p in S.RE_NEEDED] + ["/app/router/__init__.py"], vm)
            facts = dict([r for r in rec.receipts if r[1] == vm][0][3])
            self.assertEqual((facts["RL_IMAGE"], facts["RE_IMAGE"], facts["RL_FINGERPRINT"]), (RL_ID, RE_ID, "EXACT"))
        self.assertEqual(len([e for e in rfp.log if e[0] == "capture"]), 2)

    def test_an_archive_that_fails_its_check_refuses_pin_before_any_vm(self):
        root = lock_root(self)
        with open(os.path.join(root, S.ARCHIVE_DIR, "re-img.tar"), "ab") as f:
            f.write(b"x")
        L = FakeLayer()
        with self.assertRaises(Refusal) as cm:
            self.run_stubbed(L, root)
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("IMAGES.PIN", 2))
        self.assertEqual(L.calls, [])

    # An rc-3 receipt says what state was left (3.4): DOCKER_VERSION and each role's RL_LOADED / RE_LOADED.
    def failing(self, L, root=None, **patches):
        """run_s4 on L with re_fix stood in (and check_vm too unless `real_check`); returns (refusal, receipts)."""
        real = patches.pop("real_check", False)
        stands = [("re_fix", lambda layer, rows: "0")]
        if real:
            rfp = StubRfp()
            stands.append(("fingerprint_modules", lambda layer: rfp))
        else:
            stands.append(("check_vm", lambda layer, vm, v, rows, refs, fix, rfp, needed: [("CHECKED", "x")]))
        for name, fn in stands:
            p = mock.patch.object(S, name, fn)
            p.start()
            self.addCleanup(p.stop)
        c, site, rec = run_args("install", L, root or lock_root(self))
        with self.assertRaises(Refusal) as cm:
            S.run_s4(c, site, rec)
        return cm.exception, rec.receipts

    def test_an_re_load_failing_after_the_rl_load_leaves_rl_yes_and_re_unobserved(self):
        r, receipts = self.failing(FakeLayer(ls=[(0, b""), (0, ls_out(RL_ID))], load=[(0, b""), (1, b"")]))
        self.assertEqual(receipts, [("S4", "vm-a", "FAIL", [("DOCKER_VERSION", "27.5.1"), ("RL_LOADED", "yes"),
                                                           ("RE_LOADED", "UNOBSERVED")], 3, "IMAGES.LOAD")])

    def test_a_load_that_does_not_complete_is_unobserved(self):
        """The layer's own refusal of the load (a timeout is TARGET_ACCESS exit 3): the load was sent, its outcome is
        not known."""
        class Timeout(FakeLayer):
            def exec(self, vm, argv, **kw):
                if argv[1:] == ["load"]:
                    self.calls.append((vm, list(argv), kw["account"], kw["stage"], kw["writes"], None, None))
                    raise Refusal(S.STAGE + ".TARGET_ACCESS", "ssh did not complete", rc=3)
                return FakeLayer.exec(self, vm, argv, **kw)
        r, receipts = self.failing(Timeout(ls=(0, ls_out(RE_ID))))
        self.assertEqual(receipts, [("S4", "vm-a", "FAIL", [("DOCKER_VERSION", "27.5.1"), ("RL_LOADED", "UNOBSERVED"),
                                                           ("RE_LOADED", "no")], 3, "IMAGES.TARGET_ACCESS")])

    def test_an_id_mismatch_after_a_load_that_exited_0_leaves_that_role_yes(self):
        r, receipts = self.failing(FakeLayer(ls=[(0, ls_out(RE_ID)), (0, ls_out(RE_ID))]))
        self.assertEqual(receipts, [("S4", "vm-a", "FAIL", [("DOCKER_VERSION", "27.5.1"), ("RL_LOADED", "yes"),
                                                           ("RE_LOADED", "no")], 3, "IMAGES.ID_MISMATCH")])

    def test_a_check_failing_after_a_load_names_the_load(self):
        r, receipts = self.failing(FakeLayer(ls=[(0, ls_out(RE_ID)), (0, ls_out(RL_ID, RE_ID))], openssl=(1, b"")),
                                   real_check=True)
        self.assertEqual(receipts, [("S4", "vm-a", "FAIL", [("DOCKER_VERSION", "27.5.1"), ("RL_LOADED", "yes"),
                                                           ("RE_LOADED", "no")], 3, "IMAGES.OPENSSL")])

    def test_a_later_vms_exit_3_from_an_earlier_vms_load_says_it_loaded_nothing(self):
        L = FakeLayer(ls=[(0, ls_out(RE_ID)), (0, ls_out(RL_ID, RE_ID))], testx=[(0, b""), (1, b"")])
        r, receipts = self.failing(L)
        self.assertEqual(receipts[1], ("S4", "vm-b", "FAIL", [("DOCKER_VERSION", "UNOBSERVED"), ("RL_LOADED", "no"),
                                                               ("RE_LOADED", "no")], 3, "IMAGES.DOCKER"))
        self.assertEqual(receipts[0][2], "CHANGED")

    def test_an_exit_2_refusal_on_a_vm_carries_no_state(self):
        r, receipts = self.failing(FakeLayer(ls=(1, b"")))
        self.assertEqual(receipts, [("S4", "vm-a", "FAIL", [], 2, "IMAGES.UNCLASSIFIED")])

    # The lock's image rows and the run scope, refused before any VM with the first VM's receipt.
    def test_a_one_image_lock_is_the_first_vms_lock_refusal_in_a_run_and_in_a_dry_run(self):
        for command in ("install", "dry-run"):
            with self.subTest(command=command):
                L = FakeLayer()
                c, site, rec = run_args(command, L, lock_root(self))
                c.lock = s4_lock()
                c.lock["images"] = c.lock["images"][:1]
                with self.assertRaises(Refusal) as cm:
                    S.run_s4(c, site, rec)
                self.assertEqual((cm.exception.cause, cm.exception.rc), ("IMAGES.LOCK", 2))
                self.assertEqual(rec.receipts, [("S4", "vm-a", "FAIL", [], 2, "IMAGES.LOCK")])
                self.assertEqual(L.calls, [])

    def test_a_scope_of_other_than_two_vms_refuses_hosts_before_any_vm(self):
        for vms, first in (([dict(V, scope="loop")], "vm-a"), ([], None),
                           ([dict(V, scope="loop"), dict(V, name="vm-b", scope="loop"),
                             dict(V, name="vm-c", scope="loop")], "vm-a")):
            with self.subTest(n=len(vms)):
                L = FakeLayer()
                c, site, rec = run_args("install", L, lock_root(self))
                c.hosts = {"vms": vms + [dict(V, name="vm-z", scope="l3")]}
                with self.assertRaises(Refusal) as cm:
                    S.run_s4(c, site, rec)
                self.assertEqual((cm.exception.cause, cm.exception.rc), ("IMAGES.HOSTS", 2))
                self.assertEqual(rec.receipts, [("S4", first, "FAIL", [], 2, "IMAGES.HOSTS")])
                self.assertEqual(L.calls, [])


class ArchiveTest(Refuses):
    def setUp(self):
        self.root = lock_root(self)
        self.rows = S.image_rows(s4_lock())
        self.rl = os.path.join(self.root, S.ARCHIVE_DIR, "rl-img.tar")

    def test_each_archive_is_read_whole_and_checked_against_its_row(self):
        self.assertEqual(S.read_archive(self.root, self.rows[S.RL], keep=True, root_uid=UID), ARCHIVE["rl-img"])
        self.assertIsNone(S.read_archive(self.root, self.rows[S.RE], keep=False, root_uid=UID))
        self.assertIsNone(S.archives(self.root, self.rows, UID))
        self.assertEqual(S.archive_path(self.root, self.rows[S.RE]), os.path.join(self.root, "images", "re-img.tar"))

    def test_the_bound_is_2_gib_and_the_load_timeout_1800_s(self):
        self.assertEqual((S.ARCHIVE_MAX, S.LOAD_TIMEOUT_S), (2 * 1024 ** 3, 1800))

    def test_a_missing_changed_linked_or_irregular_archive_refuses_pin(self):
        def missing():
            os.unlink(self.rl)

        def changed():
            with open(self.rl, "r+b") as f:
                f.write(b"R")

        def linked():
            other = os.path.join(self.root, "rl-copy")
            os.rename(self.rl, other)
            os.symlink(other, self.rl)

        def a_dir():
            os.unlink(self.rl)
            os.mkdir(self.rl)

        def a_fifo():
            os.unlink(self.rl)
            os.mkfifo(self.rl)

        def dir_linked():
            other = os.path.join(self.root, "images-real")
            os.rename(os.path.join(self.root, S.ARCHIVE_DIR), other)
            os.symlink(other, os.path.join(self.root, S.ARCHIVE_DIR))
        for name, f in (("missing", missing), ("changed", changed), ("linked", linked), ("a dir", a_dir),
                        ("a fifo", a_fifo), ("dir linked", dir_linked)):
            with self.subTest(name):
                shutil.rmtree(self.root)
                self.root = lock_root(self)
                self.rl = os.path.join(self.root, S.ARCHIVE_DIR, "rl-img.tar")
                f()
                self.refuses("IMAGES.PIN", 2, S.read_archive, self.root, self.rows[S.RL], keep=True, root_uid=UID)
                self.refuses("IMAGES.PIN", 2, S.archives, self.root, self.rows, UID)
                self.refuses("IMAGES.PIN", 3, lambda: S.read_archive(self.root, self.rows[S.RL], keep=False, rc=3,
                                                                     root_uid=UID))

    def test_the_images_dir_and_each_archive_must_be_root_owned_0755_and_0644(self):
        """Contract 5.3's rule for the lock root and lock files, applied to images/ and each .tar: another mode, or
        another owner (here a stat whose st_uid is not UID, as the test cannot chown), refuses IMAGES.PIN, and
        a refusal after a write carries its rc. Each break is applied alone."""
        images = os.path.join(self.root, S.ARCHIVE_DIR)
        for mode in (0o775, 0o777, 0o700, 0o750):
            with self.subTest(dir_mode=oct(mode)):
                os.chmod(images, mode)
                self.refuses("IMAGES.PIN", 2, S.read_archive, self.root, self.rows[S.RL], keep=True, root_uid=UID)
                self.refuses("IMAGES.PIN", 3, lambda: S.read_archive(self.root, self.rows[S.RL], keep=False, rc=3,
                                                                     root_uid=UID))
                os.chmod(images, 0o755)
        for mode in (0o664, 0o666, 0o600, 0o640, 0o755):
            with self.subTest(file_mode=oct(mode)):
                os.chmod(self.rl, mode)
                self.refuses("IMAGES.PIN", 2, S.read_archive, self.root, self.rows[S.RL], keep=True, root_uid=UID)
                self.refuses("IMAGES.PIN", 2, S.archives, self.root, self.rows, UID)
                os.chmod(self.rl, 0o644)
        real_lstat, real_fstat = os.lstat, os.fstat

        def other_owner(real, hit):
            def f(x):
                st = list(real(x))
                if hit(x):
                    st[4] = UID + 1
                return os.stat_result(st)
            return f
        dir_owner = other_owner(real_lstat, lambda x: x == images)
        with self.subTest("dir owner"), mock.patch.object(S.os, "lstat", dir_owner):
            self.refuses("IMAGES.PIN", 2, S.read_archive, self.root, self.rows[S.RL], keep=True, root_uid=UID)
        with self.subTest("file owner"), mock.patch.object(S.os, "fstat", other_owner(real_fstat, lambda x: True)):
            self.refuses("IMAGES.PIN", 2, S.read_archive, self.root, self.rows[S.RL], keep=True, root_uid=UID)
        # The owner checked is root_uid's: the same files refuse for an owner other than the one asked for, and the
        # default is 0 (root), as on the runner.
        self.refuses("IMAGES.PIN", 2, S.read_archive, self.root, self.rows[S.RL], keep=True, root_uid=UID + 1)
        if UID != 0:
            self.refuses("IMAGES.PIN", 2, S.read_archive, self.root, self.rows[S.RL], keep=True)
        self.assertEqual(S.read_archive(self.root, self.rows[S.RL], keep=True, root_uid=UID), ARCHIVE["rl-img"])

    def test_run_s4_checks_the_archives_against_the_sites_root_uid(self):
        """run_s4 passes site.root_uid to the pre-VM check and to obtain: a site whose root is another uid refuses
        PIN before any VM."""
        L = FakeLayer()
        c, site, rec = run_args("install", L, self.root)
        site.root_uid = UID + 1
        with mock.patch.object(S, "re_fix", lambda layer, rows: "0"):
            self.refuses("IMAGES.PIN", 2, S.run_s4, c, site, rec)
        self.assertEqual(L.calls, [])

    def test_a_non_regular_or_oversized_archive_is_refused_before_a_byte_is_read(self):
        def a_dir():
            os.unlink(self.rl)
            os.mkdir(self.rl)

        def a_fifo():
            os.unlink(self.rl)
            os.mkfifo(self.rl)

        def oversized():
            p = mock.patch.object(S, "ARCHIVE_MAX", len(ARCHIVE["rl-img"]) - 1)
            p.start()
            self.addCleanup(p.stop)

        def no_read(fd, n):
            raise AssertionError("read before the fstat checks")
        for name, f in (("a dir", a_dir), ("a fifo", a_fifo), ("oversized", oversized)):
            with self.subTest(name):
                shutil.rmtree(self.root)
                self.root = lock_root(self)
                self.rl = os.path.join(self.root, S.ARCHIVE_DIR, "rl-img.tar")
                f()
                with mock.patch.object(S.os, "read", no_read):
                    self.refuses("IMAGES.PIN", 2, S.read_archive, self.root, self.rows[S.RL], keep=True, root_uid=UID)

    def test_an_archive_over_the_bound_refuses_pin_by_its_size_and_by_what_it_reads(self):
        n = len(ARCHIVE["rl-img"])
        with mock.patch.object(S, "ARCHIVE_MAX", n - 1):
            self.refuses("IMAGES.PIN", 2, S.read_archive, self.root, self.rows[S.RL], keep=False, root_uid=UID)
        with mock.patch.object(S, "ARCHIVE_MAX", n):
            self.assertEqual(S.read_archive(self.root, self.rows[S.RL], keep=True, root_uid=UID), ARCHIVE["rl-img"])
        # A file that grows past the bound after fstat (here, an fstat that says 0 bytes): the read count refuses it.
        real_fstat = os.fstat

        def zero_size(fd):
            st = list(real_fstat(fd))
            st[6] = 0
            return os.stat_result(st)
        with mock.patch.object(S, "ARCHIVE_MAX", n - 1), mock.patch.object(S.os, "fstat", zero_size):
            self.refuses("IMAGES.PIN", 2, S.read_archive, self.root, self.rows[S.RL], keep=False, root_uid=UID)

    def test_the_rows_carry_a_name_and_archive_sha_or_refuse_lock(self):
        for key, bad in (("archive_sha256", None), ("archive_sha256", "A" * 64), ("name", "../x"), ("name", None)):
            with self.subTest(key=key, bad=bad):
                d = s4_lock()
                if bad is None:
                    del d["images"][1][key]
                else:
                    d["images"][1][key] = bad
                self.refuses("IMAGES.LOCK", 2, S.image_rows, d)


class ImageIdsTest(Refuses):
    def test_the_set_of_full_ids_from_image_ls_as_the_agent_read_only(self):
        L = FakeLayer(ls=(0, ls_out(RL_ID, RE_ID, RL_ID)))
        self.assertEqual(S.image_ids(L, "vm-a", V), {RL_ID, RE_ID})
        self.assertEqual(L.calls, [("vm-a", [S.DOCKER, "image", "ls", "--no-trunc", "--quiet"], "agent", "IMAGES",
                                    False, None, None)])
        self.assertEqual(S.image_ids(FakeLayer(ls=(0, b"")), "vm-a", V), set())

    def test_a_failed_list_or_a_line_that_is_not_an_id_is_unclassified(self):
        for name, ans in (("rc", (1, b"")), ("short id", (0, b"sha256:abc\n")), ("no newline", (0, RL_ID.encode())),
                          ("blank line", (0, b"\n")), ("not ascii", (0, b"\xff\n"))):
            with self.subTest(name):
                self.refuses("IMAGES.UNCLASSIFIED", 2, S.image_ids, FakeLayer(ls=ans), "vm-a", V)
        self.refuses("IMAGES.UNCLASSIFIED", 3, S.image_ids, FakeLayer(prior=True, ls=(1, b"")), "vm-a", V)


class ObtainTest(Refuses):
    def setUp(self):
        self.root = lock_root(self)
        self.rows = S.image_rows(s4_lock())

    def loads(self, L):
        return [c for c in L.calls if c[4]]

    def test_both_present_loads_nothing_and_writes_nothing(self):
        L = FakeLayer()
        self.assertEqual(S.obtain(L, "vm-a", V, self.rows, self.root, UID),
                         ({S.RL: RL_ID, S.RE: RE_ID}, {S.RL: False, S.RE: False}))
        self.assertEqual(self.loads(L), [])
        self.assertFalse(L.wrote(S.STAGE))

    def test_an_absent_image_is_loaded_from_its_archive_as_stdin_then_listed_again(self):
        L = FakeLayer(ls=[(0, ls_out(RL_ID)), (0, ls_out(RL_ID, RE_ID))])
        self.assertEqual(S.obtain(L, "vm-a", V, self.rows, self.root, UID),
                         ({S.RL: RL_ID, S.RE: RE_ID}, {S.RL: False, S.RE: True}))
        self.assertEqual([c[1][1:3] if c[1][1] == "image" else c[1][1:] for c in L.calls],
                         [["image", "ls"], ["load"], ["image", "ls"]])
        self.assertEqual(self.loads(L),
                         [("vm-a", [S.DOCKER, "load"], "agent", "IMAGES", True, ARCHIVE["re-img"], 1800)])

    def test_both_absent_loads_rl_then_re(self):
        L = FakeLayer(ls=[(0, b""), (0, ls_out(RL_ID)), (0, ls_out(RL_ID, RE_ID))])
        self.assertEqual(S.obtain(L, "vm-a", V, self.rows, self.root, UID)[1], {S.RL: True, S.RE: True})
        self.assertEqual([c[5] for c in self.loads(L)], [ARCHIVE["rl-img"], ARCHIVE["re-img"]])

    def test_a_failed_load_refuses_load_and_an_id_still_absent_id_mismatch_both_3(self):
        self.refuses("IMAGES.LOAD", 3, S.obtain, FakeLayer(ls=(0, b""), load=(1, b"")), "vm-a", V, self.rows,
                     self.root, UID)
        self.refuses("IMAGES.ID_MISMATCH", 3, S.obtain, FakeLayer(ls=[(0, b""), (0, ls_out(RE_ID))]), "vm-a", V,
                     self.rows, self.root, UID)
        self.refuses("IMAGES.UNCLASSIFIED", 3, S.obtain, FakeLayer(ls=[(0, b""), (1, b"")]), "vm-a", V, self.rows,
                     self.root, UID)

    def test_the_archive_is_checked_again_at_load_exit_2_before_a_write_and_3_after(self):
        rl = os.path.join(self.root, S.ARCHIVE_DIR, "rl-img.tar")
        os.unlink(rl)
        L = FakeLayer(ls=(0, b""))
        self.refuses("IMAGES.PIN", 2, S.obtain, L, "vm-a", V, self.rows, self.root, UID)
        self.assertEqual(self.loads(L), [])
        os.unlink(os.path.join(self.root, S.ARCHIVE_DIR, "re-img.tar"))
        with open(rl, "wb") as f:
            f.write(ARCHIVE["rl-img"])
        L = FakeLayer(ls=[(0, b""), (0, ls_out(RL_ID))])
        self.refuses("IMAGES.PIN", 3, S.obtain, L, "vm-a", V, self.rows, self.root, UID)
        self.assertEqual(len(self.loads(L)), 1)

    def test_the_loaded_facts(self):
        self.assertEqual(S.loaded_facts({S.RL: True, S.RE: False}), [("RL_LOADED", "yes"), ("RE_LOADED", "no")])


if __name__ == "__main__":
    unittest.main()
