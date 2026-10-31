"""m1vm/man.py (m1-man): MAN's shape, its HDOT list agreeing with what
m1-seed-copy copies, and each way the write must fail.

git, docker and dpkg-query are stood in by a runner; their output forms
(`rev-parse` hex, `image inspect --format {{.Id}}`, dpkg-query's tab form)
follow those programs' documented output and are INFERRED until BAKE runs
on 208.
"""

import hashlib
import io
import json
import os
import pwd
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

M1VM = Path(__file__).resolve().parent.parent / "m1vm"
sys.path.insert(0, str(M1VM))
import man  # noqa: E402
import seed_copy  # noqa: E402

HEAD = "a" * 40
TREE = "b" * 40
IMAGE = "sha256:" + "c" * 64
ME = pwd.getpwuid(os.getuid()).pw_name


class Runner:
    def __init__(self):
        self.calls = []
        self.out = {
            "rev-parse HEAD^{commit}": HEAD + "\n",
            "rev-parse HEAD^{tree}": TREE + "\n",
            "image": IMAGE + "\n",
            "dpkg": "ii \tdocker-ce\t5:27.0.0-1\nii \tpython3\t3.12.3-0\nrc \tsnapd\t2.66\n",
        }

    def __call__(self, argv):
        self.calls.append(argv)
        if argv[0] == man.GIT:
            return self.out[f"rev-parse {argv[-1]}"]
        if argv[0] == man.DOCKER:
            return self.out["image"]
        if argv[0] == man.DPKG_QUERY:
            return self.out["dpkg"]
        raise AssertionError(argv)


class ManCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.seed = self.tmp / "sandy-seed"
        (self.seed / "sandboxes/m1-one").mkdir(parents=True)
        for name, data in ((".base_build_hash", b"b\n"), (".build_hash_claude", b"c\n"),
                           ("sandboxes/m1-one/.project_build_hash", b"p\n"), ("Dockerfile.base", b"x\n")):
            (self.seed / name).write_bytes(data)
        self.etc = self.tmp / "etc"
        self.etc.mkdir()
        (self.etc / "sudoers-m1-admin").write_bytes(b"m1-admin ALL=(ALL:ALL) NOPASSWD: ALL\n")
        os.chmod(self.etc / "sudoers-m1-admin", 0o440)
        self.repo = self.tmp / "src/amap-deploy-sandy"
        self.repo.mkdir(parents=True)
        self.runner = Runner()
        self.plan = {"pin_sha256": "d" * 64, "seed": str(self.seed),
                     "files": [str(self.etc / "sudoers-m1-admin")], "checkouts": [str(self.repo)],
                     "images": ["amap-router-local:m1"], "accounts": [ME],
                     "roles": {r: ME for r in ("op", "m1-admin", "adm", "uid-1", "uid-2", "registry")},
                     "trees": [],
                     "builds": {"router1": {"commit": HEAD, "tree": TREE, "image": "amap-router-local:m1"}}}

    def build(self):
        return man.build(self.plan, self.runner)


class BuildTest(ManCase):
    def test_shape(self):
        m = self.build()
        self.assertEqual(sorted(m), ["accounts", "builds", "checkouts", "files", "hdot", "images", "packages",
                                     "pin_sha256", "roles", "schema", "trees"])
        self.assertEqual(m["roles"]["op"], ME)
        self.assertEqual(m["builds"], {"router1": {"commit": HEAD, "tree": TREE, "image": "amap-router-local:m1",
                                                   "id": IMAGE}})
        self.assertEqual(m["schema"], "m1vm-man/1")
        self.assertEqual([e["name"] for e in m["hdot"]],
                         [".base_build_hash", ".build_hash_claude", "sandboxes/m1-one/.project_build_hash"])
        self.assertEqual(m["hdot"][0]["sha256"], hashlib.sha256(b"b\n").hexdigest())
        rec = m["files"][str(self.etc / "sudoers-m1-admin")]
        self.assertEqual((rec["mode"], rec["uid"]), ("0440", os.getuid()))
        self.assertEqual(m["checkouts"][str(self.repo)], {"head": HEAD, "tree": TREE})
        self.assertEqual(m["images"], {"amap-router-local:m1": IMAGE})
        self.assertEqual(m["packages"], {"docker-ce": "5:27.0.0-1", "python3": "3.12.3-0"})
        self.assertEqual(m["accounts"][ME]["uid"], os.getuid())
        self.assertIsInstance(m["accounts"][ME]["groups"], list)

    def test_hdot_is_what_seed_copy_accepts(self):
        m = self.build()
        for entry in m["hdot"]:
            self.assertTrue(seed_copy.is_hdot_name(entry["name"]), entry)
        self.assertEqual(man.TOP_PATTERNS, seed_copy.TOP_PATTERNS)
        self.assertEqual(man.SANDBOX_NAME, seed_copy.SANDBOX_NAME)
        self.assertEqual(man._SLUG_RE.pattern, seed_copy._SLUG_RE.pattern)

    def test_seed_copy_accepts_the_written_man(self):
        out = self.tmp / "MAN.json"
        man.write_new(str(out), man.canonical(self.build()))
        dst = self.tmp / "dst"
        dst.mkdir()
        argv = ["--man", str(out), "--src", str(self.seed), "--dst", str(dst)]
        with redirect_stdout(io.StringIO()) as o, redirect_stderr(io.StringIO()):
            self.assertEqual(seed_copy.main(argv), 0)
        self.assertTrue(o.getvalue().splitlines()[-1].startswith("M1-SEED-COPY PASS n=3 "))

    def test_trees_record_every_entry_without_following_links(self):
        t = self.tmp / "units"
        (t / "docker.socket.d").mkdir(parents=True)
        (t / "docker.socket.d/m1-acl.conf").write_text("[Socket]\n")
        os.symlink("/dev/null", t / "qemu-guest-agent.service")
        os.symlink("/etc", t / "outside")
        self.plan["trees"] = [str(t)]
        tr = self.build()["trees"][str(t)]
        self.assertEqual(sorted(tr), [".", "docker.socket.d", "docker.socket.d/m1-acl.conf", "outside",
                                      "qemu-guest-agent.service"])
        self.assertEqual(tr["qemu-guest-agent.service"], {"type": "l", "uid": os.getuid(), "target": "/dev/null"})
        self.assertEqual(tr["outside"]["type"], "l")  # recorded, never crossed
        self.assertEqual(tr["docker.socket.d/m1-acl.conf"]["sha256"], hashlib.sha256(b"[Socket]\n").hexdigest())
        self.assertEqual(tr["docker.socket.d"]["type"], "d")

    def test_tree_refuses_a_socket(self):
        import socket
        t = self.tmp / "units"
        t.mkdir()
        sk = socket.socket(socket.AF_UNIX)
        self.addCleanup(sk.close)
        sk.bind(str(t / "s"))
        self.plan["trees"] = [str(t)]
        with self.assertRaises(man.Fail):
            self.build()

    def test_canonical_is_stable(self):
        a = man.canonical(self.build())
        self.assertEqual(a, man.canonical(json.loads(a)))
        self.assertNotIn(b" ", a.replace(b"ALL=(ALL:ALL)", b""))


class FailTest(ManCase):
    def assert_fails(self, needle):
        with self.assertRaises(man.Fail) as cm:
            self.build()
        self.assertIn(needle, str(cm.exception))

    def test_breaks(self):
        breaks = {
            "seed without hashes": (lambda: [p.unlink() for p in (self.seed / ".base_build_hash",
                                                                   self.seed / ".build_hash_claude",
                                                                   self.seed / "sandboxes/m1-one/.project_build_hash")],
                                    "holds no hash dotfile"),
            "symlinked hash": (lambda: ((self.seed / ".base_build_hash").unlink(),
                                        os.symlink(self.tmp / "x", self.seed / ".base_build_hash")),
                               "a symbolic link"),
            "off-pattern slug": (lambda: (self.seed / "sandboxes/_odd").mkdir(), "m1-seed-copy would refuse"),
            "file in sandboxes": (lambda: (self.seed / "sandboxes/f").write_bytes(b""), "not a plain directory"),
            "missing file": (lambda: (self.etc / "sudoers-m1-admin").unlink(), "absent"),
            "fifo file": (lambda: ((self.etc / "sudoers-m1-admin").unlink(), os.mkfifo(self.etc / "sudoers-m1-admin")),
                          "not a regular file"),
            "symlinked ancestor": (lambda: (shutil.move(str(self.etc), str(self.tmp / "etc2")),
                                            os.symlink(self.tmp / "etc2", self.etc)), "not a plain directory"),
            "bad git output": (lambda: self.runner.out.update({"rev-parse HEAD^{tree}": "nope\n"}),
                               "did not print a commit"),
            "bad image id": (lambda: self.runner.out.update(image="\n"), "no image Id"),
            "duplicate package": (lambda: self.runner.out.update(dpkg="ii \ta\t1\nii \ta\t2\n"), "listed twice"),
            "malformed line": (lambda: self.runner.out.update(dpkg="ii a 1\n"), "not one package"),
            "no packages": (lambda: self.runner.out.update(dpkg=""), "no packages"),
            "unknown account": (lambda: self.plan.update(accounts=["nosuchaccount9"],
                                                         roles={r: "nosuchaccount9" for r in self.plan["roles"]}),
                                "absent"),
        }
        for name, (brk, needle) in breaks.items():
            with self.subTest(name):
                self.setUp()
                brk()
                self.assert_fails(needle)

    def test_plan_shape(self):
        for mutate in (lambda p: p.pop("images"), lambda p: p.update(extra=1), lambda p: p.update(pin_sha256="x"),
                       lambda p: p.update(seed="rel"), lambda p: p.update(files=[]),
                       lambda p: p.update(files=["/a", "/a"]), lambda p: p.update(accounts=["Bad Name"]),
                       lambda p: p.update(checkouts=["/x/../y"]), lambda p: p.update(builds={}),
                       lambda p: p["roles"].pop("op"), lambda p: p["roles"].update(op="nosuch"),
                       lambda p: p["roles"].update(extra=ME),
                       lambda p: p["builds"]["router1"].update(image="other:x"),
                       lambda p: p["builds"]["router1"].update(tree="nope")):
            with self.subTest(mutate):
                self.setUp()
                mutate(self.plan)
                with self.assertRaises(man.Usage):
                    self.build()


class WriteTest(ManCase):
    def test_cli_pass_and_once(self):
        plan = self.tmp / "plan.json"
        plan.write_text(json.dumps(self.plan))
        out = self.tmp / "MAN.json"
        argv = ["write", "--plan", str(plan), "--out", str(out)]
        with redirect_stdout(io.StringIO()) as o, redirect_stderr(io.StringIO()):
            self.assertEqual(man.main(argv, self.runner), 0)
        data = out.read_bytes()
        self.assertEqual(o.getvalue().strip(), f"M1-MAN PASS sha256={hashlib.sha256(data).hexdigest()}")
        self.assertEqual(os.stat(out).st_mode & 0o7777, 0o444)
        with redirect_stdout(io.StringIO()) as o, redirect_stderr(io.StringIO()) as e:
            self.assertEqual(man.main(argv, self.runner), 1)
        self.assertEqual(out.read_bytes(), data)
        self.assertNotIn("PASS", o.getvalue())

    def test_fail_writes_nothing(self):
        plan = self.tmp / "plan.json"
        self.plan["files"] = [str(self.etc / "nope")]
        plan.write_text(json.dumps(self.plan))
        out = self.tmp / "MAN.json"
        with redirect_stdout(io.StringIO()) as o, redirect_stderr(io.StringIO()):
            self.assertEqual(man.main(["write", "--plan", str(plan), "--out", str(out)], self.runner), 1)
        self.assertFalse(out.exists())
        self.assertEqual(o.getvalue(), "")

    def test_usage(self):
        for argv in (["write"], ["write", "--plan", "rel", "--out", "/x"], ["frob", "--plan", "/a", "--out", "/b"]):
            with self.subTest(argv):
                with redirect_stderr(io.StringIO()):
                    self.assertEqual(man.main(argv, self.runner), 2)

    def test_runner_failure_is_a_fail(self):
        def bad(argv):
            raise man.Fail("git exited 128")
        with self.assertRaises(man.Fail):
            man.build(self.plan, bad)


if __name__ == "__main__":
    unittest.main()
