"""m1vm/sealspec.py: the shipped spec's shape, and each expectation proven
to fire on a tree built for it (one break at a time)."""

import copy
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

M1VM = Path(__file__).resolve().parent.parent / "m1vm"
sys.path.insert(0, str(M1VM))
import sealspec  # noqa: E402

SPEC_PATH = M1VM / "sealspec.json"
REAL_CHECK = sealspec._check_one


def shipped():
    return json.loads(SPEC_PATH.read_text())


class ShippedSpecTest(unittest.TestCase):
    def test_validates(self):
        spec, sha = sealspec.load(SPEC_PATH)
        self.assertEqual(len(sha), 64)
        self.assertEqual(spec["schema"], sealspec.SCHEMA)

    def test_bundle_headers_are_patterns(self):
        # DS2 d8 §3.2: no git bundle file may survive anywhere on R or D.
        self.assertIn("# v2 git bundle\n", shipped()["patterns"])
        self.assertIn("# v3 git bundle\n", shipped()["patterns"])

    def test_check_cli_prints_the_file_sha(self):
        out = subprocess.run([sys.executable, "-I", "-S", "-B", str(M1VM / "sealspec.py"), "check", str(SPEC_PATH)],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        _, sha = sealspec.load(SPEC_PATH)
        self.assertEqual(out.stdout.strip(), f"M1-SEALSPEC VALID sha256={sha}")


class ValidateRefusesTest(unittest.TestCase):
    def refuse(self, mutate):
        spec = shipped()
        mutate(spec)
        with self.assertRaises(sealspec.SpecError):
            sealspec.validate(spec)

    def test_each_break(self):
        breaks = {
            "extra top key": lambda s: s.update(extra=1),
            "schema": lambda s: s.update(schema="m1vm-sealspec/2"),
            "params": lambda s: s.update(params=["op_user"]),
            "duplicate id": lambda s: s["items"][1].update(id=s["items"][0]["id"]),
            "bad id": lambda s: s["items"][0].update(id="X-1"),
            "two selectors": lambda s: s["items"][0].update(glob="/x*"),
            "glob expect": lambda s: s["items"][0].update(expect="empty-mountpoint") or s["items"][0].pop("path")
                           or s["items"][0].update(glob="/x*"),
            "relative path": lambda s: s["items"][2].update(path="var/lib/m1-bake"),
            "unnormalised": lambda s: s["items"][2].update(path="/var/lib/../lib/m1-bake"),
            "mid placeholder": lambda s: s["items"][2].update(path="/var/{op_home}/x"),
            "home absolute": lambda s: s["items"][7].update(home="/root/.gitconfig"),
            "no why": lambda s: s["items"][0].pop("why"),
            "empty patterns": lambda s: s.update(patterns=[]),
            "dup patterns": lambda s: s.update(patterns=["a", "a"]),
            "bad allowlist sha": lambda s: s.update(allowlist=[{"path": "/x", "sha256": "ab"}]),
            "min with none": lambda s: s["items"][11].update(min=1),
            "double star": lambda s: s["items"][11].update(glob="/etc/**/amap*"),
        }
        for name, mutate in breaks.items():
            with self.subTest(name):
                self.refuse(mutate)


class TreeCase(unittest.TestCase):
    """A fake R, laid out so that every item passes except where a test breaks it.
    The empty mountpoints' 0:0 0000 rule is exercised through a stat stand-in,
    because the test does not run as root."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        r = self.root
        (r / "etc").mkdir()
        (r / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/bash\n"
                                      "op:x:2101:2101::/home/op:/bin/bash\n"
                                      "nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n")
        (r / "root").mkdir()
        (r / "home/op").mkdir(parents=True)
        for repo in ("amap-deploy-sandy", "amap-router-local"):
            (r / f"opt/amap/src/{repo}/.git").mkdir(parents=True)
            (r / f"opt/amap/src/{repo}/.git/config").write_text("[core]\n\tbare = false\n")
        (r / "srv/data").mkdir(parents=True)
        (r / "var/lib/docker").mkdir(parents=True)
        (r / "etc/systemd/system/multi-user.target.wants").mkdir(parents=True)
        (r / "etc/apt/apt.conf.d").mkdir(parents=True)
        (r / "etc/environment").write_text('PATH="/usr/bin:/bin"\n')
        self.params = {"op_user": "op", "data_mount": "/srv/data"}
        self.spec = shipped()

        def as_root(tree, path, expect):
            if expect == "empty-mountpoint":
                st = tree.lstat(path)
                if st is not None and stat.S_ISDIR(st.st_mode) and not tree.listdir(path):
                    return True, f"{path}: empty (owner checked separately)"
            return REAL_CHECK(tree, path, expect)

        sealspec._check_one = as_root
        self.addCleanup(setattr, sealspec, "_check_one", REAL_CHECK)
        self.addCleanup(self.tmp.cleanup)

    def run_items(self):
        tree = sealspec.Tree(str(self.root))
        try:
            return {iid: (ok, detail) for iid, ok, detail in sealspec.evaluate(tree, self.spec, self.params)}
        finally:
            tree.close()

    def failing(self):
        return sorted(iid for iid, (ok, _) in self.run_items().items() if not ok)


class EvaluateTest(TreeCase):
    def test_clean_tree_passes(self):
        self.assertEqual(self.failing(), [])

    def test_each_break_fails_its_own_item(self):
        breaks = {
            "SS-01": lambda r: (r / "home/op/.sandy").mkdir(),
            "SS-02": lambda r: (r / "home/op/m1-bundles").mkdir(),
            "SS-03": lambda r: (r / "var/lib/m1-bake").mkdir(),
            "SS-04": lambda r: os.symlink("/dev/null", r / "etc/systemd/system/qemu-guest-agent.service"),
            "SS-06": lambda r: (r / "opt/amap/src/amap-router-local/.git/config").write_text(
                '[remote "origin"]\n\turl = /home/op/m1-bundles/x\n'),
            "SS-07": lambda r: (r / "etc/gitconfig").write_text("[credential]\n\thelper = store\n"),
            "SS-08": lambda r: (r / "root/.gitconfig").write_text('[url "https://a@h/"]\n\tinsteadOf = g:\n'),
            "SS-09": lambda r: ((r / "home/op/.config/git").mkdir(parents=True),
                              (r / "home/op/.config/git/config").write_text("[http]\n\tproxy = http://u:p@h:3128\n")),
            "SS-10": lambda r: (r / "srv/data/stray").write_text("x"),
            "SS-11": lambda r: (r / "var/lib/docker/overlay2").mkdir(),
            "SS-12": lambda r: (r / "etc/systemd/system/amap-relay.service").write_text(""),
            "SS-13": lambda r: os.symlink("../amap-x.service",
                                        r / "etc/systemd/system/multi-user.target.wants/amap-x.service"),
            "SS-14": lambda r: ((r / "etc/systemd/system/docker.service.d").mkdir(),
                              (r / "etc/systemd/system/docker.service.d/http-proxy.conf").write_text("")),
            "SS-15": lambda r: (r / "etc/apt/apt.conf.d/95proxy").write_text(""),
            "SS-16": lambda r: (r / "etc/environment").write_text("https_proxy=http://p:3128\n"),
            "SS-17": lambda r: (r / "home/op/.npmrc").write_text(""),
            "SS-18": lambda r: ((r / "root/.docker").mkdir(), (r / "root/.docker/config.json").write_text("{}")),
        }
        for iid, brk in breaks.items():
            with self.subTest(iid):
                self.setUp()
                brk(self.root)
                self.assertEqual(self.failing(), [iid])

    def test_dir_missing_fails(self):
        import shutil
        shutil.rmtree(self.root / "opt/amap/src")
        self.assertEqual(self.failing(), ["SS-05", "SS-06"])

    def test_glob_min(self):
        import shutil
        for repo in ("amap-deploy-sandy", "amap-router-local"):
            shutil.rmtree(self.root / f"opt/amap/src/{repo}")
        self.assertEqual(self.failing(), ["SS-06"])

    def test_symlink_on_the_way_fails_not_followed(self):
        import shutil
        outside = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, outside)
        (self.root / "home/op").rmdir()
        os.symlink(outside, self.root / "home/op")
        ok, detail = self.run_items()["SS-01"]
        self.assertFalse(ok)
        self.assertIn("not a plain directory", detail)

    def test_symlink_at_the_end_is_named(self):
        (self.root / "etc/gitconfig.real").write_text("[core]\n")
        os.symlink("gitconfig.real", self.root / "etc/gitconfig")
        ok, detail = self.run_items()["SS-07"]
        self.assertFalse(ok)
        self.assertIn("a symbolic link", detail)

    def test_root_home_checked_without_a_passwd_line(self):
        # NET r20 §2.4 covers every home in /etc/passwd AND /root.
        (self.root / "etc/passwd").write_text("op:x:2101:2101::/home/op:/bin/bash\n")
        (self.root / "root/.gitconfig").write_text("[credential]\n\thelper = store\n")
        self.assertEqual(self.failing(), ["SS-08"])

    def test_unknown_op_user(self):
        self.params["op_user"] = "nosuch"
        with self.assertRaises(sealspec.ParamError):
            self.run_items()


class MountpointOwnerTest(unittest.TestCase):
    """The real _check_one: an empty mountpoint must also be 0:0 0000."""

    def test_non_root_owner_fails(self):
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, "m"))
            tree = sealspec.Tree(d)
            try:
                ok, detail = sealspec._check_one(tree, "/m", "empty-mountpoint")
            finally:
                tree.close()
        if os.geteuid() == 0:
            self.skipTest("running as root")
        self.assertFalse(ok)
        self.assertIn("not 0:0 0000", detail)


    def test_non_empty_fails_before_owner(self):
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, "m"))
            open(os.path.join(d, "m", "x"), "w").close()
            tree = sealspec.Tree(d)
            try:
                ok, detail = sealspec._check_one(tree, "/m", "empty-mountpoint")
            finally:
                tree.close()
        self.assertFalse(ok)
        self.assertIn("holds 1 entry", detail)


class GitconfigTest(unittest.TestCase):
    def test_cases(self):
        clean = b"[core]\n\tbare = false\n[user]\n\tname = x\n"
        self.assertIsNone(sealspec.gitconfig_problem(clean))
        for text in (b'[remote "origin"]\n\turl = x\n', b"[Remote.origin]\n\turl = x\n",
                     b"[credential]\n\thelper = store\n", b'[url "x"]\n\tinsteadOf = y\n',
                     b'[url "x"]\n\tpushInsteadOf = y\n', b"[http]\n\textraHeader = https://u:p@h/\n"):
            with self.subTest(text):
                self.assertIsNotNone(sealspec.gitconfig_problem(text))


class CliTest(TreeCase):
    def cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = sealspec.main(list(args))
        return rc, out.getvalue(), err.getvalue()

    def eval_args(self):
        return ["eval", "--spec", str(SPEC_PATH), "--root", str(self.root),
                "--param", "op_user=op", "--param", "data_mount=/srv/data"]

    def test_pass_line_last(self):
        rc, out, _ = self.cli(*self.eval_args())
        self.assertEqual(rc, 0)
        self.assertTrue(out.splitlines()[-1].startswith("M1-SEALSPEC PASS n=18 spec="))

    def test_fail_is_exit_1_and_no_pass_line(self):
        (self.root / "var/lib/m1-bake").mkdir()
        rc, out, _ = self.cli(*self.eval_args())
        self.assertEqual(rc, 1)
        self.assertNotIn("M1-SEALSPEC PASS", out)
        self.assertIn("SEAL SS-03 FAIL", out)

    def test_usage_errors_are_exit_2(self):
        for args in (["eval"], ["eval", "--spec", str(SPEC_PATH), "--root", str(self.root)],
                     self.eval_args() + ["--param", "op_user=again"], ["frob"]):
            with self.subTest(args):
                self.assertEqual(self.cli(*args)[0], 2)


if __name__ == "__main__":
    unittest.main()
