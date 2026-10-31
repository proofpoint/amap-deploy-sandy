"""m1vm/b6.py (the B6 read-only phases): each phase's rows and its PASS line,
and each way a phase must FAIL, against a recording stand-in for the tools.
The stand-in outputs follow the tools' documented forms and are INFERRED
until B6 runs on 206.
"""

import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock

M1VM = Path(__file__).resolve().parent.parent / "m1vm"
sys.path.insert(0, str(M1VM))
import b6  # noqa: E402

IMG = "sha256:" + "1" * 64
COMMIT = "d" * 40


class Runner:
    def __init__(self):
        self.calls = []
        self.over = {}

    def __call__(self, argv, root=False, check=True):
        self.calls.append((list(argv), root))
        key = " ".join(argv)
        for pat, out in self.over.items():
            if pat in key:
                return out
        if argv == ["uname", "-m"]:
            return 0, "x86_64\n", ""
        if "{{.Architecture}}" in argv:
            return 0, "amd64\n", ""
        if "{{.Id}}" in argv:
            return 0, IMG + "\n", ""
        if argv[0] == "df":
            return 0, "Avail Size\n1000 2000\n", ""
        if argv[0] == b6.BLKID:
            return 0, "LABEL=m1-state\nTYPE=ext4\n", ""
        if argv[0] == b6.UDEVADM:
            return 0, "ID_SCSI_SERIAL=m1st-206\n", ""
        if b6.STATE_CHECK in argv:
            return 0, "M1-STATE-CHECK PASS dev=sdc serial=m1st-206 uuid=u label=m1-state\n", ""
        if b6.SEED_COPY in argv:
            return 0, "SEED .base_build_hash mode=0644 sha256=x copied\nM1-SEED-COPY PASS n=1 man=y\n", ""
        if "router-fingerprint" in argv:
            return 0, "EXACT\n", ""
        raise AssertionError(argv)


MAN = {"accounts": {"op": {"uid": 2101, "gid": 2101, "home": "/home/op", "groups": ["docker"]},
                    "m1adm": {"uid": 2103, "gid": 2103, "home": "/var/lib/m1adm", "groups": []}},
       "roles": {"op": "op", "adm": "m1adm"},
       "images": {"m1-hop:pin": IMG}, "hdot": [{"name": ".base_build_hash", "mode": "0644",
                                                 "sha256": hashlib.sha256(b"b\n").hexdigest()}],
       "builds": {"router1": {"commit": COMMIT, "tree": "e" * 40, "image": "m1-hop:pin", "id": IMG}}}


class PhaseTest(unittest.TestCase):
    def setUp(self):
        self.r = Runner()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_b6d_pass_and_fails(self):
        p = b6.phase_b6d(MAN, self.r)
        self.assertTrue(p.ok)
        self.assertEqual(p.lines()[-1], "M1-B6 b6d PASS")
        for pat, out in (("uname", (0, "aarch64\n", "")), ("Architecture", (0, "arm64\n", "")),
                         ("df", (1, "", "no"))):
            with self.subTest(pat):
                r = Runner()
                r.over[pat] = out
                self.assertFalse(b6.phase_b6d(MAN, r).ok)
        self.assertFalse(b6.phase_b6d({"images": {}}, self.r).ok)

    def test_facts_capture_every_device_verbatim(self):
        p = b6.phase_facts(self.r, devices=["sda", "sdc"])
        self.assertTrue(p.ok)
        facts = [l for l in p.lines() if l.startswith("FACT ")]
        self.assertEqual(len(facts), 4)
        self.assertIn('FACT sdc udevadm rc=0 "ID_SCSI_SERIAL=m1st-206\\n"', facts)
        self.assertTrue(all(root for argv, root in self.r.calls))
        r = Runner()
        r.over[b6.UDEVADM] = (1, "", "")
        self.assertFalse(b6.phase_facts(r, devices=["sda"]).ok)
        r = Runner()
        r.over[b6.BLKID] = (2, "", "")
        self.assertTrue(b6.phase_facts(r, devices=["sr0"]).ok)
        self.assertFalse(b6.phase_facts(self.r, devices=[]).ok)

    def test_state(self):
        self.assertTrue(b6.phase_state("/run/cloud-init/instance-data.json", self.r).ok)
        r = Runner()
        r.over[b6.STATE_CHECK] = (1, "M1-STATE-CHECK FAIL 0 devices carry label\n", "")
        self.assertFalse(b6.phase_state("/x", r).ok)
        r = Runner()
        r.over[b6.STATE_CHECK] = (0, "something else\n", "")
        self.assertFalse(b6.phase_state("/x", r).ok)

    def test_seed(self):
        dst = self.tmp / "sandy"
        dst.mkdir()
        (dst / ".base_build_hash").write_bytes(b"b\n")
        self.assertTrue(b6.phase_seed("/opt/amap/MAN.json", MAN, "/opt/amap/sandy-seed", str(dst), self.r).ok)
        (dst / ".base_build_hash").write_bytes(b"changed\n")
        self.assertFalse(b6.phase_seed("/m", MAN, "/s", str(dst), self.r).ok)
        (dst / ".base_build_hash").write_bytes(b"b\n")
        r = Runner()
        r.over["{{.Id}}"] = (0, "sha256:" + "2" * 64 + "\n", "")
        self.assertFalse(b6.phase_seed("/m", MAN, "/s", str(dst), r).ok)
        r = Runner()
        r.over[b6.SEED_COPY] = (1, "", "REFUSE x")
        self.assertFalse(b6.phase_seed("/m", MAN, "/s", str(dst), r).ok)

    def test_seed_runs_as_op(self):
        dst = self.tmp / "sandy"
        dst.mkdir()
        (dst / ".base_build_hash").write_bytes(b"b\n")
        b6.phase_seed("/m", MAN, "/s", str(dst), self.r)
        argv = [a for a, _ in self.r.calls if b6.SEED_COPY in a][0]
        self.assertEqual(argv[:5], ["sudo", "-n", "-u", "#2101", "--"])
        # Another valid non-root MAN account is never taken for op: only the role binding names it.
        other = json.loads(json.dumps(MAN))
        other["roles"]["op"] = "m1adm"
        b6.phase_seed("/m", other, "/s", str(dst), self.r)
        argv = [a for a, _ in self.r.calls if b6.SEED_COPY in a][-1]
        self.assertEqual(argv[3], "#2103")
        for bad in ({k: v for k, v in MAN.items() if k != "roles"},
                    dict(MAN, roles={"op": "nosuch"}),
                    dict(MAN, accounts={"op": {"uid": 0}}, roles={"op": "op"})):
            self.assertFalse(b6.phase_seed("/m", bad, "/s", str(dst), self.r).ok)

    def test_df_fields_must_be_integers(self):
        r = Runner()
        r.over["df"] = (0, "Avail Size\n12G 20G\n", "")
        self.assertFalse(b6.phase_b6d(MAN, r).ok)

    def capture(self, doc, name="router-fingerprint-image-20261030T000000Z.json"):
        d = self.tmp / "run"
        d.mkdir(exist_ok=True)
        (d / name).write_text(json.dumps(doc))
        return str(d)

    def test_fprint_pass(self):
        run_dir = self.capture({"source": "image", "image": {"ref": "m1-hop:pin", "id": IMG}})
        p = b6.phase_fprint(MAN, run_dir, "/opt/amap/src/amap-deploy-sandy", self.r)
        self.assertTrue(p.ok, p.lines())
        verify = [a for a, _ in self.r.calls if "router-fingerprint" in a][0]
        self.assertEqual(verify[-4], "--verify-image")
        self.assertNotEqual(os.path.dirname(verify[-3]), run_dir)  # a private copy, not the run_dir file
        self.assertEqual(verify[-2:], ["--commit", COMMIT])
        self.assertFalse(os.path.exists(verify[-3]))  # removed after

    def test_fprint_fails(self):
        cases = {
            "source": ({"source": "running", "image": {"id": IMG}}, None),
            "id": ({"source": "image", "image": {"id": "sha256:" + "9" * 64}}, None),
            "differs": ({"source": "image", "image": {"id": IMG}}, (1, "DIFFERS\n", "")),
            "unknown": ({"source": "image", "image": {"id": IMG}}, (2, "UNKNOWN\n", "")),
            "exact but nonzero": ({"source": "image", "image": {"id": IMG}}, (1, "EXACT\n", "")),
        }
        for name, (doc, verify) in cases.items():
            with self.subTest(name):
                self.setUp()
                r = Runner()
                if verify:
                    r.over["router-fingerprint"] = verify
                self.assertFalse(b6.phase_fprint(MAN, self.capture(doc), "/d", r).ok)

    def test_fprint_needs_exactly_one_capture(self):
        run_dir = self.capture({"source": "image", "image": {"id": IMG}})
        self.capture({"source": "image", "image": {"id": IMG}}, name="router-fingerprint-image-2.json")
        self.assertFalse(b6.phase_fprint(MAN, run_dir, "/d", self.r).ok)
        empty = self.tmp / "empty"
        empty.mkdir()
        self.assertFalse(b6.phase_fprint(MAN, str(empty), "/d", self.r).ok)

    def test_fprint_symlinked_capture_refused(self):
        d = self.tmp / "run"
        d.mkdir()
        real = self.tmp / "real.json"
        real.write_text(json.dumps({"source": "image", "image": {"id": IMG}}))
        os.symlink(real, d / "router-fingerprint-image-1.json")
        self.assertFalse(b6.phase_fprint(MAN, str(d), "/d", self.r).ok)

    def test_fprint_without_man_build(self):
        self.assertFalse(b6.phase_fprint({"builds": {}}, "/x", "/d", self.r).ok)


class CliTest(unittest.TestCase):
    def test_usage(self):
        for argv in ([], ["frob"], ["b6d"], ["b6d", "--man", "rel"], ["seed", "--man", "/a", "--seed", "/b"],
                     ["seed", "--man", "/a", "--seed", "/b", "--dst", "/c", "--op", "op"],
                     ["facts", "--man", "/a"]):
            with self.subTest(argv):
                with redirect_stderr(io.StringIO()):
                    self.assertEqual(b6.main(argv, Runner()), 2)

    def test_fail_has_no_pass_line(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        man = Path(d) / "MAN.json"
        man.write_text(json.dumps(MAN))
        r = Runner()
        r.over["uname"] = (0, "aarch64\n", "")
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(b6.main(["b6d", "--man", str(man)], r), 1)
        self.assertEqual(out.getvalue().splitlines()[-1], "M1-B6 b6d FAIL")
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(b6.main(["b6d", "--man", str(man)], Runner()), 0)
        self.assertEqual(out.getvalue().splitlines()[-1], "M1-B6 b6d PASS")


class GraphTest(unittest.TestCase):
    """phase graph against `systemctl show` KEY=VALUE output (INFERRED form
    until 206; the property names are systemd's documented ones)."""

    GOOD = {
        "m1-state-check.service": {"Type": "oneshot", "RemainAfterExit": "yes", "ActiveState": "active",
                                   "Result": "success"},
        "srv-m1\\x2dstate.mount": {"Requires": "system.slice m1-state-check.service -.mount",
                                    "After": "m1-state-check.service systemd-journald.socket",
                                    "RequiredBy": "local-fs.target", "WantedBy": "",
                                    "Options": "rw,nosuid,nodev,relatime", "What": "/dev/disk/by-label/m1-state",
                                    "Where": "/srv/m1-state", "ActiveState": "active"},
        "var-lib-docker.mount": {"RequiredBy": "local-fs.target docker.service", "Options": "rw,nodev,relatime",
                                 "ActiveState": "active"},
        "local-fs.target": {"Requires": "srv-m1\\x2dstate.mount var-lib-docker.mount -.mount"},
    }

    def setUp(self):
        # The guest's unit dir as `systemctl enable` leaves it for the two
        # RequiredBy=local-fs.target mounts (INFERRED until 206 measures it),
        # owned by the test user, who stands in for root.
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.req = self.tmp / "local-fs.target.requires"
        self.req.mkdir()
        self.req.chmod(0o755)
        for u in (b6.DATA_MOUNT, b6.DOCKER_MOUNT):
            os.symlink(f"/etc/systemd/system/{u}", self.req / u)
        for name, value in (("ROOT_UID", os.getuid()), ("ROOT_GID", os.getgid())):
            p = mock.patch.object(b6, name, value)
            p.start()
            self.addCleanup(p.stop)

    @staticmethod
    def link_owner(uid):
        """os.stat, with UID as the owner of what it reports without following
        a link: the links, while the directory's fstat is untouched."""
        real = os.stat

        def stat_(path, *a, **kw):
            st = real(path, *a, **kw)
            if kw.get("follow_symlinks") is False:
                st = os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, uid) + tuple(st)[5:])
            return st
        return stat_

    def graph(self, runner):
        return b6.phase_graph(runner, unit_dir=str(self.tmp))

    def runner(self, units):
        def run(argv, root=False, check=True):
            self.assertEqual(argv[:3], [b6.SYSTEMCTL, "show", "-p"])
            unit = argv[-1]
            props = argv[3].split(",")
            if unit not in units:
                return 1, "", "no such unit"
            return 0, "".join(f"{k}={units[unit][k]}\n" for k in props if k in units[unit]), ""
        return run

    def units(self):
        return {u: dict(v) for u, v in self.GOOD.items()}

    def test_pass(self):
        p = self.graph(self.runner(self.units()))
        self.assertTrue(p.ok, p.lines())
        self.assertEqual(p.lines()[-1], "M1-B6 graph PASS")

    def test_each_break(self):
        breaks = {
            "simple": ("m1-state-check.service", "Type", "simple"),
            "no remain": ("m1-state-check.service", "RemainAfterExit", "no"),
            "check failed": ("m1-state-check.service", "Result", "exit-code"),
            "check inactive": ("m1-state-check.service", "ActiveState", "failed"),
            "mount not requiring": ("srv-m1\\x2dstate.mount", "Requires", "system.slice"),
            "mount not after": ("srv-m1\\x2dstate.mount", "After", "systemd-journald.socket"),
            "only wanted": ("srv-m1\\x2dstate.mount", "RequiredBy", ""),
            "wanted too": ("srv-m1\\x2dstate.mount", "WantedBy", "local-fs.target"),
            "nofail": ("srv-m1\\x2dstate.mount", "Options", "rw,nofail"),
            "other device": ("srv-m1\\x2dstate.mount", "What", "/dev/sdc"),
            "mount inactive": ("srv-m1\\x2dstate.mount", "ActiveState", "failed"),
            "docker wanted": ("var-lib-docker.mount", "RequiredBy", "docker.service"),
            "docker nofail": ("var-lib-docker.mount", "Options", "nofail"),
            "local-fs misses state": ("local-fs.target", "Requires", "var-lib-docker.mount"),
        }
        for name, (unit, key, value) in breaks.items():
            with self.subTest(name):
                units = self.units()
                units[unit][key] = value
                self.assertFalse(self.graph(self.runner(units)).ok)

    def test_enable_links(self):
        self.assertIn("B6 enable-links PASS", "\n".join(self.graph(self.runner(self.units())).lines()))
        # Every break names its paths through self, which each setUp renews.
        def link():
            return self.req / b6.DOCKER_MOUNT

        def relink(target):
            link().unlink()
            os.symlink(target, link())
        breaks = {
            "relative target": lambda: relink(f"../{b6.DOCKER_MOUNT}"),
            "vendor target": lambda: relink(f"/lib/systemd/system/{b6.DOCKER_MOUNT}"),
            "link missing": lambda: link().unlink(),
            "a file, not a link": lambda: (link().unlink(), link().write_text("")),
            "dir mode": lambda: self.req.chmod(0o775),
            "dir a link": lambda: (os.rename(self.req, self.tmp / "real"),
                                   os.symlink(self.tmp / "real", self.req)),
            "dir absent": lambda: shutil.rmtree(self.req),
            "not root's": lambda: mock.patch.object(b6, "ROOT_UID", os.getuid() + 1).start(),
            "group not root's": lambda: mock.patch.object(b6, "ROOT_GID", os.getgid() + 1).start(),
            "link not root's": lambda: mock.patch.object(b6.os, "stat", self.link_owner(os.getuid() + 1)).start(),
        }
        for name, brk in breaks.items():
            with self.subTest(name):
                self.setUp()
                brk()
                lines = "\n".join(self.graph(self.runner(self.units())).lines())
                mock.patch.stopall()
                self.assertIn("B6 enable-links FAIL", lines)
                self.assertTrue(lines.endswith("M1-B6 graph FAIL"))

    def test_missing_unit_or_property(self):
        units = self.units()
        units.pop("m1-state-check.service")
        self.assertFalse(self.graph(self.runner(units)).ok)
        units = self.units()
        units["local-fs.target"] = {}
        self.assertFalse(self.graph(self.runner(units)).ok)

    def test_duplicate_property_line_fails(self):
        def run(argv, root=False, check=True):
            return 0, "Requires=a\nRequires=b\n", ""
        self.assertIsNone(b6.show("local-fs.target", ("Requires",), run))


class ReadRegularTest(unittest.TestCase):
    def test_hard_linked_capture_refused(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        (d / "run").mkdir()
        f = d / "run" / "router-fingerprint-image-1.json"
        f.write_text(json.dumps({"source": "image", "image": {"id": IMG}}))
        os.link(f, d / "second-name")
        self.assertFalse(b6.phase_fprint(MAN, str(d / "run"), "/d", Runner()).ok)


class EgressTest(unittest.TestCase):
    """phase egress runs NET's real NET_PROBE bytes. The probes here are
    loopback only (a listener this test opens, and closed ports), so no host
    is contacted; the output form is NET's own (NET 35209a88 sample)."""

    def setUp(self):
        import socket
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.addCleanup(self.listener.close)
        port = self.listener.getsockname()[1]
        self.profile = {"net_probes": {
            "clone_reach": [{"kind": "tcp", "addr": "127.0.0.1", "port": port, "what": "a loopback listener"}],
            "clone_fail": [{"kind": "tcp", "addr": "127.0.0.1", "port": 1, "what": "loopback closed tcp"},
                           {"kind": "dns", "addr": "127.0.0.1", "port": 9, "what": "loopback no dns"}]}}
        self.probe = str(M1VM / "net_probe_d94fe842.py")

    def write_profile(self):
        p = self.d / "profile.json"
        p.write_text(json.dumps(self.profile))
        return str(p), hashlib.sha256(p.read_bytes()).hexdigest()

    def test_real_probe_pass(self):
        path, sha = self.write_profile()
        p = b6.phase_egress(path, sha, self.probe, b6.run)
        self.assertTrue(p.ok, p.lines())
        self.assertEqual(hashlib.sha256((M1VM / "net_probe_d94fe842.py").read_bytes()).hexdigest(),
                         b6.NET_PROBE_SHA256)

    def test_reach_that_fails_and_fail_that_reaches(self):
        self.profile["net_probes"]["clone_reach"], self.profile["net_probes"]["clone_fail"][:1] = (
            self.profile["net_probes"]["clone_fail"][:1], self.profile["net_probes"]["clone_reach"])
        path, sha = self.write_profile()
        p = b6.phase_egress(path, sha, self.probe, b6.run)
        self.assertFalse(p.ok)
        fails = [l for l in p.lines() if " FAIL " in l]
        self.assertTrue(any("clone_reach:tcp" in l for l in fails), fails)
        self.assertTrue(any("clone_fail:tcp" in l for l in fails), fails)

    def test_shas_checked(self):
        path, sha = self.write_profile()
        self.assertFalse(b6.phase_egress(path, "0" * 64, self.probe, b6.run).ok)
        other = self.d / "probe.py"
        other.write_bytes((M1VM / "net_probe_d94fe842.py").read_bytes() + b"\n")
        self.assertFalse(b6.phase_egress(path, sha, str(other), b6.run).ok)

    def test_oversized_profile_fails_not_crashes(self):
        big = self.d / "big.json"
        big.write_bytes(b" " * ((1 << 22) + 1))
        p = b6.phase_egress(str(big), "0" * 64, self.probe, b6.run)
        self.assertFalse(p.ok)
        self.assertIn("too large", "\n".join(p.lines()))

    def test_item_shape(self):
        self.profile["net_probes"]["clone_fail"][0]["extra"] = 1
        path, sha = self.write_profile()
        self.assertFalse(b6.phase_egress(path, sha, self.probe, b6.run).ok)
        self.profile["net_probes"].pop("clone_reach")
        path, sha = self.write_profile()
        self.assertFalse(b6.phase_egress(path, sha, self.probe, b6.run).ok)

    def test_echo_and_run_failures(self):
        path, sha = self.write_profile()
        cases = {
            "reordered": lambda items: (0, json.dumps([dict(i, ok=False) for i in reversed(items)]) + "\n", ""),
            "rc": lambda items: (1, json.dumps([dict(i, ok=(i["port"] != 1 and i["kind"] == "tcp")) for i in items]) + "\n", "boom"),
            "echo altered": lambda items: (0, json.dumps([dict(i, what="changed", ok=(i["port"] != 1 and i["kind"] == "tcp"))
                                                         for i in items]) + "\n", ""),
            "two lines": lambda items: (0, "[]\n[]\n", ""),
            "not a list": lambda items: (0, "{}\n", ""),
            "extra key": lambda items: (0, json.dumps([dict(i, ok=(i["port"] != 1 and i["kind"] == "tcp"), x=1)
                                                      for i in items]) + "\n", ""),
            "ok not bool": lambda items: (0, json.dumps([dict(i, ok=1 if (i["port"] != 1 and i["kind"] == "tcp") else 0)
                                                        for i in items]) + "\n", ""),
            "short": lambda items: (0, json.dumps([dict(i, ok=False) for i in items][:-1]) + "\n", ""),
            "extra non-object": lambda items: (0, json.dumps([dict(i, ok=(i["port"] != 1 and i["kind"] == "tcp"))
                                                             for i in items] + [7]) + "\n", ""),
        }
        for name, fake in cases.items():
            with self.subTest(name):
                def runner(argv, root=False, check=True, fake=fake):
                    return fake(json.loads(argv[-1]))
                self.assertFalse(b6.phase_egress(path, sha, self.probe, runner).ok)

    def test_program_passed_as_one_argv_with_its_newline(self):
        path, sha = self.write_profile()
        seen = []

        def runner(argv, root=False, check=True):
            seen.append(argv)
            items = json.loads(argv[-1])
            return 0, json.dumps([dict(i, ok=(i["port"] != 1 and i["kind"] == "tcp")) for i in items]) + "\n", ""
        b6.phase_egress(path, sha, self.probe, runner)
        self.assertEqual(seen[0][:3], [b6.PYTHON, "-I", "-c"])
        self.assertEqual(seen[0][3], (M1VM / "net_probe_d94fe842.py").read_text())
        self.assertTrue(seen[0][3].endswith("\n"))


if __name__ == "__main__":
    unittest.main()
