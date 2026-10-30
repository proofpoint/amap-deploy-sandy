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


MAN = {"images": {"m1-hop:pin": IMG}, "hdot": [{"name": ".base_build_hash", "mode": "0644",
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
        self.assertEqual(verify[-4:], ["--verify-image", os.path.join(run_dir, os.listdir(run_dir)[0]), "--commit", COMMIT])

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


if __name__ == "__main__":
    unittest.main()
