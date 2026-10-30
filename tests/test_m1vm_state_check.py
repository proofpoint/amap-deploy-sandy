"""m1vm/state_check.py (m1-state-check): the one-device rule, each way it
must fail, and the rendered units.

The probe outputs below follow blkid's `-o export` and udevadm's
`--query=property` KEY=VALUE forms. Which udev property carries a QEMU
scsi-hd `serial=` on a PVE guest is INFERRED here (ID_SCSI_SERIAL and
ID_SERIAL_SHORT are both accepted) until NET's measured output replaces it.
"""

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
import state_check  # noqa: E402

UUID = "3f2c8a10-5b7e-4c1d-9a2e-6f0b1c2d3e4f"
OTHER_UUID = "0a0b0c0d-1111-4222-8333-944445555666"
LABEL = "m1-state"


def fs(label=None, uuid=None, type_="ext4"):
    out = {"TYPE": type_} if type_ else {}
    if label:
        out["LABEL"] = label
    if uuid:
        out["UUID"] = uuid
    return out


class Fleet:
    """A VM's block devices: R (sda), D (sdb), the state disk (sdc)."""

    def __init__(self):
        self.devs = {
            "sda": (fs(label="cloudimg-rootfs", uuid=OTHER_UUID), {"ID_SERIAL_SHORT": "drive-scsi0"}),
            "sda1": (fs(label="cloudimg-rootfs", uuid=OTHER_UUID), {}),
            "sdb": (fs(label="m1-docker", uuid="11111111-2222-4333-8444-555555555555"), {}),
            "sdc": (fs(label=LABEL, uuid=UUID), {"ID_SCSI_SERIAL": "m1st-210"}),
            "sr0": ({}, {}),
        }
        self.devs["sda"] = (fs(), {"ID_SERIAL_SHORT": "drive-scsi0"})

    def devices(self):
        return sorted(self.devs)

    def probe(self, name):
        f, u = self.devs[name]
        return dict(f), dict(u)


class CheckTest(unittest.TestCase):
    def setUp(self):
        self.f = Fleet()

    def run_check(self, vmid="210"):
        return state_check.check(UUID, vmid, LABEL, self.f.devices(), self.f.probe)

    def test_pass(self):
        self.assertEqual(self.run_check(), ("sdc", "m1st-210"))

    def test_pass_without_vmid(self):
        self.assertEqual(self.run_check(vmid=None), ("sdc", "m1st-210"))

    def test_serial_short_property_also_read(self):
        self.f.devs["sdc"] = (fs(label=LABEL, uuid=UUID), {"ID_SERIAL_SHORT": "m1st-210"})
        self.assertEqual(self.run_check(), ("sdc", "m1st-210"))

    def assert_fails(self, needle, vmid="210"):
        with self.assertRaises(state_check.Fail) as cm:
            self.run_check(vmid=vmid)
        self.assertIn(needle, str(cm.exception))

    def test_each_break(self):
        breaks = {
            "no state disk": (lambda d: d.pop("sdc"), "0 devices carry label"),
            "second label": (lambda d: d.update(sdd=(fs(label=LABEL, uuid=OTHER_UUID), {})), "2 devices carry label"),
            "second uuid": (lambda d: d.update(sdd=(fs(label="x", uuid=UUID), {})), "2 devices carry UUID"),
            "second serial": (lambda d: d.update(sdd=(fs(), {"ID_SCSI_SERIAL": "m1st-211"})), "2 devices carry an m1st-"),
            "wrong uuid": (lambda d: d.update(sdc=(fs(label=LABEL, uuid=OTHER_UUID), {"ID_SCSI_SERIAL": "m1st-210"})),
                           "0 devices carry UUID"),
            "no serial": (lambda d: d.update(sdc=(fs(label=LABEL, uuid=UUID), {})), "0 devices carry an m1st-"),
            "split devices": (lambda d: (d.update(sdc=(fs(label=LABEL, uuid=UUID), {})),
                                         d.update(sdd=(fs(), {"ID_SCSI_SERIAL": "m1st-210"}))), "not one device"),
            "other vm's disk": (lambda d: d.update(sdc=(fs(label=LABEL, uuid=UUID), {"ID_SCSI_SERIAL": "m1st-211"})),
                                "not m1st-210"),
            "not ext4": (lambda d: d.update(sdc=(fs(label=LABEL, uuid=UUID, type_="xfs"),
                                                 {"ID_SCSI_SERIAL": "m1st-210"})), "not ext4"),
            "disagreeing serials": (lambda d: d.update(sdc=(fs(label=LABEL, uuid=UUID),
                                                            {"ID_SCSI_SERIAL": "m1st-210",
                                                             "ID_SERIAL_SHORT": "m1st-211"})), "disagree"),
        }
        for name, (brk, needle) in breaks.items():
            with self.subTest(name):
                self.f = Fleet()
                brk(self.f.devs)
                self.assert_fails(needle)


class MetaTest(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        self.p = self.d / "instance-data.json"

    def write(self, meta):
        self.p.write_text(json.dumps({"ds": {"meta_data": meta}}))

    def test_reads_uuid_and_vmid(self):
        self.write({"m1_state_uuid": UUID, "m1_vmid": 210})
        self.assertEqual(state_check.read_meta(str(self.p), "m1_state_uuid", "m1_vmid"), (UUID, "210"))

    def test_refusals(self):
        cases = {
            "no uuid": {"m1_vmid": "210"},
            "upper uuid": {"m1_state_uuid": UUID.upper(), "m1_vmid": "210"},
            "no vmid": {"m1_state_uuid": UUID},
            "bool vmid": {"m1_state_uuid": UUID, "m1_vmid": True},
            "non-digit vmid": {"m1_state_uuid": UUID, "m1_vmid": "21a"},
        }
        for name, meta in cases.items():
            with self.subTest(name):
                self.write(meta)
                with self.assertRaises(state_check.Fail):
                    state_check.read_meta(str(self.p), "m1_state_uuid", "m1_vmid")

    def test_symlink_refused(self):
        self.write({"m1_state_uuid": UUID})
        link = self.d / "link.json"
        os.symlink(self.p, link)
        with self.assertRaises(state_check.Fail):
            state_check.read_meta(str(link), "m1_state_uuid", None)

    def test_absent(self):
        with self.assertRaises(state_check.Fail):
            state_check.read_meta(str(self.d / "nope"), "k", None)


class CliTest(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        self.idata = self.d / "instance-data.json"
        self.idata.write_text(json.dumps({"ds": {"meta_data": {"m1_state_uuid": UUID, "m1_vmid": "210"}}}))
        self.f = Fleet()

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = state_check.main(list(argv), devices=self.f.devices, probe=self.f.probe)
        return rc, out.getvalue(), err.getvalue()

    def check_args(self):
        return ["check", "--instance-data", str(self.idata), "--label", LABEL,
                "--uuid-key", "m1_state_uuid", "--vmid-key", "m1_vmid"]

    def test_pass_line(self):
        rc, out, _ = self.cli(*self.check_args())
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), f"M1-STATE-CHECK PASS dev=sdc serial=m1st-210 uuid={UUID} label={LABEL}")

    def test_fail_is_1_without_pass(self):
        self.f.devs.pop("sdc")
        rc, out, _ = self.cli(*self.check_args())
        self.assertEqual(rc, 1)
        self.assertTrue(out.startswith("M1-STATE-CHECK FAIL "))

    def test_usage(self):
        for argv in (["check"], ["frob"], self.check_args() + ["--label", "x"],
                     ["check", "--instance-data", str(self.idata), "--label", "bad label", "--uuid-key", "k"]):
            with self.subTest(argv):
                self.assertEqual(self.cli(*argv)[0], 2)


class UnitTest(unittest.TestCase):
    def test_escape(self):
        cases = {"/srv/m1-data": "srv-m1\\x2ddata", "/var/lib/docker": "var-lib-docker",
                 "/data": "data", "/a/.b": "a-.b", "/.a": "\\x2ea"}
        for path, want in cases.items():
            self.assertEqual(state_check.systemd_escape_path(path), want, path)

    def test_render(self):
        units = state_check.render_units(LABEL, "m1_state_uuid", "m1_vmid", "/srv/m1data",
                                         "11111111-2222-4333-8444-555555555555")
        self.assertEqual(sorted(units), ["m1-state-check.service", "srv-m1data.mount", "var-lib-docker.mount"])
        check = units["m1-state-check.service"]
        self.assertIn("Before=srv-m1data.mount", check)
        self.assertIn("--uuid-key m1_state_uuid --vmid-key m1_vmid", check)
        self.assertIn("After=cloud-init-local.service", check)
        mount = units["srv-m1data.mount"]
        self.assertIn("Requires=m1-state-check.service", mount)
        self.assertIn("After=m1-state-check.service", mount)
        self.assertIn("What=/dev/disk/by-label/m1-state", mount)
        self.assertIn("/dev/disk/by-uuid/11111111-2222-4333-8444-555555555555", units["var-lib-docker.mount"])
        for name, text in units.items():
            self.assertNotIn("nofail", text, name)

    def test_render_refuses(self):
        for args in ((LABEL, "k", None, "relative", OTHER_UUID), (LABEL, "k", None, "/", OTHER_UUID),
                     (LABEL, "k", None, "/a b", OTHER_UUID), ("bad label", "k", None, "/d", OTHER_UUID),
                     (LABEL, "k", None, "/d", "not-a-uuid")):
            with self.subTest(args):
                with self.assertRaises(state_check.Usage):
                    state_check.render_units(*args)

    def test_render_cli_writes_once(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        argv = ["render-units", "--label", LABEL, "--uuid-key", "k", "--data", "/srv/m1data",
                "--docker-uuid", OTHER_UUID, "--outdir", d]
        with redirect_stdout(io.StringIO()):
            self.assertEqual(state_check.main(argv), 0)
            with self.assertRaises(FileExistsError):
                state_check.main(argv)
        self.assertEqual(sorted(os.listdir(d)), ["m1-state-check.service", "srv-m1data.mount", "var-lib-docker.mount"])


if __name__ == "__main__":
    unittest.main()
