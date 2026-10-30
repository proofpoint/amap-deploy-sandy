"""m1vm/state_check.py (m1-state-check): the one-device rule, each way it
must fail, the strict probe parsing, and the rendered units pinned line by
line.

The probe outputs below follow blkid's `-o export` and udevadm's
`--query=property` KEY=VALUE forms. Which udev property carries a QEMU
scsi-hd `serial=` on a PVE guest is INFERRED here (ID_SCSI_SERIAL and
ID_SERIAL_SHORT are both accepted); B6 on 206 is the native proof.
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
from unittest import mock

M1VM = Path(__file__).resolve().parent.parent / "m1vm"
sys.path.insert(0, str(M1VM))
import state_check  # noqa: E402

UUID = "3f2c8a10-5b7e-4c1d-9a2e-6f0b1c2d3e4f"
OTHER_UUID = "0a0b0c0d-1111-4222-8333-944445555666"
DOCKER_UUID = "11111111-2222-4333-8444-555555555555"
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
            "sda": (fs(), {"ID_SERIAL_SHORT": "drive-scsi0"}),
            "sda1": (fs(label="cloudimg-rootfs", uuid=OTHER_UUID), {}),
            "sdb": (fs(label="m1-docker", uuid=DOCKER_UUID), {}),
            "sdc": (fs(label=LABEL, uuid=UUID), {"ID_SCSI_SERIAL": "m1st-210"}),
            "sr0": ({}, {}),
        }

    def devices(self):
        return sorted(self.devs)

    def probe(self, name):
        f, u = self.devs[name]
        return dict(f), dict(u)


class CheckTest(unittest.TestCase):
    def setUp(self):
        self.f = Fleet()

    def run_check(self, vmid="210"):
        return state_check.check(UUID, vmid, self.f.devices(), self.f.probe)

    def test_pass(self):
        self.assertEqual(self.run_check(), ("sdc", "m1st-210"))

    def test_serial_short_property_also_read(self):
        self.f.devs["sdc"] = (fs(label=LABEL, uuid=UUID), {"ID_SERIAL_SHORT": "m1st-210"})
        self.assertEqual(self.run_check(), ("sdc", "m1st-210"))

    def test_each_break(self):
        breaks = {
            "no state disk": (lambda d: d.pop("sdc"), "0 devices carry label"),
            "second label": (lambda d: d.update(sdd=(fs(label=LABEL, uuid=OTHER_UUID), {})), "2 devices carry label"),
            "second uuid": (lambda d: d.update(sdd=(fs(label="x", uuid=UUID), {})), "2 devices carry UUID"),
            "second serial": (lambda d: d.update(sdd=(fs(), {"ID_SCSI_SERIAL": "m1st-211"})), "2 devices carry an m1st-"),
            "wrong uuid": (lambda d: d.update(sdc=(fs(label=LABEL, uuid=OTHER_UUID), {"ID_SCSI_SERIAL": "m1st-210"})),
                           "0 devices carry UUID"),
            "no serial": (lambda d: d.update(sdc=(fs(label=LABEL, uuid=UUID), {})), "0 devices carry an m1st-"),
            "prefixed serial": (lambda d: d.update(sdc=(fs(label=LABEL, uuid=UUID), {"ID_SCSI_SERIAL": "xm1st-210"})),
                                "0 devices carry an m1st-"),
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
                with self.assertRaises(state_check.Fail) as cm:
                    self.run_check()
                self.assertIn(needle, str(cm.exception))


class PairsTest(unittest.TestCase):
    def test_good(self):
        self.assertEqual(state_check.parse_pairs("A=1\nB_2=x y\n\n", "t"), {"A": "1", "B_2": "x y"})

    def test_refusals(self):
        for text in ("noequals\n", "=x\n", "a=lower\n", "A=1\nA=2\n", "A=\x01\n", "A=1\r\n", " A=1\n"):
            with self.subTest(text):
                with self.assertRaises(state_check.Fail):
                    state_check.parse_pairs(text, "t")


class ProbeStubTest(unittest.TestCase):
    """real_probe against stub blkid and udevadm executables."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)

    def stub(self, name, rc, out):
        p = self.d / name
        p.write_text(f"#!/bin/sh\nprintf '%s' '{out}'\nexit {rc}\n")
        p.chmod(0o755)
        return str(p)

    def probe(self, b_rc, b_out, u_rc, u_out):
        with mock.patch.object(state_check, "BLKID", self.stub("blkid", b_rc, b_out)), \
                mock.patch.object(state_check, "UDEVADM", self.stub("udevadm", u_rc, u_out)):
            return state_check.real_probe("sdc")

    def test_ok(self):
        self.assertEqual(self.probe(0, "LABEL=m1-state\nTYPE=ext4\n", 0, "ID_SCSI_SERIAL=m1st-210\n"),
                         ({"LABEL": "m1-state", "TYPE": "ext4"}, {"ID_SCSI_SERIAL": "m1st-210"}))

    def test_no_filesystem_is_empty(self):
        self.assertEqual(self.probe(2, "", 0, "DEVNAME=/dev/sdc\n")[0], {})

    def test_exit_codes_fail(self):
        for args in ((1, "", 0, ""), (4, "", 0, ""), (2, "TYPE=ext4\n", 0, ""), (0, "", 1, "")):
            with self.subTest(args):
                with self.assertRaises(state_check.Fail):
                    self.probe(*args)

    def test_malformed_output_fails(self):
        with self.assertRaises(state_check.Fail):
            self.probe(0, "LABEL=a\nLABEL=b\n", 0, "")


class MetaTest(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        self.p = self.d / "instance-data.json"

    def write(self, meta):
        self.p.write_text(json.dumps({"ds": {"meta_data": meta}}))

    def test_reads_uuid_and_vmid(self):
        self.write({"m1-state-uuid": UUID, "m1-vmid": 210})
        self.assertEqual(state_check.read_meta(str(self.p)), (UUID, "210"))

    def test_refusals(self):
        cases = {
            "no uuid": {"m1-vmid": "210"},
            "upper uuid": {"m1-state-uuid": UUID.upper(), "m1-vmid": "210"},
            "no vmid": {"m1-state-uuid": UUID},
            "bool vmid": {"m1-state-uuid": UUID, "m1-vmid": True},
            "non-digit vmid": {"m1-state-uuid": UUID, "m1-vmid": "21a"},
        }
        for name, meta in cases.items():
            with self.subTest(name):
                self.write(meta)
                with self.assertRaises(state_check.Fail):
                    state_check.read_meta(str(self.p))

    def test_symlink_refused(self):
        self.write({"m1-state-uuid": UUID, "m1-vmid": "210"})
        link = self.d / "link.json"
        os.symlink(self.p, link)
        with self.assertRaises(state_check.Fail):
            state_check.read_meta(str(link))

    def test_absent(self):
        with self.assertRaises(state_check.Fail):
            state_check.read_meta(str(self.d / "nope"))


class CliTest(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        self.idata = self.d / "instance-data.json"
        self.idata.write_text(json.dumps({"ds": {"meta_data": {"m1-state-uuid": UUID, "m1-vmid": "210"}}}))
        self.f = Fleet()

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = state_check.main(list(argv), devices=self.f.devices, probe=self.f.probe)
        return rc, out.getvalue(), err.getvalue()

    def test_pass_line(self):
        rc, out, _ = self.cli("check", "--instance-data", str(self.idata))
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), f"M1-STATE-CHECK PASS dev=sdc serial=m1st-210 uuid={UUID} label={LABEL}")

    def test_fail_is_1_without_pass(self):
        self.f.devs.pop("sdc")
        rc, out, _ = self.cli("check", "--instance-data", str(self.idata))
        self.assertEqual(rc, 1)
        self.assertTrue(out.startswith("M1-STATE-CHECK FAIL "))

    def test_usage(self):
        for argv in (["check"], ["frob"], ["check", "--instance-data", "x", "--instance-data", "y"],
                     ["check", "--instance-data", "x", "--label", "y"], ["render-units", "--outdir", "x"]):
            with self.subTest(argv):
                self.assertEqual(self.cli(*argv)[0], 2)


def parse_unit(text):
    """{section: [(key, value)]}, in order: the graph the tests assert on."""
    out, section = {}, None
    for line in text.splitlines():
        if not line:
            continue
        if line.startswith("["):
            section = line.strip("[]")
            out[section] = []
        else:
            key, _, value = line.partition("=")
            out[section].append((key, value))
    return out


class UnitTest(unittest.TestCase):
    def setUp(self):
        self.units = state_check.render_units(DOCKER_UUID)

    def test_names(self):
        self.assertEqual(sorted(self.units), ["m1-state-check.service", "srv-m1\\x2dstate.mount", "var-lib-docker.mount"])
        self.assertEqual(state_check.systemd_escape_path("/srv/m1-state") + ".mount", state_check.DATA_MOUNT_UNIT)

    def test_escape(self):
        cases = {"/srv/m1-data": "srv-m1\\x2ddata", "/var/lib/docker": "var-lib-docker",
                 "/data": "data", "/a/.b": "a-.b", "/.a": "\\x2ea"}
        for path, want in cases.items():
            self.assertEqual(state_check.systemd_escape_path(path), want, path)

    def test_check_unit_exact(self):
        self.assertEqual(parse_unit(self.units["m1-state-check.service"]), {
            "Unit": [("Description", "M1: exactly one state disk for this VM, before /srv/m1-state is mounted"),
                     ("DefaultDependencies", "no"),
                     ("After", "cloud-init-local.service systemd-udev-trigger.service"),
                     ("Before", "srv-m1\\x2dstate.mount")],
            "Service": [("Type", "oneshot"), ("RemainAfterExit", "yes"),
                        ("ExecStartPre", "/usr/bin/udevadm settle --timeout=30"),
                        ("ExecStart", "/usr/bin/python3 -I -S -B /opt/amap/bin/m1-state-check check "
                                      "--instance-data /run/cloud-init/instance-data.json")],
        })

    def test_state_mount_exact(self):
        self.assertEqual(parse_unit(self.units["srv-m1\\x2dstate.mount"]), {
            "Unit": [("Description", "M1: the state disk at /srv/m1-state"),
                     ("Requires", "m1-state-check.service"), ("After", "m1-state-check.service")],
            "Mount": [("What", "/dev/disk/by-label/m1-state"), ("Where", "/srv/m1-state"), ("Type", "ext4"),
                      ("Options", "nodev,nosuid")],
            "Install": [("RequiredBy", "local-fs.target")],
        })

    def test_docker_mount_exact(self):
        self.assertEqual(parse_unit(self.units["var-lib-docker.mount"]), {
            "Unit": [("Description", "M1: Docker's store on D"), ("Before", "docker.service docker.socket")],
            "Mount": [("What", f"/dev/disk/by-uuid/{DOCKER_UUID}"), ("Where", "/var/lib/docker"), ("Type", "ext4"),
                      ("Options", "nodev")],
            "Install": [("RequiredBy", "local-fs.target")],
        })

    def test_boot_stop_graph(self):
        # A failed check must fail local-fs.target: nothing is merely wanted, nothing is nofail.
        for name, text in self.units.items():
            self.assertNotIn("nofail", text, name)
            self.assertNotIn("WantedBy", text, name)

    def test_render_refuses_bad_uuid(self):
        with self.assertRaises(state_check.Usage):
            state_check.render_units("not-a-uuid")


class InstallTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        self.argv = ["render-units", "--docker-uuid", DOCKER_UUID, "--outdir", self.d]

    def test_writes_once_then_refuses(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(state_check.main(self.argv), 0)
            with self.assertRaises(FileExistsError):
                state_check.main(self.argv)
        self.assertEqual(sorted(os.listdir(self.d)),
                         ["m1-state-check.service", "srv-m1\\x2dstate.mount", "var-lib-docker.mount"])
        units = state_check.render_units(DOCKER_UUID)
        for name, text in units.items():
            self.assertEqual(Path(self.d, name).read_text(), text)

    def test_short_writes_are_completed(self):
        real = os.write
        with mock.patch.object(state_check.os, "write", lambda fd, b: real(fd, bytes(b[:7]))):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(state_check.main(self.argv), 0)
        for name, text in state_check.render_units(DOCKER_UUID).items():
            self.assertEqual(Path(self.d, name).read_text(), text)

    def test_failure_leaves_no_unit(self):
        real = os.write
        calls = {"n": 0}

        def write(fd, b):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError(28, "No space left on device")
            return real(fd, b)
        with mock.patch.object(state_check.os, "write", write):
            with self.assertRaises(OSError):
                state_check.main(self.argv)
        self.assertEqual(os.listdir(self.d), [])

    def test_zero_progress_fails(self):
        with mock.patch.object(state_check.os, "write", lambda fd, b: 0):
            with self.assertRaises(OSError):
                state_check.main(self.argv)
        self.assertEqual(os.listdir(self.d), [])


if __name__ == "__main__":
    unittest.main()
