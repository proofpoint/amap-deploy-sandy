"""m1vm/vm_admit.py (ADM): the phase-independent rows against a fixture VM
tree, each row proven to FAIL on a tree broken for it, the final line's
form, and that UNKNOWN never yields a PASS line.

Ownership is root's on a real VM; the tests run unprivileged, so a stand-in
reports root ownership for the files a real VM would have root-owned. The
command outputs (systemctl show, findmnt, docker inspect, getfacl) follow
the tools' documented forms and are INFERRED until A1 runs on a clone.
"""

import hashlib
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

M1VM = Path(__file__).resolve().parent.parent / "m1vm"
sys.path.insert(0, str(M1VM))
import man  # noqa: E402
import vm_admit  # noqa: E402

STATE_UUID = "3f2c8a10-5b7e-4c1d-9a2e-6f0b1c2d3e4f"
D_UUID = "11111111-2222-4333-8444-555555555555"
BOOT = "0a0b0c0d-1111-4222-8333-944445555666"
IMG = "sha256:" + "1" * 64
KEY_OP = "ssh-ed25519 AAAAop operator"
KEY_NET = "ssh-ed25519 AAAAne net-m1"
KEY_ADMIN = "ssh-ed25519 AAAAad m1-admin"
KEY_ADM = "ssh-ed25519 AAAAam adm"
ACCOUNTS = {"op": {"name": "op", "uid": 2101, "gid": 2101}, "m1-admin": {"name": "m1admin", "uid": 2102, "gid": 2102},
            "adm": {"name": "m1adm", "uid": 2103, "gid": 2103}, "uid-1": {"name": "m1router", "uid": 2104, "gid": 2104},
            "uid-2": {"name": "m1hub", "uid": 2105, "gid": 2105}, "registry": {"name": "m1reg", "uid": 2106, "gid": 2106}}
KEYS = {"op": [KEY_OP, KEY_NET], "m1-admin": [KEY_ADMIN], "adm": [KEY_ADM]}
HOMES = {"op": "/home/op", "m1-admin": "/home/m1admin", "adm": "/var/lib/m1adm"}
DROPIN = b"[Socket]\nExecStartPost=/usr/bin/setfacl -m u:2104:rw /run/docker.sock\n"


class Vm:
    """A fixture VM rooted at a temp dir."""

    def __init__(self):
        self.root = Path(tempfile.mkdtemp())
        r = self.root
        homes = HOMES
        lines = ["root:x:0:0:root:/root:/bin/bash"]
        for role, a in ACCOUNTS.items():
            home = homes.get(role, f"/var/lib/{a['name']}")
            lines.append(f"{a['name']}:x:{a['uid']}:{a['gid']}::{home}:/bin/sh")
        (r / "etc/sudoers.d").mkdir(parents=True)
        (r / "etc/passwd").write_text("\n".join(lines) + "\n")
        (r / "etc/passwd").chmod(0o644)
        (r / "etc/group").write_text("root:x:0:\ndocker:x:999:op\n")
        (r / "etc/group").chmod(0o644)
        (r / "etc/sudoers.d/m1-admin").write_text("m1admin ALL=(ALL:ALL) NOPASSWD: ALL\n")
        (r / "etc/sudoers.d/m1adm").write_text("m1adm ALL=(root) NOPASSWD: /usr/bin/python3 -I -S -B -\n")
        for p in (r / "etc/sudoers.d").iterdir():
            p.chmod(0o440)
        for role, keys in KEYS.items():
            d = r / homes[role].lstrip("/") / ".ssh"
            d.mkdir(parents=True)
            (d / "authorized_keys").write_text("\n".join(keys) + "\n")
            (d / "authorized_keys").chmod(0o600)
        (r / "etc/systemd/system").mkdir(parents=True)
        os.symlink("/dev/null", r / "etc/systemd/system/qemu-guest-agent.service")
        # What BAKE's `systemctl enable` leaves for the two RequiredBy=local-fs.target mounts.
        (r / "etc/systemd/system/local-fs.target.requires").mkdir()
        for u in ("srv-m1\\x2dstate.mount", "var-lib-docker.mount"):
            os.symlink(f"/etc/systemd/system/{u}", r / "etc/systemd/system/local-fs.target.requires" / u)
        (r / "proc/sys/kernel/random").mkdir(parents=True)
        (r / "proc/sys/kernel/random/boot_id").write_text(BOOT + "\n")
        dev = os.stat(r).st_dev
        (r / f"proc/{os.getpid()}").mkdir(parents=True)
        (r / f"proc/{os.getpid()}/mountinfo").write_text(
            f"1 0 {os.major(dev)}:{os.minor(dev)} / / rw - ext4 /dev/sda1 rw\n"
            f"9 1 {os.major(dev)}:{os.minor(dev)} / /srv/m1-state rw - ext4 /dev/sdc rw\n")
        (r / "proc/1/fd").mkdir(parents=True)
        (r / "dev/virtio-ports").mkdir(parents=True)
        (r / "dev/vport2p1").write_text("")
        os.symlink("../vport2p1", r / "dev/virtio-ports/org.qemu.guest_agent.0")
        os.symlink("/dev/null", r / "proc/1/fd/0")
        sandy = r / "srv/m1-state/sandy"
        sandy.mkdir(parents=True)
        (sandy / ".base_build_hash").write_bytes(b"b\n")
        (sandy / ".base_build_hash").chmod(0o644)
        (r / "opt/amap").mkdir(parents=True)
        self.man = {"schema": "m1vm-man/1", "images": {"m1-hop:pin": IMG}, "packages": {"docker-ce": "5:27.0.0-1", "qemu-guest-agent": "1:8.2.2"},
                    "hdot": [{"name": ".base_build_hash", "mode": "0644", "sha256": hashlib.sha256(b"b\n").hexdigest()}],
                    "files": {"/etc/systemd/system/docker.socket.d/m1-acl.conf":
                              {"sha256": hashlib.sha256(DROPIN).hexdigest(), "mode": "0644", "uid": 0, "gid": 0}},
                    "accounts": {a["name"]: {"uid": a["uid"], "gid": a["gid"], "home": HOMES.get(role, f"/var/lib/{a['name']}"),
                                             "groups": ["docker"] if role == "op" else []}
                                 for role, a in ACCOUNTS.items()}}
        (r / "etc/systemd/system/docker.socket.d").mkdir(parents=True)
        (r / "etc/systemd/system/docker.socket.d/m1-acl.conf").write_bytes(DROPIN)
        (r / "etc/systemd/system/docker.socket.d/m1-acl.conf").chmod(0o644)
        (r / "srv/m1-state/sandy/features/amap/instances").mkdir(parents=True)
        for rel, text in (("etc/systemd/coredump.conf.d/m1.conf", "[Coredump]\nStorage=none\n"),
                          ("etc/systemd/journald.conf.d/m1.conf", "[Journal]\nStorage=volatile\n")):
            (r / rel).parent.mkdir(parents=True, exist_ok=True)
            (r / rel).write_text(text)
            (r / rel).chmod(0o644)
        (r / "proc/swaps").write_text("Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n")
        self.record_units()
        self.cmd = {}

    def record_units(self):
        """MAN's tree of /etc/systemd/system as m1-man itself records it on T0
        (man.tree, Opus round7 (b)2): the guest's tree, enable's links
        included, before G-AS-n's mask link. Files are root's on T0, as the
        checks' view reports them."""
        t = man.tree(str(self.root / "etc/systemd/system"))
        for e in t.values():
            if e["type"] == "f":
                e["uid"] = 0
        t.pop("qemu-guest-agent.service")
        self.man["trees"] = {"/etc/systemd/system": t}
        return self.write_man()

    def write_man(self):
        p = self.root / "opt/amap/MAN.json"
        if p.exists():
            p.chmod(0o644)
        p.write_text(json.dumps(self.man, sort_keys=True))
        p.chmod(0o444)
        return hashlib.sha256(p.read_bytes()).hexdigest()

    def runner(self, argv):
        key = " ".join(argv)
        for pat, out in self.cmd.items():
            if pat in key:
                return out
        if argv[:4] == ["/usr/bin/systemctl", "show", "-p", "UnitFileState"]:
            return 0, "".join("UnitFileState=masked\n" for _ in argv[5:])
        if argv[0] == "/usr/bin/dpkg-query" and "${db:Status-Abbrev}\t${Package}\t${Version}\n" in argv:
            return 0, "ii \tdocker-ce\t5:27.0.0-1\nhi \tqemu-guest-agent\t1:8.2.2\nrc \tsnapd\t2.66\n"
        if argv == ["/usr/bin/dpkg-query", "-W", "-f", "${Status}", "systemd-coredump"]:
            return 0, "install ok installed"
        if argv[0] == "/usr/bin/dpkg-query":
            return 1, ""
        if argv[:2] == ["/usr/bin/systemd-analyze", "cat-config"]:
            # The documented form: each file under a `# <path>` comment, in merge order.
            sec, val = {"systemd/journald.conf": ("Journal", "volatile"),
                        "systemd/coredump.conf": ("Coredump", "none")}[argv[2]]
            name = argv[2].split("/")[1]
            return 0, (f"# /etc/{argv[2]}\n[{sec}]\n#Storage=auto\n\n"
                       f"# /etc/systemd/{name}.d/m1.conf\n[{sec}]\nStorage={val}\n")
        if argv[:3] == ["/usr/bin/docker", "ps", "--all"]:
            return 0, ""
        if "qemu-guest-agent.service" in argv:
            return 0, "ActiveState=inactive\nUnitFileState=masked\n"
        if argv[:3] == ["/usr/bin/findmnt", "-n", "-o"] and argv[3] == "UUID,SOURCE,FSTYPE":
            return 0, f"{STATE_UUID} /dev/sdc ext4\n"
        if argv[:3] == ["/usr/bin/findmnt", "-n", "-o"]:
            return 0, D_UUID + "\n"
        if argv[:3] == ["/usr/bin/docker", "image", "inspect"]:
            return 0, IMG + "\n"
        if argv[0] == "/usr/bin/getfacl":
            return 0, "user::rw-\nuser:2104:rw-\ngroup::rw-\nmask::rw-\nother::---\n"
        raise AssertionError(argv)


def params(vm, phase="A1", **over):
    p = {"phase": phase, "host": "H1", "att": "ATT-1", "adm": "a" * 64, "prov": "b" * 64,
         "env": "none", "exp": "none", "ovl": "none", "d7": "c" * 64, "dd": "d" * 64, "ctlr": "none",
         "accounts": ACCOUNTS, "keys": KEYS, "state_uuid": STATE_UUID, "d_uuid": D_UUID,
         "man_sha256": hashlib.sha256((vm.root / "opt/amap/MAN.json").read_bytes()).hexdigest()}
    if phase not in ("A1", "A1r"):
        p.update(env="e" * 64, exp="f" * 64, ovl="0" * 64)
    p.update(over)
    return p


class AdmCase(unittest.TestCase):
    def setUp(self):
        self.vm = Vm()
        self.addCleanup(shutil.rmtree, self.vm.root)
        patcher = mock.patch.object(vm_admit, "ROOT", str(self.vm.root))
        patcher.start()
        self.addCleanup(patcher.stop)
        # The fixture's mask link is the test user's, not root's.
        mask = mock.patch.object(vm_admit, "AGENT_MASK",
                                 ("qemu-guest-agent.service", {"type": "l", "uid": os.getuid(), "target": "/dev/null"}))
        mask.start()
        self.addCleanup(mask.stop)
        # Root ownership, as on a real VM, for the files root owns there.
        real_read, real_lstat = vm_admit.read_regular, vm_admit.lstat_path
        self.foreign = set()

        def as_root(st, path):
            uid = st.st_uid
            if path.startswith(("/etc/", "/opt/", "/proc/")) and path not in self.foreign:
                uid = 0
            elif path.startswith("/srv/m1-state/sandy/"):
                uid = 2101
            elif "/.ssh/" in path:
                owner = {"/home/op": 2101, "/home/m1admin": 2102, "/var/lib/m1adm": 2103}
                uid = next((u for h, u in owner.items() if path.startswith(h)), uid)
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, uid, st.st_gid, st.st_size,
                                   st.st_atime, st.st_mtime, st.st_ctime))

        def read(path, limit=1 << 22):
            data, st = real_read(path, limit)
            return data, as_root(st, path)

        def lstat(path):
            st = real_lstat(path)
            return None if st is None else as_root(st, path)
        for name, fn in (("read_regular", read), ("lstat_path", lstat)):
            p = mock.patch.object(vm_admit, name, fn)
            p.start()
            self.addCleanup(p.stop)
        # MAN's unit tree is recorded through the same (root-owning) view the
        # checks read, as BAKE records it on T0.
        self.vm.record_units()

    def admit(self, phase="A1", **over):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = vm_admit.main(params(self.vm, phase, **over), runner=self.vm.runner,
                               now=lambda: (2026, 10, 31, 0, 0, 0, 4, 304, 0))
        return rc, out.getvalue().splitlines()

    OWED = {"agent-prov", "role-and-o-n", "identity", "machine-id", "a1-remainder", "instances", "volumes",
            "enrolment-trees",
            "units-table", "clock", "router1", "router2", "fingerprint"}  # UNKNOWN by design until their inputs exist

    def failing(self, phase="A1", owed=False, **over):
        _, lines = self.admit(phase, **over)
        return sorted(l.split()[2] for l in lines if l.startswith("CHECK ") and l.split()[3] != "PASS"
                      and (owed or l.split()[2] not in self.OWED))


class PassTest(AdmCase):
    def test_a1_owes_three_rows(self):
        rc, lines = self.admit()
        self.assertEqual(rc, 1)
        self.assertEqual(self.failing(owed=True), ["a1-remainder", "agent-prov", "identity", "machine-id"])
        self.assertTrue(lines[-1].startswith("VM-ADMIT A1 FAIL failed=0 unknown=4"))

    def test_a1_pass_line(self):
        owed = {n: mock.patch.object(vm_admit.Admission, n, lambda self: (True, "stand-in"))
                for n in ("check_agent_prov", "check_systemd_tree")}
        owed["owed"] = mock.patch.object(vm_admit.Admission, "owed", lambda self, reason: (lambda: (True, "stand-in")))
        for p in owed.values():
            p.start()
            self.addCleanup(p.stop)
        rc, lines = self.admit()
        self.assertEqual(rc, 0, lines)
        self.assertEqual(lines[-1],
                         f"VM-ADMIT A1 PASS host=H1 att=ATT-1 boot_id={BOOT} adm={'a' * 64} "
                         f"man={params(self.vm)['man_sha256']} ovl=none prov={'b' * 64} env=none exp=none "
                         f"d7={'c' * 64} dd={'d' * 64} ctlr=none role=none utc=2026-10-31T00:00:00Z")
        self.assertTrue(all(l.startswith("CHECK A1 ") for l in lines[:-1]))

    def test_a2a_is_not_yet_complete(self):
        # The B6c-bound rows are UNKNOWN until DS's receipt is reviewed: no PASS line.
        rc, lines = self.admit("A2a")
        self.assertEqual(rc, 1)
        self.assertIn("CHECK A2a role-and-o-n UNKNOWN", "\n".join(lines))
        self.assertTrue(lines[-1].startswith("VM-ADMIT A2a FAIL failed=0 unknown=12"))


class BreakTest(AdmCase):
    def test_each_break(self):
        def keyfile(rel, text):
            (self.vm.root / rel).write_text(text)
        breaks = {
            "man": lambda: (self.vm.root / "opt/amap/MAN.json").chmod(0o644),
            "accounts": lambda: (self.vm.root / "etc/passwd").write_text(
                (self.vm.root / "etc/passwd").read_text().replace(":2104:2104:", ":2199:2104:")),
            "keys": lambda: keyfile("home/op/.ssh/authorized_keys", KEY_OP + "\n"),
            "sudoers": lambda: (self.vm.root / "etc/sudoers.d/README").write_text(""),
            "agent-sealed": lambda: ((self.vm.root / "etc/systemd/system/qemu-guest-agent.service").unlink(),
                                     os.symlink("/lib/systemd/system/qemu-guest-agent.service",
                                                self.vm.root / "etc/systemd/system/qemu-guest-agent.service")),
            "root-ssh-absent": lambda: (self.vm.root / "root/.ssh").mkdir(parents=True),
            "bake-copy-absent": lambda: (self.vm.root / "var/lib/m1-bake").mkdir(parents=True),
            "mounts": lambda: self.vm.cmd.update({"UUID,SOURCE,FSTYPE": (0, f"{D_UUID} /dev/sdc ext4\n")}),
        }
        for name, brk in breaks.items():
            with self.subTest(name):
                self.setUp()
                brk()
                rc, lines = self.admit()
                self.assertEqual(rc, 1)
                self.assertNotIn(" PASS host=", lines[-1])
                self.assertIn(name, self.failing(), lines)

    def test_absent_alias_is_never_pass(self):
        # No alias (agent=0 applied, or never present): UNKNOWN, not PASS.
        (self.vm.root / "dev/virtio-ports/org.qemu.guest_agent.0").unlink()
        _, lines = self.admit()
        self.assertIn("CHECK A1 agent-sealed UNKNOWN", "\n".join(lines))

    def test_absent_alias_with_a_surviving_fd_fails(self):
        (self.vm.root / "dev/virtio-ports/org.qemu.guest_agent.0").unlink()
        # The alias is gone, but a process still holds the resolved device.
        os.symlink("/dev/vport2p1", self.vm.root / "proc/1/fd/4")
        real_stat = os.stat
        with mock.patch.object(vm_admit.os, "stat", lambda p, *a, **k: real_stat(p, *a, **k)
                               if not str(p).endswith("/proc/1/fd/4") else real_stat(self.vm.root / "dev/vport2p1")):
            _, lines = self.admit()
        self.assertIn("CHECK A1 agent-sealed FAIL the agent port is held by pid(s) ['1']", "\n".join(lines))

    def test_man_sha_must_match(self):
        self.assertEqual(self.failing(man_sha256="9" * 64), ["man"])

    def test_more_breaks(self):
        cases = {
            "unlisted keyed account": (lambda: ((self.vm.root / "var/lib/m1router/.ssh").mkdir(parents=True),
                                                (self.vm.root / "var/lib/m1router/.ssh/authorized_keys").write_text("x\n")),
                                       "keys"),
            "sudoers crlf": (lambda: ((self.vm.root / "etc/sudoers.d/m1-admin").chmod(0o640),
                                      (self.vm.root / "etc/sudoers.d/m1-admin").write_bytes(
                                          b"m1admin ALL=(ALL:ALL) NOPASSWD: ALL\r\n"),
                                      (self.vm.root / "etc/sudoers.d/m1-admin").chmod(0o440)), "sudoers"),
            "agent active": (lambda: self.vm.cmd.update({"qemu-guest-agent.service":
                                                         (0, "ActiveState=active\nUnitFileState=masked\n")}),
                             "agent-sealed"),
            "agent port held": (lambda: os.symlink(self.vm.root / "dev/vport2p1", self.vm.root / "proc/1/fd/3"),
                                "agent-sealed"),  # /proc shows the RESOLVED object, never the alias
            "op sandy home on R": (lambda: (self.vm.root / "home/op/.sandy").mkdir(), "op-sandy-absent"),
            "docker not D": (lambda: self.vm.cmd.update({"--target /var/lib/docker": (0, STATE_UUID + "\n")}),
                             "mounts"),
            "op not in docker": (lambda: (self.vm.man["accounts"]["op"].update(groups=[]), self.vm.write_man()),
                                 "accounts"),
        }
        for name, (brk, row) in cases.items():
            with self.subTest(name):
                self.setUp()
                brk()
                over = {}
                if name == "op not in docker":
                    over["man_sha256"] = hashlib.sha256((self.vm.root / "opt/amap/MAN.json").read_bytes()).hexdigest()
                self.assertIn(row, self.failing(**over))

    def test_a2_rows(self):
        cases = {
            "hdot": lambda: (self.vm.root / "srv/m1-state/sandy/.base_build_hash").write_bytes(b"x\n"),
            "images": lambda: self.vm.cmd.update({"docker image inspect": (0, "sha256:" + "2" * 64 + "\n")}),
            "socket-acl": lambda: self.vm.cmd.update({"getfacl": (0, "user::rw-\n")}),
        }
        for row, brk in cases.items():
            with self.subTest(row):
                self.setUp()
                brk()
                self.assertIn(row, self.failing("A2b"))


class ParamTest(AdmCase):
    def test_refusals(self):
        for over in ({"phase": "A3"}, {"host": "H3"}, {"adm": "x"}, {"ctlr": "x"}, {"ovl": "0" * 64},
                     {"state_uuid": "x"}, {"att": "1"}, {"extra": 1}):
            with self.subTest(over):
                p = params(self.vm)
                p.update(over)
                with redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(vm_admit.main(p, runner=self.vm.runner), 2)
                self.assertTrue(out.getvalue().startswith("VM-ADMIT USAGE "))

    def test_unknown_boot_id_is_not_pass(self):
        (self.vm.root / "proc/sys/kernel/random/boot_id").write_text("not-a-uuid\n")
        rc, lines = self.admit()
        self.assertEqual(rc, 1)
        self.assertTrue(lines[-1].startswith("VM-ADMIT A1 FAIL "))


class StdinTest(unittest.TestCase):
    """The delivery shape: one parameter line, then the program, on stdin to
    `python3 -I -S -B -`. On this (non-VM) machine every row fails; what is
    proven is the shape: rows, a FAIL last line, exit 1, never a crash."""

    def run_stdin(self, header):
        # The delivery shape against a FIXTURE root, never this machine's /:
        # the program's ROOT line is pointed at an empty temp tree.
        import subprocess
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        body = (M1VM / "vm_admit.py").read_bytes().replace(b'ROOT = "/"\n', f'ROOT = "{root}"\n'.encode(), 1)
        self.assertIn(root.encode(), body)
        return subprocess.run([sys.executable, "-I", "-S", "-B", "-"], input=header + body, capture_output=True)

    def test_params_line_then_program(self):
        p = {"phase": "A1", "host": "H1", "att": "ATT-1", "adm": "a" * 64, "prov": "b" * 64, "env": "none",
             "exp": "none", "ovl": "none", "d7": "c" * 64, "dd": "d" * 64, "ctlr": "none", "accounts": ACCOUNTS,
             "keys": KEYS, "state_uuid": STATE_UUID, "d_uuid": D_UUID, "man_sha256": "e" * 64}
        r = self.run_stdin(f"M1_ADM_PARAMS = {json.dumps(p)}\n".encode())
        lines = r.stdout.decode().splitlines()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertTrue(lines[-1].startswith("VM-ADMIT A1 FAIL "), lines[-1:])
        self.assertTrue(all(l.startswith("CHECK A1 ") for l in lines[:-1]))

    def test_bad_params_is_usage(self):
        r = self.run_stdin(b'M1_ADM_PARAMS = {"phase": "A1"}\n')
        self.assertEqual(r.returncode, 2, r.stdout)


class RealProcTest(unittest.TestCase):
    """read_proc against THIS machine's real /proc (read-only), where
    pseudo-files report size 0 and /proc/self is a link (Opus round5)."""

    def test_mountinfo_and_boot_id_are_read(self):
        self.assertEqual(vm_admit.ROOT, "/")
        info = vm_admit.read_proc(f"{os.getpid()}/mountinfo")
        self.assertTrue(info.strip(), "a real mountinfo is never empty")
        devs = vm_admit.mount_devices()
        self.assertIn("/", devs)
        bid = vm_admit.read_proc("sys/kernel/random/boot_id", 64).decode().strip()
        self.assertRegex(bid, r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")

    def test_admission_reads_the_real_boot_id(self):
        bid = vm_admit.Admission({"phase": "A1"}).boot_id()
        self.assertRegex(bid, r"\A[0-9a-f-]{36}\Z")

    def test_cap(self):
        with self.assertRaises(OSError):
            vm_admit.read_proc(f"{os.getpid()}/mountinfo", limit=8)

    def test_link_as_last_component_refused(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        (d / "proc/1").mkdir(parents=True)
        (d / "real").write_text("x")
        os.symlink(d / "real", d / "proc/1/mountinfo")
        with mock.patch.object(vm_admit, "ROOT", str(d)):
            with self.assertRaises(OSError):
                vm_admit.read_proc("1/mountinfo")

    def test_proc_self_is_never_followed(self):
        with self.assertRaises(OSError):
            vm_admit.read_proc("self/mountinfo")

    def test_read_regular_would_refuse_a_pseudo_file(self):
        # The reason read_proc exists: the size-0 check rejects /proc files.
        with self.assertRaises(OSError):
            vm_admit.read_regular(f"/proc/{os.getpid()}/mountinfo")


class ReaderTest(unittest.TestCase):
    """read_regular: to EOF through short reads; a change while read fails."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        (self.d / "f").write_bytes(b"x" * 100000)
        p = mock.patch.object(vm_admit, "ROOT", str(self.d))
        p.start()
        self.addCleanup(p.stop)

    def test_short_reads_complete(self):
        real = os.read
        with mock.patch.object(vm_admit.os, "read", lambda fd, n: real(fd, min(n, 7))):
            data, _ = vm_admit.read_regular("/f")
        self.assertEqual(data, b"x" * 100000)

    def test_change_while_read_fails(self):
        real = os.fstat
        calls = {"n": 0}

        def fstat(fd):
            st = real(fd)
            calls["n"] += 1
            if calls["n"] == 2:
                return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid, st.st_gid,
                                       st.st_size + 1, st.st_atime, st.st_mtime, st.st_ctime))
            return st
        with mock.patch.object(vm_admit.os, "fstat", fstat):
            with self.assertRaises(OSError):
                vm_admit.read_regular("/f")

    def test_cap(self):
        with self.assertRaises(OSError):
            vm_admit.read_regular("/f", limit=99999)


class PolicyTest(AdmCase):
    def test_policy_breaks(self):
        cases = {
            "passwd mode": (lambda: (self.vm.root / "etc/passwd").chmod(0o664), "accounts"),
            "keys mode": (lambda: (self.vm.root / "home/op/.ssh/authorized_keys").chmod(0o644), "keys"),
            "sudoers mode": (lambda: (self.vm.root / "etc/sudoers.d/m1adm").chmod(0o640), "sudoers"),
            "op not in docker on the guest": (lambda: (self.vm.root / "etc/group").write_text("docker:x:999:\n"),
                                              "accounts"),
        }
        for name, (brk, row) in cases.items():
            with self.subTest(name):
                self.setUp()
                brk()
                self.assertIn(row, self.failing())

    def test_foreign_owner_and_extra_link(self):
        self.foreign.add("/etc/sudoers.d/m1adm")
        self.assertIn("sudoers", self.failing())
        self.setUp()
        os.link(self.vm.root / "etc/sudoers.d/m1adm", self.vm.root / "etc/second-name")
        self.assertIn("sudoers", self.failing())

    def test_op_outside_docker_on_both_sides(self):
        (self.vm.root / "etc/group").write_text("docker:x:999:\n")
        self.vm.man["accounts"]["op"]["groups"] = []
        sha = self.vm.write_man()
        self.assertIn("accounts", self.failing(man_sha256=sha))

    def test_man_home_must_equal_the_guest(self):
        self.vm.man["accounts"]["op"]["home"] = "/home/elsewhere"
        sha = self.vm.write_man()
        self.assertIn("accounts", self.failing(man_sha256=sha))

    def test_hdot_on_the_wrong_filesystem(self):
        (self.vm.root / f"proc/{os.getpid()}/mountinfo").write_text("1 0 999:999 / / rw - ext4 /dev/sda1 rw\n"
                                                          "9 1 999:998 / /srv/m1-state rw - ext4 /dev/sdc rw\n")
        self.assertIn("hdot", self.failing("A2b"))

    def test_mountinfo_without_the_state_mount_is_unknown(self):
        dev = os.stat(self.vm.root).st_dev
        (self.vm.root / f"proc/{os.getpid()}/mountinfo").write_text(f"1 0 {os.major(dev)}:{os.minor(dev)} / / rw - ext4 /dev/sda1 rw\n")
        _, lines = self.admit("A2b")
        self.assertIn("CHECK A2b hdot UNKNOWN", "\n".join(lines))

    def test_socket_acl_exact(self):
        cases = {
            "extra entry": lambda: self.vm.cmd.update({"getfacl": (0, "user::rw-\nuser:2104:rw-\nuser:2101:rw-\n"
                                                                   "group::rw-\nmask::rw-\nother::---\n")}),
            "other readable": lambda: self.vm.cmd.update({"getfacl": (0, "user::rw-\nuser:2104:rw-\ngroup::rw-\n"
                                                                      "mask::rw-\nother::r--\n")}),
            "drop-in changed": lambda: ((self.vm.root / "etc/systemd/system/docker.socket.d/m1-acl.conf").write_bytes(b"x\n")),
        }
        for name, brk in cases.items():
            with self.subTest(name):
                self.setUp()
                brk()
                self.assertIn("socket-acl", self.failing("A2b"))

    def test_absent_is_observed_once(self):
        calls = []
        real = vm_admit.lstat_path

        def lstat(path):
            calls.append(path)
            return None if len([c for c in calls if c == path]) == 1 else real("/etc/passwd")
        with mock.patch.object(vm_admit, "lstat_path", lstat):
            ok, detail = vm_admit.Admission(params(self.vm), self.vm.runner).check_absent("/root/.ssh")()
        self.assertEqual((ok, detail), (True, "/root/.ssh: absent"))


class SchemaTest(AdmCase):
    def test_nested_refusals(self):
        def acc(**over):
            a = json.loads(json.dumps(ACCOUNTS))
            for k, v in over.items():
                a[k] = v
            return a
        for over in ({"accounts": acc(extra={"name": "x", "uid": 3000, "gid": 3000})},
                     {"accounts": {k: v for k, v in ACCOUNTS.items() if k != "registry"}},
                     {"accounts": acc(op={"name": "op", "uid": 2101})},
                     {"accounts": acc(op={"name": "op", "uid": 0, "gid": 0})},
                     {"accounts": acc(op={"name": "Op x", "uid": 2101, "gid": 2101})},
                     {"keys": {"op": [KEY_OP]}},
                     {"keys": dict(KEYS, op=[])},
                     {"keys": dict(KEYS, op=["a\nb"])}):
            with self.subTest(over):
                p = params(self.vm)
                p.update(over)
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(vm_admit.main(p, runner=self.vm.runner), 2)


class Part2Test(AdmCase):
    """ADM part 2's first real rows."""

    def test_systemd_tree_breaks(self):
        cases = {
            "extra unit at A1": (lambda: (self.vm.root / "etc/systemd/system/amap-x.service").write_text(""), "A1", "FAIL"),
            "changed drop-in": (lambda: ((self.vm.root / "etc/systemd/system/docker.socket.d/m1-acl.conf").write_text("x\n")),
                                "A1", "FAIL"),
            "mask missing": (lambda: (self.vm.root / "etc/systemd/system/qemu-guest-agent.service").unlink(), "A1", "FAIL"),
            "extra unit at A2a is UNKNOWN": (lambda: (self.vm.root / "etc/systemd/system/amap-x.service").write_text(""),
                                             "A2a", "UNKNOWN"),
        }
        for name, (brk, phase, verdict) in cases.items():
            with self.subTest(name):
                self.setUp()
                brk()
                _, lines = self.admit(phase)
                self.assertIn(f"CHECK {phase} systemd-tree {verdict}", "\n".join(lines))

    def test_template_already_masked_fails(self):
        self.vm.man["trees"]["/etc/systemd/system"]["qemu-guest-agent.service"] = {"type": "l", "uid": os.getuid(),
                                                                                  "target": "/dev/null"}
        sha = self.vm.write_man()
        _, lines = self.admit(man_sha256=sha)
        self.assertIn("CHECK A1 systemd-tree FAIL MAN's T0 already has", "\n".join(lines))

    def test_auto_change(self):
        cases = {
            "one unmasked": (0, "UnitFileState=masked\nUnitFileState=enabled\nUnitFileState=masked\nUnitFileState=masked\n"),
            "too few": (0, "UnitFileState=masked\n"),
        }
        for name, out in cases.items():
            with self.subTest(name):
                self.setUp()
                self.vm.cmd["UnitFileState"] = out
                self.assertIn("auto-change-off", self.failing())
        for name, brk in {
                "snapd installed": lambda: self.vm.cmd.update({"dpkg-query -W -f ${Status} snapd": (0, "install ok installed")}),
                "apport config left": lambda: self.vm.cmd.update({"dpkg-query -W -f ${Status} apport":
                                                                      (0, "deinstall ok config-files")}),
                "coredump stored": lambda: (self.vm.root / "etc/systemd/coredump.conf.d/m1.conf").write_text(
                    "[Coredump]\nStorage=external\n"),
                "journal persistent": lambda: (self.vm.root / "etc/systemd/journald.conf.d/m1.conf").unlink(),
                "swap on": lambda: (self.vm.root / "proc/swaps").write_text(
                    "Filename\tType\tSize\tUsed\tPriority\n/swap.img\tfile\t1\t0\t-2\n"),
        }.items():
            with self.subTest(name):
                self.setUp()
                brk()
                self.assertIn("auto-change-off", self.failing())
        self.setUp()
        self.vm.cmd["dpkg-query -W -f ${Status} snapd"] = (0, "purge ok not-installed")
        self.assertNotIn("auto-change-off", self.failing())

    def test_instances_and_containers_at_a2a(self):
        (self.vm.root / "srv/m1-state/sandy/features/amap/instances/x").mkdir()
        self.assertIn("instances-empty", self.failing("A2a"))
        self.setUp()
        self.vm.cmd["docker ps --all"] = (0, "abc\n")
        self.assertIn("containers", self.failing("A2a"))
        self.setUp()
        import shutil as sh
        sh.rmtree(self.vm.root / "srv/m1-state/sandy/features/amap/instances")
        self.assertIn("instances-empty", self.failing("A2b"))


class Round7Test(AdmCase):
    """Opus round7: enable's links in MAN, and the survivors' gaps."""

    def lines(self, phase="A1", **over):
        return "\n".join(self.admit(phase, **over)[1])

    def test_enable_links_recorded_pass_a1(self):
        tree = self.vm.man["trees"]["/etc/systemd/system"]
        self.assertEqual(tree["local-fs.target.requires/var-lib-docker.mount"]["target"],
                         "/etc/systemd/system/var-lib-docker.mount")
        self.assertIn("CHECK A1 systemd-tree PASS", self.lines())

    def test_man_taken_before_enable_fails_a1(self):
        # Round 7's order: MAN recorded before enable made its links.
        for k in [k for k in self.vm.man["trees"]["/etc/systemd/system"] if k.startswith("local-fs.target.requires")]:
            del self.vm.man["trees"]["/etc/systemd/system"][k]
        sha = self.vm.write_man()
        self.assertIn("CHECK A1 systemd-tree FAIL", self.lines(man_sha256=sha))

    def test_mask_link_wrong_target_fails(self):
        p = self.vm.root / "etc/systemd/system/qemu-guest-agent.service"
        p.unlink()
        os.symlink("/lib/systemd/system/qemu-guest-agent.service", p)
        self.assertIn("CHECK A1 systemd-tree FAIL", self.lines())

    def test_fifo_in_unit_dir_fails(self):
        os.mkfifo(self.vm.root / "etc/systemd/system/x.fifo")
        self.assertIn("CHECK A1 systemd-tree FAIL", self.lines())

    def test_man_without_trees_is_unknown(self):
        del self.vm.man["trees"]
        sha = self.vm.write_man()
        self.assertIn("CHECK A1 systemd-tree UNKNOWN", self.lines(man_sha256=sha))

    def test_coredump_and_dropins(self):
        conf = self.vm.root / "etc/systemd/coredump.conf.d"
        for name, brk in {
                "systemd-coredump absent": lambda: self.vm.cmd.update(
                    {"dpkg-query -W -f ${Status} systemd-coredump": (1, "")}),
                "systemd-coredump config only": lambda: self.vm.cmd.update(
                    {"dpkg-query -W -f ${Status} systemd-coredump": (0, "deinstall ok config-files")}),
                "drop-in with more bytes": lambda: (conf / "m1.conf").write_text("[Coredump]\nStorage=none\nX=1\n"),
                "a later drop-in": lambda: (conf / "zz.conf").write_text("[Coredump]\nStorage=external\n"),
                "systemd-coredump unknown to dpkg": lambda: self.vm.cmd.update(
                    {"dpkg-query -W -f ${Status} systemd-coredump": (0, "unknown ok not-installed")}),
                "a second journald drop-in": lambda: (self.vm.root / "etc/systemd/journald.conf.d/00-x.conf")
                .write_text("[Journal]\nStorage=volatile\n"),
                "overridden from /run": lambda: self.vm.cmd.update({"cat-config systemd/coredump.conf": (0,
                    "# /etc/systemd/coredump.conf\n[Coredump]\n\n# /etc/systemd/coredump.conf.d/m1.conf\n"
                    "[Coredump]\nStorage=none\n\n# /run/systemd/coredump.conf.d/zz.conf\n[Coredump]\n"
                    "Storage=external\n")}),
                "set in another section": lambda: self.vm.cmd.update({"cat-config systemd/journald.conf": (0,
                    "# /etc/systemd/journald.conf\n[Journal]\n#Storage=auto\n[Other]\nStorage=volatile\n")}),
                "never set": lambda: self.vm.cmd.update({"cat-config systemd/journald.conf": (0, "[Journal]\n")}),
                # Opus followup10 (b)1-2: each reading below differs from systemd's, or is not volatile.
                **{name: (lambda tail=tail: self.vm.cmd.update({"cat-config systemd/journald.conf": (0, JOURNAL + tail)}))
                   for name, tail in CAT_CONFIG_BREAKS.items()},
        }.items():
            with self.subTest(name):
                self.setUp()
                conf = self.vm.root / "etc/systemd/coredump.conf.d"
                brk()
                self.assertIn("CHECK A1 auto-change-off FAIL", self.lines())
        self.setUp()
        self.vm.cmd["dpkg-query -W -f ${Status} systemd-coredump"] = (2, "")
        self.assertIn("CHECK A1 auto-change-off UNKNOWN", self.lines())
        # Control for CAT_CONFIG_BREAKS: the same base, ended by a real volatile, PASSes.
        self.setUp()
        self.vm.cmd["cat-config systemd/journald.conf"] = (
            0, JOURNAL + "\n# /run/systemd/journald.conf.d/zzz.conf\n[Journal]\nStorage=volatile\n")
        self.assertIn("CHECK A1 auto-change-off PASS", self.lines())
        self.setUp()
        self.vm.cmd["cat-config systemd/journald.conf"] = (1, "")
        self.assertIn("CHECK A1 auto-change-off UNKNOWN", self.lines())
        self.setUp()
        self.assertIn("CHECK A1 auto-change-off PASS", self.lines())

    def test_dpkg_query_error_is_unknown(self):
        self.vm.cmd["dpkg-query -W -f ${Status} snapd"] = (2, "")
        self.assertIn("CHECK A1 auto-change-off UNKNOWN", self.lines())

    def test_systemctl_error_fails(self):
        self.vm.cmd["UnitFileState"] = (1, "".join("UnitFileState=masked\n" for _ in vm_admit.QUIET_MASK))
        self.assertIn("auto-change-off", self.failing())

    def test_docker_ps_error_is_unknown(self):
        self.vm.cmd["docker ps --all"] = (1, "")
        self.assertIn("CHECK A2a containers UNKNOWN", self.lines("A2a"))

    def test_phase_gating(self):
        (self.vm.root / "srv/m1-state/sandy/features/amap/instances/x").mkdir()
        self.vm.cmd["docker ps --all"] = (0, "abc\n")
        post = self.lines("POST")
        self.assertNotIn("instances-empty", post)
        self.assertIn("CHECK POST instances UNKNOWN", post)
        self.assertIn("CHECK A2b containers UNKNOWN", self.lines("A2b"))


# journald's cat-config with m1.conf in effect, and endings that must not read as volatile.
JOURNAL = ("# /etc/systemd/journald.conf\n[Journal]\n#Storage=auto\n\n"
           "# /etc/systemd/journald.conf.d/m1.conf\n[Journal]\nStorage=volatile\n\n"
           "# /run/systemd/journald.conf.d/zz.conf\n[Journal]\nStorage=persistent\n")
CAT_CONFIG_BREAKS = {
    "commented value after persistent": "#Storage=volatile\n;Storage=volatile\n",
    "value with a prefix": "Storage=xvolatile\n",
    "key in another case": "STORAGE=volatile\n",
    "section in another case": "[journal]\nStorage=volatile\n",
    "headerless later drop-in": "\n# /run/systemd/journald.conf.d/zzz.conf\nStorage=volatile\n",
    "continued line": "X=a\\\nStorage=volatile\n",
    "split only on newline": "X=a\x0bStorage=volatile\n",
}


class PackagesTest(AdmCase):
    def test_packages_exact(self):
        self.assertNotIn("packages", self.failing())
        agent = "hi \tqemu-guest-agent\t1:8.2.2\n"
        for out in ("ii \tdocker-ce\t5:27.0.0-2\n" + agent, "ii \tdocker-ce\t5:27.0.0-1\nii \tcurl\t8\n" + agent, "",
                    "ii \tdocker-ce\t5:27.0.0-1\n",  # the held agent gone
                    "ii \tdocker-ce\t5:27.0.0-1\nhi \tqemu-guest-agent\t1:9.9\n",  # held at another version
                    "ii \tdocker-ce\t5:27.0.0-1\n" + agent + "iF \tcurl\t8\n",  # half-configured
                    "ii \tdocker-ce\t5:27.0.0-1\n" + agent + "iiR\tcurl\t8\n",  # error flag
                    "ii \tdocker-ce\t5:27.0.0-1\n" + agent + "ii \tdocker-ce\t5:27.0.0-1\n",  # listed twice
                    "ii \tdocker-ce\t5:27.0.0-1\n" + agent + "rc \tsnapd\t1\nun \tsnapd\t\n"):  # absent twice
            with self.subTest(out):
                self.setUp()
                self.vm.cmd["${db:Status-Abbrev}"] = (0, out)
                self.assertIn("packages", self.failing())

    def test_dpkg_error_is_unknown(self):
        self.vm.cmd["${db:Status-Abbrev}"] = (2, "ii \tdocker-ce\t5:27.0.0-1\n")
        self.assertIn("CHECK A1 packages UNKNOWN", "\n".join(self.admit()[1]))

    def test_state_rule_is_m1_mans(self):
        import man
        for ab in ("ii ", "hi ", "rc ", "un ", "pn ", "iF ", "iU ", "iiR", "hH ", "it ", "iW ", "ii", "i", "ii  "):
            self.assertEqual(vm_admit.package_state(ab), man.package_state(ab), ab)

    def test_remainder_keeps_a1_from_passing(self):
        owed = {n: mock.patch.object(vm_admit.Admission, n, lambda self: (True, "stand-in"))
                for n in ("check_agent_prov",)}
        for p in owed.values():
            p.start()
            self.addCleanup(p.stop)
        rc, lines = self.admit()
        self.assertEqual(rc, 1)
        self.assertIn("CHECK A1 a1-remainder UNKNOWN", "\n".join(lines))


class SharedConstantsTest(unittest.TestCase):
    def test_quiet_sets_equal_bakes(self):
        import bake
        self.assertEqual(vm_admit.QUIET_MASK, bake.QUIET_MASK)
        self.assertEqual(vm_admit.QUIET_REMOVE, bake.QUIET_REMOVE)
        self.assertEqual(vm_admit.UNIT_DIR, bake.UNIT_DIR)


if __name__ == "__main__":
    unittest.main()
