"""S5 KEYS: the VM-side vm_keys.py (run here, as this uid, with HOME a staged home) and the runner side a2_s5 (on a
fake layer). The public key is checked against RFC 8032 section 7.1, test 1, never against the recipe itself."""

import json
import os
import shutil
import stat
import subprocess
import sys
import unittest

import a2fix
import a2_s5
from a2_causes import Refusal

INSTALL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS = os.path.join(INSTALL, "vm_keys.py")
RFC_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
RFC_PUB = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
REL = a2_s5.ROUTER_JSON


@unittest.skipUnless(os.path.exists("/usr/bin/openssl"), "openssl absent")
class VmKeysTest(unittest.TestCase):
    def setUp(self):
        self.base = a2fix.make_base()
        self.addCleanup(shutil.rmtree, self.base, True)
        self.home = os.path.join(self.base, "home")
        os.mkdir(self.home, 0o755)
        self.d = os.path.join(self.home, ".amap-delegation")
        self.seed = os.path.join(self.d, "seed")

    def run_keys(self, arg=REL):
        with open(KEYS) as f:
            src = f.read()
        return subprocess.run([sys.executable, "-I", "-S", "-c", src, arg], capture_output=True,
                              env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": self.home},
                              stdin=subprocess.DEVNULL)

    def place(self, data=RFC_SEED, mode=0o400):
        os.mkdir(self.d, 0o700)
        with open(self.seed, "wb") as f:
            f.write(data)
        os.chmod(self.seed, mode)

    def router_json(self, pub):
        p = os.path.join(self.home, REL)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            json.dump({"delegation": {"signing_key": {"public_key": pub}}}, f)

    def test_created_once_then_existing_with_the_same_key(self):
        p = self.run_keys()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertRegex(p.stdout.decode(), r"^CREATED [0-9a-f]{64}\n$")
        pub = p.stdout.split()[1]
        st = os.lstat(self.seed)
        self.assertEqual((stat.S_IMODE(st.st_mode), st.st_size, st.st_nlink), (0o400, 32, 1))
        self.assertEqual(stat.S_IMODE(os.lstat(self.d).st_mode), 0o700)
        with open(self.seed, "rb") as f:
            first = f.read()
        q = self.run_keys()
        self.assertEqual((q.returncode, q.stdout), (0, b"EXISTING " + pub + b"\n"))
        with open(self.seed, "rb") as f:
            self.assertEqual(f.read(), first)

    def test_the_public_key_is_rfc_8032s(self):
        self.place()
        p = self.run_keys()
        self.assertEqual((p.returncode, p.stdout), (0, ("EXISTING %s\n" % RFC_PUB).encode()))

    def test_a_router_json_naming_another_key_refuses_and_prints_nothing(self):
        self.place()
        self.router_json("0" * 64)
        with open(self.seed, "rb") as f:
            before = (sorted(os.listdir(self.d)), os.lstat(self.seed).st_mtime_ns, f.read())
        p = self.run_keys()
        self.assertEqual((p.returncode, p.stdout), (3, b""))
        with open(self.seed, "rb") as f:
            self.assertEqual((sorted(os.listdir(self.d)), os.lstat(self.seed).st_mtime_ns, f.read()), before)
        self.router_json(RFC_PUB)
        self.assertEqual(self.run_keys().returncode, 0)

    def test_a_router_json_key_without_a_seed_creates_nothing(self):
        """Opus's r8 N1: router.json is read first, so a key it records with no seed behind it exits 7 and leaves no
        seed and no directory; the next run meets the same state, not an orphan seed."""
        self.router_json(RFC_PUB)
        for _ in range(2):
            p = self.run_keys()
            self.assertEqual((p.returncode, p.stdout), (7, b""))
            self.assertFalse(os.path.lexists(self.d))
        os.mkdir(self.d, 0o700)
        p = self.run_keys()
        self.assertEqual((p.returncode, p.stdout), (7, b""))
        self.assertEqual(os.listdir(self.d), [])

    def test_placement_rules(self):
        cases = (
            ("a second file beside the seed", lambda: (self.place(), open(os.path.join(self.d, "seed.pub"), "w").close())),
            ("the seed 0600", lambda: self.place(mode=0o600)),
            ("the seed 31 bytes", lambda: self.place(data=RFC_SEED[:31])),
            ("the seed a symlink", lambda: (os.mkdir(self.d, 0o700), os.symlink("/dev/null", self.seed))),
            ("the directory 0750", lambda: (self.place(), os.chmod(self.d, 0o750))),
            ("the directory a symlink", lambda: os.symlink(self.base, self.d)),
            ("home group-writable", lambda: os.chmod(self.home, 0o775)),
            ("the seed with two links", lambda: (self.place(), os.link(self.seed, os.path.join(self.base, "x")))),
        )
        for label, act in cases:
            with self.subTest(case=label):
                try:
                    act()
                    p = self.run_keys()
                    self.assertEqual((p.returncode, p.stdout), (4, b""))
                finally:
                    os.chmod(self.home, 0o755)
                    if os.path.islink(self.d):
                        os.unlink(self.d)
                    elif os.path.exists(self.d):
                        os.chmod(self.d, 0o700)
                        shutil.rmtree(self.d, True)
                    if os.path.lexists(os.path.join(self.base, "x")):
                        os.unlink(os.path.join(self.base, "x"))

    def test_usage(self):
        for arg in ("/abs/router.json", "../router.json", "a/../../b", ""):
            with self.subTest(arg=arg):
                self.assertEqual(self.run_keys(arg).returncode, 2)
        self.assertFalse(os.path.exists(self.d))

    def test_the_seed_never_reaches_stdout_or_stderr(self):
        self.place()
        p = self.run_keys()
        self.assertNotIn(RFC_SEED, p.stdout + p.stderr)
        self.assertNotIn(RFC_SEED.hex().encode(), p.stdout + p.stderr)


class FakeLayer:
    def __init__(self, rc, out, prior=False):
        self.rc, self.out, self.calls, self.prior = rc, out, [], prior

    def wrote(self, stage):
        return self.prior

    def pinned_installer_file(self, name, stage):
        assert name == "vm_keys.py" and stage == "KEYS"
        return b"# pinned"

    def exec(self, vm, argv, *, account, stage, writes, stdin=None, timeout_s=None):
        self.calls.append((vm, argv, account, stage, writes))
        return self.rc, self.out, b""


class S5Test(unittest.TestCase):
    def test_facts(self):
        L = FakeLayer(0, ("CREATED %s\n" % RFC_PUB).encode())
        self.assertEqual(a2_s5.keys_on_vm(L, "vm-a", "rl", "router-a"),
                         [("KEY_ID", "router-a-k1"), ("KEY_PUBLIC", RFC_PUB), ("KEY", "CREATED")])
        self.assertEqual(L.calls, [("vm-a", ["/usr/bin/python3", "-I", "-S", "-c", "# pinned", REL], "rl", "KEYS",
                                    True)])
        L = FakeLayer(0, ("EXISTING %s\n" % RFC_PUB).encode())
        self.assertEqual(a2_s5.keys_on_vm(L, "vm-a", "rl", "router-a")[2], ("KEY", "ALREADY"))

    def test_refusals(self):
        # vm_keys writes nothing on rc 3 (another key recorded) or rc 7 (a key recorded, no seed), so each is rc 2
        # unless an earlier VM's call wrote.
        for code in (3, 7):
            for prior, want in ((False, 2), (True, 3)):
                with self.subTest(code=code, prior=prior):
                    with self.assertRaises(Refusal) as cm:
                        a2_s5.keys_on_vm(FakeLayer(code, b"", prior), "vm-a", "rl", "router-a")
                    self.assertEqual((cm.exception.cause, cm.exception.rc), ("KEYS.EXISTS_DIFFERENT", want))
        for rc, out in ((0, b""), (0, b"CREATED " + b"0" * 63 + b"\n"), (0, ("CREATED %s\nmore\n" % RFC_PUB).encode()),
                        (4, b""), (0, ("created %s\n" % RFC_PUB).encode()), (0, ("CREATED %s" % RFC_PUB).encode())):
            with self.subTest(rc=rc, out=out[:20]):
                with self.assertRaises(Refusal) as cm:
                    a2_s5.keys_on_vm(FakeLayer(rc, out), "vm-a", "rl", "router-a")
                self.assertEqual((cm.exception.cause, cm.exception.rc), ("KEYS.UNCLASSIFIED", 3))
        for slug in ("", "-x", "a" * 62 + "!", None):
            with self.subTest(slug=slug):
                with self.assertRaises(Refusal) as cm:
                    a2_s5.keys_on_vm(FakeLayer(0, b""), "vm-a", "rl", slug)
                self.assertEqual((cm.exception.cause, cm.exception.rc), ("KEYS.HOSTS", 2))


if __name__ == "__main__":
    unittest.main()
