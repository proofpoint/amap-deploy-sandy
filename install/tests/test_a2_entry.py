"""The entry file and its loader, run as real processes under the launch
line's form, and a real exec that carries lock descriptors across."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import a2fix
import make_manifest

LAUNCH_ENV = {"HOME": a2fix.ME.pw_dir, "PATH": "/usr/bin:/bin", "SSH_AUTH_SOCK": "", "TERM": "xterm"}
INTERPRETER_LINE = "CAUSE=PREFLIGHT.INTERPRETER"


def copy_install(dst):
    shutil.copytree(a2fix.INSTALL, dst, ignore=shutil.ignore_patterns("tests", "__pycache__"))


def run_entry(install_dir, argv, env=None):
    return subprocess.run([sys.executable, "-I", "-B", os.path.join(install_dir, "alpha2_install.py")] + argv,
                          env=env if env is not None else LAUNCH_ENV,
                          capture_output=True, text=True, timeout=60)


class ManifestTest(unittest.TestCase):
    def test_committed_manifest_matches_the_files(self):
        self.assertEqual(make_manifest.main(["x", "--check"]), 0,
                         "install/MANIFEST is stale: run install/tests/make_manifest.py")

    def test_the_three_installer_data_lists_are_one(self):
        import a2_vm
        import alpha2_install
        self.assertEqual(make_manifest.INSTALLER_DATA, ("a2_s3_render.py.lock",))
        self.assertEqual(alpha2_install.INSTALLER_DATA, make_manifest.INSTALLER_DATA)
        self.assertEqual(a2_vm.INSTALLER_DATA, make_manifest.INSTALLER_DATA)

    def test_a_present_lock_is_listed_and_an_absent_one_is_not(self):
        d = tempfile.mkdtemp(prefix="a2mf-")
        self.addCleanup(shutil.rmtree, d, True)
        for name, data in (("a.py", b"A = 1\n"), ("notes.txt", b"n\n"), ("x.lock", b"x\n")):
            with open(os.path.join(d, name), "wb") as f:
                f.write(data)
        self.addCleanup(setattr, make_manifest, "INSTALL", make_manifest.INSTALL)
        make_manifest.INSTALL = d
        a = make_manifest.render()
        self.assertEqual([ln.split(b"  ")[1] for ln in a.splitlines()], [b"a.py"])
        with open(os.path.join(d, "a2_s3_render.py.lock"), "wb") as f:
            f.write(b"lock\n")
        import hashlib
        self.assertEqual(make_manifest.render(),
                         a + (hashlib.sha256(b"lock\n").hexdigest() + "  a2_s3_render.py.lock\n").encode())


class LoaderTest(unittest.TestCase):
    def setUp(self):
        self.base = a2fix.make_base()
        self.addCleanup(shutil.rmtree, self.base, True)
        self.inst = os.path.join(self.base, "install")
        copy_install(self.inst)

    def test_untampered_entry_reaches_the_launcher(self):
        """With the default site, the private overlay path is unset, so the
        launcher's first file read refuses: proof the loader loaded every
        module it needed from pinned bytes."""
        r = run_entry(self.inst, ["--verify"])
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stderr.splitlines()[0], "CAUSE=PREFLIGHT.PRIVATE_SOURCE")

    def test_stray_variable_refuses_first(self):
        r = run_entry(self.inst, ["--verify"], dict(LAUNCH_ENV, EXTRA="1"))
        self.assertEqual(r.stderr.splitlines()[0], "CAUSE=RUNNER.ENV")

    def test_one_byte_change_in_a_module_refuses(self):
        p = os.path.join(self.inst, "a2_stop.py")
        with open(p, "ab") as f:
            f.write(b"\n")
        r = run_entry(self.inst, ["--verify"])
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stderr.splitlines()[0], INTERPRETER_LINE)

    def test_unlisted_module_refuses(self):
        with open(os.path.join(self.inst, "a2_extra.py"), "w") as f:
            f.write("X = 1\n")
        p = os.path.join(self.inst, "a2_main.py")
        with open(p) as f:
            src = f.read()
        with open(p, "w") as f:
            f.write("import a2_extra\n" + src)
        mf = os.path.join(self.inst, "MANIFEST")
        import hashlib
        with open(p, "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()
        with open(mf) as f:
            lines = [ln if not ln.endswith("  a2_main.py\n") else h + "  a2_main.py\n" for ln in f]
        with open(mf, "w") as f:
            f.writelines(lines)
        r = run_entry(self.inst, ["--verify"])
        self.assertEqual(r.stderr.splitlines()[0], INTERPRETER_LINE)

    def test_a_listed_render_lock_is_data_the_loader_accepts(self):
        with open(os.path.join(self.inst, "a2_s3_render.py.lock"), "wb") as f:
            f.write(b"lock\n")
        self.addCleanup(setattr, make_manifest, "INSTALL", make_manifest.INSTALL)
        make_manifest.INSTALL = self.inst
        self.assertEqual(make_manifest.main(["x"]), 0)
        with open(os.path.join(self.inst, "MANIFEST"), "rb") as f:
            self.assertIn(b"  a2_s3_render.py.lock\n", f.read())
        r = run_entry(self.inst, ["--verify"])
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stderr.splitlines()[0], "CAUSE=PREFLIGHT.PRIVATE_SOURCE")

    def test_another_data_name_in_the_manifest_refuses(self):
        mf = os.path.join(self.inst, "MANIFEST")
        with open(mf, "ab") as f:
            f.write(b"0" * 64 + b"  other.lock\n")
        r = run_entry(self.inst, ["--verify"])
        self.assertEqual(r.stderr.splitlines()[0], INTERPRETER_LINE)

    def test_missing_or_malformed_manifest_refuses(self):
        mf = os.path.join(self.inst, "MANIFEST")
        with open(mf, "rb") as f:
            good = f.read()
        first = good.splitlines(True)[0]
        bads = (None, good[:-1], good + first, b"x  a2_main.py\n",
                first.upper() + good,                       # upper-case digest
                good.replace(b"  a2_main.py", b"  a2_m\xc3\xa4in.py"),  # non-ASCII name
                good.replace(b"  a2_main.py", b"  sub/a2_main.py"),      # a path, not a name
                good.replace(b"  a2_main.py", b" a2_main.py"),           # one space
                b"\xff" + good)
        for bad in bads:
            with self.subTest(bad=bad if bad is None else bad[-20:]):
                if bad is None:
                    os.unlink(mf)
                else:
                    with open(mf, "wb") as f:
                        f.write(bad)
                r = run_entry(self.inst, ["--verify"])
                self.assertEqual(r.stderr.splitlines()[0], INTERPRETER_LINE)
                with open(mf, "wb") as f:
                    f.write(good)


class ExecCarriesLocksTest(unittest.TestCase):
    """A process takes the locks with a2_locks.acquire (inheritable) and
    execs a fresh interpreter, which finds every lock held by its inherited
    descriptors (5.1a step 5, 5.3 step 5). Without set_inheritable the
    exec closes them, and the fresh process refuses."""

    def setUp(self):
        self.base = a2fix.make_base()
        self.addCleanup(shutil.rmtree, self.base, True)
        self.w = a2fix.World(self.base)

    def run_pair(self, inheritable):
        code = (
            "import os,sys\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "import a2_locks\n"
            "root=sys.argv[2]; uid=os.getuid()\n"
            "order=a2_locks.lock_order(root, ['hv','hub'], True)\n"
            "if sys.argv[3]=='take':\n"
            "    h=a2_locks.acquire(order, uid)\n"
            "    if sys.argv[4]=='0':\n"
            "        [os.set_inheritable(fd, False) for fd in h.values()]\n"
            "    os.execv(sys.executable,[sys.executable,'-I','-c',sys.argv[5],sys.argv[1],root,'check'])\n"
            "try:\n"
            "    a2_locks.find_held(order, uid); print('held')\n"
            "except Exception as e:\n"
            "    print(getattr(e,'cause','?'))\n"
        )
        r = subprocess.run([sys.executable, "-I", "-c", code, a2fix.INSTALL, self.w.root, "take",
                            "1" if inheritable else "0", code], capture_output=True, text=True, timeout=60)
        return r.stdout.strip()

    def test_inherited(self):
        self.assertEqual(self.run_pair(True), "held")

    def test_closed_across_exec_refuses(self):
        self.assertEqual(self.run_pair(False), "RUNNER.ADMISSION")


if __name__ == "__main__":
    unittest.main()
