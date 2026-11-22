"""The shared VM layer (a2_vm) and its bootstrap (vm_bootstrap), on a fake ssh and a fake sudo.

The fake ssh checks the route's exact options, then runs the remote words with `sh -c` on this host, with
/usr/bin/sudo replaced by a fake that records its argv and drops -n, -u ACCOUNT and --. The bootstrap under test is
the shipped one with ROOT and OWNER rewritten to a temporary root and this uid, served from a temporary installer
checkout whose MANIFEST lists it, and whose sha is the lock's installer.sha256: the pin path is the real one.
"""

import copy
import hashlib
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest

import a2fix  # noqa: F401  (puts install/ on sys.path)
import a2_vm
from a2_causes import Refusal

INSTALL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHIPPED = os.path.join(INSTALL, "vm_bootstrap.py")
LAUNCHER = os.path.join(INSTALL, "vm_launch.py")
ME = (os.getuid(), os.getgid())

FAKE_SSH = r'''#!/bin/sh
# fake ssh: the route must start -F /dev/null; then the remote string runs here. The layer gives ssh an environment
# of PATH and LC_ALL only, so the log and directory paths are written into this file, not read from variables.
log=@LOG@
printf '%s\n' "SSH $*" >> "$log"
[ "$1" = -F ] && [ "$2" = /dev/null ] || { echo "fake ssh: bad route" >&2; exit 255; }
[ -e @DIR@/down ] && exit 255
[ -e @DIR@/hang ] && exec sleep 5
[ -e @DIR@/readyhang ] && { printf 'READY\n'; exec sleep 5; }
# Two slow steps, each under a 1 s timeout and over it together.
[ -e @DIR@/slowstatus ] && { sleep 0.7; printf 'READY\n'; sleep 0.7; printf 'RC 0\n'; exit 0; }
[ -e @DIR@/slowexit ] && { sleep 0.7; printf 'READY\nRC 0\n'; exec sleep 0.7; }
[ -e @DIR@/slowvalue ] && { sleep 0.7; printf 'READY\n'; sleep 0.7; cat > /dev/null; printf 'RC 0\n'; exit 0; }
[ -e @DIR@/closeout ] && { sleep 0.7; printf 'READY\nRC 0\n'; exec 1>&-; sleep 0.7; exit 0; }
[ -e @DIR@/afterrc ] && { printf 'READY\n'; cat > /dev/null; printf 'RC 0\nmore\n'; exit 0; }
# A session that never says READY and reads its stdin to EOF: every byte the layer sends is recorded, however
# late, so a value sent without READY is always seen.
[ -e @DIR@/notready ] && { printf 'NOT\n'; cat > @DIR@/drained.bytes; exit 7; }
for last; do :; done
cmd=$(printf '%s' "$last" | sed "s#/usr/bin/sudo#@DIR@/sudo#g")
# What a login session on a VM may carry: the launcher must keep it from the command.
export SANDY_HOME=/leak CLAUDE_CODE_OAUTH_TOKEN=leak HOME=/leak
umask 077
if [ -e @DIR@/tee ]; then
  f=@DIR@/stdin.fifo; rm -f "$f"; mkfifo "$f"
  exec 3<&0
  tee -a @DIR@/stdin.bytes <&3 > "$f" & tp=$!
  /bin/sh -c "$cmd" < "$f"; rc=$?
  kill $tp 2>/dev/null; exit $rc
fi
exec /bin/sh -c "$cmd"
'''
FAKE_SUDO = r'''#!/bin/sh
printf '%s\n' "SUDO $*" >> @LOG@
[ "$1" = -n ] || { echo "fake sudo: -n missing" >&2; exit 1; }
shift
if [ "$1" = -u ]; then shift 2; fi
[ "$1" = -- ] && shift
exec "$@"
'''
WRITER = r'''
import atexit
import resource
OUT = %r
HELD = []
def _after():
    # At the bootstrap's exit: what the value's bytearray holds once the bootstrap is done with it.
    with open(OUT + ".after", "ab") as f:
        f.write(b"".join(bytes(v) for v in HELD))
atexit.register(_after)
def main(mode, value, account):
    with open(OUT, "ab") as f:
        f.write(("%%s %%s %%s %%s\n" %% (mode, account, type(value).__name__,
                 "" if value is None else bytes(value).decode())).encode())
    import ctypes
    with open(OUT + ".core", "w") as f:
        f.write(repr(resource.getrlimit(resource.RLIMIT_CORE)) + " dumpable=%%d" %% ctypes.CDLL(None).prctl(3, 0, 0, 0, 0))
    if value is not None:
        HELD.append(value)
    return 0
'''


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="a2vm-")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.fake = os.path.join(self.d, "fake")
        os.mkdir(self.fake)
        self.log = os.path.join(self.d, "log")
        for name, text in (("ssh", FAKE_SSH), ("sudo", FAKE_SUDO)):
            p = os.path.join(self.fake, name)
            with open(p, "w") as f:
                f.write(text.replace("@LOG@", self.log).replace("@DIR@", self.fake))
            os.chmod(p, 0o755)
        # The VM root: usr/local/bin, a real directory owned by this uid, mode 0755.
        self.root = os.path.join(self.d, "vm")
        os.makedirs(os.path.join(self.root, "usr", "local", "bin"))
        os.makedirs(os.path.join(self.root, "opt"))
        for p in ("usr", "usr/local", "usr/local/bin", "opt"):
            os.chmod(os.path.join(self.root, p), 0o755)
        os.chmod(self.root, 0o755)
        # The installer checkout: the bootstrap with ROOT and OWNER rewritten, and a MANIFEST that lists it.
        self.repo = os.path.join(self.d, "repo")
        self.inst = os.path.join(self.repo, "install")
        os.makedirs(os.path.join(self.inst, "w"))
        self.write_bootstrap(self.bootstrap_text())
        self.out = os.path.join(self.d, "writer.out")
        with open(os.path.join(self.inst, "w", "api.py"), "w") as f:
            f.write(WRITER % self.out)
        self.lock = copy.deepcopy(a2fix.LOCK)
        self.lock["installer"]["sha256"] = self.manifest_sha()
        self.lock["writers"] = [{"use": "api_key", "path": "install/w/api.py",
                                 "sha256": self.sha_file(os.path.join(self.inst, "w", "api.py"))}]
        self.kh = os.path.join(self.d, "known_hosts")
        open(self.kh, "w").close()
        self.hosts = {"vms": [{"name": "vm-a", "ssh_alias": "vm-a-r"}]}

    def bootstrap_text(self):
        with open(SHIPPED) as f:
            t = f.read()
        assert t.count('ROOT = "/"\n') == 1 and t.count("OWNER = (0, 0)\n") == 1
        return t.replace('ROOT = "/"\n', "ROOT = %r\n" % self.root).replace("OWNER = (0, 0)\n", "OWNER = %r\n" % (ME,))

    def write_bootstrap(self, text):
        with open(os.path.join(self.inst, "vm_bootstrap.py"), "w") as f:
            f.write(text)
        if not os.path.exists(os.path.join(self.inst, "vm_launch.py")):
            shutil.copyfile(LAUNCHER, os.path.join(self.inst, "vm_launch.py"))
        with open(os.path.join(self.inst, "MANIFEST"), "w") as f:
            for name in ("vm_bootstrap.py", "vm_launch.py"):
                f.write("%s  %s\n" % (self.sha_file(os.path.join(self.inst, name)), name))

    def manifest_sha(self):
        return self.sha_file(os.path.join(self.inst, "MANIFEST"))

    @staticmethod
    def sha_file(p):
        with open(p, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def layer(self, **kw):
        args = dict(hosts=self.hosts, lock=self.lock, known_hosts_for=lambda vm: self.kh, login="op",
                    installer_dir=self.inst, ssh=os.path.join(self.fake, "ssh"))
        args.update(kw)
        return a2_vm.VmLayer(**args)

    def logged(self):
        try:
            with open(self.log) as f:
                return f.read().splitlines()
        except FileNotFoundError:
            return []

    def refuses(self, cause, fn, *a, rc=None, **kw):
        with self.assertRaises(Refusal) as cm:
            fn(*a, **kw)
        self.assertEqual(cm.exception.cause, cause)
        if rc is not None:
            self.assertEqual(cm.exception.rc, rc)
        return cm.exception


class ShippedBootstrapTest(unittest.TestCase):
    def test_the_shipped_bootstrap_targets_the_real_root_as_root(self):
        with open(SHIPPED) as f:
            t = f.read()
        self.assertEqual(t.count('ROOT = "/"\n'), 1)
        self.assertEqual(t.count("OWNER = (0, 0)\n"), 1)


class RouteTest(Base):
    def test_the_route_is_exact(self):
        rc, out, err = self.layer().exec("vm-a", ["/bin/echo", "hi"], account="op", stage="AGENTS", writes=False)
        self.assertEqual((rc, out), (0, b"hi\n"))
        ssh = [l for l in self.logged() if l.startswith("SSH ")][0]
        self.assertTrue(ssh.startswith(
            "SSH -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=%s "
            "-o GlobalKnownHostsFile=/dev/null -o IdentitiesOnly=yes -T -l op vm-a-r -- " % self.kh), ssh)

    def test_another_account_goes_through_sudo_u(self):
        self.layer().exec("vm-a", ["/bin/true"], account="agent", stage="AGENTS", writes=False)
        with open(LAUNCHER) as f:
            src = f.read()
        self.assertIn("\nSUDO -n -u agent -- /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/python3 -I -S -c "
                      + src + " /bin/true\n", "\n".join(self.logged()) + "\n")

    def test_the_login_account_runs_the_launcher_without_sudo(self):
        self.layer().exec("vm-a", ["/bin/true"], account="op", stage="AGENTS", writes=False)
        self.assertEqual([l for l in self.logged() if l.startswith("SUDO ")], [])

    def test_the_command_sees_exactly_path_lc_all_and_the_accounts_home(self):
        for account in ("op", "agent"):
            with self.subTest(account=account):
                rc, out, _ = self.layer().exec("vm-a", ["/usr/bin/env"], account=account, stage="AGENTS", writes=False)
                self.assertEqual(rc, 0)
                env = dict(l.split("=", 1) for l in out.decode().splitlines())
                self.assertEqual(env, {"PATH": "/usr/bin:/bin", "LC_ALL": "C",
                                       "HOME": pwd.getpwuid(os.getuid()).pw_dir})

    def test_the_launcher_returns_127_when_it_cannot_run_the_command(self):
        rc, _, _ = self.layer().exec("vm-a", [os.path.join(self.d, "absent")], account="op", stage="AGENTS", writes=False)
        self.assertEqual(rc, 127)

    def test_the_launcher_never_runs_a_relative_argv0(self):
        # In a directory holding an executable `x`: `x/..`-free relative names would resolve there.
        os.mkdir(os.path.join(self.d, "cwd"))
        os.mkdir(os.path.join(self.d, "cwd", "bin"))
        marker = os.path.join(self.d, "ran")
        x = os.path.join(self.d, "cwd", "bin", "x")
        with open(x, "w") as f:
            f.write("#!/bin/sh\n: > %s\n" % marker)
        os.chmod(x, 0o755)
        with open(LAUNCHER) as f:
            src = f.read()
        p = subprocess.run([sys.executable, "-I", "-S", "-c", src, "bin/x"], cwd=os.path.join(self.d, "cwd"),
                           capture_output=True)
        self.assertEqual(p.returncode, 127)
        self.assertFalse(os.path.exists(marker))

    def test_the_shipped_launcher_keeps_its_contract(self):
        import vm_launch
        calls = []
        # Every exec function is replaced, so no variant can replace this test process.
        for name in ("execve", "execv", "execl", "execvp", "execvpe", "chdir", "umask"):
            real = getattr(vm_launch.os, name)
            setattr(vm_launch.os, name, lambda *a, n=name: calls.append(n))
            self.addCleanup(setattr, vm_launch.os, name, real)
        # A relative or absent argv[0] is refused before anything happens: no chdir, no umask, no exec.
        self.assertEqual(vm_launch.main(["relative"]), 127)
        self.assertEqual(vm_launch.main(["bin/x"]), 127)
        self.assertEqual(vm_launch.main([]), 127)
        self.assertEqual(calls, [])
        vm_launch.main(["/bin/true"])
        self.assertEqual(calls, ["chdir", "umask", "execve"])
        self.assertEqual(vm_launch.environment(os.getuid()),
                         {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": pwd.getpwuid(os.getuid()).pw_dir})

    def test_words_are_quoted_for_the_remote_shell(self):
        rc, out, _ = self.layer().exec("vm-a", ["/bin/echo", "a b; touch %s" % os.path.join(self.d, "x")],
                                       account="op", stage="AGENTS", writes=False)
        self.assertEqual(out, ("a b; touch %s\n" % os.path.join(self.d, "x")).encode())
        self.assertFalse(os.path.exists(os.path.join(self.d, "x")))

    def test_ssh_route_failure_is_target_access_for_exec(self):
        open(os.path.join(self.fake, "down"), "w").close()
        self.refuses("AGENTS.TARGET_ACCESS", self.layer().exec, "vm-a", ["/bin/true"], account="op",
                     stage="AGENTS", rc=2, writes=False)

    def test_ssh_route_failure_on_a_write_call_keeps_its_cause_at_rc_3(self):
        open(os.path.join(self.fake, "down"), "w").close()
        self.refuses("AGENTS.TARGET_ACCESS", self.layer().install_file, "vm-a", b"x", "usr/local/bin/sandy",
                     mode=0o755, stage="AGENTS", rc=3)

    def test_the_route_refuses_what_it_cannot_name(self):
        for kw in (dict(login=None), dict(login="Bad"), dict(known_hosts_for=lambda vm: "rel/kh"),
                   dict(hosts={"vms": [{"name": "vm-a", "ssh_alias": "-oProxyCommand=x"}]})):
            with self.subTest(kw=sorted(kw)):
                self.refuses("AGENTS.TARGET_ACCESS", self.layer(**kw).exec, "vm-a", ["/bin/true"], account="op",
                             stage="AGENTS", writes=False)
        self.refuses("AGENTS.TARGET_ACCESS", self.layer().exec, "vm-z", ["/bin/true"], account="op", stage="AGENTS", writes=False)
        self.assertEqual([l for l in self.logged() if l.startswith("SSH ")], [])

    def test_argv0_must_be_absolute_and_the_account_a_name(self):
        self.refuses("AGENTS.TARGET_ACCESS", self.layer().exec, "vm-a", ["true"], account="op", stage="AGENTS", writes=False)
        self.refuses("AGENTS.TARGET_ACCESS", self.layer().exec, "vm-a", ["/bin/true"], account="a b",
                     stage="AGENTS", writes=False)


class PinnedBootstrapTest(Base):
    def test_a_changed_bootstrap_byte_refuses_before_ssh(self):
        p = os.path.join(self.inst, "vm_bootstrap.py")
        with open(p, "a") as f:
            f.write("#\n")
        self.refuses("AGENTS.PIN", self.layer().install_file, "vm-a", b"x", "usr/local/bin/sandy", mode=0o755,
                     stage="AGENTS")
        self.assertEqual(self.logged(), [])

    def test_a_changed_launcher_byte_refuses_before_ssh(self):
        with open(os.path.join(self.inst, "vm_launch.py"), "a") as f:
            f.write("#\n")
        self.refuses("AGENTS.PIN", self.layer().exec, "vm-a", ["/bin/true"], account="op", stage="AGENTS", writes=False)
        self.assertEqual(self.logged(), [])

    def test_a_manifest_that_is_not_the_locks_refuses(self):
        self.lock["installer"]["sha256"] = "0" * 64
        self.refuses("AGENTS.PIN", self.layer().install_file, "vm-a", b"x", "usr/local/bin/sandy", mode=0o755,
                     stage="AGENTS")
        self.assertEqual(self.logged(), [])


class InstallTest(Base):
    def path(self, rel):
        return os.path.join(self.root, rel)

    def test_changed_then_already_with_owner_and_mode(self):
        L = self.layer()
        self.assertEqual(L.install_file("vm-a", b"#!/bin/sh\n", "usr/local/bin/sandy", mode=0o755, stage="AGENTS"),
                         "CHANGED")
        st = os.lstat(self.path("usr/local/bin/sandy"))
        self.assertEqual((stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid), (0o755,) + ME)
        self.assertEqual(L.install_file("vm-a", b"#!/bin/sh\n", "usr/local/bin/sandy", mode=0o755, stage="AGENTS"),
                         "ALREADY")
        self.assertEqual(L.install_file("vm-a", b"#!/bin/sh\nnew\n", "usr/local/bin/sandy", mode=0o755,
                                        stage="AGENTS"), "CHANGED")
        with open(self.path("usr/local/bin/sandy"), "rb") as f:
            self.assertEqual(f.read(), b"#!/bin/sh\nnew\n")
        self.assertEqual([n for n in os.listdir(self.path("usr/local/bin")) if n.startswith(".a2")], [])

    def test_the_proxy_directory_is_made_and_its_files_placed(self):
        L = self.layer()
        self.assertEqual(L.install_file("vm-a", b"module x\n", "usr/local/bin/proxy/go.mod", mode=0o644,
                                        stage="AGENTS"), "CHANGED")
        st = os.lstat(self.path("usr/local/bin/proxy"))
        self.assertEqual((stat.S_ISDIR(st.st_mode), stat.S_IMODE(st.st_mode)), (True, 0o755))

    def test_the_plugin_is_placed_root_0444_in_a_0755_directory(self):
        L = self.layer()
        self.assertEqual(L.install_file("vm-a", b"plugin\n", "opt/amap-plugin/amap_hop_plugin.py", mode=0o444,
                                        stage="CONFIG"), "CHANGED")
        st = os.lstat(self.path("opt/amap-plugin/amap_hop_plugin.py"))
        self.assertEqual((stat.S_IMODE(st.st_mode), (st.st_uid, st.st_gid)), (0o444, ME))
        self.assertEqual(stat.S_IMODE(os.lstat(self.path("opt/amap-plugin")).st_mode), 0o755)
        self.assertEqual(L.install_file("vm-a", b"plugin\n", "opt/amap-plugin/amap_hop_plugin.py", mode=0o444,
                                        stage="CONFIG"), "ALREADY")
        for path, mode in (("opt/amap-plugin/amap_hop_plugin.py", 0o644), ("opt/amap-plugin/other.py", 0o444),
                           ("opt/amap_hop_plugin.py", 0o444), ("opt/x/amap-plugin/amap_hop_plugin.py", 0o444)):
            with self.subTest(path=path, mode=oct(mode)):
                self.refuses("CONFIG.UNCLASSIFIED", self.layer().install_file, "vm-a", b"x", path, mode=mode,
                             stage="CONFIG", rc=2)

    PLUGIN = "opt/amap-plugin/amap_hop_plugin.py"

    def placed_plugin(self):
        """The plugin placed once through the layer, then its (bytes, inode, mode, mtime) for an unchanged check."""
        self.assertEqual(self.layer().install_file("vm-a", b"plugin\n", self.PLUGIN, mode=0o444, stage="CONFIG"),
                         "CHANGED")
        return self.plugin_state()

    def plugin_state(self):
        st = os.lstat(self.path(self.PLUGIN))
        with open(self.path(self.PLUGIN), "rb") as f:
            return f.read(), st.st_ino, stat.S_IMODE(st.st_mode), st.st_mtime_ns

    def no_temp_left(self):
        self.assertEqual([n for n in os.listdir(self.path("opt/amap-plugin")) if n.startswith(".a2")], [])

    def test_a_plugin_with_other_bytes_is_never_replaced(self):
        before = self.placed_plugin()
        self.refuses("CONFIG.PLACED_DIFFERENT", self.layer().install_file, "vm-a", b"other\n", self.PLUGIN,
                     mode=0o444, stage="CONFIG", rc=2)
        self.assertEqual(self.plugin_state(), before)
        self.no_temp_left()

    def test_a_plugin_with_another_mode_is_never_repaired(self):
        self.placed_plugin()
        os.chmod(self.path(self.PLUGIN), 0o644)
        before = self.plugin_state()
        self.refuses("CONFIG.PLACED_DIFFERENT", self.layer().install_file, "vm-a", b"plugin\n", self.PLUGIN,
                     mode=0o444, stage="CONFIG", rc=2)
        self.assertEqual(self.plugin_state(), before)
        self.assertEqual(before[2], 0o644)
        self.no_temp_left()

    def test_a_different_plugin_after_a_write_exits_3(self):
        before = self.placed_plugin()
        L = self.layer()
        L.install_file("vm-a", b"m\n", "usr/local/bin/proxy/go.mod", mode=0o644, stage="CONFIG")
        self.refuses("CONFIG.PLACED_DIFFERENT", L.install_file, "vm-a", b"other\n", self.PLUGIN, mode=0o444,
                     stage="CONFIG", rc=3)
        self.assertEqual(self.plugin_state(), before)

    def test_a_symlink_at_the_plugin_path_still_refuses_unclassified(self):
        os.makedirs(self.path("opt/amap-plugin"), mode=0o755)
        os.chmod(self.path("opt/amap-plugin"), 0o755)
        os.symlink("/dev/null", self.path(self.PLUGIN))
        self.refuses("CONFIG.UNCLASSIFIED", self.layer().install_file, "vm-a", b"plugin\n", self.PLUGIN,
                     mode=0o444, stage="CONFIG", rc=2)
        self.assertEqual(os.readlink(self.path(self.PLUGIN)), "/dev/null")

    def test_the_sandy_binary_is_still_replaced(self):
        L = self.layer()
        L.install_file("vm-a", b"#!/bin/sh\n", "usr/local/bin/sandy", mode=0o755, stage="AGENTS")
        self.assertEqual(L.install_file("vm-a", b"#!/bin/sh\nnew\n", "usr/local/bin/sandy", mode=0o755,
                                        stage="AGENTS"), "CHANGED")

    def test_the_allowlist(self):
        # proxy/ exists, so a nested path is refused by the allowlist itself, not by a missing directory. Each case
        # is a fresh layer: in the layer that wrote go.mod, every later refusal of that stage is rc 3.
        self.layer().install_file("vm-a", b"m\n", "usr/local/bin/proxy/go.mod", mode=0o644, stage="AGENTS")
        for path, mode in (("usr/local/bin/other", 0o755), ("usr/local/bin/sandy", 0o644),
                           ("usr/local/bin/proxy/main.go", 0o755), ("usr/local/bin/proxy/sub/x.go", 0o644),
                           ("usr/local/bin/proxy/..", 0o644), ("usr/local/bin/proxy/.hidden", 0o644),
                           ("usr/bin/sandy", 0o755), ("../etc/x", 0o644)):
            with self.subTest(path=path, mode=oct(mode)):
                self.refuses("AGENTS.UNCLASSIFIED", self.layer().install_file, "vm-a", b"x", path, mode=mode,
                             stage="AGENTS", rc=2)
        self.assertFalse(os.path.exists(self.path("usr/local/bin/other")))

    def test_a_symlinked_target_or_directory_refuses(self):
        os.symlink(os.path.join(self.d, "elsewhere"), self.path("usr/local/bin/sandy"))
        self.refuses("AGENTS.UNCLASSIFIED", self.layer().install_file, "vm-a", b"x", "usr/local/bin/sandy",
                     mode=0o755, stage="AGENTS", rc=2)
        self.assertFalse(os.path.exists(os.path.join(self.d, "elsewhere")))
        os.unlink(self.path("usr/local/bin/sandy"))
        os.symlink(os.path.join(self.d, "elsedir"), self.path("usr/local/bin/proxy"))
        os.mkdir(os.path.join(self.d, "elsedir"))
        self.refuses("AGENTS.UNCLASSIFIED", self.layer().install_file, "vm-a", b"x", "usr/local/bin/proxy/go.mod",
                     mode=0o644, stage="AGENTS", rc=2)
        self.assertEqual(os.listdir(os.path.join(self.d, "elsedir")), [])

    def test_a_directory_at_the_target_refuses_before_any_write(self):
        os.mkdir(self.path("usr/local/bin/sandy"))
        self.refuses("AGENTS.UNCLASSIFIED", self.layer().install_file, "vm-a", b"x", "usr/local/bin/sandy",
                     mode=0o755, stage="AGENTS", rc=2)

    def test_a_parent_owned_by_another_refuses(self):
        t = self.bootstrap_text().replace("OWNER = %r\n" % (ME,), "OWNER = %r\n" % ((ME[0] + 1, ME[1]),))
        self.write_bootstrap(t)
        self.lock["installer"]["sha256"] = self.manifest_sha()
        self.refuses("AGENTS.UNCLASSIFIED", self.layer().install_file, "vm-a", b"x", "usr/local/bin/sandy",
                     mode=0o755, stage="AGENTS", rc=2)

    def test_a_bootstrap_pin_refusal_is_pin(self):
        t = self.bootstrap_text()
        o = "    mode = int(mode_s, 8)\n"
        self.assertEqual(t.count(o), 1)
        self.write_bootstrap(t.replace(o, "    raise Stop(PIN)\n"))
        self.lock["installer"]["sha256"] = self.manifest_sha()
        self.refuses("AGENTS.PIN", self.layer().install_file, "vm-a", b"x", "usr/local/bin/sandy", mode=0o755,
                     stage="AGENTS")

    def test_a_writable_or_symlinked_parent_refuses(self):
        os.chmod(self.path("usr/local/bin"), 0o775)
        self.refuses("AGENTS.UNCLASSIFIED", self.layer().install_file, "vm-a", b"x", "usr/local/bin/sandy",
                     mode=0o755, stage="AGENTS", rc=2)
        os.chmod(self.path("usr/local/bin"), 0o755)
        os.rename(self.path("usr/local"), self.path("usr/real-local"))
        os.symlink("real-local", self.path("usr/local"))
        self.refuses("AGENTS.UNCLASSIFIED", self.layer().install_file, "vm-a", b"x", "usr/local/bin/sandy",
                     mode=0o755, stage="AGENTS", rc=2)
        self.assertFalse(os.path.exists(self.path("usr/real-local/bin/sandy")))

    def test_a_read_back_mismatch_is_unclassified_3(self):
        # A bootstrap whose read-back always disagrees (its one check inverted): the write happened, so rc 3.
        t = self.bootstrap_text()
        o = "        if not _in_place(dfd, name, sha, mode):\n            raise Stop(READBACK)\n"
        self.assertEqual(t.count(o), 1)
        self.write_bootstrap(t.replace(o, "        if True:\n            raise Stop(READBACK)\n"))
        self.lock["installer"]["sha256"] = self.manifest_sha()
        self.refuses("AGENTS.UNCLASSIFIED", self.layer().install_file, "vm-a", b"x", "usr/local/bin/sandy",
                     mode=0o755, stage="AGENTS", rc=3)

    def test_the_data_must_be_the_sha_the_caller_named(self):
        # The layer sends the sha of the data it sends; a bootstrap that sees other bytes refuses PIN (rc 3).
        res = subprocess.run([sys.executable, "-I", "-S", "-c", self.bootstrap_text(), "install",
                              "usr/local/bin/sandy", "0755", "0" * 64], input=b"x", capture_output=True)
        self.assertEqual(res.returncode, 3)
        self.assertFalse(os.path.exists(self.path("usr/local/bin/sandy")))


class SecretTest(Base):
    def test_the_value_reaches_the_writer_as_a_bytearray(self):
        rc = self.layer().write_secret("vm-a", "api_key", "write", bytearray(b"tok-123"), account="agent",
                                       stage="AGENTS")
        self.assertEqual(rc, 0)
        with open(self.out) as f:
            self.assertEqual(f.read(), "write agent bytearray tok-123\n")
        with open(self.out + ".after", "rb") as f:
            self.assertEqual(f.read(), b"\x00" * 7)
        with open(self.out + ".core") as f:
            self.assertEqual(f.read(), "(0, 0) dumpable=0")

    def test_a_vm_that_neither_answers_nor_exits_cannot_hold_the_run(self):
        open(os.path.join(self.fake, "hang"), "w").close()
        t0 = __import__("time").monotonic()
        self.refuses("AGENTS.UNCLASSIFIED", self.layer(timeout_s=1).write_secret, "vm-a", "api_key", "write",
                     bytearray(b"t"), account="agent", stage="AGENTS", rc=3)
        self.assertLess(__import__("time").monotonic() - t0, 3)

    def test_a_writer_path_outside_the_checkout_refuses(self):
        # A real writer, with the lock's own sha, one directory above the checkout: only the path rule refuses it.
        shutil.copyfile(os.path.join(self.inst, "w", "api.py"), os.path.join(self.d, "outside.py"))
        self.lock["writers"][0]["path"] = "../outside.py"
        self.refuses("AGENTS.PIN", self.layer().write_secret, "vm-a", "api_key", "write", bytearray(b"t"),
                     account="agent", stage="AGENTS")
        self.assertEqual(self.logged(), [])

    def test_the_bootstrap_refuses_bad_words_with_usage(self):
        # stdin carries the real writer and its sha is the argument, so each bad word is the only thing wrong:
        # without the usage check the writer would run and READY would be printed.
        with open(os.path.join(self.inst, "w", "api.py"), "rb") as f:
            writer = f.read()
        sha = hashlib.sha256(writer).hexdigest()
        for words in (["bogus", "write", sha, "agent"], ["api_key", "bogus", sha, "agent"],
                      ["api_key", "write", sha[:-1], "agent"], ["api_key", "write", sha, "a b"]):
            with self.subTest(words=words):
                p = subprocess.run([sys.executable, "-I", "-S", "-c", self.bootstrap_text(), "secret"] + words,
                                   input=len(writer).to_bytes(8, "big") + writer + b"v", capture_output=True)
                self.assertEqual((p.returncode, p.stdout), (2, b""))
        self.assertFalse(os.path.exists(self.out))

    def test_finish_and_restore_send_no_value(self):
        for mode in ("finish", "restore"):
            with self.subTest(mode=mode):
                self.layer().write_secret("vm-a", "api_key", mode, None, account="agent", stage="AGENTS")
        with open(self.out) as f:
            self.assertEqual(f.read(), "finish agent NoneType \nrestore agent NoneType \n")

    def test_a_writer_that_differs_from_the_lock_sends_nothing(self):
        with open(os.path.join(self.inst, "w", "api.py"), "a") as f:
            f.write("#\n")
        self.refuses("AGENTS.PIN", self.layer().write_secret, "vm-a", "api_key", "write", bytearray(b"tok"),
                     account="agent", stage="AGENTS")
        self.assertEqual(self.logged(), [])
        self.assertFalse(os.path.exists(self.out))

    def test_the_bootstrap_refuses_a_writer_whose_sha_is_not_the_argument_before_any_value(self):
        # Run the bootstrap directly: a wrong sha argument, then a value on stdin. No READY, rc 3, and the value
        # never reached a writer.
        with open(os.path.join(self.inst, "w", "api.py"), "rb") as f:
            writer = f.read()
        p = subprocess.run([sys.executable, "-I", "-S", "-c", self.bootstrap_text(), "secret", "api_key", "write",
                            "0" * 64, "agent"], input=len(writer).to_bytes(8, "big") + writer + b"tok",
                           capture_output=True)
        self.assertEqual((p.returncode, p.stdout), (3, b""))
        self.assertFalse(os.path.exists(self.out))

    def test_a_missing_writer_row_refuses_lock(self):
        self.lock["writers"] = []
        self.refuses("AGENTS.LOCK", self.layer().write_secret, "vm-a", "api_key", "write", bytearray(b"t"),
                     account="agent", stage="AGENTS")

    def test_no_value_crosses_the_route_unless_the_bootstrap_said_ready(self):
        # A bootstrap that cannot set the core limit exits 7 before READY. The fake ssh records every byte the layer
        # sent: the writer's bytes are there, the value is not.
        t = self.bootstrap_text()
        o = "        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))\n"
        self.write_bootstrap(t.replace(o, "        raise OSError('no')\n"))
        self.lock["installer"]["sha256"] = self.manifest_sha()
        open(os.path.join(self.fake, "tee"), "w").close()
        self.refuses("AGENTS.UNCLASSIFIED", self.layer().write_secret, "vm-a", "api_key", "write",
                     bytearray(b"VALUE-NEVER-SENT"), account="agent", stage="AGENTS", rc=2)
        with open(os.path.join(self.fake, "stdin.bytes"), "rb") as f:
            sent = f.read()
        self.assertNotIn(b"VALUE-NEVER-SENT", sent)
        self.assertIn(b"def main(mode, value, account)", sent)

    def test_a_session_that_never_says_ready_reads_to_eof_and_receives_no_value(self):
        """The session reads every byte until the layer closes stdin, so this does not depend on timing: the
        writer's bytes arrive, the value never does, and the refusal is the bootstrap's own (rc 7, before READY)."""
        open(os.path.join(self.fake, "notready"), "w").close()
        self.refuses("AGENTS.UNCLASSIFIED", self.layer().write_secret, "vm-a", "api_key", "write",
                     bytearray(b"VALUE-NEVER-SENT"), account="agent", stage="AGENTS", rc=2)
        with open(os.path.join(self.fake, "drained.bytes"), "rb") as f:
            sent = f.read()
        self.assertNotIn(b"VALUE-NEVER-SENT", sent)
        self.assertIn(b"def main(mode, value, account)", sent)

    def test_the_value_does_cross_after_ready(self):
        open(os.path.join(self.fake, "tee"), "w").close()
        self.layer().write_secret("vm-a", "api_key", "write", bytearray(b"VALUE-SENT"), account="agent",
                                  stage="AGENTS")
        with open(os.path.join(self.fake, "stdin.bytes"), "rb") as f:
            self.assertIn(b"VALUE-SENT", f.read())

    def test_the_core_limit_failure_reads_no_stdin(self):
        t = self.bootstrap_text()
        o = "        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))\n"
        self.assertEqual(t.count(o), 1)
        bad = t.replace(o, "        raise OSError('no')\n")
        p = subprocess.run([sys.executable, "-I", "-S", "-c", bad, "secret", "api_key", "write", "0" * 64, "agent"],
                           input=b"", capture_output=True)
        self.assertEqual(p.returncode, 7)


class WriteRuleTest(Base):
    """Once a stage has written through the layer, every refusal of that stage is UNCLASSIFIED rc 3 (3.4, 4.2)."""

    def down(self):
        open(os.path.join(self.fake, "down"), "w").close()

    def test_a_route_failure_after_a_write_is_rc_3(self):
        L = self.layer()
        self.assertEqual(L.install_file("vm-a", b"s\n", "usr/local/bin/sandy", mode=0o755, stage="AGENTS"), "CHANGED")
        self.down()
        self.refuses("AGENTS.TARGET_ACCESS", L.exec, "vm-a", ["/bin/true"], account="op", stage="AGENTS",
                     writes=False, rc=3)

    def test_a_writing_exec_that_times_out_is_rc_3(self):
        open(os.path.join(self.fake, "hang"), "w").close()
        self.refuses("AGENTS.TARGET_ACCESS", self.layer(timeout_s=1).exec, "vm-a", ["/bin/true"], account="op",
                     stage="AGENTS", writes=True, rc=3)

    def test_a_read_only_exec_that_times_out_before_any_write_is_target_access(self):
        open(os.path.join(self.fake, "hang"), "w").close()
        self.refuses("AGENTS.TARGET_ACCESS", self.layer(timeout_s=1).exec, "vm-a", ["/bin/true"], account="op",
                     stage="AGENTS", writes=False, rc=2)

    def test_a_writing_exec_marks_its_stage_and_only_its_stage(self):
        L = self.layer()
        L.exec("vm-a", ["/bin/true"], account="op", stage="AGENTS", writes=True)
        self.down()
        self.refuses("AGENTS.TARGET_ACCESS", L.exec, "vm-a", ["/bin/true"], account="op", stage="AGENTS",
                     writes=False, rc=3)
        self.refuses("VERIFY.TARGET_ACCESS", L.exec, "vm-a", ["/bin/true"], account="op", stage="VERIFY",
                     writes=False, rc=2)

    def test_a_before_write_bootstrap_code_after_a_write_is_rc_3(self):
        L = self.layer()
        L.install_file("vm-a", b"s\n", "usr/local/bin/sandy", mode=0o755, stage="AGENTS")
        self.refuses("AGENTS.UNCLASSIFIED", L.install_file, "vm-a", b"x", "usr/local/bin/other", mode=0o755,
                     stage="AGENTS", rc=3)

    def test_writes_is_required_and_a_bool(self):
        with self.assertRaises(TypeError):
            self.layer().exec("vm-a", ["/bin/true"], account="op", stage="AGENTS")
        self.refuses("AGENTS.UNCLASSIFIED", self.layer().exec, "vm-a", ["/bin/true"], account="op", stage="AGENTS",
                     writes="yes", rc=2)
        self.assertEqual(self.logged(), [])

    def test_a_word_with_nul_or_not_a_string_refuses_before_ssh(self):
        for argv in (["/bin/echo", "a\x00b"], ["/bin/echo", 7], ["/bin/echo", b"x"]):
            with self.subTest(argv=argv):
                self.refuses("AGENTS.UNCLASSIFIED", self.layer().exec, "vm-a", argv, account="op", stage="AGENTS",
                             writes=False, rc=2)
        self.assertEqual(self.logged(), [])

    def test_a_known_hosts_path_ssh_would_split_or_expand_refuses(self):
        for kh in (self.kh + " /root/.ssh/known_hosts", self.kh + ",x", "/tmp/%h", "~/kh", "/a\tb"):
            with self.subTest(kh=kh):
                self.refuses("AGENTS.TARGET_ACCESS", self.layer(known_hosts_for=lambda vm, k=kh: k).exec, "vm-a",
                             ["/bin/true"], account="op", stage="AGENTS", writes=False)
        self.assertEqual(self.logged(), [])

    def test_the_command_runs_in_home_with_umask_022(self):
        rc, out, _ = self.layer().exec("vm-a", ["/bin/sh", "-c", "umask; pwd"], account="agent", stage="AGENTS",
                                       writes=False)
        self.assertEqual(out.decode().splitlines(), ["0022", pwd.getpwuid(os.getuid()).pw_dir])

    def test_an_absent_usr_local_bin_is_never_created(self):
        shutil.rmtree(os.path.join(self.root, "usr", "local", "bin"))
        self.refuses("AGENTS.UNCLASSIFIED", self.layer().install_file, "vm-a", b"s\n", "usr/local/bin/sandy",
                     mode=0o755, stage="AGENTS", rc=2)
        self.assertFalse(os.path.exists(os.path.join(self.root, "usr", "local", "bin")))


class HopIntakesLayerTest(Base):
    """The layer's call of vm_bootstrap's hopintakes (W7-HOPINTAKES, option R): the op's own rules are
    test_vm_hopintakes'; here, the route, the argument checks before ssh, and each rc's meaning under the write
    rule. The op is stood in by a bootstrap whose hopintakes returns a fixed code and logs its argv."""

    HOOK = '        if len(argv) == 4 and argv[0] == "hopintakes":\n            return hopintakes(argv[1], argv[2], argv[3])\n'

    def stub(self, rc):
        t = self.bootstrap_text()
        assert t.count(self.HOOK) == 1
        seen = os.path.join(self.d, "hop.argv")
        self.write_bootstrap(t.replace(self.HOOK, '        if len(argv) == 4 and argv[0] == "hopintakes":\n'
                                       '            open(%r, "w").write(" ".join(argv))\n'
                                       '            return %d\n' % (seen, rc)))
        self.lock["installer"]["sha256"] = self.manifest_sha()
        return seen

    def test_changed_and_already_and_the_argv(self):
        seen = self.stub(0)
        L = self.layer()
        self.assertEqual(L.hop_intakes("vm-a", "/home/agent/.amap-hop", "relay", "hop", stage="CONFIG"), "CHANGED")
        with open(seen) as f:
            self.assertEqual(f.read(), "hopintakes /home/agent/.amap-hop relay hop")
        self.stub(10)
        self.assertEqual(L.hop_intakes("vm-a", "/home/agent/.amap-hop", "relay", "hop", stage="CONFIG"), "ALREADY")

    def test_not_allowed_is_owner_rc_2_on_a_fresh_stage_and_3_after_a_write(self):
        self.stub(4)
        self.refuses("CONFIG.OWNER", self.layer().hop_intakes, "vm-a", "/home/agent/.amap-hop", "relay", "hop",
                     stage="CONFIG", rc=2)
        L = self.layer()
        L.exec("vm-a", ["/bin/true"], account="agent", stage="CONFIG", writes=True)
        self.refuses("CONFIG.OWNER", L.hop_intakes, "vm-a", "/home/agent/.amap-hop", "relay", "hop",
                     stage="CONFIG", rc=3)

    def test_other_codes_go_through_the_bootstrap_rule(self):
        self.stub(3)
        self.refuses("CONFIG.PIN", self.layer().hop_intakes, "vm-a", "/home/agent/.amap-hop", "relay", "hop",
                     stage="CONFIG", rc=2)
        self.stub(5)
        self.refuses("CONFIG.UNCLASSIFIED", self.layer().hop_intakes, "vm-a", "/home/agent/.amap-hop", "relay",
                     "hop", stage="CONFIG", rc=3)

    def test_bad_arguments_refuse_before_ssh(self):
        L = self.layer()
        for args, cause in ((("relative", "relay", "hop"), "CONFIG.OWNER"),
                            (("/home/agent/../x", "relay", "hop"), "CONFIG.OWNER"),
                            (("/home/agent/.amap-hop", "Relay", "hop"), "CONFIG.TARGET_ACCESS"),
                            (("/home/agent/.amap-hop", "relay", "h op"), "CONFIG.TARGET_ACCESS")):
            with self.subTest(args=args):
                self.refuses(cause, L.hop_intakes, "vm-a", *args, stage="CONFIG", rc=2)
        self.assertEqual(self.logged(), [])

    def test_the_real_op_refuses_a_root_this_account_owns_as_the_relay(self):
        """The shipped op, through the fake sudo, as this uid: the relay account is this account, which owns the
        hop root, so it refuses OWNER and makes nothing."""
        hop = os.path.join(self.root, "home", "agent", ".amap-hop")
        os.makedirs(hop)
        for p in ("home", "home/agent"):
            os.chmod(os.path.join(self.root, p), 0o755)
        os.chmod(hop, 0o2750)
        me = pwd.getpwuid(ME[0]).pw_name
        import grp
        group = grp.getgrgid(ME[1]).gr_name
        self.refuses("CONFIG.OWNER", self.layer().hop_intakes, "vm-a", "/home/agent/.amap-hop", me, group,
                     stage="CONFIG", rc=2)
        self.assertEqual(os.listdir(hop), [])


class PinAfterWriteTest(Base):
    """The contract owner's ruling (W7): once a stage has written through the layer, every refusal keeps its cause and
    exits 3, PIN and LOCK included; a stage that has written nothing exits 2 with the same cause."""

    def written(self):
        L = self.layer()
        self.assertEqual(L.install_file("vm-a", b"s\n", "usr/local/bin/sandy", mode=0o755, stage="AGENTS"), "CHANGED")
        return L

    def families(self):
        """Each PIN or LOCK path, as a callable on a layer for a stage."""
        def launcher(L, stage):
            L.exec("vm-a", ["/bin/true"], account="op", stage=stage, writes=False)
        def unpinned_use(L, stage):
            L.write_secret("vm-a", "hub_login", "finish", None, account="agent", stage=stage)
        def component(L, stage):
            L.component_file("sandy", "sandy", stage=stage)
        return (("launcher pin", launcher, "PIN"), ("writer not pinned", unpinned_use, "LOCK"),
                ("component not fetched", component, "PIN"))

    def test_after_a_write_each_pin_and_lock_family_is_rc_3_and_a_fresh_stage_keeps_its_cause(self):
        L = self.written()
        with open(os.path.join(self.inst, "vm_launch.py"), "a") as f:
            f.write("#\n")
        for label, call, cause in self.families():
            with self.subTest(family=label):
                self.refuses("AGENTS." + cause, call, L, "AGENTS", rc=3)
                self.refuses("VERIFY." + cause, call, L, "VERIFY", rc=2)

    def test_a_bootstrap_pin_after_a_write_is_rc_3(self):
        L = self.written()
        t = self.bootstrap_text()
        self.write_bootstrap(t.replace("    mode = int(mode_s, 8)\n", "    raise Stop(PIN)\n"))
        self.lock["installer"]["sha256"] = self.manifest_sha()
        self.refuses("AGENTS.PIN", L.install_file, "vm-a", b"x", "usr/local/bin/sandy", mode=0o755,
                     stage="AGENTS", rc=3)
        self.refuses("VERIFY.PIN", L.install_file, "vm-a", b"x", "usr/local/bin/sandy", mode=0o755, stage="VERIFY")

    def test_a_writing_exec_as_the_agent_account_marks_the_stage(self):
        L = self.layer()
        L.exec("vm-a", ["/bin/true"], account="agent", stage="AGENTS", writes=True)
        open(os.path.join(self.fake, "down"), "w").close()
        self.refuses("AGENTS.TARGET_ACCESS", L.exec, "vm-a", ["/bin/true"], account="agent", stage="AGENTS",
                     writes=False, rc=3)


class StageCauseRuleTest(Base):
    """W7's rule for every stage cause: exit 2 before the stage's first write, 3 after it, the cause name kept. The
    site's unfilled slots follow it through the bound layer; the multi-VM case: VM 1 written, then refusals on VM 2."""

    def test_refusal_takes_rc_3_for_a_writing_stages_cause_only(self):
        for cause in ("AGENTS.PIN", "AGENTS.LOCK", "AGENTS.TARGET_ACCESS", "CONFIG.HOSTS", "KEYS.UNCLASSIFIED"):
            with self.subTest(cause=cause):
                self.assertEqual(Refusal(cause, rc=3).rc, 3)
                self.assertEqual(Refusal(cause).rc, 2)
        for cause in ("PREFLIGHT.PIN", "PREFLIGHT.LOCK", "RUNNER.ARGS", "CREDENTIALS.FORM"):
            with self.subTest(cause=cause):
                with self.assertRaises(ValueError):
                    Refusal(cause, rc=3)

    def test_wrote_is_per_stage(self):
        L = self.layer()
        self.assertFalse(L.wrote("AGENTS"))
        L.install_file("vm-a", b"s\n", "usr/local/bin/sandy", mode=0o755, stage="AGENTS")
        self.assertTrue(L.wrote("AGENTS"))
        self.assertFalse(L.wrote("VERIFY"))

    def test_on_a_second_vm_after_a_first_wrote_every_refusal_keeps_its_cause_at_rc_3(self):
        from a2_site import Site
        self.hosts = {"vms": [{"name": "vm-a", "ssh_alias": "vm-a-r", "agent_account": "agent"},
                              {"name": "vm-b", "ssh_alias": "vm-b-r", "agent_account": "agent"}]}
        s, L = Site(), self.layer()
        a2_vm.bind(s, L)
        self.assertEqual(L.install_file("vm-a", b"s\n", "usr/local/bin/sandy", mode=0o755, stage="AGENTS"), "CHANGED")
        open(os.path.join(self.fake, "down"), "w").close()
        # A layer refusal on VM 2, a site slot's refusal, and a stage's own named cause on VM 2.
        self.refuses("AGENTS.TARGET_ACCESS", L.exec, "vm-b", ["/bin/true"], account="op", stage="AGENTS",
                     writes=False, rc=3)
        self.refuses("AGENTS.TARGET_ACCESS", s.registry_import, "vm-b", "s", "/ws/s", stage="AGENTS", rc=3)
        self.refuses("AGENTS.HOSTS", s.vm_agent_account, "vm-b", stage="AGENTS", rc=3)
        named = Refusal("AGENTS.HOSTS", "vm-b", rc=3 if L.wrote("AGENTS") else None)
        self.assertEqual((named.cause, named.rc), ("AGENTS.HOSTS", 3))
        # A fresh stage: the same refusals exit 2.
        self.refuses("VERIFY.TARGET_ACCESS", s.registry_import, "vm-b", "s", "/ws/s", stage="VERIFY", rc=2)
        self.refuses("VERIFY.HOSTS", s.vm_agent_account, "vm-b", stage="VERIFY", rc=2)

    def test_an_unbound_sites_slots_exit_2(self):
        from a2_site import Site
        s = Site()
        self.assertIsNone(s.vm_layer)
        self.refuses("AGENTS.TARGET_ACCESS", s.registry_read, "vm-a", "s", stage="AGENTS", rc=2)


class SessionDeadlineTest(Base):
    """One deadline for the whole secret session: two slow steps, each under timeout_s and over it together,
    refuse at about timeout_s, not later."""

    def check(self, flag, value):
        open(os.path.join(self.fake, flag), "w").close()
        t0 = time.monotonic()
        self.refuses("AGENTS.UNCLASSIFIED", self.layer(timeout_s=1).write_secret, "vm-a", "api_key",
                     "write" if value else "finish", value, account="agent", stage="AGENTS", rc=3)
        self.assertLess(time.monotonic() - t0, 1.3)

    def test_slow_ready_then_slow_status(self):
        self.check("slowstatus", None)

    def test_slow_ready_then_slow_exit(self):
        self.check("slowexit", None)

    def test_slow_ready_then_a_value_read_late(self):
        self.check("slowvalue", bytearray(b"v" * (64 << 10)))

    def test_slow_ready_then_stdout_closed_and_a_slow_exit(self):
        """READY and RC at 0.7 s, stdout closed (so the EOF read returns at once), the exit at 1.4 s: only the exit
        wait's share of the one deadline refuses it at about 1 s."""
        self.check("closeout", None)

    def test_output_after_the_rc_line_is_a_bootstrap_failure(self):
        """READY, then the RC line, then more output, all well inside the deadline: only the EOF check refuses."""
        open(os.path.join(self.fake, "afterrc"), "w").close()
        t0 = time.monotonic()
        self.refuses("AGENTS.UNCLASSIFIED", self.layer(timeout_s=5).write_secret, "vm-a", "api_key", "finish", None,
                     account="agent", stage="AGENTS", rc=3)
        self.assertLess(time.monotonic() - t0, 2)


class SecretPairingTest(Base):
    """The mode and the value are checked before ssh starts: a refusal sends nothing at all."""

    def sent(self):
        try:
            with open(os.path.join(self.fake, "stdin.bytes"), "rb") as f:
                return f.read()
        except FileNotFoundError:
            return b""

    def test_a_value_with_finish_or_restore_is_never_sent(self):
        open(os.path.join(self.fake, "tee"), "w").close()
        for mode in ("finish", "restore"):
            with self.subTest(mode=mode):
                self.refuses("AGENTS.UNCLASSIFIED", self.layer().write_secret, "vm-a", "api_key", mode,
                             bytearray(b"SEKRIT"), account="agent", stage="AGENTS", rc=2)
        self.assertNotIn(b"SEKRIT", self.sent())
        self.assertEqual(self.logged(), [])

    def test_write_and_rotate_need_a_non_empty_bytearray(self):
        for mode in ("write", "rotate"):
            for value in (None, "str", b"bytes", bytearray()):
                with self.subTest(mode=mode, value=value):
                    self.refuses("AGENTS.UNCLASSIFIED", self.layer().write_secret, "vm-a", "api_key", mode, value,
                                 account="agent", stage="AGENTS", rc=2)
        self.refuses("AGENTS.UNCLASSIFIED", self.layer().write_secret, "vm-a", "api_key", "bogus", None,
                     account="agent", stage="AGENTS", rc=2)
        self.refuses("AGENTS.TARGET_ACCESS", self.layer().write_secret, "vm-a", "api_key", "write",
                     bytearray(b"v"), account="a b", stage="AGENTS")
        self.assertEqual(self.logged(), [])
        self.assertFalse(os.path.exists(self.out))

    def repin_writer(self, body):
        p = os.path.join(self.inst, "w", "api.py")
        with open(p, "w") as f:
            f.write(body)
        self.lock["writers"][0]["sha256"] = self.sha_file(p)

    def test_the_writers_codes_come_back_and_a_bootstrap_failure_after_ready_is_rc_3(self):
        self.repin_writer("def main(mode, value, account):\n    return 4\n")
        self.assertEqual(self.layer().write_secret("vm-a", "api_key", "finish", None, account="agent",
                                                   stage="AGENTS"), 4)
        self.repin_writer("def main(mode, value, account):\n    raise ValueError('x')\n")
        self.refuses("AGENTS.UNCLASSIFIED", self.layer().write_secret, "vm-a", "api_key", "finish", None,
                     account="agent", stage="AGENTS", rc=3)

    def test_a_vm_that_says_ready_then_stops_reading_cannot_hold_the_run(self):
        """READY, then no read: the value (at the bound, so it fills the pipe) cannot be written. The one deadline
        expires, ssh is killed and reaped, and the refusal is rc 3 because part of the value may have crossed."""
        open(os.path.join(self.fake, "readyhang"), "w").close()
        t0 = time.monotonic()
        self.refuses("AGENTS.UNCLASSIFIED", self.layer(timeout_s=1).write_secret, "vm-a", "api_key", "write",
                     bytearray(b"v" * (64 << 10)), account="agent", stage="AGENTS", rc=3)
        self.assertLess(time.monotonic() - t0, 3)

    def test_a_value_over_the_bound_is_a_bootstrap_failure_after_ready(self):
        self.refuses("AGENTS.UNCLASSIFIED", self.layer().write_secret, "vm-a", "api_key", "write",
                     bytearray(b"v" * ((64 << 10) + 1)), account="agent", stage="AGENTS", rc=3)
        self.assertFalse(os.path.exists(self.out))


class ComponentFileTest(Base):
    def setUp(self):
        super().setUp()
        self.bare = os.path.join(self.d, "c.git")
        work = os.path.join(self.d, "work")
        a2fix.git(self.d, "init", "-q", "--bare", self.bare)
        a2fix.git(self.d, "init", "-q", work)
        with open(os.path.join(work, "sandy"), "wb") as f:
            f.write(b"SANDY\n")
        with open(os.path.join(work, "extra"), "wb") as f:
            f.write(b"EXTRA\n")
        a2fix.git(work, "add", "sandy", "extra")
        a2fix.git(work, "commit", "-q", "-m", "x")
        self.commit = a2fix.git(work, "rev-parse", "HEAD")
        a2fix.git(work, "push", "-q", self.bare, "HEAD:refs/heads/main")
        import a2_git
        self.gitobj = a2_git.Git(a2_git.env_for(self.d), protocols=("file",))
        self.lock["components"] = [{"name": "sandy", "repo": "https://git.example.org/x", "commit": self.commit,
                                    "tag": "alpha2-rc1"}]
        self.lock["files"] = [{"path": "sandy", "component": "sandy",
                               "sha256": hashlib.sha256(b"SANDY\n").hexdigest()}]

    def L(self):
        return self.layer(git=self.gitobj, fetched={"c-sandy": self.bare})

    def test_the_pinned_bytes(self):
        self.assertEqual(self.L().component_file("sandy", "sandy", stage="AGENTS"), b"SANDY\n")

    def test_refusals(self):
        self.refuses("AGENTS.PIN", self.L().component_file, "sandy", "proxy/go.mod", stage="AGENTS")
        # In the commit, but no files[] row: refused, never read.
        self.refuses("AGENTS.PIN", self.L().component_file, "sandy", "extra", stage="AGENTS")
        self.refuses("AGENTS.PIN", self.layer(git=self.gitobj).component_file, "sandy", "sandy", stage="AGENTS")
        self.lock["files"][0]["sha256"] = "0" * 64
        self.refuses("AGENTS.PIN", self.L().component_file, "sandy", "sandy", stage="AGENTS")


class ComponentTreeTest(Base):
    """component_tree (W7-R1-R2-DESIGN, R1): a pinned prefix's regular files, from S0's fetched repository at the
    lock's commit, each blob re-hashed against its object id."""

    def setUp(self):
        super().setUp()
        self.bare = os.path.join(self.d, "t.git")
        self.work = os.path.join(self.d, "twork")
        a2fix.git(self.d, "init", "-q", "--bare", self.bare)
        a2fix.git(self.d, "init", "-q", self.work)
        os.makedirs(os.path.join(self.work, "router", "sub"))
        for rel, data in (("router/a.py", b"A\n"), ("router/sub/b.py", b"B\n"), ("other/c", b"C\n"),
                          ("routerx/d", b"D\n")):
            os.makedirs(os.path.dirname(os.path.join(self.work, rel)), exist_ok=True)
            with open(os.path.join(self.work, rel), "wb") as f:
                f.write(data)
        os.chmod(os.path.join(self.work, "router", "sub", "b.py"), 0o755)
        a2fix.git(self.work, "add", "-A")
        a2fix.git(self.work, "commit", "-q", "-m", "x")
        self.push()
        import a2_git
        self.gitobj = a2_git.Git(a2_git.env_for(self.d), protocols=("file",))

    def push(self):
        self.commit = a2fix.git(self.work, "rev-parse", "HEAD")
        a2fix.git(self.work, "push", "-q", "-f", self.bare, "HEAD:refs/heads/main")
        self.lock["components"] = [{"name": "rl", "repo": "https://git.example.org/x", "commit": self.commit,
                                    "tag": "alpha2-rc1"}]

    def L(self):
        return self.layer(git=self.gitobj, fetched={"c-rl": self.bare})

    def test_the_prefix_files_with_modes_and_the_tree_id(self):
        tree, files = self.L().component_tree("rl", "router", stage="CONFIG")
        self.assertEqual(files, [("a.py", 0o644, b"A\n"), ("sub/b.py", 0o755, b"B\n")])
        self.assertEqual(tree, a2fix.git(self.work, "rev-parse", self.commit + ":router"))

    def test_refusals(self):
        for prefix in ("router/", "/router", "", "router/../other", "nope", "router/a.py", "./router"):
            with self.subTest(prefix=prefix):
                self.refuses("CONFIG.PIN", self.L().component_tree, "rl", prefix, stage="CONFIG")
        self.refuses("CONFIG.PIN", self.L().component_tree, "nope", "router", stage="CONFIG")
        self.refuses("CONFIG.PIN", self.layer(git=self.gitobj).component_tree, "rl", "router", stage="CONFIG")

    def test_a_symlink_in_the_tree_refuses(self):
        os.symlink("a.py", os.path.join(self.work, "router", "link"))
        a2fix.git(self.work, "add", "-A")
        a2fix.git(self.work, "commit", "-q", "-m", "y")
        self.push()
        self.refuses("CONFIG.PIN", self.L().component_tree, "rl", "router", stage="CONFIG")

    def test_a_blob_that_differs_from_its_id_refuses(self):
        L = self.L()
        real = self.gitobj.blob_at
        self.gitobj.blob_at = lambda bare, c, path: real(bare, c, path) + (b"x" if path.endswith("a.py") else b"")
        self.refuses("CONFIG.PIN", L.component_tree, "rl", "router", stage="CONFIG")


class SiteSlotTest(Base):
    """The site's VM slots refuse until filled, bind fills the layer's four and the agents' two registry slots (and
    not the account slot), and the logical id is read back and checked, never taken from an import's answer."""

    CALLS = (("vm_exec", ("vm-a", ["/bin/true"]), dict(account="op"), "TARGET_ACCESS"),
             ("vm_install_file", ("vm-a", b"x", "usr/local/bin/sandy"), dict(mode=0o755), "TARGET_ACCESS"),
             ("vm_write_secret", ("vm-a", "api_key", "write", bytearray(b"v")), dict(account="op"), "TARGET_ACCESS"),
             ("component_file", ("sandy", "sandy"), {}, "PIN"),
             ("registry_import", ("vm-a", "s", "k"), {}, "TARGET_ACCESS"),
             ("registry_read", ("vm-a", "s"), {}, "TARGET_ACCESS"),
             ("vm_agent_account", ("vm-a",), {}, "HOSTS"))

    def test_every_slot_refuses_until_filled(self):
        from a2_site import Site
        s = Site()
        for name, a, kw, suffix in self.CALLS:
            with self.subTest(slot=name):
                self.refuses("AGENTS." + suffix, getattr(s, name), *a, stage="AGENTS", **kw)
        self.assertEqual(self.logged(), [])

    def test_bind_fills_the_layers_four_and_the_registry_slots(self):
        import a2_agent_registry
        from a2_site import Site
        s, L = Site(), self.layer()
        before = s.vm_agent_account
        a2_vm.bind(s, L)
        self.assertEqual((s.vm_exec, s.vm_install_file, s.vm_write_secret, s.component_file),
                         (L.exec, L.install_file, L.write_secret, L.component_file))
        for name in ("registry_import", "registry_read"):
            slot = getattr(s, name)
            self.assertIsInstance(slot.__self__, a2_agent_registry.AgentRegistry)
            self.assertIs(slot.__self__.layer, L)
        self.assertIs(s.registry_import.__self__, s.registry_read.__self__)
        self.assertIs(s.vm_agent_account, before)

    def test_the_logical_id_is_32_lower_hex_or_a_refusal(self):
        from a2_site import Site
        s = Site()
        self.refuses("AGENTS.TARGET_ACCESS", a2_vm.logical_id, s, "vm-a", "s", "AGENTS")
        for bad in ("UNOBSERVED", None, "", "A" * 32, "0" * 31, "0" * 33, "0" * 32 + "\n", "0" * 32, 0, b"0" * 32):
            with self.subTest(value=bad):
                s.registry_read = lambda vm, slug, *, stage, v=bad: v
                self.refuses("AGENTS.UNCLASSIFIED", a2_vm.logical_id, s, "vm-a", "s", "AGENTS", rc=3)
        s.registry_read = lambda vm, slug, *, stage: "0123456789abcdef" * 2
        self.assertEqual(a2_vm.logical_id(s, "vm-a", "s", "AGENTS"), "0123456789abcdef" * 2)


class NeverReplacedBootstrapTest(unittest.TestCase):
    """The bootstrap module itself, imported with ROOT at a temporary VM root and OWNER this uid. Two cases the ssh
    route cannot stage as a non-root user: a plugin whose owner differs, and a plugin that appears between the
    presence check and the placement. Directory checks are kept except where a case says otherwise."""

    def setUp(self):
        import importlib.util
        d = tempfile.mkdtemp(prefix="a2boot-")
        self.addCleanup(shutil.rmtree, d, True)
        self.root = os.path.join(d, "vm")
        os.makedirs(os.path.join(self.root, "opt", "amap-plugin"))
        for p in ("", "opt", "opt/amap-plugin"):
            os.chmod(os.path.join(self.root, p), 0o755)
        spec = importlib.util.spec_from_file_location("vm_bootstrap_t", SHIPPED)
        self.b = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.b)
        self.b.ROOT, self.b.OWNER = self.root, ME
        self.target = os.path.join(self.root, self.b.PLUGIN)

    def install(self, data):
        return self.b.install(self.b.PLUGIN, "0444", hashlib.sha256(data).hexdigest(), data)

    def state(self):
        st = os.lstat(self.target)
        with open(self.target, "rb") as f:
            return f.read(), st.st_ino, stat.S_IMODE(st.st_mode), st.st_mtime_ns

    def test_a_plugin_whose_owner_differs_is_never_replaced(self):
        self.assertEqual(self.install(b"plugin\n"), self.b.OK)
        before = self.state()
        # The file's owner is this uid; the wanted owner becomes another uid. Directories are checked against the
        # same OWNER, so their check is relaxed for this case only: the file's owner is what is under test.
        self.b.OWNER = (ME[0] + 1, ME[1])
        self.b._checked_dir = lambda fd: None
        with self.assertRaises(self.b.Stop) as cm:
            self.install(b"plugin\n")
        self.assertEqual(cm.exception.args[0], self.b.DIFFERENT)
        self.assertEqual(self.state(), before)

    def test_a_plugin_that_appears_after_the_check_is_never_replaced(self):
        with open(self.target, "wb") as f:
            f.write(b"theirs\n")
        before = self.state()
        self.b._present = lambda dfd, name: False
        with self.assertRaises(self.b.Stop) as cm:
            self.install(b"plugin\n")
        self.assertEqual(cm.exception.args[0], self.b.DIFFERENT)
        self.assertEqual(self.state(), before)
        self.assertEqual([n for n in os.listdir(os.path.dirname(self.target)) if n.startswith(".a2")], [])

    def test_an_absent_plugin_is_placed_and_read_back(self):
        self.assertEqual(self.install(b"plugin\n"), self.b.OK)
        self.assertEqual(self.state()[0::2], (b"plugin\n", 0o444))
        self.assertEqual(self.install(b"plugin\n"), self.b.ALREADY)
        self.assertEqual([n for n in os.listdir(os.path.dirname(self.target)) if n.startswith(".a2")], [])


if __name__ == "__main__":
    unittest.main()
