"""The install-time check of what root will run: discovery (half A) as an
unprivileged identity with no terminal, judging (half B) as root over its
output read as data, the two scripts written by root before anything vetted
runs and checked against their digests in the one invocation that runs them.
A test cannot be root, so it keeps its own uid (the identity drop replaced,
ownership mapped to its user where a row needs a clean finding) and stands a
shell function in for sudo, which closes inherited fds above 2 as sudo's
closefrom does. The rows that need a real uid change are one opt-in class."""

import dataclasses
import getpass
import os
import pty
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

import host_steps as hs
import partition_job as pj
import partition_setup as ps

P = ps.PartitionSpec(evidence_dir="/opt/ex/ev", scratch_dir="/opt/ex/scratch", weekday=2, hour=4,
                     exec_root="/opt/ex/exec", tools={"python3": "/usr/bin/python3", "docker": "/bin/sh"})
#: sudo, as a test can have it: the command run with fds 3-9 closed (sudo's closefrom).
SUDO = 'sudo() { ( for fd in 3 4 5 6 7 8 9; do eval "exec $fd>&-"; done; exec "$@" ); }'
#: The same, leaving fds open: the control that shows the detachment alone does not close them.
LEAKY = 'sudo() { "$@"; }'


def healthy():
    """This host's interpreter and shell, when root's alone and Linux; else None."""
    if not os.path.exists("/usr/bin/ldd") or sys.platform != "linux":
        return None
    py, sh = os.path.realpath("/usr/bin/python3"), os.path.realpath("/bin/sh")
    if not all(os.path.exists(x) and os.stat(x).st_uid == 0 for x in (py, sh)):
        return None
    return "/usr/bin/python3", "/bin/sh"


def write(path, text, mode=0o755):
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, mode)
    return path


class Rig(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.d = os.path.realpath(t.name)
        self.stubs = os.path.join(self.d, "stub")
        os.mkdir(self.stubs)
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)

    def stub(self, name, text):
        return write(os.path.join(self.stubs, name), "#!/bin/sh\n" + text)

    def steps(self, kind, spec=P, *, between="", sudo=SUDO, owner="root", pass_fds=(), tty=None, bound=120):
        """The plan's validation steps run as one script, from a working
        directory that is not $R, with discovery's PATH led by the stubs.
        `between` runs after step 2 and before step 3. (stdout, rc, $R)."""
        lines = pj.validation_steps(spec, kind, template=os.path.join(self.d, "judge.XXXXXXXX"), owner=owner,
                                    identity="", path=self.stubs + ":" + pj.DISCOVERY_PATH)
        three = [i for i, l in enumerate(lines) if l.startswith("sudo sh -c '") and "closure.env" in l]
        if len(three) != 1:
            self.fail(f"{len(three)} step-3 lines")
        lines = lines[:three[0]] + [between] + lines[three[0]:three[0] + 1] + ['rc=$?'] + lines[three[0] + 1:] + \
            ['echo "R=$R" >&2', 'exit $rc']
        here = os.path.join(self.d, "elsewhere")
        os.makedirs(here, exist_ok=True)
        kw = dict(cwd=here, pass_fds=pass_fds, timeout=bound, stdin=subprocess.DEVNULL)
        if tty is not None:
            kw.update(stdin=tty, start_new_session=True,
                      preexec_fn=lambda: __import__("fcntl").ioctl(tty, __import__("termios").TIOCSCTTY, 0))
        try:
            p = subprocess.run(["/bin/sh", "-c", sudo + "\n" + "\n".join(lines)], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, **kw)
        except subprocess.TimeoutExpired:
            self.fail(f"the steps did not finish within {bound} s")
        r = [l[2:] for l in p.stderr.splitlines() if l.startswith("R=")]
        return p.stdout, p.returncode, r[-1] if r else None

    def need(self, tool):
        if shutil.which(tool) is None:
            self.skipTest(f"{tool} not installed")


class WholeStepTest(Rig):
    """Step 3 as printed: the digests checked quietly, discovery in a subshell
    that really does cd /, judging by absolute path."""

    def darwin_stubs(self):
        """otool naming this host's libc for every binary, xcode-select naming
        the interpreter's own library: a clean macOS rendering on Linux."""
        import sysconfig
        libc = os.path.realpath([p for p in ("/lib/aarch64-linux-gnu/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6",
                                             "/usr/lib/libc.so.6") if os.path.exists(p)][0])
        self.stub("otool", f'for b in "$@"; do [ "$b" = -L ] && continue; echo "$b:"; '
                           f'printf "\\t{libc} (compatibility version 1.0.0)\\n"; done\n')
        self.stub("xcode-select", f'echo {sysconfig.get_paths()["stdlib"]}\n')

    def test_a_clean_run_prints_only_the_sentinel_on_each_system(self):
        tools = healthy()
        if tools is None:
            self.skipTest("needs a Linux host whose interpreter is root's")
        spec = dataclasses.replace(P, tools={"python3": tools[0], "docker": tools[1]})
        for kind, digest in (("systemd", "sha256sum"), ("launchd", "shasum")):
            with self.subTest(kind):
                self.need(digest)
                if kind == "launchd":
                    if not os.path.exists("/usr/bin/perl"):
                        self.skipTest("/usr/bin/perl not installed")
                    self.darwin_stubs()
                out, rc, _ = self.steps(kind, spec)
                self.assertEqual((out, rc), (pj.SENTINEL + "\n", 0))

    def test_on_macos_a_cache_only_library_is_excused_whole_and_an_absent_other_is_named(self):
        """otool names this host's libc, a system library absent from disk
        (in the shared cache) and a non-system one absent: the first two
        print nothing at all; the third is absent and its tree find names it."""
        tools = healthy()
        if tools is None:
            self.skipTest("needs a Linux host whose interpreter is root's")
        self.need("shasum")
        if not os.path.exists("/usr/bin/perl"):
            self.skipTest("/usr/bin/perl not installed")
        self.darwin_stubs()
        libc = open(os.path.join(self.stubs, "otool")).read().split("\\t")[1].split(" (")[0]
        spec = dataclasses.replace(P, tools={"python3": tools[0], "docker": tools[1]})
        for extra, want in (("/usr/lib/libcache-only.dylib", None), ("/opt/absent/lib.dylib", "absent")):
            with self.subTest(extra):
                self.stub("otool", f'for b in "$@"; do [ "$b" = -L ] && continue; echo "$b:"; '
                                   f'printf "\\t{libc} (compatibility version 1.0.0)\\n\\t{extra} (compatibility version 1.0.0)\\n"; done\n')
                out, rc, _ = self.steps("launchd", spec)
                if want is None:
                    self.assertEqual((out, rc), (pj.SENTINEL + "\n", 0))
                else:
                    self.assertIn(f"absent: {extra}\n", out)
                    self.assertTrue([l for l in out.splitlines() if l.startswith("discovery failed: ") and extra in l],
                                    "it stays in Lw, so its tree find names it too")

    def test_a_script_changed_after_step_two_runs_nothing(self):
        for kind, digest in (("systemd", "sha256sum"), ("launchd", "shasum")):
            for name in ("judge.sh", "discover.sh"):
                with self.subTest(kind=kind, script=name):
                    self.need(digest)
                    marker = os.path.join(self.d, f"{kind}-{name}.ran")
                    between = f'chmod u+w "$R/{name}"; echo "touch {marker}" >> "$R/{name}"'
                    out, rc, _ = self.steps(kind, between=between)
                    self.assertEqual((out, rc), (pj.MISMATCH + "\n", 1))
                    self.assertFalse(os.path.exists(marker))

    def test_what_discovery_writes_is_cut_at_the_cap_and_refused(self):
        self.need("sha256sum")
        py = self.stub("python3", "head -c 2097152 /dev/zero | tr '\\0' 'a'\n")
        spec = dataclasses.replace(P, tools={"python3": py, "docker": "/bin/sh"})
        out, rc, r = self.steps("systemd", spec)
        self.assertEqual(os.path.getsize(os.path.join(r, "closure.env")), pj.CLOSURE_MAX + 1)
        self.assertIn(f"closure.env is not the discovery's output: larger than {pj.CLOSURE_MAX} bytes", out)
        self.assertEqual(rc, 1)

    def test_discovery_has_no_controlling_terminal(self):
        """Run under a terminal of the test's own making: with the detachment
        as rendered, discovery cannot open /dev/tty; without it (the control),
        it can, so the row is not vacuous."""
        self.need("sha256sum")
        for kind in ("systemd", "launchd"):
            if kind == "launchd" and not os.path.exists("/usr/bin/perl"):
                continue
            for detached in (True, False):
                with self.subTest(kind=kind, detached=detached):
                    marker = os.path.join(self.d, f"{kind}-{detached}.tty")
                    py = self.stub("python3", f"if (: </dev/tty) 2>/dev/null; then touch {marker}; fi\n"
                                               "for fd in 0 1 2; do perl -e 'ioctl(STDIN, 0x5412, \"x\") and "
                                               f"exit 0; exit 1' <&$fd 2>/dev/null && touch {marker}.sti; done\n"
                                               "echo /nonexistent\n")
                    spec = dataclasses.replace(P, tools={"python3": py, "docker": "/bin/sh"})
                    saved = pj.DROP[kind]
                    if not detached:
                        pj.DROP[kind] = ("",) + saved[1:]
                    master, slave = pty.openpty()
                    try:
                        self.steps(kind, spec, tty=slave)
                    finally:
                        pj.DROP[kind] = saved
                        os.close(master)
                        os.close(slave)
                    self.assertEqual(os.path.exists(marker), not detached)
                    self.assertFalse(os.path.exists(marker + ".sti"), "no terminal on fds 0-2 to type into")

    def test_discovery_holds_only_fds_0_1_and_2(self):
        """The shell's own fds, listed by ls from /proc/$$/fd (an ls of
        /proc/self/fd would count its own directory fd), below 10, where dash
        keeps its script and the fds it saves for a redirection: with sudo's
        closefrom, fd 7 the caller holds never reaches discovery; without it
        (the control), setsid passes it on."""
        if not os.path.isdir("/proc/self/fd"):
            self.skipTest("needs /proc")
        self.need("sha256sum")
        for sudo, want in ((SUDO, {"0", "1", "2"}), (LEAKY, {"0", "1", "2", "7"})):
            with self.subTest(closefrom=sudo is SUDO):
                rec = os.path.join(self.d, "fds")
                py = self.stub("python3", f"ls -l /proc/$$/fd > {rec}\necho /nonexistent\n")   # not last: never exec'd
                spec = dataclasses.replace(P, tools={"python3": py, "docker": "/bin/sh"})
                fd = os.open("/dev/null", os.O_RDONLY)
                try:
                    os.dup2(fd, 7)
                    self.steps("systemd", spec, sudo=sudo, pass_fds=(7,))
                finally:
                    os.close(7)
                    os.close(fd)
                with open(rec) as f:
                    held = {l.split(" -> ")[0].split()[-1] for l in f if " -> " in l}
                held = {n for n in held if int(n) < 10}   # dash keeps its script and saved fds at 10 and above
                self.assertEqual(held, want)


class JudgeTest(Rig):
    """judge.sh alone, over a closure.env the test writes: it executes nothing
    it judges, reads the file as data, and judges the tools from its own list
    first, whatever the file says."""

    def tools(self, writable=True):
        """Stub tools in a directory others can write (or not), each leaving a
        marker whenever it is executed."""
        tdir = os.path.join(self.d, "tools")
        os.makedirs(tdir, exist_ok=True)
        os.chmod(tdir, 0o777 if writable else 0o755)
        made = {}
        for name in ("python3", "docker", "ldd", "otool", "xcode-select"):
            made[name] = write(os.path.join(tdir, name + ".real"), f"#!/bin/sh\ntouch {self.d}/{name}.ran\n")
        for name in ("python3", "docker"):
            os.symlink(name + ".real", os.path.join(tdir, name))
            made[name] = os.path.join(tdir, name)
        return tdir, made

    def judge(self, env_text, spec, darwin=False, owner=None, bound=60):
        jpath, cpath = os.path.join(self.d, "judge.sh"), os.path.join(self.d, "closure.env")
        write(jpath, pj.judge_script(spec, darwin, owner or getpass.getuser()), 0o644)
        with open(cpath, "w") as f:
            f.write(env_text)
        try:
            p = subprocess.run(["/bin/sh", jpath, cpath], capture_output=True, text=True, timeout=bound,
                               env={"PATH": pj.DISCOVERY_PATH}, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            self.fail(f"judge.sh did not finish within {bound} s")
        return p.stdout, p.returncode

    def env(self, spec, **over):
        py, docker = spec.tools["python3"], spec.tools["docker"]
        lists = {"P": self.d, "Z": "", "T": f"{py} {os.path.realpath(py)} {docker} {os.path.realpath(docker)}",
                 "L": "", "Lw": "", "X": ""}
        lists.update(over)
        return "".join(f"{k}={lists[k]}\n" for k in pj.LISTS)

    def test_the_judging_never_executes_what_it_judges(self):
        tdir, made = self.tools()
        spec = dataclasses.replace(P, tools={"python3": made["python3"], "docker": made["docker"]})
        out, rc = self.judge(self.env(spec, L=made["ldd"], Lw=made["ldd"], X=tdir), spec)
        self.assertIn(tdir + "\n", out, "the tools' writable directory")
        self.assertEqual([n for n in made if os.path.exists(f"{self.d}/{n}.ran")], [])
        self.assertEqual(rc, 1)

    def test_closure_env_is_data_and_the_tools_are_judged_whatever_it_says(self):
        tdir, made = self.tools()
        spec = dataclasses.replace(P, tools={"python3": made["python3"], "docker": made["docker"]})
        m2 = os.path.join(self.d, "m2")
        rows = {"a command substitution": (self.env(spec, P=f"$(touch {m2})"), "not the discovery's output"),
                "a backquote": (self.env(spec, P=f"`touch {m2}`"), "not the discovery's output"),
                "P dropped": (self.env(spec, P=""), "omits P"),
                "a tool's realpath dropped": (self.env(spec, T=f"{made['python3']} {made['docker']}"),
                                              f"omits {os.path.realpath(made['python3'])}"),
                "the spelling dropped": (self.env(spec, T=f"{os.path.realpath(made['python3'])} "
                                                         f"{made['docker']}"), f"omits {made['python3']}")}
        for what, (text, said) in rows.items():
            with self.subTest(what):
                out, rc = self.judge(text, spec)
                self.assertIn(said, out)
                self.assertIn(tdir + "\n", out, "the fixed list is judged whatever closure.env says")
                self.assertFalse(os.path.exists(m2))
                self.assertEqual(rc, 1)

    def test_only_the_grammar_is_read(self):
        _, made = self.tools(writable=False)
        spec = dataclasses.replace(P, tools={"python3": made["python3"], "docker": made["docker"]})
        good = self.env(spec)
        rows = {"out of order": good.replace("Z=\n", "").replace("T=", "Z=\nT=", 1).replace("P=", "Q=", 1),
                "a list missing": good.replace("X=\n", ""),
                "a line that is not a list": good + "hello\n",
                "a list twice": good + "X=\n",
                "an unterminated last line": good.rstrip("\n"),
                "a tab": good.replace(f"P={self.d}", f"P={self.d}\t/x"),
                "two spaces": good.replace(f"P={self.d}", f"P={self.d}  /x"),
                "a leading space": good.replace(f"P={self.d}", f"P= {self.d}"),
                "an entry that is not absolute": good.replace(f"P={self.d}", f"P={self.d} -name"),
                "a glob": good.replace(f"P={self.d}", f"P={self.d}/*"),
                "a quote": good.replace(f"P={self.d}", f"P={self.d}'"),
                "a control character": good.replace(f"P={self.d}", f"P={self.d}\x1b[2J"),
                "too large": good + ("discovery failed: " + "x" * 100 + "\n") * 11000}
        for what, text in rows.items():
            with self.subTest(what):
                out, rc = self.judge(text, spec)
                self.assertIn("closure.env is not the discovery's output", out)
                self.assertEqual(rc, 1)
        out, rc = self.judge(good, spec)
        self.assertNotIn("not the discovery's output", out, "the control parses")

    def test_a_link_in_place_of_closure_env_is_refused(self):
        _, made = self.tools(writable=False)
        spec = dataclasses.replace(P, tools={"python3": made["python3"], "docker": made["docker"]})
        real = write(os.path.join(self.d, "real.env"), self.env(spec), 0o644)
        jpath, cpath = os.path.join(self.d, "judge.sh"), os.path.join(self.d, "closure.env")
        write(jpath, pj.judge_script(spec, False, getpass.getuser()), 0o644)
        os.symlink(real, cpath)
        out = subprocess.run(["/bin/sh", jpath, cpath], capture_output=True, text=True, timeout=60,
                             stdin=subprocess.DEVNULL).stdout
        self.assertIn("not a regular file", out)

    def test_on_linux_the_loader_the_interpreter_names_must_be_listed(self):
        tools = healthy()
        if tools is None:
            self.skipTest("needs a Linux host whose interpreter is root's")
        spec = dataclasses.replace(P, tools={"python3": tools[0], "docker": tools[1]})
        found = subprocess.run(["/bin/sh", "-c", pj.discover_script(spec, False)], capture_output=True, text=True,
                               timeout=180, env={"PATH": pj.DISCOVERY_PATH}).stdout
        lists = dict(l.split("=", 1) for l in found.splitlines() if "=" in l and not l.startswith("discovery"))
        loaders = [x for x in lists["L"].split() if "/ld-" in x]
        self.assertTrue(loaders, "ldd names the loader")
        without = " ".join(x for x in lists["L"].split() if x not in loaders)
        text = "".join(f"{k}={without if k == 'L' else lists[k]}\n" for k in pj.LISTS)
        out, rc = self.judge(text, spec, owner="root", bound=300)
        self.assertIn("closure.env omits the loader", out)
        out, rc = self.judge(found, spec, owner="root", bound=300)
        self.assertEqual((out, rc), (pj.SENTINEL + "\n", 0), "the symlinked spellings, as discovery lists them")

    def test_the_loader_is_never_read_from_what_is_not_a_regular_file(self):
        fifo = os.path.join(self.d, "python3")
        os.mkfifo(fifo)
        spec = dataclasses.replace(P, tools={"python3": fifo, "docker": "/bin/sh"})
        out, rc = self.judge(self.env(spec), spec, bound=30)
        self.assertIn("the interpreter's loader cannot be checked", out)

    def test_the_shared_cache_is_the_writers_own(self):
        self.assertEqual(pj.CACHE_PREFIXES, hs.SEALED_PREFIXES)

    def test_the_text_executes_no_tool_and_sources_nothing(self):
        judge = pj.judge_script(dataclasses.replace(P, tools={"python3": "/x/PYMARK", "docker": "/x/DOCKMARK"}),
                                False)
        self.assertEqual((judge.count("/x/PYMARK"), judge.count("/x/DOCKMARK")), (1, 1), "only as PY= and DOCKER=")
        import re
        words = r"(eval|source|\.|ldd|otool|xcode-select|\"?\$(PY|DOCKER|PYR|DR)\"?)"
        starts = re.compile(r"(^|[;&|{(]|\bthen|\bdo|\belse)\s*" + words + r"(\s|;|$)")
        self.assertEqual([m.group(0) for m in starts.finditer(judge)], [])
        code = "\n".join(l for l in judge.splitlines() if not l.startswith("#"))
        for word in ("ldd", "otool", "xcode-select", "-I -S -B"):
            self.assertNotIn(word, code)


class NitsTest(Rig):
    def shells(self):
        found = {}
        for sh in ("/bin/dash", "/usr/bin/dash", "/bin/bash", "/usr/bin/bash"):
            if os.path.exists(sh):
                found.setdefault(os.path.basename(sh), os.path.realpath(sh))
        for name in ("dash", "bash"):
            if name not in found:
                print(f"SKIP {name} not installed", file=sys.stderr)
        return sorted(found.values())

    def test_ldd_not_found_is_named_as_such(self):
        self.stub("ldd", "printf '\\tlibz.so.1 => not found\\n'\n")
        py = self.stub("python3", f"echo {self.d}\n")
        spec = dataclasses.replace(P, tools={"python3": py, "docker": py})
        found = subprocess.run(["/bin/sh", "-c", pj.discover_script(spec, False)], capture_output=True, text=True,
                               timeout=60, env={"PATH": self.stubs + ":" + pj.DISCOVERY_PATH}).stdout
        self.assertIn("discovery failed: libz.so.1 not found\n", found)
        self.assertNotIn("whitespace in not found", found)
        self.assertNotIn(" not", [l for l in found.splitlines() if l.startswith("L=")][0] + " ")

    def test_norm_leaves_the_callers_noglob_as_it_found_it(self):
        judge = pj.judge_script(P, False)
        norm = [l for l in judge.splitlines() if l.startswith("norm() ")][0]
        for shell in self.shells():
            for setting, want in (("set -f", "f"), ("set +f", "")):
                with self.subTest(shell=shell, setting=setting):
                    script = f"{norm}\n{setting}\nnorm /a/./b/../c >/dev/null\ncase $- in *f*) echo f;; *) echo;; esac"
                    out = subprocess.run([shell, "-c", script], capture_output=True, text=True).stdout.strip()
                    self.assertEqual(out, want)
                    out = subprocess.run([shell, "-c", f"{norm}\nnorm //a/./b/../c"], capture_output=True,
                                         text=True).stdout.strip()
                    self.assertEqual(out, "/a/c")


class FindErrorsTest(Rig):
    """Which finds name their errors: the owner-and-mode tree finds do, with
    their findings kept unprefixed; the -L target finds do not."""

    def run_judge(self, root):
        py = write(os.path.join(self.stubs, "python3"), "#!/bin/sh\n", 0o755)
        spec = dataclasses.replace(P, tools={"python3": py, "docker": py})
        cpath = os.path.join(self.d, "closure.env")
        with open(cpath, "w") as f:
            f.write(f"P={root}\nZ=\nT={py} {py}\nL=\nLw=\nX=\n")
        jpath = write(os.path.join(self.d, "judge.sh"), pj.judge_script(spec, False, getpass.getuser()), 0o644)
        return subprocess.run(["/bin/sh", jpath, cpath], capture_output=True, text=True, timeout=60,
                              stdin=subprocess.DEVNULL).stdout

    def test_an_unreadable_directory_is_named_and_a_writable_file_beside_it_kept(self):
        if os.getuid() == 0:
            self.skipTest("root reads any directory")
        root = os.path.join(self.d, "lib")
        os.mkdir(root)
        w = write(os.path.join(root, "w.py"), "x", 0o666)
        locked = os.path.join(root, "locked")
        os.mkdir(locked)
        os.chmod(locked, 0)
        self.addCleanup(os.chmod, locked, 0o755)
        out = self.run_judge(root)
        self.assertIn(w + "\n", out.splitlines(keepends=True) and out)
        self.assertTrue([l for l in out.splitlines() if l.startswith("discovery failed: ") and locked in l
                         and "Permission denied" in l], out)
        self.assertFalse([l for l in out.splitlines() if l.startswith("discovery failed: ") and w in l])

    def test_a_benign_link_loop_prints_no_loop_warning_and_judges_beyond(self):
        root = os.path.join(self.d, "lib")
        os.makedirs(os.path.join(root, "bin"))
        os.symlink(".", os.path.join(root, "bin", "X11"))
        beyond = os.path.join(self.d, "beyond")
        os.mkdir(beyond)
        os.chmod(beyond, 0o777)
        os.symlink(beyond, os.path.join(root, "bin", "out"))
        out = self.run_judge(root)
        self.assertNotIn("loop detected", out)
        self.assertIn(beyond + "\n", out)


class ParityTest(Rig):
    """Each fixture through BOTH the writer's closure_problems and the two
    halves (each shell), ownership mapped to this test's user. Each declares
    the set of paths it must report, by realpath within the fixture; each
    side must equal it. Equality between the sides alone is never the oracle."""

    def setUp(self):
        super().setUp()
        self.addCleanup(setattr, hs, "ROOT_UID", hs.ROOT_UID)
        hs.ROOT_UID = os.getuid()

    def fixture(self, name):
        d = os.path.join(self.d, name)
        os.makedirs(d)
        return d

    def mk(self, d, links=(), dirs=(), writable=(), files=()):
        for x in dirs:
            os.makedirs(os.path.join(d, x), exist_ok=True)
        for x in files:
            write(os.path.join(d, x), "x", 0o644)
        for x in writable:
            os.makedirs(os.path.join(d, x), exist_ok=True)
            os.chmod(os.path.join(d, x), 0o777)
        for link, target in links:
            os.symlink(target, os.path.join(d, link))

    def sides(self, d, roots, shell):
        import shlex
        py = write(os.path.join(self.stubs, "python3"), "#!/bin/sh\ncase \"$*\" in *zip*) echo ;; *) echo %s ;; "
                   "esac\n" % " ".join(shlex.quote(r) for r in roots), 0o755)
        spec = dataclasses.replace(P, tools={"python3": py, "docker": py})
        inside = lambda ps_: {os.path.realpath(p) for p in ps_ if os.path.realpath(p).startswith(d + "/")}
        runtime = inside(b.split(":")[0].split(" ")[0] for b in hs.closure_problems(roots))
        out = []
        text = halves(spec, owner=getpass.getuser(), shell=shell, stubs=self.stubs)
        for l in text.splitlines():
            if l.startswith("discovery failed: find: "):
                l = l.split("'")[1] if "'" in l else l
            elif l.startswith("discovery failed: "):
                continue
            out.append(l.split(": ")[0])
        return runtime, inside(out)

    def shells(self):
        return NitsTest.shells(self)

    def test_each_fixture_reports_its_declared_set_on_both_sides(self):
        for shell in self.shells():
            for name, build, want in self.fixtures():
                with self.subTest(shell=shell, fixture=name):
                    d = self.fixture(f"{os.path.basename(shell)}-" + "".join(c if c.isalnum() else "_" for c in name))
                    roots = build(d)
                    runtime, block = self.sides(d, roots, shell)
                    expect = {os.path.join(d, w) for w in want}
                    if name == "safe control":
                        self.assertEqual(expect, set())
                    else:
                        self.assertTrue(expect, "a bad fixture declares what it must report")
                    self.assertEqual(runtime, expect, "the writer")
                    self.assertEqual(block, expect, "the install-time halves")

    def fixtures(self):
        def alias(writable):
            def build(d):
                self.mk(d, dirs=["r1", "r2", "o/safe"], files=["o/safe/linked.py"],
                        writable=["o/outside"] if writable else [], links=[])
                if not writable:
                    os.makedirs(os.path.join(d, "o/outside"))
                self.mk(d, links=[("o/outside/alias", "../safe"), ("r1/first.py", os.path.join(d, "o/safe/linked.py")),
                                  ("r2/second.py", "../o/outside/alias/linked.py")])
                return [os.path.join(d, "r1"), os.path.join(d, "r2")]
            return build

        def two_hop(d):
            self.mk(d, dirs=["r", "mid", "W/c"], writable=["W/c/w"])
            self.mk(d, links=[("r/a", "../mid/b"), ("mid/b", os.path.join(d, "W/c"))])
            return [os.path.join(d, "r")]

        def parent_chain(d):
            self.mk(d, dirs=["q", "mid2"], writable=["W2/marked"])
            self.mk(d, dirs=["W2/marked/real2"], files=["W2/marked/real2/file"])
            self.mk(d, links=[("q/dirlink", "../mid2/p"), ("mid2/p", os.path.join(d, "W2/marked/real2")),
                              ("q/via", "dirlink/file")])
            return [os.path.join(d, "q")]

        def chain_then_tree(d):
            self.mk(d, dirs=["c1", "c2", "s/shared"], files=["s/shared/x"], writable=["o2/outside"])
            self.mk(d, files=["o2/outside/linked.py"])
            self.mk(d, links=[("c1/parent", os.path.join(d, "s/shared")), ("c2/lnk", os.path.join(d, "s/shared")),
                              ("s/shared/inner.py", os.path.join(d, "o2/outside/linked.py")),
                              ("c1/first.py", "parent/x")])
            return [os.path.join(d, "c1"), os.path.join(d, "c2")]

        def x11(d):
            self.mk(d, dirs=["c/bin"], writable=["w1"])
            self.mk(d, links=[("c/bin/X11", "."), ("c/bin/out", os.path.join(d, "w1"))])
            return [os.path.join(d, "c")]

        return [("alias", alias(True), ["o/outside"]), ("safe control", alias(False), []),
                ("two-hop tree", two_hop, ["W/c/w"]), ("two-hop parent chain", parent_chain, ["W2/marked"]),
                ("chain then tree", chain_then_tree, ["o2/outside"]), ("bin/X11 -> .", x11, ["w1"])]


def halves(spec, **kw):
    from test_partition_job import halves as run
    return run(spec, **kw)


@unittest.skipUnless(os.environ.get("AMAP_PRIVILEGED_ROWS") == "1", "needs passwordless sudo "
                     "(AMAP_PRIVILEGED_ROWS=1 in a disposable root Linux environment)")
class PrivilegedTest(Rig):
    """The rows that need a real uid change: discovery as nobody holds no sudo
    ticket of the operator's and cannot read what only root can. Run once in a
    disposable root Linux environment; never passed by a skip."""

    def setUp(self):
        super().setUp()
        if subprocess.run(["sudo", "-n", "true"]).returncode != 0:
            self.fail("AMAP_PRIVILEGED_ROWS=1 but sudo -n true fails")
        self.tools = healthy()
        if self.tools is None:
            self.fail("needs a Linux host whose interpreter is root's")
        self.pub = tempfile.mkdtemp(dir="/tmp")
        os.chmod(self.pub, 0o755)
        self.addCleanup(subprocess.run, ["sudo", "-n", "rm", "-rf", "--", self.pub])

    def real(self, py_text):
        py = write(os.path.join(self.pub, "python3"), "#!/bin/sh\n" + py_text)
        spec = dataclasses.replace(P, tools={"python3": py, "docker": self.tools[1]})
        lines = pj.validation_steps(spec, "systemd", template=os.path.join(self.pub, "judge.XXXXXXXX"))
        return subprocess.run(["/bin/sh", "-c", "\n".join(lines) + '\necho "R=$R" >&2'], capture_output=True,
                              text=True, timeout=300)

    def test_discovery_cannot_use_the_operators_sudo_ticket(self):
        m1 = os.path.join(self.pub, "m1")
        self.real(f"sudo -n touch {m1} 2>/dev/null\n( for i in $(seq 20); do sudo -n touch {m1} 2>/dev/null; "
                  "sleep 1; done ) >/dev/null 2>&1 &\necho /nonexistent\n")
        subprocess.run(["sudo", "-n", "-v"])
        subprocess.run(["sleep", "22"])
        self.assertFalse(os.path.exists(m1))

    def test_discovery_cannot_read_what_only_root_can(self):
        secret = os.path.join(self.pub, "secret")
        subprocess.run(["sudo", "-n", "sh", "-c", f"umask 077; echo SENTINEL-ROOT-ONLY > {secret}"], check=True)
        p = self.real(f"cat {secret} 2>/dev/null; echo /nonexistent\n")
        r = [l[2:] for l in p.stderr.splitlines() if l.startswith("R=")][-1]
        env = subprocess.run(["sudo", "-n", "cat", os.path.join(r, "closure.env")], capture_output=True,
                             text=True).stdout
        self.assertNotIn("SENTINEL-ROOT-ONLY", env + p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main()
