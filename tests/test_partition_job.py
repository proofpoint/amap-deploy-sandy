"""partition_job: the weekly job's unit and the operator's root steps before
it. The argv is the job's trusted input; the units start it weekly and once
after boot; the steps provision from the public repository, never a local
clone, and check the tools with the operating system's own."""

import dataclasses
import hashlib
import os
import plistlib
import shlex
import subprocess
import sys
import tempfile
import unittest

import partition_job as pj
import partition_setup as ps
import root_trust as rt

P = ps.PartitionSpec(evidence_dir="/opt/ex/ev", scratch_dir="/opt/ex/scratch", weekday=2, hour=4,
                     exec_root="/opt/ex/exec", tools={"python3": "/usr/bin/python3", "docker": "/usr/bin/docker"})
DOC = b'{"host_setup": {}}'
ACT = b'{"approved": "A1"}'
ARGV = pj.job_argv(P, writer="/opt/amap/host_steps.py", writer_sha256="b" * 64, host="alpha", document="/opt/ov/overlay.json",
                   document_bytes=DOC, activation_bytes=ACT)


def halves(spec, *, darwin=False, owner="root", stubs=None, shell="/bin/sh", bound=180, work=None):
    """Discovery then judging, as step 3 runs them but as this test's user:
    discovery under an empty environment (PATH the system's, after `stubs`),
    its output captured as closure.env, then judge.sh over it. The output,
    which must end with the sentinel: a judging that stopped early fails."""
    path = (stubs + ":" if stubs else "") + pj.DISCOVERY_PATH
    with tempfile.TemporaryDirectory(dir=work) as t:
        judge, ce = os.path.join(t, "judge.sh"), os.path.join(t, "closure.env")
        with open(judge, "w") as f:
            f.write(pj.judge_script(spec, darwin, owner=owner))
        try:
            found = subprocess.run([shell, "-c", pj.discover_script(spec, darwin)], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=bound,
                                   env={"PATH": path, "HOME": "/", "LC_ALL": "C"}).stdout
            with open(ce, "wb") as f:
                f.write(found[:pj.CLOSURE_MAX + 1])
            out = subprocess.run([shell, judge, ce], capture_output=True, text=True, timeout=bound,
                                 stdin=subprocess.DEVNULL).stdout
        except subprocess.TimeoutExpired:
            raise AssertionError(f"the halves did not finish within {bound} s") from None
    if not out.endswith(pj.SENTINEL + "\n"):
        raise AssertionError(f"the judging did not reach its sentinel: {out!r}")
    return out


class JobTest(unittest.TestCase):
    def test_the_argv_carries_every_input_the_job_must_not_take_from_operator_files(self):
        import root_trust as rt
        self.assertEqual(ARGV[:6], rt.anchor() + ["/bin/sh", "-c"])
        self.assertEqual(len(ARGV), 7, "the anchor, sh -c and one script")
        body = shlex.split(ARGV[6].split("; ", 1)[1])
        self.assertEqual(body[:13], ["root_exec", "b" * 64, "/usr/bin/python3", "/opt/amap/host_steps.py", "trusted-exec",
                                     "--tool", "/usr/bin/docker", "--tool", "/usr/bin/python3",
                                     "--also", "/usr/bin/docker", "--", "/usr/bin/python3"],
                         "d3.3 §4.1: the partition document's whole recorded set as --tool")
        self.assertEqual(ARGV[6].split("; ", 1)[0],
                         "command . /opt/amap/root-trust.sh && command -v root_exec >/dev/null || exit 12")
        step = body[12:]
        self.assertEqual(step[:5], ["/usr/bin/python3", "-I", "-S", "-B", "/opt/amap/host_steps.py"])
        opts = dict(zip(step[6::2], step[7::2]))
        self.assertEqual(opts, {"--exec-root": "/opt/ex/exec", "--host": "alpha", "--document": "/opt/ov/overlay.json",
                                "--document-sha256": hashlib.sha256(DOC).hexdigest(),
                                "--activation": "/opt/ex/ev/activation.json",
                                "--activation-sha256": hashlib.sha256(ACT).hexdigest()})

    def test_a1s_record_is_placed_at_its_one_place_checked_against_its_digest(self):
        steps = pj.activation_steps(P, writer="/opt/amap/host_steps.py", writer_sha256="b" * 64,
                                    tools=["/usr/bin/python3", "/usr/bin/docker", "/usr/bin/sudo"],
                                    source="/home/op/run/activation.json", activation_bytes=ACT)
        self.assertIn(f"place /home/op/run/activation.json /opt/ex/ev/activation.json --sha256 "
                      f"{hashlib.sha256(ACT).hexdigest()}", steps[-1])
        argv = shlex.split(steps[-1])
        self.assertEqual(argv, rt.typed_argv("/opt/amap/root-trust.sh", "b" * 64, "/usr/bin/python3",
                                             "/opt/amap/host_steps.py", ["/usr/bin/python3", "/usr/bin/docker"],
                                             argv[argv.index("--") + 1:]))
        self.assertEqual(argv[argv.index("--") + 1:argv.index("--") + 6],
                         ["/usr/bin/python3", "-I", "-S", "-B", "/opt/amap/host_steps.py"],
                         "the writer in trusted-exec's one exact vector (d3.3 §4.1)")
        self.assertEqual(argv[0], "/usr/bin/sudo")
        self.assertNotIn("/usr/bin/sudo", argv[1:], "root's argv never holds sudo")

    def test_systemd_runs_it_weekly_and_once_after_boot(self):
        files = dict(pj.rendered("systemd", P, ARGV))
        timer = files["/etc/systemd/system/amap-partition-weekly.timer"].decode()
        self.assertIn("OnCalendar=Tue *-*-* 04:00:00", timer)
        self.assertIn(f"OnBootSec={pj.BOOT_DELAY_S}", timer)
        service = files["/etc/systemd/system/amap-partition-weekly.service"].decode()
        self.assertIn("ExecStart=/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C /bin/sh -c ", service)
        self.assertIn("trusted-exec --tool /usr/bin/docker --tool /usr/bin/python3 --also /usr/bin/docker -- "
                      "/usr/bin/python3 -I -S -B /opt/amap/host_steps.py "
                      "partition-weekly", service)

    def test_launchd_runs_it_weekly_and_at_load(self):
        [(path, data)] = pj.rendered("launchd", P, ARGV)
        doc = plistlib.loads(data)
        self.assertEqual((path, doc["ProgramArguments"], doc["RunAtLoad"]),
                         ("/Library/LaunchDaemons/org.amap.partition-weekly.plist", ARGV, True))
        self.assertEqual(doc["StartCalendarInterval"], {"Weekday": 2, "Hour": 4, "Minute": 0})

    def test_provisioning_clones_the_public_repository_and_archives_exactly_the_closure(self):
        text = "\n".join(pj.provision_steps(P, "a" * 40, "/opt/amap/host_steps.py"))
        self.assertIn(f"clone --no-checkout {pj.PUBLIC_REPO} /opt/ex/exec/src.new", text)
        self.assertTrue(pj.PUBLIC_REPO.startswith("https://"))
        self.assertIn("GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null", text)
        self.assertIn("-c core.hooksPath=/dev/null -c protocol.allow=never -c protocol.https.allow=always", text)
        self.assertIn("archive --format=tar " + "a" * 40 + " -- partition_weekly.closure $(", text)
        self.assertIn("partition-provision /opt/ex/exec", text)
        self.assertNotIn("file://", text)

    def test_validation_uses_the_systems_own_tools_and_an_empty_environment(self):
        text = pj.discover_script(P, False) + pj.discover_script(P, True)
        for words in ("/usr/bin/python3 -I -S -B", "ldd ", "otool -L", "xcode-select -p", "DESTSHARED", ".zip"):
            self.assertIn(words, text)
        judge = pj.judge_script(P, False)
        for words in ("find ", "! -user root -o -perm -g+w -o -perm -o+w", "-maxdepth 0", "find -L ",
                      "discovery failed", 'realpath "$p"'):
            self.assertIn(words, judge)
        self.assertIn("env -i PATH=" + pj.DISCOVERY_PATH, pj.step3("systemd"))

    def block(self, python, docker, then=""):
        """Discovery then judging, as step 3 runs them, on this host; `then`
        names a list to print from discovery's output instead."""
        spec = dataclasses.replace(P, tools={"python3": python, "docker": docker})
        if then:
            found = subprocess.run(["/bin/sh", "-c", pj.discover_script(spec, False)], capture_output=True,
                                   text=True, timeout=180, env={"PATH": pj.DISCOVERY_PATH}).stdout
            return [l for l in found.splitlines() if l.startswith(then + "=")][0][len(then) + 1:]
        return halves(spec)

    def healthy(self):
        """This host's own interpreter and shell, when root's alone; else skip."""
        if not os.path.exists("/usr/bin/ldd") or sys.platform != "linux":
            self.skipTest("the Linux branch needs ldd")
        py, sh = os.path.realpath("/usr/bin/python3"), os.path.realpath("/bin/sh")
        if not all(os.path.exists(x) and os.stat(x).st_uid == 0 for x in (py, sh)):
            self.skipTest("this host's interpreter is not root's")
        return py, sh

    def test_a_host_whose_closure_is_roots_alone_prints_nothing(self):
        py, sh = self.healthy()
        self.assertEqual(self.block(py, sh), pj.SENTINEL + "\n", "an absent optional zip is not a finding")

    def test_the_list_the_checks_consume_is_ldds_on_linux_with_every_link_and_the_loader(self):
        py, sh = self.healthy()
        listed = self.block(py, sh, "L").split()
        self.assertTrue(any("libssl" in x for x in listed), "an extension module's own link")
        self.assertTrue(any("/ld-linux" in x for x in listed), "the loader")
        self.assertFalse([x for x in listed if x.endswith(":") or not x.startswith("/")], "no header, nothing else")

    def test_a_writable_directory_above_a_tool_is_printed(self):
        py, sh = self.healthy()
        with tempfile.TemporaryDirectory() as t:
            w = os.path.join(os.path.realpath(t), "w")
            os.mkdir(w)
            os.chmod(w, 0o777)
            os.symlink(sh, os.path.join(w, "docker"))
            self.assertIn(w + "\n", self.block(py, os.path.join(w, "docker")))

    def test_a_writable_target_behind_a_link_is_printed_by_the_target_check(self):
        """The link check alone: a test can only make a link it owns, which
        the owner check already prints, so the target check is run here by
        itself, as judge.sh's fixed list renders it."""
        py, _ = self.healthy()
        with tempfile.TemporaryDirectory() as t:
            d = os.path.realpath(t)
            target, link = os.path.join(d, "real-docker"), os.path.join(d, "docker")
            with open(target, "w") as f:
                f.write("x")
            os.chmod(target, 0o666)
            os.symlink(target, link)
            spec = dataclasses.replace(P, tools={"python3": py, "docker": link})
            targets = [l for l in pj.judge_script(spec, False).split("; ") if l.startswith('find -L "$PY"')]
            if len(targets) != 1:
                self.fail(f"judge.sh holds {len(targets)} link-target check(s) of the tools")
            script = f"PY={py}\nDOCKER={link}\nPYR={py}\nDR={target}\n" + targets[0]
            out = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, timeout=180).stdout
            self.assertIn(link + "\n", out, "the target is judged through the link")

    def test_each_lists_link_target_check_fires_alone(self):
        """The -L finds over the lists, a present zip and the developer
        directory, each run by itself (the walk, which also follows these
        links, absent): a writable target behind a link is printed through
        the link by that line alone. Each line is required exactly once."""
        judge = pj.judge_script(P, False)
        segments = [x.strip() for x in judge.replace("\n", "; ").split("; ")]
        rows = {"find -L $P $Lw": lambda d, link: f"P={d}\nLw=\n",
                'find -L "$z"': lambda d, link: f"z={link}\n",
                'find -L "$X"': lambda d, link: f"X={d}\n"}
        for prefix, setup in rows.items():
            with self.subTest(prefix):
                found = [x for x in segments if x.startswith(prefix + " ")]
                if len(found) != 1:
                    self.fail(f"judge.sh holds {len(found)} {prefix} line(s)")
                with tempfile.TemporaryDirectory() as t:
                    d = os.path.realpath(t)
                    tree, target = os.path.join(d, "tree"), os.path.join(d, "target.py")
                    os.mkdir(tree)
                    with open(target, "w") as f:
                        f.write("x")
                    os.chmod(target, 0o666)
                    link = os.path.join(tree, "link.py")
                    os.symlink(target, link)
                    script = "set -f\n" + setup(tree, link) + found[0]
                    out = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, timeout=60,
                                         stdin=subprocess.DEVNULL).stdout
                    self.assertIn(link + "\n", out, "the target is judged through the link, by this line alone")

    def test_a_discovery_that_fails_names_its_file_and_a_missing_path_is_named(self):
        py, _ = self.healthy()
        with tempfile.TemporaryDirectory() as t:
            script = os.path.join(os.path.realpath(t), "docker")
            with open(script, "w") as f:
                f.write("#!/bin/sh\n")
            os.chmod(script, 0o755)
            out = self.block(py, script)
            self.assertIn(f"discovery failed: {script}", out)
            self.assertNotIn(f"discovery failed: {py}", out)
            self.assertIn("absent: /nonexistent/docker", self.block(py, "/nonexistent/docker"))

class ValidationMirrorTest(unittest.TestCase):
    """The install-time block against closures this host does not have: an
    interpreter stand-in names the library paths, `uname` may be stubbed,
    and (for links) ownership is mapped to this test's user so that only
    the permission checks decide."""

    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.d = os.path.realpath(t.name)

    def interpreter(self, paths):
        py = os.path.join(self.d, "python3")
        with open(py, "w") as f:
            f.write("#!/bin/sh\ncase \"$*\" in *zip*) echo ;; *) echo %s ;; esac\n" % " ".join(paths))
        os.chmod(py, 0o755)
        return py

    def run_block(self, py, env=None, as_owner=False, bound=180, shell="/bin/sh"):
        """Both halves, rendered for macOS when a stub uname says Darwin, with
        the stubs first on discovery's PATH."""
        import getpass
        spec = dataclasses.replace(P, tools={"python3": py, "docker": os.path.realpath("/bin/sh")})
        stubs = os.path.join(self.d, "stub")
        darwin = os.path.exists(os.path.join(stubs, "uname"))
        return halves(spec, darwin=darwin, owner=getpass.getuser() if as_owner else "root",
                      stubs=stubs if os.path.isdir(stubs) else None, shell=shell, bound=bound)

    def test_on_macos_a_missing_required_path_is_named_though_it_is_under_a_system_prefix(self):
        stub = os.path.join(self.d, "stub")
        os.mkdir(stub)
        with open(os.path.join(stub, "uname"), "w") as f:
            f.write("#!/bin/sh\necho Darwin\n")
        os.chmod(os.path.join(stub, "uname"), 0o755)
        missing = "/usr/lib/absent-required-python"
        py = self.interpreter([missing, missing, missing + "/lib-dynload"])
        out = self.run_block(py)
        self.assertIn(f"absent: {missing}\n", out, "a required path is never taken for the shared cache")
        self.assertIn(f"absent: {missing}/lib-dynload\n", out)

    def stub(self, name, text):
        d = os.path.join(self.d, "stub")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, name), "w") as f:
            f.write("#!/bin/sh\n" + text)
        os.chmod(os.path.join(d, name), 0o755)
        return {"PATH": d + ":" + os.environ["PATH"]}

    def test_a_library_the_tool_names_that_is_missing_is_named(self):
        py = self.interpreter([self.d, self.d, self.d])
        env = self.stub("ldd", "printf '\\tlibz.so.1 => /nonexistent/libz.so.1 (0x1)\\n'\n")
        self.assertIn("absent: /nonexistent/libz.so.1\n", self.run_block(py, env=env))

    def test_on_macos_only_a_system_library_the_tool_names_may_be_absent(self):
        py = self.interpreter([self.d, self.d, self.d])
        self.stub("uname", "echo Darwin\n")
        env = self.stub("otool", "echo \"$1:\"; printf '\\t/usr/lib/libSystem.B.dylib (c)\\n\\t/opt/absent/lib.dylib (c)\\n'\n")
        out = self.run_block(py, env=env)
        self.assertIn("absent: /opt/absent/lib.dylib\n", out)
        self.assertNotIn("absent: /usr/lib/libSystem.B.dylib", out, "in the shared cache")

    def test_a_writable_directory_above_a_link_target_inside_the_tree_is_printed(self):
        """stdlib/link.py -> outside/linked.py, the file 0444, outside/ 0777."""
        stdlib, outside = os.path.join(self.d, "stdlib"), os.path.join(self.d, "outside")
        os.mkdir(stdlib)
        os.mkdir(outside)
        with open(os.path.join(outside, "linked.py"), "w") as f:
            f.write("x = 1\n")
        os.chmod(os.path.join(outside, "linked.py"), 0o444)
        os.chmod(outside, 0o777)
        os.symlink(os.path.join(outside, "linked.py"), os.path.join(stdlib, "link.py"))
        py = self.interpreter([stdlib, stdlib, stdlib])
        out = self.run_block(py, as_owner=True)
        self.assertIn(outside + "\n", out.replace(outside + "/", "\0"), "the target's own directory")

    def test_a_path_holding_whitespace_is_named_never_split(self):
        """stdlib/link.py -> "out side"/linked.py, and stdlib/"a b.py": each is
        named as a discovery failure rather than split into fragments that
        would be judged in its place."""
        stdlib, spaced = os.path.join(self.d, "stdlib"), os.path.join(self.d, "out side")
        os.mkdir(stdlib)
        os.mkdir(spaced)
        with open(os.path.join(spaced, "linked.py"), "w") as f:
            f.write("x = 1\n")
        os.symlink(os.path.join(spaced, "linked.py"), os.path.join(stdlib, "link.py"))
        with open(os.path.join(stdlib, "a b.py"), "w") as f:
            f.write("y = 2\n")
        py = self.interpreter([stdlib, stdlib, stdlib])
        out = self.run_block(py, as_owner=True)
        self.assertIn(f"discovery failed: whitespace in {spaced}/linked.py\n", out)
        self.assertIn(f"discovery failed: whitespace in {stdlib}/a b.py\n", out)

    def tree(self, links, writable=()):
        """Directories and links under the test's root: `links` maps a link's
        path to its target (as written); `writable` names directories made 0777."""
        for name in sorted({os.path.dirname(l) for l in links} | set(writable) | {"stdlib"}):
            os.makedirs(os.path.join(self.d, name), exist_ok=True)
        for name in writable:
            os.chmod(os.path.join(self.d, name), 0o777)
        for link, target in links.items():
            os.symlink(target, os.path.join(self.d, link))

    def test_a_chain_visit_never_stands_in_for_a_later_tree_visit(self):
        """The first root reaches shared/ only as a parent link's target (a
        chain visit); the second reaches it as a closure link (a tree visit),
        under which a link leads to a writable directory. In either order the
        writable directory is printed."""
        for first, second in (("stdlib", "dynload"), ("dynload", "stdlib")):
            with self.subTest(order=(first, second)):
                d = self.d = os.path.join(os.path.realpath(self.d), f"{first}-first")
                os.makedirs(d)
                os.makedirs(os.path.join(d, "shared"))
                with open(os.path.join(d, "shared", "file"), "w") as f:
                    f.write("x")
                os.makedirs(os.path.join(d, "outside"))
                with open(os.path.join(d, "outside", "linked.py"), "w") as f:
                    f.write("y")
                os.chmod(os.path.join(d, "outside"), 0o777)
                self.tree({"parent": os.path.join(d, "shared"),
                           "stdlib/first.py": os.path.join(d, "parent", "file"),
                           "shared/inner.py": os.path.join(d, "outside", "linked.py"),
                           "dynload/second": os.path.join(d, "shared")})
                py = self.interpreter([os.path.join(d, first), os.path.join(d, first), os.path.join(d, second)])
                out = self.run_block(py, as_owner=True, bound=60)
                self.assertIn(os.path.join(d, "outside") + "\n", out)
                self.d = os.path.dirname(d)

    def test_every_relative_cycle_ends_and_what_lies_beyond_is_still_judged(self):
        shapes = {"d/l -> ../d/l": {"stdlib/d/l": "../d/l"},
                  "bin/X11 -> .": {"stdlib/bin/X11": "."},
                  "bin/up -> ../bin": {"stdlib/bin/up": "../bin"},
                  "A/sub -> ../B, B/back -> ../A": {"stdlib/A/sub": "../B", "stdlib/B/back": "../A"},
                  "d/x -> loop/x through d/loop -> .": {"stdlib/d/loop": ".", "stdlib/d/x": "loop/x"}}
        for what, links in shapes.items():
            with self.subTest(what):
                d = self.d = os.path.join(os.path.realpath(self.d), what.split()[0].replace("/", "_"))
                os.makedirs(d)
                beyond = os.path.join(d, "beyond")
                first = sorted(links)[0]
                self.tree(dict(links, **{os.path.join(os.path.dirname(first), "w"): beyond}), writable=["beyond"])
                py = self.interpreter([os.path.join(d, "stdlib")] * 3)
                out = self.run_block(py, as_owner=True, bound=60)
                self.assertIn(beyond + "\n", out, "the walk ends, and judges past the cycle")
                unmapped = self.run_block(py, bound=60)
                self.assertFalse([l for l in unmapped.splitlines()
                                  if "loop/loop/loop" in l or "../B/../A/../B/../A" in l],
                                 "each entry is visited once; a longer spelling has only its directories judged")
                self.d = os.path.dirname(d)

    def shells(self):
        """dash and bash, each once, as installed here."""
        found = {}
        for sh in ("/bin/dash", "/usr/bin/dash", "/bin/bash", "/usr/bin/bash"):
            if os.path.exists(sh):
                found.setdefault(os.path.basename(sh), os.path.realpath(sh))
        return sorted(found.values())

    def test_every_link_along_a_chain_is_followed_in_both_shells(self):
        """a -> ../mid/b, mid/b -> <W>/c: c's tree is walked (it holds a writable
        directory); and a parent chain dirlink -> ../mid2/p, p -> <W>/marked/real2:
        the final target's writable parent is judged. Each link is its own visit."""
        root = self.d
        for shell in self.shells():
            with self.subTest(shell=shell):
                d = self.d = os.path.join(root, os.path.basename(shell))
                os.makedirs(d)
                os.makedirs(os.path.join(d, "c", "w"))
                os.chmod(os.path.join(d, "c", "w"), 0o777)
                os.makedirs(os.path.join(d, "marked", "real2", "x"))
                os.chmod(os.path.join(d, "marked"), 0o777)
                self.tree({"stdlib/a": "../mid/b", "mid/b": os.path.join(d, "c"),
                           "stdlib/c2root/dirlink": "../../mid2/p",
                           "mid2/p": os.path.join(d, "marked", "real2")})
                os.symlink(os.path.join(d, "marked", "real2", "x"), os.path.join(d, "stdlib", "lx"))
                with open(os.path.join(d, "marked", "real2", "x", "f"), "w") as f:
                    f.write("x")
                os.symlink(os.path.join(d, "stdlib", "c2root", "dirlink", "x", "f"), os.path.join(d, "stdlib", "via"))
                py = self.interpreter([os.path.join(d, "stdlib")] * 3)
                out = self.run_block(py, as_owner=True, bound=60, shell=shell)
                self.assertIn(os.path.join(d, "c", "w") + "\n", out, "the second hop's tree")
                self.assertIn(os.path.join(d, "marked") + "\n", out, "the second hop's directories")
                self.d = root

    def test_a_path_reaching_a_visited_target_still_has_its_own_directories_judged(self):
        """first.py -> safe/linked.py; second.py -> outside/alias/linked.py,
        outside/ 0777, outside/alias -> safe/. Both reach the same file; the
        second path's writable directory is judged in either order. With
        outside/ not writable, nothing about it is printed."""
        root = self.d
        for order, writable in ((("first", "second"), True), (("second", "first"), True), (("first", "second"), False)):
            with self.subTest(order=order, writable=writable):
                d = self.d = os.path.join(root, "-".join(order) + ("-w" if writable else "-safe"))
                os.makedirs(os.path.join(d, "safe"))
                with open(os.path.join(d, "safe", "linked.py"), "w") as f:
                    f.write("x")
                os.chmod(os.path.join(d, "safe", "linked.py"), 0o444)
                os.makedirs(os.path.join(d, "outside"))
                os.chmod(os.path.join(d, "outside"), 0o777 if writable else 0o755)
                self.tree({"outside/alias": os.path.join(d, "safe"),
                           "first-root/first.py": os.path.join(d, "safe", "linked.py"),
                           "second-root/second.py": os.path.join(d, "outside", "alias", "linked.py")})
                roots = [os.path.join(d, f"{o}-root") for o in order]
                py = self.interpreter([roots[0], roots[0], roots[1]])
                out = self.run_block(py, as_owner=True, bound=60)
                self.assertEqual(os.path.join(d, "outside") + "\n" in out, writable, out)
                self.d = root

    def test_on_macos_a_library_path_holding_whitespace_is_named(self):
        py = self.interpreter([self.d, self.d, self.d])
        self.stub("uname", "echo Darwin\n")
        env = self.stub("otool", "echo \"$1:\"; printf '\\t/usr/lib/a b.dylib (compatibility version 1.0.0)\\n'\n")
        self.assertIn("discovery failed: whitespace in /usr/lib/a b.dylib\n", self.run_block(py, env=env))

    def test_nested_directory_links_and_a_cycle_are_followed_once(self):
        """stdlib/sub -> outside (a directory link); outside/deeper -> elsewhere/,
        elsewhere/ 0777; elsewhere/back -> stdlib (a cycle)."""
        stdlib, outside, elsewhere = (os.path.join(self.d, n) for n in ("stdlib", "outside", "elsewhere"))
        for n in (stdlib, outside, elsewhere):
            os.mkdir(n)
        os.chmod(elsewhere, 0o777)
        os.symlink(outside, os.path.join(stdlib, "sub"))
        os.symlink(elsewhere, os.path.join(outside, "deeper"))
        os.symlink(stdlib, os.path.join(elsewhere, "back"))
        py = self.interpreter([stdlib, stdlib, stdlib])
        out = self.run_block(py, as_owner=True)
        self.assertIn(elsewhere + "\n", out, "a link found inside a linked directory is followed too")


if __name__ == "__main__":
    unittest.main()
