"""partition_job: the weekly job's unit and the operator's root steps before
it. The argv is the job's trusted input; the units start it weekly and once
after boot; the steps provision from the public repository, never a local
clone, and check the tools with the operating system's own."""

import dataclasses
import hashlib
import os
import plistlib
import subprocess
import sys
import tempfile
import unittest

import partition_job as pj
import partition_setup as ps

P = ps.PartitionSpec(evidence_dir="/opt/ex/ev", scratch_dir="/opt/ex/scratch", weekday=2, hour=4,
                     exec_root="/opt/ex/exec", tools={"python3": "/usr/bin/python3", "docker": "/usr/bin/docker"})
DOC = b'{"host_setup": {}}'
ARGV = pj.job_argv(P, writer="/opt/amap/host_steps.py", host="alpha", document="/opt/ov/overlay.json",
                   document_bytes=DOC)


class JobTest(unittest.TestCase):
    def test_the_argv_carries_every_input_the_job_must_not_take_from_operator_files(self):
        self.assertEqual(ARGV[:5], ["/usr/bin/python3", "-I", "-S", "-B", "/opt/amap/host_steps.py"])
        opts = dict(zip(ARGV[6::2], ARGV[7::2]))
        self.assertEqual(opts, {"--exec-root": "/opt/ex/exec", "--host": "alpha", "--document": "/opt/ov/overlay.json",
                                "--document-sha256": hashlib.sha256(DOC).hexdigest()})

    def test_systemd_runs_it_weekly_and_once_after_boot(self):
        files = dict(pj.rendered("systemd", P, ARGV))
        timer = files["/etc/systemd/system/amap-partition-weekly.timer"].decode()
        self.assertIn("OnCalendar=Tue *-*-* 04:00:00", timer)
        self.assertIn(f"OnBootSec={pj.BOOT_DELAY_S}", timer)
        service = files["/etc/systemd/system/amap-partition-weekly.service"].decode()
        self.assertIn("ExecStart=/usr/bin/python3 -I -S -B /opt/amap/host_steps.py partition-weekly", service)

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
        text = "\n".join(pj.validation_steps(P))
        for words in ("env -i /usr/bin/python3 -I -S -B", "find ", "ldd ", "otool -L", "xcode-select -p",
                      "! -user root -o -perm -g+w -o -perm -o+w", "DESTSHARED", ".zip", "-maxdepth 0", "find -L ",
                      "discovery failed", 'realpath "$p"', 'uname)" = Darwin'):
            self.assertIn(words, text)

    def block(self, python, docker, then=""):
        """The steps run as the operator runs them: one shell block, in order."""
        spec = dataclasses.replace(P, tools={"python3": python, "docker": docker})
        script = "\n".join(pj.validation_steps(spec)) + "\n" + then
        return subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, timeout=180).stdout

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
        self.assertEqual(self.block(py, sh), "", "an absent optional zip is not a finding")

    def test_the_list_the_checks_consume_is_ldds_on_linux_with_every_link_and_the_loader(self):
        py, sh = self.healthy()
        listed = self.block(py, sh, 'echo "$L"').split()
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
        the owner check already prints, so the target check runs here with
        just the discovery lines before it."""
        py, _ = self.healthy()
        with tempfile.TemporaryDirectory() as t:
            d = os.path.realpath(t)
            target, link = os.path.join(d, "real-docker"), os.path.join(d, "docker")
            with open(target, "w") as f:
                f.write("x")
            os.chmod(target, 0o666)
            os.symlink(target, link)
            spec = dataclasses.replace(P, tools={"python3": py, "docker": link})
            steps = pj.validation_steps(spec)
            targets = [l for l in steps if l.startswith("find -L ")]
            if len(targets) != 1:
                self.fail(f"the steps hold {len(targets)} link-target check(s)")
            script = "\n".join([l for l in steps if l.startswith(("P=", "Z=", "T=", "if "))] + targets)
            out = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, timeout=180).stdout
            self.assertIn(link + "\n", out, "the target is judged through the link")

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

if __name__ == "__main__":
    unittest.main()
