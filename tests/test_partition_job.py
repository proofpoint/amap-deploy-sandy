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
                      "! -user root -o -perm -g+w -o -perm -o+w", "DESTSHARED", "/*.so", ".zip",
                      "-maxdepth 0", "find -L ", "discovery failed", 'realpath "$p"'):
            self.assertIn(words, text)

    def test_the_parent_chain_check_prints_a_directory_others_can_write_above_a_tool(self):
        with tempfile.TemporaryDirectory() as t:
            w = os.path.join(os.path.realpath(t), "w")
            os.mkdir(w)
            os.chmod(w, 0o777)
            tool = os.path.join(w, "python3")
            with open(tool, "w") as f:
                f.write("#!/bin/sh\nexit 1\n")
            os.chmod(tool, 0o755)
            spec = dataclasses.replace(P, tools={"python3": tool, "docker": os.path.realpath(sys.executable)})
            line = pj.validation_steps(spec)[-1]
            out = subprocess.run(["/bin/sh", "-c", line], capture_output=True, text=True, timeout=60).stdout
            self.assertIn(w + "\n", out)

    def test_the_linux_library_check_reaches_the_extension_modules_links_and_the_loader(self):
        if not os.path.exists("/usr/bin/ldd"):
            self.skipTest("no ldd here")
        spec = dataclasses.replace(P, tools={"python3": os.path.realpath(sys.executable), "docker": "/bin/sh"})
        line = next(l for l in pj.validation_steps(spec) if l.startswith("L=$(ldd "))
        out = subprocess.run(["/bin/sh", "-c", line + '\necho "$L"'], capture_output=True, text=True,
                             timeout=120).stdout
        self.assertIn("libssl", out, "an extension module's own link is listed")
        self.assertRegex(out, r"/ld-linux[^ \n]*\.so", "the loader is listed")

    def shell(self, starts, spec, holding=""):
        lines = [l for l in pj.validation_steps(spec) if l.startswith(starts) and holding in l]
        if len(lines) != 1:
            self.fail(f"the steps hold {len(lines)} line(s) starting {starts!r}")
        line = lines[0]
        return subprocess.run(["/bin/sh", "-c", line], capture_output=True, text=True, timeout=120).stdout

    def test_a_writable_target_behind_a_root_owned_link_is_printed(self):
        with tempfile.TemporaryDirectory() as t:
            d = os.path.realpath(t)
            target, link = os.path.join(d, "real-docker"), os.path.join(d, "docker")
            with open(target, "w") as f:
                f.write("x")
            os.chmod(target, 0o666)
            os.symlink(target, link)
            spec = dataclasses.replace(P, tools={"python3": "/nonexistent/python3", "docker": link})
            self.assertIn(link, self.shell("find -L ", spec), "the target is judged through the link")

    def test_a_discovery_that_fails_names_its_file(self):
        if not os.path.exists("/usr/bin/ldd"):
            self.skipTest("no ldd here")
        with tempfile.TemporaryDirectory() as t:
            d = os.path.realpath(t)
            script = os.path.join(d, "docker")
            with open(script, "w") as f:
                f.write("#!/bin/sh\n")
            os.chmod(script, 0o755)
            spec = dataclasses.replace(P, tools={"python3": os.path.realpath(sys.executable), "docker": script})
            out = self.shell("for f in ", spec, holding="ldd ")
            self.assertIn(f"discovery failed: {script}", out)
            self.assertNotIn(f"discovery failed: {os.path.realpath(sys.executable)}", out)

if __name__ == "__main__":
    unittest.main()
