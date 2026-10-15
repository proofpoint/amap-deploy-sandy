"""partition_job: the weekly job's unit and the operator's root steps before
it. The argv is the job's trusted input; the units start it weekly and once
after boot; the steps provision from the public repository, never a local
clone, and check the tools with the operating system's own."""

import hashlib
import plistlib
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
                      "! -user root -o -perm -g+w -o -perm -o+w"):
            self.assertIn(words, text)


if __name__ == "__main__":
    unittest.main()
