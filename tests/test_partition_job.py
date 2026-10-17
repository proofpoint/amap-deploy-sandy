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


if __name__ == "__main__":
    unittest.main()
