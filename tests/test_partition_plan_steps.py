"""host-setup --plan's partition section, on a systemd and on a launchd
host: the install-time validation (the writer's partition-judge through the
barrier, d3.3 §5(d) §2), then the bundle's provisioning under the job's own
lock (never flock(1), which macOS lacks). The runbook carries the
re-validation sentence."""

import dataclasses
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import host_setup as hs
import hub_supervise as hv
import host_steps
import partition_job as pj
import partition_setup as ps
import root_trust as rt
from test_hub_runtime import setUpModule, tearDownModule  # noqa: F401 -- the fixture's pins, restored
from test_hub_supervise import supervise
from test_partition_setup import doc

RUNBOOK = Path(__file__).absolute().parents[1] / "docs" / "TUTORIAL.md"


def plan(kind):
    d = supervise(doc(), kind)
    if kind == "launchd":
        d["partition"]["tools"].update({"git": ps.CLT_GIT, "git-remote-https": ps.CLT_GIT_REMOTE_HTTPS})
    spec = hs.load_spec(d)
    return spec, hs.render_plan(spec)


class PlanTest(unittest.TestCase):
    def judge_line(self, lines):
        found = [l for l in lines if " partition-judge " in l and not l.lstrip().startswith("#")]
        self.assertEqual(len(found), 1, found)
        return found[0]

    def fetch_line(self, lines):
        found = [l for l in lines if " partition-fetch " in l and not l.lstrip().startswith("#")]
        self.assertEqual(len(found), 1, found)
        return found[0]

    def test_each_system_prints_the_judge_then_the_provisioning(self):
        for kind in ("systemd", "launchd"):
            with self.subTest(kind):
                spec, lines = plan(kind)
                line = self.judge_line(lines)
                self.assertLess(lines.index(line), lines.index(self.fetch_line(lines)))
                self.assertFalse([l for l in lines if "partition-provision" in l and not l.startswith("#")])
                self.assertFalse([l for l in lines if "flock" in l])
                self.assertIn("# any operating-system, interpreter or docker update, before the next weekly run. "
                              "root-trust.sh judges", lines)

    def test_the_judge_line_is_the_barrier_grammar_with_the_writer_in_its_own_vector(self):
        """d3.3 §5(d) §2.2: the anchor's sudo, root-trust.sh's root_exec with
        the writer's pin, trusted-exec with the partition tools, then the
        writer's own interpreter in its one exact vector; no shell after
        `--`, and no ldd, otool or xcode-select anywhere."""
        for kind in ("systemd", "launchd"):
            with self.subTest(kind):
                spec, lines = plan(kind)
                p, sec = spec.partition, spec.secrets
                argv = shlex.split(self.judge_line(lines))
                cut = argv.index("--")
                py = p.tools["python3"]
                pin = ["--docker-sha256", p.tool_sha256["docker"]] if kind == "launchd" else []
                self.assertEqual(argv[cut + 1:], [py, "-I", "-S", "-B", sec.writer, "partition-judge",
                                                  "--python3", py, "--docker", p.tools["docker"]] + pin,
                                 "the judge checks the partition section's docker pin where it has one")
                self.assertEqual(argv, rt.typed_argv(sec.writer_dir + "/" + rt.NAME, sec.writer_sha256, py,
                                                     sec.writer, list(p.tools.values()), argv[cut + 1:],
                                                     pins=p.pins))
                self.assertFalse(set(argv[cut + 1:]) & {"/bin/sh", "sh", "bash"})
                # §1.7's read-only git fact line is the one place xcode-select -p is printed.
                text = "\n".join(l for l in lines if '"$D/git-exec/git" --version' not in l)
                for tool in ("ldd", "otool", "xcode-select", "closure.env", "discover.sh", "judge.sh"):
                    self.assertNotIn(tool, text)

    def test_the_fetch_line_binds_one_value_to_both_places_on_each_system(self):
        """d3.3 §5(d) §1.1: each of git and its helper, rendered
        once, is the --also trusted-exec judges and the verb's argument."""
        for kind in ("systemd", "launchd"):
            with self.subTest(kind):
                spec, lines = plan(kind)
                p, sec = spec.partition, spec.secrets
                argv = shlex.split(self.fetch_line(lines))
                cut = argv.index("--")
                also = [argv[i + 1] for i in range(cut) if argv[i] == "--also"]
                verb = argv[cut + 1:]
                self.assertEqual(also, [verb[verb.index("--git") + 1], verb[verb.index("--git-remote-https") + 1]])
                self.assertEqual(also, [p.tools["git"], p.tools["git-remote-https"]])
                self.assertEqual(argv, rt.typed_argv(sec.writer_dir + "/" + rt.NAME, sec.writer_sha256,
                                                     p.tools["python3"], sec.writer, list(p.tools.values()), verb,
                                                     also=also))
                self.assertEqual(verb[verb.index("--pin") + 1], sec.clones["deploy"]["sha"])

    def test_a_launchd_host_records_the_command_line_tools_git_never_the_shim(self):
        """d3.3 §5(d) §1.1: /usr/bin/git on darwin is the xcrun
        shim, which execs another git by absolute path."""
        for git, helper in (("/usr/bin/git", ps.CLT_GIT_REMOTE_HTTPS),
                            (ps.CLT_GIT, "/usr/local/libexec/git-core/git-remote-https")):
            with self.subTest(git=git, helper=helper):
                d = supervise(doc(), "launchd")
                d["partition"]["tools"].update({"git": git, "git-remote-https": helper})
                with self.assertRaisesRegex(hs.SpecError, "xcrun shim"):
                    hs.load_spec(d)
        d = supervise(doc(), "systemd")
        self.assertEqual(hs.load_spec(d).partition.tools["git"], "/usr/bin/git", "the rule is darwin's alone")

    def test_the_git_fact_line_runs_under_exactly_git_env(self):
        """d3.3 §5(d) §1.7: the line's environment is git_env's own, rendered
        from it, printed before the fetch; run here as the operator, it makes
        and removes its own scratch directory and reports git's version."""
        for kind in ("systemd", "launchd"):
            with self.subTest(kind):
                spec, lines = plan(kind)
                [i] = [i for i, l in enumerate(lines) if '"$D/git-exec/git" --version' in l]
                self.assertLess(i, lines.index(self.fetch_line(lines)))
                env = lines[i].split("/usr/bin/env -i ", 1)[1].split(' "$D/git-exec/git" --version')[0]
                self.assertEqual(dict(kv.split("=", 1) for kv in shlex.split(env.replace('"$D', '"/D'))),
                                 host_steps.git_env("/D"))
                self.assertEqual(lines[i].startswith(host_steps.XCODE_SELECT + " -p; "), kind == "launchd")
                self.assertNotIn("sudo", lines[i])
                self.assertNotIn("clone", lines[i])
        git, helper = shutil.which("git"), "/usr/lib/git-core/git-remote-https"
        if git and os.path.exists(helper):
            p = dataclasses.replace(spec.partition, tools=dict(spec.partition.tools, git=git,
                                                               **{"git-remote-https": helper}))
            line = pj.git_fact_steps(p, "systemd")[-1]
            tmp = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, tmp, True)
            out = subprocess.run(["/bin/sh", "-c", line], capture_output=True, text=True, timeout=60,
                                 env={"PATH": "/usr/bin:/bin", "TMPDIR": tmp})
            self.assertTrue(out.stdout.startswith("git version "), out.stdout + out.stderr)
            self.assertEqual(os.listdir(tmp), [], "the scratch directory is removed")

    def test_the_sentinel_is_the_writers(self):
        self.assertEqual(pj.SENTINEL, host_steps.JUDGE_SENTINEL)


class RunbookTest(unittest.TestCase):
    def test_the_runbook_carries_the_sentence(self):
        flat = re.sub(r"\s+", " ", RUNBOOK.read_text())
        self.assertIn("Run this at install AND again after any operating-system, interpreter or docker update, "
                      "before the next weekly run.", flat)
        self.assertIn("partition-judge", flat)
        for retired in ("discover.sh", "judge.sh", "closure.env", "amap-judge."):
            self.assertNotIn(retired, flat)


if __name__ == "__main__":
    unittest.main()
