"""host-setup --plan's partition section, on a systemd and on a launchd
host: the install-time validation (the writer's partition-judge through the
barrier, d3.3 §5(d) §2), then the bundle's provisioning under the job's own
lock (never flock(1), which macOS lacks). The runbook carries the
re-validation sentence."""

import re
import shlex
import unittest
from pathlib import Path

import host_setup as hs
import hub_supervise as hv
import host_steps
import partition_job as pj
import root_trust as rt
from test_hub_runtime import setUpModule, tearDownModule  # noqa: F401 -- the fixture's pins, restored
from test_hub_supervise import sup_section
from test_partition_setup import doc

RUNBOOK = Path(__file__).absolute().parents[1] / "docs" / "TUTORIAL.md"


def plan(kind):
    d = doc()
    d[hv.SECTION] = sup_section(kind)
    spec = hs.load_spec(d)
    return spec, hs.render_plan(spec)


class PlanTest(unittest.TestCase):
    def judge_line(self, lines):
        found = [l for l in lines if " partition-judge " in l and not l.lstrip().startswith("#")]
        self.assertEqual(len(found), 1, found)
        return found[0]

    def test_each_system_prints_the_judge_then_the_provisioning(self):
        for kind in ("systemd", "launchd"):
            with self.subTest(kind):
                spec, lines = plan(kind)
                p = spec.partition
                line = self.judge_line(lines)
                provision = [i for i, l in enumerate(lines) if "partition-provision" in l and not l.startswith("#")]
                self.assertTrue(provision)
                self.assertLess(lines.index(line), provision[0])
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
                self.assertEqual(argv[cut + 1:], [py, "-I", "-S", "-B", sec.writer, "partition-judge",
                                                  "--python3", py, "--docker", p.tools["docker"]])
                self.assertEqual(argv, rt.typed_argv(sec.writer_dir + "/" + rt.NAME, sec.writer_sha256, py,
                                                     sec.writer, list(p.tools.values()), argv[cut + 1:]))
                self.assertFalse(set(argv[cut + 1:]) & {"/bin/sh", "sh", "bash"})
                text = "\n".join(lines)
                for tool in ("ldd", "otool", "xcode-select", "closure.env", "discover.sh", "judge.sh"):
                    self.assertNotIn(tool, text)

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
