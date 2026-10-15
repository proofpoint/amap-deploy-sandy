"""host-setup --plan's partition section, on a systemd and on a launchd
host: the install-time validation, then the bundle's provisioning under the
job's own lock (never flock(1), which macOS lacks), and nothing in the whole
plan that runs the vetted interpreter as root before the validation's step 3.
The runbook carries the re-validation sentence and every host-independent
command the section prints."""

import os
import re
import unittest
from pathlib import Path

import host_setup as hs
import hub_supervise as hv
import partition_job as pj
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
    def test_each_system_prints_the_validation_then_the_provisioning_under_the_writers_lock(self):
        for kind in ("systemd", "launchd"):
            with self.subTest(kind):
                spec, lines = plan(kind)
                p = spec.partition
                provision = (f"sudo {p.tools['python3']} -I -S -B {spec.secrets.writer} partition-provision "
                             f"{p.exec_root}")
                self.assertIn(provision, lines)
                self.assertFalse([l for l in lines if "flock" in l])
                step3 = [i for i, l in enumerate(lines) if l == f"sudo sh -c '{pj.step3(kind)}' sh \"$R\""]
                self.assertEqual(len(step3), 1, "step 3, exactly as rendered for this system")
                self.assertLess(step3[0], lines.index(provision))
                self.assertIn("# after any operating-system, interpreter or docker update, before the next weekly "
                              "run. Those updates", lines)

    def test_nothing_in_the_whole_plan_runs_the_vetted_interpreter_as_root_before_step_3(self):
        for kind in ("systemd", "launchd"):
            with self.subTest(kind):
                spec, lines = plan(kind)
                py = spec.partition.tools["python3"]
                names = {py, os.path.realpath(py)}
                three = [i for i, l in enumerate(lines) if l.startswith("sudo sh -c '") and "closure.env" in l][0]
                early = [l for l in lines[:three] if l.lstrip().startswith("sudo") and any(n in l for n in names)]
                self.assertEqual(early, [])
                later = [l for l in lines[three:] if l.startswith("sudo") and any(n in l for n in names)]
                self.assertTrue(later, "the provisioning runs it, after")

    def test_every_root_step_of_the_validation_touches_only_its_root_directory(self):
        for kind in ("systemd", "launchd"):
            with self.subTest(kind):
                spec, _ = plan(kind)
                steps = pj.validation_steps(spec.partition, kind)
                root = [l for l in steps if l.startswith("sudo") or l.startswith("R=$(sudo")
                        or l.startswith("printf")]
                self.assertEqual(len(root), 6, root)
                self.assertTrue(all('"$R' in l or "mktemp" in l for l in root), root)
                self.assertFalse([l for l in steps if "closure.env" in l and not l.startswith("sudo sh -c '")
                                  and not l.startswith(("#", "parse()", "body", "refuse()", "omits()"))
                                  and "$1" not in l])

    def test_discovery_runs_only_behind_the_identity_drop(self):
        self.assertEqual({k: v[:2] for k, v in pj.DROP.items()},
                         {"systemd": ("setsid -w", "runuser -u nobody --"),
                          "launchd": ('/usr/bin/perl -MPOSIX -e "POSIX::setsid() >= 0 or exit 1; exec @ARGV"',
                                      "/usr/bin/sudo -u nobody -g nobody")})
        for kind in ("systemd", "launchd"):
            with self.subTest(kind):
                detach, drop, env, home, sh = pj.DROP[kind]
                text = pj.step3(kind)
                self.assertEqual(text.count("discover.sh"), 1)
                self.assertIn(f"( cd / && {detach} {drop} {env} -i PATH={pj.DISCOVERY_PATH} {home} LC_ALL=C {sh} -c "
                              f"\"$(cat \"$1/discover.sh\")\" </dev/null 2>/dev/null ) | head -c "
                              f"{pj.CLOSURE_MAX + 1} > \"$1/closure.env\"", text)
                self.assertTrue(text.startswith(pj.DIGEST[kind] + ' "$1/judge.sha256" || '), "the digests first")
                self.assertIn(f'sh "$1/judge.sh" "$1/closure.env"', text, "by absolute path")
                self.assertNotIn("'", text)


class RunbookTest(unittest.TestCase):
    def test_the_runbook_carries_the_sentence_and_the_commands(self):
        text = RUNBOOK.read_text()
        flat = re.sub(r"\s+", " ", text)
        self.assertIn("Run these steps at install AND again after any operating-system, interpreter or docker "
                      "update, before the next weekly run.", flat)
        _, lines = plan("systemd")
        for line in ('R=$(sudo mktemp -d /tmp/amap-judge.XXXXXXXX)', 'sudo chmod 0400 "$R/judge.sh" "$R/discover.sh"',
                     f"sudo sh -c '{pj.step3('systemd')}' sh \"$R\"", f"sudo sh -c '{pj.step3('launchd')}' sh \"$R\""):
            with self.subTest(line=line[:40]):
                self.assertIn(line + "\n", text)
        self.assertIn('R=$(sudo mktemp -d /tmp/amap-judge.XXXXXXXX)', lines)


if __name__ == "__main__":
    unittest.main()
