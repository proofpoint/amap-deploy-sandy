"""The walk (d3.3 §5(d) §3.5): every line any site prints that names sudo
is the one rendered TXN line or a typed root line, and every typed line is
exactly the §3 grammar as root_trust.typed_argv builds it: the anchor's
sudo with no -n, the barrier, trusted-exec with its own section's recorded
tools, each --also a recorded tool, `--`, and then the writer in its one
exact vector or a recorded tool, never a shell.

The sites: render_plan on each system (ss, hr, hk, hv, ps and pj lines
among them), hub-start-check's start and restart lines for every state,
the NOT-RUNNING line, the enablement remedy, and the activation and
post-activation place steps."""

import itertools
import os
import shlex
import unittest

import activation_install as ai
import host_setup as hs
import hub_supervise as hv
import partition_postactivation as ppa
import partition_setup as ps
import root_trust as rt
from test_hub_runtime import setUpModule, tearDownModule  # noqa: F401 -- the fixture's pins, restored
from test_hub_supervise import supervise
from test_partition_setup import doc

SHELLS = {"/bin/sh", "sh", "bash", "/bin/bash", "zsh", "/bin/zsh"}


def built(kind):
    d = supervise(doc(), kind)
    if kind == "launchd":
        d["partition"]["tools"].update({"git": ps.CLT_GIT, "git-remote-https": ps.CLT_GIT_REMOTE_HTTPS})
    return hs.load_spec(d)


def sites(spec):
    """(where, line) for every line each site prints."""
    out = [("plan", l) for l in hs.render_plan(spec, document=("spec", "/srv/op/host-setup.json"))]
    sup = spec.supervision
    if sup.kind == "systemd":
        combos = [{"hub": h, "timer": hv.STOPPED} for h in (hv.STOPPED, hv.FAILED, hv.RUNNING)]
    else:
        combos = [{"weekly": w, "hub": h} for w, h in itertools.product(
            (hv.NOT_LOADED, hv.LOADED, hv.IN_PROGRESS), (hv.NOT_LOADED, hv.LOADED))]
    for states in combos:
        out += [("restart", l) for l in hv.restart_commands(spec, states, ("spec", "/srv/op/host-setup.json"))]
    out += [("start", l) for l in hv.start_commands(spec)]
    out.append(("not-running", hv.until_stopped_line(spec, ("overlay", "/srv/op/overlay.json"))))
    if sup.kind == "launchd":
        for c in hv.verify_enablement(spec, {}, gate=lambda: False, loaded=lambda l: True):
            out += [("remedy", part) for part in c.remedy.split("`")[1::2]]
    out.append(("activation", ai.place_step(spec, "/srv/op/run/router.activated.json", b"x")))
    out.append(("post-activation", ppa.place_line(spec, "/srv/op/run/a", "/opt/ex/ev/x", b"doc")))
    return out


class WalkTest(unittest.TestCase):
    def check_typed(self, spec, line):
        argv = shlex.split(line, comments=True)
        self.assertEqual(argv[0], rt.SUDO)
        self.assertNotEqual(argv[1], "-n", "a typed line prompts: no -n")
        n = 1 + len(rt.anchor())
        self.assertEqual(argv[1:n], rt.anchor())
        self.assertEqual(argv[n:n + 2], ["/bin/sh", "-c"])
        sha, py, writer, verb = argv[n + 4:n + 8]
        self.assertEqual((sha, writer, verb), (spec.secrets.writer_sha256, spec.secrets.writer, "trusted-exec"))
        cut = argv.index("--")
        opts = argv[n + 8:cut]
        tools = [opts[i + 1] for i in range(0, len(opts), 2) if opts[i] == "--tool"]
        also = [opts[i + 1] for i in range(0, len(opts), 2) if opts[i] == "--also"]
        self.assertEqual(len(tools) + len(also), len(opts) // 2)
        after = argv[cut + 1:]
        self.assertEqual(argv, rt.typed_argv(os.path.join(spec.secrets.writer_dir, rt.NAME), sha, py, writer, tools,
                                             after, also=also))
        sections = {"secrets": sorted({t for t in spec.secrets.tools.values() if os.path.basename(t) != "sudo"}),
                    "partition": sorted(set(spec.partition.tools.values()))}
        self.assertIn(sorted(tools), list(sections.values()), "the line's own section's recorded set")
        self.assertTrue(set(also) <= set(tools), "every --also is a recorded tool")
        self.assertNotIn(after[0], SHELLS)
        if after[0] == py:
            self.assertEqual(after[1:5], ["-I", "-S", "-B", writer])
        else:
            self.assertIn(after[0], tools)
            self.assertNotIn(os.path.basename(after[0]), {"launchctl", "systemctl", "python3"})

    def test_every_line_naming_sudo_is_txn_or_a_typed_line(self):
        for kind in ("systemd", "launchd"):
            spec = built(kind)
            found = sites(spec)
            plan_code = [l for w, l in found if w == "plan" and l and not l.startswith("#")]
            txn = plan_code[1]
            self.assertTrue(txn.startswith(" ".join(rt.OPERATOR_ENV)))
            typed = 0
            for where, line in found:
                if "sudo" not in line or line.startswith("#") or line == txn:
                    continue
                with self.subTest(kind=kind, where=where, line=line[-70:]):
                    self.assertNotIn("sudo -n", line)
                    self.check_typed(spec, line)
                    typed += 1
            self.assertGreater(typed, 0)

    def test_no_site_prints_a_bare_root_command(self):
        for kind in ("systemd", "launchd"):
            spec = built(kind)
            clone_writer = spec.secrets.clones["deploy"]["path"] + "/host_steps.py"
            code = [(w, l) for w, l in sites(spec) if l and not l.startswith("#")]
            for i, (where, line) in enumerate(code):
                with self.subTest(kind=kind, where=where, line=line[:70]):
                    self.assertFalse(line.startswith(("python3 ", "install ", "launchctl ", "systemctl ", "sudo ")))
                    for bare in (" launchctl ", " systemctl "):
                        self.assertFalse(line.startswith(rt.SUDO + bare))
                    if clone_writer in line:
                        self.assertIn(i, (0, 1), "the clone's writer only in step 1 and TXN")


if __name__ == "__main__":
    unittest.main()
