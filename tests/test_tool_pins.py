"""DS2-TOOL-SHA-PIN (d3.3 §4 C3): "Hand-placed (the Mac's planned root-owned
client): its sha256 is pinned in the document, and trusted-exec checks it as
an extra step." The document's per-section `tool_sha256`, the rules across
sections, the pins every generated trusted-exec invocation carries, the
writer's own checks before an engine call, verify's row, and the re-pin
order."""

import hashlib
import os
import plistlib
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace

import host_setup as hs
import host_steps as st
import hub_supervise as hv
import partition_job as pj
import partition_setup as ps
import root_trust as rt
import router_health as rh
import secret_setup as ss
from test_hub_runtime import setUpModule, tearDownModule  # noqa: F401 -- the fixture's pins, restored
from test_hub_supervise import DOCKER_PIN, supervise
from test_partition_setup import doc

OTHER = "ab" * 32


def document(kind, partition=True, secrets_pin=None, partition_pin=None):
    """A whole document of `kind`; the pins as given (None leaves the fixture's)."""
    d = supervise(doc(partition=ps_section() if partition else None), kind)
    if partition and kind == "launchd":
        d["partition"]["tools"].update({"git": ps.CLT_GIT, "git-remote-https": ps.CLT_GIT_REMOTE_HTTPS})
    for name, pin in (("secrets", secrets_pin), ("partition", partition_pin)):
        if pin is not None and name in d:
            d[name][rt.TOOL_SHA256] = pin
    return d


def ps_section():
    import test_partition_setup as tps
    return tps.PART


def load(d):
    return hs.load_spec(d)


class LoadTest(unittest.TestCase):
    def refuses(self, d, words):
        with self.assertRaises(hs.SpecError) as e:
            load(d)
        self.assertIn(words, str(e.exception))

    def test_a_section_pin_is_64_lower_case_hex_for_a_tool_it_records(self):
        for name in ("secrets", "partition"):
            with self.subTest(section=name):
                for bad in ("A" * 64, "0" * 63, 64, None):
                    d = document("systemd")
                    d[name][rt.TOOL_SHA256] = {"docker": bad}
                    self.refuses(d, f"{name}.tool_sha256.docker must be 64 lower-case hex digits")
                d = document("systemd")
                d[name][rt.TOOL_SHA256] = {"nosuch": OTHER}
                self.refuses(d, f"{name}.tool_sha256.nosuch pins a tool {name}.tools does not record")
                d = document("systemd")
                d[name][rt.TOOL_SHA256] = [OTHER]
                self.refuses(d, f"{name}.tool_sha256 must map")

    def test_two_names_recording_one_path_cannot_claim_two_hashes(self):
        d = document("systemd")
        d["secrets"]["tools"]["docker2"] = d["secrets"]["tools"]["docker"]
        d["secrets"][rt.TOOL_SHA256] = {"docker": OTHER, "docker2": DOCKER_PIN}
        self.refuses(d, "pins " + d["secrets"]["tools"]["docker"] + " twice, with different sha256s")

    def test_a_launchd_host_pins_docker_in_each_present_section(self):
        self.assertEqual(load(document("launchd")).secrets.tool_sha256, {"docker": DOCKER_PIN})
        d = document("launchd")
        del d["secrets"][rt.TOOL_SHA256]
        self.refuses(d, "on a launchd host, secrets.tool_sha256.docker must pin the hand-placed docker client")
        d = document("launchd")
        del d["partition"][rt.TOOL_SHA256]
        self.refuses(d, "on a launchd host, partition.tool_sha256.docker must pin the hand-placed docker client")
        # Codex: an absent partition section is not required just to carry a second pin.
        spec = load(document("launchd", partition=False))
        self.assertIsNone(spec.partition)

    def test_linux_pins_are_optional(self):
        spec = load(document("systemd"))
        self.assertEqual((spec.secrets.pins, spec.partition.pins), ({}, {}))

    def test_a_path_both_sections_record_carries_one_pin_in_both(self):
        def shared(**pins):
            d = document("systemd", **pins)
            d["partition"]["tools"]["docker"] = d["secrets"]["tools"]["docker"]
            return d
        path = document("systemd")["secrets"]["tools"]["docker"]
        for s_pin, p_pin in (({"docker": OTHER}, None), (None, {"docker": OTHER}),
                             ({"docker": OTHER}, {"docker": DOCKER_PIN})):
            with self.subTest(secrets=s_pin, partition=p_pin):
                self.refuses(shared(secrets_pin=s_pin, partition_pin=p_pin),
                             f"{path} is recorded by secrets and partition but pinned differently")
        spec = load(shared(secrets_pin={"docker": OTHER}, partition_pin={"docker": OTHER}))
        self.assertEqual(spec.secrets.pins, spec.partition.pins)

    def test_same_name_different_paths_are_independent(self):
        d = document("launchd")
        d["partition"]["tools"]["docker"] = "/opt/other/bin/docker"
        d["partition"][rt.TOOL_SHA256] = {"docker": OTHER}
        spec = load(d)
        self.assertEqual(spec.secrets.pins, {spec.secrets.tools["docker"]: DOCKER_PIN})
        self.assertEqual(spec.partition.pins, {"/opt/other/bin/docker": OTHER})


class PinArgsTest(unittest.TestCase):
    PINS = {"/d/docker": DOCKER_PIN, "/d/git": OTHER}

    def test_only_the_lines_own_tools_once_each(self):
        self.assertEqual(rt.pin_args(self.PINS, "/d/docker"), ["--sha256", f"/d/docker={DOCKER_PIN}"])
        self.assertEqual(rt.pin_args(self.PINS, "/usr/bin/python3", ["/d/docker"]),
                         ["--sha256", f"/d/docker={DOCKER_PIN}"], "an --also tool is pinned")
        self.assertEqual(rt.pin_args(self.PINS, "/d/docker", ["/d/docker", "/d/git"]),
                         ["--sha256", f"/d/docker={DOCKER_PIN}", "--sha256", f"/d/git={OTHER}"])
        self.assertEqual(rt.pin_args(self.PINS, "/usr/bin/python3"), [], "never a pin for a tool the line does not run")

    def test_trusted_exec_parses_what_is_rendered(self):
        args = rt.trusted_exec_args(["/d/docker", "/usr/bin/sudo"], ["/d/docker", "ps"], pins=self.PINS)
        self.assertEqual(args, ["trusted-exec", "--tool", "/d/docker", "--sha256", f"/d/docker={DOCKER_PIN}", "--",
                                "/d/docker", "ps"])
        seen = []
        self.addCleanup(setattr, st, "trusted_exec", st.trusted_exec)
        st.trusted_exec = lambda argv, also, shas, tools=(): seen.append((argv, also, shas, tools))
        st._trusted_exec_main(args)
        self.assertEqual(seen, [(["/d/docker", "ps"], [], {"/d/docker": DOCKER_PIN}, ["/d/docker"])])

    def test_the_writer_reads_the_member_root_trust_names(self):
        self.assertEqual(st.TOOL_SHA256, rt.TOOL_SHA256)


def _te(tokens):
    """(opts, argv) for each trusted-exec in `tokens`, and in any token that is itself a command string."""
    out = []
    for i, t in enumerate(tokens):
        if t == "trusted-exec":
            cut = tokens.index("--", i)
            out.append((tokens[i + 1:cut], tokens[cut + 1:]))
        elif "trusted-exec " in t:
            out += _te(shlex.split(t))
    return out


def invocations(spec):
    """(where, opts, argv) for every trusted-exec invocation this host's
    renderers produce: the plan and hub-start-check's lines, every placed
    supervision file, the weekly job's argv and units, and the activation
    steps. The wrapper's variables are read back to their values."""
    from test_root_walk import sites
    found = []
    for where, line in sites(spec):
        if line and not line.startswith("#"):
            found += [(where, o, a) for o, a in _te(shlex.split(line, comments=True))]
    for path, data in hv.rendered(spec):
        if path.endswith(".plist"):
            found += [(path, o, a) for o, a in _te(plistlib.loads(data)["ProgramArguments"])]
        elif path == spec.supervision.hub.get("wrapper"):
            text = data.decode()
            env = {}
            for line in text.splitlines():
                if "=" in line and line.split("=", 1)[0] in ("DOCKER", "PY", "WR", "RT", "SHA"):
                    env["$" + line.split("=", 1)[0]] = shlex.split(line.split("=", 1)[1])[0]
            for line in text.splitlines():
                if "trusted-exec" in line:
                    toks = [env.get(t, t) for t in shlex.split(line.replace("{", " ").replace("}", " "))]
                    found += [(path, o, a) for o, a in _te(toks)]
        elif path.endswith((".service", ".timer")):
            for line in data.decode().splitlines():
                if line.startswith("Exec") and "trusted-exec" in line:
                    found += [(path, o, a) for o, a in _te(shlex.split(line.split("=", 1)[1].lstrip("-").replace("$$", "$")))]
    if spec.partition is not None:
        writer = spec.secrets.writer
        argv = pj.job_argv(spec.partition, writer=writer, writer_sha256=spec.secrets.writer_sha256, host="h",
                           document="/d/doc.json", document_bytes=b"{}", activation_bytes=b"{}")
        found += [("job", o, a) for o, a in _te(argv)]
        for path, data in pj.rendered(spec.supervision.kind, spec.partition, argv):
            if path.endswith(".plist"):
                found += [(path, o, a) for o, a in _te(plistlib.loads(data)["ProgramArguments"])]
            elif path.endswith(".service"):
                for line in data.decode().splitlines():
                    if line.startswith("ExecStart="):
                        found += [(path, o, a) for o, a in _te(shlex.split(line[len("ExecStart="):].replace("$$", "$")))]
        for line in pj.activation_steps(spec.partition, writer=writer, writer_sha256=spec.secrets.writer_sha256,
                                        tools=list(spec.partition.tools.values()), source="/d/a.json",
                                        activation_bytes=b"{}"):
            if not line.startswith("#"):
                found += [("activation", o, a) for o, a in _te(shlex.split(line))]
    return found


def parsed(opts):
    tools = [opts[i + 1] for i in range(0, len(opts), 2) if opts[i] == "--tool"]
    also = [opts[i + 1] for i in range(0, len(opts), 2) if opts[i] == "--also"]
    shas = [opts[i + 1] for i in range(0, len(opts), 2) if opts[i] == "--sha256"]
    return tools, also, shas


class WalkTest(unittest.TestCase):
    """Every generated trusted-exec invocation carries exactly the pins of
    its own section for the tools it runs (argv[0] and each --also), once
    each, and no other."""

    def walk(self, spec):
        sections = {tuple(sorted({t for t in sec.tools.values() if os.path.basename(t) != "sudo"})): sec
                    for sec in (spec.secrets, spec.partition) if sec is not None}
        pinned = 0
        for where, opts, argv in invocations(spec):
            tools, also, shas = parsed(opts)
            with self.subTest(where=where, argv=argv[:2]):
                self.assertEqual(2 * (len(tools) + len(also) + len(shas)), len(opts))
                sec = sections.get(tuple(sorted(tools)))
                self.assertIsNotNone(sec, "the line's own section's recorded set")
                want = rt.pin_args(sec.pins, argv[0], also)
                self.assertEqual(shas, want[1::2], "exactly the pins of the tools this line runs")
                self.assertEqual(len(shas), len(set(shas)))
                pinned += len(shas)
        return pinned

    def test_launchd_every_line_running_docker_carries_its_pin(self):
        spec = load(document("launchd"))
        clients = {spec.secrets.tools["docker"], spec.partition.tools["docker"]}
        self.assertGreater(self.walk(spec), 0)
        runs_docker = [(w, o, d) for w, o, a in invocations(spec) for d in clients
                       if a[0] == d or d in parsed(o)[1]]
        for wanted in ("wrapper", "plist", "job"):
            self.assertTrue([w for w, _, _ in runs_docker if wanted in w or (wanted == "wrapper" and
                                                                             w == spec.supervision.hub["wrapper"])],
                            f"the walk reaches a docker line in the {wanted}")
        for where, opts, client in runs_docker:
            with self.subTest(where=where):
                self.assertIn(f"{client}={DOCKER_PIN}", parsed(opts)[2])

    def test_systemd_unpinned_carries_no_pin_and_pinned_carries_it(self):
        self.assertEqual(self.walk(load(document("systemd"))), 0)
        spec = load(document("systemd", secrets_pin={"docker": OTHER}, partition_pin={"docker": OTHER}))
        self.assertGreater(self.walk(spec), 0)

    def test_distinct_section_clients_each_carry_their_own_pin(self):
        d = document("launchd")
        d["partition"]["tools"]["docker"] = "/opt/other/bin/docker"
        d["partition"][rt.TOOL_SHA256] = {"docker": OTHER}
        spec = load(d)
        self.assertGreater(self.walk(spec), 0)
        job = [o for w, o, a in invocations(spec) if w == "job"]
        self.assertEqual([parsed(o)[2] for o in job], [[f"/opt/other/bin/docker={OTHER}"]])

    def test_the_inner_checks_get_the_pin(self):
        spec = load(document("launchd"))
        weekly = hv.weekly_argv(spec)
        inner = shlex.split(weekly[-1])
        i = inner.index("probe-weekly")
        self.assertEqual(inner[inner.index("--docker-sha256", i) + 1], DOCKER_PIN)
        judge = [l for l in pj.validation_steps(spec.partition, writer=spec.secrets.writer,
                                                writer_sha256=spec.secrets.writer_sha256,
                                                tools=list(spec.partition.tools.values()))
                 if "partition-judge" in l and not l.startswith("#")]
        self.assertEqual(shlex.split(judge[0])[-2:], ["--docker-sha256", DOCKER_PIN])


class Tmp(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.d = t.name
        self.client = os.path.join(self.d, "docker")
        with open(self.client, "wb") as f:
            f.write(b"\x7fELF client bytes")
        os.chmod(self.client, 0o555)
        self.good = hashlib.sha256(b"\x7fELF client bytes").hexdigest()


class WriterChecksTest(Tmp):
    """The writer's own checks, before any closure discovery or engine call."""

    def stub_closure(self):
        called = []
        self.addCleanup(setattr, st, "startup_closure", st.startup_closure)
        self.addCleanup(setattr, st, "_trusted_tool", st._trusted_tool)
        st.startup_closure = lambda *a, **k: called.append(a) or {}
        st._trusted_tool = lambda p: os.path.realpath(p)
        return called

    def test_verified_tools_refuses_a_mismatch_before_the_closure(self):
        called = self.stub_closure()
        with self.assertRaisesRegex(st.Tooling, "is not the client the document pins"):
            st._verified_tools(sys.executable, self.client, OTHER)
        self.assertEqual(called, [], "no closure is computed for a client the pin refuses")
        self.addCleanup(setattr, st, "closure_problems", st.closure_problems)
        st.closure_problems = lambda c: []
        st._verified_tools(sys.executable, self.client, self.good)
        self.assertEqual(len(called), 1)

    def test_a_pinned_path_that_is_a_link_is_refused(self):
        self.stub_closure()
        link = os.path.join(self.d, "docker-link")
        os.symlink(self.client, link)
        with self.assertRaises(st.Tooling):
            st._verified_tools(sys.executable, link, self.good)

    def test_probe_weekly_refuses_a_mismatched_client_and_runs_nothing(self):
        self.stub_closure()
        ran = os.path.join(self.d, "ran")
        status = os.path.join(self.d, "status.json")
        argv = ["probe-weekly", status, "w-1", "--docker", self.client, "--docker-sha256", OTHER, "--",
                sys.executable, "-c", f"open({ran!r},'w')"]
        self.addCleanup(setattr, st, "closure_problems", st.closure_problems)
        st.closure_problems = lambda c: []
        with self.assertRaises(st.Refused) as e:
            st._probe_weekly_main(argv)
        self.assertEqual(e.exception.rule, "tools")
        self.assertFalse(os.path.exists(ran))
        self.assertFalse(os.path.exists(status), "nothing is recorded")

    def test_probe_weekly_usage(self):
        for opts in (["--docker-sha256", self.good], ["--docker", self.client, "--docker-sha256", "A" * 64],
                     ["--docker", self.client, "--docker-sha256", self.good, "--docker-sha256", self.good]):
            with self.subTest(opts=opts):
                with self.assertRaises(st.Refused) as e:
                    st._probe_weekly_main(["probe-weekly", os.path.join(self.d, "s"), "w-1", *opts, "--", "/bin/true"])
                self.assertEqual(e.exception.rule, "usage")

    def test_trusted_exec_refuses_the_rendered_mismatch_and_execs_nothing(self):
        execs = []
        self.addCleanup(setattr, st, "_trusted_tool", st._trusted_tool)
        self.addCleanup(setattr, st, "closure_problems", st.closure_problems)
        self.addCleanup(setattr, st, "exec_closure", st.exec_closure)
        st._trusted_tool = lambda p: os.path.realpath(p)
        st.closure_problems = lambda c, **k: []
        discovered = []
        st.exec_closure = lambda *a, **k: discovered.append(a) or {st.REQUIRED: [], st.LIBRARIES: [], st.OPTIONAL: []}
        with self.assertRaisesRegex(st.Tooling, "is not the client the document pins"):
            st.trusted_exec([self.client, "ps"], (), {self.client: OTHER}, tools=[self.client],
                            execv=lambda *a: execs.append(a))
        self.assertEqual((execs, discovered), ([], []), "refused before closure discovery and exec")


class VerifyRowTest(Tmp):
    def row(self, want, read=None, path=None):
        return ss.tool_pin_row("secrets", "docker", path or self.client, want, os.lstat, read)

    def test_match_mismatch_unreadable_and_link(self):
        self.assertEqual(self.row(self.good).result, rh.PASS, "the production reader, a regular file")
        self.assertEqual(self.row(OTHER).result, rh.FAIL)
        self.assertEqual(self.row(self.good, lambda p: rh.Unresolved("cannot read")).result, rh.UNKNOWN)
        link = os.path.join(self.d, "link")
        os.symlink(self.client, link)
        self.assertEqual(self.row(self.good, path=link).result, rh.FAIL,
                         "trusted-exec reads the pinned path without following a link")
        self.assertIn("is a link", ss.pin_digest(link), "the reader alone refuses the leaf, whatever lstat says")
        r = ss.tool_pin_row("secrets", "docker", os.path.join(self.d, "absent", "docker"), self.good,
                            lambda p: (_ for _ in ()).throw(PermissionError(13, "denied")))
        self.assertEqual(r.result, rh.UNKNOWN)
        os.chmod(self.client, 0o000)
        if os.geteuid() != 0:
            self.assertEqual(self.row(self.good).result, rh.UNKNOWN, "unreadable bytes are UNKNOWN")
        os.chmod(self.client, 0o555)

    def test_a_fifo_in_the_pinned_place_is_a_fail_and_never_a_hang(self):
        """Codex at b6f809b7: the production reader opens without blocking and
        refuses a non-regular inode, so verify finishes and reports it. Run in
        a child with a bound, so a regression is a timeout, not a hung suite."""
        fifo = os.path.join(self.d, "fifo")
        os.mkfifo(fifo)
        code = ("import os, sys; sys.path[:0] = [os.getcwd(), os.path.join(os.getcwd(), 'tests')]\n"
                "import secret_setup as ss, router_health as rh\n"
                f"r = ss.tool_pin_row('secrets', 'docker', {fifo!r}, {self.good!r}, os.lstat)\n"
                "print(r.result == rh.FAIL, ss.pin_digest(%r))" % fifo)
        try:
            p = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True, timeout=15,
                               cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        except subprocess.TimeoutExpired:
            self.fail("the pin reader blocked on a FIFO")
        self.assertEqual(p.stdout.split()[0] if p.stdout else p.stderr, "True", p.stderr)
        self.assertIn("is not a regular file", p.stdout)

    def test_verify_tools_adds_the_row_only_for_a_pinned_tool(self):
        spec = load(document("launchd"))
        s = spec.secrets
        rows = ss.verify_tools(s, os.lstat, os.path.realpath, lambda p: DOCKER_PIN)
        self.assertTrue(all(r.result == rh.PASS for r in rows if "tool_sha256" in r.claim))
        pin_rows = [r for r in rows if "tool_sha256" in r.claim]
        self.assertEqual(len(pin_rows), 1)
        self.assertIn(s.tools["docker"], pin_rows[0].claim)
        self.assertEqual([r for r in ss.verify_tools(load(document("systemd")).secrets, os.lstat, os.path.realpath,
                                                     lambda p: DOCKER_PIN) if "tool_sha256" in r.claim], [])

    def test_the_partition_section_has_its_own_row(self):
        p = load(document("launchd")).partition
        rows = ps.verify_tools(p, os.lstat, ss._owned_chain, os.path.realpath, lambda path: OTHER)
        pin_rows = [r for r in rows if "partition.tool_sha256.docker" in r.claim]
        self.assertEqual([r.result for r in pin_rows], [rh.FAIL])

    def test_a_live_call_is_refused_for_a_client_its_pin_refuses(self):
        s = load(document("launchd")).secrets
        ok = lambda *a, **k: [rh.check("x", rh.Fact("tool", True, "t"), True, "r")]
        self.addCleanup(setattr, ss, "_tool_rows", ss._tool_rows)
        self.addCleanup(setattr, ss, "_writer_rows", ss._writer_rows)
        ss._tool_rows = ok
        ss._writer_rows = ok
        self.addCleanup(setattr, ss, "tool_pin_row", ss.tool_pin_row)
        real = ss.tool_pin_row
        ss.tool_pin_row = lambda sec, n, p, w, lstat, read=None: real(sec, n, self.client, w, os.lstat)
        got = ss.live_refusal(s, digest=hs._sha256, closure=lambda s_: None)
        self.assertEqual(got, "not run: docker not the client the document pins")
        ss.tool_pin_row = lambda sec, n, p, w, lstat, read=None: real(sec, n, self.client, self.good, os.lstat)
        self.assertIsNone(ss.live_refusal(s, digest=hs._sha256, closure=lambda s_: None))


class RepinOrderTest(unittest.TestCase):
    """RE: the four steps, in their one order, with step 1's stop through the
    supervisor and never a bare docker stop."""

    def test_the_four_steps_in_order(self):
        for kind in ("launchd", "systemd"):
            with self.subTest(kind=kind):
                pins = {"docker": OTHER} if kind == "systemd" else None
                spec = load(document(kind, secrets_pin=pins, partition_pin=pins))
                lines = hs.render_plan(spec, document=("spec", "/srv/op/host-setup.json"))
                path = spec.secrets.tools["docker"]
                at = [lines.index(step.format(path=path)) for step in hv.REPIN_STEPS]
                self.assertEqual(at, sorted(at), "1, 2, 3, 4 in that order")
                self.assertEqual(at[1:], [at[1], at[1] + 1, at[1] + 2], "2, 3 and 4 follow one another")
                self.assertEqual(lines[at[0] - 1], hv.REPIN_HEADING.format(path=path))
                stop = lines[at[0] + 1:at[1]]
                self.assertTrue(all(l.startswith(hv.REPIN_LINE) for l in stop), "step 1's lines are comments")
                stop = [l[len(hv.REPIN_LINE):] for l in stop]
                sup = spec.supervision
                if kind == "launchd":
                    self.assertEqual(stop[0], hv.service_line(spec, "bootout", sup.hub["label"]))
                    self.assertEqual(stop[2], hv.until_stopped_line(spec))
                else:
                    self.assertEqual(stop, [hv.service_line(spec, "stop", os.path.basename(sup.hub["unit"]))])
                self.assertFalse([l for l in stop if " docker stop" in l or l.endswith("docker stop")])

    def test_no_runnable_plan_line_stops_the_hub(self):
        """RE B1 at b6f809b7: the re-pin order is not part of a plan run, so no
        non-comment line of plan() or render_plan stops or boots out [2]."""
        for kind in ("launchd", "systemd"):
            pins = {"docker": OTHER} if kind == "systemd" else None
            spec = load(document(kind, secrets_pin=pins, partition_pin=pins))
            sup = spec.supervision
            hub = sup.hub["label"] if kind == "launchd" else os.path.basename(sup.hub["unit"])
            stops = {hv.service_line(spec, "bootout", hub) if kind == "launchd" else hv.service_line(spec, "stop", hub),
                     hv.until_stopped_line(spec)}
            for where, lines in (("plan", hv.plan(spec, shlex.quote, "STEPS")),
                                 ("render_plan", hs.render_plan(spec, document=("spec", "/srv/op/host-setup.json")))):
                with self.subTest(kind=kind, where=where):
                    self.assertTrue([l for l in lines if l.startswith(hv.REPIN_LINE)], "the block is there, as comments")
                    runnable = [l for l in lines if l and not l.startswith("#")]
                    self.assertFalse(stops & set(runnable), "a plan run never stops the hub")
                    block = {l[len(hv.REPIN_LINE):] for l in lines if l.startswith(hv.REPIN_LINE)}
                    self.assertFalse(block & set(runnable), "no line of the re-pin block is runnable anywhere")

    def test_no_repin_steps_without_a_pin(self):
        lines = hs.render_plan(load(document("systemd")), document=("spec", "/srv/op/host-setup.json"))
        self.assertFalse([l for l in lines if l in hv.REPIN_STEPS or "To replace the pinned docker client" in l])


if __name__ == "__main__":
    unittest.main()
