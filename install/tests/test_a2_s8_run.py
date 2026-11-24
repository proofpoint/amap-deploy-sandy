"""S8's run (a2_s8_run): step 1 on a real run record (a2_record.Run, so every receipt passes the real 3.3 reader),
step 3, and steps 5-7 against a stateful docker fake, with STATE_* on every refusal after a write.

FAKE-FIDELITY-RULE:
- docker, run.sh (through sg), date, getent: FAKED. The fake refuses any argv or account S8 does not send. docker
  inspect's State field names are RL's (2b79f2e1), and Mounts, HostConfig.GroupAdd and Privileged are docker's
  inspect names; real captures of all of them are PENDING (loop-VM items, d3.1 section 6).
- RL's status.json: RL's REAL first-poll capture (rl_capture, 2a7b2a3a), with transport_plugin added and the
  instance renamed for the "admitting" case.
- RE's obs log lines: RE's REAL captures S1 (startup) and B1 (backoff), with link and plugin set to this fixture's;
  hub-status.json: RE's REAL H1 shape, with the progress, start time and plugin varied.
- Steps 2 and 4 and section 3(a) (a2_s8, REAL-PROBED in test_a2_s8) are replaced here by their result, except in
  ReadOnlyTest, which drives read_only over stand-ins of each to pin its own checks.
"""

import json
import os
import shutil
import types
import unittest

import a2fix
import a2_main
import a2_guard
import a2_record
import a2_rundir
import a2_s6_env as e6
import a2_s8 as S
import a2_s8_re as re8
import a2_s8_run as R
import re_capture
import rl_capture
import test_a2_s6_env as TE
import test_a2_s6_render as TR
import test_a2_s8 as T8
import test_a2_stages as TS
from a2_causes import Refusal

#: What reaches S8 as an interrupt: the runner's own stop signals (a2_main.RunStopped), Ctrl-C and SystemExit.
INTERRUPTS = (a2_main.RunStopped, KeyboardInterrupt, SystemExit)

RID = TS.RID
HOME, RHOME = TE.GOOD["agent_home"], TE.GOOD["relay_home"]
ENV = dict(e6.environment(**TE.GOOD))
ROUTER = TR.render()
PIN = ROUTER["transport_plugin"]["sha256"]
RL_IMAGE, RE_IMAGE = "sha256:" + "a" * 64, "sha256:" + "b" * 64
RL_ID, RE_ID = "1" * 64, "2" * 64
DOCKER_GID = 988
#: The fake clock starts at 2026-11-23T03:00:00Z, so docker's and the documents' instants line up with it.
T0 = 1_795_402_800.0
STARTED = "2026-11-23T03:00:00.250000000Z"
LATER = "2026-11-23T03:00:01.000000Z"
STOP_T = str(re8.stop_timeout(ENV))
SLUGS = ["planner-a", "canary-a"]


def iso(t):
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(int(t))) + ".%06dZ" % int((t % 1) * 1e6)


def status(names=SLUGS, plugin=True, started=LATER, polls=1):
    doc = json.loads(rl_capture.STATUS_FIRST_POLL)
    inst = doc["instances"].pop("planner")
    doc["instances"] = {n: dict(inst) for n in names}
    doc["admitted"] = list(names)
    doc["polls"] = polls
    doc["process_started_ts"] = started
    if plugin:
        doc["transport_plugin"] = {"path": ROUTER["transport_plugin"]["path"], "sha256": PIN}
    return doc


def startup_line(**change):
    rec = json.loads(re_capture.S1)
    rec.update(link=ENV["HOP_LINK"], plugin_sha256=PIN)
    rec.update(change)
    return json.dumps(rec).encode()


def hub(progress, started="2026-11-23T04:00:00.000000Z", plugin=PIN):
    doc = json.loads(re_capture.H1)
    doc.update(progress=progress, process_started_ts=started, transport_plugin={"sha256": plugin})
    return json.dumps(doc).encode()


def measured():
    return {"home": HOME, "relay_home": RHOME, "uid": 1000, "gid": 1000, "relay_uid": 1001, "relay_gid": 1001,
            "hop_gid": 1500, "env": ENV, "router": ROUTER, "state_dir": ROUTER["state_dir"],
            "docker_gid": DOCKER_GID}


class Clock:
    def __init__(self):
        self.t = T0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


class Docker:
    """One VM's docker, run.sh and tools, as S8 calls them (agent account; the ledger stat as the relay account).
    Containers are created by run.sh and RE's run, and stopped by docker stop; each answer can be changed per case."""

    def __init__(self, clock, vm="vm-a-t"):
        self.clock, self.vm, self.calls, self.has_written = clock, vm, [], False
        self.containers = {}
        self.ledger = "no_init"
        self.rl_rc, self.re_rc, self.init_out = 0, 0, ("outcome_ledger: initialised %s\n" % ENV["RELAY_LEDGER_DIR"])
        self.rl_extra = {}
        self.re_mounts, self.re_extra = [], {}
        #: The relay-account stat of the ledger directory, as stat -c '%u %g %a %F' prints it.
        self.ledger_stat = b"1001 1001 700 directory\n"
        #: Each call's layer timeout_s (None when S8 passes none).
        self.timeouts = []
        #: realpath -e as the agent account: a source maps to itself unless named here (its target, or None: missing).
        self.links = {}
        self.rl_mounts = [{"Type": "bind", "Source": HOME + "/.amap-router"},
                          {"Type": "bind", "Source": ROUTER["state_dir"]}]
        self.status = lambda t: json.dumps(status()).encode() if t >= T0 + 4 else b""
        self.logs = lambda t: (b"plain text line\n" + startup_line() + b"\n", b"")
        self.hub = lambda t: hub(1 + int((t - T0) // 5))
        self.re_exit_at = None
        #: Whether an init that prints RE's line really initialises the ledger.
        self.init_takes = True

    def wrote(self, stage):
        """True only for START once has_written is set, as the real layer answers per stage (gate B's note N3)."""
        return stage == "START" and self.has_written

    def _container(self, name, cid, mounts, **extra):
        doc = {"Id": cid, "Created": iso(self.clock.t), "RestartCount": 0, "Mounts": mounts,
               "HostConfig": {"GroupAdd": [str(1500)], "Privileged": False},
               "State": {"Status": "running", "Restarting": False, "StartedAt": STARTED}}
        doc.update(extra)
        self.containers[name] = doc

    def exec(self, vm, argv, *, account, stage, writes, stdin=None, timeout_s=None):
        assert vm == self.vm and stage == "START" and stdin is None, (vm, argv)
        self.calls.append((list(argv), account, writes))
        self.timeouts.append(timeout_s)
        if writes:
            self.has_written = True
        t, D = self.clock.t, R.DOCKER
        if argv == [R.DATE, "+%s.%N"] and account == "agent" and not writes:
            return 0, b"%.9f\n" % t, b""
        if argv[:3] == ["/usr/bin/realpath", "-e", "--"] and account == "agent" and not writes:
            # realpath -e prints each resolved path in order, and exits 1 at the first that does not resolve.
            out = b""
            for path in argv[3:]:
                real = self.links.get(path, path)
                if real is None:
                    return 1, out, b"realpath: " + path.encode() + b": No such file or directory\n"
                out += real.encode() + b"\n"
            return 0, out, b""
        if argv == [R.GETENT, "group", "docker"] and account == "agent":
            return 0, b"docker:x:%d:agent\n" % DOCKER_GID, b""
        if argv[:3] == [R.SG, "hop", "-c"] and len(argv) == 4 and account == "agent" and writes:
            assert argv[3] == R.rl_argv({"hop_group": "hop"}, measured(), RL_IMAGE)[3], argv[3]
            if self.rl_rc == 0:
                self._container(S.RL_NAME, RL_ID, self.rl_mounts, **self.rl_extra)
            return self.rl_rc, b"", b"" if self.rl_rc == 0 else b"run.sh: refused\n"
        if argv[:2] == [D, "inspect"] and len(argv) == 3 and account == "agent" and not writes:
            c = self.containers.get(argv[2])
            if c is None:
                return 1, b"[]\n", b"Error: No such object\n"
            if argv[2] == re8.RE_NAME and self.re_exit_at is not None and t >= self.re_exit_at:
                c["State"] = dict(c["State"], Status="exited")
            return 0, json.dumps([c]).encode(), b""
        if argv[:2] == [D, "ps"] and account == "agent" and not writes:
            name = argv[4][len("name=^"):-1]
            c = self.containers.get(name)
            return 0, (c["Id"][:12] + "\n").encode() if c else b"", b""
        if argv == [S.CAT, "--", ROUTER["state_dir"] + "/status.json"] and account == "agent" and not writes:
            data = self.status(t)
            return (0, data, b"") if data else (1, b"", b"cat: No such file\n")
        led = ENV["RELAY_LEDGER_DIR"]
        if argv == re8.init_argv(led, RE_IMAGE, 1001, 1001) and account == "agent" and writes:
            if self.init_out.startswith("outcome_ledger: initialised") and self.init_takes:
                self.ledger = "initialised"
            return 0, self.init_out.encode(), b""
        if argv == S.verify_argv(led, RE_IMAGE, 1001, 1001) and account == "agent" and not writes:
            # RE's V6 once initialised, else RE's V3 (no_init), as test_a2_s8 holds it.
            return 0, re_capture.V6 if self.ledger == "initialised" else T8.V_NO_INIT, b""
        if argv == [S.STAT, "-c", S.STAT_FORMAT, "--", led] and account == "relay" and not writes:
            return 0, self.ledger_stat, b""
        env_file = HOME + "/.amap-relay-env/re.env"
        if argv == re8.start_argv(ENV, env_file, RE_IMAGE, 1001, 1001, 1500) and account == "agent" and writes:
            if self.re_rc == 0:
                self._container(re8.RE_NAME, RE_ID, self.re_mounts, **self.re_extra)
            return self.re_rc, (RE_ID + "\n").encode() if self.re_rc == 0 else b"", b""
        if argv == [D, "logs", re8.RE_NAME] and account == "agent" and not writes:
            out, err = self.logs(t)
            return 0, out, err
        if (argv == [D, "exec", re8.RE_NAME, "python3", "-c", R.READ_FILE, led + "/" + R.HUB_STATUS]
                and account == "agent" and not writes):
            return 0, self.hub(t), b""
        if argv[:2] == [D, "stop"] and account == "agent" and writes:
            c = self.containers.get(argv[-1])
            if c is not None:
                c["State"] = dict(c["State"], Status="exited")
            return (0, (argv[-1] + "\n").encode(), b"") if c else (1, b"", b"Error: No such container\n")
        raise AssertionError("not an argv S8 sends: %r as %r (writes=%r)" % (argv, account, writes))


def prior_facts(slugs=SLUGS):
    return {"rl_image": RL_IMAGE, "re_image": RE_IMAGE, "key_public": status()["delegation"]["signing_public_key"],
            "key_id": status()["delegation"]["signing_key_id"], "s6": {"PLUGIN_SHA": PIN}, "agent_uid": 1000,
            "relay_uid": 1001, "hop_gid": 1500, "agents": [], "names": list(slugs)}


VM = {"name": "vm-a-t", "agent_account": "agent", "relay_account": "relay", "hop_group": "hop"}


class Base(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.d = Docker(self.clock)
        for name, fn in (("read_only", lambda layer, vm, v, p: measured()),
                         ("read_known", lambda layer, v, p: measured())):
            orig = getattr(R, name)
            setattr(R, name, fn)
            self.addCleanup(setattr, R, name, orig)

    def run_vm(self, p=None):
        return R.run_vm(self.d, VM, p or prior_facts(), 7, self.clock, self.clock.sleep)

    def refuses(self, cause, rc=3):
        with self.assertRaises(Refusal) as cm:
            self.run_vm()
        self.assertEqual((cm.exception.cause, cm.exception.rc), (cause, rc))
        return cm.exception

    def argv0s(self):
        return [c[0][:2] for c in self.d.calls]


class RunVmTest(Base):
    def test_rl_then_the_ledger_then_re_all_pass_with_their_facts(self):
        facts, result = self.run_vm()
        self.assertEqual(result, "CHANGED")
        f = dict(facts)
        self.assertEqual((f["START"], f["SKEW_MS"], f["RL_CONTAINER"], f["RE_CONTAINER"]), ("RUNNING", "7", RL_ID, RE_ID))
        self.assertEqual((f["RL_IMAGE"], f["RE_IMAGE"], f["RL_PLUGIN_SHA"], f["RE_PLUGIN_SHA"]),
                         (RL_IMAGE, RE_IMAGE, PIN, PIN))
        self.assertEqual((f["RL_POLLS"], f["RL_ADMITTED"], f["LEDGER"], f["RE_INBOUND"]),
                         ("1", "planner-a,canary-a", "INITIALISED", "NO_FAILURE_SEEN"))
        # Every docker CLI call is the agent's; the writes are exactly RL's start, the init and RE's start.
        self.assertEqual({c[1] for c in self.d.calls}, {"agent"})
        writes = [c[0][:2] for c in self.d.calls if c[2]]
        self.assertEqual(writes, [[R.SG, "hop"], [R.DOCKER, "run"], [R.DOCKER, "run"]])
        self.assertEqual(self.d.ledger, "initialised")
        # Witness 3 watched at least 60 s, after witness 2 saw progress rise across 2 x 5 s + 5 s.
        self.assertGreaterEqual(self.clock.t - T0, R.RE_INBOUND_S + 15)

    def test_rls_start_script_refusing_is_rl_refused_and_nothing_else_runs(self):
        self.d.rl_rc = 2
        e = self.refuses("START.RL_REFUSED")
        self.assertEqual(e.detail, "start script")
        self.assertNotIn([R.DOCKER, "run"], self.argv0s())
        self.assertEqual(self.d.calls[-1][0], [R.DOCKER, "stop", S.RL_NAME])

    def test_rl_restarting_or_restarted_is_refused_and_stopped(self):
        for extra in ({"RestartCount": 1}, {"State": {"Status": "restarting", "Restarting": True,
                                                       "StartedAt": STARTED}}):
            with self.subTest(extra=extra):
                self.setUp()
                self.d.rl_extra = extra
                self.refuses("START.RL_REFUSED")
                self.assertEqual(self.d.calls[-1][0], [R.DOCKER, "stop", S.RL_NAME])
                self.assertEqual(self.d.containers[S.RL_NAME]["State"]["Status"], "exited")

    def test_no_binding_first_poll_within_60_s_is_refused(self):
        for stale in (lambda t: b"", lambda t: json.dumps(status(started="2026-11-23T02:00:00Z")).encode(),
                      lambda t: json.dumps(status(polls=0)).encode()):
            with self.subTest():
                self.setUp()
                self.d.status = stale
                self.refuses("START.RL_REFUSED")
                self.assertGreaterEqual(self.clock.t - T0, R.RL_WINDOW_S)
                self.assertLess(self.clock.t - T0, R.RL_WINDOW_S + 2 * R.POLL_S)

    def test_a_first_poll_breaking_a_condition_is_not_admitting_and_rl_is_stopped(self):
        for doc in (status(plugin=False), status(names=["planner-a"])):
            with self.subTest():
                self.setUp()
                self.d.status = lambda t, doc=doc: json.dumps(doc).encode()
                self.refuses("START.NOT_ADMITTING")
                self.assertEqual(self.d.calls[-1][0], [R.DOCKER, "stop", S.RL_NAME])

    def test_rls_container_reaching_a_relay_trust_path_or_the_daemon_is_mounted(self):
        """RE's answer d1c8069c ask 1, and 738bb7fa condition A, on RL's container."""
        cases = (("relay env dir", {"Type": "bind", "Source": HOME + "/.amap-relay-env"}, {}),
                 ("relay config dir", {"Type": "bind", "Source": HOME + "/.amap-relay-config"}, {}),
                 ("relay ledger", {"Type": "bind", "Source": ENV["RELAY_LEDGER_DIR"]}, {}),
                 ("agent home", {"Type": "bind", "Source": HOME}, {}),
                 ("docker socket", {"Type": "bind", "Source": "/var/run/docker.sock"}, {}),
                 ("socket dir", {"Type": "bind", "Source": "/run"}, {}),
                 ("docker gid", None, {"HostConfig": {"GroupAdd": ["1500", str(DOCKER_GID)], "Privileged": False}}),
                 ("docker name", None, {"HostConfig": {"GroupAdd": ["docker"], "Privileged": False}}),
                 ("privileged", None, {"HostConfig": {"GroupAdd": None, "Privileged": True}}))
        for what, mount, extra in cases:
            with self.subTest(what=what):
                self.setUp()
                if mount:
                    self.d.rl_mounts = self.d.rl_mounts + [mount]
                self.d.rl_extra = extra
                self.refuses("START.TRUSTDIR_MOUNTED")
                self.assertEqual(self.d.calls[-1][0], [R.DOCKER, "stop", S.RL_NAME])
        for hc in ({"GroupAdd": "docker", "Privileged": False}, {"GroupAdd": None}, {"GroupAdd": [], "Privileged": 0},
                   None):
            with self.subTest(hc=hc):
                self.setUp()
                self.d.rl_extra = {"HostConfig": hc}
                self.refuses("START.TRUSTDIR_UNREAD")
        text = __import__("a2_causes").sentence("START.TRUSTDIR_MOUNTED")
        self.assertIn("the router's container", text)
        self.assertIn("can reach the docker daemon", text)

    def test_a_symlinked_or_missing_rl_bind_source_refuses_unread_and_rl_is_stopped(self):
        """Gate A's W13 r4 blocker 1: RL's bind sources are resolved as the agent account before (b) and (c), so a
        source that is a symlink to the env-file's directory (or the docker socket) cannot pass as its own name."""
        x = HOME + "/x"
        for what, target in (("to the env-file dir", HOME + "/.amap-relay-env"),
                             ("to the docker socket", "/var/run/docker.sock"), ("missing", None)):
            with self.subTest(what=what):
                self.setUp()
                self.d.rl_mounts = self.d.rl_mounts + [{"Type": "bind", "Source": x}]
                self.d.links = {x: target}
                e = self.refuses("START.TRUSTDIR_UNREAD")
                self.assertEqual(e.detail, "a path is not its own realpath")
                self.assertEqual(self.d.calls[-1][0], [R.DOCKER, "stop", S.RL_NAME])
        # Gate A's W13 r5 note N-C: the sources are resolved before (b) and (c), so a symlinked source in a
        # privileged RL is UNREAD, not MOUNTED.
        self.setUp()
        self.d.rl_mounts = self.d.rl_mounts + [{"Type": "bind", "Source": x}]
        self.d.links = {x: "/var/run/docker.sock"}
        self.d.rl_extra = {"HostConfig": {"GroupAdd": None, "Privileged": True}}
        self.assertEqual(self.refuses("START.TRUSTDIR_UNREAD").detail, "a path is not its own realpath")
        self.setUp()
        self.d.rl_mounts = self.d.rl_mounts + [{"Type": "bind", "Source": x}]
        self.run_vm()
        resolved = [c for c in self.d.calls if c[0][:3] == ["/usr/bin/realpath", "-e", "--"]]
        self.assertEqual([(c[0][3:], c[1]) for c in resolved],
                         [(sorted([HOME + "/.amap-router", ROUTER["state_dir"], x]), "agent")])

    def test_rls_own_binds_pass(self):
        self.d.rl_mounts += [{"Type": "bind", "Source": ENV["HOP_ROOT"]},
                             {"Type": "bind", "Source": ROUTER["transport_plugin"]["path"]},
                             {"Type": "volume", "Source": ""}]
        self.assertEqual(self.run_vm()[1], "CHANGED")

    def test_a_failed_ledger_init_is_re_refused_and_rl_is_left_running(self):
        self.d.init_out = "outcome_ledger: LedgerUnavailable: not_private\n"
        e = self.refuses("START.RE_REFUSED")
        self.assertEqual(e.detail, "ledger init")
        self.assertEqual(self.d.containers[S.RL_NAME]["State"]["Status"], "running")
        self.assertNotIn(re8.RE_NAME, self.d.containers)

    def test_an_init_whose_ledger_is_not_available_after_is_re_refused(self):
        self.d.init_takes = False
        e = self.refuses("START.RE_REFUSED")
        self.assertEqual(e.detail, "ledger not available after init")
        self.assertNotIn(re8.RE_NAME, self.d.containers)

    def test_res_start_refused_is_re_refused_and_stopped_with_its_timeout(self):
        self.d.re_rc = 125
        self.assertEqual(self.refuses("START.RE_REFUSED").detail, "start")
        self.assertEqual(self.d.calls[-1][0], [R.DOCKER, "stop", "-t", STOP_T, re8.RE_NAME])

    def test_each_witness_failing_is_re_refused_and_re_is_stopped(self):
        backoff = json.loads(re_capture.B1)
        cases = (("backoff first", "logs", lambda t: (json.dumps(backoff).encode() + b"\n" + startup_line(), b"")),
                 ("no startup", "logs", lambda t: (b"plain\n", b"")),
                 ("another link", "logs", lambda t: (startup_line(link="other"), b"")),
                 ("no progress", "hub", lambda t: hub(1)),
                 ("another plugin", "hub", lambda t: hub(1, plugin="0" * 64)),
                 ("an old hub status", "hub", lambda t: hub(1 + int(t - T0), started="2026-11-23T02:00:00Z")),
                 ("an inbound failure", "logs",
                  lambda t: (startup_line() + b"\n" + (b'{"component": "inbound", "event": "hub.poll_failed"}'
                                                       if t > T0 + 40 else b""), b"")))
        for what, attr, fn in cases:
            with self.subTest(what=what):
                self.setUp()
                setattr(self.d, attr, fn)
                self.refuses("START.RE_REFUSED")
                self.assertEqual(self.d.calls[-1][0], [R.DOCKER, "stop", "-t", STOP_T, re8.RE_NAME])

    def test_the_startup_and_progress_waits_are_bounded(self):
        self.d.logs = lambda t: (b"plain\n", b"")
        self.assertEqual(self.refuses("START.RE_REFUSED").detail, "no startup record")
        self.assertLess(self.clock.t - T0, R.RE_STARTUP_S + 4 * R.POLL_S)
        self.setUp()
        self.d.hub = lambda t: hub(1)
        self.assertEqual(self.refuses("START.RE_REFUSED").detail, "no outbound progress")
        # 2 x (2 x interval 5 s + 5 s) after the first reading, which comes within a few polls of RE's start.
        self.assertLess(self.clock.t - T0, 2 * (2 * 5 + 5) + 10 * R.POLL_S)
        self.setUp()
        self.d.hub = lambda t: b""
        self.assertEqual(self.refuses("START.RE_REFUSED").detail, "no outbound progress")
        self.assertLess(self.clock.t - T0, R.RE_STARTUP_S + 10 * R.POLL_S)

    def test_re_exiting_during_a_witness_is_refused(self):
        for at in (T0 + 3, T0 + 20, T0 + 60):
            with self.subTest(at=at):
                self.setUp()
                self.d.re_exit_at = at
                self.refuses("START.RE_REFUSED")

    def test_res_records_on_stderr_are_read(self):
        self.d.logs = lambda t: (b"", startup_line() + b"\n")
        self.assertEqual(self.run_vm()[1], "CHANGED")

    def test_res_container_reaching_the_daemon_is_mounted_and_re_is_stopped(self):
        """Gate B's W13 r4 blocker 1: section 3(c) runs on RE's container too, before its witnesses."""
        for what, mounts, extra in (
                ("socket", [{"Type": "bind", "Source": "/var/run/docker.sock"}], {}),
                ("socket dir", [{"Type": "bind", "Source": "/run"}], {}),
                ("privileged", [], {"HostConfig": {"GroupAdd": ["1500"], "Privileged": True}}),
                ("docker gid", [], {"HostConfig": {"GroupAdd": ["1500", str(DOCKER_GID)], "Privileged": False}}),
                ("docker name", [], {"HostConfig": {"GroupAdd": ["docker"], "Privileged": False}})):
            with self.subTest(what=what):
                self.setUp()
                self.d.re_mounts, self.d.re_extra = mounts, extra
                self.refuses("START.TRUSTDIR_MOUNTED")
                self.assertEqual(self.d.calls[-1][0], [R.DOCKER, "stop", "-t", STOP_T, re8.RE_NAME])
                self.assertNotIn([R.DOCKER, "logs"], self.argv0s())
        self.setUp()
        self.d.re_extra = {"HostConfig": None}
        self.refuses("START.TRUSTDIR_UNREAD")
        self.assertEqual(self.d.calls[-1][0], [R.DOCKER, "stop", "-t", STOP_T, re8.RE_NAME])

    def test_deeply_nested_json_from_rl_or_re_is_refused_and_the_container_stopped(self):
        """Gate B's W13 r4 blocker 2: json.loads raises RecursionError on a deep document. RL's status.json, RE's
        hub-status.json and RE's log lines are each read as not there yet, so the bounded wait refuses and the
        container is stopped."""
        deep = b"[" * 200000 + b"]" * 200000
        self.d.status = lambda t: deep
        self.assertEqual(self.refuses("START.RL_REFUSED").detail, "no first poll")
        self.assertEqual(self.d.calls[-1][0], [R.DOCKER, "stop", S.RL_NAME])
        for attr, fn, detail in (("hub", lambda t: deep, "no outbound progress"),
                                 ("logs", lambda t: (deep + b"\n", b""), "no startup record")):
            with self.subTest(attr=attr):
                self.setUp()
                setattr(self.d, attr, fn)
                self.assertEqual(self.refuses("START.RE_REFUSED").detail, detail)
                self.assertEqual(self.d.calls[-1][0], [R.DOCKER, "stop", "-t", STOP_T, re8.RE_NAME])

    def test_a_failure_no_step_names_is_unclassified_exit_3_and_the_container_stopped(self):
        def boom(t):
            raise RuntimeError("not a refusal")
        self.d.logs = boom
        e = self.refuses("START.UNCLASSIFIED")
        self.assertEqual(e.detail, "start")
        self.assertIsInstance(e.__cause__, RuntimeError)
        self.assertEqual(self.d.calls[-1][0], [R.DOCKER, "stop", "-t", STOP_T, re8.RE_NAME])
        self.setUp()
        self.d.status = boom
        self.refuses("START.UNCLASSIFIED")
        self.assertEqual(self.d.calls[-1][0], [R.DOCKER, "stop", S.RL_NAME])

    def test_a_stop_signal_in_res_wait_stops_re_with_its_timeout(self):
        """Gate B's W13 r5 blocker 1: an interrupt in RE's wait is named START.UNCLASSIFIED, exit 3, and RE is
        stopped with -t T and the layer timeout T + 60."""
        for exc in INTERRUPTS:
            with self.subTest(exc=exc.__name__):
                self.setUp()

                def stopped(t, exc=exc):
                    raise exc()
                self.d.logs = stopped
                e = self.refuses("START.UNCLASSIFIED")
                self.assertIsInstance(e.__cause__, exc)
                self.assertEqual(self.d.calls[-1][0], [R.DOCKER, "stop", "-t", STOP_T, re8.RE_NAME])
                self.assertEqual(self.d.timeouts[-1], int(STOP_T) + 60)

    def test_a_stop_signal_in_rls_wait_stops_rl(self):
        """Gate B's W13 r5 blocker 1, on one VM: an interrupt in RL's wait is named, and RL is stopped."""
        for exc in INTERRUPTS:
            with self.subTest(exc=exc.__name__):
                self.setUp()

                def stopped(t, exc=exc):
                    raise exc()
                self.d.status = stopped
                e = self.refuses("START.UNCLASSIFIED")
                self.assertIsInstance(e.__cause__, exc)
                self.assertEqual(self.d.calls[-1][0], [R.DOCKER, "stop", S.RL_NAME])

    def test_res_stop_is_given_its_timeout_plus_a_margin(self):
        """Gate B's W13 r4 note N2: the layer's own timeout must not cut docker stop -t short."""
        self.d.re_rc = 125
        self.refuses("START.RE_REFUSED")
        self.assertEqual(self.d.calls[-1][0], [R.DOCKER, "stop", "-t", STOP_T, re8.RE_NAME])
        self.assertEqual(self.d.timeouts[-1], int(STOP_T) + 60)
        self.assertEqual(R.STOP_MARGIN_S, 60)

    def test_a_refusal_before_any_write_issues_no_stop(self):
        """Gate B's W13 r4 note N8: a layer refusal of RL's start before it is issued leaves exit 2 literal."""
        orig = self.d.exec

        def refused(vm, argv, **kw):
            if argv[0] == R.SG:
                raise Refusal("START.TARGET_ACCESS", vm)
            return orig(vm, argv, **kw)
        self.d.exec = refused
        self.refuses("START.TARGET_ACCESS", rc=2)
        self.assertEqual([c for c in self.d.calls if c[2]], [])

    def test_witness_2_waits_at_most_its_fixed_ceiling(self):
        """Gate B's W13 r4 note N9: an interval_s of 3600 would allow hours; the ceiling holds it to 300 s."""
        def slow(t):
            doc = json.loads(hub(1))
            doc["interval_s"] = 3600
            return json.dumps(doc).encode()
        self.d.hub = slow
        self.assertEqual(self.refuses("START.RE_REFUSED").detail, "no outbound progress")
        self.assertLess(self.clock.t - T0, 300 + R.RE_STARTUP_S)
        self.assertGreaterEqual(self.clock.t - T0, 300)
        self.assertEqual(R.PROGRESS_CEILING_S, 300)


class ReadOnlyTest(unittest.TestCase):
    """read_only's own checks, over stand-ins for the a2_s8 steps it composes (each REAL-PROBED in test_a2_s8)."""

    def setUp(self):
        self.calls = []
        m = dict(measured())
        for k in ("env", "router", "state_dir", "docker_gid"):
            m.pop(k)
        self.m, self.router = m, dict(ROUTER)
        stubs = {"measure": lambda layer, vm, v: dict(self.m),
                 "config_in_place": lambda layer, vm, v, s6, home: {"env": ENV, "router": self.router},
                 "trust_resolved": lambda layer, vm, v, env, home, rhome: self.calls.append(("trust", home, rhome)),
                 "not_started": lambda layer, vm, v, env, image, uid, gid: self.calls.append(("ns", image, uid, gid))}
        for name, fn in stubs.items():
            orig = getattr(S, name)
            setattr(S, name, fn)
            self.addCleanup(setattr, S, name, orig)
        self.d = Docker(Clock())

    def run_ro(self):
        return R.read_only(self.d, "vm-a-t", VM, prior_facts())

    def test_it_returns_the_measured_facts_and_runs_each_step(self):
        got = self.run_ro()
        self.assertEqual((got["state_dir"], got["docker_gid"], got["relay_uid"]), (ROUTER["state_dir"], DOCKER_GID, 1001))
        self.assertEqual(self.calls, [("trust", HOME, RHOME), ("ns", RE_IMAGE, 1001, 1001)])

    def test_measured_ids_other_than_s6s_refuse_config_changed(self):
        for k, val in (("uid", 1002), ("relay_uid", 1003), ("hop_gid", 1501)):
            with self.subTest(k=k):
                self.m = dict(measured(), **{k: val})
                with self.assertRaises(Refusal) as cm:
                    self.run_ro()
                self.assertEqual((cm.exception.cause, cm.exception.rc), ("START.CONFIG_CHANGED", 2))
                self.assertEqual(self.calls, [])

    def test_a_state_dir_outside_the_agent_home_refuses(self):
        for sd in ("/srv/state", "rel", HOME, HOME + "/../x", None):
            with self.subTest(sd=sd):
                self.router = dict(ROUTER, state_dir=sd)
                with self.assertRaises(Refusal) as cm:
                    self.run_ro()
                self.assertEqual(cm.exception.cause, "START.CONFIG_CHANGED")

    def test_after_a_write_its_refusals_exit_3(self):
        self.d.has_written = True
        self.m = dict(measured(), uid=1002)
        with self.assertRaises(Refusal) as cm:
            self.run_ro()
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("START.CONFIG_CHANGED", 3))

    def test_the_docker_group_as_getent_reports_it(self):
        import a2_s8_checks as C
        self.assertEqual(C.docker_gid(0, b"docker:x:988:agent,relay\n"), 988)
        self.assertIsNone(C.docker_gid(2, b""))
        for rc, out in ((1, b""), (0, b""), (0, b"wheel:x:10:\n"), (0, b"docker:x:988:\ndocker:x:989:\n"),
                        (2, b"docker:x:1:\n")):
            with self.subTest(rc=rc, out=out):
                with self.assertRaises(Refusal) as cm:
                    C.docker_gid(rc, out)
                self.assertEqual(cm.exception.cause, "START.TRUSTDIR_UNREAD")


def s7_facts(vm, agents=((1, "planner", "planner-a", False), (2, "canary", "canary-a", True))):
    f = []
    for n, aid, slug, standin in agents:
        p = "AGENT_%d_" % n
        f += [(p + "ID", aid), (p + "VM", vm), (p + "WORKSPACE", "~/dev/agent-" + aid), (p + "CONNECTOR_COMMIT", "c" * 40),
              (p + "SECRET_FILE", "present"), (p + "START_POSSIBLE", "yes"), (p + "SLUG", slug),
              (p + "REGISTRY", "active"), (p + "LOGICAL_ID", "d" * 32), (p + "IMAGE_ID", "sandy-image-opaque")]
        if standin:
            f.append((p + "STANDIN", "launched-once"))
    return f


class StageBase(TS.Base):
    def write_prior(self, skip=None, change=None):
        change = change or {}
        for vm in ("vm-a-t", "vm-b-t"):
            per = {
                "S4": [(R.S4_RL_IMAGE, RL_IMAGE), (R.S4_RE_IMAGE, RE_IMAGE)],
                "S5": [("KEY_ID", prior_facts()["key_id"]), ("KEY_PUBLIC", prior_facts()["key_public"]),
                       ("KEY", "CREATED")],
                "S6": [("CONFIG", "PLACED")] + [(f, "e" * 64) for f, _r in S.PLACED] + [
                    ("PLUGIN_SHA", PIN), ("AGENT_UID", "1000"), ("RELAY_UID", "1001"), ("HOP_GID", "1500")],
                "S6b": [("HUB_LOGIN", "WRITTEN")],
                "S7": s7_facts(vm)}
            for sid, facts in per.items():
                if (sid, vm) == skip:
                    continue
                facts = change.get((sid, vm), lambda f: f)(facts)
                self.rec.write_receipt(sid, vm, "2026-11-23T03:00:00Z", "CHANGED", facts)


class PriorTest(StageBase):
    def test_every_predecessor_is_read_and_its_facts_returned(self):
        self.write_prior()
        p = R.prior(self.rec, "vm-a-t")
        self.assertEqual((p["rl_image"], p["re_image"], p["key_id"], p["agent_uid"], p["relay_uid"], p["hop_gid"]),
                         (RL_IMAGE, RE_IMAGE, prior_facts()["key_id"], 1000, 1001, 1500))
        self.assertEqual(p["names"], ["planner-a", "canary-a"])
        self.assertEqual([(a["n"], a["workspace_rel"], a["standin"], a["image_id"]) for a in p["agents"]],
                         [(1, "dev/agent-planner", False, "sandy-image-opaque"),
                          (2, "dev/agent-canary", True, "sandy-image-opaque")])

    def test_a_missing_receipt_keeps_the_readers_cause(self):
        for sid in ("S4", "S5", "S6", "S6b", "S7"):
            with self.subTest(sid=sid):
                self.setUp()
                self.write_prior(skip=(sid, "vm-a-t"))
                with self.assertRaises(Refusal) as cm:
                    R.prior(self.rec, "vm-a-t")
                self.assertEqual((cm.exception.cause, cm.exception.detail), ("START.PREDECESSOR_MISSING",
                                                                             sid + "-vm-a-t"))

    def test_a_malformed_fact_is_incomplete(self):
        cases = (("S4", lambda f: [(R.S4_RL_IMAGE, "e" * 64), f[1]]),
                 ("S4", lambda f: f[:1]),
                 ("S5", lambda f: f[:1] + f[2:]),
                 ("S5", lambda f: [x if x[0] != "KEY_ID" else ("KEY_ID", "-k1") for x in f]),
                 ("S5", lambda f: [x if x[0] != "KEY_ID" else ("KEY_ID", "a b") for x in f]),
                 ("S5", lambda f: [x if x[0] != "KEY_PUBLIC" else ("KEY_PUBLIC", "E" * 64) for x in f]),
                 ("S5", lambda f: [x if x[0] != "KEY_PUBLIC" else ("KEY_PUBLIC", "e" * 63) for x in f]),
                 ("S6", lambda f: [("CONFIG", "PLANNED")] + f[1:]),
                 ("S6", lambda f: [x if x[0] != "PLUGIN_SHA" else ("PLUGIN_SHA", "E" * 64) for x in f]),
                 ("S6", lambda f: [x if x[0] != "RELAY_UID" else ("RELAY_UID", "0") for x in f]),
                 ("S6", lambda f: [x for x in f if x[0] != "PREFIX_JSON_SHA"]))
        for sid, fn in cases:
            with self.subTest(sid=sid):
                self.setUp()
                self.write_prior(change={(sid, "vm-a-t"): fn})
                with self.assertRaises(Refusal) as cm:
                    R.prior(self.rec, "vm-a-t")
                self.assertEqual(cm.exception.cause, "START.PREDECESSOR_INCOMPLETE")

    def test_s7s_agents_are_the_positions_present_each_whole(self):
        """No count and no contiguity (an --add-agent receipt holds one agent at its position); a partial key set or
        a value against S7's own rules is PREDECESSOR_FAILED (ruling W13-S7-FACTS-ADAPT-IN-S8)."""
        self.write_prior(change={("S7", "vm-a-t"): lambda f: s7_facts("vm-a-t", ((3, "solo", "solo-a", False),))})
        self.assertEqual([(a["n"], a["slug"]) for a in R.prior(self.rec, "vm-a-t")["agents"]], [(3, "solo-a")])
        bad = (("a key missing", lambda f: [x for x in f if x[0] != "AGENT_2_LOGICAL_ID"]),
               ("an extra key", lambda f: f + [("AGENT_1_COLOUR", "blue")]),
               ("a stray position", lambda f: f + [("AGENT_5_SLUG", "x")]),
               ("not startable", lambda f: [x if x[0] != "AGENT_1_START_POSSIBLE" else (x[0], "no") for x in f]),
               ("another VM", lambda f: [x if x[0] != "AGENT_1_VM" else (x[0], "vm-b-t") for x in f]),
               ("absolute workspace", lambda f: [x if x[0] != "AGENT_1_WORKSPACE" else (x[0], "/home/agent/dev/agent-planner")
                                                 for x in f]),
               ("another workspace", lambda f: [x if x[0] != "AGENT_1_WORKSPACE" else (x[0], "~/dev/agent-other")
                                                for x in f]),
               ("standin value", lambda f: [x if x[0] != "AGENT_2_STANDIN" else (x[0], "yes") for x in f]),
               ("duplicate slug", lambda f: [x if x[0] != "AGENT_2_SLUG" else (x[0], "planner-a") for x in f]),
               ("empty image", lambda f: [x if x[0] != "AGENT_1_IMAGE_ID" else (x[0], "") for x in f]),
               ("no agents", lambda f: [("SANDY", "present")]))
        for what, fn in bad:
            with self.subTest(what=what):
                self.setUp()
                self.write_prior(change={("S7", "vm-a-t"): fn})
                with self.assertRaises(Refusal) as cm:
                    R.prior(self.rec, "vm-a-t")
                self.assertEqual(cm.exception.cause, "START.PREDECESSOR_FAILED")


class RunS8Test(StageBase):
    def setUp(self):
        super().setUp()
        self.clock = Clock()
        self.docker = {vm: Docker(self.clock, vm) for vm in ("vm-a-t", "vm-b-t")}
        self.site.vm_layer = self

        for name, fn in (("read_only", lambda layer, vm, v, p: measured()),
                         ("read_known", lambda layer, v, p: measured())):
            orig = getattr(R, name)
            setattr(R, name, fn)
            self.addCleanup(setattr, R, name, orig)

    # One layer over both VMs, routing by VM name; `wrote` is the stage's, across VMs.
    def exec(self, vm, argv, **kw):
        out = self.docker[vm].exec(vm, argv, **kw)
        return out

    def wrote(self, stage):
        return stage == "START" and any(d.has_written for d in self.docker.values())

    def run_s8(self):
        R.run_s8(self.c, self.site, self.rec, self.clock, self.clock.sleep)

    def test_both_vms_start_and_each_receipt_passes(self):
        self.write_prior()
        self.run_s8()
        for vm in ("vm-a-t", "vm-b-t"):
            facts, rc = self.receipt("S8", vm)
            self.assertEqual((rc, facts["RESULT"], facts["START"], facts["LEDGER"]), (0, "CHANGED", "RUNNING", "INITIALISED"))
            self.assertTrue(facts["SKEW_MS"].isdigit())

    def test_a_predecessor_or_the_clock_refusing_is_written_in_the_first_receipt(self):
        self.write_prior(skip=("S4", "vm-b-t"))
        with self.assertRaises(Refusal):
            self.run_s8()
        facts, rc = self.receipt("S8", "vm-a-t")
        self.assertEqual((rc, facts["CAUSE"]), (2, "START.PREDECESSOR_MISSING"))
        self.assertEqual([c for d in self.docker.values() for c in d.calls], [])

    def test_clock_skew_refuses_before_any_vm(self):
        self.write_prior()
        orig = self.docker["vm-b-t"].exec

        def skewed(vm, argv, **kw):
            rc, out, err = orig(vm, argv, **kw)
            return (rc, b"%.9f\n" % (self.clock.t + 3), err) if argv[0] == R.DATE else (rc, out, err)
        self.docker["vm-b-t"].exec = skewed
        with self.assertRaises(Refusal) as cm:
            self.run_s8()
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("START.CLOCK_SKEW", 2))
        self.assertFalse(self.wrote("START"))

    def test_vm_2_refusing_after_vm_1_started_exits_3_with_both_vms_state(self):
        """Opus's W13 r1 blocker 1: the second VM's refusal follows the first VM's writes, so it exits 3, and its
        receipt says what was left on each VM, read, never assumed."""
        self.write_prior()
        self.docker["vm-b-t"].rl_rc = 2
        with self.assertRaises(Refusal) as cm:
            self.run_s8()
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("START.RL_REFUSED", 3))
        a, rc_a = self.receipt("S8", "vm-a-t")
        b, rc_b = self.receipt("S8", "vm-b-t")
        self.assertEqual((rc_a, rc_b), (0, 3))
        self.assertEqual((b["STATE_VM1_NAME"], b["STATE_VM1_RL"], b["STATE_VM1_RE"], b["STATE_VM1_LEDGER"]),
                         ("vm-a-t", "RUNNING", "RUNNING", "INITIALISED"))
        self.assertEqual((b["STATE_VM2_NAME"], b["STATE_VM2_RL"], b["STATE_VM2_RE"], b["STATE_VM2_LEDGER"]),
                         ("vm-b-t", "ABSENT", "ABSENT", "NO_INIT"))

    def test_a_refusal_after_rls_start_records_rl_stopped_and_unobserved_reads(self):
        self.write_prior()
        self.docker["vm-a-t"].status = lambda t: json.dumps(status(plugin=False)).encode()
        with self.assertRaises(Refusal):
            self.run_s8()
        a, rc = self.receipt("S8", "vm-a-t")
        self.assertEqual((rc, a["CAUSE"], a["STATE_VM1_RL"], a["STATE_VM1_RE"], a["STATE_VM1_LEDGER"]),
                         (3, "START.NOT_ADMITTING", "EXITED", "ABSENT", "NO_INIT"))
        self.assertEqual(a["STATE_VM2_RL"], "ABSENT")

    def test_a_state_read_that_fails_is_unobserved(self):
        self.write_prior()
        self.docker["vm-a-t"].rl_rc = 2
        orig = self.docker["vm-b-t"].exec

        def broken(vm, argv, **kw):
            if argv[:2] in ([R.DOCKER, "ps"], [R.DOCKER, "run"], [S.STAT, "-c"]):
                return 1, b"", b"daemon gone\n"
            return orig(vm, argv, **kw)
        self.docker["vm-b-t"].exec = broken
        with self.assertRaises(Refusal):
            self.run_s8()
        a, _rc = self.receipt("S8", "vm-a-t")
        self.assertEqual((a["STATE_VM2_RL"], a["STATE_VM2_RE"], a["STATE_VM2_LEDGER"]),
                         ("UNOBSERVED", "UNOBSERVED", "UNOBSERVED"))

    def test_a_failure_no_step_names_is_written_with_the_state_left(self):
        """Gate B's W13 r4 blocker 2: a non-Refusal after a write still stops the container and writes STATE_*."""
        self.write_prior()

        def boom(t):
            raise RuntimeError("not a refusal")
        self.docker["vm-a-t"].logs = boom
        with self.assertRaises(Refusal) as cm:
            self.run_s8()
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("START.UNCLASSIFIED", 3))
        # Gate B's W13 r5 note N3: run_vm's chain survives step().
        self.assertIsInstance(cm.exception.__cause__, RuntimeError)
        a, rc = self.receipt("S8", "vm-a-t")
        self.assertEqual((rc, a["CAUSE"], a["STATE_VM1_RL"], a["STATE_VM1_RE"], a["STATE_VM1_LEDGER"]),
                         (3, "START.UNCLASSIFIED", "RUNNING", "EXITED", "INITIALISED"))

    def test_a_failure_outside_run_vms_own_catches_is_unclassified_with_the_state_left(self):
        """Gate B's W13 r4 blocker 2, at run_s8's step: a non-Refusal from step 6's init, which run_vm does not wrap,
        is still named UNCLASSIFIED with exit 3 and STATE_* written, never an escaping exception."""
        self.write_prior()
        orig = self.docker["vm-a-t"].exec

        def boom(vm, argv, **kw):
            if argv[:2] == [R.DOCKER, "run"] and argv[-2:-1] == ["init"]:
                raise RuntimeError("not a refusal")
            return orig(vm, argv, **kw)
        self.docker["vm-a-t"].exec = boom
        with self.assertRaises(Refusal) as cm:
            self.run_s8()
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("START.UNCLASSIFIED", 3))
        self.assertIsInstance(cm.exception.__cause__, RuntimeError)
        a, rc = self.receipt("S8", "vm-a-t")
        self.assertEqual((rc, a["CAUSE"], a["STATE_VM1_RL"], a["STATE_VM1_RE"], a["STATE_VM1_LEDGER"]),
                         (3, "START.UNCLASSIFIED", "RUNNING", "ABSENT", "NO_INIT"))

    def test_a_stop_signal_in_the_rl_wait_stops_rl_and_writes_the_state(self):
        """Gate B's W13 r5 blocker 1: an interrupt (RunStopped, KeyboardInterrupt or SystemExit) in VM 1's RL wait is
        named START.UNCLASSIFIED, exit 3; RL is stopped and the receipt says what was left. The interrupt is not
        swallowed: the run ends there, so VM 2 is never written to and has no S8 receipt."""
        for exc in INTERRUPTS:
            with self.subTest(exc=exc.__name__):
                self.setUp()
                self.write_prior()

                def stopped(t, exc=exc):
                    raise exc()
                self.docker["vm-a-t"].status = stopped
                with self.assertRaises(Refusal) as cm:
                    self.run_s8()
                self.assertEqual((cm.exception.cause, cm.exception.rc), ("START.UNCLASSIFIED", 3))
                self.assertIsInstance(cm.exception.__cause__, exc)
                self.assertIn(([R.DOCKER, "stop", S.RL_NAME], "agent", True), self.docker["vm-a-t"].calls)
                a, rc = self.receipt("S8", "vm-a-t")
                self.assertEqual((rc, a["CAUSE"], a["STATE_VM1_RL"], a["STATE_VM1_RE"], a["STATE_VM1_LEDGER"]),
                                 (3, "START.UNCLASSIFIED", "EXITED", "ABSENT", "NO_INIT"))
                self.assertEqual([c for c in self.docker["vm-b-t"].calls if c[2]], [])
                self.assertEqual([(st["stage"], st["host"]) for st in self.rec.stages if st["stage"] == "S8"],
                                 [("S8", "vm-a-t")])

    def test_a_stop_signal_on_vm_2_after_vm_1_passed_is_written_in_vm_2s_receipt(self):
        """Gate B's W13 r5 blocker 1: with VM 1's receipt written, a2_main's dispatch writes none for VM 2, so S8's
        own receipt is the only record of what was left on either VM."""
        for exc in INTERRUPTS:
            with self.subTest(exc=exc.__name__):
                self.setUp()
                self.write_prior()

                def stopped(t, exc=exc):
                    raise exc()
                self.docker["vm-b-t"].status = stopped
                with self.assertRaises(Refusal) as cm:
                    self.run_s8()
                self.assertEqual((cm.exception.cause, cm.exception.rc), ("START.UNCLASSIFIED", 3))
                self.assertIsInstance(cm.exception.__cause__, exc)
                a, rc_a = self.receipt("S8", "vm-a-t")
                b, rc_b = self.receipt("S8", "vm-b-t")
                self.assertEqual((rc_a, a["RESULT"], rc_b, b["CAUSE"]), (0, "CHANGED", 3, "START.UNCLASSIFIED"))
                self.assertIn(([R.DOCKER, "stop", S.RL_NAME], "agent", True), self.docker["vm-b-t"].calls)
                self.assertEqual((b["STATE_VM1_RL"], b["STATE_VM1_RE"], b["STATE_VM1_LEDGER"],
                                  b["STATE_VM2_RL"], b["STATE_VM2_RE"], b["STATE_VM2_LEDGER"]),
                                 ("RUNNING", "RUNNING", "INITIALISED", "EXITED", "ABSENT", "NO_INIT"))

    def test_an_interrupt_before_any_write_is_unclassified_exit_3(self):
        """An interrupt is exit 3 even before S8 writes, as a2_main's dispatch gives it (3.4)."""
        self.write_prior()

        def stopped(layer, vm, v, p):
            raise KeyboardInterrupt()
        R.read_only = stopped
        with self.assertRaises(Refusal) as cm:
            self.run_s8()
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("START.UNCLASSIFIED", 3))
        self.assertFalse(self.wrote("START"))
        a, rc = self.receipt("S8", "vm-a-t")
        self.assertEqual((rc, a["STATE_VM1_RL"], a["STATE_VM1_RE"]), (3, "ABSENT", "ABSENT"))

    def test_a_failed_or_interrupted_stop_keeps_the_refusals_own_cause(self):
        """Gate B's W13 r5 notes N4 and B1: an OSError or an interrupt at the stop call itself leaves the cause
        NOT_ADMITTING, and the state is still read and written."""
        for exc in (OSError, KeyboardInterrupt):
            with self.subTest(exc=exc.__name__):
                self.setUp()
                self.write_prior()
                d = self.docker["vm-a-t"]
                d.status = lambda t: json.dumps(status(plugin=False)).encode()
                orig = d.exec

                def broken(vm, argv, **kw):
                    if argv[:2] == [R.DOCKER, "stop"]:
                        raise exc()
                    return orig(vm, argv, **kw)
                d.exec = broken
                with self.assertRaises(Refusal) as cm:
                    self.run_s8()
                self.assertEqual((cm.exception.cause, cm.exception.rc), ("START.NOT_ADMITTING", 3))
                a, rc = self.receipt("S8", "vm-a-t")
                self.assertEqual((rc, a["CAUSE"], a["STATE_VM1_RL"]), (3, "START.NOT_ADMITTING", "RUNNING"))

    def test_a_layer_failure_or_interrupt_in_a_state_read_is_unobserved(self):
        """Gate B's W13 r5 notes N5 and B1: a non-Refusal from the layer inside _status, or from read_known, is
        UNOBSERVED; the collection goes on and the receipt is written."""
        for exc in (OSError, KeyboardInterrupt):
            with self.subTest(exc=exc.__name__):
                self.setUp()
                self.write_prior()
                self.docker["vm-a-t"].rl_rc = 2
                orig = self.docker["vm-b-t"].exec

                def broken(vm, argv, **kw):
                    if argv[:2] == [R.DOCKER, "ps"]:
                        raise exc()
                    return orig(vm, argv, **kw)
                self.docker["vm-b-t"].exec = broken
                orig_a = self.docker["vm-a-t"].exec

                def stat_broken(vm, argv, **kw):
                    if argv[0] == S.STAT:
                        raise exc()
                    return orig_a(vm, argv, **kw)
                self.docker["vm-a-t"].exec = stat_broken

                def unknown(layer, v, p):
                    if v["name"] == "vm-b-t":
                        raise exc()
                    return measured()
                R.read_known = unknown
                with self.assertRaises(Refusal) as cm:
                    self.run_s8()
                self.assertEqual(cm.exception.cause, "START.RL_REFUSED")
                a, rc = self.receipt("S8", "vm-a-t")
                self.assertEqual((rc, a["STATE_VM2_RL"], a["STATE_VM2_RE"], a["STATE_VM2_LEDGER"]),
                                 (3, "UNOBSERVED", "UNOBSERVED", "UNOBSERVED"))
                self.assertEqual((a["STATE_VM1_RL"], a["STATE_VM1_LEDGER"]), ("ABSENT", "UNOBSERVED"))

    def test_an_unusable_ledger_is_recorded_unusable(self):
        """Gate B's W13 r4 note N3: STATE_VM<i>_LEDGER takes UNUSABLE when step 4's stat finds the wrong mode."""
        self.write_prior()
        self.docker["vm-a-t"].rl_rc = 2
        self.docker["vm-a-t"].ledger_stat = b"1001 1001 750 directory\n"
        with self.assertRaises(Refusal):
            self.run_s8()
        a, rc = self.receipt("S8", "vm-a-t")
        self.assertEqual((rc, a["STATE_VM1_LEDGER"], a["STATE_VM2_LEDGER"]), (3, "UNUSABLE", "NO_INIT"))

    def test_a_deep_ledger_report_is_read_without_aborting_the_state(self):
        self.write_prior()
        self.docker["vm-a-t"].rl_rc = 2
        orig = self.docker["vm-b-t"].exec

        def deep(vm, argv, **kw):
            if argv[:2] == [R.DOCKER, "run"] and not kw.get("writes"):
                return 0, b"[" * 200000 + b"]" * 200000, b""
            return orig(vm, argv, **kw)
        self.docker["vm-b-t"].exec = deep
        with self.assertRaises(Refusal):
            self.run_s8()
        a, _rc = self.receipt("S8", "vm-a-t")
        self.assertEqual((a["STATE_VM1_LEDGER"], a["STATE_VM2_LEDGER"]), ("NO_INIT", "UNOBSERVED"))

    def test_a_failed_ledger_read_is_unobserved_and_a_wrong_state_unusable(self):
        """Gate A's W13 r4 blocker 2: a --verify that exits non-zero or prints no report that parses is a failed read,
        UNOBSERVED; a report that parses to a state other than no_init or available is UNUSABLE."""
        for what, answer, want in (("docker 125", (125, b"", b"docker: invalid mount config\n"), "UNOBSERVED"),
                                   ("daemon gone", (1, b"", b"Cannot connect to the Docker daemon\n"), "UNOBSERVED"),
                                   ("no report", (0, b"not json\n", b""), "UNOBSERVED"),
                                   ("rc 1 with a report", (1, T8.V_NO_INIT, b""), "UNOBSERVED"),
                                   # Gate A's W13 r5 note N-B: a document whose ledger member is null is no report.
                                   ("ledger null", (0, b'{"ledger": null}\n', b""), "UNOBSERVED"),
                                   ("not private", (0, T8.V_NOT_PRIVATE, b""), "UNUSABLE")):
            with self.subTest(what=what):
                self.setUp()
                self.write_prior()
                self.docker["vm-a-t"].rl_rc = 2
                orig = self.docker["vm-b-t"].exec

                def verify(vm, argv, answer=answer, orig=orig, **kw):
                    if argv[:2] == [R.DOCKER, "run"] and not kw.get("writes"):
                        return answer
                    return orig(vm, argv, **kw)
                self.docker["vm-b-t"].exec = verify
                with self.assertRaises(Refusal):
                    self.run_s8()
                a, _rc = self.receipt("S8", "vm-a-t")
                self.assertEqual((a["STATE_VM1_LEDGER"], a["STATE_VM2_LEDGER"]), ("NO_INIT", want))

    def test_a_dry_run_plans_each_vm_and_touches_none(self):
        self.c.inv.command = "dry-run"
        self.run_s8()
        for vm in ("vm-a-t", "vm-b-t"):
            facts, _rc = self.receipt("S8", vm)
            self.assertEqual((facts["RESULT"], facts["START"]), ("PLANNED", "PLANNED"))
        self.assertEqual([c for d in self.docker.values() for c in d.calls], [])


if __name__ == "__main__":
    unittest.main()
