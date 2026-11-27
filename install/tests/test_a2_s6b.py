"""S6b HUB-LOGIN (a2_s6b) over two VMs.

REAL here: the shipped vm_login_writer.py under the shipped vm_bootstrap.py (tests/secret_session.py, with only the
writer's LOOKUP and BECOME stood in), the env-file rendered by a2_s6_env exactly as S6 renders it, and /usr/bin/stat
and /usr/bin/sha256sum run on this host on each VM's temporary relay home.
FAKED, by FakeLayer: the ssh route (an exec runs here), S6's measurement (its JSON line, as vm_measure prints it;
a2_s6's own tests prove the parser), and docker (each probe answers what the test scripts; the argv is recorded and
held to S8's own RE start form).
"""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import types
import unittest

import a2fix  # noqa: F401  (puts install/ on sys.path)
import a2_args
import a2_s1
import a2_s6
import a2_s6_env as e6
import a2_s6b as S
import a2_s8_re
import secret_session
from a2_causes import Refusal

INSTALL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WRITER = os.path.join(INSTALL, "vm_login_writer.py")
ME = (os.getuid(), os.getgid())
AGENT_UID, HOP_GID = 4242, 4343
HUB = "mail.example.org"
LOGIN = {"local": "relay", "domain": "example.org"}
VALUES = {"vm-a": bytearray(b"value-for-vm-a-0123456789!"), "vm-b": bytearray(b"value-for-vm-b-9876543210?")}
IMAGE = "sha256:" + "e" * 64


class FakeLayer:
    def __init__(self, base, vms):
        self.base = base
        self.homes = {}
        self.wrote_stages = set()
        self.calls = []
        self.probe = {}
        self.writer_text = {}
        self.rm_refuses = False
        for v in vms:
            n = v["name"]
            agent = os.path.join(base, n, "agent")
            relay = os.path.join(base, n, "relay")
            os.makedirs(os.path.join(agent, a2_s6.RE_ENV))
            os.makedirs(os.path.join(relay, ".amap-relay", "login"))
            for p in (".amap-relay", ".amap-relay/login"):
                os.chmod(os.path.join(relay, p), 0o700)
            self.homes[n] = (agent, relay)
            self.writer_text[n] = secret_session.faked_writer(WRITER, relay, v["relay_account"])
            self.probe[n] = (0, b"ok 235\n")

    def wrote(self, stage):
        return stage in self.wrote_stages

    def pinned_installer_file(self, name, stage):
        return b"# " + name.encode()

    def measure_doc(self, vm):
        agent, relay = self.homes[vm]
        return {"home": agent, "relay_home": relay, "uid": AGENT_UID, "gid": AGENT_UID, "relay_uid": ME[0],
                "relay_gid": ME[1], "hop_gid": HOP_GID, "agent_in_hop": True, "relay_in_hop": True, "python": [3, 13]}

    def exec(self, vm, argv, *, account, stage, writes, stdin=None, timeout_s=None):
        self.calls.append((vm, account, list(argv), writes))
        if writes:
            self.wrote_stages.add(stage)
        if argv[0] == a2_s6.PYTHON:
            return 0, (json.dumps(self.measure_doc(vm)) + "\n").encode(), b""
        if argv[0] in (S.STAT, S.SHA256SUM):
            p = subprocess.run(argv, capture_output=True)
            return p.returncode, p.stdout, p.stderr
        if argv[0] == S.DOCKER and argv[1] == "rm":
            if self.rm_refuses:
                raise Refusal("HUB-LOGIN.UNCLASSIFIED", "rm", rc=3)
            return 0, b"", b""
        if argv[0] == S.DOCKER:
            got = self.probe[vm]
            if isinstance(got, BaseException):
                raise got
            rc, out = got
            return rc, out, b""
        raise AssertionError("unexpected argv %r" % (argv,))

    def write_secret(self, vm, use, mode, value, *, account, stage):
        self.calls.append((vm, account, ["<secret>", use, mode], True))
        assert use == "hub_login" and mode == "write" and type(value) is bytearray and value
        self.wrote_stages.add(stage)
        rc, out, _err = secret_session.run(self.writer_text[vm], use, mode, value, account)
        if not out.startswith(b"READY\n"):
            raise Refusal(stage + ".PIN", rc=3)
        return rc


class Rec:
    run_id = "20261127T000000Z-0000000a"

    def __init__(self, receipts):
        self.receipts = receipts
        self.written = []

    def read_receipt(self, sid, host):
        key = (sid, host)
        if key not in self.receipts:
            raise Refusal("CONFIG.PREDECESSOR_MISSING")
        return dict(self.receipts[key])

    def write_receipt(self, stage, host, started, result, facts, rc=0, cause=None):
        self.written.append((stage, host, result, list(facts), rc, cause))


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="a2s6b-")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.vms = [{"name": n, "scope": "l3", "agent_account": "agent", "relay_account": "relay",
                     "hop_group": "hop", "fleet_domain": n + ".internal"} for n in ("vm-a", "vm-b")]
        self.layer = FakeLayer(self.d, self.vms)
        self.lock = {"hub_login": dict(LOGIN),
                     "writers": [{"use": "hub_login", "path": "install/vm_login_writer.py", "sha256": "f" * 64}]}
        receipts = {("S3", None): {"HUB_HOSTNAME": HUB}}
        for v in self.vms:
            agent, relay = self.layer.homes[v["name"]]
            env = e6.text(e6.environment(agent_home=agent, relay_home=relay, agent_uid=AGENT_UID,
                                         fleet_domain=v["fleet_domain"], hub_fqdn=HUB, login_local=LOGIN["local"],
                                         login_domain=LOGIN["domain"]))
            with open(os.path.join(agent, a2_s6.RE_ENV, a2_s6.RE_ENV_NAME), "wb") as f:
                f.write(env)
            receipts[("S6", v["name"])] = {"CONFIG": "PLACED", "RE_ENV_SHA": hashlib.sha256(env).hexdigest(),
                                           "AGENT_UID": str(AGENT_UID), "RELAY_UID": str(ME[0]),
                                           "HOP_GID": str(HOP_GID)}
            receipts[("S4", v["name"])] = {"RE_IMAGE": IMAGE}
        self.rec = Rec(receipts)
        self.held = types.SimpleNamespace(values={"api_key": bytearray(b"key"),
                                                  **{a2_s1.mailbox_label(n): bytearray(v) for n, v in VALUES.items()}})
        self.site = types.SimpleNamespace(vm_layer=self.layer, now=None)
        self.c = types.SimpleNamespace(inv=a2_args.Invocation("install", "L3", {}), hosts={"vms": self.vms},
                                       lock=self.lock)

    def run_stage(self):
        S.run_s6b(self.c, self.site, self.rec, self.held)

    def refuses(self, cause, rc):
        with self.assertRaises(Refusal) as cm:
            self.run_stage()
        self.assertEqual((cm.exception.cause, cm.exception.rc), (cause, rc))
        return cm.exception

    def pw(self, vm):
        return os.path.join(self.layer.homes[vm][1], e6.PASSWORD_FILE)

    def content(self, vm):
        with open(self.pw(vm), "rb") as f:
            return f.read()

    def secret_calls(self):
        return [c for c in self.layer.calls if c[2][0] == "<secret>"]


class PassTest(Base):
    def test_each_vm_gets_exactly_its_own_value_and_the_probe_passes(self):
        """The two-VM binding (3.7 rule 4): vm-a's file holds vm-a's value, vm-b's holds vm-b's, each 0400, the
        relay account's own, one link, with no newline."""
        self.run_stage()
        for n, v in VALUES.items():
            self.assertEqual(self.content(n), bytes(v))
            st = os.lstat(self.pw(n))
            self.assertEqual((st.st_mode & 0o7777, st.st_uid, st.st_gid, st.st_nlink), (0o400, ME[0], ME[1], 1))
        results = [(w[1], w[2], w[5]) for w in self.rec.written]
        self.assertEqual(results, [("vm-a", "CHANGED", None), ("vm-b", "CHANGED", None)])
        facts = dict(self.rec.written[0][3])
        self.assertEqual(facts["BINDING"], "mailbox:vm-a")
        self.assertEqual(facts["PROBE"], "ok 235")
        self.assertEqual(facts["HUB_LOGIN"], "WRITTEN")
        self.assertEqual([c[1] for c in self.secret_calls()], ["relay", "relay"])

    def test_every_call_runs_as_its_account_with_its_writes_flag(self):
        """Per VM, in order: the measure, the env re-hash and the probe as the agent account, reads; the writer as
        the relay account; the read-back stat as the relay account, a read."""
        self.run_stage()
        kinds = {a2_s6.PYTHON: "measure", S.SHA256SUM: "sha256sum", "<secret>": "writer", S.STAT: "stat",
                 S.DOCKER: "probe"}
        got = [(vm, kinds[argv[0]], account, writes) for vm, account, argv, writes in self.layer.calls]
        want = []
        for vm in ("vm-a", "vm-b"):
            want += [(vm, "measure", "agent", False), (vm, "sha256sum", "agent", False), (vm, "writer", "relay", True),
                     (vm, "stat", "relay", False), (vm, "probe", "agent", False)]
        self.assertEqual(got, want)

    def test_no_value_reaches_a_receipt_or_an_argv(self):
        self.run_stage()
        blob = repr(self.rec.written).encode() + repr([c[2] for c in self.layer.calls]).encode()
        for v in VALUES.values():
            self.assertNotIn(bytes(v[:8]), blob)

    def test_the_probe_runs_re_as_s8_runs_it(self):
        """The writer, the probe and S8 agree (S6B-d1.1 C-1): the probe's --user and --group-add are S8's start
        form for the same ids, the env-file is S6's, the file is bound read-only at its own path."""
        self.run_stage()
        probes = [c for c in self.layer.calls if c[2][0] == S.DOCKER]
        self.assertEqual(len(probes), 2)
        vm, account, argv, writes = probes[0]
        self.assertEqual((vm, account, writes), ("vm-a", "agent", False))
        agent, relay = self.layer.homes["vm-a"]
        env_file = os.path.join(agent, a2_s6.RE_ENV, a2_s6.RE_ENV_NAME)
        user = argv[argv.index("--user") + 1]
        self.assertEqual(user, "%d:%d" % ME)
        self.assertEqual(argv[argv.index("--group-add") + 1], str(HOP_GID))
        self.assertEqual(argv[argv.index("--env-file") + 1], env_file)
        pw = os.path.join(relay, e6.PASSWORD_FILE)
        self.assertEqual(argv[argv.index("--mount") + 1], "type=bind,src=%s,dst=%s,readonly" % (pw, pw))
        self.assertEqual(argv[-2:], [IMAGE, "probe-login"])
        self.assertIn("--read-only", argv)
        self.assertEqual(argv[argv.index("--name") + 1], "amap-s6b-probe-20261127t000000z-0000000a-vm-a")
        self.assertNotIn("--network", argv)

    def test_s8s_user_form_is_the_probes(self):
        """S8's RE start (a2_s8_re.start_argv) for the same ids carries the same --user and --group-add pair."""
        argv = S.probe_argv({"relay_uid": 1001, "relay_gid": 1002, "hop_gid": 1003, "relay_home": "/home/relay",
                             "home": "/home/agent"}, IMAGE, "amap-s6b-probe-x-vm-a")
        env = {k: "/home/relay/x" for k in a2_s8_re.RW_KNOBS + a2_s8_re.RO_KNOBS}
        try:
            s8 = a2_s8_re.start_argv(env, "/home/agent/.amap-relay-env/re.env", IMAGE, 1001, 1002, 1003)
        except Refusal:
            self.skipTest("S8's mount-knob rule refused the synthetic env")
        for flag in ("--user", "--group-add", "--env-file"):
            self.assertEqual(argv[argv.index(flag) + 1], s8[s8.index(flag) + 1], flag)

    def test_dry_run_plans_and_touches_nothing(self):
        self.c.inv = a2_args.Invocation("dry-run", "L3", {})
        self.run_stage()
        self.assertEqual(self.layer.calls, [])
        self.assertEqual([w[2] for w in self.rec.written], ["PLANNED", "PLANNED"])


class BeforeWriteTest(Base):
    """Every VM's inputs are read before the first write: a gap for the SECOND VM still exits 2, nothing written."""

    def assert_nothing_written(self):
        self.assertEqual(self.secret_calls(), [])
        self.assertFalse(os.path.exists(self.pw("vm-a")))

    def test_a_missing_value_for_the_second_vm(self):
        del self.held.values["mailbox:vm-b"]
        self.refuses("HUB-LOGIN.PREDECESSOR_INCOMPLETE", 2)
        self.assert_nothing_written()

    def test_an_s6_receipt_not_placed_or_short(self):
        for key, val in (("CONFIG", "PLANNED"), ("RE_ENV_SHA", "x"), ("RELAY_UID", "0")):
            with self.subTest(key=key):
                old = self.rec.receipts[("S6", "vm-b")][key]
                self.rec.receipts[("S6", "vm-b")][key] = val
                self.refuses("HUB-LOGIN.PREDECESSOR_INCOMPLETE", 2)
                self.rec.receipts[("S6", "vm-b")][key] = old
        self.assert_nothing_written()

    def test_no_re_image_or_no_hub_hostname(self):
        self.rec.receipts[("S4", "vm-b")] = {"RE_IMAGE": "latest"}
        self.refuses("HUB-LOGIN.PREDECESSOR_INCOMPLETE", 2)
        self.rec.receipts[("S4", "vm-b")] = {"RE_IMAGE": IMAGE}
        self.rec.receipts[("S3", None)] = {}
        self.refuses("HUB-LOGIN.HUB_HOSTNAME", 2)
        self.assert_nothing_written()

    def test_the_env_file_changed_on_the_vm(self):
        agent = self.layer.homes["vm-a"][0]
        with open(os.path.join(agent, a2_s6.RE_ENV, a2_s6.RE_ENV_NAME), "ab") as f:
            f.write(b"EXTRA=1\n")
        self.refuses("HUB-LOGIN.CONFIG_CHANGED", 2)
        self.assert_nothing_written()

    def test_an_env_that_no_longer_re_derives(self):
        self.lock["hub_login"]["local"] = "other"
        self.refuses("HUB-LOGIN.CONFIG_CHANGED", 2)
        self.assert_nothing_written()

    def test_measured_ids_that_are_not_s6s(self):
        self.rec.receipts[("S6", "vm-a")]["HOP_GID"] = "9999"
        self.refuses("HUB-LOGIN.CONFIG_CHANGED", 2)
        self.assert_nothing_written()


    def test_a_login_for_another_host_refuses_even_when_s6_rendered_it(self):
        """The login shape is held on its own, not only through RE_ENV_SHA: an environment() that names another
        VM's host (S6 placed what it rendered, so the sha matches) still refuses."""
        real = e6.environment

        def other_host(**kw):
            return [(k, v.replace("@vm-a.", "@vm-b.") if k in ("SMTP_USERNAME", "IMAP_USERNAME") else v)
                    for k, v in real(**kw)]
        e6.environment = other_host
        self.addCleanup(setattr, e6, "environment", real)
        agent, relay = self.layer.homes["vm-a"]
        env = e6.text(other_host(agent_home=agent, relay_home=relay, agent_uid=AGENT_UID, fleet_domain="vm-a.internal",
                                 hub_fqdn=HUB, login_local=LOGIN["local"], login_domain=LOGIN["domain"]))
        self.assertIn(b"@vm-b.", env)
        with open(os.path.join(agent, a2_s6.RE_ENV, a2_s6.RE_ENV_NAME), "wb") as f:
            f.write(env)
        self.rec.receipts[("S6", "vm-a")]["RE_ENV_SHA"] = hashlib.sha256(env).hexdigest()
        e = self.refuses("HUB-LOGIN.CONFIG_CHANGED", 2)
        self.assertEqual(e.detail, "login shape")
        self.assert_nothing_written()

class AfterWriteTest(Base):
    def test_auth_failed_is_probe_with_its_class_and_exit_3(self):
        self.layer.probe["vm-a"] = (6, b"auth_failed 535\n")
        e = self.refuses("HUB-LOGIN.PROBE", 3)
        self.assertEqual(e.detail, "auth_failed")
        self.assertEqual(self.rec.written[-1][5], "HUB-LOGIN.PROBE")

    def test_every_probe_outcome_but_ok_235_fails(self):
        for rc, out in ((0, b"ok 235"), (0, b"ok 235\nmore\n"), (0, b"ok 250\n"), (0, b""), (5, b"secret_unavailable -\n"),
                        (7, b"hub_unreachable -\n"), (11, b"temporary 451\n"), (1, b"ok 235\n"), (99, b"")):
            with self.subTest(rc=rc, out=out):
                self.layer.probe["vm-a"] = (rc, out)
                self.refuses("HUB-LOGIN.PROBE", 3)
                os.unlink(self.pw("vm-a"))
                self.layer.wrote_stages.clear()

    def test_a_probe_the_layer_could_not_finish_is_removed_by_name(self):
        """N3: a timeout (the layer's own refusal) may leave the container running; S6b removes it by its name, as
        the agent account, then lets the layer's refusal out as raised."""
        self.layer.probe["vm-a"] = Refusal("HUB-LOGIN.TARGET_ACCESS", "ssh did not complete", rc=3)
        self.refuses("HUB-LOGIN.TARGET_ACCESS", 3)
        rm = [c for c in self.layer.calls if c[2][:2] == [S.DOCKER, "rm"]]
        self.assertEqual(rm, [("vm-a", "agent", [S.DOCKER, "rm", "-f", "--",
                                                 "amap-s6b-probe-20261127t000000z-0000000a-vm-a"], True)])
        facts = dict(self.rec.written[-1][3])
        self.assertEqual(facts["PROBE_CONTAINER"], "amap-s6b-probe-20261127t000000z-0000000a-vm-a may remain; rm -f rc 0")

    def test_a_removal_that_also_fails_keeps_the_probes_own_cause(self):
        """N-a: the removal is best effort; its own refusal never replaces the layer's refusal of the probe."""
        self.layer.probe["vm-a"] = Refusal("HUB-LOGIN.TARGET_ACCESS", "ssh did not complete", rc=3)
        self.layer.rm_refuses = True
        e = self.refuses("HUB-LOGIN.TARGET_ACCESS", 3)
        self.assertEqual(e.detail, "ssh did not complete")
        self.assertEqual(len([c for c in self.layer.calls if c[2][:2] == [S.DOCKER, "rm"]]), 1)
        self.assertEqual(dict(self.rec.written[-1][3])["PROBE_CONTAINER"],
                         "amap-s6b-probe-20261127t000000z-0000000a-vm-a may remain; rm -f refused by the layer")

    def test_a_finished_probe_removes_nothing(self):
        self.layer.probe["vm-a"] = (6, b"auth_failed 535\n")
        self.refuses("HUB-LOGIN.PROBE", 3)
        self.assertEqual([c for c in self.layer.calls if c[2][:2] == [S.DOCKER, "rm"]], [])

    def test_docker_failing_is_docker(self):
        for rc in S.DOCKER_FAILED:
            with self.subTest(rc=rc):
                self.layer.probe["vm-a"] = (rc, b"")
                self.refuses("HUB-LOGIN.DOCKER", 3)
                os.unlink(self.pw("vm-a"))
                self.layer.wrote_stages.clear()

    def test_the_second_vm_failing_follows_the_first_vms_write(self):
        self.layer.probe["vm-b"] = (6, b"auth_failed 535\n")
        self.refuses("HUB-LOGIN.PROBE", 3)
        self.assertEqual([(w[1], w[2]) for w in self.rec.written], [("vm-a", "CHANGED"), ("vm-b", "FAIL")])

    def test_a_writer_refusal_on_the_first_write_is_2(self):
        os.chmod(os.path.join(self.layer.homes["vm-a"][1], ".amap-relay", "login"), 0o750)
        self.refuses("HUB-LOGIN.WRITER", 2)
        self.assertFalse(os.path.exists(self.pw("vm-a")))

    def test_a_writer_refusal_after_a_write_is_3(self):
        os.chmod(os.path.join(self.layer.homes["vm-b"][1], ".amap-relay", "login"), 0o750)
        self.refuses("HUB-LOGIN.WRITER", 3)

    def test_an_unknown_writer_outcome_is_unclassified_3(self):
        self.layer.write_secret = lambda *a, **k: (self.layer.wrote_stages.add("HUB-LOGIN"), 4)[1]
        self.refuses("HUB-LOGIN.UNCLASSIFIED", 3)

    def test_a_file_that_is_not_res_after_the_write(self):
        real = self.layer.write_secret

        def then_chmod(vm, *a, **k):
            rc = real(vm, *a, **k)
            os.chmod(self.pw(vm), 0o440)
            return rc
        self.layer.write_secret = then_chmod
        self.refuses("HUB-LOGIN.FILE", 3)
        probes = [c for c in self.layer.calls if c[2][0] == S.DOCKER]
        self.assertEqual(probes, [], "the probe never runs on a file that is not RE's")


class CauseTest(unittest.TestCase):
    def test_hub_login_sentences_are_the_contracts(self):
        import a2_causes
        from test_a2_units import contract_sentences
        want = contract_sentences()
        for cause, text in a2_causes.HUB_LOGIN_SENTENCES.items():
            self.assertEqual(want.get(cause), text, cause)
        self.assertEqual(sorted(a2_causes.HUB_LOGIN_SENTENCES),
                         sorted(k for k in want if k.startswith("HUB-LOGIN.")))
        for cause in a2_causes.HUB_LOGIN_SENTENCES:
            self.assertEqual(Refusal(cause).rc, 2)
            self.assertEqual(Refusal(cause, rc=3).rc, 3)


if __name__ == "__main__":
    unittest.main()
