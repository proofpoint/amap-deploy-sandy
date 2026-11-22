"""a2_s6: S6's steps on a fake VM layer. The measure line's shape is the shipped vm_measure.py's, captured by running
it (one sorted JSON line: agent_in_hop, gid, home, hop_gid, python, relay_gid, relay_in_hop, relay_uid, uid); the
values here are a VM's, with the relay a separate account. vm_measure itself is run once, as this account."""

import json
import os
import subprocess
import sys
import unittest

import a2fix  # noqa: F401  (puts install/ on sys.path)
import a2_s6
import vm_dirs
from a2_causes import Refusal

INSTALL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
V = {"name": "vm-a", "agent_account": "agent", "relay_account": "relay", "hop_group": "hop"}
GOOD = {"agent_in_hop": True, "gid": 1000, "home": "/home/agent", "hop_gid": 1500, "python": [3, 12],
        "relay_gid": 1001, "relay_home": "/home/relay", "relay_in_hop": True, "relay_uid": 1001, "uid": 1000}


def line(doc):
    return (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode()


class FakeLayer:
    def __init__(self, *replies, intakes="CHANGED"):
        self.replies, self.calls, self.intakes = list(replies), [], intakes

    def pinned_installer_file(self, name, stage):
        assert name in (a2_s6.MEASURE_SCRIPT, a2_s6.DIRS_SCRIPT) and stage == "CONFIG"
        return ("# pinned " + name).encode()

    def exec(self, vm, argv, *, account, stage, writes, stdin=None, timeout_s=None):
        self.calls.append(("exec", vm, argv, account, stage, writes))
        rc, out = self.replies.pop(0)
        return rc, out, b""

    def hop_intakes(self, vm, root, relay, group, *, stage):
        self.calls.append(("hop_intakes", vm, root, relay, group, stage))
        if isinstance(self.intakes, Exception):
            raise self.intakes
        return self.intakes


class MeasureTest(unittest.TestCase):

    def refuses(self, cause, L, rc=2):
        with self.assertRaises(Refusal) as cm:
            a2_s6.measure(L, "vm-a", V)
        self.assertEqual((cm.exception.cause, cm.exception.rc), (cause, rc))

    def test_the_shipped_script_prints_the_shape_parsed_here(self):
        import grp
        import pwd
        me, g = pwd.getpwuid(os.geteuid()).pw_name, grp.getgrgid(os.getegid()).gr_name
        with open(os.path.join(INSTALL, a2_s6.MEASURE_SCRIPT)) as f:
            src = f.read()
        p = subprocess.run([sys.executable, "-I", "-S", "-c", src, me, g], capture_output=True,
                           stdin=subprocess.DEVNULL, timeout=60)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(set(json.loads(p.stdout)), a2_s6.MEASURE_KEYS)
        self.assertEqual(p.stdout.count(b"\n"), 1)
        p = subprocess.run([sys.executable, "-I", "-S", "-c", src, "no-such-account-a2", g], capture_output=True,
                           stdin=subprocess.DEVNULL, timeout=60)
        self.assertEqual((p.returncode, p.stdout), (4, b""))

    def test_facts_and_the_call(self):
        L = FakeLayer((0, line(GOOD)))
        f = a2_s6.measure(L, "vm-a", V)
        self.assertEqual(f, {"home": "/home/agent", "relay_home": "/home/relay", "sandy_home": "/home/agent/.sandy", "uid": 1000, "gid": 1000,
                             "relay_uid": 1001, "relay_gid": 1001, "hop_gid": 1500, "python": "3.12"})
        self.assertEqual(L.calls, [("exec", "vm-a", ["/usr/bin/python3", "-I", "-S", "-c", "# pinned vm_measure.py",
                                                     "relay", "hop"], "agent", "CONFIG", False)])

    def test_python_311_passes_and_310_refuses(self):
        a2_s6.measure(FakeLayer((0, line(dict(GOOD, python=[3, 11])))), "vm-a", V)
        self.refuses("CONFIG.INTERPRETER", FakeLayer((0, line(dict(GOOD, python=[3, 10])))))
        self.refuses("CONFIG.INTERPRETER", FakeLayer((0, line(dict(GOOD, python=[2, 99])))))

    def test_account_refusals_are_hosts(self):
        self.refuses("CONFIG.HOSTS", FakeLayer((4, b"")))
        for change in (dict(relay_uid=1000), dict(relay_uid=0), dict(uid=0), dict(agent_in_hop=False),
                       dict(relay_in_hop=False), dict(relay_home="/home/agent"), dict(relay_home="/home/agent/r"),
                       dict(home="/home/relay/a")):
            with self.subTest(change=change):
                self.refuses("CONFIG.HOSTS", FakeLayer((0, line(dict(GOOD, **change)))))

    def test_anything_else_is_unclassified(self):
        bad = [(1, line(GOOD)), (0, b""), (0, line(GOOD) + b"x\n"), (0, line(GOOD).rstrip(b"\n")),
               (0, line(dict(GOOD, extra=1))), (0, line({k: v for k, v in GOOD.items() if k != "gid"})),
               (0, line(dict(GOOD, uid="1000"))), (0, line(dict(GOOD, uid=True))), (0, line(dict(GOOD, uid=-1))),
               (0, line(dict(GOOD, agent_in_hop=1))), (0, line(dict(GOOD, python=[3]))),
               (0, line(dict(GOOD, python=[3, "12"]))), (0, line(dict(GOOD, home="home/agent"))),
               (0, line(dict(GOOD, home="/home/../agent"))), (0, line(dict(GOOD, home="/"))),
               (0, line(dict(GOOD, home=7))), (0, line(dict(GOOD, relay_home=7))),
               (0, line(dict(GOOD, relay_home="relay"))), (0, b"[1]\n"), (0, b"NaN\n")]
        for rc, out in bad:
            with self.subTest(rc=rc, out=out[:40]):
                self.refuses("CONFIG.UNCLASSIFIED", FakeLayer((rc, out)))


def dirs_out(what="CREATED"):
    return "".join("%s %s\n" % (what, rel) for rel, _, _ in vm_dirs.DIRS).encode()


class DirectoriesTest(unittest.TestCase):
    FACTS = {"home": "/home/agent"}

    def test_dirs_then_intakes(self):
        L = FakeLayer((0, dirs_out()))
        rows, intakes = a2_s6.directories(L, "vm-a", V, self.FACTS)
        self.assertEqual(rows, [(rel, "CREATED") for rel, _, _ in vm_dirs.DIRS])
        self.assertEqual(intakes, "CHANGED")
        self.assertEqual(L.calls, [
            ("exec", "vm-a", ["/usr/bin/python3", "-I", "-S", "-c", "# pinned vm_dirs.py", "hop"], "agent", "CONFIG",
             True),
            ("hop_intakes", "vm-a", "/home/agent/.amap-hop", "relay", "hop", "CONFIG")])

    def test_not_allowed_is_owner_rc_3_and_the_intakes_are_not_tried(self):
        L = FakeLayer((4, b""))
        with self.assertRaises(Refusal) as cm:
            a2_s6.directories(L, "vm-a", V, self.FACTS)
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("CONFIG.OWNER", 3))
        self.assertEqual([c[0] for c in L.calls], ["exec"])

    def test_bad_output_is_unclassified_rc_3(self):
        good = dirs_out()
        for rc, out in ((5, b""), (0, b""), (0, good[:-1]), (0, good + b"CREATED x\n"),
                        (0, good.replace(b"CREATED .a2-registry-code\n", b"MADE .a2-registry-code\n")),
                        (0, good.replace(b".a2-registry-code\n", b".a2-registry-codex\n")),
                        (0, b"\n".join(reversed(good.rstrip(b"\n").split(b"\n"))) + b"\n")):
            with self.subTest(rc=rc, out=out[-30:]):
                L = FakeLayer((rc, out))
                with self.assertRaises(Refusal) as cm:
                    a2_s6.directories(L, "vm-a", V, self.FACTS)
                self.assertEqual((cm.exception.cause, cm.exception.rc), ("CONFIG.UNCLASSIFIED", 3))
                self.assertEqual([c[0] for c in L.calls], ["exec"])

    def test_existing_rows_and_an_intake_refusal_passes_through(self):
        L = FakeLayer((0, dirs_out("EXISTING")), intakes="ALREADY")
        self.assertEqual(a2_s6.directories(L, "vm-a", V, self.FACTS)[1], "ALREADY")
        boom = Refusal("CONFIG.OWNER", "hop intakes", rc=3)
        L = FakeLayer((0, dirs_out()), intakes=boom)
        with self.assertRaises(Refusal) as cm:
            a2_s6.directories(L, "vm-a", V, self.FACTS)
        self.assertIs(cm.exception, boom)


if __name__ == "__main__":
    unittest.main()


class FakeRecord:
    """read_receipt as a2_record.Run's: the facts of this run's predecessor receipt, or its Refusal."""
    def __init__(self, facts=None, refusal=None):
        self.facts, self.refusal, self.calls = facts, refusal, []

    def read_receipt(self, stage_id, host):
        self.calls.append((stage_id, host))
        if self.refusal is not None:
            raise Refusal(self.refusal)
        return dict(self.facts)


class HubHostnameTest(unittest.TestCase):

    def test_reads_s3s_single_receipt(self):
        rec = FakeRecord({"STAGE": "HUB-CHECK", "HUB_HOSTNAME": "a2-hub-x.example.org"})
        self.assertEqual(a2_s6.hub_hostname(rec), "a2-hub-x.example.org")
        self.assertEqual(rec.calls, [("S3", None)])

    def test_a_missing_or_malformed_fact_refuses_hub_hostname(self):
        for v in (None, "", "hub", "Hub.example.org", "hub.example.org.", "hub..example.org", "-hub.example.org",
                  "hub_x.example.org", " hub.example.org", ("a" * 61 + ".") * 4 + "abcdef"):
            facts = {"STAGE": "HUB-CHECK"} if v is None else {"HUB_HOSTNAME": v}
            with self.subTest(v=v), self.assertRaises(Refusal) as c:
                a2_s6.hub_hostname(FakeRecord(facts))
            self.assertEqual(c.exception.cause, "CONFIG.HUB_HOSTNAME")

    def test_a_253_character_name_passes(self):
        name = ("a" * 61 + ".") * 4 + "abcde"
        self.assertEqual(a2_s6.hub_hostname(FakeRecord({"HUB_HOSTNAME": name})), name)

    def test_the_readers_own_causes_stand(self):
        for cause in ("HUB-CHECK.PREDECESSOR_MISSING", "HUB-CHECK.PREDECESSOR_FAILED"):
            with self.subTest(cause=cause), self.assertRaises(Refusal) as c:
                a2_s6.hub_hostname(FakeRecord(refusal=cause))
            self.assertEqual(c.exception.cause, "CONFIG." + cause.partition(".")[2])


#: RL's captured `peer-store show --json` outputs at its ALPHA-2 pin (RL's answers 90f00634 and 300500a2: before init, and after).
SHOW_ABSENT = b'{"artefacts": [], "clock": null, "meta": "absent", "problems": [], "store": "absent", "v": 1}\n'
SHOW_READY = (b'{"artefacts": ["peer-clock.json", "peer-epochs", "peer-replay"], "clock": {"H": "2026-11-20T22:11:06Z", '
              b'"admission": "open", "f": 300, "floor": null, "p": 3600}, "meta": "present", "problems": [], '
              b'"store": "ready", "v": 1}\n')
INIT_OK = b'{"H": "2026-11-20T22:11:06Z", "admission": "open", "f": 300, "p": 3600}\n'


class RLLayer(FakeLayer):
    """The layer after placement: S6 has written."""
    def wrote(self, stage):
        return True


class RLChecksTest(unittest.TestCase):
    F = {"home": "/home/agent"}

    def run_rl(self, *replies):
        L = RLLayer(*replies)
        try:
            return a2_s6.rl_checks(L, "vm-a", V, self.F), L
        except Refusal as e:
            return (e.cause, e.rc), L

    def verbs(self, L):
        return [c[2][8:] for c in L.calls]

    def test_a_fresh_store_is_initialised_once(self):
        got, L = self.run_rl((0, b"matrix\n"), (0, SHOW_ABSENT), (0, INIT_OK), (0, SHOW_READY))
        self.assertEqual(got, [("RL_PEERS", "PASS"), ("PEER_STORE", "INITIALISED")])
        self.assertEqual(self.verbs(L), [["peers"], ["peer-store", "show", "--json"],
                                         ["peer-store", "init", "--never-admitted"], ["peer-store", "show", "--json"]])
        self.assertEqual([c[5] for c in L.calls], [False, False, True, False])

    def test_the_argv_is_rls_tree_through_the_shim_as_the_agent(self):
        _, L = self.run_rl((0, b""), (0, SHOW_READY))
        argv = L.calls[0][2]
        self.assertEqual(argv[:8], ["/usr/bin/python3", "-I", "-B", "-c", a2_s6.RL_SHIM, "/home/agent/.amap-router-code",
                                    "--config", "/home/agent/.amap-router/router.json"])
        self.assertEqual(L.calls[0][3], "agent")

    def test_a_ready_store_is_already_and_never_initialised(self):
        got, L = self.run_rl((0, b""), (0, SHOW_READY))
        self.assertEqual(got, [("RL_PEERS", "PASS"), ("PEER_STORE", "ALREADY")])
        self.assertEqual(len(L.calls), 2)

    def test_peers_failing_refuses_router_config(self):
        got, L = self.run_rl((2, b""))
        self.assertEqual(got, ("CONFIG.ROUTER_REFUSED", 3))
        self.assertEqual(len(L.calls), 1)

    def test_init_failing_refuses_and_is_not_retried(self):
        got, L = self.run_rl((0, b""), (0, SHOW_ABSENT), (1, b""))
        self.assertEqual(got, ("CONFIG.PEER_STORE", 3))
        self.assertEqual(len(L.calls), 3)

    def test_a_store_not_ready_after_init_refuses(self):
        for after in (SHOW_ABSENT, SHOW_READY.replace(b'"open"', b'"closed"'),
                      SHOW_READY.replace(b'"problems": []', b'"problems": ["x"]'),
                      SHOW_READY.replace(b', "peer-replay"', b'')):
            with self.subTest(after=after):
                got, _ = self.run_rl((0, b""), (0, SHOW_ABSENT), (0, INIT_OK), (0, after))
                self.assertEqual(got, ("CONFIG.PEER_STORE", 3))

    def test_a_partial_or_closed_existing_store_refuses_and_is_never_initialised(self):
        for show in (SHOW_READY.replace(b'"store": "ready"', b'"store": "partial"'),
                     SHOW_READY.replace(b'"open"', b'"closed"'), b"not json\n", b'{"store": "odd"}\n'):
            with self.subTest(show=show):
                got, L = self.run_rl((0, b""), (0, show))
                self.assertEqual(got, ("CONFIG.PEER_STORE", 3))
                self.assertEqual(len(L.calls), 2)

    def test_show_failing_refuses(self):
        got, _ = self.run_rl((0, b""), (1, SHOW_READY))
        self.assertEqual(got, ("CONFIG.PEER_STORE", 3))


import test_a2_registry as TR  # noqa: E402  (HOST's captured lines)

VR = dict(V, fleet_domain=TR.DOMAIN, router={"slug": "router-vm1", "stable_key": "/scratch/keys/router-vm1"})
REFUSED_KEY_BOUND = b'{"error": {"code": "key_bound", "detail": "x"}, "ok": false}\n'


class RegistryTest(unittest.TestCase):
    F = {"home": "/home/agent"}

    def run_reg(self, *replies):
        L = RLLayer(*replies)
        L.stdins = []
        orig = L.exec

        def exec_(vm, argv, *, account, stage, writes, stdin=None, timeout_s=None):
            L.stdins.append(stdin)
            return orig(vm, argv, account=account, stage=stage, writes=writes)
        L.exec = exec_
        try:
            return a2_s6.registry(L, "vm-a", VR, self.F, "20261120T224500Z-0123abcd", dict(a2fix.FIXTURE_REGISTRY)), L
        except Refusal as e:
            return (e.cause, e.rc), L

    def test_plan_apply_show(self):
        got, L = self.run_reg((0, TR.PLAN), (0, TR.APPLY), (0, TR.SHOW))
        self.assertEqual(got, [("ROUTER_LOGICAL_ID", TR.LID), ("REGISTRY", "CREATED")])
        plan, apply_, show = (c[2] for c in L.calls)
        tree = ["/usr/bin/python3", "-I", "-B", "-c"]
        self.assertEqual(plan[:4], tree)
        self.assertEqual(plan[5:], ["/home/agent/.a2-registry-code", "--registry", "/home/agent/.amap-registry", "plan",
                                    "import", "--batch", "/home/agent/.amap-registry-batch/import.json"])
        self.assertIn('"regtool.opverbs"', plan[4])
        self.assertEqual(apply_[5:], ["/home/agent/.a2-registry-code", "--registry", "/home/agent/.amap-registry", "apply",
                                      "import", "--batch", "/home/agent/.amap-registry-batch/import.json",
                                      "--confirm", "0876bd85f03a5c39", "--operator", "a2-installer",
                                      "--reason", "S6 20261120T224500Z-0123abcd"])
        self.assertEqual(show[5:], ["/home/agent/.a2-registry-code", "--registry", "/home/agent/.amap-registry"])
        self.assertIn('"regtool"', show[4])
        self.assertEqual(json.loads(L.stdins[2]), {"interface": "regtool.adapter/1", "op": "show",
                                                   "adapter": "sandy", "key": "/scratch/keys/router-vm1"})
        self.assertEqual([c[5] for c in L.calls], [False, True, False])
        self.assertEqual({c[3] for c in L.calls}, {"agent"})

    def test_already_bound_is_already(self):
        plan = TR.edit(TR.PLAN, lambda d: d["plan"]["items"][0].update(action="already_bound"))
        apply_ = TR.edit(TR.APPLY, lambda d: (d["plan"]["items"][0].update(action="already_bound"),
                                              d["results"][0].update(status="already_bound")))
        got, _ = self.run_reg((0, plan), (0, apply_), (0, TR.SHOW))
        self.assertEqual(got, [("ROUTER_LOGICAL_ID", TR.LID), ("REGISTRY", "ALREADY")])

    def test_confirm_mismatch_replans_once(self):
        got, L = self.run_reg((0, TR.PLAN), (1, TR.CONFIRM_MISMATCH), (0, TR.PLAN), (0, TR.APPLY), (0, TR.SHOW))
        self.assertEqual(got[1], ("REGISTRY", "CREATED"))
        self.assertEqual(len(L.calls), 5)

    def test_a_second_replan_refuses(self):
        got, L = self.run_reg((0, TR.PLAN), (1, TR.CONFIRM_MISMATCH), (0, TR.PLAN), (1, TR.CONFIRM_MISMATCH))
        self.assertEqual(got, ("CONFIG.REGISTRY", 3))
        self.assertEqual(len(L.calls), 4)

    def test_a_hard_refusal_is_never_retried(self):
        got, L = self.run_reg((0, TR.PLAN), (1, REFUSED_KEY_BOUND))
        self.assertEqual(got, ("CONFIG.REGISTRY", 3))
        self.assertEqual(len(L.calls), 2)

    def test_a_bad_plan_or_show_refuses(self):
        got, _ = self.run_reg((0, b"{}\n"))
        self.assertEqual(got, ("CONFIG.REGISTRY", 3))
        got, _ = self.run_reg((0, TR.PLAN), (0, TR.APPLY), (1, TR.NOT_FOUND))
        self.assertEqual(got, ("CONFIG.REGISTRY", 3))
        other = TR.edit(TR.SHOW, lambda d: d["binding"].update(address="router-vm1@other.example.org"))
        got, _ = self.run_reg((0, TR.PLAN), (0, TR.APPLY), (0, other))
        self.assertEqual(got, ("CONFIG.REGISTRY", 3))

    def test_host_json(self):
        doc = json.loads(a2_s6.host_json("vm1.internal", "/home/agent", "regtool.config/1"))
        self.assertEqual(doc, {"schema": "regtool.config/1", "domain": "vm1.internal",
                               "adapters": {"sandy": {"instances_dir": "/home/agent/.amap-registry/instances"}}})


class PlaceLayer:
    """exec runs the shipped vm_place for real, in-process, against a temporary HOME; the call is recorded."""
    def __init__(self, home, rc=None, out=None):
        self.home, self.rc, self.out, self.calls = home, rc, out, []

    def pinned_installer_file(self, name, stage):
        assert name == a2_s6.PLACE_SCRIPT and stage == "CONFIG"
        with open(os.path.join(INSTALL, name), "rb") as f:
            return f.read()

    def exec(self, vm, argv, *, account, stage, writes, stdin=None, timeout_s=None):
        self.calls.append((argv[:4], argv[5:], account, stage, writes))
        if self.rc is not None:
            return self.rc, self.out, b""
        p = subprocess.run([sys.executable] + argv[1:], input=stdin, capture_output=True, env={"HOME": self.home},
                           timeout=60)
        return p.returncode, p.stdout, p.stderr


class PlaceTest(unittest.TestCase):
    E = [("bin", 0o40755, None), ("bin/t", 0o100755, b"#!/bin/sh\n"), ("a.json", 0o100644, b"{}\n")]

    def setUp(self):
        import shutil
        import tempfile
        self.d = tempfile.mkdtemp(prefix="a2s6place-")
        self.addCleanup(shutil.rmtree, self.d, True)
        os.chmod(self.d, 0o755)

    def place(self, L, entries=None, exact=True):
        try:
            return a2_s6.place(L, "vm-a", V, ".root", entries or self.E, exact=exact)
        except Refusal as e:
            return e.cause, e.rc

    def test_changed_then_already(self):
        L = PlaceLayer(self.d)
        self.assertEqual(self.place(L), "CHANGED")
        self.assertEqual(self.place(L), "ALREADY")
        self.assertEqual(L.calls[0], (["/usr/bin/python3", "-I", "-S", "-c"], [".root", "exact"], "agent", "CONFIG",
                                      True))
        self.assertEqual(self.place(L, exact=False), "ALREADY")
        self.assertEqual(L.calls[-1][1], [".root", "subset"])

    def test_different_bytes_refuse_placed_different(self):
        self.place(PlaceLayer(self.d))
        self.assertEqual(self.place(PlaceLayer(self.d), self.E[:2] + [("a.json", 0o100644, b"[]\n")]),
                         ("CONFIG.PLACED_DIFFERENT", 3))

    def test_an_untrusted_root_refuses_owner(self):
        os.makedirs(os.path.join(self.d, ".root"))
        os.chmod(os.path.join(self.d, ".root"), 0o777)
        self.assertEqual(self.place(PlaceLayer(self.d)), ("CONFIG.OWNER", 3))

    def test_output_that_does_not_name_every_entry_in_order_refuses(self):
        for out in (b"", b"PLACED bin\nPLACED bin/t\n", b"PLACED bin\nPLACED a.json\nPLACED bin/t\n",
                    b"PLACED bin\nPLACED bin/t\nMADE a.json\n", b"PLACED bin\nPLACED bin/t\nPLACED a.json"):
            with self.subTest(out=out):
                self.assertEqual(self.place(PlaceLayer(self.d, rc=0, out=out)), ("CONFIG.UNCLASSIFIED", 3))
        for rc in (2, 5, 6, 1):
            with self.subTest(rc=rc):
                self.assertEqual(self.place(PlaceLayer(self.d, rc=rc, out=b"")), ("CONFIG.UNCLASSIFIED", 3))
        self.assertEqual(self.place(PlaceLayer(self.d, rc=0, out=b"SAME bin\nSAME bin/t\nSAME a.json\n")), "ALREADY")


class RelayDirsTest(unittest.TestCase):
    GOOD = "".join("CREATED %s\n" % r for r, _, _ in vm_dirs.RELAY_DIRS).encode()

    def test_runs_as_the_relay_account_and_parses(self):
        L = FakeLayer((0, self.GOOD))
        rows = a2_s6.relay_directories(L, "vm-a", V)
        self.assertEqual(rows, [(r, "CREATED") for r, _, _ in vm_dirs.RELAY_DIRS])
        self.assertEqual(L.calls[0][2][5:], ["--relay"])
        self.assertEqual((L.calls[0][3], L.calls[0][5]), ("relay", True))

    def test_refusals(self):
        for reply, cause in (((4, b""), "CONFIG.OWNER"), ((5, b""), "CONFIG.UNCLASSIFIED"),
                             ((0, self.GOOD[:-1]), "CONFIG.UNCLASSIFIED")):
            with self.subTest(reply=reply), self.assertRaises(Refusal) as cm:
                a2_s6.relay_directories(FakeLayer(reply), "vm-a", V)
            self.assertEqual((cm.exception.cause, cm.exception.rc), (cause, 3))
