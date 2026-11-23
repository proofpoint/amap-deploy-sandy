"""The S2-S6 dispatch (a2_main), the per-VM loop (a2_stage) and the S5/S6 stage runners, on a real run record
(a2_record.Run in a run directory made as S0 makes it, so every receipt passes the real 3.3 reader) and a scripted
VM layer that answers each script and verb as the shipped scripts and RL/HOST answer (their captured shapes)."""

import copy
import json
import os
import shutil
import types
import unittest

import a2fix
import a2_args
import a2_guard
import a2_main
import a2_record
import a2_rundir
import a2_s5
import a2_s6
import a2_s6_render as r6
import a2_site
import a2_stage
import test_a2_registry as TR
import vm_bootstrap
import vm_dirs
import vm_place
from a2_causes import Refusal

RID = "20261120T224500Z-0123abcd"
SHA = "c" * 64
PUB = {"vm-a-t": "ab" * 32, "vm-b-t": "cd" * 32}
SHOW_READY = (b'{"artefacts": ["peer-clock.json", "peer-epochs", "peer-replay"], "clock": {"H": "2026-11-20T22:11:06Z", '
              b'"admission": "open", "f": 300, "floor": null, "p": 3600}, "meta": "present", "problems": [], '
              b'"store": "ready", "v": 1}\n')


def hosts():
    h = a2fix.hosts_doc("/srv/locks")
    h = copy.deepcopy(h)
    h["agents"] = [{"id": "agent-a", "vm": "vm-a-t", "connector": "connector"},
                   {"id": "agent-b", "vm": "vm-b-t", "connector": "connector"}]
    return h


def lock():
    return copy.deepcopy(a2fix.LOCK)


class Layer:
    """The VM layer after S2. Each pinned script is recognised by its stand-in text; the router and registry
    program by their shim. Records every call."""

    def __init__(self, normalise=None):
        self.calls, self._wrote, self.placed = [], set(), {}
        #: The registry program's key normalisation (HOST's answer f46595f6, lines 17-20: it probes the VM's
        #: filesystem). The identity unless a case names another.
        self.normalise = normalise or (lambda key: key)

    def wrote(self, stage):
        return stage in self._wrote

    def pinned_installer_file(self, name, stage):
        return ("# pinned " + name).encode()

    def component_file(self, component, path, *, stage):
        self.calls.append(("component_file", component, path))
        return b"plugin bytes"

    def component_tree(self, component, prefix, *, stage):
        self.calls.append(("component_tree", component, prefix))
        if prefix == "payload":
            names = [("relay", 0o755), ("handoff-sessions", 0o755), ("submit-server", 0o755),
                     ("mcp-servers.json", 0o644), ("INBOX-POLICY.md", 0o644)]
        elif prefix == "bin":
            names = [("inbox-delivery", 0o755), ("_inboxlib.py", 0o644), ("inbox-mcp-vol", 0o755),
                     ("inbox-submit", 0o755)]
        else:
            names = [("__init__.py", 0o644), ("__main__.py", 0o644), ("sub/mod.py", 0o644)]
        return "tree", [(n, m, n.encode()) for n, m in names]

    def install_file(self, vm, data, path, *, mode, stage):
        self.calls.append(("install_file", vm, path, mode))
        self._wrote.add(stage)
        return "CHANGED"

    def hop_intakes(self, vm, root, relay, group, *, stage):
        self.calls.append(("hop_intakes", vm, root))
        return "CHANGED"

    def exec(self, vm, argv, *, account, stage, writes, stdin=None, timeout_s=None):
        if writes:
            self._wrote.add(stage)
        src = argv[4]
        self.calls.append(("exec", vm, src[:40], argv[5:], account, writes))
        if src == "# pinned vm_measure.py":
            uid = 1000 if vm == "vm-a-t" else 2000
            doc = {"agent_in_hop": True, "gid": uid, "home": "/srv/agent", "hop_gid": 1500, "python": [3, 12],
                   "relay_gid": uid + 1, "relay_home": "/srv/relay", "relay_in_hop": True, "relay_uid": uid + 1,
                   "uid": uid}
            return 0, (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode(), b""
        if src == "# pinned vm_dirs.py":
            dirs = vm_dirs.RELAY_DIRS if argv[5:] == ["--relay"] else vm_dirs.DIRS
            return 0, "".join("CREATED %s\n" % r for r, _, _ in dirs).encode(), b""
        if src == "# pinned vm_place.py":
            for p, _m, b in vm_place.parse(stdin):
                self.placed[(vm, argv[5], "/".join(p))] = b
            return 0, "".join("PLACED %s\n" % "/".join(p) for p, _m, _b in vm_place.parse(stdin)).encode(), b""
        if src == a2_s6.RL_SHIM:
            verb = argv[8:]
            if verb == ["peers"]:
                return 0, b"matrix\n", b""
            return 0, SHOW_READY, b""
        if "regtool.opverbs" in src:
            # HOST returns the batch's stable_key (the hosts file's router.stable_key) after its own normalisation.
            key = self.normalise({d["name"]: d["router"]["stable_key"] for d in hosts()["vms"]}[vm])
            return 0, (TR.PLAN if "plan" in argv else TR.APPLY).replace(b"/scratch/keys/router-vm1", key.encode()).replace(
                b"router-vm1", vm_slug(vm).encode()), b""
        if "regtool" in src:
            return 0, TR.SHOW.replace(b"router-vm1", vm_slug(vm).encode()).replace(
                b"fleet.example.org", vm_domain(vm).encode()), b""
        raise AssertionError("unexpected exec " + src[:40])


def vm_slug(vm):
    return {"vm-a-t": "router-a-t", "vm-b-t": "router-b-t"}[vm]


def vm_domain(vm):
    return {"vm-a-t": "a-t.internal", "vm-b-t": "b-t.internal"}[vm]


class Base(unittest.TestCase):
    def setUp(self):
        self.base = a2fix.make_base()
        self.addCleanup(shutil.rmtree, self.base, True)
        self.w = a2fix.World(self.base)
        self.run_fd = a2_rundir.create_run_dir(self.w.home, RID, os.getuid())
        self.addCleanup(os.close, self.run_fd)
        self.rec = a2_record.Run(self.run_fd, a2_guard.OutputGuard(), RID, "install", "L1", SHA, a2fix.H64,
                                 a2fix.H64, now=1794790923)
        self.site = types.SimpleNamespace(now=1794790923, vm_layer=None)
        self.c = types.SimpleNamespace(hosts=hosts(), lock=lock(),
                                       inv=types.SimpleNamespace(command="install", loop="L1", opts={"from": "S3"}))

    def receipt(self, sid, host):
        return a2_record.check_receipt(a2_record._read_at(self.rec.receipts_fd, a2_record.receipt_name(sid, host)),
                                       sid, host, None)

    def prior(self, hub="a2-hub-x.example.org"):
        self.rec.write_receipt("S3", None, "2026-11-20T22:45:00Z", "PASS", [("HUB_HOSTNAME", hub)])
        for vm, slug in (("vm-a-t", "router-a-t"), ("vm-b-t", "router-b-t")):
            self.rec.write_receipt("S5", vm, "2026-11-20T22:45:00Z", "CHANGED",
                                   [("KEY_ID", slug + "-k1"), ("KEY_PUBLIC", PUB[vm]), ("KEY", "CREATED")])


class DispatchTest(unittest.TestCase):

    def inv(self, command="install", loop=None, **opts):
        return types.SimpleNamespace(command=command, loop=loop, opts=opts)

    def test_the_stages_each_run_selects(self):
        self.assertEqual(a2_main.run_stages(self.inv()), list(a2_args.STAGE_IDS[2:]))
        self.assertEqual(a2_main.run_stages(self.inv("dry-run")), list(a2_args.STAGE_IDS[2:]))
        self.assertEqual(a2_main.run_stages(self.inv(loop="L1", only="S5")), ["S5"])
        self.assertEqual(a2_main.run_stages(self.inv(loop="L1", only="S0")), [])
        self.assertEqual(a2_main.run_stages(self.inv(loop="L1", **{"from": "S3"})), list(a2_args.STAGE_IDS[3:]))
        self.assertEqual(a2_main.run_stages(self.inv("verify")), list(a2_args.STAGE_IDS[2:]))

    def test_the_dispatch_table_and_the_built_ins(self):
        self.assertEqual(a2_main.DISPATCH, {"S2": "run_s2", "S3": "run_s3", "S4": "run_s4", "S5": "run_s5",
                                            "S6": "run_s6"})
        site = a2_site.Site()
        self.assertEqual((site.run_s2, site.run_s3, site.run_s4), (None, None, None))
        self.assertEqual((site.run_s5, site.run_s6), (a2_site.BUILT_IN, a2_site.BUILT_IN))
        self.assertIs(a2_main.built_in("S5"), a2_s5.run_s5)
        self.assertIs(a2_main.built_in("S6"), a2_s6.run_s6)
        self.assertIsNone(a2_main.built_in("S4"))


class PerVmTest(Base):

    def test_one_receipt_each_and_a_refusal_stops_there(self):
        seen = []

        def step(n):
            seen.append(n)
            if n == "vm-b-t":
                raise Refusal("CONFIG.OWNER", n, rc=3)
            return [("X", "1")], "CHANGED"
        with self.assertRaises(Refusal):
            a2_stage.per_vm(self.rec, self.site, "S6", ["vm-a-t", "vm-b-t", "vm-c"], step)
        self.assertEqual(seen, ["vm-a-t", "vm-b-t"])
        facts, rc = self.receipt("S6", "vm-a-t")
        self.assertEqual((facts["RESULT"], facts["X"], rc), ("CHANGED", "1", 0))
        facts, rc = self.receipt("S6", "vm-b-t")
        self.assertEqual((facts["RESULT"], facts["CAUSE"], rc), ("FAIL", "CONFIG.OWNER", 3))
        self.assertNotIn(("S6", "vm-c"), [(s["stage"], s["host"]) for s in self.rec.stages])

    def test_a_dry_run_plans_and_calls_no_step(self):
        a2_stage.per_vm(self.rec, self.site, "S5", ["vm-a-t"], None, plan=lambda n: [("KEY_ID", "k")], dry_run=True)
        facts, rc = self.receipt("S5", "vm-a-t")
        self.assertEqual((facts["RESULT"], facts["KEY_ID"], rc), ("PLANNED", "k", 0))

    def test_scope(self):
        self.assertEqual([a2_stage.scope_of(x) for x in ("L1", "L2", "L2-leak", "L3", None)],
                         ["loop", "loop", "loop", "l3", "l3"])


class S5Test(Base):

    def test_without_the_vm_layer_refuses_target_access_in_the_first_receipt(self):
        with self.assertRaises(Refusal) as cm:
            a2_s5.run_s5(self.c, self.site, self.rec)
        self.assertEqual(cm.exception.cause, "KEYS.TARGET_ACCESS")
        self.assertEqual(self.receipt("S5", "vm-a-t")[0]["CAUSE"], "KEYS.TARGET_ACCESS")

    def test_dry_run_plans_each_key_id(self):
        self.c.inv.command = "dry-run"
        a2_s5.run_s5(self.c, self.site, self.rec)
        self.assertEqual([self.receipt("S5", vm)[0]["KEY_ID"] for vm in ("vm-a-t", "vm-b-t")],
                         ["router-a-t-k1", "router-b-t-k1"])


class S6Test(Base):

    def test_a_key_the_registry_normalises_is_the_one_recorded(self):
        """The registry program returns another key than the hosts file's (its filesystem normalisation): S6
        completes, and the receipt records the program's key, never the raw one."""
        self.prior()
        L = Layer(normalise=lambda key: key.upper())
        self.site.vm_layer = L
        a2_s6.run_s6(self.c, self.site, self.rec)
        for vm in ("vm-a-t", "vm-b-t"):
            facts, rc = self.receipt("S6", vm)
            key = {d["name"]: d["router"]["stable_key"] for d in hosts()["vms"]}[vm]
            self.assertNotEqual(key.upper(), key)
            self.assertEqual((facts["REGISTRY"], facts["ROUTER_STABLE_KEY"], rc), ("CREATED", key.upper(), 0))

    def test_a_full_run_on_both_vms(self):
        self.prior()
        L = Layer()
        self.site.vm_layer = L
        a2_s6.run_s6(self.c, self.site, self.rec)
        for vm in ("vm-a-t", "vm-b-t"):
            facts, rc = self.receipt("S6", vm)
            self.assertEqual((facts["RESULT"], facts["CONFIG"], facts["PEER_STORE"], facts["REGISTRY"], rc),
                             ("CHANGED", "PLACED", "ALREADY", "CREATED", 0))
            self.assertEqual(facts["PLUGIN_SHA"], a2_s6._sha(b"plugin bytes"))
            self.assertEqual(facts["PREFIX_JSON_SHA"], a2_s6._sha(L.placed[(vm, ".amap-relay-config", "prefix.json")]))
            self.assertEqual(facts["D7_SHA"], a2_s6._sha(L.placed[(vm, ".amap-relay-config", "d7.json")]))
            key = {d["name"]: d["router"]["stable_key"] for d in hosts()["vms"]}[vm]
            self.assertEqual(facts["ROUTER_STABLE_KEY"], key)
        roots = [c[3][0] for c in L.calls if c[0] == "exec" and c[2] == "# pinned vm_place.py"]
        self.assertEqual(roots[:8], [".amap-router-code", ".a2-registry-code", ".sandy/features/amap", ".amap-router",
                                     ".amap-relay-env", ".amap-relay-config", ".amap-registry",
                                     ".amap-registry-batch"])
        self.assertIn(("component_tree", "registry", "regtool"), L.calls)
        self.assertIn(("component_file", "router", "dist/plugin.py"), L.calls)
        placed = [c for c in L.calls if c[0] == "install_file"]
        self.assertEqual(placed, [("install_file", "vm-a-t", vm_bootstrap.PLUGIN, 0o444),
                                  ("install_file", "vm-b-t", vm_bootstrap.PLUGIN, 0o444)])
        # The argument S6 passes is one the real bootstrap admits, and it names the file router.json and the
        # env-file name from /.
        for _op, _vm, path, mode in placed:
            self.assertTrue(vm_bootstrap._allowed(path, mode))
            self.assertEqual("/" + path, r6.PLUGIN_PATH)
        relay = [c for c in L.calls if c[0] == "exec" and c[3] == ["--relay"]]
        self.assertEqual([c[4] for c in relay], ["relay", "relay"])

    def test_the_plugin_must_be_hops_pin(self):
        self.prior()
        L = Layer()
        L.component_file = lambda *a, **k: b"other bytes"
        self.site.vm_layer = L
        with self.assertRaises(Refusal) as cm:
            a2_s6.run_s6(self.c, self.site, self.rec)
        self.assertEqual(cm.exception.cause, "CONFIG.PIN")

    def setUp(self):
        super().setUp()
        old = r6.PLUGIN_SHA256
        r6.PLUGIN_SHA256 = a2_s6._sha(b"plugin bytes")
        self.addCleanup(setattr, r6, "PLUGIN_SHA256", old)

    def test_a_value_the_renders_refuse_stops_before_any_write(self):
        """A login domain longer than the env-file's 63-character rule (Opus's r8 N3 example): the renders run
        before S6's first write, so the stage refuses UNCLASSIFIED rc 2 with no write made on the VM."""
        self.prior()
        self.c.lock["hub_login"]["domain"] = "d" * 64 + ".example.org"
        L = Layer()
        self.site.vm_layer = L
        with self.assertRaises(Refusal) as cm:
            a2_s6.run_s6(self.c, self.site, self.rec)
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("CONFIG.UNCLASSIFIED", 2))
        self.assertFalse(L.wrote("CONFIG"))
        self.assertEqual([c for c in L.calls if c[0] == "install_file"], [])
        facts, rc = self.receipt("S6", "vm-a-t")
        self.assertEqual((facts["CAUSE"], rc), ("CONFIG.UNCLASSIFIED", 2))

    def test_before_any_vm_each_refusal_is_in_the_first_receipt(self):
        cases = [
            (lambda: None, "CONFIG.TARGET_ACCESS"),
            (lambda: setattr(self.site, "vm_layer", Layer()), "CONFIG.PREDECESSOR_MISSING"),
        ]
        for prep, cause in cases:
            with self.subTest(cause=cause):
                self.setUp()
                prep()
                with self.assertRaises(Refusal) as cm:
                    a2_s6.run_s6(self.c, self.site, self.rec)
                self.assertEqual(cm.exception.cause, cause)
                self.assertEqual(self.receipt("S6", "vm-a-t")[0]["CAUSE"], cause)

    def test_a_bad_hub_hostname_refuses_before_any_vm_call(self):
        self.prior(hub="Not A Name")
        L = Layer()
        self.site.vm_layer = L
        with self.assertRaises(Refusal) as cm:
            a2_s6.run_s6(self.c, self.site, self.rec)
        self.assertEqual(cm.exception.cause, "CONFIG.HUB_HOSTNAME")
        self.assertEqual(L.calls, [])

    def test_a_scope_of_other_than_two_vms_refuses(self):
        self.c.hosts["vms"] = self.c.hosts["vms"][:1] + self.c.hosts["vms"][2:]
        self.site.vm_layer = Layer()
        with self.assertRaises(Refusal) as cm:
            a2_s6.run_s6(self.c, self.site, self.rec)
        self.assertEqual(cm.exception.cause, "CONFIG.HOSTS")

    def test_dry_run_touches_no_vm(self):
        self.c.inv.command = "dry-run"
        L = Layer()
        self.site.vm_layer = L
        a2_s6.run_s6(self.c, self.site, self.rec)
        self.assertEqual(L.calls, [])
        self.assertEqual(self.receipt("S6", "vm-b-t")[0]["RESULT"], "PLANNED")


if __name__ == "__main__":
    unittest.main()


import test_a2_s1  # noqa: E402  (its harness pieces: a World, its git remotes, S1's prompt)


class DispatchUnitTest(unittest.TestCase):

    def run_dispatch(self, command="install", loop="L2", opts=None, **slots):
        calls = []
        site = types.SimpleNamespace(**{slot: None for slot in a2_main.DISPATCH.values()})
        for slot, sid in slots.items():
            setattr(site, slot, (lambda s: lambda c, st, rec: calls.append(s))(sid))
        c = types.SimpleNamespace(inv=types.SimpleNamespace(command=command, loop=loop, opts=opts or {}))
        active = ["S1"]
        stop = a2_main.dispatch(c, site, None, active)
        return stop, calls, active[0]

    def all_slots(self):
        return {slot: sid for sid, slot in a2_main.DISPATCH.items()}

    def test_every_slot_in_order_then_the_first_undispatched_stage_stops(self):
        stop, calls, active = self.run_dispatch(**self.all_slots())
        self.assertEqual(calls, ["S2", "S3", "S4", "S5", "S6"])
        self.assertEqual((stop.cause, stop.rc, stop.detail), ("RUNNER.UNCLASSIFIED", 3, "S6b not built"))
        self.assertEqual(active, "S6")

    def test_an_unfilled_slot_stops_there(self):
        slots = self.all_slots()
        del slots["run_s4"]
        stop, calls, _ = self.run_dispatch(**slots)
        self.assertEqual(calls, ["S2", "S3"])
        self.assertEqual(stop.detail, "S4 not built")

    def test_an_l1_set_inside_the_dispatch_ends_with_none(self):
        stop, calls, _ = self.run_dispatch(loop="L1", opts={"only": "S5"}, **self.all_slots())
        self.assertEqual((stop, calls), (None, ["S5"]))

    def test_a_command_it_does_not_run_calls_no_stage(self):
        for command in ("verify", "destroy", "canary"):
            with self.subTest(command=command):
                stop, calls, _ = self.run_dispatch(command=command, **self.all_slots())
                self.assertEqual((calls, stop.cause, stop.rc, stop.detail),
                                 ([], "RUNNER.UNCLASSIFIED", 3, command + " not built"))

    def test_dry_run_dispatches(self):
        _stop, calls, _ = self.run_dispatch(command="dry-run", **self.all_slots())
        self.assertEqual(calls, ["S2", "S3", "S4", "S5", "S6"])


class RunnerDispatchTest(test_a2_s1._KeepsMask):
    """The dispatch inside a full run (S0, S1, the stages, S10), with test_a2_s1's harness for a chosen command
    line: L2 stops at the first stage past S6; an L1 whose one stage passes ends with 0."""
    site_for = test_a2_s1.RunnerS1Test.site_for
    read = test_a2_s1.RunnerS1Test.read
    finished = test_a2_s1.RunnerS1Test.finished

    def admit(self, argv):
        import hashlib
        import a2_budget
        import a2_locks
        self.base = a2fix.make_base()
        self.addCleanup(shutil.rmtree, self.base, True)
        self.w = a2fix.World(self.base)
        self.gw = a2fix.GitWorld(self.w)
        held = []
        self.addCleanup(lambda: [a2_locks.release(h) for h in held])
        inv = a2_args.parse(argv)
        vms = a2_locks.run_vms(self.w.hosts, inv, "loop")
        held.append(a2_locks.acquire(a2_locks.lock_order(self.w.root, a2_locks.targets(self.w.hosts, vms), True),
                                     os.getuid()))
        b = a2fix.FakeBroker(self.w)
        try:
            shas = []
            for n in ("alpha2.lock", "alpha2.hosts"):
                with open(os.path.join(self.w.private, n), "rb") as f:
                    shas.append(hashlib.sha256(f.read()).hexdigest())
            self.rid, _ = a2_budget.ask_broker(self.w.root, inv, shas[0], shas[1], "c" * 64, root_uid=os.getuid())
        finally:
            b.close()

    def slots(self, calls):
        def stage(sid):
            def run_sn(c, site, rec):
                calls.append(sid)
                rec.write_receipt(sid, None if sid == "S3" else c.hosts["vms"][0]["name"], rec.started, "PASS", [])
            return run_sn
        return {slot: stage(sid) for sid, slot in a2_main.DISPATCH.items()}

    def test_l2_runs_every_slot_and_stops_past_s6(self):
        self.admit(["--loop", "L2"])
        calls = []
        site, _p = self.site_for([b"api-secret-1", b"mbx-secret-a", b"mbx-secret-b"], **self.slots(calls))
        with self.assertRaises(Refusal) as cm:
            a2_main.run(self.rid, ["--loop", "L2"], site)
        self.assertEqual(calls, ["S2", "S3", "S4", "S5", "S6"])
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("RUNNER.UNCLASSIFIED", 3))
        self.finished(site)

    def test_an_l1_whose_stages_all_pass_ends_with_0(self):
        self.admit(["--only", "S5"])
        calls = []
        site, _p = self.site_for([b"api-secret-1", b"mbx-secret-a", b"mbx-secret-b"], **self.slots(calls))
        self.assertEqual(a2_main.run(self.rid, ["--only", "S5"], site), 0)
        self.assertEqual(calls, ["S5"])
        self.finished(site)


class S5RunTest(Base):

    def test_created_is_changed_and_existing_is_already(self):
        for line, result in ((b"CREATED " + b"ab" * 32 + b"\n", "CHANGED"), (b"EXISTING " + b"ab" * 32 + b"\n", "ALREADY")):
            with self.subTest(result=result):
                self.setUp()
                L = Layer()
                L.exec = lambda vm, argv, **kw: (0, line, b"")
                self.site.vm_layer = L
                a2_s5.run_s5(self.c, self.site, self.rec)
                self.assertEqual(self.receipt("S5", "vm-a-t")[0]["RESULT"], result)
