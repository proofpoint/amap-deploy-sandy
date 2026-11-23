"""W8 r7 on W7 r8.2 (be0e6a9): S7 against the real agent registry slots (a2_agent_registry,
filled by a2_vm.bind), the slug guard (ruling W8-SLUG-LENGTH-IN-S7) and the HOME guard.

- RealRegistryTest: the sandbox name and workspace path S7 actually sends pass
  registry_import's own input rules, and its refusals reach S7's receipt as raised.
- SlugGuardTest: an agent id whose sandbox name the registry would refuse is refused
  AGENTS.SLUG_TOO_LONG, exit 2, before any VM contact; the boundary is the registry's.
- HomeGuardTest: an agent HOME that would make a workspace path the registry refuses is
  AGENTS.VM_ACCESS at contact, before any write.
"""

import types

import a2fix  # noqa: F401 - puts install/ on sys.path, as the other test modules
import a2_agent_registry
import a2_s7 as S7
from a2_causes import Refusal

from test_w8_s7 import Base, Run, TOKEN


class Reached(Exception):
    """Raised by the stub layer's exec: registry_import got past its input checks."""


def stub_layer(base, vm_name):
    """The part of a2_vm.VmLayer that AgentRegistry reads before its first VM call."""
    def exec_(vm, argv, *, account, stage, writes, stdin=None):
        raise Reached((vm, account, stage))
    return types.SimpleNamespace(vms={vm_name: {"agent_account": "agent", "fleet_domain": "f.example.org"}},
                                 wrote=lambda stage: stage in base.fake.wrote, exec=exec_,
                                 lock={"registry_program": base.lock.get("registry_program", {})})


def agent_id(n):
    """A valid alpha2.hosts agent id (a2_private "name") of length n."""
    return "a" + "b" * (n - 1)


class R7Base(Base):
    def real_registry(self, layer=None):
        reg = a2_agent_registry.AgentRegistry(layer or stub_layer(self, self.vm_name))
        self.site.registry_import = reg.registry_import
        self.site.registry_read = reg.registry_read
        return reg

    def cmd_ctx(self, command, **opts):
        c = self.ctx(command)
        c.inv.opts = opts
        return c

    def nothing_happened(self):
        self.assertEqual(self.fake.exec_log, [])
        self.assertEqual(self.fake.wrote, set())
        self.assertIsNone(self.fake.token())


class RealRegistryTest(R7Base):
    def test_s7s_slug_and_workspace_pass_registry_imports_input_rules(self):
        """S7's real (slug, ws) reach the registry's first VM call: had either failed its
        rule, registry_import would have refused UNCLASSIFIED before it."""
        self.real_registry()
        with self.assertRaises(Reached) as cm:
            self.s7()
        self.assertEqual(cm.exception.args[0], (self.vm_name, "agent", "AGENTS"))

    def test_a_registry_refusal_reaches_the_receipt_as_raised(self):
        layer = stub_layer(self, self.vm_name)
        layer.vms = {}  # the registry's AGENTS.HOSTS, after S7's writes: exit 3
        self.real_registry(layer)
        self.assert_refused("AGENTS.HOSTS", rc=3, token_written=True)


class SlugGuardTest(R7Base):
    def test_the_limit_is_the_registrys_own_rule(self):
        """slug_fits is registry_import's slug rule applied to expected_slug: at the boundary
        both agree, so the guard neither restates nor drifts from it."""
        for n in (1, 48, 49, 50, 63):
            with self.subTest(n=n):
                slug = S7.expected_slug(self.fake.home + "/dev/agent-" + agent_id(n))
                self.assertEqual(S7.slug_fits(agent_id(n)),
                                 a2_agent_registry._SLUG.fullmatch(slug) is not None)
        self.assertTrue(S7.slug_fits(agent_id(49)))
        self.assertFalse(S7.slug_fits(agent_id(50)))

    def test_without_the_guard_the_registry_refuses_only_after_the_writes(self):
        """Why the guard exists: registry_import refuses a 50-character id's slug, and S7
        reaches it only after the credential write."""
        reg = self.real_registry()
        ws = self.fake.home + "/dev/agent-" + agent_id(50)
        with self.assertRaises(Refusal) as cm:
            reg.registry_import(self.vm_name, S7.expected_slug(ws), ws, stage="AGENTS")
        self.assertEqual(cm.exception.cause, "AGENTS.UNCLASSIFIED")

    def test_an_id_of_49_reaches_the_registry(self):
        self.hosts["agents"] = [{"id": agent_id(49), "vm": self.vm_name, "connector": "connector"}]
        self.real_registry()
        with self.assertRaises(Reached):
            self.s7()

    def test_an_id_of_50_refuses_exit_2_with_no_vm_contact(self):
        self.hosts["agents"] = [{"id": agent_id(50), "vm": self.vm_name, "connector": "connector"}]
        run, r = self.s7()
        self.assertEqual((r.cause, r.rc), ("AGENTS.SLUG_TOO_LONG", 2))
        self.nothing_happened()
        self.assertEqual(run.receipts, {})

    def test_a_second_vms_long_id_refuses_before_the_first_vm_is_touched(self):
        a, b = self.hosts["vms"][0], self.hosts["vms"][1]
        self.hosts["agents"] = [{"id": "alice", "vm": a["name"], "connector": "connector"},
                                {"id": agent_id(50), "vm": b["name"], "connector": "connector"}]
        c = self.ctx()
        c.run_vms = [a, b]
        run = Run(self.s6)
        with self.assertRaises(Refusal) as cm:
            S7.run_s7(c, self.site, run, types.SimpleNamespace(values={"api_key": TOKEN}))
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("AGENTS.SLUG_TOO_LONG", 2))
        self.nothing_happened()

    def test_add_agent_with_a_long_id_refuses_before_vm_contact(self):
        self.hosts["agents"].append({"id": agent_id(50), "vm": self.vm_name, "connector": "connector"})
        with self.assertRaises(Refusal) as cm:
            S7.run_add_agent(self.cmd_ctx("add-agent", host=self.vm_name, id=agent_id(50)), self.site,
                             Run(self.s6), types.SimpleNamespace(values={"api_key": TOKEN}))
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("AGENTS.SLUG_TOO_LONG", 2))
        self.nothing_happened()

    def test_add_agent_without_id_refuses_the_selected_long_id_before_any_write(self):
        self.hosts["agents"] = [{"id": agent_id(50), "vm": self.vm_name, "connector": "connector"}]
        run = Run(self.s6)
        with self.assertRaises(Refusal) as cm:
            S7.run_add_agent(self.cmd_ctx("add-agent", host=self.vm_name), self.site, run,
                             types.SimpleNamespace(values={"api_key": TOKEN}))
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("AGENTS.SLUG_TOO_LONG", 2))
        self.assertTrue(self.fake.exec_log)  # the read-only selection ran
        self.assertEqual([argv for argv, writes in self.fake.exec_log if writes], [])
        self.assertEqual(self.fake.wrote, set())
        self.assertIsNone(self.fake.token())


class HomeGuardTest(R7Base):
    def with_home(self, home):
        real = self.site.vm_exec

        def vm_exec(vm, argv, **kw):
            if argv == ["/usr/bin/printenv", "HOME"]:
                return 0, home.encode() + b"\n", b""
            return real(vm, argv, **kw)
        self.site.vm_exec = vm_exec

    def test_a_home_the_registry_would_refuse_is_vm_access_before_any_write(self):
        for home in ("/", "//home/u", "/home/u/", "/home//u", "/home/./u", "/home/x/../u", "home/u", ""):
            with self.subTest(home=home):
                self.with_home(home)
                run, r = self.s7()
                self.assertEqual((r.cause, r.rc), ("AGENTS.VM_ACCESS", 2))
                self.assertEqual(self.fake.wrote, set())
                self.assertIsNone(self.fake.token())

    def test_home_ok_is_the_registrys_key_rule_plus_its_home_rule(self):
        """Every HOME home_ok accepts gives a workspace path registry_import accepts."""
        reg = self.real_registry()
        for home in ("/home/u", "/x", "/srv/agents/a-1"):
            with self.subTest(home=home):
                self.assertTrue(S7.home_ok(home))
                ws = home + "/dev/agent-alice"
                with self.assertRaises(Reached):
                    reg.registry_import(self.vm_name, S7.expected_slug(ws), ws, stage="AGENTS")


class ConnectorTreeTest(R7Base):
    """Ruling W8-CONNECTOR-READ-TREE (Opus W8 r10 blocker): S7 reads the connector's pinned tree
    as S6 does, never one files[] row per connector file (the lock has none)."""

    def test_the_lock_has_no_connector_rows_and_s7_passes(self):
        self.assertEqual([f for f in self.lock["files"] if f["component"] == "connector"], [])
        run, r = self.s7()
        self.assertIsNone(r)

    def test_the_fake_component_file_refuses_a_connector_file(self):
        """The fake follows the real layer's row rule, so a return to component_file fails."""
        with self.assertRaises(Refusal) as cm:
            self.component_file("connector", "bin/" + S7.CONNECTOR_FILES[0][1], stage="AGENTS")
        self.assertEqual(cm.exception.cause, "AGENTS.PIN")

    def test_a_payload_file_missing_from_the_tree_refuses_pin(self):
        import test_w8_s7
        src = S7.CONNECTOR_FILES[0][1]
        saved = test_w8_s7.CONNECTOR_BYTES.pop(src)
        self.addCleanup(test_w8_s7.CONNECTOR_BYTES.__setitem__, src, saved)
        self.assert_refused("AGENTS.PIN", rc=3, token_written=False)

    def test_a_layer_without_component_tree_refuses_pin(self):
        self.site.vm_layer = None
        run, r = self.s7()
        self.assertEqual(r.cause, "AGENTS.PIN")


class S6FactsBeforeContactTest(R7Base):
    """Opus W8 r10 note 7: a bad S6 receipt exits 2, before any VM contact, for any run VM."""

    def test_a_second_vms_unplaced_receipt_exits_2_before_any_contact(self):
        a, b = self.hosts["vms"][0], self.hosts["vms"][1]
        self.hosts["agents"] = [{"id": "alice", "vm": a["name"], "connector": "connector"},
                                {"id": "bob", "vm": b["name"], "connector": "connector"}]
        c = self.ctx()
        c.run_vms = [a, b]
        from test_w8_r6 import PerHostRun
        run = PerHostRun({a["name"]: self.s6, b["name"]: dict(self.s6, CONFIG="ABSENT")})
        with self.assertRaises(Refusal) as cm:
            S7.run_s7(c, self.site, run, types.SimpleNamespace(values={"api_key": TOKEN}))
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("AGENTS.CONFIG_NOT_PLACED", 2))
        self.nothing_happened()

    def test_add_agent_checks_the_receipt_before_contact(self):
        self.s6["CONFIG"] = "ABSENT"
        with self.assertRaises(Refusal) as cm:
            S7.run_add_agent(self.cmd_ctx("add-agent", host=self.vm_name, id="alice"), self.site,
                             Run(self.s6), types.SimpleNamespace(values={"api_key": TOKEN}))
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("AGENTS.CONFIG_NOT_PLACED", 2))
        self.nothing_happened()
