"""W8 on DS's VM layer (install/a2_vm.py): S7's calls against the real layer.

- LayerSignatureTest: the S7 tests' fake layer and registry slots have the real layer's
  and a2_agent_registry's signatures, so a green S7 test is about calls the real ones
  accept; a2_vm.bind fills every slot S7 calls, the registry's included.
- WritesDeclarationTest: every vm_exec call S7 makes states `writes` as a bool, True
  exactly for the argvs that can change the VM. It checks both the calls a run makes
  and, through the AST, every call site in a2_s7.py, including those a run in these
  tests does not reach.
- RealLayerTest: VmAccess on a real a2_vm.VmLayer, bound with a2_vm.bind, over DS's
  fake ssh and sudo (test_a2_vm.Base). It covers the write rule (a route failure before
  any write is TARGET_ACCESS exit 2, and after a writing exec it is UNCLASSIFIED exit
  3) and the secret's mode and value pairing as S7 sends it.
"""

import ast
import inspect
import os
import pwd

import a2fix  # noqa: F401  (puts install/ on sys.path)
import a2_agent_registry
import a2_s7 as S7
import a2_site
import a2_vm
from a2_causes import Refusal

import test_a2_vm
from test_w8_s7 import Base as S7Base, CONNECTOR_BYTES, FakeVm, TOKEN

INSTALL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
#: The argvs S7 sends that can change a VM: mkdir, and every sandy call (sandy at
#: 924fa5b6 creates $SANDY_HOME's fixtures on every invocation, lines 256-258, and
#: --approvals writes a temporary report, line 6030; DS's ruling on W8 r5 note 4).
WRITING = {("/usr/bin/mkdir",), (S7.SANDY, "--build-only"), (S7.SANDY, "--start"), (S7.SANDY, "--stop"),
           (S7.SANDY, "--approvals"), (S7.SANDY, "--print-state"), (S7.SANDY, "--print-schema")}


def params(fn):
    """A callable's parameters without `self`: (name, kind, default)."""
    return [(p.name, p.kind, p.default) for p in inspect.signature(fn).parameters.values() if p.name != "self"]


class LayerSignatureTest(S7Base):
    def test_the_fake_has_the_real_layers_signatures(self):
        for fake, real in ((FakeVm.vm_exec, a2_vm.VmLayer.exec),
                           (FakeVm.vm_write_secret, a2_vm.VmLayer.write_secret),
                           (FakeVm.vm_install_file, a2_vm.VmLayer.install_file),
                           (S7Base.component_file, a2_vm.VmLayer.component_file),
                           (S7Base.component_tree, a2_vm.VmLayer.component_tree),
                           (S7Base.registry_import, a2_agent_registry.AgentRegistry.registry_import),
                           (S7Base.registry_read, a2_agent_registry.AgentRegistry.registry_read)):
            with self.subTest(real=real.__name__):
                self.assertEqual(params(fake), params(real))

    def test_bind_fills_the_slots_s7_calls(self):
        site = a2_site.Site()
        layer = a2_vm.VmLayer(hosts={"vms": []}, lock={}, known_hosts_for=None, login=None, installer_dir="/")
        a2_vm.bind(site, layer)
        for slot, method in (("vm_exec", "exec"), ("vm_write_secret", "write_secret"),
                             ("vm_install_file", "install_file"), ("component_file", "component_file")):
            self.assertEqual(getattr(site, slot), getattr(layer, method))
        # The registry slots: one AgentRegistry over the same layer (W7 r8.1, ruling W7-REGISTRY-SLOTS-IN-R8-1).
        for slot in ("registry_import", "registry_read"):
            with self.subTest(slot=slot):
                bound = getattr(site, slot)
                self.assertIs(bound.__func__, getattr(a2_agent_registry.AgentRegistry, slot))
                self.assertIs(bound.__self__.layer, layer)
        self.assertIs(site.registry_import.__self__, site.registry_read.__self__)

    def test_logical_id_reads_through_the_site_slot(self):
        """S7's registry read is a2_vm.logical_id; the fake's registry_read has the
        shape logical_id calls (vm, slug, stage=)."""
        self.assertEqual(S7.Registry(self.site).read(self.vm_name, "agent-alice-0"),
                         self.registry_read(self.vm_name, "agent-alice-0", stage="AGENTS"))


class WritesDeclarationTest(S7Base):
    def test_every_exec_of_a_run_states_writes_true_exactly_for_writing_argvs(self):
        run, r = self.s7()
        self.assertIsNone(r)
        self.assertTrue(self.fake.exec_log)
        for argv, writes in self.fake.exec_log:
            with self.subTest(argv=argv[:2]):
                self.assertIs(type(writes), bool)
                self.assertEqual(writes, tuple(argv[:1]) in WRITING or tuple(argv[:2]) in WRITING)
        kinds = {tuple(a[:2]) if a[0] == S7.SANDY else tuple(a[:1]) for a, w in self.fake.exec_log if w}
        self.assertEqual(kinds, {("/usr/bin/mkdir",), (S7.SANDY, "--build-only"), (S7.SANDY, "--approvals"),
                                 (S7.SANDY, "--print-state"), (S7.SANDY, "--print-schema")})
        self.assertTrue(all(w for a, w in self.fake.exec_log if a[0] == S7.SANDY))  # every sandy call

    def test_every_call_site_in_s7_states_writes(self):
        """Every .run(...) and .sandy(...) call in a2_s7.py passes `writes=` with a
        literal bool. Only VmAccess.run and VmAccess.sandy pass their own `writes`
        parameter on (`writes=writes`); no other function may (Opus W8 r5, note 5(a))."""
        with open(os.path.join(INSTALL, "a2_s7.py")) as f:
            tree = ast.parse(f.read())
        owner = {}  # each call node -> the qualified name of the function holding it
        for top in tree.body:
            defs = [(top.name, top)] if isinstance(top, ast.FunctionDef) else \
                [(top.name + "." + f.name, f) for f in top.body if isinstance(f, ast.FunctionDef)] \
                if isinstance(top, ast.ClassDef) else []
            for qual, fn in defs:
                for node in ast.walk(fn):
                    owner[node] = qual
        seen = 0
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("run", "sandy", "vm_exec")):
                continue
            seen += 1
            kw = {k.arg: k.value for k in node.keywords}
            with self.subTest(line=node.lineno):
                self.assertIn("writes", kw)
                v = kw["writes"]
                if isinstance(v, ast.Name):
                    self.assertEqual(v.id, "writes")
                    self.assertIn(owner.get(node), ("VmAccess.run", "VmAccess.sandy"))
                else:
                    self.assertIsInstance(v, ast.Constant)
                    self.assertIs(type(v.value), bool)
        self.assertGreater(seen, 10)

    def test_the_writing_call_sites_say_true(self):
        """Each writing argv in a2_s7.py is sent with writes=True, wherever it is."""
        with open(os.path.join(INSTALL, "a2_s7.py")) as f:
            tree = ast.parse(f.read())
        found = set()
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("run", "sandy")):
                continue
            kw = {k.arg: k.value for k in node.keywords}
            if node.func.attr == "sandy":
                first = node.args[0] if node.args else None
                key = (S7.SANDY, first.value) if isinstance(first, ast.Constant) else None
            else:
                lst = node.args[0] if node.args else None
                first = lst.elts[0] if isinstance(lst, ast.List) and lst.elts else None
                key = (first.value,) if isinstance(first, ast.Constant) else None
            if key is None:
                continue
            w = kw["writes"]
            with self.subTest(line=node.lineno, argv=key):
                self.assertEqual(w.value, key in WRITING)
            if key in WRITING:
                found.add(key)
        self.assertEqual(found, WRITING)


class RealLayerTest(test_a2_vm.Base):
    """S7's VmAccess on a real VmLayer, over DS's fake ssh (test_a2_vm)."""

    def setUp(self):
        super().setUp()
        self.account = pwd.getpwuid(os.getuid()).pw_name
        self.site = a2_site.Site()
        self.L = self.layer()
        a2_vm.bind(self.site, self.L)

    def access(self):
        return S7.VmAccess(self.site, "vm-a", self.account)

    def down(self):
        open(os.path.join(self.fake, "down"), "w").close()

    def test_the_home_read_runs_through_the_layer_as_a_read(self):
        vm = self.access()
        self.assertEqual(vm.home, pwd.getpwuid(os.getuid()).pw_dir)
        self.assertEqual(self.L._wrote, set())

    def test_a_route_failure_before_any_write_is_target_access_exit_2(self):
        vm = self.access()
        self.assertEqual(vm.run(["/usr/bin/true"], writes=False)[0], 0)
        self.down()
        self.refuses("AGENTS.TARGET_ACCESS", vm.run, ["/usr/bin/true"], writes=False, rc=2)

    def test_after_a_writing_exec_every_refusal_keeps_its_cause_exit_3(self):  # b043a1e VmLayer._refused
        vm = self.access()
        self.assertEqual(vm.run(["/usr/bin/true"], writes=True)[0], 0)
        self.assertEqual(self.L._wrote, {"AGENTS"})
        self.assertTrue(self.L.wrote("AGENTS"))
        self.down()
        self.refuses("AGENTS.TARGET_ACCESS", vm.run, ["/usr/bin/true"], writes=False, rc=3)
        # PIN included: a component file that is not pinned, after the write.
        self.refuses("AGENTS.PIN", S7.sandy_bytes, self.site, {"path": "sandy", "sha256": "0" * 64}, rc=3)

    def connector_repo(self, files):
        """A fetched connector repository at the lock's commit, holding `files` under bin/;
        the lock names the component and has NO files[] row for it (as a real lock)."""
        bare, work = os.path.join(self.d, "conn.git"), os.path.join(self.d, "conn")
        a2fix.git(self.d, "init", "-q", "--bare", bare)
        a2fix.git(self.d, "init", "-q", work)
        for name, data in files.items():
            os.makedirs(os.path.join(work, "bin"), exist_ok=True)
            with open(os.path.join(work, "bin", name), "wb") as f:
                f.write(data)
        a2fix.git(work, "add", "-A")
        a2fix.git(work, "commit", "-q", "-m", "c")
        commit = a2fix.git(work, "rev-parse", "HEAD")
        a2fix.git(work, "push", "-q", bare, "HEAD:refs/heads/main")
        self.lock["components"] = [c for c in self.lock["components"] if c["name"] != "connector"]
        self.lock["components"].append({"name": "connector", "repo": "https://git.example.org/x/connector",
                                        "commit": commit, "tag": "alpha2-rc1"})
        self.assertEqual([f for f in self.lock["files"] if f["component"] == "connector"], [])
        import a2_git
        L = self.layer(git=a2_git.Git(a2_git.env_for(self.d), protocols=("file",)), fetched={"c-connector": bare})
        site = a2_site.Site()
        a2_vm.bind(site, L)
        return site, commit

    def placed_vm(self, site, files):
        """VmAccess on the real layer, its $SANDY_HOME a scratch dir holding S6's placed connector files."""
        vm = S7.VmAccess(site, "vm-a", self.account)
        vm.sandy_home = os.path.join(self.d, "sandy-home")
        for placed, src in S7.CONNECTOR_FILES:
            p = os.path.join(vm.sandy_home, placed)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(files[src])
        return vm

    def test_check_connector_passes_on_a_real_layer_with_no_connector_rows(self):  # Opus r10 blocker
        """The real layer, a connector repository and a lock with no connector files[] rows:
        component_file would refuse PIN for each file; S7 reads the tree, as S6 does, and passes."""
        site, commit = self.connector_repo(CONNECTOR_BYTES)
        vm = self.placed_vm(site, CONNECTOR_BYTES)
        for _placed, src in S7.CONNECTOR_FILES:
            self.refuses("AGENTS.PIN", site.component_file, "connector", "bin/" + src, stage="AGENTS", rc=2)
        self.assertEqual(S7.check_connector(vm, self.lock, {"connector": "connector"}), commit)

    def test_check_connector_on_a_real_layer_refuses_a_placed_file_that_differs(self):
        site, _commit = self.connector_repo(CONNECTOR_BYTES)
        changed = dict(CONNECTOR_BYTES)
        changed[S7.CONNECTOR_FILES[-1][1]] = b"#!/bin/sh\n# changed\n"
        vm = self.placed_vm(site, changed)
        self.refuses("AGENTS.PIN", S7.check_connector, vm, self.lock, {"connector": "connector"}, rc=2)

    def test_check_connector_on_a_real_layer_refuses_a_tree_without_a_payload_file(self):
        site, _commit = self.connector_repo({k: v for k, v in CONNECTOR_BYTES.items()
                                             if k != S7.CONNECTOR_FILES[0][1]})
        vm = self.placed_vm(site, CONNECTOR_BYTES)
        self.refuses("AGENTS.PIN", S7.check_connector, vm, self.lock, {"connector": "connector"}, rc=2)

    def test_writes_must_be_a_bool(self):
        vm = self.access()
        for bad in (None, 1, "yes"):
            with self.subTest(writes=bad):
                self.refuses("AGENTS.UNCLASSIFIED", vm.run, ["/usr/bin/true"], writes=bad, rc=2)

    def test_the_secret_goes_as_s7_sends_it(self):
        vm = self.access()
        self.assertEqual(vm.write_secret("write", bytearray(TOKEN)), ("done", None))
        self.assertEqual(vm.write_secret("finish"), ("done", None))
        with open(self.out) as f:
            lines = f.read().splitlines()
        self.assertEqual(lines, ["write %s bytearray %s" % (self.account, bytes(TOKEN).decode()),
                                 "finish %s NoneType " % self.account])

    def test_a_pairing_refused_before_ssh_is_raised_with_exit_2_not_unknown(self):
        vm = self.access()
        before = self.logged()
        for mode, value in (("write", bytearray()), ("write", bytes(TOKEN)), ("finish", bytearray(TOKEN))):
            with self.subTest(mode=mode, value=type(value).__name__):
                e = self.refuses("AGENTS.UNCLASSIFIED", vm.write_secret, mode, value, rc=2)
                self.assertIsInstance(e, Refusal)
        self.assertEqual(self.logged(), before)  # ssh never started
        self.assertFalse(os.path.exists(self.out))

    def test_a_refusal_after_the_secret_was_sent_is_unknown(self):
        vm = self.access()
        open(os.path.join(self.fake, "readyhang"), "w").close()  # READY, then nothing
        self.L.timeout_s = 1
        outcome, err = vm.write_secret("write", bytearray(TOKEN))
        self.assertEqual(outcome, "unknown")
        self.assertEqual((err.cause, err.rc), ("AGENTS.UNCLASSIFIED", 3))


class LayerResultShapeTest(S7Base):
    def test_a_result_not_in_the_layers_shape_is_unclassified_exit_3(self):
        """S7 cannot show what a call it cannot read did (3.4)."""
        for bad in ("UNOBSERVED", None, (0, b""), ("0", b"", b""), [0, b"", b""], (0, "text", b"")):
            with self.subTest(result=bad):
                self.site.vm_exec = lambda *a, _r=bad, **k: _r
                run, r = self.s7()
                self.assertEqual((r.cause, r.rc), ("AGENTS.UNCLASSIFIED", 3))
                self.assertIsNone(self.fake.token())
