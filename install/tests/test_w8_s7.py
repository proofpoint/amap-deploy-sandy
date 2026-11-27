"""W8: S7 AGENTS, --add-agent's selection and --rotate-key, against a fake of DS's VM
layer (install/a2_vm.py). The fake's calls have the layer's exact signatures
(LayerSignatureTest pins them to a2_vm.VmLayer and a2_site) and its write rule (W7
b043a1e): once a stage has written, every refusal it raises keeps its cause and exits 3.

The fake VM is a real temporary directory:
- vm_exec runs the real /usr/bin tool for the fixed file argv S7 sends (printenv, stat,
  mkdir, sha256sum, cat, grep);
- vm_write_secret runs the real S7 writer through the test stand-in bootstrap.
sandy is modelled only as far as its source at 924fa5b6 shows: --approvals exit 0/2 and
sandbox_name, --build-only, --print-state's installed_images, --print-schema, --stop and
--start. S6's output is modelled as b043a1e's S6 writes it: one receipt per VM with CONFIG,
ROUTER_JSON_SHA and FEATURE_JSON_SHA; router.json under $HOME/.amap-router; the connector's
bin/ files under the feature's payload (S6AgreementTest holds these to a2_s6).
"""

import copy
import hashlib
import json
import os
import subprocess
import tempfile
import types
import unittest

import a2fix
import a2_causes
import a2_s7 as S7
import a2_site
from a2_causes import Refusal

from test_a2_units import contract_sentences

TOKEN = bytearray(b"sk-ant-oat01-SYNTHETIC-token-value-0001")
TOKEN2 = bytearray(b"sk-ant-oat01-SYNTHETIC-token-value-0002")
CONNECTOR = "c" * 40
SANDY_BYTES = b"#!/usr/bin/env bash\n# synthetic sandy\n"
SANDY_FILES = {"sandy": SANDY_BYTES, "proxy/go.mod": b"module proxy\n", "proxy/main.go": b"package main\n",
               "proxy/.gitignore": b"bin/\n"}
WRITER = os.path.join(a2fix.INSTALL, "vm_token_writer.py")
FILE_TOOLS = ("/usr/bin/stat", "/usr/bin/mkdir", "/usr/bin/sha256sum", "/usr/bin/cat", "/usr/bin/grep")
#: The connector's bin/ tree, by path under CONNECTOR_PREFIX (component_tree's shape), with
#: one file S6 does not place: the tree holds more than the payload.
CONNECTOR_BYTES = {"inbox-delivery": b"#!/usr/bin/env python3\n# synthetic inbox-delivery\n",
                   "_inboxlib.py": b"# synthetic _inboxlib\n",
                   "inbox-mcp-vol": b"#!/bin/sh\n# synthetic inbox-mcp-vol\n",
                   "inbox-submit": b"#!/bin/sh\n# synthetic inbox-submit\n",
                   "not-placed": b"# in the tree, not in S6's payload\n"}
#: sandy 924fa5b6's `--print-schema`, MEASURED: the real script run with a scratch HOME and
#: SANDY_HOME (rc 0, empty stderr; full output 64116 bytes, sha256
#: f703f2c092b097cd19b690204226aa4cc3b3ddf93df36410be936b918fc68beb). Kept here: the two
#: members S7 reads, schema_version and the whole manifest object, as printed.
SCHEMA_924 = {"manifest": {"agent_args_compose": [{"agent": "claude", "flag": "--append-system-prompt-file", "policy": "concat"}, {"agent": "claude", "flag": "--append-subagent-system-prompt-file", "policy": "concat"}, {"agent": "claude", "flag": "--system-prompt-file", "policy": "report"}], "mount_keys": ["name", "from", "mode", "export"], "receives_values": ["cross_session"], "submount_keys": ["parent", "path", "from", "mode", "agents"], "top_level_keys": ["schema", "sandboxes", "agents", "create", "mounts", "entry", "expose", "feature", "agent_args", "receives", "submounts", "agent_wrapper"]}, "schema_version": 4}


def sha_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class FakeVm:
    """DS's layer for one VM, as the tests need it."""

    def __init__(self, root):
        self.home = os.path.join(root, "home")
        self.sandy_home = os.path.join(self.home, ".sandy")
        os.makedirs(os.path.join(self.sandy_home, "features", "amap", "payload"))
        os.chmod(self.sandy_home, 0o700)
        os.makedirs(os.path.join(self.home, ".amap-router"))
        self.put_home(S7.ROUTER_JSON, b'{"r":1}\n')
        self.put("features/amap/feature.json", b'{"f":1}\n')
        os.makedirs(os.path.join(self.sandy_home, "features", "amap", "payload", "bin"))
        for placed, src in S7.CONNECTOR_FILES:
            self.put(placed, CONNECTOR_BYTES[src], 0o755)
        self.schema_rc = 0
        self.schema_out = json.dumps(SCHEMA_924).encode()
        self.approvals_rc = 0
        self.approvals_by_ws = {}
        self.build_rc = 0
        self.start_rc = [0]
        self.slug_override = None
        self.image = None
        self.running = False
        self.calls = []
        #: (argv, writes) for every vm_exec call
        self.exec_log = []
        self.secret_calls = []
        self.reachable = True
        #: the stages that have written through this fake layer (a2_vm's _wrote)
        self.wrote = set()
        self.root = {}  # path under /usr/local/bin -> (bytes or None, "uid:gid mode kind")
        self.writer = None
        self.writer_rc_override = {}
        #: mode -> an rc or an exception, given AFTER the real writer ran (a transport
        #: result that hides a real change; Opus W8 r2, 1)
        self.writer_after = {}
        self.installs = 0

    def put_home(self, rel, data):
        with open(os.path.join(self.home, rel), "wb") as f:
            f.write(data)

    def put(self, rel, data, mode=None):
        p = os.path.join(self.sandy_home, rel)
        with open(p, "wb") as f:
            f.write(data)
        if mode is not None:
            os.chmod(p, mode)

    def token(self):
        p = os.path.join(self.sandy_home, ".secrets")
        if not os.path.exists(p):
            return None
        with open(p, "rb") as f:
            lines = [l for l in f.read().splitlines() if l.startswith(S7.TOKEN_KEY.encode() + b"=")]
        return lines[-1].split(b"=", 1)[1] if lines else None

    # -- the layer's write rule (a2_vm.VmLayer._refused)
    def refused(self, stage, detail, cause="UNCLASSIFIED"):
        if stage in self.wrote:
            return Refusal(stage + "." + cause, detail, rc=3)
        return Refusal(stage + "." + cause, detail)

    # -- DS's interface (a2_vm.VmLayer; signatures pinned by LayerSignatureTest)
    def vm_exec(self, vm, argv, *, account, stage, writes, stdin=None, timeout_s=None):
        assert isinstance(argv, list) and all(isinstance(a, str) for a in argv), argv
        assert account == "agent" and stage == "AGENTS"
        if type(writes) is not bool:
            raise self.refused(stage, "writes is not a bool")
        self.exec_log.append((list(argv), writes))
        if writes:
            self.wrote.add(stage)
        if not self.reachable:
            raise self.refused(stage, "ssh route failed", "TARGET_ACCESS")
        self.calls.append(list(argv))
        if argv[0] == "/usr/bin/find" and argv[1] == S7.PROXY_DIR:
            if S7.PROXY_DIR not in self.root:
                return 1, b"", b""
            names = sorted(p.rsplit("/", 1)[1] for p in self.root if p.startswith(S7.PROXY_DIR + "/"))
            return 0, "".join(n + "\n" for n in names).encode(), b""
        if argv[-1].startswith(S7.SANDY_DIR + "/") and argv[0] in ("/usr/bin/stat", "/usr/bin/sha256sum"):
            ent = self.root.get(argv[-1])
            if ent is None:
                return 1, b"", b""
            data, facts = ent
            if argv[0] == "/usr/bin/stat":
                return 0, (facts + "\n").encode(), b""
            if data is None:
                return 1, b"", b""
            return 0, (hashlib.sha256(data).hexdigest() + "  " + argv[-1] + "\n").encode(), b""
        if argv == ["/usr/bin/printenv", "HOME"]:
            return 0, self.home.encode() + b"\n", b""
        if argv[0] in FILE_TOOLS or (argv[0] == "/usr/bin/find" and argv[1] == self.sandy_home):
            p = subprocess.run(argv, input=stdin, capture_output=True, timeout=60)
            return p.returncode, p.stdout, p.stderr
        assert argv[0] == S7.SANDY, argv
        assert S7.SANDY in self.root, "sandy called before it was installed"
        verb = argv[1]
        if verb == "--print-state":
            assert argv == [S7.SANDY, "--print-state"]  # it takes no --workspace
            imgs = [{"name": S7.AGENT_IMAGE, "id": self.image, "created": "x"}] if self.image else []
            return 0, json.dumps({"installed_images": imgs}).encode(), b""
        if verb == "--print-schema":
            assert argv == [S7.SANDY, "--print-schema"]
            return self.schema_rc, self.schema_out, b""
        assert argv[-2] == "--workspace", argv
        ws = argv[-1]
        if verb == "--approvals":
            slug = self.slug_override or S7.expected_slug(ws)
            rc = self.approvals_by_ws.get(ws, self.approvals_rc)
            return rc, json.dumps({"sandbox_name": slug}).encode(), b""
        if verb == "--build-only":
            if self.build_rc == 0:
                self.image = "sha256:" + "9" * 64
            return self.build_rc, b"", b""
        if verb == "--stop":
            self.running = False
            return 0, b"", b""
        if verb == "--start":
            rc = self.start_rc.pop(0) if len(self.start_rc) > 1 else self.start_rc[0]
            if rc == 0 and self.token():
                self.running = True
            return rc, b"", b""
        raise AssertionError(argv)

    def vm_install_file(self, vm, data, path, *, mode, stage):
        assert path.startswith(S7.SANDY_DIR + "/") and stage == "AGENTS"
        assert mode == (0o755 if path == S7.SANDY else 0o644)
        self.wrote.add(stage)
        self.installs += 1
        parent = path.rsplit("/", 1)[0]
        if parent != S7.SANDY_DIR and parent not in self.root:
            self.root[parent] = (None, "0:0 755 directory")
        self.root[path] = (bytes(data), "0:0 %o regular file" % mode)
        return "CHANGED"

    def vm_write_secret(self, vm, use, mode, value, *, account, stage):
        assert use == "api_key" and account == "agent" and stage == "AGENTS"
        # The layer's pairing check, before ssh (a2_vm.write_secret): nothing is sent.
        if mode in ("write", "rotate"):
            if type(value) is not bytearray or not value:
                raise self.refused(stage, "a value mode needs a non-empty bytearray")
        elif mode in ("finish", "restore"):
            if value is not None:
                raise self.refused(stage, "finish and restore take no value")
        else:
            raise self.refused(stage, "mode")
        self.wrote.add(stage)
        self.secret_calls.append(mode)
        if self.writer_rc_override and mode in self.writer_rc_override:
            return self.writer_rc_override[mode]
        if self.writer is None:
            # The shipped writer under the REAL bootstrap; FAKED: its LOOKUP and BECOME only.
            import secret_session
            self.writer = secret_session.faked_writer(WRITER, self.home, "agent")
        import secret_session
        rc, _out, _err = secret_session.run(self.writer, "api_key", mode, value, "agent")
        if mode in self.writer_after:
            after = self.writer_after[mode]
            if isinstance(after, BaseException):
                raise after
            return after
        return rc


class Run:
    def __init__(self, s6):
        self.s6 = s6
        self.started = "2026-11-20T00:00:00Z"
        self.receipts = {}

    def read_receipt(self, stage, host):
        assert stage == "S6"
        return self.s6

    def write_receipt(self, stage, host, started, result, facts, rc=0, cause=None):
        self.receipts[(stage, host)] = (result, list(facts), rc, cause)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.fake = FakeVm(self.tmp.name)
        self.hosts = a2fix.hosts_doc("/srv/locks")
        self.vm_name = self.hosts["vms"][0]["name"]
        self.hosts["agents"] = [{"id": "alice", "vm": self.vm_name, "connector": "connector"}]
        self.lock = copy.deepcopy(a2fix.LOCK)
        self.lock["components"][1]["commit"] = CONNECTOR
        self.lock["components"].append({"name": "sandy", "repo": "https://git.example.org/x/sandy",
                                        "commit": "e" * 40, "tag": "alpha2-rc1"})
        for path, data in SANDY_FILES.items():
            self.lock["files"].append({"path": path, "component": "sandy",
                                       "sha256": hashlib.sha256(data).hexdigest()})
        self.s6 = {"CONFIG": "PLACED",
                   "ROUTER_JSON_SHA": sha_file(os.path.join(self.fake.home, S7.ROUTER_JSON)),
                   "FEATURE_JSON_SHA": sha_file(os.path.join(self.fake.sandy_home, S7.FEATURE_JSON))}
        self.registry = {}
        self.imports = []
        self.site = types.SimpleNamespace(vm_exec=self.fake.vm_exec, vm_write_secret=self.fake.vm_write_secret,
                                          vm_install_file=self.fake.vm_install_file,
                                          component_file=self.component_file,
                                          vm_layer=types.SimpleNamespace(wrote=lambda stage: stage in self.fake.wrote,
                                                                         component_tree=self.component_tree),
                                          registry_import=self.registry_import,
                                          registry_read=self.registry_read)

    def refuse_pin(self, detail):
        # a2_vm.VmLayer._refused: the stage's PIN, exit 3 once the stage has written.
        raise Refusal("AGENTS.PIN", detail, rc=3 if "AGENTS" in self.fake.wrote else None)

    def component_file(self, component, path, *, stage):
        """a2_vm.VmLayer.component_file's rule: exactly one lock files[] row for (component,
        path), and the bytes must match it; otherwise PIN."""
        assert stage == "AGENTS"
        rows = [f for f in self.lock["files"] if f["component"] == component and f["path"] == path]
        data = SANDY_FILES.get(path) if component == "sandy" else None
        if len(rows) != 1 or data is None:
            self.refuse_pin("component file not pinned or not fetched")
        if hashlib.sha256(data).hexdigest() != rows[0]["sha256"]:
            self.refuse_pin("component file differs from its pin")
        return data

    def component_tree(self, component, prefix, *, stage):
        """a2_vm.VmLayer.component_tree's shape: (tree id, [(path under prefix, mode, bytes)]),
        for a component the lock names; it reads no files[] row."""
        assert stage == "AGENTS"
        if component != "connector" or prefix != "bin" or not any(c["name"] == component
                                                                    for c in self.lock["components"]):
            self.refuse_pin("component tree not pinned or not fetched")
        return "t" * 40, [(p, 0o755, b) for p, b in sorted(CONNECTOR_BYTES.items())]

    def registry_import(self, vm, slug, stable_key, *, stage):
        assert stage == "AGENTS"
        self.imports.append((vm, slug, stable_key))

    def registry_read(self, vm, slug, *, stage):
        assert stage == "AGENTS"
        return self.registry.get(slug, hashlib.sha256(slug.encode()).hexdigest()[:32])

    def ctx(self, command="install"):
        return types.SimpleNamespace(inv=types.SimpleNamespace(command=command), hosts=self.hosts,
                                     lock=self.lock, run_vms=[self.hosts["vms"][0]])

    def s7(self, command="install", value=TOKEN):
        run = Run(self.s6)
        held = types.SimpleNamespace(values={"api_key": value})
        try:
            S7.run_s7(self.ctx(command), self.site, run, held)
        except Refusal as r:
            return run, r
        return run, None

    def assert_refused(self, cause, rc=3, token_written=False):
        run, r = self.s7()
        self.assertIsNotNone(r, "S7 passed")
        self.assertEqual((r.cause, r.rc), (cause, rc))
        result, facts, frc, fcause = run.receipts[("S7", self.vm_name)]
        self.assertEqual((result, fcause), ("FAIL", cause))
        self.assertEqual(self.fake.token() is not None, token_written)
        return run

    def vm(self):
        return S7.VmAccess(self.site, self.vm_name, "agent")


class S7Test(Base):
    def test_pass_writes_the_token_and_records_no_value(self):
        run, r = self.s7()
        self.assertIsNone(r)
        result, facts, rc, cause = run.receipts[("S7", self.vm_name)]
        self.assertEqual(result, "CHANGED")
        d = dict(facts)
        self.assertEqual(d["AGENT_1_ID"], "alice")
        self.assertEqual(d["AGENT_1_WORKSPACE"], "~/dev/agent-alice")
        self.assertEqual(d["AGENT_1_CONNECTOR_COMMIT"], CONNECTOR)
        self.assertEqual(d["AGENT_1_SECRET_FILE"], "present")
        self.assertEqual(d["AGENT_1_START_POSSIBLE"], "yes")
        self.assertEqual(d["AGENT_1_SLUG"], S7.expected_slug(self.fake.home + "/dev/agent-alice"))
        self.assertEqual(d["AGENT_1_REGISTRY"], "active")
        self.assertEqual(d["AGENT_1_IMAGE_ID"], "sha256:" + "9" * 64)
        self.assertEqual(self.fake.token(), bytes(TOKEN))
        self.assertFalse(self.fake.running)  # left stopped
        blob = json.dumps(facts)
        self.assertNotIn(bytes(TOKEN).decode(), blob)
        self.assertNotIn(hashlib.sha256(bytes(TOKEN)).hexdigest()[:8], blob)
        self.assertNotIn("ADDRESS", blob)  # DS point 3: the address is not a fact here

    def test_the_value_reaches_only_vm_write_secret(self):
        self.s7()
        for argv in self.fake.calls:
            self.assertNotIn(bytes(TOKEN).decode(), " ".join(argv))
        self.assertEqual(self.fake.secret_calls, ["write"])

    def test_every_vm_call_is_a_fixed_argv_list(self):
        self.s7()
        self.assertTrue(self.fake.calls)
        for argv in self.fake.calls:
            self.assertTrue(argv[0].startswith("/usr/bin/") or argv[0] == S7.SANDY, argv)

    def test_slug_matches_sandys_own_derivation(self):
        # sandy 16682-16687: basename with [a-zA-Z0-9._-] only, then the first 8 hex
        # of sha256(the absolute workspace path).
        self.assertEqual(S7.expected_slug("/home/op/dev/agent-alice"),
                         "agent-alice-" + hashlib.sha256(b"/home/op/dev/agent-alice").hexdigest()[:8])
        self.assertEqual(S7.expected_slug("/x/a b!c"), "abc-" + hashlib.sha256(b"/x/a b!c").hexdigest()[:8])

    def test_dry_run_touches_no_vm(self):
        self.site.vm_exec = lambda *a, **k: self.fail("dry-run reached the VM")
        run, r = self.s7("dry-run")
        self.assertIsNone(r)
        self.assertEqual(run.receipts[("S7", self.vm_name)][0], "PLANNED")

    def test_no_vm_layer_refuses_and_writes_nothing(self):
        self.fake.reachable = False  # the route fails at S7's first call, a read
        self.assert_refused("AGENTS.TARGET_ACCESS", rc=2)
        self.fake.reachable = True
        # The site's slots before a2_vm.bind fills them refuse, and write nothing.
        self.site = a2_site.Site()
        self.assert_refused("AGENTS.TARGET_ACCESS", rc=2)  # vm_exec, unbound

    def test_the_account_is_the_hosts_key_and_no_slot_is_asked(self):  # e5: vms[].agent_account is required
        self.assertFalse(hasattr(self.site, "vm_agent_account"))
        run, r = self.s7()
        self.assertIsNone(r)
        self.hosts["vms"][0]["agent_account"] = "someone-else"
        with self.assertRaises(AssertionError):  # the fake layer accepts only "agent": the key reached it
            self.s7()

    def test_a_route_failure_after_a_write_keeps_its_cause_exit_3(self):  # contract 4.2 TARGET_ACCESS
        real = self.fake.vm_exec

        def drop_after_mkdir(vm, argv, **kw):
            r = real(vm, argv, **kw)
            if argv[0] == "/usr/bin/mkdir":
                self.fake.reachable = False
            return r
        self.site.vm_exec = drop_after_mkdir
        self.assert_refused("AGENTS.TARGET_ACCESS", rc=3)

    def refused_before_contact(self, cause):
        """`cause`, exit 2, with no VM contact and no receipt (read-only checks of the run's own records)."""
        run, r = self.s7()
        self.assertEqual((r.cause, r.rc), (cause, 2))
        self.assertEqual(self.fake.exec_log, [])
        self.assertEqual(run.receipts, {})

    def test_s6_not_placed_or_changed_since(self):
        self.s6["CONFIG"] = "ABSENT"
        self.refused_before_contact("AGENTS.CONFIG_NOT_PLACED")  # Opus W8 r10 note 7: the receipt, before contact
        self.s6["CONFIG"] = "PLACED"
        for fact in ("ROUTER_JSON_SHA", "FEATURE_JSON_SHA"):
            with self.subTest(missing=fact):
                s6 = dict(self.s6)
                del self.s6[fact]
                self.refused_before_contact("AGENTS.CONFIG_NOT_PLACED")
                self.s6 = s6
        self.fake.put("features/amap/feature.json", b'{"f":2}\n')
        self.assert_refused("AGENTS.CONFIG_NOT_PLACED")
        self.fake.put("features/amap/feature.json", b'{"f":1}\n')
        self.fake.put_home(S7.ROUTER_JSON, b'{"r":2}\n')
        self.assert_refused("AGENTS.CONFIG_NOT_PLACED")

    def test_router_json_is_read_under_home_not_sandy_home(self):  # b043a1e a2_s6.ROUTER_DIR
        os.makedirs(os.path.join(self.fake.sandy_home, "features", "amap"), exist_ok=True)
        self.fake.put("features/amap/router.json", b'{"elsewhere":1}\n')  # the r5.1 path: never read
        run, r = self.s7()
        self.assertIsNone(r)

    def test_a_vm_prefixed_s6_receipt_is_not_read(self):  # r5.1's provisional names
        v = self.vm_name.upper().replace("-", "_")
        self.s6 = {"CONFIG_" + v: "PLACED", "CONFIG_%s_ROUTER_JSON_SHA" % v: self.s6["ROUTER_JSON_SHA"],
                   "CONFIG_%s_FEATURE_JSON_SHA" % v: self.s6["FEATURE_JSON_SHA"]}
        self.refused_before_contact("AGENTS.CONFIG_NOT_PLACED")

    def test_a_connector_file_not_at_its_pin(self):
        for placed, _src in S7.CONNECTOR_FILES:
            with self.subTest(file=placed):
                self.fake.put(placed, b"#!/bin/sh\n# changed\n", 0o755)
                self.assert_refused("AGENTS.PIN")
                run, r = self.s7()
                self.assertEqual(r.detail, "connector")
                self.fake.put(placed, CONNECTOR_BYTES[_src], 0o755)
        os.unlink(os.path.join(self.fake.sandy_home, S7.CONNECTOR_FILES[0][0]))
        self.assert_refused("AGENTS.PIN")

    def test_a_leftover_previous_file_refuses_before_the_writer(self):
        self.fake.put(".secrets.prev", b"OLD\n", 0o600)
        self.assert_refused("AGENTS.ROTATE_LEFTOVER")
        self.assertEqual(self.fake.secret_calls, [])

    def test_a_writer_refusal_is_agents_writer(self):
        os.chmod(self.fake.sandy_home, 0o750)  # the writer refuses SECRETS_DIR
        self.assert_refused("AGENTS.WRITER")

    def test_image_build_fails(self):
        self.fake.build_rc = 1
        self.assert_refused("AGENTS.IMAGE_BUILD", token_written=True)

    def test_approvals_pending_is_no_start_path(self):
        self.fake.approvals_rc = 2
        self.assert_refused("AGENTS.NO_START_PATH", token_written=True)

    def test_slug_differing_from_sandys_derivation(self):
        self.fake.slug_override = "something-else-00000000"
        self.assert_refused("AGENTS.SLUG_UNOBSERVED", token_written=True)

    def test_registry_import_and_logical_id_read_back(self):
        run, r = self.s7()
        ws = self.fake.home + "/dev/agent-alice"
        slug = S7.expected_slug(ws)
        self.assertEqual(self.imports, [(self.vm_name, slug, ws)])
        self.assertEqual(dict(run.receipts[("S7", self.vm_name)][1])["AGENT_1_LOGICAL_ID"],
                         hashlib.sha256(slug.encode()).hexdigest()[:32])

    def test_registry_unobserved_or_none_is_refused(self):  # Opus 4; a2_vm.logical_id
        for answer in ("UNOBSERVED", None, "", "bad id with spaces", "A" * 32, "a" * 31, "0" * 32):
            with self.subTest(answer=answer):
                self.registry = {S7.expected_slug(self.fake.home + "/dev/agent-alice"): answer}
                run, r = self.s7()
                self.assertEqual((r.cause, r.rc), ("AGENTS.UNCLASSIFIED", 3))
                self.assertNotIn("AGENT_1_LOGICAL_ID", dict(run.receipts[("S7", self.vm_name)][1]))
                os.unlink(os.path.join(self.fake.sandy_home, ".secrets"))

    def test_registry_slots_raising_or_unset_refuse(self):
        def boom(vm, slug, stable_key, *, stage):
            raise Refusal("AGENTS.UNCLASSIFIED", "import failed", rc=3)
        self.site.registry_import = boom
        run, r = self.s7()
        self.assertEqual((r.cause, r.rc), ("AGENTS.UNCLASSIFIED", 3))  # as the slot raised it
        os.unlink(os.path.join(self.fake.sandy_home, ".secrets"))
        # a2_site's slot before a2_vm.bind fills it: its own cause, following the write
        # rule (exit 3 once S7 has written through the site's bound layer). The real
        # registry's own refusals: test_w8_r7.RealRegistryTest.
        unfilled = a2_site.Site()
        unfilled.vm_layer = self.site.vm_layer
        self.site.registry_import = unfilled.registry_import
        run, r = self.s7()
        self.assertEqual((r.cause, r.rc), ("AGENTS.TARGET_ACCESS", 3))

    def test_registry_not_active(self):
        self.registry = {S7.expected_slug(self.fake.home + "/dev/agent-alice"): None}
        self.assert_refused("AGENTS.UNCLASSIFIED", rc=3, token_written=True)


class StandinAgentTest(Base):  # DS 726a48c8, e321121f
    def setUp(self):
        super().setUp()
        os.makedirs(os.path.join(self.fake.sandy_home, "features/amap/payload"), exist_ok=True)
        self.standin = b"# synthetic vm_standin.py\n"
        self.fake.put("features/amap/payload/vm_standin.py", self.standin)
        self.lock["components"].append({"name": "amap-deploy-sandy", "repo": "https://git.example.org/x/d",
                                        "commit": "f" * 40, "tag": "alpha2-rc1"})
        self.lock["files"].append({"path": "install/vm_standin.py", "component": "amap-deploy-sandy",
                                   "sha256": hashlib.sha256(self.standin).hexdigest()})
        self.hosts["agents"].append({"id": "canary", "vm": self.vm_name, "connector": "amap-deploy-sandy"})

    def test_a_standin_is_checked_against_its_lock_row_and_launched_once(self):
        run, r = self.s7()
        self.assertIsNone(r)
        facts = dict(run.receipts[("S7", self.vm_name)][1])
        self.assertEqual(facts["AGENT_2_ID"], "canary")
        self.assertEqual(facts["AGENT_2_CONNECTOR_COMMIT"], "f" * 40)
        self.assertEqual(facts["AGENT_2_STANDIN"], "launched-once")
        self.assertFalse(self.fake.running)  # stopped again

    def test_a_standin_not_at_its_pin_is_refused(self):
        self.fake.put("features/amap/payload/vm_standin.py", self.standin + b"# changed\n")
        run, r = self.s7()
        self.assertEqual((r.cause, r.detail), ("AGENTS.PIN", "stand-in"))


class LeftoverTempTest(Base):  # monitor M2
    def test_a_writer_temporary_refuses_before_the_writer_and_in_verify(self):
        with open(os.path.join(self.fake.sandy_home, ".secrets.tmp-4242"), "wb") as f:
            f.write(b"CLAUDE_CODE_OAUTH_TOKEN=leftover\n")
        run, r = self.s7()
        self.assertEqual(r.cause, "AGENTS.SECRETS_TEMP_LEFTOVER")
        self.assertEqual(self.fake.secret_calls, [])

    def test_verify_reports_a_temporary(self):
        self.s7()
        with open(os.path.join(self.fake.sandy_home, ".secrets.tmp-9"), "wb") as f:
            f.write(b"x\n")
        self.assertEqual(S7.verify_agent(self.vm(), {"id": "alice"}), "secrets_temp_leftover")


class SandyInstallTest(Base):
    def facts(self, run):
        return dict(run.receipts[("S7", self.vm_name)][1])

    def test_installed_once_then_already(self):
        run, r = self.s7()
        self.assertIsNone(r)
        self.assertEqual(self.facts(run)["SANDY"], "CHANGED")
        self.assertEqual(self.fake.installs, len(SANDY_FILES))
        run, r = self.s7()
        self.assertEqual(self.facts(run)["SANDY"], "ALREADY")
        self.assertEqual(self.fake.installs, len(SANDY_FILES))

    def test_placed_root_owned_with_the_ruled_modes(self):
        self.s7()
        self.assertEqual(self.fake.root[S7.SANDY][1], "0:0 755 regular file")
        self.assertEqual(self.fake.root[S7.PROXY_DIR][1], "0:0 755 directory")
        for name in ("go.mod", "main.go", ".gitignore"):
            self.assertEqual(self.fake.root[S7.PROXY_DIR + "/" + name][1], "0:0 644 regular file")

    def test_the_tree_sha_is_recorded_and_deterministic(self):
        run, r = self.s7()
        rows = sorted((f for f in self.lock["files"] if f["component"] == "sandy"), key=lambda f: f["path"])
        lines = "".join("%s  %s\n" % (f["sha256"], f["path"]) for f in rows if f["path"].startswith("proxy/"))
        self.assertEqual(self.facts(run)["SANDY_PROXY_TREE_SHA"], hashlib.sha256(lines.encode()).hexdigest())

    def test_every_sandy_call_uses_the_absolute_path(self):
        self.s7()
        sandy_calls = [a for a in self.fake.calls if a[0].endswith("sandy")]
        self.assertTrue(sandy_calls)
        self.assertTrue(all(a[0] == "/usr/local/bin/sandy" for a in sandy_calls))

    def test_one_file_off_its_pin_refuses_before_any_install(self):
        files = dict(SANDY_FILES, **{"proxy/main.go": b"package main // changed\n"})
        self.site.component_file = lambda comp, path, *, stage: files.get(path)
        run, r = self.s7()
        self.assertEqual((r.cause, r.detail), ("AGENTS.PIN", "sandy files"))
        self.assertEqual(self.fake.installs, 0)

    def test_rows_missing_or_out_of_shape_refuse(self):
        for name, mutate in (("no sandy", lambda f: f["path"] != "sandy"),
                             ("no go.mod", lambda f: f["path"] != "proxy/go.mod"),
                             ("no main.go", lambda f: f["path"] != "proxy/main.go")):
            with self.subTest(name=name):
                lock = copy.deepcopy(self.lock)
                lock["files"] = [f for f in lock["files"] if f["component"] != "sandy" or mutate(f)]
                with self.assertRaises(Refusal) as cm:
                    S7.sandy_rows(lock)
                self.assertEqual(cm.exception.detail, "sandy files")
        for bad in ("proxy/sub/x.go", "other", "proxy/"):
            with self.subTest(bad=bad):
                lock = copy.deepcopy(self.lock)
                lock["files"].append({"path": bad, "component": "sandy", "sha256": "1" * 64})
                with self.assertRaises(Refusal):
                    S7.sandy_rows(lock)

    def test_an_extra_file_in_proxy_or_a_wrong_mode_is_not_in_place(self):
        self.s7()
        v, rows = self.vm(), S7.sandy_rows(self.lock)
        self.assertTrue(S7.sandy_in_place(v, rows))
        self.fake.root[S7.PROXY_DIR + "/extra.go"] = (b"x", "0:0 644 regular file")
        self.assertFalse(S7.sandy_in_place(v, rows))
        del self.fake.root[S7.PROXY_DIR + "/extra.go"]
        self.fake.root[S7.PROXY_DIR + "/main.go"] = (SANDY_FILES["proxy/main.go"], "1000:1000 664 regular file")
        self.assertFalse(S7.sandy_in_place(v, rows))

    def test_a_writable_or_foreign_owned_file_is_replaced_then_rechecked(self):
        self.s7()
        self.fake.root[S7.SANDY] = (SANDY_BYTES, "1000:1000 775 regular file")
        before = self.fake.installs
        run, r = self.s7()
        self.assertIsNone(r)
        self.assertEqual(self.fake.installs, before + 1)  # only the file that was off

    def test_an_install_that_does_not_take_is_refused(self):
        for answer in ("CHANGED", "ALREADY", 0, None):  # claims success, or not the layer's answer
            with self.subTest(answer=answer):
                self.site.vm_install_file = lambda *a, **k: answer  # places nothing
                run, r = self.s7()
                self.assertEqual(r.cause, "AGENTS.PIN")

    def test_no_install_path_refuses(self):
        self.site.vm_install_file = a2_site.Site().vm_install_file  # unbound: refuses, places nothing
        run, r = self.s7()
        self.assertEqual((r.cause, r.rc), ("AGENTS.TARGET_ACCESS", 2))
        self.assertEqual(self.fake.root, {})

    def test_verify_refuses_a_sandy_not_root_owned(self):
        self.s7()
        self.fake.root[S7.SANDY] = (SANDY_BYTES, "1000:1000 755 regular file")
        self.assertEqual(S7.verify_agent(self.vm(), {"id": "alice"}), "sandy")


class AddAgentTest(Base):
    def setUp(self):
        super().setUp()
        other = self.hosts["vms"][1]["name"]
        self.hosts["agents"] = [{"id": "alice", "vm": self.vm_name, "connector": "connector"},
                                {"id": "bob", "vm": self.vm_name, "connector": "connector"},
                                {"id": "alice", "vm": other, "connector": "connector"}]

    def test_with_id_picks_that_hosts_entry(self):
        a = S7.add_agent_target(self.hosts, self.vm_name, "bob", lambda i: True)
        self.assertEqual((a["id"], a["vm"]), ("bob", self.vm_name))

    def test_with_an_id_of_another_host_refuses(self):
        with self.assertRaises(Refusal) as cm:
            S7.add_agent_target(self.hosts, self.vm_name, "carol", lambda i: False)
        self.assertEqual(cm.exception.cause, "AGENTS.ADD_AGENT_AMBIGUOUS")
        self.assertNotIn("carol", cm.exception.detail)

    def test_without_id_the_one_not_yet_on_the_vm(self):
        a = S7.add_agent_target(self.hosts, self.vm_name, None, lambda i: i == "alice")
        self.assertEqual(a["id"], "bob")

    def test_without_id_zero_or_two_refuse_with_a_count_only(self):
        for on_vm, count in ((lambda i: True, 0), (lambda i: False, 2)):
            with self.subTest(count=count):
                with self.assertRaises(Refusal) as cm:
                    S7.add_agent_target(self.hosts, self.vm_name, None, on_vm)
                self.assertEqual(cm.exception.detail, "candidate entries: %d" % count)
                self.assertNotIn("alice", cm.exception.detail)


class RotateTest(Base):
    def setUp(self):
        super().setUp()
        run, r = self.s7()
        self.assertIsNone(r)
        self.v = self.vm()
        self.ws = S7.workspace(self.v, "alice")

    def prev_exists(self):
        return os.path.exists(os.path.join(self.fake.sandy_home, ".secrets.prev"))

    def test_rotation_takes_and_leaves_no_previous(self):
        S7.rotate_vm(self.v, [self.ws], [self.ws], TOKEN2)
        self.assertEqual(self.fake.token(), bytes(TOKEN2))
        self.assertTrue(self.fake.running)
        self.assertFalse(self.prev_exists())
        self.assertIsNone(S7.verify_agent(self.v, {"id": "alice"}))

    def test_a_failed_start_restores_the_old_token_exit_3(self):
        self.fake.start_rc = [1, 0]  # the new start fails, the recovery start succeeds
        with self.assertRaises(Refusal) as cm:
            S7.rotate_vm(self.v, [self.ws], [self.ws], TOKEN2)
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("AGENTS.ROTATE_UNDONE", 3))
        self.assertEqual(self.fake.token(), bytes(TOKEN))
        self.assertTrue(self.fake.running)
        self.assertFalse(self.prev_exists())

    def test_the_same_value_is_refused_before_any_stop(self):
        self.fake.running = True
        with self.assertRaises(Refusal) as cm:
            S7.rotate_vm(self.v, [self.ws], [self.ws], TOKEN)
        self.assertEqual(cm.exception.cause, "AGENTS.WRITER")
        self.assertTrue(self.fake.running)
        self.assertFalse(self.prev_exists())

    def test_a_failed_restore_is_not_restored_even_if_a_start_succeeds(self):  # kills W7
        self.fake.start_rc = [1, 0]
        real = self.site.vm_write_secret

        def write_secret(vm_name, use, mode, value, *, account, stage):
            return 2 if mode == "restore" else real(vm_name, use, mode, value, account=account, stage=stage)
        self.site.vm_write_secret = write_secret
        v = self.vm()
        with self.assertRaises(Refusal) as cm:
            S7.rotate_vm(v, [self.ws], [self.ws], TOKEN2)
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("AGENTS.NOT_RESTORED", 3))

    def test_two_token_lines_are_not_a_present_credential(self):  # kills W9
        with open(os.path.join(self.fake.sandy_home, ".secrets"), "ab") as f:
            f.write(b"CLAUDE_CODE_OAUTH_TOKEN=second\n")
        self.assertEqual(S7.start_possible(self.v, self.ws), "credential")

    def test_recovery_start_failing_is_not_restored_exit_3(self):
        self.fake.start_rc = [1]
        with self.assertRaises(Refusal) as cm:
            S7.rotate_vm(self.v, [self.ws], [self.ws], TOKEN2)
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("AGENTS.NOT_RESTORED", 3))

    def test_no_start_path_stops_nothing(self):
        self.fake.approvals_rc = 2
        self.fake.running = True
        with self.assertRaises(Refusal) as cm:
            S7.rotate_vm(self.v, [self.ws], [self.ws], TOKEN2)
        self.assertEqual(cm.exception.cause, "AGENTS.NO_START_PATH")
        self.assertTrue(self.fake.running)
        self.assertEqual(self.fake.token(), bytes(TOKEN))

    def test_verify_refuses_a_leftover_previous(self):
        self.fake.put(".secrets.prev", b"OLD\n", 0o600)
        self.assertEqual(S7.verify_agent(self.v, {"id": "alice"}), "rotate_leftover")


class CommandEntryTest(Base):
    def cmd_ctx(self, command, **opts):
        c = self.ctx(command)
        c.inv.opts = opts
        return c

    def held(self, value=TOKEN):
        return types.SimpleNamespace(values={"api_key": value})

    def test_add_agent_places_only_the_selected_agent(self):
        self.hosts["agents"].append({"id": "bob", "vm": self.vm_name, "connector": "connector"})
        run = Run(self.s6)
        S7.run_add_agent(self.cmd_ctx("add-agent", host=self.vm_name, id="bob"), self.site, run, self.held())
        facts = dict(run.receipts[("S7", self.vm_name)][1])
        self.assertEqual(facts["AGENT_2_ID"], "bob")
        self.assertNotIn("AGENT_1_ID", facts)
        self.assertTrue(os.path.isdir(self.fake.home + "/dev/agent-bob"))
        self.assertFalse(os.path.exists(self.fake.home + "/dev/agent-alice"))

    def test_add_agent_without_id_takes_the_one_not_on_the_vm(self):
        self.s7()  # alice in place
        self.hosts["agents"].append({"id": "bob", "vm": self.vm_name, "connector": "connector"})
        os.unlink(os.path.join(self.fake.sandy_home, ".secrets"))
        run = Run(self.s6)
        S7.run_add_agent(self.cmd_ctx("add-agent", host=self.vm_name), self.site, run, self.held())
        self.assertEqual(dict(run.receipts[("S7", self.vm_name)][1])["AGENT_2_ID"], "bob")

    def test_add_agent_on_an_unknown_host_refuses(self):
        with self.assertRaises(Refusal) as cm:
            S7.run_add_agent(self.cmd_ctx("add-agent", host="no-such-vm"), self.site, Run(self.s6), self.held())
        self.assertEqual(cm.exception.cause, "AGENTS.ADD_AGENT_AMBIGUOUS")

    def test_rotate_key_rotates_every_agent_and_records_no_value(self):
        self.s7()
        run = Run(self.s6)
        S7._rotate_key_all_vms(self.cmd_ctx("rotate-key"), self.site, run, self.held(TOKEN2))
        result, facts, rc, cause = run.receipts[("S7", self.vm_name)]
        self.assertEqual((result, dict(facts)), ("CHANGED", {"ROTATED": "yes", "AGENTS_RESTARTED": "1",
                                                    "AGENTS_RESTARTED_IDS": "alice"}))
        self.assertEqual(self.fake.token(), bytes(TOKEN2))
        self.assertNotIn(bytes(TOKEN2).decode(), json.dumps(facts))

    def test_two_agents_one_rotation_every_agent_restarted(self):  # Opus 1
        self.hosts["agents"].append({"id": "bob", "vm": self.vm_name, "connector": "connector"})
        self.s7()
        self.fake.secret_calls.clear()
        run = Run(self.s6)
        S7._rotate_key_all_vms(self.cmd_ctx("rotate-key"), self.site, run, self.held(TOKEN2))
        result, facts, rc, cause = run.receipts[("S7", self.vm_name)]
        self.assertEqual((result, dict(facts)), ("CHANGED", {"ROTATED": "yes", "AGENTS_RESTARTED": "2",
                                                    "AGENTS_RESTARTED_IDS": "alice,bob"}))
        self.assertEqual(self.fake.secret_calls, ["rotate", "finish"])  # once per VM
        self.assertEqual(self.fake.token(), bytes(TOKEN2))
        starts = [a[-1] for a in self.fake.calls if a[1:2] == ["--start"]]
        self.assertEqual(sorted(starts), sorted([self.fake.home + "/dev/agent-alice", self.fake.home + "/dev/agent-bob"]))

    def test_two_agents_a_failed_start_restores_once_and_restarts_both(self):
        self.hosts["agents"].append({"id": "bob", "vm": self.vm_name, "connector": "connector"})
        self.s7()
        self.fake.secret_calls.clear()
        self.fake.start_rc = [0, 1, 0, 0]  # alice ok, bob fails; then both recover
        with self.assertRaises(Refusal) as cm:
            S7._rotate_key_all_vms(self.cmd_ctx("rotate-key"), self.site, Run(self.s6), self.held(TOKEN2))
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("AGENTS.ROTATE_UNDONE", 3))
        self.assertEqual(self.fake.secret_calls, ["rotate", "restore"])
        self.assertEqual(self.fake.token(), bytes(TOKEN))

    def test_a_real_rotate_then_rc4_is_undone_with_the_old_token_back(self):  # Opus 2, M1; r2 3
        self.s7()
        self.fake.secret_calls.clear()
        self.fake.writer_after = {"rotate": 4}  # the real rotate ran; the layer says 4
        with self.assertRaises(Refusal) as cm:
            S7._rotate_key_all_vms(self.cmd_ctx("rotate-key"), self.site, Run(self.s6), self.held(TOKEN2))
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("AGENTS.ROTATE_UNDONE", 3))
        self.assertEqual(self.fake.secret_calls, ["rotate", "restore"])
        self.assertEqual(self.fake.token(), bytes(TOKEN))
        self.assertFalse(os.path.exists(os.path.join(self.fake.sandy_home, ".secrets.prev")))

    def test_a_first_write_that_stands_but_is_not_durable_is_not_restored(self):
        self.fake.writer_rc_override = {"write": 4}
        run, r = self.s7()
        self.assertEqual((r.cause, r.rc), ("AGENTS.NOT_RESTORED", 3))

    def test_rotate_key_checks_all_agents_of_a_vm_before_rotating_any(self):  # kills W8
        self.hosts["agents"].append({"id": "bob", "vm": self.vm_name, "connector": "connector"})
        self.s7()
        self.fake.approvals_by_ws[self.fake.home + "/dev/agent-bob"] = 2
        with self.assertRaises(Refusal) as cm:
            S7._rotate_key_all_vms(self.cmd_ctx("rotate-key"), self.site, Run(self.s6), self.held(TOKEN2))
        self.assertEqual(cm.exception.cause, "AGENTS.NO_START_PATH")
        self.assertEqual(self.fake.token(), bytes(TOKEN))  # alice was not rotated either

    def test_rotate_key_checks_every_agent_before_any_stop(self):
        self.s7()
        self.fake.running = True
        self.fake.approvals_rc = 2
        run = Run(self.s6)
        with self.assertRaises(Refusal) as cm:
            S7._rotate_key_all_vms(self.cmd_ctx("rotate-key"), self.site, run, self.held(TOKEN2))
        self.assertEqual(cm.exception.cause, "AGENTS.NO_START_PATH")
        self.assertTrue(self.fake.running)
        self.assertEqual(self.fake.token(), bytes(TOKEN))


class WriterOutcomeTest(Base):  # Opus W8 r2, 1 and 3; Dan "on W8 go A"
    """Only 0 and the writer's own 2 and 3 are known outcomes. Every other result of
    vm_write_secret, after a REAL write or rotate, is unknown and never AGENTS.WRITER."""
    UNKNOWN = (4, 255, None, -9, "raise-refusal", "raise-other")

    def after(self, kind):
        if kind == "raise-refusal":  # what the layer raises after a write (a2_vm.write_secret)
            return Refusal("AGENTS.UNCLASSIFIED", "the bootstrap failed after READY", rc=3)
        if kind == "raise-other":
            return RuntimeError("transport dropped")
        return kind

    def prev(self):
        return os.path.exists(os.path.join(self.fake.sandy_home, ".secrets.prev"))

    def rotate(self):
        with self.assertRaises(Refusal) as cm:
            S7.rotate_vm(self.vm(), [self.ws], [self.ws], TOKEN2)
        return cm.exception

    def setup_rotation(self):
        run, r = self.s7()
        self.assertIsNone(r)
        self.ws = S7.workspace(self.vm(), "alice")

    def test_a_real_rotate_with_an_unknown_result_takes_the_restore_path(self):
        self.setup_rotation()
        for kind in self.UNKNOWN:
            with self.subTest(result=kind):
                self.fake.secret_calls.clear()
                self.fake.writer_after = {"rotate": self.after(kind)}
                e = self.rotate()
                self.assertEqual((e.cause, e.rc), ("AGENTS.ROTATE_UNDONE", 3))
                self.assertEqual(self.fake.secret_calls, ["rotate", "restore"])
                self.assertEqual(self.fake.token(), bytes(TOKEN))  # the old token is back
                self.assertFalse(self.prev())
                self.assertTrue(self.fake.running)  # the recovery restart ran

    def test_an_unknown_result_with_no_change_is_not_restored(self):
        self.setup_rotation()
        self.fake.writer_rc_override = {"rotate": 255}  # nothing ran, so restore finds no previous
        e = self.rotate()
        self.assertEqual((e.cause, e.rc), ("AGENTS.NOT_RESTORED", 3))
        self.assertEqual(self.fake.token(), bytes(TOKEN))

    def test_the_writers_own_no_change_codes_are_agents_writer_and_stop_nothing(self):  # X9
        self.setup_rotation()
        for rc in (2, 3):
            with self.subTest(rc=rc):
                self.fake.secret_calls.clear()
                self.fake.calls.clear()
                self.fake.writer_rc_override = {"rotate": rc}
                e = self.rotate()
                # Its name kept, exit 3: rule 10's sandy calls wrote first (DS 1d2129d4; 3.4).
                self.assertEqual((e.cause, e.rc), ("AGENTS.WRITER", 3))
                self.assertEqual(self.fake.secret_calls, ["rotate"])
                self.assertEqual([a for a in self.fake.calls if a[1:2] in (["--stop"], ["--start"])], [])

    def test_a_failed_finish_is_not_restored_with_the_previous_file_left(self):  # X8
        self.setup_rotation()
        for result in (4, 255, RuntimeError("transport dropped")):
            with self.subTest(result=result):
                if self.prev():
                    os.unlink(os.path.join(self.fake.sandy_home, ".secrets.prev"))
                self.fake.put(".secrets", S7.TOKEN_KEY.encode() + b"=" + bytes(TOKEN) + b"\n", 0o600)
                self.fake.writer_rc_override = {}
                self.fake.writer_after = {}
                if isinstance(result, BaseException):
                    def finish_raises(vm_name, use, mode, value, *, account, stage, real=self.fake.vm_write_secret):
                        if mode == "finish":
                            raise result
                        return real(vm_name, use, mode, value, account=account, stage=stage)
                    self.site.vm_write_secret = finish_raises
                else:
                    self.site.vm_write_secret = self.fake.vm_write_secret
                    self.fake.writer_rc_override = {"finish": result}  # finish did not run
                e = self.rotate()
                self.assertEqual((e.cause, e.rc), ("AGENTS.NOT_RESTORED", 3))
                self.assertEqual(self.fake.token(), bytes(TOKEN2))
                self.assertTrue(self.prev())

    def test_a_real_write_with_an_unknown_result_is_not_restored_never_writer(self):
        for kind in self.UNKNOWN:
            with self.subTest(result=kind):
                p = os.path.join(self.fake.sandy_home, ".secrets")
                if os.path.exists(p):
                    os.unlink(p)
                self.fake.writer_after = {"write": self.after(kind)}
                if kind == "raise-refusal":  # the layer's own refusal, let out as raised
                    self.assert_refused("AGENTS.UNCLASSIFIED", rc=3, token_written=True)
                else:
                    self.assert_refused("AGENTS.NOT_RESTORED", rc=3, token_written=True)

    def test_a_write_the_writer_refused_or_undid_is_agents_writer(self):
        for rc in (2, 3):
            with self.subTest(rc=rc):
                self.fake.writer_rc_override = {"write": rc}
                # Its name kept, exit 3: the workspace mkdir wrote first (DS 1d2129d4; 3.4).
                self.assert_refused("AGENTS.WRITER", rc=3)

    def test_a_failed_restore_still_restarts_every_agent(self):  # X2
        self.setup_rotation()
        self.fake.start_rc = [1, 0]
        self.fake.writer_rc_override = {"restore": 2}
        self.fake.calls.clear()
        e = self.rotate()
        self.assertEqual((e.cause, e.rc), ("AGENTS.NOT_RESTORED", 3))
        self.assertEqual(len([a for a in self.fake.calls if a[1:2] == ["--start"]]), 2)  # first, then recovery
        self.assertTrue(self.fake.running)

    def test_restart_all_starts_every_agent_after_a_failed_start(self):  # X1
        self.setup_rotation()
        ws2 = S7.workspace(self.vm(), "bob")
        self.fake.start_rc = [1, 0]
        self.fake.calls.clear()
        self.assertFalse(S7._restart_all(self.vm(), [self.ws, ws2]))
        self.assertEqual([a[-1] for a in self.fake.calls if a[1:2] == ["--start"]], [self.ws, ws2])


class StandinRotationTest(Base):  # Opus W8 r2, 2; DS e321121f
    """--rotate-key checks the stand-in (rule 10) and never starts it."""

    def setUp(self):
        super().setUp()
        self.standin = b"# synthetic vm_standin.py\n"
        self.fake.put("features/amap/payload/vm_standin.py", self.standin)
        self.lock["components"].append({"name": "amap-deploy-sandy", "repo": "https://git.example.org/x/d",
                                        "commit": "f" * 40, "tag": "alpha2-rc1"})
        self.lock["files"].append({"path": "install/vm_standin.py", "component": "amap-deploy-sandy",
                                   "sha256": hashlib.sha256(self.standin).hexdigest()})
        self.hosts["agents"].append({"id": "canary", "vm": self.vm_name, "connector": "amap-deploy-sandy"})
        run, r = self.s7()
        self.assertIsNone(r)
        self.canary = self.fake.home + "/dev/agent-canary"
        self.alice = self.fake.home + "/dev/agent-alice"
        self.fake.calls.clear()
        self.fake.secret_calls.clear()

    def ctx_rotate(self):
        c = self.ctx("rotate-key")
        c.inv.opts = {}
        return c

    def sandy_verbs(self, ws):
        return [a[1] for a in self.fake.calls if a[:1] == [S7.SANDY] and a[-1] == ws and a[1] != "--approvals"]

    def test_a_successful_rotation_leaves_the_standin_stopped(self):
        run = Run(self.s6)
        S7._rotate_key_all_vms(self.ctx_rotate(), self.site, run, types.SimpleNamespace(values={"api_key": TOKEN2}))
        result, facts, rc, cause = run.receipts[("S7", self.vm_name)]
        self.assertEqual((result, dict(facts)), ("CHANGED", {"ROTATED": "yes", "AGENTS_RESTARTED": "1",
                                                             "AGENTS_RESTARTED_IDS": "alice"}))
        self.assertEqual(self.sandy_verbs(self.canary), [])  # never stopped, never started
        self.assertEqual(self.sandy_verbs(self.alice), ["--stop", "--start"])
        self.assertEqual(self.fake.token(), bytes(TOKEN2))

    def test_a_failed_rotation_leaves_the_standin_stopped(self):
        self.fake.start_rc = [1, 0]  # alice's start fails, her recovery start succeeds
        with self.assertRaises(Refusal) as cm:
            S7._rotate_key_all_vms(self.ctx_rotate(), self.site, Run(self.s6),
                              types.SimpleNamespace(values={"api_key": TOKEN2}))
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("AGENTS.ROTATE_UNDONE", 3))
        self.assertEqual(self.sandy_verbs(self.canary), [])
        self.assertEqual(self.sandy_verbs(self.alice), ["--stop", "--start", "--stop", "--start"])
        self.assertEqual(self.fake.token(), bytes(TOKEN))

    def test_rule_10_still_covers_the_standin(self):
        self.fake.approvals_by_ws[self.canary] = 2
        with self.assertRaises(Refusal) as cm:
            S7._rotate_key_all_vms(self.ctx_rotate(), self.site, Run(self.s6),
                              types.SimpleNamespace(values={"api_key": TOKEN2}))
        self.assertEqual(cm.exception.cause, "AGENTS.NO_START_PATH")
        self.assertEqual(self.fake.secret_calls, [])
        self.assertEqual(self.fake.token(), bytes(TOKEN))

    def test_a_vm_with_only_a_standin_refuses_before_any_change(self):
        self.hosts["agents"] = [a for a in self.hosts["agents"] if a["id"] == "canary"]
        with self.assertRaises(Refusal) as cm:
            S7._rotate_key_all_vms(self.ctx_rotate(), self.site, Run(self.s6),
                              types.SimpleNamespace(values={"api_key": TOKEN2}))
        self.assertEqual((cm.exception.cause, cm.exception.detail), ("AGENTS.NO_START_PATH", "no agent to restart"))
        self.assertEqual(self.fake.secret_calls, [])
        self.assertEqual(self.sandy_verbs(self.canary), [])


class RotateKeyUnsupportedTest(Base):  # Dan ALPHA2-W8-ROTATE-FALLBACK
    """--rotate-key is not in ALPHA-2: refused before any VM contact, write or receipt.
    The rotation tests above call the kept body (_rotate_key_all_vms, rotate_vm)
    directly; this class pins that no installer code reaches it."""

    def test_rotate_key_refuses_with_zero_vm_calls(self):
        self.s7()
        self.fake.calls.clear()
        self.fake.secret_calls.clear()
        c = self.ctx("rotate-key")
        c.inv.opts = {}
        for held in (types.SimpleNamespace(values={"api_key": TOKEN2}), None):
            with self.subTest(held=held is not None):
                run = Run(self.s6)
                with self.assertRaises(Refusal) as cm:
                    S7.run_rotate_key(c, self.site, run, held)
                self.assertEqual((cm.exception.cause, cm.exception.rc), ("AGENTS.ROTATE_UNSUPPORTED", 2))
                self.assertEqual((self.fake.calls, self.fake.secret_calls, run.receipts), ([], [], {}))
                self.assertEqual(self.fake.token(), bytes(TOKEN))

    def test_no_installer_code_reaches_rotation(self):
        """Every reference to a rotation function in install/*.py (tests excluded), as a
        call, a value or an attribute, is inside rotation itself; run_rotate_key calls
        only Refusal."""
        import ast
        rotation = {"_rotate_key_all_vms", "rotate_vm", "precheck_vm", "rotate_checked", "_restart_all"}
        refs = set()

        def walk(node, where):
            for child in ast.iter_child_nodes(node):
                inner = child.name if isinstance(child, (ast.FunctionDef, ast.ClassDef)) else where
                ref = child.id if isinstance(child, ast.Name) else (
                    child.attr if isinstance(child, ast.Attribute) else None)
                if ref in rotation:
                    refs.add((ref, where))
                walk(child, inner)
        for name in sorted(os.listdir(a2fix.INSTALL)):
            if name.endswith(".py"):
                with open(os.path.join(a2fix.INSTALL, name), encoding="utf-8") as f:
                    walk(ast.parse(f.read()), name + ":<module>")
        self.assertEqual(refs, {("rotate_vm", "_rotate_key_all_vms"), ("_restart_all", "rotate_vm")})
        src = __import__("inspect").getsource(S7.run_rotate_key)
        body = ast.parse(__import__("textwrap").dedent(src)).body[0].body
        calls = {n.func.id for n in ast.walk(ast.Module(body=body, type_ignores=[]))
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        self.assertEqual(calls, {"Refusal"})


class CausesTest(unittest.TestCase):
    def test_agents_sentences_are_the_contracts(self):
        want = contract_sentences()
        for cause, text in a2_causes.AGENTS_SENTENCES.items():
            self.assertEqual(want.get(cause), text, cause)
        self.assertEqual(sorted(a2_causes.AGENTS_SENTENCES),
                         sorted(k for k in want if k.startswith("AGENTS.")))

    def test_not_restored_exits_3(self):
        self.assertEqual(Refusal("AGENTS.NOT_RESTORED", rc=3).rc, 3)
        with self.assertRaises(ValueError):  # an after-write-only cause names its exit (a2_causes.AFTER_WRITE_ONLY)
            Refusal("AGENTS.NOT_RESTORED")
        self.assertEqual(Refusal("AGENTS.ROTATE_UNDONE").rc, 3)
        self.assertEqual(Refusal("AGENTS.NO_START_PATH").rc, 2)


if __name__ == "__main__":
    unittest.main()
