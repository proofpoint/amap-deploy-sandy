"""W8 r6 on W7 b043a1e: S7 against S6's real output, sandy's schema after install, and the
stage-wide exit rule (DS 1d2129d4, 78e68fd9)."""

import ast
import copy
import json
import os
import types

import a2fix  # noqa: F401 - puts install/ on sys.path, as the other test modules
import a2_causes
import a2_s6
import a2_s6_payload
import a2_sandy_caps
import a2_s7 as S7
from a2_causes import Refusal

from test_w8_s7 import Base, Run, SCHEMA_924, TOKEN

INSTALL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def s7_tree():
    with open(os.path.join(INSTALL, "a2_s7.py")) as f:
        return ast.parse(f.read())


def receipt_fact_names():
    """The fact names in a2_s6's per-VM receipt list (`receipt = [("CONFIG", "PLACED"), ...]`)."""
    with open(os.path.join(INSTALL, "a2_s6.py")) as f:
        tree = ast.parse(f.read())
    names = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "receipt"):
            for elt in ast.walk(node.value):
                if isinstance(elt, ast.Tuple) and elt.elts and isinstance(elt.elts[0], ast.Constant):
                    names.add(elt.elts[0].value)
    return names


class S6AgreementTest(Base):
    """What S7 reads is what b043a1e's S6 writes, taken from S6's own modules."""

    def test_the_fact_names_are_s6s_receipt_names(self):
        self.assertTrue(set(S7.CONFIG_FACTS) <= receipt_fact_names(), receipt_fact_names())

    def test_router_json_is_s6s_router_dir(self):
        self.assertEqual(S7.ROUTER_JSON, a2_s6.ROUTER_DIR + "/router.json")

    def test_feature_json_is_under_s6s_feature_root(self):
        # S7's $SANDY_HOME is $HOME/.sandy (VmAccess); S6 places feature.json at FEATURE_ROOT under $HOME.
        self.assertEqual(a2_s6.FEATURE_ROOT, a2_s6.SANDY_SUBDIR + "/features/amap")
        self.assertEqual(self.vm().sandy_home, self.fake.home + "/" + a2_s6.SANDY_SUBDIR)
        self.assertEqual(S7.FEATURE_JSON, "features/amap/feature.json")

    def test_the_connector_files_are_s6s_payload(self):
        want = tuple(("features/amap/payload/" + path, src)
                     for path, source, src, _x in a2_s6_payload.PAYLOAD if source == "connector")
        self.assertEqual(S7.CONNECTOR_FILES, want)


class SandySchemaTest(Base):
    """After install, the installed sandy's --print-schema answers a2_sandy_caps."""

    def facts(self, run):
        return dict(run.receipts[("S7", self.vm_name)][1])

    def test_the_real_924fa5b6_schema_passes_and_is_recorded(self):
        run, r = self.s7()
        self.assertIsNone(r)
        self.assertEqual(self.facts(run)["SANDY_SCHEMA_VERSION"], "4")
        self.assertIn([S7.SANDY, "--print-schema"], [a for a, _w in self.fake.exec_log])

    def test_the_check_runs_after_install_and_before_any_agent(self):
        self.s7()
        argvs = [a for a, _w in self.fake.exec_log]
        at = argvs.index([S7.SANDY, "--print-schema"])
        self.assertGreater(self.fake.installs, 0)  # the fake asserts sandy is installed before any sandy call
        self.assertFalse(any(a[0] == "/usr/bin/mkdir" for a in argvs[:at]))  # no workspace before it

    def refuses(self, schema=None, out=None, rc=0):
        self.fake.schema_rc = rc
        self.fake.schema_out = out if out is not None else json.dumps(schema).encode()
        run, r = self.s7()
        self.assertIsNotNone(r, "S7 passed")
        self.assertEqual((r.cause, r.detail, r.rc), ("AGENTS.PIN", "sandy schema", 3))
        self.assertEqual(self.fake.secret_calls, [])  # refused before any agent step
        self.assertNotIn("SANDY_SCHEMA_VERSION", self.facts(run))

    def test_every_departure_refuses(self):
        def edit(f):
            d = copy.deepcopy(SCHEMA_924)
            f(d)
            return d
        cases = {
            "version 3": edit(lambda d: d.update(schema_version=3)),
            "version 5": edit(lambda d: d.update(schema_version=5)),
            "version as a string": edit(lambda d: d.update(schema_version="4")),
            "version true": edit(lambda d: d.update(schema_version=True)),
            "no version": edit(lambda d: d.pop("schema_version")),
            "no manifest": edit(lambda d: d.pop("manifest")),
            "no receives key": edit(lambda d: d["manifest"]["top_level_keys"].remove("receives")),
            "no agent_wrapper key": edit(lambda d: d["manifest"]["top_level_keys"].remove("agent_wrapper")),
            "keys not a list": edit(lambda d: d["manifest"].update(top_level_keys="receives agent_wrapper")),
            "no cross_session value": edit(lambda d: d["manifest"].update(receives_values=[])),
            "no receives_values": edit(lambda d: d["manifest"].pop("receives_values")),
        }
        for name, schema in cases.items():
            with self.subTest(case=name):
                self.refuses(schema)
        with self.subTest(case="rc 1"):
            self.refuses(SCHEMA_924, rc=1)
        with self.subTest(case="not JSON"):
            self.refuses(out=b"schema_version: 4\n")
        with self.subTest(case="not UTF-8"):
            self.refuses(out=b"\xff\xfe{}")

    def test_the_capabilities_are_imported_never_copied(self):
        self.assertIs(S7.a2_sandy_caps, a2_sandy_caps)
        consts = {n.value for n in ast.walk(s7_tree()) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        for v in a2_sandy_caps.MANIFEST_KEYS + a2_sandy_caps.RECEIVES_VALUES:
            self.assertNotIn(v, consts)

    def test_add_agent_checks_it_too(self):
        self.fake.schema_out = json.dumps(dict(SCHEMA_924, schema_version=3)).encode()
        c = self.ctx("add-agent")
        c.inv.opts = {"host": self.vm_name}
        held = types.SimpleNamespace(values={"api_key": TOKEN})
        with self.assertRaises(Refusal) as cm:
            S7.run_add_agent(c, self.site, Run(self.s6), held)
        self.assertEqual((cm.exception.cause, cm.exception.detail), ("AGENTS.PIN", "sandy schema"))


class PerHostRun(Run):
    def __init__(self, by_host):
        super().__init__(None)
        self.by_host = by_host

    def read_receipt(self, stage, host):
        assert stage == "S6"
        v = self.by_host[host]
        if isinstance(v, Refusal):
            raise v
        return v


class ExitRuleTest(Base):
    """Exit 2 means S7 wrote nothing (3.4): every AGENTS cause after VM contact takes
    wrote_rc, the rule is stage-wide, and S6's receipts are all read before any write."""

    #: AGENTS causes raised without wrote_rc, each with its reason.
    WITHOUT = {
        "AGENTS.ROTATE_UNSUPPORTED": "raised before any VM contact (run_rotate_key)",
        "AGENTS.ADD_AGENT_AMBIGUOUS": "add_agent_target: --add-agent's first write is install_sandy, after it",
        "AGENTS.NOT_RESTORED": "exit 3 by the contract (4.2)",
        "AGENTS.ROTATE_UNDONE": "exit 3 by the contract",
        "AGENTS.UNCLASSIFIED": "its rc is always written out (2 before contact, 3 for a bad layer result)",
    }

    def test_every_agents_cause_after_contact_takes_wrote_rc(self):
        bad = []
        for node in ast.walk(s7_tree()):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Refusal"):
                continue
            first = node.args[0] if node.args else None
            if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
                continue  # read_s6's rename, read before any write
            rc = [k for k in node.keywords if k.arg == "rc"]
            if first.value in self.WITHOUT:
                if first.value == "AGENTS.UNCLASSIFIED":
                    self.assertTrue(rc and isinstance(rc[0].value, ast.Constant), node.lineno)
                continue
            ok = (rc and isinstance(rc[0].value, ast.Call) and isinstance(rc[0].value.func, ast.Name)
                  and rc[0].value.func.id == "wrote_rc")
            if not ok:
                bad.append((node.lineno, first.value))
        self.assertEqual(bad, [])

    def test_wrote_rc_reads_the_layer(self):
        self.assertIsNone(S7.wrote_rc(self.site))
        self.fake.wrote.add("AGENTS")
        self.assertEqual(S7.wrote_rc(self.site), 3)
        self.assertIsNone(S7.wrote_rc(types.SimpleNamespace()))  # an unbound site: nothing written through it

    def test_every_agents_sentence_may_exit_3(self):  # W8's own _two_or_three line
        for cause in a2_causes.AGENTS_SENTENCES:
            with self.subTest(cause=cause):
                self.assertEqual(Refusal(cause, rc=3).rc, 3)

    def two_vms(self):
        a, b = self.hosts["vms"][0], self.hosts["vms"][1]
        self.hosts["agents"] = [{"id": "alice", "vm": a["name"], "connector": "connector"},
                                {"id": "bob", "vm": b["name"], "connector": "connector"}]
        c = self.ctx()
        c.run_vms = [a, b]
        return c, a["name"], b["name"]

    def test_the_second_vms_cause_follows_the_first_vms_writes(self):
        c, a, b = self.two_vms()
        # b's receipt is well-formed (it passes check_s6_facts before any contact), but its
        # router sha differs from the VM's file: a cause only b's own VM contact can raise.
        run = PerHostRun({a: self.s6, b: dict(self.s6, ROUTER_JSON_SHA="0" * 64)})
        held = types.SimpleNamespace(values={"api_key": TOKEN})
        with self.assertRaises(Refusal) as cm:
            S7.run_s7(c, self.site, run, held)
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("AGENTS.CONFIG_NOT_PLACED", 3))
        self.assertEqual(run.receipts[("S7", a)][0], "CHANGED")
        self.assertEqual(run.receipts[("S7", b)][3], "AGENTS.CONFIG_NOT_PLACED")

    def test_every_s6_receipt_is_read_before_any_vm_contact(self):
        c, a, b = self.two_vms()
        for name in ("PREDECESSOR_MISSING", "PREDECESSOR_INCOMPLETE", "PREDECESSOR_FAILED",
                     "PREDECESSOR_INSTALLER"):
            with self.subTest(cause=name):
                run = PerHostRun({a: self.s6, b: Refusal("CONFIG." + name)})
                held = types.SimpleNamespace(values={"api_key": TOKEN})
                with self.assertRaises(Refusal) as cm:
                    S7.run_s7(c, self.site, run, held)
                # Its name kept, in S7's stage (DS 78e68fd9; as a2_s6.read_prior), exit 2: nothing written.
                self.assertEqual((cm.exception.cause, cm.exception.detail, cm.exception.rc),
                                 ("AGENTS." + name, "S6-" + b, 2))
                self.assertEqual(self.fake.exec_log, [])
                self.assertEqual(run.receipts, {})


class SandyWritesStaticTest(Base):  # Opus W8 r5.1 advisory
    def test_every_sandy_call_says_writes_true(self):
        """Every `.sandy(...)` call in a2_s7.py outside VmAccess.sandy passes writes=True as a
        literal: every sandy invocation can write (sandy 256-258; DS's ruling)."""
        seen = 0
        for top in s7_tree().body:
            fns = [top] if isinstance(top, ast.FunctionDef) else \
                [f for f in top.body if isinstance(f, ast.FunctionDef) and f.name != "sandy"] \
                if isinstance(top, ast.ClassDef) else []
            for fn in fns:
                for node in ast.walk(fn):
                    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                            and node.func.attr == "sandy"):
                        w = [k for k in node.keywords if k.arg == "writes"]
                        self.assertTrue(w and isinstance(w[0].value, ast.Constant) and w[0].value.value is True,
                                        "line %d" % node.lineno)
                        seen += 1
        self.assertGreaterEqual(seen, 8)
