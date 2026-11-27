"""Unit tests: causes against the contract text, the private-file checks,
argv, environment and account. Each refusal has a test that makes it fire
on a surface only that check can produce."""

import ast
import copy
import io
import json
import os
import re
import unittest

import a2fix  # noqa: F401  (puts install/ on sys.path)
import a2_args
import a2_causes
import a2_host
import a2_private
from a2_causes import Refusal

CONTRACT = os.path.join(a2fix.REPO, "alpha2", "STAGE-CONTRACT.md")


def contract_sentences():
    """Section 4.7's table, read from the contract file itself."""
    with open(CONTRACT, encoding="utf-8") as f:
        text = f.read()
    sec = text.split("### 4.7 Cause sentences", 1)[1].split("\n## 5.", 1)[0]
    out = {}
    for line in sec.splitlines():
        m = re.fullmatch(r"\| `([^`]+)` \| (.+) \|", line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def contract_exit_cells():
    """Section 4.2's table: {NAME: its Exit cell}, read from the contract file itself."""
    with open(CONTRACT, encoding="utf-8") as f:
        text = f.read()
    sec = text.split("### 4.2 Names every stage carries", 1)[1].split("\n### 4.3", 1)[0]
    out = {}
    for line in sec.splitlines():
        m = re.fullmatch(r"\| `([A-Z][A-Z0-9_]*)` \| ([^|]+) \| .+ \|", line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def _calls_in_functions(tree):
    """(enclosing function name, call node) for every call in a module."""
    out = []

    def visit(node, func):
        for ch in ast.iter_child_nodes(node):
            here = ch.name if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)) else func
            if isinstance(ch, ast.Call):
                out.append((here, ch))
            visit(ch, here)
    visit(tree, "<module>")
    return out


class CausesTest(unittest.TestCase):
    def test_every_4_2_exit_cell_matches_what_the_code_allows(self):
        """Codex's W13 r2 blocker 1: 4.2's Exit cell is the exit before a write. A cause that arises only after a
        write (AFTER_WRITE_ONLY, which the constructor holds to rc 3) says "3"; no other cause says "3" alone, and
        a "3 after a write" cell names a cause that can take rc 3."""
        cells = contract_exit_cells()
        self.assertEqual(sorted(cells), sorted(a2_causes.STAGE_SENTENCES))
        self.assertEqual(sorted(n for n, c in cells.items() if c == "3"), sorted(a2_causes.AFTER_WRITE_ONLY))
        self.assertEqual(sorted(n for n, c in cells.items() if c == "2"), sorted(a2_causes.BEFORE_WRITE_ONLY))
        for name, cell in cells.items():
            with self.subTest(name=name):
                self.assertIn(cell, ("2", "3", "2 (3 after a write)", "3, or 2 only when no write can be shown"))
                if cell == "2 (3 after a write)":
                    self.assertEqual(Refusal("START." + name, rc=3).rc, 3)
                    self.assertEqual(Refusal("START." + name).rc, 2)
                if cell == "2":
                    # Gate B's note N4: a "2" cell's cause cannot be built at rc 3.
                    with self.assertRaises(ValueError):
                        Refusal("START." + name, rc=3)
                    self.assertEqual(Refusal("START." + name).rc, 2)

    def test_an_after_write_only_cause_cannot_exit_2(self):
        for name in a2_causes.AFTER_WRITE_ONLY:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    Refusal("START." + name)
                self.assertEqual(Refusal("START." + name, rc=3).rc, 3)

    def test_every_after_write_only_raise_site_passes_rc_3(self):
        """Opus's W13 r3 note N-C7: a Refusal naming an AFTER_WRITE_ONLY cause without rc=3 is a ValueError, which
        a2_main turns into UNCLASSIFIED and so loses the cause's name. Every call in install/*.py that names one
        such cause passes the literal rc=3; the sites found are S4's obtain, S7 and the three S8 helpers, so the
        scan is not empty. A BEFORE_WRITE_ONLY cause (every "2" cell: step 3's CLOCK_SKEW, the receipt readers'
        PREDECESSOR_*, and the rest) passes no rc at any named site."""
        found, before, dynamic = [], [], set()
        known = set(a2_causes.STAGE_SENTENCES)
        for name in sorted(os.listdir(a2fix.INSTALL)):
            if not name.endswith(".py"):
                continue
            with open(os.path.join(a2fix.INSTALL, name), encoding="utf-8") as f:
                tree = ast.parse(f.read())
            for func, node in _calls_in_functions(tree):
                # Gate B's W13 r4 note N7: `Refusal(...)` and `<module>.Refusal(...)` alike.
                if not ((isinstance(node.func, ast.Name) and node.func.id == "Refusal")
                        or (isinstance(node.func, ast.Attribute) and node.func.attr == "Refusal")):
                    continue
                # The cause positional or as cause= (gate A's W13 r4 note N7).
                arg = node.args[0] if node.args else next((k.value for k in node.keywords if k.arg == "cause"), None)
                if arg is None:
                    dynamic.add((name, func))
                    continue
                consts = [c.value for c in ast.walk(arg)
                          if isinstance(c, ast.Constant) and isinstance(c.value, str)]
                if not ({c.rpartition(".")[2] for c in consts} & known
                        or any(c.startswith(("RUNNER.", "PREFLIGHT.", "CREDENTIALS.")) for c in consts)
                        or any(c in a2_causes.AGENTS_SENTENCES for c in consts)):
                    dynamic.add((name, func))
                names = {c.rpartition(".")[2] for c in consts}
                for cause in names & a2_causes.AFTER_WRITE_ONLY:
                    found.append((name, cause))
                    rc = [k.value for k in node.keywords if k.arg == "rc"]
                    with self.subTest(site=(name, node.lineno)):
                        self.assertTrue(len(rc) == 1 and isinstance(rc[0], ast.Constant) and rc[0].value == 3)
                for cause in names & a2_causes.BEFORE_WRITE_ONLY:
                    # Gate B's note N4: a before-write-only cause never passes rc, so it keeps exit 2.
                    before.append((name, cause))
                    with self.subTest(site=(name, node.lineno)):
                        self.assertEqual([k.arg for k in node.keywords if k.arg == "rc"], [])
        # A cause built at runtime escapes the name scan, so each such site is listed here and read by hand: a new
        # one fails until it is added (and reviewed for AFTER_WRITE_ONLY and BEFORE_WRITE_ONLY causes).
        self.assertEqual(sorted(dynamic), [
            ("a2_admit.py", "_common"), ("a2_main.py", "_run"), ("a2_main.py", "dispatch"),
            ("a2_s0.py", "_fetch_tag"), ("a2_s0.py", "_run_checks"), ("a2_s0.py", "check_l7"),
            ("a2_s0.py", "check_probes"), ("a2_s1.py", "check_l5"), ("a2_s6.py", "read_prior"),
            # S6b: _read keeps the reader's PREDECESSOR_* (no rc); _refused, measure and write pass rc only for
            # CONFIG_CHANGED, FILE, DOCKER, PROBE, WRITER, HOSTS, INTERPRETER and UNCLASSIFIED.
            ("a2_s6b.py", "_read"), ("a2_s6b.py", "_refused"), ("a2_s6b.py", "measure"), ("a2_s6b.py", "write"),
            ("a2_s7.py", "read_s6"), ("a2_s8.py", "measure"), ("a2_s8.py", "run"), ("a2_s8_run.py", "_read"), ("a2_s8_run.py", "run_s8"),
            ("a2_site.py", "slot"), ("a2_vm.py", "_refused")])
        self.assertEqual(sorted(found), [("a2_s4.py", "ID_MISMATCH"), ("a2_s4.py", "LOAD"),
                                         ("a2_s7.py", "NOT_RESTORED"), ("a2_s7.py", "NOT_RESTORED"),
                                         ("a2_s7.py", "NOT_RESTORED"), ("a2_s8_re.py", "RE_REFUSED"),
                                         ("a2_s8_rl.py", "NOT_ADMITTING"), ("a2_s8_rl.py", "RL_REFUSED")])
        self.assertEqual(sorted(set(before)), [
            ("a2_record.py", "PREDECESSOR_FAILED"), ("a2_record.py", "PREDECESSOR_INCOMPLETE"),
            ("a2_record.py", "PREDECESSOR_INSTALLER"), ("a2_record.py", "PREDECESSOR_MISSING"),
            ("a2_s4.py", "RE_FIX"), ("a2_s6.py", "HUB_HOSTNAME"), ("a2_s6.py", "PREDECESSOR_INCOMPLETE"),
            ("a2_s6b.py", "HUB_HOSTNAME"), ("a2_s6b.py", "PREDECESSOR_INCOMPLETE"),
            ("a2_s8_checks.py", "CLOCK_SKEW"),
            ("a2_s8_run.py", "PREDECESSOR_FAILED"), ("a2_s8_run.py", "PREDECESSOR_INCOMPLETE")])

    def test_every_sentence_is_the_contracts_byte_for_byte(self):
        want = contract_sentences()
        for cause, text in a2_causes.RUNNER_SENTENCES.items():
            self.assertEqual(want.get(cause), text, cause)
        for cause, text in a2_causes.CREDENTIALS_SENTENCES.items():
            self.assertEqual(want.get(cause), text, cause)
        self.assertEqual(sorted(a2_causes.CREDENTIALS_SENTENCES),
                         sorted(k for k in want if k.startswith("CREDENTIALS.")))
        for name, text in a2_causes.STAGE_SENTENCES.items():
            self.assertEqual(want.get("<STAGE>." + name), text, name)

    def test_unknown_cause_cannot_be_raised(self):
        with self.assertRaises(ValueError):
            Refusal("RUNNER.NOT_A_CAUSE")

    def test_report_prints_one_cause_line_and_the_sentence(self):
        buf = io.StringIO()
        rc = a2_causes.report(Refusal("RUNNER.ENV"), buf)
        self.assertEqual(rc, 2)
        self.assertEqual(buf.getvalue().splitlines(),
                         ["CAUSE=RUNNER.ENV", a2_causes.RUNNER_SENTENCES["RUNNER.ENV"]])

    def test_rc_override_only_for_two_or_three_causes(self):
        self.assertEqual(Refusal("RUNNER.UNCLASSIFIED", rc=3).rc, 3)
        self.assertEqual(Refusal("RUNNER.CUSTODY", rc=3).rc, 3)
        for cause, rc in (("RUNNER.ENV", 3), ("RUNNER.UNCLASSIFIED", 4), ("RUNNER.UNCLASSIFIED", 2)):
            with self.subTest(cause=cause, rc=rc):
                with self.assertRaises(ValueError):
                    Refusal(cause, rc=rc)

    def test_default_site_reads_the_reviewed_slots(self):
        import a2_site
        s = a2_site.Site()
        self.assertEqual(s.private_dir, "/srv/a2-private")
        self.assertIs(s.host_identity, a2_site.host_identity)

    def test_sums_exits_4(self):
        self.assertEqual(Refusal("RUNNER.SUMS").rc, 4)


def _pair(lock=None, hosts=None):
    lock = lock if lock is not None else a2fix.lock_bytes()
    hosts = hosts if hosts is not None else a2fix.dumps(a2fix.hosts_doc("/srv/locks"))
    return lock, hosts


class L1StageSetTest(unittest.TestCase):
    """Ruling W5-R13-L1-STAGESET-REQUIRED at argument parsing: an L1 stage set that includes S6 or later must
    include S3; every other --only/--from is unchanged."""

    def test_every_only_and_from(self):
        import a2_args
        late = a2_args.STAGE_IDS[a2_args.STAGE_IDS.index("S6"):]
        for flag in ("--only", "--from"):
            for stage in a2_args.STAGE_IDS:
                stages = [stage] if flag == "--only" else list(a2_args.STAGE_IDS[a2_args.STAGE_IDS.index(stage):])
                refused = any(s in late for s in stages) and "S3" not in stages
                with self.subTest(flag=flag, stage=stage):
                    if refused:
                        with self.assertRaises(Refusal) as cm:
                            a2_args.parse([flag, stage])
                        self.assertEqual((cm.exception.cause, cm.exception.rc), ("RUNNER.STAGE_SET", 2))
                    else:
                        inv = a2_args.parse([flag, stage])
                        self.assertEqual((inv.command, inv.loop), ("install", "L1"))
        self.assertEqual(a2_args.parse(["--from", "S3"]).opts, {"from": "S3"})
        self.assertEqual(a2_args.parse(["--only", "S5"]).opts, {"only": "S5"})


class RegistryProgramLockTest(unittest.TestCase):
    """The lock's registry_program (W7-REGISTRY-NAME-IN-LOCK): shape, and each name held to its pin (the fixture
    points the pins at its invented names, as a2fix states)."""

    def bad(self, change, path=None):
        d = copy.deepcopy(a2fix.LOCK)
        change(d)
        with self.assertRaises(a2_private.Invalid) as cm:
            a2_private.check_lock(d)
        if path is not None:
            self.assertEqual(cm.exception.path, path)

    def test_the_fixture_passes_and_each_name_is_pinned(self):
        a2_private.check_lock(copy.deepcopy(a2fix.LOCK))
        for key, other in (("package", "othertool"), ("config_schema", "othertool.config/1"),
                           ("adapter_interface", "othertool.adapter/1")):
            with self.subTest(key=key):
                self.bad(lambda d: d["registry_program"].update({key: other}), "$.registry_program." + key)

    def test_shape(self):
        for change in (lambda d: d.pop("registry_program"), lambda d: d["registry_program"].update(extra="x"),
                       lambda d: d["registry_program"].update(package="Reg-Tool"),
                       lambda d: d["registry_program"].update(config_schema="regtool.config"),
                       lambda d: d["registry_program"].update(adapter_interface="regtool.adapter/0")):
            self.bad(change)

    def test_the_component_is_pinned_and_names_exactly_one_component(self):
        self.bad(lambda d: d["registry_program"].update(component="router"), "$.registry_program.component")

        def gone(d):
            d["components"] = [c for c in d["components"] if c["name"] != "registry"]
        self.bad(gone, "$.registry_program.component")

    def test_the_plugin_is_exactly_one_files_row(self):
        def zero(d):
            d["files"] = [f for f in d["files"] if f["sha256"] != d["plugin"]["sha256"]]

        def two(d):
            d["files"].append({"path": "dist/other.py", "component": "connector", "sha256": d["plugin"]["sha256"]})

        def mismatch(d):
            d["plugin"]["sha256"] = "d" * 64
        for change in (zero, two, mismatch):
            with self.subTest(change=change.__name__):
                self.bad(change, "$.plugin.sha256")
        self.assertEqual([(f["component"], f["path"]) for f in a2_private.plugin_rows(a2fix.LOCK)],
                         [("router", "dist/plugin.py")])

    def test_the_pins_are_sha256_shaped_and_distinct(self):
        import importlib
        fresh = importlib.reload(a2_private)
        pins = (fresh.REGISTRY_PACKAGE_SHA256, fresh.REGISTRY_CONFIG_SCHEMA_SHA256,
                fresh.REGISTRY_ADAPTER_INTERFACE_SHA256, fresh.REGISTRY_COMPONENT_SHA256)
        importlib.reload(a2fix)
        self.assertTrue(all(len(p) == 64 and set(p) <= set("0123456789abcdef") for p in pins))
        self.assertEqual(len(set(pins)), 4)


class HubLoginLockTest(unittest.TestCase):
    """The lock's hub_login (W7-HUB-LOGIN-IN-LOCK): shape, and each name held to its pin (the fixture points the
    pins at its invented names, as a2fix states)."""

    def bad(self, change, path):
        d = copy.deepcopy(a2fix.LOCK)
        change(d)
        with self.assertRaises(a2_private.Invalid) as cm:
            a2_private.check_lock(d)
        self.assertEqual(cm.exception.path, path)

    def test_the_fixture_passes_and_each_name_is_pinned(self):
        a2_private.check_lock(copy.deepcopy(a2fix.LOCK))
        self.bad(lambda d: d["hub_login"].update(local="other"), "$.hub_login.local")
        self.bad(lambda d: d["hub_login"].update(domain="other.example"), "$.hub_login.domain")

    def test_shape(self):
        for change in (lambda d: d.pop("hub_login"), lambda d: d["hub_login"].update(extra="x"),
                       lambda d: d["hub_login"].update(local="L"), lambda d: d["hub_login"].update(domain="nodot"),
                       lambda d: d["hub_login"].update(local=7)):
            d = copy.deepcopy(a2fix.LOCK)
            change(d)
            with self.assertRaises(a2_private.Invalid):
                a2_private.check_lock(d)


class HostsKeysTest(unittest.TestCase):
    """The W7 hosts keys: each VM's accounts and router; RL's slug rules."""

    def bad(self, change):
        d = a2fix.hosts_doc("/srv/locks")
        change(d)
        with self.assertRaises(a2_private.Invalid):
            a2_private.check_hosts(d)

    def test_the_fixture_passes(self):
        a2_private.check_hosts(a2fix.hosts_doc("/srv/locks"))

    def test_refusals(self):
        cases = {
            "relay is the agent": lambda d: d["vms"][0].update(relay_account="agent"),
            "no router": lambda d: d["vms"][0].pop("router"),
            "no hop group": lambda d: d["vms"][0].pop("hop_group"),
            "a slug off RL's pattern": lambda d: d["vms"][0]["router"].update(slug="Router-A"),
            "a reserved slug": lambda d: d["vms"][0]["router"].update(slug="postmaster"),
            "two slugs with one skeleton": lambda d: d["vms"][1]["router"].update(slug="r0uter-a-t"),
            "a slug and an agent id with one skeleton": lambda d: d["agents"][0].update(id="routera-t"),
            "a relative stable_key": lambda d: d["vms"][0]["router"].update(stable_key="srv/x"),
            "two stable keys alike": lambda d: d["vms"][1]["router"].update(
                stable_key=d["vms"][0]["router"]["stable_key"]),
            "an extra router key": lambda d: d["vms"][0]["router"].update(logical_id="0" * 32),
            "a fleet domain that is not <host>.internal": lambda d: d["vms"][0].update(fleet_domain="a.example.org"),
            "a fleet domain with two labels before internal": lambda d: d["vms"][0].update(fleet_domain="x.a.internal"),
            "the hub login's domain": lambda d: (self.reserve("resv.internal"),
                                                 d["vms"][0].update(fleet_domain="resv.internal")),
            "an upper-case fleet domain": lambda d: d["vms"][0].update(fleet_domain="A-t.internal"),
            "a bare internal": lambda d: d["vms"][0].update(fleet_domain="internal"),
            "an authored key_id (the key id is router.slug + -k1, never authored)":
                lambda d: d["vms"][0].update(key_id="router-a-t-k1"),
        }
        for label, change in cases.items():
            with self.subTest(case=label):
                self.bad(change)

    def reserve(self, domain):
        """Point the login-domain pin at an invented `<host>.internal`, for this test (W7-LOGIN-DOMAIN-BY-PIN)."""
        import hashlib
        old = a2_private.LOGIN_DOMAIN_SHA256
        self.addCleanup(setattr, a2_private, "LOGIN_DOMAIN_SHA256", old)
        a2_private.LOGIN_DOMAIN_SHA256 = hashlib.sha256(domain.encode()).hexdigest()

    def test_fleet_host_refuses_the_login_domain_by_its_pin(self):
        self.assertEqual(a2_private.fleet_host("resv.internal"), "resv")
        self.reserve("resv.internal")
        self.assertIsNone(a2_private.fleet_host("resv.internal"))
        self.assertEqual(a2_private.fleet_host("resvx.internal"), "resvx")

    def test_fleet_host(self):
        self.assertEqual(a2_private.fleet_host("a-t.internal"), "a-t")
        self.assertEqual(a2_private.fleet_host("x" * 63 + ".internal"), "x" * 63)
        for bad in ("a.internal.", "a.internalx", "a_b.internal", "-a.internal", "a-.internal",
                    "x" * 64 + ".internal", ".internal", "a.Internal", None, 7):
            self.assertIsNone(a2_private.fleet_host(bad), bad)

    def test_the_skeleton_rule_is_per_vm_for_agent_ids(self):
        """RL's names are per router: an agent id may share a skeleton with ANOTHER VM's router slug, never with its
        own VM's; router slugs are distinct across the whole file."""
        d = a2fix.hosts_doc("/srv/locks")
        d["agents"][0].update(id="r0uter-b-t")
        a2_private.check_hosts(d)
        d["agents"][0].update(id="r0uter-a-t")
        with self.assertRaises(a2_private.Invalid) as cm:
            a2_private.check_hosts(d)
        self.assertEqual(cm.exception.path, "$.agents")

    def test_skeleton(self):
        self.assertEqual(a2_private.skeleton("R0uter_1.i-5"), "routerlls")
        self.assertEqual(a2_private.skeleton("router-a"), a2_private.skeleton("r0uter_a"))


class HubLoopTest(unittest.TestCase):
    """hub_loop and the loop's snapshot set (W5-HUBT, DS's half): one restore set, one hub per scope, and the hosts
    rules that tie them together."""

    def hosts(self):
        return a2fix.hosts_doc("/srv/locks")

    def invalid(self, doc, path=None):
        with self.assertRaises(a2_private.Invalid) as cm:
            a2_private.check_hosts(doc)
        if path is not None:
            self.assertEqual(cm.exception.path, path)

    def test_the_restore_set_and_the_hub_per_scope(self):
        h = self.hosts()
        self.assertEqual(a2_private.loop_restore_set(h), ("hub-t", "vm-a-t", "vm-b-t"))
        self.assertEqual(a2_private.hub_for_scope(h, "loop"), {"name": "hub-t", "domain": "hub-t.example.org"})
        self.assertEqual(a2_private.hub_for_scope(h, "l3"), {"name": "hub", "domain": "hub.example.org"})
        with self.assertRaises(ValueError):
            a2_private.hub_for_scope(h, "L2")
        a2_private.check_hosts(h)

    def test_the_pinned_set_must_name_exactly_the_restore_set(self):
        for change in (lambda d: d["loop_snapshots"].pop(), lambda d: d["loop_snapshots"].append(
                           {"vm": "vm-a", "snaptime": "1795000003"}),
                       lambda d: d["loop_snapshots"].__setitem__(0, {"vm": "vm-x", "snaptime": "1795000000"})):
            with self.subTest(change=change):
                d = self.hosts()
                change(d)
                self.invalid(d, "$.loop_snapshots")

    def test_shapes(self):
        cases = (("$.loop_snapshots", lambda d: d["loop_snapshots"].append(dict(d["loop_snapshots"][0]))),
                 ("$.loop_snapshots[0].snaptime", lambda d: d["loop_snapshots"][0].update(snaptime="0")),
                 ("$.loop_snapshots[0].snaptime", lambda d: d["loop_snapshots"][0].update(snaptime="1" * 13)),
                 ("$.loop_snapshots[0].snaptime", lambda d: d["loop_snapshots"][0].update(snaptime=1795000000)),
                 ("$.hub_loop", lambda d: d.pop("hub_loop")),
                 ("$.hub_loop.vm_id", lambda d: d["hub_loop"].update(vm_id="x")),
                 ("$.hub_loop.domain", lambda d: d["hub_loop"].update(domain=d["hub"]["domain"])))
        for path, change in cases:
            with self.subTest(path=path):
                d = self.hosts()
                change(d)
                self.invalid(d)

    def test_the_default_site_reads_no_snapshot_set(self):
        import a2_site
        h = self.hosts()
        self.assertEqual(a2_site.Site().probe_loop_snapshots(h, a2_private.loop_restore_set(h)), "UNOBSERVED")

    def test_hub_loop_takes_part_in_the_distinct_names(self):
        import a2_locks
        for change in (lambda d: d["hub_loop"].update(name="vm-a"), lambda d: d["hub_loop"].update(vm_id="300"),
                       lambda d: d["hub_loop"].update(name="hub")):
            with self.subTest(change=change):
                d = self.hosts()
                change(d)
                with self.assertRaises(Refusal) as cm:
                    a2_locks.check_names_distinct(d)
                self.assertEqual(cm.exception.cause, "RUNNER.HOSTS_TARGETS")

    def test_a_loop_run_locks_hub_loop_and_an_l3_run_does_not(self):
        import a2_locks
        h = self.hosts()
        loop = a2_locks.targets(h, [v for v in h["vms"] if v["scope"] == "loop"])
        l3 = a2_locks.targets(h, [v for v in h["vms"] if v["scope"] == "l3"])
        self.assertIn("hub-t", loop)
        self.assertIn("vm:320", loop)
        self.assertNotIn("hub-t", l3)
        self.assertNotIn("vm:320", l3)
        # A destroy-shaped list holds VMs of both scopes: one loop VM among them is enough to lock hub-t.
        mixed = a2_locks.targets(h, h["vms"])
        self.assertIn("hub-t", mixed)
        self.assertIn("vm:320", mixed)


class HostIdentityTest(unittest.TestCase):
    """a2_site.host_identity: "a2-" + the first 16 hex of sha256 over the
    machine id's 32 hex characters, from a file that reads as exactly those
    and at most one newline; anything else is None (RUNNER.LOCK_ROOT)."""

    MID = b"0123456789abcdef0123456789abcdef"

    def setUp(self):
        import tempfile
        self.d = tempfile.mkdtemp(prefix="a2mid-")
        self.addCleanup(__import__("shutil").rmtree, self.d, True)

    def ident(self, raw):
        import a2_site
        p = os.path.join(self.d, "machine-id")
        with open(p, "wb") as f:
            f.write(raw)
        return a2_site.host_identity(p)

    def test_the_identity_is_a2_and_16_hex_of_the_32_characters(self):
        import hashlib
        want = "a2-" + hashlib.sha256(self.MID).hexdigest()[:16]
        self.assertEqual(self.ident(self.MID + b"\n"), want)
        self.assertEqual(self.ident(self.MID), want)
        self.assertNotEqual(want, "a2-" + hashlib.sha256(self.MID + b"\n").hexdigest()[:16])

    def test_the_identity_fits_the_host_id_pattern(self):
        import a2_private
        self.assertTrue(a2_private.matches("host_id", self.ident(self.MID + b"\n")))

    def test_any_other_content_is_none(self):
        for raw in (b"", b"\n", self.MID[:31], self.MID + b"0", self.MID.upper(), self.MID + b"\n\n",
                    self.MID + b"\r\n", self.MID + b" ", b" " + self.MID, self.MID[:30] + b"g0",
                    self.MID + b"\x00", b"\xef\xbb\xbf" + self.MID, self.MID * 4 + b"\n", b"0" * 200):
            with self.subTest(raw=raw):
                self.assertIsNone(self.ident(raw))

    def test_an_unreadable_or_missing_file_is_none(self):
        import a2_site
        self.assertIsNone(a2_site.host_identity(os.path.join(self.d, "absent")))
        self.assertIsNone(a2_site.host_identity(self.d))


class GitTrustTest(unittest.TestCase):
    """a2_git names no safe.directory: git refuses a checkout another
    account owns, and S0 runs no git in the private overlay checkout at all.
    Reachability: has_commit needs a fetched branch or tag to reach the
    commit."""

    def setUp(self):
        import tempfile
        self.d = tempfile.mkdtemp(prefix="a2sd-")
        self.addCleanup(__import__("shutil").rmtree, self.d, True)

    def env(self):
        import a2_git
        return dict(a2_git.env_for(self.d), GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.org",
                    GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.org")

    def test_real_git_refuses_another_owners_checkout(self):
        """Why S0 runs no git in the private checkout: git refuses a
        repository another account owns (measured with git's own test switch,
        GIT_TEST_ASSUME_DIFFERENT_OWNER, git 2.35.2 and later), and a2_git
        names no safe.directory to get past that."""
        import subprocess
        import a2_git
        repo = os.path.join(self.d, "repo")
        os.mkdir(repo)
        subprocess.run(["/usr/bin/git", "-C", repo, "init", "-q"], env=self.env(), check=True)
        subprocess.run(["/usr/bin/git", "-C", repo, "commit", "-q", "--allow-empty", "-m", "x"], env=self.env(),
                       check=True)
        self.assertRegex(a2_git.Git(a2_git.env_for(self.d)).head(repo), "^[0-9a-f]{40}$")
        other = dict(a2_git.env_for(self.d), GIT_TEST_ASSUME_DIFFERENT_OWNER="1")
        with self.assertRaises(a2_git.GitError):
            a2_git.Git(other).head(repo)
        self.assertFalse(hasattr(a2_git, "for_site"))
        import inspect
        self.assertNotIn("safe_dirs", inspect.signature(a2_git.Git).parameters)

    def test_has_commit_needs_a_fetched_ref_to_reach_it(self):
        """A commit object in the bare repository that no refs/a2h or
        refs/a2t ref reaches is not had: an object a server put in the pack
        beside the refs' closure does not count."""
        import subprocess
        import a2_git
        bare = os.path.join(self.d, "b.git")
        subprocess.run(["/usr/bin/git", "init", "-q", "--bare", bare], env=self.env(), check=True)
        run = lambda *a: subprocess.run(["/usr/bin/git", "-C", bare] + list(a), env=self.env(), check=True,
                                        capture_output=True, text=True, input="").stdout.strip()
        tree = run("mktree")
        reached = run("commit-tree", tree, "-m", "reached")
        loose = run("commit-tree", tree, "-m", "loose")
        run("update-ref", "refs/a2h/main", reached)
        run("update-ref", "refs/other/x", loose)
        g = a2_git.Git(a2_git.env_for(self.d))
        self.assertTrue(g.has_commit(bare, reached))
        self.assertFalse(g.has_commit(bare, loose))
        self.assertFalse(g.has_commit(bare, "1" * 40))

class ReadPrivatePairTest(unittest.TestCase):
    """a2_admit.read_private_pair: the shared reader of the two private
    files, the same bytes S0 reads, nothing parsed."""

    def setUp(self):
        import tempfile
        self.d = tempfile.mkdtemp(prefix="a2rpp-")
        self.addCleanup(__import__("shutil").rmtree, self.d, True)
        for name, data in (("alpha2.lock", b"lock-bytes\n"), ("alpha2.hosts", b"hosts-bytes\n")):
            with open(os.path.join(self.d, name), "wb") as f:
                f.write(data)

    def refuses(self, private_dir):
        import a2_admit
        with self.assertRaises(Refusal) as cm:
            a2_admit.read_private_pair(private_dir)
        self.assertEqual(cm.exception.cause, "PREFLIGHT.PRIVATE_SOURCE")

    def test_returns_the_raw_bytes_unparsed(self):
        import a2_admit
        self.assertEqual(a2_admit.read_private_pair(self.d), (b"lock-bytes\n", b"hosts-bytes\n"))

    def test_unset_refuses(self):
        self.refuses(None)
        self.refuses("")

    def test_a_symlinked_file_refuses(self):
        target = os.path.join(self.d, "elsewhere")
        os.rename(os.path.join(self.d, "alpha2.hosts"), target)
        os.symlink(target, os.path.join(self.d, "alpha2.hosts"))
        self.refuses(self.d)

    def test_a_directory_in_place_of_the_file_refuses(self):
        os.remove(os.path.join(self.d, "alpha2.lock"))
        os.mkdir(os.path.join(self.d, "alpha2.lock"))
        self.refuses(self.d)

    def test_a_missing_file_refuses(self):
        os.remove(os.path.join(self.d, "alpha2.hosts"))
        self.refuses(self.d)

    def test_more_than_the_bound_refuses_and_the_bound_passes(self):
        import a2_admit
        with open(os.path.join(self.d, "alpha2.lock"), "wb") as f:
            f.write(b"x" * a2_admit.READ_MAX)
        self.assertEqual(len(a2_admit.read_private_pair(self.d)[0]), a2_admit.READ_MAX)
        with open(os.path.join(self.d, "alpha2.lock"), "ab") as f:
            f.write(b"x")
        self.refuses(self.d)


class PrivateFilesTest(unittest.TestCase):
    def fails(self, which, check, lock=None, hosts=None):
        with self.assertRaises(a2_private.PairInvalid) as cm:
            a2_private.load_pair(*_pair(lock, hosts))
        self.assertEqual(cm.exception.which, which)
        self.assertEqual(cm.exception.inv.check, check)
        return cm.exception

    def test_valid_pair_passes(self):
        lock, hosts = a2_private.load_pair(*_pair())
        self.assertEqual(lock["schema"], "alpha2.lock/1")
        self.assertEqual(hosts["schema"], "alpha2.hosts/1")

    def test_L1_bom(self):
        self.fails("lock", "L1", lock=b"\xef\xbb\xbf" + a2fix.lock_bytes())

    def test_L1_not_utf8(self):
        self.fails("hosts", "L1", hosts=b'{"schema": "\xff"}')

    def test_L1_duplicate_key(self):
        raw = a2fix.lock_bytes().replace(b'"schema": "alpha2.lock/1"',
                                         b'"schema": "alpha2.lock/1", "schema": "alpha2.lock/1"')
        self.fails("lock", "L1", lock=raw)

    def test_L1_nan(self):
        raw = a2fix.lock_bytes().replace(b'"d7_source": {', b'"x": NaN, "d7_source": {')
        self.fails("lock", "L1", lock=raw)

    def test_L1_schema_token(self):
        d = copy.deepcopy(a2fix.LOCK)
        d["schema"] = "alpha2.lock/2"
        self.fails("lock", "L1", lock=a2fix.dumps(d))

    def test_L2_unknown_key_names_parent_and_ordinal_never_the_key(self):
        h = a2fix.hosts_doc("/srv/locks")
        h["runner"]["secretish_key_text"] = "x"
        e = self.fails("hosts", "L2", hosts=a2fix.dumps(h))
        self.assertEqual(e.inv.path, "$.runner#4")
        self.assertNotIn("secretish", e.detail)

    def test_L2_extra_pins_absent_until_E23(self):
        d = copy.deepcopy(a2fix.LOCK)
        d["extra_pins"] = []
        self.fails("lock", "L2", lock=a2fix.dumps(d))

    def test_L3_pattern(self):
        h = a2fix.hosts_doc("/srv/locks")
        h["vms"][0]["vm_id"] = "12a"
        e = self.fails("hosts", "L3", hosts=a2fix.dumps(h))
        self.assertEqual(e.inv.path, "$.vms[0].vm_id")

    def test_L3_missing_required(self):
        d = copy.deepcopy(a2fix.LOCK)
        del d["plugin"]
        self.fails("lock", "L3", lock=a2fix.dumps(d))

    def test_L3_relpath_dotdot(self):
        d = copy.deepcopy(a2fix.LOCK)
        d["files"][0]["path"] = "alpha/../x"
        self.fails("lock", "L3", lock=a2fix.dumps(d))

    def test_L3_writers_exactly_two_unique(self):
        d = copy.deepcopy(a2fix.LOCK)
        d["writers"][1]["use"] = "api_key"
        self.fails("lock", "L3", lock=a2fix.dumps(d))

    def test_L3_accounts_differ(self):
        h = a2fix.hosts_doc("/srv/locks", loop_account="same", l3_account="same")
        self.fails("hosts", "L3", hosts=a2fix.dumps(h))

    def test_L3_both_scopes_present(self):
        h = a2fix.hosts_doc("/srv/locks")
        h["vms"] = [v for v in h["vms"] if v["scope"] == "loop"]
        self.fails("hosts", "L3", hosts=a2fix.dumps(h))

    def test_L3_agent_names_a_vm(self):
        h = a2fix.hosts_doc("/srv/locks")
        h["agents"][0]["vm"] = "nope"
        self.fails("hosts", "L3", hosts=a2fix.dumps(h))

    def test_L3_agent_connector_is_a_component(self):
        h = a2fix.hosts_doc("/srv/locks")
        h["agents"][0]["connector"] = "nope"
        self.fails("hosts", "L3", hosts=a2fix.dumps(h))

    def test_L3_unique_vm_id(self):
        h = a2fix.hosts_doc("/srv/locks")
        h["vms"][1]["vm_id"] = h["vms"][0]["vm_id"]
        self.fails("hosts", "L3", hosts=a2fix.dumps(h))

    def test_L3_image_archive_sha256_is_a_sha256(self):
        for bad in ("D" * 64, "d" * 63, 7):
            d = copy.deepcopy(a2fix.LOCK)
            d["images"][0]["archive_sha256"] = bad
            self.fails("lock", "L3", lock=a2fix.dumps(d))

    def test_L3_image_archive_sha256_is_required(self):
        d = copy.deepcopy(a2fix.LOCK)
        del d["images"][0]["archive_sha256"]
        self.fails("lock", "L3", lock=a2fix.dumps(d))

    def test_L3_image_built_from_component(self):
        d = copy.deepcopy(a2fix.LOCK)
        d["images"][0]["built_from"] = "nope"
        self.fails("lock", "L3", lock=a2fix.dumps(d))

    # L4 runs after L1 to L3; no field pattern of section 6 admits a deny
    # shape, so on a schema-valid file only check_deny itself can fire.
    # These tests call it directly, on each of its two passes.

    def deny(self, raw, doc):
        with self.assertRaises(a2_private.Invalid) as cm:
            a2_private.check_deny(raw, doc)
        self.assertEqual(cm.exception.check, "L4")
        return cm.exception

    def test_L4_parsed_pass_catches_escaped_token(self):
        raw = b'{"a": "\\u0067hp_x"}'
        doc = {"a": "ghp_x"}
        self.assertNotIn(b"ghp_", raw)
        e = self.deny(raw, doc)
        self.assertEqual(e.path, "$.a")

    def test_L4_raw_pass_catches_bytes(self):
        self.deny(b"x -----BEGIN OPENSSH PRIVATE KEY----- y", {})
        self.deny(b"see https://u:p@x.example.org/", {})
        for tok in (b"ghp_", b"github_pat_", b"glpat-"):
            self.deny(b"..." + tok + b"...", {})

    def test_L4_passes_a_clean_pair(self):
        lock, hosts = _pair()
        a2_private.check_deny(lock, a2_private.parse(lock, "alpha2.lock/1"))

    def test_L3_refuses_url_userinfo_before_L4(self):
        d = copy.deepcopy(a2fix.LOCK)
        d["components"][0]["repo"] = "https://u:p@git.example.org/x"
        self.fails("lock", "L3", lock=a2fix.dumps(d))

    def test_L3_tags_and_overlay(self):
        """e3 6.1: overlay is required; every components[].tag is an rc_tag
        and equals overlay.tag."""
        for mut in (lambda d: d.__delitem__("overlay"),
                    lambda d: d["components"][0].__delitem__("tag"),
                    lambda d: d["components"][0].__setitem__("tag", "alpha2-rc2"),
                    lambda d: d["overlay"].__setitem__("tag", "alpha2-rc0"),
                    lambda d: d["overlay"].__setitem__("tag", "v1.0"),
                    lambda d: d["overlay"].__setitem__("commit", "abc")):
            d = copy.deepcopy(a2fix.LOCK)
            mut(d)
            self.fails("lock", "L3", lock=a2fix.dumps(d))
        d = copy.deepcopy(a2fix.LOCK)
        for c in d["components"]:
            c["tag"] = "alpha2-rc12"
        d["overlay"]["tag"] = "alpha2-rc12"
        a2_private.load_pair(a2fix.dumps(d), a2fix.dumps(a2fix.hosts_doc("/srv/locks")))

    def test_L3_the_installer_component_is_the_installer_commit(self):
        """The installer's own component in components[] has installer.commit (S4 reads its root files from the
        installer checkout, by files[] rows of this component). Absent, it is not required."""
        d = copy.deepcopy(a2fix.LOCK)
        d["components"].append({"name": a2_private.INSTALLER_COMPONENT, "repo": d["installer"]["repo"],
                                "commit": "d" * 40, "tag": "alpha2-rc1"})
        self.fails("lock", "L3", lock=a2fix.dumps(d))
        d["components"][-1]["commit"] = d["installer"]["commit"]
        a2_private.load_pair(a2fix.dumps(d), a2fix.dumps(a2fix.hosts_doc("/srv/locks")))

    def test_L3_destroy_deny(self):
        """6.2: optional; names of vms[] entries, unique; [] allowed."""
        for bad in (["vm-a", "vm-a"], ["nope"], ["Bad_Name"], "vm-a"):
            with self.subTest(bad=bad):
                h = a2fix.hosts_doc("/srv/locks")
                h["destroy_deny"] = bad
                self.fails("hosts", "L3", hosts=a2fix.dumps(h))
        for ok in ([], ["vm-a"], None):
            h = a2fix.hosts_doc("/srv/locks")
            if ok is None:
                del h["destroy_deny"]
            else:
                h["destroy_deny"] = ok
            a2_private.load_pair(a2fix.lock_bytes(), a2fix.dumps(h))

    def test_cause_is_leak_lock_or_hosts(self):
        e = self.fails("hosts", "L1", hosts=b"[]")
        self.assertEqual(e.cause, "PREFLIGHT.LEAK_HOSTS")


class ArgsTest(unittest.TestCase):
    def ok(self, argv, command, loop, opts=None):
        self.assertEqual(a2_args.parse(argv), a2_args.Invocation(command, loop, opts or {}))

    def bad(self, argv):
        with self.assertRaises(Refusal) as cm:
            a2_args.parse(argv)
        self.assertEqual(cm.exception.cause, "RUNNER.ARGS")
        self.assertIsNone(cm.exception.detail)

    def test_table(self):
        self.ok([], "install", None)
        self.ok(["--dry-run"], "dry-run", None)
        self.ok(["--verify"], "verify", None)
        self.ok(["--verify", "--canary"], "canary", None)
        self.ok(["--add-agent", "vm-a"], "add-agent", None, {"host": "vm-a"})
        self.ok(["--add-agent", "vm-a", "--id", "agent-b"], "add-agent", None,
                {"host": "vm-a", "id": "agent-b"})
        self.ok(["--check-roundtrip", "abcd1234"], "check-roundtrip", None, {"nonce": "abcd1234"})
        self.ok(["--only", "S5"], "install", "L1", {"only": "S5"})
        self.ok(["--from", "S3"], "install", "L1", {"from": "S3"})
        self.ok(["--leak-run"], "install", "L2-leak")
        self.ok(["--loop", "L2"], "install", "L2")
        self.ok(["--loop", "L3"], "install", "L3")
        self.ok(["--destroy"], "destroy", None)

    def test_refusals(self):
        self.bad(["--loop", "L2", "--only", "S1"])
        self.bad(["--loop", "L2", "--leak-run"])
        self.bad(["--loop", "L2", "--loop", "L2"])
        self.bad(["--loop", "L1"])
        self.bad(["--only", "S11"])
        self.bad(["--add-agent", "Bad_Name"])
        self.bad(["--check-roundtrip", "short"])
        self.bad(["--canary"])
        self.bad(["--id", "x"])
        self.bad(["--verify", "--dry-run"])
        self.bad(["--destroy", "--loop", "L3"])
        self.bad(["--bogus"])
        self.bad(["--only"])
        self.bad(["--runner"])

    def test_rotate_key_is_refused_at_the_parse(self):  # Dan ALPHA2-W8-ROTATE-FALLBACK
        with self.assertRaises(Refusal) as cm:
            a2_args.parse(["--rotate-key"])
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("RUNNER.ROTATE_UNSUPPORTED", 2))
        # The existing validation still comes first: a malformed line is RUNNER.ARGS.
        for argv in (["--rotate-key", "--rotate-key"], ["--rotate-key", "--dry-run"],
                     ["--rotate-key", "--loop", "L2"], ["--rotate-key", "--bogus"],
                     ["--rotate-key", "--canary"], ["--rotate-key", "--id", "agent-b"],
                     ["--rotate-key", "--only", "S1"]):
            with self.subTest(argv=argv):
                self.bad(argv)

    def test_writes_target(self):
        for cmd in ("dry-run", "verify", "check-roundtrip"):
            self.assertFalse(a2_args.Invocation(cmd, None, {}).writes_target)
        for cmd in ("install", "canary", "add-agent", "rotate-key", "destroy"):
            self.assertTrue(a2_args.Invocation(cmd, None, {}).writes_target)


class EnvAccountTest(unittest.TestCase):
    RUNNER = {"loop_account": "loopr", "l3_account": "l3r"}

    def env(self, **kw):
        e = {"HOME": "/h", "PATH": "/usr/bin:/bin", "SSH_AUTH_SOCK": "", "TERM": "xterm"}
        e.update(kw)
        return e

    def refuses(self, cause, fn, *a):
        with self.assertRaises(Refusal) as cm:
            fn(*a)
        self.assertEqual(cm.exception.cause, cause)

    def test_env(self):
        a2_host.check_env(self.env(), "l3", "/h")
        a2_host.check_env(self.env(SSH_AUTH_SOCK="/s"), "loop", "/h")
        self.refuses("RUNNER.ENV", a2_host.check_env, self.env(EXTRA="1"), "loop", "/h")
        self.refuses("RUNNER.ENV", a2_host.check_env, self.env(PATH="/bin"), "loop", "/h")
        self.refuses("RUNNER.ENV", a2_host.check_env, self.env(HOME="/other"), "loop", "/h")
        self.refuses("RUNNER.ENV", a2_host.check_env, self.env(SSH_AUTH_SOCK="/s"), "l3", "/h")
        e = self.env()
        del e["TERM"]
        self.refuses("RUNNER.ENV", a2_host.check_env, e, "loop", "/h")
        self.refuses("RUNNER.ENV", a2_host.check_env_names, self.env(X="1"))

    def test_a_home_a_shell_would_split_refuses(self):
        """HOME reaches git's GIT_SSH_COMMAND, which a shell runs: it must be a plain absolute path, even when it
        is the account database's own home."""
        import a2_git
        self.assertEqual(a2_host.SAFE_HOME.pattern, a2_git.SAFE_HOME.pattern)
        for home in ("/h x", "/h;id", "/h/$X", "/h/../h", "/h/.", "relative", "/h'q", "/"):
            with self.subTest(home=home):
                self.refuses("RUNNER.ENV", a2_host.check_env, self.env(HOME=home), "loop", home)
                with self.assertRaises(ValueError):
                    a2_git.env_for(home)

    def test_git_reads_only_the_overlay_ssh_configuration(self):
        import a2_git
        e = a2_git.env_for("/var/lib/acct")
        self.assertEqual(e["GIT_SSH_COMMAND"], "ssh -F /var/lib/acct/.ssh/config_overlay")
        self.assertEqual(set(e), {"PATH", "HOME", "SSH_AUTH_SOCK", "GIT_SSH_COMMAND", "GIT_CONFIG_NOSYSTEM",
                                  "GIT_CONFIG_GLOBAL", "GIT_TERMINAL_PROMPT", "LC_ALL", "GIT_NO_REPLACE_OBJECTS",
                                  "GIT_OPTIONAL_LOCKS"})

    def test_received_environ(self):
        import shutil
        import tempfile
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "environ")
        def env_of(raw):
            with open(p, "wb") as f:
                f.write(raw)
            return a2_host.received_environ(p)
        self.assertEqual(env_of(b"HOME=/h\0PATH=/usr/bin:/bin\0SSH_AUTH_SOCK=\0TERM=x\0"),
                         {"HOME": "/h", "PATH": "/usr/bin:/bin", "SSH_AUTH_SOCK": "", "TERM": "x"})
        self.assertEqual(env_of(b""), {})
        for bad in (b"HOME=/h", b"HOME\0", b"=x\0", b"A=1\0A=2\0", b"A=\xff\0"):
            with self.subTest(bad=bad):
                self.refuses("RUNNER.ENV", env_of, bad)
        self.refuses("RUNNER.ENV", a2_host.received_environ, os.path.join(d, "absent"))

    def test_received_environ_is_what_the_launch_line_passed(self):
        """MEASURED with the system interpreter: os.environ gains LC_CTYPE
        under env -i (PEP 538); /proc/self/environ holds the four names."""
        import subprocess, sys
        code = ("import os,sys; sys.path.insert(0, sys.argv[1]); import a2_host; "
                "print(sorted(a2_host.received_environ())); print('LC_CTYPE' in os.environ)")
        r = subprocess.run([sys.executable, "-I", "-B", "-c", code, a2fix.INSTALL],
                           env={"HOME": "/h", "PATH": "/usr/bin:/bin", "SSH_AUTH_SOCK": "", "TERM": "x"},
                           capture_output=True, text=True, timeout=30)
        lines = r.stdout.splitlines()
        self.assertEqual(lines[0], "['HOME', 'PATH', 'SSH_AUTH_SOCK', 'TERM']")
        self.assertEqual(lines[1], "True")

    def pw(self, name):
        import pwd
        return lambda uid: pwd.struct_passwd((name, "x", uid, uid, "", "/h/" + name, "/bin/sh"))

    def test_kernel_account(self):
        self.assertEqual(a2_host.kernel_account(self.RUNNER, lambda: 5, lambda: 5, self.pw("l3r"))[0], "l3")
        self.assertEqual(a2_host.kernel_account(self.RUNNER, lambda: 5, lambda: 5, self.pw("loopr"))[0], "loop")
        self.refuses("RUNNER.ACCOUNT", a2_host.kernel_account, self.RUNNER, lambda: 5, lambda: 6, self.pw("l3r"))
        self.refuses("RUNNER.ACCOUNT", a2_host.kernel_account, self.RUNNER, lambda: 5, lambda: 5, self.pw("other"))

    def test_command_needs_account(self):
        I = a2_args.Invocation
        a2_host.check_account(I("install", "L3", {}), "l3")
        a2_host.check_account(I("install", None, {}), "l3")
        a2_host.check_account(I("install", "L2", {}), "loop")
        a2_host.check_account(I("install", "L1", {}), "loop")
        a2_host.check_account(I("install", "L2-leak", {}), "loop")
        a2_host.check_account(I("destroy", None, {}), "l3")
        a2_host.check_account(I("verify", None, {}), "loop")
        a2_host.check_account(I("verify", None, {}), "l3")
        self.refuses("RUNNER.ACCOUNT", a2_host.check_account, I("install", "L3", {}), "loop")
        self.refuses("RUNNER.ACCOUNT", a2_host.check_account, I("install", None, {}), "loop")
        self.refuses("RUNNER.ACCOUNT", a2_host.check_account, I("install", "L2", {}), "l3")
        self.refuses("RUNNER.ACCOUNT", a2_host.check_account, I("destroy", None, {}), "loop")


class WritersRequiredTest(unittest.TestCase):
    """a2_private.writers_required over every command and stage set."""

    def req(self, argv):
        import a2_private
        return a2_private.writers_required(a2_args.parse(argv), a2_args.STAGE_IDS)

    def req_l1(self, opts):
        """The function itself, over every stage set, including those RUNNER.STAGE_SET now refuses at parsing."""
        import a2_private
        return a2_private.writers_required(a2_args.Invocation("install", "L1", opts), a2_args.STAGE_IDS)

    def test_l1_only(self):
        both = {"api_key", "hub_login"}
        for st in a2_args.STAGE_IDS:
            want = {"S6b": {"hub_login"}, "S7": {"api_key"}}.get(st, set())
            with self.subTest(only=st):
                self.assertEqual(self.req_l1({"only": st}), want)
        for st in a2_args.STAGE_IDS:
            i = a2_args.STAGE_IDS.index(st)
            want = ({"hub_login"} if i <= a2_args.STAGE_IDS.index("S6b") else set()) | \
                   ({"api_key"} if i <= a2_args.STAGE_IDS.index("S7") else set())
            with self.subTest(frm=st):
                self.assertEqual(self.req_l1({"from": st}), want)
        self.assertEqual(self.req(["--from", "S0"]), both)
        self.assertEqual(self.req(["--only", "S5"]), set())

    def test_every_other_command_needs_both(self):
        for argv in (["--loop", "L2"], ["--loop", "L3"], ["--leak-run"], [], ["--dry-run"], ["--verify"],
                     ["--destroy"]):
            with self.subTest(argv=argv):
                self.assertEqual(self.req(argv), {"api_key", "hub_login"})
        # --rotate-key never reaches writers_required in ALPHA-2: the parse refuses it.
        with self.assertRaises(a2_causes.Refusal) as cm:
            self.req(["--rotate-key"])
        self.assertEqual(cm.exception.cause, "RUNNER.ROTATE_UNSUPPORTED")


if __name__ == "__main__":
    unittest.main()
