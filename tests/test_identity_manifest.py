"""The policy's `identity` opt-in, rendered into the manifest.

Off (the key absent) the manifest is what it was. On, it gains one mount,
LAST, of `by-slug/${slug}` read-only with its export, and one `expose`
carrying the name.json schema id from the deployment overlay. Turning it on
needs a sandy whose schema_version is reviewed for a missing mount source
and an overlay; either missing refuses, by name.
"""

import argparse
import json
import os
import tempfile
import unittest
from pathlib import Path

import amap_sandy as prov
import fleet_policy as fp
import host_adapter as ha
import _wrapper as w
from _registry import IDS, write_overlay

ON = {prov.IDENTITY_KEY: prov.IDENTITY_REGISTRY}
FIXTURE = Path(__file__).parent / "fixtures" / "registry_cli.json"
SHOW = next(json.loads(c["stdout"])["binding"] for c in json.loads(FIXTURE.read_text())["cases"]
            if c["case"] == "show")
DOMAIN = SHOW["address"].partition("@")[2]
SLUG = "alpha-1a2b3c4d"
ALPHA, BRAVO = "/srv/example/ws/alpha", "/srv/example/ws/bravo"
NAME_JSON = json.dumps({"schema": IDS.name_schema, "name": SHOW["name"], "address": SHOW["address"],
                        "logical_id": SHOW["logical_id"], "epoch": SHOW["epoch"]},
                       sort_keys=True, indent=2) + "\n"


class RenderTest(unittest.TestCase):

    def setUp(self):
        self.policy = fp.default_policy()

    def test_off_renders_exactly_what_it_did(self):
        self.assertNotIn(prov.IDENTITY_KEY, self.policy)
        doc = prov.render_manifest(self.policy, identity_schema=IDS.name_schema)
        self.assertNotIn(prov.IDENTITY_MOUNT_NAME, [m["name"] for m in doc["mounts"]])
        self.assertNotIn(prov.EXPOSE_IDENTITY, doc["expose"])

    def test_on_appends_the_identity_mount_last_and_exposes_the_schema(self):
        off = prov.render_manifest(self.policy)
        on = prov.render_manifest(dict(self.policy, **ON), identity_schema=IDS.name_schema)
        self.assertEqual(on["mounts"][:-1], off["mounts"])
        self.assertEqual(on["mounts"][-1], {
            "name": prov.IDENTITY_MOUNT_NAME, "mode": "ro",
            "from": f"{prov.FEATURE_IDENTITY_SUBDIR}/{prov.MANIFEST_SLUG}",
            "export": prov.EXPORT_IDENTITY_DIR})
        self.assertEqual(on["expose"][prov.EXPOSE_IDENTITY], IDS.name_schema)

    def test_sandy_never_creates_the_link_path(self):
        """A `create` entry would make sandy mkdir a real directory where the
        link belongs."""
        on = prov.render_manifest(dict(self.policy, **ON), identity_schema=IDS.name_schema)
        self.assertFalse([c for c in on["create"] if c.startswith(prov.FEATURE_IDENTITY_SUBDIR)])

    def test_on_without_a_schema_and_an_unknown_value_refuse(self):
        with self.assertRaises(prov.ProvisionError) as cm:
            prov.render_manifest(dict(self.policy, **ON))
        self.assertIn("no name.json schema id", str(cm.exception))
        for bad in ("slug", False, "", 0, "Registry"):
            with self.subTest(value=bad):
                with self.assertRaises(prov.ProvisionError) as cm:
                    prov.render_manifest(dict(self.policy, **{prov.IDENTITY_KEY: bad}),
                                         identity_schema=IDS.name_schema)
                self.assertIn(repr(prov.IDENTITY_REGISTRY), str(cm.exception))

    def test_the_relay_reads_the_names_the_manifest_exports(self):
        relay = w.WRAPPER.read_text()
        for name in (prov.EXPORT_IDENTITY_DIR, prov.EXPOSE_IDENTITY):
            self.assertIn("${" + name, relay)


class SchemaForTest(unittest.TestCase):
    """`identity_schema_for`: sandy's schema token, then the overlay."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.asked = []
        self.schema = {"schema_version": 4}
        orig = prov._sandy_json
        prov._sandy_json = lambda b, flag: self.asked.append(flag) or self.schema
        self.addCleanup(setattr, prov, "_sandy_json", orig)

    def args(self, overlay=True):
        return argparse.Namespace(sandy="sandy",
                                  overlay=write_overlay(self.dir / "o.json") if overlay else
                                  self.dir / "absent.json")

    def test_off_asks_nothing(self):
        self.assertIsNone(prov.identity_schema_for(fp.default_policy(), self.args(False)))
        self.assertEqual(self.asked, [])

    def test_on_returns_the_overlays_schema(self):
        self.assertEqual(prov.identity_schema_for(ON, self.args()), IDS.name_schema)

    def test_each_gap_refuses(self):
        rows = (("unreviewed token", {"schema_version": 3}, True, "not one reviewed"),
                ("token of another type", {"schema_version": "4"}, True, "not one reviewed"),
                ("a float equal to the token", {"schema_version": 4.0}, True, "not one reviewed"),
                ("a later token", {"schema_version": 5}, True, "not one reviewed"),
                ("a bool", {"schema_version": True}, True, "not one reviewed"),
                ("unreadable schema", None, True, "cannot read"),
                ("no overlay", {"schema_version": 4}, False, "unreadable"))
        for name, schema, overlay, says in rows:
            with self.subTest(name):
                self.schema = schema
                with self.assertRaises(prov.ProvisionError) as cm:
                    prov.identity_schema_for(ON, self.args(overlay))
                self.assertIn(says, str(cm.exception))


class VerifyTest(unittest.TestCase):
    """verify's manifest problems with the identity mount on."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.policy = dict(fp.default_policy(), **ON)
        self.schema = {"schema_version": 4, "manifest": {"top_level_keys": [], "receives_values": []}}
        orig = prov._sandy_json
        prov._sandy_json = lambda b, flag: self.schema
        self.addCleanup(setattr, prov, "_sandy_json", orig)
        self.args = argparse.Namespace(sandy="sandy", overlay=write_overlay(self.home / "o.json"))

    def test_a_manifest_installed_with_the_mount_is_current(self):
        prov.install_manifest(self.home, self.policy, dry_run=False, receives=False,
                              identity_schema=IDS.name_schema)
        self.assertEqual(prov.manifest_problems(self.home, self.policy, self.args), [])

    def test_one_installed_without_it_is_drift(self):
        prov.install_manifest(self.home, fp.default_policy(), dry_run=False, receives=False)
        found = prov.manifest_problems(self.home, self.policy, self.args)
        self.assertTrue(found and found[0].startswith("manifest drift"), found)
        self.assertIn("mounts", found[0])

    def test_an_identity_that_cannot_be_rendered_is_the_problem_reported(self):
        self.args.overlay = self.home / "absent.json"
        found, = prov.manifest_problems(self.home, self.policy, self.args)
        self.assertTrue(found.startswith("identity: "), found)


class VerifyEachSandboxTest(unittest.TestCase):
    """`identity_check`: off is nothing at all; on, one read-only `show` per
    running sandbox, and every gap UNKNOWN for that sandbox alone."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.repo = self.dir / "checkout"
        (self.repo / IDS.module).mkdir(parents=True)
        (self.repo / IDS.module / "cli.py").write_text("")
        self.policy = dict(fp.default_policy(), **ON)
        self.policy[fp.FLEET_DOMAIN_KEY] = DOMAIN
        self.requests = []
        self.answers = {}
        orig_call = ha.Client.call
        ha.Client.call = lambda c, req: self.requests.append(req) or self.answers[req["key"]]
        self.addCleanup(setattr, ha.Client, "call", orig_call)
        self.seen = []
        orig = prov.container_identity_findings

        def findings(slug, container, shown, *, fleet_domain, name_schema):
            self.seen.append((slug, container, fleet_domain, name_schema))
            return prov.identity_findings(slug, shown, {prov.EXPORT_IDENTITY_DIR: "/x"},
                                          NAME_JSON, "", fleet_domain, name_schema)
        prov.container_identity_findings = findings
        self.addCleanup(setattr, prov, "container_identity_findings", orig)
        old = os.environ.pop(ha.CHECKOUT_ENV, None)
        self.addCleanup(lambda: old and os.environ.__setitem__(ha.CHECKOUT_ENV, old))

    def args(self, **override):
        kw = dict(directory=str(self.dir / "registry"), checkout=str(self.repo))
        kw.update(override)
        kw = {k: v for k, v in kw.items() if v is not None}
        path = self.dir / f"o-{len(list(self.dir.glob('o-*.json')))}.json"
        return argparse.Namespace(overlay=write_overlay(path, **kw))

    def test_off_returns_nothing_and_reads_no_overlay(self):
        orig = ha.load_identifiers
        ha.load_identifiers = lambda p: self.fail("read the overlay with identity off")
        self.addCleanup(setattr, ha, "load_identifiers", orig)
        self.assertIsNone(prov.identity_check(fp.default_policy(),
                                              argparse.Namespace(overlay=None)))

    def test_the_verify_loop_calls_it_only_when_it_exists(self):
        import ast
        import inspect
        tree = ast.parse(inspect.getsource(prov.run_verify))
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Name) and n.func.id == "check_identity"]
        guards = [n for n in ast.walk(tree) if isinstance(n, ast.If)
                  and ast.unparse(n.test) == "check_identity is not None"]
        self.assertEqual(len(calls), 1)
        self.assertTrue(any(calls[0] in list(ast.walk(g)) for g in guards))

    def test_on_each_running_sandbox_is_shown_read_only_and_checked(self):
        self.answers[ALPHA] = ha.Answer(0, {"ok": True, "binding": SHOW})
        check = prov.identity_check(self.policy, self.args())
        self.assertEqual(check(SLUG, "ctr", Path(ALPHA)), [])
        self.assertEqual([r["op"] for r in self.requests], [ha.OP_SHOW])
        self.assertEqual(self.requests[0]["interface"], IDS.interface)
        self.assertEqual(self.seen, [(SLUG, "ctr", DOMAIN, IDS.name_schema)])

    def test_a_codex_sandbox_also_gets_the_codex_check_and_only_it(self):
        self.answers[ALPHA] = ha.Answer(0, {"ok": True, "binding": SHOW})
        state = self.dir / "codex-state"
        state.mkdir()
        (state / prov.CODEX_CONTROLLER_NAME).write_text(f'self_address = "{SLUG}@{DOMAIN}"\n')
        check = prov.identity_check(self.policy, self.args())
        self.assertEqual(check(SLUG, "ctr", Path(ALPHA), False, state), [])
        found = check(SLUG, "ctr", Path(ALPHA), True, state)
        self.assertEqual([f.split(":")[0] for f in found], ["identity not applied"])

    def test_a_show_without_an_answer_is_unknown_and_the_next_sandbox_still_runs(self):
        self.answers[ALPHA] = ha.Answer(None, None, "no_answer: 0 line(s)")
        self.answers[BRAVO] = ha.Answer(0, {"ok": True, "binding": SHOW})
        check = prov.identity_check(self.policy, self.args())
        first = check(SLUG, "c1", Path(ALPHA))
        self.assertEqual([f.split(":")[0] for f in first], ["identity unknown"])
        self.assertEqual(check("bravo-2b3c4d5e", "c2", Path(BRAVO)), [])

    def test_every_setup_gap_is_unknown_per_sandbox(self):
        rows = (("bad value", dict(fp.default_policy(), **{prov.IDENTITY_KEY: "slug"}), None,
                 "'registry'"),
                ("no overlay", self.policy, argparse.Namespace(overlay=self.dir / "none.json"),
                 "unreadable"),
                ("no directory", self.policy, self.args(directory=None), "registry.directory"),
                ("no checkout", self.policy, self.args(checkout=None), "no registry checkout"))
        for name, policy, args, says in rows:
            with self.subTest(name):
                check = prov.identity_check(policy, args or self.args())
                found, = check(SLUG, "ctr", Path(ALPHA))
                self.assertTrue(found.startswith(f"identity unknown: {SLUG}: "), found)
                self.assertIn(says, found)
        found, = prov.identity_check(self.policy, self.args())(SLUG, "ctr", None)
        self.assertIn("no workspace", found)
        self.assertEqual(self.requests, [])


class CodexAddressTest(unittest.TestCase):
    """A Codex sandbox's supervisor runs under the registry's address, read
    from the controller.toml payload/codex/relay writes."""

    def setUp(self):
        self.state = Path(tempfile.mkdtemp()) / "codex"
        self.state.mkdir()
        self.shown = ha.Result(ha.REGISTERED, binding=SHOW)

    def controller(self, address):
        lines = ['instance_id = "alpha-1a2b3c4d"']
        if address is not None:
            lines.insert(1, f"self_address = {json.dumps(address)}")
        (self.state / prov.CODEX_CONTROLLER_NAME).write_text("\n".join(lines) + "\n")

    def heads(self, found):
        return [f.split(":", 1)[0] for f in found]

    def test_the_registrys_address_is_no_finding(self):
        self.controller(SHOW["address"])
        self.assertEqual(prov.codex_identity_findings(SLUG, self.state, self.shown), [])

    def test_the_slug_address_is_not_applied(self):
        self.controller(f"{SLUG}@{DOMAIN}")
        found, = prov.codex_identity_findings(SLUG, self.state, self.shown)
        self.assertTrue(found.startswith("identity not applied"), found)
        self.assertIn(SHOW["address"], found)
        self.controller(None)
        self.assertEqual(self.heads(prov.codex_identity_findings(SLUG, self.state, self.shown)),
                         ["identity not applied"])

    def test_a_hold_and_an_unregistered_sandbox_are_reported_elsewhere(self):
        self.controller(f"{SLUG}@{DOMAIN}")
        (self.state / prov.CODEX_HOLD_NAME).write_text('{"reason": "x"}')
        self.assertEqual(prov.codex_identity_findings(SLUG, self.state, self.shown), [])
        (self.state / prov.CODEX_HOLD_NAME).unlink()
        nf = ha.Result(ha.REFUSED, ha.CODE_NOT_FOUND, "x")
        self.assertEqual(prov.codex_identity_findings(SLUG, self.state, nf), [])

    def test_no_state_or_no_controller_is_unknown(self):
        self.assertEqual(self.heads(prov.codex_identity_findings(SLUG, None, self.shown)),
                         ["identity unknown"])
        self.assertEqual(self.heads(prov.codex_identity_findings(SLUG, self.state, self.shown)),
                         ["identity unknown"])


if __name__ == "__main__":
    unittest.main()
