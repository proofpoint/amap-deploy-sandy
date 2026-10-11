"""install's identity step: zero-touch registration, then the link.

The registry is a small in-memory stand-in answering in the captured
fixture's shapes (`tests/fixtures/registry_cli.json`): `list` refuses with
`registry_absent` until the first binding, `show` refuses `not_found` for a
workspace never registered, and `register` binds, idempotently. The links
are made in a temporary directory.
"""

import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

import amap_sandy as prov
import host_adapter as ha
from _registry import IDS

FIXTURE = Path(__file__).parent / "fixtures" / "registry_cli.json"
SHOW = next(json.loads(c["stdout"])["binding"] for c in json.loads(FIXTURE.read_text())["cases"]
            if c["case"] == "show")
DOMAIN = SHOW["address"].partition("@")[2]


class Registry:
    """Answers `ha.Client.call` as the registry would, from a dict."""

    def __init__(self, exists=True):
        self.bindings = {}
        self.exists = exists
        self.calls = []
        self.fail = {}          # workspace -> Answer to give `register` instead

    def binding(self, ws):
        lid = hashlib.sha256(ws.encode()).hexdigest()[:32]
        name = Path(ws).name
        return dict(SHOW, address=f"{name}@{DOMAIN}", name=name, logical_id=lid,
                    identity_dir=f"/srv/example/identity/{lid}")

    def __call__(self, client, req):
        self.calls.append(req["op"])
        ws = req.get("key")
        if req["op"] == ha.OP_LIST:
            if not self.exists:
                return ha.Answer(1, {"ok": False, "error": {"code": ha.CODE_REGISTRY_ABSENT,
                                                            "detail": "no registry"}})
            return ha.Answer(0, {"ok": True, "bindings": list(self.bindings.values())})
        if req["op"] == ha.OP_SHOW:
            if ws not in self.bindings:
                return ha.Answer(1, {"ok": False, "error": {"code": ha.CODE_NOT_FOUND,
                                                            "detail": "no binding"}})
            return ha.Answer(0, {"ok": True, "binding": self.bindings[ws]})
        if req["op"] == ha.OP_REGISTER:
            if ws in self.fail:
                return self.fail[ws]
            created = ws not in self.bindings
            self.bindings.setdefault(ws, self.binding(ws))
            self.exists = True
            return ha.Answer(0, {"ok": True, "binding": dict(self.bindings[ws], created=created)})
        raise AssertionError(req)


class InstallIdentityTest(unittest.TestCase):

    def setUp(self):
        self.links = Path(tempfile.mkdtemp()) / prov.FEATURE_IDENTITY_SUBDIR
        self.reg = Registry()
        orig = ha.Client.call
        ha.Client.call = lambda c, req: self.reg(c, req)
        self.addCleanup(setattr, ha.Client, "call", orig)
        self.client = ha.Client(Path("/srv/example/reg"), Path("/srv/example/checkout"), IDS,
                                sleep=lambda s: None)
        self.reg.bindings["/srv/example/ws/old"] = self.reg.binding("/srv/example/ws/old")

    def run_it(self, members, apply=True):
        return prov.install_identity(self.client, self.links, members, apply=apply)

    def test_a_fresh_sandbox_is_registered_and_linked_with_no_import(self):
        lines, failed = self.run_it({"fresh-1a2b3c4d": Path("/srv/example/ws/fresh")})
        self.assertFalse(failed, lines)
        b = self.reg.bindings["/srv/example/ws/fresh"]
        self.assertEqual(os.readlink(self.links / "fresh-1a2b3c4d"), b["identity_dir"])
        self.assertTrue(any("registered as fresh@" in l for l in lines), lines)
        self.assertNotIn("import", " ".join(self.reg.calls))

    def test_a_second_install_changes_nothing(self):
        m = {"fresh-1a2b3c4d": Path("/srv/example/ws/fresh")}
        self.run_it(m)
        lines, failed = self.run_it(m)
        self.assertEqual((lines, failed), ([], False))

    def test_dry_run_only_reads(self):
        lines, failed = self.run_it({"fresh-1a2b3c4d": Path("/srv/example/ws/fresh")}, apply=False)
        self.assertNotIn(ha.OP_REGISTER, self.reg.calls)
        self.assertFalse(self.links.exists())
        self.assertTrue(any("would register /srv/example/ws/fresh" in l for l in lines), lines)
        self.assertFalse(failed)

    def test_before_the_registry_exists_nothing_is_registered(self):
        self.reg.exists = False
        lines, failed = self.run_it({"old-0a0b0c0d": Path("/srv/example/ws/old2")})
        self.assertTrue(failed)
        self.assertEqual(self.reg.calls, [ha.OP_LIST])
        self.assertIn("migrate-registry", lines[0])
        self.assertFalse(self.links.exists())

    def test_a_list_that_exits_non_zero_never_opens_the_gate(self):
        orig = self.reg.__call__
        self.reg.exists = False

        def answer(client, req):
            if req["op"] == ha.OP_LIST:
                self.reg.calls.append(req["op"])
                return ha.Answer(3, {"ok": True, "bindings": []})
            return orig(client, req)
        ha.Client.call = answer
        lines, failed = self.run_it({"fresh-1a2b3c4d": Path("/srv/example/ws/fresh")})
        self.assertTrue(failed)
        self.assertEqual(self.reg.calls, [ha.OP_LIST])
        self.assertIn("did not answer", lines[0])

    def test_each_sandbox_fails_closed_alone(self):
        self.reg.fail["/srv/example/ws/bad"] = ha.Answer(
            3, {"ok": False, "committed": "unknown",
                "error": {"code": ha.CODE_INTERNAL, "detail": "disk full"}})
        lines, failed = self.run_it({"bad-1a1a1a1a": Path("/srv/example/ws/bad"),
                                     "good-2b2b2b2b": Path("/srv/example/ws/good")})
        self.assertTrue(failed)
        self.assertFalse(os.path.lexists(self.links / "bad-1a1a1a1a"))
        self.assertTrue((self.links / "good-2b2b2b2b").is_symlink())
        self.assertTrue(any(l.startswith("  FAIL  register bad-1a1a1a1a: unknown") for l in lines),
                        lines)

    def test_a_refused_registration_fails_and_gets_no_link(self):
        self.reg.fail["/srv/example/ws/ref"] = ha.Answer(
            1, {"ok": False, "error": {"code": "stable_key", "detail": "not absolute"}})
        lines, failed = self.run_it({"ref-4d4d4d4d": Path("/srv/example/ws/ref")})
        self.assertTrue(failed, lines)
        self.assertFalse(os.path.lexists(self.links / "ref-4d4d4d4d"))
        self.assertTrue(any(l.startswith("  FAIL  register ref-4d4d4d4d: refused") for l in lines),
                        lines)

    def test_bound_but_undelivered_is_a_failure_and_still_linked(self):
        b = self.reg.binding("/srv/example/ws/und")
        self.reg.fail["/srv/example/ws/und"] = ha.Answer(
            1, {"ok": False, "committed": True, "binding": dict(b, created=True),
                "error": {"code": ha.CODE_INSTANCES_DIR_ABSENT, "detail": "no dir"}})
        lines, failed = self.run_it({"und-3c3c3c3c": Path("/srv/example/ws/und")})
        self.assertTrue(failed)
        self.assertEqual(os.readlink(self.links / "und-3c3c3c3c"), b["identity_dir"])
        self.assertTrue(any("not delivered" in l for l in lines), lines)


ROSTERS = Path(__file__).parent / "fixtures" / "roster"


def roster(slugs, domain=DOMAIN):
    """A roster as the router writes it, listing `slugs` (shape: the spec's
    valid fixture, roster-basic.json)."""
    doc = json.loads((ROSTERS / "valid-roster-basic.json").read_text())
    doc["members"] = [{"address": f"{s}@{domain}", "state": "admitted"} for s in sorted(slugs)]
    return json.dumps(doc)


class PreIdentityGuardTest(unittest.TestCase):
    """The per-agent guard: an agent that existed before identity was turned
    on (its slug is in the record) and that the registry has not bound is
    refused, never registered under a new name."""

    setUp = InstallIdentityTest.setUp

    def test_a_pre_identity_agent_never_imported_is_refused(self):
        lines, failed = prov.install_identity(self.client, self.links,
                                              {"live-5e5e5e5e": Path("/srv/example/ws/live")},
                                              apply=True, pre=frozenset({"live-5e5e5e5e"}))
        self.assertTrue(failed)
        self.assertNotIn(ha.OP_REGISTER, self.reg.calls)
        self.assertNotIn("/srv/example/ws/live", self.reg.bindings)
        self.assertFalse(os.path.lexists(self.links / "live-5e5e5e5e"))
        self.assertTrue(any(l.startswith("  FAIL  register live-5e5e5e5e: it existed before identity")
                            and "migrate-registry" in l for l in lines), lines)

    def test_a_pre_identity_agent_already_imported_is_registered_as_bound(self):
        self.reg.bindings["/srv/example/ws/live"] = self.reg.binding("/srv/example/ws/live")
        lines, failed = prov.install_identity(self.client, self.links,
                                              {"live-5e5e5e5e": Path("/srv/example/ws/live")},
                                              apply=True, pre=frozenset({"live-5e5e5e5e"}))
        self.assertFalse(failed, lines)
        self.assertIn(ha.OP_REGISTER, self.reg.calls)
        self.assertTrue((self.links / "live-5e5e5e5e").is_symlink())

    def test_an_agent_not_in_the_record_registers_zero_touch(self):
        lines, failed = prov.install_identity(self.client, self.links,
                                              {"fresh-1a2b3c4d": Path("/srv/example/ws/fresh")},
                                              apply=True, pre=frozenset({"live-5e5e5e5e"}))
        self.assertFalse(failed, lines)
        self.assertIn("/srv/example/ws/fresh", self.reg.bindings)

    def test_an_unreadable_record_registers_nothing(self):
        err = prov.PreIdentityError("the pre-identity record is unreadable")
        lines, failed = prov.install_identity(self.client, self.links,
                                              {"fresh-1a2b3c4d": Path("/srv/example/ws/fresh")},
                                              apply=True, pre=err)
        self.assertTrue(failed)
        self.assertNotIn(ha.OP_REGISTER, self.reg.calls)
        self.assertTrue(any(l.startswith("  UNKNOWN register fresh-1a2b3c4d: the pre-identity record")
                            for l in lines), lines)

    def test_a_registry_that_cannot_say_whether_it_is_bound_registers_nothing(self):
        orig = self.reg.__call__

        def answer(client, req):
            if req["op"] == ha.OP_SHOW:
                return ha.Answer(3, {"ok": False, "error": {"code": ha.CODE_INTERNAL, "detail": "x"}})
            return orig(client, req)
        ha.Client.call = answer
        lines, failed = prov.install_identity(self.client, self.links,
                                              {"live-5e5e5e5e": Path("/srv/example/ws/live")},
                                              apply=True, pre=frozenset({"live-5e5e5e5e"}))
        self.assertTrue(failed)
        self.assertNotIn("/srv/example/ws/live", self.reg.bindings)

    def test_dry_run_shows_the_refusal_and_writes_nothing(self):
        lines, failed = prov.install_identity(self.client, self.links,
                                              {"live-5e5e5e5e": Path("/srv/example/ws/live")},
                                              apply=False, pre=frozenset({"live-5e5e5e5e"}))
        self.assertTrue(failed)
        self.assertNotIn(ha.OP_REGISTER, self.reg.calls)
        self.assertFalse(any("would register" in l for l in lines), lines)


class PreIdentityRecordTest(unittest.TestCase):
    """The record: the roster's members when identity is first applied,
    created exclusively, never rewritten."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        prov.feature_roster_dir(self.home).mkdir(parents=True)
        self.path = prov.pre_identity_path(self.home)

    def write_roster(self, text):
        (prov.feature_roster_dir(self.home) / prov.ROSTER_FILE_NAME).write_text(text)

    def test_no_roster_records_an_empty_set(self):
        slugs, note = prov.pre_identity(self.home, apply=True)
        self.assertEqual(slugs, frozenset())
        self.assertEqual(json.loads(self.path.read_text())["slugs"], [])
        self.assertIn("recorded 0", note)

    def test_the_rosters_members_are_recorded_by_slug(self):
        self.write_roster(roster({"alpha-1a2b3c4d", "bravo-5e6f7a8b"}))
        slugs, _ = prov.pre_identity(self.home, apply=True)
        self.assertEqual(slugs, {"alpha-1a2b3c4d", "bravo-5e6f7a8b"})
        doc = json.loads(self.path.read_text())
        self.assertEqual(doc["schema"], prov.PRE_IDENTITY_SCHEMA)
        self.assertEqual(doc["slugs"], ["alpha-1a2b3c4d", "bravo-5e6f7a8b"])

    def test_the_record_is_never_rewritten(self):
        self.write_roster(roster({"alpha-1a2b3c4d"}))
        prov.pre_identity(self.home, apply=True)
        before = self.path.read_bytes()
        self.write_roster(roster({"alpha-1a2b3c4d", "newcomer-9f9f9f9f"}))
        slugs, note = prov.pre_identity(self.home, apply=True)
        self.assertEqual(slugs, {"alpha-1a2b3c4d"})
        self.assertIsNone(note)
        self.assertEqual(self.path.read_bytes(), before)

    def test_once_recorded_the_roster_is_not_read_again(self):
        self.write_roster(roster({"alpha-1a2b3c4d"}))
        prov.pre_identity(self.home, apply=True)
        self.write_roster("{torn")
        self.assertEqual(prov.pre_identity(self.home, apply=True), (frozenset({"alpha-1a2b3c4d"}), None))

    def test_a_record_made_between_the_read_and_the_write_is_kept(self):
        self.write_roster(roster({"alpha-1a2b3c4d"}))
        prov.pre_identity(self.home, apply=True)
        before = self.path.read_bytes()
        real = prov.read_pre_identity
        calls = []

        def racing(path):
            calls.append(path)
            return None if len(calls) == 1 else real(path)
        prov.read_pre_identity = racing
        self.addCleanup(setattr, prov, "read_pre_identity", real)
        self.write_roster(roster({"alpha-1a2b3c4d", "newcomer-9f9f9f9f"}))
        slugs, _ = prov.pre_identity(self.home, apply=True)
        self.assertEqual(slugs, {"alpha-1a2b3c4d"})
        self.assertEqual(self.path.read_bytes(), before)

    def test_dry_run_records_nothing(self):
        self.write_roster(roster({"alpha-1a2b3c4d"}))
        slugs, note = prov.pre_identity(self.home, apply=False)
        self.assertEqual(slugs, {"alpha-1a2b3c4d"})
        self.assertFalse(self.path.exists())
        self.assertIn("would record 1", note)

    def test_an_unreadable_record_is_refused(self):
        for bad in ("{torn", "[]", json.dumps({"schema": "other", "slugs": []}),
                    json.dumps({"schema": prov.PRE_IDENTITY_SCHEMA, "slugs": [""]})):
            self.path.write_text(bad)
            with self.subTest(bad=bad), self.assertRaises(prov.PreIdentityError):
                prov.pre_identity(self.home, apply=True)

    def test_a_link_at_the_record_is_not_followed(self):
        target = self.home / "elsewhere.json"
        target.write_text(json.dumps({"schema": prov.PRE_IDENTITY_SCHEMA, "slugs": []}))
        os.symlink(target, self.path)
        with self.assertRaises(prov.PreIdentityError):
            prov.pre_identity(self.home, apply=True)

    def test_every_valid_spec_roster_is_read(self):
        for f in sorted(ROSTERS.glob("valid-*.json")):
            self.write_roster(f.read_text())
            with self.subTest(f=f.name):
                self.assertIsInstance(prov.roster_slugs(self.home), frozenset)
        self.write_roster((ROSTERS / "valid-roster-basic.json").read_text())
        self.assertEqual(prov.roster_slugs(self.home), {"alpha-1a2b3c4d", "bravo-5e6f7a8b"})

    def test_every_invalid_spec_roster_records_nothing(self):
        fixtures = sorted(ROSTERS.glob("invalid-*.json"))
        self.assertTrue(fixtures)
        for f in fixtures + [None]:
            self.write_roster(f.read_text() if f else "{torn")
            with self.subTest(f=f.name if f else "torn"), self.assertRaises(prov.PreIdentityError):
                prov.pre_identity(self.home, apply=True)
            self.assertFalse(self.path.exists())


class RunInstallIdentityTest(unittest.TestCase):

    def test_off_does_nothing(self):
        import argparse
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(prov.run_install_identity(argparse.Namespace(), Path("/nonexistent"),
                                                       {}, [], {}), 0)
        self.assertEqual(out.getvalue(), "")

    def test_on_without_an_overlay_fails_the_step_by_name(self):
        import argparse
        out = io.StringIO()
        old = os.environ.pop(ha.OVERLAY_ENV, None)
        self.addCleanup(lambda: old and os.environ.__setitem__(ha.OVERLAY_ENV, old))
        with contextlib.redirect_stdout(out):
            rc = prov.run_install_identity(
                argparse.Namespace(overlay=None, apply=True), Path("/nonexistent"),
                {prov.IDENTITY_KEY: prov.IDENTITY_REGISTRY}, [], {})
        self.assertEqual(rc, 1)
        self.assertIn("no deployment overlay", out.getvalue())


class InstallVerbTest(unittest.TestCase):
    """`install --apply` end to end, through `main`: with the policy's
    identity on, a fresh selected sandbox ends up registered and linked.
    The steps install shares with every mode (the payload, the router's
    config) are replaced; sandy's report and the registry are stand-ins."""

    def setUp(self):
        import fleet_policy as fp
        from _registry import write_overlay
        self.home = Path(tempfile.mkdtemp())
        policy = dict(fp.default_policy(), **{prov.IDENTITY_KEY: prov.IDENTITY_REGISTRY,
                                              fp.FLEET_DOMAIN_KEY: DOMAIN})
        path = prov.feature_manifest_path(self.home)
        path.parent.mkdir(parents=True)
        path.write_text(prov.manifest_text(policy, identity_schema=IDS.name_schema))
        checkout = self.home / "checkout"
        (checkout / IDS.module).mkdir(parents=True)
        (checkout / IDS.module / "cli.py").write_text("")
        self.overlay = write_overlay(self.home / "overlay.json", checkout=str(checkout),
                                     directory=str(self.home / "registry"))
        self.ws = "/srv/example/ws/fresh"
        boxes = [{"name": "fresh-1a2b3c4d", "path": "/x", "workspace_path": self.ws}]
        self.reg = Registry()
        self.reg.bindings["/srv/example/ws/old"] = self.reg.binding("/srv/example/ws/old")
        patches = {"discover_sandboxes": lambda sandy_bin="sandy": boxes,
                   "selection_states": lambda home, b: {"fresh-1a2b3c4d": (prov.STATE_SELECTED, "t")},
                   "run_provision": lambda *a, **k: 0,
                   "run_render_router": lambda *a, **k: 0,
                   "load_servers": lambda path: {}}
        for name, value in patches.items():
            orig = getattr(prov, name)
            setattr(prov, name, value)
            self.addCleanup(setattr, prov, name, orig)
        orig = ha.Client.call
        ha.Client.call = lambda c, req: self.reg(c, req)
        self.addCleanup(setattr, ha.Client, "call", orig)

    def main(self, *verb):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = prov.main(["--sandy-home", str(self.home), "--overlay", str(self.overlay), *verb])
        return rc, out.getvalue()

    def test_install_apply_registers_and_links_a_fresh_sandbox(self):
        rc, out = self.main("install", "--apply")
        self.assertEqual(rc, 0, out)
        b = self.reg.bindings[self.ws]
        self.assertEqual(os.readlink(prov.identity_links_dir(self.home) / "fresh-1a2b3c4d"),
                         b["identity_dir"])
        self.assertIn("registered as fresh@", out)

    def write_roster(self, slugs):
        prov.feature_roster_dir(self.home).mkdir(parents=True, exist_ok=True)
        (prov.feature_roster_dir(self.home) / prov.ROSTER_FILE_NAME).write_text(roster(slugs))

    def test_an_agent_the_roster_listed_when_identity_was_enabled_is_refused(self):
        self.write_roster({"fresh-1a2b3c4d"})
        rc, out = self.main("install", "--apply")
        self.assertEqual(rc, 1, out)
        self.assertNotIn(self.ws, self.reg.bindings)
        self.assertIn("recorded 1 pre-identity agent(s)", out)
        self.assertIn("Import it with migrate-registry", out)

    def test_an_agent_launched_after_identity_was_enabled_registers(self):
        rc, out = self.main("install", "--apply")      # no roster yet: the record is empty
        self.assertEqual(rc, 0, out)
        self.write_roster({"fresh-1a2b3c4d"})            # the router lists it now
        rc, out = self.main("install", "--apply")
        self.assertEqual(rc, 0, out)
        self.assertIn(self.ws, self.reg.bindings)

    def test_an_unreadable_roster_at_enable_registers_nothing(self):
        prov.feature_roster_dir(self.home).mkdir(parents=True, exist_ok=True)
        (prov.feature_roster_dir(self.home) / prov.ROSTER_FILE_NAME).write_text("{torn")
        rc, out = self.main("install", "--apply")
        self.assertEqual(rc, 1, out)
        self.assertNotIn(self.ws, self.reg.bindings)
        self.assertFalse(prov.pre_identity_path(self.home).exists())
        self.assertIn("UNKNOWN register fresh-1a2b3c4d", out)

    def test_install_without_apply_registers_nothing(self):
        rc, out = self.main("install")
        self.assertNotIn(self.ws, self.reg.bindings)
        self.assertNotIn(ha.OP_REGISTER, self.reg.calls)
        self.assertFalse(prov.identity_links_dir(self.home).exists())
        self.assertIn("would register", out)


if __name__ == "__main__":
    unittest.main()
