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


if __name__ == "__main__":
    unittest.main()
