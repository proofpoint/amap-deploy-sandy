"""The registry migration, prepared by `migrate-registry`.

It writes an import batch of every selected sandbox's slug and workspace,
and prints the host registry's operator commands that import it. It never
runs them. Running the printed commands against the real registry is the
deployment overlay's test, because the registry is private.
"""

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

import amap_sandy as prov
import host_adapter as ha
from _registry import IDS, write_overlay

SEL, NOT, UNK = prov.STATE_SELECTED, prov.STATE_NOT_SELECTED, prov.STATE_UNKNOWN


class MembersTest(unittest.TestCase):

    def test_only_selected_sandboxes_with_a_workspace_are_imported(self):
        states = {"alpha-1a2b3c4d": (SEL, "at t"), "bravo-2b3c4d5e": (NOT, "excluded by rule"),
                  "charlie-3c4d5e6f": (UNK, "not launched"), "delta-4d5e6f70": (SEL, "at t"),
                  "-flag-5e6f7081": (SEL, "at t")}
        ws = {s: Path(f"/srv/example/{s}") for s in states if s != "delta-4d5e6f70"}
        members, excluded = prov.migration_members(states, ws)
        self.assertEqual(sorted(members), ["alpha-1a2b3c4d"])
        self.assertIn("excluded by rule", excluded["bravo-2b3c4d5e"])
        self.assertTrue(excluded["charlie-3c4d5e6f"].startswith(UNK))
        self.assertIn("no workspace path", excluded["delta-4d5e6f70"])
        self.assertIn("router refuses", excluded["-flag-5e6f7081"])

    def test_the_batch_is_sorted_and_carries_the_raw_workspace(self):
        members = {"bravo-2b3c4d5e": Path("/srv/example/Bravo"), "alpha-1a2b3c4d": Path("/srv/example/alpha")}
        self.assertEqual(ha.import_items(members), [
            {"adapter": "sandy", "key": "/srv/example/alpha", "slug": "alpha-1a2b3c4d"},
            {"adapter": "sandy", "key": "/srv/example/Bravo", "slug": "bravo-2b3c4d5e"}])
        self.assertEqual(ha.import_batch_text(members), ha.import_batch_text(dict(reversed(list(members.items())))))

    def test_the_commands_are_the_operators_and_quote_their_paths(self):
        plan, apply_ = ha.import_commands(Path("/srv/ex ample/registry"), Path("/srv/example/reg"),
                                          Path("/srv/example/batch.json"), IDS)
        self.assertIn(f"cd '/srv/ex ample/registry' && python3 -m {IDS.operator_module}", plan)
        self.assertIn("plan import --batch /srv/example/batch.json", plan)
        self.assertIn("apply import", apply_)
        for placeholder in (ha.CONFIRM_PLACEHOLDER, ha.OPERATOR_PLACEHOLDER):
            self.assertIn(placeholder, apply_)


class VerbTest(unittest.TestCase):
    """The verb, with sandy's report replaced: it shows or writes the batch
    and prints the commands. It runs no registry process at all."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.overlay = write_overlay(self.tmp / "overlay.json")
        self.repo = self.tmp / "checkout"
        (self.repo / IDS.module).mkdir(parents=True)
        (self.repo / IDS.module / "cli.py").write_text("")
        self.boxes = [{"name": "alpha-1a2b3c4d", "path": "/x", "workspace_path": "/srv/example/alpha"},
                      {"name": "bravo-2b3c4d5e", "path": "/y", "workspace_path": "/srv/example/bravo"}]
        states = {"alpha-1a2b3c4d": (SEL, "at t"), "bravo-2b3c4d5e": (NOT, "rule")}
        for name, value in (("discover_sandboxes", lambda sandy_bin="sandy": self.boxes),
                            ("selection_states", lambda home, boxes: states)):
            orig = getattr(prov, name)
            setattr(prov, name, value)
            self.addCleanup(setattr, prov, name, orig)
        orig_run = ha.Client.call
        ha.Client.call = lambda *a, **k: self.fail("migrate-registry ran the registry")
        self.addCleanup(setattr, ha.Client, "call", orig_run)

    def run_verb(self, *extra):
        argv = ["--sandy-home", str(self.tmp), "--overlay", str(self.overlay), "migrate-registry",
                "--registry", str(self.tmp / "reg"), "--batch", str(self.tmp / "batch.json"),
                "--registry-repo", str(self.repo), *extra]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = prov.main(argv)
        return rc, out.getvalue()

    def test_dry_run_shows_the_batch_and_writes_nothing(self):
        rc, out = self.run_verb()
        self.assertEqual(rc, 0)
        self.assertIn("import  alpha-1a2b3c4d", out)
        self.assertIn("skip    bravo-2b3c4d5e", out)
        self.assertIn('"slug": "alpha-1a2b3c4d"', out)
        self.assertIn("plan import --batch", out)
        self.assertIn("host.json does not exist yet", out)
        self.assertFalse((self.tmp / "batch.json").exists())

    def test_apply_writes_exactly_the_batch(self):
        rc, out = self.run_verb("--apply")
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads((self.tmp / "batch.json").read_text()),
                         [{"adapter": "sandy", "key": "/srv/example/alpha", "slug": "alpha-1a2b3c4d"}])
        self.assertIn("this tool runs neither", out)

    def test_without_an_overlay_it_refuses_by_name(self):
        old = os.environ.pop(ha.OVERLAY_ENV, None)
        self.addCleanup(lambda: old and os.environ.__setitem__(ha.OVERLAY_ENV, old))
        argv = ["--sandy-home", str(self.tmp), "migrate-registry", "--registry",
                str(self.tmp / "reg"), "--batch", str(self.tmp / "batch.json"), "--apply"]
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = prov.main(argv)
        self.assertEqual(rc, 2)
        self.assertIn("no deployment overlay", err.getvalue())
        self.assertFalse((self.tmp / "batch.json").exists())


if __name__ == "__main__":
    unittest.main()
