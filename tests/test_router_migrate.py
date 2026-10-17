"""router-migrate (the runbook's R2) and install --render-to.

No row runs Docker or the router: a fake runner stands in for the hop
checkout's docker/run.sh and answers as the pinned router's code does. The
dry-run plan's members and the refusal that names N are the router's own
at the pin (router/generations.py: operator_migrate's summary and
legacy_basis's message), as the router's maintainers answered the deploy's
Q5 and Q6.
"""

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import amap_sandy
import router_migrate as rm

CHECKOUT = "/hop"
IMAGE = "sha256:" + "e" * 64
LID_A, LID_B = "a" * 32, "b" * 32
REASON = "R2 on this host"


def entry(lid, seq=1):
    return {"logical_id": lid, "adapter": "sandy", "stable_key": "k-" + lid[:4], "binding_seq": seq,
            "held": "state_not_migrated"}


def the_map(**over):
    doc = {"registry_state": "ok", "seq": 7, "instances": {"alice": entry(LID_A), "bob": entry(LID_B)},
           "unknown": []}
    doc.update(over)
    return doc


def plan(name, lid, *, local=1, root=("/inst/" + "alice", 41, 9), **legacy):
    facts = {"basis": "attested", "counter": None, "inflight": 0, "local": local, "malformed": 0,
             "manifest_sha256": "0" * 64, "positive_evidence_count": 0, "transport": 0}
    facts.update(legacy)
    return {"verb": "adopt", "dry_run": True, "phase": "planned", "name": name, "logical_id": lid,
            "generation": os.urandom(4).hex(), "root": {"path": root[0], "st_dev": root[1], "st_ino": root[2]},
            "paths": [], "converted": {}, "legacy": facts}


class FakeRouter:
    """Answers each run.sh call as the pinned router's code would."""

    def __init__(self, the_map=None, plans=None, n=None, adopt_rc=0):
        self.map = the_map if the_map is not None else globals()["the_map"]()
        self.plans = plans or {}
        self.n = n or {}
        self.adopt_rc = adopt_rc
        self.calls = []

    def __call__(self, argv, input=b"", **kw):
        self.calls.append((list(argv), input))
        inner = argv[argv.index("shell") + 1:]
        if inner[:4] == ["python3", "-I", "-S", "-"]:
            return self.done(0, json.dumps(self.map))
        name = inner[inner.index("adopt") + 1]
        given = next((int(a.split("=", 1)[1]) for a in inner if a.startswith("--no-transport-history=")), None)
        need = self.n.get(name)
        if need is not None and given is None:
            return self.done(1, "", "router: generation adopt: refused: the transport counter is absent and "
                                    f"{need} local anchor(s) remain; if this instance never had a transport route, "
                                    f"attest it with --no-transport-history={need}\n")
        if "--dry-run" not in inner:
            return self.done(self.adopt_rc, json.dumps({"name": name, "verb": "adopt"}),
                             "" if self.adopt_rc == 0 else "router: generation adopt: refused: no\n")
        cfg = json.loads(Path(inner[inner.index("--config") + 1]).read_text())
        self.seen_state = cfg["state_dir"]
        return self.done(0, json.dumps(self.plans[name]))

    @staticmethod
    def done(rc, out, err=""):
        return SimpleNamespace(returncode=rc, stdout=out.encode(), stderr=err.encode())


class Base(unittest.TestCase):

    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        self.state = self.base / "state"
        self.state.mkdir(mode=0o700)
        self.run_dir = self.base / "run"
        self.run_dir.mkdir()
        self.config = self.base / "r2-config.json"
        self.config.write_text(json.dumps({"state_dir": str(self.state), "registry_dir": "/reg",
                                           "instances": {"alice": {}, "bob": {}}}))

    def write_map(self, doc=None):
        p = self.run_dir / f"map-{len(list(self.run_dir.iterdir()))}.json"
        p.write_text(json.dumps({"schema": rm.SCHEMA, "step": "map", "map": doc or the_map()}))
        return str(p)


class MapProgram(unittest.TestCase):

    def test_the_program_is_pinned(self):
        """The router maintainers' text, byte for byte: any edit moves this."""
        self.assertEqual(rm.MAP_PROGRAM_SHA256, "7e8b25dd4614e473bace9b0e7c49a157b0bd032678513e158506337b6528196d")
        self.assertEqual(hashlib.sha256(rm.MAP_PROGRAM.encode()).hexdigest(), rm.MAP_PROGRAM_SHA256)
        self.assertIn("persist=False", rm.MAP_PROGRAM)
        self.assertEqual(rm.MAP_PROGRAM.count("\n"), 1)

    def test_the_map_runs_the_pinned_code_on_stdin(self):
        fake = FakeRouter()
        rm.read_map(CHECKOUT, IMAGE, "/c.json", fake)
        argv, stdin = fake.calls[0]
        self.assertEqual(argv, ["/hop/docker/run.sh", "--config", "/c.json", "--image", IMAGE, "--name",
                                "amap-router-migrate", "--", "shell", "python3", "-I", "-S", "-", "/c.json"])
        self.assertEqual(stdin, rm.MAP_PROGRAM.encode())

    def test_the_stop_rules(self):
        for doc, exc in ((the_map(registry_state="unavailable"), rm.Stop), (the_map(unknown=["carol"]), rm.Stop),
                         ({"registry_state": "ok"}, rm.Cannot),
                         (the_map(instances={"alice": dict(entry(LID_A), logical_id="short")}), rm.Cannot)):
            with self.subTest(doc=doc):
                with self.assertRaises(exc):
                    rm.parse_map(json.dumps(doc))
        with self.assertRaises(rm.Cannot):
            rm.parse_map("Traceback")


class DryRunRows(Base):

    def test_n_is_taken_from_the_refusal_and_asked_again(self):
        fake = FakeRouter(plans={"alice": plan("alice", LID_A, local=3)}, n={"alice": 3})
        got, n = rm.dry_run(CHECKOUT, IMAGE, str(self.config), "alice", REASON, fake)
        self.assertEqual(n, 3)
        self.assertEqual(len(fake.calls), 2)
        self.assertIn("--no-transport-history=3", fake.calls[1][0])
        self.assertIn("--dry-run", fake.calls[1][0])

    def test_no_refusal_needs_no_n(self):
        fake = FakeRouter(plans={"alice": plan("alice", LID_A, local=0, basis="empty")})
        self.assertEqual(rm.dry_run(CHECKOUT, IMAGE, str(self.config), "alice", REASON, fake)[1], None)
        self.assertEqual(len(fake.calls), 1)

    def test_any_other_refusal_stops(self):
        runner = lambda argv, **kw: FakeRouter.done(1, "", "router: generation adopt: refused: something else\n")
        with self.assertRaises(rm.Stop):
            rm.dry_run(CHECKOUT, IMAGE, str(self.config), "alice", REASON, runner)
        runner = lambda argv, **kw: FakeRouter.done(2, "", "config error\n")
        with self.assertRaises(rm.Cannot):
            rm.dry_run(CHECKOUT, IMAGE, str(self.config), "alice", REASON, runner)

    def test_transport_history_stops(self):
        for k, v in (("counter", 5), ("inflight", 1), ("transport", 1), ("positive_evidence_count", 1),
                     ("malformed", 1)):
            with self.subTest(fact=k):
                fake = FakeRouter(plans={"alice": plan("alice", LID_A, **{k: v})})
                with self.assertRaises(rm.Stop):
                    rm.dry_run(CHECKOUT, IMAGE, str(self.config), "alice", REASON, fake)

    def test_a_real_run_is_never_taken_for_a_plan(self):
        p = plan("alice", LID_A)
        p["dry_run"] = False
        with self.assertRaises(rm.Cannot):
            rm.dry_run(CHECKOUT, IMAGE, str(self.config), "alice", REASON, FakeRouter(plans={"alice": p}))


class CompareRows(unittest.TestCase):

    def test_each_compared_field_stops(self):
        base = plan("alice", LID_A)
        for k, v in (("name", "bob"), ("logical_id", LID_B), ("verb", "fence-legacy"), ("phase", "done")):
            with self.subTest(field=k):
                with self.assertRaises(rm.Stop):
                    rm.compare_plans("alice", base, dict(base, **{k: v}))
        for k in rm.ROOT_COMPARED:
            with self.subTest(field="root." + k):
                other = json.loads(json.dumps(base))
                other["root"][k] = "x"
                with self.assertRaises(rm.Stop):
                    rm.compare_plans("alice", base, other)

    def test_the_free_fields_never_stop(self):
        a = plan("alice", LID_A, local=1, basis="empty", manifest_sha256="1" * 64)
        b = plan("alice", LID_A, local=4, basis="attested", manifest_sha256="2" * 64)
        b.update(paths=["results/x"], converted={"pending": 2})
        self.assertNotEqual(a["generation"], b["generation"])
        rm.compare_plans("alice", a, b)

    def test_a_binding_change_stops(self):
        for k, v in (("logical_id", LID_B), ("adapter", "other"), ("stable_key", "k2"), ("binding_seq", 2)):
            with self.subTest(field=k):
                after = the_map()
                after["instances"]["alice"][k] = v
                with self.assertRaises(rm.Stop):
                    rm.compare_maps(the_map(), after)
        with self.assertRaises(rm.Stop):
            rm.compare_maps(the_map(), the_map(instances={"alice": entry(LID_A)}))


class MoveRows(Base):

    def test_moves_each_name_to_its_logical_id_and_journals_it(self):
        (self.state / "alice" / "results").mkdir(parents=True)
        journal = rm.do_move(str(self.config), self.write_map(), self.run_dir)
        self.assertTrue((self.state / LID_A / "results").is_dir())
        self.assertFalse((self.state / "alice").exists())
        self.assertEqual(json.loads(journal.read_text())["moves"], [["alice", LID_A]])

    def test_the_guards(self):
        os.symlink(str(self.base), str(self.state / "alice"))
        with self.assertRaises(rm.Stop):
            rm.to_migrate(self.state, the_map())
        os.unlink(self.state / "alice")
        (self.state / "alice").mkdir()
        os.symlink("/nowhere", str(self.state / LID_A))
        with self.assertRaises(rm.Stop):
            rm.to_migrate(self.state, the_map())
        os.unlink(self.state / LID_A)
        (self.state / LID_A).write_text("x")
        with self.assertRaises(rm.Stop):
            rm.to_migrate(self.state, the_map())

    def test_an_instance_with_no_name_state_is_left_alone(self):
        self.assertEqual(rm.to_migrate(self.state, the_map()), [])

    def test_reverse_undoes_newest_first_and_refuses_a_reborn_name(self):
        (self.state / "alice").mkdir()
        (self.state / "bob").mkdir()
        journal = rm.do_move(str(self.config), self.write_map(), self.run_dir)
        rm.do_move(str(self.config), None, self.run_dir, reverse=str(journal))
        self.assertTrue((self.state / "alice").is_dir() and (self.state / "bob").is_dir())
        self.assertFalse((self.state / LID_A).exists() or (self.state / LID_B).exists())
        journal = rm.do_move(str(self.config), self.write_map(), self.run_dir)
        (self.state / "bob").mkdir()
        with self.assertRaises(rm.Stop):
            rm.do_move(str(self.config), None, self.run_dir, reverse=str(journal))


class PreviewCheckAdoptRows(Base):

    def setUp(self):
        super().setUp()
        (self.state / "alice" / "results").mkdir(parents=True)
        (self.state / "alice" / "results" / "r1.json").write_text("{}")

    def test_preview_runs_on_a_scratch_copy_and_removes_it(self):
        fake = FakeRouter(plans={"alice": plan("alice", LID_A)}, n={"alice": 1})
        out = rm.do_preview(CHECKOUT, IMAGE, str(self.config), self.write_map(), REASON, self.run_dir, fake)
        self.assertNotEqual(fake.seen_state, str(self.state))
        self.assertTrue(fake.seen_state.endswith("/state"))
        self.assertFalse(Path(fake.seen_state).exists())
        self.assertTrue((self.state / "alice" / "results" / "r1.json").is_file())
        doc = json.loads(out.read_text())
        self.assertEqual(doc["instances"]["alice"]["advisory_n"], 1)
        self.assertEqual([p.name for p in self.run_dir.iterdir() if p.suffix == ".d"], [])

    def test_a_preview_for_another_logical_id_stops(self):
        fake = FakeRouter(plans={"alice": plan("alice", LID_B)})
        with self.assertRaises(rm.Stop):
            rm.do_preview(CHECKOUT, IMAGE, str(self.config), self.write_map(), REASON, self.run_dir, fake)

    def flow(self, preview_n, post_n, post_local):
        m = self.write_map()
        pre = rm.do_preview(CHECKOUT, IMAGE, str(self.config), m, REASON, self.run_dir,
                            FakeRouter(plans={"alice": plan("alice", LID_A, local=preview_n)},
                                       n={"alice": preview_n}))
        rm.do_move(str(self.config), m, self.run_dir)
        return rm.do_check(CHECKOUT, IMAGE, str(self.config), str(pre), self.write_map(), REASON, self.run_dir,
                           FakeRouter(plans={"alice": plan("alice", LID_A, local=post_local)},
                                      n={"alice": post_n}))

    def test_check_takes_n_only_from_the_post_stop_refusal(self):
        check = self.flow(preview_n=1, post_n=4, post_local=4)
        self.assertEqual(json.loads(check.read_text())["instances"], {"alice": {"logical_id": LID_A, "n": 4}})

    def test_adopt_runs_with_the_checked_n_and_stops_on_a_failure(self):
        check = self.flow(preview_n=1, post_n=2, post_local=2)
        fake = FakeRouter(n={"alice": 2})
        rm.do_adopt(CHECKOUT, IMAGE, str(self.config), str(check), REASON, self.run_dir, fake)
        argv = fake.calls[0][0]
        self.assertIn("--no-transport-history=2", argv)
        self.assertNotIn("--dry-run", argv)
        with self.assertRaises(rm.Stop):
            rm.do_adopt(CHECKOUT, IMAGE, str(self.config), str(check), REASON, self.run_dir,
                        FakeRouter(n={"alice": 2}, adopt_rc=1))

    def test_a_step_run_twice_in_one_second_gets_a_second_record(self):
        """A resumed adopt re-runs at once; its record never collides."""
        a = rm.do_map(CHECKOUT, IMAGE, str(self.config), self.run_dir, FakeRouter())
        b = rm.do_map(CHECKOUT, IMAGE, str(self.config), self.run_dir, FakeRouter())
        self.assertNotEqual(a, b)
        self.assertTrue(a.is_file() and b.is_file())

    def test_a_config_with_no_registry_dir_is_refused(self):
        self.config.write_text(json.dumps({"state_dir": str(self.state)}))
        with self.assertRaises(rm.Stop):
            rm.do_map(CHECKOUT, IMAGE, str(self.config), self.run_dir, FakeRouter())


class VerbRows(Base):

    def args(self, step, **kw):
        base = dict(step=step, config=str(self.config), map=None, preview=None, check=None, reverse=None,
                    reason=None, spec=None, overlay=None, apply=False)
        base.update(kw)
        return SimpleNamespace(**base)

    def setUp(self):
        super().setUp()
        import router_fingerprint as rfp
        real = rfp._load_spec
        self.addCleanup(setattr, rfp, "_load_spec", real)
        spec = SimpleNamespace(secrets=SimpleNamespace(run_dir=str(self.run_dir)),
                               router=SimpleNamespace(image_digest=IMAGE, container="amap-rl"))
        rfp._load_spec = lambda *a, **k: spec

    def test_a_dry_run_makes_no_call(self):
        fake = FakeRouter()
        lines = []
        self.assertEqual(rm.run(self.args("map"), out=lines.append, runner=fake), 0)
        self.assertEqual(fake.calls, [])
        self.assertIn("would run router-migrate map", lines[-1])
        self.assertEqual(list(self.run_dir.iterdir()), [])

    def test_exit_codes(self):
        lines = []
        self.assertEqual(rm.run(self.args("map", apply=True), out=lines.append, runner=FakeRouter()), 0)
        self.assertEqual(rm.run(self.args("map", apply=True), out=lines.append,
                                runner=FakeRouter(the_map=the_map(registry_state="rolled_back"))), 1)
        self.assertIn("STOP", lines[-1])
        self.assertEqual(rm.run(self.args("preview", apply=True), out=lines.append, runner=FakeRouter()), 2)
        self.assertIn("needs --map, --reason", lines[-1])


class RenderToRows(unittest.TestCase):

    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        self.live = self.base / "router.json"
        self.live.write_text("{}\n")

    def test_writes_only_a_new_file_and_never_the_live_config(self):
        out = self.base / "r2-config.json"
        doc = {"state_dir": "/s", "registry_dir": "/r"}
        self.assertEqual(amap_sandy.run_render_to(out, doc, self.live, apply=False, hop=True, combined=False), 0)
        self.assertFalse(out.exists())
        self.assertEqual(amap_sandy.run_render_to(out, doc, self.live, apply=True, hop=True, combined=False), 0)
        self.assertEqual(out.read_text(), amap_sandy.sibling_text(doc))
        self.assertEqual(self.live.read_text(), "{}\n")
        self.assertEqual(amap_sandy.run_render_to(out, doc, self.live, apply=True, hop=True, combined=False), 2)

    def test_refusals(self):
        out = self.base / "x.json"
        self.assertEqual(amap_sandy.run_render_to(out, {}, self.live, apply=True, hop=False, combined=False), 2)
        self.assertEqual(amap_sandy.run_render_to(out, {}, self.live, apply=True, hop=True, combined=True), 2)
        self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
