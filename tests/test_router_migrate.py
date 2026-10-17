"""router-migrate (the runbook's R2) and install --render-to.

No row runs Docker or the router: a fake runner stands in for the hop
checkout's docker/run.sh and answers as the pinned router's code does. The
dry-run plan's members and the refusal that names N are the router's own
at the pin (router/generations.py: operator_migrate's summary and
legacy_basis's message), as the router's maintainers answered the deploy's
Q5 and Q6. The renames, the journal and the drain lock run on real files in
a scratch directory.
"""

import fcntl
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import amap_sandy
import router_migrate as rm

CHECKOUT = "/hop"
IMAGE = "sha256:" + "e" * 64
LID_A, LID_B, LID_C = "a" * 32, "b" * 32, "c" * 32
REASON = "R2 on this host"


def entry(lid, seq=1):
    return {"logical_id": lid, "adapter": "sandy", "stable_key": "k-" + lid[:4], "binding_seq": seq,
            "held": "state_not_migrated"}


def the_map(**over):
    doc = {"registry_state": "ok", "seq": 7, "instances": {"alice": entry(LID_A), "bob": entry(LID_B)},
           "unknown": []}
    doc.update(over)
    return doc


def plan(name, lid, *, local=1, root=("/inst/alice", 41, 9), **legacy):
    facts = {"basis": "attested", "counter": None, "inflight": 0, "local": local, "malformed": 0,
             "manifest_sha256": "0" * 64, "positive_evidence_count": 0, "transport": 0}
    facts.update(legacy)
    return {"verb": "adopt", "dry_run": True, "phase": "planned", "name": name, "logical_id": lid,
            "generation": os.urandom(4).hex(), "root": {"path": root[0], "st_dev": root[1], "st_ino": root[2]},
            "paths": [], "converted": {}, "legacy": facts}


class FakeRouter:
    """Answers each run.sh call as the pinned router's code would."""

    def __init__(self, maps=None, plans=None, n=None, adopt_rc=0, answer_lid=None):
        self.maps = list(maps) if maps is not None else []
        self.plans = plans or {}
        self.n = n or {}
        self.adopt_rc = adopt_rc
        self.answer_lid = answer_lid or {}
        self.calls = []

    def __call__(self, argv, input=b"", **kw):
        self.calls.append((list(argv), input))
        inner = argv[argv.index("shell") + 1:]
        if inner[:4] == ["python3", "-I", "-S", "-"]:
            m = self.maps.pop(0) if len(self.maps) > 1 else (self.maps[0] if self.maps else the_map())
            return self.done(0, json.dumps(m))
        name = inner[inner.index("adopt") + 1]
        given = next((int(a.split("=", 1)[1]) for a in inner if a.startswith("--no-transport-history=")), None)
        need = self.n.get(name)
        if need is not None and given is None:
            return self.done(1, "", "router: generation adopt: refused: the transport counter is absent and "
                                    f"{need} local anchor(s) remain; if this instance never had a transport route, "
                                    f"attest it with --no-transport-history={need}\n")
        if "--dry-run" not in inner:
            lid = self.answer_lid.get(name, the_map()["instances"].get(name, entry(LID_C))["logical_id"])
            return self.done(self.adopt_rc, json.dumps({"name": name, "verb": "adopt", "logical_id": lid}),
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
        (self.state / "status.json").write_text("{}")
        (self.state / ".router.lock").write_text("")
        self.run_dir = self.base / "run"
        self.run_dir.mkdir()
        self.config = self.base / "r2-config.json"
        self.write_config()

    def write_config(self, **over):
        doc = {"state_dir": str(self.state), "registry_dir": "/reg", "instances": {"alice": {}, "bob": {}}}
        doc.update(over)
        self.config.write_text(json.dumps(doc))

    def name_dir(self, name):
        (self.state / name / "results").mkdir(parents=True)
        (self.state / name / "results" / "r1.json").write_text("{}")

    def preview(self, plans=None, n=None, maps=None):
        fake = FakeRouter(maps=maps, plans=plans or {"alice": plan("alice", LID_A)}, n=n)
        return rm.do_preview(CHECKOUT, IMAGE, str(self.config), REASON, self.run_dir, fake), fake

    def move(self, preview, runner=None):
        return rm.do_move(CHECKOUT, IMAGE, str(self.config), str(preview), self.run_dir, runner or FakeRouter())

    def check(self, preview, plans=None, n=None, maps=None):
        return rm.do_check(CHECKOUT, IMAGE, str(self.config), str(preview), REASON, self.run_dir,
                           FakeRouter(maps=maps, plans=plans or {"alice": plan("alice", LID_A)}, n=n))


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
                         (the_map(instances={"alice": dict(entry(LID_A), logical_id="short")}), rm.Cannot),
                         (the_map(instances={"alice": dict(entry(LID_A), logical_id="A" * 32)}), rm.Cannot)):
            with self.subTest(doc=doc):
                with self.assertRaises(exc):
                    rm.parse_map(json.dumps(doc))
        with self.assertRaises(rm.Cannot):
            rm.parse_map("Traceback")


class DryRunRows(Base):

    def test_n_is_taken_from_the_refusal_and_asked_again(self):
        fake = FakeRouter(plans={"alice": plan("alice", LID_A, local=3)}, n={"alice": 3})
        _, n = rm.dry_run(CHECKOUT, IMAGE, str(self.config), "alice", REASON, fake)
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
        want = rm.bindings(the_map())
        for k, v in (("logical_id", LID_C), ("adapter", "other"), ("stable_key", "k2"), ("binding_seq", 2)):
            with self.subTest(field=k):
                now = the_map()
                now["instances"]["alice"][k] = v
                with self.assertRaises(rm.Stop):
                    rm.compare_bindings(want, now)
        with self.assertRaises(rm.Stop):
            rm.compare_bindings(want, the_map(instances={"bob": entry(LID_B)}))


class LayoutRows(Base):
    """The plan is built from the layout the stop gate reads (Codex's B1 and
    B2, Opus's 2): nothing the gate counts as needing migration is missed."""

    def test_a_name_dir_is_renamed_and_a_logical_id_dir_is_adopted_in_place(self):
        self.name_dir("alice")
        self.name_dir(LID_B)
        got = rm.classify(self.state, the_map())
        self.assertEqual({n: p["source"] for n, p in got.items()}, {"alice": rm.BY_NAME, "bob": rm.BY_ID})
        rm.cover(self.state, got, moved=False)

    def test_generation_keyed_and_fresh_instances_are_not_planned(self):
        self.name_dir(LID_A)
        (self.state / LID_A / "generations.json").write_text("{}")
        self.assertEqual(rm.classify(self.state, the_map()), {})
        rm.cover(self.state, {}, moved=False)

    def test_what_the_router_would_not_guess_stops(self):
        cases = {
            "a file under a name": lambda: (self.state / "alice").write_text("x"),
            "a link under a name": lambda: os.symlink(str(self.base), str(self.state / "alice")),
            "both name and logical_id": lambda: (self.name_dir("alice"), self.name_dir(LID_A)),
            "an adopt begun": lambda: (self.name_dir(LID_A), (self.state / LID_A / "migration.json").write_text("{}")),
        }
        for name, make in cases.items():
            with self.subTest(case=name):
                d = self.base / "s"
                if d.exists():
                    shutil.rmtree(d)
                self.state = d
                d.mkdir()
                make()
                with self.assertRaises(rm.Stop):
                    rm.classify(self.state, the_map())

    def test_layout_needs_reads_as_the_gate_does(self):
        self.name_dir("alice")
        self.name_dir(LID_B)
        (self.state / "registry").mkdir()
        (self.state / "_runtime").mkdir()
        self.assertEqual(rm.layout_needs(self.state), ({"alice"}, {LID_B}))
        for bad, make in (("carol-file", lambda p: p.write_text("x")), ("A" * 32, lambda p: p.mkdir()),
                          ("_weird", lambda p: p.mkdir())):
            with self.subTest(entry=bad):
                make(self.state / bad)
                with self.assertRaises(rm.Stop):
                    rm.layout_needs(self.state)
                p = self.state / bad
                p.rmdir() if p.is_dir() else p.unlink()

    def test_an_unconfigured_name_dir_stops_the_preview(self):
        """Opus's (c): a removed instance's state is counted by the gate and
        no step would touch it, so the preview refuses before anything."""
        self.name_dir("alice")
        self.name_dir("carol")
        with self.assertRaises(rm.Stop):
            self.preview()

    def test_a_logical_id_dir_with_no_mapping_stops_the_preview(self):
        self.name_dir("alice")
        self.name_dir(LID_C)
        with self.assertRaises(rm.Stop):
            self.preview()


class PlanRows(Base):

    def test_preview_runs_on_a_scratch_copy_and_removes_it(self):
        self.name_dir("alice")
        out, fake = self.preview(n={"alice": 1})
        self.assertNotEqual(fake.seen_state, str(self.state))
        self.assertFalse(Path(fake.seen_state).exists())
        self.assertTrue((self.state / "alice" / "results" / "r1.json").is_file())
        doc = json.loads(out.read_text())
        self.assertEqual(doc["instances"]["alice"]["advisory_n"], 1)
        self.assertEqual(doc["context"]["config_sha256"], hashlib.sha256(self.config.read_bytes()).hexdigest())
        self.assertEqual([p.name for p in self.run_dir.iterdir() if p.suffix == ".d"], [])

    def test_a_logical_id_dir_is_previewed_checked_and_adopted_without_a_rename(self):
        """Codex's B2, Opus's (a): state already under its logical_id."""
        self.name_dir(LID_A)
        pre, _ = self.preview()
        journal = json.loads(self.move(pre).read_text())
        self.assertEqual(journal["moves"], [])
        check = self.check(pre)
        self.assertEqual(json.loads(check.read_text())["instances"]["alice"]["logical_id"], LID_A)
        fake = FakeRouter()
        rm.do_adopt(CHECKOUT, IMAGE, str(self.config), str(check), REASON, self.run_dir, fake)
        self.assertTrue(any("adopt" in c[0] and "--dry-run" not in c[0] for c in fake.calls))

    def test_a_name_dir_that_appears_after_the_preview_stops_the_move(self):
        """Opus's (b): the running router made bob's state after the plan."""
        self.name_dir("alice")
        pre, _ = self.preview()
        self.name_dir("bob")
        with self.assertRaises(rm.Stop):
            self.move(pre)
        self.assertTrue((self.state / "alice").is_dir())
        self.assertFalse((self.state / LID_A).exists())

    def test_check_takes_n_only_from_the_post_stop_refusal(self):
        self.name_dir("alice")
        pre, _ = self.preview(n={"alice": 1})
        self.move(pre)
        check = self.check(pre, plans={"alice": plan("alice", LID_A, local=4)}, n={"alice": 4})
        rec = json.loads(check.read_text())["instances"]["alice"]
        self.assertEqual((rec["logical_id"], rec["n"]), (LID_A, 4))

    def test_check_stops_unless_every_planned_rename_was_made(self):
        self.name_dir("alice")
        pre, _ = self.preview()
        with self.assertRaises(rm.Stop):
            self.check(pre)

    def test_adopt_runs_with_the_checked_n_and_stops_on_a_failure_or_another_identity(self):
        self.name_dir("alice")
        pre, _ = self.preview(n={"alice": 2}, plans={"alice": plan("alice", LID_A, local=2)})
        self.move(pre)
        check = self.check(pre, plans={"alice": plan("alice", LID_A, local=2)}, n={"alice": 2})
        fake = FakeRouter(n={"alice": 2})
        rm.do_adopt(CHECKOUT, IMAGE, str(self.config), str(check), REASON, self.run_dir, fake)
        argv = fake.calls[-1][0]
        self.assertIn("--no-transport-history=2", argv)
        self.assertNotIn("--dry-run", argv)
        for runner in (FakeRouter(n={"alice": 2}, adopt_rc=1), FakeRouter(n={"alice": 2}, answer_lid={"alice": LID_C})):
            with self.subTest(runner=runner.adopt_rc):
                with self.assertRaises(rm.Stop):
                    rm.do_adopt(CHECKOUT, IMAGE, str(self.config), str(check), REASON, self.run_dir, runner)

    def test_a_step_run_twice_in_one_second_gets_a_second_record(self):
        a = rm.do_map(CHECKOUT, IMAGE, str(self.config), self.run_dir, FakeRouter())
        b = rm.do_map(CHECKOUT, IMAGE, str(self.config), self.run_dir, FakeRouter())
        self.assertNotEqual(a, b)

    def test_a_config_with_no_registry_dir_is_refused(self):
        self.write_config(registry_dir=None)
        with self.assertRaises(rm.Stop):
            rm.do_map(CHECKOUT, IMAGE, str(self.config), self.run_dir, FakeRouter())


class BindingRows(Base):
    """Codex's B4: every step after the preview is bound to its context."""

    def setUp(self):
        super().setUp()
        self.name_dir("alice")
        self.pre, _ = self.preview()

    def test_a_changed_config_stops_every_later_step(self):
        self.write_config(extra=1)
        for step in (lambda: self.move(self.pre), lambda: self.check(self.pre)):
            with self.subTest(step=step):
                with self.assertRaises(rm.Stop):
                    step()
        self.assertTrue((self.state / "alice").is_dir())

    def test_another_checkout_or_image_stops(self):
        for checkout, image in (("/other", IMAGE), (CHECKOUT, "sha256:" + "f" * 64)):
            with self.subTest(checkout=checkout, image=image):
                with self.assertRaises(rm.Stop):
                    rm.do_move(checkout, image, str(self.config), str(self.pre), self.run_dir, FakeRouter())

    def test_a_changed_binding_stops_before_any_rename(self):
        now = the_map()
        now["instances"]["alice"]["binding_seq"] = 2
        with self.assertRaises(rm.Stop):
            self.move(self.pre, FakeRouter(maps=[now]))
        self.assertTrue((self.state / "alice").is_dir())

    def test_adopt_is_bound_to_the_checked_config(self):
        self.move(self.pre)
        check = self.check(self.pre)
        self.write_config(extra=1)
        fake = FakeRouter()
        with self.assertRaises(rm.Stop):
            rm.do_adopt(CHECKOUT, IMAGE, str(self.config), str(check), REASON, self.run_dir, fake)
        self.assertFalse(any("adopt" in c[0] for c in fake.calls))


class MoveRows(Base):
    """Codex's B3, Opus's 1: an atomic no-replace rename, a durable journal
    and an idempotent reverse."""

    def setUp(self):
        super().setUp()
        self.name_dir("alice")
        self.name_dir("bob")
        self.pre, _ = self.preview(plans={"alice": plan("alice", LID_A), "bob": plan("bob", LID_B)})

    def journal(self, path):
        return json.loads(Path(path).read_text())

    def test_moves_each_name_and_journals_it_done(self):
        out = self.move(self.pre)
        self.assertTrue((self.state / LID_A / "results").is_dir() and (self.state / LID_B).is_dir())
        self.assertEqual([m["state"] for m in self.journal(out)["moves"]], ["done", "done"])

    def test_a_failed_second_rename_then_a_full_reverse(self):
        real = rm.rename_noreplace
        calls = []

        def failing(src, dst):
            calls.append(src)
            if len(calls) == 2:
                raise OSError(5, "Input/output error", str(dst))
            real(src, dst)
        with mock.patch.object(rm, "rename_noreplace", failing):
            with self.assertRaises(rm.Stop) as cm:
                self.move(self.pre)
        self.assertIn("the journal is", str(cm.exception))
        journal = str(cm.exception).rsplit("the journal is ", 1)[1]
        self.assertEqual([m["state"] for m in self.journal(journal)["moves"]], ["done", "not_applied"])
        rm.do_reverse(str(self.config), journal)
        self.assertTrue((self.state / "alice").is_dir() and (self.state / "bob").is_dir())
        self.assertFalse((self.state / LID_A).exists() or (self.state / LID_B).exists())

    def test_an_interrupted_reverse_resumes(self):
        out = self.move(self.pre)
        real = rm.rename_noreplace
        calls = []

        def once_then_crash(src, dst):
            calls.append(src)
            if len(calls) == 2:
                raise OSError(5, "Input/output error", str(dst))
            real(src, dst)
        with mock.patch.object(rm, "rename_noreplace", once_then_crash):
            with self.assertRaises(OSError):
                rm.do_reverse(str(self.config), str(out))
        rm.do_reverse(str(self.config), str(out))
        rm.do_reverse(str(self.config), str(out))
        self.assertTrue((self.state / "alice").is_dir() and (self.state / "bob").is_dir())

    def test_a_destination_that_appears_is_never_replaced(self):
        real = rm.rename_noreplace

        def interpose(src, dst):
            os.mkdir(dst)
            real(src, dst)
        with mock.patch.object(rm, "rename_noreplace", interpose):
            with self.assertRaises(rm.Stop):
                self.move(self.pre)
        self.assertTrue((self.state / "alice" / "results").is_dir())
        self.assertEqual(list((self.state / LID_A).iterdir()), [])

    def test_a_different_directory_at_the_destination_after_the_rename_stops(self):
        """The rename is checked: the directory now under the logical_id must
        be the one the plan recorded."""
        def swap(src, dst):
            os.rename(src, self.base / "elsewhere")
            os.mkdir(dst)
        with mock.patch.object(rm, "rename_noreplace", swap):
            with self.assertRaises(rm.Stop) as cm:
                self.move(self.pre)
        self.assertIn("is not the directory moved from", str(cm.exception))

    @unittest.skipUnless(sys.platform.startswith("linux") or sys.platform == "darwin", "no-replace rename")
    def test_rename_noreplace_refuses_an_existing_entry_of_any_type(self):
        for make in (lambda p: p.mkdir(), lambda p: p.write_text("x"), lambda p: os.symlink("/nowhere", str(p))):
            with self.subTest(make=make):
                dst = self.base / "dst"
                make(dst)
                with self.assertRaises(OSError):
                    rm.rename_noreplace(self.state / "alice", dst)
                self.assertTrue((self.state / "alice").is_dir())
                dst.unlink() if dst.is_symlink() or dst.is_file() else dst.rmdir()

    def test_reverse_refuses_another_state_dir_and_an_ambiguous_entry(self):
        out = self.move(self.pre)
        other = self.base / "other"
        other.mkdir()
        cfg = self.base / "other.json"
        cfg.write_text(json.dumps({"state_dir": str(other), "registry_dir": "/reg"}))
        with self.assertRaises(rm.Stop):
            rm.do_reverse(str(cfg), str(out))
        (self.state / "bob").mkdir()
        with self.assertRaises(rm.Stop):
            rm.do_reverse(str(self.config), str(out))

    def test_a_held_drain_lock_stops_the_move(self):
        fd = os.open(self.state / ".router.lock", os.O_RDWR)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with self.assertRaises(rm.Stop):
            self.move(self.pre)
        self.assertTrue((self.state / "alice").is_dir())


class VerbRows(Base):

    def args(self, step, **kw):
        base = dict(step=step, config=str(self.config), preview=None, check=None, reverse=None,
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
                                runner=FakeRouter(maps=[the_map(registry_state="rolled_back")])), 1)
        self.assertIn("STOP", lines[-1])
        self.assertEqual(rm.run(self.args("check", apply=True), out=lines.append, runner=FakeRouter()), 2)
        self.assertIn("needs --preview, --reason", lines[-1])
        self.assertEqual(rm.run(self.args("move", apply=True), out=lines.append, runner=FakeRouter()), 2)
        self.assertIn("exactly one", lines[-1])

    def test_a_relative_config_is_made_absolute(self):
        fake = FakeRouter()
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(self.base)
        self.assertEqual(rm.run(self.args("map", config=self.config.name, apply=True), out=lambda s: None,
                                runner=fake), 0)
        self.assertEqual(fake.calls[0][0][2], str(self.config))


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

    def test_install_render_to_runs_nothing_but_the_rendering_and_returns_its_code(self):
        """Opus's 3: install --render-to is its own path. It never reaches
        the connector guard, the provision, or the identity step, and its
        exit code is the render's."""
        args = SimpleNamespace(render_to=str(self.base / "r.json"), apply=True, sandy="sandy")
        home = self.base / "home"
        seen = []
        with mock.patch.object(amap_sandy, "feature_manifest_path", lambda h: self.live), \
                mock.patch.object(amap_sandy.fp, "load_policy", lambda p: {}), \
                mock.patch.object(amap_sandy, "discover_sandboxes", lambda s: []), \
                mock.patch.object(amap_sandy, "run_provision", lambda *a, **k: seen.append("provision")), \
                mock.patch.object(amap_sandy, "run_install_identity", lambda *a, **k: seen.append("identity")), \
                mock.patch.object(amap_sandy.cpin, "guard", lambda *a, **k: seen.append("guard")), \
                mock.patch.object(amap_sandy, "run_render_router", lambda *a, **k: 2):
            self.assertEqual(amap_sandy.run_sync(args, home, self.base), 2)
        self.assertEqual(seen, [])


if __name__ == "__main__":
    unittest.main()
