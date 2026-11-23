"""a2_registry against HOST's captured output (the registry program at its pin, HOST's answer to W7 O1): every success line below
is HOST's bytes as it sent them, its scratch path prefix shown as <S>; every refusal case changes one thing."""

import json
import unittest

import a2fix  # noqa: F401  (puts install/ on sys.path)
import a2_registry as R

PLAN = (b'{"confirm": "0876bd85f03a5c39", "ok": true, "plan": {"items": [{"action": "import", "adapter": "sandy", '
        b'"slug": "router-vm1", "stable_key": "<S>/keys/router-vm1"}], "registry_seq": 0, "verb": "import"}}\n')
APPLY = (b'{"ok": true, "plan": {"items": [{"action": "import", "adapter": "sandy", "slug": "router-vm1", '
         b'"stable_key": "<S>/keys/router-vm1"}], "registry_seq": 0, "verb": "import"}, "results": [{"identity_dir": '
         b'"<S>/inst/9fa85d666786094c773ac344e759a52d", "index": 0, "logical_id": "9fa85d666786094c773ac344e759a52d", '
         b'"name": "router-vm1", "status": "imported"}]}\n')
SHOW = (b'{"binding": {"adapter": "sandy", "address": "router-vm1@fleet.example.org", "epoch": 1, '
        b'"first_registered_ts": "2026-11-20T21:56:57Z", "identity_dir": "<S>/inst/9fa85d666786094c773ac344e759a52d", '
        b'"logical_id": "9fa85d666786094c773ac344e759a52d", "name": "router-vm1", "name_json": "current", '
        b'"state": "active"}, "ok": true}\n')
CONFIRM_MISMATCH = (b'{"error": {"code": "confirm_mismatch", "detail": "the confirmation does not match the change as '
                    b'it stands now; run plan again"}, "ok": false}\n')
NOT_FOUND = b'{"error": {"code": "not_found", "detail": "no such binding"}, "ok": false}\n'
LID = "9fa85d666786094c773ac344e759a52d"
# HOST replaced its scratch directory's absolute prefix with <S>; the real lines carry an absolute path there.
PLAN, APPLY, SHOW = (x.replace(b"<S>", b"/scratch") for x in (PLAN, APPLY, SHOW))


def edit(raw, change):
    doc = json.loads(raw)
    change(doc)
    return (json.dumps(doc, sort_keys=True) + "\n").encode()


DOMAIN = "fleet.example.org"
IDIR = "/scratch/inst/9fa85d666786094c773ac344e759a52d"


def plan_obj():
    return json.loads(PLAN)["plan"]


class RegistryTest(unittest.TestCase):
    def plan(self, rc, out):
        return R.parse_plan(rc, out, "router-vm1")

    def apply(self, rc, out, plan=None):
        return R.parse_apply(rc, out, "router-vm1", plan if plan is not None else plan_obj())

    def show(self, rc, out, lid=LID, idir=IDIR, domain=DOMAIN):
        return R.parse_show(rc, out, "router-vm1", lid, idir, domain)

    def refused(self, fn, rc, out, **kw):
        with self.assertRaises((R.RegistryRefused, R.RegistryError)):
            fn(rc, out, **kw)

    def test_hosts_captured_lines_parse(self):
        confirm, action, plan, key = self.plan(0, PLAN)
        self.assertEqual((confirm, action, key), ("0876bd85f03a5c39", "import", "/scratch/keys/router-vm1"))
        self.assertEqual(self.apply(0, APPLY, plan), (LID, "imported", IDIR))
        self.assertEqual(self.show(0, SHOW), LID)

    def test_already_bound_is_already(self):
        plan = edit(PLAN, lambda d: d["plan"]["items"][0].update(action="already_bound"))
        self.assertEqual(self.plan(0, plan)[1], "already_bound")
        apply_ = edit(APPLY, lambda d: d["results"][0].update(status="already_bound"))
        self.assertEqual(self.apply(0, apply_), (LID, "already_bound", IDIR))

    def test_refusal_codes_route_the_caller(self):
        with self.assertRaises(R.RegistryError) as cm:
            self.apply(1, CONFIRM_MISMATCH)
        self.assertEqual((cm.exception.code, R.next_step(cm.exception)), ("confirm_mismatch", R.REPLAN))
        delivery = edit(APPLY, lambda d: (d.update(ok=False, committed=True, error={"code": "delivery_failed",
                                                                                    "detail": "x"}),
                                          d["results"][0].update(delivery={"ok": False})))
        with self.assertRaises(R.RegistryError) as cm:
            self.apply(1, delivery)
        self.assertEqual((cm.exception.code, cm.exception.committed, R.next_step(cm.exception)),
                         ("delivery_failed", True, R.REPLAN))
        for code in ("import_conflict", "key_bound", "anything"):
            with self.subTest(code=code):
                raw = ('{"error": {"code": "%s", "detail": "x"}, "ok": false}\n' % code).encode()
                with self.assertRaises(R.RegistryError) as cm:
                    self.apply(1, raw)
                self.assertEqual(R.next_step(cm.exception), R.REFUSE)
        with self.assertRaises(R.RegistryError) as cm:
            self.apply(3, b'{"error": {"code": "internal", "detail": "x"}, "ok": false}\n')
        self.assertEqual((cm.exception.committed, R.next_step(cm.exception)), ("unknown", R.REPLAN))
        with self.assertRaises(R.RegistryError) as cm:
            self.show(1, NOT_FOUND)
        self.assertEqual(cm.exception.code, "not_found")
        self.refused(self.apply, 2, b'{"ok": false}\n')

    def test_refusals(self):
        for fn, raw in ((self.plan, PLAN), (self.apply, APPLY), (self.show, SHOW)):
            with self.subTest(fn=fn.__name__):
                self.refused(fn, 1, raw)
                self.refused(fn, 0, raw[:-1])
                self.refused(fn, 0, raw + raw)
                self.refused(fn, 0, raw.replace(b'"ok": true', b'"ok": true, "ok": true', 1))
                self.refused(fn, 0, b"")
        show_cases = {
            "another slug": lambda d: d["binding"].update(name="router-vm2"),
            "retired": lambda d: d["binding"].update(state="retired"),
            "name_json stale": lambda d: d["binding"].update(name_json="stale"),
            "no name_json": lambda d: d["binding"].pop("name_json"),
            "an extra binding key": lambda d: d["binding"].update(extra=1),
            "upper-case id": lambda d: d["binding"].update(logical_id=LID.upper()),
            "all-zero id": lambda d: d["binding"].update(logical_id="0" * 32),
            "epoch 0": lambda d: d["binding"].update(epoch=0),
            "epoch true": lambda d: d["binding"].update(epoch=True),
            "another adapter": lambda d: d["binding"].update(adapter="codex"),
            "an extra top key": lambda d: d.update(interfaces=[]),
            "another id than apply's": lambda d: d["binding"].update(logical_id="1" * 32),
            "another identity_dir": lambda d: d["binding"].update(identity_dir="/scratch/inst/other"),
            "another address": lambda d: d["binding"].update(address="router-vm1@other.example.org"),
        }
        for label, change in show_cases.items():
            with self.subTest(show=label):
                self.refused(self.show, 0, edit(SHOW, change))
        plan_cases = {
            "two items": lambda d: d["plan"]["items"].append(dict(d["plan"]["items"][0])),
            "another slug": lambda d: d["plan"]["items"][0].update(slug="x"),
            "a bad confirm": lambda d: d.update(confirm="xyz"),
            "another verb": lambda d: d["plan"].update(verb="retire"),
            "another action": lambda d: d["plan"]["items"][0].update(action="rebind"),
            "stable_key an int": lambda d: d["plan"]["items"][0].update(stable_key=5),
            "stable_key relative": lambda d: d["plan"]["items"][0].update(stable_key="keys/x"),
            "registry_seq a string": lambda d: d["plan"].update(registry_seq="x"),
            "registry_seq a bool": lambda d: d["plan"].update(registry_seq=False),
            "registry_seq negative": lambda d: d["plan"].update(registry_seq=-1),
            "an extra plan key": lambda d: d["plan"].update(extra=1),
            "an extra item key": lambda d: d["plan"]["items"][0].update(extra=1),
        }
        for label, change in plan_cases.items():
            with self.subTest(plan=label):
                self.refused(self.plan, 0, edit(PLAN, change))
        apply_cases = {
            "index 1": lambda d: d["results"][0].update(index=1),
            "index False": lambda d: d["results"][0].update(index=False),
            "a delivery member": lambda d: d["results"][0].update(delivery={}),
            "a short id": lambda d: d["results"][0].update(logical_id=LID[:31]),
            "another status": lambda d: d["results"][0].update(status="retired"),
            "an echoed plan that differs": lambda d: d["plan"].update(registry_seq=1),
            "an echoed plan for another stable_key": lambda d: d["plan"]["items"][0].update(stable_key="/scratch/x"),
        }
        for label, change in apply_cases.items():
            with self.subTest(apply=label):
                self.refused(self.apply, 0, edit(APPLY, change))

    def test_inputs_and_argv(self):
        self.assertEqual(R.show_input("/k", "regtool.adapter/1"),
                         b'{"interface":"regtool.adapter/1","op":"show","adapter":"sandy","key":"/k"}')
        self.assertEqual(json.loads(R.batch("/k", "s")), [{"adapter": "sandy", "key": "/k", "slug": "s"}])


if __name__ == "__main__":
    unittest.main()
