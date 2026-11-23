"""The agents' registry slots (a2_agent_registry), against a scripted layer and HOST's captured registry output
(test_a2_registry: PLAN, APPLY and SHOW as the registry program printed them; the binding's slug and key are the
fixture's)."""

import json
import unittest

import a2fix  # noqa: F401  (puts install/ on sys.path)
import a2_agent_registry as A
import a2_vm
import test_a2_registry as TR
import vm_place
from a2_causes import Refusal

SLUG, KEY = "router-vm1", "/scratch/keys/router-vm1"
HOME = b"/home/agent\n"
PLACED = b"PLACED " + SLUG.encode() + b".json\n"


class ScriptLayer:
    def __init__(self, *replies):
        self.vms = {"vm-a": {"name": "vm-a", "agent_account": "agent", "fleet_domain": TR.DOMAIN}}
        self.lock = {"registry_program": dict(a2fix.FIXTURE_REGISTRY)}
        self.replies, self.calls, self._wrote = list(replies), [], set()

    def wrote(self, stage):
        return stage in self._wrote

    def pinned_installer_file(self, name, stage):
        assert name == "vm_place.py" and stage == "AGENTS"
        return b"# pinned vm_place"

    def exec(self, vm, argv, *, account, stage, writes, stdin=None, timeout_s=None):
        self.calls.append(dict(vm=vm, argv=argv, account=account, stage=stage, writes=writes, stdin=stdin))
        if writes:
            self._wrote.add(stage)
        rc, out = self.replies.pop(0)
        return rc, out, b""


class Base(unittest.TestCase):
    def refuses(self, cause, rc, fn, *a, **kw):
        with self.assertRaises(Refusal) as cm:
            fn(*a, **kw)
        self.assertEqual((cm.exception.cause, cm.exception.rc), (cause, rc))

    def imported(self, *more):
        L = ScriptLayer((0, HOME), (0, PLACED), (0, TR.PLAN), (0, TR.APPLY), (0, TR.SHOW), *more)
        R = A.AgentRegistry(L)
        self.assertIsNone(R.registry_import("vm-a", SLUG, KEY, stage="AGENTS"))
        return L, R


class ImportTest(Base):
    def test_home_place_plan_apply_show_then_a_fresh_show_on_read(self):
        L, R = self.imported((0, TR.SHOW))
        self.assertEqual(R.registry_read("vm-a", SLUG, stage="AGENTS"), TR.LID)
        home, place, plan, apply_, show, read = L.calls
        self.assertEqual(home["argv"], A.HOME_ARGV)
        self.assertEqual(place["argv"], ["/usr/bin/python3", "-I", "-S", "-c", "# pinned vm_place",
                                         ".amap-registry-agents", "subset"])
        self.assertEqual(vm_place.parse(place["stdin"]), [([SLUG + ".json"], 0o100644, TR_batch())])
        code = "/home/agent/.a2-registry-code"
        self.assertEqual(plan["argv"][5:], [code, "--registry", "/home/agent/.amap-registry", "plan", "import",
                                            "--batch", "/home/agent/.amap-registry-agents/router-vm1.json"])
        self.assertIn('"regtool.opverbs"', plan["argv"][4])
        self.assertEqual(apply_["argv"][5:], [code, "--registry", "/home/agent/.amap-registry", "apply", "import",
                                              "--batch", "/home/agent/.amap-registry-agents/router-vm1.json",
                                              "--confirm", "0876bd85f03a5c39", "--operator", "a2-installer",
                                              "--reason", "AGENTS agent router-vm1"])
        for c in (show, read):
            self.assertEqual(c["argv"][5:], [code, "--registry", "/home/agent/.amap-registry"])
            self.assertIn('"regtool"', c["argv"][4])
            self.assertEqual(json.loads(c["stdin"]), {"interface": "regtool.adapter/1", "op": "show",
                                                      "adapter": "sandy", "key": KEY})
        self.assertEqual([c["writes"] for c in L.calls], [False, True, False, True, False, False])
        self.assertEqual({c["account"] for c in L.calls}, {"agent"})
        self.assertEqual({c["stage"] for c in L.calls}, {"AGENTS"})

    def test_the_home_is_read_once_per_vm(self):
        L, R = self.imported((0, PLACED), (0, TR.PLAN), (0, TR.APPLY), (0, TR.SHOW))
        R.registry_import("vm-a", SLUG, KEY, stage="AGENTS")
        self.assertEqual([c["argv"] for c in L.calls].count(A.HOME_ARGV), 1)

    def test_an_already_placed_batch_is_same(self):
        L = ScriptLayer((0, HOME), (0, b"SAME router-vm1.json\n"), (0, TR.PLAN), (0, TR.APPLY), (0, TR.SHOW))
        self.assertIsNone(A.AgentRegistry(L).registry_import("vm-a", SLUG, KEY, stage="AGENTS"))

    def test_bind_fills_both_slots_and_the_logical_id_reads_back(self):
        from a2_site import Site
        s, L = Site(), ScriptLayer((0, HOME), (0, PLACED), (0, TR.PLAN), (0, TR.APPLY), (0, TR.SHOW), (0, TR.SHOW))
        L.install_file = L.write_secret = L.component_file = None
        a2_vm.bind(s, L)
        s.registry_import("vm-a", SLUG, KEY, stage="AGENTS")
        self.assertEqual(a2_vm.logical_id(s, "vm-a", SLUG, "AGENTS"), TR.LID)


def TR_batch():
    import a2_registry
    return a2_registry.batch(KEY, SLUG)


class RefusalTest(Base):
    def test_an_unknown_vm_refuses_hosts(self):
        self.refuses("AGENTS.HOSTS", 2, A.AgentRegistry(ScriptLayer()).registry_import, "vm-z", SLUG, KEY,
                     stage="AGENTS")

    def test_a_bad_slug_or_key_refuses_before_any_call(self):
        for slug, key in (("", KEY), ("-x", KEY), ("a/b", KEY), (None, KEY), (SLUG, "rel"), (SLUG, "/a/../b"),
                          (SLUG, None), (SLUG, "/a/"), (SLUG, "//a/b")):
            with self.subTest(slug=slug, key=key):
                L = ScriptLayer()
                self.refuses("AGENTS.UNCLASSIFIED", 2, A.AgentRegistry(L).registry_import, "vm-a", slug, key,
                             stage="AGENTS")
                self.assertEqual(L.calls, [])

    def test_a_home_it_cannot_use_refuses_before_any_write(self):
        for rc, out in ((0, b"rel\n"), (0, b"/\n"), (0, b"/home/../x\n"), (0, b"/home/agent"), (1, HOME),
                        (0, b"/home/a\nb\n")):
            with self.subTest(out=out, rc=rc):
                L = ScriptLayer((rc, out))
                self.refuses("AGENTS.UNCLASSIFIED", 2, A.AgentRegistry(L).registry_import, "vm-a", SLUG, KEY,
                             stage="AGENTS")
                self.assertEqual(len(L.calls), 1)

    def test_the_batch_placement_refusals(self):
        for rc, out, cause in ((vm_place.DIFFERENT, b"", "AGENTS.PLACED_DIFFERENT"),
                               (vm_place.NOT_ALLOWED, b"", "AGENTS.OWNER"),
                               (0, b"PLACED other.json\n", "AGENTS.UNCLASSIFIED"),
                               (0, PLACED + PLACED, "AGENTS.UNCLASSIFIED"),
                               (5, PLACED, "AGENTS.UNCLASSIFIED")):
            with self.subTest(rc=rc, out=out):
                L = ScriptLayer((0, HOME), (rc, out))
                self.refuses(cause, 3, A.AgentRegistry(L).registry_import, "vm-a", SLUG, KEY, stage="AGENTS")
                self.assertEqual(len(L.calls), 2)

    def test_confirm_mismatch_replans_once_and_a_second_refuses(self):
        L = ScriptLayer((0, HOME), (0, PLACED), (0, TR.PLAN), (1, TR.CONFIRM_MISMATCH), (0, TR.PLAN), (0, TR.APPLY),
                        (0, TR.SHOW))
        A.AgentRegistry(L).registry_import("vm-a", SLUG, KEY, stage="AGENTS")
        self.assertEqual(len(L.calls), 7)
        L = ScriptLayer((0, HOME), (0, PLACED), (0, TR.PLAN), (1, TR.CONFIRM_MISMATCH), (0, TR.PLAN),
                        (1, TR.CONFIRM_MISMATCH))
        self.refuses("AGENTS.REGISTRY", 3, A.AgentRegistry(L).registry_import, "vm-a", SLUG, KEY, stage="AGENTS")
        self.assertEqual(len(L.calls), 6)

    def test_a_hard_refusal_is_never_retried(self):
        L = ScriptLayer((0, HOME), (0, PLACED), (0, TR.PLAN),
                        (1, b'{"error": {"code": "key_bound", "detail": "x"}, "ok": false}\n'))
        self.refuses("AGENTS.REGISTRY", 3, A.AgentRegistry(L).registry_import, "vm-a", SLUG, KEY, stage="AGENTS")
        self.assertEqual(len(L.calls), 4)

    def test_a_key_the_registry_normalised_passes_and_every_show_uses_it(self):
        """HOST normalises the batch's key against the VM's filesystem (HOST's answer f46595f6, lines 17-20), so its
        plan may return another key than the raw one. That key is kept, and both shows query by it."""
        norm = "/scratch/Keys/router-vm1"
        plan, apply_ = (TR.edit(x, lambda d: d["plan"]["items"][0].update(stable_key=norm)) for x in (TR.PLAN, TR.APPLY))
        L = ScriptLayer((0, HOME), (0, PLACED), (0, plan), (0, apply_), (0, TR.SHOW), (0, TR.SHOW))
        R = A.AgentRegistry(L)
        self.assertIsNone(R.registry_import("vm-a", SLUG, KEY, stage="AGENTS"))
        self.assertEqual(R.registry_read("vm-a", SLUG, stage="AGENTS"), TR.LID)
        self.assertEqual([json.loads(c["stdin"])["key"] for c in L.calls[4:]], [norm, norm])
        self.assertEqual(json.loads(vm_place.parse(L.calls[1]["stdin"])[0][2])[0]["key"], KEY)

    def test_an_apply_for_another_key_than_the_plan_refuses(self):
        apply_ = TR.edit(TR.APPLY, lambda d: d["plan"]["items"][0].update(stable_key="/scratch/keys/other"))
        L = ScriptLayer((0, HOME), (0, PLACED), (0, TR.PLAN), (0, apply_))
        self.refuses("AGENTS.REGISTRY", 3, A.AgentRegistry(L).registry_import, "vm-a", SLUG, KEY, stage="AGENTS")
        self.assertEqual(len(L.calls), 4)

    def test_a_bad_plan_refuses(self):
        L = ScriptLayer((0, HOME), (0, PLACED), (0, b"{}\n"))
        self.refuses("AGENTS.REGISTRY", 3, A.AgentRegistry(L).registry_import, "vm-a", SLUG, KEY, stage="AGENTS")

    def test_a_show_that_does_not_match_refuses_and_records_nothing(self):
        other = TR.edit(TR.SHOW, lambda d: d["binding"].update(address="router-vm1@other.example.org"))
        L = ScriptLayer((0, HOME), (0, PLACED), (0, TR.PLAN), (0, TR.APPLY), (0, other))
        R = A.AgentRegistry(L)
        self.refuses("AGENTS.REGISTRY", 3, R.registry_import, "vm-a", SLUG, KEY, stage="AGENTS")
        self.refuses("AGENTS.REGISTRY", 3, R.registry_read, "vm-a", SLUG, stage="AGENTS")

    def test_a_read_without_an_import_refuses(self):
        self.refuses("AGENTS.REGISTRY", 2, A.AgentRegistry(ScriptLayer()).registry_read, "vm-a", SLUG,
                     stage="AGENTS")

    def test_a_read_whose_show_differs_refuses(self):
        other = TR.edit(TR.SHOW, lambda d: d["binding"].update(logical_id="1" * 32))
        L, R = self.imported((0, other))
        self.refuses("AGENTS.REGISTRY", 3, R.registry_read, "vm-a", SLUG, stage="AGENTS")
        L, R = self.imported((1, b'{"error": {"code": "not_found", "detail": "x"}, "ok": false}\n'))
        self.refuses("AGENTS.REGISTRY", 3, R.registry_read, "vm-a", SLUG, stage="AGENTS")


if __name__ == "__main__":
    unittest.main()
