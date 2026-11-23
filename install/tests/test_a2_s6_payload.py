"""a2_s6_payload: the feature payload from two component trees on a fake VM layer. Agreement of PAYLOAD with this
repo's install is tests/test_a2_s6_agreement.py."""

import unittest

import a2fix  # noqa: F401  (puts install/ on sys.path)
import a2_s6_payload as p6
from a2_causes import Refusal

INSTALLER = [("relay", 0o755, b"r"), ("handoff-sessions", 0o755, b"h"), ("submit-server", 0o755, b"s"),
             ("mcp-servers.json", 0o644, b"{}"), ("INBOX-POLICY.md", 0o644, b"p"), ("codex/relay", 0o755, b"c")]
CONNECTOR = [("inbox-delivery", 0o755, b"d"), ("_inboxlib.py", 0o644, b"l"), ("inbox-mcp-vol", 0o755, b"v"),
             ("inbox-submit", 0o755, b"u"), ("extra-tool", 0o755, b"x")]


class Layer:
    def __init__(self, installer=INSTALLER, connector=CONNECTOR, wrote=False):
        self.trees = {("amap-deploy-sandy", "payload"): installer, ("connector", "bin"): connector}
        self.calls, self._wrote = [], wrote

    def component_tree(self, component, prefix, *, stage):
        self.calls.append((component, prefix, stage))
        return "tree-id", list(self.trees[(component, prefix)])

    def wrote(self, stage):
        return self._wrote


class PayloadTest(unittest.TestCase):

    def test_the_entries_and_their_modes(self):
        L = Layer()
        got = p6.entries(L, "connector")
        self.assertEqual(got, [("relay", 0o100755, b"r"), ("handoff-sessions", 0o100755, b"h"),
                               ("submit-server", 0o100755, b"s"), ("inbox-delivery", 0o100755, b"d"),
                               ("_inboxlib.py", 0o100644, b"l"), ("mcp-servers.json", 0o100644, b"{}"),
                               ("INBOX-POLICY.md", 0o100644, b"p"), ("bin", 0o40755, None),
                               ("bin/inbox-mcp-vol", 0o100755, b"v"), ("bin/inbox-submit", 0o100755, b"u")])
        self.assertEqual(L.calls, [("amap-deploy-sandy", "payload", "CONFIG"), ("connector", "bin", "CONFIG")])

    def test_nothing_else_of_either_tree_is_placed(self):
        paths = [p for p, _m, _b in p6.entries(Layer(), "connector")]
        self.assertNotIn("codex/relay", paths)
        self.assertNotIn("extra-tool", paths)
        self.assertNotIn("bin/extra-tool", paths)

    def test_a_missing_file_refuses_pin(self):
        for installer, connector in ((INSTALLER[1:], CONNECTOR), (INSTALLER, CONNECTOR[:-2])):
            with self.subTest(n=len(installer) + len(connector)), self.assertRaises(Refusal) as cm:
                p6.entries(Layer(installer, connector), "connector")
            self.assertEqual((cm.exception.cause, cm.exception.rc), ("CONFIG.PIN", 2))
        with self.assertRaises(Refusal) as cm:
            p6.entries(Layer(INSTALLER[1:], CONNECTOR, wrote=True), "connector")
        self.assertEqual(cm.exception.rc, 3)

    def test_the_connector_is_the_vms_agents_one(self):
        hosts = {"agents": [{"id": "a", "vm": "vm-a", "connector": "c1"}, {"id": "b", "vm": "vm-a", "connector": "c1"},
                            {"id": "a", "vm": "vm-b", "connector": "c2"}]}
        self.assertEqual(p6.connector_of(hosts, "vm-a"), "c1")
        self.assertEqual(p6.connector_of(hosts, "vm-b"), "c2")
        hosts["agents"].append({"id": "c", "vm": "vm-a", "connector": "c3"})
        for vm in ("vm-a", "vm-c"):
            with self.subTest(vm=vm), self.assertRaises(Refusal) as cm:
                p6.connector_of(hosts, vm)
            self.assertEqual(cm.exception.cause, "CONFIG.HOSTS")


if __name__ == "__main__":
    unittest.main()
