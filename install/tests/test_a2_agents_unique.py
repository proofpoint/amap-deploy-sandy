"""agents[] unique per (vm, id) (E9; DS ruling W7-AGENTS-UNIQUENESS). Carried verbatim from W8's
test_w8_private.py; W8 drops this class there at its rebase onto W7."""

import copy
import unittest

import a2fix
import a2_private


class AgentsUniquePerVmTest(unittest.TestCase):
    def doc(self, agents):
        h = a2fix.hosts_doc("/srv/locks")
        h["agents"] = agents
        return h

    def test_the_same_id_on_two_vms_is_admitted(self):
        h = a2fix.hosts_doc("/srv/locks")
        a, b = h["vms"][0]["name"], h["vms"][1]["name"]
        a2_private.check_hosts(self.doc([{"id": "agent-a", "vm": a, "connector": "connector"},
                                         {"id": "agent-a", "vm": b, "connector": "connector"}]))

    def test_two_ids_on_one_vm_are_admitted(self):  # kills W11
        h = a2fix.hosts_doc("/srv/locks")
        a = h["vms"][0]["name"]
        a2_private.check_hosts(self.doc([{"id": "agent-a", "vm": a, "connector": "connector"},
                                         {"id": "agent-b", "vm": a, "connector": "connector"}]))

    def test_the_same_vm_and_id_twice_is_refused(self):
        h = a2fix.hosts_doc("/srv/locks")
        a = h["vms"][0]["name"]
        with self.assertRaises(a2_private.Invalid) as cm:
            a2_private.check_hosts(self.doc([{"id": "agent-a", "vm": a, "connector": "connector"},
                                             {"id": "agent-a", "vm": a, "connector": "connector"}]))
        self.assertEqual((cm.exception.check, cm.exception.path), ("L3", "$.agents"))

    def test_a_single_key_unique_still_works(self):
        lock = copy.deepcopy(a2fix.LOCK)
        lock["components"].append(dict(lock["components"][0]))
        with self.assertRaises(a2_private.Invalid):
            a2_private.check_lock(lock)


if __name__ == "__main__":
    unittest.main()
