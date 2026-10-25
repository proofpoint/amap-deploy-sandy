"""fleet_keys: the pinned inventory of the fleet's public signing keys.

The keys are synthetic: each public key is 32 bytes chosen here, and each
key_id is computed in the test as the key step prints it (the sha256 of the
raw key), so the module's comparison is checked against an independent
computation, never against itself."""

import hashlib
import json
import unittest

import fleet_keys as fk
from test_hub_runtime import setUpModule, tearDownModule  # noqa: F401 -- the hub fixture's pins, restored


def pub(n):
    return bytes([n]) * 32


def host(name, domains, n, **over):
    p = pub(n)
    h = {"name": name, "domains": sorted(domains), "runtime": "amap.router@" + sorted(domains)[0],
         "public_key": p.hex(), "key_id": hashlib.sha256(p).hexdigest()}
    h.update(over)
    return h


def doc(*hosts):
    return {"schema": fk.SCHEMA, "hosts": sorted(hosts, key=lambda h: h["name"])}


def raw(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


TWO = doc(host("alpha", ["alpha.example.org"], 1), host("beta", ["beta.example.org"], 2))


class ParseTest(unittest.TestCase):

    def refuses(self, data, words):
        with self.assertRaises(fk.FleetKeysError) as cm:
            fk.parse(data)
        self.assertIn(words, str(cm.exception))

    def test_a_canonical_inventory_parses(self):
        hosts = fk.parse(raw(TWO))
        self.assertEqual([h.name for h in hosts], ["alpha", "beta"])
        self.assertEqual(hosts[1].key_id, hashlib.sha256(pub(2)).hexdigest())

    def test_strict_shapes_refuse(self):
        self.refuses(b'{"schema":"x","schema":"y","hosts":[]}', "twice")
        self.refuses(raw(dict(TWO, extra=1)), "exactly {schema, hosts}")
        self.refuses(raw(dict(TWO, schema="amap-deploy.fleet-keys/2")), "schema")
        self.refuses(json.dumps(TWO, indent=2, sort_keys=True).encode(), "canonical")
        self.refuses(raw(TWO).replace(b'"hosts":[', b'"hosts":[NaN,'), "not JSON")
        self.refuses(raw(doc(dict(host("alpha", ["alpha.example.org"], 1), note="x"))), "exactly")
        self.refuses(raw({"schema": fk.SCHEMA, "hosts": list(reversed(TWO["hosts"]))}), "sorted by name")

    def test_key_id_rules(self):
        h = host("alpha", ["alpha.example.org"], 1)
        self.refuses(raw(doc(dict(h, key_id=h["key_id"] + "0"))), "64 lower-case hex")
        self.refuses(raw(doc(dict(h, key_id=h["key_id"].upper()))), "64 lower-case hex")
        self.refuses(raw(doc(dict(h, key_id=hashlib.sha256(pub(9)).hexdigest()))), "not the sha256 of its public_key")
        self.refuses(raw(doc(dict(h, public_key=h["public_key"][:-2]))), "public_key must be 64")

    def test_a_domain_or_key_id_shared_by_two_entries_refuses(self):
        self.refuses(raw(doc(host("alpha", ["one.example.org"], 1), host("beta", ["one.example.org"], 2))),
                     "both list one.example.org")
        self.refuses(raw(doc(host("alpha", ["a.example.org"], 1), host("beta", ["b.example.org"], 1))),
                     "share a key_id")

    def test_runtime_names_one_of_its_domains(self):
        self.refuses(raw(doc(host("alpha", ["alpha.example.org"], 1, runtime="amap.router@other.example.org"))),
                     "runtime must be amap.router@")


class PinTest(unittest.TestCase):

    def test_the_section_is_exactly_path_and_sha256(self):
        pin = fk.load({"path": "/opt/ex/fleet-keys.json", "sha256": "a" * 64})
        self.assertEqual(pin.path, "/opt/ex/fleet-keys.json")
        for bad in ({"path": "rel.json", "sha256": "a" * 64}, {"path": "/x", "sha256": "A" * 64},
                    {"path": "/x", "sha256": "a" * 64, "extra": 1}):
            with self.assertRaises(fk.FleetKeysError):
                fk.load(bad)

    def test_bytes_that_do_not_hash_to_the_pin_are_never_parsed(self):
        data = raw(TWO)
        good = fk.FleetKeysPin("/x", hashlib.sha256(data).hexdigest())
        self.assertEqual(len(fk.read(good, lambda p: data)), 2)
        bad = fk.FleetKeysPin("/x", "0" * 64)
        parsed = []
        with self.assertRaises(fk.FleetKeysError) as cm:
            fk.read(bad, lambda p: parsed.append(p) or b"not json at all")
        self.assertIn("not the pinned", str(cm.exception))


class SelectTest(unittest.TestCase):

    def setUp(self):
        self.hosts = fk.parse(raw(TWO))

    def test_this_host_is_the_entry_listing_the_fleet_domain(self):
        me, peers = fk.select(self.hosts, "alpha.example.org", ["beta.example.org"])
        self.assertEqual((me.name, [p.name for p in peers]), ("alpha", ["beta"]))
        # The table entry carries the inventory's key_id byte for byte.
        self.assertEqual(peers[0].table_entry()["keys"], [{"key_id": TWO["hosts"][1]["key_id"],
                                                           "public_key": TWO["hosts"][1]["public_key"]}])

    def test_zero_or_two_self_entries_refuse(self):
        with self.assertRaises(fk.FleetKeysError) as cm:
            fk.select(self.hosts, "gamma.example.org", ["alpha.example.org", "beta.example.org"])
        self.assertIn("0 inventory entries", str(cm.exception))

    def test_a_peer_outside_the_trusted_hosts_refuses_by_name(self):
        with self.assertRaises(fk.FleetKeysError) as cm:
            fk.select(self.hosts, "alpha.example.org", [])
        self.assertIn("'beta'", str(cm.exception))

    def test_each_host_selects_the_other(self):
        me, peers = fk.select(self.hosts, "beta.example.org", ["alpha.example.org"])
        self.assertEqual((me.name, [p.name for p in peers]), ("beta", ["alpha"]))

    def test_an_inventory_of_this_host_alone_parses_and_is_refused_at_selection(self):
        one = fk.parse(raw(doc(host("alpha", ["alpha.example.org"], 1))))
        self.assertEqual([h.name for h in one], ["alpha"])
        with self.assertRaises(fk.FleetKeysError) as cm:
            fk.select(one, "alpha.example.org", ["beta.example.org"])
        self.assertIn("lists only this host ('alpha')", str(cm.exception))

    def test_a_trusted_host_with_no_entry_refuses_by_domain(self):
        with self.assertRaises(fk.FleetKeysError) as cm:
            fk.select(self.hosts, "alpha.example.org", ["beta.example.org", "gamma.example.org"])
        self.assertIn("gamma.example.org", str(cm.exception))
        self.assertNotIn("beta.example.org", str(cm.exception))

    def test_this_hosts_own_domain_among_the_trusted_is_not_a_counterpart(self):
        me, peers = fk.select(self.hosts, "alpha.example.org", ["alpha.example.org", "beta.example.org"])
        self.assertEqual([p.name for p in peers], ["beta"])


class SectionTest(unittest.TestCase):
    """The section in a host-setup document, through host_setup.load_spec."""

    def test_the_document_carries_the_pin_and_needs_the_keys_section(self):
        import host_setup as hs
        from test_hub_keys import full_doc
        d = full_doc()
        d[fk.SECTION] = {"path": "/opt/ex/fleet-keys.json", "sha256": "a" * 64}
        self.assertEqual(hs.load_spec(d).fleet_keys, fk.FleetKeysPin("/opt/ex/fleet-keys.json", "a" * 64))
        del d["keys"]
        with self.assertRaises(hs.SpecError) as cm:
            hs.load_spec(d)
        self.assertIn("needs a keys section", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
