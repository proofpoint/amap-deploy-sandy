"""a2_s6_d7: one loop VM's D7 file and prefix template. The rules are RE's at its ALPHA-2 pin, as RE measured them
from its hub link module (members exactly delivered_domains/sha256/attestation; the digest over the sorted domains,
one newline after each; the attestation's members, time shape and approved statement)."""

import hashlib
import json
import unittest

import a2fix  # noqa: F401  (puts install/ on sys.path)
import a2_s6_d7 as d7

OWN, OTHER = "vm1.internal", "vm2.internal"
RUN = "20261120T224500Z-0123abcd"


def render(**kw):
    args = dict(own_domain=OWN, other_domains=[OTHER], run_id=RUN)
    args.update(kw)
    return d7.d7(**args)


class D7Test(unittest.TestCase):

    def test_the_document_is_res_shape(self):
        doc = render()
        self.assertEqual(list(doc), ["delivered_domains", "sha256", "attestation"])
        self.assertEqual(doc["delivered_domains"], [OTHER])
        self.assertEqual(doc["sha256"], hashlib.sha256(b"vm2.internal\n").hexdigest())
        self.assertEqual(doc["attestation"], {"by": "the operator", "at": "2026-11-20T22:45:00Z",
                                              "statement": d7.STATEMENT})

    def test_the_statement_is_res_approved_text(self):
        self.assertEqual(hashlib.sha256(d7.STATEMENT.encode()).hexdigest(),
                         hashlib.sha256(b"the hub is inside the deployment and under the operator's control")
                         .hexdigest())

    def test_the_digest_sorts_and_ends_each_with_a_newline(self):
        self.assertEqual(d7.digest(["b.internal", "a.internal"]),
                         hashlib.sha256(b"a.internal\nb.internal\n").hexdigest())

    def test_two_others_are_sorted(self):
        doc = render(other_domains=["vm3.internal", OTHER])
        self.assertEqual(doc["delivered_domains"], [OTHER, "vm3.internal"])

    def test_bad_inputs_refuse(self):
        for kw in (dict(other_domains=[]), dict(other_domains=[OWN]), dict(other_domains=[OTHER, OTHER]), dict(other_domains=[1]),
                   dict(other_domains=["vm2.example.org"]),
                   dict(own_domain="vm1.example.org"), dict(run_id="20261120T224500Z"),
                   dict(run_id="2026-11-20T22:45:00Z-0123abcd")):
            with self.subTest(kw=kw), self.assertRaises(d7.D7Refused):
                render(**kw)

    def test_a_reserved_domain_refuses_by_its_pin(self):
        old = d7.RESERVED_SHA256
        self.addCleanup(setattr, d7, "RESERVED_SHA256", old)
        d7.RESERVED_SHA256 = old + (hashlib.sha256(b"vm3.internal").hexdigest(),)
        with self.assertRaises(d7.D7Refused):
            render(other_domains=["vm3.internal"])
        self.assertEqual(len(old), 2)

    def test_the_bytes_are_strict_json(self):
        doc = render()
        self.assertEqual(json.loads(d7.text(doc)), doc)


class CheckTest(unittest.TestCase):

    def good(self):
        return json.loads(d7.text(render()))

    def refused(self, doc):
        with self.assertRaises(d7.D7Refused):
            d7.check(json.dumps(doc).encode(), OWN)

    def test_the_rendered_bytes_pass(self):
        d7.check(d7.text(render()), OWN)

    def test_an_extra_or_missing_member_refuses(self):
        for change in ({"version": 1}, {"links": []}, {"hub": "x"}):
            doc = self.good()
            doc.update(change)
            self.refused(doc)
        doc = self.good()
        del doc["sha256"]
        self.refused(doc)

    def test_a_wrong_digest_refuses(self):
        doc = self.good()
        doc["sha256"] = d7.digest(["vm3.internal"])
        self.refused(doc)

    def test_the_own_domain_refuses(self):
        doc = self.good()
        doc["delivered_domains"] = [OWN]
        doc["sha256"] = d7.digest([OWN])
        self.refused(doc)

    def test_a_non_canonical_domain_refuses(self):
        for bad in ("VM2.internal", "vm2.internal.", " vm2.internal", "vm2.example.org"):
            doc = self.good()
            doc["delivered_domains"] = [bad]
            doc["sha256"] = d7.digest([bad])
            self.refused(doc)

    def test_the_attestation_rules(self):
        for change in ({"at": "2026-11-20T22:45:00.5Z"}, {"at": "2026-11-20 22:45:00Z"},
                       {"at": "2026-11-20T22:45:00+00:00"}, {"statement": d7.STATEMENT + "."}, {"by": "  "},
                       {"extra": "x"}):
            with self.subTest(change=change):
                doc = self.good()
                doc["attestation"].update(change)
                self.refused(doc)

    def test_size_and_encoding(self):
        raw = d7.text(render())
        d7.check(raw + b" " * (d7.D7_MAX_BYTES - len(raw)), OWN)
        with self.assertRaises(d7.D7Refused):
            d7.check(raw + b" " * (d7.D7_MAX_BYTES - len(raw) + 1), OWN)
        with self.assertRaises(d7.D7Refused):
            d7.check(b"\xff", OWN)
        with self.assertRaises(d7.D7Refused):
            d7.check(b"[]", OWN)


class PrefixTest(unittest.TestCase):

    def test_the_template_takes_both_names_as_given(self):
        self.assertEqual(d7.prefix(hub_fqdn="a2-hub-x.example.org", hub_short="hub-x"),
                         {"hub_fqdn": "a2-hub-x.example.org", "hub_short": "hub-x", "final": True})

    def test_a_bad_name_refuses(self):
        for kw in (dict(hub_fqdn="org"), dict(hub_fqdn="Hub.example.org"), dict(hub_fqdn="hub.example.org."),
                   dict(hub_fqdn=None), dict(hub_fqdn=("a" * 61 + ".") * 4 + "abcdef"), dict(hub_short="a.b"),
                   dict(hub_short="Hub"), dict(hub_short=""), dict(hub_short=None)):
            args = dict(hub_fqdn="hub.example.org", hub_short="hub")
            args.update(kw)
            with self.subTest(kw=kw), self.assertRaises(d7.D7Refused):
                d7.prefix(**args)

    def test_a_253_character_fqdn_passes(self):
        name = ("a" * 61 + ".") * 4 + "abcde"
        self.assertEqual(len(name), 253)
        self.assertEqual(d7.prefix(hub_fqdn=name, hub_short="hub")["hub_fqdn"], name)


if __name__ == "__main__":
    unittest.main()
