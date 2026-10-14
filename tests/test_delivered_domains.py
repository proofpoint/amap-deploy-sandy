"""delivered_domains: the D7 render, the deployed file's rules, and verify.

Every value is synthetic. The source shape is the producer's version 1 as
its generator writes it (json.dumps(indent=2) + "\\n", insertion order), and
the deployed shape is the one both hub-link readers accept.
"""

import hashlib
import json
import os
import stat
import unittest
from types import SimpleNamespace

import delivered_domains as dd
import router_health as rh

STATEMENT = "an approved statement, synthetic"
RULES = dd.Rules(host_label="alpha", own_domain="alpha.internal",
                 excluded=("probe-x.internal", "logins.internal"), statement=STATEMENT,
                 fleet_hosts=("beta.internal", "gamma.internal"))
ATT = {"by": "an operator", "at": "2026-10-14T00:00:00Z", "statement": STATEMENT}


def sha(domains):
    return hashlib.sha256("".join(d + "\n" for d in sorted(domains)).encode()).hexdigest()


def link(host="alpha", domains=("beta.internal", "gamma.internal"), digest=None, att=None, hub="hub.example"):
    return {"host": host, "hub": hub, "delivered_domains": list(domains),
            "delivered_domains_sha256": sha(domains) if digest is None else digest,
            "attestation": dict(ATT if att is None else att)}


def source(links=None, attested=True, version=1, hub="hub.example", **extra):
    doc = {"version": version, "hub": hub, "attested": attested,
           "host_domains": {"alpha": ["alpha.internal"], "beta": ["beta.internal"]},
           "links": [link()] if links is None else links}
    doc.update(extra)
    return (json.dumps(doc, indent=2) + "\n").encode()


class RenderTest(unittest.TestCase):
    def test_an_attested_link_renders_compact_sorted_bytes(self):
        out = dd.render(source(), RULES)
        self.assertEqual(out, (json.dumps({"attestation": ATT, "delivered_domains": ["beta.internal", "gamma.internal"],
                                           "sha256": sha(["beta.internal", "gamma.internal"])},
                                          sort_keys=True, separators=(",", ":")) + "\n").encode())

    def test_two_renders_of_one_link_are_byte_identical_whatever_the_source_order(self):
        a = dd.render(source(links=[link(domains=("gamma.internal", "beta.internal"))]), RULES)
        b = dd.render(source(), RULES)
        self.assertEqual(a, b)

    def test_the_hash_member_is_renamed_and_host_and_hub_are_dropped(self):
        doc = json.loads(dd.render(source(), RULES))
        self.assertEqual(set(doc), {"delivered_domains", "sha256", "attestation"})

    def test_an_unattested_source_renders_nothing(self):
        out = dd.render(source(attested=False, links=[]), RULES)
        self.assertIsInstance(out, dd.NotAttested)

    def test_an_unattested_source_with_a_link_for_this_host_still_renders_nothing(self):
        out = dd.render(source(attested=False), RULES)
        self.assertIsInstance(out, dd.NotAttested)
        self.assertIn("not attested", out.reason)

    def test_no_link_for_this_host_renders_nothing(self):
        out = dd.render(source(links=[link(host="beta")]), RULES)
        self.assertIsInstance(out, dd.NotAttested)

    def test_two_links_for_this_host_refuse(self):
        with self.assertRaises(dd.D7Error) as e:
            dd.render(source(links=[link(), link()]), RULES)
        self.assertEqual(e.exception.rule, "links")

    def refuses(self, raw, rule):
        with self.assertRaises(dd.D7Error) as e:
            dd.render(raw, RULES)
        self.assertEqual(e.exception.rule, rule, str(e.exception))

    def test_another_version_refuses(self):
        self.refuses(source(version=2), "version")

    def test_a_boolean_version_refuses(self):
        self.refuses(source(version=True), "version")

    def test_an_unknown_top_level_member_refuses(self):
        self.refuses(source(extra="x"), "shape")

    def test_an_unknown_link_member_refuses(self):
        bad = link()
        bad["note"] = "x"
        self.refuses(source(links=[bad]), "shape")

    def test_a_link_naming_another_hub_refuses(self):
        self.refuses(source(links=[link(hub="other.example")]), "shape")

    def test_a_duplicate_key_refuses(self):
        raw = source().replace(b'"version": 1,', b'"version": 1, "version": 1,')
        self.refuses(raw, "duplicate_key")

    def test_nan_refuses(self):
        self.refuses(source().replace(b'"version": 1', b'"version": NaN'), "not_json")

    def test_an_oversized_source_refuses(self):
        self.refuses(b" " * (dd.MAX_BYTES + 1), "size")

    def test_an_upper_case_domain_refuses_and_is_never_lowered(self):
        domains = ("Beta.internal", "gamma.internal")
        self.refuses(source(links=[link(domains=domains)]), "domains")

    def test_a_two_label_domain_refuses(self):
        self.refuses(source(links=[link(domains=("a.beta.internal", "gamma.internal"))]), "domains")

    def test_the_own_domain_refuses(self):
        self.refuses(source(links=[link(domains=("alpha.internal", "beta.internal"))]), "domains")

    def test_an_excluded_domain_refuses(self):
        self.refuses(source(links=[link(domains=("probe-x.internal", "beta.internal"))]), "domains")

    def test_a_duplicate_domain_refuses(self):
        self.refuses(source(links=[link(domains=("beta.internal", "beta.internal"))]), "domains")

    def test_an_empty_domain_list_refuses(self):
        self.refuses(source(links=[link(domains=())]), "domains")

    def test_a_wrong_hash_refuses(self):
        self.refuses(source(links=[link(digest="0" * 64)]), "hash")

    def test_an_upper_case_hash_refuses(self):
        self.refuses(source(links=[link(digest=sha(["beta.internal", "gamma.internal"]).upper())]), "hash")

    def test_a_reworded_statement_refuses(self):
        self.refuses(source(links=[link(att=dict(ATT, statement=STATEMENT + "."))]), "attestation")

    def test_a_blank_attestation_member_refuses(self):
        self.refuses(source(links=[link(att=dict(ATT, by="  "))]), "attestation")

    def test_a_bad_at_refuses(self):
        self.refuses(source(links=[link(att=dict(ATT, at="2026-10-14 00:00:00"))]), "attestation")

    def test_an_extra_attestation_member_refuses(self):
        self.refuses(source(links=[link(att=dict(ATT, note="x"))]), "shape")

    def test_a_set_that_differs_from_the_fleet_hosts_refuses(self):
        rules = dd.Rules(**dict(RULES.__dict__, fleet_hosts=("beta.internal",)))
        with self.assertRaises(dd.D7Error) as e:
            dd.render(source(), rules)
        self.assertEqual(e.exception.rule, "fleet")


class DeployedTest(unittest.TestCase):
    def test_a_rendered_file_parses_back(self):
        doc = dd.parse_deployed(dd.render(source(), RULES), RULES)
        self.assertEqual(doc["delivered_domains"], ["beta.internal", "gamma.internal"])

    def test_a_hand_edited_list_with_a_stale_hash_refuses(self):
        doc = json.loads(dd.render(source(), RULES))
        doc["delivered_domains"] = ["beta.internal"]
        with self.assertRaises(dd.D7Error) as e:
            dd.parse_deployed(json.dumps(doc).encode(), RULES)
        self.assertEqual(e.exception.rule, "hash")

    def test_a_deployed_file_carrying_host_refuses(self):
        doc = json.loads(dd.render(source(), RULES))
        doc["host"] = "alpha"
        with self.assertRaises(dd.D7Error) as e:
            dd.parse_deployed(json.dumps(doc).encode(), RULES)
        self.assertEqual(e.exception.rule, "shape")


def st(mode, uid=0, gid=0, nlink=1):
    return SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid, st_nlink=nlink)


DIR = stat.S_IFDIR | 0o755
REG = stat.S_IFREG | 0o444


class VerifyTest(unittest.TestCase):
    def setUp(self):
        self.files = {"/": st(DIR), "/opt": st(DIR), "/opt/d7": st(DIR), "/opt/d7/d7.json": st(REG)}
        self.bytes = {"/opt/d7/d7.json": dd.render(source(), RULES)}
        self.entries = ["d7.json"]

    def lstat(self, p):
        if p not in self.files:
            raise FileNotFoundError(p)
        return self.files[p]

    def read(self, p):
        if p not in self.bytes:
            raise FileNotFoundError(p)
        return self.bytes[p]

    def run_verify(self, src=None):
        return dd.verify("/opt/d7", "d7.json", RULES, source() if src is None else src, lstat=self.lstat,
                         listdir=lambda d: list(self.entries), read=self.read)

    def by_claim(self, found, words):
        hits = [c for c in found if words in c.claim]
        self.assertEqual(len(hits), 1, [c.claim for c in found])
        return hits[0]

    def test_a_correct_host_passes_every_check(self):
        found = self.run_verify()
        self.assertTrue(found)
        self.assertEqual([c.claim for c in found if c.result != rh.PASS], [])

    def test_a_group_writable_file_fails_its_mode_check(self):
        self.files["/opt/d7/d7.json"] = st(stat.S_IFREG | 0o464)
        self.assertEqual(self.by_claim(self.run_verify(), "root:root 0444").result, rh.FAIL)

    def test_a_second_entry_fails_the_directory_check(self):
        self.entries.append("other")
        self.assertEqual(self.by_claim(self.run_verify(), "holds only").result, rh.FAIL)

    def test_place_s_temp_file_is_a_note_not_a_failure(self):
        self.entries.append(".d7.json.4242.tmp")
        self.assertEqual(self.by_claim(self.run_verify(), "holds only").result, rh.PASS)
        self.assertEqual(len(dd.notes("/opt/d7", "d7.json", listdir=lambda d: list(self.entries))), 1)

    def test_a_writable_ancestor_fails(self):
        self.files["/opt"] = st(stat.S_IFDIR | 0o777)
        self.assertEqual(self.by_claim(self.run_verify(), "every directory above").result, rh.FAIL)

    def test_a_deployed_file_that_differs_from_the_render_fails_the_byte_compare(self):
        other = source(links=[link(att=dict(ATT, by="someone else"))])
        self.bytes["/opt/d7/d7.json"] = dd.render(other, RULES)
        found = self.run_verify()
        self.assertEqual(self.by_claim(found, "byte-identical").result, rh.FAIL)
        self.assertEqual(self.by_claim(found, "carries the source").result, rh.FAIL)

    def test_a_withdrawn_attestation_fails_and_says_so(self):
        found = self.run_verify(src=source(attested=False, links=[]))
        c = self.by_claim(found, "byte-identical")
        self.assertEqual(c.result, rh.FAIL)
        self.assertIn("no longer attests", str(c.actual))

    def test_an_unreadable_source_is_unknown_never_pass(self):
        c = self.by_claim(self.run_verify(src=rh.Unresolved("no clone")), "byte-identical")
        self.assertEqual(c.result, rh.UNKNOWN)

    def test_an_absent_file_fails(self):
        del self.files["/opt/d7/d7.json"]
        del self.bytes["/opt/d7/d7.json"]
        self.assertEqual(self.by_claim(self.run_verify(), "meets the hub-link").result, rh.FAIL)


if __name__ == "__main__":
    unittest.main()
