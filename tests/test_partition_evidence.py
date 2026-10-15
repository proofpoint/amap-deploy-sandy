"""partition_evidence: the document's canonical bytes, its strict parse, the
token that names it, its freshness against the current bindings, and the
verify checks over a placed document. The documents are built by
partition_evidence.build, the producer partition-probe uses, never by hand."""

import json
import os
import stat
import unittest

import partition_evidence as pe
import router_health as rh

HOST = "alpha"
AT = "2026-10-14T12:00:00Z"
NOW = pe.at_seconds(AT) + 3600
BINDINGS = {"host_setup": "a" * 64, "router_activation": "b" * 64}
SCRIPTS = {"P01": "c" * 64, "P02": "d" * 64, "P03": "e" * 64, "P04": "f" * 64, "verb": "0" * 64}


ROLES = {"P01": ["runtime:upstream", "runtime:downstream"], "P02": ["marker:up/identity.json"],
         "P03": ["key:signing", "key:dir", "mount:hop"], "P04": ["peer:alpha", "peer:beta"]}


def probe(pid, verdict="PASS"):
    """An entry as partition_probe writes one: a fail-stop PASS has outcome
    ENOENT and its witness ok; anything else names what it saw."""
    passing = verdict == "PASS"
    return {"id": pid, "vantage": [{"container": "ex-down", "image": "sha256:" + "a" * 64, "uid": 2102,
                                    "gids": [2102, 2200]}],
            "operation": "lstat", "target_role": list(ROLES[pid]),
            "outcome": "ENOENT" if passing else ("unresolved" if verdict == "UNKNOWN" else "ok"),
            "witness": {"operation": "open", "outcome": "ok"}, "verdict": verdict}


def build(**over):
    verdicts = over.pop("verdicts", {})
    args = dict(host=HOST, run_id="r1", at=AT, script_sha256=SCRIPTS, bindings=BINDINGS,
                probes=[probe(i, verdicts.get(i, "PASS")) for i in pe.PROBE_IDS])
    args.update(over)
    return pe.build(**args)


def resign(doc):
    """`doc` re-serialised canonically with its token recomputed: a document
    that is self-consistent but otherwise whatever the test made it."""
    doc = dict(doc)
    if doc[pe.TOKEN_MEMBER] is not None:
        doc[pe.TOKEN_MEMBER] = pe.token_of(doc)
    return pe.canonical(doc)


class TokenTest(unittest.TestCase):
    def test_both_fail_stop_probes_passing_gives_the_documents_own_token(self):
        doc = json.loads(build())
        self.assertEqual(doc[pe.TOKEN_MEMBER], pe.token_of(doc))
        self.assertTrue(doc[pe.TOKEN_MEMBER].startswith("r1:"))
        self.assertEqual(doc["fail_stop"], {"P03": "PASS", "P04": "PASS"})

    def test_the_token_hashes_the_canonical_bytes_with_the_token_null(self):
        raw = build()
        doc = json.loads(raw)
        expect = pe.sha_bytes(pe.canonical(dict(doc, **{pe.TOKEN_MEMBER: None})))
        self.assertEqual(doc[pe.TOKEN_MEMBER], "r1:" + expect)

    def test_any_fail_stop_probe_not_passing_leaves_no_token(self):
        for pid in pe.FAIL_STOP:
            for verdict in ("FAIL", "UNKNOWN"):
                with self.subTest(pid=pid, verdict=verdict):
                    try:
                        raw = build(verdicts={pid: verdict})
                    except pe.EvidenceError as e:
                        self.fail(f"build produced a document its own parse refuses: {e}")
                    self.assertIsNone(json.loads(raw)[pe.TOKEN_MEMBER])

    def test_p01_or_p02_failing_does_not_withhold_the_token(self):
        """P01 and P02 are probes, not fail-stop: their failure is reported
        and blocks nothing by itself."""
        doc = json.loads(build(verdicts={"P01": "FAIL", "P02": "FAIL"}))
        self.assertIsNotNone(doc[pe.TOKEN_MEMBER])

    def test_the_config_binding_ignores_only_partition_verified(self):
        cfg = {"state_dir": "/s", "delegation": {"partition_verified": "r1:x", "signing_key": {"path": "/k"}}}
        same = json.loads(json.dumps(cfg))
        same["delegation"]["partition_verified"] = "r2:y"
        self.assertEqual(pe.config_binding(cfg), pe.config_binding(same))
        other = json.loads(json.dumps(cfg))
        other["delegation"]["signing_key"]["path"] = "/k2"
        self.assertNotEqual(pe.config_binding(cfg), pe.config_binding(other))
        self.assertEqual(cfg["delegation"]["partition_verified"], "r1:x", "the caller's config is not changed")


class ParseTest(unittest.TestCase):
    def refuses(self, raw, words):
        with self.assertRaises(pe.EvidenceError) as e:
            pe.parse(raw, host=HOST)
        self.assertIn(words, str(e.exception))

    def test_a_built_document_parses(self):
        self.assertEqual(pe.parse(build(), host=HOST)["run_id"], "r1")

    def test_bytes_that_are_not_the_canonical_form_refuse(self):
        doc = json.loads(build())
        self.refuses(json.dumps(doc, indent=1).encode(), "canonical")
        self.refuses(build() + b"\n", "canonical")

    def test_duplicate_keys_and_non_finite_numbers_refuse(self):
        self.refuses(b'{"schema":1,"schema":2}', "twice")
        self.refuses(b'{"x":NaN}', "not JSON")

    def test_a_missing_or_extra_member_refuses(self):
        doc = json.loads(build())
        del doc["at"]
        self.refuses(pe.canonical(doc), "members")
        doc = json.loads(build())
        doc["extra"] = 1
        self.refuses(pe.canonical(doc), "members")

    def test_another_schema_refuses(self):
        doc = json.loads(build())
        doc["schema"] = "amap-deploy.partition-evidence/0"
        self.refuses(resign(doc), "schema")

    def test_another_hosts_document_refuses(self):
        with self.assertRaises(pe.EvidenceError) as e:
            pe.parse(build(), host="beta")
        self.assertIn("for host 'alpha'", str(e.exception))

    def test_the_probe_set_is_exactly_p01_to_p04(self):
        doc = json.loads(build())
        doc["probes"] = doc["probes"][:3]
        self.refuses(resign(doc), "exactly P01")

    def test_a_fail_stop_summary_that_disagrees_with_the_probes_refuses(self):
        doc = json.loads(build(verdicts={"P04": "FAIL"}))
        doc["fail_stop"]["P04"] = "PASS"
        self.refuses(pe.canonical(doc), "fail_stop")

    def test_a_token_that_is_not_the_documents_own_refuses(self):
        doc = json.loads(build())
        doc[pe.TOKEN_MEMBER] = "r1:" + "0" * 64
        self.refuses(pe.canonical(doc), "not this document's")

    def test_a_token_beside_a_failing_fail_stop_probe_refuses(self):
        doc = json.loads(build(verdicts={"P03": "FAIL"}))
        doc[pe.TOKEN_MEMBER] = pe.token_of(doc)
        self.refuses(pe.canonical(doc), "did not pass")

    def test_a_binding_that_is_not_hex_refuses(self):
        with self.assertRaises(pe.EvidenceError):
            build(bindings={"host_setup": "A" * 64})


class ProbeShapeTest(unittest.TestCase):
    """Every probe member has its declared type and shape, and a fail-stop
    PASS is only one its entry supports. Each row breaks one thing in an
    otherwise healthy document, re-signed so only that thing is wrong."""

    def refuses(self, edit, words):
        """Refused as malformed evidence: any other exception is a failure
        here, since verify catches only EvidenceError."""
        doc = json.loads(build())
        edit(doc)
        try:
            pe.parse(resign(doc), host=HOST)
        except pe.EvidenceError as e:
            self.assertIn(words, str(e))
        except Exception as e:  # noqa: BLE001 -- the point of the test
            self.fail(f"refused by {type(e).__name__}, not as malformed evidence: {e}")
        else:
            self.fail("accepted")

    def p(self, doc, pid):
        return next(x for x in doc["probes"] if x["id"] == pid)

    def test_the_healthy_document_parses(self):
        self.assertEqual([x["id"] for x in pe.parse(build(), host=HOST)["probes"]], list(pe.PROBE_IDS))

    def test_wrong_types_refuse(self):
        rows = [("operation", 42, "operation"), ("operation", "", "operation"), ("vantage", None, "vantage"),
                ("vantage", [], "vantage"), ("vantage", [{"container": "x"}], "vantage"),
                ("outcome", [], "outcome"), ("outcome", "maybe", "outcome"), ("witness", "not-a-witness", "witness"),
                ("witness", {"operation": "open"}, "witness"), ("target_role", "key:signing", "target_role"),
                ("target_role", ["/opt/ex/keys"], "target_role"), ("target_role", ["key:dir", "key:dir"], "repeat a role"),
                ("target_role", [{}], "typed roles"), ("target_role", [[]], "typed roles"),
                ("target_role", ["runtime:upstream", {}], "typed roles")]
        # On P01, which is not fail-stop, so only the type check can refuse.
        for member, value, words in rows:
            with self.subTest(member=member, value=value):
                self.refuses(lambda d, m=member, v=value: self.p(d, "P01").__setitem__(m, v), words)

    def test_a_vantage_uid_that_is_not_an_integer_refuses(self):
        self.refuses(lambda d: self.p(d, "P01")["vantage"][0].__setitem__("uid", True), "vantage")

    def test_a_fail_stop_pass_with_outcome_ok_refuses(self):
        self.refuses(lambda d: self.p(d, "P03").__setitem__("outcome", "ok"), "outcome ENOENT")
        self.refuses(lambda d: self.p(d, "P04").__setitem__("outcome", "ok"), "outcome ENOENT")

    def test_a_fail_stop_pass_without_its_witness_refuses(self):
        self.refuses(lambda d: self.p(d, "P03")["witness"].__setitem__("outcome", "ENOENT"), "witness ok")

    def test_p03_must_cover_the_key_and_its_directory(self):
        self.refuses(lambda d: self.p(d, "P03").__setitem__("target_role", ["key:signing"]), "do not cover")

    def test_p04_roles_are_lanes_only(self):
        self.refuses(lambda d: self.p(d, "P04").__setitem__("target_role", ["peer:alpha", "key:dir"]), "lanes")

    def test_an_impossible_timestamp_refuses(self):
        for at in ("2026-99-99T25:61:61Z", "2026-02-30T00:00:00Z"):
            with self.subTest(at=at):
                self.refuses(lambda d, at=at: d.__setitem__("at", at), "not a real UTC time")


class StalenessTest(unittest.TestCase):
    def test_a_fresh_passing_document_with_current_bindings_counts(self):
        self.assertEqual(pe.staleness(pe.parse(build(), host=HOST), now=NOW, bindings=BINDINGS), [])

    def test_a_week_plus_the_grace_counts_and_a_second_more_does_not(self):
        doc = pe.parse(build(), host=HOST)
        start = pe.at_seconds(AT)
        self.assertEqual(pe.staleness(doc, now=start + pe.FRESH_FOR_S, bindings=BINDINGS), [])
        why = pe.staleness(doc, now=start + pe.FRESH_FOR_S + 1, bindings=BINDINGS)
        self.assertTrue(any("24-hour grace" in w for w in why), why)
        self.assertEqual(pe.FRESH_FOR_S, 8 * 86400, "a week plus a 24-hour grace")

    def test_a_document_from_the_future_does_not_count(self):
        doc = pe.parse(build(), host=HOST)
        why = pe.staleness(doc, now=pe.at_seconds(AT) - pe.CLOCK_TOLERANCE_S - 1, bindings=BINDINGS)
        self.assertTrue(any("future" in w for w in why), why)

    def test_a_changed_binding_voids_it_at_once(self):
        doc = pe.parse(build(), host=HOST)
        why = pe.staleness(doc, now=NOW, bindings=dict(BINDINGS, router_activation="9" * 64))
        self.assertEqual(why, ["router_activation has changed since the run"])

    def test_a_different_binding_set_voids_it(self):
        doc = pe.parse(build(), host=HOST)
        why = pe.staleness(doc, now=NOW, bindings=dict(BINDINGS, extra="1" * 64))
        self.assertEqual(len(why), 1, why)
        self.assertIn("it binds", why[0])

    def test_roles_that_are_not_todays_targets_void_it(self):
        doc = pe.parse(build(), host=HOST)
        self.assertEqual(pe.staleness(doc, now=NOW, bindings=BINDINGS, roles=TODAY), [])
        why = pe.staleness(doc, now=NOW, bindings=BINDINGS, roles=dict(TODAY, P04=["peer:alpha", "peer:beta", "peer:gamma"]))
        self.assertEqual(len(why), 1, why)
        self.assertIn("P04 targeted", why[0])

    def test_a_missing_fail_stop_role_set_is_stale_never_unchecked(self):
        doc = pe.parse(build(), host=HOST)
        why = pe.staleness(doc, now=NOW, bindings=BINDINGS, roles={"P04": ["peer:alpha", "peer:beta"]})
        self.assertEqual(why, ["today's roles for P03 were not given, so the document cannot be held to them"])

    def test_a_document_without_a_token_never_counts(self):
        doc = pe.parse(build(verdicts={"P04": "FAIL"}), host=HOST)
        self.assertIn("its fail-stop probes did not both pass", pe.staleness(doc, now=NOW, bindings=BINDINGS))


TODAY = {"P03": ROLES["P03"], "P04": ROLES["P04"]}


def st(mode, uid=0, gid=0, nlink=1):
    return os.stat_result((mode, 0, 0, nlink, uid, gid, 0, 0, 0, 0))


class VerifyDocumentTest(unittest.TestCase):
    PATH = "/opt/ev/partition-r1.json"

    def setUp(self):
        self.files = {"/": st(stat.S_IFDIR | 0o755), "/opt": st(stat.S_IFDIR | 0o755),
                      "/opt/ev": st(stat.S_IFDIR | 0o755), self.PATH: st(stat.S_IFREG | 0o444)}
        self.raw = build()

    def lstat(self, p):
        if p not in self.files:
            raise FileNotFoundError(p)
        return self.files[p]

    def run_it(self, live="token", now=NOW, bindings=BINDINGS):
        token = json.loads(self.raw)[pe.TOKEN_MEMBER]
        return pe.verify_document(self.PATH, host=HOST, now=now, bindings=bindings,
                                  live_token=token if live == "token" else live, roles=TODAY, lstat=self.lstat,
                                  read=lambda p: self.raw)

    def claim(self, found, words):
        hits = [c for c in found if words in c.claim]
        self.assertEqual(len(hits), 1, [c.claim for c in found])
        return hits[0]

    def test_a_good_document_and_a_router_signing_with_its_token_pass(self):
        found = self.run_it()
        self.assertEqual([(c.claim, c.result) for c in found if c.result != rh.PASS], [])

    def test_a_router_not_signing_passes_the_token_check(self):
        self.assertEqual(self.claim(self.run_it(live=None), "signs with").result, rh.PASS)

    def test_a_router_signing_with_another_token_fails(self):
        self.assertEqual(self.claim(self.run_it(live="r0:" + "1" * 64), "signs with").result, rh.FAIL)

    def test_a_router_signing_on_a_stale_document_fails(self):
        found = self.run_it(now=pe.at_seconds(AT) + pe.FRESH_FOR_S + 1)
        self.assertEqual(self.claim(found, "current and passing").result, rh.FAIL)
        self.assertEqual(self.claim(found, "signs with").result, rh.FAIL)

    def test_an_unaskable_router_is_unknown(self):
        found = self.run_it(live=rh.Unresolved("docker exec exited 1"))
        self.assertEqual(self.claim(found, "signs with").result, rh.UNKNOWN)

    def test_a_document_not_placed_by_root_fails(self):
        self.files[self.PATH] = st(stat.S_IFREG | 0o644, uid=501)
        self.assertEqual(self.claim(self.run_it(), "root:root 0444").result, rh.FAIL)

    def test_a_writable_parent_fails(self):
        self.files["/opt/ev"] = st(stat.S_IFDIR | 0o777)
        self.assertEqual(self.claim(self.run_it(), "every directory above").result, rh.FAIL)

    def test_a_malformed_document_fails_and_never_edits(self):
        self.raw = self.raw + b" "
        c = self.claim(self.run_it(live=None), "current and passing")
        self.assertEqual(c.result, rh.FAIL)
        self.assertIn("never edit", c.do_not)

    def test_an_impossible_timestamp_is_a_malformed_fail_never_a_crash(self):
        doc = json.loads(self.raw)
        doc["at"] = "2026-99-99T25:61:61Z"
        self.raw = resign(doc)
        c = self.claim(self.run_it(live=None), "current and passing")
        self.assertEqual(c.result, rh.FAIL)
        self.assertIn("not a real UTC time", str(c.actual))

    def test_an_absent_document_is_unknown(self):
        def gone(p):
            raise FileNotFoundError(p)
        found = pe.verify_document(self.PATH, host=HOST, now=NOW, bindings=BINDINGS, live_token=None,
                                   roles=TODAY, lstat=self.lstat, read=gone)
        self.assertEqual(self.claim(found, "current and passing").result, rh.UNKNOWN)

    def test_an_unhashable_role_is_a_malformed_fail_never_an_exception(self):
        doc = json.loads(self.raw)
        next(p for p in doc["probes"] if p["id"] == "P01")["target_role"] = [{}]
        self.raw = resign(doc)
        try:
            found = self.run_it(live="run1:" + "a" * 64)
        except Exception as e:  # noqa: BLE001 -- verify must report, never raise
            self.fail(f"verify raised {type(e).__name__}: {e}")
        self.assertEqual(self.claim(found, "current and passing").result, rh.FAIL)
        self.assertEqual(self.claim(found, "signs with").result, rh.FAIL)
        doc = json.loads(build())
        self.raw = resign(doc)
        self.assertEqual(self.claim(self.run_it(), "current and passing").result, rh.PASS, "the valid companion")

    def test_a_signing_router_without_a_readable_passing_document_fails_on_every_path(self):
        """The token claim is made on every path: absent, unreadable and
        malformed evidence each leave no current token, so a live one FAILs
        with the remedy that stops the signing."""
        def gone(p):
            raise FileNotFoundError(p)

        def unreadable(p):
            raise PermissionError(p)
        reads = {"absent": gone, "unreadable": unreadable, "malformed": lambda p: b"{}"}
        for name, read in reads.items():
            with self.subTest(path=name):
                found = pe.verify_document(self.PATH, host=HOST, now=NOW, bindings=BINDINGS,
                                           live_token="run1:" + "a" * 64, roles=TODAY, lstat=self.lstat, read=read)
                c = self.claim(found, "signs with")
                self.assertEqual(c.result, rh.FAIL)
                self.assertIn("without delegation", c.remedy)
                found = pe.verify_document(self.PATH, host=HOST, now=NOW, bindings=BINDINGS, live_token=None,
                                           roles=TODAY, lstat=self.lstat, read=read)
                self.assertEqual(self.claim(found, "signs with").result, rh.PASS)


class ReadProtectedTest(unittest.TestCase):
    def test_the_bytes_come_from_the_descriptor_that_was_checked(self):
        """One open: the fd that passed the fstat check is the one read."""
        import tempfile
        import unittest.mock as um
        opened = []
        real_open = os.open

        def counting(*a, **k):
            opened.append(a[0])
            return real_open(*a, **k)
        fake = os.stat_result((0o100444, 0, 0, 1, 0, 0, 2, 0, 0, 0))
        with tempfile.TemporaryDirectory() as t:
            f = os.path.join(t, "e.json")
            with open(f, "wb") as fh:
                fh.write(b"{}")
            with um.patch.object(pe.os, "open", counting), um.patch.object(pe.os, "fstat", lambda fd: fake):
                self.assertEqual(pe.read_placed(f), b"{}")
        self.assertEqual(opened, [f])

    def test_the_opened_file_must_itself_be_root_0444_with_one_link(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            f = os.path.join(t, "e.json")
            with open(f, "wb") as fh:
                fh.write(b"{}")
            os.chmod(f, 0o444)
            if os.geteuid() == 0:
                self.skipTest("root owns what it writes")
            with self.assertRaises(OSError) as e:
                pe.read_placed(f)
            self.assertIn("as opened", str(e.exception))

    def test_a_symbolic_link_is_never_followed(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            real = os.path.join(t, "real.json")
            with open(real, "wb") as f:
                f.write(b"{}")
            link = os.path.join(t, "link.json")
            os.symlink(real, link)
            self.assertEqual(pe.read_protected(real), b"{}")
            with self.assertRaises(OSError):
                pe.read_protected(link)


if __name__ == "__main__":
    unittest.main()
