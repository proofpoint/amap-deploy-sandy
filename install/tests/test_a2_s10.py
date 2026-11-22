"""S10 and the eligibility rule (5.4, 5.5) on run records built with the
real record writer: a complete eligible install, then one break per rule."""

import json
import os
import shutil
import unittest

import a2fix
import a2_guard
import a2_record
import a2_rundir
import a2_s10

RID = "20261116T000000Z-0000e1e1"
SHA = "c" * 64


class Rec(unittest.TestCase):
    """A run record for an install whose loop is null, run as the L3
    account (scope l3: one VM, vm-a), with every stage S0 to S10."""

    def setUp(self):
        self.base = a2fix.make_base()
        self.addCleanup(shutil.rmtree, self.base, True)
        self.w = a2fix.World(self.base)
        self.hosts_raw = a2fix.dumps(self.w.hosts)
        import hashlib
        self.hosts_sha = hashlib.sha256(self.hosts_raw).hexdigest()
        self.run_fd = a2_rundir.create_run_dir(self.w.home, RID, os.getuid())
        self.addCleanup(os.close, self.run_fd)
        self.dir = os.path.join(self.w.home, "alpha2-work", "runs", RID)

    def build(self, command="install", loop=None, skip=(), fail=None, result=None, extra=None,
              hosts_sha=None, summary=True):
        run = a2_record.Run(self.run_fd, a2_guard.OutputGuard(), RID, command, loop, SHA, a2fix.H64,
                            hosts_sha or self.hosts_sha)
        self.addCleanup(run.close)
        run.write_manifest(final=False)
        for sid, host in a2_s10.expected_receipts(self.w.hosts, "l3"):
            if (sid, host) in skip:
                continue
            facts = list((extra or {}).get(sid, []))
            if sid == "S9":
                facts.append(("PROCESSING_PROOF", "pass"))
            if fail == sid:
                cause = a2_record.STAGE_NAME[sid] + ".UNCLASSIFIED"
                run.write_receipt(sid, host, "2026-11-16T00:00:00Z", "FAIL", facts, rc=3, cause=cause)
            else:
                run.write_receipt(sid, host, "2026-11-16T00:00:00Z", (result or {}).get(sid, "PASS"), facts)
        run.write_manifest(final=True)
        if summary:
            data = b"RESULT PASS\nELIGIBLE\n"
            a2_record._write_atomic(self.run_fd, a2_record.SUMMARY, data)
            run._append_sums(a2_record.SUMMARY, data)
        return run

    def eligible(self, **kw):
        return a2_s10.eligibility(self.run_fd, self.hosts_raw, **kw)


class EligibilityTest(Rec):
    def test_a_complete_install_is_eligible(self):
        self.build()
        self.assertEqual(self.eligible(), (True, ""))
        a2_record.verify_sums(self.run_fd)

    def test_l3_loop_is_eligible_too(self):
        self.build(loop="L3")
        self.assertEqual(self.eligible(), (True, ""))

    def test_each_rule(self):
        cases = [
            ("dry-run", dict(command="dry-run")),
            ("L2", dict(loop="L2")),
            ("L2-leak", dict(loop="L2-leak")),
            ("missing S4 vm-a", dict(skip=[("S4", "vm-a")])),
            ("failed S5", dict(fail="S5")),
            ("PLANNED result", dict(result={"S6": "PLANNED"})),
            ("UNOBSERVED fact", dict(extra={"S3": [("CUSTODY_PLACEMENT", "UNOBSERVED")]})),
            ("no summary", dict(summary=False)),
        ]
        for label, kw in cases:
            with self.subTest(label=label):
                for n in os.listdir(self.dir):
                    p = os.path.join(self.dir, n)
                    shutil.rmtree(p) if os.path.isdir(p) else os.unlink(p)
                os.mkdir(os.path.join(self.dir, "receipts"), 0o700)
                self.build(**kw)
                ok, reason = self.eligible()
                self.assertFalse(ok, label)
                self.assertTrue(reason)

    def rechain(self, entries):
        import hashlib
        prev, out = "0" * 64, ""
        for n, (path, digest) in enumerate(entries, 1):
            ln = "%d %s %s %s\n" % (n, digest, prev, path)
            out += ln
            prev = hashlib.sha256(ln.encode()).hexdigest()
        p = os.path.join(self.dir, "SUMS")
        os.chmod(p, 0o600)
        with open(p, "w") as f:
            f.write(out)

    def entries(self):
        with open(os.path.join(self.dir, "SUMS")) as f:
            return [(ln.split(" ")[3].rstrip("\n"), ln.split(" ")[1]) for ln in f]

    def rewrite_manifest(self, edit):
        import hashlib
        p = os.path.join(self.dir, "manifest.json")
        with open(p) as f:
            man = json.load(f)
        edit(man)
        data = (json.dumps(man, indent=1) + "\n").encode()
        os.chmod(p, 0o600)
        with open(p, "wb") as f:
            f.write(data)
        e = [(path, hashlib.sha256(data).hexdigest() if path == "manifest.json" else d)
             for path, d in self.entries()]
        self.rechain(e)

    def test_a_broken_chain_is_not_eligible(self):
        self.build()
        with open(os.path.join(self.dir, "receipts", "S3--.txt"), "ab") as f:
            f.write(b"X")
        self.assertEqual(self.eligible(), (False, "SUMS does not verify"))

    def test_summary_must_be_last(self):
        """A valid chain whose last two lines are summary then manifest."""
        self.build()
        e = self.entries()
        self.rechain(e[:-2] + [e[-1], e[-2]])
        a2_record.verify_sums(self.run_fd)
        self.assertEqual(self.eligible(), (False, "SUMS does not end with the manifest and the summary"))

    def test_manifest_stage_order_must_be_the_sums_order(self):
        self.build()

        def swap(man):
            man["stages"][1], man["stages"][2] = man["stages"][2], man["stages"][1]
        self.rewrite_manifest(swap)
        a2_record.verify_sums(self.run_fd)
        self.assertEqual(self.eligible(), (False, "the receipt lines are not the manifest's stages"))

    def test_a_nonzero_rc_in_the_manifest(self):
        self.build()

        def rc3(man):
            man["stages"][3]["rc"] = 3
        self.rewrite_manifest(rc3)
        ok, reason = self.eligible()
        self.assertEqual((ok, reason.split(":")[0]), (False, "a stage did not pass"))

    def test_another_hosts_file_is_refused(self):
        self.build()
        h = dict(self.w.hosts)
        h["hub"] = {"name": "hub", "domain": "other.example.org"}
        ok, reason = a2_s10.eligibility(self.run_fd, a2fix.dumps(h))
        self.assertEqual((ok, reason), (False, "the hosts file is not the one this run read"))

    def test_s9_without_the_processing_proof(self):
        run = a2_record.Run(self.run_fd, a2_guard.OutputGuard(), RID, "install", None, SHA, a2fix.H64,
                            self.hosts_sha)
        self.addCleanup(run.close)
        run.write_manifest(final=False)
        for sid, host in a2_s10.expected_receipts(self.w.hosts, "l3"):
            run.write_receipt(sid, host, "2026-11-16T00:00:00Z", "PASS", [])
        run.write_manifest(final=True)
        data = b"x\n"
        a2_record._write_atomic(self.run_fd, a2_record.SUMMARY, data)
        run._append_sums(a2_record.SUMMARY, data)
        self.assertEqual(self.eligible(), (False, "S9 has no processing proof"))

    def test_the_manifests_stages_must_be_the_sums_receipt_lines(self):
        self.build()
        p = os.path.join(self.dir, "manifest.json")
        with open(p) as f:
            man = json.load(f)
        man["stages"] = man["stages"][1:]
        os.chmod(p, 0o600)
        with open(p, "w") as f:
            json.dump(man, f)
        ok, reason = self.eligible()
        self.assertFalse(ok)

    def test_expected_receipts_table(self):
        exp = a2_s10.expected_receipts(self.w.hosts, "loop")
        self.assertIn(("S2", "vm-a-t"), exp)
        self.assertIn(("S2", "vm-b-t"), exp)
        self.assertIn(("S3", None), exp)
        self.assertNotIn(("S2", "vm-a"), exp)
        self.assertEqual([s for s, _ in exp][0], "S0")
        self.assertEqual([s for s, _ in exp][-1], "S10")


class RuleByRuleTest(Rec):
    """One test per eligibility rule. Each break keeps SUMS verifying (the
    chain is rebuilt) so that only the rule under test can fail, and the
    reason string is asserted."""

    def setUp(self):
        super().setUp()
        self.build()
        self.assertEqual(self.eligible(), (True, ""))

    def entries(self):
        with open(os.path.join(self.dir, "SUMS")) as f:
            return [(ln.split(" ")[3].rstrip("\n"), ln.split(" ")[1]) for ln in f]

    def rechain(self, entries):
        import hashlib
        prev, out = "0" * 64, ""
        for n, (path, digest) in enumerate(entries, 1):
            ln = "%d %s %s %s\n" % (n, digest, prev, path)
            out += ln
            prev = hashlib.sha256(ln.encode()).hexdigest()
        p = os.path.join(self.dir, "SUMS")
        os.chmod(p, 0o600)
        with open(p, "w") as f:
            f.write(out)

    def put(self, rel, data):
        import hashlib
        p = os.path.join(self.dir, rel)
        os.chmod(p, 0o600)
        with open(p, "wb") as f:
            f.write(data)
        return hashlib.sha256(data).hexdigest()

    def manifest(self):
        with open(os.path.join(self.dir, "manifest.json")) as f:
            return json.load(f)

    def set_manifest(self, man, digests=None):
        """Write the manifest and rebuild SUMS so it verifies."""
        digests = dict(digests or {})
        digests["manifest.json"] = self.put("manifest.json", (json.dumps(man, indent=1) + "\n").encode())
        self.rechain([(p, digests.get(p, d)) for p, d in self.entries()])

    def edit_manifest(self, edit):
        man = self.manifest()
        edit(man)
        self.set_manifest(man)

    def replace_receipt(self, sid, host, transform, fix_manifest_sha=True):
        """Rewrite one receipt's bytes; the manifest row's sha follows, and
        SUMS is rebuilt, so only the receipt's content differs."""
        rel = "receipts/" + a2_record.receipt_name(sid, host)
        with open(os.path.join(self.dir, rel), "rb") as f:
            data = transform(f.read())
        d = self.put(rel, data)
        man = self.manifest()
        if fix_manifest_sha:
            for st in man["stages"]:
                if st["receipt"] == rel:
                    st["sha256"] = d
        self.set_manifest(man, {rel: d})

    def reason(self):
        ok, why = self.eligible()
        self.assertFalse(ok)
        return why

    # -- the manifest's schema (6.3)
    def test_manifest_schema_rules(self):
        cases = [
            (lambda m: m.__setitem__("extra", 1), "the manifest has a key 6.3 does not name"),
            (lambda m: m.__setitem__("schema", "alpha2.run/2"), "the manifest's schema token"),
            (lambda m: m.__setitem__("state", "done"), "the manifest's state"),
            (lambda m: m.__setitem__("run_id", "x"), "the manifest's run_id"),
            (lambda m: m.__setitem__("command", "build"), "the manifest's command"),
            (lambda m: m.__setitem__("loop", "L9"), "the manifest's loop"),
            (lambda m: m.__setitem__("source_run", {"run_id": RID}), "the manifest's source_run"),
            (lambda m: m.__setitem__("installer_sha256", "x"), "the manifest's installer_sha256"),
            (lambda m: m.__setitem__("lock_sha256", "x"), "the manifest's lock_sha256"),
            (lambda m: m.__setitem__("started", "now"), "the manifest's started"),
            (lambda m: m.__delitem__("ended"), "the manifest's ended"),
            (lambda m: m.__setitem__("env_names", ["HOME"]), "the manifest's env_names"),
            (lambda m: m.__setitem__("stages", {}), "the manifest's stages"),
            (lambda m: m["stages"][0].__setitem__("x", 1), "a manifest stage row's keys"),
            (lambda m: m["stages"][0].__setitem__("stage", "S11"), "a manifest stage row's stage"),
            (lambda m: m["stages"][0].__setitem__("host", "Bad_Host"), "a manifest stage row's host"),
            (lambda m: m["stages"][0].__setitem__("receipt", "receipts/S1--.txt"), "a manifest stage row's receipt path"),
            (lambda m: m["stages"][0].__setitem__("sha256", "x"), "a manifest stage row's sha256"),
            (lambda m: m["stages"][0].__setitem__("rc", True), "a manifest stage row's rc"),
            (lambda m: m["stages"].append(dict(m["stages"][0])), "a stage and host appear twice"),
        ]
        for edit, why in cases:
            with self.subTest(why=why):
                original = self.manifest()
                self.edit_manifest(edit)
                self.assertEqual(self.reason(), why)
                self.set_manifest(original)
                self.assertEqual(self.eligible(), (True, ""))

    def test_an_active_manifest_with_ended(self):
        def edit(m):
            m["state"] = "active"
        self.edit_manifest(edit)
        self.assertEqual(self.reason(), "an active manifest has ended")

    def test_an_active_manifest(self):
        def edit(m):
            m["state"] = "active"
            del m["ended"]
        self.edit_manifest(edit)
        self.assertEqual(self.reason(), "the manifest is not final")

    def test_source_run_set(self):
        def edit(m):
            m["source_run"] = {"run_id": RID, "sums_sha256": "d" * 64}
        self.edit_manifest(edit)
        self.assertEqual(self.reason(), "the run took predecessors from another run")

    def test_manifest_row_digest_differs_from_sums(self):
        def edit(m):
            m["stages"][2]["sha256"] = "e" * 64
        self.edit_manifest(edit)
        self.assertEqual(self.reason(), "a receipt digest differs from the manifest")

    def test_hosts_with_the_right_sha_but_failing_its_schema(self):
        import hashlib
        bad = self.hosts_raw.replace(b'"hub": {', b'"extra": 1, "hub": {')

        def edit(m):
            m["hosts_sha256"] = hashlib.sha256(bad).hexdigest()
        self.edit_manifest(edit)
        ok, why = a2_s10.eligibility(self.run_fd, bad)
        self.assertEqual((ok, why), (False, "the hosts file does not pass its schema"))

    def test_an_unexpected_row(self):
        """A per-VM receipt for a VM outside the run's scope."""
        import hashlib
        run = a2_record.Run(self.run_fd, a2_guard.OutputGuard(), RID, "install", None, SHA, a2fix.H64,
                            self.hosts_sha)
        self.addCleanup(run.close)
        # Rebuild from scratch with one extra row before the final manifest.
        for n in os.listdir(self.dir):
            p = os.path.join(self.dir, n)
            shutil.rmtree(p) if os.path.isdir(p) else os.unlink(p)
        os.mkdir(os.path.join(self.dir, "receipts"), 0o700)
        run2 = a2_record.Run(self.run_fd, a2_guard.OutputGuard(), RID, "install", None, SHA, a2fix.H64,
                             self.hosts_sha)
        self.addCleanup(run2.close)
        run2.write_manifest(final=False)
        for sid, host in a2_s10.expected_receipts(self.w.hosts, "l3"):
            facts = [("PROCESSING_PROOF", "pass")] if sid == "S9" else []
            run2.write_receipt(sid, host, "2026-11-16T00:00:00Z", "PASS", facts)
            if (sid, host) == ("S2", "vm-a"):
                run2.write_receipt("S2", "vm-a-t", "2026-11-16T00:00:00Z", "PASS", [])
        run2.write_manifest(final=True)
        data = b"x\n"
        a2_record._write_atomic(self.run_fd, a2_record.SUMMARY, data)
        run2._append_sums(a2_record.SUMMARY, data)
        self.assertEqual(self.reason(), "a stage row the run does not have")

    def test_a_receipt_breaking_a_33_rule(self):
        self.replace_receipt("S3", None, lambda d: d.replace(b"RESULT=PASS\n", b"RESULT=PASS\nRESULT=PASS\n"))
        self.assertEqual(self.reason(), "a receipt breaks a 3.3 rule: S3")

    def test_a_receipt_rc_differing_from_its_row(self):
        def to_fail(d):
            text = a2_record.a2_causes.sentence("HUB-CHECK.UNCLASSIFIED").encode()
            return (d.replace(b"RESULT=PASS\n", b"RESULT=FAIL\nCAUSE=HUB-CHECK.UNCLASSIFIED\nCAUSE_TEXT=" + text + b"\n")
                    .replace(b"STAGE-END S3 - rc=0", b"STAGE-END S3 - rc=3"))
        self.replace_receipt("S3", None, to_fail)
        self.assertEqual(self.reason(), "a receipt's rc differs from the manifest")

    def test_a_receipt_bound_to_another_run(self):
        for old, new in ((b"RUN_ID=" + RID.encode(), b"RUN_ID=20261116T000000Z-0000ffff"),
                         (b"COMMAND=install", b"COMMAND=verify"),
                         (b"LOOP=-", b"LOOP=L3")):
            with self.subTest(old=old):
                self.setUp_again()
                self.replace_receipt("S3", None, lambda d, o=old, n=new: d.replace(o, n))
                self.assertEqual(self.reason(), "a receipt is not bound to this run")

    def test_each_receipt_sha(self):
        for key, why in ((b"INSTALLER_SHA", "a receipt's installer sha differs from the manifest"),
                         (b"LOCK_SHA", "a receipt's lock sha differs from the manifest"),
                         (b"HOSTS_SHA", "a receipt's hosts sha differs from the manifest")):
            with self.subTest(key=key):
                self.setUp_again()

                def change(d, k=key):
                    lines = d.split(b"\n")
                    return b"\n".join(k + b"=" + b"d" * 64 if ln.startswith(k + b"=") else ln for ln in lines)
                self.replace_receipt("S3", None, change)
                self.assertEqual(self.reason(), why)

    def setUp_again(self):
        for n in os.listdir(self.dir):
            p = os.path.join(self.dir, n)
            shutil.rmtree(p) if os.path.isdir(p) else os.unlink(p)
        os.mkdir(os.path.join(self.dir, "receipts"), 0o700)
        self.build()

    def test_malformed_shapes_never_raise(self):
        for data in (b"not json", b"[]", b"null", b'{"stages": [1, 2]}'):
            with self.subTest(data=data):
                self.put("manifest.json", data)
                ok, why = self.eligible()
                self.assertFalse(ok)
                self.assertTrue(isinstance(why, str) and why)

    def test_a_malformed_manifest_behind_a_verifying_chain_is_not_eligible(self):
        """SUMS is rebuilt over the bad bytes, so verify_sums passes and the
        parse itself fails: that failure is the one reason, never an
        exception."""
        for data in (b"not json", b"\xff\xfe"):
            with self.subTest(data=data):
                d = self.put("manifest.json", data)
                self.rechain([(p, d if p == "manifest.json" else g) for p, g in self.entries()])
                self.assertEqual(self.eligible(), (False, "the run record is malformed"))

    def test_the_whole_applicability_table(self):
        self.assertEqual(a2_s10.expected_receipts(self.w.hosts, "l3"), [
            ("S0", None), ("S1", None), ("S2", "vm-a"), ("S3", None), ("S4", "vm-a"), ("S5", "vm-a"),
            ("S6", "vm-a"), ("S6b", "vm-a"), ("S7", "vm-a"), ("S8", "vm-a"), ("S9", None), ("S10", None)])


class SummaryTest(Rec):
    def ctx(self, loop, account, command="install"):
        class C:
            pass
        c = C()
        c.hosts = self.w.hosts
        c.inv = __import__("a2_args").Invocation(command, loop, {"only": "S1"} if loop == "L1" else {})
        c.account = account
        return c

    def test_summary_lines(self):
        run = self.build(summary=False)
        c = self.ctx("L2", "loop")
        text = a2_s10.summary_text(c, run, False, "a reason", {("S5", "vm-a"): "KEYS.UNCLASSIFIED"},
                                   None, "abcd1234abcd1234")
        lines = text.splitlines()
        # Every stage rc is 0, so RESULT is PASS; eligibility is its own line.
        self.assertEqual(lines[0], "RESULT PASS")
        self.assertEqual(lines[-1], "NOT ELIGIBLE: a reason")
        self.assertIn("RL reply-depth check UNMEASURED", lines)
        self.assertIn("operator steps UNMEASURED: not supplied to this package", lines)
        self.assertIn("round trip: alpha2_install.py --check-roundtrip abcd1234abcd1234", lines)
        self.assertIn("agent agent-a address agent-a@a-t.internal INFERRED", lines)
        self.assertIn("vm vm-a-t access: ssh vm-a-t INFERRED", lines)
        self.assertIn("lock sha " + a2fix.H64, lines)
        # The run's VMs only: an L2 run lists no l3 VM.
        self.assertFalse(any(ln.startswith("vm vm-a ") for ln in lines))
        text = a2_s10.summary_text(c, run, True, "", {}, ["one", "two", "three"], "n")
        self.assertTrue(text.endswith("ELIGIBLE\n"))
        self.assertIn("operator step 3: three", text)

    def test_result_fail_from_a_stage_rc(self):
        run = self.build(fail="S5", summary=False)
        text = a2_s10.summary_text(self.ctx(None, "l3"), run, False, "r", {}, None, "n")
        self.assertTrue(text.startswith("RESULT FAIL\n"))

    def test_operator_steps_exactly_three(self):
        run = self.build(summary=False)
        c = self.ctx("L3", "l3")
        for bad in ([], ["one"], ["a", "b", "c", "d"], ["a", "b", ""], ["a", "b", "c\nd"], "abc"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    a2_s10.summary_text(c, run, True, "", {}, bad, "n")

    def test_no_reply_depth_line_for_l1(self):
        run = self.build(summary=False)
        self.assertNotIn("reply-depth", a2_s10.summary_text(self.ctx("L1", "loop"), run, False, "r", {}, None, "n"))


if __name__ == "__main__":
    unittest.main()
