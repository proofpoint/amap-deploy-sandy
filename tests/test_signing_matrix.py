"""hub_keys.verify_signing: the local router signs exactly as the policy and
the gate allow, one row per cell of the design's matrix, then the router's
own status.json as the witness a PASS needs.

The reload-failure row's status document is produced by the local router's
own code at the hop pin (its StatusTracker over `service.classification_
status` for a config whose reload failed), in a separate process: that is the
only producer that can put `config_reload_failed` where this check reads it.
"""

import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import hub_keys as hk
import router_health as rh
from _workspace import HOP_ROUTER_ROOT
from test_hub_keys import LOCAL, spec
from test_hub_runtime import setUpModule, tearDownModule  # noqa: F401 -- the fixture's pins, restored

NOW = 2_000_000_000
RID = "r1"
TOKEN = RID + ":" + "a" * 64
BLOCK = {"signing_key": {"path": "/opt/ex/keys/signing.key", "key_id": "b" * 64, "public_key": "c" * 64},
         "runtimes": [], "crypto": {"crypto_backend": "pyca"}}


def ts(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def fresh_status(**over):
    doc = {"interval_s": 5.0, "last_poll_ts": ts(NOW - 1), "started_ts": ts(NOW - 30)}
    doc.update(over)
    return doc


#: A1's run spec, in the shape prospective_spec and spec_from_running give.
SPEC = {"name": "ex-up", "image": "sha256:" + "b" * 64, "user": "2101:2101", "network": "none",
        "restart": "unless-stopped", "env": {"ROUTER_CONFIG": LOCAL},
        "mounts": [{"type": "bind", "source": LOCAL, "target": LOCAL, "readonly": True}]}


def named(at=NOW - 3600, outcome=None, binding=None):
    """partition_evidence.named_document's answer: the evidence that issued
    TOKEN, carrying `binding` as its local_router binding (A1's own by
    default)."""
    import partition_activation as pa

    def ask(token):
        if outcome is not None:
            return None, outcome, f"the document is {outcome}"
        if token != TOKEN:
            return None, "mismatch", "the token is not its document's"
        bound = binding or pa.activation_binding(SPEC, approved()["staged"].encode())
        return {"run_id": RID, "at": ts(at), "bindings": {"local_router": bound}}, b"raw", ""
    return ask


def approved(block=BLOCK, spec=None):
    return {"staged": json.dumps({"instances": {}, "delegation": block}, indent=2) + "\n",
            "final_config_path": LOCAL, "host": "alpha", "spec": spec or SPEC}


def live(block=None):
    doc = {"instances": {}}
    if block is not None:
        doc["delegation"] = block
    return json.dumps(doc).encode()


SIGNED = dict(BLOCK, partition_verified=TOKEN)


class Base(unittest.TestCase):

    def setUp(self):
        self.k = spec().keys
        self.bind = rh.check("bind", rh.Fact("live config", 1, "test"), 1, "r")

    def verdict(self, raw, **over):
        fields = dict(policy_on=True, gate_ok=True, approved=approved(), approved_why="", named=named(),
                      status=fresh_status(), witness=lambda host_sha: (rh.PASS, "adopted"), now=NOW)
        fields.update(over)
        c = hk.verify_signing(self.k, raw, self.bind, hk.Signing(**fields))
        self.assertEqual(c.claim, hk.SIGNING_CLAIM)
        return c


class Matrix(Base):

    def test_policy_off(self):
        self.assertEqual(self.verdict(live(), policy_on=False).result, rh.PASS)
        self.assertEqual(self.verdict(live(SIGNED), policy_on=False).result, rh.FAIL)

    def test_policy_on_and_the_gate_does_not_hold(self):
        self.assertEqual(self.verdict(live(), gate_ok=False).result, rh.PASS)
        c = self.verdict(live(SIGNED), gate_ok=False)
        self.assertEqual(c.result, rh.FAIL)
        self.assertIn("fail-stop", str(c.actual))

    def test_enabled_and_the_gate_holds_but_unsigned_is_never_pass(self):
        c = self.verdict(live())
        self.assertEqual(c.result, rh.UNKNOWN)
        self.assertIn("NOT YET ACTIVATED", c.reason)
        self.assertEqual(c.remedy, "complete A1 to A5")

    def test_no_approved_activation_fails_and_an_unreadable_one_is_unknown(self):
        c = self.verdict(live(SIGNED), approved=None, approved_why="activation.json is absent")
        self.assertEqual(c.result, rh.FAIL)
        self.assertIn("no approved activation", str(c.actual))
        self.assertEqual(self.verdict(live(SIGNED), approved=rh.Unresolved("EIO")).result, rh.UNKNOWN)

    def test_a_block_that_is_not_a1_s_fails(self):
        other = dict(SIGNED, crypto={"crypto_backend": "openssl"})
        self.assertEqual(self.verdict(live(other)).result, rh.FAIL)

    def test_equality_is_on_the_member_never_on_file_bytes(self):
        """A1 is indent-2; the live file here is compact and the member's keys
        are in another order. The same member passes."""
        reordered = {k: SIGNED[k] for k in reversed(list(SIGNED))}
        self.assertEqual(self.verdict(live(reordered)).result, rh.PASS)

    def test_the_named_document_must_hold(self):
        for outcome in ("missing", "malformed", "no_run"):
            with self.subTest(outcome=outcome):
                self.assertEqual(self.verdict(live(SIGNED), named=named(outcome=outcome)).result, rh.FAIL)
        wrong = dict(SIGNED, partition_verified=RID + ":" + "f" * 64)
        self.assertEqual(self.verdict(live(wrong)).result, rh.FAIL)

    def test_evidence_bound_to_another_a1_fails(self):
        """The same block, current passing evidence, but bound to another A1
        run spec: the evidence is not this activation's."""
        import partition_activation as pa
        other = pa.activation_binding(dict(SPEC, user="2102:2102"), approved()["staged"].encode())
        c = self.verdict(live(SIGNED), named=named(binding=other))
        self.assertEqual(c.result, rh.FAIL)
        self.assertIn("bound to another activation", str(c.actual))
        self.assertEqual(self.verdict(live(SIGNED), approved=approved(spec=dict(SPEC, user="2102:2102"))).result,
                         rh.FAIL)

    def test_a_stale_named_document_fails(self):
        c = self.verdict(live(SIGNED), named=named(at=NOW - 9 * 86400))
        self.assertEqual(c.result, rh.FAIL)
        self.assertIn("not current", str(c.actual))

    def test_the_named_document_current_and_passing_passes(self):
        self.assertEqual(self.verdict(live(SIGNED)).result, rh.PASS)

    def test_an_unreadable_policy_or_gate_decides_only_where_every_value_agrees(self):
        unread = rh.Unresolved("no manifest")
        self.assertEqual(self.verdict(live(), policy_on=unread, gate_ok=False).result, rh.PASS)
        self.assertEqual(self.verdict(live(), policy_on=unread, gate_ok=True).result, rh.UNKNOWN)
        self.assertEqual(self.verdict(live(), policy_on=False, gate_ok=unread).result, rh.PASS)
        self.assertEqual(self.verdict(live(SIGNED), policy_on=unread).result, rh.UNKNOWN)

    def test_an_unreadable_live_config_is_unknown(self):
        self.assertEqual(self.verdict(rh.Unresolved("absent")).result, rh.UNKNOWN)
        self.assertEqual(self.verdict(b"[1]").result, rh.UNKNOWN)


class StartGateTest(Base):
    """hub_keys.verify_start_delegation, the hub-link router's start gate on
    the local router's config: no block, or exactly A1's approved block
    with the static matrix holding over real inputs. The router's status
    and the adoption witness are never asked."""

    NEVER = rh.Unresolved("the start gate reads no router status")

    def never(self, host_sha):
        self.fail("the start gate asked the adoption witness")

    def gate(self, raw, live_ok=True, signing=True, **over):
        fields = dict(policy_on=True, gate_ok=True, approved=approved(), approved_why="", named=named(),
                      status=self.NEVER, witness=self.never, now=NOW)
        fields.update(over)
        sha = hk._sha(raw) if isinstance(raw, bytes) else None
        found = hk.verify_start_delegation(self.k, (self.k.local_config, sha if live_ok else "0" * 64),
                                           lambda p: raw, hk.Signing(**fields) if signing else None)
        self.assertEqual(len(found), 2)
        self.assertEqual(found[1].claim, hk.START_CLAIM.format(path=self.k.local_config))
        return found[1]

    def test_unsigned_passes_whatever_the_activation_inputs(self):
        self.assertEqual(self.gate(live()).result, rh.PASS)
        self.assertEqual(self.gate(live(), signing=False).result, rh.PASS)
        self.assertEqual(self.gate(live(), policy_on=rh.Unresolved("no manifest"), approved=None).result, rh.PASS)

    def test_a1_s_approved_block_under_the_static_matrix_passes_with_no_witness(self):
        self.assertEqual(self.gate(live(SIGNED)).result, rh.PASS)

    def test_a_block_that_is_not_a1_s_fails(self):
        other = dict(SIGNED, crypto={"crypto_backend": "openssl"})
        self.assertEqual(self.gate(live(other)).result, rh.FAIL)

    def test_a_failing_static_matrix_fails(self):
        for label, over in (("policy off", dict(policy_on=False)), ("gate not holding", dict(gate_ok=False)),
                            ("no A1 record", dict(approved=None, approved_why="absent")),
                            ("stale evidence", dict(named=named(at=NOW - 9 * 86400))),
                            ("no named evidence", dict(named=named(outcome="missing")))):
            with self.subTest(label):
                self.assertEqual(self.gate(live(SIGNED), **over).result, rh.FAIL)

    def test_inputs_that_cannot_be_read_are_unknown_never_pass(self):
        unread = rh.Unresolved("no manifest")
        for label, kw in (("policy unread", dict(policy_on=unread)), ("gate unread", dict(gate_ok=unread)),
                          ("A1 unreadable", dict(approved=rh.Unresolved("EIO"))),
                          ("no inputs at all", dict(signing=False))):
            with self.subTest(label):
                c = self.gate(live(SIGNED), **kw)
                self.assertEqual(c.result, rh.UNKNOWN)

    def test_an_unreadable_or_unbound_config_is_unknown(self):
        self.assertEqual(self.gate(b"[1]").result, rh.UNKNOWN)
        self.assertEqual(self.gate(b"{").result, rh.UNKNOWN)
        for raw in (live(), live(SIGNED)):
            with self.subTest(signed=raw == live(SIGNED)):
                c = self.gate(raw, live_ok=False)
                self.assertEqual(c.result, rh.UNKNOWN)
                self.assertIn("not shown to read", c.reason)


class RealEvidenceTest(Base):
    """The start gate and the signing verdict over producer-built evidence
    read through the real partition_evidence.named_document: only the token
    the evidence ISSUED, bound to this A1, is admitted."""

    def evidence(self, verdicts=None, spec=None):
        import partition_activation as pa
        import partition_evidence as pe
        import test_partition_evidence as tpe
        binding = pa.activation_binding(spec or SPEC, approved()["staged"].encode())
        raw = tpe.build(host="alpha", run_id=RID, at=ts(NOW - 3600), verdicts=verdicts or {},
                        bindings=dict(tpe.BINDINGS, local_router=binding))
        doc = json.loads(raw)
        token = doc[pe.TOKEN_MEMBER] or pe.token_of(doc)
        named = lambda t: pe.named_document(t, evidence_dir="/ev", host="alpha",
                                            read=lambda path: raw if path == f"/ev/partition-{RID}.json" else b"")
        return live(dict(BLOCK, partition_verified=token)), named

    def both(self, raw, named):
        start = hk.verify_start_delegation(self.k, (self.k.local_config, hk._sha(raw)), lambda p: raw,
                                           hk.Signing(policy_on=True, gate_ok=True, approved=approved(),
                                                      approved_why="", named=named, now=NOW,
                                                      status=rh.Unresolved("not read"),
                                                      witness=lambda h: self.fail("witness asked")))[1]
        return start.result, self.verdict(raw, named=named).result

    def test_passing_evidence_bound_to_this_a1_is_admitted(self):
        self.assertEqual(self.both(*self.evidence()), (rh.PASS, rh.PASS))

    def test_failed_evidence_s_computed_token_is_refused(self):
        for failing in ("P03", "P04"):
            with self.subTest(failing=failing):
                self.assertEqual(self.both(*self.evidence({failing: "FAIL"})), (rh.FAIL, rh.FAIL))

    def test_passing_evidence_bound_to_another_a1_is_refused(self):
        other = self.evidence(spec=dict(SPEC, user="2102:2102"))
        self.assertEqual(self.both(*other), (rh.FAIL, rh.FAIL))


class ConstantsTest(unittest.TestCase):
    """The two strings another program pins are emitted from these symbols,
    verbatim."""

    def test_the_activated_reason_and_the_kind_clause_are_the_emitted_strings(self):
        sg = hk.Signing(policy_on=True, gate_ok=True, approved=approved(), approved_why="", named=named(),
                        status=fresh_status(), witness=lambda h: (rh.PASS, ""), now=NOW)
        self.assertEqual(hk._verdict(json.loads(live(SIGNED)), True, True, sg),
                         (rh.PASS, hk.SIGNING_ACTIVATED.format(run_id=RID)))
        self.assertEqual(hk.platform_problem({"kind": "launchd"}, {}), hk.KIND_NOT_LINUX)
        self.assertEqual(hk.SIGNING_ACTIVATED, "it signs under the token of {run_id}, current and passing")
        self.assertEqual(hk.KIND_NOT_LINUX,
                         "the host-setup document declares no Linux host (its supervision is not systemd)")


class StatusWitness(Base):

    def test_a_reload_failure_fails_from_the_router_s_own_document(self):
        doc = router_reload_failed_status()
        self.assertIs(doc["classification"]["config_reload_failed"], True)
        c = self.verdict(live(SIGNED), status=doc)
        self.assertEqual(c.result, rh.FAIL)
        self.assertIn("refused its config file", str(c.actual))

    def test_a_pass_needs_the_adoption_witness(self):
        self.assertEqual(self.verdict(live(SIGNED)).result, rh.PASS)
        c = self.verdict(live(SIGNED), witness=lambda h: (rh.UNKNOWN, "the router did not poll twice"))
        self.assertEqual(c.result, rh.UNKNOWN)
        self.assertIn("did not poll twice", c.reason)

    def test_the_witness_is_handed_the_host_file_s_sha256(self):
        seen = []
        self.verdict(live(SIGNED), witness=lambda h: (seen.append(h), (rh.PASS, ""))[1])
        self.assertEqual(seen, [hk._sha(live(SIGNED))])

    def test_a_pass_needs_the_binding(self):
        self.bind = rh.unknown("bind", rh.Fact("live config", 1, "test"), "not asked", "r")
        c = self.verdict(live(SIGNED))
        self.assertEqual(c.result, rh.UNKNOWN)
        self.assertIn("not shown to read", c.reason)


class AdoptionTest(unittest.TestCase):
    """hub_keys.adoption over a scripted container, host and status: what the
    router reads (its device, inode, change time, size and bytes), the
    host's view of the same file with the host's clock, and its polls."""

    HOST = "a" * 64
    C = 1_000_000_000_000_000_000

    def run_it(self, tuples, statuses, host=None):
        """The scripted reads end in an Unresolved, never StopIteration, so a
        row past its script fails on its reason, not on a crash."""
        t, s = iter(tuples), iter(statuses)
        view = host if host is not None else (lambda: self.view())
        try:
            return hk.adoption(lambda: next(t, rh.Unresolved("the row scripted no further config read")),
                               lambda: next(s, rh.Unresolved("the row scripted no further status document")),
                               self.HOST, host_view=view, sleep=lambda x: None)
        except Exception as e:  # a crash is not an outcome
            self.fail(f"adoption raised {e!r}")

    def a(self, ctime=None, sha=None, ino=7, dev=1):
        return {"dev": dev, "ino": ino, "ctime_ns": ctime or self.C, "size": 10, "sha256": sha or self.HOST,
                "now": 0.0, "boot_id": "boot-1", "fstype": "ext4"}

    def view(self, **over):
        v = {"kind": "systemd", "platform": "linux", "boot_id": "boot-1", "fstype": "ext4", "dev": 1, "ino": 7,
             "ctime_ns": self.C, "sha256": self.HOST, "now": self.C / 1e9 + 60}
        v.update(over)
        return v

    def polls(self, *ns, started="s", failed=False, interval=5.0):
        out = [{"polls": n, "started_ts": started, "interval_s": interval} for n in ns]
        if failed:
            out[-1]["classification"] = {"config_reload_failed": True}
        return out

    def test_native_same_inode_stable_config_and_two_polls_pass(self):
        self.assertEqual(self.run_it([self.a(), self.a()], self.polls(10, 11, 12))[0], rh.PASS)

    def test_an_edit_and_restore_between_the_reads_is_never_a_pass(self):
        result, why = self.run_it([self.a(), self.a(ctime=self.C + 5_000_000_000)], self.polls(10, 11, 12))
        self.assertEqual(result, rh.UNKNOWN)
        self.assertIn("changed while verify watched", why)

    def test_a_host_rename_the_pinned_bind_does_not_see_is_unknown(self):
        self.assertEqual(self.run_it([self.a(sha="b" * 64)], [])[0], rh.UNKNOWN)

    def test_a_vm_share_is_unsupported_by_design(self):
        """Another device or inode in the container than on the host: not one
        inode in one kernel, so no documented bound holds; UNKNOWN before any
        poll is waited for."""
        for name, view in (("not linux", self.view(platform="darwin")),
                           ("a launchd document", self.view(kind="launchd")),
                           ("another kernel", self.view(boot_id="boot-2")),
                           ("a fuse share", self.view(fstype="fuse.orbstack")), ("overlay", self.view(fstype="overlay")),
                           ("tmpfs", self.view(fstype="tmpfs")), ("unreadable mountinfo", self.view(fstype=None))):
            with self.subTest(case=name):
                result, why = self.run_it([self.a()], [], host=lambda v=view: v)
                self.assertEqual(result, rh.UNKNOWN)
                self.assertIn("native-Linux single-file bind", why)

    def test_a_replaced_or_changed_bind_says_so_and_names_the_restart(self):
        for name, view in (("other device", self.view(dev=99)), ("other inode", self.view(ino=8)),
                           ("other ctime", self.view(ctime_ns=self.C + 1))):
            with self.subTest(case=name):
                result, why = self.run_it([self.a()], [], host=lambda v=view: v)
                self.assertEqual(result, rh.UNKNOWN)
                self.assertIn("binds a replaced inode", why)
                self.assertNotIn("native-Linux", why)

    def test_the_inode_is_compared_at_the_start_not_only_at_the_end(self):
        """A mismatch seen only at T1 (it has resolved by T5) still refuses:
        the window opened on a file the router was not reading."""
        views = iter([self.view(ino=8), self.view()])
        result, why = self.run_it([self.a(), self.a()], self.polls(10, 11, 12), host=lambda: next(views))
        self.assertEqual(result, rh.UNKNOWN)
        self.assertIn("binds a replaced inode", why)

    def test_the_host_file_replaced_during_the_window_is_unknown(self):
        """A host-side install --apply during verify's window replaces the
        live file by rename: the container still reads the old inode, which
        T1 and T5 agree on, and only the host's view at T5 differs."""
        for label, over in (("ino", dict(ino=8)), ("dev", dict(dev=2)), ("ctime", dict(ctime_ns=self.C + 1)),
                            ("bytes", dict(sha256="b" * 64))):
            with self.subTest(label):
                views = iter([self.view(), self.view(**over)])
                result, why = self.run_it([self.a(), self.a()], self.polls(10, 11, 12), host=lambda: next(views))
                self.assertEqual(result, rh.UNKNOWN)
                self.assertIn("at the end of the window: the local router binds a replaced inode", why)

    def test_the_filesystem_is_compared_again_at_the_end_of_the_window(self):
        views = iter([self.view(), self.view(fstype="xfs")])
        result, why = self.run_it([self.a(), self.a()], self.polls(10, 11, 12), host=lambda: next(views))
        self.assertEqual(result, rh.UNKNOWN)
        self.assertIn("at the end of the window", why)
        self.assertIn("'xfs' on the host", why)

    def test_a_container_without_the_single_file_bind_entry_is_unknown(self):
        result, why = self.run_it([dict(self.a(), fstype=None)], [])
        self.assertEqual(result, rh.UNKNOWN)
        self.assertIn("filesystem", why)

    def test_the_interval_must_be_a_finite_number_of_at_least_one_second(self):
        self.assertEqual(self.run_it([self.a(), self.a()], self.polls(10, 11, 12, interval=1.0))[0], rh.PASS)
        for bad in (True, float("nan"), float("inf"), float("-inf"), "5", None):
            with self.subTest(interval=bad):
                result, why = self.run_it([self.a()], self.polls(10, interval=bad))
                self.assertEqual(result, rh.UNKNOWN)
                self.assertIn("interval_s", why)

    def test_other_host_bytes_under_the_same_inode_are_unknown(self):
        result, why = self.run_it([self.a()], [], host=lambda: self.view(sha256="b" * 64))
        self.assertEqual(result, rh.UNKNOWN)
        self.assertIn("replaced inode, or one changed", why)

    def test_the_same_unlisted_filesystem_on_both_sides_is_unknown(self):
        """A VM share reports one type on both sides (virtiofs, measured on
        a sandbox's own config path); agreement never qualifies a type."""
        for fs in ("virtiofs", "tmpfs", "overlay", "fuse.example", "nfs", "9p", "zfs"):
            with self.subTest(fstype=fs):
                result, why = self.run_it([dict(self.a(), fstype=fs)], [], host=lambda fs=fs: self.view(fstype=fs))
                self.assertEqual(result, rh.UNKNOWN)
                self.assertIn(f"{fs!r} on the host and {fs!r} in the container", why)
        for fs in hk.LOCAL_FS:
            with self.subTest(fstype=fs):
                tuples = [dict(self.a(), fstype=fs), dict(self.a(), fstype=fs)]
                self.assertEqual(self.run_it(tuples, self.polls(10, 11, 12),
                                             host=lambda fs=fs: self.view(fstype=fs))[0], rh.PASS)

    def test_the_container_s_filesystem_must_be_the_host_s(self):
        result, why = self.run_it([dict(self.a(), fstype="xfs")], [])
        self.assertEqual(result, rh.UNKNOWN)
        self.assertIn("filesystem", why)

    def test_the_platform_is_checked_again_at_the_end_of_the_window(self):
        views = iter([self.view(), self.view(boot_id="boot-2")])
        result, why = self.run_it([self.a(), self.a()], self.polls(10, 11, 12), host=lambda: next(views))
        self.assertEqual(result, rh.UNKNOWN)
        self.assertIn("at the end of the window", why)

    def test_a_config_changed_moments_ago_on_the_host_s_clock_is_unknown(self):
        young = lambda: self.view(now=self.C / 1e9 + 1)
        self.assertIn("moments ago", self.run_it([self.a(), self.a()], self.polls(10, 11, 12), host=young)[1])

    def test_an_interval_under_one_second_is_unknown(self):
        result, why = self.run_it([self.a(), self.a()], self.polls(10, 11, 12, interval=0.5))
        self.assertEqual(result, rh.UNKNOWN)
        self.assertIn("at least 1s", why)

    def test_a_missing_interval_is_unknown(self):
        self.assertEqual(self.run_it([self.a()], [{"polls": 10, "started_ts": "s"}])[0], rh.UNKNOWN)

    def test_one_poll_is_not_enough(self):
        result, why = self.run_it([self.a(), self.a()], self.polls(10, *([11] * 10)))
        self.assertEqual(result, rh.UNKNOWN)
        self.assertIn("did not poll twice", why)

    def test_a_restart_while_watching_is_unknown(self):
        self.assertIn("restarted", self.run_it([self.a()], self.polls(10) + self.polls(1, started="t"))[1])

    def test_a_refused_reload_in_the_last_document_fails(self):
        self.assertEqual(self.run_it([self.a(), self.a()], self.polls(10, 11, 12, failed=True))[0], rh.FAIL)

    def test_the_settle_far_exceeds_the_kernel_tick(self):
        self.assertGreaterEqual(hk.CTIME_SETTLE_S, 2 * 0.010)


class MountinfoTest(unittest.TestCase):
    """hub_keys.mount_fstype, the one rule both sides read mountinfo by:
    the opened file's real path (host_view), whole path components, the
    topmost of equal mount points, and mountinfo's octal escapes decoded
    without narrowing any other character."""

    TEXT = ("1 0 8:1 / / rw - ext4 /dev/a rw\n"
            "2 1 0:41 / {fuse} rw - fuse.example f rw\n"
            "3 1 8:2 / /mnt/\u6587\u4ef6 rw - xfs b rw\n"
            "4 1 8:3 / /my\\040dir rw - btrfs c rw\n"
            "5 1 8:4 / /back\\134slash rw - ext4 d rw\n"
            "6 1 8:5 / /esc\\303\\251 rw - xfs e rw\n")

    def fstype(self, *a, **k):
        try:
            return hk.mount_fstype(*a, **k)
        except Exception as e:  # a crash is not an outcome
            self.fail(f"mount_fstype raised {e!r}")

    def setUp(self):
        import os
        import tempfile
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.fuse = os.path.join(os.path.realpath(td.name), "fuse")
        os.makedirs(self.fuse)
        with open(os.path.join(self.fuse, "router.json"), "w") as f:
            f.write("{}")
        self.alias = os.path.join(os.path.realpath(td.name), "alias.json")
        os.symlink(os.path.join(self.fuse, "router.json"), self.alias)
        self.text = self.TEXT.format(fuse=self.fuse)

    def test_an_alias_names_its_target_s_filesystem(self):
        """host_view, as production calls it: an alias into a listed fuse
        mount gives the target's type, never the lexical path's."""
        from types import SimpleNamespace
        import host_setup as hsu
        self.addCleanup(setattr, hk, "read_mountinfo", hk.read_mountinfo)
        hk.read_mountinfo = lambda: self.text
        v = hsu.host_view(SimpleNamespace(keys=SimpleNamespace(local_config=self.alias),
                                          supervision=SimpleNamespace(kind="systemd")))
        if sys.platform == "linux":
            self.assertEqual(v["fstype"], "fuse.example")
        self.assertEqual(self.fstype(self.alias, self.text), "ext4")   # the lexical path would lie

    def test_unicode_escapes_and_boundaries(self):
        self.assertEqual(self.fstype("/mnt/\u6587\u4ef6/r.json", self.text), "xfs")
        self.assertEqual(self.fstype("/my dir/r.json", self.text), "btrfs")
        self.assertEqual(self.fstype("/back\\slash/r.json", self.text), "ext4")
        self.assertEqual(self.fstype("/mnt/\u6587\u4ef6x/r.json", self.text), "ext4")    # not a component of it

    def test_of_equal_mount_points_the_last_listed_is_the_one_on_top(self):
        text = ("1 0 8:1 / / rw - ext4 a rw\n"
                "2 1 8:2 / /srv rw - xfs b rw\n"
                "3 2 0:9 / /srv rw - tmpfs c rw\n")
        self.assertEqual(self.fstype("/srv/r.json", text), "tmpfs")
        self.assertEqual(self.fstype("/srv", text, exact=True), "tmpfs")

    def test_an_unescaped_mount_point_never_matches_its_escaped_spelling(self):
        self.assertEqual(self.fstype("/my\\040dir/r.json", self.text), "ext4")

    def test_escaped_bytes_decode_as_a_file_name_not_as_latin_1(self):
        """mountinfo escapes bytes; two escaped bytes that are one UTF-8
        character name that character, as the kernel's path does."""
        self.assertEqual(self.fstype("/esc\u00e9/r.json", self.text), "xfs")
        self.assertEqual(self.fstype("/esc\u00c3\u00a9/r.json", self.text), "ext4")

    def test_the_container_counts_only_the_entry_at_the_path_itself(self):
        self.assertEqual(self.fstype("/mnt/\u6587\u4ef6", self.text, exact=True), "xfs")
        self.assertIsNone(self.fstype("/mnt/\u6587\u4ef6/r.json", self.text, exact=True))


class OpenResolvedTest(unittest.TestCase):
    """hub_keys.open_resolved, which both sides read the config through: the
    path resolved once, and that file alone opened, stat'ed and read."""

    def setUp(self):
        import os
        import tempfile
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        d = os.path.realpath(td.name)
        self.target, self.alias, self.other = (os.path.join(d, n) for n in ("router.json", "alias.json", "other.json"))
        for path, body in ((self.target, b"{}"), (self.other, b'{"x": 1}')):
            with open(path, "wb") as f:
                f.write(body)
        os.symlink(self.target, self.alias)

    def test_an_alias_is_read_and_stat_ed_as_its_target(self):
        import os
        real, st, raw = hk.open_resolved(self.alias)
        self.assertEqual((real, raw), (self.target, b"{}"))
        self.assertEqual((st.st_dev, st.st_ino), (os.stat(self.target).st_dev, os.stat(self.target).st_ino))

    def test_an_alias_that_resolves_elsewhere_while_read_is_refused(self):
        import os
        real = os.path.realpath
        answers = iter([self.target, self.other])
        os.path.realpath = lambda p, *a, **k: next(answers) if p == self.alias else real(p, *a, **k)
        self.addCleanup(setattr, os.path, "realpath", real)
        with self.assertRaisesRegex(OSError, "resolved to another file"):
            hk.open_resolved(self.alias)

    def test_a_name_still_a_link_after_resolution_is_never_followed(self):
        import errno
        import os
        real = os.path.realpath
        os.path.realpath = lambda p, *a, **k: p
        self.addCleanup(setattr, os.path, "realpath", real)
        with self.assertRaises(OSError) as e:
            hk.open_resolved(self.alias)
        self.assertEqual(e.exception.errno, errno.ELOOP)

    def test_the_host_view_is_the_resolved_file_s(self):
        """host_setup.host_view through an alias: the target's identity and
        bytes, and the filesystem looked up for the target's own path."""
        import hashlib
        import os
        import sys
        from types import SimpleNamespace
        import host_setup as hsu
        v = hsu.host_view(SimpleNamespace(keys=SimpleNamespace(local_config=self.alias),
                                          supervision=SimpleNamespace(kind="systemd")))
        st = os.stat(self.target)
        self.assertEqual((v["dev"], v["ino"], v["ctime_ns"], v["sha256"]),
                         (st.st_dev, st.st_ino, st.st_ctime_ns, hashlib.sha256(b"{}").hexdigest()))
        if sys.platform == "linux":
            self.assertEqual(v["fstype"], hk.mount_fstype(self.target, hk.read_mountinfo()))

    def test_the_host_view_looks_up_the_file_it_read_never_a_new_resolution(self):
        """A later resolution of the name (here to another file on another
        filesystem) never decides the filesystem of the file that was read."""
        import os
        import sys
        from types import SimpleNamespace
        import host_setup as hsu
        if sys.platform != "linux":
            self.skipTest("the host view reads mountinfo on Linux only")
        real = os.path.realpath
        answers = iter([self.target, self.target, self.other])
        os.path.realpath = lambda p, *a, **k: next(answers) if p == self.alias else real(p, *a, **k)
        self.addCleanup(setattr, os.path, "realpath", real)
        text = f"1 0 8:1 / / rw - ext4 a rw\n2 1 8:2 / {self.other} rw - fuse.example b rw\n"
        self.addCleanup(setattr, hk, "read_mountinfo", hk.read_mountinfo)
        hk.read_mountinfo = lambda: text
        v = hsu.host_view(SimpleNamespace(keys=SimpleNamespace(local_config=self.alias),
                                          supervision=SimpleNamespace(kind="systemd")))
        self.assertEqual(v["fstype"], "ext4")

    def test_a_host_view_whose_alias_moves_is_unresolved(self):
        import os
        from types import SimpleNamespace
        import host_setup as hsu
        real = os.path.realpath
        answers = iter([self.target, self.other])
        os.path.realpath = lambda p, *a, **k: next(answers) if p == self.alias else real(p, *a, **k)
        self.addCleanup(setattr, os.path, "realpath", real)
        v = hsu.host_view(SimpleNamespace(keys=SimpleNamespace(local_config=self.alias),
                                          supervision=SimpleNamespace(kind="systemd")))
        self.assertIsInstance(v, rh.Unresolved)
        self.assertIn("resolved to another file", v.reason)

    def test_a_directory_is_not_a_config(self):
        import os
        with self.assertRaisesRegex(OSError, "not a regular file"):
            hk.open_resolved(os.path.dirname(self.target))

    def test_the_container_script_reads_through_the_same_rule(self):
        """The in-container text runs here against an alias: it prints the
        target's identity and bytes."""
        import hashlib
        import json
        import os
        import subprocess
        import sys
        p = subprocess.run([sys.executable, "-I", "-S", "-c", hk.CONFIG_TUPLE_SCRIPT], capture_output=True, text=True,
                           env={"ROUTER_CONFIG": self.alias})
        if p.returncode and "boot_id" in p.stderr:
            self.skipTest("no /proc/sys/kernel/random/boot_id here")
        doc = json.loads(p.stdout)
        self.assertEqual((doc["ino"], doc["sha256"]), (os.stat(self.target).st_ino, hashlib.sha256(b"{}").hexdigest()))
        self.assertIsNone(doc["fstype"], "a file that is not itself a mount point has no exact entry")

    def test_a_config_past_the_bound_is_refused(self):
        with open(self.target, "wb") as f:
            f.write(b" " * (hk.CONFIG_MAX + 1))
        with self.assertRaisesRegex(OSError, "larger than"):
            hk.open_resolved(self.alias)
        with open(self.target, "wb") as f:
            f.write(b" " * hk.CONFIG_MAX)
        self.assertEqual(len(hk.open_resolved(self.alias)[2]), hk.CONFIG_MAX)


class PolicyTest(unittest.TestCase):
    """amap_sandy.delegation_policy: the manifest's hop_link decides, and a
    policy that cannot be read is an Unresolved, never False."""

    def answer(self, load):
        import amap_sandy as prov
        real = prov.fp.load_policy
        self.addCleanup(setattr, prov.fp, "load_policy", real)
        prov.fp.load_policy = load
        return prov.delegation_policy(Path("/nonexistent-home"))

    def test_the_hop_link_s_delegation_member_turns_it_on(self):
        link = {"link": "link-a", "trusted_fleet_hosts": ["beta.internal"], "egress": True}
        self.assertIs(self.answer(lambda p: {}), False)
        self.assertIs(self.answer(lambda p: {"hop_link": link}), False)
        self.assertIs(self.answer(lambda p: {"hop_link": dict(link, delegation={"inbound": False})}), True)

    def test_an_unreadable_policy_is_unresolved(self):
        def missing(p):
            raise FileNotFoundError(p)
        self.assertIsInstance(self.answer(missing), rh.Unresolved)
        self.assertIsInstance(self.answer(lambda p: {"hop_link": {"link": "x"}}), rh.Unresolved)


PRODUCER = r'''
import dataclasses, json, sys
sys.path.insert(0, sys.argv[1])
from router import config as C, service as S, status as St
cfg = C.load_obj({"state_dir": sys.argv[2] + "/state",
                  "instances": {"a": {"namespace": sys.argv[2] + "/a", "peers": []}}})
cfg = dataclasses.replace(cfg, reload_failed=True)
t = St.StatusTracker(interval_s=5.0)
t.record_classification(S.classification_status(cfg, None, None))
print(json.dumps(t.to_doc()))
'''


def router_reload_failed_status():
    """status.json as the local router at the hop pin writes it while its
    config reload is refused."""
    with tempfile.TemporaryDirectory() as td:
        import os
        os.makedirs(os.path.join(td, "a"))
        p = subprocess.run([sys.executable, "-I", "-B", "-c", PRODUCER, str(HOP_ROUTER_ROOT), td],
                           capture_output=True, text=True, timeout=120, check=True)
    return json.loads(p.stdout)


if __name__ == "__main__":
    unittest.main()
