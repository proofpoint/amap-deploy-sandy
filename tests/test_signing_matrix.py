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


def named(at=NOW - 3600, outcome=None):
    def ask(token):
        if outcome is not None:
            return None, outcome, f"the document is {outcome}"
        if token != TOKEN:
            return None, "mismatch", "the token is not its document's"
        return {"run_id": RID, "at": ts(at)}, b"raw", ""
    return ask


def approved(block=BLOCK):
    return {"staged": json.dumps({"instances": {}, "delegation": block}, indent=2) + "\n",
            "final_config_path": LOCAL, "host": "alpha"}


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
        t, s = iter(tuples), iter(statuses)
        view = host if host is not None else (lambda: self.view())
        return hk.adoption(lambda: next(t), lambda: next(s), self.HOST, host_view=view, sleep=lambda x: None)

    def a(self, ctime=None, sha=None, ino=7, dev=1):
        return {"dev": dev, "ino": ino, "ctime_ns": ctime or self.C, "size": 10, "sha256": sha or self.HOST,
                "now": 0.0}

    def view(self, **over):
        v = {"platform": "linux", "dev": 1, "ino": 7, "ctime_ns": self.C, "now": self.C / 1e9 + 60}
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
        for name, view in (("other device", self.view(dev=99)), ("other inode", self.view(ino=8)),
                           ("other ctime", self.view(ctime_ns=self.C + 1)), ("not linux", self.view(platform="darwin"))):
            with self.subTest(case=name):
                result, why = self.run_it([self.a()], [], host=lambda v=view: v)
                self.assertEqual(result, rh.UNKNOWN)
                self.assertIn("native-Linux single-file bind", why)

    def test_a_config_changed_moments_ago_on_the_host_s_clock_is_unknown(self):
        young = lambda: self.view(now=self.C / 1e9 + 1)
        self.assertIn("moments ago", self.run_it([self.a(), self.a()], self.polls(10, 11, 12), host=young)[1])

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
