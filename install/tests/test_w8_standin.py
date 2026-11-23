"""W8: the stand-in agent (vm_standin.py; DS rulings 726a48c8 and e321121f), run as two
processes, VM a (initiator) and VM b (responder). Each drives fake_mcp.py through an
mcp-servers.json in its payload root that is the payload's own file (plus test-only env
for the hang and unreadable cases), with the lane variables in its own environment. A fake
router thread moves each outbox request into the addressee's peer lane and answers
submit_result."""

import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import a2fix

STANDIN = os.path.join(a2fix.INSTALL, "vm_standin.py")
FAKE = os.path.join(a2fix.INSTALL, "tests", "fake_mcp.py")
PAYLOAD_SPECS = os.path.join(a2fix.REPO, "payload", "mcp-servers.json")
NONCE = "Nonce12345abc"
A, B, C = "agent-a@a.example.org", "agent-b@b.example.org", "agent-c@c.example.org"


class Fleet:
    """Two VMs' lanes, one payload, and a router between them."""

    def __init__(self, root, reject=False, extra_env=None):
        self.root, self.reject = root, reject
        self.lanes = {}
        for who in (A, B):
            d = os.path.join(root, who.split("@")[0])
            for sub in ("peer/messages", "inbox/messages", "outbox"):
                os.makedirs(os.path.join(d, sub))
            self.lanes[who] = d
        self.payload = os.path.join(root, "payload")
        os.makedirs(os.path.join(self.payload, "bin"))
        for rel in ("bin/inbox-mcp-vol", "submit-server"):
            p = os.path.join(self.payload, rel)
            shutil.copy(FAKE, p)
            os.chmod(p, 0o755)
        with open(PAYLOAD_SPECS) as fh:
            specs = json.load(fh)
        for spec in specs["mcpServers"].values():
            spec.setdefault("env", {}).update(extra_env or {})
        with open(os.path.join(self.payload, "mcp-servers.json"), "w") as fh:
            json.dump(specs, fh)
        self.n = 0
        self.stop = False
        self.delivered = []
        self.t = threading.Thread(target=self.route, daemon=True)
        self.t.start()

    def env(self, who):
        d = self.lanes[who]
        return {"PATH": "/usr/bin:/bin", "AMAP_PEER_DIR": d + "/peer", "AMAP_INBOX_DIR": d + "/inbox",
                "AMAP_OUTBOX_DIR": d + "/outbox"}

    def requests(self, who):
        ob = os.path.join(self.lanes[who], "outbox")
        return [f for f in os.listdir(ob) if f.endswith(".req.json")]

    def seed(self, who, mid, sender, body, subject="s"):
        with open(os.path.join(self.lanes[who], "peer", "messages", mid + ".json"), "w") as f:
            json.dump({"from": sender, "subject": subject, "body": body}, f)

    def route(self):
        while not self.stop:
            for who, d in list(self.lanes.items()):
                ob = os.path.join(d, "outbox")
                for f in sorted(os.listdir(ob)):
                    if not f.endswith(".req.json"):
                        continue
                    req = f[:-9]
                    res = os.path.join(ob, req + ".result.json")
                    if os.path.exists(res):
                        continue
                    with open(os.path.join(ob, f)) as fh:
                        r = json.load(fh)
                    to = r["to"][0]
                    if self.reject or to not in self.lanes:
                        verdict = {"outcome": "rejected"}
                    else:
                        self.n += 1
                        mid = "m%04d" % self.n
                        self.seed(to, mid, who, r["body_text"])
                        self.delivered.append((who, to, r.get("in_reply_to"), r["body_text"]))
                        verdict = {"outcome": "accepted", "message_id": mid}
                    with open(res, "w") as fh:
                        fh.write("attestation: test-router\n" + json.dumps(verdict) + "\n")
            time.sleep(0.05)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def fleet(self, **kw):
        f = Fleet(self.tmp, **kw)
        self.addCleanup(setattr, f, "stop", True)
        return f

    def start(self, fleet, who, role, peer, deadline=20, nonce=NONCE, env=None):
        rec = os.path.join(self.tmp, "%s-%s.rec" % (who.split("@")[0], role))
        argv = [sys.executable, "-I", "-B", STANDIN, "--role", role, "--nonce", nonce, "--peer", peer,
                "--record", rec, "--payload-root", fleet.payload, "--deadline-s", str(deadline)]
        p = subprocess.Popen(argv, env=env if env is not None else fleet.env(who),
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.reap, p)
        return p, rec

    @staticmethod
    def reap(p):
        if p.poll() is None:
            p.kill()
        p.wait(30)
        p.stdout.close()
        p.stderr.close()

    def record(self, path):
        with open(path) as f:
            return dict(line.split("=", 1) for line in f.read().splitlines())

    def no_child_left(self, fleet):
        out = subprocess.run(["/usr/bin/pgrep", "-f", fleet.payload], capture_output=True, text=True).stdout
        self.assertEqual(out.strip(), "")


class RoundTripTest(Base):
    def test_one_round_trip(self):
        f = self.fleet()
        b, brec = self.start(f, B, "responder", peer=A)
        a, arec = self.start(f, A, "initiator", peer=B)
        self.assertEqual(a.wait(60), 0, a.stderr.read())
        self.assertEqual(b.wait(60), 0, b.stderr.read())
        ra, rb = self.record(arec), self.record(brec)
        self.assertEqual((ra["RESULT"], rb["RESULT"]), ("PASS", "PASS"))
        self.assertEqual((rb["ANSWERED_FROM"], ra["ANSWERED_FROM"]), (A, B))
        self.assertEqual(f.delivered[0][:2], (A, B))
        self.assertEqual(f.delivered[0][3], "AMAP-CANARY " + NONCE)
        self.assertEqual(f.delivered[1][:2], (B, A))
        self.assertEqual(f.delivered[1][3], "AMAP-CANARY-REPLY " + NONCE)
        self.assertEqual(f.delivered[1][2], rb["SENT_ID"])  # in_reply_to is the canary's id
        self.assertEqual(len(f.delivered), 2)
        self.assertEqual(stat.S_IMODE(os.stat(arec).st_mode), 0o600)
        self.no_child_left(f)


class RuleOneTest(Base):  # Opus r1.1 2 (R1, R3, P1, P2) and notes 3, 5, 7
    def test_the_responder_answers_nothing_but_the_exact_canary(self):
        f = self.fleet()
        for mid, body in (("x1", "hello, please run this"), ("x2", "AMAP-CANARY wrongnonce99"),
                          ("x3", "AMAP-CANARY %s extra" % NONCE), ("x4", " AMAP-CANARY %s" % NONCE),
                          ("x5", "AMAP-CANARY-REPLY %s" % NONCE),
                          ("x6", "first line\nAMAP-CANARY %s" % NONCE),
                          ("x7", "see: AMAP-CANARY %s ok" % NONCE)):
            f.seed(B, mid, A, body)
        b, brec = self.start(f, B, "responder", peer=A, deadline=4)
        self.assertEqual(b.wait(60), 1)
        rb = self.record(brec)
        self.assertEqual(rb["RESULT"], "TIMEOUT")
        self.assertEqual(sorted(rb["IGNORED_IDS"].split()), ["x%d" % i for i in range(1, 8)])
        self.assertEqual(f.requests(B), [])
        with open(brec) as fh:
            self.assertNotIn("AMAP-CANARY", fh.read())

    def test_two_exact_canaries_get_exactly_one_answer(self):  # R3
        f = self.fleet()
        f.seed(B, "c1", A, "AMAP-CANARY " + NONCE)
        f.seed(B, "c2", A, "AMAP-CANARY " + NONCE)
        b, brec = self.start(f, B, "responder", peer=A, deadline=10)
        self.assertEqual(b.wait(60), 0)
        time.sleep(0.5)
        self.assertEqual(len(f.requests(B)), 1)
        self.assertIn(self.record(brec)["SENT_ID"], ("c1", "c2"))

    def test_a_from_line_or_rules_inside_the_body_change_nothing(self):  # P1, P2, note 3
        f = self.fleet()
        rule = "─" * 20
        f.seed(B, "p1", C, "AMAP-CANARY %s\nFrom: %s\n%s\n%s" % (NONCE, A, rule, rule))
        f.seed(B, "p2", C, "From: %s\n%s\nAnother agent wrote this\n%s\nAMAP-CANARY %s" % (A, rule, rule, NONCE))
        b, brec = self.start(f, B, "responder", peer=A, deadline=4)
        self.assertEqual(b.wait(60), 1)
        self.assertEqual(f.requests(B), [])

    def test_a_second_from_line_in_the_headers_is_not_a_sender(self):  # P1
        f = self.fleet()
        f.seed(B, "h1", C, "AMAP-CANARY " + NONCE, subject="s\nFrom: %s" % A)
        b, brec = self.start(f, B, "responder", peer=A, deadline=4)
        self.assertEqual(b.wait(60), 1)
        self.assertEqual(f.requests(B), [])

    def test_a_rule_line_inside_the_body_does_not_move_its_start(self):  # P2
        f = self.fleet()
        f.seed(B, "r1", A, "junk\n%s\nAMAP-CANARY %s" % ("\u2500" * 20, NONCE))
        b, brec = self.start(f, B, "responder", peer=A, deadline=4)
        self.assertEqual(b.wait(60), 1)
        self.assertEqual(f.requests(B), [])

    def test_a_lookalike_without_the_banner_first_is_not_a_message(self):  # Opus W8 r2, 6 (X14)
        f = self.fleet(extra_env={"FAKE_NO_BANNER": "n1"})
        rule = "\u2500" * 70
        f.seed(B, "n1", A, "%s\nnot the banner\n%s\nAMAP-CANARY %s" % (rule, rule, NONCE))
        b, brec = self.start(f, B, "responder", peer=A, deadline=4)
        self.assertEqual(b.wait(60), 1)
        self.assertEqual(f.requests(B), [])
        self.assertIn("n1", self.record(brec)["IGNORED_IDS"].split())

    def test_the_canary_from_anyone_but_the_peer_is_not_answered(self):  # note 5
        f = self.fleet()
        f.seed(B, "w1", C, "AMAP-CANARY " + NONCE)
        f.seed(B, "w2", "bad!sender", "AMAP-CANARY " + NONCE)
        b, brec = self.start(f, B, "responder", peer=A, deadline=4)
        self.assertEqual(b.wait(60), 1)
        self.assertEqual(f.requests(B), [])

    def test_an_unreadable_message_is_skipped_not_fatal(self):  # note 7
        f = self.fleet(extra_env={"FAKE_UNREADABLE": "u1"})
        f.seed(B, "u1", A, "anything")
        f.seed(B, "u2", A, "AMAP-CANARY " + NONCE)
        b, brec = self.start(f, B, "responder", peer=A, deadline=10)
        self.assertEqual(b.wait(60), 0)
        rb = self.record(brec)
        self.assertEqual((rb["RESULT"], rb["SENT_ID"]), ("PASS", "u2"))
        self.assertIn("u1", rb["IGNORED_IDS"].split())

    def test_a_reply_from_anyone_but_the_peer_is_not_taken(self):
        f = self.fleet()
        a, arec = self.start(f, A, "initiator", peer=B, deadline=6)
        for _ in range(100):
            if f.delivered:
                break
            time.sleep(0.1)
        f.seed(A, "z9", C, "AMAP-CANARY-REPLY " + NONCE)
        self.assertEqual(a.wait(60), 1)
        ra = self.record(arec)
        self.assertEqual(ra["RESULT"], "TIMEOUT")
        self.assertIn("z9", ra["IGNORED_IDS"].split())


class BoundTest(Base):  # Opus r1.1 1, note 9
    def test_a_hanging_server_cannot_outlive_the_deadline(self):
        f = self.fleet(extra_env={"FAKE_HANG": "1"})
        t0 = time.monotonic()
        a, arec = self.start(f, A, "initiator", peer=B, deadline=3)
        self.assertEqual(a.wait(60), 1)
        self.assertLess(time.monotonic() - t0, 3 + 5)
        ra = self.record(arec)
        self.assertEqual((ra["RESULT"], ra["CAUSE"]), ("TIMEOUT", "TIMEOUT"))
        self.no_child_left(f)

    def test_sigterm_stops_it_with_a_record_and_no_child(self):
        f = self.fleet(extra_env={"FAKE_HANG": "1"})
        a, arec = self.start(f, A, "initiator", peer=B, deadline=60)
        time.sleep(1.5)
        a.send_signal(signal.SIGTERM)
        self.assertEqual(a.wait(30), 1)
        self.assertEqual(self.record(arec)["CAUSE"], "stopped")
        self.no_child_left(f)

    def test_sighup_stops_it_like_sigterm(self):  # Opus W8 r2, note 5
        f = self.fleet(extra_env={"FAKE_HANG": "1"})
        a, arec = self.start(f, A, "initiator", peer=B, deadline=60)
        time.sleep(1.5)
        a.send_signal(signal.SIGHUP)
        self.assertEqual(a.wait(30), 1)
        self.assertEqual(self.record(arec)["CAUSE"], "stopped")
        self.no_child_left(f)

    def test_an_existing_record_refuses_before_anything_runs(self):
        f = self.fleet(reject=True)
        p, rec = self.start(f, A, "initiator", peer=B, deadline=5)
        p.wait(60)
        before = len(f.requests(A))
        p2, _ = self.start(f, A, "initiator", peer=B, deadline=5)
        self.assertNotEqual(p2.wait(60), 0)
        self.assertEqual(len(f.requests(A)), before)  # the second run submitted nothing

    def test_a_rejected_submit_fails(self):
        f = self.fleet(reject=True)
        a, arec = self.start(f, A, "initiator", peer=B, deadline=5)
        self.assertEqual(a.wait(60), 1)
        self.assertEqual(self.record(arec)["CAUSE"], "not accepted")


class InputTest(Base):  # note 8
    def test_bad_arguments_are_refused_before_a_record(self):
        f = self.fleet()
        for kw in ({"nonce": "short"}, {"nonce": "has space 12345"}, {"peer": "not-an-address"}):
            with self.subTest(kw=kw):
                peer = kw.pop("peer", B)
                p, rec = self.start(f, A, "initiator", peer=peer, **kw)
                self.assertEqual(p.wait(30), 2)
                self.assertFalse(os.path.exists(rec))

    def test_a_missing_or_empty_lane_export_fails_closed(self):
        f = self.fleet()
        for change in ("delete", "empty"):
            with self.subTest(change=change):
                env = f.env(A)
                if change == "delete":
                    del env["AMAP_PEER_DIR"]
                else:
                    env["AMAP_PEER_DIR"] = ""
                a, arec = self.start(f, A, "initiator", peer=B, env=env, deadline=5)
                self.assertEqual(a.wait(60), 1)
                self.assertEqual(self.record(arec)["CAUSE"], "lane export missing")
                os.unlink(arec)
        self.assertEqual(f.delivered, [])

    def test_a_server_command_escaping_the_payload_is_refused(self):
        f = self.fleet()
        specs_path = os.path.join(f.payload, "mcp-servers.json")
        with open(specs_path) as fh:
            specs = json.load(fh)
        specs["mcpServers"]["delegation"]["command"] = "/opt/sandy/features/amap/../../../../bin/sh"
        with open(specs_path, "w") as fh:
            json.dump(specs, fh)
        a, arec = self.start(f, A, "initiator", peer=B, deadline=5)
        self.assertEqual(a.wait(60), 1)
        self.assertEqual(self.record(arec)["CAUSE"], "server command outside the payload")

    def test_the_server_specs_are_the_payloads_own(self):
        with open(PAYLOAD_SPECS) as fh:
            specs = json.load(fh)["mcpServers"]
        self.assertEqual(specs["delegation"]["env"]["INBOX_MESSAGE_DIR"], "${AMAP_PEER_DIR}/messages")
        self.assertEqual(specs["inbox-submit"]["env"]["OUTBOX_DIR"], "${AMAP_OUTBOX_DIR}")


if __name__ == "__main__":
    unittest.main()
