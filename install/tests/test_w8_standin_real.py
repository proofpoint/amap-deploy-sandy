"""STANDIN-REAL-MCP-CHECK: the stand-in agent (vm_standin.py) against the connector's REAL MCP servers.

test_w8_standin drives vm_standin through tests/fake_mcp.py; this test drives it through the connector's own
bin/inbox-mcp-vol and bin/inbox-submit (and this repo's payload/submit-server, which execs the latter), placed in a
payload tree the way S6 places them, under the payload's own mcp-servers.json. One round trip, initiator to
responder and back.

The connector checkout is $AMAP_CONNECTOR_REPO, else `amap-connector-claude` beside this repository. Its HEAD must be
the pin: $A2_CONNECTOR_PIN when set (the commit alpha2.lock names), else siblings.json's. Without a checkout the test
SKIPS, loudly (a skipped check is not a passed one); a checkout at another commit FAILS.

FAKED: the router only. The test's router thread reads each drop-box request the real inbox-submit wrote
(`<outbox>/req-<id>.json`, the spec's submit-request: draft.to, draft.body_text, draft.reply_to_message_id),
publishes the message into the addressee's peer lane as the spool document the real reader reads
(`messages/notice-<id>.json`, the spec's inbound-message shape, fixtures/valid/message-clean.json), and answers
with `<outbox>/results/<req_id>.json` (fixtures/valid/result-accepted.json's members).
"""

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid

import a2fix

STANDIN = os.path.join(a2fix.INSTALL, "vm_standin.py")
PAYLOAD = os.path.join(a2fix.REPO, "payload")
SIBLINGS = os.path.join(a2fix.REPO, "siblings.json")
CONNECTOR_FILES = ("inbox-mcp-vol", "inbox-submit", "_inboxlib.py")
NONCE = "RealNonce12345"
A, B = "agent-a@a.example.org", "agent-b@b.example.org"


def connector_checkout():
    """(path, pin) or (None, reason)."""
    path = os.environ.get("AMAP_CONNECTOR_REPO") or os.path.join(os.path.dirname(a2fix.REPO), "amap-connector-claude")
    if not os.path.isfile(os.path.join(path, "bin", "inbox-mcp-vol")):
        return None, "no amap-connector-claude checkout at %s (set AMAP_CONNECTOR_REPO)" % path
    pin = os.environ.get("A2_CONNECTOR_PIN")
    if not pin:
        with open(SIBLINGS) as f:
            pin = [s["commit"] for s in json.load(f)["siblings"] if s["name"] == "amap-connector-claude"][0]
    return path, pin


class RealFleet:
    def __init__(self, root, connector):
        self.root = root
        self.lanes = {}
        for who in (A, B):
            d = os.path.join(root, who.split("@")[0])
            for sub in ("peer/messages", "inbox/messages", "outbox"):
                os.makedirs(os.path.join(d, sub))
            self.lanes[who] = d
        self.payload = os.path.join(root, "payload")
        os.makedirs(os.path.join(self.payload, "bin"))
        for name in CONNECTOR_FILES:
            shutil.copy(os.path.join(connector, "bin", name), os.path.join(self.payload, "bin", name))
        for name in ("inbox-mcp-vol", "inbox-submit"):
            os.chmod(os.path.join(self.payload, "bin", name), 0o755)
        shutil.copy(os.path.join(PAYLOAD, "submit-server"), os.path.join(self.payload, "submit-server"))
        os.chmod(os.path.join(self.payload, "submit-server"), 0o755)
        shutil.copy(os.path.join(PAYLOAD, "mcp-servers.json"), os.path.join(self.payload, "mcp-servers.json"))
        self.delivered = []
        self.seen = set()
        self.stop = False
        self.t = threading.Thread(target=self.route, daemon=True)
        self.t.start()

    def env(self, who):
        d = self.lanes[who]
        return {"PATH": "/usr/bin:/bin", "AMAP_PEER_DIR": d + "/peer", "AMAP_INBOX_DIR": d + "/inbox",
                "AMAP_OUTBOX_DIR": d + "/outbox"}

    def publish(self, to, sender, body, subject):
        nid = uuid.uuid4().hex
        doc = {"contract_version": "2", "notice_id": nid, "id": nid, "date": "Mon, 20 Jul 2026 04:00:00 +0000",
               "from": sender, "to": to, "subject": subject, "body_text": body}
        d = os.path.join(self.lanes[to], "peer", "messages")
        tmp = os.path.join(d, ".notice-%s.json.tmp" % nid)
        with open(tmp, "w") as f:
            json.dump(doc, f)
        os.rename(tmp, os.path.join(d, "notice-%s.json" % nid))
        return nid

    def route(self):
        while not self.stop:
            for who, d in list(self.lanes.items()):
                ob = os.path.join(d, "outbox")
                for name in sorted(os.listdir(ob)):
                    if not (name.startswith("req-") and name.endswith(".json")) or (who, name) in self.seen:
                        continue
                    self.seen.add((who, name))
                    with open(os.path.join(ob, name)) as f:
                        req = json.load(f)
                    draft = req["draft"]
                    to = draft["to"][0]
                    nid = self.publish(to, who, draft["body_text"], draft.get("subject") or "")
                    self.delivered.append((who, to, draft.get("reply_to_message_id"), draft["body_text"], nid))
                    os.makedirs(os.path.join(ob, "results"), exist_ok=True)
                    res = {"contract_version": "2", "req_id": req["req_id"], "outcome": "accepted", "detail": None,
                           "reason_code": "peer_routed", "ts": "2026-07-20T04:06:00Z", "recipients": [to],
                           "message_id": nid}
                    tmp = os.path.join(ob, "results", ".%s.tmp" % req["req_id"])
                    with open(tmp, "w") as f:
                        json.dump(res, f)
                    os.rename(tmp, os.path.join(ob, "results", req["req_id"] + ".json"))
            time.sleep(0.05)


class RealMcpRoundTripTest(unittest.TestCase):
    def setUp(self):
        path, pin = connector_checkout()
        if path is None:
            self.skipTest("STANDIN-REAL-MCP-CHECK not run: " + pin)
        head = subprocess.run(["git", "-C", path, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        self.assertEqual(head, pin, "the connector checkout is not at the pin")
        dirty = subprocess.run(["git", "-C", path, "status", "--porcelain", "--", "bin"], capture_output=True,
                               text=True).stdout
        self.assertEqual(dirty, "", "the connector's bin/ differs from its pin")
        self.tmp = tempfile.mkdtemp(prefix="a2real-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fleet = RealFleet(self.tmp, path)
        self.addCleanup(setattr, self.fleet, "stop", True)

    def start(self, who, role, peer, deadline=40):
        rec = os.path.join(self.tmp, "%s-%s.rec" % (who.split("@")[0], role))
        argv = [sys.executable, "-I", "-B", STANDIN, "--role", role, "--nonce", NONCE, "--peer", peer,
                "--record", rec, "--payload-root", self.fleet.payload, "--deadline-s", str(deadline)]
        p = subprocess.Popen(argv, env=self.fleet.env(who), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        def reap():
            if p.poll() is None:
                p.kill()
            p.wait(30)
            p.stdout.close()
            p.stderr.close()
        self.addCleanup(reap)
        return p, rec

    @staticmethod
    def record(path):
        with open(path) as f:
            return dict(line.split("=", 1) for line in f.read().splitlines())

    def test_one_round_trip_through_the_real_servers(self):
        b, brec = self.start(B, "responder", peer=A)
        a, arec = self.start(A, "initiator", peer=B)
        rca, rcb = a.wait(90), b.wait(90)
        ra, rb = self.record(arec), self.record(brec)
        self.assertEqual((rca, rcb), (0, 0), (ra, rb, a.stderr.read(), b.stderr.read()))
        self.assertEqual((ra["RESULT"], rb["RESULT"]), ("PASS", "PASS"), (ra, rb))
        self.assertEqual((rb["ANSWERED_FROM"], ra["ANSWERED_FROM"]), (A, B))
        d = self.fleet.delivered
        self.assertEqual(len(d), 2)
        self.assertEqual(d[0][:2] + (d[0][3],), (A, B, "AMAP-CANARY " + NONCE))
        self.assertEqual(d[1][:2] + (d[1][3],), (B, A, "AMAP-CANARY-REPLY " + NONCE))
        # The reply names the canary the responder read, by the id the REAL reader showed it.
        self.assertEqual(rb["SENT_ID"], d[0][4])
        self.assertIn(d[1][2], (d[0][4], "notice-" + d[0][4]))
        self.assertEqual(stat.S_IMODE(os.stat(arec).st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
