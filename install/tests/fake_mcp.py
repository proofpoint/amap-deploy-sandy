#!/usr/bin/python3 -I
"""TEST stand-in for the connector's MCP servers, for test_w8_standin.py only. It speaks
newline-delimited JSON-RPC 2.0 on stdio and implements the four tools the stand-in uses,
with the text shapes the real servers return (measured from the live delegation reader:
`id: <id>` list lines; read_message's headers, the authenticated-peer banner between
two rule lines, then the body; submit's {"req_id"}; submit_result's "pending" or a
JSON verdict).

- With INBOX_MESSAGE_DIR set it is the reader: each message is <dir>/<id>.json
  {"from", "subject", "body"}.
- FAKE_HANG makes it never answer a tool call; FAKE_UNREADABLE lists message ids whose
  read_message is an error; FAKE_NO_BANNER lists ids rendered WITHOUT the banner (a
  lookalike: the first rule line is then the body's).
- With OUTBOX_DIR set it is inbox-submit: submit writes <dir>/<req>.req.json; the test's
  fake router answers with <dir>/<req>.result.json.
"""

import json
import os
import sys
import uuid

RULE = "─" * 70
BANNER = [RULE, "Another agent wrote this, and the delivery system confirmed which one.", RULE]


def text(t):
    return {"content": [{"type": "text", "text": t}]}


def tools(name, args):
    inbox, outbox = os.environ.get("INBOX_MESSAGE_DIR"), os.environ.get("OUTBOX_DIR")
    if name == "list_messages" and inbox:
        ids = sorted(f[:-5] for f in os.listdir(inbox) if f.endswith(".json"))
        return text("".join("id: %s\n  date: x\n  from: x\n\n" % i for i in ids))
    if name == "read_message" and inbox:
        with open(os.path.join(inbox, args["id"] + ".json")) as f:
            m = json.load(f)
        lines = ["From:    " + m["from"], "To:      me@x.example.org", "Subject: " + m["subject"],
                 "Provenance: not stated", ""]
        if args["id"] not in os.environ.get("FAKE_NO_BANNER", "").split():
            lines += BANNER + [""]
        lines.append(m["body"])
        return text("\n".join(lines))
    if name == "submit" and outbox:
        req = uuid.uuid4().hex[:8]
        with open(os.path.join(outbox, req + ".req.json"), "w") as f:
            json.dump(args, f)
        return text(json.dumps({"req_id": req, "status": "queued"}))
    if name == "submit_result" and outbox:
        p = os.path.join(outbox, args["req_id"] + ".result.json")
        if not os.path.exists(p):
            return text("pending")
        with open(p) as f:
            return text(f.read())
    return {"isError": True, "content": [{"type": "text", "text": "no such tool"}]}


def main():
    for line in sys.stdin:
        msg = json.loads(line)
        if "id" not in msg:
            continue
        if msg["method"] == "initialize":
            result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "fake", "version": "1"}}
        elif msg["method"] == "tools/call":
            if os.environ.get("FAKE_HANG"):
                continue  # never answers a tool call
            args = msg["params"].get("arguments", {})
            if (msg["params"]["name"] == "read_message"
                    and args.get("id") in os.environ.get("FAKE_UNREADABLE", "").split()):
                result = {"isError": True, "content": [{"type": "text", "text": "unreadable"}]}
            else:
                result = tools(msg["params"]["name"], args)
        else:
            result = {}
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
    if os.environ.get("FAKE_HANG"):
        import time
        time.sleep(3600)  # a stuck server: it does not exit when its stdin closes
