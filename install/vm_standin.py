"""The stand-in agent (W8; DS rulings 726a48c8 and e321121f), run on a VM by vm_exec as the
agent account, in the closed environment, only for the canary command's duration (W13
starts and stops it). It is a separate agents[] entry per VM (for example agent-canary),
never a real agent's lanes. It runs from the amap payload, which S6 places.

    /usr/bin/python3 -I -B <payload>/vm_standin.py --role initiator|responder --nonce N
        --peer ADDRESS --record PATH --payload-root <payload> [--deadline-s S]

It is not a model and not a general responder. It drives the connector's REAL MCP servers
over stdio, with the commands and lane variables of the payload's own mcp-servers.json:
- the `delegation` reader (list_messages, read_message) on the agent's peer lane;
- `inbox-submit` (submit, submit_result) on its outbox.
No private path into router state is used.

The roles:
- initiator: submits ONE delegation to --peer whose body is exactly `AMAP-CANARY <nonce>`,
  waits for the router's `accepted`, then waits for ONE delegation from --peer whose
  body is exactly `AMAP-CANARY-REPLY <nonce>`.
- responder: answers ONLY a delegation from --peer whose body is exactly
  `AMAP-CANARY <nonce>` for this run's nonce, ONCE, with the reply and in_reply_to set
  to its id. Every other message, and one it cannot read, is recorded by id only and
  left unanswered.
"Exactly" means exact after the connector's rendering (read_message's text: headers,
then the authenticated-peer banner between two rule lines, then the body). The sender
is taken only from the headers before the banner. The nonce matches ^[A-Za-z0-9]{8,64}$.

The bound is hard: every read from a server waits only for the time left before the
deadline. The servers run in their own process group, which is killed on exit and on
SIGTERM or SIGHUP. The record is created at the start (O_EXCL, mode 0600) and always written,
whatever happens. It holds key=value lines: ROLE, RESULT (PASS, FAIL or TIMEOUT), CAUSE,
SENT_ID, REPLY_ID, ANSWERED_FROM, IGNORED_IDS. It never holds a message body.
Exit 0 on PASS, 1 otherwise.
"""

import argparse
import json
import os
import re
import select
import signal
import subprocess
import sys
import time

NONCE = re.compile(r"[A-Za-z0-9]{8,64}")
ADDRESS = re.compile(r"[A-Za-z0-9._-]{1,64}@[A-Za-z0-9.-]{1,253}")
CANARY = "AMAP-CANARY %s"
REPLY = "AMAP-CANARY-REPLY %s"
CONTAINER_ROOT = "/opt/sandy/features/amap"
RULE = "───"
BANNER_FIRST = "Another agent wrote this"
PASS_THROUGH = ("AMAP_SELF", "AMAP_FLEET_DOMAIN", "AMAP_IDENTITY_DIR", "AMAP_IDENTITY")
POLL_S = 1.0
PROTOCOL = "2024-11-05"
LINE_MAX = 1 << 20


class Failed(Exception):
    pass


class Stopped(BaseException):
    pass


# ------------------------------------------------------------- MCP over stdio

class McpServer:
    """One MCP server process in its own process group, spoken to with newline-delimited
    JSON-RPC 2.0. Every read waits only until the deadline."""

    def __init__(self, argv, env, deadline):
        self.deadline = deadline
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, env=env, close_fds=True, start_new_session=True)
        self.buf = b""
        self.next_id = 0
        try:
            self.call("initialize", {"protocolVersion": PROTOCOL, "capabilities": {},
                                     "clientInfo": {"name": "amap-standin", "version": "1"}})
            self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        except BaseException:
            self.close()
            raise

    def _send(self, msg):
        try:
            self.p.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
            self.p.stdin.flush()
        except OSError:
            raise Failed("server ended")

    def _line(self):
        fd = self.p.stdout.fileno()
        while b"\n" not in self.buf:
            left = self.deadline - time.monotonic()
            if left <= 0:
                raise Failed("TIMEOUT")
            ready, _, _ = select.select([fd], [], [], left)
            if not ready:
                raise Failed("TIMEOUT")
            chunk = os.read(fd, 65536)
            if not chunk:
                raise Failed("server ended")
            self.buf += chunk
            if len(self.buf) > LINE_MAX:
                raise Failed("server line too long")
        line, self.buf = self.buf.split(b"\n", 1)
        return line

    def call(self, method, params):
        self.next_id += 1
        want = self.next_id
        self._send({"jsonrpc": "2.0", "id": want, "method": method, "params": params})
        while True:
            try:
                msg = json.loads(self._line())
            except ValueError:
                raise Failed("server spoke no JSON")
            if isinstance(msg, dict) and msg.get("id") == want:
                if "error" in msg:
                    raise Failed("server error")
                return msg["result"]

    def tool(self, name, **arguments):
        result = self.call("tools/call", {"name": name, "arguments": arguments})
        if result.get("isError"):
            raise Failed("tool error")
        return "".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")

    def close(self):
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(self.p.pid, sig)
            except (ProcessLookupError, PermissionError):
                break
            try:
                self.p.wait(timeout=2)
                break
            except subprocess.TimeoutExpired:
                continue


def server_env(spec, environ):
    """The env mcp-servers.json gives a server, with ${AMAP_*} from `environ` (the agent's
    lane exports). An AMAP variable that is unset or empty refuses."""
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    for k in ("HOME",) + PASS_THROUGH:
        if environ.get(k):
            env[k] = environ[k]
    for key, value in spec.get("env", {}).items():
        def sub(m):
            if not environ.get(m.group(1)):
                raise Failed("lane export missing")
            return environ[m.group(1)]
        env[key] = re.sub(r"\$\{(AMAP_[A-Z_]+)\}", sub, value)
    return env


def server_argv(spec, payload_root):
    """The spec's command, mapped from the container's payload path to the VM's, and
    required to stay under the payload root once resolved."""
    cmd = spec["command"]
    if not cmd.startswith(CONTAINER_ROOT + "/"):
        raise Failed("server command outside the payload")
    path = os.path.realpath(payload_root + cmd[len(CONTAINER_ROOT):])
    root = os.path.realpath(payload_root)
    if not path.startswith(root + "/"):
        raise Failed("server command outside the payload")
    return [path] + [str(a) for a in spec.get("args", [])]


def start(payload_root, environ, deadline, started):
    with open(os.path.join(payload_root, "mcp-servers.json"), encoding="utf-8") as f:
        specs = json.load(f)["mcpServers"]
    for name in ("delegation", "inbox-submit"):
        started[name] = None
        started[name] = McpServer(server_argv(specs[name], payload_root), server_env(specs[name], environ),
                                  deadline)
    return started


# ---------------------------------------------------- the connector's text

def listed_ids(text):
    return re.findall(r"(?m)^id: +(\S+)$", text)


def message_parts(text):
    """(sender, body) from read_message's text, or (None, None). The sender comes only
    from the headers before the FIRST rule line; that rule line must open the
    authenticated-peer banner; the body is everything after the banner's closing rule."""
    lines = text.split("\n")
    rules = [i for i, line in enumerate(lines) if line.startswith(RULE)]
    if len(rules) < 2 or rules[0] + 1 >= len(lines) or not lines[rules[0] + 1].startswith(BANNER_FIRST):
        return None, None
    senders = [m.group(1) for line in lines[:rules[0]] for m in [re.fullmatch(r"From: +(\S+)", line)] if m]
    if len(senders) != 1:
        return None, None
    return senders[0], "\n".join(lines[rules[1] + 1:]).strip("\n")


def verdict_of(text):
    """submit_result's verdict: "pending", or the last line that is a JSON object (a
    preceding attestation line is tolerated)."""
    if text.strip() == "pending":
        return None
    for line in reversed(text.strip().splitlines()):
        try:
            v = json.loads(line)
        except ValueError:
            continue
        if isinstance(v, dict):
            return v
    raise Failed("submit_result gave no verdict")


def submitted(submit, text, deadline):
    try:
        req = json.loads(text.strip().splitlines()[-1])["req_id"]
    except (ValueError, KeyError, TypeError, IndexError):
        raise Failed("submit gave no req_id")
    while time.monotonic() < deadline:
        v = verdict_of(submit.tool("submit_result", req_id=req))
        if v is not None:
            if v.get("outcome") != "accepted":
                raise Failed("not accepted")
            return v.get("message_id")
        time.sleep(min(POLL_S, max(0.0, deadline - time.monotonic())))
    raise Failed("TIMEOUT")


def read(srv, mid):
    """(sender, body) of one message; (None, None) when it cannot be read."""
    try:
        return message_parts(srv["delegation"].tool("read_message", id=mid))
    except Failed as e:
        if str(e) == "TIMEOUT":
            raise
        return None, None


# --------------------------------------------------------------- the roles

def initiator(srv, nonce, peer, deadline, rec):
    seen = set(listed_ids(srv["delegation"].tool("list_messages", n=50)))
    out = srv["inbox-submit"].tool("submit", to=[peer], subject="AMAP-CANARY", body_text=CANARY % nonce)
    rec["SENT_ID"] = submitted(srv["inbox-submit"], out, deadline) or "-"
    while time.monotonic() < deadline:
        for mid in listed_ids(srv["delegation"].tool("list_messages", n=50)):
            if mid in seen:
                continue
            seen.add(mid)
            sender, body = read(srv, mid)
            if sender == peer and body == REPLY % nonce:
                rec["REPLY_ID"], rec["ANSWERED_FROM"] = mid, sender
                return
            rec.setdefault("IGNORED", []).append(mid)
        time.sleep(min(POLL_S, max(0.0, deadline - time.monotonic())))
    raise Failed("TIMEOUT")


def responder(srv, nonce, peer, deadline, rec):
    seen = set()
    while time.monotonic() < deadline:
        for mid in listed_ids(srv["delegation"].tool("list_messages", n=50)):
            if mid in seen:
                continue
            seen.add(mid)
            sender, body = read(srv, mid)
            if sender == peer and body == CANARY % nonce:
                out = srv["inbox-submit"].tool("submit", to=[sender], in_reply_to=mid,
                                               subject="AMAP-CANARY-REPLY", body_text=REPLY % nonce)
                rec["SENT_ID"], rec["ANSWERED_FROM"] = mid, sender
                rec["REPLY_ID"] = submitted(srv["inbox-submit"], out, deadline) or "-"
                return
            rec.setdefault("IGNORED", []).append(mid)
        time.sleep(min(POLL_S, max(0.0, deadline - time.monotonic())))
    raise Failed("TIMEOUT")


def finish_record(fd, rec):
    lines = ["%s=%s" % (k, v) for k, v in rec.items() if k != "IGNORED"]
    lines.append("IGNORED_IDS=%s" % " ".join(rec.get("IGNORED", [])))
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write("\n".join(lines) + "\n")


def _on_term(_sig, _frame):
    raise Stopped()


def main(argv, environ=None):
    ap = argparse.ArgumentParser(prog="vm_standin.py")
    ap.add_argument("--role", choices=("initiator", "responder"), required=True)
    ap.add_argument("--nonce", required=True)
    ap.add_argument("--peer", required=True)
    ap.add_argument("--payload-root", required=True)
    ap.add_argument("--deadline-s", type=int, default=300)
    ap.add_argument("--record", required=True)
    a = ap.parse_args(argv)
    if not NONCE.fullmatch(a.nonce) or not 1 <= a.deadline_s <= 3600 or not ADDRESS.fullmatch(a.peer):
        ap.error("invalid arguments")
    rec_fd = os.open(a.record, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    rec = {"ROLE": a.role, "RESULT": "FAIL", "CAUSE": "unclassified"}
    srv = {}
    deadline = time.monotonic() + a.deadline_s
    for sig in (signal.SIGTERM, signal.SIGHUP):  # a hangup (ssh teardown) is a stop too
        signal.signal(sig, _on_term)
    try:
        start(a.payload_root, os.environ if environ is None else environ, deadline, srv)
        if a.role == "initiator":
            initiator(srv, a.nonce, a.peer, deadline, rec)
        else:
            responder(srv, a.nonce, a.peer, deadline, rec)
        rec["RESULT"] = "PASS"
        del rec["CAUSE"]
    except Failed as e:
        rec["RESULT"] = "TIMEOUT" if str(e) == "TIMEOUT" else "FAIL"
        rec["CAUSE"] = str(e)
    except Stopped:
        rec["RESULT"], rec["CAUSE"] = "FAIL", "stopped"
    except BaseException:
        rec["RESULT"], rec["CAUSE"] = "FAIL", "unclassified"
    finally:
        for s in srv.values():
            if s is not None:
                s.close()
        finish_record(rec_fd, rec)
    return 0 if rec["RESULT"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
