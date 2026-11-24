"""S8 steps 6 and 7's decisions on RE's own outputs (design W13 d3; rulings W13-S8-LEDGER-INIT-IN-S8 and
W13-S8-RE-START; RE's answers 496e29e5 and 42923c47). Pure functions; the calls that fetch the bytes are the stage's.

Every refusal here is START.RE_REFUSED, rc 3: the ledger init is S8's first RE-path write, and RE's container is
S8's own after it.

- Step 6: `init_argv`, `init_ok` (rc 0 and exactly RE's one line) and `available` (the re-run --verify's ledger
  member is `{"available": true}`).
- Step 7: `start_argv` (the A2-07 [2] render: each mount's container path is its knob's value, the RW and RO sets
  fixed, nothing else; the env-file checked for the forbidden keys first), `obs_records` (one JSON object per log
  line, every other line skipped), `startup` (witness 1), `hub_progress` and `progressed` (witness 2), `inbound_clear`
  (witness 3), `exited` (the container state polled through all three) and `stop_timeout`.
"""

import json
import math

import a2_s6_env as e6
import a2_s8_checks as checks
from a2_causes import Refusal

STAGE = "START"
DOCKER = "/usr/bin/docker"
RE_NAME = "amap-re"
OUTCOME_LEDGER = "/app/host/outcome_ledger.py"
#: RE's mounts (A2-07 [2]): each knob's value is both the host and the container path.
RW_KNOBS = ("MAILBOX_ROOT_DIR", "RELAY_LEDGER_DIR", "HUB_INBOUND_STATE_DIR", "HOP_ROOT")
RO_KNOBS = ("HOP_REGISTRY_DIR", "HUB_D7_CONFIG", "HUB_PREFIX_TEMPLATE", "SMTP_PASSWORD_FILE", "TRANSPORT_PLUGIN_PATH")
#: RE's obs events, matched on the separate component and event members (RE's C3).
STARTUP = ("relay", "startup")
BACKOFF = ("relay", "hub_session_backoff")
REFUSALS = {("relay", "config_error"), ("relay", "secret_unavailable")}
INBOUND_FAILURES = {("inbound", "hub.poll_failed"), ("inbound", "hub.pump_stopped"), ("inbound", "hub.pump_failed"),
                    ("relay", "hub_auth_failed"), ("relay", "hub_protocol_error")}
#: The stop timeout: RELAY_SMTP_DOT_TIMEOUT (default 600, valid (0, 3600]) plus RE's join slack 60 and 10 (RE's C6).
DOT_DEFAULT_S, DOT_MAX_S, STOP_SLACK_S = 600, 3600, 70
#: Witness 2's window: progress must rise across at least 2 x interval_s + this many seconds.
PROGRESS_EXTRA_S = 5


def _refused(what):
    return Refusal(STAGE + ".RE_REFUSED", what, rc=3)


def init_argv(ledger, image_id, relay_uid, relay_gid):
    """RE's C5 form: --entrypoint python3, no -I, --mount (never -v), no env-file, no network. The ledger keeps S6's
    path rule (checks.mount_path) before it is spliced into --mount."""
    if not checks.mount_path(ledger):
        raise _refused("env-file mount knob")
    return [DOCKER, "run", "--rm", "--pull", "never", "--network", "none", "--user", "%d:%d" % (relay_uid, relay_gid),
            "--entrypoint", "python3", "--mount", "type=bind,src=%s,dst=%s" % (ledger, ledger), image_id,
            OUTCOME_LEDGER, "init", ledger]


def init_ok(rc, out, ledger):
    if rc != 0 or out != ("outcome_ledger: initialised %s\n" % ledger).encode():
        raise _refused("ledger init")


def available(out):
    """The --verify re-run after init: its ledger member must be exactly {"available": true}."""
    try:
        led = json.loads(out)["ledger"]
    except (ValueError, KeyError, TypeError, RecursionError):
        raise _refused("ledger check output")
    if led != {"available": True}:
        raise _refused("ledger not available after init")


def start_argv(env, env_file, image_id, relay_uid, relay_gid, hop_gid):
    """`docker run -d` for RE in the both mode, or RE_REFUSED when the env-file names a forbidden key or a mount knob
    is missing or breaks S6's path rule (checks.mount_path)."""
    if any(k in e6.ABSENT or k.startswith(e6.ABSENT_PREFIXES) for k in env):
        raise _refused("env-file forbidden key")
    mounts = []
    for knobs, ro in ((RW_KNOBS, False), (RO_KNOBS, True)):
        for k in knobs:
            v = env.get(k)
            if not checks.mount_path(v):
                raise _refused("env-file mount knob")
            mounts += ["--mount", "type=bind,src=%s,dst=%s%s" % (v, v, ",readonly" if ro else "")]
    return ([DOCKER, "run", "-d", "--pull", "never", "--restart", "no", "--name", RE_NAME,
             "--user", "%d:%d" % (relay_uid, relay_gid), "--group-add", str(hop_gid), "--env-file", env_file]
            + mounts + [image_id, "both"])


def obs_records(logs):
    """Each line of `docker logs` that parses as one JSON object, in order. Any other line (both_loop's plain text)
    is skipped, never a failure."""
    out = []
    for line in logs.split(b"\n"):
        try:
            doc = json.loads(line)
        except (ValueError, UnicodeDecodeError, RecursionError):
            continue
        if isinstance(doc, dict):
            out.append(doc)
    return out


def _key(rec):
    return rec.get("component"), rec.get("event")


def startup(records, link, plugin_sha):
    """Witness 1: True once RE logged its hub startup on `link` with the pinned plugin; False while it has not. A
    backoff or a refusal logged first refuses at once, as does a startup with another link or plugin."""
    for rec in records:
        k = _key(rec)
        if k == BACKOFF:
            raise _refused("hub session backoff before startup")
        if k in REFUSALS:
            raise _refused("relay refused its config")
        if k == STARTUP:
            if rec.get("role") != "hub" or rec.get("link") != link or rec.get("plugin_sha256") != plugin_sha:
                raise _refused("startup with another role, link or plugin")
            return True
    return False


def hub_progress(raw, created_ns, plugin_sha):
    """Witness 2's reading of <L>/hub-status.json: (progress, interval_s) when the document is this container's
    (process_started_ts at or after Created) and carries the pinned plugin; None when it is not this container's yet
    or does not parse. Another plugin refuses. Both write shapes are read; only progress is used."""
    import a2_s8_rl
    try:
        doc = json.loads(raw)
    except (ValueError, TypeError, UnicodeDecodeError, RecursionError):
        return None
    if not isinstance(doc, dict):
        return None
    began = a2_s8_rl.instant_ns(doc.get("process_started_ts"))
    progress, interval = doc.get("progress"), doc.get("interval_s")
    if (began is None or began < created_ns or type(progress) is not int
            or type(interval) not in (int, float) or not 0 < interval <= DOT_MAX_S):
        return None
    tp = doc.get("transport_plugin")
    if not isinstance(tp, dict) or tp.get("sha256") != plugin_sha:
        raise _refused("hub status names another plugin")
    return progress, interval


def progressed(first, now):
    """first and now are (monotonic ns, progress, interval_s). True once progress rose across at least
    2 x interval_s + 5 s."""
    (t0, p0, interval), (t1, p1, _i) = first, now
    return p1 > p0 and t1 - t0 >= int((2 * interval + PROGRESS_EXTRA_S) * 1_000_000_000)


def inbound_clear(records):
    """Witness 3: refuses on any inbound failure or final hub error RE logged."""
    for rec in records:
        if _key(rec) in INBOUND_FAILURES:
            raise _refused("inbound failure")


def exited(inspect_out):
    """The container state, polled through all three witnesses: RE_REFUSED once it is not running."""
    try:
        doc = json.loads(inspect_out)
        st = doc[0]["State"]
    except (ValueError, KeyError, IndexError, TypeError, RecursionError):
        raise _refused("inspect output")
    if not isinstance(st, dict) or st.get("Status") != "running" or st.get("Restarting") is not False:
        raise _refused("relay container exited")


def stop_timeout(env):
    """`docker stop -t` seconds: RELAY_SMTP_DOT_TIMEOUT when set and valid ((0, 3600]), else the default 600, plus
    70. A set but invalid value takes the maximum, so a stop never cuts a DOT short."""
    v = env.get("RELAY_SMTP_DOT_TIMEOUT")
    if v is None:
        return DOT_DEFAULT_S + STOP_SLACK_S
    try:
        dot = float(v)
    except ValueError:
        dot = None
    if dot is None or not 0 < dot <= DOT_MAX_S:
        return DOT_MAX_S + STOP_SLACK_S
    return math.ceil(dot) + STOP_SLACK_S
