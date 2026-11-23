"""S8 step 5's decisions on RL's own documents (design W13 d3, ruling W13-S8-RL-START; RL's answers 4bcf9669 and
2b79f2e1). Pure functions over bytes; the calls that fetch them are the stage's.

- `container_state(inspect_out)`: `docker inspect amap-rl`'s one object. Running, not restarting, and a top-level
  RestartCount of 0, or START.RL_REFUSED at once. Returns State.StartedAt in nanoseconds. The field names are RL's
  (2b79f2e1); a real capture is PENDING (a loop-VM item).
- `binds(status, started_ns)`: whether status.json is THIS process's first poll: process_started_ts at or after
  StartedAt less 1 s, and polls >= 1, as RL binds them. A document that does not parse is not yet bound.
- `admitting(status, ...)`: RL's six conditions on the bound document. Any broken one is START.NOT_ADMITTING; the
  peer store's `why` and `warnings` come back as receipt notes, never a refusal.

Both causes are rc 3: RL's container was started by S8 before any of these is read.
"""

import json
import re

from a2_causes import Refusal

STAGE = "START"
#: RL's clock-resolution allowance between State.StartedAt and process_started_ts, as RL states it.
BIND_SLACK_NS = 1_000_000_000
_INSTANT = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z")


def _refused(what):
    return Refusal(STAGE + ".RL_REFUSED", what, rc=3)


def _not_admitting(what):
    return Refusal(STAGE + ".NOT_ADMITTING", what, rc=3)


def instant_ns(s):
    """A UTC instant ("...Z", up to nanoseconds: docker's RFC 3339 and RL's microsecond form) in nanoseconds since the
    epoch, or None."""
    import calendar
    m = _INSTANT.fullmatch(s) if isinstance(s, str) else None
    if m is None:
        return None
    y, mo, d, h, mi, sec = (int(g) for g in m.groups()[:6])
    if not (1 <= y and 1 <= mo <= 12 and 1 <= d <= calendar.monthrange(y, mo)[1] and h < 24 and mi < 60
            and sec < 60):
        return None
    try:
        whole = calendar.timegm((y, mo, d, h, mi, sec, 0, 0, 0))
    except (ValueError, OverflowError):
        return None
    frac = (m.group(7) or "").ljust(9, "0")
    return whole * 1_000_000_000 + int(frac)


def _doc(raw):
    try:
        return json.loads(raw)
    except (ValueError, TypeError, UnicodeDecodeError, RecursionError):
        return None


def container_state(inspect_out):
    """State.StartedAt in ns from `docker inspect amap-rl`'s stdout (a JSON array of one object), or RL_REFUSED."""
    doc = _doc(inspect_out)
    if not isinstance(doc, list) or len(doc) != 1 or not isinstance(doc[0], dict):
        raise _refused("inspect output")
    c = doc[0]
    st = c.get("State")
    if not isinstance(st, dict) or st.get("Status") != "running" or st.get("Restarting") is not False:
        raise _refused("not running")
    if type(c.get("RestartCount")) is not int or c["RestartCount"] != 0:
        raise _refused("restarted")
    started = instant_ns(st.get("StartedAt"))
    if started is None:
        raise _refused("StartedAt")
    return started


def binds(status_raw, started_ns):
    """The parsed status document when it is THIS process's first poll, else None (not yet)."""
    doc = _doc(status_raw)
    if not isinstance(doc, dict):
        return None
    began = instant_ns(doc.get("process_started_ts"))
    polls = doc.get("polls")
    if began is None or type(polls) is not int or polls < 1 or began < started_ns - BIND_SLACK_NS:
        return None
    return doc


def admitting(doc, names, key_public, key_id, plugin_sha, plugin_path):
    """RL's six conditions on a bound status document. Returns the receipt notes (the peer store's why and
    warnings); any broken condition refuses NOT_ADMITTING."""
    polls = doc["polls"]
    admitted, instances = doc.get("admitted"), doc.get("instances")
    if not isinstance(admitted, list) or not isinstance(instances, dict) or not names:
        raise _not_admitting("instance")
    for n in names:
        inst = instances.get(n)
        totals = inst.get("totals") if isinstance(inst, dict) else None
        if (n not in admitted or not isinstance(totals, dict) or type(inst.get("poll")) is not int
                or inst["poll"] != polls or type(totals.get("instance_errored")) is not int
                or totals["instance_errored"] != 0):
            raise _not_admitting("instance")
    reg = doc.get("registry")
    if not isinstance(reg, dict) or reg.get("state") != "ok" or reg.get("held") != {}:
        raise _not_admitting("registry")
    ps = doc.get("peer_store")
    if not isinstance(ps, dict) or ps.get("admission") != "open":
        raise _not_admitting("peer store admission")
    dl = doc.get("delegation")
    if (not isinstance(dl, dict) or dl.get("active") is not True or "error" in dl
            or dl.get("signing_public_key") != key_public or dl.get("signing_key_id") != key_id):
        raise _not_admitting("delegation")
    cl = doc.get("classification")
    if cl is not None and (not isinstance(cl, dict) or "config_reload_failed" in cl):
        raise _not_admitting("classification")
    tp = doc.get("transport_plugin")
    if not isinstance(tp, dict) or tp.get("sha256") != plugin_sha or tp.get("path") != plugin_path:
        raise _not_admitting("transport plugin")
    notes = []
    if ps.get("why") is not None:
        notes.append(("RL_PEER_STORE_WHY", _token(ps["why"])))
    w = ps.get("warnings")
    if isinstance(w, list) and w:
        notes.append(("RL_PEER_STORE_WARNINGS", ",".join(_token(x) for x in w[:NOTE_MAX])))
    return notes


#: At most this many peer-store warnings are noted; each is kept only as a token, since a receipt value is printable
#: ASCII that the output guard reads.
NOTE_MAX = 8
_TOKEN = re.compile(r"[a-z0-9_]{1,64}")


def _token(v):
    return v if isinstance(v, str) and _TOKEN.fullmatch(v) else "other"
