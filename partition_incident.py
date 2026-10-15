"""The FAIL-STOP incident: what the weekly job does when a fail-stop probe
fails while the local router may be signing, the record it keeps, and the one
way the incident is closed.

The record, one root-owned directory per incident under the evidence
directory, never deleted:
- `incident-<run_id>/detected.json`: the failing run's id, the failing
  probes, the token in force, the local router's verified container id, the
  actions pending; written FIRST;
- `incident-<run_id>/events.jsonl`: append-only, each line fsynced, one
  event per effect (`rewrite_ok`/`rewrite_failed`, `stop_ok`/`stop_failed`/
  `stop_not_attempted`) and the one lifecycle event, `resolved`.
An incident is OPEN from `detected.json` until a `resolved` event. A history
that cannot be read, or that is incomplete, is OPEN.

The order never makes the stop depend on anything before it: the record,
then the rewrite (the local router's live config without `delegation`), then
the stop of the verified container id, each attempted whatever the earlier
step did. "Stopped" is recorded only when an inspect shows the id not
running, and nothing is ever stopped by name. When the record itself cannot
be written, the run says so exactly (`incident NOT recorded: <why>; rewrite
<outcome>; stop <outcome>`), still acts, and a later run writes the
incident late, marked so, from what is durable and what it can observe.

Closing: only `resolve`, with the operator's reason and fresh passing
evidence later than the incident, after checking CURRENT facts. A scheduled
pass never closes an incident.
"""

import json
import os
import posixpath
import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import router_health as rh

PREFIX = "incident-"
DETECTED = "detected.json"
EVENTS = "events.jsonl"
_RUN_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")
EFFECT_EVENTS = frozenset({"rewrite_ok", "rewrite_failed", "stop_ok", "stop_failed", "stop_not_attempted"})
LIFECYCLE_EVENTS = frozenset({"resolved"})


class Store:
    """The incident directory's durable writes: a new file by temporary name,
    fsync, rename and directory fsync; an appended line, fsynced. Each is one
    method so a test can make exactly one of them fail."""

    def mkdir(self, path: str) -> None:
        os.mkdir(path, 0o755)
        self._fsync_dir(posixpath.dirname(path))

    def new_file(self, path: str, data: bytes) -> None:
        tmp = f"{path}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(tmp, path)
        self._fsync_dir(posixpath.dirname(path))

    def append(self, path: str, line: bytes) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o644)
        try:
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)

    def read(self, path: str) -> bytes:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            chunks = []
            while True:
                b = os.read(fd, 65536)
                if not b:
                    return b"".join(chunks)
                chunks.append(b)
        finally:
            os.close(fd)

    def listdir(self, path: str) -> List[str]:
        return os.listdir(path)

    @staticmethod
    def _fsync_dir(path: str) -> None:
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class Effects:
    """What the job does to the world, and what it observes, as callables:
    - `rewrite()`: write the local router's live config without `delegation`
      (an atomic replace); raises on any failure;
    - `inspect(cid)`: {"running": bool} for that container id, None when no
      such container exists, or an Unresolved;
    - `stop(cid)`: `docker stop -t <bound> <cid>`; its result is never
      trusted alone, only the inspect after it;
    - `live_has_delegation()`: whether the live config file carries
      `delegation` now (bool or Unresolved);
    - `squatter_signing()`: whether any running container holding the local
      router's NAME runs with `delegation` (bool or Unresolved)."""

    def __init__(self, **kw: Callable):
        self.__dict__.update(kw)


def _line(event: Dict[str, Any]) -> bytes:
    return (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _try(fn: Callable, *a: Any) -> Optional[str]:
    """None when `fn` succeeded, else why it did not."""
    try:
        fn(*a)
        return None
    except (OSError, ValueError) as e:
        return f"{type(e).__name__}: {e}"


def act(store: Store, fx: Effects, *, evidence_dir: str, run_id: str, at: str, failing: Sequence[str],
        token: Optional[str], identity: Any, evidence_persisted: bool,
        emit: Callable[[str], None] = print) -> Tuple[int, str]:
    """The weekly job's FAIL-STOP action, decided by the run's IN-MEMORY
    fail-stop failure (`failing`). `identity` is the local router's verified
    container id from what is already durable (the activation document's
    vantage, or the last run record), or an Unresolved. Returns (exit code,
    status line); the exit is always nonzero, since an incident is never a
    success. Every diagnostic is also emitted, best-effort."""
    if not _RUN_ID.fullmatch(run_id):
        raise ValueError("the run id must be 1-64 of [A-Za-z0-9._-]")
    d = posixpath.join(evidence_dir, PREFIX + run_id)
    detected = {"run_id": run_id, "at": at, "failing": sorted(failing), "token": token,
                "identity": identity if isinstance(identity, str) else None,
                "pending": ["rewrite", "stop"], "failing_evidence_persisted": evidence_persisted}
    why = _try(store.mkdir, d) or _try(store.new_file, posixpath.join(d, DETECTED),
                                        json.dumps(detected, sort_keys=True).encode("utf-8"))
    recorded = why is None
    events = posixpath.join(d, EVENTS)

    def record(event: Dict[str, Any]) -> None:
        if recorded:
            failed = _try(store.append, events, _line(dict(event, at=at)))
            if failed:
                emit(f"partition-incident: could not record {event['event']}: {failed}")

    rewrite_failed = _try(fx.rewrite)
    rewrite = "ok" if rewrite_failed is None else f"failed ({rewrite_failed})"
    record({"event": "rewrite_ok"} if rewrite_failed is None else {"event": "rewrite_failed", "reason": rewrite_failed})
    stop = _stop(fx, identity)
    record(stop)
    status = (f"incident {'recorded' if recorded else 'NOT recorded: ' + str(why)}; "
              f"rewrite {rewrite}; stop {_stop_words(stop)}")
    emit(status)
    return 1, status


def _stop(fx: Effects, identity: Any) -> Dict[str, Any]:
    if not isinstance(identity, str):
        reason = identity.reason if isinstance(identity, rh.Unresolved) else "no identity"
        return {"event": "stop_not_attempted", "reason": f"the local router's identity is unreadable: {reason}"}
    seen = fx.inspect(identity)
    if isinstance(seen, rh.Unresolved):
        return {"event": "stop_not_attempted", "reason": f"cannot inspect {identity}: {seen.reason}"}
    if seen is None or not seen.get("running"):
        return {"event": "stop_not_attempted", "reason": f"{identity} is not running", "seen": seen}
    fx.stop(identity)
    after = fx.inspect(identity)
    if isinstance(after, rh.Unresolved):
        return {"event": "stop_failed", "reason": f"cannot inspect {identity} after the stop: {after.reason}"}
    if after is None or not after.get("running"):
        return {"event": "stop_ok", "id": identity}
    return {"event": "stop_failed", "reason": f"{identity} is still running", "id": identity}


def _stop_words(stop: Dict[str, Any]) -> str:
    return {"stop_ok": "ok"}.get(stop["event"], f"{stop['event'].replace('stop_', '')} ({stop.get('reason', '')})")


# --- Reading the record ----------------------------------------------------------------


class Incident:
    def __init__(self, run_id: str, detected: Any, events: Any):
        self.run_id, self.detected, self.events = run_id, detected, events

    @property
    def open(self) -> bool:
        """Closed only by a well-formed history holding a `resolved` event."""
        if isinstance(self.detected, rh.Unresolved) or isinstance(self.events, rh.Unresolved):
            return True
        return not any(e.get("event") == "resolved" for e in self.events)

    def pending(self) -> List[str]:
        if isinstance(self.events, rh.Unresolved):
            return ["rewrite", "stop"]
        kinds = {e.get("event") for e in self.events}
        out = []
        if "rewrite_ok" not in kinds:
            out.append("rewrite")
        if "stop_ok" not in kinds:
            out.append("stop")
        return out


def read_all(store: Store, evidence_dir: str) -> Any:
    """Every incident under `evidence_dir`, or an Unresolved when the
    directory cannot be listed (which vetoes as an open incident would)."""
    try:
        names = sorted(n for n in store.listdir(evidence_dir) if n.startswith(PREFIX))
    except OSError as e:
        return rh.Unresolved(f"cannot list {evidence_dir}: {e}")
    out = []
    for n in names:
        d = posixpath.join(evidence_dir, n)
        try:
            detected: Any = json.loads(store.read(posixpath.join(d, DETECTED)))
            if not isinstance(detected, dict):
                raise ValueError("not an object")
        except (OSError, ValueError) as e:
            detected = rh.Unresolved(f"{n}/{DETECTED}: {e}")
        try:
            raw = store.read(posixpath.join(d, EVENTS))
        except FileNotFoundError:
            raw = b""
        except OSError as e:
            raw = rh.Unresolved(f"{n}/{EVENTS}: {e}")
        events: Any = raw
        if not isinstance(raw, rh.Unresolved):
            try:
                events = [json.loads(l) for l in raw.decode("utf-8").splitlines() if l.strip()]
                if not raw.endswith(b"\n") and raw:
                    raise ValueError("a truncated last line")
                if not all(isinstance(e, dict) and e.get("event") in EFFECT_EVENTS | LIFECYCLE_EVENTS for e in events):
                    raise ValueError("an event outside the vocabulary")
            except (UnicodeDecodeError, ValueError) as e:
                events = rh.Unresolved(f"{n}/{EVENTS}: {e}")
        out.append(Incident(n[len(PREFIX):], detected, events))
    return out


def open_incidents(store: Store, evidence_dir: str) -> Any:
    got = read_all(store, evidence_dir)
    return got if isinstance(got, rh.Unresolved) else [i for i in got if i.open]


# --- Completion and the late record ----------------------------------------------------


def complete(store: Store, fx: Effects, *, evidence_dir: str, at: str, identity: Any,
             late: Optional[Dict[str, Any]] = None, emit: Callable[[str], None] = print) -> List[str]:
    """Finish what crashed or could not be recorded, idempotently, from
    CURRENT facts. `late`: an incident a run acted on but could not record
    ({run_id, failing, token, failing_evidence_persisted}), written now,
    marked `recorded_late` and `taken_without_record`, so the veto applies.
    Each completion is appended as an event."""
    said = []
    if late is not None:
        d = posixpath.join(evidence_dir, PREFIX + late["run_id"])
        detected = dict(late, identity=identity if isinstance(identity, str) else None,
                        pending=["rewrite", "stop"], recorded_late=True, taken_without_record=True)
        why = None if _exists(store, d) else _try(store.mkdir, d)
        why = why or _try(store.new_file, posixpath.join(d, DETECTED), json.dumps(detected, sort_keys=True).encode())
        said.append(f"late incident {late['run_id']}: " + ("recorded" if why is None else f"NOT recorded: {why}"))
    got = read_all(store, evidence_dir)
    if isinstance(got, rh.Unresolved):
        return said + [got.reason]
    for inc in got:
        if not inc.open:
            continue
        events = posixpath.join(evidence_dir, PREFIX + inc.run_id, EVENTS)
        if "rewrite" in inc.pending():
            has = fx.live_has_delegation()
            if has is True:
                failed = _try(fx.rewrite)
                ev = {"event": "rewrite_ok"} if failed is None else {"event": "rewrite_failed", "reason": failed}
            elif has is False:
                ev = {"event": "rewrite_ok", "observed": "the live config carries no delegation"}
            else:
                ev = {"event": "rewrite_failed", "reason": f"cannot observe the live config: {has.reason}"}
            _try(store.append, events, _line(dict(ev, at=at, completion=True)))
            said.append(f"{inc.run_id}: {ev['event']}")
        if "stop" in inc.pending():
            seen = fx.inspect(identity) if isinstance(identity, str) else None
            if isinstance(identity, str) and isinstance(seen, dict) and not seen.get("running"):
                ev = {"event": "stop_ok", "id": identity, "observed": "not running"}
            else:
                ev = _stop(fx, identity)
            _try(store.append, events, _line(dict(ev, at=at, completion=True)))
            said.append(f"{inc.run_id}: {ev['event']}")
    for s in said:
        emit(s)
    return said


def _exists(store: Store, path: str) -> bool:
    try:
        store.listdir(path)
        return True
    except OSError:
        return False


# --- Resolution ---------------------------------------------------------------------------


def resolve(store: Store, fx: Effects, *, evidence_dir: str, run_id: str, reason: str, at: str,
            fresh: Any, identity: Any) -> List[str]:
    """Close incident `run_id`: every prerequisite is checked against CURRENT
    facts, and the one `resolved` event is appended. `fresh`: the newer
    evidence document (parsed) with its staleness reasons, as (doc, reasons),
    or an Unresolved. Returns why it refuses; empty when it resolved."""
    got = read_all(store, evidence_dir)
    if isinstance(got, rh.Unresolved):
        return [got.reason]
    inc = next((i for i in got if i.run_id == run_id), None)
    if inc is None:
        return [f"no incident {run_id}"]
    if not inc.open:
        return [f"incident {run_id} is already resolved"]
    bad = []
    if isinstance(inc.detected, rh.Unresolved) or isinstance(inc.events, rh.Unresolved):
        bad.append("its record cannot be read; complete it first (--complete-incident)")
    elif "rewrite" in inc.pending():
        bad.append("its rewrite is not complete")
    if not reason.strip():
        bad.append("an operator reason is required")
    has = fx.live_has_delegation()
    if has is not False:
        bad.append("the live config still carries delegation" if has is True else f"cannot observe the live config: {has.reason}")
    squat = fx.squatter_signing()
    if squat is not False:
        bad.append("a container holding the local router's name runs with delegation" if squat is True
                   else f"cannot observe the containers: {squat.reason}")
    running = fx.inspect(identity) if isinstance(identity, str) else None
    if isinstance(running, rh.Unresolved):
        bad.append(f"cannot inspect the local router: {running.reason}")
    if isinstance(fresh, rh.Unresolved):
        bad.append(f"no fresh evidence: {fresh.reason}")
    else:
        doc, stale = fresh
        detected_at = inc.detected.get("at") if isinstance(inc.detected, dict) else None
        if stale:
            bad.append("the fresh evidence does not count: " + "; ".join(stale))
        if detected_at is None or not doc["at"] > detected_at or doc["run_id"] == run_id:
            bad.append("the evidence is not later than the incident")
    if bad:
        return bad
    failed = _try(store.append, posixpath.join(evidence_dir, PREFIX + run_id, EVENTS),
                  _line({"event": "resolved", "at": at, "evidence": fresh[0]["run_id"], "reason": reason}))
    return [f"the resolution could not be recorded: {failed}"] if failed else []
