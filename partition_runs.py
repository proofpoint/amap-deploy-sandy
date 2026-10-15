"""The weekly job's run record, as verify reads it: "no run of the weekly job
is left undecided".

The pinned writer (host_steps.py partition-weekly) keeps `weekly-runs.json`
in the evidence directory, beside the stop target: root:root 0444, a name
outside EVIDENCE_NAME, so the child's store can neither create nor replace
it. Whenever a run directory exists in the exec root (root 0700, which verify
cannot read), the record is absent or lists it: as `running` (its writer
published it before the child started), `kept` (its decision could not show
every effect done) or `undecided` (unreadable, or its directory could not be
removed). An empty list, on a valid record, is the only PASS.

A running entry is judged by its age on this host's wall clock, the same
clock the writer stamped it with: within the writer's own bound it is
UNKNOWN (recorded as in progress, not confirmed live), beyond it FAIL
(overdue and undecided). Neither asserts that any process lives or died.
A time ahead of this clock is UNKNOWN, never recent.
"""

import calendar
import posixpath
import re
import time
from typing import Any, Callable, Dict, List

import partition_activation as pa
import partition_evidence as pe
import partition_setup as ps
import router_health as rh

#: host_steps.WEEKLY_RUNS and its schema, held equal by a test: one name on each side.
WEEKLY_RUNS = "weekly-runs.json"
RUNS_SCHEMA = "amap-deploy.partition-runs/1"
RUNNING, KEPT, UNDECIDED = "running", "kept", "undecided"
#: host_steps.STALE_AFTER_S and PLACED_SLACK_S, held equal by a test.
STALE_AFTER_S = 5320
PLACED_SLACK_S = 2
RUNS_MEMBERS = {"schema": str, "host": str, "at": str, "runs": list}
RUN_MEMBERS = {"run_id": str, "state": str, "since": str}
_RUN_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")
_AT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")

RUNS_CLAIM = "no run of the weekly job is left undecided"
RUNS_REMEDY = ("start the weekly job once with its unit's exact argv; it decides the run first. A lock-held handoff "
               "means another holder still owns the per-host lock: wait and retry, never breaking or bypassing it")
KEPT_REMEDY = ("the writer kept a run's directory because it could not show its effects done: an open incident "
               "(incident-<run_id> under the evidence directory, if one exists) or a run recorded under another "
               "engine or docker; the job's journal names which. Start the job once to complete it")
RUNS_DO_NOT = "never remove a run directory, the lock or the record by hand, and never bypass the lock"


def _seconds(at: str) -> int:
    return calendar.timegm(time.strptime(at, "%Y-%m-%dT%H:%M:%SZ"))


def parse_runs(raw: bytes) -> Dict[str, Any]:
    """The record by its strict grammar: canonical JSON, exactly its members,
    times that parse, run ids by the run-id grammar, unique and sorted, at
    most one running. ValueError otherwise."""
    doc = ps._strict(raw)
    if not isinstance(doc, dict) or set(doc) != set(RUNS_MEMBERS):
        raise ValueError("not exactly the record's members")
    if pe.canonical(doc) != raw:
        raise ValueError("not in canonical form")
    if not all(isinstance(doc[k], t) for k, t in RUNS_MEMBERS.items()) or doc["schema"] != RUNS_SCHEMA:
        raise ValueError("not this record's schema")
    if not _AT.fullmatch(doc["at"]):
        raise ValueError("its time is malformed")
    _seconds(doc["at"])
    ids = []
    for run in doc["runs"]:
        if not isinstance(run, dict) or set(run) != set(RUN_MEMBERS) or \
                not all(isinstance(run[k], t) for k, t in RUN_MEMBERS.items()):
            raise ValueError("a run that is not exactly its members")
        if not _RUN_ID.fullmatch(run["run_id"]) or run["state"] not in (RUNNING, KEPT, UNDECIDED) or \
                not _AT.fullmatch(run["since"]):
            raise ValueError("a run's id, state or time is malformed")
        _seconds(run["since"])
        ids.append(run["run_id"])
    if ids != sorted(set(ids)):
        raise ValueError("its runs are repeated or out of order")
    if sum(r["state"] == RUNNING for r in doc["runs"]) > 1:
        raise ValueError("more than one run is running")
    return doc


def verify_runs(part: Any, gs: Any, *, live_config: str, read: Callable[[str], bytes] = ps.read_placed,
                read_live: Callable[[str], bytes] = ps.read_record,
                now: Callable[[], float] = time.time) -> List[rh.Check]:
    """The run record, read like the stop target's copy (one descriptor,
    root:root 0444, one link), in scope exactly as the stop target is: not
    required only when the live config, a strict object, carries no
    delegation AND the gate is not set. Any kept, undecided or overdue
    entry FAILs, even beside an UNKNOWN one; an empty list PASSes."""
    if part is None:
        return []
    want = rh.Fact("undecided runs", True, "the weekly job's own record of the runs it has not finished deciding")

    def fail(why: str, remedy: str = RUNS_REMEDY) -> List[rh.Check]:
        return [rh.check(RUNS_CLAIM, want, why, remedy, ok=lambda e, a: a is True, do_not=RUNS_DO_NOT)]

    def unknown(why: str, remedy: str = RUNS_REMEDY) -> List[rh.Check]:
        return [rh.unknown(RUNS_CLAIM, want, why, remedy)]
    try:
        live = ps._strict(read_live(live_config))
        if not isinstance(live, dict):
            raise ValueError("it is not a JSON object")
    except (OSError, ValueError, UnicodeDecodeError) as e:
        return unknown(f"whether delegation is rendered cannot be told: {e}",
                       "make the local router's live config readable, one JSON object")
    if "delegation" not in live and gs is None:
        return [rh.check(f"{RUNS_CLAIM} (not required: delegation is not rendered and the gate is not set)",
                         want, True, RUNS_REMEDY, ok=lambda e, a: a is True)]
    try:
        raw = read(posixpath.join(part.evidence_dir, WEEKLY_RUNS))
    except FileNotFoundError:
        return fail("no run record is published (the job has not run, or its record was invalidated and not "
                    "republished)")
    except OSError as e:
        if e.errno is None:
            return fail(f"its record is not the writer's: {e}")
        return unknown(f"its record cannot be read: {e}")
    try:
        doc = parse_runs(raw)
    except (ValueError, UnicodeDecodeError) as e:
        return fail(f"its record is not the writer's grammar: {e}")
    try:
        host = pa.parse_activation(read(posixpath.join(part.evidence_dir, ps.ACTIVATION)))["host"]
    except (OSError, ValueError) as e:
        return unknown(f"the host the record must name cannot be told from A1's record: {e}",
                       "place A1's approved record at its one place")
    if doc["host"] != host:
        return fail("its record is another host's")
    clock = now()
    if _seconds(doc["at"]) > clock + PLACED_SLACK_S:
        return unknown("the record's time is ahead of this host's clock", "check the host's clock")
    failing, unsure, kept = [], [], False
    for run in doc["runs"]:
        rid = run["run_id"]
        if run["state"] == KEPT:
            failing.append(f"run {rid} is kept: an effect is not yet shown done")
            kept = True
        elif run["state"] == UNDECIDED:
            failing.append(f"run {rid} is undecided: the writer could not read or remove it")
        elif _seconds(run["since"]) > clock + PLACED_SLACK_S:
            unsure.append(f"run {rid}'s time is ahead of this host's clock")
        elif clock - _seconds(run["since"]) > STALE_AFTER_S:
            failing.append(f"run {rid} is overdue and undecided")
        else:
            unsure.append(f"run {rid} is recorded as in progress; it is not confirmed live")
    if failing:
        return fail("; ".join(failing + unsure), KEPT_REMEDY if kept else RUNS_REMEDY)
    if unsure:
        return unknown("; ".join(unsure))
    return [rh.check(RUNS_CLAIM, want, True, RUNS_REMEDY, ok=lambda e, a: a is True)]
