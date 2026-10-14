"""delivery_checks.py — what `verify` reports about delivery itself: which
session lister a sandbox needs, the posture of its named sessions, which
connector build the payload's daemon is, and the peer notices it has not
handled.

FOUR DETECTORS, all read host-side from files sandy, the payload and the
daemon already keep:

- MODE. Sandy's named Claude sessions (`.sandy/sessions/*.md`) run the
  agent as background jobs with no tmux pane, and the shipped session
  lister (`payload/handoff-sessions`) lists panes only. A sandbox whose last
  launch declared named sessions therefore gets no delivery at all: the
  daemon finds no target, waits, and logs nothing. The mode is read from
  `--print-state`'s `claude_sessions` (sandy 2.9.0, additive): `null` is
  "cannot answer" and is read against `marker.state`; `declared` non-empty
  is named mode.
- POSTURE, in named mode only, AS SANDY REPORTS IT: `claude_sessions.status`
  is copied from a file in the agent's own home, so it is a report and not a
  trust root. The claimant (the one declared session receiving
  `cross_session`) must be `up` and must not have been created without this
  feature's arguments (`drift` `missing:`); every other session must carry
  the refuse pin (`inbound_pinned` `no` is a failure) and must not hold this
  feature's arguments (`drift` `extra:`). Sandy diverts a receiving
  feature's `agent_args` to the claimant alone, so this feature's arguments
  on another session mean it was created before that, and it holds the
  submit tools without being the one that receives.
- DAEMON VERSION. The payload's `inbox-delivery` is hashed (the file's
  sha256) and mapped to the connector commit whose `bin/inbox-delivery` has
  those bytes, by walking the file's history in the connector checkout. The
  siblings.json pin is what CI ran; deployed bytes that are another commit's
  are DRIFT, never "older", and bytes no commit has are UNKNOWN, naming the
  hash.
- UNHANDLED. Peer notices with no ledger entry, counted with THE DEPLOYED
  DAEMON'S OWN `NOTICE_FILE_RE`, parsed out of the deployed file, because
  the pattern decides which notices a daemon sees at all. A ledger entry
  means "handled" (delivered, refused or denied alike), so the count is
  labelled unhandled, never undelivered. Over `UNHANDLED_MAX_AGE_SECONDS`
  on a running sandbox is a problem.

Standard library only, and nothing here runs sandy, docker or the daemon:
the caller hands in the record, the paths and the checkout.
"""

import ast
import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

# `--print-state`'s per-sandbox key for named Claude sessions, and its parts.
CLAUDE_SESSIONS_KEY = "claude_sessions"
DECLARED_KEY = "declared"
STATUS_KEY = "status"
RECEIVES_CROSS_SESSION = "cross_session"

# The values sandy writes into a session's status row (`.sandy-sessions.tsv`).
STATE_UP = "up"
PINNED_NO = "no"
DRIFT_MISSING = "missing: "
DRIFT_EXTRA = "extra: "

# Whether the payload's session lister can serve named sessions. It lists
# tmux panes only; a lister for named sessions is issue #45's fix.
DEPLOYED_LISTER_SERVES_NAMED_SESSIONS = False

# The connector file whose bytes identify the daemon, relative to its checkout.
DAEMON_REL = "bin/inbox-delivery"
# The daemon's notice-file pattern, by the name it binds in that file.
NOTICE_RE_NAME = "NOTICE_FILE_RE"
# The daemon's ledger: one empty file per handled notice, `<tree>-<id>`.
LEDGER_PEER_PREFIX = "peer-"
# The router's timestamp in a notice.
NOTICE_TS_KEY = "ts"
# A notice larger than this is not read for its timestamp.
NOTICE_READ_LIMIT = 1 << 20

# How long a peer notice may sit unhandled on a running sandbox before verify
# calls it a problem. A healthy daemon handles one within a poll or two.
UNHANDLED_MAX_AGE_SECONDS = 15 * 60


# ------------------------------------------------------------------ mode

NAMED = "named"
PANE = "pane"


def session_mode(record: Optional[Dict[str, Any]], marker_present: str = "present"
                 ) -> Tuple[Optional[str], str]:
    """`(mode, why)`: NAMED, PANE, or None when it cannot be told.

    Absent key: this sandy predates named sessions, so none can run. `null`
    with the marker present: the last launch was by a sandy predating the
    field, which could not run them either. `null` otherwise: not launched,
    or a marker sandy cannot read, so it cannot be told."""
    if not isinstance(record, dict) or CLAUDE_SESSIONS_KEY not in record:
        return PANE, "this sandy reports no claude_sessions, so it has no named sessions"
    cs = record[CLAUDE_SESSIONS_KEY]
    if cs is None:
        marker = record.get("marker")
        state = marker.get("state") if isinstance(marker, dict) else None
        if state == marker_present:
            return PANE, "its last launch predates named sessions"
        return None, f"sandy cannot answer for it (marker {state!r})"
    if not isinstance(cs, dict) or not isinstance(cs.get(DECLARED_KEY), list):
        return None, f"sandy reports {CLAUDE_SESSIONS_KEY} as {cs!r}, a shape this does not know"
    if cs[DECLARED_KEY]:
        return NAMED, "its last launch declared named Claude sessions"
    return PANE, "its last launch declared no named sessions"


def _drift_pairs(drift: Any, prefix: str) -> List[str]:
    """The flag/value pairs sandy's drift text lists under `prefix`:
    `missing: a | b; extra: c` (sandy's own format, `|`-joined pairs)."""
    if not isinstance(drift, str):
        return []
    for part in drift.split("; "):
        if part.startswith(prefix):
            return [p.strip() for p in part[len(prefix):].split(" | ") if p.strip()]
    return []


def _ours(pairs: Sequence[str], feature_dir: str) -> List[str]:
    """The pairs that pass one of this feature's files: a value under its
    container directory."""
    return [p for p in pairs if (feature_dir.rstrip("/") + "/") in p]


def verify_sessions(slug: str, record: Optional[Dict[str, Any]], feature_dir: str
                    ) -> Tuple[List[str], List[str]]:
    """`(problems, notes)`: the mode, and in named mode the posture."""
    problems: List[str] = []
    notes: List[str] = []
    mode, why = session_mode(record)
    if mode is None:
        problems.append(f"delivery mode unknown: {slug}: {why} — whether its sessions can be "
                        f"served cannot be told; relaunch it")
        return problems, notes
    if mode == PANE:
        return problems, notes
    cs = record[CLAUDE_SESSIONS_KEY]
    declared = [d for d in cs[DECLARED_KEY] if isinstance(d, dict)]
    claimants = [d for d in declared if RECEIVES_CROSS_SESSION in (d.get("receives") or [])]
    if not DEPLOYED_LISTER_SERVES_NAMED_SESSIONS:
        problems.append(
            f"named sessions unserved: {slug}: {why}, and the deployed session lister lists "
            f"tmux panes only, so no session receives peer notices — they wait unhandled, and "
            f"nothing is logged. Until the named-session lister is deployed, relaunch it "
            f"without .sandy/sessions/ (issue #45); do not point the daemon at another lister")
    if len(claimants) != 1:
        problems.append(f"named-session claimant: {slug}: {len(claimants)} declared sessions "
                        f"receive {RECEIVES_CROSS_SESSION}, not exactly one — relaunch with one")
        return problems, notes
    claimant = claimants[0].get("slug")
    status = cs.get(STATUS_KEY)
    sessions = status.get("sessions") if isinstance(status, dict) else None
    if not isinstance(sessions, list):
        problems.append(f"named-session posture unknown: {slug}: the container reported no "
                        f"session status for its last launch — relaunch it")
        return problems, notes
    rows = {s.get("slug"): s for s in sessions if isinstance(s, dict)}
    clean = True
    for d in declared:
        s = d.get("slug")
        row = rows.get(s)
        if row is None:
            problems.append(f"named-session posture unknown: {slug}: session {s!r} has no "
                            f"status row — relaunch it")
            clean = False
            continue
        if s == claimant:
            if row.get("state") != STATE_UP:
                problems.append(f"named-session claimant down: {slug}: {s!r} is "
                                f"{row.get('state')!r} ({row.get('reason')}), so nothing "
                                f"receives peer notices — relaunch it")
                clean = False
            missing = _ours(_drift_pairs(row.get("drift"), DRIFT_MISSING), feature_dir)
            if missing:
                problems.append(f"named-session claimant posture: {slug}: {s!r} was created "
                                f"without {' | '.join(missing)}, so it cannot answer delegations "
                                f"through the router — recreate that session")
                clean = False
        else:
            if row.get("inbound_pinned") == PINNED_NO:
                problems.append(f"named-session posture: {slug}: {s!r} does not receive "
                                f"{RECEIVES_CROSS_SESSION} but lacks the refuse pin, so a "
                                f"misdirected frame lands in it — recreate that session")
                clean = False
            extra = _ours(_drift_pairs(row.get("drift"), DRIFT_EXTRA), feature_dir)
            if extra:
                problems.append(f"named-session posture: {slug}: {s!r} does not receive "
                                f"{RECEIVES_CROSS_SESSION} but holds {' | '.join(extra)} — "
                                f"recreate that session")
                clean = False
    if clean:
        notes.append(f"{slug}: named sessions, as sandy reports: claimant {claimant!r} up, "
                     f"every other session pinned to refuse")
    return problems, notes


# ------------------------------------------------------- daemon version

def _git(args: List[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, timeout=60)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_history(checkout: Path, commits: Sequence[str], rel: str = DAEMON_REL,
                 git: Callable = _git) -> Tuple[Dict[str, List[str]], Optional[str]]:
    """`({file sha256: [commits that introduced those bytes, newest first]},
    error)`: every version of `rel` reachable from `commits`."""
    log = git(["log", "--format=%H", *commits, "--", rel], checkout)
    if log.returncode != 0:
        return {}, f"git log failed in {checkout}: {log.stderr.decode(errors='replace').strip()}"
    out: Dict[str, List[str]] = {}
    for c in log.stdout.decode().split():
        show = git(["show", f"{c}:{rel}"], checkout)
        if show.returncode == 0:
            out.setdefault(sha256(show.stdout), []).append(c)
    return out, None


class DaemonVersion:
    """What the payload's daemon is, against the pin, and its notice pattern."""

    def __init__(self, problems: List[str], notes: List[str],
                 notice_re: Optional["re.Pattern[str]"], why: str):
        self.problems, self.notes, self.notice_re, self.why = problems, notes, notice_re, why


def notice_pattern(source: bytes) -> Tuple[Optional["re.Pattern[str]"], str]:
    """The daemon's `NOTICE_FILE_RE = re.compile(<literal>)`, compiled from
    its own source. None, with the reason, when it is not exactly that."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError) as e:
        return None, f"the deployed daemon does not parse ({e})"
    found = [n.value for n in tree.body if isinstance(n, ast.Assign)
             and [t.id for t in n.targets if isinstance(t, ast.Name)] == [NOTICE_RE_NAME]]
    if len(found) != 1:
        return None, f"the deployed daemon binds {NOTICE_RE_NAME} {len(found)} times at module level"
    call = found[0]
    if not (isinstance(call, ast.Call) and len(call.args) == 1 and not call.keywords
            and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str)):
        return None, f"the deployed daemon's {NOTICE_RE_NAME} is not a compile of one literal"
    try:
        return re.compile(call.args[0].value), ""
    except re.error as e:
        return None, f"the deployed daemon's {NOTICE_RE_NAME} does not compile ({e})"


def daemon_version(payload_daemon: Path, checkout: Optional[Path], pinned: str,
                   git: Callable = _git) -> DaemonVersion:
    """The payload's daemon mapped to a connector commit, and against the pin."""
    problems: List[str] = []
    notes: List[str] = []
    try:
        deployed = payload_daemon.read_bytes()
    except OSError as e:
        why = f"cannot read {payload_daemon}: {e}"
        problems.append(f"daemon version unknown: {why} — run install --apply")
        return DaemonVersion(problems, notes, None, why)
    notice_re, why = notice_pattern(deployed)
    have = sha256(deployed)
    if checkout is None:
        problems.append(f"daemon version unknown: the payload's {payload_daemon.name} is sha256 "
                        f"{have}, and no connector checkout was found to map it to a commit — "
                        f"pass --connector-src")
        return DaemonVersion(problems, notes, notice_re, why)
    at_pin = git(["show", f"{pinned}:{DAEMON_REL}"], checkout)
    if at_pin.returncode != 0:
        problems.append(f"daemon version unknown: the pinned connector commit {pinned} (or its "
                        f"{DAEMON_REL}) is not in {checkout} — fetch it (amap-siblings.py "
                        f"--apply), then re-run verify")
        return DaemonVersion(problems, notes, notice_re, why)
    if have == sha256(at_pin.stdout):
        notes.append(f"daemon: the payload's {payload_daemon.name} is the pinned connector's "
                     f"({pinned[:12]})")
        return DaemonVersion(problems, notes, notice_re, why)
    history, err = file_history(checkout, [pinned, "HEAD"], git=git)
    origin = history.get(have)
    if err:
        problems.append(f"daemon version unknown: {err} — the payload's {payload_daemon.name} "
                        f"(sha256 {have}) is not the pin's, and cannot be mapped to a commit")
    elif origin is None:
        problems.append(f"daemon version unknown: the payload's {payload_daemon.name} is sha256 "
                        f"{have}, which no commit of {DAEMON_REL} in {checkout} has — a local "
                        f"edit, or a commit this checkout does not hold; put the checkout at its "
                        f"pin and re-run install --apply")
    else:
        problems.append(f"daemon drift: the payload's {payload_daemon.name} has the bytes "
                        f"connector {origin[-1][:12]} introduced, not the siblings.json pin "
                        f"{pinned[:12]}'s — put the connector checkout at its pin "
                        f"(amap-siblings.py --apply) and re-run install --apply; do not move the "
                        f"pin to match the payload")
    return DaemonVersion(problems, notes, notice_re, why)


# ------------------------------------------------------------- unhandled

def _age_seconds(value: Any, now: float) -> Optional[float]:
    if not isinstance(value, str):
        return None
    try:
        when = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if when.tzinfo is None:
        return None
    return now - when.timestamp()


def _notice_ts(path: Path) -> Any:
    try:
        if path.stat().st_size > NOTICE_READ_LIMIT:
            return None
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return doc.get(NOTICE_TS_KEY) if isinstance(doc, dict) else None


def verify_unhandled(slug: str, notice_dir: Path, ledger_dir: Path,
                     notice_re: Optional["re.Pattern[str]"], why: str, *, now: float,
                     running: bool) -> Tuple[List[str], List[str]]:
    """`(problems, notes)`: the peer notices the daemon has no ledger entry
    for, and the oldest one's age from the router's own `ts`."""
    problems: List[str] = []
    notes: List[str] = []
    if notice_re is None:
        problems.append(f"unhandled count unknown: {slug}: {why}, so which notices the daemon "
                        f"sees cannot be told — re-run install --apply")
        return problems, notes
    try:
        names = sorted(p.name for p in notice_dir.iterdir())
    except OSError:
        return problems, notes       # the lane check reports a missing lane
    try:
        ledger = {p.name for p in ledger_dir.iterdir()}
        no_ledger = ""
    except FileNotFoundError:
        ledger, no_ledger = set(), " (the daemon has written no ledger yet)"
    except OSError as e:
        problems.append(f"unhandled count unknown: {slug}: cannot read the daemon's ledger "
                        f"{ledger_dir}: {e}")
        return problems, notes
    ages: List[Optional[float]] = []
    for name in names:
        m = notice_re.match(name)
        if m and (LEDGER_PEER_PREFIX + m.group(1)) not in ledger:
            ages.append(_age_seconds(_notice_ts(notice_dir / name), now))
    if not ages:
        return problems, notes
    known = [a for a in ages if a is not None]
    undated = len(ages) - len(known)
    oldest = max(known) if known else None
    detail = (f"{len(ages)} peer notice(s) with no ledger entry{no_ledger}"
              + (f", the oldest {int(oldest)}s old" if oldest is not None else "")
              + (f", {undated} with no readable ts" if undated else ""))
    over = undated > 0 or (oldest is not None and oldest > UNHANDLED_MAX_AGE_SECONDS)
    if over and running:
        problems.append(f"unhandled peer notices: {slug}: {detail} (over "
                        f"{UNHANDLED_MAX_AGE_SECONDS}s, or undated) — the daemon is not handling "
                        f"them; check its supervisor log and the session lister. Unhandled, not "
                        f"undelivered: a ledger entry means only handled")
    else:
        notes.append(f"{slug}: {detail}" + ("" if running else " — not running"))
    return problems, notes
