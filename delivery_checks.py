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
  `--print-state`'s `claude_sessions` (`{declared, status}`) where sandy
  reports it, and otherwise from the host copy of the launch marker: a sandy
  whose `--print-state` lacks the field can still have launched named
  sessions. Neither answering, or the two disagreeing, is UNKNOWN; no
  record from sandy is UNKNOWN; never pane by default.
- POSTURE, in named mode only, AS SANDY REPORTS IT: `claude_sessions.status`
  is copied from a file in the agent's own home, so it is a report and not a
  trust root. Every value must be one sandy writes for a judged session:
  the claimant (the one declared session receiving `cross_session`) `up`
  with `inbound_pinned` `receiver`; every other session `yes` (`no` is a
  failure); `drift` `none` or sandy's `missing:`/`extra:` text. Anything
  else (`-`, which sandy writes when the session has no job to read;
  `unknown`; a value it never writes) is posture UNKNOWN. The claimant must
  not lack this feature's arguments (`missing:`), and no other session may
  hold them (`extra:`): sandy diverts a receiving feature's `agent_args` to
  the claimant alone, so this feature's arguments on another session mean
  it was created before that, and it holds the submit tools without being
  the one that receives. The clean note is written only when every row was
  judged.
- DAEMON VERSION. The payload's `inbox-delivery` is hashed (the file's
  sha256) and mapped to the connector commit whose `bin/inbox-delivery` has
  those bytes, by walking the file's history in the connector checkout. The
  siblings.json pin is what CI ran; deployed bytes that are another commit's
  are DRIFT, never "older", and bytes no commit has are UNKNOWN, naming the
  hash. The payload's other connector files are compared with the pin's
  bytes too, because the daemon file can be identical across commits that
  differ elsewhere.
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
PINNED_YES = "yes"
PINNED_RECEIVER = "receiver"
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
NOT_LAUNCHED = "not launched"


def _marker_declared(marker: Any) -> Tuple[Optional[List[Any]], str]:
    """The named sessions the host copy of the launch marker declares:
    `(list, why)`, or `(None, why)` when it cannot say. `marker` is the
    parsed file, None when the file is absent, or a string saying why it
    could not be read. A marker without the key was written by a sandy
    without named sessions, which cannot have run them."""
    if marker is None:
        return None, "it has no launch marker on the host"
    if isinstance(marker, str):
        return None, f"its launch marker is {marker}"
    if not isinstance(marker, dict):
        return None, "its launch marker is not an object"
    if CLAUDE_SESSIONS_KEY not in marker:
        return [], "its launch marker predates named sessions"
    declared = marker[CLAUDE_SESSIONS_KEY]
    if not isinstance(declared, list):
        return None, f"its launch marker carries {CLAUDE_SESSIONS_KEY}={declared!r}"
    return declared, "its launch marker"


def session_mode(record: Optional[Dict[str, Any]], marker: Any, *, marker_absent: str = "absent"
                 ) -> Tuple[Optional[str], str, List[Any], Any]:
    """`(mode, why, declared, status)`. `mode` is NAMED, PANE, NOT_LAUNCHED,
    or None when it cannot be told.

    `--print-state`'s `{declared, status}` is read where sandy reports it.
    Where it does not (no key: a sandy whose `--print-state` predates the
    field, which may still have LAUNCHED named sessions; or `null`), the
    host copy of the launch marker decides, and the status is unknown. Both
    present and disagreeing about whether any session was declared cannot
    be told."""
    if not isinstance(record, dict):
        return None, "sandy reports no record for it", [], None
    m_declared, m_why = _marker_declared(marker)
    reported = record.get(CLAUDE_SESSIONS_KEY)
    if isinstance(reported, dict):
        declared = reported.get(DECLARED_KEY)
        if not isinstance(declared, list):
            return None, f"sandy reports {CLAUDE_SESSIONS_KEY} as {reported!r}", [], None
        if m_declared is not None and bool(m_declared) != bool(declared):
            return (None, f"sandy reports {len(declared)} declared session(s) and {m_why} "
                          f"{len(m_declared)}", [], None)
        return (NAMED if declared else PANE, "its last launch declared named Claude sessions",
                declared, reported.get(STATUS_KEY))
    if reported is not None:
        return None, f"sandy reports {CLAUDE_SESSIONS_KEY} as {reported!r}", [], None
    if m_declared is None:
        state = (record.get("marker") or {}).get("state") if isinstance(record.get("marker"),
                                                                         dict) else None
        if marker is None and state == marker_absent:
            return NOT_LAUNCHED, "not launched yet", [], None
        return None, m_why, [], None
    if m_declared:
        return NAMED, f"{m_why} declares named Claude sessions", m_declared, None
    return PANE, f"{m_why} declares no named sessions", [], None


def _drift(drift: Any) -> Optional[Dict[str, List[str]]]:
    """Sandy's drift text as `{"missing": [...], "extra": [...]}`: `none`, or
    `missing: a | b`, `extra: c`, or both joined by `; `. None for anything
    else (`-`, which sandy writes when the session has no job to read;
    `unknown`; a non-string), which cannot be judged."""
    out: Dict[str, List[str]] = {"missing": [], "extra": []}
    if drift == "none":
        return out
    if not isinstance(drift, str) or not drift:
        return None
    for part in drift.split("; "):
        for key, prefix in (("missing", DRIFT_MISSING), ("extra", DRIFT_EXTRA)):
            if part.startswith(prefix) and not out[key]:
                out[key] = [p.strip() for p in part[len(prefix):].split(" | ") if p.strip()]
                if not out[key]:
                    return None
                break
        else:
            return None
    return out


def _ours(pairs: Sequence[str], feature_dir: str) -> List[str]:
    """The pairs that pass one of this feature's files: a value under its
    container directory."""
    return [p for p in pairs if (feature_dir.rstrip("/") + "/") in p]


def verify_sessions(slug: str, record: Optional[Dict[str, Any]], feature_dir: str, *,
                    marker: Any) -> Tuple[List[str], List[str]]:
    """`(problems, notes)`: the mode, and in named mode the posture.
    `marker` is the host copy of the launch marker: the parsed file, None
    when absent, or why it could not be read."""
    problems: List[str] = []
    notes: List[str] = []
    mode, why, declared, status = session_mode(record, marker)
    if mode is None:
        problems.append(f"delivery mode unknown: {slug}: {why} — whether its sessions can be "
                        f"served cannot be told; relaunch it")
        return problems, notes
    if mode == NOT_LAUNCHED:
        notes.append(f"{slug}: not launched yet, so whether its sessions can be served is not "
                     f"knowable until it is")
        return problems, notes
    if mode == PANE:
        return problems, notes
    declared = [d for d in declared if isinstance(d, dict)]
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
    sessions = status.get("sessions") if isinstance(status, dict) else None
    if not isinstance(sessions, list):
        problems.append(f"named-session posture unknown: {slug}: sandy reports no session "
                        f"status for its last launch — relaunch it")
        return problems, notes
    rows = {s.get("slug"): s for s in sessions if isinstance(s, dict)}
    before = len(problems)
    for d in declared:
        s = d.get("slug")
        row = rows.get(s)
        if row is None:
            problems.append(f"named-session posture unknown: {slug}: session {s!r} has no "
                            f"status row — relaunch it")
            continue
        is_claimant = s == claimant
        pinned = row.get("inbound_pinned")
        drift = _drift(row.get("drift"))
        if is_claimant and row.get("state") != STATE_UP:
            problems.append(f"named-session claimant down: {slug}: {s!r} is "
                            f"{row.get('state')!r} ({row.get('reason')}), so nothing "
                            f"receives peer notices — relaunch it")
        if not is_claimant and pinned == PINNED_NO:
            problems.append(f"named-session posture: {slug}: {s!r} does not receive "
                            f"{RECEIVES_CROSS_SESSION} but lacks the refuse pin, so a "
                            f"misdirected frame lands in it — recreate that session")
        elif pinned != (PINNED_RECEIVER if is_claimant else PINNED_YES):
            problems.append(f"named-session posture unknown: {slug}: {s!r} reports "
                            f"inbound_pinned {pinned!r}, not "
                            f"{PINNED_RECEIVER if is_claimant else PINNED_YES!r} — relaunch it")
        if drift is None:
            problems.append(f"named-session posture unknown: {slug}: {s!r} reports drift "
                            f"{row.get('drift')!r}, which says nothing about its arguments — "
                            f"relaunch it")
            continue
        if is_claimant and _ours(drift["missing"], feature_dir):
            problems.append(f"named-session claimant posture: {slug}: {s!r} was created "
                            f"without {' | '.join(_ours(drift['missing'], feature_dir))}, so it "
                            f"cannot answer delegations through the router — recreate that "
                            f"session")
        if not is_claimant and _ours(drift["extra"], feature_dir):
            problems.append(f"named-session posture: {slug}: {s!r} does not receive "
                            f"{RECEIVES_CROSS_SESSION} but holds "
                            f"{' | '.join(_ours(drift['extra'], feature_dir))} — recreate that "
                            f"session")
    if len(problems) == before:
        notes.append(f"{slug}: named sessions, as sandy reports: claimant {claimant!r} up and "
                     f"receiving, every other session pinned to refuse, no session's "
                     f"arguments drifted from this feature's")
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
    if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
            and call.func.attr == "compile" and isinstance(call.func.value, ast.Name)
            and call.func.value.id == "re" and len(call.args) == 1 and not call.keywords
            and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str)):
        return None, f"the deployed daemon's {NOTICE_RE_NAME} is not re.compile of one literal"
    try:
        pattern = re.compile(call.args[0].value)
    except re.error as e:
        return None, f"the deployed daemon's {NOTICE_RE_NAME} does not compile ({e})"
    if pattern.groups < 1:
        return None, f"the deployed daemon's {NOTICE_RE_NAME} captures no notice id"
    return pattern, ""


def _companions_at_pin(companions: Sequence[Tuple[Path, str]], checkout: Path, pinned: str,
                       git: Callable) -> List[str]:
    """A problem for each of the payload's other connector files whose bytes
    are not the pinned commit's (the daemon file alone can be identical across
    commits that differ elsewhere)."""
    out = []
    for path, rel in companions:
        at_pin = git(["show", f"{pinned}:{rel}"], checkout)
        try:
            have = path.read_bytes()
        except OSError as e:
            out.append(f"connector version unknown: cannot read the payload's {path.name}: {e}")
            continue
        if at_pin.returncode != 0:
            out.append(f"connector version unknown: the pinned commit {pinned[:12]} has no {rel}")
        elif sha256(have) != sha256(at_pin.stdout):
            out.append(f"connector drift: the payload's {path.name} (sha256 {sha256(have)}) is "
                       f"not the siblings.json pin {pinned[:12]}'s {rel}")
    return out


def daemon_version(payload_daemon: Path, checkout: Optional[Path], pinned: str,
                   git: Callable = _git, *,
                   companions: Sequence[Tuple[Path, str]] = ()) -> DaemonVersion:
    """The payload's daemon mapped to a connector commit, and against the pin;
    `companions` are the payload's other connector files, as `(payload path,
    path in the checkout)`, compared with the pin's bytes."""
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
    companion_problems = _companions_at_pin(companions, checkout, pinned, git)
    if have == sha256(at_pin.stdout):
        problems += companion_problems
        if not companion_problems:
            notes.append(f"connector: the payload's {payload_daemon.name} and "
                         f"{len(companions)} other connector file(s) equal the siblings.json "
                         f"pin {pinned[:12]}'s bytes")
        return DaemonVersion(problems, notes, notice_re, why)
    problems += companion_problems
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
                        f"{pinned[:12]}'s — reinstall from a checkout at the pin "
                        f"(amap-siblings.py --apply, then install --apply), or move the pin by "
                        f"its own reviewed PR")
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
