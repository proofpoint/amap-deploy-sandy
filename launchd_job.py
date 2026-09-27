"""launchd_job.py — the container recreation cadence, as a launchd job.

Sandy's own threat model records "a process planted at the container uid
lives until the container is recreated" as an ACCEPTED RISK with a named
cadence. Sandy does not schedule `sandy --update-sessions` itself; run by
hand, the accepted risk is accepted against a cadence nobody keeps. This
job keeps it.

WHAT THIS MODULE IS AND IS NOT. It RENDERS the job and READS its record. It
never loads, unloads, or runs anything: installing a launch agent is an
operator action on the operator's own account, and a tool that bootstraps a
job which recreates every container on the box is a tool that recreates every
container on the box. `install_command()` hands the operator the exact line;
`amap-sandy.py cadence` reads the record and reports.

THE NUMBER IS THE POLICY'S, NOT THIS FILE'S. `container_recreate_interval_hours`
lives in the manifest's `feature` section and `install` refuses a policy
that omits it. That refusal is what makes writing it in the operator's
ratification of the cadence — so this module takes the
interval as an argument and has no default. A default here would be a cadence
the fleet runs on that appears in no reviewed artifact.

WHY A STAMP FILE. "Is the job loaded" and "did it actually run" are different
questions, and launchd answers only the first in any form this repo can rely
on across macOS versions. So the job records its own outcome — an ISO-8601
UTC timestamp and the exit status — and `last_run()` reads it. That makes
three states distinguishable, which is the whole point:

    no stamp          the job has never run (or has never been loaded)
    stamp, status 0   it ran, and sandy was happy
    stamp, status n   it ran and FAILED — the containers were not recreated,
                      and this is the state a plain "did it run recently"
                      check would report as healthy

`; ` and not `&& `, deliberately: a failing `--update-sessions` must still
leave a record. With `&&` a job that failed every night for a week would be
indistinguishable from one that was never loaded, and the remedies are
different.
"""
from __future__ import annotations

import shlex
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

LABEL = "com.amp.sandy-update-sessions"

# 04:00 local. Chosen because it is after any plausible end-of-day session and
# before any plausible start-of-day one: `--update-sessions` is a rolling
# restart, and a container recreated under a live session loses that session's
# panes.
RUN_HOUR = 4
RUN_MINUTE = 0

# How late the job may be before `amap-sandy.py cadence` calls it overdue. launchd does not
# run a calendar job at the exact second, a laptop asleep at 04:00 runs it on
# wake, and a fleet of containers takes minutes to cycle — so a check with no
# slack is a check that pages the operator for nothing. Two hours is long
# enough to cover a late wake and short enough that a job which silently
# stopped is caught the same day.
SLACK_HOURS = 2


def plist_path(home: Optional[Path] = None) -> Path:
    """`~/Library/LaunchAgents/<label>.plist`. A user agent, not a daemon:
    it runs `sandy` as the operator, against the operator's own docker
    context and `$SANDY_HOME`. Run as root it would find neither."""
    return (home or Path.home()) / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def stamp_path(sandy_home: Path) -> Path:
    """Beside the enrolment record and the router config, in `$SANDY_HOME` —
    operator state about the fleet, which is exactly what this is. Not in the
    plist directory (that is launchd's) and not in any sandbox (an agent must
    not be able to forge evidence that the cadence is being kept)."""
    return Path(sandy_home) / "update-sessions.stamp"


def job_command(sandy_bin: str, sandy_home: Path) -> str:
    """The shell command the job runs: the rolling restart, then the record.

    Quoted with `shlex.quote` because `sandy_bin` and `$SANDY_HOME` are
    operator-supplied paths that may contain spaces, and this string is
    handed to `/bin/sh -c`."""
    # `rc=$?` FIRST: inside the printf, `$?` would be read after the
    # `$(date)` substitution has run and is 0 on /bin/sh (bash 3.2, the shell
    # launchd hands this to), so every failed restart stamped as a success.
    return (f"{shlex.quote(str(sandy_bin))} --update-sessions --yes; rc=$?; "
            f'printf "%s %s\\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$rc" '
            f"> {shlex.quote(str(stamp_path(sandy_home)))}")


def render_plist(sandy_bin: str, sandy_home: Path, interval_hours: int) -> str:
    """The launch agent, rendered from the RATIFIED interval.

    24 hours becomes a `StartCalendarInterval` at 04:00 — a wall-clock time,
    which is what "daily at 04:00" means and what survives a sleeping laptop
    (launchd runs a missed calendar job on wake; a missed `StartInterval` one
    simply slips). Any other interval becomes a plain `StartInterval` in
    seconds, because a calendar entry cannot express "every 7 hours" and
    pretending otherwise would silently run the fleet on a cadence the policy
    did not ask for.
    """
    if interval_hours <= 0:
        raise ValueError(f"interval_hours must be positive, got {interval_hours!r}")
    if interval_hours == 24:
        schedule = ("    <key>StartCalendarInterval</key>\n"
                    "    <dict>\n"
                    f"        <key>Hour</key><integer>{RUN_HOUR}</integer>\n"
                    f"        <key>Minute</key><integer>{RUN_MINUTE}</integer>\n"
                    "    </dict>\n")
    else:
        schedule = ("    <key>StartInterval</key>\n"
                    f"    <integer>{interval_hours * 3600}</integer>\n")
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0">\n'
        "<dict>\n"
        "    <key>Label</key>\n"
        f"    <string>{LABEL}</string>\n"
        "    <key>ProgramArguments</key>\n"
        "    <array>\n"
        "        <string>/bin/sh</string>\n"
        "        <string>-c</string>\n"
        f"        <string>{_xml_escape(job_command(sandy_bin, sandy_home))}</string>\n"
        "    </array>\n"
        + schedule +
        # NOT RunAtLoad. Bootstrapping the agent would otherwise recreate every
        # container on the box immediately, during whatever the operator was
        # doing when they ran the install command.
        "    <key>RunAtLoad</key>\n"
        "    <false/>\n"
        "    <key>StandardOutPath</key>\n"
        f"    <string>{_xml_escape(str(Path(sandy_home) / 'update-sessions.log'))}</string>\n"
        "    <key>StandardErrorPath</key>\n"
        f"    <string>{_xml_escape(str(Path(sandy_home) / 'update-sessions.log'))}</string>\n"
        "</dict>\n"
        "</plist>\n"
    )


def _xml_escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace('"', "&quot;"))


def install_command(home: Optional[Path] = None) -> str:
    """The exact line the operator runs. NEVER run from here.

    `bootstrap gui/$(id -u)` rather than the deprecated `load`: a GUI-domain
    agent is what runs as the logged-in operator with their docker context,
    and `load` has been unreliable for that since Catalina."""
    return (f"launchctl bootstrap gui/$(id -u) {plist_path(home)}"
            f"   # then: launchctl print gui/$(id -u)/{LABEL}")


def last_run(sandy_home: Path) -> Dict[str, Any]:
    """`{"at": datetime|None, "status": int|None, "reason": str|None}`.

    Never raises: this is read by `amap-sandy.py cadence`, which may run from cron on a
    host where the job has never been installed, and a traceback there is a
    cron mail nobody reads."""
    path = stamp_path(sandy_home)
    try:
        text = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return {"at": None, "status": None,
                "reason": f"no stamp at {path} — the job has never run"}
    except OSError as e:
        return {"at": None, "status": None, "reason": f"cannot read {path}: {e}"}
    parts = text.split()
    if len(parts) != 2:
        return {"at": None, "status": None,
                "reason": f"{path} does not hold '<timestamp> <status>': {text!r}"}
    try:
        when = datetime.fromisoformat(parts[0].replace("Z", "+00:00"))
    except ValueError:
        return {"at": None, "status": None,
                "reason": f"{path} has an unparsable timestamp: {parts[0]!r}"}
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    try:
        status = int(parts[1])
    except ValueError:
        return {"at": when, "status": None,
                "reason": f"{path} has an unparsable status: {parts[1]!r}"}
    return {"at": when, "status": status, "reason": None}


def overdue_reason(sandy_home: Path, interval_hours: int,
                   now: Optional[datetime] = None) -> Optional[str]:
    """Why the cadence is not being kept, or `None` if it is.

    Three separate answers, never collapsed into one boolean: never ran, ran
    but failed, ran too long ago. They have three different remedies, and a
    check that says only "overdue" sends the operator looking for the wrong
    one."""
    record = last_run(sandy_home)
    if record["at"] is None:
        return record["reason"]
    if record["status"] != 0:
        return (f"the last run at {record['at'].isoformat()} exited "
                f"{record['status']} — the containers were NOT recreated")
    reference = now or datetime.now(timezone.utc)
    deadline = record["at"] + timedelta(hours=interval_hours + SLACK_HOURS)
    if reference > deadline:
        age = (reference - record["at"]).total_seconds() / 3600
        return (f"the last successful run was {age:.1f}h ago, past the ratified "
                f"{interval_hours}h cadence plus {SLACK_HOURS}h slack")
    return None
