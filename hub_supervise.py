"""The hub-link email router's supervision and its start check: the files
that start it and keep it running, the weekly login probe's job, and the
live-start ancestry check. NOTHING HERE STARTS, LOADS OR ENABLES ANYTHING:
the files are rendered into the operator's run directory under an explicit
`--apply`, the plan's root steps place them, and the start step (enable and
start) is printed only by `hub-start-check`, only when every check passes.
Starting is the operator's act.

On macOS, launchd loads every plist in /Library/LaunchDaemons at boot, so
placing one would start it at the next boot. The plan therefore disables
both labels BEFORE placing them (a persistent override that launchd
honours at boot), through the writer's `service` verb as every manager
call is, and the start step is enable followed by bootstrap. Verify reads the
override back (`launchctl print-disabled system`): a label that is not
disabled is a FAIL unless every start check passes now.

The host-setup document's `supervision` section names, all operator data:
- `kind`: `systemd` (Linux) or `launchd` (macOS);
- `engine`: the docker engine every rendered job talks to, `unix:///…`,
  set as DOCKER_HOST explicitly (root's own docker context is never used);
- `hub`: where the runtime's supervisor goes. systemd: `unit`, a
  `/etc/systemd/system/<name>.service` path. launchd: `label`, `plist` (a
  `/Library/LaunchDaemons/<label>.plist` path), `wrapper` and `status`;
- `weekly`: the weekly login probe's job, at `weekday` (0 is Sunday),
  `hour` and `minute`. systemd: `service` and `timer` paths, in
  `/etc/systemd/system/`. launchd: `label` and `plist`, in
  `/Library/LaunchDaemons/`;
- `requires`: the reviewed merge commits the runtime's code must contain,
  each `{name, commit}`. The runtime image's commit is the secrets
  section's `runtime` clone sha; every required commit must be its
  ancestor, asked of that clone with system and user git configuration
  ignored, and where the image carries the OCI revision label it must be
  that commit.

The runtime's restart policy: 0 and 2-11 never restart, every other code
restarts after 30 s, rate-limited. On Linux that is the unit's
`RestartPreventExitStatus`, plus `SuccessExitStatus=143`, which classifies
an actual docker-client exit of 143 as a success and does nothing else: a
planned stop is clean because the router's SIGTERM handler, a required
commit, makes it exit 0. Without the handler a planned stop runs out the
`docker stop` timeout and exits 137, which this setting does not cover. On
macOS a wrapper maps the codes for a LaunchDaemon whose KeepAlive restarts
only on a non-zero wrapper exit; it passes 143 on, so launchd restarts it.
The wrapper is placed root 0444 by the plan's `place --sha256` and run as
`/bin/sh <wrapper>` under the barrier's anchor, never directly. Every command
root runs goes through the one barrier (`root_cmd`, ROOT-BOOTSTRAP d3.2): the
anchor's empty environment, then `root_exec` from the placed root-trust.sh,
which judges the OS interpreter and the pinned writer before the writer's
`trusted-exec` judges the command and its fresh closure. The first barrier
line runs the writer's `noop` step and judges docker with it: on Linux the unit's first
ExecStartPre, whose failure fails the start; on macOS the wrapper's step 0,
which records UNTRUSTED and exits 0, so launchd does not restart it. Each
docker call after it passes through the barrier again. It starts `docker run` in the
background and blocks in `wait`, because a POSIX shell defers a trap while a
foreground command runs.
"""

import json
import math
import os
import plistlib
import posixpath
import re
import shlex
import stat
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import hub_runtime as hr
import root_trust as rt
import router_health as rh
import secret_setup as ss

SECTION = "supervision"
KINDS = ("systemd", "launchd")
#: The restart policy: these exits never restart; every other non-zero exit does.
NO_RESTART = (2, 3, 4, 5, 6, 7, 8, 9, 10, 11)
#: The docker-client exit treated as a success on Linux (the operator's ruling).
STOP_CODE = 143
RESTART_SEC = 30
START_LIMIT_INTERVAL_S = 600
START_LIMIT_BURST = 5
#: `docker stop -t`: at least the router's own join bound (the rendered dot
#: budget + JOIN_SLACK_S + DONE_POLL_S), so a planned stop ends in the
#: router's exit, 0 or 4, never in the engine's kill. verify derives the bound
#: from the rendering and holds this to it.
STOP_TIMEOUT_S = 100
#: The router's join slack beyond the dot budget (the router's frozen
#: constant, with no knob), and its main thread's poll for the stop.
JOIN_SLACK_S = 60
DONE_POLL_S = 1
#: The start probe's login runs before the join exists: connect, then five
#: command phases (EHLO, STARTTLS, the TLS handshake, EHLO, AUTH), then at most
#: this long for QUIT. A stop in that window can end in the engine's kill,
#: with nothing committed.
START_PROBE_COMMANDS = 5
QUIT_S = 5
#: The supervisors' own bounds sit above the stop: systemd's default
#: TimeoutStopSec (90 s) and launchd's default ExitTimeOut (20 s) are below it.
SUPERVISOR_STOP_S = 120
#: The barrier's own cost before a stop's `docker stop` starts (RE N1): the
#: ExecStop line and the wrapper's stop_it both pass through it. Measured on
#: one Linux host at about 0.5 s (the shell half 0.3 s, trusted-exec 0.2 s,
#: with no docker in the closure); macOS is not measured, so this is a
#: declared bound, and the supervisors' bound must cover it plus the stop.
BARRIER_S = 10
#: What a planned restart's budget keeps beyond its stop and its three barrier lines.
SERVICE_MARGIN_S = 30
#: The barrier lines a planned restart passes after its stop: the anchor ExecStartPre, `-docker rm`, ExecStart.
RESTART_BARRIER_LINES = 3
#: Each kind's manager, recorded in secrets.tools under this name.
MANAGERS = {"systemd": "systemctl", "launchd": "launchctl"}
ORPHAN = "orphan_running"
#: The wrapper's record once the barrier passed and the run is next; the run's own end replaces it.
STARTED = "started"
#: `docker run`'s own exit when the container never started (no image, a name conflict, a
#: missing bind source, an unreadable env file, an engine that does not answer).
ENGINE_EXIT = 125
#: The wrapper's record when the writer finds docker or python3 not root's alone: nothing ran.
UNTRUSTED = "untrusted_tools"
#: The wrapper's error stream, launchd's StandardErrorPath (d3.3 §5 B3): beside
#: its status, in the root-owned status directory. Its own lines start SAY. The
#: run line's output, docker's own errors for it included, goes to /dev/null
#: (the container's to the engine's log), so this holds the wrapper's lines and
#: the other docker calls' errors: a few per start, at most one start per
#: ThrottleInterval when launchd restarts it (RE N6). A run that exits 125 is
#: followed by what the engine says about its image and its name (RE N7).
ERR_NAME = "hub-link-run.err"
SAY = "hub-link-run: "
#: What the wrapper says when a refusal could not be recorded: the one line
#: that tells verify the status beside it may be a stale, earlier one.
UNRECORDED = "the refusal could not be recorded"
#: What the wrapper says when the barrier refused the run line itself (exit 12, which the
#: router never uses): the last line of a start whose `started` record is not this run's health.
REFUSED_RUN = "the barrier refused the run"
LAUNCHCTL = "/bin/launchctl"
WEEKLY_RUN_ID = "weekly"
REVISION_LABEL = "org.opencontainers.image.revision"
DAYS = ("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat")
_HEX40 = re.compile(r"[0-9a-f]{40}")
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_ENGINE = re.compile(r"unix:///[^\s]+")
#: Where each supervisor reads its files: a unit or plist anywhere else is never loaded.
SYSTEMD_DIR = "/etc/systemd/system"
LAUNCHD_DIR = "/Library/LaunchDaemons"


class SupervisionSpecError(ValueError):
    """The supervision section is unusable."""


@dataclass(frozen=True)
class SupervisionSpec:
    kind: str
    engine: str
    hub: Dict[str, str]
    weekly: Dict[str, Any]
    requires: Tuple[Tuple[str, str], ...]


def _abs(p: Any, what: str) -> str:
    if not isinstance(p, str) or not p.startswith("/") or posixpath.normpath(p) != p or p == "/":
        raise SupervisionSpecError(f"supervision.{what} must be an absolute, normalised path")
    return p


def _exact(d: Any, keys: Sequence[str], what: str) -> Dict[str, Any]:
    if not isinstance(d, dict) or set(d) != set(keys):
        raise SupervisionSpecError(f"supervision.{what} must have exactly {', '.join(keys)}")
    return d


def _int(v: Any, lo: int, hi: int, what: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        raise SupervisionSpecError(f"supervision.{what} must be an integer from {lo} to {hi}")
    return v


def _in(p: str, directory: str, what: str) -> None:
    if posixpath.dirname(p) != directory:
        raise SupervisionSpecError(f"supervision.{what} must be directly in {directory}/")


def load(sec: Any, spec: Any) -> SupervisionSpec:
    """Parse and validate the section. It needs the hub section (the runtime
    it supervises) and the secrets section (the weekly probe, the writer,
    the tools and the runtime clone)."""
    if spec.hub is None or spec.secrets is None or spec.secrets.probe is None:
        raise SupervisionSpecError("the supervision section needs the hub section and a secrets section "
                                   "with its probe settings")
    sec = _exact(sec, ("kind", "engine", "hub", "weekly", "requires"), "(the section)")
    kind = sec["kind"]
    if kind not in KINDS:
        raise SupervisionSpecError(f"supervision.kind must be one of {', '.join(KINDS)}")
    if not isinstance(sec["engine"], str) or not _ENGINE.fullmatch(sec["engine"]):
        raise SupervisionSpecError("supervision.engine must be unix:///<socket path>")
    tools = spec.secrets.tools
    if not isinstance(tools.get(MANAGERS[kind]), str) or not posixpath.isabs(tools[MANAGERS[kind]]):
        raise SupervisionSpecError(f"a {kind} host records its manager as secrets.tools.{MANAGERS[kind]}")
    if "launchctl" in tools and tools["launchctl"] != LAUNCHCTL:
        raise SupervisionSpecError(f"secrets.tools.launchctl must be {LAUNCHCTL}")
    if kind == "systemd":
        hub = _exact(sec["hub"], ("unit",), "hub")
        if not _abs(hub["unit"], "hub.unit").endswith(".service"):
            raise SupervisionSpecError("supervision.hub.unit must be a .service path")
        _in(hub["unit"], SYSTEMD_DIR, "hub.unit")
        wk_keys = ("service", "timer", "weekday", "hour", "minute")
    else:
        hub = _exact(sec["hub"], ("label", "plist", "wrapper", "status"), "hub")
        for k in ("plist", "wrapper", "status"):
            _abs(hub[k], f"hub.{k}")
        if not isinstance(hub["label"], str) or not _LABEL.fullmatch(hub["label"]):
            raise SupervisionSpecError("supervision.hub.label must be a launchd label")
        if posixpath.basename(hub["plist"]) != f"{hub['label']}.plist":
            raise SupervisionSpecError("supervision.hub.plist must be <label>.plist")
        _in(hub["plist"], LAUNCHD_DIR, "hub.plist")
        wk_keys = ("label", "plist", "weekday", "hour", "minute")
    weekly = _exact(sec["weekly"], wk_keys, "weekly")
    _int(weekly["weekday"], 0, 6, "weekly.weekday")
    _int(weekly["hour"], 0, 23, "weekly.hour")
    _int(weekly["minute"], 0, 59, "weekly.minute")
    if kind == "systemd":
        if not _abs(weekly["service"], "weekly.service").endswith(".service") \
                or not _abs(weekly["timer"], "weekly.timer").endswith(".timer"):
            raise SupervisionSpecError("supervision.weekly needs a .service and a .timer path")
        _in(weekly["service"], SYSTEMD_DIR, "weekly.service")
        _in(weekly["timer"], SYSTEMD_DIR, "weekly.timer")
    elif not isinstance(weekly["label"], str) or not _LABEL.fullmatch(weekly["label"]) \
            or posixpath.basename(_abs(weekly["plist"], "weekly.plist")) != f"{weekly['label']}.plist":
        raise SupervisionSpecError("supervision.weekly needs a launchd label and its <label>.plist path")
    else:
        _in(weekly["plist"], LAUNCHD_DIR, "weekly.plist")
    req = sec["requires"]
    if not isinstance(req, list) or not req:
        raise SupervisionSpecError("supervision.requires must list the reviewed commits the runtime needs")
    requires = []
    for i, r in enumerate(req):
        r = _exact(r, ("name", "commit"), f"requires[{i}]")
        if not isinstance(r["name"], str) or not r["name"].strip() \
                or not isinstance(r["commit"], str) or not _HEX40.fullmatch(r["commit"]):
            raise SupervisionSpecError(f"supervision.requires[{i}] needs a name and a full commit sha")
        requires.append((r["name"], r["commit"]))
    return SupervisionSpec(kind=kind, engine=sec["engine"], hub=dict(hub), weekly=dict(weekly),
                           requires=tuple(requires))


# --- The rendering --------------------------------------------------------------


def hub_name(spec: Any) -> str:
    return spec.runtime_of(spec.secrets.principal)["container"]


def run_argv(spec: Any) -> List[str]:
    """The runtime's `docker run`, by the recorded docker, from its run spec.
    Supervisors run as root, so no sudo."""
    return [spec.secrets.tools["docker"], "run"] + hr.argv(hr.run_spec(spec, spec.hub))


#: The writer's step that does nothing: the barrier's first line judges docker
#: (--also) and runs none of it, through the one vector trusted-exec admits.
NOOP = "noop"


def rt_path(spec: Any) -> str:
    """root-trust.sh, placed root 0444 beside the writer."""
    return posixpath.join(spec.secrets.writer_dir, rt.NAME)


def root_cmd(spec: Any, argv: List[str], also: Sequence[str] = ()) -> List[str]:
    """`argv`, run by root through the one barrier (ROOT-BOOTSTRAP d3.2):
    the anchor (with the engine, which env -i would wipe), root-trust.sh's
    root_exec judging the OS interpreter and the pinned writer, then the
    writer's trusted-exec judging argv and `also`, and exec'ing argv."""
    s = spec.secrets
    args = ["trusted-exec"] + tool_args(spec) + [x for t in also for x in ("--also", t)] + ["--"] + list(argv)
    return rt.root_argv(rt_path(spec), s.writer_sha256, s.tools["python3"], s.writer, args,
                        engine=spec.supervision.engine)


def tool_args(spec: Any) -> List[str]:
    """`--tool T` for every tool the document records: trusted-exec's argv[0]
    allowlist (d3.3 §4.1), the document's whole set, never a line's own. sudo
    is left out: trusted-exec refuses it anywhere, and root's line never names it."""
    return [x for t in sorted(set(spec.secrets.tools.values())) if posixpath.basename(t) != "sudo"
            for x in ("--tool", t)]


def own(spec: Any, *step: str) -> List[str]:
    """The pinned writer run by its own interpreter: the one vector trusted-exec admits."""
    s = spec.secrets
    return [s.tools["python3"], "-I", "-S", "-B", s.writer] + list(step)


def weekly_argv(spec: Any) -> List[str]:
    """The weekly probe: the one-shot login probe, under the run directory's
    lock, recorded by the pinned writer's probe-weekly, all of it through the
    barrier. Root runs docker directly: root's argv never holds sudo."""
    s = spec.secrets
    sup = spec.supervision
    status = posixpath.join(s.status_dir, ss.STATUS_FILE)
    inner = own(spec, "probe-weekly", status, WEEKLY_RUN_ID, "--engine", sup.engine, "--docker", s.tools["docker"],
                "--") + ss.probe(s, WEEKLY_RUN_ID, root=True)
    return root_cmd(spec, own(spec, "lock", s.run_dir, "--") + inner, also=[s.tools["docker"]])


def _sd(arg: str) -> str:
    """One systemd command-line word: `%` and `$` escaped, quoted when needed."""
    a = arg.replace("%", "%%").replace("$", "$$")
    if a and re.fullmatch(r"[A-Za-z0-9_@+=:,./-]+", a):
        return a
    return '"' + a.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _sd_line(argv: Sequence[str]) -> str:
    return " ".join(_sd(a) for a in argv)


HEADER = "# Rendered by amap-deploy-sandy hub-supervise from the anchored overlay. Place it; never edit it.\n"


def systemd_unit(spec: Any) -> bytes:
    sup = spec.supervision
    docker, name = spec.secrets.tools["docker"], hub_name(spec)
    return (HEADER + "[Unit]\n"
            f"Description=amap hub-link email router ({name})\n"
            "After=docker.service\nRequires=docker.service\n"
            f"StartLimitIntervalSec={START_LIMIT_INTERVAL_S}\nStartLimitBurst={START_LIMIT_BURST}\n\n"
            "[Service]\nType=exec\n"
            f"ExecStartPre={_sd_line(root_cmd(spec, own(spec, NOOP), also=[docker]))}\n"
            f"ExecStartPre=-{_sd_line(root_cmd(spec, [docker, 'rm', name]))}\n"
            f"ExecStart={_sd_line(root_cmd(spec, run_argv(spec)))}\n"
            f"ExecStop={_sd_line(root_cmd(spec, [docker, 'stop', '-t', str(STOP_TIMEOUT_S), name]))}\n"
            f"TimeoutStopSec={SUPERVISOR_STOP_S}\n"
            f"Restart=on-failure\nRestartSec={RESTART_SEC}\n"
            f"RestartPreventExitStatus={' '.join(map(str, NO_RESTART))}\n"
            f"SuccessExitStatus={STOP_CODE}\n\n"
            "[Install]\nWantedBy=multi-user.target\n").encode("utf-8")


def systemd_weekly(spec: Any) -> Tuple[bytes, bytes]:
    sup = spec.supervision
    w = sup.weekly
    service = (HEADER + "[Unit]\nDescription=amap hub-link login probe, weekly\n\n"
               "[Service]\nType=oneshot\n"
               f"ExecStart={_sd_line(weekly_argv(spec))}\n").encode("utf-8")
    timer = (HEADER + "[Unit]\nDescription=amap hub-link login probe, weekly\n\n"
             f"[Timer]\nOnCalendar={DAYS[w['weekday']]} *-*-* {w['hour']:02d}:{w['minute']:02d}:00\n"
             f"Persistent=true\nUnit={posixpath.basename(w['service'])}\n\n"
             "[Install]\nWantedBy=timers.target\n").encode("utf-8")
    return service, timer


def wrapper(spec: Any) -> bytes:
    """The macOS wrapper, POSIX sh (dash and bash --posix)."""
    sup = spec.supervision
    q = shlex.quote
    keep = "|".join(map(str, (0,) + NO_RESTART))
    run = " ".join(q(a) for a in run_argv(spec)[1:])
    tools = " ".join(q(a) for a in tool_args(spec))
    image = q(hr.run_spec(spec, spec.hub)["image"])
    s = spec.secrets
    return f"""#!/bin/sh
# hub-link-run. Rendered by amap-deploy-sandy hub-supervise from the anchored
# overlay; placed root 0444 by the pinned writer and run by its LaunchDaemon as
# /bin/sh <this file>. Never edit it.
set -u
DOCKER={q(spec.secrets.tools['docker'])}
RT={q(rt_path(spec))}
SHA={q(s.writer_sha256)}
PY={q(s.tools['python3'])}
WR={q(s.writer)}
NAME={q(hub_name(spec))}
STATUS={q(sup.hub['status'])}
DOCKER_HOST={q(sup.engine)}
export DOCKER_HOST
say() {{ printf '{SAY}%s\\n' "$1" >&2; }}
# Every docker call root makes goes through the one barrier, in a subshell (root_exec execs).
root_docker() {{ ( command . "$RT" && command -v root_exec >/dev/null || exit {rt.EXIT}; root_exec "$SHA" "$PY" "$WR" trusted-exec {tools} -- "$DOCKER" "$@" ); }}
record() {{
    printf '%s %s\\n' "$1" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$STATUS.tmp" && mv -f "$STATUS.tmp" "$STATUS"
}}

# 0. Root runs docker only when the pinned writer finds it, and python3, root's
#    alone; otherwise nothing runs, and the refusal is final (no restart) once
#    it is recorded. A refusal that cannot be recorded removes the last status,
#    so no earlier result stands for it, and exits 1: launchd retries, and each
#    retry refuses again.
if ! ( command . "$RT" && command -v root_exec >/dev/null || exit {rt.EXIT}; root_exec "$SHA" "$PY" "$WR" trusted-exec {tools} --also "$DOCKER" -- "$PY" -I -S -B "$WR" {NOOP} ) >/dev/null; then
    if record {UNTRUSTED}; then
        say "docker or python3 is not root's alone: nothing was run"
        exit 0
    fi
    rm -f "$STATUS" || say "the last status could not be removed: it may be an earlier one"
    say "docker or python3 is not root's alone: nothing was run, and {UNRECORDED}"
    exit 1
fi

# 1. A container left by the last run: a stopped one is removed (never -f);
#    a running one is an orphan, left alone, and this run ends cleanly.
if state=$(root_docker inspect -f '{{{{.State.Status}}}}' "$NAME" 2>/dev/null); then
    case "$state" in
        created|exited|dead) root_docker rm "$NAME" >/dev/null || exit 125 ;;
        running|paused|restarting)
            record {ORPHAN}
            say "$NAME is already $state: not started, and not stopped"
            exit 0 ;;
        *) say "$NAME is in an unknown state: $state"; exit 125 ;;
    esac
else
    ids=$(root_docker ps -a -q --filter "name=^/$NAME\\$") || {{ say "the engine does not answer"; exit 125; }}
    [ -z "$ids" ] || {{ say "$NAME exists but cannot be inspected"; exit 125; }}
fi

# 1b. The barrier passed and the run is next: recorded and said, so a healthy start's status
#     is not missing and its last line is not an earlier refusal (Opus N1).
record {STARTED} || say "the start could not be recorded"
say "started: the barrier passed"

# 2. A stop request becomes a docker stop; the run continues to its exit. A stop the barrier
#    refuses never reaches docker: the container keeps running, and launchd's ExitTimeOut
#    then kills this wrapper and the client, not the container (RE N2).
interrupted=0
stop_it() {{
    interrupted=1
    root_docker stop -t {STOP_TIMEOUT_S} "$NAME" >/dev/null 2>&1 \
        || say "the stop was refused or failed: the container may still be running; docker ps names it"
}}
trap stop_it TERM INT

# 3. The run, in the background, so a signal is handled while it runs. Its own output
#    (the router's lines) goes to the engine's log, not to the error stream, which
#    holds this wrapper's lines alone (RE N6).
root_docker {run} >/dev/null 2>&1 &
child=$!
wait "$child"
code=$?
while [ "$interrupted" = 1 ]; do
    interrupted=0
    wait "$child"
    again=$?
    [ "$again" = 127 ] || code=$again
done

# 4. The code: 0 and 2-11 are final (recorded, exit 0, no restart); any other
#    code is passed on, and launchd restarts on it.
case "$code" in
    {keep})
        record "$code"
        say "exit $code: recorded, not restarted"
        exit 0 ;;
    {ENGINE_EXIT})
        # docker's own "the container never started" (RE N7): its words went with the run's output,
        # so say what the engine can still tell about the two likeliest causes, then pass it on
        if found=$(root_docker image inspect --format '{{{{.Id}}}}' {image} 2>&1); then
            say "exit $code: the image is present ($found)"
        else
            say "exit $code: the image {image} cannot be inspected: $found"
        fi
        if found=$(root_docker ps -a -q --filter "name=^/$NAME\\$" 2>&1); then
            say "exit $code: a container named $NAME: ${{found:-none}}"
        else
            say "exit $code: the engine does not answer: $found"
        fi
        say "exit $code: passed on"
        exit "$code" ;;
    {rt.EXIT})
        say "exit $code: {REFUSED_RUN} (its own words went with the run's output); passed on, and the next start's step 0 records why"
        exit "$code" ;;
    *)
        say "exit $code: passed on"
        exit "$code" ;;
esac
""".encode("utf-8")


def err_path(spec: Any) -> str:
    """The wrapper's StandardErrorPath, beside its status."""
    return posixpath.join(posixpath.dirname(spec.supervision.hub["status"]), ERR_NAME)


def hub_plist(spec: Any) -> bytes:
    h = spec.supervision.hub
    return plistlib.dumps({
        "Label": h["label"],
        "ProgramArguments": rt.anchor() + ["/bin/sh", h["wrapper"]],
        "StandardErrorPath": err_path(spec),
        "KeepAlive": {"SuccessfulExit": False},
        "ThrottleInterval": RESTART_SEC,
        "RunAtLoad": True,
        "ExitTimeOut": SUPERVISOR_STOP_S,
    }, sort_keys=True)


def weekly_plist(spec: Any) -> bytes:
    sup = spec.supervision
    w = sup.weekly
    return plistlib.dumps({
        "Label": w["label"],
        "ProgramArguments": weekly_argv(spec),
        "StartCalendarInterval": {"Weekday": w["weekday"], "Hour": w["hour"], "Minute": w["minute"]},
        "RunAtLoad": False,
    }, sort_keys=True)


def rendered(spec: Any) -> List[Tuple[str, bytes]]:
    """`(placed path, bytes)` for every supervision file, in placement order."""
    sup = spec.supervision
    first = [(rt_path(spec), rt.render(sup.kind, rt_path(spec)).encode("utf-8"))]   # sourced by all the rest
    if sup.kind == "systemd":
        service, timer = systemd_weekly(spec)
        return first + [(sup.hub["unit"], systemd_unit(spec)), (sup.weekly["service"], service),
                        (sup.weekly["timer"], timer)]
    return first + [(sup.hub["wrapper"], wrapper(spec)), (sup.hub["plist"], hub_plist(spec)),
                    (sup.weekly["plist"], weekly_plist(spec))]


def rt_sha256(spec: Any) -> str:
    """sha256 of root-trust.sh as this host's render gives it: what G and
    the deployed context pin."""
    return hr._sha(rt.render(spec.supervision.kind, rt_path(spec)).encode("utf-8"))


#: The deployed context's bound, for the reader; its schema, which a reader refuses unless it knows it.
CONTEXT_MAX = 65536
CONTEXT_SCHEMA = "amap-deploy.deployed-context/1"


def context_path(spec: Any) -> str:
    return posixpath.join(spec.secrets.writer_dir, rt.CONTEXT_NAME)


def context_doc(spec: Any, overlay_sha256: str) -> Dict[str, Any]:
    """What an install publishes last, through the barrier, under the pins
    it names: the identities a later update's U0 compares with the new
    document, and the pins it reads the old hub under. overlay_sha256, the
    approved document's own digest, is informational and never compared."""
    sup = spec.supervision
    if sup.kind == "systemd":
        hub, weekly = posixpath.basename(sup.hub["unit"]), [posixpath.basename(sup.weekly["service"]),
                                                            posixpath.basename(sup.weekly["timer"])]
    else:
        hub, weekly = sup.hub["label"], [sup.weekly["label"]]
    return {"schema": CONTEXT_SCHEMA, "writer_sha256": spec.secrets.writer_sha256,
            "root_trust_sha256": rt_sha256(spec), "host": spec.hub.host_label, "engine": sup.engine,
            "hub_container": hub_name(spec), "hub": hub, "weekly": weekly, "overlay_sha256": overlay_sha256}


def context_bytes(spec: Any, overlay_sha256: str) -> bytes:
    return (json.dumps(context_doc(spec, overlay_sha256), indent=2, sort_keys=True) + "\n").encode("utf-8")


def staged(path: str) -> str:
    """The name a file is written under in the run directory."""
    return "supervise-" + posixpath.basename(path)


def write_files(spec: Any, *, apply: bool, out=print, overlay_sha256: Optional[str] = None) -> int:
    """Every supervision file into the run directory, and the deployed
    context when the document's digest is known."""
    run_dir = spec.secrets.run_dir
    files = rendered(spec)
    if overlay_sha256 is not None:
        files = files + [(context_path(spec), context_bytes(spec, overlay_sha256))]
    for path, data in files:
        dest = posixpath.join(run_dir, staged(path))
        if apply:
            hr.dd.write_atomically(dest, data)
            out(f"hub-supervise: wrote {dest} (sha256 {hr._sha(data)})")
        else:
            out(f"hub-supervise: would write {dest} (sha256 {hr._sha(data)}); run again with --apply")
    return 0


def labels(spec: Any) -> List[str]:
    """The launchd labels, weekly first; none for systemd."""
    sup = spec.supervision
    return [sup.weekly["label"], sup.hub["label"]] if sup.kind == "launchd" else []


#: A LaunchDaemon's plist is root:wheel 0644, as the reviewed design says; every other placed file is 0444.
PLIST_MODE = 0o644
FILE_MODE = 0o444


def mode_of(spec: Any, path: str) -> int:
    """The mode a placed supervision file must have."""
    sup = spec.supervision
    plists = (sup.hub["plist"], sup.weekly["plist"]) if sup.kind == "launchd" else ()
    return PLIST_MODE if path in plists else FILE_MODE


def manager(spec: Any) -> str:
    """The recorded manager of the host's kind: ONE value, rendered both as
    the line's --also and as the verb's --manager."""
    return spec.secrets.tools[MANAGERS[spec.supervision.kind]]


def service_line(spec: Any, action: str, *args: str, q: Callable[[str], str] = shlex.quote) -> str:
    """The typed root line for one row of the writer's service table."""
    m = manager(spec)
    return ss.typed_root(spec.secrets, own(spec, "service", "--manager", m, spec.supervision.kind, action, *args), q,
                         also=[m])


def plan(spec: Any, q: Callable[[str], str], steps: str) -> List[str]:
    """The root steps that place the files. Enabling them is NOT here: it is
    the gated start step, which `hub-start-check` prints only on a pass. On
    macOS both labels are disabled BEFORE their plists are placed, because
    launchd loads every placed plist at boot."""
    run_dir = spec.secrets.run_dir
    lines = [f"# The hub-link router's supervision, staged in {run_dir} by step 0. Placing it enables nothing."]
    for label in labels(spec):
        lines.append("# Before placing: launchd would load it at the next boot.")
        lines.append(service_line(spec, "disable", label, q=q))
    for path, data in rendered(spec):
        mode = mode_of(spec, path)
        lines.append(f"{steps} place {q(posixpath.join(run_dir, staged(path)))} {q(path)} --sha256 {hr._sha(data)}"
                     + (f" --mode {mode:04o}" if mode != FILE_MODE else ""))
    return lines


def start_commands(spec: Any) -> List[str]:
    """The gated first start: printed only after every start check passes,
    each a typed line through the writer's service verb."""
    sup = spec.supervision
    if sup.kind == "systemd":
        return [service_line(spec, "daemon-reload"),
                service_line(spec, "enable-now", posixpath.basename(sup.weekly["timer"])),
                service_line(spec, "enable-now", posixpath.basename(sup.hub["unit"]))]
    return [service_line(spec, "enable", sup.weekly["label"]),
            service_line(spec, "bootstrap", sup.weekly["label"], sup.weekly["plist"]),
            service_line(spec, "enable", sup.hub["label"]),
            service_line(spec, "bootstrap", sup.hub["label"], sup.hub["plist"])]


# --- The planned restart: each unit's or label's state, read as the operator ----

RUNNING, STOPPED, FAILED, LOADED, NOT_LOADED, IN_PROGRESS = (
    "running", "not running", "failed", "loaded", "not loaded", "a weekly run in progress")
#: is-active's answer while a unit restarts or starts: neither running nor stopped yet.
ACTIVATING = ("a restart loop or a start in progress; re-run hub-start-check after it settles, at most about "
              "StartLimitBurst × RestartSec")


def active_state(answer: Any) -> Any:
    """One unit's `systemctl is-active` (rc, stdout), by its exact pairs:
    running, not running, failed, or an Unresolved (activating named)."""
    if isinstance(answer, rh.Unresolved):
        return answer
    rc, out = answer
    if (rc, out) in ((0, "active"), (0, "reloading")):
        return RUNNING
    if (rc, out) == (3, "inactive"):
        return STOPPED
    if rt.SYSTEMD_UNIT_MISSING_ACTIVE is not None and (rc, out) == rt.SYSTEMD_UNIT_MISSING_ACTIVE:
        return STOPPED  # the measured answer for a unit that does not exist: it cannot be running
    if (rc, out) == (3, "failed"):
        return FAILED
    if out == "activating" and rc in (0, 3):
        return rh.Unresolved(ACTIVATING)
    return rh.Unresolved(f"systemctl is-active answered ({rc}, {out!r})")


def ask_active(spec: Any, unit: str) -> Any:
    """`systemctl --no-pager is-active <unit>`, by the recorded manager, for one unit alone."""
    try:
        p = rh.run([manager(spec), "--no-pager", "is-active", unit])
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    return p.rc, p.out.strip()


def ask_print(label: str) -> Any:
    """`launchctl print system/<label>`: (rc, its output)."""
    try:
        p = rh.run([LAUNCHCTL, "print", f"system/{label}"])
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    return p.rc, p.out + p.err


def weekly_state(answer: Any) -> Any:
    """The weekly label: loaded and idle, a run in progress, not loaded, or
    an Unresolved, by print's MEASURED answers alone, as TXN reads them:
    running and idle by its exact lines (root_trust.LAUNCHD_STATE_RUNNING and
    _IDLE), not loaded by its exact (status, output) (LAUNCHD_NOT_FOUND).
    Each answer is unknown while it is unmeasured."""
    if isinstance(answer, rh.Unresolved):
        return answer
    rc, out = answer
    if rc == 0:
        lines = out.split("\n")
        if rt.LAUNCHD_STATE_RUNNING is not None and rt.LAUNCHD_STATE_RUNNING in lines:
            return IN_PROGRESS
        if rt.LAUNCHD_STATE_IDLE is not None and rt.LAUNCHD_STATE_IDLE in lines:
            return LOADED
        return rh.Unresolved("launchctl print's wording for a loaded weekly label is not measured here")
    absent = launchd_absent(rc, out)
    return NOT_LOADED if absent is True else absent


def until_stopped_line(spec: Any, document: Optional[Tuple[str, str]] = None) -> str:
    """The NOT-RUNNING check as the operator runs it, from the deploy clone."""
    s = spec.secrets
    head = [s.tools["python3"], posixpath.join(s.clones["deploy"]["path"], "amap-sandy.py")]
    if document is not None and document[0] == "overlay":
        argv = head + ["--overlay", document[1], "hub-start-check", "--until-stopped"]
    else:
        argv = head + ["hub-start-check", "--until-stopped"] + (["--spec", document[1]] if document else [])
    return " ".join(shlex.quote(a) for a in argv)


def restart_commands(spec: Any, states: Dict[str, Any], document: Optional[Tuple[str, str]] = None) -> List[str]:
    """The start step for the states read now (d3.3 §5(d) §4.3). systemd:
    the hub not running gets its first start, failed gets reset-failed
    first, running is restarted. launchd, weekly label first: a label not
    loaded is enabled and bootstrapped; a loaded one is booted out first
    (the hub then waits for NOT-RUNNING), because a loaded job keeps its
    registered arguments; a weekly run in progress gets nothing."""
    sup = spec.supervision
    if sup.kind == "systemd":
        hub, timer = posixpath.basename(sup.hub["unit"]), posixpath.basename(sup.weekly["timer"])
        lines = [service_line(spec, "daemon-reload")]
        if states["hub"] == FAILED:
            lines.append(service_line(spec, "reset-failed", hub))
        lines.append(service_line(spec, "enable-now", timer))
        lines.append(service_line(spec, "restart", hub) if states["hub"] == RUNNING
                     else service_line(spec, "enable-now", hub))
        return lines
    lines: List[str] = []
    for key, conf in (("weekly", sup.weekly), ("hub", sup.hub)):
        label, state = conf["label"], states[key]
        if state == IN_PROGRESS:
            lines.append("# A weekly run is in progress: nothing for its label; re-run hub-start-check after it ends.")
            continue
        if state == LOADED or state is True:
            lines.append(service_line(spec, "bootout", label))
            if key == "hub":
                lines.append("# Do not go on until this prints NOT-RUNNING:")
                lines.append(until_stopped_line(spec, document))
        lines += [service_line(spec, "enable", label), service_line(spec, "bootstrap", label, conf["plist"])]
    return lines


# --- The old context, and NOT-RUNNING -------------------------------------------

#: The named stop when the placed writer's own install record cannot be used.
NO_OLD_CONTEXT = "no approved old context for the placed writer: the update cannot observe the old hub; the maintainers' call"
#: What an engine that cannot be read is told.
ENGINE_UNREAD = ("the engine could not be read (on a sudo-route host, run `sudo -v` first so the barriered read has "
                 "a ticket), then re-run")
_CONTEXT_MEMBERS = {"schema": str, "writer_sha256": str, "root_trust_sha256": str, "host": str, "engine": str,
                    "hub_container": str, "hub": str, "weekly": list, "overlay_sha256": str}
_HEX64 = re.compile(r"[0-9a-f]{64}")


def _no_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"a duplicate key {k!r}")
        out[k] = v
    return out


def read_old_context(spec: Any, *, lstat: Callable = os.lstat, digest: Optional[Callable[[str], Any]] = None,
                     acl: Optional[Callable[[List[str]], List[str]]] = None, root_uid: int = 0,
                     read: Callable[[int, int], bytes] = os.read) -> Any:
    """The deployed context the placed writer's install published, read
    strictly, or an Unresolved naming why not: its route root's alone,
    searchable, no ACL; the file regular, one link, exactly root:root 0444;
    one JSON object within CONTEXT_MAX, strict UTF-8, no duplicate keys,
    exactly its members and schema; its pins the placed bytes' own; its
    identities the new document's. The measured hashes are never adopted:
    they must merely equal the pins the root-placed record names."""
    path = context_path(spec)
    if digest is None:
        import host_setup
        digest = host_setup._sha256
    if acl is None:
        import host_steps  # operator side: the ACL rule the barrier itself uses
        acl = host_steps.acl_problems
    route = [path]
    while route[0] != "/":
        route.insert(0, posixpath.dirname(route[0]))
    try:
        sts = [lstat(p) for p in route]
    except OSError as e:
        return rh.Unresolved(f"{e.filename or path}: {e.strerror or e}")
    for p, st in zip(route[:-1], sts[:-1]):
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != root_uid or st.st_mode & 0o022 or not st.st_mode & 0o001:
            return rh.Unresolved(f"{p} is not a root-owned directory others can search and no one else can write")
    st = sts[-1]
    if not stat.S_ISREG(st.st_mode) or (st.st_uid, st.st_gid) != (root_uid, 0) or stat.S_IMODE(st.st_mode) != 0o444 \
            or st.st_nlink != 1:
        return rh.Unresolved(f"{path} is not exactly root:root 0444, one link")
    bad = acl(route)
    if bad:
        return rh.Unresolved("; ".join(bad))
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except OSError as e:
        return rh.Unresolved(f"{path}: {e.strerror}")
    try:
        f = os.fstat(fd)
        if (f.st_dev, f.st_ino) != (st.st_dev, st.st_ino):
            return rh.Unresolved(f"{path} changed while it was read")
        if f.st_size > CONTEXT_MAX:
            return rh.Unresolved(f"{path} is larger than {CONTEXT_MAX} bytes")
        # A short read is not the end: read to EOF, never past the bound plus one.
        raw = b""
        while len(raw) <= CONTEXT_MAX:
            chunk = read(fd, CONTEXT_MAX + 1 - len(raw))
            if not chunk:
                break
            raw += chunk
    finally:
        os.close(fd)
    if len(raw) > CONTEXT_MAX:
        return rh.Unresolved(f"{path} is larger than {CONTEXT_MAX} bytes")
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, ValueError) as e:
        return rh.Unresolved(f"{path} is not one strict JSON object ({e})")
    if not isinstance(doc, dict) or set(doc) != set(_CONTEXT_MEMBERS) or \
            any(not isinstance(doc[k], t) for k, t in _CONTEXT_MEMBERS.items()) or \
            not all(isinstance(x, str) for x in doc["weekly"]):
        return rh.Unresolved(f"{path} does not hold exactly the context's members")
    if doc["schema"] != CONTEXT_SCHEMA:
        return rh.Unresolved(f"{path} is schema {doc['schema']!r}, not {CONTEXT_SCHEMA}")
    if not all(_HEX64.fullmatch(doc[k]) for k in ("writer_sha256", "root_trust_sha256", "overlay_sha256")):
        return rh.Unresolved(f"{path} names a pin that is not 64 lowercase hex")
    s = spec.secrets
    if digest(s.writer) != doc["writer_sha256"] or digest(rt_path(spec)) != doc["root_trust_sha256"]:
        return rh.Unresolved("its pins are not the placed writer's and root-trust.sh's bytes")
    new = context_doc(spec, doc["overlay_sha256"])
    for k in ("host", "engine", "hub_container", "hub", "weekly"):
        if doc[k] != new[k]:
            return rh.Unresolved(f"its {k} {doc[k]!r} is not the new document's {new[k]!r}")
    return doc


def under_context(spec: Any, doc: Dict[str, Any]) -> Any:
    """The new document with only the writer's pin replaced by the old
    context's, so the real pin gate admits the placed, old writer."""
    import dataclasses
    return dataclasses.replace(spec, secrets=dataclasses.replace(spec.secrets, writer_sha256=doc["writer_sha256"]))


def ask_running_container(spec: Any) -> Any:
    """Whether the engine lists a RUNNING container named the hub container,
    through verify's gated live route: True, False, or an Unresolved."""
    name = hub_name(spec)
    try:
        with ss.trust_gate(spec.secrets, engine=spec.supervision.engine):
            p = rh.run(ss.live_docker(spec.secrets) + ["ps", "-q", "--no-trunc", "--filter", f"name=^/{name}$"])
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    if p.rc != 0:
        return rh.Unresolved(f"docker ps exited {p.rc}")
    return bool(p.out.strip())


def not_running(spec: Any, *, old_context: bool, active: Optional[Callable[[str], Any]] = None,
                loaded: Callable[[str], Any] = None, container: Optional[Callable[[Any], Any]] = None,
                context: Optional[Callable[[Any], Any]] = None) -> str:
    """The NOT-RUNNING check's last line: `NOT-RUNNING` only when the hub
    (and on systemd the weekly service and timer) are stopped by their
    exact answers AND the engine lists no running hub container; otherwise
    the first unmet condition, `running: …`, `running container: …` or
    `unknown: …`. Under old_context the engine is read through the old
    context's pin, and a context that cannot be used is the named stop."""
    sup = spec.supervision
    read = spec
    if old_context:
        doc = (context or read_old_context)(spec)
        if isinstance(doc, rh.Unresolved):
            return f"unknown: {NO_OLD_CONTEXT} ({doc.reason})"
        read = under_context(spec, doc)
    if sup.kind == "systemd":
        units = [(posixpath.basename(sup.hub["unit"]), (STOPPED, FAILED)),
                 (posixpath.basename(sup.weekly["service"]), (STOPPED, FAILED)),
                 (posixpath.basename(sup.weekly["timer"]), (STOPPED,))]
        for unit, ok in units:
            state = active_state((active or (lambda u: ask_active(spec, u)))(unit))
            if isinstance(state, rh.Unresolved):
                return f"unknown: {unit}: {state.reason}"
            if state not in ok:
                return f"running: {unit}"
    else:
        up = (loaded or ask_loaded)(sup.hub["label"])
        if isinstance(up, rh.Unresolved):
            return f"unknown: {sup.hub['label']}: {up.reason}"
        if up:
            return f"running: {sup.hub['label']}"
    there = (container or ask_running_container)(read)
    if isinstance(there, rh.Unresolved):
        return f"unknown: {ENGINE_UNREAD} ({there.reason})"
    if there:
        return f"running container: {hub_name(spec)}"
    return "NOT-RUNNING"


_BLOCK_OPEN = re.compile(r"[A-Za-z][A-Za-z ]* = \{")
_ENTRY = re.compile(r'"([^"]+)"\s*=>\s*(disabled|enabled|true|false)')


def parse_disabled(text: str) -> Any:
    """`launchctl print-disabled system` as {label: disabled}, or an
    Unresolved when the output is not in the documented form. The form is
    `<name> = {` blocks of `"<label>" => disabled|enabled` lines
    (`true|false` on older macOS, true meaning disabled), each closed by
    `}`, with at least the `disabled services` block. Anything else makes
    the whole answer unknown: a label merely missing from a misread output
    would read as "no override", which launchd loads at boot. A label absent
    from a well-formed output has no override."""
    out: Dict[str, bool] = {}
    inside, seen = False, False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if not inside and _BLOCK_OPEN.fullmatch(line):
            inside = True
            seen = seen or line.startswith("disabled services")
        elif inside and line == "}":
            inside = False
        elif inside and _ENTRY.fullmatch(line):
            m = _ENTRY.fullmatch(line)
            out[m.group(1)] = m.group(2) in ("disabled", "true")
        else:
            return rh.Unresolved("launchctl print-disabled printed a line not in its documented form")
    if inside or not seen:
        return rh.Unresolved("launchctl print-disabled printed no complete `disabled services` block")
    return out


def ask_disabled(spec: Any) -> Any:
    """{label: disabled} for the system domain, or an Unresolved."""
    try:
        p = rh.run([LAUNCHCTL, "print-disabled", "system"])
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    if p.rc != 0:
        return rh.Unresolved(f"launchctl print-disabled system exited {p.rc}")
    return parse_disabled(p.out)


def launchd_absent(rc: int, text: str) -> Any:
    """Whether `launchctl print`'s answer is the MEASURED not-loaded answer:
    True only on the exact (status, output) root_trust.LAUNCHD_NOT_FOUND
    names, trailing newlines dropped as TXN captures it; an Unresolved
    while that fact is unmeasured, or for any other answer. The one test
    every absence reader uses: TXN's U0, the service verb's bootout wait,
    weekly_state and ask_loaded."""
    if rt.LAUNCHD_NOT_FOUND is None:
        return rh.Unresolved("launchctl print's answer for a label that is not loaded is not measured here")
    if (rc, text.rstrip("\n")) == rt.LAUNCHD_NOT_FOUND:
        return True
    return rh.Unresolved(f"launchctl print answered ({rc}, {text.strip()[:80]!r}), not the measured not-loaded answer")


def ask_loaded(label: str) -> Any:
    """True when the system domain has `label` loaded (`launchctl print
    system/<label>` exits 0), False only on the measured not-loaded answer
    (launchd_absent), an Unresolved otherwise, including while that answer
    is unmeasured."""
    try:
        p = rh.run([LAUNCHCTL, "print", f"system/{label}"])
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    if p.rc == 0:
        return True
    absent = launchd_absent(p.rc, p.out + p.err)
    return False if absent is True else absent


def verify_enablement(spec: Any, disabled: Any, gate: Callable[[], Any],
                      loaded: Callable[[str], Any] = ask_loaded) -> List[rh.Check]:
    """Each launchd label stays disabled, and unloaded, until the gated
    start: a label that is not disabled (enabled, or with no override, which
    launchd loads at boot), or is disabled but already LOADED (bootstrapped
    before the override, which the override does not unload), is a FAIL
    unless every start check passes now. `gate` answers that, True, False or
    an Unresolved, and is asked only when needed."""
    out = []
    asked: List[Any] = []
    for label in labels(spec):
        claim = f"{label} is disabled, or every start check passes"
        want = _fact("enablement", True, "placing a plist must not start the router at boot without "
                                         "hub-start-check passing")
        remedy = (f"run `{service_line(spec, 'disable', label)}` (and `{service_line(spec, 'bootout', label)}` "
                  "if it is loaded) until hub-start-check passes, then use the start step it prints")
        state = disabled if isinstance(disabled, rh.Unresolved) else disabled.get(label)
        if isinstance(state, rh.Unresolved):
            out.append(rh.unknown(claim, want, state.reason, remedy))
            continue
        if state is True:
            up = loaded(label)
            if isinstance(up, rh.Unresolved):
                out.append(rh.unknown(claim, want, up.reason, remedy))
                continue
            if up is False:
                out.append(rh.check(claim, want, True, remedy))
                continue
        if not asked:
            asked.append(gate())
        g = asked[0]
        if isinstance(g, rh.Unresolved):
            out.append(rh.unknown(claim, want, g.reason, remedy))
        else:
            out.append(rh.check(claim, want, g is True, remedy,
                                do_not="never enable a label by hand; the start step is printed only on a pass"))
    return out


# --- Verify ---------------------------------------------------------------------


def _fact(name: str, value: Any, provenance: str) -> rh.Fact:
    return rh.Fact(name, value, provenance)


def verify_files(spec: Any, lstat: Callable, read: Callable[[str], bytes]) -> List[rh.Check]:
    """Each placed file: owned by uid 0 and gid 0 (root:wheel on macOS), one
    link, mode 0644 for a plist and 0444 for everything else, under root-owned
    directories nobody else can write, and byte-identical to a fresh render.
    A placed file that differs is a FAIL whether or not it is enabled."""
    out = []
    for path, data in rendered(spec):
        why = "it starts or schedules the hub-link router as root"
        remedy = "render it (`hub-supervise --apply`) and place it as the plan does"
        out.append(ss._owned_chain(f"every directory above {path} is root-owned and not group- or "
                                   f"world-writable", path, (0,), why, lstat))
        try:
            got: Any = read(path)
        except FileNotFoundError:
            got = None
        except OSError as e:
            got = rh.Unresolved(f"cannot read {path}: {e}")
        claim = f"{path} is byte-identical to a fresh render"
        want = _fact("bytes", True, "rendered from the anchored overlay")
        if isinstance(got, rh.Unresolved):
            out.append(rh.unknown(claim, want, got.reason, remedy))
        else:
            out.append(rh.check(claim, want, "absent" if got is None else got == data, remedy,
                                do_not="never edit the placed file; change the overlay and render"))
        st = ss._lst(path, lstat)
        mode = mode_of(spec, path)
        claim = f"{path} is owned by uid 0 and gid 0, mode {mode:04o}, with one link"
        want = _fact("mode", (0, 0, mode, 1), why)
        if isinstance(st, rh.Unresolved):
            out.append(rh.unknown(claim, want, st.reason, remedy))
        elif st is not None:
            out.append(rh.check(claim, want, (st.st_uid, st.st_gid, st.st_mode & 0o7777, st.st_nlink), remedy))
    return out


def ask_ancestor(spec: Any, commit: str, of: str) -> Any:
    """True, False, or an Unresolved: is `commit` an ancestor of `of`, in
    the runtime clone, with system and user git configuration ignored."""
    s = spec.secrets
    path = s.clones["runtime"]["path"]
    try:
        p = rh.run([s.tools["git"], "-C", path, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                    "merge-base", "--is-ancestor", commit, of], extra_env=ss.git_env(path))
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    if p.rc in (0, 1):
        return p.rc == 0
    return rh.Unresolved(f"git merge-base in {path} exited {p.rc}: {p.err.strip()[:200]}")


def ask_label(spec: Any) -> Any:
    """The image's OCI revision label, None when it has none, or an Unresolved."""
    try:
        p = rh.run(ss.live_docker(spec.secrets) + ["image", "inspect", "--format", "{{json .Config.Labels}}",
                                              spec.secrets.image])
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    if p.rc != 0:
        return rh.Unresolved(f"docker image inspect exited {p.rc}")
    try:
        labels = json.loads(p.out) or {}
    except ValueError:
        return rh.Unresolved("docker image inspect printed no JSON")
    return labels.get(REVISION_LABEL) if isinstance(labels, dict) else None


def verify_ancestry(spec: Any, ancestor: Callable[[str, str], Any], label: Any) -> List[rh.Check]:
    """Every required commit is in the runtime's reviewed commit, and the
    image's revision label, where it has one, is that commit."""
    out = []
    image_commit = spec.secrets.clones["runtime"]["sha"]
    remedy = "build the runtime image from a commit that contains it, record that commit, and re-anchor"
    for name, commit in spec.supervision.requires:
        claim = f"the runtime's reviewed commit contains {name} ({commit[:12]})"
        want = _fact("ancestor", True, "the live-start ancestry check: the image must carry the reviewed unit")
        got = ancestor(commit, image_commit)
        out.append(rh.unknown(claim, want, got.reason, remedy) if isinstance(got, rh.Unresolved)
                   else rh.check(claim, want, got, remedy))
    claim = "the runtime image's revision label, where it has one, is its recorded commit"
    want = _fact("label", True, "an image pinned against the wrong commit")
    if isinstance(label, rh.Unresolved):
        out.append(rh.unknown(claim, want, label.reason, "make the engine answer"))
    else:
        out.append(rh.check(claim, want, label is None or label == image_commit,
                            "rebuild the image from the recorded commit, or record the commit it was built from"))
    return out


ASK = hr.ASK


#: The email router's own defaults for a budget left unset, and its bound on
#: each (its smtp_send.DEADLINE_MAX): it reads them as seconds, a float in
#: (0, RE_BUDGET_MAX]. The email router is not a sibling of this repository,
#: so these are cited from its source, not imported from it.
RE_BUDGET_DEFAULTS = {"RELAY_SMTP_CONNECT_TIMEOUT": 300, "RELAY_SMTP_COMMAND_TIMEOUT": 300,
                      "RELAY_SMTP_DOT_TIMEOUT": 600}
RE_BUDGET_MAX = 3600


def _budget(env: Dict[str, str], key: str) -> float:
    """One budget as the email router reads it: its default when unset, else
    a float in (0, RE_BUDGET_MAX]; ValueError naming it otherwise."""
    raw = env.get(key)
    if raw is None or raw == "":
        return float(RE_BUDGET_DEFAULTS[key])
    try:
        v = float(raw)
    except ValueError:
        raise ValueError(f"{key}={raw!r} is not a number of seconds") from None
    if not 0 < v <= RE_BUDGET_MAX:
        raise ValueError(f"{key}={raw!r} is not in (0, {RE_BUDGET_MAX}]")
    return v


def stop_budget(env: Dict[str, str]) -> Tuple[int, int]:
    """(the join bound the stop timeout must cover, the start probe's window),
    from the rendered budgets, read as the email router reads them and
    rounded up to whole seconds; ValueError when one is not a budget it
    accepts."""
    dot = _budget(env, "RELAY_SMTP_DOT_TIMEOUT")
    window = _budget(env, "RELAY_SMTP_CONNECT_TIMEOUT") + START_PROBE_COMMANDS * _budget(env, "RELAY_SMTP_COMMAND_TIMEOUT")
    return math.ceil(dot) + JOIN_SLACK_S + DONE_POLL_S, math.ceil(window) + QUIT_S


def verify_stop_budget(spec: Any) -> List[rh.Check]:
    """The stop timeout held to the join bound DERIVED FROM THE RENDERING, not
    read from the placed environment file: that is sound only because
    verify_files FAILs a placed file that differs from the rendering."""
    try:
        bound, window = stop_budget(dict(hr.environment(spec, spec.hub)))
    except ValueError as e:
        claim = "the rendered SMTP budgets are ones the email router accepts"
        want = rh.Fact("budgets", True, f"the email router reads each as seconds in (0, {RE_BUDGET_MAX}], its default "
                                        "when unset")
        return [rh.check(claim, want, str(e), "render each budget as a number of seconds the router accepts",
                         ok=lambda e_, a: a is True)]
    covered = "covers" if STOP_TIMEOUT_S >= window else "does not cover"
    claim = (f"the stop timeout ({STOP_TIMEOUT_S} s) covers the router's own join (the rendered dot budget + "
             f"{JOIN_SLACK_S} s + {DONE_POLL_S} s); it {covered} the start probe's login window ({window} s), where "
             f"a stop can end in the engine's kill with nothing committed")
    want = rh.Fact("join bound", bound, "the rendered RELAY_SMTP_DOT_TIMEOUT + the router's join slack + its poll")
    return [rh.check(claim, want, STOP_TIMEOUT_S, f"raise STOP_TIMEOUT_S to at least {bound}, or lower the rendered "
                     "dot budget", ok=lambda e, a: a >= e)]


def verify_stop_bound(spec: Any) -> List[rh.Check]:
    """RE N1: the supervisor's own stop bound (systemd TimeoutStopSec, launchd
    ExitTimeOut, both rendered from SUPERVISOR_STOP_S and held to the
    rendering by verify_files) covers the barrier and then the stop timeout,
    so a planned stop is never cut short by the barrier in front of it."""
    claim = (f"the supervisor's stop bound ({SUPERVISOR_STOP_S} s) covers the barrier in front of `docker stop` "
             f"({BARRIER_S} s, declared) and then the stop timeout ({STOP_TIMEOUT_S} s)")
    want = rh.Fact("stop with barrier", BARRIER_S + STOP_TIMEOUT_S,
                   "BARRIER_S, a declared bound measured on Linux only, + STOP_TIMEOUT_S")
    return [rh.check(claim, want, SUPERVISOR_STOP_S, "raise SUPERVISOR_STOP_S to at least the barrier plus the "
                     "stop timeout", ok=lambda e, a: a >= e,
                     do_not="lower STOP_TIMEOUT_S below the router's join bound to make room")]


def verify_service_bound(spec: Any) -> List[rh.Check]:
    """The writer's one service budget covers a planned restart:
    the supervisor's stop bound, three barrier lines (the anchor
    ExecStartPre, `-docker rm` and ExecStart) and the margin."""
    import host_steps  # the writer, never in the weekly bundle's closure: imported only here
    claim = (f"the writer's service budget ({host_steps.SERVICE_TIMEOUT_S} s) covers a planned restart: the stop "
             f"bound ({SUPERVISOR_STOP_S} s), {RESTART_BARRIER_LINES} barrier lines ({BARRIER_S} s each) and "
             f"{SERVICE_MARGIN_S} s")
    want = rh.Fact("restart budget", SUPERVISOR_STOP_S + RESTART_BARRIER_LINES * BARRIER_S + SERVICE_MARGIN_S,
                   "SUPERVISOR_STOP_S + RESTART_BARRIER_LINES × BARRIER_S + SERVICE_MARGIN_S")
    return [rh.check(claim, want, host_steps.SERVICE_TIMEOUT_S, "raise host_steps.SERVICE_TIMEOUT_S to at least the "
                     "stop bound plus three barrier lines and the margin", ok=lambda e, a: a >= e,
                     do_not="lower SUPERVISOR_STOP_S to make room")]


def verify_wrapper_status(spec: Any, lstat: Callable, read: Callable[[str], bytes]) -> List[rh.Check]:
    """d3.3 §5 B3, launchd: the wrapper's error stream goes to a root-owned
    place; its status says how the last start ended, and a missing one is a
    FAIL (a refusal that could not be recorded removes it), never "not
    started"; a refusal, recorded or not, is a FAIL. When the status could not
    be removed either, the error stream's last wrapper line says so."""
    status, err = spec.supervision.hub["status"], err_path(spec)
    why = "launchd writes the wrapper's error stream as root"
    remedy = "keep the status directory root's alone, as the plan creates it"
    out = [ss._owned_chain(f"every directory above {err} is root-owned and not group- or world-writable", err,
                           (0,), why, lstat)]
    st = ss._lst(err, lstat)
    claim = f"{err} is owned by uid 0 and not group- or world-writable"
    want = _fact("error stream", True, why)
    if isinstance(st, rh.Unresolved):
        out.append(rh.unknown(claim, want, st.reason, remedy))
    elif st is not None:
        out.append(rh.check(claim, want, st.st_uid == 0 and not st.st_mode & 0o022, remedy))
    claim = f"the wrapper's status {status} records a start that was not refused"
    want = _fact("status", True, "the wrapper records every end; a refusal it cannot record removes the last one")
    remedy = (f"read {err} for why, fix what the barrier refused (verify's tool and closure rows name it), and "
              "let launchd start the wrapper again")
    try:
        got: Any = read(status).decode("utf-8", "replace").split()
    except FileNotFoundError:
        got = None
    except OSError as e:
        got = rh.Unresolved(f"cannot read {status}: {e}")
    if isinstance(got, rh.Unresolved):
        out.append(rh.unknown(claim, want, got.reason, remedy))
    else:
        out.append(rh.check(claim, want, bool(got) and got[0] != UNTRUSTED, remedy,
                            do_not="never write a status by hand: a missing one is the refusal's own evidence"))
    try:
        lines = read(err).decode("utf-8", "replace").splitlines()
    except FileNotFoundError:
        lines = []
    except OSError as e:
        lines = rh.Unresolved(f"cannot read {err}: {e}")
    claim = f"the wrapper's last line in {err} is not a refusal the status does not show"
    want = _fact("unrecorded refusal", False, f"the wrapper says \"{UNRECORDED}\" when it could not record one, "
                                               f"and \"{REFUSED_RUN}\" when the run line itself was refused")
    if isinstance(lines, rh.Unresolved):
        out.append(rh.unknown(claim, want, lines.reason, remedy))
    else:
        mine = [l for l in lines if l.startswith(SAY)]
        out.append(rh.check(claim, want, bool(mine) and (UNRECORDED in mine[-1] or REFUSED_RUN in mine[-1]), remedy))
    return out


def checks(spec: Any, *, lstat: Callable, read: Callable[[str], bytes] = hr.dd.read_file,
           ancestor: Any = ASK, label: Any = ASK) -> List[rh.Check]:
    out = verify_files(spec, lstat, read)
    if spec.supervision.kind == "launchd":
        out += verify_wrapper_status(spec, lstat, read)
    out += verify_stop_budget(spec)
    out += verify_stop_bound(spec)
    out += verify_service_bound(spec)
    out += verify_ancestry(spec, (lambda c, o: ask_ancestor(spec, c, o)) if ancestor is ASK else ancestor,
                           ask_label(spec) if label is ASK else label)
    return out
