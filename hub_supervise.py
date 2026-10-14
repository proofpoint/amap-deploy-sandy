"""The hub-link email router's supervision and its start check: the files
that start it and keep it running, the weekly login probe's job, and the
live-start ancestry check. NOTHING HERE STARTS, LOADS OR ENABLES ANYTHING:
the files are rendered into the operator's run directory under an explicit
`--apply`, the plan's root steps place them, and the start step (enable and
start) is printed only by `hub-start-check`, only when every check passes.
Starting is the operator's act.

On macOS, launchd loads every plist in /Library/LaunchDaemons at boot, so
placing one would start it at the next boot. The plan therefore runs
`launchctl disable system/<label>` for both labels BEFORE placing them (a
persistent override that launchd honours at boot), and the start step is
`launchctl enable` followed by `launchctl bootstrap`. Verify reads the
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
`/bin/sh <wrapper>`, never directly. It starts `docker run` in the
background and blocks in `wait`, because a POSIX shell defers a trap while a
foreground command runs.
"""

import json
import plistlib
import posixpath
import re
import shlex
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import hub_runtime as hr
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
#: `docker stop -t`: at least the rendered dot budget + 60 s, the router's own
#: join bound, so a stop during a slow dot ends in the router's join, never in
#: the engine's kill.
STOP_TIMEOUT_S = 100
#: The supervisors' own bounds sit above the stop: systemd's default
#: TimeoutStopSec (90 s) and launchd's default ExitTimeOut (20 s) are below it.
SUPERVISOR_STOP_S = 120
ORPHAN = "orphan_running"
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


def weekly_argv(spec: Any) -> List[str]:
    """The weekly probe: the one-shot login probe, under the run directory's
    lock, recorded by the pinned writer's probe-weekly."""
    s = spec.secrets
    sup = spec.supervision
    status = posixpath.join(s.status_dir, ss.STATUS_FILE)
    inner = [s.tools["python3"], "-I", "-S", s.writer, "probe-weekly", status, WEEKLY_RUN_ID,
             "--engine", sup.engine, "--docker", s.tools["docker"], "--"] + ss.probe(s, WEEKLY_RUN_ID)
    return ss.locked(s, inner)


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
            f"Environment={_sd('DOCKER_HOST=' + sup.engine)}\n"
            f"ExecStartPre=-{_sd_line([docker, 'rm', name])}\n"
            f"ExecStart={_sd_line(run_argv(spec))}\n"
            f"ExecStop={_sd_line([docker, 'stop', '-t', str(STOP_TIMEOUT_S), name])}\n"
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
               f"Environment={_sd('DOCKER_HOST=' + sup.engine)}\n"
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
    run = " ".join(q(a) for a in run_argv(spec))
    return f"""#!/bin/sh
# hub-link-run. Rendered by amap-deploy-sandy hub-supervise from the anchored
# overlay; placed root 0444 by the pinned writer and run by its LaunchDaemon as
# /bin/sh <this file>. Never edit it.
set -u
DOCKER={q(spec.secrets.tools['docker'])}
NAME={q(hub_name(spec))}
STATUS={q(sup.hub['status'])}
DOCKER_HOST={q(sup.engine)}
export DOCKER_HOST
say() {{ printf 'hub-link-run: %s\\n' "$1" >&2; }}
record() {{
    printf '%s %s\\n' "$1" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$STATUS.tmp" && mv -f "$STATUS.tmp" "$STATUS"
}}

# 1. A container left by the last run: a stopped one is removed (never -f);
#    a running one is an orphan, left alone, and this run ends cleanly.
if state=$("$DOCKER" inspect -f '{{{{.State.Status}}}}' "$NAME" 2>/dev/null); then
    case "$state" in
        created|exited|dead) "$DOCKER" rm "$NAME" >/dev/null || exit 125 ;;
        running|paused|restarting)
            record {ORPHAN}
            say "$NAME is already $state: not started, and not stopped"
            exit 0 ;;
        *) say "$NAME is in an unknown state: $state"; exit 125 ;;
    esac
else
    ids=$("$DOCKER" ps -a -q --filter "name=^/$NAME\\$") || {{ say "the engine does not answer"; exit 125; }}
    [ -z "$ids" ] || {{ say "$NAME exists but cannot be inspected"; exit 125; }}
fi

# 2. A stop request becomes a docker stop; the run continues to its exit.
interrupted=0
stop_it() {{ interrupted=1; "$DOCKER" stop -t {STOP_TIMEOUT_S} "$NAME" >/dev/null 2>&1; }}
trap stop_it TERM INT

# 3. The run, in the background, so a signal is handled while it runs.
{run} &
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
    *)
        say "exit $code: passed on"
        exit "$code" ;;
esac
""".encode("utf-8")


def hub_plist(spec: Any) -> bytes:
    h = spec.supervision.hub
    return plistlib.dumps({
        "Label": h["label"],
        "ProgramArguments": ["/bin/sh", h["wrapper"]],
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
        "EnvironmentVariables": {"DOCKER_HOST": sup.engine},
        "RunAtLoad": False,
    }, sort_keys=True)


def rendered(spec: Any) -> List[Tuple[str, bytes]]:
    """`(placed path, bytes)` for every supervision file, in placement order."""
    sup = spec.supervision
    if sup.kind == "systemd":
        service, timer = systemd_weekly(spec)
        return [(sup.hub["unit"], systemd_unit(spec)), (sup.weekly["service"], service),
                (sup.weekly["timer"], timer)]
    return [(sup.hub["wrapper"], wrapper(spec)), (sup.hub["plist"], hub_plist(spec)),
            (sup.weekly["plist"], weekly_plist(spec))]


def staged(path: str) -> str:
    """The name a file is written under in the run directory."""
    return "supervise-" + posixpath.basename(path)


def write_files(spec: Any, *, apply: bool, out=print) -> int:
    run_dir = spec.secrets.run_dir
    for path, data in rendered(spec):
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


def plan(spec: Any, q: Callable[[str], str], steps: str) -> List[str]:
    """The root steps that place the files. Enabling them is NOT here: it is
    the gated start step, which `hub-start-check` prints only on a pass. On
    macOS both labels are disabled BEFORE their plists are placed, because
    launchd loads every placed plist at boot."""
    run_dir = spec.secrets.run_dir
    lines = ["# The hub-link router's supervision. First, as the operator: `amap-sandy.py hub-supervise "
             f"--apply` writes the files into {run_dir}. Placing them enables nothing."]
    for label in labels(spec):
        lines.append(f"{LAUNCHCTL} disable {q('system/' + label)}  # before placing: launchd would load "
                     "it at the next boot")
    for path, data in rendered(spec):
        mode = mode_of(spec, path)
        lines.append(f"{steps} place {q(posixpath.join(run_dir, staged(path)))} {q(path)} --sha256 {hr._sha(data)}"
                     + (f" --mode {mode:04o}" if mode != FILE_MODE else ""))
    return lines


def start_commands(spec: Any) -> List[str]:
    """The gated start step: printed only after every start check passes."""
    sup = spec.supervision
    if sup.kind == "systemd":
        return ["systemctl daemon-reload",
                f"systemctl enable --now {posixpath.basename(sup.weekly['timer'])}",
                f"systemctl enable --now {posixpath.basename(sup.hub['unit'])}"]
    return [f"{LAUNCHCTL} enable system/{sup.weekly['label']}",
            f"{LAUNCHCTL} bootstrap system {sup.weekly['plist']}",
            f"{LAUNCHCTL} enable system/{sup.hub['label']}",
            f"{LAUNCHCTL} bootstrap system {sup.hub['plist']}"]


def parse_disabled(text: str) -> Dict[str, bool]:
    """`launchctl print-disabled system` as {label: disabled}. A line is
    `"<label>" => disabled|enabled` (`true|false` on older macOS, true
    meaning disabled). A label absent from the output has no override."""
    out = {}
    for m in re.finditer(r'^\s*"([^"]+)"\s*=>\s*(disabled|enabled|true|false)\s*$', text, re.M):
        out[m.group(1)] = m.group(2) in ("disabled", "true")
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


def verify_enablement(spec: Any, disabled: Any, gate: Callable[[], Any]) -> List[rh.Check]:
    """Each launchd label stays disabled until the gated start: a label that
    is not disabled (enabled, or with no override, which launchd loads at
    boot) is a FAIL unless every start check passes now. `gate` answers
    that, True, False or an Unresolved, and is asked only when needed."""
    out = []
    asked: List[Any] = []
    for label in labels(spec):
        claim = f"{label} is disabled, or every start check passes"
        want = _fact("enablement", True, "placing a plist must not start the router at boot without "
                                         "hub-start-check passing")
        remedy = (f"run `{LAUNCHCTL} disable system/{label}` (and `{LAUNCHCTL} bootout system/{label}` if "
                  "it is loaded) until hub-start-check passes, then use the start step it prints")
        state = disabled if isinstance(disabled, rh.Unresolved) else disabled.get(label)
        if isinstance(state, rh.Unresolved):
            out.append(rh.unknown(claim, want, state.reason, remedy))
            continue
        if state is True:
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
        p = rh.run(ss.docker(spec.secrets) + ["image", "inspect", "--format", "{{json .Config.Labels}}",
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


def checks(spec: Any, *, lstat: Callable, read: Callable[[str], bytes] = hr.dd.read_file,
           ancestor: Any = ASK, label: Any = ASK) -> List[rh.Check]:
    out = verify_files(spec, lstat, read)
    out += verify_ancestry(spec, (lambda c, o: ask_ancestor(spec, c, o)) if ancestor is ASK else ancestor,
                           ask_label(spec) if label is ASK else label)
    return out
