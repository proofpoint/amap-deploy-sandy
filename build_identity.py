"""What each running runtime was built from: `verify --host-facts`'s
"runtime builds" phase.

Four claims, each PASS, FAIL or UNKNOWN by router_health's discipline, each
with a stable id the conformance harness keys on (the claim prose may
change; the ids may not):

- `build.hop_router`: [1], the local router with its hop keys, runs the
  image the host-setup document's `router` section records, and that record's
  commit is siblings.json's hop pin.
- `build.hub_router`: [2], the hub-link router, runs an image whose
  `org.opencontainers.image.revision` label is the `secrets.image_commit` the
  document records. The label is read from the IMAGE, by the container's
  image id, because `docker run --label` can set a container label at run
  time; a container label that differs from its image's is a FAIL.
- `build.connector`: the stamp `install` placed in the payload names the
  connector commit siblings.json pins, from a clean checkout.
- `build.hop_plugin`: once per router that loads the transport plugin, the
  sha256 that router's loader computed from the bytes it executed, as the
  router publishes it in its own status document, is the overlay pin's.
  Bytes read host-side are never evidence: the file can change between a
  check and a read, and after the load, on clocks verify cannot qualify.
  A router that publishes no digest is UNKNOWN. [1]'s document is read
  host-side from its identity-bound state directory; [2]'s by one `docker
  exec` of HUB_READER, because its ledger is private to its user. Both are
  bound to the running process by the process start and, where the engine
  records no exit (always for [2]), by a progress counter seen to rise.

ABSENT IS UNKNOWN. A missing label, stamp, record, container or mount never
passes, and an `observed_*` value is reported only when it was read.

A claim appears exactly when its role is deployed here, and the phase names
the deployed roles (`deployed_roles`), so a reader can tell "not deployed"
from "left out". When the host-setup document exists but cannot be read,
both router roles are listed and their claims are UNKNOWN: an unreadable
document must refuse, not read as "nothing deployed".
"""

import calendar
import datetime
import errno
import json
import math
import os
import posixpath
import re
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set

import router_health as rh

SECTION_ID = "runtime-builds"
TITLE = "runtime builds"
LABEL = "org.opencontainers.image.revision"
STAMP_NAME = "connector-commit.json"
STAMP_SCHEMA = 1

ROLE_HOP, ROLE_HUB, ROLE_CONNECTOR = "hop_router", "hub_router", "connector"
ID_HOP, ID_HUB, ID_CONNECTOR, ID_PLUGIN = "build.hop_router", "build.hub_router", "build.connector", "build.hop_plugin"

#: The router's status-document members for the plugin it loaded: the
#: member, its digest key, and the process start that binds it.
PLUGIN_MEMBER, PLUGIN_SHA256, PROCESS_START = "transport_plugin", "sha256", "process_started_ts"
STATUS_NAME = "status.json"
#: The most of a status document verify reads.
MAX_STATUS_BYTES = 16 * 2 ** 20
#: The progress witness's contract, the same for [1] and [2]
#: (DS-BUILD-ID-HUB-READER design v2.2 §1, v2.3):
#: - an `interval_s` is admitted only in (0, INTERVAL_CAP_S], so 2 × it is at
#:   most 120 s (HAR's plan cap of 60);
#: - the witness waits 2 × interval_s + PROGRESS_MARGIN_S, never more than
#:   WINDOW_MAX_S, re-reading every PROGRESS_STEP_S. The margin is an
#:   availability policy taken from the rendered per-phase SMTP budget (30 s),
#:   not a measured bound on a request;
#: - [2]'s one `docker exec` holds the whole witness, within HUB_EXEC_TIMEOUT_S;
#: - every other engine call in the phase gets AUX_TIMEOUT_S, and the whole
#:   runtime-builds phase PHASE_BUDGET_S, each call min(its own, the time left).
INTERVAL_CAP_S = 60.0
PROGRESS_MARGIN_S = 30.0
PROGRESS_STEP_S = 0.5
WINDOW_MAX_S = 2 * INTERVAL_CAP_S + PROGRESS_MARGIN_S
HUB_EXEC_TIMEOUT_S = WINDOW_MAX_S + 15.0
AUX_TIMEOUT_S = 20.0
PHASE_BUDGET_S = 540.0
#: No call starts with less than this left of the phase.
BUDGET_FLOOR_S = 1.0

_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
#: docker's State.StartedAt: RFC 3339 in UTC, nanoseconds optional.
_STARTED = re.compile(r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?Z")


@dataclass(frozen=True)
class Claim:
    """A check, and what the host-facts document says beside it."""
    id: str
    check: rh.Check
    observed: Dict[str, str] = field(default_factory=dict)
    host_role: str = ""

    def extras(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"id": self.id, **self.observed}
        if self.host_role:
            out["host_role"] = self.host_role
        return out


def _fact(name: str, value: Any, provenance: str) -> rh.Fact:
    return rh.Fact(name, value, provenance)


def _not_running(live: Any, who: str) -> Optional[str]:
    """Why `live` is not an affirmatively RUNNING container, or None. docker
    inspect answers for an exited container too, with its image; only
    State.Running true says a build is running now."""
    state = live.get("State") if isinstance(live, dict) else None
    running = state.get("Running") if isinstance(state, dict) else None
    if running is True:
        return None
    if running is False:
        status = state.get("Status") if isinstance(state, dict) else None
        return f"{who} is not running (docker reports it {status or 'stopped'}), so no build of it is running"
    return f"docker inspect of {who} does not say whether it is running"


def _running_image(live: Any, who: str) -> Any:
    """The RUNNING container's image id, or an Unresolved saying why not."""
    if isinstance(live, rh.Unresolved):
        return live
    if live is None:
        return rh.Unresolved(f"{who} is not running, so the image it runs cannot be read")
    stopped = _not_running(live, who)
    if stopped is not None:
        return rh.Unresolved(stopped)
    image = live.get("Image") if isinstance(live, dict) else None
    if not isinstance(image, str) or not _DIGEST.fullmatch(image):
        return rh.Unresolved(f"docker inspect of {who} shows no image id")
    return image


def inspect_container(docker: List[str], name: str, run: Optional[Callable[..., rh.Proc]] = None) -> Any:
    """The container's inspect document; None when `docker ps -a` lists no
    container by that name (absence is decided by a listing that succeeds
    and is empty, never by a daemon's error prose); else an Unresolved."""
    run = run or rh.run       # looked up at the call, so the one run the process uses is the one asked
    try:
        p = run(docker + ["inspect", "--type", "container", name])
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    if p.rc != 0:
        try:
            q = run(docker + ["ps", "-a", "-q", "--filter", f"name=^/{name}$"])
        except rh.CannotRun as e:
            return rh.Unresolved(str(e))
        if q.rc == 0 and not q.out.strip():
            return None
        return rh.Unresolved(f"docker inspect {name} exited {p.rc}")
    try:
        doc = json.loads(p.out)
    except ValueError:
        return rh.Unresolved(f"docker inspect {name} printed no JSON")
    return doc[0] if isinstance(doc, list) and doc and isinstance(doc[0], dict) else \
        rh.Unresolved(f"docker inspect {name} printed no container")


def image_labels(docker: List[str], image_id: str, run: Optional[Callable[..., rh.Proc]] = None) -> Any:
    """The image's own Config.Labels (a dict, {} when it has none), asked by
    its id, or an Unresolved."""
    run = run or rh.run
    try:
        p = run(docker + ["image", "inspect", "--format", "{{json .Config.Labels}}", image_id])
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    if p.rc != 0:
        return rh.Unresolved(f"docker image inspect exited {p.rc}")
    try:
        labels = json.loads(p.out)
    except ValueError:
        return rh.Unresolved("docker image inspect printed no JSON")
    if labels is None:
        return {}
    return labels if isinstance(labels, dict) else rh.Unresolved("docker image inspect printed no labels object")


# --- [1] ---------------------------------------------------------------------


def hop_router(router: Any, pin: Any, live: Any) -> Claim:
    """`router` is the document's RouterSpec; `pin` the hop pin (or an
    Unresolved); `live` [1]'s inspect document, None, or an Unresolved.
    observed_commit is DIGEST-BOUND: the commit the document records for the
    digest [1] is running, reported only when the running digest is the
    recorded one; it is not read from the image."""
    who = f"[1] ({router.container})"
    claim = f"{who} runs its recorded image, built from the hop pin"
    remedy = ("build [1]'s image from the hop pin's commit, record its digest and that commit in the "
              "router section, and start it with the hop checkout's docker/run.sh")
    # An unreadable pin is the whole Fact's value: a tuple holding an
    # Unresolved would count as known and compare to a FAIL.
    want = _fact("image and commit", pin if isinstance(pin, rh.Unresolved) else (router.image_digest, pin),
                 "the router section's recorded digest, and siblings.json's hop pin")
    image = _running_image(live, who)
    observed: Dict[str, str] = {}
    if not isinstance(image, rh.Unresolved):
        observed["observed_image_digest"] = image
        if image == router.image_digest:
            observed["observed_commit"] = router.image_commit
        return Claim(ID_HOP, rh.check(claim, want, (image, router.image_commit), remedy), observed)
    return Claim(ID_HOP, rh.check(claim, want, image, remedy))


# --- [2] ---------------------------------------------------------------------


def hub_router(container: str, image_commit: Optional[str], live: Any, image_labels: Any) -> Claim:
    """`image_commit` is the document's `secrets.image_commit` (None when it
    records none); `live` [2]'s inspect document; `image_labels` the
    running image's Config.Labels (asked by the image id), or an Unresolved."""
    who = f"[2] ({container})"
    claim = f"{who} runs an image built from the recorded commit"
    remedy = ("build [2]'s image with the router's docker/build.sh from a clean checkout at the "
              "recorded commit (it labels the image with that commit), and record the commit as "
              "secrets.image_commit")
    want = _fact("commit", image_commit if image_commit is not None else
                 rh.Unresolved("the host-setup document records no secrets.image_commit"),
                 "the host-setup document's secrets.image_commit")
    image = _running_image(live, who)
    if isinstance(image, rh.Unresolved):
        return Claim(ID_HUB, rh.check(claim, want, image, remedy))
    if isinstance(image_labels, rh.Unresolved):
        return Claim(ID_HUB, rh.check(claim, want, image_labels, remedy))
    label = (image_labels or {}).get(LABEL) if isinstance(image_labels, dict) else None
    if not isinstance(label, str) or not _HEX40.fullmatch(label):
        if label is None:
            why = f"[2]'s image carries no {LABEL} label (an image not built by the router's build.sh)"
        elif label == "":
            why = f"[2]'s image's {LABEL} label is empty (built from an unknown tree: dirty, or not its own checkout)"
        else:
            why = f"[2]'s image's {LABEL} label is not a full commit"
        return Claim(ID_HUB, rh.check(claim, want, rh.Unresolved(why), remedy))
    observed = {"observed_commit": label}
    config = live.get("Config") if isinstance(live, dict) else None
    labels = config.get("Labels") if isinstance(config, dict) else None
    own = labels.get(LABEL) if isinstance(labels, dict) else None
    if own is not None and own != label:
        override = rh.check(claim, _fact("container label", label, "the image's own label"), own,
                            f"start [2] without --label {LABEL}: a run-time label is not what was built",
                            do_not="do not set the label at run time to match the record")
        return Claim(ID_HUB, override, observed)
    return Claim(ID_HUB, rh.check(claim, want, label, remedy), observed)


# --- the connector -----------------------------------------------------------


def stamp_text(commit: Optional[str], dirty: bool, pinned: str) -> str:
    """The stamp `install` writes: what it copied the connector from."""
    return json.dumps({"schema": STAMP_SCHEMA, "commit": commit, "dirty": dirty, "pinned": pinned},
                      sort_keys=True) + "\n"


def read_stamp(payload_dir: Path) -> Any:
    """`(commit, dirty)` from the payload's stamp, or an Unresolved."""
    path = payload_dir / STAMP_NAME
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return rh.Unresolved(f"the payload has no {STAMP_NAME}: it was installed before install "
                             "recorded the connector's commit")
    except (OSError, ValueError) as e:
        return rh.Unresolved(f"the payload's {STAMP_NAME} cannot be read: {e}")
    if not isinstance(doc, dict) or doc.get("schema") != STAMP_SCHEMA or not isinstance(doc.get("dirty"), bool) \
            or not isinstance(doc.get("commit"), str) or not _HEX40.fullmatch(doc["commit"]):
        return rh.Unresolved(f"the payload's {STAMP_NAME} does not name a full commit")
    return doc["commit"], doc["dirty"]


def connector(stamp: Any, pin: Any) -> Claim:
    claim = "the connector payload was installed from the pinned connector commit, clean"
    remedy = ("put the connector checkout at its siblings.json pin (amap-siblings.py --apply) and "
              "run install --apply")
    want = _fact("commit", pin if isinstance(pin, rh.Unresolved) else (pin, False),
                 "siblings.json's amap-connector-claude pin, from a clean checkout")
    if isinstance(stamp, rh.Unresolved):
        return Claim(ID_CONNECTOR, rh.check(claim, want, stamp, remedy))
    commit, dirty = stamp
    return Claim(ID_CONNECTOR, rh.check(claim, want, (commit, dirty), remedy),
                 {} if dirty else {"observed_commit": commit})


# --- the transport plugin, per router ---------------------------------------


def started_at(live: Any) -> Any:
    """State.StartedAt as integer epoch nanoseconds, or an Unresolved."""
    t = _ns(((live.get("State") or {}).get("StartedAt")) if isinstance(live, dict) else None)
    return rh.Unresolved("the container's start time cannot be read") if t is None else t


def _settled(live: Any, who: str) -> Optional[str]:
    """Why `live` is not one settled incarnation (running, not restarting,
    not paused, as docker reports it, with a 64-hex Id), or None when it is."""
    stopped = _not_running(live, who)
    if stopped is not None:
        return stopped
    if live["State"].get("Restarting") is not False or live["State"].get("Paused") is not False:
        return f"docker inspect of {who} does not say it is running, not restarting and not paused"
    if not isinstance(live.get("Id"), str) or not _HEX64.fullmatch(live["Id"]):
        return f"docker inspect of {who} shows no full container Id"
    return None


def _ns(value: Any, *, fraction: bool = False) -> Optional[int]:
    """An RFC 3339 UTC timestamp as integer epoch nanoseconds (exact, so a
    comparison never rounds), or None; with `fraction`, None for a value
    without one."""
    m = _STARTED.fullmatch(value) if isinstance(value, str) else None
    if not m or (fraction and m.group(7) is None):
        return None
    y, mo, d, h, mi, se, frac = m.groups()
    # A real instant only: datetime refuses month 99, October 32 or hour 24,
    # which calendar.timegm would quietly roll into another day.
    try:
        instant = datetime.datetime(int(y), int(mo), int(d), int(h), int(mi), int(se),
                                    tzinfo=datetime.timezone.utc)
    except ValueError:
        return None
    whole = calendar.timegm(instant.utctimetuple())
    return whole * 10 ** 9 + int((frac or "").ljust(9, "0"))


def _lex(p: str) -> str:
    """A CONTAINER path, normalised lexically: never through this host's
    symlinks, which say nothing about the container's namespace."""
    n = posixpath.normpath(p)
    return "/" + n.lstrip("/") if n.startswith("//") else n


def _lex_within(a: str, b: str) -> bool:
    """Whether container path `a` is `b` or lies under it, lexically."""
    x, y = _lex(a), _lex(b)
    return x == y or x.startswith(y.rstrip("/") + "/")


def _mounts_shape(live: Any, who: str) -> Any:
    """(Mounts, the HostConfig.Tmpfs paths) when docker inspect shows them in
    the engine's shape (every row an object with string Type, Source and
    Destination; HostConfig an object; Tmpfs an object or null), else an
    Unresolved."""
    mounts = live.get("Mounts") if isinstance(live, dict) else None
    host = live.get("HostConfig") if isinstance(live, dict) else None
    tmpfs = host.get("Tmpfs") if isinstance(host, dict) else None
    if not isinstance(mounts, list) or not isinstance(host, dict) or not isinstance(tmpfs, (dict, type(None))) \
            or not all(isinstance(m, dict) and all(isinstance(m.get(k), str) for k in ("Type", "Source", "Destination"))
                       for m in mounts) \
            or not all(isinstance(t, str) for t in (tmpfs or {})):
        return rh.Unresolved(f"docker inspect of {who} does not list its mounts in the engine's shape")
    return mounts, list(tmpfs or {}) + [m["Destination"] for m in mounts if m["Type"] == "tmpfs"]


def own_mounts_refusal(live: Any, host_root: str, container_root: str, line_end: str, who: str) -> Any:
    """None when `live` mounts `host_root` at `container_root` exactly once,
    as a bind, and nothing else of its own on the line from there down to
    `line_end` (a container path at or below container_root) or below it,
    tmpfs included; else an Unresolved. Destinations are compared lexically
    (_lex), the Source under this host's spellings (design v2.2 §3, rules
    (i)-(iv)). A mount above container_root, or beside the line, does not
    matter: the deeper mount is the one the container sees."""
    shape = _mounts_shape(live, who)
    if isinstance(shape, rh.Unresolved):
        return shape
    mounts, tmpfs = shape
    at = [m for m in mounts if _lex(m["Destination"]) == _lex(container_root)]
    if len(at) != 1 or at[0]["Type"] != "bind" or not _spellings(at[0]["Source"]) & _spellings(host_root):
        return rh.Unresolved(f"{who} does not bind {host_root} at {container_root} exactly once, so the "
                             "directory it writes is not shown to be the host's")

    def on_line(dest: str) -> bool:
        return _lex_within(dest, container_root) and (_lex_within(line_end, dest) or _lex_within(dest, line_end))
    if any(m is not at[0] and m["Type"] != "tmpfs" and on_line(m["Destination"]) for m in mounts) \
            or any(on_line(t) for t in tmpfs):
        return rh.Unresolved(f"{who} mounts something else over {line_end}, so the host's status document "
                             "may not be the one it writes")
    return None


def read_status(live: Any, state_dir: str, who: str,
                read: Callable[[str], bytes] = lambda p: _read_nofollow(p)) -> Any:
    """[1]'s status document, read now host-side from the state directory
    the inspected container `live` binds by identity (as the router's
    docker/run.sh mounts it), after own_mounts_refusal with C = H =
    state_dir: the document, or an Unresolved. A Destination that reaches
    the state directory only through a symlink inside the image is not seen
    (residue)."""
    refused = own_mounts_refusal(live, state_dir, state_dir, state_dir, who)
    if refused is not None:
        return refused
    path = posixpath.join(state_dir, STATUS_NAME)
    try:
        doc = json.loads(read(path))
    except FileNotFoundError:
        return rh.Unresolved(f"{who} has written no status document yet")
    except OSError as e:
        return rh.Unresolved(f"{path} cannot be read: {e.strerror}")
    except ValueError:
        return rh.Unresolved(f"{path} is not a JSON document")
    return doc


class Progressed(dict):
    """A status document the reader saw advance: its counter rose under the
    same process start, every document on the way admitted (admission)."""


def no_recorded_exit(live: Any) -> bool:
    """Whether the engine records no exit for `live` since its creation (a
    zero FinishedAt), or does not say."""
    created = _ns(live.get("Created")) if isinstance(live, dict) else None
    state = live.get("State") if isinstance(live, dict) else None
    finished = _ns(state.get("FinishedAt")) if isinstance(state, dict) else None
    return created is None or finished is None or finished < created


def _counter(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _interval(v: Any) -> bool:
    """An interval in (0, INTERVAL_CAP_S], total over any JSON value: an int
    is compared as an int, so one too large for a float never overflows."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return False
    if isinstance(v, float) and not math.isfinite(v):
        return False
    return 0 < v <= INTERVAL_CAP_S


def admission(doc: Any, counter: str, first: Any = None) -> Optional[str]:
    """Why `doc` is not admitted (design v2.2 §1), or None: an object; a
    full-resolution process_started_ts; an interval_s in (0,
    INTERVAL_CAP_S]; `counter` an int, never a bool; and, after the first,
    the same process start and interval as `first`. Nothing missing is
    defaulted."""
    if not isinstance(doc, dict):
        return "is not an object"
    if _ns(doc.get(PROCESS_START), fraction=True) is None:
        return "has no full-resolution process start"
    if not _interval(doc.get("interval_s")):
        return f"has no interval_s in (0, {INTERVAL_CAP_S:g}]"
    if not _counter(doc.get(counter)):
        return f"has no {counter} count"
    if first is not None and (doc[PROCESS_START] != first[PROCESS_START]
                              or doc["interval_s"] != first["interval_s"]):
        return "is another process's, or changed its interval"
    return None


def read_progressing(live: Any, state_dir: str, who: str, budget: "Budget") -> Any:
    """[1]'s witness, host-side: read_status, then again every step until
    `polls` rises, within min(2 × interval_s + PROGRESS_MARGIN_S,
    WINDOW_MAX_S, the phase's time left), the deadline set once after the
    first document is admitted. Every document is admitted; each count is
    compared with the one before it (lower is UNKNOWN at once). A read that
    completes after the deadline is not counted. The rising document is
    returned as Progressed, else an Unresolved."""
    first = read_status(live, state_dir, who)
    if isinstance(first, rh.Unresolved):
        return first
    why = admission(first, "polls")
    if why is not None:
        return rh.Unresolved(f"{who}'s status document {why}, so its writer cannot be seen to advance it")
    deadline = _monotonic() + min(2 * first["interval_s"] + PROGRESS_MARGIN_S, WINDOW_MAX_S, budget.left())
    before = first["polls"]
    while _monotonic() < deadline:
        _sleep(min(PROGRESS_STEP_S, max(deadline - _monotonic(), 0.0)))
        doc = read_status(live, state_dir, who)
        if _monotonic() > deadline:
            break
        if isinstance(doc, rh.Unresolved):
            return doc
        why = admission(doc, "polls", first)
        if why is not None:
            return rh.Unresolved(f"{who}'s later status document {why}, so it is not this process's progress")
        if doc["polls"] < before:
            return rh.Unresolved(f"{who}'s status document went back from {before} polls to {doc['polls']} "
                                 "under the same process start, so it is not one process's progress")
        if doc["polls"] > before:
            return Progressed(doc)
    return rh.Unresolved(f"{who}'s status document did not advance within its window, so it is not shown to "
                         "be written by the running process")


class Budget:
    """The runtime-builds phase's time: PHASE_BUDGET_S from its start, on
    _monotonic. Every engine call takes min(its own timeout, the time left);
    none starts with less than BUDGET_FLOOR_S left."""

    def __init__(self, total: float = PHASE_BUDGET_S) -> None:
        self.end = _monotonic() + total

    def left(self) -> float:
        return max(self.end - _monotonic(), 0.0)

    def timeout(self, own: float) -> float:
        left = self.left()
        if left < BUDGET_FLOOR_S:
            raise rh.CannotRun("the runtime-builds phase ran out of its time budget")
        return min(own, left)

    def runner(self, own: float, **fixed: Any) -> Callable[..., rh.Proc]:
        """rh.run, looked up at each call, with this budget's timeout."""
        def run(argv: Sequence[str], **kwargs: Any) -> rh.Proc:
            kwargs.pop("timeout", None)
            return rh.run(argv, timeout=self.timeout(own), **{**fixed, **kwargs})
        return run


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


def _monotonic() -> float:
    return time.monotonic()


def state_sharers(docker: List[str], state_dir: str, own_id: Any,
                  run: Optional[Callable[..., rh.Proc]] = None) -> Any:
    """Every OTHER container, in any state, with a mount whose source is
    `state_dir`, a directory above it, or anything below it (a single-file
    bind of the status document itself included), so that it could have
    written the status document there: a list of (Id, Source) pairs (empty
    when none), or an Unresolved. The router's lock keeps two routers from running at
    once, not one from running after another, so a stopped container that
    shares the directory may have left the document there. Read after the
    status document: a container created later cannot have written it.

    The engine does not clean every bind Source the same way (-v against
    --mount, and across versions), so both sides are normalised ("/a/",
    "/a//b", "/a/./b", a leading "//") and also compared with their
    symlinks resolved on this host. A Source that is not an absolute path
    (a tmpfs mount's empty one) names nothing on the host and is skipped.

    Not found, and so residue:
    - an alias this host cannot resolve (a path that exists only inside the
      engine's VM, such as the VM's own view of a shared folder);
    - a named volume whose driver binds the state directory (local, with
      o=bind and device=<state_dir>): its Source is the engine's volume
      path, not the device;
    - a symlink on a parent component re-pointed after [1] started: the
      host's directory tree is trusted to the operator;
    - a router run on the host itself, not in a container;
    - a sharer on an engine that is neither [1]'s bare engine nor [2]'s
      supervision engine (verify lists both where both are deployed);
    - a process exec'd into the router's own container, which writes as its
      user;
    - a sharer REMOVED before verify runs, which leaves no record in the
      engine. Its document can pass only until [1]'s first status write
      replaces it (start-up plus the first poll). The conformance harness
      reads this claim at preflight and again at collect, hours apart,
      requires both to equal its bundle and refuses a preflight digest that
      is not the bundle's, so that window yields the same digest or a void
      run, never a wrong pass."""
    run = run or rh.run
    try:
        p = run(docker + ["ps", "-a", "-q", "--no-trunc"])
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    if p.rc != 0:
        return rh.Unresolved(f"docker ps -a exited {p.rc}, so the containers sharing {state_dir} cannot be listed")
    ids = [i for i in p.out.split() if i != own_id]
    if not ids:
        return []
    try:
        q = run(docker + ["inspect", "--type", "container"] + ids)
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    try:
        docs = json.loads(q.out) if q.rc == 0 else None
    except ValueError:
        docs = None
    if not isinstance(docs, list):
        return rh.Unresolved(f"the other containers cannot all be inspected, so the ones sharing {state_dir} "
                             "cannot be ruled out")
    if sorted(str(d.get("Id")) if isinstance(d, dict) else "" for d in docs) != sorted(ids):
        return rh.Unresolved(f"docker inspect did not answer for every other container, so the ones sharing "
                             f"{state_dir} cannot be ruled out")
    sharers = []
    for doc in docs:
        if not isinstance(doc, dict):
            return rh.Unresolved(f"docker inspect answered with something other than a container, so the ones "
                                 f"sharing {state_dir} cannot be ruled out")
        mounts = doc.get("Mounts")
        if not isinstance(mounts, list):
            return rh.Unresolved(f"docker inspect shows no mounts for a container, so it cannot be ruled out "
                                 f"as sharing {state_dir}")
        if not all(isinstance(m, dict) and isinstance(m.get("Source"), str)
                   and isinstance(m.get("Destination"), str) for m in mounts):
            return rh.Unresolved(f"docker inspect shows a mount without its source and destination, so a "
                                 f"container cannot be ruled out as sharing {state_dir}")
        for m in mounts:
            src = m["Source"]
            if src.startswith("/") and _overlaps(src, state_dir):
                sharers.append((doc.get("Id"), src))
                break
    return sharers


def sharers_reason(who: str, what: str, path: str, sharers: List[Any]) -> str:
    """The UNKNOWN reason for `sharers` of `who`'s `what` at `path`, each by
    its short Id and the Source it binds, an ancestor named as one (a home
    or /Users bind is a standing sharer, to fix rather than puzzle over)."""
    parts = []
    for cid, src in sharers:
        above = _within(path, src) and not _within(src, path)
        parts.append(f"{str(cid)[:12]} binds {src}" + (f", a directory above {path}" if above else ""))
    return f"another container shares {who}'s {what} {path} ({'; '.join(parts)}), so the status document may be its"


def _spellings(p: str) -> Set[str]:
    """`p` normalised, and with its symlinks resolved on this host. normpath
    keeps a leading "//"; realpath folds it, so the second spelling covers
    it whether or not the path exists here."""
    n = posixpath.normpath(p)
    return {n, os.path.realpath(n)}


def _within(a: str, b: str) -> bool:
    """Whether `a` is `b` or lies under it, under any spelling _spellings
    gives either."""
    return any(x == y or x.startswith(y.rstrip("/") + "/") for x in _spellings(a) for y in _spellings(b))


def _overlaps(a: str, b: str) -> bool:
    """Whether one path is the other or lies under it, either way round."""
    return _within(a, b) or _within(b, a)


def _read_nofollow(path: str) -> bytes:
    """A regular file's bytes, at most MAX_STATUS_BYTES: never through a
    symlink, and never blocking on a FIFO or a device (O_NONBLOCK, then
    fstat before any read)."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        data = b""
        while len(data) <= MAX_STATUS_BYTES:
            chunk = os.read(fd, MAX_STATUS_BYTES + 1 - len(data))
            if not chunk:
                break
            data += chunk
    finally:
        os.close(fd)
    if len(data) > MAX_STATUS_BYTES:
        raise OSError(errno.EFBIG, f"larger than {MAX_STATUS_BYTES} bytes")
    return data


# --- [2]'s reader -------------------------------------------------------------

#: [2]'s status document (RE #28, merged as bc394178), its progress counter,
#: and the bounds on what the one exec may print: at most HUB_OBS_MAX
#: observations between the first and the taken document, and
#: HUB_CAPTURE_MAX bytes in all, computed on the encoded form (ensure_ascii
#: writes at most 6 bytes per input byte).
HUB_STATUS_NAME, HUB_COUNTER = "hub-status.json", "progress"
HUB_OBS_MAX = int(WINDOW_MAX_S / PROGRESS_STEP_S)
HUB_OBS_BYTES = 256
HUB_CAPTURE_MAX = 2 * (6 * MAX_STATUS_BYTES) + HUB_OBS_MAX * HUB_OBS_BYTES + 4096

#: The program `docker exec` runs in [2] under `python3 -I -S -c`, as the run
#: spec's user. argv: the document's container path, then PROGRESS_STEP_S,
#: PROGRESS_MARGIN_S, WINDOW_MAX_S, INTERVAL_CAP_S, MAX_STATUS_BYTES,
#: HUB_OBS_MAX and HUB_CAPTURE_MAX, every one a literal from this module.
#: Each read is O_NOFOLLOW|O_NONBLOCK, fstat S_ISREG, bounded, to EOF. It
#: admits EVERY document as `admission` does (the first before it sets its
#: deadline) and stops at the first that fails (exit 10). Its deadline is
#: its own monotonic clock once the first document is read and admitted,
#: plus min(2 × interval_s + margin, the window cap); a read that completes after it is discarded, and
#: no sleep runs past it, so it ends itself within the cap and one step,
#: also when the exec client is killed. It writes nothing and takes no lock.
#: It prints {"first", "between", "taken"} and exits 0, or exits with
#: HUB_EXIT's code and nothing on stdout.
HUB_READER = r"""
import datetime, errno, json, math, os, re, stat, sys, time
path = sys.argv[1]
step, margin, window, cap = (float(a) for a in sys.argv[2:6])
limit, obs_max, capture = (int(a) for a in sys.argv[6:9])
ts = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})[.][0-9]{1,9}Z")
def instant(v):
    m = ts.fullmatch(v) if isinstance(v, str) else None
    if not m:
        return False
    try:
        datetime.datetime(*(int(g) for g in m.groups()))
    except ValueError:
        return False
    return True
def interval(v):
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return False
    if isinstance(v, float) and not math.isfinite(v):
        return False
    return 0 < v <= cap
def read():
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as e:
        sys.exit({errno.ENOENT: 3, errno.ENOTDIR: 3, errno.ELOOP: 4, errno.EACCES: 8}.get(e.errno, 6))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            sys.exit(4)
        data = b""
        while len(data) <= limit:
            chunk = os.read(fd, limit + 1 - len(data))
            if not chunk:
                break
            data += chunk
    except OSError:
        sys.exit(6)
    finally:
        os.close(fd)
    if len(data) > limit:
        sys.exit(5)
    try:
        return json.loads(data)
    except ValueError:
        sys.exit(7)
def count(v):
    return isinstance(v, int) and not isinstance(v, bool)
def admit(doc, first):
    if not isinstance(doc, dict) or not instant(doc.get("process_started_ts")) \
            or not interval(doc.get("interval_s")):
        sys.exit(10)
    if not count(doc.get("progress")):
        sys.exit(10)
    if first is not None and (doc["process_started_ts"] != first["process_started_ts"]
                              or doc["interval_s"] != first["interval_s"]):
        sys.exit(10)
first = read()
admit(first, None)
deadline = time.monotonic() + min(2 * first["interval_s"] + margin, window)
between, taken, before = [], None, first["progress"]
while time.monotonic() < deadline:
    time.sleep(max(min(step, deadline - time.monotonic()), 0))
    doc = read()
    if time.monotonic() > deadline:
        break
    admit(doc, first)
    # A rise or a drop ends the wait and is taken; the host refuses a drop.
    if doc["progress"] != before:
        taken = doc
        break
    if len(between) < obs_max:
        between.append([doc["process_started_ts"], doc["interval_s"], doc["progress"]])
out = json.dumps({"first": first, "between": between, "taken": taken}, ensure_ascii=True)
if len(out) > capture:
    sys.exit(9)
sys.stdout.write(out)
"""

#: HUB_READER's exits other than 0, by what each means ({who} and {path}
#: filled in). Any other rc reads "the status reader in {who} failed (rc N)".
HUB_EXIT = {
    3: "{who} has no status document at {path}: not yet written, or its ledger directory is missing",
    4: "{who}'s status document is not a regular file",
    5: "{who}'s status document is larger than " + str(MAX_STATUS_BYTES) + " bytes",
    6: "{who}'s status document cannot be read",
    7: "{who}'s status document is not JSON",
    8: "{who}'s reader was refused access (EACCES) to {path} or a directory above it as {user}; "
       "supplementary groups may not apply to docker exec",
    9: "{who}'s reader output would exceed " + str(HUB_CAPTURE_MAX) + " bytes",
    10: "{who}'s status document is not admissible: a missing, mistyped, out-of-range or changed member",
}


def hub_reader_argv(docker: List[str], cid: str, user: str, path: str) -> List[str]:
    """[2]'s one exec: the hub client (with its engine), the run spec's
    user, the inspected Id, and HUB_READER with its literal arguments."""
    return docker + ["exec", "-u", user, cid, "python3", "-I", "-S", "-c", HUB_READER, path,
                     repr(PROGRESS_STEP_S), repr(PROGRESS_MARGIN_S), repr(WINDOW_MAX_S), repr(INTERVAL_CAP_S),
                     str(MAX_STATUS_BYTES), str(HUB_OBS_MAX), str(HUB_CAPTURE_MAX)]


def _no_duplicate_keys(pairs: List[Any]) -> Dict[str, Any]:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("a repeated key")
    return dict(pairs)


def read_hub_status(docker: List[str], live: Dict[str, Any], path: str, user: str, who: str,
                    run: Callable[..., rh.Proc]) -> Any:
    """[2]'s status document by HUB_READER, through one `docker exec` into
    the inspected container (its Id): Progressed (the taken document) when
    `progress` rose, every document admitted, else an Unresolved. `run` is
    the budgeted runner; the capture is bounded at HUB_CAPTURE_MAX. Any rc
    other than 0 is UNKNOWN by HUB_EXIT, and its stdout is never parsed.

    A [2] in --loop writes interval_s from its first write (RE #28), so a
    document without it is a --once run, a build before #28, or a
    predecessor's document before the current process's first write; each
    is UNKNOWN (exit 10), never defaulted."""
    try:
        p = run(hub_reader_argv(docker, live["Id"], user, path), max_output=HUB_CAPTURE_MAX)
    except rh.CannotRun as e:
        return rh.Unresolved(f"the status reader in {who} did not finish: {e}")
    if p.rc != 0:
        return rh.Unresolved(HUB_EXIT[p.rc].format(who=who, path=path, user=user) if p.rc in HUB_EXIT
                             else f"the status reader in {who} failed (rc {p.rc})")
    try:
        out = json.loads(p.out, object_pairs_hook=_no_duplicate_keys)
    except ValueError:
        return rh.Unresolved(f"the status reader in {who} printed no single JSON object")
    return judge_hub_output(out, who)


def judge_hub_output(out: Any, who: str) -> Any:
    """The host's own judgement of HUB_READER's envelope: exactly first,
    between and taken; every document and observation admitted; each count
    compared with the one before it; the taken one the first rise."""
    if not isinstance(out, dict) or set(out) != {"first", "between", "taken"}:
        return rh.Unresolved(f"the status reader in {who} printed something other than its envelope")
    first, between, taken = out["first"], out["between"], out["taken"]
    why = admission(first, HUB_COUNTER)
    if why is not None:
        return rh.Unresolved(f"{who}'s status document {why}, so its writer cannot be seen to advance it")
    if not isinstance(between, list) or len(between) > HUB_OBS_MAX:
        return rh.Unresolved(f"the status reader in {who} printed a malformed observation list")
    before = first[HUB_COUNTER]
    for entry in between:
        if not isinstance(entry, list) or len(entry) != 3 \
                or len(json.dumps(entry, ensure_ascii=True)) > HUB_OBS_BYTES:
            return rh.Unresolved(f"the status reader in {who} printed a malformed observation")
        seen = {PROCESS_START: entry[0], "interval_s": entry[1], HUB_COUNTER: entry[2]}
        why = admission(seen, HUB_COUNTER, first)
        if why is not None:
            return rh.Unresolved(f"{who}'s later status document {why}, so it is not this process's progress")
        if seen[HUB_COUNTER] != before:
            return rh.Unresolved(f"{who}'s status document moved from {before} to {seen[HUB_COUNTER]} "
                                 "before the reader took it, so it is not one process's progress")
    if taken is None:
        return rh.Unresolved(f"{who}'s status document did not advance within its window, so it is not "
                             "shown to be written by the running process")
    why = admission(taken, HUB_COUNTER, first)
    if why is not None:
        return rh.Unresolved(f"{who}'s later status document {why}, so it is not this process's progress")
    if taken[HUB_COUNTER] < before:
        return rh.Unresolved(f"{who}'s status document went back from {before} to {taken[HUB_COUNTER]} "
                             f"{HUB_COUNTER} under the same process start, so it is not one process's progress")
    if taken[HUB_COUNTER] == before:
        return rh.Unresolved(f"{who}'s status document did not advance, so it is not shown to be written by "
                             "the running process")
    return Progressed(taken)


def ledger_env_refusal(live: Any, ledger: str, who: str) -> Any:
    """None when [2]'s Config.Env (checked raw, before anything str()s it)
    is a list of strings with exactly one RELAY_LEDGER_DIR= entry whose
    value is `ledger` exactly; else an Unresolved."""
    config = live.get("Config") if isinstance(live, dict) else None
    env = config.get("Env") if isinstance(config, dict) else None
    if not isinstance(env, list) or not all(isinstance(e, str) for e in env):
        return rh.Unresolved(f"docker inspect of {who} does not list its environment as strings")
    found = [e[len("RELAY_LEDGER_DIR="):] for e in env if e.startswith("RELAY_LEDGER_DIR=")]
    if found != [ledger]:
        return rh.Unresolved(f"{who}'s RELAY_LEDGER_DIR is not exactly {ledger}, so the document it writes is "
                             "not the one the reader reads")
    return None


def hop_plugin(role: str, container: str, before: Any, published: Any, after: Any, pin_sha256: str) -> Claim:
    """The plugin the RUNNING router loaded, from its own status document:
    `published[PLUGIN_MEMBER]` is the sha256 the router's loader computed
    from the bytes it read once and executed, written at activation.
    `published` is read between `before` and `after`, two inspects that
    show the same container (Id and StartedAt), running and not restarting.
    The status document outlives the container, so it is bound to this
    incarnation by `PROCESS_START`, the process's own start at full
    resolution, taken before the load, against a bound the engine records
    BEFORE the current process can exist (same kernel clock, which must not
    step back between runs, as an operator or NTP fault could make it): the
    container's `Created` (create returns before start is called), and the
    previous run's `State.FinishedAt` (a restart follows the exit). A
    process of an earlier container started before that container was
    removed, so before `Created`; an earlier run of this container started
    before it exited, so before `FinishedAt`. StartedAt is NOT the bound:
    the engine records it after the task starts, so the current process can
    precede it. Both hold only for one container's processes: the reader
    refuses a document from a directory another container, in any state,
    also mounts (state_sharers). A whole-second or missing start cannot
    separate the two and is UNKNOWN. Nothing read host-side about the plugin file is evidence of
    what was loaded."""
    who = f"[{1 if role == ROLE_HOP else 2}] ({container})"
    claim = f"the transport plugin {who} loaded is the pinned overlay"
    remedy = ("place the overlay at its pin with host_steps.py place, then restart the router so it "
              "loads it")
    want = _fact("sha256", pin_sha256, "the overlay pin's sha256")

    def unknown(why: str) -> Claim:
        return Claim(ID_PLUGIN, rh.check(claim, want, rh.Unresolved(why), remedy), host_role=role)

    for live in (before, after):
        if isinstance(live, rh.Unresolved):
            return unknown(live.reason)
        if live is None:
            return unknown(f"{who} is not running, so no plugin is loaded")
        unsettled = _settled(live, who)
        if unsettled is not None:
            return unknown(unsettled)
    start = started_at(before)
    if isinstance(start, rh.Unresolved):
        return unknown(start.reason)
    if started_at(after) != start or not isinstance(before.get("Id"), str) or after.get("Id") != before["Id"]:
        return unknown(f"{who} restarted while verify read it")
    if isinstance(published, rh.Unresolved):
        return unknown(published.reason)
    member = published.get(PLUGIN_MEMBER) if isinstance(published, dict) else None
    if member is None:
        return unknown("the router does not publish the plugin it loaded")
    sha = member.get(PLUGIN_SHA256) if isinstance(member, dict) else None
    if not isinstance(sha, str) or not _HEX64.fullmatch(sha):
        return unknown("the router's published plugin digest is malformed")
    began = _ns(published.get(PROCESS_START), fraction=True)
    if began is None:
        return unknown("the router's status document has no full-resolution process start, so it cannot "
                       "be tied to the running container")
    created = _ns(before.get("Created"))
    finished = _ns(before["State"].get("FinishedAt"))
    if created is None or finished is None:
        return unknown(f"docker inspect of {who} does not say when it was created and last exited, so "
                       "an earlier run's document cannot be excluded")
    # No exit recorded since creation: the bound is Created alone, which
    # holds only for a first run. Docker Engine 29.8.1 keeps FinishedAt
    # across a stop and start, but an engine that cleared it would make a
    # container that has run before look the same. So a document is taken
    # only when the reader saw it advance (read_progressing): its writer is
    # running now, and the sharing and own-mount checks leave [1]'s current
    # process as the only running writer of that file.
    if finished < created and not isinstance(published, Progressed):
        return unknown(f"the engine shows no previous exit for {who}, and its status document was not seen "
                       "to advance, so an earlier run's document cannot be excluded")
    if began < max(created, finished):
        return unknown(f"the status document is from an earlier run of {who}")
    return Claim(ID_PLUGIN, rh.check(claim, want, sha, remedy), {"observed_sha256": sha}, role)


# --- the phase ---------------------------------------------------------------


@dataclass
class Phase:
    """The phase: its claims, and the roles deployed on this host."""
    claims: List[Claim]
    deployed_roles: List[str]

    def outcome(self) -> rh.Outcome:
        return rh.Outcome(rh.Section(SECTION_ID, TITLE, lambda ctx: iter(())),
                          [c.check for c in self.claims],
                          extras=[c.extras() for c in self.claims],
                          phase_extras={"deployed_roles": sorted(self.deployed_roles)})


def collect(spec: Any, payload_dir: Path, *, hop_pin: Any, connector_pin: Any,
            inspect: Callable[[str, str], Any], labels: Callable[[str], Any],
            status: Callable[[str, str, Any], Any]) -> Phase:
    """Every claim this host's deployment calls for. `spec` is the host-setup
    Spec, None when the host has no host-setup document, or an Unresolved
    when it has one that cannot be read. `inspect(role, name)` gives a
    container's inspect document, None or an Unresolved; `labels(image_id)`
    [2]'s image's own Config.Labels, or an Unresolved; `status(role, name,
    live)` that router's status document read now from the inspected
    container `live`, None when no reader exists for it, or an Unresolved."""
    claims: List[Claim] = []
    roles: List[str] = []
    if isinstance(spec, rh.Unresolved):
        roles += [ROLE_HOP, ROLE_HUB]
        claims += [Claim(ID_HOP, _unreadable(spec, "[1]")), Claim(ID_HUB, _unreadable(spec, "[2]"))]
    elif spec is not None:
        router = getattr(spec, "router", None)
        if router is not None:
            roles.append(ROLE_HOP)
            live = inspect(ROLE_HOP, router.container)
            claims.append(hop_router(router, hop_pin, live))
            if spec.overlay_path and spec.overlay_pin:
                claims.append(_plugin(ROLE_HOP, router.container, live, spec, inspect, status))
        if getattr(spec, "hub", None) is not None and spec.secrets is not None:
            roles.append(ROLE_HUB)
            name = spec.runtime_of(spec.secrets.principal)["container"]
            live = inspect(ROLE_HUB, name)
            image = _running_image(live, f"[2] ({name})")
            got = labels(image) if not isinstance(image, rh.Unresolved) else image
            claims.append(hub_router(name, spec.secrets.image_commit, live, got))
            if spec.overlay_path and spec.overlay_pin:
                claims.append(_plugin(ROLE_HUB, name, live, spec, inspect, status))
    if payload_dir.is_dir():
        roles.append(ROLE_CONNECTOR)
        claims.append(connector(read_stamp(payload_dir), connector_pin))
    return Phase(claims, roles)


def _plugin(role: str, name: str, before: Any, spec: Any, inspect: Callable[[str, str], Any],
            status: Callable[[str, str, Any], Any]) -> Claim:
    """The plugin claim: `status(role, name, before)` reads the status document
    now, from the container `before` inspected, and a second inspect
    follows it, so the read is inside the bracket hop_plugin checks."""
    published = status(role, name, before) if isinstance(before, dict) else None
    return hop_plugin(role, name, before, published, inspect(role, name), spec.overlay_pin["sha256"])


def _unreadable(spec: rh.Unresolved, who: str) -> rh.Check:
    return rh.check(f"{who} runs an image built from its recorded commit",
                    _fact("commit", spec, "the host-setup document"), spec,
                    "fix the host-setup document so verify can read it")
