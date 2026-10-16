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
  A router that publishes no digest is UNKNOWN.

ABSENT IS UNKNOWN. A missing label, stamp, record, container or mount never
passes, and an `observed_*` value is reported only when it was read.

A claim appears exactly when its role is deployed here, and the phase names
the deployed roles (`deployed_roles`), so a reader can tell "not deployed"
from "left out". When the host-setup document exists but cannot be read,
both router roles are listed and their claims are UNKNOWN: an unreadable
document must refuse, not read as "nothing deployed".
"""

import calendar
import os
import posixpath
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

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
    own = ((live.get("Config") or {}).get("Labels") or {}).get(LABEL)
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
    """Why `live` is not one settled incarnation (running and not
    restarting, as docker reports it), or None when it is."""
    stopped = _not_running(live, who)
    if stopped is not None:
        return stopped
    if live["State"].get("Restarting") is not False:
        return f"docker inspect of {who} does not say it is running and not restarting"
    return None


def _ns(value: Any, *, fraction: bool = False) -> Optional[int]:
    """An RFC 3339 UTC timestamp as integer epoch nanoseconds (exact, so a
    comparison never rounds), or None; with `fraction`, None for a value
    without one."""
    m = _STARTED.fullmatch(value) if isinstance(value, str) else None
    if not m or (fraction and m.group(7) is None):
        return None
    y, mo, d, h, mi, se, frac = m.groups()
    whole = calendar.timegm((int(y), int(mo), int(d), int(h), int(mi), int(se)))
    return whole * 10 ** 9 + int((frac or "").ljust(9, "0"))


def read_status(live: Any, state_dir: str, who: str,
                read: Callable[[str], bytes] = lambda p: _read_nofollow(p)) -> Any:
    """The router's status document, read now from the state directory the
    inspected container `live` itself mounts (by identity, as the router's
    docker/run.sh mounts it): the document, or an Unresolved."""
    mounts = [m for m in (live.get("Mounts") or []) if isinstance(m, dict)] if isinstance(live, dict) else []
    hits = [m for m in mounts if m.get("Destination") == state_dir]
    if len(hits) != 1 or hits[0].get("Source") != state_dir:
        return rh.Unresolved(f"{who} does not mount its state directory {state_dir} once and by identity, "
                             "so its status document cannot be read")
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


def state_sharers(docker: List[str], state_dir: str, own_id: Any,
                  run: Optional[Callable[..., rh.Proc]] = None) -> Any:
    """The Ids of every OTHER container, in any state, with a mount whose
    source is `state_dir`, a directory above it, or anything below it (a
    single-file bind of the status document itself included), so that it
    could have written the status document there: a list (empty when none),
    or an Unresolved. Paths are compared as the engine reports them,
    literally: the same directory spelled another way (a symlinked parent,
    or /private/var for /var on macOS) is not matched, as read_status's
    mount check is literal too. The router's lock keeps two routers from running at once,
    not one from running after another, so a stopped container that shares
    the directory may have left the document there. Read after the status
    document: a container created later cannot have written it."""
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
    if not isinstance(docs, list) or len(docs) != len(ids):
        return rh.Unresolved(f"the other containers cannot all be inspected, so the ones sharing {state_dir} "
                             "cannot be ruled out")
    sharers = []
    for doc in docs:
        mounts = (doc.get("Mounts") or []) if isinstance(doc, dict) else None
        if not isinstance(mounts, list):
            return rh.Unresolved(f"docker inspect shows no mounts for a container, so it cannot be ruled out "
                                 f"as sharing {state_dir}")
        for m in mounts:
            src = m.get("Source") if isinstance(m, dict) else None
            if isinstance(src, str) and _overlaps(src, state_dir):
                sharers.append(doc.get("Id"))
                break
    return sharers


def _overlaps(a: str, b: str) -> bool:
    """Whether one path is the other or lies under it (literal paths)."""
    a, b = a.rstrip("/") or "/", b.rstrip("/") or "/"
    return a == b or b.startswith(a.rstrip("/") + "/") or a.startswith(b.rstrip("/") + "/")


def _read_nofollow(path: str) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as f:
        return f.read()


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
