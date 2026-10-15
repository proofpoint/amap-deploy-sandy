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
- `build.hop_plugin`: once per router that mounts the transport plugin, the
  plugin file's sha256 is the overlay pin's. Both routers bind-mount the
  plugin's directory read-only BY IDENTITY (host path = container path), so
  the bytes are read host-side from the mount source, with no `docker exec`
  into a production container, and only when that mount is present,
  read-only and by identity, and the directory has not changed since the
  container started (a directory renamed into place afterwards would be the
  right file from the wrong subject).

ABSENT IS UNKNOWN. A missing label, stamp, record, container or mount never
passes, and an `observed_*` value is reported only when it was read.

A claim appears exactly when its role is deployed here, and the phase names
the deployed roles (`deployed_roles`), so a reader can tell "not deployed"
from "left out". When the host-setup document exists but cannot be read,
both router roles are listed and their claims are UNKNOWN: an unreadable
document must refuse, not read as "nothing deployed".
"""

import calendar
import hashlib
import json
import os
import posixpath
import re
import stat
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


def _running_image(live: Any, who: str) -> Any:
    """The container's image id, or an Unresolved saying why not."""
    if isinstance(live, rh.Unresolved):
        return live
    if live is None:
        return rh.Unresolved(f"{who} is not running, so the image it runs cannot be read")
    image = live.get("Image") if isinstance(live, dict) else None
    if not isinstance(image, str) or not _DIGEST.fullmatch(image):
        return rh.Unresolved(f"docker inspect of {who} shows no image id")
    return image


def inspect_container(docker: List[str], name: str, run: Callable[..., rh.Proc] = rh.run) -> Any:
    """The container's inspect document; None when `docker ps -a` lists no
    container by that name (absence is decided by a listing that succeeds
    and is empty, never by a daemon's error prose); else an Unresolved."""
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


def image_labels(docker: List[str], image_id: str, run: Callable[..., rh.Proc] = rh.run) -> Any:
    """The image's own Config.Labels (a dict, {} when it has none), asked by
    its id, or an Unresolved."""
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
    Unresolved); `live` [1]'s inspect document, None, or an Unresolved."""
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
        why = (f"[2]'s image carries no {LABEL} label (an image not built by build.sh, or built "
               "from a dirty tree)" if label is None else f"[2]'s image's {LABEL} label is not a full commit")
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
    """State.StartedAt as epoch seconds (the fraction kept), or an Unresolved."""
    s = ((live.get("State") or {}).get("StartedAt")) if isinstance(live, dict) else None
    m = _STARTED.fullmatch(s) if isinstance(s, str) else None
    if not m:
        return rh.Unresolved("the container's start time cannot be read")
    y, mo, d, h, mi, se, frac = m.groups()
    return calendar.timegm((int(y), int(mo), int(d), int(h), int(mi), int(se))) + float(f"0.{frac or 0}")


def hop_plugin(role: str, container: str, live: Any, overlay_path: str, pin_sha256: str,
               lstat: Callable[[str], os.stat_result] = os.lstat,
               read: Callable[[str], bytes] = lambda p: Path(p).read_bytes()) -> Claim:
    who = f"[{1 if role == ROLE_HOP else 2}] ({container})"
    claim = f"the transport plugin {who} loads is the pinned overlay"
    remedy = ("place the overlay at its pin with host_steps.py place, then restart the router so it "
              "mounts that directory")
    want = _fact("sha256", pin_sha256, "the overlay pin's sha256")
    d = posixpath.dirname(overlay_path)

    def unknown(why: str) -> Claim:
        return Claim(ID_PLUGIN, rh.check(claim, want, rh.Unresolved(why), remedy), host_role=role)

    if isinstance(live, rh.Unresolved):
        return unknown(live.reason)
    if live is None:
        return unknown(f"{who} is not running, so what it mounts cannot be read")
    hits = [m for m in live.get("Mounts") or [] if isinstance(m, dict) and m.get("Destination") == d]
    if len(hits) != 1 or hits[0].get("Source") != d or hits[0].get("RW") is not False:
        return unknown(f"{who} does not mount {d} once, read-only and by identity, so the host's file "
                       "is not the one it loads")
    start = started_at(live)
    if isinstance(start, rh.Unresolved):
        return unknown(start.reason)
    try:
        st = lstat(d)
    except OSError as e:
        return unknown(f"{d} cannot be examined: {e.strerror}")
    if not stat.S_ISDIR(st.st_mode) or st.st_ctime > start:
        return unknown("the overlay directory changed after the container started")
    try:
        sha = hashlib.sha256(read(overlay_path)).hexdigest()
    except OSError as e:
        return unknown(f"{overlay_path} cannot be read: {e.strerror}")
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
            lstat: Callable[[str], os.stat_result] = os.lstat,
            read: Callable[[str], bytes] = lambda p: Path(p).read_bytes()) -> Phase:
    """Every claim this host's deployment calls for. `spec` is the host-setup
    Spec, None when the host has no host-setup document, or an Unresolved
    when it has one that cannot be read. `inspect(role, name)` gives a
    container's inspect document, None or an Unresolved; `labels(image_id)`
    [2]'s image's own Config.Labels, or an Unresolved."""
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
                claims.append(hop_plugin(ROLE_HOP, router.container, live, spec.overlay_path,
                                         spec.overlay_pin["sha256"], lstat, read))
        if getattr(spec, "hub", None) is not None and spec.secrets is not None:
            roles.append(ROLE_HUB)
            name = spec.runtime_of(spec.secrets.principal)["container"]
            live = inspect(ROLE_HUB, name)
            image = _running_image(live, f"[2] ({name})")
            got = labels(image) if not isinstance(image, rh.Unresolved) else image
            claims.append(hub_router(name, spec.secrets.image_commit, live, got))
            if spec.overlay_path and spec.overlay_pin:
                claims.append(hop_plugin(ROLE_HUB, name, live, spec.overlay_path,
                                         spec.overlay_pin["sha256"], lstat, read))
    if payload_dir.is_dir():
        roles.append(ROLE_CONNECTOR)
        claims.append(connector(read_stamp(payload_dir), connector_pin))
    return Phase(claims, roles)


def _unreadable(spec: rh.Unresolved, who: str) -> rh.Check:
    return rh.check(f"{who} runs an image built from its recorded commit",
                    _fact("commit", spec, "the host-setup document"), spec,
                    "fix the host-setup document so verify can read it")
