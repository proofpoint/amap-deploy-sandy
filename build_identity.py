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
import errno
import json
import os
import posixpath
import re
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

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
#: When the engine records no exit for a container, its status document is
#: taken only after the reader has seen it advance: `polls` rising under the
#: same process start, within PROGRESS_INTERVALS of the document's own poll
#: intervals plus PROGRESS_MARGIN_S (a poll's own duration and the reader's
#: step), re-read every PROGRESS_STEP_S. A document whose window would be
#: longer than MAX_PROGRESS_WAIT_S is not waited for.
PROGRESS_INTERVALS = 2
PROGRESS_MARGIN_S = 2.0
PROGRESS_STEP_S = 0.5
MAX_PROGRESS_WAIT_S = 120.0

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
    docker/run.sh mounts it): the document, or an Unresolved. A second mount
    of the container's own at or below the state directory is refused; one
    whose Destination reaches the state directory only through a symlink
    inside the container's image is not seen (residue). Every mount row must
    carry a string Source and Destination, and a tmpfs from `--tmpfs`, which
    the engine lists in HostConfig.Tmpfs and not in Mounts, counts as a
    mount at its path."""
    mounts = live.get("Mounts") if isinstance(live, dict) else None
    host = live.get("HostConfig") if isinstance(live, dict) else None
    tmpfs = host.get("Tmpfs") if isinstance(host, dict) else None
    if not isinstance(mounts, list) or not isinstance(host, dict) or not isinstance(tmpfs, (dict, type(None))) \
            or not all(isinstance(m, dict) and isinstance(m.get("Source"), str)
                       and isinstance(m.get("Destination"), str) for m in mounts) \
            or not all(isinstance(t, str) for t in (tmpfs or {})):
        return rh.Unresolved(f"docker inspect of {who} does not list its mounts in the engine's shape, so "
                             "its state directory cannot be shown to be the host's")
    hits = [m for m in mounts if m["Destination"] == state_dir]
    if len(hits) != 1 or hits[0].get("Source") != state_dir:
        return rh.Unresolved(f"{who} does not mount its state directory {state_dir} once and by identity, "
                             "so its status document cannot be read")
    # A second mount at or below the state directory (a bind over the status
    # document itself, or a subdirectory) would send the router's writes
    # elsewhere, while the host's file under the identity mount never changes.
    if any(m is not hits[0] and _within(m["Destination"], state_dir) for m in mounts) \
            or any(_within(t, state_dir) for t in (tmpfs or {})):
        return rh.Unresolved(f"{who} mounts something else at or below its state directory {state_dir}, so "
                             "the host's status document may not be the one it writes")
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


#: The program `docker exec` runs in [2], as its own user, under `python3 -I
#: -S -c`: argv is the document's container path, the most it may wait, the
#: margin beyond 2 × the document's own interval_s, the step and the byte
#: bound. It reads the document like _read_nofollow (no symlink, no FIFO, a
#: regular file, bounded, read to the end), and, while `pumps` has not risen
#: under the same process_started_ts and the window has not passed, reads it
#: again. It writes nothing and takes no lock. It prints
#: {"first": ..., "later": ...} ("later" null when nothing rose) and exits 0,
#: or exits HUB_EXIT[...] with nothing on stdout. The host judges every
#: value it prints again (read_hub_status); it trusts only that the reads
#: were the container's own.
HUB_READER = r"""
import errno, json, os, stat, sys, time
path, most, margin, step, limit = sys.argv[1], float(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4]), int(sys.argv[5])
def read():
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        sys.exit(3)
    except OSError as e:
        sys.exit(4 if e.errno == errno.ELOOP else 6)
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
def counted(d):
    p = d.get("pumps") if isinstance(d, dict) else None
    return p if isinstance(p, int) and not isinstance(p, bool) else None
first = read()
interval = first.get("interval_s") if isinstance(first, dict) else None
later = None
if counted(first) is not None and isinstance(interval, (int, float)) and not isinstance(interval, bool) \
        and 0 < interval and interval * 2 + margin <= most:
    deadline = time.monotonic() + interval * 2 + margin
    while time.monotonic() < deadline:
        time.sleep(step)
        doc = read()
        if not isinstance(doc, dict) or doc.get("process_started_ts") != first.get("process_started_ts"):
            continue
        n = counted(doc)
        if n is not None and n != counted(first):
            later = doc
            break
sys.stdout.write(json.dumps({"first": first, "later": later}))
"""

#: [2]'s status document and its progress counter (RE-HUB-PROGRESS), and how
#: long past the reader's own longest wait `docker exec` may take.
HUB_STATUS_NAME, HUB_COUNTER = "hub-status.json", "pumps"
HUB_EXEC_SLACK_S = 15.0

#: HUB_READER's exit codes, by what each means.
HUB_EXIT = {3: "{who} has written no status document yet", 4: "{who}'s status document is not a regular file",
            5: "{who}'s status document is larger than " + str(MAX_STATUS_BYTES) + " bytes",
            6: "{who}'s status document cannot be read", 7: "{who}'s status document is not a JSON document"}


def hub_mounts_refusal(live: Any, host_root: str, container_root: str, ledger: str, who: str) -> Any:
    """None when [2]'s inspect shows its principal bind (`host_root` at
    `container_root`) exactly once and nothing else of its own at or below
    the part of that bind that holds `ledger` (a container path): no bind
    over hub-status.json, no subdirectory mount, no tmpfs. Else an
    Unresolved. Paths are compared under _spellings."""
    mounts = live.get("Mounts") if isinstance(live, dict) else None
    host = live.get("HostConfig") if isinstance(live, dict) else None
    tmpfs = host.get("Tmpfs") if isinstance(host, dict) else None
    if not isinstance(mounts, list) or not isinstance(host, dict) or not isinstance(tmpfs, (dict, type(None))) \
            or not all(isinstance(m, dict) and isinstance(m.get("Source"), str)
                       and isinstance(m.get("Destination"), str) for m in mounts) \
            or not all(isinstance(t, str) for t in (tmpfs or {})):
        return rh.Unresolved(f"docker inspect of {who} does not list its mounts in the engine's shape, so "
                             "its ledger directory cannot be shown to be the host's")
    binds = [m for m in mounts if _same(m["Destination"], container_root)]
    if len(binds) != 1 or not _same(binds[0]["Source"], host_root):
        return rh.Unresolved(f"{who} does not mount {host_root} at {container_root} exactly once, so its "
                             "ledger directory is not the host's")
    # Under the bind, any mount whose path meets the ledger directory's line
    # (an ancestor of it below the bind, the directory, or anything inside)
    # puts something other than the host's directory there.
    def meets(dest: str) -> bool:
        return _within(dest, container_root) and _overlaps(dest, ledger)
    if any(m is not binds[0] and meets(m["Destination"]) for m in mounts) or any(meets(t) for t in (tmpfs or {})):
        return rh.Unresolved(f"{who} mounts something else over its ledger directory {ledger}, so the host's "
                             "status document may not be the one it writes")
    return None


def _same(a: str, b: str) -> bool:
    """Whether two paths are one under any spelling _spellings gives."""
    return bool(_spellings(a) & _spellings(b))


def read_hub_status(docker: List[str], live: Any, path: str, user: str, who: str, *, margin: float,
                    run: Optional[Callable[..., rh.Proc]] = None) -> Any:
    """[2]'s status document, read by HUB_READER through `docker exec` into
    the container `live` names (its Id), as `user`, with `path` its
    container path: Progressed (the later document) when `pumps` rose under
    the same process start within 2 × interval_s + `margin`, else an
    Unresolved. Every value the reader prints is judged here again."""
    run = run or rh.run
    argv = docker + ["exec", "-u", user, str(live.get("Id")), "python3", "-I", "-S", "-c", HUB_READER, path,
                     repr(MAX_PROGRESS_WAIT_S), repr(margin), repr(PROGRESS_STEP_S), str(MAX_STATUS_BYTES)]
    try:
        p = run(argv, timeout=int(MAX_PROGRESS_WAIT_S + HUB_EXEC_SLACK_S))
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    if p.rc in HUB_EXIT:
        return rh.Unresolved(HUB_EXIT[p.rc].format(who=who))
    if p.rc != 0:
        return rh.Unresolved(f"the status reader in {who} exited {p.rc}")
    try:
        out = json.loads(p.out)
    except ValueError:
        return rh.Unresolved(f"the status reader in {who} printed no JSON")
    first, later = (out.get("first"), out.get("later")) if isinstance(out, dict) else (None, None)
    return _progress(first, later, HUB_COUNTER, margin, who)


def _counter(doc: Any, name: str) -> Optional[int]:
    v = doc.get(name) if isinstance(doc, dict) else None
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _usable_interval(doc: Any, margin: float) -> bool:
    v = doc.get("interval_s") if isinstance(doc, dict) else None
    return isinstance(v, (int, float)) and not isinstance(v, bool) and 0 < v \
        and v * PROGRESS_INTERVALS + margin <= MAX_PROGRESS_WAIT_S


def _progress(first: Any, later: Any, counter: str, margin: float, who: str) -> Any:
    """The witness, judged: Progressed(later) when `counter` rose under the
    same process start, else an Unresolved naming why."""
    if not isinstance(first, dict) or _counter(first, counter) is None or not _usable_interval(first, margin):
        return rh.Unresolved(f"{who}'s status document has no usable interval_s and {counter}, so its writer "
                             "cannot be seen to advance it")
    if later is None:
        return rh.Unresolved(f"{who}'s status document did not advance within {PROGRESS_INTERVALS} intervals, "
                             "so it is not shown to be written by the running process")
    if not isinstance(later, dict) or later.get(PROCESS_START) != first.get(PROCESS_START) \
            or _counter(later, counter) is None:
        return rh.Unresolved(f"{who}'s later status document is not the same process's, so it is not progress")
    if _counter(later, counter) < _counter(first, counter):
        return rh.Unresolved(f"{who}'s status document went back from {_counter(first, counter)} {counter} to "
                             f"{_counter(later, counter)} under the same process start, so it is not one "
                             "process's progress")
    if _counter(later, counter) == _counter(first, counter):
        return rh.Unresolved(f"{who}'s status document did not advance, so it is not shown to be written by "
                             "the running process")
    return Progressed(later)


class Progressed(dict):
    """A status document the reader saw advance: `polls` rose under the same
    process start between two of its reads."""


def no_recorded_exit(live: Any) -> bool:
    """Whether the engine records no exit for `live` since its creation (a
    zero FinishedAt), or does not say."""
    created = _ns(live.get("Created")) if isinstance(live, dict) else None
    state = live.get("State") if isinstance(live, dict) else None
    finished = _ns(state.get("FinishedAt")) if isinstance(state, dict) else None
    return created is None or finished is None or finished < created


def read_progressing(live: Any, state_dir: str, who: str) -> Any:
    """read_status, then again every PROGRESS_STEP_S until `polls` rises under
    the same PROCESS_START, within the document's own progress window
    (PROGRESS_INTERVALS × `interval_s` + PROGRESS_MARGIN_S): the later
    document as Progressed, or an Unresolved. Under that start `polls` never
    falls; a read where it does is UNKNOWN at once."""
    first = read_status(live, state_dir, who)
    if not isinstance(first, dict):
        return first
    interval, polls, began = first.get("interval_s"), first.get("polls"), first.get(PROCESS_START)
    if not isinstance(interval, (int, float)) or isinstance(interval, bool) or not 0 < interval \
            or interval * PROGRESS_INTERVALS + PROGRESS_MARGIN_S > MAX_PROGRESS_WAIT_S \
            or not isinstance(polls, int) or isinstance(polls, bool):
        return rh.Unresolved(f"{who}'s status document has no usable interval_s and polls, so its writer "
                             "cannot be seen to advance it")
    deadline = _monotonic() + interval * PROGRESS_INTERVALS + PROGRESS_MARGIN_S
    while _monotonic() < deadline:
        _sleep(PROGRESS_STEP_S)
        doc = read_status(live, state_dir, who)
        if not isinstance(doc, dict):
            return doc
        later = doc.get("polls")
        if doc.get(PROCESS_START) != began or not isinstance(later, int) or isinstance(later, bool):
            continue
        if later < polls:
            return rh.Unresolved(f"{who}'s status document went back from {polls} polls to {later} under the "
                                 "same process start, so it is not one process's progress")
        if later > polls:
            return Progressed(doc)
    return rh.Unresolved(f"{who}'s status document did not advance within {PROGRESS_INTERVALS} poll "
                         "intervals, so it is not shown to be written by the running process")


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


def _monotonic() -> float:
    return time.monotonic()


def state_sharers(docker: List[str], state_dir: str, own_id: Any,
                  run: Optional[Callable[..., rh.Proc]] = None) -> Any:
    """The Ids of every OTHER container, in any state, with a mount whose
    source is `state_dir`, a directory above it, or anything below it (a
    single-file bind of the status document itself included), so that it
    could have written the status document there: a list (empty when none),
    or an Unresolved. The router's lock keeps two routers from running at
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
                sharers.append(doc.get("Id"))
                break
    return sharers


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
