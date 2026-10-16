"""The local router ([1]) on a host with a hop link: the deploy constant for
its hop tree, and the check that its image was built from the reviewed
router code. NOTHING HERE STARTS OR RENDERS A ROUTER.

The hop constant. `hop.version_write` and `hop.caps` are a DS deploy
constant, versioned with the transport plugin they were reviewed for
(`PLUGIN_SHA256`), not operator data (the controller's ruling, with the
router's, the hop plugin's and the email router's owners):
- `version_write` 1: the hop contract version, the only one the hub-link
  email router ([2]) reads and writes;
- `caps.request` 1048576: [2]'s request cap. The router's loader does not
  check it, so `cap_problems` does;
- `caps.attachment` 1048576: the router's least per-sidecar cap, within
  [2]'s default per-attachment cap (10485760; [2]'s environment sets none);
- `caps.total` 20971520: [2]'s total attachment cap;
- `caps.document` 23418699: the router's own `hoplink.document_floor` at
  those values and the router's default count and file caps (16, 8 MiB).
  A test recomputes it with the hop checkout's function, in a separate
  process, so a change on either side shows.

The host-setup document's `router` section names, all operator data:
- `image`: `name`, `digest` and `commit`, the router image the operator
  built. `digest` is the image's ID (`docker image inspect --format
  '{{.Id}}'`, `sha256:<64 hex>`), the engine's content-addressed image Id:
  the config digest on the classic image store, the manifest (list) digest
  on the containerd store. The running container's `.Image` is that ID. The name is never the
  factory router's own default tag, and the commit is the one the image was
  built from, which must be the deployment's hop pin (siblings.json's
  `amap-router-local-hop` entry): a recorded-commit check, not a label rule;
- `container`: the name `docker/run.sh --name` gives the running router,
  which verify inspects. The section is mandatory on a hop host.
"""

import hashlib
import json
import os
import posixpath
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import delegation_render as dr
import router_health as rh
import siblings

SECTION = "router"
#: The transport plugin the hop constant was reviewed for (the hop pin's artifact).
PLUGIN_SHA256 = "f15855c974df021c2ae5c551aff2448d934725a6796fb03434e573305d24fe93"
HOP_VERSION_WRITE = 1
HOP_CAPS = (("document", 23418699), ("request", 1048576), ("attachment", 1048576), ("total", 20971520))
#: The bounds the hop constant must meet: [2]'s request cap, the router's
#: least per-sidecar cap, [2]'s default per-attachment cap and its total cap.
REQUEST_CAP_MAX = 1048576
ATTACHMENT_CAP_MIN = 1048576
HUB_ATTACH_MAX_BYTES = 10485760
HUB_ATTACH_MAX_TOTAL = 20971520
#: The router's own default count and per-file caps, the floor's other inputs.
FLOOR_COUNT_CAP = 16
FLOOR_FILE_CAP = 8 * 1024 * 1024
#: The factory router's default image tag (its docker/build.sh): never the hop image's name.
FACTORY_IMAGE = "amap-router-local"
#: The siblings.json checkout directory of the hop pin.
HOP_PIN_DIR = "amap-router-local-hop"

_HEX40 = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_NAME = re.compile(r"[a-z0-9][a-z0-9._/-]*")


class RouterSpecError(ValueError):
    """The router section is unusable."""


def caps() -> Dict[str, int]:
    return dict(HOP_CAPS)


def cap_problems(caps_: Dict[str, int], version_write: int) -> List[str]:
    """What breaks the bounds the hop constant must meet; empty when none does.
    The document floor is the router's own check, made by its loader."""
    bad = []
    if version_write != HOP_VERSION_WRITE:
        bad.append(f"version_write {version_write}: [2] reads and writes only hop contract {HOP_VERSION_WRITE}")
    if caps_.get("request", 0) > REQUEST_CAP_MAX:
        bad.append(f"caps.request {caps_.get('request')} exceeds [2]'s request cap {REQUEST_CAP_MAX}")
    a = caps_.get("attachment", 0)
    if not ATTACHMENT_CAP_MIN <= a <= HUB_ATTACH_MAX_BYTES:
        bad.append(f"caps.attachment {a} is outside {ATTACHMENT_CAP_MIN}..{HUB_ATTACH_MAX_BYTES}")
    if caps_.get("total", 0) > HUB_ATTACH_MAX_TOTAL:
        bad.append(f"caps.total {caps_.get('total')} exceeds [2]'s total attachment cap {HUB_ATTACH_MAX_TOTAL}: "
                   "a request between the two would pass [1] and be held at [2]")
    return bad


class RouterSpec:
    def __init__(self, image_name: str, image_digest: str, image_commit: str, container: str):
        self.image_name, self.image_digest, self.image_commit = image_name, image_digest, image_commit
        self.container = container

    @property
    def image_ref(self) -> str:
        """The image by its ID: what the preflight runs, never pulled."""
        return self.image_digest


_CONTAINER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")


def load(sec: Any, spec: Any) -> RouterSpec:
    if not isinstance(sec, dict) or set(sec) != {"image", "container"}:
        raise RouterSpecError("router must have exactly image and container")
    if not isinstance(sec["container"], str) or not _CONTAINER.fullmatch(sec["container"]):
        raise RouterSpecError("router.container must be a container name")
    img = sec["image"]
    if not isinstance(img, dict) or set(img) != {"name", "digest", "commit"}:
        raise RouterSpecError("router.image must have exactly name, digest and commit")
    name = img["name"]
    if not isinstance(name, str) or not _NAME.fullmatch(name) or posixpath.basename(name) == FACTORY_IMAGE:
        raise RouterSpecError(f"router.image.name must be an image name other than the factory router's "
                              f"own tag ({FACTORY_IMAGE})")
    if not isinstance(img["digest"], str) or not _DIGEST.fullmatch(img["digest"]):
        raise RouterSpecError("router.image.digest must be sha256:<64 hex>")
    if not isinstance(img["commit"], str) or not _HEX40.fullmatch(img["commit"]):
        raise RouterSpecError("router.image.commit must be a full commit sha")
    return RouterSpec(name, img["digest"], img["commit"], sec["container"])


def hop_pin(load_pins: Callable[[], List[Dict[str, str]]] = siblings.load_pins) -> Any:
    """The hop pin's commit, from siblings.json, or an Unresolved."""
    try:
        pins = [p for p in load_pins() if p.get("dir") == HOP_PIN_DIR]
    except (siblings.SiblingError, OSError) as e:
        return rh.Unresolved(f"siblings.json cannot be read: {e}")
    if len(pins) != 1:
        return rh.Unresolved(f"siblings.json has {len(pins)} {HOP_PIN_DIR} entries, not one")
    return pins[0]["commit"]


def checks(spec: Any, *, pin: Any = None) -> List[rh.Check]:
    """[1]'s recorded image commit against the hop pin; the hop constant
    against the plugin it was reviewed for, and against [2]'s bounds."""
    out: List[rh.Check] = []
    r = spec.router
    pin = hop_pin() if pin is None else pin
    claim = f"[1]'s image {r.image_name}@{r.image_digest[:19]} was built from the hop pin"
    want = rh.Fact("commit", pin, "siblings.json's hop pin: [1]'s image is built from it (HOP-IMAGE-PIN = A)")
    remedy = (f"build [1]'s image from the hop pin's commit as {r.image_name} (never {FACTORY_IMAGE}), and "
              "record that commit and the image's digest in the router section")
    if isinstance(pin, rh.Unresolved):
        out.append(rh.unknown(claim, want, pin.reason, remedy))
    else:
        out.append(rh.check(claim, want, r.image_commit, remedy,
                            do_not="never record the pin's commit for an image built from anything else"))
    claim = "the hop constant was reviewed for this transport plugin"
    want = rh.Fact("plugin", PLUGIN_SHA256, "hop_router.PLUGIN_SHA256: the constant is versioned with the plugin")
    remedy = "review the hop constant against the new plugin, then move PLUGIN_SHA256 and the constant together"
    if spec.overlay_pin is None:
        out.append(rh.unknown(claim, want, "the document has no plugin pin", "pin the plugin in the overlay"))
    else:
        out.append(rh.check(claim, want, spec.overlay_pin.get("sha256"), remedy))
    claim = "the hop constant meets [2]'s bounds"
    want = rh.Fact("bounds", [], "[2]'s request, attachment and total caps, and the hop contract version")
    out.append(rh.check(claim, want, cap_problems(caps(), HOP_VERSION_WRITE),
                        "correct the constant; [2]'s caps are its owner's"))
    return out


# --- The local router's hop keys in router.json (P3b-2) --------------------------
#
# On a host with a hop link, `install` adds these TOP-LEVEL keys to the
# router.json it renders. The trigger is the fleet policy's `hop_link` key,
# never the host-setup document; the document then must be complete. Every
# value has one source: the document's hub, router and overlay sections, the
# hop constant above, and `hop_link`.

HOP_LINK_KEY = "hop_link"
HOP_LINK_MEMBERS = ("link", "trusted_fleet_hosts", "egress")
#: The router's own link grammar (its `config.HOP_LINK_RE`).
LINK_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
_HOST = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
#: The router.json keys this section renders, and the attachment tunables a
#: hop host must NOT render: the document floor was computed at the router's
#: defaults for them.
HOP_KEYS = ("transport_plugin", "hop", "registry_dir", "delivered_domains_file", "fleet_hosts",
            "trusted_fleet_hosts", "egress")
ATTACHMENT_TUNABLES = ("attachment_max_bytes", "attachment_max_count", "attachment_max_total_bytes")
#: The router container's system paths (the router's derive-mounts, the same
#: floor): never a hop path as a whole directory, or at or under the trees.
SYSTEM_DIRS = ("/", "/boot", "/etc", "/home", "/media", "/mnt", "/opt", "/root", "/run", "/srv", "/tmp", "/var")
SYSTEM_TREES = ("/app", "/bin", "/dev", "/lib", "/lib32", "/lib64", "/libx32", "/proc", "/sbin", "/sys", "/usr")
PLUGIN_MODES = (0o444, 0o644)
#: Where the hop pin's checkout lives: beside this repository, as siblings.py
#: places it, or wherever the override names.
HOP_CHECKOUT_ENV = "AMAP_HOP_ROUTER_REPO"


class HopRenderError(ValueError):
    """The hop keys cannot be rendered; nothing is written."""


class HopLink:
    def __init__(self, link: str, trusted: Tuple[str, ...], egress: bool, inbound: Optional[bool] = None):
        self.link, self.trusted, self.egress = link, trusted, egress
        #: The `delegation` member: None when absent (the host renders no
        #: delegation block), else whether inbound verification is on.
        self.inbound = inbound


def parse_hop_link(policy: Dict[str, Any]) -> Optional[HopLink]:
    """The policy's `hop_link`, or None when the host has no hop link. Every
    member is required and none is defaulted, except `delegation`, whose
    absence means no delegation block (delegation_render.parse_policy)."""
    if HOP_LINK_KEY not in policy:
        return None
    raw = policy[HOP_LINK_KEY]          # present: null or anything else malformed is refused
    if not isinstance(raw, dict) or not set(HOP_LINK_MEMBERS) <= set(raw) \
            or set(raw) - set(HOP_LINK_MEMBERS) - {dr.POLICY_MEMBER}:
        raise HopRenderError(f"{HOP_LINK_KEY} must have exactly {', '.join(HOP_LINK_MEMBERS)}, "
                             f"and may have {dr.POLICY_MEMBER}")
    link = raw["link"]
    if not isinstance(link, str) or not LINK_RE.fullmatch(link):
        raise HopRenderError(f"{HOP_LINK_KEY}.link must match [a-z0-9][a-z0-9-]{{0,62}}")
    trusted = raw["trusted_fleet_hosts"]
    if not isinstance(trusted, list) or not all(isinstance(h, str) and _HOST.fullmatch(h) for h in trusted) \
            or len(set(trusted)) != len(trusted):
        raise HopRenderError(f"{HOP_LINK_KEY}.trusted_fleet_hosts must list canonical host domains, once each")
    if not isinstance(raw["egress"], bool):
        raise HopRenderError(f"{HOP_LINK_KEY}.egress must be true or false; it has no default")
    inbound = None
    if dr.POLICY_MEMBER in raw:
        try:
            inbound = dr.parse_policy(raw[dr.POLICY_MEMBER])
        except dr.DelegationRenderError as e:
            raise HopRenderError(str(e)) from None
    return HopLink(link, tuple(sorted(trusted)), raw["egress"], inbound)


def _within(a: str, b: str) -> bool:
    return a == b or a.startswith(b.rstrip("/") + "/")


def system_path(p: str) -> bool:
    return p in SYSTEM_DIRS or any(_within(p, t) for t in SYSTEM_TREES)


def hop_keys(spec: Any, link: HopLink, fleet_domain: Optional[str]) -> Dict[str, Any]:
    """The hop keys for router.json, from the host-setup document `spec`,
    the policy's `link` and the fleet domain; HopRenderError when anything
    is missing or breaks a rule. Fails closed: never a partial set."""
    missing = [n for n, v in (("hub", spec.hub), ("router", spec.router), ("secrets", spec.secrets),
                              ("the overlay pin", spec.overlay_pin)) if v is None]
    if missing:
        raise HopRenderError(f"the host-setup document lacks {', '.join(missing)}: a hop host needs them all")
    if not fleet_domain:
        raise HopRenderError("a hop host needs the policy's fleet_domain")
    hub = spec.hub
    if spec.overlay_pin.get("sha256") != PLUGIN_SHA256:
        raise HopRenderError("the overlay's plugin pin is not the plugin the hop constant was reviewed for")
    if link.link != hub.link:
        raise HopRenderError(f"{HOP_LINK_KEY}.link {link.link!r} is not the hub's hop link {hub.link!r}: "
                             "both ends of one link carry one name")
    fleet = list(hub.fleet_hosts)
    own = fleet_domain.lower()
    if own in fleet:
        raise HopRenderError(f"fleet_hosts names this router's own domain {own}")
    outside = sorted(set(link.trusted) - set(fleet))
    if outside:
        raise HopRenderError(f"{HOP_LINK_KEY}.trusted_fleet_hosts {outside} are not in the hub's fleet_hosts")
    # trusted ⊆ fleet, and the own domain is not in fleet, so it is not in trusted either.
    plugin = spec.overlay_path
    paths = (("hop.root", hub.hop_root), ("registry_dir", hub.registry_dir),
             ("the D7 directory", posixpath.dirname(hub.d7_path)), ("the plugin's directory", posixpath.dirname(plugin)))
    for what, p in paths:
        if system_path(p):
            raise HopRenderError(f"{what} {p} is a container system path; an identity mount there would "
                                 "replace what the router's image needs")
    peer = spec.principals[spec.secrets.principal].uid
    return {
        "transport_plugin": {"path": plugin, "sha256": spec.overlay_pin["sha256"]},
        "hop": {"root": hub.hop_root, "peer_uid": peer, "version_write": HOP_VERSION_WRITE, "caps": caps(),
                "link": link.link},
        "registry_dir": hub.registry_dir,
        "delivered_domains_file": hub.d7_path,
        "fleet_hosts": fleet,
        "trusted_fleet_hosts": list(link.trusted),
        "egress": link.egress,
    }


def plugin_nesting_problems(doc: Dict[str, Any], roots: Any = ()) -> List[str]:
    """The plugin's directory may sit inside no other mount the router gets
    (RL's condition for the in-container preflight): there, startup would
    walk the HOST directory's owner and mode, while the preflight, which
    mounts only the plugin's directory, would see a docker-made root 0755
    parent, and could pass a plugin startup refuses."""
    plugin_dir = os.path.realpath(posixpath.dirname(doc["transport_plugin"]["path"]))
    sel = posixpath.dirname(doc.get("selected_json") or "") or None
    others = [("state_dir", doc.get("state_dir")), ("instances_dir", doc.get("instances_dir")),
              ("selected_json's directory", sel),
              ("the roster directory", posixpath.join(sel, "roster") if sel else None),
              ("intake_dir", doc.get("intake_dir")),
              ("hop.root", doc["hop"]["root"]), ("registry_dir", doc.get("registry_dir")),
              ("the D7 directory", posixpath.dirname(doc.get("delivered_domains_file") or "") or None)]
    unknown = []
    if isinstance(roots, rh.Unresolved):
        unknown = [f"the agent-reachable roots cannot be derived ({roots.reason}), so the plugin's directory "
                   f"{plugin_dir} cannot be shown to sit outside them"]
    else:
        others += [("an agent-reachable root", r) for r in roots]
    return unknown + [f"the plugin's directory {plugin_dir} is inside {what} {p}; the router's plugin checks "
                      "walk its ancestors, so it must sit outside every other mount" for what, p in others
                      if p and _within(plugin_dir, os.path.realpath(p))]


def tunable_problems(doc: Dict[str, Any]) -> List[str]:
    """No attachment tunable on a hop host: caps.document is the loader's
    floor at the router's defaults for them, with no slack."""
    return [f"{k} is set; on a hop host the attachment caps stay at the router's defaults, which "
            "caps.document was computed for" for k in ATTACHMENT_TUNABLES if k in doc]


def router_principal(spec: Any) -> Tuple[int, int]:
    """[1]'s uid and primary gid: the other end of the hub's hop."""
    for name, up, down, _env in spec.hops:
        if name == spec.hub.hop:
            other = up if down == spec.secrets.principal else down
            p = spec.principals[other]
            return p.uid, p.gids[0]
    raise HopRenderError(f"the document has no hop named {spec.hub.hop}")


def plugin_problems(path: str, sha256: str, *, lstat: Callable = os.lstat,
                    listdir: Callable[[str], List[str]] = os.listdir,
                    read: Callable[[str], bytes] = lambda p: open(p, "rb").read()) -> List[str]:
    """The plugin file on the host, checked WITHOUT importing it: a regular
    file, not a symlink, owned by root, mode exactly 0444 or 0644, its bytes
    the pin; and alone in its directory, which is mounted into the router.
    The router's own startup checks (every ancestor, size, realpath) run
    inside its container; see `in_container_plugin_check`."""
    bad = []
    try:
        st = lstat(path)
    except OSError as e:
        return [f"the plugin {path} cannot be read: {e.strerror}"]
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        return [f"the plugin {path} is not a regular file"]
    if st.st_uid != 0:
        bad.append(f"the plugin {path} is owned by uid {st.st_uid}, not root")
    if stat.S_IMODE(st.st_mode) not in PLUGIN_MODES:
        bad.append(f"the plugin {path} has mode {stat.S_IMODE(st.st_mode):04o}; the router loads only 0444 or 0644")
    try:
        if hashlib.sha256(read(path)).hexdigest() != sha256:
            bad.append(f"the plugin {path}'s bytes are not the pin")
    except OSError as e:
        bad.append(f"the plugin {path} cannot be read: {e.strerror}")
    try:
        others = sorted(n for n in listdir(posixpath.dirname(path)) if n != posixpath.basename(path))
    except OSError as e:
        others = [f"<unreadable: {e.strerror}>"]
    if others:
        bad.append(f"the plugin's directory {posixpath.dirname(path)} holds more than the plugin ({len(others)} "
                   "other entries); it is mounted into the router whole")
    return bad


def hop_checkout() -> str:
    env = os.environ.get(HOP_CHECKOUT_ENV)
    return env if env else str(Path(__file__).resolve().parent.parent / HOP_PIN_DIR)


def checkout_problems(path: str, pin: Any) -> List[str]:
    """The hop pin's checkout must be AT the pin and clean: the router code
    the rendering is validated against is the reviewed code."""
    if isinstance(pin, rh.Unresolved):
        return [f"the hop pin cannot be read: {pin.reason}"]
    git = ["git", "-C", path, "-c", "core.hooksPath=/dev/null"]
    try:
        head = subprocess.run(git + ["rev-parse", "HEAD"], capture_output=True, text=True, timeout=60)
        dirty = subprocess.run(git + ["status", "--porcelain"], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        return [f"the hop checkout {path} cannot be read: {e}"]
    if head.returncode:
        return [f"{path} is not a git checkout (run amap-siblings.py --apply)"]
    bad = []
    if head.stdout.strip() != pin:
        bad.append(f"the hop checkout {path} is at {head.stdout.strip()[:12]}, not the hop pin {pin[:12]}")
    if dirty.returncode or dirty.stdout.strip():
        bad.append(f"the hop checkout {path} has uncommitted changes")
    return bad


def validate_with_hop_router(doc: Dict[str, Any], checkout: str) -> Optional[str]:
    """The hop checkout's own loader, in a SEPARATE process with only that
    checkout on its path (the primary checkout is also a package named
    `router`). None when it accepts the document, else its refusal."""
    code = ("import json, sys\nsys.path.insert(0, sys.argv[1])\nfrom router.config import load_obj\n"
            "load_obj(json.loads(sys.stdin.read()))\n")
    try:
        p = subprocess.run([sys.executable, "-I", "-c", code, checkout], input=json.dumps(doc),
                           capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"the hop router's loader could not run: {e}"
    if p.returncode == 0:
        return None
    lines = [l for l in p.stderr.strip().splitlines() if l.strip()]
    return lines[-1] if lines else f"exit {p.returncode}"


#: The local router's config key for how long it remembers an ingress item
#: it has seen (its dedup horizon), in days; absent means the router's default.
HORIZON_KEY = "ingress_dedup_horizon_days"


def horizon_default(checkout: str) -> Tuple[Optional[int], str]:
    """The hop checkout's own default for HORIZON_KEY, read in a separate
    process as validate_with_hop_router reads its loader: (days, where), or
    (None, why it could not be read)."""
    code = ("import sys\nsys.path.insert(0, sys.argv[1])\n"
            "from router.config import INGRESS_DEDUP_HORIZON_DAYS_DEFAULT as d\nprint(d)\n")
    where = f"router.config.INGRESS_DEDUP_HORIZON_DAYS_DEFAULT in the hop checkout {checkout}"
    try:
        p = subprocess.run([sys.executable, "-I", "-c", code, checkout], capture_output=True, text=True,
                           timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, f"{where} could not be read: {e}"
    out = p.stdout.strip()
    if p.returncode != 0 or not out.isdigit():
        return None, f"{where} could not be read: exit {p.returncode}"
    return int(out), where


def state_problems(state_dir: str, keys: Optional[Dict[str, Any]]) -> List[str]:
    """What `state_dir`'s durable hop records say against the rendering.
    Every generation's `transport/hop.json` pins `hop_root` for the life of
    state_dir, so all of them are compared. `version_write` is compared only
    against each identity's CURRENT generation and the runtime namespace's
    recorded one: a retired generation keeps the contract it was admitted
    under, and a new contract begins in new generations. Each identity's
    current generation pins its link in `ingress/link.json`. With `keys` None (no
    hop_link), any hop record is a problem: removing a link is an explicit
    decommission, never a silent render."""
    bad = []
    pins = sorted(Path(state_dir).glob("*/gen-*/transport/hop.json")) + \
        sorted(Path(state_dir).glob("_runtime/*/transport/hop.json"))
    if keys is None:
        if pins:
            bad.append(f"{len(pins)} generation(s) in {state_dir} hold hop state, and the policy has no "
                       f"{HOP_LINK_KEY}: removing a hop link is `install --decommission-hop` and a router restart")
        return bad
    hop = keys["hop"]
    for p in pins:
        try:
            pin = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            bad.append(f"{p} cannot be read: a hop pin the router wrote is unreadable")
            continue
        if pin.get("hop_root") != hop["root"]:
            bad.append(f"{p} pins hop.root {pin.get('hop_root')!r}; the rendering says {hop['root']!r}. hop.root "
                       "is fixed for the life of state_dir: keep it, or start a new state_dir")
    current_pins = []
    try:
        rgen = json.loads((Path(state_dir) / "_runtime" / "generation.json").read_text(encoding="utf-8"))
        if isinstance(rgen, dict) and isinstance(rgen.get("generation"), str):
            current_pins.append(Path(state_dir) / "_runtime" / rgen["generation"] / "transport" / "hop.json")
    except (OSError, ValueError):
        pass
    for gens in sorted(Path(state_dir).glob("*/generations.json")):
        try:
            cur = json.loads(gens.read_text(encoding="utf-8")).get("current")
        except (OSError, ValueError, AttributeError):
            continue                        # reported below
        current_pins.append(gens.parent / f"gen-{cur}" / "transport" / "hop.json")
    for p in current_pins:
        try:
            pin = json.loads(p.read_text(encoding="utf-8"))
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            continue                        # already reported above
        if isinstance(pin, dict) and pin.get("version_write") != hop["version_write"]:
            bad.append(f"{p}, a CURRENT generation, pins version_write {pin.get('version_write')!r}; the "
                       f"constant says {hop['version_write']}. A changed hop contract needs new generations")
    for gens in sorted(Path(state_dir).glob("*/generations.json")):
        try:
            current = json.loads(gens.read_text(encoding="utf-8")).get("current")
        except (OSError, ValueError, AttributeError):
            bad.append(f"{gens} cannot be read")
            continue
        lid = gens.parent.name
        lp = gens.parent / f"gen-{current}" / "ingress" / "link.json"
        try:
            pinned = json.loads(lp.read_text(encoding="utf-8")).get("link")
        except FileNotFoundError:
            continue
        except (OSError, ValueError, AttributeError):
            bad.append(f"{lp} cannot be read")
            continue
        if pinned != hop.get("link"):
            bad.append(f"{lid}'s current generation pins link {pinned!r}; the rendering says {hop.get('link')!r}. "
                       f"Run `router generation new {lid} --reason <text>` first: a changed link latches the "
                       "generation's inbound off")
    return bad


def restart_notice(old: Any, new: Dict[str, Any]) -> Optional[str]:
    """The restart the router needs when `hop` or `transport_plugin` change:
    it refuses a reload that changes either."""
    old = old if isinstance(old, dict) else {}
    changed = [k for k in ("hop", "transport_plugin") if old.get(k) != new.get(k)]
    if not changed:
        return None
    return (f"{' and '.join(changed)} changed: RESTART the router (docker/run.sh from the hop checkout); "
            "it refuses a reload that changes them")


# --- The running router, checked live (verify, on a hop host) ----------------------

#: The router's own startup checks on the plugin, run INSIDE its image: the
#: first three steps of `transport.load_plugin`, which stop before the plugin
#: is executed. These are private names of the router's (carry
#: RL-PUBLIC-PREFLIGHT): a pin move re-checks them, and their absence fails.
PREFLIGHT = """
import hashlib, json, sys
from pathlib import Path
sys.path.insert(0, "/app")
from router import transport as t
path, sha, roots = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
try:
    p = t._check_path(path, [Path(r) for r in roots], t.TRUSTED_UIDS)
    data = t._read_pinned(p, t.TRUSTED_UIDS)
except t.PluginRefused as e:
    print("refused " + e.reason + ": " + e.detail); sys.exit(1)
if hashlib.sha256(data).hexdigest() != sha.lower():
    print("refused hash_mismatch"); sys.exit(1)
print("ok")
"""

ROOTS = """
import json, sys
sys.path.insert(0, sys.argv[1])
from router import config
cfg = config.load_obj(json.loads(sys.stdin.read()))
print(json.dumps(sorted(str(r) for r in config.agent_reachable_roots(cfg.instances))))
"""


def loader_roots(doc: Dict[str, Any], checkout: str) -> Any:
    """The directories an agent can reach, as the hop pin's loader derives
    them from `doc` (the plugin may not sit inside one); an Unresolved when
    the loader cannot say."""
    try:
        p = subprocess.run([sys.executable, "-I", "-c", ROOTS, checkout], input=json.dumps(doc),
                           capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        return rh.Unresolved(f"the hop router's loader could not run: {e}")
    if p.returncode:
        return rh.Unresolved("the hop router's loader refuses the rendering")
    try:
        return json.loads(p.stdout)
    except ValueError:
        return rh.Unresolved("the hop router's loader printed no roots")


def preflight_argv(r: RouterSpec, plugin: str, sha256: str, roots: List[str], uid: int, gid: int) -> List[str]:
    """`docker run` of [1]'s recorded image, by its ID and never pulled,
    with ONLY the plugin's directory mounted read-only, no network, no
    capability and no new privileges, as [1]'s principal."""
    d = posixpath.dirname(plugin)
    return ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", f"{uid}:{gid}",
            "--mount", f"type=bind,src={d},dst={d},readonly", "--entrypoint", "python3", r.image_ref,
            "-I", "-c", PREFLIGHT, plugin, sha256, json.dumps(roots)]


def live_problems(spec: Any, keys: Dict[str, Any], roots: Any, *, run: Callable = None,
                  uid: Optional[int] = None, gid: Optional[int] = None) -> List[str]:
    """The running router against the rendering: its container's identity
    mounts (source = target, the mode, once each), its image's digest, its
    user, and the plugin preflight in its image. Every unanswerable read is a
    problem by name, never a pass."""
    run = run or rh.run
    if uid is None or gid is None:
        uid, gid = router_principal(spec)
    r = spec.router
    bad: List[str] = []
    try:
        p = run(["docker", "inspect", r.container])
    except rh.CannotRun as e:
        return [f"[1] ({r.container}) cannot be inspected: {e}"]
    try:
        c = json.loads(p.out)[0] if p.rc == 0 else None
    except (ValueError, IndexError):
        c = None
    if not isinstance(c, dict):
        return [f"[1] ({r.container}) is not running or cannot be inspected; start it with the hop "
                "checkout's docker/run.sh"]
    mounts = [m for m in c.get("Mounts") or [] if isinstance(m, dict)]
    hop = keys["hop"]
    want = [(hop["root"], True), (keys["registry_dir"], False),
            (posixpath.dirname(keys["delivered_domains_file"]), False),
            (posixpath.dirname(keys["transport_plugin"]["path"]), False)]
    for path, rw in want:
        hits = [m for m in mounts if m.get("Destination") == path]
        if len(hits) != 1 or hits[0].get("Source") != path or bool(hits[0].get("RW")) != rw:
            bad.append(f"[1] does not mount {path} exactly once, by identity, {'read-write' if rw else 'read-only'}")
    cfg, host = c.get("Config") or {}, c.get("HostConfig") or {}
    if cfg.get("User") != f"{uid}:{gid}":
        bad.append(f"[1] runs as {cfg.get('User')!r}, not its principal's {uid}:{gid}: run docker/run.sh "
                   "as that account")
    if host.get("UsernsMode") not in ("", None, "host"):
        bad.append(f"[1] runs in a remapped user namespace ({host.get('UsernsMode')!r}); the hop trees' "
                   "owners would not be what they seem")
    # A daemon-wide remap (daemon.json userns-remap) leaves UsernsMode empty.
    try:
        info = run(["docker", "info", "--format", "{{json .SecurityOptions}}"])
        options = json.loads(info.out) if info.rc == 0 else None
    except (rh.CannotRun, ValueError):
        options = None
    if not isinstance(options, list):
        bad.append("the engine's security options cannot be read, so a daemon-wide user-namespace remap "
                   "cannot be ruled out")
    else:
        # Each entry is `name=<option>[,key=value...]`, as `docker info` prints it.
        names = {str(o).split(",")[0] for o in options}
        for name, what in (("name=userns", "remaps user namespaces daemon-wide (userns-remap)"),
                           ("name=rootless", "runs rootless, so every container's uids are mapped")):
            if name in names:
                bad.append(f"the engine {what}; the hop trees' owners would not be what they seem")
    if c.get("Image") != r.image_digest:
        bad.append(f"[1] runs image {c.get('Image')!r}, not the recorded {r.image_name} ({r.image_digest})")
    if isinstance(roots, rh.Unresolved):
        bad.append(f"the plugin preflight cannot run: {roots.reason}")
        return bad
    plugin = keys["transport_plugin"]
    try:
        pf = run(preflight_argv(r, plugin["path"], plugin["sha256"], roots, uid, gid))
    except rh.CannotRun as e:
        bad.append(f"the plugin preflight cannot run: {e}")
        return bad
    # Both: a container that exits non-zero has not passed, whatever it printed.
    if pf.rc != 0 or pf.out.strip() != "ok":
        line = (pf.out.strip() or pf.err.strip()).splitlines()
        bad.append(f"the router's own plugin checks, in its image, refuse: {line[-1] if line else 'exit ' + str(pf.rc)}")
    return bad
