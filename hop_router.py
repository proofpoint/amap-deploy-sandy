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
- `image`: `name`, `digest` (`sha256:<64 hex>`) and `commit`, the router
  image the operator built and runs by digest. The name is never the
  factory router's own default tag, and the commit is the one the image was
  built from, which must be the deployment's hop pin (siblings.json's
  `amap-router-local-hop` entry): a recorded-commit check, not a label rule.
"""

import posixpath
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

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
    def __init__(self, image_name: str, image_digest: str, image_commit: str):
        self.image_name, self.image_digest, self.image_commit = image_name, image_digest, image_commit


def load(sec: Any, spec: Any) -> RouterSpec:
    if not isinstance(sec, dict) or set(sec) != {"image"}:
        raise RouterSpecError("router must have exactly image")
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
    return RouterSpec(name, img["digest"], img["commit"])


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
