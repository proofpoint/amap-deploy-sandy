"""The router's host-registry entry on a VM (S6), through the registry program's verbs (E23) at its pinned commit.

HOST's answer to W7 O1 fixes every shape here (captured at the registry program's pin; tests use those bytes). The
program's package name and its interface tokens are private identifiers (ruling W7-REGISTRY-NAME-IN-LOCK): the lock's
registry_program supplies them, and a2_private pins each by sha256. Here they are <package>, <interface>:
- import: `<package>.opverbs --registry <R> plan import --batch <file>`, then `apply import` with that plan's
  `confirm`, as the registry's writer (the agent account), from the program's placed tree (a2_s6).
- read-back: `{"interface":<interface>,"op":"show","adapter":"sandy","key":<abs key>}` on stdin to `<package>
  --registry <R>`; one sorted-key JSON line; parsed strictly, as HOST recommends.

This module builds the inputs and parses the outputs; a2_s6 runs them through the VM layer. Every refusal is
CONFIG's, under the write rule.
"""

import json
import re

STAGE = "CONFIG"
ADAPTER = "sandy"
_LOGICAL_ID = re.compile(r"[0-9a-f]{32}")
_CONFIRM = re.compile(r"[0-9a-f]{16}")
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
#: The two exact binding key sets of a show (HOST): with identity_dir always, and name_json only when active and
#: the adapter is configured.
BINDING_KEYS = ({"adapter", "address", "epoch", "first_registered_ts", "identity_dir", "logical_id", "name",
                 "state"},
                {"adapter", "address", "epoch", "first_registered_ts", "identity_dir", "logical_id", "name",
                 "name_json", "state"})
OUTPUT_MAX = 1 << 16


class RegistryRefused(Exception):
    """A registry answer S6 cannot accept; the caller raises CONFIG.REGISTRY under the write rule."""


class RegistryError(Exception):
    """A well-formed refusal from the registry program: rc 1 (or 3), `{"error": {"code", "detail"}, "ok": false, ...}`.
    `code` is HOST's; `committed` is True, False or "unknown" where HOST reports it."""

    def __init__(self, code, committed=None):
        super().__init__(code)
        self.code = code
        self.committed = committed


#: What the caller does with an apply refusal (HOST's answer to the parser review): re-plan and apply again with the
#: fresh confirm; or a hard refusal, never retried.
REPLAN, REFUSE = "replan", "refuse"


def next_step(err):
    """confirm_mismatch: re-plan. delivery_failed with committed true: the binding is written; re-plan (it shows
    already_bound) and apply again to redeliver. An rc-3 "committed": "unknown": re-plan to learn the outcome.
    Everything else (import_conflict, key_bound, any other code): refuse."""
    if err.code == "confirm_mismatch":
        return REPLAN
    if err.code == "delivery_failed" and err.committed is True:
        return REPLAN
    if err.committed == "unknown":
        return REPLAN
    return REFUSE


#: The binding key set of a show for an active binding whose adapter is configured (HOST): the only one S6 accepts.
BINDING_KEYS = {"adapter", "address", "epoch", "first_registered_ts", "identity_dir", "logical_id", "name",
                "name_json", "state"}
PLAN_KEYS = {"items", "registry_seq", "verb"}
ITEM_KEYS = {"action", "adapter", "slug", "stable_key"}
RESULT_KEYS = {"identity_dir", "index", "logical_id", "name", "status"}
OUTPUT_MAX = 1 << 16


def _strict_json(raw):
    def pairs(ps):
        seen = set()
        for k, _ in ps:
            if k in seen:
                raise ValueError("duplicate key")
            seen.add(k)
        return dict(ps)

    def const(_):
        raise ValueError("constant")
    if len(raw) > OUTPUT_MAX or not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise RegistryRefused("not one line")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=const)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise RegistryRefused("not strict JSON")


def _refusal(rc, doc):
    """A well-formed registry program refusal as RegistryError, or RegistryRefused for anything else."""
    if rc in (1, 3) and isinstance(doc, dict) and doc.get("ok") is False and isinstance(doc.get("error"), dict):
        code = doc["error"].get("code")
        if isinstance(code, str) and code:
            committed = doc.get("committed")
            if rc == 3 and committed is None:
                committed = "unknown"
            raise RegistryError(code, committed)
    raise RegistryRefused("refusal")


def batch(key, slug):
    """The import batch FILE's bytes: one item, strict JSON. The caller writes it to a REGULAR file the agent account
    owns (the program opens it O_NOFOLLOW; no FIFO or /dev/stdin), at most 1 MiB."""
    return json.dumps([{"adapter": ADAPTER, "key": key, "slug": slug}], sort_keys=True).encode()


def show_input(key, interface):
    return json.dumps({"interface": interface, "op": "show", "adapter": ADAPTER, "key": key},
                      separators=(",", ":")).encode()


def _check_plan(plan, slug):
    if not isinstance(plan, dict) or set(plan) != PLAN_KEYS or plan["verb"] != "import":
        raise RegistryRefused("plan")
    seq = plan["registry_seq"]
    if type(seq) is not int or seq < 0 or not isinstance(plan["items"], list) or len(plan["items"]) != 1:
        raise RegistryRefused("plan")
    it = plan["items"][0]
    if (not isinstance(it, dict) or set(it) != ITEM_KEYS or it["adapter"] != ADAPTER or it["slug"] != slug
            or it["action"] not in ("import", "already_bound") or not isinstance(it["stable_key"], str)
            or not it["stable_key"].startswith("/")):
        raise RegistryRefused("plan item")
    return it


def parse_plan(rc, out, slug):
    """(confirm, action, plan, stable_key) of a one-item import plan for `slug`. The plan is kept: apply must echo it
    exactly, and stable_key is recorded once, as HOST returns it."""
    doc = _strict_json(out)
    if rc != 0:
        _refusal(rc, doc)
    if not isinstance(doc, dict) or set(doc) != {"confirm", "ok", "plan"} or doc["ok"] is not True:
        raise RegistryRefused("plan")
    confirm = doc["confirm"]
    if not isinstance(confirm, str) or not _CONFIRM.fullmatch(confirm):
        raise RegistryRefused("confirm")
    it = _check_plan(doc["plan"], slug)
    return confirm, it["action"], doc["plan"], it["stable_key"]


def parse_apply(rc, out, slug, plan):
    """(logical_id, status, identity_dir) of a one-item apply whose echoed plan equals `plan`, the one confirmed.
    A refusal raises RegistryError with HOST's code (see next_step)."""
    doc = _strict_json(out)
    if rc != 0:
        _refusal(rc, doc)
    if not isinstance(doc, dict) or doc.get("ok") is not True or set(doc) != {"ok", "plan", "results"}:
        raise RegistryRefused("apply")
    if doc["plan"] != plan:
        raise RegistryRefused("apply's plan is not the plan confirmed")
    res = doc["results"]
    if not isinstance(res, list) or len(res) != 1 or not isinstance(res[0], dict) or set(res[0]) != RESULT_KEYS:
        raise RegistryRefused("apply results")
    r = res[0]
    lid, idir = r["logical_id"], r["identity_dir"]
    if (type(r["index"]) is not int or r["index"] != 0 or r["name"] != slug
            or r["status"] not in ("imported", "already_bound")
            or not isinstance(lid, str) or not _LOGICAL_ID.fullmatch(lid) or lid == "0" * 32
            or not isinstance(idir, str) or not idir.startswith("/")):
        raise RegistryRefused("apply result")
    return lid, r["status"], idir


def parse_show(rc, out, slug, logical_id, identity_dir, domain):
    """The binding's logical id, by HOST's recommended strict parse, cross-checked against the apply it follows
    (logical id and identity_dir) and the host.json S6 wrote (address = slug@domain). not_found and every other
    refusal raise RegistryError."""
    doc = _strict_json(out)
    if rc != 0:
        _refusal(rc, doc)
    if not isinstance(doc, dict) or set(doc) != {"binding", "ok"} or doc["ok"] is not True:
        raise RegistryRefused("show")
    b = doc["binding"]
    if not isinstance(b, dict) or set(b) != BINDING_KEYS:
        raise RegistryRefused("binding keys")
    lid = b["logical_id"]
    if (b["adapter"] != ADAPTER or b["name"] != slug or b["state"] != "active" or b["name_json"] != "current"
            or not isinstance(lid, str) or not _LOGICAL_ID.fullmatch(lid) or lid == "0" * 32
            or type(b["epoch"]) is not int or b["epoch"] < 1
            or not isinstance(b["first_registered_ts"], str) or not _UTC.fullmatch(b["first_registered_ts"])):
        raise RegistryRefused("binding")
    if lid != logical_id or b["identity_dir"] != identity_dir or b["address"] != slug + "@" + domain:
        raise RegistryRefused("show does not match the apply and host.json")
    return lid
