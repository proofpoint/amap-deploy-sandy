"""S5 KEYS: each VM's router delegation key, by RL's recipe (ruling W7-S5-KEY-RECIPE), through the VM layer.

On each VM of the run, as the account RL runs as, the pinned vm_keys.py creates the seed if absent and prints only the
public key; the seed never leaves the VM. The key id is `<router slug>-k1`. A re-run recomputes the public key from
the existing seed, and an existing router.json that names another key refuses `KEYS.EXISTS_DIFFERENT`: a key is never
regenerated. The receipt of each VM carries KEY_ID, KEY_PUBLIC and KEY (CREATED or ALREADY); S6 renders them into the
VM's own router.json and the other VM's delegation.runtimes[].
"""

import re

from a2_causes import Refusal

STAGE = "KEYS"
KEYS_SCRIPT = "vm_keys.py"
PYTHON = "/usr/bin/python3"
#: router.json's path under the router account's home; S6 places it there.
ROUTER_JSON = ".amap-router/router.json"
KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_LINE = re.compile(rb"(CREATED|EXISTING) ([0-9a-f]{64})\n")
_EXISTS_DIFFERENT = 3


def key_id(slug):
    """`<slug>-k1`, in RL's key-id grammar; anything else refuses HOSTS (the slug is alpha2.hosts')."""
    kid = slug + "-k1" if isinstance(slug, str) else ""
    if not KEY_ID.fullmatch(kid):
        raise Refusal(STAGE + ".HOSTS", "router slug")
    return kid


def keys_on_vm(layer, vm, router_account, slug):
    """The facts of this VM's S5 receipt: [(KEY_ID, id), (KEY_PUBLIC, 64 hex), (KEY, CREATED or ALREADY)]."""
    kid = key_id(slug)
    src = layer.pinned_installer_file(KEYS_SCRIPT, STAGE).decode("utf-8")
    rc, out, _err = layer.exec(vm, [PYTHON, "-I", "-S", "-c", src, ROUTER_JSON], account=router_account,
                               stage=STAGE, writes=True)
    if rc == _EXISTS_DIFFERENT:
        raise Refusal(STAGE + ".EXISTS_DIFFERENT", vm, rc=3)
    m = _LINE.fullmatch(out) if rc == 0 else None
    if m is None:
        raise Refusal(STAGE + ".UNCLASSIFIED", "keys rc %d" % rc, rc=3)
    return [("KEY_ID", kid), ("KEY_PUBLIC", m.group(2).decode()),
            ("KEY", "CREATED" if m.group(1) == b"CREATED" else "ALREADY")]


def run_s5(c, site, rec):
    """S5 over the run scope's VMs, one receipt each (a2_stage.per_vm): CHANGED when the seed was created, ALREADY
    when it was there. A dry-run plans each VM's key id and touches nothing."""
    import a2_stage
    vms = [v for v in c.hosts["vms"] if v["scope"] == a2_stage.scope_of(c.inv.loop)]
    names = [v["name"] for v in vms]
    by_name = {v["name"]: v for v in vms}
    if c.inv.command == "dry-run":
        a2_stage.per_vm(rec, site, "S5", names, None, plan=lambda n: [("KEY_ID", key_id(by_name[n]["router"]["slug"]))],
                        dry_run=True)
        return
    if site.vm_layer is None:
        a2_stage.refuse_before_vms(rec, site, "S5", names, Refusal(STAGE + ".TARGET_ACCESS", "the VM layer is not bound"))

    def step(n):
        facts = keys_on_vm(site.vm_layer, n, by_name[n]["agent_account"], by_name[n]["router"]["slug"])
        return facts, "CHANGED" if ("KEY", "CREATED") in facts else "ALREADY"
    a2_stage.per_vm(rec, site, "S5", names, step)
