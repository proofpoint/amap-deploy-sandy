"""The agents' registry entries on a VM: the site's `registry_import` and `registry_read` slots (ruling
W7-REGISTRY-SLOTS-IN-R8-1), filled by a2_vm.bind.

Each agent is imported by the registry program S6 placed (the lock's registry_program, from A/.a2-registry-code,
through the same shim as S6), as the agent account, with adapter `sandy`, key = the workspace path and slug = the
sandbox name, under the registry and host.json S6 made. The discipline is S6's for the router's entry: plan, apply
with that plan's confirm, then a strict show by key, cross-checked against the apply and host.json. Each agent's
batch is placed by vm_place under its own root, one file per slug, never replaced.

`registry_import(vm, slug, stable_key, stage=)` returns nothing. `registry_read(vm, slug, stage=)` runs a fresh
strict show by that import's key and returns its logical id, which must equal the import's; a slug not imported in
this run refuses. Every refusal
names the calling stage: `<STAGE>.REGISTRY`, `<STAGE>.PLACED_DIFFERENT` (a batch already there with other bytes)
or `<STAGE>.UNCLASSIFIED`, rc 3 once the stage has written through the layer (3.4, 4.2).
"""

import posixpath
import re

import a2_registry as reg
import a2_s6
import vm_place
from a2_causes import Refusal

#: Each agent's import batch, one file per slug, under the agent account's home (vm_place, subset: never replaced).
AGENT_BATCH_ROOT = ".amap-registry-agents"
#: The agent account's home, as its passwd entry gives it (the launcher's HOME is the same entry).
HOME_ARGV = [a2_s6.PYTHON, "-I", "-S", "-c", "import os, pwd; print(pwd.getpwuid(os.geteuid()).pw_dir)"]
#: The slug registry_import accepts, so a caller can check its own slug before its first write.
SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


class AgentRegistry:
    def __init__(self, layer):
        self.layer = layer
        self._homes = {}
        #: (vm, slug) -> (stable_key, logical_id, identity_dir) of this run's imports.
        self._imported = {}

    def _rc(self, stage):
        return 3 if self.layer.wrote(stage) else None

    def _vm(self, vm, stage):
        v = self.layer.vms.get(vm)
        if v is None:
            raise Refusal(stage + ".HOSTS", vm, rc=self._rc(stage))
        return v

    def _home(self, vm, v, stage):
        if vm not in self._homes:
            rc, out, _err = self.layer.exec(vm, HOME_ARGV, account=v["agent_account"], stage=stage, writes=False)
            home = out[:-1].decode("utf-8", "replace") if rc == 0 and out.endswith(b"\n") else ""
            if not (home.startswith("/") and home != "/" and posixpath.normpath(home) == home and "\n" not in home):
                raise Refusal(stage + ".UNCLASSIFIED", "agent home", rc=self._rc(stage))
            self._homes[vm] = home
        return self._homes[vm]

    def _host(self, vm, v, home, module, args, writes, stage, stdin=None):
        argv = [a2_s6.PYTHON, "-I", "-B", "-c", a2_s6._shim(module), posixpath.join(home, a2_s6.HOST_TREE)] + args
        return self.layer.exec(vm, argv, account=v["agent_account"], stage=stage, writes=writes, stdin=stdin)

    def _place_batch(self, vm, v, slug, stable_key, stage):
        src = self.layer.pinned_installer_file(a2_s6.PLACE_SCRIPT, stage).decode("utf-8")
        entries = [(slug + ".json", a2_s6.F_FILE, reg.batch(stable_key, slug))]
        rc, out, _err = self.layer.exec(vm, [a2_s6.PYTHON, "-I", "-S", "-c", src, AGENT_BATCH_ROOT, "subset"],
                                        account=v["agent_account"], stage=stage, writes=True,
                                        stdin=vm_place.encode(entries))
        if rc == vm_place.DIFFERENT:
            raise Refusal(stage + ".PLACED_DIFFERENT", vm + ":" + AGENT_BATCH_ROOT, rc=3)
        if rc == vm_place.NOT_ALLOWED:
            raise Refusal(stage + ".OWNER", vm + ":" + AGENT_BATCH_ROOT, rc=3)
        if rc != 0 or out not in (b"PLACED " + entries[0][0].encode() + b"\n", b"SAME " + entries[0][0].encode() + b"\n"):
            raise Refusal(stage + ".UNCLASSIFIED", "place " + AGENT_BATCH_ROOT, rc=3)

    def registry_import(self, vm, slug, stable_key, *, stage):
        """Import one agent: its batch placed, then plan, apply with that plan's confirm, then a strict show. The
        stable_key kept is HOST's, as its plan returns it (HOST normalises the batch's key against the VM's
        filesystem), never compared with `stable_key`; the apply echoes it (parse_apply), and the shows query by it."""
        v = self._vm(vm, stage)
        if (not isinstance(slug, str) or not SLUG.fullmatch(slug) or not isinstance(stable_key, str)
                or not stable_key.startswith("/") or stable_key.startswith("//")
                or posixpath.normpath(stable_key) != stable_key):
            raise Refusal(stage + ".UNCLASSIFIED", "agent slug or key", rc=self._rc(stage))
        program = self.layer.lock["registry_program"]
        home = self._home(vm, v, stage)
        self._place_batch(vm, v, slug, stable_key, stage)
        r = posixpath.join(home, a2_s6.REGISTRY_DIR)
        batch = posixpath.join(home, AGENT_BATCH_ROOT, slug + ".json")
        refused = Refusal(stage + ".REGISTRY", "registry", rc=3)
        for _ in range(a2_s6.REGISTRY_ATTEMPTS):
            rc, out, _err = self._host(vm, v, home, program["package"] + ".opverbs",
                                       ["--registry", r, "plan", "import", "--batch", batch], False, stage)
            try:
                confirm, _action, plan, stable = reg.parse_plan(rc, out, slug)
                rc, out, _err = self._host(vm, v, home, program["package"] + ".opverbs",
                                           ["--registry", r, "apply", "import", "--batch", batch, "--confirm", confirm,
                                            "--operator", a2_s6.OPERATOR, "--reason", stage + " agent " + slug],
                                           True, stage)
                lid, _status, idir = reg.parse_apply(rc, out, slug, plan)
            except reg.RegistryError as e:
                if reg.next_step(e) == reg.REPLAN:
                    continue
                raise refused
            except reg.RegistryRefused:
                raise refused
            rc, out, _err = self._host(vm, v, home, program["package"], ["--registry", r], False, stage,
                                       stdin=reg.show_input(stable, program["adapter_interface"]))
            try:
                lid = reg.parse_show(rc, out, slug, lid, idir, v["fleet_domain"])
            except (reg.RegistryError, reg.RegistryRefused):
                raise refused
            self._imported[(vm, slug)] = (stable, lid, idir)
            return None
        raise refused

    def registry_read(self, vm, slug, *, stage):
        """A fresh strict show of this run's import of `slug` on `vm`: its logical id, equal to the import's."""
        got = self._imported.get((vm, slug))
        if got is None:
            raise Refusal(stage + ".REGISTRY", "not imported in this run", rc=self._rc(stage))
        stable_key, lid, idir = got
        v = self._vm(vm, stage)
        program = self.layer.lock["registry_program"]
        home = self._home(vm, v, stage)
        rc, out, _err = self._host(vm, v, home, program["package"], ["--registry", posixpath.join(home, a2_s6.REGISTRY_DIR)],
                                   False, stage, stdin=reg.show_input(stable_key, program["adapter_interface"]))
        try:
            return reg.parse_show(rc, out, slug, lid, idir, v["fleet_domain"])
        except (reg.RegistryError, reg.RegistryRefused):
            raise Refusal(stage + ".REGISTRY", "registry read-back", rc=self._rc(stage))
