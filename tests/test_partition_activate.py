"""A1, `partition-activate`: from install's own rendering, after every
hop-host check install makes, the staged bytes, the prospective run spec for
the final path, and A1's record, written only into the run directory and only
with --apply. The host, the rendering and the inventory are A3's fixture
(test_activation_install). Two collaborators are stubbed and proved
elsewhere: the no-seed check (test_delegation_render, against the hop
checkout) and derive-mounts, which needs the config's paths to exist on this
machine (test_partition_activation)."""

import argparse
import contextlib
import hashlib
import io
import json
import shlex
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import activation_install as ai
import amap_sandy as prov
import delegation_render as dr
import fleet_keys as fk
import hop_router as hp
import partition_activation as pa
import partition_evidence as pe
import partition_setup as ps
import test_activation_install as tai
from test_hub_runtime import setUpModule, tearDownModule  # noqa: F401 -- the fixture's pins, restored
from test_partition_evidence import NOW, build


class A1(tai.A3):

    def setUp(self):
        super().setUp()
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.t = Path(td.name)
        (self.t / "run").mkdir()
        self.overlay = self.t / "overlay.json"
        self.overlay.write_bytes(b'{"host_setup": {"fixture": 1}}')
        self.live = self.t / "router.json"
        self.live.write_text(json.dumps(self.doc, indent=2) + "\n")
        self.spec = SimpleNamespace(**{k: getattr(self.spec, k) for k in (
            "partition", "router", "keys", "gate", "overlay_pin", "hub", "fleet_keys", "hops")},
            secrets=SimpleNamespace(run_dir=str(self.t / "run"), writer_dir="/opt/ex/libexec"),
            runtime_of=self.spec.runtime_of)
        self.policy = {"fleet_domain": tai.FLEET_DOMAIN, "hop_link": {
            "link": "link-a", "trusted_fleet_hosts": list(self.link.trusted), "egress": True,
            "delegation": {"inbound": False}}}
        self.gate = []
        for mod, name, value in ((prov.ps, "gate_problems", lambda *a, **k: self.gate),
                                 (dr, "no_seed_problem", lambda d, checkout: None),
                                 (dr, "no_seed_problem_bytes", lambda b, checkout: None),
                                 (fk, "_read", lambda p: self.inv),
                                 (prov.ha, "overlay_path", lambda o: self.overlay),
                                 (pa, "derived_mounts", lambda checkout, final, staged: [
                                     {"type": "bind", "source": "/srv/x/state", "target": "/srv/x/state",
                                      "readonly": False}])):
            self.addCleanup(setattr, mod, name, getattr(mod, name))
            setattr(mod, name, value)

    def tree(self):
        return {str(p): p.read_bytes() for p in sorted(self.t.rglob("*")) if p.is_file()}

    def prepare(self, apply=False):
        before, out, err = self.tree(), io.StringIO(), io.StringIO()
        args = argparse.Namespace(apply=apply, overlay=None, prepare=True)
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = prov.run_prepare(args, self.policy, self.doc, self.live, apply=apply, spec=self.spec)
            except Exception as e:  # a crash is not an outcome
                self.fail(f"run_prepare raised {e!r}")
        return rc, before, self.tree(), out.getvalue(), err.getvalue()


class PrepareTest(A1):

    def test_a_dry_run_writes_nothing_and_prints_the_steps(self):
        rc, before, after, out, err = self.prepare()
        self.assertEqual((rc, after), (0, before), err)
        self.assertIn("its sha256, A3's --activation-sha256:", out)
        self.assertIn(" place ", out)
        lines = [l.strip() for l in out.splitlines() if l.strip().startswith("/usr/bin/sudo ")]
        self.assertEqual(len(lines), 2, out)
        a2, d7 = (shlex.split(l) for l in lines)
        self.assertEqual(a2, d7 + ["--prospective"])            # 7b and 7d differ only by the flag
        self.assertEqual(a2[0], "/usr/bin/sudo")

    def test_apply_writes_exactly_the_record_into_the_run_directory(self):
        rc, before, after, out, err = self.prepare(apply=True)
        self.assertEqual(rc, 0, err)
        source = str(self.t / "run" / ps.ACTIVATION)
        self.assertEqual(set(after) - set(before), {source})
        record = after[source]
        approved = pa.parse_activation(record)
        sha = hashlib.sha256(record).hexdigest()
        self.assertIn(f"A3's --activation-sha256: {sha}", out)
        self.assertIn(f"--sha256 {sha}", out)                      # the place step binds the record's bytes
        self.assertIn(f"--activation-sha256 {sha}", out)           # so do both weekly argv
        self.assertEqual(approved["final_config_path"], self.spec.keys.local_config)
        self.assertEqual(approved["spec"]["env"]["ROUTER_CONFIG"], self.spec.keys.local_config)
        self.assertEqual(approved["spec"]["image"], self.spec.router.image_digest)

    def test_each_refusal_writes_nothing(self):
        def no_delegation():
            self.policy["hop_link"].pop("delegation")

        def gate_shut():
            self.gate = ["the record is absent"]

        def inventory_pin():
            fk._read = lambda p: self.inv + b" "

        def no_seed():
            dr.no_seed_problem_bytes = lambda b, checkout: "a key table refused"
        for label, change in (("no delegation member", no_delegation), ("the gate", gate_shut),
                              ("the inventory pin", inventory_pin), ("the no-seed check", no_seed)):
            with self.subTest(label):
                self.setUp()
                change()
                rc, before, after, out, err = self.prepare(apply=True)
                self.assertEqual((rc, after), (2, before), out + err)
                self.assertIn("nothing was written", err)

    def test_a_live_delegation_prints_the_de_activate_note(self):
        self.live.write_text(json.dumps(dict(self.doc, delegation={}), indent=2) + "\n")
        self.assertIn("De-activate first", self.prepare()[3])

    def test_a3_accepts_what_a1_wrote(self):
        """The chain: A1's record, A2's evidence bound to it, then A3."""
        rc, _, after, out, err = self.prepare(apply=True)
        self.assertEqual(rc, 0, err)
        record = after[str(self.t / "run" / ps.ACTIVATION)]
        approved = pa.parse_activation(record)
        staged = approved["staged"].encode()
        evidence = build(bindings={"local_router": pa.activation_binding(approved["spec"], staged)})
        self.placed = {self.spec.partition.evidence_dir + "/activation.json": record,
                       self.spec.partition.evidence_dir + "/partition-r1.json": evidence}
        self.staged = staged
        final, why = self.run_a3(activation_sha256=hashlib.sha256(record).hexdigest())
        self.assertIsNotNone(final, why)
        self.assertEqual(final, pa.final_bytes(staged, json.loads(evidence)[pe.TOKEN_MEMBER]))


class HopHostRefusalsTest(unittest.TestCase):
    """A1 runs inside install's rendering path, so every hop-host check comes
    first: a refusal there writes nothing and A1 is never reached."""

    def test_each_install_refusal_comes_before_a1(self):
        reached = []
        stubs = {
            (prov, "router_sibling_path"): lambda home: Path("/nonexistent/router.json"),
            (prov, "load_membership"): lambda home, boxes: {},
            (prov, "sibling_state_dir"): lambda home, explicit: Path("/nonexistent/state"),
            (prov, "render_router_sibling"): lambda *a, **k: {"_doc": {}, "_warnings": []},
            (prov, "run_prepare"): lambda *a, **k: reached.append(1) or 0,
            (hp, "plugin_nesting_problems"): lambda doc, roots: [],
            (hp, "tunable_problems"): lambda doc: [],
            (hp, "loader_roots"): lambda doc, checkout: [],
            (hp, "validate_with_hop_router"): lambda doc, checkout: None,
        }
        rows = {
            "the hop checkout off its pin": {(prov, "hop_router_keys"): lambda *a, **k: (None, ["the hop checkout "
                                                                                              "is not at its pin"])},
            "the plugin's sha256": {(prov, "hop_router_keys"): lambda *a, **k: (None, ["the plugin is not its pin"])},
            "local_config not the rendered path": {(prov, "hop_router_keys"): lambda *a, **k: (
                None, ["keys.local_config is not the router config this renders"])},
            "a nested plugin": {(prov, "hop_router_keys"): lambda *a, **k: ({}, []),
                                (hp, "plugin_nesting_problems"): lambda doc, roots: ["the plugin is nested"]},
            "a tunable out of bounds": {(prov, "hop_router_keys"): lambda *a, **k: ({}, []),
                                        (hp, "tunable_problems"): lambda doc: ["a tunable out of bounds"]},
            "the hop loader refusing": {(prov, "hop_router_keys"): lambda *a, **k: ({}, []),
                                        (hp, "validate_with_hop_router"): lambda doc, checkout: "refused"},
        }
        for label, extra in rows.items():
            with self.subTest(label):
                reached.clear()
                applied = {**stubs, **extra}
                for (mod, name), value in applied.items():
                    self.addCleanup(setattr, mod, name, getattr(mod, name))
                    setattr(mod, name, value)
                args = argparse.Namespace(apply=True, prepare=True, state_dir=None, overlay=None,
                                          decommission_hop=False)
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    rc = prov.run_render_router(args, Path("/nonexistent"), [], {}, apply=True)
                self.assertEqual((rc, reached), (2, []))
