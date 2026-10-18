"""activation_install: A3's refusals, each writing nothing, and the bytes it
hands to root's place step.

The no-seed check is delegation_render's, proved in its own tests; here it is
a recorder, so these rows reach every refusal before it and show which bytes
(f) checks. Every document is built by the producer the real flow uses:
A1's record by partition_activation.activation_record, A2's evidence by
partition_evidence.build, the staged bytes by partition_activation.staged_bytes.
"""

import hashlib
import json
import unittest

import activation_install as ai
import fleet_keys as fk
import host_setup as hs
import hop_router as hp
import partition_activation as pa
import partition_evidence as pe
from test_hop_render import FLEET_DOMAIN, link, router_doc, spec
from test_partition_evidence import AT, NOW, build
from test_partition_setup import doc as partition_doc
from test_hub_runtime import setUpModule, tearDownModule  # noqa: F401 -- the fixture's pins, restored

HOST = "alpha"
SPEC = {"name": "ex-up", "image": "sha256:" + "1" * 64, "user": "2101:2201", "network": "none", "restart": "no",
        "env": {}, "mounts": []}


def inventory_bytes():
    hosts = []
    for name, domain, n in (("alpha", FLEET_DOMAIN, 1), ("beta", "beta.internal", 2)):
        pub = hashlib.sha256(bytes([n])).digest()
        hosts.append({"name": name, "domains": [domain], "runtime": "amap.router@" + domain,
                      "public_key": pub.hex(), "key_id": hashlib.sha256(pub).hexdigest()})
    return json.dumps({"schema": fk.SCHEMA, "hosts": hosts}, sort_keys=True, separators=(",", ":")).encode()


class A3(unittest.TestCase):

    def setUp(self):
        d = partition_doc()
        d["router"] = {"image": {"name": "example.org/hop-router", "digest": "sha256:" + "c" * 64, "commit": "d" * 40},
                       "container": "ex-up"}
        d["overlay"]["pin"]["sha256"] = hp.PLUGIN_SHA256
        self.inv = inventory_bytes()
        d[fk.SECTION] = {"path": "/opt/ex/fleet-keys.json", "sha256": hashlib.sha256(self.inv).hexdigest()}
        self.spec = hs.load_spec(d)
        self.link = link(delegation={"inbound": False})
        self.doc = router_doc(hp.hop_keys(self.spec, self.link, FLEET_DOMAIN))
        self.pre = (json.dumps(self.doc, indent=2) + "\n").encode()
        self.validated = []
        self.staged = ai.render_staged(spec=self.spec, doc=self.doc, fleet_domain=FLEET_DOMAIN,
                                       trusted=self.link.trusted, inbound=False, validate=self.no_seed,
                                       read_inventory=lambda p: self.inv)
        self.record = pa.activation_record(host=HOST, spec=SPEC, staged=self.staged,
                                           final_config_path=self.spec.keys.local_config)
        self.evidence = build(bindings={"local_router": pa.activation_binding(SPEC, self.staged)})
        self.placed = {self.spec.partition.evidence_dir + "/activation.json": self.record,
                       self.spec.partition.evidence_dir + "/partition-r1.json": self.evidence}
        self.final_now = self.pre

    def no_seed(self, d):
        self.validated.append(d)
        return None

    def read_placed(self, path):
        if path not in self.placed:
            raise FileNotFoundError(path)
        return self.placed[path]

    def run_a3(self, **over):
        args = dict(spec=self.spec, host=HOST, doc=self.doc, pre_activation=self.pre, fleet_domain=FLEET_DOMAIN,
                    trusted=self.link.trusted, inbound=False, run_id="r1",
                    activation_sha256=hashlib.sha256(self.record).hexdigest(), gate=[], validate=self.no_seed,
                    validate_bytes=lambda b: self.validated.append(b) or None, read_placed=self.read_placed,
                    read_final=lambda p: self.final_now, read_inventory=lambda p: self.inv, now=NOW)
        args.update(over)
        return ai.activate(**args)

    def refused(self, letter, **over):
        final, why = self.run_a3(**over)
        self.assertIsNone(final)
        self.assertTrue(why and why[0].startswith(letter), why)
        return why[0]


class ActivateTest(A3):

    def test_a1_plus_t_is_the_staged_bytes_with_the_token_and_nothing_else(self):
        final, why = self.run_a3()
        self.assertEqual(why, [])
        token = json.loads(self.evidence)[pe.TOKEN_MEMBER]
        self.assertEqual(final, pa.final_bytes(self.staged, token))
        self.assertEqual(self.validated[-1], final)       # (f) checked the bytes to be placed

    def test_an_idempotent_rerun_passes(self):
        self.final_now = self.run_a3()[0]
        self.assertIsNotNone(self.run_a3()[0])

    def test_a_gate_that_does_not_hold_refuses(self):
        self.refused("(a)", gate=["G3: the overlay commit differs"])

    def test_the_activation_sha256_is_never_the_file_s_own(self):
        """A replaced record, root-placed from another A1, fails (b): the
        argument is A1's printed digest, compared, never taken from the file."""
        other = pa.activation_record(host=HOST, spec=dict(SPEC, user="2101:2202"), staged=self.staged,
                                     final_config_path=self.spec.keys.local_config)
        self.placed[self.spec.partition.evidence_dir + "/activation.json"] = other
        self.assertIn("not the", self.refused("(b)"))

    def test_a_malformed_digest_argument_refuses(self):
        final, why = self.run_a3(activation_sha256="A" * 64)
        self.assertIsNone(final)
        self.assertIn("64 lower-case hex", why[0])

    def test_an_unplaced_record_refuses(self):
        del self.placed[self.spec.partition.evidence_dir + "/activation.json"]
        self.refused("(b)")

    def test_the_named_run_s_evidence_must_hold(self):
        failing = build(bindings={"local_router": pa.activation_binding(SPEC, self.staged)},
                        verdicts={"P03": "FAIL"})
        for raw, words in ((failing, "not passing"),
                           (build(bindings={"local_router": "0" * 64}), "not produced for this A1"),
                           (build(bindings={"local_router": pa.activation_binding(SPEC, self.staged)},
                                  at="2026-10-01T00:00:00Z"), "not current")):
            with self.subTest(words=words):
                self.placed[self.spec.partition.evidence_dir + "/partition-r1.json"] = raw
                self.assertIn(words, self.refused("(c)"))
        self.refused("(c)", run_id="r2")

    def test_a_changed_rendering_since_a1_refuses(self):
        self.refused("(d)", inbound=True)

    def test_a_third_state_at_the_final_path_refuses(self):
        self.final_now = b'{"hand": "edited"}\n'
        self.refused("(e)")

    def test_a_no_seed_refusal_of_the_final_bytes_refuses(self):
        self.refused("(f)", validate_bytes=lambda b: "key_small_order: x")

    def test_the_place_step_binds_the_sha256_of_a1_plus_t(self):
        final, _ = self.run_a3()
        step = ai.place_step(self.spec, "/srv/op/run/router.activated.json", final)
        self.assertIn(f"--sha256 {hashlib.sha256(final).hexdigest()}", step)
        self.assertIn(f" place /srv/op/run/router.activated.json {self.spec.keys.local_config} ", step)


class CliTest(unittest.TestCase):

    def test_an_absent_digest_or_run_is_a_usage_error_never_a_default(self):
        import argparse
        import contextlib
        import io
        import amap_sandy as prov
        for activate, digest in (("r1", None), (None, "a" * 64), ("r1", "")):
            with self.subTest(activate=activate, digest=digest):
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    rc = prov.run_activation(argparse.Namespace(activate=activate, activation_sha256=digest),
                                             {}, {}, None, apply=True, spec=None)
                self.assertEqual(rc, 2)
                self.assertIn("go together", err.getvalue())


if __name__ == "__main__":
    unittest.main()


class StartInputsRealTest(A3):
    """host_setup.start_inputs over real records: the A1 record and the
    evidence as placed, the gate from the document. This document has no
    delegation_gate section, so the gate does not hold, and the start gate
    refuses A1's own block under its own current evidence."""

    def inputs(self):
        return hs.start_inputs(self.spec, True, {"read_placed": self.read_placed, "read_evidence": self.read_placed,
                                                 "rl_sha": "a" * 40})

    def test_the_real_records_are_read_and_a_shut_gate_refuses(self):
        import hub_keys as hk
        import router_health as rh
        sg = self.inputs()
        self.assertIsInstance(sg.approved, dict, sg.approved_why)
        self.assertEqual(pa.activation_record(host=HOST, spec=sg.approved["spec"], staged=self.staged,
                                              final_config_path=self.spec.keys.local_config), self.record)
        self.assertIs(sg.gate_ok, False)
        token = json.loads(self.evidence)[pe.TOKEN_MEMBER]
        doc, _, why = sg.named(token)
        self.assertEqual((doc["run_id"], why), ("r1", ""))
        final = pa.final_bytes(self.staged, token)
        found = hk.verify_start_delegation(self.spec.keys, (self.spec.keys.local_config, hashlib.sha256(final).hexdigest()),
                                           lambda p: final, hk.Signing(**dict(vars(sg), now=NOW)))
        self.assertEqual(found[1].result, rh.FAIL)
        self.assertIn("gate does not hold", str(found[1].actual))


class CommandTest(unittest.TestCase):
    """`install --activate` through install's real entry (run_sync): both
    arguments are checked, and every refusal propagates, before ANY write.
    The whole throwaway tree is compared before and after. Collaborators
    that would reach sandy, the engine or the hop checkout are stubbed, as in
    test_hop_render's InstallRenderTest; the activation verdict itself is
    activation_install.activate's, proved above, stubbed here per letter."""

    def setUp(self):
        import argparse
        import tempfile
        from pathlib import Path
        from types import SimpleNamespace
        import amap_sandy as prov
        import delegation_render as dr
        import partition_setup as ps
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.t = Path(td.name)
        self.home = self.t / "home"
        manifest = prov.feature_manifest_path(self.home)
        manifest.parent.mkdir(parents=True)
        manifest.write_text("{}\n")
        (self.t / "run").mkdir()
        self.prov, self.ai_ = prov, ai
        self.spec = SimpleNamespace(
            secrets=SimpleNamespace(run_dir=str(self.t / "run"), writer_dir="/opt/ex/libexec"),
            partition=SimpleNamespace(tools={"python3": "/usr/bin/python3"}), keys=SimpleNamespace(local_config="/x", group_add=(2100,)),
            gate=None, overlay_pin={"commit": "a" * 40}, hub=SimpleNamespace(host_label="alpha"),
            router=SimpleNamespace(container="router-a"), supervision=SimpleNamespace(kind="systemd"))
        self.policy = {"fleet_domain": FLEET_DOMAIN, "hop_link": {"link": "link-a", "trusted_fleet_hosts": ["beta.internal"],
                                                                  "egress": True, "delegation": {"inbound": False}}}
        self.verdict = (None, ["(a) the harness gate does not hold"])
        self.asked = []
        base = {"state_dir": str(self.t / "state"), "instances_dir": str(self.t / "inst"),
                "selected_json": str(self.t / "sel.json")}
        self.base = base

        def hop_router_keys(*a, **k):
            if k.get("spec_out") is not None:
                k["spec_out"].append(self.spec)
            return {}, []
        stubs = {
            (prov.fp, "load_policy"): lambda p: dict(self.policy),
            (prov, "discover_sandboxes"): lambda sandy: self.asked.append(sandy) or [],
            (prov, "router_sibling_path"): lambda home: self.t / "router.json",
            (prov, "load_membership"): lambda home, boxes: {},
            (prov, "sibling_state_dir"): lambda home, explicit: self.t / "state",
            (prov, "render_router_sibling"): lambda *a, **k: {"_doc": dict(base), "_warnings": []},
            (prov, "install_router_state_dir"): lambda *a, **k: self.fail("state_dir made on the activation path"),
            (prov, "run_provision"): lambda *a, **k: self.fail("provisioned on the activation path"),
            (prov, "hop_router_keys"): hop_router_keys,
            (prov, "validate_with_router"): lambda doc: None,
            (hp, "validate_with_hop_router"): lambda doc, checkout: None,
            (hp, "loader_roots"): lambda doc, checkout: [],
            (hp, "plugin_nesting_problems"): lambda doc, roots: [],
            (ps, "gate_problems"): lambda *a, **k: [],
            (ai, "activate"): lambda **k: self.verdict,
        }
        for (mod, name), value in stubs.items():
            self.addCleanup(setattr, mod, name, getattr(mod, name))
            setattr(mod, name, value)
        self.args = lambda **over: argparse.Namespace(**dict(
            dict(apply=True, activate="r1", activation_sha256="a" * 64, sandy="sandy", overlay=None, state_dir=None,
                 decommission_hop=False, connector_src=None, servers=None), **over))

    def tree(self):
        return {str(p): (p.read_bytes() if p.is_file() else None) for p in sorted(self.t.rglob("*"))}

    def install(self, args):
        import contextlib
        import io
        before = self.tree()
        err, self.out = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(self.out), contextlib.redirect_stderr(err):
            try:
                rc = self.prov.run_sync(args, self.home, self.t / "boxes")
            except Exception as e:  # a crash is not an outcome
                self.fail(f"run_sync raised {e!r}")
        return rc, before, self.tree(), err.getvalue()

    def test_either_argument_alone_writes_nothing_and_refuses(self):
        for over in (dict(activation_sha256=None), dict(activate=None), dict(activate="", activation_sha256="")):
            with self.subTest(args=over):
                rc, before, after, err = self.install(self.args(**over))
                self.assertEqual(rc, 2)
                self.assertEqual(after, before)
                self.assertIn("go together", err)
                self.assertEqual(self.asked, [])           # refused before sandy is asked anything

    def test_no_manifest_refuses_before_anything_is_read(self):
        self.prov.feature_manifest_path(self.home).unlink()
        rc, before, after, err = self.install(self.args())
        self.assertEqual((rc, after, self.asked), (2, before, []))
        self.assertIn("cannot activate — no ", err)

    def test_each_refusal_propagates_and_writes_nothing(self):
        for letter in ("(a)", "(b)", "(c)", "(d)", "(e)", "(f)"):
            with self.subTest(refusal=letter):
                self.verdict = (None, [f"{letter} refused for this row"])
                rc, before, after, err = self.install(self.args())
                self.assertEqual(rc, 2)
                self.assertEqual(after, before)
                self.assertIn(f"{letter} refused for this row", err)

    def test_a_passing_a3_writes_only_the_activation_config_into_the_run_directory(self):
        self.verdict = (b'{"activated": true}\n', [])
        rc, before, after, err = self.install(self.args())
        self.assertEqual(rc, 0, err)
        added = set(after) - set(before)
        self.assertEqual(added, {str(self.t / "run" / ai.ACTIVATED_NAME)})
        self.assertEqual({k: v for k, v in after.items() if k in before}, before)

    def test_a_dry_run_writes_nothing(self):
        self.verdict = (b'{"activated": true}\n', [])
        rc, before, after, err = self.install(self.args(apply=False))
        self.assertEqual((rc, after), (0, before))

    def test_a3_prints_every_step_through_a5_and_the_back_out_in_order(self):
        """The printed sequence is the operator's only copy of the order: the
        root place sits between A3's write and the host-file check, and the
        back-out gates the start on the HOST file carrying no delegation."""
        self.verdict = (b'{"activated": true}\n', [])
        rc, _, _, err = self.install(self.args())
        self.assertEqual(rc, 0, err)
        out = self.out.getvalue()
        order = ["1. done:", "2. as root:", " place ", "3. the host's", "4. A4:", "5. A5:", "back out in this order",
                 "B1.", "B2.", "B3. read the host's", "no delegation member", "STOP", "B4.", "B5. docker stop router-a",
                 "docker start router-a"]
        at = [out.find(m) for m in order]
        self.assertNotIn(-1, at, out)
        self.assertEqual(at, sorted(at), out)
        pre = hashlib.sha256(self.prov.sibling_text(self.base).encode()).hexdigest()
        self.assertIn(f"pre-activation sha256 {pre}", out)

    def test_a4s_restart_line_carries_the_principals_added_group(self):
        """A4's printed run.sh line adds the local router's group after its
        primary (the fixture's keys carry 2100), and adds none when there is
        none: the flag comes from the document, never a constant."""
        self.verdict = (b'{"activated": true}\n', [])
        rc, _, _, err = self.install(self.args())
        self.assertEqual(rc, 0, err)
        a4 = [l for l in self.out.getvalue().splitlines() if "4. A4:" in l]
        self.assertEqual(len(a4), 1, a4)
        self.assertRegex(a4[0], r"docker/run\.sh --config \S+ --detach --group-add 2100, from the hop checkout$")
        self.out.seek(0); self.out.truncate()
        self.spec.keys = __import__("types").SimpleNamespace(local_config="/x", group_add=())
        rc, _, _, err = self.install(self.args())
        self.assertEqual(rc, 0, err)
        a4 = [l for l in self.out.getvalue().splitlines() if "4. A4:" in l]
        self.assertRegex(a4[0], r"docker/run\.sh --config \S+ --detach, from the hop checkout$")

    def test_a_launchd_host_s_a5_step_names_verify_a5(self):
        """A5 on a launchd host is `verify --a5`; a systemd host's is plain
        verify, whose signing check must pass."""
        from types import SimpleNamespace
        self.verdict = (b'{"activated": true}\n', [])
        for kind, want, never in (("launchd", "5. A5: python3 amap-sandy.py verify --a5;", None),
                                  ("systemd", "5. A5: python3 amap-sandy.py verify; the signing check must PASS",
                                   "--a5")):
            with self.subTest(kind=kind):
                self.spec.supervision = SimpleNamespace(kind=kind)
                rc, _, _, err = self.install(self.args())
                self.assertEqual(rc, 0, err)
                self.assertIn(want, self.out.getvalue())
                if never:
                    self.assertNotIn(never, self.out.getvalue())
