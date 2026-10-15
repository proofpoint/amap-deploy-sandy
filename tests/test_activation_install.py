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
from test_hop_render import FLEET_DOMAIN, link, router_doc
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
