"""m1_b6c: the B6c receipt's byte forms, the O-n file map and the atomic
write. The artifact's known answer is the router's own vector for V = 0
(router/tests/vectors/sender_age_policy_digest.json at the hop pin, read by
path here, never retyped). Every other value is invented."""

import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

import m1_b6c as b
from _workspace import HOP_ROUTER_ROOT

VECTORS = HOP_ROUTER_ROOT / "router" / "tests" / "vectors" / "sender_age_policy_digest.json"


class BytesTest(unittest.TestCase):

    def test_the_artifact_is_the_routers_known_answer(self):
        cases = json.loads(VECTORS.read_text())["cases"]
        for case in cases:
            with self.subTest(v=case["min_sender_age_s"]):
                got = b.artifact_bytes(case["min_sender_age_s"])
                self.assertEqual(got.decode("utf-8"), case["canonical"])
                self.assertEqual(b.digest(b.sha256(got)), case["digest"])

    def test_v0_is_exactly_these_bytes(self):
        self.assertEqual(b.artifact_bytes(0), b'{"min_sender_age_s":0,"v":1}')

    def test_a_bad_v_is_refused(self):
        for v in (True, False, -1, b.MIN_SENDER_AGE_MAX_S + 1, 1.0, "0"):
            with self.subTest(v=v), self.assertRaises(b.Refused):
                b.artifact_bytes(v)

    def test_the_receipt_is_one_ascii_line(self):
        data = b.receipt_bytes({"z": 1, "a": "\u00e9", "m": [True, None]})
        self.assertEqual(data, b'{"a":"\\u00e9","m":[true,null],"z":1}\n')
        self.assertEqual(data.count(b"\n"), 1)
        data.decode("ascii")

    def test_nan_is_refused(self):
        with self.assertRaises(b.Refused):
            b.canonical({"x": float("nan")})

    def test_a_digest_needs_64_lowercase_hex(self):
        self.assertEqual(b.digest("a" * 64), "sha256:" + "a" * 64)
        for bad in ("A" * 64, "a" * 63, "sha256:" + "a" * 64, None):
            with self.subTest(bad=bad), self.assertRaises(b.Refused):
                b.digest(bad)


class StrictLoadsTest(unittest.TestCase):

    def test_a_plain_object_loads(self):
        self.assertEqual(b.strict_loads(b'{"a":1}', "x"), {"a": 1})

    def test_a_repeated_key_is_refused_at_any_depth(self):
        for data in (b'{"a":1,"a":2}', b'{"o":{"k":1,"k":1}}'):
            with self.subTest(data=data), self.assertRaisesRegex(b.Refused, "appears twice"):
                b.strict_loads(data, "x")

    def test_nan_and_infinity_are_refused(self):
        for data in (b'{"a":NaN}', b'{"a":Infinity}', b'{"a":-Infinity}'):
            with self.subTest(data=data), self.assertRaises(b.Refused):
                b.strict_loads(data, "x")

    def test_non_ascii_is_refused(self):
        with self.assertRaisesRegex(b.Refused, "not ASCII"):
            b.strict_loads('{"a":"\u00e9"}'.encode("utf-8"), "x")


class KeyAndModeTest(unittest.TestCase):

    def test_good_keys(self):
        for k in ("feature.json", "payload/relay", "payload/bin/inbox-mcp-vol"):
            self.assertEqual(b.check_key(k), k)

    def test_bad_keys(self):
        for k in ("", "/abs", "a/../b", "./a", "a//b", "a/", "a b", "a/\u00e9", None):
            with self.subTest(k=k), self.assertRaises(b.Refused):
                b.check_key(k)

    def test_the_mode_class(self):
        self.assertEqual(b.mode_class(0o100755, "payload/relay"), b.MODE_EXEC)
        self.assertEqual(b.mode_class(0o100555, "payload/relay"), b.MODE_EXEC)
        self.assertEqual(b.mode_class(0o100644, "payload/x"), b.MODE_PLAIN)

    def test_a_partial_x_pattern_is_refused(self):
        for m in (0o100744, 0o100710, 0o100701):
            with self.subTest(m=oct(m)), self.assertRaisesRegex(b.Refused, "partial execute"):
                b.mode_class(m, "payload/x")

    def test_a_fixed_name_is_never_executable(self):
        with self.assertRaisesRegex(b.Refused, "never executable"):
            b.mode_class(0o100755, "router.json")


class WalkTest(unittest.TestCase):

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.t = Path(os.path.realpath(td.name))
        self.vm = self.t / "vm1"
        (self.vm / "payload" / "bin").mkdir(parents=True)
        for name in b.FIXED_FILES:
            (self.vm / name).write_text(name + "\n")
            os.chmod(self.vm / name, 0o644)
        (self.vm / "payload" / "relay").write_text("#!/bin/sh\n")
        os.chmod(self.vm / "payload" / "relay", 0o755)
        (self.vm / "payload" / "bin" / "tool").write_text("tool\n")
        os.chmod(self.vm / "payload" / "bin" / "tool", 0o644)

    def test_the_map(self):
        files = b.walk(str(self.vm))
        self.assertEqual(sorted(files), sorted(list(b.FIXED_FILES) + ["payload/relay", "payload/bin/tool"]))
        self.assertEqual(files["payload/relay"]["mode"], b.MODE_EXEC)
        self.assertEqual(files["router.json"],
                         {"mode": b.MODE_PLAIN, "sha256": b.sha256(b"router.json\n")})

    def test_the_on_manifest_sha_is_canonical_without_lf(self):
        files = b.walk(str(self.vm))
        self.assertEqual(b.on_manifest_sha256(files), b.sha256(b.canonical(files)))
        self.assertFalse(b.canonical(files).endswith(b"\n"))

    def test_a_link_refuses(self):
        os.symlink("relay", self.vm / "payload" / "alias")
        with self.assertRaisesRegex(b.Refused, "neither a regular file nor a directory"):
            b.walk(str(self.vm))

    def test_a_fifo_refuses(self):
        os.mkfifo(self.vm / "payload" / "pipe")
        with self.assertRaisesRegex(b.Refused, "neither a regular file nor a directory"):
            b.walk(str(self.vm))

    def test_a_hard_link_refuses(self):
        os.link(self.vm / "payload" / "relay", self.vm / "payload" / "relay2")
        with self.assertRaisesRegex(b.Refused, "more than one link"):
            b.walk(str(self.vm))

    def test_an_empty_directory_refuses(self):
        (self.vm / "payload" / "empty").mkdir()
        with self.assertRaisesRegex(b.Refused, "holds no file"):
            b.walk(str(self.vm))

    def test_a_missing_fixed_name_refuses(self):
        (self.vm / "m1-role.json").unlink()
        with self.assertRaisesRegex(b.Refused, "lacks m1-role.json"):
            b.walk(str(self.vm))

    def test_a_stray_top_level_file_refuses(self):
        (self.vm / "extra.json").write_text("{}")
        with self.assertRaisesRegex(b.Refused, "outside the fixed names"):
            b.walk(str(self.vm))

    def test_no_payload_file_refuses(self):
        shutil.rmtree(self.vm / "payload")
        with self.assertRaisesRegex(b.Refused, "payload/ holds no file"):
            b.walk(str(self.vm))

    def test_a_linked_root_refuses(self):
        os.symlink(self.vm, self.t / "via")
        with self.assertRaisesRegex(b.Refused, "without following a link"):
            b.walk(str(self.t / "via"))


class NetValuesTest(unittest.TestCase):

    def test_every_input_refuses_until_the_shape_is_fixed(self):
        for data in (b"{}", b'{"vm1":{}}', b""):
            with self.subTest(data=data), self.assertRaisesRegex(b.Refused, "not fixed yet"):
                b.net_values(data)


class WriteReceiptTest(unittest.TestCase):

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.out = Path(os.path.realpath(td.name))

    def test_the_receipt_is_written_and_the_temp_is_gone(self):
        doc = {"schema": b.SCHEMA, "v": 0}
        sha = b.write_receipt(str(self.out), doc)
        data = (self.out / b.RECEIPT_NAME).read_bytes()
        self.assertEqual(data, b.receipt_bytes(doc))
        self.assertEqual(sha, b.sha256(data))
        self.assertFalse((self.out / b.RECEIPT_TEMP).exists())
        self.assertEqual(stat.S_IMODE((self.out / b.RECEIPT_NAME).stat().st_mode), 0o444)

    def test_an_existing_receipt_is_never_replaced(self):
        (self.out / b.RECEIPT_NAME).write_bytes(b"old\n")
        with self.assertRaisesRegex(b.Refused, "already exists"):
            b.write_receipt(str(self.out), {"v": 0})
        self.assertEqual((self.out / b.RECEIPT_NAME).read_bytes(), b"old\n")

    def test_a_leftover_temp_refuses(self):
        (self.out / b.RECEIPT_TEMP).write_bytes(b"partial")
        with self.assertRaisesRegex(b.Refused, "left from an earlier run"):
            b.write_receipt(str(self.out), {"v": 0})
        self.assertFalse((self.out / b.RECEIPT_NAME).exists())


if __name__ == "__main__":
    unittest.main()


# --- the receipt's parsers, pre-flight and reader -----------------------------------

HEX40 = "1" * 40
TREE40 = "2" * 40
ART = b.artifact_bytes(0)
ART_DIGEST = b.digest(b.sha256(ART))
NET = {"vm1": {"vm": "m1vm1", "hostname": "m1vm1", "own_domain": "m1vm1.example.org"},
       "vm2": {"vm": "m1vm2", "hostname": "m1vm2", "own_domain": "m1vm2.example.org"}}
NET_BYTES = b'{"stand-in":"NET has not fixed its shape"}\n'


def role_doc(n):
    role, host = ("H1", "m1vm1") if n == "vm1" else ("H2", "m1vm2")
    return {"schema": "amap-m1-role/1", "role": role, "vm": host, "hostname": host,
            "fd": f"sandy.{host}.internal", "own_domain": f"{host}.example.org",
            "ids": {"op": 1000}, "units": ["m1-state-check.service"], "fleet_policy_digest": ART_DIGEST,
            "start": {"uid_1": 1001, "group_add": 1002, "config": "/srv/m1-state/sandy/features/amap/router.json",
                      "image": "sha256:" + "d" * 64, "name": f"amap-rl-{n}"}}


def build_out(t: Path, mutate=None):
    """A complete OUT built from this module's own functions, since no real
    B6c render exists yet; NET's values are a stand-in dict given straight to
    preflight(), because net_values() refuses every input until NET fixes its
    shape. `mutate(parts)` edits the parts before anything is written."""
    out = t / "OUT"
    out.mkdir()
    parts = {"artifact": ART, "net": NET_BYTES, "man": b'', "vms": {}}
    for n in b.VMS:
        role = role_doc(n)
        parts["vms"][n] = {
            "feature.json": json.dumps({"feature": {"min_sender_age_s": 0, "fleet_domain": role["fd"]}}).encode(),
            "router.json": json.dumps({"min_sender_age_s": 0, "state_dir": "/s"}).encode(),
            "m1-role.json": b.canonical(role),
            "deploy-overlay.json": b'{"registry":{},"host_setup":{}}',
            "payload/relay": b"#!/bin/sh\n",
            "payload/INBOX-POLICY.md": b"policy\n",
        }
    man = {"checkouts": {b.DEPLOY_CHECKOUT: {"head": HEX40, "tree": TREE40}},
           "builds": {"router1": {"commit": b.ENROL_COMMIT}}}
    parts["man"] = json.dumps(man).encode()
    if mutate:
        mutate(parts)
    (out / b.ARTIFACT_NAME).write_bytes(parts["artifact"])
    (out / b.NET_VALUES_NAME).write_bytes(parts["net"])
    vms, facts = {}, {}
    for n in b.VMS:
        root = out / n
        for key, data in parts["vms"][n].items():
            p = root / key
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
            os.chmod(p, 0o755 if key == "payload/relay" else 0o644)
        files = b.walk(str(root))
        role = b.parse_role_manifest((root / "m1-role.json").read_bytes())
        vms[n] = {"role": role["role"], "vm": role["vm"], "hostname": role["hostname"],
                  "own_domain": role["own_domain"], "fd": role["fd"], "files": files,
                  "on_manifest_sha256": b.on_manifest_sha256(files), "role_sha256": files["m1-role.json"]["sha256"],
                  "carried_digest": role["fleet_policy_digest"], "router_min_sender_age_s": 0,
                  "start": role["start"], "state_dir": "/srv/m1-state/router-state", "run_dir": "/srv/m1-state/run",
                  "router_container": role["start"]["name"]}
        facts[n] = {"files": files, "role": role,
                    "router_age": b.parse_router((root / "router.json").read_bytes()),
                    "feature": b.parse_feature((root / "feature.json").read_bytes())}
    doc = {"schema": b.SCHEMA, "deploy_commit": HEX40, "deploy_tree": TREE40, "hop_pin": b.ENROL_COMMIT,
           "t0_manifest_sha256": b.sha256(parts["man"]), "net_values_sha256": b.sha256(parts["net"]),
           "sandy_schema_version": "4", "v": 0,
           "fleet_artifact": {"path": b.ARTIFACT_NAME, "sha256": b.sha256(parts["artifact"]),
                              "digest": b.digest(b.sha256(parts["artifact"])), "schema_v": 1, "min_sender_age_s": 0},
           "vms": vms}
    doc["preflight"] = b.preflight(doc, man=parts["man"], vectors=VECTORS.read_bytes(), hop_ancestry=True,
                                   artifact=parts["artifact"], net=NET, vms=facts)
    b.write_receipt(str(out), doc)
    return out, parts["man"], doc


class ParsersTest(unittest.TestCase):

    def test_a_role_manifest_parses_and_closes(self):
        self.assertEqual(b.parse_role_manifest(b.canonical(role_doc("vm1")))["role"], "H1")
        bad = dict(role_doc("vm1"))
        del bad["fleet_policy_digest"]
        with self.assertRaisesRegex(b.Refused, "must have exactly"):
            b.parse_role_manifest(b.canonical(bad))
        for k, v in (("role", "H3"), ("hostname", "Bad_Host"), ("fleet_policy_digest", "a" * 64)):
            with self.subTest(k=k), self.assertRaises(b.Refused):
                b.parse_role_manifest(b.canonical(dict(role_doc("vm1"), **{k: v})))

    def test_router_json_must_carry_an_int(self):
        self.assertEqual(b.parse_router(b'{"min_sender_age_s":0}'), 0)
        for data in (b'{}', b'{"min_sender_age_s":false}', b'{"min_sender_age_s":0.0}'):
            with self.subTest(data=data), self.assertRaises(b.Refused):
                b.parse_router(data)

    def test_the_artifact_must_be_canonical(self):
        self.assertEqual(b.parse_artifact(ART), 0)
        for data in (b'{"v":1,"min_sender_age_s":0}', b'{"min_sender_age_s":0,"v":2}',
                     b'{"min_sender_age_s":0,"v":1}\n', b'{"min_sender_age_s":0,"v":1,"x":1}'):
            with self.subTest(data=data), self.assertRaises(b.Refused):
                b.parse_artifact(data)

    def test_the_known_answer_is_read_by_path(self):
        self.assertEqual(b.known_answer(VECTORS.read_bytes(), 0), ART_DIGEST)
        doubled = json.loads(VECTORS.read_text())
        doubled["cases"].append(doubled["cases"][0])
        with self.assertRaisesRegex(b.Refused, "not exactly one"):
            b.known_answer(json.dumps(doubled).encode(), 0)
        with self.assertRaisesRegex(b.Refused, "not exactly one"):
            b.known_answer(VECTORS.read_bytes(), 17)

    def test_man_is_read_by_key_lookup(self):
        man = {"checkouts": {b.DEPLOY_CHECKOUT: {"head": HEX40, "tree": TREE40}}, "builds": {"router1": {"commit": HEX40}}}
        self.assertEqual(b.man_values(json.dumps(man).encode()), (HEX40, TREE40, HEX40))
        with self.assertRaisesRegex(b.Refused, "MAN lacks"):
            b.man_values(b'{"checkouts":{}}')


class ReadReceiptTest(unittest.TestCase):
    """A correct OUT passes every check and refuses only at NET's step; one
    tampering at a time refuses earlier, by name."""

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.t = Path(os.path.realpath(td.name))
        self.vectors = VECTORS.read_bytes()

    def read(self, out, man, ancestry=True):
        return b.read_receipt(str(out), man, self.vectors, ancestry)

    def test_a_correct_out_reaches_nets_refusal(self):
        out, man, _ = build_out(self.t)
        with self.assertRaisesRegex(b.Refused, "NET's net-values shape is not fixed yet"):
            self.read(out, man)

    def test_an_extra_top_level_entry_refuses(self):
        out, man, _ = build_out(self.t)
        (out / "stray").write_text("x")
        with self.assertRaisesRegex(b.Refused, "OUT's top level"):
            self.read(out, man)

    def test_a_changed_payload_byte_refuses(self):
        out, man, _ = build_out(self.t)
        p = out / "vm1" / "payload" / "INBOX-POLICY.md"
        os.chmod(p, 0o644)
        p.write_bytes(b"other\n")
        with self.assertRaisesRegex(b.Refused, "is not the walk of OUT/vm1"):
            self.read(out, man)

    def test_a_changed_mode_refuses(self):
        out, man, _ = build_out(self.t)
        os.chmod(out / "vm2" / "payload" / "relay", 0o644)
        with self.assertRaisesRegex(b.Refused, "is not the walk of OUT/vm2"):
            self.read(out, man)

    def test_another_man_refuses(self):
        out, man, _ = build_out(self.t)
        with self.assertRaisesRegex(b.Refused, "t0_manifest_sha256"):
            self.read(out, man + b" ")

    def test_a_noncanonical_receipt_refuses(self):
        out, man, doc = build_out(self.t)
        p = out / b.RECEIPT_NAME
        os.chmod(p, 0o644)
        p.write_bytes(json.dumps(doc, indent=1).encode() + b"\n")
        with self.assertRaisesRegex(b.Refused, "canonical form"):
            self.read(out, man)

    def test_a_false_stored_preflight_refuses(self):
        out, man, doc = build_out(self.t)
        doc["preflight"]["fd_differ"] = False
        p = out / b.RECEIPT_NAME
        os.chmod(p, 0o644)
        p.unlink()
        b.write_receipt(str(out), doc)
        with self.assertRaisesRegex(b.Refused, "all-true"):
            self.read(out, man)

    def test_a_missing_input_refuses(self):
        out, man, _ = build_out(self.t)
        for args in ((None, self.vectors, True), (man, None, True), (man, self.vectors, None)):
            with self.subTest(args=[type(a).__name__ for a in args]), self.assertRaisesRegex(b.Refused, "needs"):
                b.read_receipt(str(out), *args)

    def test_a_crossed_role_pair_refuses(self):
        def cross(parts):
            parts["vms"]["vm1"]["m1-role.json"], parts["vms"]["vm2"]["m1-role.json"] = (
                parts["vms"]["vm2"]["m1-role.json"], parts["vms"]["vm1"]["m1-role.json"])
        out, man, doc = build_out(self.t, cross)
        self.assertFalse(doc["preflight"]["manifest_is_receipt_vm1"])
        self.assertFalse(doc["preflight"]["manifest_is_receipt_vm2"])
        with self.assertRaisesRegex(b.Refused, "vms.vm1.role is not H1"):
            self.read(out, man)


class PreflightTest(unittest.TestCase):
    """The pre-flight's own equalities, each broken alone."""

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.t = Path(os.path.realpath(td.name))

    def test_a_correct_out_is_all_true(self):
        _, _, doc = build_out(self.t)
        self.assertTrue(doc["preflight"] and all(doc["preflight"].values()), doc["preflight"])

    def test_each_break_is_named(self):
        cases = {
            "router_value_vm1": lambda p: p["vms"]["vm1"].__setitem__("router.json", b'{"min_sender_age_s":7}'),
            "feature_value_vm2": lambda p: p["vms"]["vm2"].__setitem__(
                "feature.json", json.dumps({"feature": {"min_sender_age_s": 9, "fleet_domain": "sandy.m1vm2.internal"}}).encode()),
            "deploy_commit_is_man": lambda p: p.__setitem__("man", p["man"].replace(HEX40.encode(), b"3" * 40)),
        }
        for key, mutate in cases.items():
            with self.subTest(key=key):
                t = self.t / key
                t.mkdir()
                _, _, doc = build_out(t, mutate)
                self.assertFalse(doc["preflight"][key], doc["preflight"])
                self.assertEqual([k for k, ok in doc["preflight"].items() if not ok], [key])

    def test_no_ancestry_is_false(self):
        out, man, doc = build_out(self.t)
        self.assertFalse(b.preflight(doc, man=man, vectors=VECTORS.read_bytes(), hop_ancestry=False,
                                     artifact=ART, net=NET,
                                     vms={n: {"files": doc["vms"][n]["files"],
                                              "role": b.parse_role_manifest(b.canonical(role_doc(n))),
                                              "router_age": 0,
                                              "feature": (0, doc["vms"][n]["fd"])} for n in b.VMS})["hop_pin_has_enrol"])
