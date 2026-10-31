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
