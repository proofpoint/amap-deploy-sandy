"""m1vm/adm_stdin.py: the operator-side bytes for ADM's stdin. Each refusal,
the line forms ADM decodes (B6C d5.1 §2c.1), and the CLI's new-file write."""

import base64
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

M1VM = Path(__file__).resolve().parent.parent / "m1vm"
sys.path.insert(0, str(M1VM))
import adm_stdin  # noqa: E402
import vm_admit  # noqa: E402

PROGRAM = b"print('stand-in program')\n"
SHA = hashlib.sha256(PROGRAM).hexdigest()
RECEIPT = b'{"a":true,"q":"\\"","e":"\\u00e9"}\n'


def params(phase="A1", **over):
    p = {"phase": phase, "host": "H1", "adm": SHA}
    if phase not in ("A1", "A1r"):
        p["b6c_receipt_sha256"] = hashlib.sha256(RECEIPT).hexdigest()
    p.update(over)
    return p


class BuildTest(unittest.TestCase):
    def lines(self, data):
        head, _, rest = data.partition(b"\n")
        return head, rest

    def test_a1_form(self):
        data = adm_stdin.build(params(), PROGRAM, SHA)
        head, rest = self.lines(data)
        self.assertTrue(head.startswith(b'M1_ADM_PARAMS_B64 = "') and head.endswith(b'"'))
        self.assertEqual(rest, PROGRAM)
        value = head[len(b'M1_ADM_PARAMS_B64 = "'):-1].decode()
        self.assertEqual(vm_admit.params_from(value), params())

    def test_a2a_receipt_round_trips_exactly(self):
        data = adm_stdin.build(params("A2a"), PROGRAM, SHA, RECEIPT)
        l1, rest = self.lines(data)
        l2, rest = self.lines(rest)
        self.assertEqual(rest, PROGRAM)
        value = l2[len(b'M1_ADM_RECEIPT_B64 = "'):-1].decode()
        self.assertTrue(l2.startswith(b'M1_ADM_RECEIPT_B64 = "'))
        self.assertEqual(vm_admit.receipt_from(value, params("A2a")["b6c_receipt_sha256"]), RECEIPT)
        # As Python, the two lines bind str values that decode to the exact bytes.
        names = {}
        exec(l1 + b"\n" + l2 + b"\n", names)
        self.assertEqual(base64.b64decode(names["M1_ADM_RECEIPT_B64"], validate=True), RECEIPT)

    def test_refusals(self):
        cases = {
            "program not reviewed": lambda: adm_stdin.build(params(), PROGRAM + b"#", SHA),
            "adm not the program": lambda: adm_stdin.build(params(adm="0" * 64), PROGRAM, SHA),
            "A1 with a receipt": lambda: adm_stdin.build(params(), PROGRAM, SHA, RECEIPT),
            "A1 with the key": lambda: adm_stdin.build(params(b6c_receipt_sha256="0" * 64), PROGRAM, SHA),
            "A2a without a receipt": lambda: adm_stdin.build(params("A2a"), PROGRAM, SHA),
            "another receipt": lambda: adm_stdin.build(params("A2a"), PROGRAM, SHA, RECEIPT + b" "),
            "receipt over 1 MiB": lambda: adm_stdin.build(
                params("A2a", b6c_receipt_sha256=hashlib.sha256(b"x" * ((1 << 20) + 1)).hexdigest()),
                PROGRAM, SHA, b"x" * ((1 << 20) + 1)),
            "params over 64 KiB": lambda: adm_stdin.build(params(pad="x" * (1 << 16)), PROGRAM, SHA),
        }
        for name, call in cases.items():
            with self.subTest(name):
                with self.assertRaises(adm_stdin.Refused):
                    call()


class CliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        (self.tmp / "p.json").write_text(json.dumps(params("A2a")))
        (self.tmp / "prog.py").write_bytes(PROGRAM)
        (self.tmp / "r.json").write_bytes(RECEIPT)

    def cli(self, *extra, params_text=None):
        if params_text is not None:
            (self.tmp / "p.json").write_text(params_text)
        argv = ["--params", str(self.tmp / "p.json"), "--program", str(self.tmp / "prog.py"),
                "--program-sha256", SHA, "--out", str(self.tmp / "stdin.bin"), *extra]
        with redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
            rc = adm_stdin.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_writes_a_new_file(self):
        rc, out, _ = self.cli("--receipt", str(self.tmp / "r.json"))
        self.assertEqual(rc, 0)
        data = (self.tmp / "stdin.bin").read_bytes()
        self.assertEqual(out, f"ADM-STDIN OK sha256={hashlib.sha256(data).hexdigest()}\n")
        self.assertEqual((self.tmp / "stdin.bin").stat().st_mode & 0o777, 0o600)
        rc, _, err = self.cli("--receipt", str(self.tmp / "r.json"))  # never overwritten
        self.assertEqual(rc, 1)
        self.assertIn("ADM-STDIN REFUSED", err)

    def test_refusals_and_usage(self):
        rc, _, _ = self.cli()  # A2a without --receipt
        self.assertEqual(rc, 1)
        self.assertFalse((self.tmp / "stdin.bin").exists())
        # Valid but for one key given twice (the same value), so only the duplicate rule refuses it.
        dup = json.dumps(params("A2a"))[:-1] + ', "host": "H1"}'
        rc, _, _ = self.cli("--receipt", str(self.tmp / "r.json"), params_text=dup)
        self.assertEqual(rc, 1)
        self.assertFalse((self.tmp / "stdin.bin").exists())
        rc, _, _ = self.cli("--receipt", str(self.tmp / "r.json"), params_text='{"phase":NaN}')
        self.assertEqual(rc, 1)
        rc, _, _ = self.cli("--bogus", "x")
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
