"""The name.json checker the relay, the submit server and the Codex relay embed.

It is lifted out of the SHIPPED files, required to be byte-identical in
all three, and run directly, one row per way a file can fail the name schema:
exactly its five members, a 32-hex logical_id, an integer epoch of at least
1, a local part the registry could have assigned (and never 32 hex), and an
address that is <name>@<fleet domain>. The relay's and the submit server's
own tests prove each wrapper acts on the verdict.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from _registry import IDS

ROOT = Path(__file__).resolve().parent.parent
READERS = (ROOT / "payload" / "relay", ROOT / "payload" / "submit-server",
           ROOT / "payload" / "codex" / "relay")
DOMAIN = "fleet.example.org"
LID = "0123456789abcdef0123456789abcdef"


FIRST, LAST = "import json, os, re, sys\n", 'print("ok " + address)\n'


def checker(path: Path) -> str:
    text = path.read_text()
    start = text.index(FIRST)
    return text[start:text.index(LAST, start) + len(LAST)]


CHECKER = checker(READERS[0])


def doc(**over):
    d = {"schema": IDS.name_schema, "name": "gamma", "address": f"gamma@{DOMAIN}",
         "logical_id": LID, "epoch": 1}
    for k, v in over.items():
        if v is DROP:
            d.pop(k)
        else:
            d[k] = v
    return d


DROP = object()


def verdict(content) -> str:
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "name.json"
        path.write_text(content if isinstance(content, str) else json.dumps(content))
        env = {"PATH": os.environ.get("PATH", ""), "AMAP_FLEET_DOMAIN": DOMAIN,
               "AMAP_IDENTITY": IDS.name_schema}
        r = subprocess.run([sys.executable, "-c", CHECKER, str(path)], env=env,
                           capture_output=True, text=True, timeout=30)
    return r.stdout.strip()


class OneCheckerTest(unittest.TestCase):

    def test_every_reader_embeds_the_same_checker_once(self):
        for path in READERS[1:]:
            with self.subTest(path=path.name):
                self.assertEqual(checker(path), CHECKER)
        for path in READERS:
            self.assertEqual(path.read_text().count(FIRST), 1, path)
        self.assertIn("def no(why):", CHECKER)


class TheNameSchemaTest(unittest.TestCase):

    def test_a_name_json_the_registry_writes_is_accepted(self):
        self.assertEqual(verdict(doc()), f"ok gamma@{DOMAIN}")
        for name in ("a", "A1", "al.pha", "al_pha-2", "x" * 64, "0" * 31, "0" * 33):
            with self.subTest(name=name):
                self.assertEqual(verdict(doc(name=name, address=f"{name}@{DOMAIN}")),
                                 f"ok {name}@{DOMAIN}")

    def test_each_departure_from_the_schema_is_refused(self):
        rows = (
            ("no epoch", doc(epoch=DROP), "exactly schema, name"),
            ("no logical_id", doc(logical_id=DROP), "exactly schema, name"),
            ("an extra member", doc(note="x"), "exactly schema, name"),
            ("epoch 0", doc(epoch=0), "epoch"),
            ("epoch negative", doc(epoch=-1), "epoch"),
            ("epoch a bool", doc(epoch=True), "epoch"),
            ("epoch a string", doc(epoch="1"), "epoch"),
            ("epoch a float", doc(epoch=1.0), "epoch"),
            ("logical_id upper case", doc(logical_id=LID.upper()), "logical_id"),
            ("logical_id short", doc(logical_id=LID[:-1]), "logical_id"),
            ("logical_id with a newline", doc(logical_id=LID + "\n"), "logical_id"),
            ("name with a space", doc(name="Al pha", address=f"Al pha@{DOMAIN}"), "name is not"),
            ("name leading dash", doc(name="-x", address=f"-x@{DOMAIN}"), "name is not"),
            ("name leading dot", doc(name=".x", address=f".x@{DOMAIN}"), "name is not"),
            ("name too long", doc(name="x" * 65, address=f"{'x' * 65}@{DOMAIN}"), "name is not"),
            ("name empty", doc(name="", address=f"@{DOMAIN}"), "name is not"),
            ("name with a newline", doc(name="x\n", address=f"x\n@{DOMAIN}"), "name is not"),
            ("name 32 hex", doc(name=LID, address=f"{LID}@{DOMAIN}"), "name is not"),
            ("name 32 HEX", doc(name=LID.upper(), address=f"{LID.upper()}@{DOMAIN}"), "name is not"),
            ("name not a string", doc(name=7), "name is not"),
            ("address another domain", doc(address="gamma@other.example.org"), "is for domain"),
            ("address another local part", doc(address=f"delta@{DOMAIN}"), "local part"),
            ("address two at signs", doc(address=f"gamma@x@{DOMAIN}"), "no usable address"),
            ("address not a string", doc(address=None), "no usable address"),
            ("another schema", doc(schema=IDS.name_schema + "x"), "no schema"),
            ("not an object", [doc()], "no schema"),
            ("not JSON", "{torn", "unreadable"),
        )
        for name, content, says in rows:
            with self.subTest(name):
                v = verdict(content)
                self.assertTrue(v.startswith("no "), v)
                self.assertIn(says, v)


if __name__ == "__main__":
    unittest.main()
