"""The SHIPPED `payload/submit-server`, executed under /bin/sh.

It derives AMAP_SELF for the connector's inbox-submit server, which uses it
only to mark the agent's own roster entry in `peers`, then execs the server.
Unlike the relay it is never fatal: `submit` is the agent's only way to send.
Each test copies the shipped file into a temporary directory beside a fake
`bin/inbox-submit` that prints what it was given, and points the hardcoded
session-file line at a staged file, as `_wrapper.py` does for the relay.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Dict, Optional, Tuple

HERE = Path(__file__).resolve().parents[1]
WRAPPER = HERE / "payload" / "submit-server"
SESSION_LINE = "SANDY_SESSION_FILE=/etc/sandy-session.json"
FAKE_SERVER = """#!/bin/sh
printf 'args=%s\\n' "$*"
if [ -n "${AMAP_SELF+x}" ]; then printf 'AMAP_SELF=%s\\n' "$AMAP_SELF"; fi
"""


def run(*, domain: Optional[str] = "agents.example.org", session: Optional[dict] = None,
        inherited_self: Optional[str] = None) -> Tuple[int, Dict[str, str], str]:
    text = WRAPPER.read_text()
    assert SESSION_LINE in text, "the session-file line is not in payload/submit-server"
    with TemporaryDirectory() as d:
        root = Path(d)
        session_path = root / "sandy-session.json"
        if session is not None:
            session_path.write_text(json.dumps(session))
        script = root / "submit-server"
        script.write_text(text.replace(SESSION_LINE, f"SANDY_SESSION_FILE={session_path}", 1))
        script.chmod(0o755)
        (root / "bin").mkdir()
        server = root / "bin" / "inbox-submit"
        server.write_text(FAKE_SERVER)
        server.chmod(0o755)
        env = {"PATH": os.environ.get("PATH", ""), "HOME": d}
        if domain is not None:
            env["AMAP_FLEET_DOMAIN"] = domain
        if inherited_self is not None:
            env["AMAP_SELF"] = inherited_self
        r = subprocess.run(["/bin/sh", str(script), "mcp"], env=env,
                           capture_output=True, text=True, timeout=30)
    values = dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line)
    return r.returncode, values, r.stderr


class SubmitServerTest(unittest.TestCase):

    def test_it_derives_the_address_and_execs_the_server_with_its_args(self):
        rc, values, err = run(session={"sandbox_name": "alpha-1a2b3c4d"})
        self.assertEqual(rc, 0, err)
        self.assertEqual(values["AMAP_SELF"], "alpha-1a2b3c4d@agents.example.org")
        self.assertEqual(values["args"], "mcp")

    def test_every_gap_leaves_it_unset_and_still_starts_the_server(self):
        rows = (("no domain", dict(domain=None, session={"sandbox_name": "a-1"}), "AMAP_FLEET_DOMAIN"),
                ("empty domain", dict(domain="", session={"sandbox_name": "a-1"}), "AMAP_FLEET_DOMAIN"),
                ("no session file", dict(session=None), "unreadable"),
                ("no name in it", dict(session={"schema": 1}), "no sandbox_name"))
        for name, kwargs, says in rows:
            with self.subTest(name):
                rc, values, err = run(**kwargs)
                self.assertEqual(rc, 0, err)
                self.assertEqual(values["args"], "mcp", "the server started")
                self.assertNotIn("AMAP_SELF", values)
                self.assertIn(says, err)

    def test_an_inherited_value_never_survives_a_gap(self):
        """Only the derivation sets it: a value already in the environment is
        dropped when the address cannot be derived."""
        rc, values, err = run(domain=None, session={"sandbox_name": "a-1"},
                              inherited_self="someone-else@agents.example.org")
        self.assertEqual(rc, 0, err)
        self.assertNotIn("AMAP_SELF", values)

    def test_it_is_on_the_payload_and_executable(self):
        if str(HERE) not in sys.path:
            sys.path.insert(0, str(HERE))
        import amap_sandy as prov
        sources = {rel: (src, x) for rel, src, x in prov.payload_sources(Path("/fake/bin"))}
        self.assertEqual(sources[prov.SUBMIT_SERVER_NAME], (WRAPPER, True))
        self.assertTrue(os.access(WRAPPER, os.X_OK))


if __name__ == "__main__":
    unittest.main()
