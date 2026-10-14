"""payload/relay's measurement session source: the one override of the daemon's
session lister, honoured only for exactly <workspace>/.sandy/m4/session-source.

The SHIPPED relay is executed under /bin/sh, as tests/_wrapper.py does, with
its final `exec` replaced by `env`, so the test reads the daemon's whole
environment as the exec would have handed it over. The session file the
relay reads is staged in a temporary directory, its `workspace` naming a
temporary workspace whose `.sandy/m4/session-source` the tests create or
break one way at a time.
"""

import hashlib
import json
import os
import re
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import _wrapper

OVERRIDE = "AMAP_DELIVERY_SESSION_SOURCE_OVERRIDE"
SOURCE = "AMAP_DELIVERY_SESSION_SOURCE"
BLOCK = re.compile(r"# BEGIN measurement session source\n.*?# END measurement session source\n\n", re.S)
EXEC = re.compile(r'^exec "\$SELF_DIR/inbox-delivery" "\$@"$', re.M)
#: payload/relay as it was before the block was added (main at f5e3a833). The
#: block removed, the relay must be exactly that file: with the variable
#: absent the block is the only difference, and it does nothing.
BEFORE_SHA256 = "5b37f078b17200c03d691ffe7bacea00c7c4439daaf0242ffb2711d78989125d"


class Relay(unittest.TestCase):
    def setUp(self):
        td = TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = Path(td.name)
        self.ws = self.root / "workspace"
        self.m4 = self.ws / ".sandy" / "m4"
        self.m4.mkdir(parents=True)
        self.expected = str(self.ws / ".sandy" / "m4" / "session-source")
        self.session = self.root / "sandy-session.json"
        self.session.write_text(json.dumps({"sandbox_name": "box-1", "workspace": str(self.ws)}))
        self.payload = self.root / "payload"
        self.payload.mkdir()
        self.layout = {k: str(self.root / k) for k in ("home", "inbox", "outbox", "peer")}

    def lister(self, path=None):
        p = Path(path or self.expected)
        p.write_text("#!/bin/sh\n")
        p.chmod(0o755)
        return str(p)

    def run_relay(self, value=None, *, text=None):
        """(rc, stderr, env lines) for the relay with `value` as the override."""
        text = _wrapper.WRAPPER.read_text() if text is None else text
        text = _wrapper.with_session_file(text, self.session)
        script, n = EXEC.subn("exec env", text)
        self.assertEqual(n, 1, "the daemon's exec line is not in payload/relay")
        path = self.payload / "relay"
        path.write_text(script)
        env = {"HOME": self.layout["home"], "PATH": os.environ.get("PATH", ""), "SANDY_AGENT": "claude",
               _wrapper.LANE_EXPORT["inbox"]: self.layout["inbox"],
               _wrapper.LANE_EXPORT["outbox"]: self.layout["outbox"],
               _wrapper.LANE_EXPORT["peer"]: self.layout["peer"]}
        if value is not None:
            env[OVERRIDE] = value
        r = subprocess.run(["/bin/sh", str(path)], env=env, capture_output=True)
        return r.returncode, r.stderr.decode(), r.stdout

    def source_of(self, out):
        lines = dict(l.split("=", 1) for l in out.decode().splitlines() if "=" in l)
        self.assertNotIn(OVERRIDE, lines, "the override reached the daemon")
        return lines[SOURCE]

    def shipped(self):
        return str(self.payload / "handoff-sessions")


class AbsentTest(Relay):
    def test_without_the_variable_the_daemon_gets_exactly_what_it_got_before(self):
        """Byte for byte: the relay with the block and the relay without it
        hand the daemon the same environment and say the same on stderr."""
        with_block = self.run_relay()
        without = self.run_relay(text=BLOCK.sub("", _wrapper.WRAPPER.read_text()))
        self.assertEqual(with_block, without)
        self.assertEqual(with_block[0], 0, with_block[1])
        self.assertEqual(self.source_of(with_block[2]), self.shipped())

    def test_the_block_is_the_only_change_to_the_relay(self):
        stripped = BLOCK.sub("", _wrapper.WRAPPER.read_text())
        self.assertNotEqual(stripped, _wrapper.WRAPPER.read_text(), "the block markers are gone")
        self.assertEqual(hashlib.sha256(stripped.encode()).hexdigest(), BEFORE_SHA256)


class HonouredTest(Relay):
    def test_exactly_the_m4_session_source_is_used_and_said(self):
        rc, err, out = self.run_relay(self.lister())
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.source_of(out), self.expected)
        self.assertIn(f"relay: MEASUREMENT session source in use: {self.expected}", err)


class RefusedTest(Relay):
    """Each one: the shipped lister, one loud line naming the value, and the
    variable kept from the daemon."""

    def refused(self, value, why):
        rc, err, out = self.run_relay(value)
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.source_of(out), self.shipped())
        lines = [l for l in err.splitlines() if l.startswith("relay: REFUSED")]
        self.assertEqual(len(lines), 1, err)
        self.assertIn(f"{OVERRIDE}={value}:", lines[0])
        self.assertIn(why, lines[0])
        self.assertIn("using the shipped session lister", lines[0])

    def test_a_symbolic_link_at_the_path(self):
        target = self.lister(self.root / "elsewhere")
        os.symlink(target, self.expected)
        self.refused(self.expected, "it is a symbolic link")

    def test_another_file_under_dot_sandy(self):
        self.refused(self.lister(self.ws / ".sandy" / "config"), "its real path is not exactly")

    def test_the_workspace_secrets(self):
        self.refused(self.lister(self.ws / ".sandy" / ".secrets"), "its real path is not exactly")

    def test_a_missing_file(self):
        self.refused(self.expected, "it does not exist")

    def test_a_directory(self):
        os.mkdir(self.expected)
        self.refused(self.expected, "it is not a regular file")

    def test_a_real_file_through_a_symlinked_m4(self):
        """lstat sees a regular file at the end; only the literal comparison
        of the real path catches the linked directory above it."""
        real = self.root / "real-m4"
        real.mkdir()
        self.lister(real / "session-source")
        self.m4.rmdir()
        os.symlink(real, self.m4)
        self.refused(self.expected, "its real path is not exactly")

    def test_the_host_path_of_the_same_workspace(self):
        """The variable must carry the CONTAINER path the session file names;
        a path to the same layout anywhere else is refused."""
        host = self.root / "host-view" / ".sandy" / "m4"
        host.mkdir(parents=True)
        self.refused(self.lister(host / "session-source"), "its real path is not exactly")

    def test_a_relative_or_empty_value(self):
        self.refused(".sandy/m4/session-source", "it is not an absolute path")
        self.refused("", "it is not an absolute path")

    def test_a_session_file_without_a_workspace(self):
        self.session.write_text(json.dumps({"sandbox_name": "box-1"}))
        self.refused(self.lister(), "the session file names no absolute workspace")


if __name__ == "__main__":
    unittest.main()
