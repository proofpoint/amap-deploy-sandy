"""The SHIPPED session lister, `payload/handoff-sessions`, executed under bash.

The daemon runs it as `AMAP_DELIVERY_SESSION_SOURCE` and injects into the one
`claude` row it prints. Identity comes from sandy's published pane-identity
contract: the tmux session "sandy", the `@sandy_pane_agent` pane option in
multi-agent mode, `$SANDY_AGENT` for the sole pane in single-agent mode, and
`$SANDY_AGENT` as spawn order, never `pane_index`.

Nothing here touches the real tmux or /proc. `tmux` is a fake on PATH that
prints staged `list-panes` rows, and the file's three hardcoded roots (the
process table, Claude Code's socket directory and its key directory) are
rewritten to a staged tree, the way `_wrapper.py` rewrites the relay's
session-file path. The shipped file carries no test hook of its own.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import amap_sandy as prov  # noqa: E402
import _wrapper  # noqa: E402

LISTER = HERE / "payload" / prov.SESSION_SOURCE_NAME
ROOT_LINES = ("PROC=/proc", "SOCK_DIR=/tmp/cc-socks", 'KEY_DIR="$HOME/.claude/sessions"')

# A pane: (pane_index, pane_pid, @sandy_pane_agent or "" when unset,
#          agent process name under it, or None for an idle shell).
Pane = Tuple[int, int, str, Optional[str]]


class _Staged:
    """A process table, socket directory and key directory for `panes`, and a
    fake `tmux` that prints them only when asked for the session "sandy"."""

    def __init__(self, root: Path, panes: List[Pane], *, session_exists: bool = True):
        self.root = root
        self.proc = root / "proc"
        self.socks = root / "s"          # short: a unix socket path has a length limit
        self.keys = root / "keys"
        for d in (self.proc, self.socks, self.keys):
            d.mkdir()
        self._servers: List[socket.socket] = []
        rows = []
        for idx, pane_pid, tag, agent in panes:
            self._proc(pane_pid, "bash", 1)
            if agent:
                apid = pane_pid + 1
                self._proc(apid, agent, pane_pid)
                if agent == "claude":
                    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    s.bind(str(self.socks / f"{apid}.sock"))
                    self._servers.append(s)
                    (self.keys / f"{apid}.k1.key").write_text("{}")
            rows.append(f"{idx}\t{pane_pid}\t{tag}")
        bindir = root / "bin"
        bindir.mkdir()
        (root / "panes").write_text("".join(r + "\n" for r in rows))
        # Refuses anything but `list-panes -t sandy`: contract fact 1.
        body = ('[ "$1" = list-panes ] && [ "$2" = -t ] && [ "$3" = sandy ] || exit 1\n'
                + (f'cat "{root / "panes"}"\n' if session_exists
                   else 'echo "no server running" >&2; exit 1\n'))
        tmux = bindir / "tmux"
        tmux.write_text("#!/bin/sh\n" + body)
        tmux.chmod(0o755)
        self.bindir = bindir

    def _proc(self, pid: int, comm: str, ppid: int) -> None:
        d = self.proc / str(pid)
        d.mkdir()
        (d / "stat").write_text(f"{pid} ({comm}) S {ppid} {pid} {pid} 0 -1\n")
        (d / "cmdline").write_bytes(f"/usr/bin/{comm}\0".encode())

    def close(self) -> None:
        for s in self._servers:
            s.close()


def run_lister(panes: List[Pane], sandy_agent: str, *,
               session_exists: bool = True) -> Tuple[int, str, List[Dict[str, str]]]:
    """`(rc, stderr, rows)`, each row keyed by the six column names."""
    text = LISTER.read_text()
    with TemporaryDirectory(dir="/tmp") as d:
        staged = _Staged(Path(d), panes, session_exists=session_exists)
        try:
            for line, repl in zip(ROOT_LINES, (f"PROC={staged.proc}",
                                               f"SOCK_DIR={staged.socks}",
                                               f"KEY_DIR={staged.keys}")):
                assert line in text, f"{line!r} is not in payload/{prov.SESSION_SOURCE_NAME}"
                text = text.replace(line, repl, 1)
            script = Path(d) / "lister"
            script.write_text(text)
            env = {"PATH": f"{staged.bindir}:{os.environ.get('PATH', '')}",
                   "HOME": d, "SANDY_AGENT": sandy_agent}
            r = subprocess.run([shutil.which("bash") or "/bin/bash", str(script)],
                               env=env, capture_output=True, text=True, timeout=30)
        finally:
            staged.close()
    cols = ("agent", "pane_index", "pane_pid", "agent_pid", "socket", "keyfile")
    rows = [dict(zip(cols, line.split("\t"))) for line in r.stdout.splitlines()]
    for row in rows:
        row["socket"] = os.path.basename(row["socket"])
        row["keyfile"] = os.path.basename(row["keyfile"])
    return r.returncode, r.stderr, rows


class TheRelayPointsTheDaemonAtTheShippedListerTest(unittest.TestCase):

    def test_the_session_source_is_the_lister_beside_the_wrapper(self):
        """Found through `$0` like the daemon, never a path sandy owns."""
        rc, err, env = _wrapper.run_wrapper(_wrapper.FOREIGN_LAYOUT)
        self.assertEqual(rc, 0, err)
        source = env["AMAP_DELIVERY_SESSION_SOURCE"]
        self.assertEqual(os.path.basename(source), prov.SESSION_SOURCE_NAME)
        self.assertTrue(source.startswith(os.path.realpath(tempfile.gettempdir())), source)

    def test_the_lister_is_on_the_payload_and_executable(self):
        sources = {rel: (src, x) for rel, src, x in prov.payload_sources(Path("/fake/bin"))}
        self.assertEqual(sources[prov.SESSION_SOURCE_NAME], (LISTER, True))
        self.assertTrue(os.access(LISTER, os.X_OK), f"{LISTER} is not executable")


class PaneIdentityContractTest(unittest.TestCase):

    def test_single_agent_the_sole_pane_is_SANDY_AGENT(self):
        """Single-agent mode sets no option; the one pane is `$SANDY_AGENT`."""
        rc, err, rows = run_lister([(0, 100, "", "claude")], "claude")
        self.assertEqual(rc, 0, err)
        self.assertEqual(rows, [{"agent": "claude", "pane_index": "0", "pane_pid": "100",
                                 "agent_pid": "101", "socket": "101.sock",
                                 "keyfile": "101.k1.key"}])

    def test_four_agent_grid_identity_is_the_option_not_pane_index(self):
        """Contract fact 4: in the four-agent grid pane_index 0/1/2/3 holds
        agents 1/4/2/3. Rows follow spawn order and carry each pane's own
        index; reading identity by index would swap agents 2, 3 and 4."""
        agents = "claude,codex,gemini,opencode"
        grid = [(0, 200, "claude", "claude"), (1, 500, "opencode", "opencode"),
                (2, 300, "codex", "codex"), (3, 400, "gemini", "gemini")]
        rc, err, rows = run_lister(grid, agents)
        self.assertEqual(rc, 0, err)
        self.assertEqual([(r["agent"], r["pane_index"], r["pane_pid"]) for r in rows],
                         [("claude", "0", "200"), ("codex", "2", "300"),
                          ("gemini", "3", "400"), ("opencode", "1", "500")])
        claude = rows[0]
        self.assertEqual((claude["socket"], claude["keyfile"]), ("201.sock", "201.k1.key"))
        self.assertEqual([r["socket"] for r in rows[1:]], ["-", "-", "-"])

    def test_a_multi_agent_pane_without_the_option_gets_no_row(self):
        """An unset option identifies nothing outside single-agent mode, even
        with a claude process under the pane."""
        rc, err, rows = run_lister([(0, 200, "", "claude"), (1, 300, "codex", "codex")],
                                   "claude,codex")
        self.assertEqual(rc, 0, err)
        self.assertEqual([r["agent"] for r in rows], ["codex"])

    def test_single_agent_with_a_second_pane_identifies_neither(self):
        """Two option-less panes are not "the sole pane": no guess, no row."""
        rc, err, rows = run_lister([(0, 100, "", "claude"), (1, 200, "", "claude")], "claude")
        self.assertEqual(rc, 0, err)
        self.assertEqual(rows, [])

    def test_no_sandy_session_is_zero_rows_not_a_failure(self):
        """The daemon reads a nonzero exit as "the helper failed" and zero
        rows as "no session yet"; a missing session is the second."""
        rc, err, rows = run_lister([(0, 100, "", "claude")], "claude", session_exists=False)
        self.assertEqual((rc, rows), (0, []), err)


if __name__ == "__main__":
    unittest.main()
