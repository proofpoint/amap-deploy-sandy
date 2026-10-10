"""The SHIPPED session lister, `payload/handoff-sessions`, executed under bash.

The daemon runs it as `AMAP_DELIVERY_SESSION_SOURCE` and injects into the one
`claude` row it prints. Identity comes from sandy's published pane-identity
contract: the tmux session "sandy", the `@sandy_pane_agent` pane option on
every pane sandy creates (multi-agent mode only before sandy 2.4.0),
`$SANDY_AGENT` for the sole pane of an untagged single-agent session, and
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
from typing import Callable, Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import amap_sandy as prov  # noqa: E402
import _wrapper  # noqa: E402

LISTER = HERE / "payload" / prov.SESSION_SOURCE_NAME
ROOT_LINES = ("PROC=/proc", 'SOCK_DIRS="/tmp/cc-socks /tmp/cc-socks-$(id -u)"',
              'KEY_DIR="$HOME/.claude/sessions"')

# A pane: (pane_index, pane_pid, @sandy_pane_agent or "" when unset,
#          agent process name under it, or None for an idle shell).
Pane = Tuple[int, int, str, Optional[str]]


class _Staged:
    """A process table, socket directory and key directory for `panes`, and a
    fake `tmux` that prints them only when asked for the session "sandy"."""

    def __init__(self, root: Path, panes: List[Pane], *, session_exists: bool = True,
                 fallback_socket: bool = False):
        self.root = root
        self.proc = root / "proc"
        self.socks = root / "s"          # short: a unix socket path has a length limit
        self.socks_uid = root / "u"      # the per-uid fallback directory
        self.socks_uid.mkdir()
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
                    where = self.socks_uid if fallback_socket else self.socks
                    s.bind(str(where / f"{apid}.sock"))
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

    def socket_for(self, pid: int) -> None:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(str(self.socks / f"{pid}.sock"))
        self._servers.append(s)
        (self.keys / f"{pid}.k1.key").write_text("{}")

    def session_file(self, pid: int, text: str) -> None:
        """Claude Code's `<pid>.json` beside the key files."""
        (self.keys / f"{pid}.json").write_text(text)

    def _proc(self, pid: int, comm: str, ppid: int) -> None:
        d = self.proc / str(pid)
        d.mkdir()
        (d / "stat").write_text(f"{pid} ({comm}) S {ppid} {pid} {pid} 0 -1\n")
        (d / "cmdline").write_bytes(f"/usr/bin/{comm}\0".encode())

    def close(self) -> None:
        for s in self._servers:
            s.close()


def run_lister(panes: List[Pane], sandy_agent: str, *, session_exists: bool = True,
               fallback_socket: bool = False,
               stage: Optional[Callable[["_Staged"], None]] = None,
               ) -> Tuple[int, str, List[Dict[str, str]]]:
    """`(rc, stderr, rows)`, each row keyed by the six column names. `stage`
    adds to the staged tree (session files, more processes) before the run."""
    text = LISTER.read_text()
    with TemporaryDirectory(dir="/tmp") as d:
        staged = _Staged(Path(d), panes, session_exists=session_exists,
                         fallback_socket=fallback_socket)
        if stage:
            stage(staged)
        try:
            for line, repl in zip(ROOT_LINES, (f"PROC={staged.proc}",
                                               f'SOCK_DIRS="{staged.socks} {staged.socks_uid}"',
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
        """With no option anywhere (sandy before 2.4.0), two panes are not
        "the sole pane": no guess, no row."""
        rc, err, rows = run_lister([(0, 100, "", "claude"), (1, 200, "", "claude")], "claude")
        self.assertEqual(rc, 0, err)
        self.assertEqual(rows, [])

    def test_a_tagged_single_agent_pane_beside_a_user_split_is_identified(self):
        """Sandy 2.4.0+ tags its single-agent pane too, so a user's shell
        split beside it no longer hides the agent. The split is at index 0 to
        show that position does not decide."""
        rc, err, rows = run_lister([(0, 100, "", None), (1, 200, "claude", "claude")],
                                   "claude")
        self.assertEqual(rc, 0, err)
        self.assertEqual([(r["agent"], r["pane_index"], r["socket"]) for r in rows],
                         [("claude", "1", "201.sock")])

    def test_agent_team_teammates_beside_a_tagged_lead_get_no_row(self):
        """Teammate panes run real claude processes with their own sockets,
        but sandy did not create them and they carry no option: only the
        lead is a target, so the daemon sees one claude row, not three."""
        panes = [(0, 100, "claude", "claude"), (1, 200, "", "claude"), (2, 300, "", "claude")]
        rc, err, rows = run_lister(panes, "claude")
        self.assertEqual(rc, 0, err)
        self.assertEqual([(r["pane_pid"], r["socket"]) for r in rows], [("100", "101.sock")])

    def test_a_socket_in_the_per_uid_fallback_directory_is_found(self):
        """Claude Code falls back to a private /tmp/cc-socks-<uid> when it
        cannot use /tmp/cc-socks. A lister that looked only in the default
        would find no socket, and the daemon would wait silently."""
        rc, err, rows = run_lister([(0, 100, "claude", "claude")], "claude",
                                   fallback_socket=True)
        self.assertEqual(rc, 0, err)
        self.assertEqual([(r["agent_pid"], r["socket"]) for r in rows], [("101", "101.sock")])

    def test_no_sandy_session_is_zero_rows_not_a_failure(self):
        """The daemon reads a nonzero exit as "the helper failed" and zero
        rows as "no session yet"; a missing session is the second."""
        rc, err, rows = run_lister([(0, 100, "", "claude")], "claude", session_exists=False)
        self.assertEqual((rc, rows), (0, []), err)


class AParkedSessionIsFollowedToItsSuccessorTest(unittest.TestCase):
    """A conversation sent to the background leaves the pane's claude alive
    with its socket, but parked: it queues a frame unread. The shape staged
    here is the one measured on a live sandbox: the pane's session file
    carries `parkedJobId`, the background session's carries the same
    `jobId`, and the background session descends from the pane's claude
    through Claude Code's own daemon processes (pane claude -> `claude daemon
    run` -> pty host -> background claude)."""

    PANE = [(0, 100, "claude", "claude")]        # the pane's claude is pid 101

    @staticmethod
    def parked(staged, *, successor_ppid=103, successor_socket=True,
               successor_json='{"pid": 104, "jobId": "505fa38b", "kind": "bg"}'):
        staged.session_file(101, '{"pid": 101, "status": "idle", "parkedJobId": "505fa38b"}')
        staged._proc(102, "claude", 101)          # `claude daemon run`: no socket
        staged._proc(103, "bg-pty-host", 102)
        staged._proc(104, "claude", successor_ppid)
        if successor_socket:
            staged.socket_for(104)
        if successor_json is not None:
            staged.session_file(104, successor_json)

    def test_a_live_pane_session_keeps_its_row(self):
        rc, err, rows = run_lister(self.PANE, "claude", stage=lambda st: st.session_file(
            101, '{"pid": 101, "status": "busy"}'))
        self.assertEqual(rc, 0, err)
        self.assertEqual([(r["agent_pid"], r["socket"]) for r in rows], [("101", "101.sock")])

    def test_the_successor_takes_the_one_row_with_its_own_socket_and_key(self):
        """Exactly one row, never the parked pid beside it: two rows would
        make the daemon refuse every notice as ambiguous_target."""
        rc, err, rows = run_lister(self.PANE, "claude", stage=self.parked)
        self.assertEqual(rc, 0, err)
        self.assertEqual(rows, [{"agent": "claude", "pane_index": "0", "pane_pid": "100",
                                 "agent_pid": "104", "socket": "104.sock",
                                 "keyfile": "104.k1.key"}])
        self.assertIn("parked", err)

    def test_no_session_file_carries_the_job_so_no_row(self):
        rc, err, rows = run_lister(self.PANE, "claude",
                                   stage=lambda st: self.parked(st, successor_json=None))
        self.assertEqual((rc, rows), (0, []), err)
        self.assertIn("505fa38b", err)

    def test_two_sessions_carrying_the_job_give_no_row(self):
        """Never guess between them, even when both are live under the pane."""
        def two(st):
            self.parked(st)
            st._proc(105, "claude", 103)
            st.socket_for(105)
            st.session_file(105, '{"pid": 105, "jobId": "505fa38b", "kind": "bg"}')
        rc, err, rows = run_lister(self.PANE, "claude", stage=two)
        self.assertEqual((rc, rows), (0, []), err)
        self.assertIn("2 session files", err)

    def test_a_successor_file_whose_pid_is_not_its_name_is_not_the_successor(self):
        rc, err, rows = run_lister(self.PANE, "claude", stage=lambda st: self.parked(
            st, successor_json='{"pid": 999, "jobId": "505fa38b"}'))
        self.assertEqual((rc, rows), (0, []), err)

    def test_a_successor_outside_the_pane_is_not_followed(self):
        """The session files are writable by any process in the sandbox, so
        a successor is believed only when the process tree agrees."""
        rc, err, rows = run_lister(self.PANE, "claude",
                                   stage=lambda st: self.parked(st, successor_ppid=1))
        self.assertEqual((rc, rows), (0, []), err)
        self.assertIn("not a live claude", err)

    def test_a_successor_without_a_socket_is_not_followed(self):
        rc, err, rows = run_lister(self.PANE, "claude",
                                   stage=lambda st: self.parked(st, successor_socket=False))
        self.assertEqual((rc, rows), (0, []), err)

    def test_a_session_file_that_does_not_parse_gives_no_row(self):
        rc, err, rows = run_lister(self.PANE, "claude",
                                   stage=lambda st: st.session_file(101, '{"pid": 101, "par'))
        self.assertEqual((rc, rows), (0, []), err)
        self.assertIn("does not parse", err)

    def test_parked_sessions_that_name_each_other_give_no_row(self):
        def loop(st):
            self.parked(st, successor_json='{"pid": 104, "jobId": "505fa38b", '
                                            '"parkedJobId": "a1"}')
            st.session_file(101, '{"pid": 101, "jobId": "a1", "parkedJobId": "505fa38b"}')
        rc, err, rows = run_lister(self.PANE, "claude", stage=loop)
        self.assertEqual((rc, rows), (0, []), err)
        self.assertIn("loop", err)

    def test_once_the_pane_claude_has_exited_the_background_session_gets_no_row(self):
        """Claude Code's daemon is then reparented away from the pane, so the
        background session is no longer under it. Nothing ties it to this
        pane, so it is not a target: the pane's row names no session and no
        socket, as it does for a pane whose claude has not started."""
        def gone(st):
            st._proc(102, "claude", 1)
            st._proc(104, "claude", 102)
            st.socket_for(104)
            st.session_file(104, '{"pid": 104, "jobId": "505fa38b", "kind": "bg"}')
        rc, err, rows = run_lister([(0, 100, "claude", None)], "claude", stage=gone)
        self.assertEqual(rc, 0, err)
        self.assertEqual([(r["agent_pid"], r["socket"]) for r in rows], [("-", "-")])


if __name__ == "__main__":
    unittest.main()
