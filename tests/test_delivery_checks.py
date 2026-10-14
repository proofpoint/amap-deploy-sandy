"""delivery_checks: the lister mode, the named-session posture, the daemon's
build against the pin, and the unhandled peer notices.

WHERE THE SHAPES COME FROM.
- `claude_sessions` is built the way sandy's `--print-state` writer builds
  it (sandy 52967c3, the `claude_sessions` block of the per-sandbox loop):
  `null`, or `{declared, status}`, where `declared` is the marker's list of
  `{slug, name, receives}` and `status` is `null` or `{launch_id,
  sessions: [{slug, state, session_id, name, inbound_pinned, drift,
  reason}]}`, read from `.sandy-sessions.tsv`. Its `drift` text is sandy's
  own: `-`, `none`, `unknown`, or `missing: a | b; extra: c` (the
  `_SANDY_CS_JS` drift mode); `inbound_pinned` is `-`, `yes`, `no` or
  `receiver`.
- A peer notice is `notice-<id>.json` holding `{contract_version, kind,
  message, notice_id, ts}`, measured in a running sandbox's peer lane; the
  ledger is the connector's `Ledger`: one empty `peer-<id>` per handled
  notice.
- The daemon's source is the connector checkout's real `bin/inbox-delivery`
  (at its pin in CI); the history tests use a scratch repository holding
  two versions of it.
"""

import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import amap_sandy as prov
import delivery_checks as dc

FEATURE_DIR = prov.CONTAINER_FEATURE_DIR
MCP_PAIR = f"--mcp-config {FEATURE_DIR}/mcp-servers.json"
PROMPT_PAIR = f"--append-system-prompt-file {FEATURE_DIR}/INBOX-POLICY.md"

GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.org",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}


def git(*args, cwd):
    r = subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True,
                       env={**os.environ, **GIT_ENV}, timeout=60)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def row(slug, state="up", pinned="yes", drift="none", reason="-"):
    return {"slug": slug, "state": state, "session_id": f"{slug}-0000", "name": slug,
            "inbound_pinned": pinned, "drift": drift, "reason": reason}


DECLARED = [{"slug": "designer", "name": "designer", "receives": []},
            {"slug": "monitor", "name": "monitor", "receives": ["cross_session"]}]


def named_record(rows, declared=None):
    """A sandbox whose last launch declared a `monitor` claimant and a
    `designer` that does not receive (the bug's own shape)."""
    return {"claude_sessions": {"declared": DECLARED if declared is None else declared,
                                "status": None if rows is None else
                                {"launch_id": "L1", "sessions": rows}},
            "marker": {"state": "present", "sandy_version": "2.9.0", "launched_at": "x"}}


def marker_doc(declared):
    """The host copy of the launch marker; `None` for one written before
    the key existed."""
    doc = {"schema": 1, "sandy_version": "2.8.1-dev"}
    if declared is not None:
        doc["claude_sessions"] = declared
    return doc


def healthy_rows():
    return [row("designer"), row("monitor", pinned="receiver")]


PRESENT = {"marker": {"state": "present"}}


class ModeTest(unittest.TestCase):
    def mode(self, record, marker):
        return dc.session_mode(record, marker)[0]

    def test_no_record_from_sandy_cannot_be_told(self):
        self.assertIsNone(self.mode(None, marker_doc([])))
        [p], _ = dc.verify_sessions("box-1", None, FEATURE_DIR, marker=marker_doc([]))
        self.assertTrue(p.startswith("delivery mode unknown: box-1: sandy reports no record"), p)

    def test_without_the_field_the_host_marker_decides_and_named_is_named(self):
        """A --print-state without claude_sessions over a launch that ran
        them (a 2.8.1-dev marker with two sessions, as measured): named,
        never pane, and its posture unknown."""
        self.assertEqual(self.mode(PRESENT, marker_doc(DECLARED)), dc.NAMED)
        self.addCleanup(setattr, dc, "DEPLOYED_LISTER_SERVES_NAMED_SESSIONS",
                        dc.DEPLOYED_LISTER_SERVES_NAMED_SESSIONS)
        dc.DEPLOYED_LISTER_SERVES_NAMED_SESSIONS = True
        [p], notes = dc.verify_sessions("box-1", PRESENT, FEATURE_DIR, marker=marker_doc(DECLARED))
        self.assertTrue(p.startswith("named-session posture unknown: box-1: sandy reports no "
                                     "session status"), p)
        self.assertEqual(notes, [])

    def test_null_with_a_named_host_marker_is_named(self):
        rec = {"claude_sessions": None, **PRESENT}
        self.assertEqual(self.mode(rec, marker_doc(DECLARED)), dc.NAMED)

    def test_the_host_marker_saying_none_is_pane(self):
        for marker in (marker_doc([]), marker_doc(None)):
            self.assertEqual(self.mode(PRESENT, marker), dc.PANE, marker)
            self.assertEqual(dc.verify_sessions("box-1", PRESENT, FEATURE_DIR, marker=marker),
                             ([], []))

    def test_without_the_field_and_an_unreadable_host_marker_cannot_be_told(self):
        for marker in ("unreadable (x): denied", {"claude_sessions": "x"}, ["not", "a", "doc"]):
            self.assertIsNone(self.mode(PRESENT, marker), marker)

    def test_no_host_marker_is_not_launched_only_when_sandy_says_so(self):
        rec = {"marker": {"state": "absent"}}
        problems, [n] = dc.verify_sessions("box-1", rec, FEATURE_DIR, marker=None)
        self.assertEqual(problems, [])
        self.assertIn("not launched yet", n)
        self.assertIsNone(self.mode(PRESENT, None))

    def test_print_state_and_the_host_marker_disagreeing_cannot_be_told(self):
        rec = {"claude_sessions": {"declared": [], "status": None}, **PRESENT}
        self.assertIsNone(self.mode(rec, marker_doc(DECLARED)))
        self.assertIsNone(self.mode(named_record(healthy_rows()), marker_doc([])))

    def test_print_state_is_read_where_the_host_marker_cannot_be(self):
        self.assertEqual(self.mode(named_record(healthy_rows()), None), dc.NAMED)
        self.assertEqual(self.mode({"claude_sessions": {"declared": [], "status": None}},
                                   "unreadable"), dc.PANE)

    def test_a_shape_this_does_not_know_cannot_be_told(self):
        for cs in ({"declared": "x"}, ["x"]):
            self.assertIsNone(self.mode({"claude_sessions": cs, **PRESENT}, marker_doc([])))

    def test_named_mode_is_a_problem_while_the_lister_serves_panes_only(self):
        problems, _ = dc.verify_sessions("box-1", named_record(healthy_rows()), FEATURE_DIR,
                                         marker=marker_doc(DECLARED))
        self.assertEqual([p for p in problems if p.startswith("named sessions unserved: box-1:")],
                         problems)
        self.assertTrue(problems)

    def test_the_unserved_problem_follows_the_lister_capability(self):
        self.addCleanup(setattr, dc, "DEPLOYED_LISTER_SERVES_NAMED_SESSIONS",
                        dc.DEPLOYED_LISTER_SERVES_NAMED_SESSIONS)
        dc.DEPLOYED_LISTER_SERVES_NAMED_SESSIONS = True
        problems, notes = dc.verify_sessions("box-1", named_record(healthy_rows()), FEATURE_DIR,
                                             marker=marker_doc(DECLARED))
        self.assertEqual(problems, [])
        self.assertIn("as sandy reports", notes[0])


class PostureTest(unittest.TestCase):
    """Each posture fault, one at a time, must raise the finding that names
    it, and the clean note appears only when every row was judged."""

    def setUp(self):
        self.addCleanup(setattr, dc, "DEPLOYED_LISTER_SERVES_NAMED_SESSIONS",
                        dc.DEPLOYED_LISTER_SERVES_NAMED_SESSIONS)
        dc.DEPLOYED_LISTER_SERVES_NAMED_SESSIONS = True

    def run_rows(self, rows, declared=None):
        return dc.verify_sessions("box-1", named_record(rows, declared), FEATURE_DIR,
                                  marker=marker_doc(DECLARED if declared is None else declared))

    def problems(self, rows, declared=None):
        return self.run_rows(rows, declared)[0]

    def unknown(self, rows):
        problems, notes = self.run_rows(rows)
        self.assertEqual(len(problems), 1, problems)
        self.assertTrue(problems[0].startswith("named-session posture unknown: box-1:"), problems)
        self.assertEqual(notes, [], "a clean note over a row that was not judged")
        return problems[0]

    def test_a_healthy_posture_has_no_problem_and_a_clean_note(self):
        problems, [n] = self.run_rows(healthy_rows())
        self.assertEqual(problems, [])
        self.assertIn("every other session pinned to refuse", n)

    def test_a_non_claimant_without_the_refuse_pin(self):
        [p] = self.problems([row("designer", pinned="no"), row("monitor", pinned="receiver")])
        self.assertIn("'designer' does not receive cross_session but lacks the refuse pin", p)

    def test_every_other_non_claimant_pin_value_is_unknown(self):
        for value in ("-", None, "receiver", "YES", 1):
            with self.subTest(value=value):
                designer = row("designer", pinned=value)
                if value is None:
                    del designer["inbound_pinned"]
                self.assertIn("'designer' reports inbound_pinned",
                              self.unknown([designer, row("monitor", pinned="receiver")]))

    def test_every_claimant_pin_value_but_receiver_is_unknown(self):
        for value in ("-", "yes", "no", None):
            with self.subTest(value=value):
                self.assertIn("'monitor' reports inbound_pinned",
                              self.unknown([row("designer"), row("monitor", pinned=value)]))

    def test_every_drift_value_sandy_cannot_judge_is_unknown(self):
        for value in ("-", "unknown", "", None, 3, "missing: ", "something else",
                      "missing: a; missing: b"):
            with self.subTest(value=value):
                self.assertIn("reports drift",
                              self.unknown([row("designer", drift=value),
                                            row("monitor", pinned="receiver")]))

    def test_a_claimant_created_without_this_features_arguments(self):
        [p] = self.problems([row("designer"),
                             row("monitor", pinned="receiver",
                                 drift=f"missing: {MCP_PAIR} | {PROMPT_PAIR}")])
        self.assertIn("'monitor' was created without", p)
        self.assertIn(MCP_PAIR, p)

    def test_a_claimant_missing_only_another_features_argument_is_not_ours_to_report(self):
        problems, [n] = self.run_rows([row("designer"),
                                       row("monitor", pinned="receiver",
                                           drift="missing: --effort high")])
        self.assertEqual(problems, [])

    def test_a_non_claimant_holding_this_features_arguments(self):
        [p] = self.problems([row("designer", drift=f"missing: --effort high; extra: {MCP_PAIR}"),
                             row("monitor", pinned="receiver")])
        self.assertIn(f"'designer' does not receive cross_session but holds {MCP_PAIR}", p)

    def test_a_claimant_that_is_not_up(self):
        [p] = self.problems([row("designer"),
                             row("monitor", state="missing", pinned="receiver", reason="no job")])
        self.assertTrue(p.startswith("named-session claimant down: box-1:"), p)

    def test_no_status_from_the_container_is_unknown_not_clean(self):
        [p] = self.problems(None)
        self.assertTrue(p.startswith("named-session posture unknown: box-1:"), p)

    def test_a_declared_session_with_no_status_row_is_unknown(self):
        self.assertIn("'designer' has no status row",
                      self.unknown([row("monitor", pinned="receiver")]))

    def test_no_claimant_is_a_problem(self):
        none = [{"slug": "a", "name": "a", "receives": []}]
        [p] = self.problems([row("a")], declared=none)
        self.assertIn("0 declared sessions receive cross_session", p)

    def test_two_claimants_is_a_problem(self):
        both = [{"slug": s, "name": s, "receives": ["cross_session"]} for s in ("a", "b")]
        [p] = self.problems([row("a", pinned="receiver"), row("b", pinned="receiver")],
                            declared=both)
        self.assertIn("2 declared sessions receive cross_session", p)


class Scratch(unittest.TestCase):
    """A scratch connector checkout holding two versions of the real daemon:
    the pin's bytes, and an older commit's with a narrower notice pattern."""

    real = (Path(prov.DEFAULT_CONNECTOR_SRC) / prov.DELIVERY_DAEMON_NAME).read_bytes()
    pattern_line = next(l for l in real.decode().splitlines()
                        if l.startswith(dc.NOTICE_RE_NAME + " = "))
    older = real.replace(pattern_line.encode(),
                         b'NOTICE_FILE_RE = re.compile(r"^notice-([a-f0-9]{32})\\.json$")')

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = Path(td.name)
        self.repo = self.root / "connector"
        (self.repo / "bin").mkdir(parents=True)
        git("init", "--quiet", "-b", "main", cwd=self.repo)
        self.commit(self.older, "older")
        self.old = git("rev-parse", "HEAD", cwd=self.repo)
        (self.repo / "README").write_text("unrelated\n")
        git("add", "-A", cwd=self.repo)
        git("commit", "--quiet", "-m", "unrelated", cwd=self.repo)
        self.commit(self.real, "pin")
        self.pin = git("rev-parse", "HEAD", cwd=self.repo)
        self.payload = self.root / "payload" / prov.DELIVERY_DAEMON_NAME
        self.payload.parent.mkdir()

    def commit(self, data, msg):
        (self.repo / dc.DAEMON_REL).write_bytes(data)
        git("add", "-A", cwd=self.repo)
        git("commit", "--quiet", "-m", msg, cwd=self.repo)

    def version(self, deployed, pinned=None):
        self.payload.write_bytes(deployed)
        return dc.daemon_version(self.payload, self.repo, pinned or self.pin)


class DaemonVersionTest(Scratch):
    def test_the_pins_bytes_are_a_note_naming_the_pin(self):
        v = self.version(self.real)
        self.assertEqual(v.problems, [])
        self.assertIn(self.pin[:12], v.notes[0])

    def test_another_commits_bytes_are_drift_naming_that_commit(self):
        v = self.version(self.older)
        [p] = v.problems
        self.assertTrue(p.startswith("daemon drift:"), p)
        self.assertIn(self.old[:12], p)
        self.assertIn(self.pin[:12], p)

    def test_drift_is_found_when_the_checkout_has_moved_past_the_pin(self):
        self.commit(self.real + b"\n# later\n", "later")
        v = self.version(self.older)
        self.assertTrue(v.problems[0].startswith("daemon drift:"), v.problems)

    def test_bytes_no_commit_has_are_unknown_naming_the_hash(self):
        edited = self.real + b"\n# a local edit\n"
        [p] = self.version(edited).problems
        self.assertTrue(p.startswith("daemon version unknown:"), p)
        self.assertIn(dc.sha256(edited), p)

    def test_a_pin_the_checkout_does_not_hold_is_unknown(self):
        [p] = self.version(self.real, pinned="f" * 40).problems
        self.assertTrue(p.startswith("daemon version unknown:"), p)
        self.assertIn("f" * 40, p)

    def test_no_checkout_is_unknown_not_a_pass(self):
        self.payload.write_bytes(self.real)
        v = dc.daemon_version(self.payload, None, self.pin)
        self.assertTrue(v.problems[0].startswith("daemon version unknown:"), v.problems)

    def test_the_notice_pattern_is_the_deployed_files_own(self):
        id40 = "a" * 40
        self.assertIsNotNone(self.version(self.real).notice_re.match(f"notice-{id40}.json"))
        self.assertIsNone(self.version(self.older).notice_re.match(f"notice-{id40}.json"))

    def test_drift_text_names_both_remedies(self):
        [p] = self.version(self.older).problems
        self.assertIn("move the pin by its own reviewed PR", p)
        self.assertNotIn("do not move", p)

    def test_a_companion_file_off_the_pin_is_drift_even_when_the_daemon_matches(self):
        """F-1's shape: inbox-delivery can be byte-identical across commits
        that differ elsewhere, so the other connector files are compared too."""
        (self.repo / "bin" / "inbox-submit").write_text("pinned\n")
        git("add", "-A", cwd=self.repo)
        git("commit", "--quiet", "-m", "submit", cwd=self.repo)
        pin = git("rev-parse", "HEAD", cwd=self.repo)
        companion = self.payload.parent / "bin" / "inbox-submit"
        companion.parent.mkdir()
        self.payload.write_bytes(self.real)
        companion.write_text("pinned\n")
        v = dc.daemon_version(self.payload, self.repo, pin,
                              companions=[(companion, "bin/inbox-submit")])
        self.assertEqual(v.problems, [])
        self.assertIn("1 other connector file(s) equal the siblings.json pin", v.notes[0])
        companion.write_text("an older build\n")
        v = dc.daemon_version(self.payload, self.repo, pin,
                              companions=[(companion, "bin/inbox-submit")])
        [p] = v.problems
        self.assertTrue(p.startswith("connector drift: the payload's inbox-submit"), p)
        self.assertEqual(v.notes, [])

    def test_a_companion_the_pin_does_not_have_is_unknown(self):
        companion = self.root / "payload" / "extra"
        companion.write_text("x")
        self.payload.write_bytes(self.real)
        v = dc.daemon_version(self.payload, self.repo, self.pin, companions=[(companion, "bin/extra")])
        self.assertTrue(v.problems[0].startswith("connector version unknown:"), v.problems)

    def test_a_pattern_not_built_by_re_compile_has_none(self):
        for call in (b'os.system("x")', b'regex.compile("^notice-(x)$")'):
            with self.subTest(call=call):
                v = self.version(self.real.replace(self.pattern_line.encode(),
                                                   b"NOTICE_FILE_RE = " + call))
                self.assertIsNone(v.notice_re)
                self.assertIn("is not re.compile of one literal", v.why)

    def test_a_pattern_capturing_no_id_has_none(self):
        v = self.version(self.real.replace(self.pattern_line.encode(),
                                           b'NOTICE_FILE_RE = re.compile(r"^notice-.+\\.json$")'))
        self.assertIsNone(v.notice_re)
        self.assertIn("captures no notice id", v.why)

    def test_a_daemon_without_the_pattern_has_none(self):
        v = self.version(self.real.replace(self.pattern_line.encode(), b"X = 1"))
        self.assertIsNone(v.notice_re)
        self.assertIn(dc.NOTICE_RE_NAME, v.why)


class UnhandledTest(unittest.TestCase):
    NOW = datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc)

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.notices = Path(td.name) / "peer" / "notices"
        self.ledger = Path(td.name) / "delivery-state" / "ledger"
        self.notices.mkdir(parents=True)
        self.ledger.mkdir(parents=True)
        self.pattern = dc.notice_pattern(Scratch.real)[0]

    def notice(self, nid, age_s, handled=False, ts=None):
        when = (self.NOW - timedelta(seconds=age_s)).strftime("%Y-%m-%dT%H:%M:%SZ")
        (self.notices / f"notice-{nid}.json").write_text(json.dumps(
            {"contract_version": "2", "kind": "peer", "message": "m", "notice_id": nid,
             "ts": when if ts is None else ts}))
        if handled:
            (self.ledger / f"{dc.LEDGER_PEER_PREFIX}{nid}").touch()

    def check(self, running=True, pattern="default"):
        return dc.verify_unhandled("box-1", self.notices, self.ledger,
                                   self.pattern if pattern == "default" else pattern, "why",
                                   now=self.NOW.timestamp(), running=running)

    def test_every_notice_handled_says_nothing(self):
        self.notice("a" * 32, 3600, handled=True)
        self.assertEqual(self.check(), ([], []))

    def test_an_old_unhandled_notice_on_a_running_sandbox_is_a_problem(self):
        self.notice("a" * 32, 3600, handled=True)
        self.notice("b" * 32, dc.UNHANDLED_MAX_AGE_SECONDS + 60)
        self.notice("c" * 32, 10)
        [p], _ = self.check()
        self.assertTrue(p.startswith("unhandled peer notices: box-1: 2 peer notice(s)"), p)
        self.assertIn(f"the oldest {dc.UNHANDLED_MAX_AGE_SECONDS + 60}s old", p)

    def test_young_unhandled_notices_are_a_note(self):
        self.notice("c" * 32, 10)
        problems, [n] = self.check()
        self.assertEqual(problems, [])
        self.assertIn("1 peer notice(s) with no ledger entry", n)

    def test_a_stopped_sandbox_is_a_note_however_old(self):
        self.notice("b" * 32, 86400)
        problems, [n] = self.check(running=False)
        self.assertEqual(problems, [])
        self.assertIn("not running", n)

    def test_an_undated_notice_is_counted_as_over_the_bound(self):
        self.notice("b" * 32, 0, ts="not a time")
        [p], _ = self.check()
        self.assertIn("1 with no readable ts", p)

    def test_the_count_uses_the_deployed_daemons_pattern(self):
        """A notice id the older 32-hex pattern cannot see is not counted
        against a daemon that never sees it."""
        long_id = "b" * 40
        self.notice(long_id, 86400)
        self.assertTrue(self.check()[0])
        older = dc.notice_pattern(Scratch.older)[0]
        self.assertEqual(self.check(pattern=older), ([], []))

    def test_no_ledger_directory_counts_every_notice_and_says_so(self):
        self.ledger.rmdir()
        self.notice("b" * 32, 86400)
        [p], _ = self.check()
        self.assertIn("the daemon has written no ledger yet", p)

    def test_no_pattern_is_unknown(self):
        [p], _ = self.check(pattern=None)
        self.assertTrue(p.startswith("unhandled count unknown: box-1: why"), p)

    def test_the_bound_is_fifteen_minutes(self):
        self.assertEqual(dc.UNHANDLED_MAX_AGE_SECONDS, 15 * 60)


if __name__ == "__main__":
    unittest.main()
