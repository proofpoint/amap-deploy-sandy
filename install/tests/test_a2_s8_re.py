"""S8 steps 6 and 7's decisions (a2_s8_re) on RE's REAL outputs (re_capture, RE's answer to W13 d2 at fc542edc).

The ledger init lines (L1, L4), the --verify reports (V6, V7), the backoff lines (B1-B3), the refusals (R1, R3) and
the six hub-status writes (H1-H6) are RE's own bytes. S1, the startup line, is RE's obs call with placeholder values;
a case that needs the deployment's link and plugin puts them in its place and says so. `docker inspect` for RE is
FAKED on the field names RE's start uses (State.Status, State.Restarting).
"""

import json
import unittest

import a2fix  # noqa: F401  (puts install/ on sys.path)
import a2_s6_env as e6
import a2_s8_re as E
import a2_s8_rl
import re_capture as C
from a2_causes import Refusal

T = "<T>/ledger"
IMAGE = "sha256:" + "e" * 64
LINK = "alpha2-link"
PIN = "2aca9e214a8cca789bd081d43a04de776dc9eb6844f6c3b180d148e01b7dd893"
CREATED = a2_s8_rl.instant_ns("2026-11-22T18:08:03Z")
ENV = {"MAILBOX_ROOT_DIR": "/home/relay/.amap-relay/mail", "RELAY_LEDGER_DIR": "/home/relay/.amap-relay/ledger",
       "HUB_INBOUND_STATE_DIR": "/home/relay/.amap-relay/inbound", "HOP_ROOT": "/home/agent/.amap-hop",
       "HOP_REGISTRY_DIR": "/home/agent/.amap-registry", "HUB_D7_CONFIG": "/home/agent/.amap-relay-config/d7.json",
       "HUB_PREFIX_TEMPLATE": "/home/agent/.amap-relay-config/prefix.json",
       "SMTP_PASSWORD_FILE": "/home/relay/.amap-relay/smtp-password",
       "TRANSPORT_PLUGIN_PATH": "/opt/amap-plugin/amap_hop_plugin.py", "HOP_LINK": LINK}


def startup_line(**change):
    """RE's S1 line with the deployment's link and plugin in place of its placeholders."""
    rec = dict(json.loads(C.S1), link=LINK, plugin_sha256=PIN)
    rec.update(change)
    return json.dumps(rec).encode()


def logs(*lines):
    return b"\n".join(lines) + b"\n"


class Refuses(unittest.TestCase):
    def refuses(self, fn, *a):
        with self.assertRaises(Refusal) as cm:
            fn(*a)
        self.assertEqual((cm.exception.cause, cm.exception.rc), ("START.RE_REFUSED", 3))
        return cm.exception


class LedgerInitTest(Refuses):
    def test_argv_is_res_c5_form(self):
        self.assertEqual(E.init_argv("/l", IMAGE, 1001, 1002),
                         ["/usr/bin/docker", "run", "--rm", "--pull", "never", "--network", "none", "--user", "1001:1002",
                          "--entrypoint", "python3", "--mount", "type=bind,src=/l,dst=/l", IMAGE,
                          "/app/host/outcome_ledger.py", "init", "/l"])
        self.assertNotIn("-I", E.init_argv("/l", IMAGE, 1, 1))
        self.assertNotIn("-v", E.init_argv("/l", IMAGE, 1, 1))

    def test_a_ledger_breaking_s6s_path_rule_is_never_spliced(self):
        """Gate B's W13 r4 note N1: init_argv and verify_argv apply the one mount_path check themselves."""
        import a2_s8 as S
        for bad in ("/l,bind-propagation=rshared", "/l=x", '/l"', "/l x", "/a/../l", "rel", "/", None):
            with self.subTest(bad=bad):
                self.assertEqual(self.refuses(E.init_argv, bad, IMAGE, 1, 1).detail, "env-file mount knob")
                with self.assertRaises(Refusal) as cm:
                    S.verify_argv(bad, IMAGE, 1, 1)
                self.assertEqual(cm.exception.cause, "START.CONFIG_CHANGED")

    def test_only_rc_0_and_exactly_res_line_pass(self):
        E.init_ok(0, C.L1 + b"\n", T)
        for rc, out in ((0, C.L1), (0, C.L1 + b"\nmore\n"), (1, C.L1 + b"\n"), (1, C.L4 + b"\n"),
                        (0, C.L1.replace(b"ledger", b"other") + b"\n"), (2, b"")):
            with self.subTest(rc=rc, out=out[-30:]):
                self.refuses(E.init_ok, rc, out, T)

    def test_the_re_run_verify_must_say_available(self):
        E.available(C.V6 + b"\n")
        for out in (C.V7 + b"\n", b"", b"{}", C.V6.replace(b'"available": true', b'"available": "true"')):
            with self.subTest(out=out[-40:]):
                self.refuses(E.available, out)


class StartArgvTest(Refuses):
    def test_each_mount_is_its_knobs_value_rw_or_ro_and_nothing_else(self):
        argv = E.start_argv(ENV, "/home/agent/.amap-relay-env/re.env", IMAGE, 1001, 1002, 1500)
        self.assertEqual(argv[:14], ["/usr/bin/docker", "run", "-d", "--pull", "never", "--restart", "no", "--name",
                                     "amap-re", "--user", "1001:1002", "--group-add", "1500", "--env-file"])
        self.assertEqual(argv[14], "/home/agent/.amap-relay-env/re.env")
        self.assertEqual(argv[-2:], [IMAGE, "both"])
        mounts = argv[15:-2]
        self.assertEqual(mounts[0::2], ["--mount"] * 9)
        got = {}
        for spec in mounts[1::2]:
            parts = spec.split(",")
            src, dst = parts[1][4:], parts[2][4:]
            self.assertEqual(src, dst)
            got[src] = parts[3:] == ["readonly"]
        self.assertEqual(got, {ENV[k]: k in E.RO_KNOBS for k in E.RW_KNOBS + E.RO_KNOBS})
        self.assertNotIn(ENV["HOP_LINK"], " ".join(mounts))

    def test_a_forbidden_key_or_a_bad_mount_knob_refuses(self):
        for k in e6.ABSENT + ("OAUTH2_TOKEN",):
            with self.subTest(k=k):
                self.refuses(E.start_argv, dict(ENV, **{k: "x"}), "/e", IMAGE, 1, 1, 1)
        for k in E.RW_KNOBS + E.RO_KNOBS:
            for bad in (None, "rel", "/a,b", "/a=b", '/a"b', "/a b", "/a/../b", "/"):
                with self.subTest(k=k, bad=bad):
                    env = dict(ENV)
                    if bad is None:
                        del env[k]
                    else:
                        env[k] = bad
                    self.refuses(E.start_argv, env, "/e", IMAGE, 1, 1, 1)


class ObsTest(Refuses):
    def test_json_lines_are_records_and_plain_text_is_skipped(self):
        got = E.obs_records(logs(b"both_loop: a hub side exited (2); stopping the process", C.B1, b"[1, 2]", b"", C.S1,
                                 b"\xff\xfe"))
        self.assertEqual([r["event"] for r in got], ["hub_session_backoff", "startup"])

    def test_startup_with_the_link_and_pin_is_witness_1(self):
        self.assertTrue(E.startup(E.obs_records(logs(b"plain", startup_line())), LINK, PIN))
        self.assertFalse(E.startup(E.obs_records(logs(b"plain")), LINK, PIN))

    def test_res_own_s1_line_has_placeholders_so_it_refuses(self):
        self.refuses(E.startup, E.obs_records(logs(C.S1)), LINK, PIN)

    def test_a_backoff_or_refusal_first_refuses_at_once(self):
        for line in (C.B1, C.B2, C.B3, C.R1, C.R3):
            with self.subTest(line=line[60:110]):
                self.refuses(E.startup, E.obs_records(logs(line, startup_line())), LINK, PIN)

    def test_a_startup_with_another_role_link_or_plugin_refuses(self):
        for change in (dict(role="client"), dict(link="other"), dict(plugin_sha256="0" * 64)):
            with self.subTest(change=change):
                self.refuses(E.startup, E.obs_records(logs(startup_line(**change))), LINK, PIN)

    def test_matching_is_on_separate_members_never_a_dotted_string(self):
        rec = json.dumps({"component": "relay.startup", "event": "x", "role": "hub"}).encode()
        self.assertFalse(E.startup(E.obs_records(logs(rec)), LINK, PIN))

    def test_inbound_witness(self):
        E.inbound_clear(E.obs_records(logs(startup_line(), C.B1.replace(b"hub_session_backoff", b"other"))))
        for comp, ev in sorted(E.INBOUND_FAILURES):
            with self.subTest(ev=ev):
                rec = json.dumps({"component": comp, "event": ev}).encode()
                self.refuses(E.inbound_clear, E.obs_records(logs(startup_line(), rec)))
        # The same event under another component is not one of RE's failures.
        E.inbound_clear(E.obs_records(logs(json.dumps({"component": "relay", "event": "hub.poll_failed"}).encode())))


class HubStatusTest(Refuses):
    def test_both_write_shapes_give_progress(self):
        got = [E.hub_progress(getattr(C, "H%d" % i), CREATED, PIN) for i in range(1, 7)]
        self.assertEqual([g[0] for g in got], [1, 2, 3, 3, 4, 4])
        self.assertEqual({g[1] for g in got}, {5.0})

    def test_another_containers_document_or_garbage_is_not_yet(self):
        self.assertIsNone(E.hub_progress(C.H1, CREATED + 1_000_000_000, PIN))
        for raw in (b"", b"{", b"[]", C.H1.replace(b'"progress":1', b'"progress":"1"'),
                    C.H1.replace(b'"interval_s":5.0', b'"interval_s":0'),
                    C.H1.replace(b'"process_started_ts":"2026-11-22T18:08:03.614363Z"', b'"process_started_ts":null')):
            with self.subTest(raw=raw[:40]):
                self.assertIsNone(E.hub_progress(raw, CREATED, PIN))

    def test_another_plugin_refuses(self):
        self.refuses(E.hub_progress, C.H1, CREATED, "0" * 64)
        self.refuses(E.hub_progress, C.H1.replace(b'"transport_plugin"', b'"other"'), CREATED, PIN)

    def test_progress_must_rise_across_two_intervals_and_five_seconds(self):
        s = 1_000_000_000
        self.assertTrue(E.progressed((0, 1, 5.0), (15 * s, 2, 5.0)))
        self.assertFalse(E.progressed((0, 1, 5.0), (15 * s - 1, 2, 5.0)))
        self.assertFalse(E.progressed((0, 1, 5.0), (60 * s, 1, 5.0)))


class StateAndStopTest(Refuses):
    def test_any_exit_refuses(self):
        E.exited(json.dumps([{"State": {"Status": "running", "Restarting": False}}]).encode())
        for st in ({"Status": "exited", "Restarting": False}, {"Status": "running", "Restarting": True},
                   {"Status": "running"}):
            with self.subTest(st=st):
                self.refuses(E.exited, json.dumps([{"State": st}]).encode())
        for out in (b"", b"[]", b"{}"):
            self.refuses(E.exited, out)

    def test_stop_timeout(self):
        self.assertEqual(E.stop_timeout({}), 670)
        self.assertEqual(E.stop_timeout({"RELAY_SMTP_DOT_TIMEOUT": "120"}), 190)
        self.assertEqual(E.stop_timeout({"RELAY_SMTP_DOT_TIMEOUT": "0.5"}), 71)
        self.assertEqual(E.stop_timeout({"RELAY_SMTP_DOT_TIMEOUT": "3600"}), 3670)
        for bad in ("0", "-1", "3601", "nan", "inf", "x", ""):
            with self.subTest(bad=bad):
                self.assertEqual(E.stop_timeout({"RELAY_SMTP_DOT_TIMEOUT": bad}), 3670)



class DeepJsonTest(Refuses):
    """Gate B's W13 r4 blocker 2: json.loads raises RecursionError, not ValueError, on a deeply nested document
    (about 20000 levels on Python 3.13). Every S8 parser of RL, RE or docker bytes answers it as it answers any
    unreadable document, never by letting it escape."""

    DEEP = b"[" * 200000 + b"]" * 200000

    def test_the_parse_really_recurses(self):
        with self.assertRaises(RecursionError):
            json.loads(self.DEEP)

    def test_each_parser_reads_it_as_unreadable(self):
        import a2_s8 as S
        import a2_s8_run as R
        self.assertEqual(self.refuses(E.available, self.DEEP).detail, "ledger check output")
        self.assertEqual(self.refuses(E.exited, self.DEEP).detail, "inspect output")
        self.assertIsNone(E.hub_progress(self.DEEP, 0, "0" * 64))
        self.assertEqual(E.obs_records(self.DEEP + b"\n" + C.S1), [json.loads(C.S1)])
        self.assertIsNone(a2_s8_rl._doc(self.DEEP))
        with self.assertRaises(Refusal) as cm:
            S.ledger_state(self.DEEP)
        self.assertEqual(cm.exception.cause, "START.LEDGER_UNUSABLE")

        class Layer:
            def exec(self, vm, argv, **kw):
                return 0, DeepJsonTest.DEEP, b""
        self.assertIsNone(R._inspect(Layer(), {"name": "vm", "agent_account": "agent"}, "amap-re"))

if __name__ == "__main__":
    unittest.main()
