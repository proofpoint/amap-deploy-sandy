"""host_adapter, the sandy adapter's client for the host registry's CLI.

The replayed answers are `tests/fixtures/registry_cli.json`, captured from
the REAL CLI at its reviewed pin and never written by hand, with the
registry's identifiers replaced by the test overlay's (`_registry.IDS`).
The capture and the end-to-end run against the real CLI live with the
deployment overlay, which is private.
"""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import host_adapter as ha
from _registry import IDS, write_overlay

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixtures" / "registry_cli.json"
REGISTRY = Path("/srv/example/registry")
HOST_REPO = Path("/srv/example/registry-checkout")
ALPHA = "/srv/example/ws/alpha"
BETA = "/srv/example/ws/beta"


def _cases():
    with open(FIXTURE) as f:
        return {c["case"]: c for c in json.load(f)["cases"]}


CASES = _cases()


class Replay:
    """A runner that answers with recorded cases, in order, and records what
    it was asked."""

    def __init__(self, *names):
        self.queue = [CASES[n] for n in names]
        self.calls = []

    def __call__(self, argv, stdin, env, cwd, timeout):
        self.calls.append({"argv": list(argv), "request": json.loads(stdin), "env": env, "cwd": cwd})
        c = self.queue.pop(0)
        return c["rc"], c["stdout"], ""


class Raw:
    """A runner that answers with literal output."""

    def __init__(self, *answers):
        self.queue = list(answers)
        self.calls = 0

    def __call__(self, argv, stdin, env, cwd, timeout):
        self.calls += 1
        a = self.queue.pop(0)
        if isinstance(a, BaseException):
            raise a
        return a


def client(runner, **kw):
    sleeps = []
    c = ha.Client(REGISTRY, HOST_REPO, IDS, python="python3", runner=runner, sleep=sleeps.append, **kw)
    c.sleeps = sleeps
    return c


class TheFixtureIsTheProducersTest(unittest.TestCase):
    """The fixture holds what the registry printed, so it must look like it."""

    def test_every_case_is_one_json_line_with_a_boolean_ok(self):
        for name, c in CASES.items():
            with self.subTest(case=name):
                lines = [ln for ln in c["stdout"].splitlines() if ln.strip()]
                self.assertEqual(len(lines), 1)
                self.assertIsInstance(json.loads(lines[0])["ok"], bool)

    def test_it_is_identifier_clean(self):
        text = FIXTURE.read_text()
        self.assertNotIn("/tmp", text)
        self.assertNotIn("/Users/", text)
        self.assertNotIn("/home/", text)

    def test_its_identifiers_are_the_test_overlays(self):
        self.assertEqual(CASES["register_again"]["request"]["interface"], IDS.interface)
        self.assertIn(IDS.interface, json.loads(CASES["version"]["stdout"])["interfaces"])


class RequestShapeTest(unittest.TestCase):

    def test_register_sends_the_workspace_path_as_sandy_reports_it(self):
        r = Replay("register_again")
        client(r).register(ALPHA)
        self.assertEqual(r.calls[0]["request"],
                         {"interface": IDS.interface, "op": "register", "adapter": "sandy", "key": ALPHA})

    def test_the_child_runs_from_the_checkout_with_a_clean_environment(self):
        r = Replay("register_again")
        client(r).register(ALPHA)
        call = r.calls[0]
        self.assertEqual(call["argv"], ["python3", "-m", IDS.module, "--registry", str(REGISTRY)])
        self.assertEqual(call["cwd"], str(HOST_REPO))
        self.assertNotIn("PYTHONPATH", call["env"])
        self.assertEqual(call["env"]["PYTHONNOUSERSITE"], "1")

    def test_no_operator_verb_is_reachable(self):
        ops = {v for k, v in vars(ha).items() if k.startswith("OP_")}
        self.assertEqual(ops, {"version", "register", "show", "list"})


class RegisterOutcomesTest(unittest.TestCase):

    def test_a_new_binding_is_registered_and_says_so(self):
        r = client(Replay("register_after_internal")).register(BETA)
        self.assertEqual(r.outcome, ha.REGISTERED)
        self.assertTrue(r.created)
        self.assertEqual(r.binding["address"], "beta@fleet.example.org")

    def test_registering_again_keeps_the_identity(self):
        first = client(Replay("register_redelivers")).register(ALPHA)
        again = client(Replay("register_again")).register(ALPHA)
        self.assertEqual(again.outcome, ha.REGISTERED)
        self.assertFalse(again.created)
        self.assertEqual(again.binding["logical_id"], first.binding["logical_id"])

    def test_committed_but_undelivered_is_neither_success_nor_failure(self):
        r = client(Replay("instances_dir_absent")).register(ALPHA)
        self.assertEqual(r.outcome, ha.UNDELIVERED)
        self.assertEqual(r.code, ha.CODE_INSTANCES_DIR_ABSENT)
        self.assertIsNotNone(r.binding["logical_id"])

    def test_internal_is_retried_and_a_later_success_is_registered(self):
        c = client(Replay("internal", "register_after_internal"))
        r = c.register(BETA)
        self.assertEqual(r.outcome, ha.REGISTERED)
        self.assertEqual(r.attempts, 2)
        self.assertEqual(len(c.sleeps), 1)

    def test_internal_every_time_is_unknown_never_refused(self):
        c = client(Replay(*["internal"] * ha.RETRIES))
        r = c.register(BETA)
        self.assertEqual(r.outcome, ha.UNKNOWN)
        self.assertEqual(r.code, ha.CODE_INTERNAL)
        self.assertEqual(r.attempts, ha.RETRIES)
        self.assertEqual(len(c.sleeps), ha.RETRIES - 1)

    def test_a_refusal_is_not_retried(self):
        rr = Replay("stable_key_relative", "register_again")
        r = client(rr).register("relative/path")
        self.assertEqual(r.outcome, ha.REFUSED)
        self.assertEqual(r.code, "stable_key")
        self.assertEqual(len(rr.calls), 1)

    def test_a_bad_request_is_a_refusal_naming_it(self):
        r = client(Replay("bad_request_operator_verb")).register(ALPHA)
        self.assertEqual((r.outcome, r.code), (ha.REFUSED, ha.CODE_BAD_REQUEST))

    def test_an_unsupported_interface_is_a_refusal(self):
        r = client(Replay("interface")).register(ALPHA)
        self.assertEqual((r.outcome, r.code), (ha.REFUSED, ha.CODE_INTERFACE))


class ExitAndCodeTest(unittest.TestCase):
    """The exit status and the error code each decide on their own: either
    saying `internal` makes the answer UNKNOWN."""

    def err(self, code, **extra):
        return json.dumps(dict({"ok": False, "error": {"code": code, "detail": "d"}}, **extra)) + "\n"

    def test_register(self):
        rows = (("exit 3, another code", (3, self.err("stable_key"), ""), ha.UNKNOWN),
                ("exit 1, code internal", (1, self.err(ha.CODE_INTERNAL), ""), ha.UNKNOWN),
                ("committed unknown, exit 1", (1, self.err("x", committed="unknown"), ""), ha.UNKNOWN),
                ("committed true without a binding", (1, self.err("x", committed=True), ""), ha.REFUSED),
                ("exit 1, a plain refusal", (1, self.err("stable_key"), ""), ha.REFUSED),
                ("ok with exit 1", (1, CASES["register_again"]["stdout"], ""), ha.UNKNOWN))
        for name, answer, want in rows:
            with self.subTest(name):
                r = client(Raw(*[answer] * ha.RETRIES)).register(ALPHA)
                self.assertEqual(r.outcome, want, r)

    def test_a_success_body_with_a_failure_exit_is_never_believed(self):
        for rc in (3, 1, 2):
            with self.subTest(op="show", rc=rc):
                r = client(Raw((rc, CASES["show"]["stdout"], ""))).show(ALPHA)
                self.assertEqual((r.outcome, r.binding), (ha.UNKNOWN, None))
            with self.subTest(op="list", rc=rc):
                r = client(Raw((rc, CASES["list"]["stdout"], ""))).list()
                self.assertEqual(r.outcome, ha.UNKNOWN)
                self.assertNotIn("bindings", r.extra)
            with self.subTest(op="version", rc=rc):
                ok, why = client(Raw((rc, CASES["version"]["stdout"], ""))).supports_interface()
                self.assertIsNone(ok)
                self.assertIn(str(rc), why)

    def test_show_and_list(self):
        for op in ("show", "list"):
            for name, answer, want in (("exit 3", (3, self.err("x"), ""), ha.UNKNOWN),
                                       ("code internal", (1, self.err(ha.CODE_INTERNAL), ""), ha.UNKNOWN),
                                       ("plain", (1, self.err("x"), ""), ha.REFUSED)):
                with self.subTest(op=op, case=name):
                    c = client(Raw(answer))
                    r = c.show(ALPHA) if op == "show" else c.list()
                    self.assertEqual(r.outcome, want)


class NoAnswerIsUnknownTest(unittest.TestCase):
    """Anything but exactly one JSON object is UNKNOWN, and is retried."""

    def assertUnknownAfterRetries(self, answer):
        runner = Raw(*[answer] * ha.RETRIES)
        r = client(runner).register(ALPHA)
        self.assertEqual(r.outcome, ha.UNKNOWN)
        self.assertEqual(runner.calls, ha.RETRIES)
        return r

    def test_empty_stdout(self):
        r = self.assertUnknownAfterRetries((1, "", "Traceback (most recent call last):\nOSError: boom\n"))
        self.assertIn("OSError: boom", r.detail)

    def test_two_lines_even_if_the_first_is_a_whole_success(self):
        line = CASES["register_again"]["stdout"].strip()
        self.assertUnknownAfterRetries((0, line + "\n" + line + "\n", ""))

    def test_not_json(self):
        self.assertUnknownAfterRetries((0, "registered\n", ""))

    def test_no_boolean_ok(self):
        self.assertUnknownAfterRetries((0, '{"ok": "yes"}\n', ""))

    def test_ok_without_a_binding(self):
        self.assertUnknownAfterRetries((0, '{"ok": true}\n', ""))

    def test_the_process_cannot_be_run(self):
        runner = Raw(*[FileNotFoundError("python3")] * ha.RETRIES)
        r = client(runner).register(ALPHA)
        self.assertEqual(r.outcome, ha.UNKNOWN)
        self.assertIn(ha.CODE_NOT_RUN, r.detail)

    def test_a_timeout(self):
        runner = Raw(*[subprocess.TimeoutExpired("python3", 1)] * ha.RETRIES)
        self.assertEqual(client(runner).register(ALPHA).outcome, ha.UNKNOWN)


class ReadOnlyOpsTest(unittest.TestCase):

    def test_show_reports_the_name_json_status(self):
        r = client(Replay("show")).show(ALPHA)
        self.assertEqual(r.outcome, ha.REGISTERED)
        self.assertEqual(r.binding["name_json"], ha.NAME_JSON_CURRENT)
        self.assertTrue(r.binding["identity_dir"].startswith("/srv/example/identity/"))

    def test_show_of_an_unregistered_workspace_is_not_found(self):
        r = client(Replay("not_found")).show("/srv/example/ws/missing")
        self.assertEqual((r.outcome, r.code), (ha.REFUSED, ha.CODE_NOT_FOUND))

    def test_absences_keep_their_own_codes(self):
        self.assertEqual(client(Replay("registry_absent")).list().code, ha.CODE_REGISTRY_ABSENT)
        self.assertEqual(client(Replay("config_absent")).list().code, ha.CODE_CONFIG_ABSENT)

    def test_list_before_any_registration_is_never_empty(self):
        r = client(Replay("registry_absent")).list()
        self.assertEqual(r.outcome, ha.REFUSED)
        self.assertNotIn("bindings", r.extra)

    def test_interface_membership_is_whole_tokens_only(self):
        for listed in ([IDS.interface + "0"], [IDS.interface[:-1]], ["x" + IDS.interface],
                       [IDS.interface + "0", "other/1"]):
            with self.subTest(listed=listed):
                body = json.dumps({"ok": True, "interfaces": listed}) + "\n"
                ok, _ = client(Raw((0, body, ""))).supports_interface()
                self.assertIs(ok, False)

    def test_list(self):
        r = client(Replay("list")).list()
        self.assertEqual([b["name"] for b in r.extra["bindings"]], ["alpha"])

    def test_interface_membership(self):
        ok, toks = client(Replay("version")).supports_interface()
        self.assertTrue(ok)
        self.assertIn(IDS.interface, toks)
        ok, why = client(Raw((1, "", ""))).supports_interface()
        self.assertIsNone(ok)


class DomainTest(unittest.TestCase):

    def test_same_domain_is_no_finding(self):
        b = client(Replay("show")).show(ALPHA).binding
        self.assertIsNone(ha.domain_mismatch(b, "fleet.example.org"))

    def test_a_host_json_domain_other_than_the_policys_is_named(self):
        b = client(Replay("show_other_domain")).show(ALPHA).binding
        msg = ha.domain_mismatch(b, "fleet.example.org")
        self.assertIn("other.example.org", msg)
        self.assertIn("fleet.example.org", msg)

    def test_no_policy_domain_is_no_finding(self):
        b = client(Replay("show")).show(ALPHA).binding
        self.assertIsNone(ha.domain_mismatch(b, None))


class OverlayTest(unittest.TestCase):
    """The identifiers come from the overlay, or the verb refuses by name."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def test_the_overlay_names_every_identifier(self):
        self.assertEqual(ha.load_identifiers(write_overlay(self.dir / "o.json")), IDS)

    def test_each_gap_refuses_and_names_what_is_missing(self):
        rows = (("absent path", None, "no deployment overlay"),
                ("missing file", self.dir / "nope.json", "unreadable"),
                ("no section", self.dir / "empty.json", "no 'registry' object"))
        (self.dir / "empty.json").write_text("{}")
        for name, path, says in rows:
            with self.subTest(name):
                with self.assertRaises(ha.OverlayError) as cm:
                    ha.load_identifiers(path)
                self.assertIn(says, str(cm.exception))
        for key in ha.IDENTIFIER_KEYS:
            for bad in ("", "two words", 7):
                with self.subTest(key=key, bad=bad):
                    with self.assertRaises(ha.OverlayError) as cm:
                        ha.load_identifiers(write_overlay(self.dir / "o.json", **{key: bad}))
                    self.assertIn(f"registry.{key}", str(cm.exception))
        with self.assertRaises(ha.OverlayError):
            ha.load_identifiers(write_overlay(self.dir / "o.json", checkout="relative/dir"))

    def test_an_absent_key_refuses_and_names_it(self):
        for key in ha.IDENTIFIER_KEYS:
            with self.subTest(key=key):
                section = {k: getattr(IDS, k) for k in ha.IDENTIFIER_KEYS if k != key}
                path = self.dir / f"absent-{key}.json"
                path.write_text(json.dumps({ha.OVERLAY_SECTION: section}))
                with self.assertRaises(ha.OverlayError) as cm:
                    ha.load_identifiers(path)
                self.assertIn(f"registry.{key}", str(cm.exception))

    def test_the_path_comes_from_the_flag_else_the_environment(self):
        old = os.environ.pop(ha.OVERLAY_ENV, None)
        self.addCleanup(lambda: os.environ.__setitem__(ha.OVERLAY_ENV, old) if old else
                        os.environ.pop(ha.OVERLAY_ENV, None))
        self.assertIsNone(ha.overlay_path(None))
        os.environ[ha.OVERLAY_ENV] = "/srv/example/env.json"
        self.assertEqual(ha.overlay_path(None), Path("/srv/example/env.json"))
        self.assertEqual(ha.overlay_path(Path("/srv/example/flag.json")),
                         Path("/srv/example/flag.json"))

    def test_the_checkout_must_hold_the_overlays_module(self):
        old = os.environ.pop(ha.CHECKOUT_ENV, None)
        self.addCleanup(lambda: os.environ.__setitem__(ha.CHECKOUT_ENV, old) if old else
                        os.environ.pop(ha.CHECKOUT_ENV, None))
        repo = self.dir / "checkout"
        self.assertIsNone(ha.registry_checkout(IDS, repo))
        (repo / IDS.module).mkdir(parents=True)
        (repo / IDS.module / "cli.py").write_text("")
        self.assertEqual(ha.registry_checkout(IDS, repo), repo.absolute())
        os.environ[ha.CHECKOUT_ENV] = str(repo)
        self.assertEqual(ha.registry_checkout(IDS), repo.absolute())
        del os.environ[ha.CHECKOUT_ENV]
        from dataclasses import replace
        self.assertEqual(ha.registry_checkout(replace(IDS, checkout=str(repo))), repo.absolute())


if __name__ == "__main__":
    unittest.main()
