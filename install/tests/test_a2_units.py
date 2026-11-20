"""Unit tests: causes against the contract text, the private-file checks,
argv, environment and account. Each refusal has a test that makes it fire
on a surface only that check can produce."""

import copy
import io
import json
import os
import re
import unittest

import a2fix  # noqa: F401  (puts install/ on sys.path)
import a2_args
import a2_causes
import a2_host
import a2_private
from a2_causes import Refusal

CONTRACT = os.path.join(a2fix.REPO, "alpha2", "STAGE-CONTRACT.md")


def contract_sentences():
    """Section 4.7's table, read from the contract file itself."""
    with open(CONTRACT, encoding="utf-8") as f:
        text = f.read()
    sec = text.split("### 4.7 Cause sentences", 1)[1].split("\n## 5.", 1)[0]
    out = {}
    for line in sec.splitlines():
        m = re.fullmatch(r"\| `([^`]+)` \| (.+) \|", line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


class CausesTest(unittest.TestCase):
    def test_every_sentence_is_the_contracts_byte_for_byte(self):
        want = contract_sentences()
        for cause, text in a2_causes.RUNNER_SENTENCES.items():
            self.assertEqual(want.get(cause), text, cause)
        for cause, text in a2_causes.CREDENTIALS_SENTENCES.items():
            self.assertEqual(want.get(cause), text, cause)
        self.assertEqual(sorted(a2_causes.CREDENTIALS_SENTENCES),
                         sorted(k for k in want if k.startswith("CREDENTIALS.")))
        for name, text in a2_causes.STAGE_SENTENCES.items():
            self.assertEqual(want.get("<STAGE>." + name), text, name)

    def test_unknown_cause_cannot_be_raised(self):
        with self.assertRaises(ValueError):
            Refusal("RUNNER.NOT_A_CAUSE")

    def test_report_prints_one_cause_line_and_the_sentence(self):
        buf = io.StringIO()
        rc = a2_causes.report(Refusal("RUNNER.ENV"), buf)
        self.assertEqual(rc, 2)
        self.assertEqual(buf.getvalue().splitlines(),
                         ["CAUSE=RUNNER.ENV", a2_causes.RUNNER_SENTENCES["RUNNER.ENV"]])

    def test_rc_override_only_for_two_or_three_causes(self):
        self.assertEqual(Refusal("RUNNER.UNCLASSIFIED", rc=3).rc, 3)
        self.assertEqual(Refusal("RUNNER.CUSTODY", rc=3).rc, 3)
        for cause, rc in (("RUNNER.ENV", 3), ("RUNNER.UNCLASSIFIED", 4), ("RUNNER.UNCLASSIFIED", 2)):
            with self.subTest(cause=cause, rc=rc):
                with self.assertRaises(ValueError):
                    Refusal(cause, rc=rc)

    def test_default_site_accepts_no_host_identity(self):
        import a2_site
        from unittest import mock
        with mock.patch.object(a2_site, "_machine_id", lambda: "0123456789abcdef0123456789abcdef"):
            self.assertIsNone(a2_site.Site().host_identity())

    def test_sums_exits_4(self):
        self.assertEqual(Refusal("RUNNER.SUMS").rc, 4)


def _pair(lock=None, hosts=None):
    lock = lock if lock is not None else a2fix.lock_bytes()
    hosts = hosts if hosts is not None else a2fix.dumps(a2fix.hosts_doc("/srv/locks"))
    return lock, hosts


class ReadPrivatePairTest(unittest.TestCase):
    """a2_admit.read_private_pair: the shared reader of the two private
    files, the same bytes S0 reads, nothing parsed."""

    def setUp(self):
        import tempfile
        self.d = tempfile.mkdtemp(prefix="a2rpp-")
        self.addCleanup(__import__("shutil").rmtree, self.d, True)
        for name, data in (("alpha2.lock", b"lock-bytes\n"), ("alpha2.hosts", b"hosts-bytes\n")):
            with open(os.path.join(self.d, name), "wb") as f:
                f.write(data)

    def refuses(self, private_dir):
        import a2_admit
        with self.assertRaises(Refusal) as cm:
            a2_admit.read_private_pair(private_dir)
        self.assertEqual(cm.exception.cause, "PREFLIGHT.PRIVATE_SOURCE")

    def test_returns_the_raw_bytes_unparsed(self):
        import a2_admit
        self.assertEqual(a2_admit.read_private_pair(self.d), (b"lock-bytes\n", b"hosts-bytes\n"))

    def test_unset_refuses(self):
        self.refuses(None)
        self.refuses("")

    def test_a_symlinked_file_refuses(self):
        target = os.path.join(self.d, "elsewhere")
        os.rename(os.path.join(self.d, "alpha2.hosts"), target)
        os.symlink(target, os.path.join(self.d, "alpha2.hosts"))
        self.refuses(self.d)

    def test_a_directory_in_place_of_the_file_refuses(self):
        os.remove(os.path.join(self.d, "alpha2.lock"))
        os.mkdir(os.path.join(self.d, "alpha2.lock"))
        self.refuses(self.d)

    def test_a_missing_file_refuses(self):
        os.remove(os.path.join(self.d, "alpha2.hosts"))
        self.refuses(self.d)

    def test_more_than_the_bound_refuses_and_the_bound_passes(self):
        import a2_admit
        with open(os.path.join(self.d, "alpha2.lock"), "wb") as f:
            f.write(b"x" * a2_admit.READ_MAX)
        self.assertEqual(len(a2_admit.read_private_pair(self.d)[0]), a2_admit.READ_MAX)
        with open(os.path.join(self.d, "alpha2.lock"), "ab") as f:
            f.write(b"x")
        self.refuses(self.d)


class PrivateFilesTest(unittest.TestCase):
    def fails(self, which, check, lock=None, hosts=None):
        with self.assertRaises(a2_private.PairInvalid) as cm:
            a2_private.load_pair(*_pair(lock, hosts))
        self.assertEqual(cm.exception.which, which)
        self.assertEqual(cm.exception.inv.check, check)
        return cm.exception

    def test_valid_pair_passes(self):
        lock, hosts = a2_private.load_pair(*_pair())
        self.assertEqual(lock["schema"], "alpha2.lock/1")
        self.assertEqual(hosts["schema"], "alpha2.hosts/1")

    def test_L1_bom(self):
        self.fails("lock", "L1", lock=b"\xef\xbb\xbf" + a2fix.lock_bytes())

    def test_L1_not_utf8(self):
        self.fails("hosts", "L1", hosts=b'{"schema": "\xff"}')

    def test_L1_duplicate_key(self):
        raw = a2fix.lock_bytes().replace(b'"schema": "alpha2.lock/1"',
                                         b'"schema": "alpha2.lock/1", "schema": "alpha2.lock/1"')
        self.fails("lock", "L1", lock=raw)

    def test_L1_nan(self):
        raw = a2fix.lock_bytes().replace(b'"d7_source": {', b'"x": NaN, "d7_source": {')
        self.fails("lock", "L1", lock=raw)

    def test_L1_schema_token(self):
        d = copy.deepcopy(a2fix.LOCK)
        d["schema"] = "alpha2.lock/2"
        self.fails("lock", "L1", lock=a2fix.dumps(d))

    def test_L2_unknown_key_names_parent_and_ordinal_never_the_key(self):
        h = a2fix.hosts_doc("/srv/locks")
        h["runner"]["secretish_key_text"] = "x"
        e = self.fails("hosts", "L2", hosts=a2fix.dumps(h))
        self.assertEqual(e.inv.path, "$.runner#4")
        self.assertNotIn("secretish", e.detail)

    def test_L2_extra_pins_absent_until_E23(self):
        d = copy.deepcopy(a2fix.LOCK)
        d["extra_pins"] = []
        self.fails("lock", "L2", lock=a2fix.dumps(d))

    def test_L3_pattern(self):
        h = a2fix.hosts_doc("/srv/locks")
        h["vms"][0]["vm_id"] = "12a"
        e = self.fails("hosts", "L3", hosts=a2fix.dumps(h))
        self.assertEqual(e.inv.path, "$.vms[0].vm_id")

    def test_L3_missing_required(self):
        d = copy.deepcopy(a2fix.LOCK)
        del d["plugin"]
        self.fails("lock", "L3", lock=a2fix.dumps(d))

    def test_L3_relpath_dotdot(self):
        d = copy.deepcopy(a2fix.LOCK)
        d["files"][0]["path"] = "alpha/../x"
        self.fails("lock", "L3", lock=a2fix.dumps(d))

    def test_L3_writers_exactly_two_unique(self):
        d = copy.deepcopy(a2fix.LOCK)
        d["writers"][1]["use"] = "api_key"
        self.fails("lock", "L3", lock=a2fix.dumps(d))

    def test_L3_accounts_differ(self):
        h = a2fix.hosts_doc("/srv/locks", loop_account="same", l3_account="same")
        self.fails("hosts", "L3", hosts=a2fix.dumps(h))

    def test_L3_both_scopes_present(self):
        h = a2fix.hosts_doc("/srv/locks")
        h["vms"] = [v for v in h["vms"] if v["scope"] == "loop"]
        self.fails("hosts", "L3", hosts=a2fix.dumps(h))

    def test_L3_agent_names_a_vm(self):
        h = a2fix.hosts_doc("/srv/locks")
        h["agents"][0]["vm"] = "nope"
        self.fails("hosts", "L3", hosts=a2fix.dumps(h))

    def test_L3_agent_connector_is_a_component(self):
        h = a2fix.hosts_doc("/srv/locks")
        h["agents"][0]["connector"] = "nope"
        self.fails("hosts", "L3", hosts=a2fix.dumps(h))

    def test_L3_unique_vm_id(self):
        h = a2fix.hosts_doc("/srv/locks")
        h["vms"][1]["vm_id"] = h["vms"][0]["vm_id"]
        self.fails("hosts", "L3", hosts=a2fix.dumps(h))

    def test_L3_image_built_from_component(self):
        d = copy.deepcopy(a2fix.LOCK)
        d["images"][0]["built_from"] = "nope"
        self.fails("lock", "L3", lock=a2fix.dumps(d))

    # L4 runs after L1 to L3; no field pattern of section 6 admits a deny
    # shape, so on a schema-valid file only check_deny itself can fire.
    # These tests call it directly, on each of its two passes.

    def deny(self, raw, doc):
        with self.assertRaises(a2_private.Invalid) as cm:
            a2_private.check_deny(raw, doc)
        self.assertEqual(cm.exception.check, "L4")
        return cm.exception

    def test_L4_parsed_pass_catches_escaped_token(self):
        raw = b'{"a": "\\u0067hp_x"}'
        doc = {"a": "ghp_x"}
        self.assertNotIn(b"ghp_", raw)
        e = self.deny(raw, doc)
        self.assertEqual(e.path, "$.a")

    def test_L4_raw_pass_catches_bytes(self):
        self.deny(b"x -----BEGIN OPENSSH PRIVATE KEY----- y", {})
        self.deny(b"see https://u:p@x.example.org/", {})
        for tok in (b"ghp_", b"github_pat_", b"glpat-"):
            self.deny(b"..." + tok + b"...", {})

    def test_L4_passes_a_clean_pair(self):
        lock, hosts = _pair()
        a2_private.check_deny(lock, a2_private.parse(lock, "alpha2.lock/1"))

    def test_L3_refuses_url_userinfo_before_L4(self):
        d = copy.deepcopy(a2fix.LOCK)
        d["components"][0]["repo"] = "https://u:p@git.example.org/x"
        self.fails("lock", "L3", lock=a2fix.dumps(d))

    def test_L3_tags_and_overlay(self):
        """e3 6.1: overlay is required; every components[].tag is an rc_tag
        and equals overlay.tag."""
        for mut in (lambda d: d.__delitem__("overlay"),
                    lambda d: d["components"][0].__delitem__("tag"),
                    lambda d: d["components"][0].__setitem__("tag", "alpha2-rc2"),
                    lambda d: d["overlay"].__setitem__("tag", "alpha2-rc0"),
                    lambda d: d["overlay"].__setitem__("tag", "v1.0"),
                    lambda d: d["overlay"].__setitem__("commit", "abc")):
            d = copy.deepcopy(a2fix.LOCK)
            mut(d)
            self.fails("lock", "L3", lock=a2fix.dumps(d))
        d = copy.deepcopy(a2fix.LOCK)
        for c in d["components"]:
            c["tag"] = "alpha2-rc12"
        d["overlay"]["tag"] = "alpha2-rc12"
        a2_private.load_pair(a2fix.dumps(d), a2fix.dumps(a2fix.hosts_doc("/srv/locks")))

    def test_L3_destroy_deny(self):
        """6.2: optional; names of vms[] entries, unique; [] allowed."""
        for bad in (["vm-a", "vm-a"], ["nope"], ["Bad_Name"], "vm-a"):
            with self.subTest(bad=bad):
                h = a2fix.hosts_doc("/srv/locks")
                h["destroy_deny"] = bad
                self.fails("hosts", "L3", hosts=a2fix.dumps(h))
        for ok in ([], ["vm-a"], None):
            h = a2fix.hosts_doc("/srv/locks")
            if ok is None:
                del h["destroy_deny"]
            else:
                h["destroy_deny"] = ok
            a2_private.load_pair(a2fix.lock_bytes(), a2fix.dumps(h))

    def test_cause_is_leak_lock_or_hosts(self):
        e = self.fails("hosts", "L1", hosts=b"[]")
        self.assertEqual(e.cause, "PREFLIGHT.LEAK_HOSTS")


class ArgsTest(unittest.TestCase):
    def ok(self, argv, command, loop, opts=None):
        self.assertEqual(a2_args.parse(argv), a2_args.Invocation(command, loop, opts or {}))

    def bad(self, argv):
        with self.assertRaises(Refusal) as cm:
            a2_args.parse(argv)
        self.assertEqual(cm.exception.cause, "RUNNER.ARGS")
        self.assertIsNone(cm.exception.detail)

    def test_table(self):
        self.ok([], "install", None)
        self.ok(["--dry-run"], "dry-run", None)
        self.ok(["--verify"], "verify", None)
        self.ok(["--verify", "--canary"], "canary", None)
        self.ok(["--add-agent", "vm-a"], "add-agent", None, {"host": "vm-a"})
        self.ok(["--add-agent", "vm-a", "--id", "agent-b"], "add-agent", None,
                {"host": "vm-a", "id": "agent-b"})
        self.ok(["--rotate-key"], "rotate-key", None)
        self.ok(["--check-roundtrip", "abcd1234"], "check-roundtrip", None, {"nonce": "abcd1234"})
        self.ok(["--only", "S6b"], "install", "L1", {"only": "S6b"})
        self.ok(["--from", "S3"], "install", "L1", {"from": "S3"})
        self.ok(["--leak-run"], "install", "L2-leak")
        self.ok(["--loop", "L2"], "install", "L2")
        self.ok(["--loop", "L3"], "install", "L3")
        self.ok(["--destroy"], "destroy", None)

    def test_refusals(self):
        self.bad(["--loop", "L2", "--only", "S1"])
        self.bad(["--loop", "L2", "--leak-run"])
        self.bad(["--loop", "L2", "--loop", "L2"])
        self.bad(["--loop", "L1"])
        self.bad(["--only", "S11"])
        self.bad(["--add-agent", "Bad_Name"])
        self.bad(["--check-roundtrip", "short"])
        self.bad(["--canary"])
        self.bad(["--id", "x"])
        self.bad(["--verify", "--dry-run"])
        self.bad(["--destroy", "--loop", "L3"])
        self.bad(["--bogus"])
        self.bad(["--only"])
        self.bad(["--runner"])

    def test_writes_target(self):
        for cmd in ("dry-run", "verify", "check-roundtrip"):
            self.assertFalse(a2_args.Invocation(cmd, None, {}).writes_target)
        for cmd in ("install", "canary", "add-agent", "rotate-key", "destroy"):
            self.assertTrue(a2_args.Invocation(cmd, None, {}).writes_target)


class EnvAccountTest(unittest.TestCase):
    RUNNER = {"loop_account": "loopr", "l3_account": "l3r"}

    def env(self, **kw):
        e = {"HOME": "/h", "PATH": "/usr/bin:/bin", "SSH_AUTH_SOCK": "", "TERM": "xterm"}
        e.update(kw)
        return e

    def refuses(self, cause, fn, *a):
        with self.assertRaises(Refusal) as cm:
            fn(*a)
        self.assertEqual(cm.exception.cause, cause)

    def test_env(self):
        a2_host.check_env(self.env(), "l3", "/h")
        a2_host.check_env(self.env(SSH_AUTH_SOCK="/s"), "loop", "/h")
        self.refuses("RUNNER.ENV", a2_host.check_env, self.env(EXTRA="1"), "loop", "/h")
        self.refuses("RUNNER.ENV", a2_host.check_env, self.env(PATH="/bin"), "loop", "/h")
        self.refuses("RUNNER.ENV", a2_host.check_env, self.env(HOME="/other"), "loop", "/h")
        self.refuses("RUNNER.ENV", a2_host.check_env, self.env(SSH_AUTH_SOCK="/s"), "l3", "/h")
        e = self.env()
        del e["TERM"]
        self.refuses("RUNNER.ENV", a2_host.check_env, e, "loop", "/h")
        self.refuses("RUNNER.ENV", a2_host.check_env_names, self.env(X="1"))

    def test_received_environ(self):
        import shutil
        import tempfile
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "environ")
        def env_of(raw):
            with open(p, "wb") as f:
                f.write(raw)
            return a2_host.received_environ(p)
        self.assertEqual(env_of(b"HOME=/h\0PATH=/usr/bin:/bin\0SSH_AUTH_SOCK=\0TERM=x\0"),
                         {"HOME": "/h", "PATH": "/usr/bin:/bin", "SSH_AUTH_SOCK": "", "TERM": "x"})
        self.assertEqual(env_of(b""), {})
        for bad in (b"HOME=/h", b"HOME\0", b"=x\0", b"A=1\0A=2\0", b"A=\xff\0"):
            with self.subTest(bad=bad):
                self.refuses("RUNNER.ENV", env_of, bad)
        self.refuses("RUNNER.ENV", a2_host.received_environ, os.path.join(d, "absent"))

    def test_received_environ_is_what_the_launch_line_passed(self):
        """MEASURED with the system interpreter: os.environ gains LC_CTYPE
        under env -i (PEP 538); /proc/self/environ holds the four names."""
        import subprocess, sys
        code = ("import os,sys; sys.path.insert(0, sys.argv[1]); import a2_host; "
                "print(sorted(a2_host.received_environ())); print('LC_CTYPE' in os.environ)")
        r = subprocess.run([sys.executable, "-I", "-B", "-c", code, a2fix.INSTALL],
                           env={"HOME": "/h", "PATH": "/usr/bin:/bin", "SSH_AUTH_SOCK": "", "TERM": "x"},
                           capture_output=True, text=True, timeout=30)
        lines = r.stdout.splitlines()
        self.assertEqual(lines[0], "['HOME', 'PATH', 'SSH_AUTH_SOCK', 'TERM']")
        self.assertEqual(lines[1], "True")

    def pw(self, name):
        import pwd
        return lambda uid: pwd.struct_passwd((name, "x", uid, uid, "", "/h/" + name, "/bin/sh"))

    def test_kernel_account(self):
        self.assertEqual(a2_host.kernel_account(self.RUNNER, lambda: 5, lambda: 5, self.pw("l3r"))[0], "l3")
        self.assertEqual(a2_host.kernel_account(self.RUNNER, lambda: 5, lambda: 5, self.pw("loopr"))[0], "loop")
        self.refuses("RUNNER.ACCOUNT", a2_host.kernel_account, self.RUNNER, lambda: 5, lambda: 6, self.pw("l3r"))
        self.refuses("RUNNER.ACCOUNT", a2_host.kernel_account, self.RUNNER, lambda: 5, lambda: 5, self.pw("other"))

    def test_command_needs_account(self):
        I = a2_args.Invocation
        a2_host.check_account(I("install", "L3", {}), "l3")
        a2_host.check_account(I("install", None, {}), "l3")
        a2_host.check_account(I("install", "L2", {}), "loop")
        a2_host.check_account(I("install", "L1", {}), "loop")
        a2_host.check_account(I("install", "L2-leak", {}), "loop")
        a2_host.check_account(I("destroy", None, {}), "l3")
        a2_host.check_account(I("verify", None, {}), "loop")
        a2_host.check_account(I("verify", None, {}), "l3")
        self.refuses("RUNNER.ACCOUNT", a2_host.check_account, I("install", "L3", {}), "loop")
        self.refuses("RUNNER.ACCOUNT", a2_host.check_account, I("install", None, {}), "loop")
        self.refuses("RUNNER.ACCOUNT", a2_host.check_account, I("install", "L2", {}), "l3")
        self.refuses("RUNNER.ACCOUNT", a2_host.check_account, I("destroy", None, {}), "loop")


if __name__ == "__main__":
    unittest.main()
