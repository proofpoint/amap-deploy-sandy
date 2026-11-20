"""The D2 texts of W17 (alpha2/d2): the profile capture (capture.sh, its two parts and
profile_check.py) and the positive control that part A's interpreter lines satisfy S0.

Usage: UV_OFFLINE=1 /usr/bin/python3 -I -B alpha2/d2/tests/test_d2_texts.py
Runs the shipped scripts with /bin/sh and bash on this host. The shell startup files are
synthetic, and every write goes under a fresh temporary directory. Needs install/*.py and
alpha2/STAGE-CONTRACT.md from the same checkout.
"""

import copy
import glob
import hashlib
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
D2 = os.path.dirname(HERE)
REPO = os.path.dirname(os.path.dirname(D2))
INSTALL = os.path.join(REPO, "install")
sys.path.insert(0, INSTALL)
sys.path.insert(0, D2)

import a2_private  # noqa: E402
import a2_s0  # noqa: E402
import a2_site  # noqa: E402
import profile_check  # noqa: E402
from a2_causes import Refusal  # noqa: E402

ENV_SH = os.path.join(D2, "profile-env.sh")
CAPTURE = os.path.join(D2, "capture.sh")
CHECK = os.path.join(D2, "profile_check.py")
LINE = re.compile(r"[a-z][a-z0-9_.-]*(\.[A-Za-z0-9_.+-]+)*=[^\n]*")
BASH = "/usr/bin/bash"


def parse(out):
    facts = {}
    for line in out.splitlines():
        assert LINE.fullmatch(line), line
        k, v = line.split("=", 1)
        assert k not in facts, k
        facts[k] = v
    return facts


def run_env(*accounts, script=ENV_SH):
    p = subprocess.run(["/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "/bin/sh", script, *accounts],
                       capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
    return p.returncode, parse(p.stdout), p.stdout


def checker(part, text):
    return profile_check.check(part, text.encode("ascii") if isinstance(text, str) else text)


class _Git:
    def __init__(self, head):
        self._head = head

    def head(self, _checkout):
        return self._head

    def status_clean(self, _checkout):
        return True


# ------------------------------------------------------------------ part A

class PartATest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rc, cls.f, cls.out = run_env()

    def test_schema_end_and_interpreter_lines(self):
        self.assertEqual(self.f["profile.schema"], "d2-profile-env/2")
        self.assertEqual(list(self.f)[-1], "profile.end")
        for k in ("path", "sha256", "resolved_path", "resolved_sha256", "version"):
            self.assertIn("interpreter." + k, self.f)
        self.assertEqual(self.f["interpreter.path"], "/usr/bin/python3")

    def test_interpreter_lines_match_an_independent_reading(self):
        # Read here by Python, not by the script's tools. Where /usr/bin/python3 is a
        # symlink, the two shas are of the same bytes (M6, equivalent on such a host).
        real = os.path.realpath("/usr/bin/python3")
        self.assertEqual(self.f["interpreter.resolved_path"], real)
        for key, path in (("sha256", "/usr/bin/python3"), ("resolved_sha256", real)):
            with open(path, "rb") as fh:
                self.assertEqual(self.f["interpreter." + key], hashlib.sha256(fh.read()).hexdigest())

    def test_tool_list_covers_every_absolute_tool_in_the_installer(self):
        used = set()
        for path in glob.glob(os.path.join(INSTALL, "*.py")):
            with open(path, encoding="utf-8") as fh:
                used |= set(re.findall(r'"(/(?:usr/)?s?bin/[A-Za-z0-9_.-]+)"', fh.read()))
        used.discard("/usr/bin/python3")  # captured as `interpreter`, not as a tool
        with open(ENV_SH, encoding="utf-8") as fh:
            tools = re.search(r'^TOOLS="([^"]*)"$', fh.read(), re.M).group(1).split()
        self.assertTrue(used, "no tool literal found: the census itself is broken")
        self.assertLessEqual(used, set(tools))
        self.assertIn("/usr/bin/env", tools)  # the launch line's first word (5.1)
        # The checker's list is the script's list.
        self.assertEqual(tuple(os.path.basename(t) for t in tools), profile_check.TOOLS)

    def test_every_listed_tool_is_reported_with_a_sha(self):
        for name in profile_check.TOOLS:
            self.assertRegex(self.f["tool.%s.sha256" % name], r"^[0-9a-f]{64}$")

    def test_accounts_by_name_and_a_bad_name_refused(self):
        rc, f, _ = run_env("root")
        self.assertEqual(f["account.root.uid"], "0")
        rc, f, out = run_env("bad;name")
        self.assertEqual(rc, 1)
        self.assertEqual(f["account.invalid_name"], "REFUSED")
        self.assertNotIn("bad;name", out)

    def test_absent_account_is_rc1_and_still_prints(self):
        rc, f, _ = run_env("no-such-account-d2")
        self.assertEqual(rc, 1)
        self.assertEqual(f["account.no-such-account-d2"], "ABSENT")
        self.assertEqual(f["profile.end"], "incomplete")


class PartAEdgeTest(unittest.TestCase):
    """Part A with ONE controlled change to a scratch copy of the shipped file (the
    interpreter or a tool repointed). Every other byte is the shipped file."""

    def run_copy(self, *pairs):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        with open(ENV_SH, encoding="utf-8") as fh:
            text = fh.read()
        for old, new in zip(pairs[::2], pairs[1::2]):
            self.assertEqual(text.count(old), 1, old)
            text = text.replace(old, new.replace("@D@", d))
        path = os.path.join(d, "profile-env.sh")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        rc, f, _ = run_env(script=path)
        return d, rc, f

    SLEEP_OK = ("if [ -x /usr/bin/systemctl ]; then", "if true; then",
                'w=$(/usr/bin/systemctl is-enabled "$u" 2>/dev/null </dev/null)', "w=masked")

    def test_missing_interpreter_is_rc1(self):  # Opus R1
        _, rc, f = self.run_copy(*self.SLEEP_OK)
        self.assertEqual((rc, f["profile.end"]), (0, "complete"))  # control: nothing else sets rc
        _, rc, f = self.run_copy("py=/usr/bin/python3\n", "py=@D@/no-python3\n", *self.SLEEP_OK)
        self.assertEqual(rc, 1)
        self.assertEqual(f["interpreter.path"], "ABSENT")
        self.assertEqual(f["profile.end"], "incomplete")

    def test_execute_only_tool_is_unobserved_never_empty(self):  # Opus 3b, Codex 2
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        xo = os.path.join(d, "xorealpath")
        shutil.copy("/usr/bin/realpath", xo)
        os.chmod(xo, 0o111)
        if os.access(xo, os.R_OK):
            self.skipTest("this user reads mode 0111 files (root)")
        _, rc, f = self.run_copy('TOOLS="/usr/bin/env ', 'TOOLS="%s /usr/bin/env ' % xo)
        self.assertEqual(rc, 1)
        self.assertEqual(f["tool.xorealpath.sha256"], "UNOBSERVED")
        self.assertEqual(f["profile.end"], "incomplete")
        self.assertFalse([k for k, v in f.items() if v == ""])

    def test_a_directory_in_a_tools_place_is_unobserved(self):
        _, rc, f = self.run_copy('TOOLS="/usr/bin/env ', 'TOOLS="@D@ /usr/bin/env ')
        self.assertEqual(rc, 1)
        self.assertFalse([k for k, v in f.items() if v == ""])

    def test_unobserved_sleep_is_rc1(self):  # Opus 3c, Codex 2
        # The systemctl branch taken with a systemctl that answers nothing for any unit.
        _, rc, f = self.run_copy("if [ -x /usr/bin/systemctl ]; then", "if true; then",
                                 "w=$(/usr/bin/systemctl is-enabled", "w=$(/usr/bin/true is-enabled")
        self.assertEqual(rc, 1)
        self.assertEqual(f["sleep.sleep.target"], "UNOBSERVED")
        self.assertEqual(f["profile.end"], "incomplete")


class PositiveControlTest(unittest.TestCase):
    """Part A's interpreter lines, as a lock block, pass S0's own check on this host's
    /usr/bin/python3; changing any one of the five fields alone refuses."""

    def setUp(self):
        _, f, _ = run_env()
        self.block = {k: f["interpreter." + k]
                      for k in ("path", "sha256", "resolved_path", "resolved_sha256", "version")}
        real = os.path.realpath(sys.executable)
        if real != self.block["resolved_path"]:
            self.skipTest("run this test with /usr/bin/python3 (it runs under %s)" % real)
        self.lock = {"interpreter": self.block,
                     "installer": {"sha256": "c" * 64, "commit": "d" * 40}}
        self.site = a2_site.Site()
        self.site.installer_sha = "c" * 64
        self.site.entry = os.path.join(REPO, "install", "alpha2_install.py")
        self.site.git = _Git("d" * 40)

    def test_captured_block_passes(self):
        a2_s0.check_interpreter(self.lock, self.site)

    def test_each_field_changed_alone_refuses(self):
        other = {"sha256": "e" * 64, "resolved_path": "/usr/bin/python9",
                 "resolved_sha256": "e" * 64, "version": "3.0.0"}
        for k, v in other.items():
            with self.subTest(field=k):
                lock = copy.deepcopy(self.lock)
                lock["interpreter"][k] = v
                with self.assertRaises(Refusal) as cm:
                    a2_s0.check_interpreter(lock, self.site)
                self.assertEqual(cm.exception.cause, "PREFLIGHT.INTERPRETER")

    def test_the_path_field_is_refused_by_the_lock_check(self):
        # `interpreter.path` is the constant /usr/bin/python3 (6.1). S0's
        # check_interpreter hashes the fixed launch path and never reads this field;
        # the lock check (L3) refuses any other value before S0 runs.
        sys.path.insert(0, os.path.join(INSTALL, "tests"))
        import a2fix
        lock = copy.deepcopy(a2fix.LOCK)
        lock["interpreter"] = dict(self.block)
        a2_private.check_lock(lock)
        lock["interpreter"]["path"] = "/usr/bin/python9"
        with self.assertRaises(a2_private.Invalid) as cm:
            a2_private.check_lock(lock)
        self.assertEqual((cm.exception.check, cm.exception.path), ("L3", "$.interpreter.path"))


# ---------------------------------------------------------- the checker

def _valid_env_text():
    _, f, out = run_env("root")
    lines = [l for l in out.splitlines() if not l.startswith(("sleep.", "profile.end="))]
    lines += ["sleep.%s=masked" % u for u in profile_check.SLEEP] + ["profile.end=complete"]
    return "\n".join(lines) + "\n"


class CheckerTest(unittest.TestCase):
    def test_env_valid_and_each_breakage_refused(self):
        good = _valid_env_text()
        self.assertIsNone(checker("env", good))
        sha_key = next(l for l in good.splitlines() if l.startswith("interpreter.sha256="))
        cases = {
            "empty": "",
            "no final newline": good[:-1],
            "duplicate key": good.replace("profile.end=complete\n", sha_key + "\nprofile.end=complete\n"),
            "missing key": good.replace(sha_key + "\n", ""),
            "extra key": good.replace("profile.end=complete\n", "extra.key=x\nprofile.end=complete\n"),
            "bad sha shape": good.replace(sha_key, "interpreter.sha256=" + "A" * 64),
            "unobserved": good.replace("sleep.sleep.target=masked", "sleep.sleep.target=UNOBSERVED"),
            "unobserved version": re.sub(r"(?m)^tool\.git\.version=.*$", "tool.git.version=UNOBSERVED", good),
            "end not last": good.replace("profile.end=complete\n", "").replace(
                "profile.schema=", "profile.end=complete\nprofile.schema="),
            "incomplete end": good.replace("profile.end=complete", "profile.end=incomplete"),
            "control byte": good.replace("host.arch=", "host.arch=\x1b"),
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                self.assertIsNotNone(checker("env", text))

    def test_shell_refusals(self):
        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home)
        good = CaptureTest.capture(home, "")[2]
        self.assertIsNotNone(good)
        self.assertIsNone(checker("shell", good))
        for name, text in {
            "launch interposed": good.replace("launch.first_word=file", "launch.first_word=function"),
            "shadow": "shadow.trap=function\n" + good,
            "value-shaped name": good.replace("env.names=", "env.names=A=1 "),
            "kind other": good.replace("shell.kind=bash", "shell.kind=other"),
            "refused end": good.replace("profile.end=complete", "profile.end=refused"),
        }.items():
            with self.subTest(case=name):
                self.assertIsNotNone(checker("shell", text))

    def test_over_the_limit_is_refused_and_nothing_admitted(self):  # Opus r2-1
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        good = _valid_env_text()
        src, out = os.path.join(d, "x.txt"), os.path.join(d, "out.txt")
        pad = "host.pad=" + "a" * (profile_check.LIMIT) + "\n"
        with open(src, "w") as fh:
            fh.write(good + pad + "API_TOKEN=ghp_PASTLIMIT77\n")
        rc = profile_check.main(["x", "env", src, out])
        self.assertEqual(rc, 1)
        self.assertFalse(os.path.exists(out))
        self.assertEqual(profile_check.read_bounded(src),
                         (None, "the file is longer than %d bytes" % profile_check.LIMIT))

    def test_the_admitted_bytes_are_the_validated_bytes(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        good = _valid_env_text().encode()
        src, out = os.path.join(d, "x.txt"), os.path.join(d, "out.txt")
        with open(src, "wb") as fh:
            fh.write(good)
        self.assertEqual(profile_check.main(["x", "env", src, out]), 0)
        with open(out, "rb") as fh:
            self.assertEqual(fh.read(), good)
        self.assertEqual(os.stat(out).st_mode & 0o777, 0o600)
        # A second admission never overwrites.
        self.assertEqual(profile_check.main(["x", "env", src, out]), 1)

    def test_the_cli_prints_no_value(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        path = os.path.join(d, "x.txt")
        with open(path, "w") as fh:
            fh.write(_valid_env_text().replace("host.arch=", "host.arch=SECRETISH 77 ="))
        p = subprocess.run(["/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "/usr/bin/python3", "-I", "-S", "-B",
                            CHECK, "env", path], capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 1)
        self.assertNotIn("SECRETISH", p.stdout + p.stderr)


# ---------------------------------------------------- the whole capture

@unittest.skipUnless(os.path.exists(BASH), "bash absent")
class CaptureTest(unittest.TestCase):
    """capture.sh end to end, typed as the text gives it, against a bash login shell
    whose startup files are hostile in the ways both W17 r1 reviews measured."""

    PLANTED = ("echo RCPRINT77\n"
               "alias d2al='echo ALIASBODY77'\n"
               "d2fn() { echo FUNCBODY77; }\n"
               "PROMPT_COMMAND='echo HOOKTEXT77'\n"
               "trap 'echo TRAPTEXT77' DEBUG\n"
               "export D2SECRET=ENVVALUE77\n")
    # Opus f1: aliases over tools, one of which would leak a token through `env`.
    F1 = ("export API_TOKEN=ghp_FAKEVALUE1234567890\n"
          "alias env='env; echo ALIASENVBODY'\n"
          "alias sed='echo SEDALIAS77'\n"
          "alias printf='echo PRINTFALIAS77'\n"
          "alias builtin='echo BUILTINALIAS77; '\n")
    # Opus f2: multi-line values whose inner lines look like NAME=..., and a function over env.
    F2 = ("export PEMKEY=$'-----BEGIN KEY-----\\nKEYTAILabc123XYZ=\\n-----END KEY-----'\n"
          "export CFG=$'host=a\\nDB_PASSWORD=hunter2'\n"
          "alias zz=$'echo a\\nalias LEAKEDALIASLINE=x'\n"
          "env() { command env \"$@\"; echo FNENVBODY=1; }\n")
    # Opus f3: a printf function that logs every argument outside the capture.
    F3 = "printf() { builtin printf \"$@\"; builtin printf '%s\\n' \"$*\" >> \"$HOME/printf.log\"; }\n"
    # Codex's probe: a DEBUG trap writing a marker to fd 3, and a startup file that
    # opens fd 3 itself.
    FD3 = ("if { true >&3; } 2>/dev/null; then echo OPEN > \"$HOME/fd3-open-at-startup\"; fi\n"
           "trap 'echo FD3MARK77 >&3' DEBUG\n"
           "exec 3>>\"$HOME/own-fd3.log\"\n")

    @staticmethod
    def capture(home, extra, profile_only=None, out=None):
        for name in (".bash_profile", ".bashrc"):
            with open(os.path.join(home, name), "w") as fh:
                if profile_only is not None and name == ".bash_profile":
                    fh.write(profile_only)
                else:
                    fh.write(CaptureTest.PLANTED + extra)
        out = out or os.path.join(home, "out")
        os.makedirs(out, exist_ok=True)
        # The text's own line (PROFILE-CAPTURE.md); the current shell here is /bin/sh.
        p = subprocess.run(["/bin/sh", "-c",
                            '/usr/bin/env -i HOME="$HOME" SHELL="$SHELL" TERM="$TERM" USER="$USER" '
                            'LOGNAME="$LOGNAME" SSH_AUTH_SOCK="$SSH_AUTH_SOCK" PATH=/usr/bin:/bin '
                            '/bin/sh "$0" "$1" root', CAPTURE, out],
                           env={"HOME": home, "SHELL": BASH, "TERM": "dumb", "USER": "op", "LOGNAME": "op",
                                "SSH_AUTH_SOCK": "", "PATH": "/usr/bin:/bin"},
                           capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
        path = os.path.join(out, "profile-shell.txt")
        text = None
        if os.path.exists(path):
            with open(path, encoding="ascii") as fh:
                text = fh.read()
        return p, path, text

    def run_case(self, extra="", profile_only=None):
        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home)
        self.home = home
        p, path, text = self.capture(home, extra, profile_only)
        self.assertRegex(p.stdout, r"(?m)^PART-B shell_rc=")
        return p, text

    def assert_admitted(self, p, text):
        self.assertIn("CHECK shell VALID", p.stdout)
        self.assertIsNotNone(text)
        self.assertEqual(text.splitlines()[-1], "profile.end=complete")
        self.assertEqual(os.stat(os.path.join(self.home, "out", "profile-shell.txt")).st_mode & 0o777, 0o600)
        return parse(text)

    def assert_no_leak(self, p, text, *needles):
        for n in needles:
            self.assertNotIn(n, text or "")
            self.assertNotIn(n, p.stdout + p.stderr)

    def test_names_only_never_bodies_or_values(self):
        p, text = self.run_case()
        f = self.assert_admitted(p, text)
        self.assertIn("d2al", f["alias.names"].split())
        self.assertIn("d2fn", f["function.names"].split())
        self.assertEqual(f["hook.PROMPT_COMMAND"], "set")
        self.assertEqual(f["hook.trap_DEBUG"], "set")
        self.assertEqual(f["hook.BASH_ENV"], "unset")
        self.assertIn("D2SECRET", f["env.names"].split())
        self.assertEqual(f["launch.first_word"], "file")
        self.assertFalse([n for n in f["function.names"].split() if n.startswith("__d2_")])
        self.assert_no_leak(p, text, "RCPRINT77", "ALIASBODY77", "FUNCBODY77", "HOOKTEXT77", "TRAPTEXT77",
                            "ENVVALUE77")

    def test_f1_aliases_over_tools_are_never_called(self):
        p, text = self.run_case(self.F1)
        f = self.assert_admitted(p, text)
        self.assert_no_leak(p, text, "ghp_FAKEVALUE", "ALIASENVBODY", "SEDALIAS77", "PRINTFALIAS77", "BUILTINALIAS77")
        self.assertIn("API_TOKEN", f["env.names"].split())
        self.assertIn("env", f["alias.names"].split())

    def test_f2_multiline_values_never_surface_as_names(self):
        p, text = self.run_case(self.F2)
        f = self.assert_admitted(p, text)
        self.assertIn("PEMKEY", f["env.names"].split())
        self.assertIn("CFG", f["env.names"].split())
        self.assertIn("zz", f["alias.names"].split())
        self.assertIn("env", f["function.names"].split())
        self.assert_no_leak(p, text, "KEYTAILabc123XYZ", "DB_PASSWORD", "hunter2", "LEAKEDALIASLINE", "FNENVBODY")

    def test_f3_a_printf_function_is_never_called(self):
        p, text = self.run_case(self.F3)
        f = self.assert_admitted(p, text)
        self.assertFalse(os.path.exists(os.path.join(self.home, "printf.log")))
        self.assertIn("printf", f["function.names"].split())

    def test_f4_a_startup_exit_is_not_admitted(self):
        p, text = self.run_case(profile_only="exit 0\n")
        self.assertIn("CHECK shell INVALID", p.stdout)
        self.assertIsNone(text)
        self.assertIn("D2-PROFILE INCOMPLETE", p.stdout)
        self.assertNotEqual(p.returncode, 0)

    def test_codex_fd3_probe_never_reaches_the_capture(self):
        p, text = self.run_case(self.FD3)
        self.assert_admitted(p, text)
        self.assert_no_leak(p, text, "FD3MARK77")
        self.assertFalse(os.path.exists(os.path.join(self.home, "fd3-open-at-startup")))

    def test_functions_named_builtin_trap_unset_are_never_called(self):  # Codex r2-2
        logging = "".join('%s() { echo PWN > "$HOME/pwn-%s"; command %s "$@"; }\n' % (f, f, f)
                          for f in ("builtin", "trap", "unset", "shopt", "set", "printf", "compgen"))
        p, text = self.run_case(logging)
        self.assert_admitted(p, text)
        self.assertEqual([n for n in os.listdir(self.home) if n.startswith("pwn-")], [])

    def test_a_stray_set_dashdash_never_redirects_or_truncates(self):  # Codex r2-1, Opus r2-3
        victim = 'printf OPERATORDATA > "$HOME/victim"\nset -- "$HOME/victim"\nshift 0\n'
        p, text = self.run_case(victim)
        self.assert_admitted(p, text)
        with open(os.path.join(self.home, "victim")) as fh:
            self.assertEqual(fh.read(), "OPERATORDATA")

    def test_a_trap_builtin_disabled_is_refused_not_admitted_as_unset(self):  # Opus r2-2a
        p, text = self.run_case("trap 'echo T >> \"$HOME/dbg.log\"' DEBUG\nenable -n trap\n")
        self.assertIn("CHECK shell INVALID", p.stdout)
        self.assertIsNone(text)

    def test_an_extdebug_trap_that_skips_commands_is_refused(self):  # Opus r2-2b
        # extdebug set in a startup file is off again by the time -c runs (measured, bash
        # 5.2.37), so the trap turns it on itself, as Opus's r2 probe did.
        p, text = self.run_case("trap 'shopt -s extdebug; ! [[ $BASH_COMMAND == *trap* || $BASH_COMMAND == *shopt* ]]' DEBUG\n")
        self.assertIn("CHECK shell INVALID", p.stdout)
        self.assertIsNone(text)

    def test_a_trap_that_skips_only_its_own_removal_is_refused(self):  # kills C2
        p, text = self.run_case("trap 'shopt -s extdebug; ! [[ $BASH_COMMAND == *shopt* || $BASH_COMMAND == *\"trap - \"* ]]' DEBUG\n")
        self.assertIn("CHECK shell INVALID", p.stdout)
        self.assertIsNone(text)

    # -- Opus r3 finding 4: shapes that defeat a plain `unset -f builtin`. Each must
    # end with nothing admitted AND no startup function called.
    LOGB = 'builtin() { echo PWN > "$HOME/pwn-builtin"; command builtin "$@"; }\n'

    def assert_nothing_called_nothing_admitted(self, extra):
        p, text = self.run_case(extra)
        self.assertIsNone(text, p.stdout)
        self.assertEqual([n for n in os.listdir(self.home) if n.startswith("pwn")], [])

    def test_a_readonly_builtin_function_is_never_called(self):
        self.assert_nothing_called_nothing_admitted(self.LOGB + "readonly -f builtin\n")

    def test_a_disabled_unset_builtin_never_calls_builtin(self):
        self.assert_nothing_called_nothing_admitted(self.LOGB + "enable -n unset\n")

    def test_a_readonly_posixly_correct_is_refused(self):
        self.assert_nothing_called_nothing_admitted(self.LOGB + "readonly POSIXLY_CORRECT\n")

    def test_a_nameref_posixly_correct_is_refused(self):
        self.assert_nothing_called_nothing_admitted(self.LOGB + "declare -n POSIXLY_CORRECT=d2zzz\n")

    def test_an_alias_over_if_never_runs(self):
        p, text = self.run_case('d2x() { echo PWN > "$HOME/pwn-aliasif"; }\nalias if="d2x; if"\n')
        self.assert_admitted(p, text)
        self.assertFalse(os.path.exists(os.path.join(self.home, "pwn-aliasif")))

    def test_a_disabled_shopt_with_an_alias_over_builtin(self):
        self.assert_nothing_called_nothing_admitted(
            'alias builtin="echo X >> $HOME/pwn-alias; builtin "\nenable -n shopt\n')

    def test_posix_mode_is_the_operators_own(self):  # Opus r3 finding 8
        p, text = self.run_case()
        self.assertEqual(self.assert_admitted(p, text)["shell.posix_mode"], "off")
        p, text = self.run_case("set -o posix\n")
        self.assertEqual(self.assert_admitted(p, text)["shell.posix_mode"], "on")

    # -- Opus r2/r3: the rest of the named corpus, as measured on r3.
    def test_corpus_refused(self):
        for name, extra in (("set -e", "set -e\n"), ("IFS", "IFS=x\n"),
                            ("ERR trap", "set -o errtrace\ntrap 'echo ERRMARK77' ERR\n")):
            with self.subTest(name=name):
                p, text = self.run_case(extra)
                self.assertIsNone(text, p.stdout)
                self.assertNotIn("ERRMARK77", p.stdout + p.stderr)

    def test_corpus_admitted_clean(self):
        for name, extra in (
                ("set -u, noclobber", "set -u -o noclobber\n"),
                ("EXIT trap", "trap 'echo EXITMARK77' EXIT\n"),
                ("exec redirects", 'exec 5>>"$HOME/r5" 1>>"$HOME/r1" 2>&1\necho EXECMARK77\n'),
                ("background job", '(sleep 1; echo BGMARK77) &\n'),
                ("PS0 and PROMPT_COMMAND", "PS0='PS0MARK77'\nPROMPT_COMMAND='echo PCMARK77'\n"),
                ("set -- and shift", 'set -- a b c\nshift\n')):
            with self.subTest(name=name):
                p, text = self.run_case(extra)
                f = self.assert_admitted(p, text)
                for marker in ("EXITMARK77", "EXECMARK77", "BGMARK77", "PS0MARK77", "PCMARK77"):
                    self.assertNotIn(marker, text)

    def test_a_file_created_in_out_during_the_run_is_never_overwritten(self):  # Opus R4, kills B6
        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home)
        out = os.path.join(home, "out")
        os.makedirs(out)
        p, _, text = self.capture(home, 'printf OPERATORFILE > "%s/profile-shell.txt"\n' % out, out=out)
        self.assertEqual(text, "OPERATORFILE")
        self.assertIn("NOT ADMITTED profile-shell.txt", p.stdout)
        self.assertIn("D2-PROFILE INCOMPLETE", p.stdout)

    def test_bash_env_and_env_reported_set(self):  # Opus R2
        p, text = self.run_case("export BASH_ENV=/nonexistent/BASHENVPATH77\nexport ENV=/nonexistent/ENVPATH77\n")
        f = self.assert_admitted(p, text)
        self.assertEqual(f["hook.BASH_ENV"], "set")
        self.assertEqual(f["hook.ENV"], "set")
        self.assert_no_leak(p, text, "BASHENVPATH77", "ENVPATH77")

    def test_a_function_in_front_of_the_launch_line_is_not_admitted(self):
        p, text = self.run_case("/usr/bin/env() { command env \"$@\"; }\n")
        self.assertIn("CHECK shell INVALID: something stands in front of /usr/bin/env", p.stdout)
        self.assertIsNone(text)

    def test_an_existing_output_is_never_overwritten(self):
        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home)
        out = os.path.join(home, "out")
        os.makedirs(out)
        with open(os.path.join(out, "profile-shell.txt"), "w") as fh:
            fh.write("KEEP\n")
        p, _, text = self.capture(home, "", out=out)
        self.assertEqual(text, "KEEP\n")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("nothing is overwritten", p.stdout)


class PartAStepTest(unittest.TestCase):
    """PART-A-STEP.md's step 1, the typed line, run as written under /bin/sh with the
    placeholders filled and the caller's umask 022 (Codex r4A 1-3)."""

    PART_A = os.path.join(D2, "part-a.sh")

    def typed_line(self):
        with open(os.path.join(D2, "PART-A-STEP.md"), encoding="utf-8") as fh:
            text = fh.read()
        lines = re.findall(r"^   ('/usr/bin/env' .*part-a\.sh.*)$", text, re.M)
        self.assertEqual(len(lines), 1, lines)
        with open(self.PART_A, encoding="utf-8") as fh:
            self.assertIn("#   " + lines[0] + "\n", fh.read())
        return lines[0]

    def checkout(self, env_sh_pairs=(), stub_check=None):
        """A checkout copy holding part-a.sh, profile-env.sh (with any listed
        replacements) and profile_check.py (or a stub)."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        dd = os.path.join(d, "alpha2", "d2")
        os.makedirs(dd)
        shutil.copy(self.PART_A, dd)
        with open(ENV_SH, encoding="utf-8") as fh:
            text = fh.read()
        for old, new in zip(env_sh_pairs[::2], env_sh_pairs[1::2]):
            self.assertEqual(text.count(old), 1, old)
            text = text.replace(old, new)
        with open(os.path.join(dd, "profile-env.sh"), "w", encoding="utf-8") as fh:
            fh.write(text)
        if stub_check is None:
            shutil.copy(CHECK, dd)
        else:
            with open(os.path.join(dd, "profile_check.py"), "w", encoding="utf-8") as fh:
                fh.write(stub_check)
        return d

    def run_step(self, checkout, out=None):
        if out is None:
            d = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, d)
            out = os.path.join(d, "out")
            os.makedirs(out)
        cmd = (self.typed_line().replace("<checkout>", checkout).replace("<out>", out)
               .replace("<loop-account>", "root").replace("<l3-account>", pwd.getpwuid(os.getuid()).pw_name))
        p = subprocess.run(["/bin/sh", "-c", "umask 022; " + cmd], capture_output=True, text=True, timeout=120,
                           env={"PATH": "/usr/bin:/bin"})
        return out, p

    def test_the_refused_path_admits_nothing_and_leaves_no_scratch(self):
        if os.path.exists("/usr/bin/systemctl"):
            self.skipTest("this host has systemctl")
        out, p = self.run_step(REPO)
        self.assertIn("CHECK env INVALID: sleep.systemctl was not observed", p.stdout)
        self.assertEqual(p.stdout.splitlines()[-1], "D2.1-PART-A NOT ADMITTED")
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(os.listdir(out), [])

    def test_the_admitted_path(self):
        out, p = self.run_step(self.checkout(PartAEdgeTest.SLEEP_OK))
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertEqual(p.stdout.splitlines()[-1], "D2.1-PART-A ADMITTED")
        self.assertIn("CHECK env VALID\nADMITTED profile-env.txt", p.stdout)
        self.assertEqual(os.listdir(out), ["profile-env.txt"])
        path = os.path.join(out, "profile-env.txt")
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        with open(path, "rb") as fh:
            self.assertIn(hashlib.sha256(fh.read()).hexdigest(), p.stdout)

    def test_the_scratch_file_is_0600_under_a_022_caller(self):  # Codex r4A 1
        stub = ("import os, sys\n"
                "print('SCRATCH-MODE', oct(os.stat(sys.argv[2]).st_mode & 0o777))\n"
                "sys.exit(1)\n")
        out, p = self.run_step(self.checkout(stub_check=stub))
        self.assertIn("SCRATCH-MODE 0o600", p.stdout)
        self.assertEqual(os.listdir(out), [])  # removed by the run that made it

    def test_an_existing_scratch_file_is_refused_and_untouched(self):  # Codex r4A 2
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        out = os.path.join(d, "out")
        os.makedirs(out)
        sentinel = os.path.join(out, "profile-env.unchecked")
        with open(sentinel, "w") as fh:
            fh.write("SENTINEL\n")
        out, p = self.run_step(self.checkout(PartAEdgeTest.SLEEP_OK), out=out)
        self.assertIn("already exists; nothing was changed", p.stdout)
        self.assertNotEqual(p.returncode, 0)
        with open(sentinel) as fh:
            self.assertEqual(fh.read(), "SENTINEL\n")
        self.assertEqual(os.listdir(out), ["profile-env.unchecked"])

    def test_a_symlink_or_fifo_at_the_scratch_path_is_refused_and_kept(self):  # Opus r4A.1 blocker 2
        for kind in ("symlink-devnull", "symlink-file", "dangling", "fifo", "directory"):
            with self.subTest(kind=kind):
                d = tempfile.mkdtemp()
                self.addCleanup(shutil.rmtree, d)
                out = os.path.join(d, "out")
                os.makedirs(out)
                target = os.path.join(d, "target")
                with open(target, "w") as fh:
                    fh.write("TARGET\n")
                scratch = os.path.join(out, "profile-env.unchecked")
                if kind == "symlink-devnull":
                    os.symlink("/dev/null", scratch)
                elif kind == "symlink-file":
                    os.symlink(target, scratch)
                elif kind == "dangling":
                    os.symlink(os.path.join(d, "nothing"), scratch)
                elif kind == "fifo":
                    os.mkfifo(scratch, 0o600)
                else:
                    os.mkdir(scratch)
                before = os.lstat(scratch)
                out, p = self.run_step(self.checkout(PartAEdgeTest.SLEEP_OK), out=out)
                self.assertIn("already exists; nothing was changed", p.stdout)
                self.assertNotEqual(p.returncode, 0)
                after = os.lstat(scratch)
                self.assertEqual((before.st_ino, before.st_mode), (after.st_ino, after.st_mode))
                self.assertEqual(os.listdir(out), ["profile-env.unchecked"])
                with open(target) as fh:
                    self.assertEqual(fh.read(), "TARGET\n")

    @unittest.skipUnless(next((z for z in (os.environ.get("D2_TEST_ZSH"), "/usr/bin/zsh", "/bin/zsh")
                               if z and os.access(z, os.X_OK)), None), "no zsh (set D2_TEST_ZSH)")
    def test_zsh_aliases_cannot_replace_a_quoted_word(self):  # Opus r4A.1 blocker 1
        zsh = next(z for z in (os.environ.get("D2_TEST_ZSH"), "/usr/bin/zsh", "/bin/zsh")
                   if z and os.access(z, os.X_OK))
        with open(os.path.join(D2, "PART-A-STEP.md"), encoding="utf-8") as fh:
            step0 = re.search(r"^   ('whence' .*)$", fh.read(), re.M).group(1)
        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home)
        out = os.path.join(home, "out")
        os.makedirs(out)
        step1 = (self.typed_line().replace("<checkout>", self.checkout(PartAEdgeTest.SLEEP_OK))
                 .replace("<out>", out).replace("<loop-account>", "root")
                 .replace("<l3-account>", pwd.getpwuid(os.getuid()).pw_name))

        def run(zshrc):
            with open(os.path.join(home, ".zshrc"), "w") as fh:
                fh.write(zshrc)
            for name in os.listdir(out):
                os.unlink(os.path.join(out, name))
            return subprocess.run([zsh, "-i", "-c", step0 + "\n" + step1],
                                  env={"HOME": home, "ZDOTDIR": home, "PATH": "/usr/bin:/bin", "TERM": "dumb"},
                                  capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)

        # Global aliases on argument words: quoted words are never expanded, so step 0
        # passes truthfully and step 1 runs the real programs.
        # A global alias on an argument word that step 0 does not name (/bin/sh): the
        # quoted word is never expanded, so step 1 runs the real program.
        p = run("alias -g /bin/sh='/bin/echo HIJACKED-SH'\n")
        self.assertNotIn("HIJACKED", p.stdout)
        self.assertTrue(p.stdout.startswith("whence: builtin\n/usr/bin/env: command\n"), p.stdout)
        self.assertEqual(p.stdout.splitlines()[-1], "D2.1-PART-A ADMITTED")
        # A global alias on /usr/bin/env itself: step 0 reports it, and the quoted step 1
        # still runs the real program.
        p = run("alias -g /usr/bin/env='/bin/echo HIJACKED-ENV'\n")
        self.assertNotIn("HIJACKED", p.stdout)
        self.assertTrue(p.stdout.startswith("whence: builtin\n/usr/bin/env: global alias\n"), p.stdout)
        # An alias that would forge step 0's lines: the quoted command word is not
        # expanded, and the real whence reports the alias, so the operator stops.
        p = run("alias whence='print -l \"whence: builtin\" \"/usr/bin/env: command\" #'\n")
        self.assertTrue(p.stdout.startswith("whence: alias\n"), p.stdout)

    def test_the_operator_shell_runs_only_the_gated_words(self):  # Codex r4A 3
        with open(os.path.join(D2, "PART-A-STEP.md"), encoding="utf-8") as fh:
            text = fh.read()
        blocks = re.findall(r"```sh\n(.*?)```", text, re.S)
        lines = [line for b in blocks for line in b.strip().splitlines()]
        words = sorted({line.split()[0].strip("'") for line in lines})
        self.assertEqual(words, ["/usr/bin/env", "whence"])
        for line in lines:  # Opus r4A.1 blocker 1: every word quoted
            for w in line.split():
                self.assertTrue(len(w) > 1 and w.startswith("'") and w.endswith("'"), (line, w))
        self.assertIn("'whence' '-w' 'whence' '/usr/bin/env'", text)
        self.assertIn("   whence: builtin\n   /usr/bin/env: command\n", text)


class TextsAgreeTest(unittest.TestCase):
    def test_capture_text_types_the_shipped_line(self):
        with open(os.path.join(D2, "PROFILE-CAPTURE.md"), encoding="utf-8") as fh:
            text = fh.read()
        with open(CAPTURE, encoding="utf-8") as fh:
            line = re.search(r"^#   (/usr/bin/env -i .*capture\.sh <out> <loop-account> <l3-account>)$",
                             fh.read(), re.M).group(1)
        self.assertIn(line, text)
        self.assertNotIn("$(", line)  # the current shell runs no command substitution

    def test_dry_run_text_uses_the_contract_launch_line(self):
        with open(os.path.join(REPO, "alpha2", "STAGE-CONTRACT.md"), encoding="utf-8") as fh:
            contract = fh.read()
        launch = re.search(r"^(/usr/bin/env -i HOME=.*alpha2_install\.py) \[flags\]$", contract, re.M).group(1)
        with open(os.path.join(D2, "POSITIVE-CONTROL-DRY-RUN.md"), encoding="utf-8") as fh:
            self.assertIn(launch + " --dry-run;", fh.read())


if __name__ == "__main__":
    unittest.main()
