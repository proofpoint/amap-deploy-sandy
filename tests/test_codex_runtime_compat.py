"""Host-compatible separate entry and explicit native-runtime transition guards."""
import builtins
import contextlib
import io
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import codex_transition as transition


class RuntimeBoundaryTest(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory(prefix="runtime-", dir=os.environ.get("AMAP_TEST_TMPDIR", HERE))
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name)
        self.controller = self.state / "controller.toml"

    @contextlib.contextmanager
    def host39(self):
        real = builtins.__import__
        def bounded(name, *args, **kwargs):
            if name == "tomllib" or name.startswith("amap_codex"):
                raise AssertionError("host separate guard reached native dependency " + name)
            return real(name, *args, **kwargs)
        with mock.patch.object(sys, "version_info", (3, 9, 18)), mock.patch("builtins.__import__", bounded):
            yield

    def test_canonical_separate_controller_is_read_only_without_native_imports(self):
        raw = (b'instance_id = "codex-host"\nlaunch_argv = ["codex", "app-server"]\n'
               b'operator_kickoff_enabled = true\npoll_interval_ms = 500\n'
               b'codex_model = "literal # conversation_mode = unified"\n'
               b'[lanes.mail]\nnotice_dir = "/fixture/notices"\n')
        self.controller.write_bytes(raw)
        with self.host39():
            self.assertEqual(transition.entry_mode(self.state), "separate")
        self.assertEqual(self.controller.read_bytes(), raw)
        self.assertEqual(list(self.state.iterdir()), [self.controller])

    def test_explicit_separate_and_comment_only_fixture_execute_the_guard(self):
        for raw in (b'# rendered controller\n', b'conversation_mode = "separate" # reviewed\n'):
            with self.subTest(raw=raw), self.host39():
                self.controller.write_bytes(raw)
                self.assertEqual(transition.entry_mode(self.state), "separate")

    def test_manual_unified_or_unknown_mode_never_defaults_to_separate(self):
        for value in ('"unified"', '"foreign"', 'true', 'null', '{}'):
            with self.subTest(value=value), self.host39():
                self.controller.write_text('conversation_mode = ' + value + '\n')
                with self.assertRaises(ValueError):
                    transition.entry_mode(self.state)

    def test_noncanonical_or_hidden_mode_syntax_needs_native_inspection(self):
        for raw in ('"conversation_mode" = "unified"\n',
                    '"conversation_\\u006dode" = "unified"\n',
                    "conversation_mode = 'unified'\n", '[conversation_mode]\n',
                    'conversation_mode = """unified"""\n', 'mode.value = "unified"\n',
                    'conversation_mode = "separate"\nconversation_mode = "unified"\n',
                    'launch_argv = [\n"codex"\n]\n'):
            with self.subTest(raw=raw), self.host39():
                self.controller.write_text(raw)
                with self.assertRaises(ValueError):
                    transition.entry_mode(self.state)

    def test_unicode_comment_and_string_characters_do_not_create_physical_lines(self):
        for separator in ("\u0085", "\u2028", "\u2029"):
            for mode in ("separate", "unified", "foreign"):
                prefixes = ("# comment" + separator + "[lanes.mail]\n",
                            'instance_id = "host" # comment' + separator + "[lanes.mail]\n",
                            'instance_id = "literal' + separator + '[lanes.mail]"\n')
                for prefix in prefixes:
                    raw = (prefix + 'conversation_mode = "' + mode + '"\n').encode()
                    if sys.version_info >= (3, 11):
                        import tomllib
                        self.assertEqual(tomllib.loads(raw.decode())["conversation_mode"], mode)
                    with self.subTest(separator=repr(separator), prefix=prefix, mode=mode), self.host39():
                        self.controller.write_bytes(raw)
                        self.assertEqual(transition.configuration_mode(raw), mode)
                        if mode == "separate":
                            self.assertEqual(transition.entry_mode(self.state), "separate")
                        else:
                            with self.assertRaises(ValueError):
                                transition.entry_mode(self.state)

    def test_crlf_is_supported_and_nonphysical_controls_refuse(self):
        with self.host39():
            self.controller.write_bytes(b'instance_id = "host"\r\nconversation_mode = "separate"\r\n')
            self.assertEqual(transition.entry_mode(self.state), "separate")
            for control in ("\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x7f"):
                with self.subTest(control=repr(control)):
                    self.controller.write_text('# comment' + control + '[lanes.mail]\nconversation_mode = "unified"\n')
                    with self.assertRaises(ValueError):
                        transition.entry_mode(self.state)

    def test_transition_record_requires_native_runtime_before_loading_connector(self):
        self.controller.write_text('conversation_mode = "unified"\n')
        for raw in ('{}', '{"state":"prepared"}', '{"state":"confirmed"}'):
            with self.subTest(record=raw), self.host39():
                (self.state / transition.RECORD).write_text(raw)
                with self.assertRaisesRegex(ValueError, "Python 3.11"):
                    transition.entry_mode(self.state)

    def test_maintenance_cli_refuses_unsupported_runtime_without_writes(self):
        for command in (['prepare', '--thread', '11111111-1111-4111-8111-111111111111', '--apply'],
                        ['confirm', '--apply'], ['pause', '--note', 'maintenance', '--apply']):
            before = list(self.state.iterdir())
            error = io.StringIO()
            with self.subTest(command=command), self.host39(), contextlib.redirect_stderr(error):
                self.assertEqual(transition.main(['--state', str(self.state), *command]), 1)
            self.assertIn('Python 3.11', error.getvalue())
            self.assertNotIn('Traceback', error.getvalue())
            self.assertEqual(list(self.state.iterdir()), before)


class ShippedHostWrapperTest(unittest.TestCase):
    def test_separate_start_hold_and_unified_refusal_with_native_imports_unavailable(self):
        import test_codex_interactive as surface
        box = surface._Sandbox(self)
        box.ready()
        driver = box.root / "host39-driver.py"
        driver.write_text('''import builtins, runpy, sys
from pathlib import Path
from collections import namedtuple
real = builtins.__import__
def bounded(name, *args, **kwargs):
    if name == "tomllib" or name.startswith("amap_codex"):
        raise ModuleNotFoundError("native dependency unavailable in host control", name=name)
    return real(name, *args, **kwargs)
builtins.__import__ = bounded
sys.version_info = namedtuple("version_info", "major minor micro releaselevel serial")(3, 9, 18, "final", 0)
args = sys.argv[1:]
if args[0] == "-c":
    sys.argv = ["-c", *args[2:]]
    exec(compile(args[1], "<host39-control>", "exec"), {"__name__": "__main__"})
else:
    sys.argv = args
    sys.path.insert(0, str(Path(args[0]).resolve().parent))
    runpy.run_path(args[0], run_name="__main__")
''')
        shim = box.root / "bin/python3"
        text = shim.read_text()
        needle = 'exec ' + sys.executable + ' "$@"'
        self.assertIn(needle, text)
        shim.write_text(text.replace(needle, 'exec ' + sys.executable + ' "' + str(driver) + '" "$@"'))
        result = box.run('interactive-launch', *surface.NATIVE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNotNone(box.interactive())
        (box.root / 'interactive-argv').unlink()
        (box.state / 'hold.json').write_text('{"reason":"fixture service hold"}')
        result = box.run('interactive-launch', *surface.NATIVE)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('fixture service hold', result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        self.assertIsNone(box.interactive())
        (box.state / 'hold.json').unlink()
        (box.state / 'controller.toml').write_text('conversation_mode = "unified"\n')
        calls = box.calls()
        result = box.run('interactive-launch', *surface.NATIVE)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('explicit adapter transition', result.stderr)
        self.assertEqual(box.calls(), calls)
        for separator in ("\u0085", "\u2028", "\u2029"):
            with self.subTest(hidden_header=repr(separator)):
                (box.state / 'controller.toml').write_text('# comment' + separator + '[lanes.mail]\nconversation_mode = "unified"\n')
                result = box.run('interactive-launch', *surface.NATIVE)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('explicit adapter transition', result.stderr)
                self.assertIsNone(box.interactive())
                self.assertEqual(box.calls(), calls)
        (box.state / transition.RECORD).write_text('{"state":"confirmed"}')
        result = box.run('interactive-launch', *surface.NATIVE)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Python 3.11', result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        self.assertEqual(box.calls(), calls)


if __name__ == '__main__':
    unittest.main()
