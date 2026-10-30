"""Synthetic Linux lifetime facts shared by a fixture and its helper processes."""
from pathlib import Path
import shlex
import sys
from unittest import mock

import codex_settings


def fixture(test, root):
    proc = root / "proc"
    (proc / "sys/kernel/random").mkdir(parents=True)
    (proc / "sys/kernel/random/boot_id").write_text("11111111-1111-4111-8111-111111111111")
    (proc / "1").mkdir()
    (proc / "1/stat").write_text("1 (fixture init) " + " ".join(["0"] * 19 + ["123"]))
    (proc / "self/ns").mkdir(parents=True)
    (proc / "self/ns/pid").touch()
    patch = mock.patch.object(codex_settings.environment_generation, "__defaults__", (proc,))
    patch.start()
    test.addCleanup(patch.stop)
    driver = root / "fixture-python.py"
    driver.write_text(
        "import runpy, sys\nfrom pathlib import Path\n"
        "script = sys.argv.pop(1)\n"
        "sys.path.insert(0, str(Path(script).resolve().parent))\n"
        "import codex_settings\n"
        f"codex_settings.environment_generation.__defaults__ = (Path({str(proc)!r}),)\n"
        "if Path(script).name == 'codex_settings.py':\n"
        "    raise SystemExit(codex_settings.main())\n"
        "runpy.run_path(script, run_name='__main__')\n")
    return (f'if [ -f "$1" ]; then exec {shlex.quote(sys.executable)} '
            f'{shlex.quote(str(driver))} "$@"; fi\n')


def install_driver(shim, snippet):
    raw = shim.read_text()
    marker = "exec " + shlex.quote(sys.executable)
    # Fixtures spell their fallback with the unquoted executable as well.
    if marker not in raw:
        marker = "exec " + sys.executable
    position = raw.rfind(marker)
    if position < 0:
        raise AssertionError("fixture Python shim has no real-interpreter fallback")
    shim.write_text(raw[:position] + snippet + raw[position:])
