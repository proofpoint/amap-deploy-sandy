"""ALPHA-2 installer entry (stage contract, section 5.1).

Run only by the launch line:
  /usr/bin/env -i HOME=... SSH_AUTH_SOCK=... TERM=... PATH=/usr/bin:/bin \
      /usr/bin/python3 -I -B <checkout>/install/alpha2_install.py [flags]

This file loads no code except through the one loader below, which hashes
each module's bytes in memory, compares them with `install/MANIFEST`, and
executes those same bytes (section 6.1, `installer`). A module that is not
listed, or whose bytes differ, refuses with `PREFLIGHT.INTERPRETER`.
"""

import hashlib
import importlib.abc
import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.realpath(__file__))
MANIFEST = "MANIFEST"
_LINE = re.compile(rb"([0-9a-f]{64})  ([A-Za-z0-9_]{1,64}\.py)")
_INTERPRETER_TEXT = ("CAUSE=PREFLIGHT.INTERPRETER\n"
                     "Look at the interpreter and the installer files: a hash differs from alpha2.lock.\n")


def _refuse_interpreter():
    sys.stderr.write(_INTERPRETER_TEXT)
    sys.stderr.flush()
    os._exit(2)


def _read_manifest():
    try:
        with open(os.path.join(HERE, MANIFEST), "rb") as f:
            raw = f.read()
    except OSError:
        _refuse_interpreter()
    if not raw.endswith(b"\n"):
        _refuse_interpreter()
    listed = {}
    for line in raw.split(b"\n")[:-1]:
        m = _LINE.fullmatch(line)
        if m is None:
            _refuse_interpreter()
        name = m.group(2).decode("ascii")
        if name in listed:
            _refuse_interpreter()
        listed[name] = m.group(1).decode("ascii")
    return raw, listed


class _PinnedFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Serves the installer's own modules from the bytes it hashed, and
    lets only the interpreter's standard library through otherwise."""

    def __init__(self, listed):
        self.listed = listed

    def find_spec(self, name, path=None, target=None):
        fname = name + ".py"
        if fname in self.listed:
            return importlib.util.spec_from_loader(name, self, origin=os.path.join(HERE, fname))
        top = name.partition(".")[0]
        if top in sys.stdlib_module_names or top in sys.builtin_module_names:
            return None
        _refuse_interpreter()

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        fname = module.__name__ + ".py"
        try:
            with open(os.path.join(HERE, fname), "rb") as f:
                data = f.read()
        except OSError:
            _refuse_interpreter()
        if hashlib.sha256(data).hexdigest() != self.listed[fname]:
            _refuse_interpreter()
        exec(compile(data, os.path.join(HERE, fname), "exec"), module.__dict__)


def main(argv):
    raw, listed = _read_manifest()
    sys.meta_path.insert(0, _PinnedFinder(listed))
    import a2_main
    return a2_main.main(argv, hashlib.sha256(raw).hexdigest(), os.path.realpath(__file__))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
