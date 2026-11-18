"""argv to (command, loop, options), per the flag table of section 5.1.

Every argv value is matched in full against its pattern before it is used
or recorded (section 3.3). A mismatch, an unknown flag, or a forbidden
combination is `RUNNER.ARGS`; the detail never echoes the argument.
"""

import re

from a2_causes import Refusal
from a2_private import matches

STAGE_IDS = ("S0", "S1", "S2", "S3", "S4", "S5", "S6", "S6b", "S7", "S8", "S9", "S10")
NONCE = re.compile(r"[A-Za-z0-9]{8,64}")

#: Commands that can write to a target (5.1, 5.3b): every command except
#: these three.
NON_WRITING = ("dry-run", "verify", "check-roundtrip")


class Invocation:
    def __init__(self, command, loop, opts):
        self.command = command
        self.loop = loop
        self.opts = opts

    @property
    def writes_target(self):
        return self.command not in NON_WRITING

    def __eq__(self, other):
        return (isinstance(other, Invocation) and self.command == other.command
                and self.loop == other.loop and self.opts == other.opts)

    def __repr__(self):
        return "Invocation(%r, %r, %r)" % (self.command, self.loop, self.opts)


def _bad():
    return Refusal("RUNNER.ARGS")


def parse(argv):
    flags = {}
    i = 0
    takes_value = {"--add-agent": "name", "--id": "name", "--check-roundtrip": "nonce",
                   "--only": "stage", "--from": "stage", "--loop": "loop"}
    bare = ("--dry-run", "--verify", "--canary", "--rotate-key", "--leak-run", "--destroy")
    while i < len(argv):
        a = argv[i]
        if a in bare:
            if a in flags:
                raise _bad()
            flags[a] = True
            i += 1
        elif a in takes_value:
            if a in flags or i + 1 >= len(argv):
                raise _bad()
            v = argv[i + 1]
            kind = takes_value[a]
            ok = (matches("name", v) if kind == "name"
                  else NONCE.fullmatch(v) is not None if kind == "nonce"
                  else v in STAGE_IDS if kind == "stage"
                  else v in ("L2", "L3"))
            if not ok:
                raise _bad()
            flags[a] = v
            i += 2
        else:
            raise _bad()
    return _resolve(flags)


def _resolve(f):
    keys = set(f)
    modes = keys & {"--dry-run", "--verify", "--add-agent", "--rotate-key",
                    "--check-roundtrip", "--destroy"}
    if len(modes) > 1:
        raise _bad()
    if "--canary" in keys and "--verify" not in keys:
        raise _bad()
    if "--id" in keys and "--add-agent" not in keys:
        raise _bad()
    install_mods = keys & {"--only", "--from", "--leak-run", "--loop"}
    if modes and install_mods:
        raise _bad()
    if len(keys & {"--only", "--from"}) > 1:
        raise _bad()
    if "--loop" in keys and keys & {"--only", "--from", "--leak-run"}:
        raise _bad()
    if "--leak-run" in keys and keys & {"--only", "--from"}:
        raise _bad()

    if "--dry-run" in keys:
        return Invocation("dry-run", None, {})
    if "--verify" in keys:
        return Invocation("canary" if "--canary" in keys else "verify", None, {})
    if "--add-agent" in keys:
        opts = {"host": f["--add-agent"]}
        if "--id" in keys:
            opts["id"] = f["--id"]
        return Invocation("add-agent", None, opts)
    if "--rotate-key" in keys:
        return Invocation("rotate-key", None, {})
    if "--check-roundtrip" in keys:
        return Invocation("check-roundtrip", None, {"nonce": f["--check-roundtrip"]})
    if "--destroy" in keys:
        return Invocation("destroy", None, {})
    if "--only" in keys:
        return Invocation("install", "L1", {"only": f["--only"]})
    if "--from" in keys:
        return Invocation("install", "L1", {"from": f["--from"]})
    if "--leak-run" in keys:
        return Invocation("install", "L2-leak", {})
    if "--loop" in keys:
        return Invocation("install", f["--loop"], {})
    return Invocation("install", None, {})
