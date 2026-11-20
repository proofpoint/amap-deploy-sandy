"""Validate one D2 profile capture file before it is admitted (alpha2/d2/capture.sh).

Usage: /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/python3 -I -S -B profile_check.py {shell|env} FILE [OUT]

Standard library only. It reads FILE once, at most LIMIT bytes; a longer file is
INVALID. With OUT, it writes exactly the bytes it validated to OUT, created new (O_EXCL,
never over an existing file or through a symlink) with mode 0600. The admitted bytes
are therefore the validated bytes.

It prints `CHECK <part> VALID` or `CHECK <part> INVALID: <reason>`, then, with OUT,
`ADMITTED <basename of OUT>` or `NOT ADMITTED <basename of OUT>: <reason>`. A reason
names a key, a line number or a limit, never a value. Exit 0 only when the file is
valid AND complete AND, with OUT, written; exit 1 otherwise.

Valid means:
- every line is `key=value` in printable ASCII, and no key appears twice;
- the key set is exactly the one listed here for that part and shell, with no key
  missing and none extra;
- every value has its shape;
- the last line is `profile.end=complete`.

For part B, a launch line that something stands in front of (`launch.first_word` not
a plain file or command) is also refused.
"""

import os
import re
import sys

#: The most bytes a capture may hold. A real capture is about 5 KiB.
LIMIT = 64 * 1024

PRINTABLE = re.compile(r"[ -~]*")
KEY = re.compile(r"[a-z][a-z0-9_]*(\.[A-Za-z0-9_+-]+)*")
SHA = r"[0-9a-f]{64}"
ABSPATH = r"/[A-Za-z0-9._+-]+(/[A-Za-z0-9._+-]+)*"
WORD = r"[A-Za-z0-9._+-]+"
NAMES = r"([^ =]+( [^ =]+)*)?"
ENVNAMES = r"([A-Za-z_][A-Za-z0-9_]*( [A-Za-z_][A-Za-z0-9_]*)*)?"
SETUNSET = r"set|unset"

SHELL_COMMON = {
    "profile.schema": r"d2-profile-shell/3",
    "shell.login": ABSPATH,
    "shell.version": r"[0-9][ -~]*",
    "alias.names": NAMES,
    "function.names": NAMES,
    "env.names": ENVNAMES,
    "env.PATH": r"[!-~]*",
    "env.SSH_AUTH_SOCK": SETUNSET,
    "env.TERM": WORD + r"|UNSET",
    "profile.end": r"complete",
}
SHELL_BASH = dict(SHELL_COMMON, **{
    "shell.kind": r"bash",
    "shell.posix_mode": r"on|off",
    "hook.PROMPT_COMMAND": SETUNSET,
    "hook.PS0": SETUNSET,
    "hook.trap_DEBUG": SETUNSET,
    "hook.trap_RETURN": SETUNSET,
    "hook.BASH_ENV": SETUNSET,
    "hook.ENV": SETUNSET,
    "launch.first_word": r"file|function|alias|builtin|keyword|none",
    "launch.sudo": r"file|function|alias|builtin|keyword|none",
})
SHELL_ZSH = dict(SHELL_COMMON, **{
    "shell.kind": r"zsh",
    "alias.global_names": NAMES,
    "hook.preexec_functions": NAMES,
    "hook.precmd_functions": NAMES,
    "hook.zshaddhistory_functions": NAMES,
    "hook.trap_DEBUG": SETUNSET,
    "hook.ZDOTDIR": SETUNSET,
    "launch.first_word": r"command|function|alias|builtin|reserved|none",
    "launch.sudo": r"command|function|alias|builtin|reserved|none",
})
LAUNCH_OK = {"file", "command"}

TOOLS = ("env", "git", "realpath", "ssh", "sha256sum", "sh")
SLEEP = ("sleep.target", "suspend.target", "hibernate.target", "hybrid-sleep.target")
ENV_FIXED = {
    "profile.schema": r"d2-profile-env/2",
    "captured_at": r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
    "host.kernel": r"[!-~][ -~]*",
    "host.arch": WORD,
    "interpreter.path": r"/usr/bin/python3",
    "interpreter.sha256": SHA,
    "interpreter.resolved_path": ABSPATH,
    "interpreter.resolved_sha256": SHA,
    "interpreter.version": r"3\.[0-9]{1,2}\.[0-9]{1,3}",
    "profile.end": r"complete",
}
for _t in TOOLS:
    ENV_FIXED["tool.%s.path" % _t] = ABSPATH
    ENV_FIXED["tool.%s.resolved_path" % _t] = ABSPATH
    ENV_FIXED["tool.%s.sha256" % _t] = SHA
    ENV_FIXED["tool.%s.version" % _t] = r"[!-~][ -~]*"
for _u in SLEEP:
    ENV_FIXED["sleep." + _u] = r"[a-z][a-z-]*"
ACCOUNT_KEY = re.compile(r"account\.[A-Za-z0-9._-]+\.(uid|gid)")
NOT_A_FACT = {"ABSENT", "UNOBSERVED", "REFUSED"}


def parse(raw):
    """[(key, value)] in order, or a reason string."""
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return "not ASCII"
    if not text.endswith("\n"):
        return "no final newline (empty or cut short)"
    pairs, seen = [], set()
    for n, line in enumerate(text[:-1].split("\n"), 1):
        if not PRINTABLE.fullmatch(line) or "=" not in line:
            return "line %d is not key=value printable ASCII" % n
        key, value = line.split("=", 1)
        if not KEY.fullmatch(key):
            return "line %d has a malformed key" % n
        if key in seen:
            return "key %s appears twice" % key
        seen.add(key)
        pairs.append((key, value))
    return pairs


def check(part, raw):
    pairs = parse(raw)
    if isinstance(pairs, str):
        return pairs
    if not pairs or pairs[-1][0] != "profile.end":
        return "the last line is not profile.end"
    doc = dict(pairs)
    if part == "shell":
        if any(k.startswith("shadow.") for k in doc):
            return "a function shadows a name the capture calls (%s)" % ", ".join(
                k for k in doc if k.startswith("shadow."))
        kind = doc.get("shell.kind")
        want = {"bash": SHELL_BASH, "zsh": SHELL_ZSH}.get(kind)
        if want is None:
            return "shell.kind is not bash or zsh"
        accounts = {}
    else:
        want = ENV_FIXED
        accounts = {k: v for k, v in doc.items() if ACCOUNT_KEY.fullmatch(k)}
        doc = {k: v for k, v in doc.items() if k not in accounts}
    for key in list(doc) + list(accounts):
        if (doc.get(key) if key in doc else accounts[key]) in NOT_A_FACT:
            return "%s was not observed" % key
    missing = sorted(set(want) - set(doc))
    extra = sorted(set(doc) - set(want))
    if missing:
        return "missing key %s" % missing[0]
    if extra:
        return "unexpected key %s" % extra[0]
    for key, shape in want.items():
        if not re.fullmatch(shape, doc[key]):
            return "%s does not have its shape" % key
    for key, value in accounts.items():
        if not re.fullmatch(r"[0-9]{1,10}", value):
            return "%s does not have its shape" % key
    if part == "shell" and doc["launch.first_word"] not in LAUNCH_OK:
        return "something stands in front of /usr/bin/env (launch.first_word)"
    return None


def read_bounded(path):
    """FILE's bytes, read once, or a reason. More than LIMIT bytes is a reason."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return None, "the file cannot be read"
    try:
        chunks, total = [], 0
        while total <= LIMIT:
            b = os.read(fd, LIMIT + 1 - total)
            if not b:
                break
            chunks.append(b)
            total += len(b)
    except OSError:
        return None, "the file cannot be read"
    finally:
        os.close(fd)
    if total > LIMIT:
        return None, "the file is longer than %d bytes" % LIMIT
    return b"".join(chunks), None


def admit(data, out):
    """Write `data` to a NEW file `out`, mode 0600; never over an existing path."""
    try:
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except FileExistsError:
        return "it already exists; nothing is overwritten"
    except OSError:
        return "it cannot be created"
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            view = view[n:]
        os.fsync(fd)
    except OSError:
        return "the write failed"
    finally:
        os.close(fd)
    return None


def main(argv):
    if len(argv) not in (3, 4) or argv[1] not in ("shell", "env"):
        sys.stdout.write("CHECK usage: profile_check.py {shell|env} FILE [OUT]\n")
        return 1
    part = argv[1]
    raw, reason = read_bounded(argv[2])
    if reason is None:
        reason = check(part, raw)
    if reason is not None:
        sys.stdout.write("CHECK %s INVALID: %s\n" % (part, reason))
        if len(argv) == 4:
            sys.stdout.write("NOT ADMITTED %s: not valid\n" % os.path.basename(argv[3]))
        return 1
    sys.stdout.write("CHECK %s VALID\n" % part)
    if len(argv) == 4:
        why = admit(raw, argv[3])
        if why is not None:
            sys.stdout.write("NOT ADMITTED %s: %s\n" % (os.path.basename(argv[3]), why))
            return 1
        sys.stdout.write("ADMITTED %s\n" % os.path.basename(argv[3]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
