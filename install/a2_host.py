"""The launch environment (section 3.2, `RUNNER.ENV`) and the runner
account (section 5.3b, `RUNNER.ACCOUNT`), both read from the kernel and the
account database, never from the environment's own claims.
"""

import os
import pwd

from a2_causes import Refusal

ENV_NAMES = ("HOME", "PATH", "SSH_AUTH_SOCK", "TERM")
LAUNCH_PATH = "/usr/bin:/bin"


def received_environ(path="/proc/self/environ"):
    """The environment this process was exec'd with, as the kernel recorded
    it. Not `os.environ`: under the launch line CPython's C-locale
    coercion (PEP 538) adds `LC_CTYPE` to `os.environ` after start, which
    the launch line never set. An entry that is not `NAME=value`, a name
    given twice, or a file that cannot be read is `RUNNER.ENV`."""
    try:
        with open(path, "rb") as f:
            raw = f.read(1 << 20)
    except OSError:
        raise Refusal("RUNNER.ENV")
    out = {}
    if raw and not raw.endswith(b"\0"):
        raise Refusal("RUNNER.ENV")
    for item in raw.split(b"\0")[:-1] if raw else []:
        name, sep, value = item.partition(b"=")
        try:
            key = name.decode("utf-8", "strict")
            val = value.decode("utf-8", "strict")
        except UnicodeDecodeError:
            raise Refusal("RUNNER.ENV")
        if not sep or not key or key in out:
            raise Refusal("RUNNER.ENV")
        out[key] = val
    return out


def kernel_account(hosts_runner, getuid=os.getuid, geteuid=os.geteuid,
                   getpwuid=pwd.getpwuid):
    """('loop' | 'l3', account name, home). Real and effective uid must agree
    and name one of the two runner accounts of `alpha2.hosts`."""
    uid, euid = getuid(), geteuid()
    if uid != euid:
        raise Refusal("RUNNER.ACCOUNT")
    try:
        ent = getpwuid(uid)
    except KeyError:
        raise Refusal("RUNNER.ACCOUNT")
    if ent.pw_name == hosts_runner["l3_account"]:
        return "l3", ent.pw_name, ent.pw_dir
    if ent.pw_name == hosts_runner["loop_account"]:
        return "loop", ent.pw_name, ent.pw_dir
    raise Refusal("RUNNER.ACCOUNT")


def required_account(inv):
    """The account a command needs, or None when either may run it (5.3b)."""
    if inv.command == "install":
        return "l3" if inv.loop in ("L3", None) else "loop"
    if inv.command == "destroy":
        return "l3"
    return None


def check_account(inv, account):
    need = required_account(inv)
    if need is not None and need != account:
        raise Refusal("RUNNER.ACCOUNT")


def check_env(environ, account, home):
    """Exactly the four names of the launch line; `PATH` fixed; `HOME` the
    account database's home for the kernel account; for the L3 runner
    account, `SSH_AUTH_SOCK` empty."""
    if set(environ) != set(ENV_NAMES):
        raise Refusal("RUNNER.ENV")
    if environ["PATH"] != LAUNCH_PATH:
        raise Refusal("RUNNER.ENV")
    if environ["HOME"] != home:
        raise Refusal("RUNNER.ENV")
    if account == "l3" and environ["SSH_AUTH_SOCK"] != "":
        raise Refusal("RUNNER.ENV")


def check_env_names(environ):
    """The part of `RUNNER.ENV` that needs no private file: run before the
    files are read, so a stray variable refuses before anything else."""
    if set(environ) != set(ENV_NAMES) or environ.get("PATH") != LAUNCH_PATH:
        raise Refusal("RUNNER.ENV")
