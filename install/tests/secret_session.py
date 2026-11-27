"""The REAL rule-7 secret session, run on this host: the shipped vm_bootstrap.py, executed the way a2_vm executes it
on a VM (`/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/python3 -I -S -c <its bytes> secret <use> <mode>
<sha> <account>`), fed what a2_vm.write_secret feeds it (an 8-byte length, the writer's bytes, then the value).

FAKED, and only these, in the writer's bytes: LOOKUP (the account is this uid with the test's home) and BECOME (no
uid change without root). faked_writer replaces exactly those two lines of a shipped writer, each counted once;
every other byte is the shipped file. The bootstrap is not altered at all.
"""

import hashlib
import os
import subprocess

INSTALL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BOOTSTRAP = os.path.join(INSTALL, "vm_bootstrap.py")
REAL_LOOKUP = "LOOKUP = pwd.getpwnam\n"
REAL_BECOME = "BECOME = _become_account\n"


def faked_writer(shipped, home, account, uid=None, gid=None):
    """The text of `shipped` with LOOKUP answering `account` as (uid, gid, home), any other name KeyError, and
    BECOME a no-op."""
    uid = os.getuid() if uid is None else uid
    gid = os.getgid() if gid is None else gid
    with open(shipped) as f:
        t = f.read()
    lookup = ("LOOKUP = (lambda n: pwd.struct_passwd((%r, 'x', %d, %d, '', %r, '/bin/sh')) if n == %r else {}[n])\n"
              % (account, uid, gid, home, account))
    for old, new in ((REAL_LOOKUP, lookup), (REAL_BECOME, "BECOME = (lambda uid, gid: None)\n")):
        if t.count("\n" + old) != 1:
            raise AssertionError("the shipped writer's %r line is not there exactly once" % old.strip())
        t = t.replace("\n" + old, "\n" + new)
    return t


def run(writer_bytes, use, mode, value, account, want=None, timeout=60):
    """One session: (bootstrap exit code, stdout, stderr). `want` is the sha the runner passes (the writer's own by
    default), so a changed writer can be sent under its original pin."""
    with open(BOOTSTRAP, "rb") as f:
        src = f.read().decode("utf-8")
    if isinstance(writer_bytes, str):
        writer_bytes = writer_bytes.encode("utf-8")
    sha = want or hashlib.sha256(writer_bytes).hexdigest()
    stdin = len(writer_bytes).to_bytes(8, "big") + writer_bytes + (bytes(value) if value is not None else b"")
    p = subprocess.run(["/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LC_ALL=C", "/usr/bin/python3", "-I", "-S", "-c",
                        src, "secret", use, mode, sha, account],
                       input=stdin, capture_output=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr
