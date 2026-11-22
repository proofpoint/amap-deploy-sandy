"""The launcher `exec` runs on a VM before a stage's argv (the VM layer, a2_vm).

It is never a file on the VM. The runner reads these bytes from its own checkout, checks them against
install/MANIFEST, and runs them as `[sudo -n -u <account> --] /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C
/usr/bin/python3 -I -S -c <these bytes> <argv>`. They exec argv with exactly three variables: PATH, LC_ALL and HOME,
the running account's home from the password database, in that HOME as its working directory and with umask 022.
Nothing else reaches the command: no SANDY_HOME, so sandy uses its default under that HOME, and no token variable.

Exit code: the command's own, or 127 when the launcher cannot run it (argv[0] not absolute, no password entry, HOME
not enterable, the exec failed).
"""

import os
import pwd
import sys

PATH = "/usr/bin:/bin"
CANNOT_RUN = 127


def environment(uid):
    return {"PATH": PATH, "LC_ALL": "C", "HOME": pwd.getpwuid(uid).pw_dir}


def main(argv):
    try:
        if not argv or not argv[0].startswith("/"):
            return CANNOT_RUN
        env = environment(os.getuid())
        os.chdir(env["HOME"])
        os.umask(0o022)
        os.execve(argv[0], argv, env)
    except (OSError, KeyError):
        return CANNOT_RUN


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
