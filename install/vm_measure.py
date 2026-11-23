"""S6 CONFIG step 1 on one VM: the accounts, the hop group and the interpreter, read only.

It is never a file on the VM. The runner reads these bytes from its own checkout, checks them against
install/MANIFEST, and runs them through the VM layer's launcher as `/usr/bin/python3 -I -S -c <these bytes>
<relay account> <hop group>`, as the agent account, with HOME that account's home. It writes nothing.

The only output is one line of JSON with exactly these keys, sorted:
  home        this account's home from the password database (the launcher sets HOME to it)
  uid, gid    this account's uid and primary gid
  relay_uid, relay_gid   the relay account's
  relay_home  the relay account's home (RE's state and password file live under it)
  hop_gid     the hop group's gid
  agent_in_hop, relay_in_hop   whether each account has the hop group (primary or supplementary)
  python      [major, minor] of this interpreter
Exit codes: 0 done, 2 usage, 4 an account or the group does not exist.
"""

import grp
import json
import os
import pwd
import sys

USAGE, MISSING = 2, 4


def _in_group(pw, gr):
    return pw.pw_gid == gr.gr_gid or pw.pw_name in gr.gr_mem


def main(argv):
    if len(argv) != 2:
        return USAGE
    try:
        me = pwd.getpwuid(os.geteuid())
        relay = pwd.getpwnam(argv[0])
        hop = grp.getgrnam(argv[1])
    except (KeyError, ValueError):
        return MISSING
    doc = {"home": me.pw_dir, "uid": me.pw_uid, "gid": me.pw_gid, "relay_uid": relay.pw_uid,
           "relay_gid": relay.pw_gid, "relay_home": relay.pw_dir, "hop_gid": hop.gr_gid, "agent_in_hop": _in_group(me, hop),
           "relay_in_hop": _in_group(relay, hop), "python": list(sys.version_info[:2])}
    os.write(1, (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
