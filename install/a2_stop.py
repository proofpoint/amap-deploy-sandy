"""The stop file (section 5.3b, E19): `stop.d` in the lock root.

Read result is 'set', 'unset' or 'UNOBSERVED'. Missing counts as set
(fail closed); a listing that cannot be made is UNOBSERVED. Both refuse.
"""

import errno
import os
import stat

SETTERS = ("operator", "controller", "monitor")
#: Entries that are not stops, each only while it is a regular file
#: (5.3c path (b)).
MONITOR_NON_STOPS = ("permit.json", ".permit-next.json")


def applies(inv):
    """Every command that can write to a target, except an `install` whose
    loop is `L3` or `null` (which needs the L3 arm gate instead)."""
    if not inv.writes_target:
        return False
    if inv.command == "install" and inv.loop in ("L3", None):
        return False
    return True


def _listing(path):
    """Names in a directory, or 'set' when it is missing or not a
    directory, or 'UNOBSERVED' when it cannot be listed."""
    try:
        st = os.lstat(path)
    except OSError as e:
        return "set" if e.errno == errno.ENOENT else "UNOBSERVED"
    if not stat.S_ISDIR(st.st_mode):
        return "set"
    try:
        return os.listdir(path)
    except OSError:
        return "UNOBSERVED"


def read(lock_root):
    top = os.path.join(lock_root, "stop.d")
    names = _listing(top)
    if isinstance(names, str):
        return names
    if set(names) - set(SETTERS):
        return "set"
    result = "unset"
    for setter in SETTERS:
        if setter not in names:
            return "set"
        sub = os.path.join(top, setter)
        entries = _listing(sub)
        if entries == "UNOBSERVED":
            result = "UNOBSERVED"
            continue
        if isinstance(entries, str):
            return "set"
        for e in entries:
            if setter == "monitor" and e in MONITOR_NON_STOPS:
                try:
                    est = os.lstat(os.path.join(sub, e))
                except OSError:
                    result = "UNOBSERVED"
                    continue
                if stat.S_ISREG(est.st_mode):
                    continue
            return "set"
    return result
