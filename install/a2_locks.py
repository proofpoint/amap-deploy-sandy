"""Target locks (section 5.3) and the lock half of custody (5.3b step 1).

`root_uid` is the owner every lock-root object must have. It is 0 on a
runner host; the tests pass their own uid so that the owner checks run
without root, and every check reads it from this one parameter.
"""

import errno
import fcntl
import grp
import hashlib
import os
import pwd
import stat

from a2_causes import Refusal

RUNNER_LOCK = "runner.lock"

#: Local filesystem types the lock root may be on (5.3 step 4). The list
#: is named by the S0 review; these are the candidates submitted to it.
LOCAL_FS_TYPES = ("ext4", "xfs", "btrfs")

ACL_XATTRS = ("system.posix_acl_access", "system.posix_acl_default")


# ------------------------------------------------------------- targets


def run_vms(hosts, inv, account):
    """The run's VM entries (5.3b): the account's scope; for `destroy`,
    every entry of either scope not on `destroy_deny` (6.2). A destroy
    whose hosts file has no `destroy_deny` refuses RUNNER.DESTROY_DENY."""
    if inv.command == "destroy":
        deny = hosts.get("destroy_deny")
        if not _deny_list_ok(deny, hosts):
            raise Refusal("RUNNER.DESTROY_DENY")
        return [v for v in hosts["vms"] if v["name"] not in deny]
    return [v for v in hosts["vms"] if v["scope"] == account]


def _deny_list_ok(hard_deny, hosts):
    """A list of distinct names, each naming a `vms[]` entry (L3 already
    checked this; it is checked again where destroy relies on it)."""
    if not isinstance(hard_deny, list):
        return False
    names = {v["name"] for v in hosts["vms"]}
    return len(set(hard_deny)) == len(hard_deny) and all(
        isinstance(n, str) and n in names for n in hard_deny)


def check_names_distinct(hosts):
    """6.2 and 4.3: across the whole file, `hypervisor.name`, `hub.name`,
    `hub_loop.name`, every `vms[].name` and every `vm:<vm_id>` (hub_loop's
    included) are pairwise distinct, whatever the run's scope."""
    names = [hosts["hypervisor"]["name"], hosts["hub"]["name"],
             hosts["hub_loop"]["name"], "vm:" + hosts["hub_loop"]["vm_id"]]
    for v in hosts["vms"]:
        names.append(v["name"])
        names.append("vm:" + v["vm_id"])
    if len(set(names)) != len(names):
        raise Refusal("RUNNER.HOSTS_TARGETS")


def targets(hosts, vms):
    """5.3 step 1: sorted by UTF-8 byte order; a duplicate refuses. A run
    with any `loop` VM also locks hub_loop, which the loop restores with
    its VMs."""
    names = [hosts["hypervisor"]["name"], hosts["hub"]["name"]]
    for v in vms:
        names.append(v["name"])
        names.append("vm:" + v["vm_id"])
    if any(v["scope"] == "loop" for v in vms):
        names.append(hosts["hub_loop"]["name"])
        names.append("vm:" + hosts["hub_loop"]["vm_id"])
    if len(set(names)) != len(names):
        raise Refusal("RUNNER.HOSTS_TARGETS")
    return sorted(names, key=lambda n: n.encode("utf-8"))


def target_key(target):
    """5.3 step 2."""
    return hashlib.sha256(target.encode("utf-8") + b"\n").hexdigest()


def lock_path(lock_root, target):
    return os.path.join(lock_root, target_key(target) + ".lock")


# ---------------------------------------------------------- lock root


def _has_acl(path):
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError as e:
        if e.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
            return False
        return True
    return any(n in names for n in ACL_XATTRS)


def _account_ids(name):
    ent = pwd.getpwnam(name)
    gids = {ent.pw_gid} | {g.gr_gid for g in grp.getgrall() if name in g.gr_mem}
    return ent.pw_uid, gids


def _writable_by(st, uid, gids):
    m = st.st_mode
    return ((st.st_uid == uid and m & stat.S_IWUSR)
            or (st.st_gid in gids and m & stat.S_IWGRP)
            or (m & stat.S_IWOTH))


def fs_type(path, mountinfo="/proc/self/mountinfo"):
    """The filesystem type of the mount holding `path`: longest mount-point
    prefix in mountinfo. None when it cannot be read."""
    try:
        with open(mountinfo, "rb") as f:
            lines = f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return None
    best, best_type = "", None
    for ln in lines:
        left, sep, right = ln.partition(" - ")
        if not sep:
            continue
        fields = left.split(" ")
        if len(fields) < 5:
            continue
        mnt = fields[4].replace("\\040", " ")
        rf = right.split(" ")
        if not rf:
            continue
        if (path == mnt or path.startswith(mnt.rstrip("/") + "/")) and len(mnt) >= len(best):
            best, best_type = mnt, rf[0]
    return best_type


def check_lock_root(hosts, host_identity, root_uid=0, fs_type_of=fs_type,
                    account_ids=_account_ids):
    """5.3 step 0 and the step 4 filesystem allow-list."""
    r = hosts["runner"]
    if host_identity is None or host_identity != r["host_id"]:
        raise Refusal("RUNNER.LOCK_ROOT")
    root = r["lock_root"]
    try:
        if os.path.realpath(root) != root:
            raise Refusal("RUNNER.LOCK_ROOT")
        st = os.lstat(root)
    except OSError:
        raise Refusal("RUNNER.LOCK_ROOT")
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != root_uid or stat.S_IMODE(st.st_mode) != 0o755:
        raise Refusal("RUNNER.LOCK_ROOT")
    if _has_acl(root):
        raise Refusal("RUNNER.LOCK_ROOT")
    try:
        ids = [account_ids(r["loop_account"]), account_ids(r["l3_account"])]
    except KeyError:
        raise Refusal("RUNNER.LOCK_ROOT")
    parent = os.path.dirname(root)
    while True:
        try:
            pst = os.lstat(parent)
        except OSError:
            raise Refusal("RUNNER.LOCK_ROOT")
        for uid, gids in ids:
            if _writable_by(pst, uid, gids):
                raise Refusal("RUNNER.LOCK_ROOT")
        if _has_acl(parent):
            raise Refusal("RUNNER.LOCK_ROOT")
        if parent == "/":
            break
        parent = os.path.dirname(parent)
    if fs_type_of(root) not in LOCAL_FS_TYPES:
        raise Refusal("RUNNER.LOCK_ROOT")


# -------------------------------------------------------------- taking


def _open_lock_file(path, root_uid):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise Refusal("RUNNER.LOCK_ROOT")
    st = os.fstat(fd)
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != root_uid
            or stat.S_IMODE(st.st_mode) != 0o644):
        os.close(fd)
        raise Refusal("RUNNER.LOCK_ROOT")
    return fd


def lock_order(lock_root, target_list, writes_target):
    """(label, path) in acquisition order: `runner.lock` first for a
    command that can write to a target (5.3 step 3a), then the targets."""
    order = []
    if writes_target:
        order.append((RUNNER_LOCK, os.path.join(lock_root, RUNNER_LOCK)))
    order.extend((t, lock_path(lock_root, t)) for t in target_list)
    return order


def acquire(order, root_uid=0):
    """5.3 step 3: all or nothing. Returns {label: fd}, each fd made
    inheritable (step 5). A held lock releases what was taken and refuses
    naming the target; a missing or mis-owned file refuses LOCK_ROOT."""
    held = {}
    try:
        for label, path in order:
            fd = _open_lock_file(path, root_uid)
            held[label] = fd
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as e:
                if e.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                    raise Refusal("RUNNER.TARGET_LOCKED", "target: " + label)
                raise Refusal("RUNNER.LOCK_ROOT")
    except Refusal:
        release(held)
        raise
    for fd in held.values():
        os.set_inheritable(fd, True)
    return held


def release(held):
    for fd in held.values():
        try:
            os.close(fd)
        except OSError:
            pass
    held.clear()


# ------------------------------------------------ inherited (runner side)


def _inherited_fds(fd_dir="/proc/self/fd"):
    try:
        names = os.listdir(fd_dir)
    except OSError:
        return None
    out = []
    for n in names:
        if n.isdigit():
            out.append(int(n))
    return out


def find_held(order, root_uid=0, fd_dir="/proc/self/fd"):
    """S0's check that the runner holds every lock of its run (5.1a).

    For each lock file: an inherited descriptor names its inode, a fresh
    open of the path CANNOT take the lock (so someone holds it), and the
    inherited descriptor CAN (so the holder is that descriptor's open file
    description, not another process). Returns {label: fd}. Anything else
    is `RUNNER.ADMISSION`."""
    fds = _inherited_fds(fd_dir)
    if fds is None:
        raise Refusal("RUNNER.ADMISSION")
    ident = {}
    for fd in fds:
        try:
            st = os.fstat(fd)
        except OSError:
            continue
        ident.setdefault((st.st_dev, st.st_ino), fd)
    held = {}
    for label, path in order:
        try:
            pst = os.stat(path, follow_symlinks=False)
        except OSError:
            raise Refusal("RUNNER.ADMISSION")
        fd = ident.get((pst.st_dev, pst.st_ino))
        if fd is None:
            raise Refusal("RUNNER.ADMISSION")
        probe = _open_lock_file(path, root_uid)
        try:
            try:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as e:
                if e.errno not in (errno.EWOULDBLOCK, errno.EAGAIN):
                    raise Refusal("RUNNER.ADMISSION")
            else:
                raise Refusal("RUNNER.ADMISSION")
        finally:
            os.close(probe)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise Refusal("RUNNER.ADMISSION")
        held[label] = fd
    return held


def adopt(held, lock_root, fd_dir="/proc/self/fd"):
    """After S0 has found its locks: no child inherits them (5.3 step 5,
    a child must not outlive the run holding a lock), and any other
    inherited descriptor into the lock root is closed."""
    keep = set(held.values())
    for fd in keep:
        os.set_inheritable(fd, False)
    names = _inherited_fds(fd_dir)
    if names is None:
        raise Refusal("RUNNER.ADMISSION")
    root = os.path.realpath(lock_root).rstrip("/") + "/"
    for fd in names:
        if fd in keep or fd < 3:
            continue
        try:
            target = os.readlink(os.path.join(fd_dir, str(fd)))
        except OSError:
            continue
        if target.startswith(root):
            try:
                os.close(fd)
            except OSError:
                pass


def custody_locks(order, held, root_uid=0):
    """5.3b custody step 1: 'held', 'lost' or 'UNOBSERVED'."""
    try:
        for label, path in order:
            fd = held.get(label)
            if fd is None:
                return "lost"
            try:
                fst = os.fstat(fd)
            except OSError:
                return "lost"
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return "lost"
            pst = os.stat(path, follow_symlinks=False)
            if (pst.st_dev, pst.st_ino) != (fst.st_dev, fst.st_ino):
                return "lost"
            if pst.st_uid != root_uid or stat.S_IMODE(pst.st_mode) != 0o644:
                return "lost"
    except OSError:
        return "UNOBSERVED"
    return "held"
