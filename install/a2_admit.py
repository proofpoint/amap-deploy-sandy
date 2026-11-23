"""The launcher (section 5.1a) and S0's admission (5.1a, 5.3, 5.3b, 5.3c).

The launcher refuses early. S0 is the admission authority: it re-checks
every launcher condition on its own reads, so a run that reaches it by any
route passes every limit or refuses.
"""

import hashlib
import os
import stat
import time

import a2_args
import a2_budget
import a2_host
import a2_locks
import a2_private
import a2_rundir
import a2_stop
from a2_causes import Refusal

LOCK_FILE = "alpha2.lock"
HOSTS_FILE = "alpha2.hosts"
READ_MAX = 1 << 20


def _read_to_eof(fd, limit):
    """Every byte up to EOF; at most limit + 1 are read."""
    chunks, n = [], 0
    while n <= limit:
        b = os.read(fd, limit + 1 - n)
        if not b:
            break
        chunks.append(b)
        n += len(b)
    return b"".join(chunks)


def _read_private(site):
    return read_private_pair(site.private_dir)


def read_private_pair(private_dir):
    """The raw bytes of alpha2.lock and alpha2.hosts in the private overlay
    checkout `private_dir`, as S0 reads them: each opened O_RDONLY |
    O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, a regular file, read to EOF, at
    most READ_MAX bytes. O_NOFOLLOW covers the last path component only.
    Nothing is parsed. Every failure, an unset `private_dir` included, is
    PREFLIGHT.PRIVATE_SOURCE. Returns (lock_raw, hosts_raw)."""
    if not private_dir:
        raise Refusal("PREFLIGHT.PRIVATE_SOURCE")
    out = []
    for name in (LOCK_FILE, HOSTS_FILE):
        path = os.path.join(private_dir, name)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        except OSError:
            raise Refusal("PREFLIGHT.PRIVATE_SOURCE")
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise Refusal("PREFLIGHT.PRIVATE_SOURCE")
            raw = _read_to_eof(fd, READ_MAX)
        except OSError:
            raise Refusal("PREFLIGHT.PRIVATE_SOURCE")
        finally:
            os.close(fd)
        if len(raw) > READ_MAX:
            raise Refusal("PREFLIGHT.PRIVATE_SOURCE")
        out.append(raw)
    return tuple(out)


def _gate_open(gate):
    """("open", remaining seconds), the seconds a non-bool int >= 0."""
    return (isinstance(gate, tuple) and len(gate) == 2 and gate[0] == "open"
            and isinstance(gate[1], int) and not isinstance(gate[1], bool) and gate[1] >= 0)


class Checked:
    """What the shared checks established, for the launcher and for S0."""

    def __init__(self, **kw):
        self.__dict__.update(kw)


def _common(argv, site):
    """Steps both sides run, in the launcher's order up to the locks:
    environment names, argv, the private files with L1 to L4, the account,
    the full environment, and the arm gate."""
    if site.environ is None:
        site.environ = a2_host.received_environ()
    a2_host.check_env_names(site.environ)
    inv = a2_args.parse(argv)
    lock_raw, hosts_raw = _read_private(site)
    try:
        lock, hosts = a2_private.load_pair(lock_raw, hosts_raw)
    except a2_private.PairInvalid as e:
        raise Refusal(e.cause, e.detail)
    # A writer this run's stages execute must be pinned (6.1, 3.7).
    pinned = {w["use"] for w in lock["writers"]}
    if a2_private.writers_required(inv, a2_args.STAGE_IDS) - pinned:
        raise Refusal("PREFLIGHT.LOCK", "writers")
    account, _name, home = a2_host.kernel_account(hosts["runner"], site.getuid, site.geteuid,
                                                     site.getpwuid)
    a2_host.check_account(inv, account)
    a2_host.check_env(site.environ, account, home)
    if inv.command == "destroy" or (inv.command == "install" and inv.loop in ("L3", None)):
        gate = site.arm_gate(hosts)
        if not _gate_open(gate):
            raise Refusal("PREFLIGHT.HANDOFF")
        if inv.command == "install":
            if site.full_run_bound_s is None or gate[1] < site.full_run_bound_s:
                raise Refusal("PREFLIGHT.HANDOFF")
    kw = {}
    if site.fs_type_of is not None:
        kw["fs_type_of"] = site.fs_type_of
    if site.account_ids is not None:
        kw["account_ids"] = site.account_ids
    a2_locks.check_lock_root(hosts, site.host_identity(), site.root_uid, **kw)
    a2_locks.check_names_distinct(hosts)
    vms = a2_locks.run_vms(hosts, inv, account)
    order = a2_locks.lock_order(hosts["runner"]["lock_root"],
                                a2_locks.targets(hosts, vms), inv.writes_target)
    return Checked(inv=inv, lock=lock, hosts=hosts, account=account, home=home,
                   lock_raw=lock_raw, hosts_raw=hosts_raw,
                   lock_sha=hashlib.sha256(lock_raw).hexdigest(),
                   hosts_sha=hashlib.sha256(hosts_raw).hexdigest(),
                   order=order, lock_root=hosts["runner"]["lock_root"])


def _handoff_and_usage(c, site):
    """Stop file, loop tasks, and path (a) usage, for a command that can
    write to a target (5.1a step 4; S0 again)."""
    if not c.inv.writes_target:
        return
    if a2_stop.applies(c.inv) and a2_stop.read(c.lock_root) != "unset":
        raise Refusal("PREFLIGHT.HANDOFF")
    if site.loop_tasks(c.hosts) != "none":
        raise Refusal("PREFLIGHT.HANDOFF")
    if site.usage_path == "a":
        pct = site.usage_read(c.hosts)
        if not isinstance(pct, int) or isinstance(pct, bool) or pct >= 80 or pct < 0:
            raise Refusal("PREFLIGHT.BUDGET")
    elif site.usage_path != "b":
        raise Refusal("PREFLIGHT.BUDGET")


# ------------------------------------------------------------ launcher


def prepare_launch(argv, site):
    """5.1a steps 1 to 4. Returns (exec argv, held lock descriptors). On a
    refusal nothing stays held."""
    c = _common(argv, site)
    held = a2_locks.acquire(c.order, site.root_uid)
    try:
        _handoff_and_usage(c, site)
        if c.inv.writes_target:
            run_id, _sha = a2_budget.ask_broker(c.lock_root, c.inv, c.lock_sha, c.hosts_sha,
                                                site.installer_sha, site.root_uid)
        else:
            run_id = a2_rundir.mint_run_id(site.now)
    except BaseException:
        a2_locks.release(held)
        raise
    args = [site.interpreter, "-I", "-B", site.entry, "--runner", "--run-id", run_id] + list(argv)
    return args, held, run_id


def launch(argv, site):
    """5.1a steps 1 to 5. On success the runner replaces this process with
    every lock descriptor still open (step 5), and this does not return."""
    args, held, run_id = prepare_launch(argv, site)
    try:
        site.execve(site.interpreter, args, dict(site.environ))
    except Exception:
        pass
    a2_locks.release(held)
    # 5.1a step 5: an exec that fails in any way. A target-writing run's
    # start record stays counted (5.3c); the terminal names the run id.
    raise Refusal("RUNNER.NOT_STARTED", "run id: " + run_id)


# ------------------------------------------------------------------ S0


def admit(run_id, argv, site):
    """S0's admission, before the run directory exists. Returns the
    admission facts and the created run directory."""
    s0_began = time.time() if site.now is None else site.now
    if not a2_private.matches("run_id", run_id):
        raise Refusal("RUNNER.ADMISSION")
    c = _common(argv, site)
    held = a2_locks.find_held(c.order, site.root_uid, site.fd_dir)
    a2_locks.adopt(held, c.lock_root, site.fd_dir)
    _handoff_and_usage(c, site)
    admission_sha = None
    if c.inv.writes_target:
        admission_sha = a2_budget.check_start_record(
            os.path.join(c.lock_root, "budget.d"), c.account, run_id, c.inv,
            c.lock_sha, c.hosts_sha, site.installer_sha, s0_began, site.root_uid)
    c.run_fd = a2_rundir.create_run_dir(c.home, run_id, site.getuid())
    c.run_id = run_id
    c.held = held
    c.admission_sha = admission_sha
    return c
