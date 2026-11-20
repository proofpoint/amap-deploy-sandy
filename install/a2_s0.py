"""S0 PREFLIGHT after admission: the hoisted refusals that need no earlier
write (section 4.4), the leak checks L6 and L7 (section 8), the lock's
overlay pin (6.1), and the custody read-back (5.3b), ending with S0's
receipt.

Every probe another owner supplies is a slot in a2_site that answers
UNOBSERVED until it is filled, and UNOBSERVED refuses.
"""

import hashlib
import os
import stat
import subprocess
import sys

import a2_git
import a2_locks
import a2_rundir
import a2_stop
from a2_causes import Refusal

LAUNCH_INTERPRETER = "/usr/bin/python3"
REALPATH = "/usr/bin/realpath"
LOCK_NAME = "alpha2.lock"
HOSTS_NAME = "alpha2.hosts"
FETCH_DIR = "fetched"


def _sha_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------- INTERPRETER


def check_interpreter(lock, site):
    """6.1 `interpreter` and `installer`: the launch path and the fully
    resolved binary, each hashed; the resolved path found by a fixed tool
    outside the interpreter under test; the version; MANIFEST's sha; the
    installer checkout clean at `installer.commit`."""
    want = lock["interpreter"]
    try:
        launch_sha = _sha_file(site.launch_interpreter)
        p = subprocess.run([site.realpath_tool, "-e", "--", site.launch_interpreter],
                           env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, capture_output=True,
                           timeout=30, stdin=subprocess.DEVNULL)
        if p.returncode != 0:
            raise OSError("realpath")
        resolved = p.stdout.decode("utf-8", "strict").rstrip("\n")
        resolved_sha = _sha_file(resolved)
    except (OSError, UnicodeDecodeError, subprocess.TimeoutExpired):
        raise Refusal("PREFLIGHT.INTERPRETER")
    version = "%d.%d.%d" % tuple(site.version_info[:3])
    if (launch_sha != want["sha256"] or resolved != want["resolved_path"]
            or resolved_sha != want["resolved_sha256"] or version != want["version"]):
        raise Refusal("PREFLIGHT.INTERPRETER")
    if site.installer_sha != lock["installer"]["sha256"]:
        raise Refusal("PREFLIGHT.INTERPRETER")
    checkout = os.path.dirname(os.path.dirname(site.entry))
    try:
        if (site.git.head(checkout) != lock["installer"]["commit"]
                or not site.git.status_clean(checkout)):
            raise Refusal("PREFLIGHT.INTERPRETER")
    except a2_git.GitError:
        raise Refusal("PREFLIGHT.INTERPRETER")


# ------------------------------------------------- L6, the overlay pin


def check_private_source(c, site):
    """Section 8 L6 for both files, and the lock's `overlay` pin, rules 1
    to 4 (6.1). Returns the overlay HEAD commit, which the receipt records.

    The checkout is read for three things only: its HEAD commit id, that
    it is clean, and that both files are tracked. Rule 1 binds that HEAD id
    to the annotated tag the overlay remote returns. Every tree, blob and
    ancestry read is then made in the installer's own bare repository, at
    the commit the fetched tag peels to: those objects came from the remote
    and were verified on transfer, so nothing in the checkout's object
    store (replace refs, alternates, grafts) can stand in for them.
    A remote that does not answer is PREFLIGHT.REPO_ACCESS; every other
    failure here is PREFLIGHT.PRIVATE_SOURCE."""
    repo = site.private_dir
    git = site.git
    ov = c.lock["overlay"]
    try:
        head = git.head(repo)
        if not git.status_clean(repo):
            raise Refusal("PREFLIGHT.PRIVATE_SOURCE")
        for name in (LOCK_NAME, HOSTS_NAME):
            if not git.tracked(repo, name):
                raise Refusal("PREFLIGHT.PRIVATE_SOURCE")
    except (a2_git.GitError, ValueError):
        raise Refusal("PREFLIGHT.PRIVATE_SOURCE")
    # Rule 1: the annotated tag the overlay remote returns peels to HEAD.
    typ, peeled = _fetch_tag(c, site, "overlay", ov["repo"], ov["tag"], "PREFLIGHT.PRIVATE_SOURCE")
    if typ != "tag" or peeled != head:
        raise Refusal("PREFLIGHT.PRIVATE_SOURCE")
    bare = c.fetched["overlay"]
    try:
        fmt = git.object_format(bare)
        # L6: the exact bytes read at admission are the blobs at that commit.
        for name, raw in ((LOCK_NAME, c.lock_raw), (HOSTS_NAME, c.hosts_raw)):
            entry = git.tree_entry(bare, peeled, name)
            if entry is None or entry[1] != "blob" or entry[2] != a2_git.blob_id(raw, fmt):
                raise Refusal("PREFLIGHT.PRIVATE_SOURCE")
        # Rule 4: alpha2.lock there is a regular blob, mode 100644.
        entry = git.tree_entry(bare, peeled, LOCK_NAME)
        if entry[0] != "100644":
            raise Refusal("PREFLIGHT.PRIVATE_SOURCE")
        # Rule 2: HEAD is overlay.commit or descends from it.
        if peeled != ov["commit"] and not git.is_ancestor(bare, ov["commit"], peeled):
            raise Refusal("PREFLIGHT.PRIVATE_SOURCE")
        # Rule 3: no entries, or exactly one at alpha2.lock (renames off).
        changes = git.diff_tree(bare, ov["commit"], peeled)
        if changes:
            if len(changes) != 1:
                raise Refusal("PREFLIGHT.PRIVATE_SOURCE")
            old_mode, new_mode, status, path = changes[0]
            if path != LOCK_NAME or new_mode != "100644" or old_mode not in ("100644", "000000"):
                raise Refusal("PREFLIGHT.PRIVATE_SOURCE")
    except (a2_git.GitError, ValueError):
        raise Refusal("PREFLIGHT.PRIVATE_SOURCE")
    return head


def check_l7(site):
    """Section 8 L7: each file allows no access by others, and its realpath
    is under no root of the committed deny list of sandbox mount roots
    (a slot of the S0 review; unset refuses)."""
    if site.sandbox_mount_roots is None:
        raise Refusal("PREFLIGHT.LEAK_LOCK", "check L7 at $")
    for name, cause in ((LOCK_NAME, "PREFLIGHT.LEAK_LOCK"), (HOSTS_NAME, "PREFLIGHT.LEAK_HOSTS")):
        path = os.path.join(site.private_dir, name)
        try:
            st = os.stat(path)
            real = os.path.realpath(path)
        except OSError:
            raise Refusal(cause, "check L7 at $")
        if stat.S_IMODE(st.st_mode) & 0o007:
            raise Refusal(cause, "check L7 at $")
        for root in site.sandbox_mount_roots:
            root = os.path.realpath(root)
            if real == root or real.startswith(root.rstrip("/") + "/"):
                raise Refusal(cause, "check L7 at $")


# ----------------------------------------------- LIVE_DEPLOY, fetches


def check_live_deploy(c, site):
    """The work directory is not the runner host's live deploy (5.2). The
    live deploy's paths are a slot of the S0 review; unset refuses."""
    if site.live_deploy_paths is None:
        raise Refusal("PREFLIGHT.LIVE_DEPLOY")
    work = os.path.realpath(os.path.join(c.home, "alpha2-work"))
    for live in site.live_deploy_paths:
        live = os.path.realpath(live)
        if (work == live or work.startswith(live.rstrip("/") + "/")
                or live.startswith(work.rstrip("/") + "/")):
            raise Refusal("PREFLIGHT.LIVE_DEPLOY")


def open_fetch_dir(c, site):
    """A fresh directory for this run's fetches, pinned by descriptor:
    `<work>/fetched/<run_id>/`. `<work>` is opened without following a
    symlink and checked as 5.2 requires; `fetched` is created if absent and
    must then be a real directory owned by the run's account, mode 0700;
    `<run_id>` is created exclusively, so no repository, configuration or
    link in it predates this run. Returns the descriptor."""
    uid = site.getuid()
    try:
        home_fd = os.open(c.home, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError:
        raise Refusal("PREFLIGHT.FETCH")
    fds = [home_fd]
    try:
        work_fd = os.open(a2_rundir.WORK_NAME, a2_rundir.DIR_FLAGS, dir_fd=home_fd)
        fds.append(work_fd)
        a2_rundir._check_dir_fd(work_fd, uid)
        try:
            os.mkdir(FETCH_DIR, 0o700, dir_fd=work_fd)
        except FileExistsError:
            pass
        top_fd = os.open(FETCH_DIR, a2_rundir.DIR_FLAGS, dir_fd=work_fd)
        fds.append(top_fd)
        a2_rundir._check_dir_fd(top_fd, uid)
        os.mkdir(c.run_id, 0o700, dir_fd=top_fd)
        run_fd = os.open(c.run_id, a2_rundir.DIR_FLAGS, dir_fd=top_fd)
        try:
            a2_rundir._check_dir_fd(run_fd, uid)
        except Refusal:
            os.close(run_fd)
            raise
        return run_fd
    except (OSError, Refusal):
        raise Refusal("PREFLIGHT.FETCH")
    finally:
        for fd in fds:
            os.close(fd)


def _fetch_tag(c, site, name, url, tag, wrong_cause, label=None):
    """Fetch one tag into `<fetch dir>/<name>.git`. Names are unique within
    a run: the overlay's is "overlay", each component's "c-<name>"."""
    label = label or name
    url = site.repo_url_map.get(url, url)
    if getattr(c, "fetch_fd", None) is None:
        c.fetch_fd = open_fetch_dir(c, site)
    try:
        os.mkdir(name + ".git", 0o700, dir_fd=c.fetch_fd)
        bare = "/proc/%d/fd/%d/%s.git" % (os.getpid(), c.fetch_fd, name)
        site.git.init_bare(bare)
        if getattr(c, "fetched", None) is None:
            c.fetched = {}
        c.fetched[name] = bare
    except (a2_git.GitError, OSError):
        raise Refusal("PREFLIGHT.FETCH")
    try:
        listed = site.git.ls_remote_tag(bare, url, tag)
    except a2_git.GitError:
        raise Refusal("PREFLIGHT.REPO_ACCESS", "repository: " + label)
    if not listed:
        raise Refusal(wrong_cause)
    try:
        return site.git.fetch_tag(bare, url, tag)
    except a2_git.GitError:
        raise Refusal("PREFLIGHT.FETCH", "repository: " + label)


def check_fetch(c, site):
    """6.1 `components[]`: each pinned commit is fetched into the work
    directory by its annotated tag, read from the refs the remote fetch
    returned and peeled; it must be exactly the pinned commit."""
    for comp in c.lock["components"]:
        typ, peeled = _fetch_tag(c, site, "c-" + comp["name"], comp["repo"], comp["tag"], "PREFLIGHT.FETCH",
                                 label=comp["name"])
        if typ != "tag" or peeled != comp["commit"]:
            raise Refusal("PREFLIGHT.FETCH", "repository: " + comp["name"])


# ---------------------------------------------------- probe slots


def check_probes(c, site):
    """The probes owned elsewhere. Each answers "ok", or anything else,
    which refuses with its cause."""
    probes = [("PREFLIGHT.MAC_TOOLS", site.probe_tools),
              ("PREFLIGHT.NET_RUNTIME", site.probe_net_runtime),
              ("PREFLIGHT.KEEP_AWAKE", site.probe_keep_awake),
              ("PREFLIGHT.TARGET_ACCESS", site.probe_target_access),
              ("PREFLIGHT.HUB_READ", site.probe_hub_read),
              ("PREFLIGHT.OPERATOR_ROUTE", site.probe_operator_route)]
    if c.inv.command == "install" and c.inv.loop in ("L3", None):
        probes.append(("PREFLIGHT.SURVEY", site.probe_survey))
    for cause, probe in probes:
        if probe(c.hosts) != "ok":
            raise Refusal(cause)


# --------------------------------------------------------- custody


def custody(c, site):
    """5.3b: lock, placement and stop read-backs, as receipt facts."""
    locks = a2_locks.custody_locks(c.order, c.held, site.root_uid)
    placement = site.probe_placement(c.hosts)
    if placement not in ("match", "differs"):
        placement = "UNOBSERVED"
    if a2_stop.applies(c.inv):
        stop = a2_stop.read(c.lock_root)
    else:
        stop = "-"
    return {"CUSTODY_LOCKS": locks, "CUSTODY_PLACEMENT": placement, "CUSTODY_STOP": stop}


def custody_refusal(facts):
    """At S0, a set or UNOBSERVED stop file is PREFLIGHT.HANDOFF; any other
    mismatch is RUNNER.CUSTODY (5.3b)."""
    if facts["CUSTODY_STOP"] not in ("unset", "-"):
        return "PREFLIGHT.HANDOFF"
    if facts["CUSTODY_LOCKS"] != "held" or facts["CUSTODY_PLACEMENT"] != "match":
        return "RUNNER.CUSTODY"
    return None


# ------------------------------------------------------------- S0


def run_s0(c, site, run):
    """S0's checks after admission, in order, then its receipt. Returns
    None on PASS; raises the refusal after writing a FAIL receipt."""
    started = run.started
    facts = []
    try:
        _run_checks(c, site, run, started, facts)
    finally:
        if getattr(c, "fetch_fd", None) is not None:
            os.close(c.fetch_fd)
            c.fetch_fd = None


def _run_checks(c, site, run, started, facts):
    try:
        check_interpreter(c.lock, site)
        commit = check_private_source(c, site)
        facts.append(("PRIVATE_COMMIT", commit))
        check_l7(site)
        facts.append(("LEAK_CHECK", "L1 L2 L3 L4 L6 L7 L8 pass"))
        check_live_deploy(c, site)
        check_fetch(c, site)
        check_probes(c, site)
        cust = custody(c, site)
        facts += [(k, cust[k]) for k in ("CUSTODY_LOCKS", "CUSTODY_PLACEMENT", "CUSTODY_STOP")]
        bad = custody_refusal(cust)
        if bad:
            raise Refusal(bad)
        if c.admission_sha:
            facts.append(("ADMISSION_SHA", c.admission_sha))
    except Refusal as r:
        run.write_receipt("S0", None, started, "FAIL", facts, rc=r.rc, cause=r.cause)
        raise
    except Exception:
        # A failure S0 does not name: rc 3, since S0 has written in the work
        # directory (3.4), with the facts gathered so far as the final
        # observed state. A failure of this write is a2_main's to record.
        run.write_receipt("S0", None, started, "FAIL", facts, rc=3, cause="PREFLIGHT.UNCLASSIFIED")
        raise Refusal("PREFLIGHT.UNCLASSIFIED", rc=3) from None
    run.write_receipt("S0", None, started, "PASS", facts)
