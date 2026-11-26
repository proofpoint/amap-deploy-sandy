"""S4 IMAGES: each VM's RL and RE images, checked as they will run (design DESIGN-W6-d2.1-S4).

The lock's images[] holds exactly two entries. RL's is the one built from the RL component, and RE's is the other;
no component name beyond RL's is named here. Each entry's built-from commit is its component's commit in
components[]. On each VM of the run scope, `obtain` makes each image present by the lock's Id (decision D-W6-1:
a build-once `docker save` archive on the runner, checked by its sha and loaded only where the Id is absent; a load
is S4's only write). S4 then checks each image through the VM layer, as the agent account that runs docker for S8,
without writing:
- inspect: the image's Id, and its revision label equal to the built-from commit (IMAGES.REVISION);
- readback as root: every entry under the working directory root-owned, directories 0755, files 0644 or 0755
  (IMAGES.READBACK, 3.5 K1);
- readback as the runtime user, uid:hop gid: each file the container needs is readable (IMAGES.READBACK, K10);
- openssl: an absolute openssl CLI, version 3.0 or later (IMAGES.OPENSSL);
- RL only: the router fingerprint EXACT against the RL component's pin (IMAGES.FINGERPRINT), by this repository's
  router_fingerprint run on the runner, its docker calls carried by the VM layer.
Every one-shot run sets its entrypoint (3.5 K2). The receipt carries RL_IMAGE and RE_IMAGE, which S8 runs, and
RL_BUILT_FROM and RE_BUILT_FROM, the commits the images were built from.
"""

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import types

import a2_private
import a2_s6
from a2_causes import Refusal

STAGE = "IMAGES"
DOCKER = "/usr/bin/docker"
TEST = "/usr/bin/test"
#: A server version as the receipt records it; anything else is recorded UNOBSERVED (3.1), never refused.
_DOCKER_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+~_-]{0,63}")
PYTHON = "/usr/bin/python3"
#: The python3 inside both images, for every in-image --entrypoint: python:3.11-slim installs Python under /usr/local
#: (INFERRED from that image's layout; PENDING CAPTURE until a real image shows it). PYTHON is the VM host's.
IMAGE_PYTHON = "/usr/local/bin/python3"
RL, RE = "RL", "RE"
UNOBSERVED = "UNOBSERVED"
RL_COMPONENT = a2_s6.RL_COMPONENT
#: The installer's own component: router_fingerprint.py and hygiene_gate.py are files of it, at the repository
#: root, each pinned by a files[] row; the lock check makes its commit installer.commit.
INSTALLER_COMPONENT = a2_private.INSTALLER_COMPONENT
FINGERPRINT_FILES = ("hygiene_gate.py", "router_fingerprint.py")
REVISION_LABEL = "org.opencontainers.image.revision"
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_ABS = re.compile(r"/[A-Za-z0-9._/-]{1,4095}")
_OPENSSL = re.compile(r"OpenSSL ([0-9]{1,9})\.([0-9]{1,9})\.([0-9]{1,9})(?![0-9])")
OPENSSL_FLOOR = (3, 0)
#: Each image's `docker save` archive on the runner: `<lock_root>/ARCHIVE_DIR/<images[].name>.tar`, a regular file
#: of at most ARCHIVE_MAX bytes whose sha256 is the row's archive_sha256 (6.1, D-W6-1).
ARCHIVE_DIR = "images"
ARCHIVE_MAX = 2 * 1024 ** 3
_CHUNK = 1 << 20
#: One `docker load` of an archive, against the layer's per-call default.
LOAD_TIMEOUT_S = 1800
_SHA256 = re.compile(r"[0-9a-f]{64}")
#: The one-shot flags of every image run S4 makes (vm-build r2): removed, never pulled, no logs, no network, a
#: read-only root, no capability, no privilege gain.
#: The readback's per-file test, as the runtime user: a regular file, not a symlink (the walk does not judge a link's
#: target), and readable.
READ_TEST = 'test -f "$1" && test ! -L "$1" && test -r "$1"'
ONE_SHOT = ["run", "--rm", "--pull", "never", "--log-driver", "none", "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges"]
#: The working directory an image without one runs in (vm-build r2).
DEFAULT_WORKDIR = "/app"
#: The mode S8 starts RE in (a2_s8_re.start_argv's last word, the image's CMD).
RE_MODE = "both"
#: The files S4 itself reads as RE's runtime user, in each mode: the mode's exec chain, as paths in RE's tree; the
#: image holds them under its working directory /app (RE's Dockerfile: WORKDIR /app, COPY docker/entrypoint.sh,
#: ENTRYPOINT /app/docker/entrypoint.sh). They are not everything the container needs: the modules those import
#: come in through the Dockerfile's COPY list, which the Dockerfile's pin below fixes, and the root walk checks every
#: entry's owner and mode. The mode picks the module the entrypoint execs, and both_loop.py loads relay.py and
#: imap_notify.py. RE measured
#: this map at its commit f42aa0af; it holds while RE's Dockerfile and entrypoint.sh are the bytes pinned in
#: RE_DERIVATION_PINS, and otherwise S4 refuses PIN, so a change to either is re-read before S4 accepts it.
RE_NEEDED_BY_MODE = {"both": ("docker/entrypoint.sh", "host/both_loop.py", "host/relay.py", "host/imap_notify.py")}
RE_DERIVATION_PINS = {
    "docker/Dockerfile": "5c353cd827baa625de4d7cd5203c6ff3edd9f339ebdf8bb4308fb68c707d5fac",
    "docker/entrypoint.sh": "8d82b27f6699ddbddcc08302b75cb6e8acbf208cb43389d5dbb577fd52cff8ed",
}
RE_NEEDED = RE_NEEDED_BY_MODE[RE_MODE]
#: RE's fix commit for the wedge (W12; rulings W12-SCOPE-ALPHA2-VMS and the controller's W12-P1 ancestry ruling; HOP's
#: witness P1): the RE image must be built from this commit or a descendant, read in S0's fetched RE history.
RE_FIX_COMMIT = "fc542edc9f829c89c6378755b87acd26681571d8"

#: The readback walk (vm-build r2 5b), run in the image as root: every entry under the working directory, by lstat.
#: It never follows a link, so each needed path (argv[2:], relative to the working directory) must be a regular file
#: the walk reached: one under a symlinked directory, or itself a link, counts as off (3.5 K1, K10).
WALK = r'''import os, stat, sys
root, need, bad, n, first, files = sys.argv[1], sys.argv[2:], [], 0, None, set()
rs = os.lstat(root)
if not (rs.st_uid == 0 and rs.st_gid == 0 and stat.S_IMODE(rs.st_mode) == 0o755):
    bad.append(root)
for d, ds, fs in os.walk(root):
    ds.sort(); fs.sort()
    for x in ds + fs:
        q = os.path.join(d, x); st = os.lstat(q)
        if stat.S_ISLNK(st.st_mode):
            continue
        n += 1; m = stat.S_IMODE(st.st_mode)
        ok = st.st_uid == 0 and st.st_gid == 0 and (m == 0o755 if stat.S_ISDIR(st.st_mode) else m in (0o644, 0o755))
        if not ok:
            bad.append(q)
        if stat.S_ISREG(st.st_mode):
            files.add(q)
        if first is None and x.endswith(".py") and not stat.S_ISDIR(st.st_mode):
            first = q
bad += [p for p in need if os.path.join(root, p) not in files]
print("FIRSTPY", first or "-")
print("ENTRIES", n, "OFF-MODE", len(bad))
sys.exit(0 if n and not bad and first else 1)
'''
_WALK_OUT = re.compile(rb"FIRSTPY (/[A-Za-z0-9._/-]{1,4095})\nENTRIES ([0-9]{1,9}) OFF-MODE 0\n")


def _rc(layer):
    """A cause of S4's own after an obtain that wrote exits 3, and 2 before (3.4, 4.2)."""
    return 3 if layer.wrote(STAGE) else None


# -- before any VM contact

def image_rows(lock):
    """{RL: row, RE: row}, each row {"name", "image_id", "archive_sha256", "component", "commit"}; IMAGES.LOCK
    otherwise."""
    images = lock.get("images") if isinstance(lock, dict) else None
    components = lock.get("components") if isinstance(lock, dict) else None
    if not isinstance(images, list) or len(images) != 2 or not isinstance(components, list):
        raise Refusal(STAGE + ".LOCK", "images")
    rl = [i for i in images if isinstance(i, dict) and i.get("built_from") == RL_COMPONENT]
    re_ = [i for i in images if isinstance(i, dict) and i.get("built_from") != RL_COMPONENT]
    if len(rl) != 1 or len(re_) != 1:
        raise Refusal(STAGE + ".LOCK", "images")
    out = {}
    for role, row in ((RL, rl[0]), (RE, re_[0])):
        commits = [c.get("commit") for c in components if isinstance(c, dict) and c.get("name") == row.get("built_from")]
        if (len(commits) != 1 or not isinstance(commits[0], str) or not _COMMIT.fullmatch(commits[0])
                or not isinstance(row.get("image_id"), str) or not _IMAGE_ID.fullmatch(row["image_id"])
                or not isinstance(row.get("archive_sha256"), str) or not _SHA256.fullmatch(row["archive_sha256"])
                or not isinstance(row.get("name"), str) or not a2_private._COMPILED["name"].fullmatch(row["name"])):
            raise Refusal(STAGE + ".LOCK", "images")
        out[role] = {"name": row["name"], "image_id": row["image_id"], "archive_sha256": row["archive_sha256"],
                     "component": row["built_from"], "commit": commits[0]}
    return out


def plan_facts(rows):
    """A dry-run's facts: the commit each image is built from."""
    return [("RL_BUILT_FROM", rows[RL]["commit"]), ("RE_BUILT_FROM", rows[RE]["commit"])]


def archive_path(lock_root, row):
    return os.path.join(lock_root, ARCHIVE_DIR, row["name"] + ".tar")


def read_archive(lock_root, row, keep, rc=None, root_uid=0):
    """The archive of image `row`, checked: its directory a real directory owned by `root_uid` with mode 0755, the
    file opened O_NOFOLLOW|O_NONBLOCK, a regular file owned by `root_uid` with mode 0644 (the lock files' rule,
    contract 5.3), of at most ARCHIVE_MAX bytes read to EOF, its sha256 the row's archive_sha256. Returns the bytes
    when `keep`, else None. IMAGES.PIN otherwise."""
    try:
        dst = os.lstat(os.path.join(lock_root, ARCHIVE_DIR))
        if not stat.S_ISDIR(dst.st_mode):
            raise Refusal(STAGE + ".PIN", "image archive", rc=rc)
        if dst.st_uid != root_uid or stat.S_IMODE(dst.st_mode) != 0o755:
            raise Refusal(STAGE + ".PIN", "image archive", rc=rc)
        fd = os.open(archive_path(lock_root, row), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise Refusal(STAGE + ".PIN", "image archive", rc=rc)
    h, chunks, total = hashlib.sha256(), [], 0
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > ARCHIVE_MAX:
            raise Refusal(STAGE + ".PIN", "image archive", rc=rc)
        if st.st_uid != root_uid or stat.S_IMODE(st.st_mode) != 0o644:
            raise Refusal(STAGE + ".PIN", "image archive", rc=rc)
        while True:
            b = os.read(fd, _CHUNK)
            if not b:
                break
            total += len(b)
            if total > ARCHIVE_MAX:
                raise Refusal(STAGE + ".PIN", "image archive", rc=rc)
            h.update(b)
            if keep:
                chunks.append(b)
    except OSError:
        raise Refusal(STAGE + ".PIN", "image archive", rc=rc)
    finally:
        os.close(fd)
    if h.hexdigest() != row["archive_sha256"]:
        raise Refusal(STAGE + ".PIN", "image archive", rc=rc)
    return b"".join(chunks) if keep else None


def archives(lock_root, rows, root_uid=0):
    """Both archives checked on the runner before any VM contact, read only; IMAGES.PIN otherwise (rc 2)."""
    for role in (RL, RE):
        read_archive(lock_root, rows[role], keep=False, root_uid=root_uid)


# -- on the VM, read only

def runtime_users(layer, vm, v):
    """{RL: "uid:hop_gid", RE: "relay_uid:hop_gid"}: the users S8 runs RL and RE as, from S6's measure script."""
    src = layer.pinned_installer_file(a2_s6.MEASURE_SCRIPT, STAGE).decode("utf-8")
    rc, out, _err = layer.exec(vm, [PYTHON, "-I", "-S", "-c", src, v["relay_account"], v["hop_group"]],
                               account=v["agent_account"], stage=STAGE, writes=False)
    if rc == a2_s6._MISSING:
        raise Refusal(STAGE + ".HOSTS", vm, rc=_rc(layer))
    doc = a2_s6._strict_line(out) if rc == 0 else None
    if (doc is None or set(doc) != a2_s6.MEASURE_KEYS
            or not all(a2_s6._int(doc.get(k)) for k in ("uid", "relay_uid", "hop_gid"))):
        raise Refusal(STAGE + ".UNCLASSIFIED", "measure rc %d" % rc, rc=_rc(layer))
    if doc["uid"] == 0 or doc["relay_uid"] in (0, doc["uid"]):
        raise Refusal(STAGE + ".HOSTS", vm, rc=_rc(layer))
    return {RL: "%d:%d" % (doc["uid"], doc["hop_gid"]), RE: "%d:%d" % (doc["relay_uid"], doc["hop_gid"])}


def _docker(layer, vm, v, args):
    return layer.exec(vm, [DOCKER] + list(args), account=v["agent_account"], stage=STAGE, writes=False)


def inspect(layer, vm, v, ref, commit):
    """(Id, working directory) of image `ref`, whose revision label must be `commit`."""
    rc, out, _err = _docker(layer, vm, v, ["image", "inspect", "--format", "{{json .}}", ref])
    try:
        doc = json.loads(out.decode("utf-8")) if rc == 0 else None
    except (ValueError, UnicodeDecodeError):
        doc = None
    config = doc.get("Config") if isinstance(doc, dict) else None
    iid = doc.get("Id") if isinstance(doc, dict) else None
    if not isinstance(config, dict) or not isinstance(iid, str) or not _IMAGE_ID.fullmatch(iid):
        raise Refusal(STAGE + ".UNCLASSIFIED", "inspect rc %d" % rc, rc=_rc(layer))
    labels = config.get("Labels") or {}
    if not isinstance(labels, dict) or labels.get(REVISION_LABEL) != commit:
        raise Refusal(STAGE + ".REVISION", vm, rc=_rc(layer))
    wd = config.get("WorkingDir") or DEFAULT_WORKDIR
    if not isinstance(wd, str) or not _ABS.fullmatch(wd) or os.path.normpath(wd) != wd:
        raise Refusal(STAGE + ".READBACK", vm, rc=_rc(layer))
    return iid, wd


def readback(layer, vm, v, iid, workdir, user, needed):
    """The walk as root, which must also reach each needed file (under `workdir`) as a regular file, then each needed
    file and the walk's first .py read as `user`. Returns the entry count."""
    rc, out, _err = _docker(layer, vm, v, ONE_SHOT + ["--user", "0:0", "--entrypoint", IMAGE_PYTHON, iid,
                                                      "-I", "-S", "-c", WALK, workdir] + list(needed))
    m = _WALK_OUT.fullmatch(out) if rc == 0 else None
    if m is None:
        raise Refusal(STAGE + ".READBACK", vm, rc=_rc(layer))
    first = m.group(1).decode()
    for path in [workdir + "/" + p for p in needed] + [first]:
        rc, _out, _err = _docker(layer, vm, v, ONE_SHOT + ["--user", user, "--entrypoint", "/bin/sh", iid,
                                                           "-c", READ_TEST, "readback", path])
        if rc != 0:
            raise Refusal(STAGE + ".READBACK", vm, rc=_rc(layer))
    return int(m.group(2))


def openssl(layer, vm, v, iid):
    """"version=x.y.z|path=<abs>" of the image's openssl CLI, which must be 3.0 or later."""
    rc, out, _err = _docker(layer, vm, v, ONE_SHOT + ["--entrypoint", "/bin/sh", iid, "-c",
                                                      'p=$(command -v openssl) || exit 9; printf "%s\\n" "$p"; '
                                                      'exec "$p" version'])
    lines = out.decode("utf-8", "replace").split("\n") if rc == 0 else []
    if len(lines) != 3 or lines[2] != "" or not _ABS.fullmatch(lines[0]):
        raise Refusal(STAGE + ".OPENSSL", vm, rc=_rc(layer))
    m = _OPENSSL.match(lines[1])
    if m is None or (int(m.group(1)), int(m.group(2))) < OPENSSL_FLOOR:
        raise Refusal(STAGE + ".OPENSSL", vm, rc=_rc(layer))
    return "version=%s.%s.%s|path=%s" % (m.group(1), m.group(2), m.group(3), lines[0])


# -- the router fingerprint, on the runner

def fingerprint_modules(layer):
    """router_fingerprint, with its hygiene_gate, from the installer checkout's root, each checked against its
    files[] row of the installer component before either is run (PIN otherwise). Loaded as fresh modules, never from
    sys.path; sys.modules holds them only while they load (a dataclass reads its module there), then is restored."""
    root = os.path.dirname(os.path.abspath(layer.installer_dir))
    sources = []
    for fname in FINGERPRINT_FILES:
        rows = [f for f in layer.lock.get("files", []) if f.get("component") == INSTALLER_COMPONENT
                and f.get("path") == fname]
        try:
            with open(os.path.join(root, fname), "rb") as f:
                data = f.read()
        except OSError:
            raise Refusal(STAGE + ".PIN", fname, rc=_rc(layer))
        if len(rows) != 1 or hashlib.sha256(data).hexdigest() != rows[0].get("sha256"):
            raise Refusal(STAGE + ".PIN", fname, rc=_rc(layer))
        sources.append((fname[:-3], os.path.join(root, fname), data))
    saved = {name: sys.modules.get(name) for name, _p, _d in sources}
    mods = {}
    try:
        for name, path, data in sources:
            mod = types.ModuleType(name)
            mod.__file__ = path
            sys.modules[name] = mod
            exec(compile(data, path, "exec"), mod.__dict__)
            mods[name] = mod
    finally:
        for name, old in saved.items():
            if old is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old
    return mods["router_fingerprint"]


def layer_runner(layer, vm, v, iid, program):
    """A subprocess.run stand-in for router_fingerprint.capture_image, for image `iid` (the lock's Id) and the module's
    `program`. It admits exactly capture_image's two argvs: `image inspect <iid>`, sent as it is, and its one-shot,
    rewritten to S4's ONE_SHOT flags with the absolute entrypoint (3.5 K2). Each goes through the VM layer with the
    module's timeout; any other argv, or any keyword but capture_output and timeout, raises OSError, which
    capture_image reports as a CaptureError."""
    inspect_argv = [DOCKER, "image", "inspect", iid]
    run_argv = [DOCKER, "run", "--rm", "--network", "none", "--entrypoint", "python3", iid, "-I", "-S", "-c", program,
                "image"]

    def run(argv, capture_output=True, timeout=None, **kw):
        if kw:
            raise OSError("not an argument S4 admits")
        if argv == inspect_argv:
            words = argv
        elif argv == run_argv:
            words = [DOCKER] + ONE_SHOT + ["--entrypoint", IMAGE_PYTHON, iid, "-I", "-S", "-c", program, "image"]
        else:
            raise OSError("not an argv S4 admits")
        rc, out, err = layer.exec(vm, words, account=v["agent_account"], stage=STAGE, writes=False,
                                  timeout_s=timeout)
        return subprocess.CompletedProcess(argv, rc, out, err)
    return run


def fingerprint(layer, vm, v, iid, commit, rfp):
    """The RL image's router fingerprint against the RL component's pin: EXACT, or IMAGES.FINGERPRINT."""
    bare = rl_fetched(layer)
    try:
        capture = rfp.capture_image([DOCKER], iid, run=layer_runner(layer, vm, v, iid, rfp.PROGRAM))
        history = rfp.read_history(bare, commit, commit, git=layer.git.git)
    except (rfp.CaptureError, rfp.HistoryReadError):
        raise Refusal(STAGE + ".FINGERPRINT", vm, rc=_rc(layer))
    outcome, code, _reason, _text = rfp.verify_image(rfp.canonical(capture), history, commit)
    if outcome != rfp.EXACT or code != 0 or capture["image"]["id"] != iid:
        raise Refusal(STAGE + ".FINGERPRINT", vm, rc=_rc(layer))
    return "EXACT"


def re_needed(layer):
    """RE_NEEDED for RE_MODE, from the RE component's tree at the lock's commit: the Dockerfile and entrypoint.sh
    must be the bytes RE_DERIVATION_PINS names, and each needed path a regular file of the tree. Anything else
    refuses PIN; no path is skipped."""
    rows = image_rows(layer.lock)
    trees = {}

    def file_of(p):
        prefix, _, name = p.rpartition("/")
        if prefix not in trees:
            trees[prefix] = {path: data for path, _mode, data in
                             layer.component_tree(rows[RE]["component"], prefix, stage=STAGE)[1]}
        return trees[prefix].get(name)
    for p, sha in RE_DERIVATION_PINS.items():
        data = file_of(p)
        if data is None or hashlib.sha256(data).hexdigest() != sha:
            raise Refusal(STAGE + ".PIN", "RE derivation file", rc=_rc(layer))
    for p in RE_NEEDED:
        if file_of(p) is None:
            raise Refusal(STAGE + ".PIN", "RE needed file", rc=_rc(layer))
    return RE_NEEDED


def re_fix(layer, rows):
    """"0" when RE_FIX_COMMIT is an ancestor of (or is) RE's built-from commit in S0's fetched RE repository, the
    exit status of `git merge-base --is-ancestor` HOP's witness requires. Run before any VM contact, read only:
    otherwise RE_FIX (a BEFORE_WRITE_ONLY cause), or PIN when the repository was not fetched."""
    import a2_git
    bare = layer.fetched.get("c-" + rows[RE]["component"])
    if bare is None or layer.git is None:
        raise Refusal(STAGE + ".PIN", "RE repository not fetched", rc=_rc(layer))
    try:
        ok = layer.git.is_ancestor(bare, RE_FIX_COMMIT, rows[RE]["commit"])
    except a2_git.GitError:
        ok = False
    if not ok:
        raise Refusal(STAGE + ".RE_FIX", "RE's built-from commit")
    return "0"


def pre_vm(layer, rows):
    """Every S4 check that reads only the lock, S0's fetch and the installer checkout, run before any VM contact so a
    fault there is exit 2 with nothing written: RE_FIX, RE's derivation pins and needed files, the fingerprint
    modules' files[] rows, and the RL repository fetched. Returns (fix, needed, rfp)."""
    fix = re_fix(layer, rows)
    needed = re_needed(layer)
    rfp = fingerprint_modules(layer)
    rl_fetched(layer)
    return fix, needed, rfp


def rl_fetched(layer):
    """S0's fetched RL repository, which the fingerprint's history is read from; IMAGES.PIN when it is absent."""
    bare = layer.fetched.get("c-" + RL_COMPONENT)
    if bare is None or layer.git is None:
        raise Refusal(STAGE + ".PIN", "RL repository not fetched", rc=_rc(layer))
    return bare


def check_vm(layer, vm, v, rows, refs, fix, rfp, needed):
    """S4's read-only checks on one VM, for images `refs` ({RL: ref, RE: ref}) already present, with pre_vm's `fix`,
    `rfp` and RE's `needed` files. Each image's inspected Id must be the lock's (IMAGES.UNCLASSIFIED otherwise), and
    every check runs on that Id. Returns facts."""
    users = runtime_users(layer, vm, v)
    needed = {RL: (), RE: needed}
    facts = [("RE_FIX_ANCESTOR", fix)]
    for role in (RL, RE):
        want = rows[role]["image_id"]
        iid, wd = inspect(layer, vm, v, refs[role], rows[role]["commit"])
        if iid != want:
            raise Refusal(STAGE + ".UNCLASSIFIED", "inspect Id", rc=_rc(layer))
        n = readback(layer, vm, v, want, wd, users[role], needed[role])
        ssl = openssl(layer, vm, v, want)
        facts += [(role + "_IMAGE", want), (role + "_BUILT_FROM", rows[role]["commit"]),
                  (role + "_READBACK", "PASS entries=%d" % n), (role + "_OPENSSL", ssl)]
        if role == RL:
            facts.append(("RL_FINGERPRINT", fingerprint(layer, vm, v, want, rows[RL]["commit"], rfp)))
    return facts


def docker_ready(layer, vm, v):
    """Docker usable on the VM by the agent account, before any other docker call: `test -x /usr/bin/docker`, then
    `docker version --format '{{.Server.Version}}'`, each exiting 0, or IMAGES.DOCKER. Decided on the exit status
    only; the daemon's text is never read. Returns the server version for the receipt, UNOBSERVED if it is not a
    version-shaped line."""
    rc, _out, _err = layer.exec(vm, [TEST, "-x", DOCKER], account=v["agent_account"], stage=STAGE, writes=False)
    if rc != 0:
        raise Refusal(STAGE + ".DOCKER", vm, rc=_rc(layer))
    rc, out, _err = _docker(layer, vm, v, ["version", "--format", "{{.Server.Version}}"])
    if rc != 0:
        raise Refusal(STAGE + ".DOCKER", vm, rc=_rc(layer))
    try:
        text = out.decode("ascii")
    except UnicodeDecodeError:
        text = ""
    ver = text[:-1] if text.endswith("\n") else ""
    return ver if _DOCKER_VERSION.fullmatch(ver) else "UNOBSERVED"


def image_ids(layer, vm, v):
    """The set of image Ids on the VM, from `docker image ls --no-trunc --quiet` as the agent account: rc 0 and every
    line an Id, or IMAGES.UNCLASSIFIED. An image is absent when that list succeeds and does not name it; a daemon's
    error text is never read."""
    rc, out, _err = _docker(layer, vm, v, ["image", "ls", "--no-trunc", "--quiet"])
    try:
        text = out.decode("ascii") if rc == 0 else None
    except UnicodeDecodeError:
        text = None
    lines = text.split("\n") if text is not None else None
    if lines is None or lines[-1] != "" or not all(_IMAGE_ID.fullmatch(x) for x in lines[:-1]):
        raise Refusal(STAGE + ".UNCLASSIFIED", "image ls rc %d" % rc, rc=_rc(layer))
    return set(lines[:-1])


def obtain(layer, vm, v, rows, lock_root, root_uid=0, state=None):
    """Each image present on the VM by the lock's Id: one already there is left alone; an absent one is loaded from
    its archive on the runner, re-read and re-checked at use, by `docker load` with the archive as stdin (a write).
    Returns ({RL: ref, RE: ref}, {RL: loaded, RE: loaded}). A load that exits non-zero is IMAGES.LOAD; a load after
    which the list does not name the lock's Id is IMAGES.ID_MISMATCH; both exit 3. `state`, when given, is filled as
    the VM is learned, so a refusal can say what was left: each role "yes" once its load exits 0, "UNOBSERVED" from
    the moment its load is sent until then (a load that fails or does not complete), and otherwise left as given."""
    state = {} if state is None else state
    present = image_ids(layer, vm, v)
    loaded = {}
    for role in (RL, RE):
        iid = rows[role]["image_id"]
        if iid in present:
            loaded[role] = False
            continue
        data = read_archive(lock_root, rows[role], keep=True, rc=_rc(layer), root_uid=root_uid)
        state[role] = UNOBSERVED
        rc, _out, _err = layer.exec(vm, [DOCKER, "load"], account=v["agent_account"], stage=STAGE, writes=True,
                                    stdin=data, timeout_s=LOAD_TIMEOUT_S)
        del data
        if rc != 0:
            raise Refusal(STAGE + ".LOAD", vm, rc=3)
        loaded[role] = True
        state[role] = "yes"
        present = image_ids(layer, vm, v)
        if iid not in present:
            raise Refusal(STAGE + ".ID_MISMATCH", vm, rc=3)
    return {role: rows[role]["image_id"] for role in (RL, RE)}, loaded


def loaded_facts(loaded):
    return [(role + "_LOADED", "yes" if loaded[role] else "no") for role in (RL, RE)]


def new_state():
    """A VM's state before S4 has learned anything of it: no load sent, the docker version not read."""
    return {"DOCKER_VERSION": UNOBSERVED, RL: "no", RE: "no"}


def state_facts(state):
    """What an rc-3 refusal on a VM leaves (3.4): the docker version, and whether each image was loaded there by
    this run: "yes", "no", or "UNOBSERVED" for a load that failed or did not complete."""
    return [("DOCKER_VERSION", state["DOCKER_VERSION"])] + [(role + "_LOADED", state[role]) for role in (RL, RE)]


def run_s4(c, site, rec):
    """S4 over the run scope's VMs, one receipt each (a2_stage.per_vm). A dry-run plans each VM's built-from
    commits and touches nothing."""
    import a2_stage
    names = [v["name"] for v in c.hosts["vms"] if v["scope"] == a2_stage.scope_of(c.inv.loop)]
    if c.inv.command == "dry-run":
        try:
            rows = image_rows(c.lock)
        except Refusal as r:
            a2_stage.refuse_before_vms(rec, site, "S4", names, r)
        a2_stage.per_vm(rec, site, "S4", names, None, plan=lambda _n: plan_facts(rows), dry_run=True)
        return
    try:
        rows = image_rows(c.lock)
        try:
            _scope, vms = a2_s6.scope_vms(c.hosts, c.inv.loop)
        except Refusal as r:
            # scope_vms refuses only <its stage>.HOSTS, for a scope of other than two VMs.
            raise Refusal(STAGE + ".HOSTS", r.detail)
        if site.vm_layer is None:
            raise Refusal(STAGE + ".TARGET_ACCESS", "the VM layer is not bound")
        fix, needed, rfp = pre_vm(site.vm_layer, rows)
        archives(c.lock_root, rows, site.root_uid)
    except Refusal as r:
        a2_stage.refuse_before_vms(rec, site, "S4", names, r)
    by_name = {v["name"]: v for v in vms}

    def step(n):
        state = new_state()
        try:
            state["DOCKER_VERSION"] = docker_ready(site.vm_layer, n, by_name[n])
            refs, loaded = obtain(site.vm_layer, n, by_name[n], rows, c.lock_root, site.root_uid, state)
            facts = [("DOCKER_VERSION", state["DOCKER_VERSION"])] + loaded_facts(loaded) + check_vm(
                site.vm_layer, n, by_name[n], rows, refs, fix, rfp, needed)
        except Refusal as r:
            if r.rc == 3:
                r.facts = state_facts(state)
            raise
        return facts, "CHANGED" if any(loaded.values()) else "ALREADY"
    a2_stage.per_vm(rec, site, "S4", names, step)
