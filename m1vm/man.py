"""m1-man: write MAN, T0's manifest, as BAKE's last step (LC d8 §1; DS2 d8 §1.1
steps 1, 6 and 9). Standard library only; run by BAKE with root.

  python3 -I -S -B man.py write --plan PLAN --out MAN

PLAN is the `man` member of PIN, a JSON object naming what MAN records:

  {"pin_sha256": HEX, "seed": "/opt/amap/sandy-seed",
   "files": [ABS, ...], "checkouts": [ABS, ...], "images": [REF, ...],
   "accounts": [NAME, ...], "roles": {ROLE: NAME, ...},
   "builds": {NAME: {"commit": HEX40, "tree": HEX40, "image": REF}, ...},
   "trees": [ABS, ...]}

MAN then holds, in canonical JSON (sorted keys, no spaces):
  - `schema` "m1vm-man/1" and `pin_sha256`;
  - `hdot`: every hash dotfile in the seed as {name, mode, sha256}; the list
    m1-seed-copy copies and A2a compares (LC d8 §2.3);
  - `files`: {path: {sha256, mode, uid, gid}} for each named regular file;
  - `checkouts`: {path: {head, tree}};
  - `images`: {ref: image Id}, from the engine;
  - `packages`: {name: version}, every installed package (dpkg-query -W);
  - `accounts`: {name: {uid, gid, home, groups}} (supplementary groups);
  - `roles`: {role: name}, exactly the six PIN roles, each naming one of
    `accounts`, so a reader binds a role (e.g. `op`) to its account
    unambiguously;
  - `builds`: {name: {commit, tree, image, id}}, each router image's pin, its
    clean export's tree and its engine Id (the per-VM fingerprint check reads
    these; controller ruling (i));
  - `trees`: {root: {relpath: entry}} for each named tree, every entry
    under it (the root itself as "."): `{"type": "d", "mode", "uid", "gid"}`,
    `{"type": "f", "mode", "uid", "gid", "sha256"}` or `{"type": "l",
    "uid", "target"}`; anything else (a socket, a device) fails the write.
    Walked without following a link, so a link is recorded, never crossed.

Every path is opened from / one component at a time with O_NOFOLLOW; a link,
a missing file or a non-regular file fails the write. MAN is created O_EXCL
and never overwritten. The last stdout line is `M1-MAN PASS sha256=<MAN's
sha256>` only on success.

Exit status: 0 PASS; 1 FAIL (one `FAIL <reason>` line on stderr, no MAN
written); 2 usage; 3 internal.
"""

import errno
import fnmatch
import hashlib
import json
import os
import grp
import pwd
import re
import stat
import subprocess
import sys

SCHEMA = "m1vm-man/1"
PLAN_KEYS = {"pin_sha256", "seed", "files", "checkouts", "images", "accounts", "roles", "builds", "trees"}
MAX_TREE_ENTRIES = 4096
ROLES = ("op", "m1-admin", "adm", "uid-1", "uid-2", "registry")
GIT = "/usr/bin/git"
DOCKER = "/usr/bin/docker"
DPKG_QUERY = "/usr/bin/dpkg-query"
RUN_TIMEOUT_S = 120
RUN_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "HOME": "/root"}
MAX_FILE_BYTES = 64 << 20

# HDOT's closed set; equal to m1-seed-copy's (a test pins the two together,
# because under -I neither program can import the other).
TOP_PATTERNS = (".base_build_hash", ".build_hash*", ".skills_*_build_hash", ".skill_version_*")
SANDBOX_NAME = ".project_build_hash"
_SLUG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_TOP_RE = re.compile(r"[!-~]+\Z")
_SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
_HEX40_RE = re.compile(r"[0-9a-f]{40}\Z")
_IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_NAME_RE = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class Fail(Exception):
    """MAN cannot be written: exit 1."""


class Usage(Exception):
    """A usage error: exit 2."""


# ------------------------------------------------------------------ paths

def _norm_abs(path):
    return isinstance(path, str) and path.startswith("/") and not path.startswith("//") \
        and os.path.normpath(path) == path and path != "/"


def open_dir(path):
    """A descriptor for directory PATH, walked from / with O_NOFOLLOW."""
    fd = os.open("/", _DIR_FLAGS)
    for part in [p for p in path.split("/") if p]:
        try:
            nfd = os.open(part, _DIR_FLAGS, dir_fd=fd)
        except FileNotFoundError:
            os.close(fd)
            raise Fail(f"{path}: absent") from None
        except OSError as exc:
            os.close(fd)
            if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                raise Fail(f"{path}: {part} is not a plain directory") from None
            raise
        os.close(fd)
        fd = nfd
    return fd


def file_record(dir_fd, name, label):
    """{sha256, mode, uid, gid} of regular file NAME in DIR_FD."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=dir_fd)
    except FileNotFoundError:
        raise Fail(f"{label}: absent") from None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise Fail(f"{label}: a symbolic link") from None
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Fail(f"{label}: not a regular file")
        h, total = hashlib.sha256(), 0
        while True:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                raise Fail(f"{label}: larger than {MAX_FILE_BYTES} bytes")
            h.update(chunk)
        return {"sha256": h.hexdigest(), "mode": f"{stat.S_IMODE(st.st_mode):04o}",
                "uid": st.st_uid, "gid": st.st_gid}
    finally:
        os.close(fd)


def record_path(path):
    head, name = os.path.split(path)
    dfd = open_dir(head)
    try:
        return file_record(dfd, name, path)
    finally:
        os.close(dfd)


# ------------------------------------------------------------------ the parts

def hdot(seed):
    """The seed's hash dotfiles as [{name, mode, sha256}], sorted by name."""
    out = []
    sfd = open_dir(seed)
    try:
        for n in sorted(os.listdir(sfd)):
            if _TOP_RE.match(n) and any(fnmatch.fnmatchcase(n, p) for p in TOP_PATTERNS):
                rec = file_record(sfd, n, f"{seed}/{n}")
                out.append({"name": n, "mode": rec["mode"], "sha256": rec["sha256"]})
        try:
            bfd = os.open("sandboxes", _DIR_FLAGS, dir_fd=sfd)
        except FileNotFoundError:
            bfd = None
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                raise Fail(f"{seed}/sandboxes: not a plain directory") from None
            raise
        if bfd is not None:
            try:
                for slug in sorted(os.listdir(bfd)):
                    st = os.stat(slug, dir_fd=bfd, follow_symlinks=False)
                    if not stat.S_ISDIR(st.st_mode):
                        raise Fail(f"{seed}/sandboxes/{slug!r}: not a plain directory")
                    if not _SLUG_RE.match(slug):
                        raise Fail(f"{seed}/sandboxes/{slug!r}: a slug m1-seed-copy would refuse")
                    dfd = os.open(slug, _DIR_FLAGS, dir_fd=bfd)
                    try:
                        try:
                            os.stat(SANDBOX_NAME, dir_fd=dfd, follow_symlinks=False)
                        except FileNotFoundError:
                            continue
                        rec = file_record(dfd, SANDBOX_NAME, f"{seed}/sandboxes/{slug}/{SANDBOX_NAME}")
                    finally:
                        os.close(dfd)
                    out.append({"name": f"sandboxes/{slug}/{SANDBOX_NAME}", "mode": rec["mode"],
                                "sha256": rec["sha256"]})
            finally:
                os.close(bfd)
    finally:
        os.close(sfd)
    if not out:
        raise Fail(f"{seed}: holds no hash dotfile; sandy --build-only did not run")
    return sorted(out, key=lambda e: e["name"])


def run(argv):
    r = subprocess.run(argv, capture_output=True, text=True, timeout=RUN_TIMEOUT_S, env=RUN_ENV)
    if r.returncode != 0:
        raise Fail(f"{os.path.basename(argv[0])} exited {r.returncode}")
    return r.stdout


def tree(root):
    """{relpath: entry} for every object under ROOT, walked fd-relative with
    O_NOFOLLOW; links recorded by target, never followed."""
    out = {}

    def entry(st, dir_fd, name, rel):
        mode = f"{stat.S_IMODE(st.st_mode):04o}"
        if stat.S_ISDIR(st.st_mode):
            return {"type": "d", "mode": mode, "uid": st.st_uid, "gid": st.st_gid}
        if stat.S_ISREG(st.st_mode):
            rec = file_record(dir_fd, name, f"{root}/{rel}")
            return {"type": "f", "mode": rec["mode"], "uid": rec["uid"], "gid": rec["gid"], "sha256": rec["sha256"]}
        if stat.S_ISLNK(st.st_mode):
            return {"type": "l", "uid": st.st_uid, "target": os.readlink(name, dir_fd=dir_fd)}
        raise Fail(f"{root}/{rel}: neither a file, a directory nor a link")

    def walk(fd, rel):
        for name in sorted(os.listdir(fd)):
            sub = f"{rel}/{name}" if rel != "." else name
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            out[sub] = entry(st, fd, name, sub)
            if len(out) > MAX_TREE_ENTRIES:
                raise Fail(f"{root}: more than {MAX_TREE_ENTRIES} entries")
            if stat.S_ISDIR(st.st_mode):
                nfd = os.open(name, _DIR_FLAGS, dir_fd=fd)
                try:
                    walk(nfd, sub)
                finally:
                    os.close(nfd)

    fd = open_dir(root)
    try:
        st = os.fstat(fd)
        out["."] = {"type": "d", "mode": f"{stat.S_IMODE(st.st_mode):04o}", "uid": st.st_uid, "gid": st.st_gid}
        walk(fd, ".")
    finally:
        os.close(fd)
    return out


def checkout(path, runner):
    os.close(open_dir(path))  # the path itself must be a plain directory, walked from /
    head =runner([GIT, "-C", path, "rev-parse", "--verify", "HEAD^{commit}"]).strip()
    tree = runner([GIT, "-C", path, "rev-parse", "--verify", "HEAD^{tree}"]).strip()
    if not _HEX40_RE.match(head) or not _HEX40_RE.match(tree):
        raise Fail(f"{path}: git did not print a commit and a tree")
    return {"head": head, "tree": tree}


def image_id(ref, runner):
    out = runner([DOCKER, "image", "inspect", "--format", "{{.Id}}", ref]).strip()
    if not _IMAGE_ID_RE.match(out):
        raise Fail(f"image {ref}: the engine printed no image Id")
    return out


def package_state(abbrev):
    """dpkg's ${db:Status-Abbrev} (desired, status, error flag) read as
    "installed", "absent" or None (neither: half-installed, unpacked,
    triggers pending, or an error flag). Desired is ignored, so a held
    package (`hi `) is installed (Opus round9 (a)2)."""
    if len(abbrev) != 3 or abbrev[2] != " ":
        return None
    return {"i": "installed", "n": "absent", "c": "absent"}.get(abbrev[1])


def packages(runner):
    """Every installed package, held ones included, in the form ADM reads
    them back; a not-installed or config-files entry is skipped, and any
    package in another state is a Fail."""
    out = {}
    for n, line in enumerate(runner([DPKG_QUERY, "-W", "-f", "${db:Status-Abbrev}\t${Package}\t${Version}\n"])
                             .splitlines(), 1):
        f = line.split("\t")
        if len(f) != 3 or not f[1]:
            raise Fail(f"dpkg-query: line {n} is not one package")
        state = package_state(f[0])
        if state is None:
            raise Fail(f"dpkg-query: {f[1]} is {f[0]!r}, neither installed nor absent")
        if state == "absent":
            continue
        if not f[2]:
            raise Fail(f"dpkg-query: {f[1]} is installed with no version")
        if f[1] in out:
            raise Fail(f"dpkg-query: {f[1]} listed twice")
        out[f[1]] = f[2]
    if not out:
        raise Fail("dpkg-query: no packages")
    return out


def account(name):
    try:
        pw = pwd.getpwnam(name)
    except KeyError:
        raise Fail(f"account {name}: absent") from None
    groups = sorted(g.gr_name for g in grp.getgrall() if name in g.gr_mem)
    return {"uid": pw.pw_uid, "gid": pw.pw_gid, "home": pw.pw_dir, "groups": groups}


# ------------------------------------------------------------------ MAN

def validate_plan(plan):
    if not isinstance(plan, dict) or set(plan) != PLAN_KEYS:
        raise Usage(f"the plan must be exactly {sorted(PLAN_KEYS)}")
    if not isinstance(plan["pin_sha256"], str) or not _SHA_RE.match(plan["pin_sha256"]):
        raise Usage("pin_sha256 must be 64 lowercase hex")
    if not _norm_abs(plan["seed"]):
        raise Usage("seed must be a normalised absolute path")
    for key in ("files", "checkouts", "images", "accounts"):
        value = plan[key]
        if not isinstance(value, list) or not value or len(set(value)) != len(value) \
                or not all(isinstance(v, str) and v for v in value):
            raise Usage(f"{key} must be a non-empty list of distinct strings")
    for p in plan["files"] + plan["checkouts"]:
        if not _norm_abs(p):
            raise Usage(f"{p!r}: not a normalised absolute path")
    for a in plan["accounts"]:
        if not _NAME_RE.match(a):
            raise Usage(f"{a!r}: not an account name")
    r = plan["roles"]
    if not (isinstance(r, dict) and set(r) == set(ROLES) and all(isinstance(v, str) and v in plan["accounts"]
                                                                 for v in r.values())):
        # Distinct names per role are PIN's rule (bake.validate_pin: distinct uids).
        raise Usage(f"roles must be exactly {list(ROLES)}, each a name in accounts")
    t = plan["trees"]
    if not isinstance(t, list) or len(set(t)) != len(t) or not all(_norm_abs(p) for p in t):
        raise Usage("trees must be a list of distinct normalised absolute paths")
    b = plan["builds"]
    if not isinstance(b, dict) or not b:
        raise Usage("builds must be a non-empty object")
    for name, rec in b.items():
        if not (isinstance(rec, dict) and set(rec) == {"commit", "tree", "image"}
                and isinstance(rec["commit"], str) and _HEX40_RE.match(rec["commit"])
                and isinstance(rec["tree"], str) and _HEX40_RE.match(rec["tree"])
                and isinstance(rec["image"], str) and rec["image"] in plan["images"]):
            raise Usage(f"builds.{name}: exactly {{commit, tree, image}}, the image one of `images`")


def build(plan, runner=run):
    validate_plan(plan)
    return {
        "schema": SCHEMA,
        "pin_sha256": plan["pin_sha256"],
        "hdot": hdot(plan["seed"]),
        "files": {p: record_path(p) for p in plan["files"]},
        "checkouts": {p: checkout(p, runner) for p in plan["checkouts"]},
        "images": {r: image_id(r, runner) for r in plan["images"]},
        "packages": packages(runner),
        "accounts": {a: account(a) for a in plan["accounts"]},
        "roles": dict(plan["roles"]),
        "builds": {n: dict(rec, id=image_id(rec["image"], runner)) for n, rec in plan["builds"].items()},
        "trees": {p: tree(p) for p in plan["trees"]},
    }


def canonical(man):
    return (json.dumps(man, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def write_new(path, data):
    """PATH created O_EXCL with DATA in full, 0444, fsynced."""
    head, name = os.path.split(path)
    dfd = open_dir(head)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
        try:
            view = memoryview(data)
            while view:
                n = os.write(fd, view)
                if n <= 0:
                    raise OSError(errno.EIO, "no progress writing MAN")
                view = view[n:]
            os.fchmod(fd, 0o444)
            os.fsync(fd)
        except BaseException:
            os.close(fd)
            fd = None
            os.unlink(name, dir_fd=dfd)
            raise
        finally:
            if fd is not None:
                os.close(fd)
        os.fsync(dfd)
    finally:
        os.close(dfd)


# ------------------------------------------------------------------ the CLI

USAGE = "usage: man.py write --plan PLAN --out MAN"


def main(argv, runner=run):
    try:
        if argv[:1] != ["write"] or len(argv) != 5 or argv[1] != "--plan" or argv[3] != "--out":
            raise Usage(USAGE)
        plan_path, out = argv[2], argv[4]
        if not _norm_abs(plan_path) or not _norm_abs(out):
            raise Usage("--plan and --out must be normalised absolute paths")
        head, name = os.path.split(plan_path)
        dfd = open_dir(head)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
        finally:
            os.close(dfd)
        try:
            raw = os.read(fd, 1 << 20)
        finally:
            os.close(fd)
        try:
            plan = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise Usage("the plan is not JSON") from None
        data = canonical(build(plan, runner))
        write_new(out, data)
    except Usage as exc:
        print(exc, file=sys.stderr)
        return 2
    except (Fail, subprocess.TimeoutExpired, FileExistsError, FileNotFoundError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    print(f"M1-MAN PASS sha256={hashlib.sha256(data).hexdigest()}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception as exc:  # the guard: a crash never prints a PASS line
        print(f"internal-error {type(exc).__name__}", file=sys.stderr)
        sys.exit(3)
