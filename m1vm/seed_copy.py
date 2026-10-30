"""m1-seed-copy: copy sandy's build-hash dotfiles (HDOT) from the baked seed
into a VM's SANDY_HOME, exactly as MAN lists them (LC d8 §2.3). Standard
library only; installed by BAKE as /opt/amap/bin/m1-seed-copy.

  python3 -I -S -B m1-seed-copy --man MAN --src SEED --dst SANDY_HOME

A new SANDY_HOME forces sandy to rebuild everything unless these files carry
over (REPORTED sandy a010af93). sandy regenerates its other build files
byte-identically at the same commit, so this closed list is all that moves.

It runs as the agents' account (`<op>`), never as root, so the copies are
that account's; the caller binds the process to `<op>`. It copies exactly
MAN's `hdot` entries, keeping names and modes. Every path is opened from `/`
one component at a time with O_NOFOLLOW, so a link anywhere on the way to
MAN, SEED, SANDY_HOME or an entry is refused, never followed. It refuses,
before anything is written:
  - an entry missing from SEED, or a hash dotfile in SEED or SANDY_HOME that
    MAN does not list (a `sandboxes/` entry that is a link, not a directory, or
    an off-pattern slug holding a project hash counts as extra);
  - anything that is not a regular file with one link;
  - a source whose sha256 or mode differs from MAN's;
  - a destination file that differs from the source, or is not owned by the
    running account (an identical one is `present`), and a destination
    directory not owned by it;
  - a DST that is missing or not a plain directory (it is never created).

Writes are atomic per file (temp, fsync, rename, directory fsync), not for
the whole set. An internal error after N files leaves those N in place and
prints no SEED or PASS line; a rerun reports them `present` and finishes.

Output: one `SEED <name> mode=<octal> sha256=<hex> copied|present` line per
entry, then `M1-SEED-COPY PASS n=<count> man=<sha256 of MAN>` last.

Exit status: 0 PASS; 1 REFUSED (one `REFUSE <reason>` line on stderr, and
nothing written); 2 a usage error; 3 an internal error.
"""

import errno
import fnmatch
import hashlib
import json
import os
import re
import stat
import sys

MAN_SCHEMA = "m1vm-man/1"
MAX_MAN_BYTES = 4 << 20
MAX_HDOT_BYTES = 1 << 20

# The closed hash-dotfile set (LC d8 §2.3; REPORTED sandy a010af93). Top-level
# names in SANDY_HOME, plus one per sandbox.
TOP_PATTERNS = (".base_build_hash", ".build_hash*", ".skills_*_build_hash", ".skill_version_*")
SANDBOX_NAME = ".project_build_hash"
_SLUG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_TOP_RE = re.compile(r"[!-~]+\Z")  # printable, no whitespace
_SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
_MODE_RE = re.compile(r"0[0-7]{3}\Z")

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _euid():
    return os.geteuid()


class Refused(Exception):
    """A contract violation: exit 1, nothing written."""


class Usage(Exception):
    """A usage error: exit 2."""


def is_hdot_name(name):
    """True for a name in HDOT's closed set, relative to SANDY_HOME."""
    parts = name.split("/")
    if len(parts) == 1:
        return bool(_TOP_RE.match(name)) and any(fnmatch.fnmatchcase(name, p) for p in TOP_PATTERNS)
    return (len(parts) == 3 and parts[0] == "sandboxes" and bool(_SLUG_RE.match(parts[1]))
            and parts[2] == SANDBOX_NAME)


# ------------------------------------------------------------------ files

def _open_dir(base_fd, parts, what):
    """A descriptor for directory PARTS under BASE_FD, every component a real
    directory; None if one is absent. A link or non-directory is Refused."""
    fd = base_fd
    for part in parts:
        try:
            nfd = os.open(part, _DIR_FLAGS, dir_fd=fd)
        except FileNotFoundError:
            nfd = None
        except OSError as exc:
            if fd != base_fd:
                os.close(fd)
            if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                raise Refused(f"{what}: {part} is not a plain directory") from None
            raise
        if fd != base_fd:
            os.close(fd)
        if nfd is None:
            return None
        fd = nfd
    return fd


def open_abs_dir(path, what):
    """A descriptor for absolute directory PATH, walked from / with O_NOFOLLOW
    at every component; Refused if any is absent, a link or not a directory."""
    if not path.startswith("/") or os.path.normpath(path) != path or path.startswith("//"):
        raise Usage(f"{what} must be a normalised absolute path")
    root = os.open("/", _DIR_FLAGS)
    try:
        fd = _open_dir(root, [p for p in path.split("/") if p], f"{what} {path}")
    finally:
        pass
    if fd is None:
        os.close(root)
        raise Refused(f"{what} {path}: absent")
    if fd != root:
        os.close(root)
    return fd


def _read_regular(dir_fd, name, limit):
    """(bytes, mode, uid) of regular file NAME in DIR_FD; None if absent."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise Refused(f"{name}: a symbolic link") from None
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Refused(f"{name}: not a regular file")
        if st.st_nlink != 1:
            raise Refused(f"{name}: {st.st_nlink} links, not one")
        if st.st_size > limit:
            raise Refused(f"{name}: larger than {limit} bytes")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise Refused(f"{name}: larger than {limit} bytes")
            chunks.append(chunk)
        return b"".join(chunks), stat.S_IMODE(st.st_mode), st.st_uid
    finally:
        os.close(fd)


# ------------------------------------------------------------------ MAN

def _no_duplicates(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise Refused(f"MAN: duplicate key {key!r}")
        seen[key] = value
    return seen


def load_hdot(man_path):
    """(entries, man_sha): MAN's validated `hdot` list and MAN's sha256."""
    if not man_path.startswith("/") or os.path.normpath(man_path) != man_path or man_path.startswith("//"):
        raise Usage("--man must be a normalised absolute path")
    head, name = os.path.split(man_path)
    dfd = open_abs_dir(head, "MAN's directory")
    try:
        got = _read_regular(dfd, name, MAX_MAN_BYTES)
    finally:
        os.close(dfd)
    if got is None:
        raise Refused(f"MAN {man_path}: absent")
    raw = got[0]
    try:
        man = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, ValueError):
        raise Refused("MAN: not JSON") from None
    if not isinstance(man, dict) or man.get("schema") != MAN_SCHEMA:
        raise Refused(f"MAN: schema is not {MAN_SCHEMA!r}")
    hdot = man.get("hdot")
    if not isinstance(hdot, list) or not hdot:
        raise Refused("MAN: hdot must be a non-empty list")
    seen = set()
    for entry in hdot:
        if (not isinstance(entry, dict) or set(entry) != {"name", "mode", "sha256"}
                or not all(isinstance(entry[k], str) for k in entry)):
            raise Refused("MAN: every hdot entry must be exactly {name, mode, sha256}")
        if not is_hdot_name(entry["name"]) or entry["name"] in seen:
            raise Refused(f"MAN: hdot name {entry['name']!r} is not a distinct HDOT name")
        if not _MODE_RE.match(entry["mode"]) or not _SHA_RE.match(entry["sha256"]):
            raise Refused(f"MAN: {entry['name']}: mode must be 0NNN and sha256 64 lowercase hex")
        seen.add(entry["name"])
    return hdot, hashlib.sha256(raw).hexdigest()


# ------------------------------------------------------------------ the copy

def hash_names(root_fd, what):
    """Every hash dotfile under ROOT_FD, relative to it. A `sandboxes/` entry
    that is a link or not a directory is Refused; an off-pattern slug holding
    a project hash is returned as is, so the caller reports it as extra."""
    names = {n for n in os.listdir(root_fd)
             if "/" not in n and any(fnmatch.fnmatchcase(n, p) for p in TOP_PATTERNS)}
    sfd = _open_dir(root_fd, ["sandboxes"], what)
    if sfd is None:
        return names
    try:
        for slug in os.listdir(sfd):
            st = os.stat(slug, dir_fd=sfd, follow_symlinks=False)
            if not stat.S_ISDIR(st.st_mode):
                raise Refused(f"{what}: sandboxes/{slug!r} is not a plain directory")
            try:
                os.stat(f"{slug}/{SANDBOX_NAME}", dir_fd=sfd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            names.add(f"sandboxes/{slug}/{SANDBOX_NAME}")
    finally:
        os.close(sfd)
    return names


def _check_owner(st, label):
    if st.st_uid != _euid():
        raise Refused(f"{label}: owned by uid {st.st_uid}, not the running account")


def plan(hdot, src_fd, dst_fd):
    """[(entry, data, state)] with state 'copy' or 'present'; Refused on any
    violation, before anything is written."""
    listed = {e["name"] for e in hdot}
    for fd, what in ((src_fd, "the seed"), (dst_fd, "the destination")):
        extra = sorted(hash_names(fd, what) - listed)
        if extra:
            raise Refused(f"{what} holds hash dotfiles MAN does not list: {', '.join(map(repr, extra))}")
    _check_owner(os.fstat(dst_fd), "the destination")
    out = []
    for entry in hdot:
        parts = entry["name"].split("/")
        sdir = _open_dir(src_fd, parts[:-1], "the seed")
        if sdir is None:
            raise Refused(f"{entry['name']}: absent from the seed")
        try:
            got = _read_regular(sdir, parts[-1], MAX_HDOT_BYTES)
        finally:
            if sdir != src_fd:
                os.close(sdir)
        if got is None:
            raise Refused(f"{entry['name']}: absent from the seed")
        data, mode, _ = got
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise Refused(f"{entry['name']}: the seed's sha256 differs from MAN's")
        if mode != int(entry["mode"], 8):
            raise Refused(f"{entry['name']}: the seed's mode {mode:04o} differs from MAN's {entry['mode']}")
        state = "copy"
        ddir = _open_dir(dst_fd, parts[:-1], "the destination")
        if ddir is not None:
            try:
                if ddir != dst_fd:
                    _check_owner(os.fstat(ddir), f"{'/'.join(parts[:-1])}/ in the destination")
                have = _read_regular(ddir, parts[-1], MAX_HDOT_BYTES)
            finally:
                if ddir != dst_fd:
                    os.close(ddir)
            if have is not None:
                if have[0] != data or have[1] != mode:
                    raise Refused(f"{entry['name']}: the destination already holds a different file")
                if have[2] != _euid():
                    raise Refused(f"{entry['name']}: the destination's copy is owned by uid {have[2]}, "
                                  "not the running account")
                state = "present"
        out.append((entry, data, state))
    return out


def _ensure_dirs(src_fd, dst_fd, parts):
    """DST's directories for PARTS, created with the seed's modes where absent."""
    fd, sfd = dst_fd, src_fd
    for part in parts:
        smode = stat.S_IMODE(os.stat(part, dir_fd=sfd, follow_symlinks=False).st_mode)
        try:
            os.mkdir(part, smode, dir_fd=fd)
            os.chmod(part, smode, dir_fd=fd, follow_symlinks=False)
        except FileExistsError:
            pass
        nfd = _open_dir(fd, [part], "the destination")
        nsfd = _open_dir(sfd, [part], "the seed")
        if fd != dst_fd:
            os.close(fd)
        if sfd != src_fd:
            os.close(sfd)
        fd, sfd = nfd, nsfd
    if sfd != src_fd:
        os.close(sfd)
    return fd


def write(src_fd, dst_fd, entry, data):
    parts = entry["name"].split("/")
    dfd = _ensure_dirs(src_fd, dst_fd, parts[:-1])
    tmp = f".{parts[-1]}.m1-seed-copy.tmp"
    try:
        try:
            os.unlink(tmp, dir_fd=dfd)
        except FileNotFoundError:
            pass
        mode = int(entry["mode"], 8)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(tmp, parts[-1], src_dir_fd=dfd, dst_dir_fd=dfd)
        os.fsync(dfd)
    finally:
        if dfd != dst_fd:
            os.close(dfd)


# ------------------------------------------------------------------ the CLI

USAGE = "usage: m1-seed-copy --man MAN --src SEED --dst SANDY_HOME"


def parse(argv):
    got = {}
    rest = list(argv)
    while rest:
        flag = rest.pop(0)
        key = {"--man": "man", "--src": "src", "--dst": "dst"}.get(flag)
        if key is None or key in got or not rest:
            raise Usage(USAGE)
        got[key] = rest.pop(0)
    if set(got) != {"man", "src", "dst"}:
        raise Usage(USAGE)
    return got


def main(argv):
    try:
        args = parse(argv)
    except Usage as exc:
        print(exc, file=sys.stderr)
        return 2
    if _euid() == 0:
        print("REFUSE runs as the agents' account, never as root", file=sys.stderr)
        return 1
    src_fd = dst_fd = None
    try:
        for flag in ("man", "src", "dst"):
            value = args[flag]
            if not value.startswith("/") or os.path.normpath(value) != value or value.startswith("//"):
                raise Usage(f"--{flag} must be a normalised absolute path")
        hdot, man_sha = load_hdot(args["man"])
        src_fd = open_abs_dir(args["src"], "--src")
        dst_fd = open_abs_dir(args["dst"], "--dst")
        steps = plan(hdot, src_fd, dst_fd)
        lines = []
        for entry, data, state in steps:
            if state == "copy":
                write(src_fd, dst_fd, entry, data)
            lines.append(f"SEED {entry['name']} mode={entry['mode']} sha256={entry['sha256']} "
                         f"{'copied' if state == 'copy' else 'present'}")
    except Usage as exc:
        print(exc, file=sys.stderr)
        return 2
    except Refused as exc:
        print(f"REFUSE {exc}", file=sys.stderr)
        return 1
    finally:
        for fd in (src_fd, dst_fd):
            if fd is not None:
                os.close(fd)
    for line in lines:
        print(line)
    print(f"M1-SEED-COPY PASS n={len(lines)} man={man_sha}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception as exc:  # the guard: a crash never prints a PASS line
        print(f"internal-error {type(exc).__name__}", file=sys.stderr)
        sys.exit(3)
