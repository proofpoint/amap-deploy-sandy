"""SEALSPEC: DS2's file-level seal items and literal scan patterns for the
M1 template (LC d8 B4b; DS2 d8 §3), and the reference evaluator that checks
the items against an offline, mounted copy of R. Standard library only.

  python3 -I -S -B sealspec.py check SPEC
        the spec's own shape; prints its sha256
  python3 -I -S -B sealspec.py eval --spec SPEC --root DIR --param op_user=NAME --param data_mount=PATH
        every item, against the tree mounted at DIR

NET's seal (`seal 208`, G-B4b step 3) runs the items with the spec's sha bound
in its profile; the patterns and the allow-list feed its absence scan (NET
r20 §2.5). Every path is resolved one component at a time under DIR with
O_NOFOLLOW, so a symbolic link anywhere on the way is a FAIL, never followed.

Exit status: 0 every item passed; 1 an item failed; 2 a usage error or a spec
that is not valid; 3 an internal error. The last stdout line is
`M1-SEALSPEC PASS ...` only when every item passed.
"""

import errno
import fnmatch
import hashlib
import json
import os
import re
import stat
import sys

SCHEMA = "m1vm-sealspec/1"
PARAMS = ("op_user", "data_mount")
PLACEHOLDERS = ("{op_home}", "{data_mount}")
ID_RE = re.compile(r"SS-[0-9]{2}\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")

# Which expectations each selector may carry. A glob names a set, so it can
# only be "none" or a per-match check; a path names one object.
PATH_EXPECT = ("absent", "dir", "empty-mountpoint", "absent-or-gitconfig-clean",
               "absent-or-no-proxy", "gitconfig-clean")
GLOB_EXPECT = ("none", "gitconfig-clean")
HOME_EXPECT = ("absent", "absent-or-gitconfig-clean")

# A config file larger than this is refused rather than read.
MAX_CONFIG_BYTES = 1 << 20

# A git config section that may carry a remote, a credential helper or a URL
# rewrite. Section names are case-insensitive in git.
_SECTION_RE = re.compile(r'^\s*\[\s*([A-Za-z0-9.-]+)(?:\s+"[^"]*")?\s*\]')
_USERINFO_RE = re.compile(r"://[^/@\s]+@")
_PROXY_RE = re.compile(r"^\s*(?:export\s+)?[A-Za-z_]*proxy\s*=", re.IGNORECASE)


class SpecError(Exception):
    """The spec itself is not valid."""


class ParamError(Exception):
    """A parameter is missing, or names nothing in the tree."""


# ------------------------------------------------------------------ the spec

def _norm_abs(path):
    return path.startswith("/") and os.path.normpath(path) == path and "//" not in path


def validate(spec):
    """Raise SpecError unless SPEC has exactly the documented shape."""
    if not isinstance(spec, dict) or set(spec) != {"schema", "params", "items", "patterns", "allowlist"}:
        raise SpecError("the top level must be exactly {schema, params, items, patterns, allowlist}")
    if spec["schema"] != SCHEMA:
        raise SpecError(f"schema must be {SCHEMA!r}")
    if spec["params"] != list(PARAMS):
        raise SpecError(f"params must be exactly {list(PARAMS)!r}")
    items = spec["items"]
    if not isinstance(items, list) or not items:
        raise SpecError("items must be a non-empty list")
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            raise SpecError("every item must be an object")
        iid = item.get("id")
        if not isinstance(iid, str) or not ID_RE.match(iid) or iid in seen:
            raise SpecError(f"item id {iid!r} is not a unique SS-NN")
        seen.add(iid)
        selectors = [k for k in ("path", "glob", "home") if k in item]
        if len(selectors) != 1:
            raise SpecError(f"{iid}: exactly one of path, glob, home")
        sel = selectors[0]
        allowed = {"id", sel, "expect", "why"} | ({"min"} if sel == "glob" else set())
        if set(item) - allowed or not {"expect", "why"} <= set(item):
            raise SpecError(f"{iid}: keys must be {sorted(allowed)}")
        if not isinstance(item["why"], str) or not item["why"].strip():
            raise SpecError(f"{iid}: why must be a sentence")
        expect = item["expect"]
        table = {"path": PATH_EXPECT, "glob": GLOB_EXPECT, "home": HOME_EXPECT}[sel]
        if expect not in table:
            raise SpecError(f"{iid}: expect {expect!r} is not one of {table}")
        value = item[sel]
        if not isinstance(value, str) or not value:
            raise SpecError(f"{iid}: {sel} must be a non-empty string")
        if sel == "home":
            if value.startswith("/") or os.path.normpath(value) != value or value.startswith(".."):
                raise SpecError(f"{iid}: home must be a relative path inside a home")
        else:
            bare = value
            for ph in PLACEHOLDERS:
                if bare.startswith(ph):
                    bare = "/" + bare[len(ph):].lstrip("/") if bare != ph else "/"
            if "{" in bare or "}" in bare or not _norm_abs(bare):
                raise SpecError(f"{iid}: {sel} must be absolute and normalised, a placeholder only at its start")
        if sel == "glob":
            if "**" in value:
                raise SpecError(f"{iid}: ** is not supported")
            if "min" in item and (not isinstance(item["min"], int) or isinstance(item["min"], bool)
                                  or item["min"] < 1 or expect == "none"):
                raise SpecError(f"{iid}: min must be a positive integer, and not with 'none'")
    patterns = spec["patterns"]
    if (not isinstance(patterns, list) or not patterns
            or not all(isinstance(p, str) and p for p in patterns) or len(set(patterns)) != len(patterns)):
        raise SpecError("patterns must be a non-empty list of distinct non-empty strings")
    allowlist = spec["allowlist"]
    if not isinstance(allowlist, list):
        raise SpecError("allowlist must be a list")
    paths = set()
    for entry in allowlist:
        if (not isinstance(entry, dict) or set(entry) != {"path", "sha256"}
                or not isinstance(entry["path"], str) or not _norm_abs(entry["path"])
                or not isinstance(entry["sha256"], str) or not SHA_RE.match(entry["sha256"])
                or entry["path"] in paths):
            raise SpecError(f"allowlist entry {entry!r} is not a distinct {{path, sha256}}")
        paths.add(entry["path"])


def load(path):
    """The spec at PATH, validated, and the sha256 of its bytes."""
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        spec = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise SpecError(f"not JSON: {exc}") from None
    validate(spec)
    return spec, hashlib.sha256(raw).hexdigest()


# ------------------------------------------------------------- the tree walk

class Tree:
    """A directory tree resolved strictly beneath one root descriptor."""

    def __init__(self, root):
        self.root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

    def close(self):
        os.close(self.root_fd)

    def _parts(self, path):
        return [p for p in path.split("/") if p]

    def lstat(self, path):
        """lstat of PATH under the root, or None if it (or a parent) is absent.
        A symbolic link at any component other than the last raises OSError
        ELOOP; the last component's own lstat is returned as is."""
        parts = self._parts(path)
        if not parts:
            return os.fstat(self.root_fd)
        fd = self._open_dir(parts[:-1])
        if fd is None:
            return None
        try:
            return os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        finally:
            if fd != self.root_fd:
                os.close(fd)

    def _open_dir(self, parts):
        """A descriptor for the directory PARTS, or None if a part is absent."""
        fd = self.root_fd
        for part in parts:
            try:
                nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            except FileNotFoundError:
                nfd = None
            except OSError as exc:
                if fd != self.root_fd:
                    os.close(fd)
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise OSError(errno.ELOOP, f"not a plain directory on the way: {part}") from None
                raise
            if fd != self.root_fd:
                os.close(fd)
            if nfd is None:
                return None
            fd = nfd
        return fd

    def listdir(self, path):
        """The names in directory PATH, or None if it is absent."""
        fd = self._open_dir(self._parts(path))
        if fd is None:
            return None
        try:
            return sorted(os.listdir(fd))
        finally:
            if fd != self.root_fd:
                os.close(fd)

    def read(self, path):
        """The bytes of regular file PATH, bounded; OSError if it is anything else."""
        parts = self._parts(path)
        fd = self._open_dir(parts[:-1])
        if fd is None:
            raise FileNotFoundError(path)
        try:
            ffd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=fd)
        finally:
            if fd != self.root_fd:
                os.close(fd)
        try:
            st = os.fstat(ffd)
            if not stat.S_ISREG(st.st_mode):
                raise OSError(errno.EINVAL, "not a regular file")
            if st.st_size > MAX_CONFIG_BYTES:
                raise OSError(errno.EFBIG, "larger than the config bound")
            chunks, total = [], 0
            while True:
                chunk = os.read(ffd, 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_CONFIG_BYTES:
                    raise OSError(errno.EFBIG, "larger than the config bound")
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(ffd)

    def glob(self, pattern):
        """Every existing path matching PATTERN, one component at a time.
        Wildcards never cross a '/' and never descend through a link."""
        results = ["/"]
        for part in self._parts(pattern):
            nxt = []
            for base in results:
                child = (base.rstrip("/") + "/")
                if any(c in part for c in "*?["):
                    names = self.listdir(base) or []
                    nxt.extend(child + n for n in names if fnmatch.fnmatchcase(n, part))
                else:
                    if self.lstat(child + part) is not None:
                        nxt.append(child + part)
            results = nxt
        return sorted(r for r in results if r != "/")


# ------------------------------------------------------------- the checks

def gitconfig_problem(data):
    """A sentence if git config DATA carries a remote, credential or rewrite."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return "not UTF-8"
    section = None
    for n, line in enumerate(text.splitlines(), 1):
        m = _SECTION_RE.match(line)
        if m:
            section = m.group(1).lower()
            head = section.split(".", 1)[0]
            if head in ("remote", "credential"):
                return f"line {n}: a [{head}] section"
            rest = line[m.end():]
        else:
            rest = line
        stripped = rest.strip()
        if section is not None and section.split(".", 1)[0] == "url":
            key = stripped.split("=", 1)[0].strip().lower()
            if key in ("insteadof", "pushinsteadof"):
                return f"line {n}: a url rewrite"
        if _USERINFO_RE.search(stripped):
            return f"line {n}: URL userinfo"
    return None


def proxy_problem(data):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return "not UTF-8"
    for n, line in enumerate(text.splitlines(), 1):
        if _PROXY_RE.match(line):
            return f"line {n}: a proxy setting"
    return None


def _check_one(tree, path, expect):
    """(ok, detail) for one concrete PATH."""
    try:
        st = tree.lstat(path)
    except OSError as exc:
        return False, f"{path}: {exc.strerror or exc}"
    if expect == "absent":
        return (st is None, f"{path}: absent" if st is None else f"{path}: present")
    if st is None:
        if expect.startswith("absent-or-"):
            return True, f"{path}: absent"
        return False, f"{path}: absent"
    if stat.S_ISLNK(st.st_mode):
        return False, f"{path}: a symbolic link"
    if expect == "dir":
        return (stat.S_ISDIR(st.st_mode), f"{path}: " + ("a directory" if stat.S_ISDIR(st.st_mode) else "not a directory"))
    if expect == "empty-mountpoint":
        if not stat.S_ISDIR(st.st_mode):
            return False, f"{path}: not a directory"
        names = tree.listdir(path)
        if names:
            return False, f"{path}: holds {len(names)} entr{'y' if len(names) == 1 else 'ies'}"
        if st.st_uid != 0 or st.st_gid != 0 or stat.S_IMODE(st.st_mode) != 0:
            return False, f"{path}: owner {st.st_uid}:{st.st_gid} mode {stat.S_IMODE(st.st_mode):04o}, not 0:0 0000"
        return True, f"{path}: empty, 0:0 0000"
    try:
        data = tree.read(path)
    except OSError as exc:
        return False, f"{path}: {exc.strerror or exc}"
    if expect in ("gitconfig-clean", "absent-or-gitconfig-clean"):
        problem = gitconfig_problem(data)
    elif expect == "absent-or-no-proxy":
        problem = proxy_problem(data)
    else:
        raise AssertionError(expect)
    return (problem is None, f"{path}: {problem or 'clean'}")


def homes(tree):
    """{user: home} from the tree's /etc/passwd, plus root's /root."""
    data = tree.read("/etc/passwd").decode("utf-8")
    out = {}
    for line in data.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) != 7:
            raise ParamError(f"/etc/passwd: a line without 7 fields: {line!r}")
        name, home = fields[0], fields[5]
        if not home.startswith("/") or os.path.normpath(home) != home:
            raise ParamError(f"/etc/passwd: {name}'s home {home!r} is not a normalised absolute path")
        out[name] = home
    out.setdefault("root", "/root")
    return out


def evaluate(tree, spec, params):
    """[(id, ok, detail)] for every item, in spec order."""
    if set(params) != set(PARAMS):
        raise ParamError(f"parameters must be exactly {list(PARAMS)}")
    data_mount = params["data_mount"]
    if not _norm_abs(data_mount) or data_mount == "/":
        raise ParamError("data_mount must be a normalised absolute path other than /")
    users = homes(tree)
    if params["op_user"] not in users:
        raise ParamError(f"op_user {params['op_user']!r} is not in the tree's /etc/passwd")
    subst = {"{op_home}": users[params["op_user"]], "{data_mount}": data_mount}
    all_homes = sorted(set(users.values()))

    def expand(value):
        for ph, real in subst.items():
            if value.startswith(ph):
                return os.path.normpath(real + value[len(ph):])
        return value

    results = []
    for item in spec["items"]:
        iid, expect = item["id"], item["expect"]
        details, ok = [], True
        if "path" in item:
            good, detail = _check_one(tree, expand(item["path"]), expect)
            ok, details = good, [detail]
        elif "home" in item:
            for home in all_homes:
                good, detail = _check_one(tree, os.path.normpath(home + "/" + item["home"]), expect)
                if not good:
                    ok = False
                    details.append(detail)
            if ok:
                details = [f"{len(all_homes)} homes clean"]
        else:
            try:
                matches = tree.glob(expand(item["glob"]))
            except OSError as exc:
                matches, ok = [], False
                details.append(f"{item['glob']}: {exc.strerror or exc}")
            if ok and expect == "none":
                ok = not matches
                details = ["no match"] if ok else [f"{m}: present" for m in matches]
            elif ok:
                if len(matches) < item.get("min", 0):
                    ok = False
                    details.append(f"{len(matches)} match(es), fewer than {item['min']}")
                for m in matches:
                    good, detail = _check_one(tree, m, expect)
                    if not good:
                        ok = False
                        details.append(detail)
                if ok:
                    details = [f"{len(matches)} clean"]
        results.append((iid, ok, "; ".join(details)))
    return results


# ------------------------------------------------------------------ the CLI

USAGE = __doc__.split("\n\n")[1]


def _parse_params(args):
    params = {}
    for arg in args:
        key, sep, value = arg.partition("=")
        if not sep or key not in PARAMS or key in params or not value:
            raise ParamError(f"--param {arg!r}: want one of {list(PARAMS)}=VALUE, each once")
        params[key] = value
    return params


def main(argv):
    if len(argv) == 2 and argv[0] == "check":
        try:
            _, sha = load(argv[1])
        except (OSError, SpecError) as exc:
            print(f"M1-SEALSPEC INVALID {exc}", file=sys.stderr)
            return 2
        print(f"M1-SEALSPEC VALID sha256={sha}")
        return 0
    if not argv or argv[0] != "eval":
        print(USAGE, file=sys.stderr)
        return 2
    spec_path = root = None
    raw_params = []
    rest = argv[1:]
    while rest:
        flag = rest.pop(0)
        if flag in ("--spec", "--root", "--param") and rest:
            value = rest.pop(0)
            if flag == "--spec" and spec_path is None:
                spec_path = value
                continue
            if flag == "--root" and root is None:
                root = value
                continue
            if flag == "--param":
                raw_params.append(value)
                continue
        print(USAGE, file=sys.stderr)
        return 2
    if spec_path is None or root is None:
        print(USAGE, file=sys.stderr)
        return 2
    try:
        params = _parse_params(raw_params)
        spec, sha = load(spec_path)
        tree = Tree(root)
    except (OSError, SpecError, ParamError) as exc:
        print(f"M1-SEALSPEC USAGE {exc}", file=sys.stderr)
        return 2
    try:
        results = evaluate(tree, spec, params)
    except ParamError as exc:
        print(f"M1-SEALSPEC USAGE {exc}", file=sys.stderr)
        return 2
    finally:
        tree.close()
    failed = 0
    for iid, ok, detail in results:
        print(f"SEAL {iid} {'PASS' if ok else 'FAIL'} {detail}")
        failed += not ok
    if failed:
        print(f"M1-SEALSPEC FAIL failed={failed} n={len(results)} spec={sha}")
        return 1
    print(f"M1-SEALSPEC PASS n={len(results)} spec={sha}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception as exc:  # the guard: a crash never prints a PASS line
        print(f"internal-error {type(exc).__name__}", file=sys.stderr)
        sys.exit(3)
