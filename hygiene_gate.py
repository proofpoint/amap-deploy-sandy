"""The public/private hygiene gate: finds private names and private fixture
content in what a public repository holds, or is about to publish.

The CODE is public and holds no private data. Every list is private and is
read from a directory named on the command line (`--lists`), never from
this repository:

  names.txt          what must never appear (below)
  allow.txt          located exceptions, each with a reason (below)
  fingerprints.json  hashes of the private fixture set's files and lines,
                     built by the `fingerprint` subcommand

A scan reads git objects and text files and prints each finding as a
location and the LINE NUMBER of the list entry that matched, never the
entry's text unless `--show` is given. Exit 0 is clean, 1 is a finding, 2 is
"cannot run" (a missing, empty or malformed list, a shallow clone, a git
failure). 2 is never 0: an unreadable list is not a clean bill.

names.txt, one entry per line, `#` comments:

  token <word>     matched after normalisation (lower case; `-`, `_`, `.`,
                   space and tab removed, in the text and in the word) as a
                   substring. At least MIN_TOKEN normalised characters, and
                   never a generic label (GENERIC_LABELS).
  word <word>      as token, but the match must be bounded by characters
                   that are not letters or digits in the raw text.
  regex <pattern>  case-insensitive, line by line; at most MAX_REGEX
                   characters, no quantified group that itself contains a
                   quantifier; lines longer than MAX_LINE are scanned in
                   overlapping pieces.
  email <regex>    matched against identity fields (author, committer and
                   tagger emails) and against email-shaped text.
  allow <regex>    applied FIRST: every span it matches is masked before any
                   other entry runs. It must be followed by at least one
                   `+ <text>` line (a string it must mask whole) and one
                   `- <text>` line (a near string it must not touch); the
                   examples are checked on load, and each run reports how
                   many spans each allow entry masked.

allow.txt, one exception per line, each ending in a reason:

  path <repo> <path> <line-sha256> <reason>
      that line, at that path, in that repository, wherever it is read;
  commit <repo> <full sha> <reason>
      everything that commit adds (message, identities, added lines, path
      names), in that repository only, never the same text elsewhere;
  tree <repo> <full commit sha> <path> <line-sha256> <reason>
      that line, at that path, only while scanning exactly that commit's
      tree.
  identity <repo> <boundary commit sha> <address-sha256> <reason>
      an author or committer address whose lower-cased sha256 is the given
      one, accepted only in a commit that IS the boundary or is reachable
      from it (an ancestor). Any other commit carrying it, whatever its
      dates say, is checked: reachability is fixed by history, a date is
      whatever the writer's clock said. A boundary the repository does not
      hold is "cannot run".
  tag <repo> <tag object sha> <reason>
      the tagger and message of exactly that annotated tag OBJECT, under
      whichever ref resolves to it, and wherever it sits in a chain of tags:
      the object's sha covers its tagger, message and target, so every ref
      naming it carries the same content, and a tag re-created or moved under
      the same name is a different object and is checked. Each ref's name is
      always checked, and a lightweight tag has no tag object, so it is never
      accepted.

A line's sha256 is over its bytes without the trailing "\\n". Every run
lists the commit and tree exceptions that matched nothing.

What a scan reads:
  --tree REV       every file at REV: its path, its text, the sha256 of its
                   bytes and of each of its lines (the fingerprints);
  --range A..B, --all-history
                   each commit's message, author and committer, every line
                   it adds and every path it adds, deletes or renames (both
                   names). A merge's added lines are git's combined diff
                   (`--cc`): only the lines the merge itself introduced, a
                   line it brings in from a parent being the work of the
                   commit that added it, which is scanned in its own right;
  --refs           every ref name, and each annotated tag's message and
                   tagger;
  --text FILE      a PR title and body, a comment, a release note.

The `fingerprint` subcommand builds fingerprints.json from the private
fixture source, bound by a private source record; see `build_fingerprints`.
The `install-hook` subcommand installs a pre-push hook that blocks on exit 1
and on exit 2. Standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

HERE = Path(__file__).resolve().parent

#: The fewest normalised characters a token or word may have: a shorter one
#: matches too much ordinary text to mean anything.
MIN_TOKEN = 6
#: Words that are on every host and in every repository; an entry naming one
#: is refused, because it would make every scan red.
GENERIC_LABELS = frozenset({
    "internal", "hosts", "local", "localhost", "example", "default", "private", "public", "server",
    "client", "router", "sandbox", "github", "origin", "master", "readme", "config", "secret",
    "secrets", "docker", "systemd", "launchd", "domain", "address",
})
MAX_REGEX = 200
MAX_LINE = 4096
#: Where a long line is cut for regex scanning, each piece overlaps the next
#: by this much, so a match no longer than MAX_REGEX's worth is not split.
LINE_OVERLAP = 512
#: The most nested tags scan_refs follows below a ref's own tag; a deeper
#: chain is "cannot run", never a partial scan.
MAX_TAG_CHAIN = 8
#: git's own test for binary content: a NUL in the first 8000 bytes.
BINARY_SNIFF = 8000

#: Fingerprint eligibility: a normalised line of at least ELIGIBLE_LEN
#: characters holding a run of at least RUN_LEN characters from RUN_CHARS
#: with at least RUN_CLASSES character classes, or at least RUN_ENTROPY bits
#: of Shannon entropy per character. Keys, signatures, base64 and digests
#: qualify; prose does not.
ELIGIBLE_LEN = 32
RUN_LEN = 20
RUN_CLASSES = 4
RUN_ENTROPY = 3.5
_RUN = re.compile(r"[A-Za-z0-9+/=_-]{%d,}" % RUN_LEN)
#: RFC 8032 §7.1's published Ed25519 test vectors (TEST 1-3: secret key,
#: public key, signature). A line holding one is public by definition and
#: is never a fingerprint. Each was checked: the public key derived from the
#: secret, and the signature verified over its test message.
RFC8032_VECTORS = (
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd"
    "25bf5f0595bbe24655141438e7a100b",
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8"
    "c387b2eaeb4302aeeb00d291612bb0c00",
    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc65"
    "94a7c15e9716ed28dc027beceea1ec40a",
)
LIST_FILES = ("names.txt", "allow.txt", "fingerprints.json")
FINGERPRINT_SCHEMA = 1
SOURCE_KEYS = ("bundle", "commit", "tag", "profile", "fixture_root", "fixture_count")

_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
#: A quantified group that itself contains a quantifier: the shape of
#: catastrophic backtracking.
_NESTED = re.compile(r"\((?:[^()\\]|\\.)*[*+}?](?:[^()\\]|\\.)*\)\s*(?:[*+?]|\{\d)")
_SEPARATORS = str.maketrans("", "", "-_. \t")


class CannotRun(Exception):
    """Exit 2: the gate cannot give an answer."""


# --- Lists ----------------------------------------------------------------------


@dataclass
class Entry:
    line: int
    kind: str
    value: str
    norm: str = ""
    rx: Optional["re.Pattern[str]"] = None
    plus: List[str] = field(default_factory=list)
    minus: List[str] = field(default_factory=list)


@dataclass
class Exception_:
    line: int
    kind: str
    repo: str
    commit: str = ""
    path: str = ""
    digest: str = ""
    #: A `tag` exception's annotated tag object sha.
    obj: str = ""
    used: int = 0


@dataclass
class Lists:
    names: List[Entry]
    exceptions: List[Exception_]
    files: Set[str]
    lines: Set[str]
    digest: str
    masked: Dict[int, int] = field(default_factory=dict)

    def of(self, kind: str) -> List[Entry]:
        return [e for e in self.names if e.kind == kind]


def normalise(text: str) -> str:
    return text.lower().translate(_SEPARATORS)


def _safe_regex(pattern: str, where: str) -> "re.Pattern[str]":
    if len(pattern) > MAX_REGEX:
        raise CannotRun(f"{where}: the pattern is longer than {MAX_REGEX} characters")
    if _NESTED.search(pattern):
        raise CannotRun(f"{where}: a quantified group contains a quantifier (unbounded backtracking)")
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        raise CannotRun(f"{where}: the pattern does not compile ({e})")


def parse_names(text: str) -> List[Entry]:
    """names.txt, checked whole: any bad entry refuses the list."""
    out: List[Entry] = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        where = f"names.txt line {n}"
        if line[:2] in ("+ ", "- ") or line in ("+", "-"):
            if not out or out[-1].kind != "allow":
                raise CannotRun(f"{where}: an example line follows no allow entry")
            (out[-1].plus if line[0] == "+" else out[-1].minus).append(raw.strip()[2:])
            continue
        kind, _, value = line.partition(" ")
        value = value.strip()
        if not value:
            raise CannotRun(f"{where}: an entry needs a value")
        e = Entry(n, kind, value)
        if kind in ("token", "word"):
            e.norm = normalise(value)
            if len(e.norm) < MIN_TOKEN:
                raise CannotRun(f"{where}: a {kind} shorter than {MIN_TOKEN} normalised characters")
            if e.norm in GENERIC_LABELS:
                raise CannotRun(f"{where}: a generic label matches every host")
        elif kind in ("regex", "email", "allow"):
            e.rx = _safe_regex(value, where)
        else:
            raise CannotRun(f"{where}: unknown entry type {kind!r}")
        out.append(e)
    if not any(e.kind != "allow" for e in out):
        raise CannotRun("names.txt has no entry to match")
    for e in out:
        if e.kind == "allow":
            if not e.plus or not e.minus:
                raise CannotRun(f"names.txt line {e.line}: an allow entry needs a + and a - example")
            for ex in e.plus:
                if not e.rx.fullmatch(ex):
                    raise CannotRun(f"names.txt line {e.line}: an allow entry does not mask its + example")
            for ex in e.minus:
                if e.rx.search(ex):
                    raise CannotRun(f"names.txt line {e.line}: an allow entry touches its - example")
    return out


def parse_allow(text: str) -> List[Exception_]:
    out: List[Exception_] = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        f = line.split()
        where = f"allow.txt line {n}"
        if f[0] == "path" and len(f) >= 5 and _HEX64.fullmatch(f[3]):
            out.append(Exception_(n, "path", f[1], path=f[2], digest=f[3]))
        elif f[0] == "commit" and len(f) >= 4 and _HEX40.fullmatch(f[2]):
            out.append(Exception_(n, "commit", f[1], commit=f[2]))
        elif f[0] == "tree" and len(f) >= 6 and _HEX40.fullmatch(f[2]) and _HEX64.fullmatch(f[4]):
            out.append(Exception_(n, "tree", f[1], commit=f[2], path=f[3], digest=f[4]))
        elif f[0] == "identity" and len(f) >= 5 and _HEX40.fullmatch(f[2]) and _HEX64.fullmatch(f[3]):
            out.append(Exception_(n, "identity", f[1], commit=f[2], digest=f[3]))
        elif f[0] == "tag" and len(f) >= 4 and _HEX40.fullmatch(f[2]):
            out.append(Exception_(n, "tag", f[1], obj=f[2]))
        else:
            raise CannotRun(f"{where}: not a path, commit, tree, identity or tag exception with its reason")
    return out


def parse_fingerprints(text: str) -> Tuple[Set[str], Set[str]]:
    try:
        doc = json.loads(text)
    except ValueError:
        raise CannotRun("fingerprints.json is not JSON")
    if not isinstance(doc, dict) or doc.get("schema") != FINGERPRINT_SCHEMA:
        raise CannotRun("fingerprints.json is not a fingerprint document this gate reads")
    files, lines = doc.get("files"), doc.get("lines")
    if not isinstance(files, list) or not isinstance(lines, list) or not files \
            or not all(isinstance(h, str) and _HEX64.fullmatch(h) for h in files + lines):
        raise CannotRun("fingerprints.json needs non-empty lists of sha256 values")
    return set(files), set(lines)


def load_lists(directory: str, fingerprints: bool = True) -> Lists:
    """Every list, or CannotRun. The digest is over the files' bytes. With
    `fingerprints` False (the explicit `--no-fingerprints`), fingerprints.json
    is neither read nor required, the digest says so, and no fixture is
    matched: a missing fingerprint file is never a silent skip."""
    h = hashlib.sha256()
    texts = {}
    if not fingerprints:
        h.update(b"no-fingerprints\0")
    for name in LIST_FILES if fingerprints else LIST_FILES[:2]:
        p = os.path.join(directory, name)
        try:
            with open(p, "rb") as f:
                data = f.read()
        except OSError as e:
            raise CannotRun(f"cannot read {name} from the lists directory: {e.strerror}")
        h.update(name.encode() + b"\0" + hashlib.sha256(data).digest())
        try:
            texts[name] = data.decode("utf-8")
        except UnicodeDecodeError:
            raise CannotRun(f"{name} is not UTF-8")
    files, lines = parse_fingerprints(texts["fingerprints.json"]) if fingerprints else (set(), set())
    return Lists(parse_names(texts["names.txt"]), parse_allow(texts["allow.txt"]), files, lines,
                 h.hexdigest())


# --- Matching -------------------------------------------------------------------


@dataclass(frozen=True)
class Where:
    """Where text was read. `surface` is tree, commit, ref, tag or text."""
    surface: str
    repo: str
    commit: str = ""
    path: str = ""
    lineno: int = 0
    field: str = ""
    #: An annotated tag's object sha, for `tag` exceptions; not printed.
    obj: str = ""

    def __str__(self) -> str:
        bits = [self.surface]
        if self.commit:
            bits.append(self.commit[:12])
        if self.path:
            bits.append(f"{self.path}:{self.lineno}" if self.lineno else self.path)
        if self.field:
            bits.append(self.field)
        return " ".join(bits)


@dataclass(frozen=True)
class Finding:
    where: Where
    what: str          # "name" or "fixture file" or "fixture line"
    entry: int = 0     # the names.txt line, for a name

    @property
    def immutable(self) -> bool:
        """Content a commit sha fixes: its tree and its commits."""
        return self.where.surface in ("tree", "commit")


def line_digest(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8", "surrogateescape")).hexdigest()


def fingerprint_digest(line: str) -> str:
    """A line's fingerprint: whitespace collapsed and trimmed, then sha256."""
    return line_digest(" ".join(line.split()))


class Matcher:
    def __init__(self, lists: Lists, repo: str):
        self.lists = lists
        self.repo = repo
        self.findings: List[Finding] = []
        #: The git directory history is read from, for `identity` exceptions'
        #: reachability; set by scan_history.
        self.git_dir: Optional[str] = None
        self._reach: Dict[Tuple[str, str], bool] = {}

    def _reachable(self, commit: str, boundary: str) -> bool:
        """`commit` is `boundary` or one of its ancestors."""
        key = (commit, boundary)
        if key not in self._reach:
            if not self.git_dir:
                raise CannotRun("an identity exception needs the history's git directory")
            try:
                git(self.git_dir, "cat-file", "-e", boundary + "^{commit}")
            except CannotRun:
                raise CannotRun(f"identity exception: boundary {boundary[:12]} is not in {self.repo}")
            p = subprocess.run(["git", "-C", self.git_dir, *GIT_OPTS, "merge-base", "--is-ancestor", commit,
                                boundary], capture_output=True, env=git_env())
            if p.returncode not in (0, 1):
                raise CannotRun(f"identity exception: reachability of {commit[:12]} could not be read")
            self._reach[key] = p.returncode == 0
        return self._reach[key]

    def _identity_excepted(self, where: Where, email: str) -> bool:
        if where.surface != "commit" or not where.commit:
            return False
        d = hashlib.sha256(email.strip().lower().encode("utf-8", "surrogateescape")).hexdigest()
        for ex in self.lists.exceptions:
            if ex.kind == "identity" and ex.repo == self.repo and ex.digest == d \
                    and self._reachable(where.commit, ex.commit):
                ex.used += 1
                return True
        return False

    # Exceptions.
    def _excepted(self, where: Where, line: Optional[str]) -> bool:
        d = line_digest(line) if line is not None else None
        for ex in self.lists.exceptions:
            if ex.repo != self.repo:
                continue
            hit = False
            if ex.kind == "commit":
                hit = where.surface == "commit" and where.commit == ex.commit
            elif ex.kind == "tree":
                hit = (where.surface == "tree" and where.commit == ex.commit and where.path == ex.path
                       and d == ex.digest)
            elif ex.kind == "path":
                hit = where.surface in ("tree", "commit") and where.path == ex.path and d == ex.digest
            elif ex.kind == "tag":
                hit = where.obj == ex.obj          # only an annotated tag's surfaces carry obj
            if hit:
                ex.used += 1
                return True
        return False

    def _mask(self, text: str) -> str:
        for e in self.lists.of("allow"):
            spans = [m.span() for m in e.rx.finditer(text) if m.end() > m.start()]
            if spans:
                self.lists.masked[e.line] = self.lists.masked.get(e.line, 0) + len(spans)
                chars = list(text)
                for a, b in spans:
                    chars[a:b] = "\0" * (b - a)
                text = "".join(chars)
        return text

    def _names_in(self, text: str) -> Iterator[int]:
        """The names.txt lines of every entry matching `text` (masked).
        `index` maps each normalised character back to its source character;
        a character whose lower case is longer (U+0130 is two) maps every
        one of its pieces to itself."""
        norm, index = [], []
        for i, ch in enumerate(text):
            for c in ch.lower():
                if c in "-_. \t":
                    continue
                norm.append(c)
                index.append(i)
        flat = "".join(norm)
        for e in self.lists.of("token"):
            if e.norm in flat:
                yield e.line
        for e in self.lists.of("word"):
            start = flat.find(e.norm)
            while start >= 0:
                a, b = index[start], index[start + len(e.norm) - 1]
                if (a == 0 or not text[a - 1].isalnum()) and (b + 1 >= len(text) or not text[b + 1].isalnum()):
                    yield e.line
                    break
                start = flat.find(e.norm, start + 1)
        for piece in _pieces(text):
            for e in self.lists.of("regex"):
                if e.rx.search(piece):
                    yield e.line
            for email in _EMAIL.findall(piece):
                for e in self.lists.of("email"):
                    if e.rx.fullmatch(email):
                        yield e.line

    def text(self, where: Where, text: str, line: Optional[str] = None) -> None:
        """One piece of text (a line, a name, a message line)."""
        hits = sorted(set(self._names_in(self._mask(text))))
        if hits and not self._excepted(where, text if line is None else line):
            for n in hits:
                self.findings.append(Finding(where, "name", n))

    def identity(self, where: Where, name: str, email: str) -> None:
        """An identity: the name as text; the email as text, which runs the
        email entries on it once allow entries have masked it."""
        self.text(where, name)
        if not self._identity_excepted(where, email):
            self.text(where, email)

    def lines(self, where: Where, data: bytes, fingerprints: bool = True) -> None:
        """A file's text, line by line, for names and fixture lines."""
        text = data.decode("utf-8", "surrogateescape")
        for n, line in enumerate(text.split("\n"), 1):
            w = Where(where.surface, where.repo, where.commit, where.path, n, where.field)
            self.text(w, line)
            if fingerprints:
                self.fixture_line(w, line)

    def fixture_line(self, where: Where, line: str) -> None:
        if fingerprint_digest(line) in self.lists.lines and not self._excepted(where, line):
            self.findings.append(Finding(where, "fixture line"))

    def fixture_file(self, where: Where, data: bytes) -> None:
        if hashlib.sha256(data).hexdigest() in self.lists.files and not self._excepted(where, None):
            self.findings.append(Finding(where, "fixture file"))

    def unused(self) -> List[Exception_]:
        return [ex for ex in self.lists.exceptions if ex.kind in ("commit", "tree", "identity", "tag") and not ex.used]


def _pieces(text: str) -> Iterator[str]:
    for line in text.split("\n"):
        if len(line) <= MAX_LINE:
            yield line
            continue
        step = MAX_LINE - LINE_OVERLAP
        for i in range(0, len(line), step):
            yield line[i:i + MAX_LINE]


def is_binary(data: bytes) -> bool:
    return b"\0" in data[:BINARY_SNIFF]


# --- Git ------------------------------------------------------------------------


def git_env() -> Dict[str, str]:
    """git with no system or user configuration and no pager or prompt,
    reading only the PHYSICAL object graph: replace refs and grafts, which
    let a repository's own refs or local files rewrite what a commit's
    parents, identities or content appear to be, are ignored by every git
    call the gate makes, so what is scanned and what reachability is
    decided over are the same objects."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0",
               GIT_PAGER="cat", PAGER="cat", LC_ALL="C",
               GIT_NO_REPLACE_OBJECTS="1", GIT_GRAFT_FILE=os.devnull)
    return env


GIT_OPTS = ("-c", "core.hooksPath=" + os.devnull, "-c", "core.fsmonitor=false", "-c", "core.quotePath=false",
            "-c", "diff.external=", "-c", "log.showSignature=false")


def git(repo: str, *args: str, ok: Sequence[int] = (0,)) -> bytes:
    try:
        p = subprocess.run(["git", "-C", repo, *GIT_OPTS, *args], capture_output=True, env=git_env())
    except OSError as e:
        raise CannotRun(f"git cannot run: {e.strerror}")
    if p.returncode not in ok:
        raise CannotRun(f"git {args[0]} exited {p.returncode}: "
                        f"{p.stderr.decode('utf-8', 'replace').strip()[:200]}")
    return p.stdout


class Blobs:
    """`git cat-file --batch`, one process, each blob read once per run."""

    def __init__(self, repo: str):
        try:
            self.p = subprocess.Popen(["git", "-C", repo, *GIT_OPTS, "cat-file", "--batch"], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=git_env())
        except OSError as e:
            raise CannotRun(f"git cannot run: {e.strerror}")
        self.seen: Dict[str, bytes] = {}

    def read(self, oid: str) -> bytes:
        self.p.stdin.write(oid.encode() + b"\n")
        self.p.stdin.flush()
        head = self.p.stdout.readline().split()
        if len(head) != 3:
            raise CannotRun(f"git cat-file could not read {oid}")
        data = self.p.stdout.read(int(head[2]))
        self.p.stdout.read(1)
        return data

    def close(self) -> None:
        self.p.stdin.close()
        self.p.stdout.close()
        self.p.wait()


def check_full_history(repo: str) -> None:
    if git(repo, "rev-parse", "--is-shallow-repository").strip() != b"false":
        raise CannotRun("the clone is shallow: a partial history is never a clean one")


def _unquote(path: str) -> str:
    if len(path) >= 2 and path[0] == '"' and path[-1] == '"':
        return path[1:-1].encode("latin-1", "backslashreplace").decode("unicode_escape") \
            .encode("latin-1").decode("utf-8", "surrogateescape")
    return path


def scan_tree(m: Matcher, repo: str, rev: str, blobs: Blobs) -> None:
    commit = git(repo, "rev-parse", "--verify", rev + "^{commit}").decode().strip()
    out = git(repo, "ls-tree", "-r", "-z", "--full-tree", commit)
    for rec in out.split(b"\0"):
        if not rec:
            continue
        meta, _, path_b = rec.partition(b"\t")
        mode, kind, oid = meta.decode().split()
        if kind != "blob":
            continue
        path = path_b.decode("utf-8", "surrogateescape")
        w = Where("tree", m.repo, commit, path)
        m.text(Where("tree", m.repo, commit, path, field="path name"), path, line=None)
        data = blobs.read(oid)
        m.fixture_file(w, data)
        if not is_binary(data):
            m.lines(w, data)


def _commits(repo: str, revs: Sequence[str]) -> List[Tuple[str, List[str]]]:
    out = git(repo, "rev-list", "--parents", "--reverse", *revs, "--")
    rows = []
    for line in out.decode().splitlines():
        f = line.split()
        rows.append((f[0], f[1:]))
    return rows


def scan_history(m: Matcher, repo: str, revs: Sequence[str], blobs: Blobs,
                 skip: Optional[Set[str]] = None) -> List[str]:
    """Every commit in `revs`: message, identities, added lines and paths,
    and each new blob's fingerprint. Returns the commits scanned."""
    skip = skip or set()
    m.git_dir = repo
    todo = [(c, ps) for c, ps in _commits(repo, revs) if c not in skip]
    if not todo:
        return []
    ids = [c for c, _ in todo]
    parents = dict(todo)
    # Messages and identities.
    meta = git(repo, "show", "-s", "--format=%H%x00%an%x00%ae%x00%cn%x00%ce%x00%B%x1e", "--no-walk=unsorted", *ids)
    for rec in meta.decode("utf-8", "surrogateescape").split("\x1e"):
        rec = rec.lstrip("\n")
        if not rec:
            continue
        c, an, ae, cn, ce, body = rec.split("\x00", 5)
        m.identity(Where("commit", m.repo, c, field="author"), an, ae)
        m.identity(Where("commit", m.repo, c, field="committer"), cn, ce)
        for n, line in enumerate(body.split("\n"), 1):
            m.text(Where("commit", m.repo, c, field=f"message:{n}"), line)
    # Paths and new blobs.
    for c in ids:
        out = git(repo, "diff-tree", "-r", "-z", "--root", "--no-abbrev", "-M", "-c", "--no-commit-id", c)
        _paths(m, c, out, blobs)
    # Added lines.
    for c in ids:
        n = max(1, len(parents[c]))
        out = git(repo, "show", "--format=", "-p", *(("--cc",) if n > 1 else ()), "-M", "--no-color",
                  "--no-ext-diff", "--no-textconv", "--src-prefix=a/", "--dst-prefix=b/", c)
        _added(m, c, out, n)
    return ids


def _paths(m: Matcher, commit: str, out: bytes, blobs: Blobs) -> None:
    """`diff-tree -z -c` records: `:modes oids status\\0path\\0[path\\0]`, or
    `::…` for a merge."""
    fields = out.split(b"\0")
    i = 0
    while i < len(fields):
        head = fields[i].decode()
        if not head.startswith(":"):
            i += 1
            continue
        colons = len(head) - len(head.lstrip(":"))
        parts = head[colons:].split()
        status = parts[-1]
        oids = parts[colons + 1:-1]
        new_oid = oids[-1] if oids else ""
        renamed = colons == 1 and status[:1] in ("R", "C")
        names = [fields[i + 1].decode("utf-8", "surrogateescape")]
        if renamed:
            names.append(fields[i + 2].decode("utf-8", "surrogateescape"))
        i += 1 + len(names)
        for name in names:
            m.text(Where("commit", m.repo, commit, name, field="path name"), name, line=None)
        if new_oid and set(new_oid) != {"0"} and "D" not in status:
            data = blobs.read(new_oid)
            m.fixture_file(Where("commit", m.repo, commit, names[-1]), data)


def _added(m: Matcher, commit: str, out: bytes, parents: int) -> None:
    path = ""
    in_hunk = False
    lineno = 0
    for raw in out.split(b"\n"):
        line = raw.decode("utf-8", "surrogateescape")
        if line.startswith("diff --git ") or line.startswith("diff --cc ") or line.startswith("diff --combined "):
            in_hunk, path = False, ""
            if line.startswith("diff --cc ") or line.startswith("diff --combined "):
                path = _unquote(line.split(" ", 2)[2])
            continue
        if not in_hunk and line.startswith("+++ "):
            target = line[4:]
            if target != "/dev/null":
                target = _unquote(target)
                path = target[2:] if target.startswith("b/") else target
            continue
        if line.startswith("@@"):
            in_hunk = True
            m_ = re.search(r"\+(\d+)", line.split("@@")[1] if line.count("@@") >= 2 else line)
            lineno = int(m_.group(1)) if m_ else 0
            continue
        if not in_hunk or len(line) < parents or line.startswith("\\"):
            continue
        prefix, body = line[:parents], line[parents:]
        if prefix == "+" * parents:
            w = Where("commit", m.repo, commit, path, lineno)
            m.text(w, body)
            m.fixture_line(w, body)
        if "-" not in prefix:
            lineno += 1


def scan_refs(m: Matcher, repo: str, blobs: Blobs) -> None:
    """Every ref's name, and every annotated tag object reachable from a ref,
    following a tag whose target is itself a tag (a chain) down to the first
    non-tag object. Each tag object's tagger and message are scanned once,
    under the first ref that reaches it, however many refs or chains do; a
    nested one is labelled `<ref> (nested <depth>)`. Every chain is walked
    to its end whatever was scanned before, so a chain nested deeper than
    MAX_TAG_CHAIN is "cannot run" whichever refs also name its inner tags,
    never a silent stop."""
    out = git(repo, "for-each-ref", "--format=%(refname)%00%(objecttype)%00%(objectname)%1e")
    seen: Set[str] = set()
    for rec in out.decode("utf-8", "surrogateescape").split("\x1e"):
        rec = rec.strip("\n")
        if not rec:
            continue
        name, kind, oid = rec.split("\x00")
        m.text(Where("ref", m.repo, path=name, field="ref name"), name)
        depth = 0
        while kind == "tag":
            if depth > MAX_TAG_CHAIN:
                raise CannotRun(f"{name}: a chain of more than {MAX_TAG_CHAIN} nested tags")
            body = blobs.read(oid).decode("utf-8", "surrogateescape")
            head, _, message = body.partition("\n\n")
            target, kind, taggers = "", "", []
            for hl in head.split("\n"):
                if hl.startswith("object "):
                    target = hl[len("object "):].strip()
                elif hl.startswith("type "):
                    kind = hl[len("type "):].strip()
                elif hl.startswith("tagger "):
                    taggers.append(hl[len("tagger "):])
            if oid not in seen:
                seen.add(oid)
                label = name if not depth else f"{name} (nested {depth})"
                for who in taggers:
                    nm, _, rest = who.partition(" <")
                    m.identity(Where("tag", m.repo, path=label, field="tagger", obj=oid), nm,
                               rest.partition(">")[0])
                for n, line in enumerate(message.split("\n"), 1):
                    m.text(Where("tag", m.repo, path=label, field=f"message:{n}", obj=oid), line)
            oid, depth = target, depth + 1


def scan_text(m: Matcher, label: str, data: bytes) -> None:
    w = Where("text", m.repo, path=label)
    m.lines(w, data)


# --- Fingerprints ---------------------------------------------------------------


def _classes(run: str) -> int:
    return sum(any(f(c) for c in run) for f in (str.isupper, str.islower, str.isdigit,
                                                 lambda c: c in "+/=_-"))


def _entropy(run: str) -> float:
    counts: Dict[str, int] = {}
    for c in run:
        counts[c] = counts.get(c, 0) + 1
    n = len(run)
    return -sum(k / n * math.log2(k / n) for k in counts.values())


def eligible(line: str) -> bool:
    norm = " ".join(line.split())
    if len(norm) < ELIGIBLE_LEN or any(v in norm.lower() for v in RFC8032_VECTORS):
        return False
    return any(_classes(r) >= RUN_CLASSES or _entropy(r) >= RUN_ENTROPY for r in _RUN.findall(norm))


def load_source(path: str) -> Tuple[dict, str]:
    """The private source record, checked whole, and its sha256."""
    try:
        with open(path, "rb") as f:
            data = f.read()
        rec = json.loads(data)
    except (OSError, ValueError) as e:
        raise CannotRun(f"the source record cannot be read: {e}")
    ok = (isinstance(rec, dict) and set(rec) == set(SOURCE_KEYS)
          and isinstance(rec["bundle"], dict) and set(rec["bundle"]) == {"filename", "sha256"}
          and isinstance(rec["bundle"]["filename"], str) and _HEX64.fullmatch(str(rec["bundle"]["sha256"]))
          and _HEX40.fullmatch(str(rec["commit"])) and isinstance(rec["tag"], str) and rec["tag"]
          and isinstance(rec["profile"], dict) and set(rec["profile"]) == {"path", "sha256"}
          and isinstance(rec["profile"]["path"], str) and _HEX64.fullmatch(str(rec["profile"]["sha256"]))
          and isinstance(rec["fixture_root"], dict) and set(rec["fixture_root"]) == {"path", "tree"}
          and isinstance(rec["fixture_root"]["path"], str) and _HEX40.fullmatch(str(rec["fixture_root"]["tree"]))
          and isinstance(rec["fixture_count"], int) and not isinstance(rec["fixture_count"], bool)
          and rec["fixture_count"] > 0)
    if not ok:
        raise CannotRun("the source record does not have exactly the fields " + ", ".join(SOURCE_KEYS)
                        + ", each full-length")
    return rec, hashlib.sha256(data).hexdigest()


def _file_sha(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def gate_commit() -> str:
    try:
        out = git(str(HERE), "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    except CannotRun:
        out = ""
    if not _HEX40.fullmatch(out):
        raise CannotRun("the gate is not run from a git checkout, so its commit cannot be recorded")
    return out


def _public_lines(repo: str) -> Dict[str, List[str]]:
    """{fingerprint digest: [path, …]} over every text file at a public
    clone's HEAD."""
    out: Dict[str, List[str]] = {}
    blobs = Blobs(repo)
    try:
        listing = git(repo, "ls-tree", "-r", "-z", "--full-tree", "HEAD")
        for rec in listing.split(b"\0"):
            if not rec:
                continue
            meta, _, path_b = rec.partition(b"\t")
            _mode, kind, oid = meta.decode().split()
            if kind != "blob":
                continue
            data = blobs.read(oid)
            if is_binary(data):
                continue
            for line in data.decode("utf-8", "surrogateescape").split("\n"):
                out.setdefault(fingerprint_digest(line), []).append(path_b.decode("utf-8", "surrogateescape"))
    finally:
        blobs.close()
    return out


def build_fingerprints(source: str, bundle: str, public: Sequence[str], allow_path: Optional[str],
                       scratch: Optional[str] = None) -> Tuple[dict, List[str]]:
    """The fingerprint document, or CannotRun, and the build's findings.

    The record binds every input: the bundle's sha256, the tag's commit, the
    profile's path and sha256, the fixture root's path and git tree id, and
    the number of blobs under it. The bundle is expanded into a temporary
    directory that is removed on success and on failure, and no source byte
    is written anywhere else or printed. Every blob under the root is a
    fixture: there is no subset. An eligible fixture line already present
    in a public clone is a finding, not a dropped line; only the private
    fingerprint-allow file (`<line digest> <reason>`) excludes one."""
    rec, rec_sha = load_source(source)
    if not public:
        raise CannotRun("name at least one public clone to check the fixture lines against")
    if _file_sha(bundle) != rec["bundle"]["sha256"]:
        raise CannotRun("the bundle's sha256 is not the record's")
    excluded: Set[str] = set()
    if allow_path:
        try:
            with open(allow_path, encoding="utf-8") as f:
                for n, raw in enumerate(f, 1):
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    digest, _, reason = line.partition(" ")
                    if not _HEX64.fullmatch(digest) or not reason.strip():
                        raise CannotRun(f"the fingerprint-allow file, line {n}: a digest and a reason")
                    excluded.add(digest)
        except OSError as e:
            raise CannotRun(f"the fingerprint-allow file cannot be read: {e.strerror}")
    gate = gate_commit()
    work = tempfile.mkdtemp(prefix="hygiene-fp-", dir=scratch)
    try:
        repo = os.path.join(work, "src")
        git(work, "init", "-q", repo)
        git(repo, "bundle", "verify", bundle)
        ref = f"refs/tags/{rec['tag']}"
        git(repo, "fetch", "-q", "--no-tags", bundle, f"{ref}:{ref}")
        commit = git(repo, "rev-parse", "--verify", ref + "^{commit}").decode().strip()
        if commit != rec["commit"]:
            raise CannotRun("the bundle's tag does not resolve to the record's commit")
        profile = git(repo, "rev-parse", "--verify", f"{commit}:{rec['profile']['path']}",
                      ok=(0, 128)).decode().strip()
        if not _HEX40.fullmatch(profile):
            raise CannotRun("the record's profile path is not in the commit")
        blobs = Blobs(repo)
        try:
            if hashlib.sha256(blobs.read(profile)).hexdigest() != rec["profile"]["sha256"]:
                raise CannotRun("the profile's sha256 is not the record's")
            root = rec["fixture_root"]["path"].strip("/")
            tree = git(repo, "rev-parse", "--verify", f"{commit}:{root}", ok=(0, 128)).decode().strip()
            if tree != rec["fixture_root"]["tree"]:
                raise CannotRun("the fixture root's tree id is not the record's")
            listing = git(repo, "ls-tree", "-r", "-z", tree)
            entries = []
            for r in listing.split(b"\0"):
                if r:
                    meta, _, p = r.partition(b"\t")
                    _mode, kind, oid = meta.decode().split()
                    if kind == "blob":
                        entries.append((p.decode("utf-8", "surrogateescape"), oid))
            if len(entries) != rec["fixture_count"]:
                raise CannotRun("the number of fixtures under the root is not the record's")
            files, lines, none = set(), set(), []
            for path, oid in entries:
                data = blobs.read(oid)
                files.add(hashlib.sha256(data).hexdigest())
                got = 0
                if not is_binary(data):
                    for line in data.decode("utf-8", "surrogateescape").split("\n"):
                        if eligible(line):
                            d = fingerprint_digest(line)
                            if d not in excluded:
                                lines.add(d)
                                got += 1
                if not got:
                    none.append(path)
        finally:
            blobs.close()
    finally:
        shutil.rmtree(work, ignore_errors=True)
    findings = []
    for clone in public:
        seen = _public_lines(clone)
        for d in sorted(lines & set(seen)):
            for p in sorted(set(seen[d])):
                findings.append(f"{os.path.basename(os.path.normpath(clone))}: {p}: an eligible fixture line "
                                "is already public")
    doc = {"schema": FINGERPRINT_SCHEMA, "gate_commit": gate, "source_sha256": rec_sha,
           "files": sorted(files), "lines": sorted(lines), "no_eligible_line": sorted(none)}
    return doc, findings


# --- The hook -------------------------------------------------------------------

HOOK = """#!/bin/sh
# Installed by amap-hygiene.py install-hook: blocks a push on a finding (exit
# 1) and when the gate cannot run (exit 2), so a missing list never passes.
z=0000000000000000000000000000000000000000
while read -r local_ref local_sha remote_ref remote_sha; do
    [ "$local_sha" = "$z" ] && continue
    if [ "$remote_sha" = "$z" ]; then range=$local_sha; else range=$remote_sha..$local_sha; fi
    {python} {gate} --lists {lists} --repo {repo} --git . --tree "$local_sha" --range "$range" --refs || {{
        echo "hygiene: push blocked (exit $?)" >&2
        exit 1
    }}
done
exit 0
"""


def install_hook(repo: str, lists: str, name: str) -> str:
    # Asked without GIT_OPTS, whose hooksPath turns hooks off for the scan's own git.
    try:
        p = subprocess.run(["git", "-C", repo, "rev-parse", "--git-path", "hooks"], capture_output=True, env=git_env())
    except OSError as e:
        raise CannotRun(f"git cannot run: {e.strerror}")
    if p.returncode:
        raise CannotRun(f"{repo} is not a git repository")
    hooks = p.stdout.decode().strip()
    hooks = hooks if os.path.isabs(hooks) else os.path.join(repo, hooks)
    os.makedirs(hooks, exist_ok=True)
    dest = os.path.join(hooks, "pre-push")
    if os.path.lexists(dest):
        raise CannotRun(f"{dest} exists; move it aside first (a hook is never overwritten)")
    import shlex
    body = HOOK.format(python=shlex.quote(sys.executable), gate=shlex.quote(str(HERE / "amap-hygiene.py")),
                       lists=shlex.quote(os.path.abspath(lists)), repo=shlex.quote(name))
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o755)
    with os.fdopen(fd, "w") as f:
        f.write(body)
    return dest


# --- The command line -----------------------------------------------------------


def report(m: Matcher, out=print, show: bool = False) -> None:
    by_line = {e.line: e for e in m.lists.names}
    for f in m.findings:
        if f.what == "name":
            label = f"names.txt line {f.entry}"
            if show:
                label += f" ({by_line[f.entry].kind} {by_line[f.entry].value})"
            out(f"FINDING: {f.where}: private name, {label}")
        else:
            out(f"FINDING: {f.where}: s5-r4 {f.what}")
    for line, n in sorted(m.lists.masked.items()):
        out(f"allow: names.txt line {line} masked {n} span(s)")
    for kind in ("path", "commit", "tree"):
        n = sum(ex.used for ex in m.lists.exceptions if ex.kind == kind)
        if n:
            out(f"exceptions: {kind} applied {n} time(s)")
    for ex in m.unused():
        out(f"exceptions: allow.txt line {ex.line} ({ex.kind}) matched nothing")
    if not m.lists.files and not m.lists.lines:
        out("fingerprints: not used (--no-fingerprints): no fixture content was matched")
    out(f"lists: sha256 {m.lists.digest}")


def scan(args: argparse.Namespace, out=print) -> int:
    lists = load_lists(args.lists, not args.no_fingerprints)
    m = Matcher(lists, args.repo)
    needs_git = args.tree or args.range or args.all_history or args.refs
    if needs_git:
        check_full_history(args.git)
        blobs = Blobs(args.git)
        try:
            for rev in args.tree:
                scan_tree(m, args.git, rev, blobs)
            revs = list(args.range)
            if args.all_history:
                revs.append("--all")
            if revs:
                scan_history(m, args.git, revs, blobs)
            if args.refs:
                scan_refs(m, args.git, blobs)
        finally:
            blobs.close()
    for path in args.text:
        try:
            with open(path, "rb") as f:
                scan_text(m, path, f.read())
        except OSError as e:
            raise CannotRun(f"cannot read {path}: {e.strerror}")
    report(m, out, args.show)
    return 1 if m.findings else 0


def main(argv: Optional[Sequence[str]] = None, out=print) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    p = argparse.ArgumentParser(prog="amap-hygiene.py", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="command")
    for name in ("scan",):
        s = sub.add_parser(name, help="scan git objects and text (the default)")
        s.add_argument("--lists", required=True)
        s.add_argument("--repo", required=True, help="the repository's name, as allow.txt names it")
        s.add_argument("--git", default=".")
        s.add_argument("--tree", action="append", default=[])
        s.add_argument("--range", action="append", default=[])
        s.add_argument("--all-history", action="store_true")
        s.add_argument("--refs", action="store_true")
        s.add_argument("--text", action="append", default=[])
        s.add_argument("--show", action="store_true", help="print each matched entry's text (local use only)")
        s.add_argument("--no-fingerprints", action="store_true",
                       help="match names only; fingerprints.json is not read")
    c = sub.add_parser("check-lists", help="load and check the lists, and print their digest")
    c.add_argument("--lists", required=True)
    c.add_argument("--no-fingerprints", action="store_true")
    f = sub.add_parser("fingerprint", help="build fingerprints.json from the private fixture source")
    f.add_argument("--source", required=True)
    f.add_argument("--bundle", required=True)
    f.add_argument("--public", action="append", default=[], help="a public clone to check fixture lines against")
    f.add_argument("--allow", help="the private fingerprint-allow file")
    f.add_argument("--out", required=True)
    ci = sub.add_parser("ci", help="the scheduled run over every public fleet repository (hygiene_api)")
    ci.add_argument("--lists", required=True)
    ci.add_argument("--owner", required=True)
    ci.add_argument("--repos", required=True, help="repos.txt: <name> public|private")
    ci.add_argument("--fleet-rule", required=True, help="fleet-rule.txt: prefix <p> / topic <t>")
    ci.add_argument("--workdir", required=True, help="where the public mirrors are kept")
    ci.add_argument("--api", default="https://api.github.com")
    ci.add_argument("--git-base", default="https://github.com")
    ci.add_argument("--token-env", help="the environment variable holding the public-read token")
    ci.add_argument("--private-token-env", help="the environment variable holding the metadata-only token")
    ci.add_argument("--verdicts", help="where to write the {repo, sha, state} hand-over")
    ci.add_argument("--cache", help="the incremental cache, keyed by the lists' digest and the gate's commit")
    ci.add_argument("--no-fingerprints", action="store_true", help="match names only")
    h = sub.add_parser("install-hook", help="install a pre-push hook that blocks on exit 1 and 2")
    h.add_argument("--lists", required=True)
    h.add_argument("--repo", required=True)
    h.add_argument("--git", default=".")
    if argv and argv[0].startswith("-") and argv[0] not in ("-h", "--help"):
        argv = ["scan"] + argv
    args = p.parse_args(argv)
    try:
        if args.command == "scan":
            return scan(args, out)
        if args.command == "check-lists":
            lists = load_lists(args.lists, not args.no_fingerprints)
            out(f"lists: OK, sha256 {lists.digest}")
            return 0
        if args.command == "fingerprint":
            doc, findings = build_fingerprints(args.source, args.bundle, args.public, args.allow)
            for line in findings:
                out(f"FINDING: {line}")
            if findings:
                out("fingerprint: nothing written; remove the leak or exclude the line by review")
                return 1
            tmp = args.out + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(doc, fh, indent=1, sort_keys=True)
                fh.write("\n")
            os.replace(tmp, args.out)
            out(f"fingerprint: wrote {args.out}: {len(doc['files'])} files, {len(doc['lines'])} lines, "
                f"{len(doc['no_eligible_line'])} with no eligible line")
            return 0
        if args.command == "ci":
            import hygiene_api
            return hygiene_api.run_ci(
                args.lists, args.owner, args.repos, args.fleet_rule, args.workdir, api=args.api,
                git_base=args.git_base, token=os.environ.get(args.token_env) if args.token_env else None,
                private_token=os.environ.get(args.private_token_env) if args.private_token_env else None,
                verdicts_out=args.verdicts, cache_path=args.cache, out=out,
                fingerprints=not args.no_fingerprints)
        if args.command == "install-hook":
            out(f"install-hook: wrote {install_hook(args.git, args.lists, args.repo)}")
            return 0
        p.print_help()
        return 2
    except CannotRun as e:
        out(f"CANNOT RUN: {e}")
        return 2
    except Exception as e:      # never a traceback's exit 1, which would read as a finding
        out(f"CANNOT RUN: internal error {type(e).__name__}")
        return 2
