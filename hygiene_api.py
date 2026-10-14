"""The hygiene gate's scheduled run: every public fleet repository, its git
history and the text GitHub holds beside it, with every read bounded.

`amap-hygiene.py ci` (see `run_ci`) runs in the private repository's CI,
where the private lists are present. In order:

1. The fleet. `repos.txt` lists every fleet repository with its expected
   visibility (`<name> public|private`); `fleet-rule.txt` holds `prefix
   <name prefix>` and `topic <topic>` lines. A listed repository outside the
   rule, a listed repository whose live visibility differs or cannot be
   read, and a listed private repository the owner's public listing shows,
   are each "cannot run" (exit 2). An unlisted PUBLIC repository that
   matches the rule is a finding; every other public repository of the
   owner is skipped and counted.
2. Each verified public repository is mirrored WITHOUT a credential (every
   ref, `refs/pull/*` included) and scanned by hygiene_gate: every ref's
   name, every annotated tag, every commit reachable from any ref, and the
   tree of every branch, tag and pull-request head.
3. The text beside the git history, read through the API: pull requests,
   issues, their comments, review comments, commit comments, releases (and
   each asset's bytes, for the fixture file hashes), Actions logs and
   artifacts, and the wiki. Discussions are not read: a repository with
   them enabled is a named limit.
4. The verdicts: for the default branch's head and each open pull request's
   head, `{"repo", "sha", "state"}`, where `state` is `failure` when the
   tree at that sha or any commit reachable from it has a finding. Only
   those IMMUTABLE surfaces decide it; a ref name, a tag, a comment or a
   release can change without a new sha, so their findings turn this run
   red but never a verdict.

Every read is bounded (the constants below). A read that cannot be
finished within them is a LIMIT, printed as `LIMIT: <repo> <surface> <id>:
<reason>`; the run scans everything else, then exits 1 if there were
findings, else 2 if there was a LIMIT, never 0.

Credentials. Git clones carry none. API reads send the token named by
`--token-env` (the job's own token, a rate-limit identity for public data)
only to the API host, never across a redirect to another host, and never in
an argument, a log line or an output file. Listed PRIVATE repositories'
visibility is read with the token named by `--private-token-env`, a
metadata-only credential, and with nothing else. Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Set, Tuple

import hygiene_gate as hg

#: Bodies are read and scanned in pieces of this size.
CHUNK = 64 * 1024
#: The most read for one release asset, Actions log or artifact download.
MAX_OBJECT = 50 * 1024 * 1024
#: The most one archive member may decompress to, and one archive in all.
MAX_MEMBER = 50 * 1024 * 1024
MAX_ARCHIVE = 200 * 1024 * 1024
#: The most one run reads in all: bytes downloaded plus bytes decompressed.
MAX_RUN = 2 * 1024 * 1024 * 1024
#: A listing's page size and the most pages it may take.
PER_PAGE = 100
MAX_PAGES = 50
#: Seconds for a connect or a read, and for one object in all.
IO_TIMEOUT = 30
OBJECT_TIMEOUT = 300
MAX_REDIRECTS = 5
#: A line held across chunks longer than this is scanned in pieces.
MAX_CARRY = 1024 * 1024
ARCHIVE_SUFFIXES = (".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".jar", ".whl")
VERDICT_KEYS = ("repo", "sha", "state")
VERDICT_STATES = ("success", "failure")

_NEXT = re.compile(r'<([^>]+)>\s*;\s*rel="next"')
_NAME = re.compile(r"[A-Za-z0-9._-]+")


class Limit(Exception):
    """One read that could not be finished within its bounds."""


@dataclass
class Budget:
    """The run's bytes, and the API's own counts for the run summary."""
    used: int = 0
    requests: int = 0
    rate_remaining: Optional[str] = None

    def charge(self, n: int) -> None:
        self.used += n
        if self.used > MAX_RUN:
            raise Limit("run budget")


@dataclass
class Http:
    """GET with bounds. The token goes only to `api_host`."""
    api: str
    token: Optional[str]
    budget: Budget
    opener: urllib.request.OpenerDirector = field(default=None)

    def __post_init__(self):
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        self.opener = urllib.request.build_opener(NoRedirect)
        self.api_host = urllib.parse.urlsplit(self.api).netloc

    def open(self, url: str, token: Optional[str] = "default"):
        """The response after redirects, each followed by hand so that the
        Authorization header never leaves the host it was meant for."""
        token = self.token if token == "default" else token
        for _ in range(MAX_REDIRECTS + 1):
            req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                                       "User-Agent": "amap-hygiene"})
            if token and urllib.parse.urlsplit(url).netloc == self.api_host:
                req.add_header("Authorization", f"Bearer {token}")
            self.budget.requests += 1
            try:
                resp = self.opener.open(req, timeout=IO_TIMEOUT)
            except urllib.error.HTTPError as e:
                if e.code in (301, 302, 303, 307, 308) and e.headers.get("Location"):
                    url = urllib.parse.urljoin(url, e.headers["Location"])
                    e.close()
                    continue
                e.close()
                raise Limit(f"HTTP {e.code}")
            except (urllib.error.URLError, socket.timeout, OSError) as e:
                raise Limit("timeout" if "timed out" in str(e) else f"unreachable ({type(e).__name__})")
            if resp.headers.get("X-RateLimit-Remaining") is not None:
                self.budget.rate_remaining = resp.headers["X-RateLimit-Remaining"]
            return resp
        raise Limit("too many redirects")

    def stream(self, url: str, sink: Callable[[bytes], None], cap: Optional[int] = None) -> None:
        """The body, in CHUNKs, to `sink`; LIMIT when it is longer than
        `cap` (MAX_OBJECT), cut short, or slower than OBJECT_TIMEOUT."""
        cap = MAX_OBJECT if cap is None else cap
        start = time.monotonic()
        resp = self.open(url)
        with resp:
            declared = resp.headers.get("Content-Length")
            if declared is not None and declared.isdigit() and int(declared) > cap:
                raise Limit("oversize")
            got = 0
            while True:
                try:
                    chunk = resp.read(CHUNK)
                except (socket.timeout, OSError) as e:
                    raise Limit("timeout" if "timed out" in str(e) else "truncated")
                except Exception:   # http.client.IncompleteRead and its kin
                    raise Limit("truncated")
                if not chunk:
                    break
                got += len(chunk)
                if got > cap:
                    raise Limit("oversize")
                self.budget.charge(len(chunk))
                if time.monotonic() - start > OBJECT_TIMEOUT:
                    raise Limit("timeout")
                sink(chunk)
            if declared is not None and declared.isdigit() and got != int(declared):
                raise Limit("truncated")

    def json(self, url: str, token: Optional[str] = "default") -> Tuple[object, Optional[str]]:
        """One JSON document and the `next` link, read whole under MAX_OBJECT."""
        parts: List[bytes] = []
        resp_next: List[Optional[str]] = [None]
        start = time.monotonic()
        resp = self.open(url, token)
        with resp:
            m = _NEXT.search(resp.headers.get("Link") or "")
            resp_next[0] = m.group(1) if m else None
            declared = resp.headers.get("Content-Length")
            got = 0
            while True:
                try:
                    chunk = resp.read(CHUNK)
                except Exception as e:
                    raise Limit("timeout" if "timed out" in str(e) else "truncated")
                if not chunk:
                    break
                got += len(chunk)
                if got > MAX_OBJECT:
                    raise Limit("oversize")
                self.budget.charge(len(chunk))
                if time.monotonic() - start > OBJECT_TIMEOUT:
                    raise Limit("timeout")
                parts.append(chunk)
            if declared is not None and declared.isdigit() and got != int(declared):
                raise Limit("truncated")
        try:
            return json.loads(b"".join(parts)), resp_next[0]
        except ValueError:
            raise Limit("truncated")

    def listing(self, path: str, key: Optional[str] = None) -> Iterator[dict]:
        """Every item of a paginated listing; LIMIT "incomplete listing"
        when a `next` link outlives MAX_PAGES."""
        sep = "&" if "?" in path else "?"
        url: Optional[str] = f"{self.api}{path}{sep}per_page={PER_PAGE}"
        pages = 0
        while url:
            if pages == MAX_PAGES:
                raise Limit("incomplete listing")
            doc, url = self.json(url)
            pages += 1
            items = doc.get(key) if key and isinstance(doc, dict) else doc
            if not isinstance(items, list):
                raise Limit("truncated")
            for item in items:
                if isinstance(item, dict):
                    yield item


class Lines:
    """A streamed body's lines, fed to a Matcher, and its sha256."""

    def __init__(self, m: hg.Matcher, where: hg.Where, text: bool = True):
        self.m, self.where, self.text = m, where, text
        self.sha = hashlib.sha256()
        self.carry = b""
        self.n = 0
        self.head = b""

    def feed(self, chunk: bytes) -> None:
        self.sha.update(chunk)
        if len(self.head) < hg.BINARY_SNIFF:
            self.head += chunk[:hg.BINARY_SNIFF - len(self.head)]
            if b"\0" in self.head:
                self.text = False
        if not self.text:
            return
        data = self.carry + chunk
        *lines, self.carry = data.split(b"\n")
        for line in lines:
            self._line(line)
        if len(self.carry) > MAX_CARRY:
            self._line(self.carry)
            self.carry = b""

    def _line(self, raw: bytes) -> None:
        self.n += 1
        text = raw.decode("utf-8", "surrogateescape")
        w = hg.Where(self.where.surface, self.where.repo, self.where.commit, self.where.path, self.n)
        self.m.text(w, text)
        self.m.fixture_line(w, text)

    def finish(self) -> None:
        if self.text and self.carry:
            self._line(self.carry)
        self.carry = b""
        if self.sha.hexdigest() in self.m.lists.files:
            self.m.findings.append(hg.Finding(self.where, "fixture file"))


# --- The fleet ------------------------------------------------------------------


@dataclass
class Fleet:
    expected: Dict[str, str]
    prefixes: List[str]
    topics: List[str]

    def matches(self, name: str, topics: Sequence[str]) -> bool:
        return any(name.startswith(p) for p in self.prefixes) or bool(set(topics) & set(self.topics))


def load_fleet(repos_path: str, rule_path: str) -> Fleet:
    expected: Dict[str, str] = {}
    prefixes: List[str] = []
    topics: List[str] = []
    for path, what in ((repos_path, "repos"), (rule_path, "rule")):
        try:
            with open(path, encoding="utf-8") as f:
                text = f.read()
        except (OSError, UnicodeDecodeError) as e:
            raise hg.CannotRun(f"cannot read {os.path.basename(path)}: {e}")
        for n, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            a = line.split()
            where = f"{os.path.basename(path)} line {n}"
            if len(a) != 2 or not _NAME.fullmatch(a[1] if what == "rule" else a[0]):
                raise hg.CannotRun(f"{where}: not `<name> public|private`" if what == "repos"
                                   else f"{where}: not `prefix <name>` or `topic <topic>`")
            if what == "repos":
                if a[1] not in ("public", "private") or a[0] in expected:
                    raise hg.CannotRun(f"{where}: not `<name> public|private`, once per name")
                expected[a[0]] = a[1]
            elif a[0] == "prefix":
                prefixes.append(a[1])
            elif a[0] == "topic":
                topics.append(a[1])
            else:
                raise hg.CannotRun(f"{where}: not `prefix <name>` or `topic <topic>`")
    if not expected or not (prefixes or topics):
        raise hg.CannotRun("repos.txt and fleet-rule.txt each need at least one entry")
    return Fleet(expected, prefixes, topics)


@dataclass
class FleetView:
    public: List[str]
    findings: List[str]
    skipped: int


def resolve_fleet(http: Http, owner: str, fleet: Fleet, private_token: Optional[str]) -> FleetView:
    """The repositories to scan, verified public, or CannotRun on any drift."""
    listed_public: Dict[str, dict] = {}
    try:
        for r in http.listing(f"/orgs/{owner}/repos?type=public"):
            if r.get("visibility") == "public" and not r.get("private"):
                listed_public[str(r.get("name"))] = r
    except Limit as e:
        raise hg.CannotRun(f"the owner's public listing could not be read whole ({e})")
    findings, skipped = [], 0
    for name, r in sorted(listed_public.items()):
        if name in fleet.expected:
            continue
        topics = r.get("topics") if isinstance(r.get("topics"), list) else []
        if fleet.matches(name, topics):
            findings.append(f"FINDING: fleet: {name} is public, matches the fleet rule, and is not in repos.txt")
        else:
            skipped += 1
    scan = []
    for name, want in sorted(fleet.expected.items()):
        if want == "public":
            if name not in listed_public:
                raise hg.CannotRun(f"repos.txt lists {name} as public, and the owner's public listing "
                                   "does not show it")
            doc = listed_public[name]
            scan.append(name)
        else:
            if name in listed_public:
                raise hg.CannotRun(f"repos.txt lists {name} as private, and it is public")
            if not private_token:
                raise hg.CannotRun(f"{name}'s visibility cannot be read: no private metadata credential")
            try:
                got, _ = http.json(f"{http.api}/repos/{owner}/{name}", token=private_token)
            except Limit as e:
                raise hg.CannotRun(f"{name}'s visibility cannot be read ({e})")
            if not isinstance(got, dict) or got.get("visibility") != "private":
                raise hg.CannotRun(f"repos.txt lists {name} as private, and its visibility reads "
                                   f"{got.get('visibility') if isinstance(got, dict) else 'nothing'}")
            doc = got
        topics = doc.get("topics") if isinstance(doc.get("topics"), list) else []
        if not fleet.matches(name, topics):
            raise hg.CannotRun(f"repos.txt lists {name}, which the fleet rule does not match")
    return FleetView(scan, findings, skipped)


# --- One repository -------------------------------------------------------------


def mirror(git_base: str, owner: str, name: str, workdir: str) -> str:
    """A credential-free mirror of every ref, created or brought up to date."""
    dest = os.path.join(workdir, f"{name}.git")
    url = f"{git_base}/{owner}/{name}.git"
    cfg = ("-c", "credential.helper=", "-c", "core.askPass=")
    env = hg.git_env()
    if os.path.isdir(dest):
        cmd = ["git", "-C", dest, *cfg, "remote", "update", "--prune"]
    else:
        cmd = ["git", *cfg, "clone", "-q", "--mirror", url, dest]
    p = subprocess.run(cmd, capture_output=True, env=env)
    if p.returncode:
        raise hg.CannotRun(f"{name} could not be mirrored (git exited {p.returncode})")
    return dest


def heads(repo: str) -> List[Tuple[str, str]]:
    out = hg.git(repo, "for-each-ref", "--format=%(refname)%00%(objectname)%00%(*objectname)",
                 "refs/heads", "refs/tags", "refs/pull")
    rows = []
    for line in out.decode().splitlines():
        ref, oid, peeled = line.split("\x00")
        if ref.startswith("refs/pull/") and not ref.endswith("/head"):
            continue
        rows.append((ref, peeled or oid))
    return rows


def scan_git(m: hg.Matcher, repo: str, cache: Dict[str, dict]) -> Dict[str, List[hg.Finding]]:
    """Refs, every reachable commit (those not in the cache), and every
    head's tree. Returns the immutable findings by commit and by head."""
    hg.check_full_history(repo)
    blobs = hg.Blobs(repo)
    by_commit: Dict[str, List[hg.Finding]] = {}
    try:
        hg.scan_refs(m, repo, blobs)
        before = len(m.findings)
        scanned = hg.scan_history(m, repo, ["--all"], blobs, skip=set(cache))
        for f in m.findings[before:]:
            by_commit.setdefault(f.where.commit, []).append(f)
        for c in scanned:
            cache[c] = {"findings": len(by_commit.get(c, []))}
        tree_commits = {}
        for _ref, oid in heads(repo):
            kind = hg.git(repo, "cat-file", "-t", oid).decode().strip()
            if kind == "commit" and oid not in tree_commits:
                before = len(m.findings)
                hg.scan_tree(m, repo, oid, blobs)
                tree_commits[oid] = m.findings[before:]
    finally:
        blobs.close()
    return {"commits": by_commit, "trees": tree_commits}


def scan_api(m: hg.Matcher, http: Http, owner: str, name: str, info: dict, limits: List[str],
             seen_runs: Set[str]) -> None:
    """The mutable text surfaces. Each failure is a LIMIT for that surface."""
    base = f"/repos/{owner}/{name}"

    def guarded(surface: str, ident: str, fn: Callable[[], None]) -> None:
        try:
            fn()
        except Limit as e:
            limits.append(f"LIMIT: {name} {surface} {ident}: {e}")

    def text(surface: str, ident: str, *parts: Optional[str]) -> None:
        body = "\n".join(p for p in parts if isinstance(p, str))
        hg.scan_text(m, f"{surface} {ident}", body.encode("utf-8", "surrogateescape"))

    def pulls():
        for pr in http.listing(f"{base}/pulls?state=all"):
            text("pull", f"#{pr.get('number')}", pr.get("title"), pr.get("body"))

    def issues():
        for it in http.listing(f"{base}/issues?state=all"):
            if "pull_request" not in it:
                text("issue", f"#{it.get('number')}", it.get("title"), it.get("body"))

    def comments(path: str, surface: str):
        def run():
            for c in http.listing(f"{base}/{path}"):
                text(surface, str(c.get("id")), c.get("body"))
        return run

    def releases():
        for rel in http.listing(f"{base}/releases"):
            rid = str(rel.get("id"))
            text("release", rid, rel.get("name"), rel.get("tag_name"), rel.get("body"))
            for a in rel.get("assets") or []:
                aid = str(a.get("id"))
                text("asset", aid, a.get("name"))

                def one(a=a, aid=aid):
                    lines = Lines(m, hg.Where("text", m.repo, path=f"asset {aid}"), text=False)
                    http.stream(a.get("browser_download_url") or "", lines.feed)
                    lines.finish()
                guarded("asset", aid, one)

    def runs():
        for run in http.listing(f"{base}/actions/runs", key="workflow_runs"):
            rid = str(run.get("id"))
            if rid in seen_runs or run.get("status") != "completed":
                continue
            guarded("log", rid, lambda rid=rid: scan_zip(m, http, f"{http.api}{base}/actions/runs/{rid}/logs",
                                                         f"log {rid}", limits, name))
            seen_runs.add(rid)

    def artifacts():
        for art in http.listing(f"{base}/actions/artifacts", key="artifacts"):
            aid = str(art.get("id"))
            text("artifact", aid, art.get("name"))
            if art.get("expired") or f"artifact {aid}" in seen_runs:
                continue
            guarded("artifact", aid, lambda aid=aid, art=art: scan_zip(
                m, http, art.get("archive_download_url") or "", f"artifact {aid}", limits, name))
            seen_runs.add(f"artifact {aid}")

    guarded("pulls", "listing", pulls)
    guarded("issues", "listing", issues)
    guarded("issue-comments", "listing", comments("issues/comments", "comment"))
    guarded("review-comments", "listing", comments("pulls/comments", "review-comment"))
    guarded("commit-comments", "listing", comments("comments", "commit-comment"))
    guarded("releases", "listing", releases)
    guarded("actions-runs", "listing", runs)
    guarded("artifacts", "listing", artifacts)
    if info.get("has_discussions"):
        limits.append(f"LIMIT: {name} discussions all: not read (discussions are enabled)")


def scan_zip(m: hg.Matcher, http: Http, url: str, label: str, limits: List[str], name: str) -> None:
    """An archive, spooled to a temporary file under MAX_OBJECT, then read
    member by member under MAX_MEMBER and MAX_ARCHIVE; both the download and
    the decompressed bytes are charged to the run."""
    with tempfile.TemporaryFile() as spool:
        http.stream(url, spool.write)
        spool.seek(0)
        try:
            z = zipfile.ZipFile(spool)
        except zipfile.BadZipFile:
            raise Limit("truncated")
        total = 0
        with z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                if info.filename.lower().endswith(ARCHIVE_SUFFIXES):
                    limits.append(f"LIMIT: {name} {label} {info.filename}: nested archive")
                    continue
                lines = Lines(m, hg.Where("text", m.repo, path=f"{label} {info.filename}"))
                got = 0
                with z.open(info) as member:
                    while True:
                        chunk = member.read(CHUNK)
                        if not chunk:
                            break
                        got += len(chunk)
                        total += len(chunk)
                        if got > MAX_MEMBER or total > MAX_ARCHIVE:
                            raise Limit("oversize")
                        http.budget.charge(len(chunk))
                        lines.feed(chunk)
                lines.finish()


def scan_wiki(m: hg.Matcher, git_base: str, owner: str, name: str, workdir: str, limits: List[str]) -> None:
    dest = os.path.join(workdir, f"{name}.wiki.git")
    url = f"{git_base}/{owner}/{name}.wiki.git"
    cfg = ("-c", "credential.helper=", "-c", "core.askPass=")
    if not os.path.isdir(dest):
        p = subprocess.run(["git", *cfg, "clone", "-q", "--mirror", url, dest], capture_output=True,
                           env=hg.git_env())
        if p.returncode:
            if b"not found" in p.stderr.lower():
                return
            limits.append(f"LIMIT: {name} wiki all: could not be read")
            return
    else:
        subprocess.run(["git", "-C", dest, *cfg, "remote", "update", "--prune"], capture_output=True,
                       env=hg.git_env())
    wm = hg.Matcher(m.lists, m.repo)
    blobs = hg.Blobs(dest)
    try:
        hg.scan_history(wm, dest, ["--all"], blobs)
    finally:
        blobs.close()
    for f in wm.findings:
        m.findings.append(hg.Finding(hg.Where("wiki", f.where.repo, f.where.commit, f.where.path,
                                              f.where.lineno, f.where.field), f.what, f.entry))


# --- Verdicts -------------------------------------------------------------------


def verdict_targets(http: Http, owner: str, name: str, info: dict, repo: str) -> List[str]:
    """The default branch's head and each open pull request's head."""
    out = []
    branch = info.get("default_branch")
    if isinstance(branch, str):
        try:
            out.append(hg.git(repo, "rev-parse", "--verify", f"refs/heads/{branch}^{{commit}}").decode().strip())
        except hg.CannotRun:
            pass
    for pr in http.listing(f"/repos/{owner}/{name}/pulls?state=open"):
        sha = (pr.get("head") or {}).get("sha")
        if isinstance(sha, str) and hg._HEX40.fullmatch(sha):
            out.append(sha)
    return sorted(set(out))


def verdicts(repo: str, name: str, targets: Sequence[str], dirty: Set[str],
             trees: Dict[str, List[hg.Finding]], tree_of: Callable[[str], List[hg.Finding]]) -> List[dict]:
    """`failure` when the tree at the sha, or any commit reachable from it,
    has an immutable finding. Nothing else decides it."""
    out = []
    for sha in targets:
        reach = set(hg.git(repo, "rev-list", sha, "--").decode().split())
        tree = trees[sha] if sha in trees else tree_of(sha)
        bad = bool(reach & dirty) or any(f.immutable for f in tree)
        out.append({"repo": name, "sha": sha, "state": "failure" if bad else "success"})
    return out


def check_verdicts(doc: object, repos: Sequence[str]) -> List[dict]:
    """The status job's own check of the hand-over: exactly the schema, or
    ValueError and nothing posted."""
    if not isinstance(doc, list):
        raise ValueError("verdicts must be a list")
    for v in doc:
        if not isinstance(v, dict) or set(v) != set(VERDICT_KEYS):
            raise ValueError("each verdict has exactly repo, sha and state")
        if v["repo"] not in repos or not isinstance(v["sha"], str) or not hg._HEX40.fullmatch(v["sha"]) \
                or v["state"] not in VERDICT_STATES:
            raise ValueError("a verdict names an unknown repo, a short sha or an unknown state")
    return doc


# --- The run --------------------------------------------------------------------


def load_cache(path: Optional[str], digest: str) -> dict:
    if not path or not os.path.exists(path):
        return {"digest": digest, "repos": {}}
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError):
        return {"digest": digest, "repos": {}}
    if not isinstance(doc, dict) or doc.get("digest") != digest or not isinstance(doc.get("repos"), dict):
        return {"digest": digest, "repos": {}}
    return doc


def run_ci(lists_dir: str, owner: str, repos_path: str, rule_path: str, workdir: str, *, api: str,
           git_base: str, token: Optional[str], private_token: Optional[str], verdicts_out: Optional[str],
           cache_path: Optional[str], out=print) -> int:
    lists = hg.load_lists(lists_dir)
    fleet = load_fleet(repos_path, rule_path)
    budget = Budget()
    http = Http(api.rstrip("/"), token, budget)
    view = resolve_fleet(http, owner, fleet, private_token)
    cache = load_cache(cache_path, lists.digest)
    full = not cache["repos"]
    findings: List[str] = list(view.findings)
    limits: List[str] = []
    all_verdicts: List[dict] = []
    unused: List[str] = []
    for name in view.public:
        m = hg.Matcher(lists, name)
        state = cache["repos"].setdefault(name, {"commits": {}, "runs": []})
        repo = mirror(git_base, owner, name, workdir)
        try:
            info, _ = http.json(f"{http.api}/repos/{owner}/{name}")
            if not isinstance(info, dict) or info.get("visibility") != "public":
                raise hg.CannotRun(f"{name} is no longer public")
        except Limit as e:
            raise hg.CannotRun(f"{name}'s metadata cannot be read ({e})")
        got = scan_git(m, repo, state["commits"])
        dirty = {c for c, rec in state["commits"].items() if rec.get("findings")}
        seen = set(state.get("runs") or [])
        scan_api(m, http, owner, name, info, limits, seen)
        state["runs"] = sorted(seen)
        if info.get("has_wiki"):
            scan_wiki(m, git_base, owner, name, workdir, limits)
        try:
            targets = verdict_targets(http, owner, name, info, repo)
        except Limit as e:
            limits.append(f"LIMIT: {name} pulls open: {e}")
            targets = []

        def tree_of(sha: str, name=name, repo=repo) -> List[hg.Finding]:
            tm = hg.Matcher(lists, name)
            blobs = hg.Blobs(repo)
            try:
                hg.scan_tree(tm, repo, sha, blobs)
            finally:
                blobs.close()
            return tm.findings
        all_verdicts += verdicts(repo, name, targets, dirty, got["trees"], tree_of)
        hg.report(m, lambda line: findings.append(line) if line.startswith("FINDING") else None)
        if full:
            unused += [f"exceptions: allow.txt line {ex.line} ({ex.kind}) matched nothing in {name}"
                       for ex in m.unused() if ex.repo == name]
    for line in findings:
        out(line)
    for line in limits:
        out(line)
    for line in unused:
        out(line)
    out(f"fleet: {len(view.public)} public fleet repositories scanned; skipped {view.skipped} public "
        "repositories outside the fleet rule")
    out(f"api: {budget.requests} requests, {budget.used} bytes; rate limit remaining "
        f"{budget.rate_remaining if budget.rate_remaining is not None else 'not reported'}")
    out(f"lists: sha256 {lists.digest}" + ("" if full else " (incremental: commits scanned before were skipped)"))
    if verdicts_out:
        tmp = verdicts_out + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(check_verdicts(all_verdicts, view.public), f, sort_keys=True)
        os.replace(tmp, verdicts_out)
    if cache_path:
        tmp = cache_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cache, f, sort_keys=True)
        os.replace(tmp, cache_path)
    if findings:
        return 1
    return 2 if limits else 0
