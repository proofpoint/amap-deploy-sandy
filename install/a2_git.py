"""Git, read through plumbing only, by a fixed absolute path, in an
explicit environment that carries no system or global configuration.

Git runs in two kinds of repository only:
- the bare repositories this installer creates, fresh and exclusively, in
  the work directory (section 2: S0 writes "the fetched commits in the work
  directory"), where every fetch goes and every tree, blob and ancestry
  read is made;
- the installer's own checkout, owned by the account that runs it, where
  only its HEAD id and its status are read (6.1).
It never runs in a repository another account owns, the private overlay
checkout included: git refuses one, and naming one in safe.directory would
hand that account's configuration (a clean filter, for one) a command in
the runner's environment. S0 proves the overlay checkout without git.
"""

import hashlib
import os
import re
import subprocess

GIT = "/usr/bin/git"
TIMEOUT_S = 120
SHA_RE = re.compile(rb"[0-9a-f]{40}|[0-9a-f]{64}")


class GitError(Exception):
    pass


#: A home git's ssh command may name: absolute, plain segments, nothing a shell would split or expand
#: (GIT_SSH_COMMAND is run by a shell).
SAFE_HOME = re.compile(r"(/[A-Za-z0-9._-]+)+")
#: The overlay's ssh configuration under the account's home (NET's creds r7 part 2): one Host block for the
#: overlay's real host, with its own key and known_hosts. -F makes it ssh's whole configuration.
OVERLAY_SSH_CONFIG = ".ssh/config_overlay"
SSH = "/usr/bin/ssh"


def ssh_effective(home, host, port, run=subprocess.run):
    """ssh's effective configuration for `host`:`port` under the account's overlay configuration, as
    `ssh -G -F <home>/.ssh/config_overlay` prints it: {option: [values]}, option names lower-case. Connects to
    nothing. GitError if ssh refuses the configuration."""
    env_for(home)
    if not isinstance(port, int) or not 0 < port < 65536:
        raise GitError("port")
    try:
        p = run([SSH, "-G", "-F", home + "/" + OVERLAY_SSH_CONFIG, "-p", str(port), "--", host],
                env={"PATH": "/usr/bin:/bin", "HOME": home, "LC_ALL": "C"}, stdin=subprocess.DEVNULL,
                capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        raise GitError("ssh -G did not run")
    if p.returncode != 0:
        raise GitError("ssh -G refused the configuration")
    out = {}
    for line in p.stdout.decode("utf-8", "strict").splitlines():
        key, _, value = line.partition(" ")
        if key:
            out.setdefault(key.lower(), []).append(value)
    return out


def env_for(home, ssh_auth_sock=""):
    """The child's whole environment: never os.environ (3.2; PEP 538 adds
    LC_CTYPE to it). ssh reads only the account's overlay configuration."""
    if not isinstance(home, str) or not SAFE_HOME.fullmatch(home) or any(
            s in (".", "..") for s in home.split("/")):
        raise ValueError("home is not a plain absolute path")
    return {"PATH": "/usr/bin:/bin", "HOME": home, "SSH_AUTH_SOCK": ssh_auth_sock,
            "GIT_SSH_COMMAND": "ssh -F " + home + "/" + OVERLAY_SSH_CONFIG,
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C",
            # No replace refs: an object is what its id names.
            "GIT_NO_REPLACE_OBJECTS": "1",
            # Status must not refresh and rewrite a checkout's index.
            "GIT_OPTIONAL_LOCKS": "0"}


#: The transports a fetch may use: repo_url (6.0) admits ssh and https only.
PROTOCOLS = ("ssh", "https")


class Git:
    def __init__(self, env, git=GIT, timeout_s=TIMEOUT_S, protocols=PROTOCOLS):
        self.env = env
        self.git = git
        self.timeout_s = timeout_s
        self.protocols = protocols

    def run(self, repo, *args, ok=(0,)):
        cfg = ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
               "-c", "protocol.allow=never"]
        for proto in self.protocols:
            cfg += ["-c", "protocol." + proto + ".allow=always"]
        cmd = [self.git] + cfg + ["-C", repo] + list(args)
        try:
            p = subprocess.run(cmd, env=self.env, stdin=subprocess.DEVNULL, capture_output=True,
                               timeout=self.timeout_s, close_fds=True)
        except (OSError, subprocess.TimeoutExpired):
            raise GitError("git did not run")
        if p.returncode not in ok:
            raise GitError("git refused")
        return p.returncode, p.stdout

    # -- reads of a checkout

    def head(self, repo):
        _, out = self.run(repo, "rev-parse", "--verify", "--end-of-options", "HEAD^{commit}")
        out = out.strip()
        if not SHA_RE.fullmatch(out):
            raise GitError("no head")
        return out.decode()

    def status_clean(self, repo):
        _, out = self.run(repo, "status", "--porcelain=v1", "-z", "--untracked-files=all",
                          "--ignore-submodules=none")
        return out == b""

    def tracked(self, repo, path):
        rc, _ = self.run(repo, "ls-files", "--error-unmatch", "--", path, ok=(0, 1))
        return rc == 0

    def object_format(self, repo):
        _, out = self.run(repo, "rev-parse", "--show-object-format")
        fmt = out.strip().decode()
        if fmt not in ("sha1", "sha256"):
            raise GitError("unknown object format")
        return fmt

    def tree_files(self, repo, rev):
        """{path: (mode, type, object id)} of every entry of `rev`'s whole tree,
        recursively (directories are not entries; a submodule is, as type
        "commit")."""
        _, out = self.run(repo, "ls-tree", "-r", "-z", "--full-tree", rev)
        files = {}
        for e in out.split(b"\0"):
            if not e:
                continue
            meta, _, name = e.partition(b"\t")
            mode, typ, oid = meta.split(b" ")
            files[name.decode("utf-8", "strict")] = (mode.decode(), typ.decode(), oid.decode())
        return files

    def tree_entry(self, repo, rev, path):
        """(mode, type, object id) of `path` in `rev`'s tree, or None."""
        _, out = self.run(repo, "ls-tree", "-z", "--full-tree", rev, "--", path)
        if not out:
            return None
        entries = [e for e in out.split(b"\0") if e]
        if len(entries) != 1:
            raise GitError("ambiguous tree entry")
        meta, _, name = entries[0].partition(b"\t")
        mode, typ, oid = meta.split(b" ")
        if name.decode("utf-8", "strict") != path:
            raise GitError("tree entry path")
        return mode.decode(), typ.decode(), oid.decode()

    def is_ancestor(self, repo, a, b):
        rc, _ = self.run(repo, "merge-base", "--is-ancestor", a, b, ok=(0, 1))
        return rc == 0

    def diff_tree(self, repo, a, b):
        """[(old_mode, new_mode, status, path)] of a recursive tree
        comparison with rename and copy detection off."""
        _, out = self.run(repo, "diff-tree", "--no-renames", "--no-ext-diff", "-r", "-z", "--raw",
                          "--end-of-options", a, b)
        parts = out.split(b"\0")
        if parts and parts[-1] == b"":
            parts = parts[:-1]
        if len(parts) % 2:
            raise GitError("diff-tree output")
        entries = []
        for i in range(0, len(parts), 2):
            meta = parts[i].decode("ascii", "strict")
            if not meta.startswith(":"):
                raise GitError("diff-tree output")
            old_mode, new_mode, _o, _n, status = meta[1:].split(" ")
            entries.append((old_mode, new_mode, status, parts[i + 1].decode("utf-8", "strict")))
        return entries

    # -- fetches into the installer's own bare repositories

    def init_bare(self, path):
        """Initialize a bare repository in `path`, a directory the caller has
        just created empty and exclusively: no configuration exists in it
        that this installer did not write."""
        self.run(path, "init", "--quiet", "--bare", ".")
        return path

    def ls_remote_tag(self, bare, url, tag):
        """The read-only access probe: the remote answers. Returns whether
        the tag ref is listed."""
        _, out = self.run(bare, "ls-remote", "--tags", "--end-of-options", url, "refs/tags/" + tag)
        want = ("refs/tags/" + tag).encode()
        for line in out.splitlines():
            _oid, _, ref = line.partition(b"\t")
            if ref == want:
                return True
        return False

    def ls_remote_any(self, bare, url):
        """The read-only access probe for a commit-only fetch: the remote
        answers. Whether it has the commit is fetch_refs' and has_commit's."""
        self.run(bare, "ls-remote", "--heads", "--tags", "--end-of-options", url)

    def fetch_refs(self, bare, url):
        """Fetch every branch and tag of `url` into this bare repository's own
        namespaces (refs/a2h/*, refs/a2t/*): the objects that arrive are only
        those the remote's refs reach."""
        self.run(bare, "fetch", "--quiet", "--no-tags", "--no-write-fetch-head", "--force",
                 "--end-of-options", url, "+refs/heads/*:refs/a2h/*", "+refs/tags/*:refs/a2t/*")

    def has_commit(self, bare, commit):
        """Whether `commit` is a commit object in `bare`, by its full id, AND
        reachable from a fetched branch or tag (refs/a2h, refs/a2t): an object
        a server added to the pack beside the refs' closure does not count."""
        rc, _ = self.run(bare, "rev-parse", "--verify", "--quiet", "--end-of-options", commit + "^{commit}",
                         ok=(0, 1))
        if rc != 0:
            return False
        _, out = self.run(bare, "for-each-ref", "--count=1", "--format=%(refname)", "--contains", commit,
                          "refs/a2h", "refs/a2t")
        return out.strip() != b""

    def blob_at(self, bare, commit, path):
        """The bytes of `path` at `commit` in a bare repository this installer fetched: plumbing only, no checkout,
        no filter. A path that is not a blob refuses."""
        _, typ = self.run(bare, "cat-file", "-t", "--end-of-options", commit + ":" + path)
        if typ.strip() != b"blob":
            raise GitError("not a blob")
        _, data = self.run(bare, "cat-file", "blob", "--end-of-options", commit + ":" + path)
        return data

    def fetch_tag(self, bare, url, tag):
        """Fetch exactly refs/tags/<tag> into refs/a2/<tag>; return
        (object type of the ref, the commit it peels to)."""
        ref = "refs/a2/" + tag
        self.run(bare, "fetch", "--quiet", "--no-tags", "--no-write-fetch-head", "--force",
                 "--end-of-options", url, "refs/tags/" + tag + ":" + ref)
        _, typ = self.run(bare, "cat-file", "-t", ref)
        _, peeled = self.run(bare, "rev-parse", "--verify", "--end-of-options", ref + "^{commit}")
        return typ.strip().decode(), peeled.strip().decode()


def blob_id(data, fmt):
    """The git blob id of exact bytes, computed here: no filter, no index."""
    h = hashlib.sha1 if fmt == "sha1" else hashlib.sha256
    return h(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
