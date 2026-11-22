"""The shared VM layer: how a stage runs anything on a VM, places a root-owned file, hands a secret to its writer,
and reads a pinned component file. Nothing here decides what a stage does; it only carries it, fail-closed.

- `exec(vm, argv, account=..., stage=..., writes=..., stdin=..., timeout_s=...)`: one fixed argv on the VM, as
  `account`, in a closed environment (vm_launch). `writes` is required.
- `install_file(vm, data, path, mode=..., stage=...)`: a root-owned file at an allowlisted path (vm_bootstrap's list).
- `write_secret(vm, use, mode, value, account=..., stage=...)`: the writer for `use` (writers[]) receives the value.
- `component_file(component, path, stage=...)`: a pinned component file's bytes, from S0's fetched repository.

The write rule (3.4, 4.2): once a stage has written through this layer (install_file, write_secret, or an exec with
writes=True, on any VM), every refusal the layer raises for that stage is UNCLASSIFIED rc 3, PIN and LOCK included,
so rc 2 always means that nothing was written. Before that, a route
failure is TARGET_ACCESS rc 2.

The route is ssh to the VM's `ssh_alias`, BatchMode, with the host key pinned by the known_hosts file the caller
names (S2's receipt), and no ssh configuration file. Every remote word is shell-quoted, because ssh joins its
arguments into one string for the remote shell. ssh's own failure (rc 255) is the route's, reported as such and
never as the command's rc. Root work runs the bootstrap's bytes, which this module reads from the installer's own
checkout and checks against install/MANIFEST and the lock's installer.sha256, so they are the bytes the VM runs.
"""

import hashlib
import os
import re
import select
import shlex
import subprocess
import time

from a2_causes import Refusal
import a2_git

SSH = "/usr/bin/ssh"
SSH_ROUTE_FAILED = 255
BOOTSTRAP = "vm_bootstrap.py"
LAUNCHER = "vm_launch.py"
MANIFEST = "MANIFEST"
_MANIFEST_LINE = re.compile(rb"([0-9a-f]{64})  ([A-Za-z0-9_]{1,64}\.py)")
_ACCOUNT = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
_ALIAS = re.compile(r"[a-z0-9][a-z0-9._-]{0,252}")
_SHA = re.compile(r"[0-9a-f]{64}")
_LOGICAL_ID = re.compile(r"[0-9a-f]{32}")
#: S2's known_hosts path: absolute, and nothing ssh would split or expand (whitespace, %, ~, a comma).
_KNOWN_HOSTS = re.compile(r"/[A-Za-z0-9._/-]{1,4095}")
SECRET_MODES = ("write", "rotate", "finish", "restore")
VALUE_MODES = ("write", "rotate")
ALREADY = 10
_NOT_ALLOWED = 4
#: vm_bootstrap's DIFFERENT: a never-replaced file is present and differs; nothing was written.
_DIFFERENT = 8
#: vm_bootstrap's hop root pattern: absolute, plain segments.
_HOP_ROOT = re.compile(r"(/[A-Za-z0-9._-]+)+")


#: Bootstrap codes that come before any write on the VM (usage, not allowed, core limit). 3 is the pin, and is PIN
#: either way. Every other code may follow a write.
_BEFORE_WRITE = (2, 4, 7)


_STATUS = re.compile(rb"RC ([0-9]{1,3})\n")


def _ready(fd, event, left):
    """poll(2), with no FD_SETSIZE limit: whether `fd` is ready (or hung up) within `left` seconds."""
    p = select.poll()
    p.register(fd, event)
    return bool(p.poll(max(1, int(left * 1000))))


def _write_all(stream, data, deadline):
    """A full-write loop on a nonblocking pipe, under the call's one deadline: a VM that stops reading cannot hold
    the run. No copy of the data is kept in a Python buffer."""
    fd = stream.fileno()
    view = memoryview(data)
    try:
        while view:
            left = deadline - time.monotonic()
            if left <= 0 or not _ready(fd, select.POLLOUT, left):
                raise subprocess.TimeoutExpired("ssh", 0)
            try:
                view = view[os.write(fd, view):]
            except BlockingIOError:
                continue
    finally:
        view.release()


def _read_line(stream, deadline, limit=64):
    """One short line from a pipe, or b"" at EOF; past the deadline it raises TimeoutExpired, so a VM that neither
    answers nor exits cannot hold the run."""
    fd = stream.fileno()
    buf = b""
    while not buf.endswith(b"\n") and len(buf) < limit:
        left = deadline - time.monotonic()
        if left <= 0 or not _ready(fd, select.POLLIN, left):
            raise subprocess.TimeoutExpired("ssh", 0)
        b = os.read(fd, 1)
        if not b:
            break
        buf += b
    return buf


class VmLayer:
    """Built by the runner once per run, after S0 (the lock, the hosts document and the fetched repositories) and
    S2 (each VM's pinned known_hosts). `login` is the account ssh logs in as: a slot of the VM base contract, None
    refuses. `stage` is the cause prefix of the stage that calls (for example "AGENTS")."""

    def __init__(self, hosts, lock, known_hosts_for, login, installer_dir, git=None, fetched=None, ssh=SSH,
                 timeout_s=120):
        self.vms = {v["name"]: v for v in hosts["vms"]}
        self.lock = lock
        self.known_hosts_for = known_hosts_for
        self.login = login
        self.installer_dir = installer_dir
        self.git = git
        self.fetched = fetched or {}
        self.ssh = ssh
        self.timeout_s = timeout_s
        #: The stages that have issued a write through this layer. Once a stage is here, every refusal the layer
        #: raises for it exits 3, keeping its cause: the stage can no longer show that it wrote nothing (3.4, 4.2).
        self._wrote = set()

    def wrote(self, stage):
        """Whether `stage` has issued a write through this layer: a stage's own causes then exit 3 (3.4, 4.2)."""
        return stage in self._wrote

    def _refused(self, stage, detail, cause="UNCLASSIFIED", wrote=False):
        """Every refusal the layer raises goes through here (the write rule, 3.4, 4.2): `cause` keeps its name, and
        exits 3 once this stage has written (now or before), 2 before that. Exit 2 always means nothing was
        written."""
        if wrote or stage in self._wrote:
            return Refusal(stage + "." + cause, detail, rc=3)
        return Refusal(stage + "." + cause, detail)

    def _bootstrap_refused(self, stage, rc, prior):
        """A bootstrap's refusal. `prior`: whether the stage had written before this call (the call itself has
        already set the flag). A code from before any write is rc 2 only if nothing was written before."""
        if rc == 3:
            return Refusal(stage + ".PIN", "bootstrap pin", rc=3 if prior else None)
        if rc in _BEFORE_WRITE and not prior:
            return Refusal(stage + ".UNCLASSIFIED", "bootstrap rc %d" % rc)
        return Refusal(stage + ".UNCLASSIFIED", "bootstrap rc %d" % rc, rc=3)

    # -- the route

    def _route(self, vm, stage):
        if vm not in self.vms:
            raise self._refused(stage, "vm not in alpha2.hosts", "TARGET_ACCESS")
        alias = self.vms[vm]["ssh_alias"]
        kh = self.known_hosts_for(vm)
        if (self.login is None or not _ACCOUNT.fullmatch(self.login) or not _ALIAS.fullmatch(alias)
                or not isinstance(kh, str) or not _KNOWN_HOSTS.fullmatch(kh)):
            raise self._refused(stage, "route not configured", "TARGET_ACCESS")
        return [self.ssh, "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", "UserKnownHostsFile=" + kh, "-o", "GlobalKnownHostsFile=/dev/null",
                "-o", "IdentitiesOnly=yes", "-T", "-l", self.login, alias, "--"]

    def _words(self, words, stage):
        if not all(isinstance(w, str) and "\x00" not in w for w in words):
            raise self._refused(stage, "a word is not a string without NUL")
        return " ".join(shlex.quote(w) for w in words)

    def _run(self, vm, words, stdin, stage, timeout_s, writes):
        cmd = self._route(vm, stage) + [self._words(words, stage)]
        if writes:
            self._wrote.add(stage)
        try:
            p = subprocess.run(cmd, input=bytes(stdin) if stdin is not None else b"", capture_output=True,
                               timeout=timeout_s or self.timeout_s, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                               close_fds=True)
        except (OSError, subprocess.TimeoutExpired):
            raise self._refused(stage, "ssh did not complete", "TARGET_ACCESS")
        if p.returncode == SSH_ROUTE_FAILED:
            raise self._refused(stage, "ssh route failed", "TARGET_ACCESS")
        return p.returncode, p.stdout, p.stderr

    # -- the four calls

    def exec(self, vm, argv, *, account, stage, writes, stdin=None, timeout_s=None):
        """One fixed argv as `account`: (rc, stdout, stderr). argv[0] must be an absolute path. The command runs
        through the pinned launcher (vm_launch): its environment is exactly PATH, LC_ALL and the account's HOME, its
        cwd that HOME, its umask 022.

        `writes` is required: True for an argv that can change the VM. From then on every refusal of this stage is
        UNCLASSIFIED rc 3, because a route failure or timeout leaves the remote command's effect unknown."""
        if type(writes) is not bool:
            raise self._refused(stage, "writes is not a bool")
        if not argv or not isinstance(argv[0], str) or not argv[0].startswith("/"):
            raise self._refused(stage, "argv[0] is not an absolute path", "TARGET_ACCESS")
        if not isinstance(account, str) or not _ACCOUNT.fullmatch(account):
            raise self._refused(stage, "account is not a name", "TARGET_ACCESS")
        launch = self.pinned_installer_file(LAUNCHER, stage).decode("utf-8")
        words = ["/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LC_ALL=C", "/usr/bin/python3", "-I", "-S", "-c", launch]
        words += list(argv)
        if account != self.login:
            words = ["/usr/bin/sudo", "-n", "-u", account, "--"] + words
        return self._run(vm, words, stdin, stage, timeout_s, writes)

    def _root(self, vm, op_words, stdin, stage):
        src = self.pinned_installer_file(BOOTSTRAP, stage)
        words = ["/usr/bin/sudo", "-n", "--", "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LC_ALL=C",
                 "/usr/bin/python3", "-I", "-S", "-c", src.decode("utf-8")] + op_words
        prior = stage in self._wrote
        return self._run(vm, words, stdin, stage, None, True)[0], prior

    def install_file(self, vm, data, path, *, mode, stage):
        """A root-owned file at an allowlisted path. Returns "CHANGED" or "ALREADY"; anything else refuses."""
        rc, prior = self._root(vm, ["install", path, "%04o" % mode, hashlib.sha256(data).hexdigest()], data, stage)
        if rc == 0:
            return "CHANGED"
        if rc == ALREADY:
            return "ALREADY"
        if rc == _DIFFERENT:
            # A never-replaced file (the plugin) is present with other bytes, owner or mode; it was left untouched.
            raise Refusal(stage + ".PLACED_DIFFERENT", "installed file", rc=3 if prior else None)
        raise self._bootstrap_refused(stage, rc, prior)

    def hop_intakes(self, vm, root, relay_account, group, *, stage):
        """The hop root's two intakes, owned by `relay_account` in `group` (vm_bootstrap's hopintakes). Returns
        "CHANGED" or "ALREADY". The bootstrap checks every existing intake before it makes one, so its NOT_ALLOWED
        means nothing was written by this call: an existing intake, the root or an ancestor that breaks a rule,
        refused as OWNER and never repaired."""
        for w in (relay_account, group):
            if not isinstance(w, str) or not _ACCOUNT.fullmatch(w):
                raise self._refused(stage, "account or group is not a name", "TARGET_ACCESS")
        if not isinstance(root, str) or not _HOP_ROOT.fullmatch(root) or any(p in (".", "..") for p in root.split("/")):
            raise self._refused(stage, "hop root is not an absolute path", "OWNER")
        rc, prior = self._root(vm, ["hopintakes", root, relay_account, group], b"", stage)
        if rc == 0:
            return "CHANGED"
        if rc == ALREADY:
            return "ALREADY"
        if rc == _NOT_ALLOWED:
            # The call has already marked the stage as written (_root writes), so the rc comes from `prior`.
            raise Refusal(stage + ".OWNER", "hop intakes", rc=3 if prior else None)
        raise self._bootstrap_refused(stage, rc, prior)

    def write_secret(self, vm, use, mode, value, *, account, stage):
        """The writer for `use` receives the value (write, rotate: a non-empty bytearray) or nothing (finish,
        restore: None). Returns the writer's rc, from the bootstrap's `RC <n>` line.

        Every argument is checked before ssh starts (the use through writer_bytes: no writers[] row is LOCK), and a
        refusal then sends nothing (rc 2 unless the stage has written). Two steps in one ssh session (3.7 rule 7): the writer's bytes go first, checked here against the
        lock; the bootstrap hashes them itself and answers `READY` only on a match; the value is written only after
        that line, unbuffered, so a mismatched writer never receives it and it is never sent. After the writer, the
        bootstrap prints `RC <n>`: a session without it is the bootstrap's own failure, UNCLASSIFIED rc 3."""
        if mode not in SECRET_MODES:
            raise self._refused(stage, "mode")
        if mode in VALUE_MODES:
            if type(value) is not bytearray or not value:
                raise self._refused(stage, "a value mode needs a non-empty bytearray")
        elif value is not None:
            raise self._refused(stage, "finish and restore take no value")
        if not isinstance(account, str) or not _ACCOUNT.fullmatch(account):
            raise self._refused(stage, "account is not a name", "TARGET_ACCESS")
        writer = self.writer_bytes(use, stage)
        src = self.pinned_installer_file(BOOTSTRAP, stage).decode("utf-8")
        words = ["/usr/bin/sudo", "-n", "--", "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LC_ALL=C",
                 "/usr/bin/python3", "-I", "-S", "-c", src,
                 "secret", use, mode, hashlib.sha256(writer).hexdigest(), account]
        cmd = self._route(vm, stage) + [self._words(words, stage)]
        try:
            p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, close_fds=True, bufsize=0)
        except OSError:
            raise self._refused(stage, "ssh did not start", "TARGET_ACCESS")
        prior = stage in self._wrote
        self._wrote.add(stage)
        ready = status = b""
        # One deadline for the whole session: every write, both reads and the exit.
        deadline = time.monotonic() + self.timeout_s
        try:
            os.set_blocking(p.stdin.fileno(), False)
            _write_all(p.stdin, len(writer).to_bytes(8, "big") + bytes(writer), deadline)
            ready = _read_line(p.stdout, deadline)
            if ready == b"READY\n" and value is not None:
                _write_all(p.stdin, value, deadline)
            p.stdin.close()
            if ready == b"READY\n":
                status = _read_line(p.stdout, deadline)
                if _read_line(p.stdout, deadline) != b"":
                    status = b""
            rc = p.wait(timeout=max(0.0, deadline - time.monotonic()))
        except (OSError, subprocess.TimeoutExpired):
            p.kill()
            p.wait()
            raise self._refused(stage, "ssh did not complete")
        finally:
            for stream in (p.stdin, p.stdout):
                try:
                    stream.close()
                except OSError:
                    pass
        if rc == SSH_ROUTE_FAILED:
            raise self._refused(stage, "ssh route failed")
        if ready != b"READY\n":
            raise self._bootstrap_refused(stage, rc, prior)
        m = _STATUS.fullmatch(status)
        if m is None or int(m.group(1)) != rc:
            raise self._refused(stage, "the bootstrap failed after READY")
        return rc

    def component_file(self, component, path, *, stage):
        """A file of a pinned component, from S0's fetched repository, checked against its files[] row."""
        rows = [f for f in self.lock["files"] if f["component"] == component and f["path"] == path]
        commits = [c["commit"] for c in self.lock["components"] if c["name"] == component]
        bare = self.fetched.get("c-" + component)
        if len(rows) != 1 or len(commits) != 1 or bare is None or self.git is None:
            raise self._refused(stage, "component file not pinned or not fetched", "PIN")
        try:
            data = self.git.blob_at(bare, commits[0], path)
        except a2_git.GitError:
            raise self._refused(stage, "component file not readable", "PIN")
        if hashlib.sha256(data).hexdigest() != rows[0]["sha256"]:
            raise self._refused(stage, "component file differs from its pin", "PIN")
        return data

    #: The modes a placed tree may hold: regular files only (a symlink or a submodule refuses).
    TREE_MODES = {"100644": 0o644, "100755": 0o755}

    def component_tree(self, component, prefix, *, stage):
        """(tree id, [(path under prefix, mode, bytes)]) of `prefix` in a pinned component, from S0's fetched
        repository at the lock's commit (ruling W7-R1-R2-DESIGN, R1). Transfer and the commit pin verified the
        objects; each blob is re-hashed here against the tree's object id, and the caller re-hashes each placed
        file on the VM. A prefix that is not a directory, an empty one, or an entry that is not a regular file
        refuses PIN."""
        commits = [c["commit"] for c in self.lock["components"] if c["name"] == component]
        bare = self.fetched.get("c-" + component)
        if (len(commits) != 1 or bare is None or self.git is None or not isinstance(prefix, str)
                or not prefix or prefix.startswith("/") or prefix.endswith("/")
                or any(s in ("", ".", "..") for s in prefix.split("/"))):
            raise self._refused(stage, "component tree not pinned or not fetched", "PIN")
        try:
            entry = self.git.tree_entry(bare, commits[0], prefix)
            fmt = self.git.object_format(bare)
            files = self.git.tree_files(bare, commits[0])
            if entry is None or entry[1] != "tree":
                raise a2_git.GitError("not a tree")
            out = []
            for path in sorted(files):
                if not path.startswith(prefix + "/"):
                    continue
                mode, typ, oid = files[path]
                if typ != "blob" or mode not in self.TREE_MODES:
                    raise a2_git.GitError("not a regular file")
                data = self.git.blob_at(bare, commits[0], path)
                h = hashlib.new(fmt)
                h.update(b"blob %d\0" % len(data) + data)
                if h.hexdigest() != oid:
                    raise a2_git.GitError("blob differs from its object id")
                out.append((path[len(prefix) + 1:], self.TREE_MODES[mode], data))
        except (a2_git.GitError, ValueError, UnicodeError):
            raise self._refused(stage, "component tree not readable", "PIN")
        if not out:
            raise self._refused(stage, "component tree is empty", "PIN")
        return entry[2], out

    # -- the installer's own bytes

    def pinned_installer_file(self, fname, stage):
        """`install/<fname>`'s bytes, checked against install/MANIFEST, whose own sha must be the lock's
        installer.sha256."""
        try:
            with open(os.path.join(self.installer_dir, MANIFEST), "rb") as f:
                manifest = f.read()
            with open(os.path.join(self.installer_dir, fname), "rb") as f:
                data = f.read()
        except OSError:
            raise self._refused(stage, "installer file unreadable", "PIN")
        if hashlib.sha256(manifest).hexdigest() != self.lock["installer"]["sha256"]:
            raise self._refused(stage, "installer manifest", "PIN")
        listed = {}
        for line in manifest.split(b"\n"):
            m = _MANIFEST_LINE.fullmatch(line)
            if m:
                listed[m.group(2).decode()] = m.group(1).decode()
        if listed.get(fname) != hashlib.sha256(data).hexdigest():
            raise self._refused(stage, "installer file " + fname, "PIN")
        return data

    def writer_bytes(self, use, stage):
        rows = [w for w in self.lock["writers"] if w["use"] == use]
        if len(rows) != 1:
            raise self._refused(stage, "writer not pinned", "LOCK")
        path = os.path.normpath(os.path.join(os.path.dirname(self.installer_dir), rows[0]["path"]))
        if not path.startswith(os.path.dirname(self.installer_dir) + os.sep):
            raise self._refused(stage, "writer path", "PIN")
        try:
            with open(path, "rb") as f:
                data = bytearray(f.read())
        except OSError:
            raise self._refused(stage, "writer unreadable", "PIN")
        if hashlib.sha256(data).hexdigest() != rows[0]["sha256"]:
            raise self._refused(stage, "writer differs from its pin", "PIN")
        return data


def bind(site, layer):
    """Fill the site's VM slots from a built layer (the runner, after S2), the agents' registry slots included
    (a2_agent_registry, through this layer). The account slot stays as it is: it is not this layer's."""
    import a2_agent_registry
    site.vm_exec = layer.exec
    site.vm_install_file = layer.install_file
    site.vm_write_secret = layer.write_secret
    site.component_file = layer.component_file
    site.vm_layer = layer
    agents = a2_agent_registry.AgentRegistry(layer)
    site.registry_import = agents.registry_import
    site.registry_read = agents.registry_read


def logical_id(site, vm, slug, stage):
    """The instance's logical id, read back from the registry after an import: 32 lower-case hex characters, or a
    refusal. A read-back follows a write, so its failure is UNCLASSIFIED (rc 3), never a value recorded as active."""
    value = site.registry_read(vm, slug, stage=stage)
    if not isinstance(value, str) or not _LOGICAL_ID.fullmatch(value) or value == "0" * 32:
        raise Refusal(stage + ".UNCLASSIFIED", "registry read-back is not a logical id", rc=3)
    return value
