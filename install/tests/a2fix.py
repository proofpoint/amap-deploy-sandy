"""Shared fixtures for the installer tests: example private files (every
value is an illustration in the shape section 6 gives, with example.org
domains), a staged lock root, and a fake budget broker.

The fake broker speaks the client's request/answer shape (a2_budget). The
broker's real protocol is [OPEN: budget broker, DS]; this stub models only
what the client sends and accepts, and refuses any other request shape.
"""

import copy
import hashlib
import json
import os
import pwd
import socket
import stat
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
INSTALL = os.path.dirname(HERE)
REPO = os.path.dirname(INSTALL)
sys.path.insert(0, INSTALL)

import a2_private  # noqa: E402

#: The fixture lock's invented hub login names. a2_private pins the real, frozen ones by sha256; every test process
#: that imports this fixture points the pins at these (as tests/test_hub_runtime.py does for hub_runtime).
FIXTURE_LOGIN = {"local": "lname", "domain": "logins.example"}
a2_private.LOGIN_LOCAL_SHA256 = hashlib.sha256(FIXTURE_LOGIN["local"].encode()).hexdigest()
a2_private.LOGIN_DOMAIN_SHA256 = hashlib.sha256(FIXTURE_LOGIN["domain"].encode()).hexdigest()
#: The fixture lock's invented registry program names, pinned the same way.
FIXTURE_REGISTRY = {"package": "regtool", "config_schema": "regtool.config/1", "adapter_interface": "regtool.adapter/1",
                    "component": "registry"}
a2_private.REGISTRY_PACKAGE_SHA256 = hashlib.sha256(FIXTURE_REGISTRY["package"].encode()).hexdigest()
a2_private.REGISTRY_CONFIG_SCHEMA_SHA256 = hashlib.sha256(FIXTURE_REGISTRY["config_schema"].encode()).hexdigest()
a2_private.REGISTRY_ADAPTER_INTERFACE_SHA256 = hashlib.sha256(FIXTURE_REGISTRY["adapter_interface"].encode()).hexdigest()
a2_private.REGISTRY_COMPONENT_SHA256 = hashlib.sha256(FIXTURE_REGISTRY["component"].encode()).hexdigest()

ME = pwd.getpwuid(os.getuid())
H40 = "a" * 40
H64 = "b" * 64

LOCK = {
    "schema": "alpha2.lock/1",
    "installer": {"repo": "https://git.example.org/amap/amap-deploy-sandy", "commit": H40,
                  "entry": "install/alpha2_install.py", "sha256": H64},
    "interpreter": {"path": "/usr/bin/python3", "sha256": H64, "resolved_path": "/usr/bin/python3.13",
                    "resolved_sha256": H64, "version": "3.13.5"},
    "overlay": {"repo": "ssh://git@git.example.org/amap/private-overlay", "commit": H40, "tag": "alpha2-rc1"},
    "components": [{"name": "router", "repo": "ssh://git@git.example.org/amap/router", "commit": H40,
                    "tag": "alpha2-rc1"},
                   {"name": "connector", "repo": "https://git.example.org/amap/connector", "commit": H40,
                    "tag": "alpha2-rc1"},
                   {"name": "registry", "repo": "ssh://git@git.example.org/amap/registry", "commit": H40,
                    "tag": "alpha2-rc1"}],
    "images": [{"name": "router-img", "built_from": "router", "image_id": "sha256:" + H64}],
    "files": [{"path": "alpha/packages/a.sh", "component": "router", "sha256": H64},
              {"path": "dist/plugin.py", "component": "router", "sha256": "c" * 64}],
    "writers": [{"use": "api_key", "path": "install/w/api.py", "sha256": H64},
                {"use": "hub_login", "path": "install/w/hub.py", "sha256": H64}],
    "plugin": {"sha256": "c" * 64, "plugin_api": "1.2"},
    "d7_source": {"sha256": H64},
    "vm_template": {"name": "tmpl"},
    "hub_login": dict(FIXTURE_LOGIN),
    "registry_program": dict(FIXTURE_REGISTRY),
}


def hosts_doc(lock_root, loop_account=None, l3_account="l3-runner", host_id="host-ident-0001"):
    return {
        "schema": "alpha2.hosts/1",
        "runner": {"host_id": host_id, "lock_root": lock_root,
                   "loop_account": loop_account or ME.pw_name, "l3_account": l3_account},
        "hypervisor": {"name": "hv", "ssh_alias": "hv"},
        "hub": {"name": "hub", "domain": "hub.example.org"},
        "hub_loop": {"name": "hub-t", "domain": "hub-t.example.org", "vm_id": "320"},
        "loop_snapshots": [{"vm": "hub-t", "snaptime": "1795000000"}, {"vm": "vm-a-t", "snaptime": "1795000001"},
                           {"vm": "vm-b-t", "snaptime": "1795000002"}],
        "vms": [
            {"name": "vm-a-t", "scope": "loop", "vm_id": "300", "fleet_domain": "a-t.internal",
             "ssh_alias": "vm-a-t", "agent_account": "agent", "relay_account": "relay",
             "hop_group": "hop", "router": {"slug": "router-a-t", "stable_key": "/srv/agent/.amap-router"}},
            {"name": "vm-b-t", "scope": "loop", "vm_id": "301", "fleet_domain": "b-t.internal",
             "ssh_alias": "vm-b-t", "agent_account": "agent", "relay_account": "relay",
             "hop_group": "hop", "router": {"slug": "router-b-t", "stable_key": "/srv/agent-b/.amap-router"}},
            {"name": "vm-a", "scope": "l3", "vm_id": "310", "fleet_domain": "a.internal",
             "ssh_alias": "vm-a", "agent_account": "agent", "relay_account": "relay",
             "hop_group": "hop", "router": {"slug": "router-a", "stable_key": "/srv/agent-l3/.amap-router"}},
        ],
        "agents": [{"id": "agent-a", "vm": "vm-a-t", "connector": "connector"}],
        "destroy_deny": [],
    }


def dumps(doc):
    return json.dumps(doc, indent=1).encode()


def lock_bytes():
    return dumps(copy.deepcopy(LOCK))


def make_base():
    """A directory whose ancestors no runner account in the tests can write:
    under HOME, never /tmp (world-writable)."""
    base = tempfile.mkdtemp(prefix="a2t-", dir=os.path.expanduser("~"))
    os.chmod(base, 0o755)
    return base


class World:
    """A staged runner host: lock root, lock files, stop.d, budget.d, the
    private files, and a HOME."""

    def __init__(self, base, writes=True):
        self.base = base
        self.root = os.path.join(base, "locks")
        os.mkdir(self.root, 0o755)
        os.chmod(self.root, 0o755)
        self.home = os.path.join(base, "home")
        os.mkdir(self.home, 0o700)
        os.mkdir(os.path.join(self.home, "alpha2-work"), 0o700)
        os.mkdir(os.path.join(self.home, "alpha2-work", "runs"), 0o700)
        self.private = os.path.join(base, "private")
        os.mkdir(self.private, 0o700)
        self.hosts = hosts_doc(self.root)
        self.write_private()
        stop = os.path.join(self.root, "stop.d")
        os.mkdir(stop, 0o755)
        for s in ("operator", "controller", "monitor"):
            os.mkdir(os.path.join(stop, s), 0o755)
        budget = os.path.join(self.root, "budget.d")
        os.mkdir(budget, 0o755)
        for s in ("loop", "l3"):
            os.mkdir(os.path.join(budget, s), 0o755)
            os.chmod(os.path.join(budget, s), 0o755)
        os.chmod(budget, 0o755)
        import a2_locks
        names = [a2_locks.RUNNER_LOCK]
        hv = self.hosts
        tg = [hv["hypervisor"]["name"], hv["hub"]["name"], hv["hub_loop"]["name"], "vm:" + hv["hub_loop"]["vm_id"]]
        for v in hv["vms"]:
            tg += [v["name"], "vm:" + v["vm_id"]]
        names += [a2_locks.target_key(t) + ".lock" for t in tg]
        for n in names:
            p = os.path.join(self.root, n)
            with open(p, "wb"):
                pass
            os.chmod(p, 0o644)

    def write_private(self, lock_raw=None, hosts_raw=None):
        for name, raw in (("alpha2.lock", lock_raw if lock_raw is not None else lock_bytes()),
                          ("alpha2.hosts", hosts_raw if hosts_raw is not None else dumps(self.hosts))):
            p = os.path.join(self.private, name)
            if os.path.exists(p):
                os.chmod(p, 0o600)
            with open(p, "wb") as f:
                f.write(raw)
            os.chmod(p, 0o600)

    def site(self, **over):
        from a2_site import Site
        s = Site()
        s.private_dir = self.private
        s.root_uid = os.getuid()
        home = self.home
        s.getpwuid = lambda uid: pwd.struct_passwd((ME.pw_name, "x", uid, ME.pw_gid, "", home, "/bin/sh"))
        s.environ = {"HOME": home, "PATH": "/usr/bin:/bin", "SSH_AUTH_SOCK": "", "TERM": "xterm"}
        s.host_identity = lambda: "host-ident-0001"
        s.arm_gate = lambda h: ("open", 100000)
        s.loop_tasks = lambda h: "none"
        s.full_run_bound_s = 3600
        # S1 never sees a real terminal in a test: stdin is a pipe and the
        # controlling terminal path does not exist (CREDENTIALS.NO_ECHO),
        # unless a test supplies a pseudo-terminal.
        if not hasattr(self, "_stdin_pipe"):
            self._stdin_pipe = os.pipe()
        s.stdin_fd = self._stdin_pipe[0]
        import io
        s.out = io.StringIO()
        s.tty_path = os.path.join(self.base, "no-such-tty")
        s.usage_path = "b"
        s.fs_type_of = lambda p: "ext4"
        s.account_ids = lambda name: ((99990, {99990}) if name != ME.pw_name else (99991, {99991}))
        s.installer_sha = "c" * 64
        s.entry = os.path.join(INSTALL, "alpha2_install.py")
        s.interpreter = sys.executable
        calls = []
        s.execve = lambda path, args, env: calls.append((path, args, env))
        s.exec_calls = calls
        for k, v in over.items():
            setattr(s, k, v)
        return s


class FakeBroker:
    """Serves one request per connection on <lock_root>/budget.sock and
    writes a start record under budget.d/<sub>/ by the publication rule."""

    def __init__(self, world, sub="loop", answer=None, delay=0.0, started_at=None, close_after_publish=False):
        self.world = world
        self.sub = sub
        self.answer = answer
        self.delay = delay
        self.started_at = started_at
        self.close_after_publish = close_after_publish
        self.requests = []
        self.answers = []
        self.path = os.path.join(world.root, "budget.sock")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.path)
        self.sock.listen(4)
        self.t = threading.Thread(target=self._serve, daemon=True)
        self.t.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                data = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                try:
                    req = json.loads(data)
                except ValueError:
                    # The client closed without a request (it refused first).
                    continue
                self.requests.append(req)
                if set(req) != {"command", "loop", "lock_sha256", "hosts_sha256", "installer_sha256"}:
                    continue
                if self.delay:
                    time.sleep(self.delay)
                if self.answer is not None:
                    try:
                        conn.sendall(self.answer)
                    except OSError:
                        pass
                    continue
                rid = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + os.urandom(4).hex()
                rec = {"kind": "start", "run_id": rid, "command": req["command"], "loop": req["loop"],
                       "started_at": self.started_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "lock_sha256": req["lock_sha256"], "hosts_sha256": req["hosts_sha256"],
                       "installer_sha256": req["installer_sha256"], "permit_id": "-"}
                raw = json.dumps(rec).encode()
                d = os.path.join(self.world.root, "budget.d", self.sub)
                p = os.path.join(d, "start-" + rid + ".json")
                with open(p, "wb") as f:
                    f.write(raw)
                os.chmod(p, 0o644)
                if self.close_after_publish:
                    continue
                self.answers.append((rid, hashlib.sha256(raw).hexdigest()))
                try:
                    conn.sendall(json.dumps({"run_id": rid, "sha256": hashlib.sha256(raw).hexdigest()}).encode())
                except OSError:
                    # The client gave up first (the hung-broker test): its answer is lost.
                    pass

    def close(self):
        """Wake the accept, wait for the thread, then close the socket. A
        socket closed under a blocked accept would leave the thread holding
        a descriptor number the next broker may reuse."""
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.t.join(timeout=10)
        self.sock.close()
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass


def write_record(world, sub, rec, name=None, mode=0o644):
    raw = json.dumps(rec).encode()
    p = os.path.join(world.root, "budget.d", sub, name or ("start-" + rec["run_id"] + ".json"))
    with open(p, "wb") as f:
        f.write(raw)
    os.chmod(p, mode)
    return hashlib.sha256(raw).hexdigest()


def record(run_id, command="install", loop="L2", lock_sha=None, hosts_sha=None,
           installer="c" * 64, started=None):
    return {"kind": "start", "run_id": run_id, "command": command, "loop": loop,
            "started_at": started or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "lock_sha256": lock_sha or H64, "hosts_sha256": hosts_sha or H64,
            "installer_sha256": installer, "permit_id": "-"}


def is_mode(path, mode):
    return stat.S_IMODE(os.lstat(path).st_mode) == mode


# ------------------------------------------------------------- git world

GIT_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0",
           "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.org",
           "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.org",
           "GIT_AUTHOR_DATE": "2026-11-16T00:00:00Z", "GIT_COMMITTER_DATE": "2026-11-16T00:00:00Z"}


def git(repo, *args):
    import subprocess
    p = subprocess.run(["/usr/bin/git", "-c", "init.defaultBranch=main", "-c", "protocol.file.allow=always",
                        "-C", repo] + list(args), env=GIT_ENV, capture_output=True)
    if p.returncode != 0:
        raise RuntimeError("git %r: %s" % (args, p.stderr.decode()[-400:]))
    return p.stdout.decode().strip()


class GitWorld:
    """Remotes with annotated alpha2-rc1 tags, an overlay checkout that is
    the World's private directory, and an installer checkout; the lock is
    written with every pin the S0 checks read."""

    URLS = {"overlay": "ssh://git@git.example.org/amap/private-overlay",
            "router": "ssh://git@git.example.org/amap/router",
            "connector": "https://git.example.org/amap/connector",
            "registry": "ssh://git@git.example.org/amap/registry"}

    def __init__(self, world, tag="alpha2-rc1"):
        import shutil
        import sys
        self.w = world
        self.tag = tag
        self.remotes = os.path.join(world.base, "remotes")
        os.mkdir(self.remotes)
        self.url_map = {}
        commits = {}
        for name in ("router", "connector", "registry"):
            bare = self._bare(name)
            work = os.path.join(world.base, "work-" + name)
            git(world.base, "init", "-q", work)
            with open(os.path.join(work, "README"), "w") as f:
                f.write(name + "\n")
            git(work, "add", "README")
            git(work, "commit", "-q", "-m", "c")
            git(work, "tag", "-a", tag, "-m", tag)
            git(work, "push", "-q", bare, "HEAD:refs/heads/main", "refs/tags/" + tag)
            commits[name] = git(work, "rev-parse", "HEAD")
        # The installer checkout: clean at its commit.
        self.inst = os.path.join(world.base, "installer")
        git(world.base, "init", "-q", self.inst)
        os.mkdir(os.path.join(self.inst, "install"))
        with open(os.path.join(self.inst, "install", "alpha2_install.py"), "w") as f:
            f.write("# stand-in\n")
        git(self.inst, "add", "install")
        git(self.inst, "commit", "-q", "-m", "i")
        self.inst_commit = git(self.inst, "rev-parse", "HEAD")
        # The overlay: hosts at overlay.commit, then the lock, tagged.
        priv = world.private
        for n in os.listdir(priv):
            os.unlink(os.path.join(priv, n))
        git(world.base, "init", "-q", priv)
        world.write_private(hosts_raw=dumps(world.hosts), lock_raw=b"{}")
        os.unlink(os.path.join(priv, "alpha2.lock"))
        git(priv, "add", "alpha2.hosts")
        git(priv, "commit", "-q", "-m", "hosts")
        self.overlay_commit = git(priv, "rev-parse", "HEAD")
        py = "/usr/bin/python3"
        real = os.path.realpath(py)
        lock = copy.deepcopy(LOCK)
        lock["installer"]["commit"] = self.inst_commit
        lock["installer"]["sha256"] = "c" * 64
        lock["interpreter"].update({"sha256": _sha(py), "resolved_path": real,
                                    "resolved_sha256": _sha(real),
                                    "version": "%d.%d.%d" % tuple(sys.version_info[:3])})
        lock["overlay"] = {"repo": self.URLS["overlay"], "commit": self.overlay_commit, "tag": tag}
        for comp in lock["components"]:
            comp["repo"] = self.URLS[comp["name"]]
            comp["commit"] = commits[comp["name"]]
            comp["tag"] = tag
        self.lock = lock
        self.commit_lock(lock)

    def _bare(self, name):
        bare = os.path.join(self.remotes, name + ".git")
        git(self.remotes, "init", "-q", "--bare", bare)
        self.url_map[self.URLS[name]] = bare
        return bare

    def commit_lock(self, lock, tag=None, push_tag=True):
        """Write the lock, commit it, tag that commit and push both."""
        import os as _os
        priv = self.w.private
        self.w.write_private(lock_raw=dumps(lock), hosts_raw=dumps(self.w.hosts))
        git(priv, "add", "alpha2.lock", "alpha2.hosts")
        git(priv, "commit", "-q", "-m", "lock")
        tag = tag or lock["overlay"]["tag"]
        if "overlay" not in self.url_map:
            self._bare("overlay")
        if push_tag:
            git(priv, "tag", "-f", "-a", tag, "-m", tag)
            git(priv, "push", "-q", "-f", self.url_map[self.URLS["overlay"]],
                "HEAD:refs/heads/main", "+refs/tags/" + tag)
        return git(priv, "rev-parse", "HEAD")

    def site_over(self):
        import a2_git
        g = a2_git.Git(a2_git.env_for(self.w.home), protocols=("file",))
        ok = lambda h, scope: "ok"
        return dict(git=g, repo_url_map=dict(self.url_map),
                    entry=os.path.join(self.inst, "install", "alpha2_install.py"),
                    sandbox_mount_roots=(os.path.join(self.w.base, "sandbox-mounts"),),
                    live_deploy_paths=(os.path.join(self.w.base, "live"),),
                    probe_tools=ok, probe_net_runtime=ok, probe_keep_awake=ok,
                    probe_target_access=ok, probe_hub_read=ok, probe_operator_route=ok,
                    probe_survey=ok, probe_placement=lambda h: "match",
                    probe_loop_snapshots=pinned_snapshots, overlay_ssh_config=overlay_ssh)


def overlay_ssh(home, host, port):
    """ssh -G's effective overlay configuration as NET's config_overlay gives it, for any host and port (its
    options sit under `Host *`); shape measured from OpenSSH 10.0's `ssh -G`."""
    return {"user": ["git"], "hostname": [host], "port": [str(port)], "batchmode": ["yes"],
            "identitiesonly": ["yes"], "stricthostkeychecking": ["true"], "hostkeyalias": ["a2-overlay"],
            "identityagent": ["none"], "forwardagent": ["no"],
            "userknownhostsfile": [home + "/.ssh/known_hosts_overlay"],
            "identityfile": [home + "/.ssh/id_a2_loop_overlay"]}


def pinned_snapshots(hosts, names):
    """A `snapshots` read that agrees with the hosts document: every member at its pinned snaptime, its base
    snapshot the current parent and the only one."""
    pinned = {e["vm"]: int(e["snaptime"]) for e in hosts["loop_snapshots"]}
    return {n: {"snaptime": pinned[n], "current_parent": True, "only": True} for n in names}


def _sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()
