"""A runtime's secret file on a hop deployment's host: the `secrets` section
of the host-setup document, the root-run steps it adds to the plan, and the
checks of the host against it. NOTHING HERE READS THE SECRET OR APPLIES
ANYTHING: the plan is printed for the operator, and every check is stat,
inspect, listing or a tool's own report.

The secret lives in a container-engine named volume, so its owner and mode
are the engine's own (Linux) and no host file-sharing layer is in the
runtime's read path. The volume holds one file, 0400, owned by the runtime's
uid, in a 0700 root owned by that uid; it is written only by the pinned
writer (`host_steps.py secret`), run in a one-shot container from a pipe.

What the section names, all operator data (nothing here knows a runtime's
names or paths):
- the volume, its role label, the principal that owns it and whose runtime
  mounts it, the file's name, the container directory it is mounted at,
  and the runtime image by digest;
- the writer: the root-owned directory holding the pinned `host_steps.py`,
  its sha256 and the commit it came from;
- the anchor (the reviewed overlay's sha, written by the operator alone) and
  the state file (`pending_b5`, `active` or `retired`), both root-owned 0444;
- the fresh clones the tooling runs from, each at a recorded sha (the
  overlay's own sha is the anchor's);
- `tools`: the absolute path of every executable the checks and the runbook
  run, so nothing is found through PATH;
- uv's binary, cache and interpreter directories; the status and run
  directories; the hub ssh config, its pinned known_hosts and the alias.

What it checks, through router_health's three outcomes:
- the writer: root-owned 0444, one link, every ancestor root-owned and not
  group- or world-writable, and its bytes hash to the pin;
- the anchor and the state file: the same ownership, and a well-formed value;
- each clone: operator-owned 0700, HEAD at its recorded sha, no hook that
  can run, and no change or ignored file in the tree, asked with system and
  user git configuration ignored;
- each tool: a regular executable file, its real path and every ancestor
  owned by root or the operator and not group- or world-writable;
- the uv, status and run directories, and the lock file;
- the hub's host key pinned in the known_hosts under the alias, and ssh's
  effective host-key checking strict in the producer's own option order;
- the volume's entries, by lstat in a one-shot container, against the state;
- the host's core-dump settings, which no container limit covers;
- the weekly probe's status, in the `active` state: the document
  host_steps' probe-weekly writes, {class, smtp_code, at, run_id,
  previous_class, last_ok_at}, every member required.
"""

import json
import os
import posixpath
import re
import stat
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import router_health as rh

SECTION = "secrets"
STATES = ("pending_b5", "active", "retired")
FILE_MODE = 0o400
ROOT_MODE = 0o700
PINNED_MODE = 0o444
LOCK_MODE = 0o600
KNOWN_HOSTS_MODE = 0o400
#: The writer's file name inside its directory, and where the one-shot
#: containers mount that directory and the volume.
WRITER = "host_steps.py"
IN_WRITER = "/w"
IN_VOLUME = "/v"
LOCK_FILE = "oneshot.lock"
#: Every tool the checks run; the runbook's own tools are the document's too.
REQUIRED_TOOLS = ("git", "docker", "python3", "ssh", "ssh-keygen")
CLONE_ROLES = ("deploy", "overlay", "producer", "runtime")
#: The weekly probe's status: older than this is a job that did not run, and
#: a last pass older than the second is a problem whatever the last class.
STATUS_MAX_AGE_S = 8 * 86400
LAST_OK_MAX_AGE_S = 15 * 86400
PROBE_CLASSES_NOT_FAILURES = ("ok", "engine_unavailable", "hub_unreachable", "tls_failed",
                              "connect_failed", "temporary")
_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_IMAGE = re.compile(r"[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}")
_LABEL = re.compile(r"[a-z0-9][a-z0-9._-]*=[A-Za-z0-9._-]+")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
#: The weekly job's run id, as host_steps' probe-weekly checks it.
_RUN_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")


class SecretSpecError(ValueError):
    """The secrets section is unusable."""


@dataclass(frozen=True)
class SecretSpec:
    volume: str
    label: str
    uid: int
    gid: int
    file: str
    container_dir: str
    image: str
    writer_dir: str
    writer_sha256: str
    writer_commit: str
    anchor: str
    state_file: str
    clones: Dict[str, Dict[str, str]]       # role -> {path, sha?}; overlay's sha is the anchor
    tools: Dict[str, str]
    uv: Dict[str, str]                      # binary, cache_dir, python_dir
    status_dir: str
    run_dir: str
    ssh: Dict[str, str]                     # config, known_hosts, alias
    operator_uid: int
    docker_via_sudo: bool
    extra: Dict[str, Any]                   # caps_allow, attestations: read by the exposure checks

    @property
    def writer(self) -> str:
        return posixpath.join(self.writer_dir, WRITER)


def _abs(p: Any, what: str) -> str:
    if not isinstance(p, str) or not p.startswith("/") or posixpath.normpath(p) != p \
            or p.startswith("//") or p == "/":
        raise SecretSpecError(f"secrets.{what} must be an absolute, normalised path")
    return p


def _exact(d: Any, keys: Sequence[str], what: str, optional: Sequence[str] = ()) -> Dict[str, Any]:
    if not isinstance(d, dict) or not set(keys) <= set(d) or set(d) - set(keys) - set(optional):
        extra = f", and optionally {', '.join(optional)}" if optional else ""
        raise SecretSpecError(f"secrets.{what} must have {', '.join(keys)}{extra}")
    return d


def load(sec: Any, principals: Dict[str, Any], runtimes: Sequence[Dict[str, Any]]) -> SecretSpec:
    """Parse and validate the section. Refuses rather than guesses: an unknown
    member, a principal with no runtime to mount the volume, a relative path,
    a tag where a digest belongs, a clone without its sha, a tool missing."""
    keys = ("volume", "label", "principal", "file", "container_dir", "image", "writer", "anchor",
            "state_file", "clones", "tools", "uv", "status_dir", "run_dir", "ssh", "operator_uid")
    sec = _exact(sec, keys, "(the section)", ("docker_via_sudo", "caps_allow", "attestations"))
    if not isinstance(sec["volume"], str) or not _NAME.fullmatch(sec["volume"]):
        raise SecretSpecError("secrets.volume must be a volume name")
    if not isinstance(sec["label"], str) or not _LABEL.fullmatch(sec["label"]):
        raise SecretSpecError("secrets.label must be key=value")
    if sec["principal"] not in principals:
        raise SecretSpecError(f"secrets.principal {sec['principal']!r} is not a declared principal")
    if not any(r["principal"] == sec["principal"] for r in runtimes):
        raise SecretSpecError(f"secrets.principal {sec['principal']} has no runtime to mount the volume")
    owner = principals[sec["principal"]]
    if not isinstance(sec["file"], str) or not _NAME.fullmatch(sec["file"]):
        raise SecretSpecError("secrets.file must be one file name")
    if not isinstance(sec["image"], str) or not _IMAGE.fullmatch(sec["image"]):
        raise SecretSpecError("secrets.image must be the runtime image by digest (name@sha256:...)")
    w = _exact(sec["writer"], ("dir", "sha256", "commit"), "writer")
    if not isinstance(w["sha256"], str) or not _HEX64.fullmatch(w["sha256"]):
        raise SecretSpecError("secrets.writer.sha256 must be 64 lower-case hex digits")
    if not isinstance(w["commit"], str) or not _HEX40.fullmatch(w["commit"]):
        raise SecretSpecError("secrets.writer.commit must be a full commit sha")
    clones = {}
    if not isinstance(sec["clones"], dict) or set(sec["clones"]) != set(CLONE_ROLES):
        raise SecretSpecError(f"secrets.clones must name exactly {', '.join(CLONE_ROLES)}")
    for role, c in sec["clones"].items():
        if role == "overlay":
            c = _exact(c, ("path",), f"clones.{role}")
            clones[role] = {"path": _abs(c["path"], f"clones.{role}.path")}
            continue
        c = _exact(c, ("path", "sha"), f"clones.{role}")
        if not isinstance(c["sha"], str) or not _HEX40.fullmatch(c["sha"]):
            raise SecretSpecError(f"secrets.clones.{role}.sha must be a full commit sha")
        clones[role] = {"path": _abs(c["path"], f"clones.{role}.path"), "sha": c["sha"]}
    tools = sec["tools"]
    if not isinstance(tools, dict) or set(REQUIRED_TOOLS) - set(tools):
        raise SecretSpecError(f"secrets.tools must give at least {', '.join(REQUIRED_TOOLS)}")
    tools = {name: _abs(path, f"tools.{name}") for name, path in tools.items()}
    uv = _exact(sec["uv"], ("binary", "cache_dir", "python_dir"), "uv")
    if "uv" in tools and tools["uv"] != uv.get("binary"):
        raise SecretSpecError("secrets.tools.uv and secrets.uv.binary name different binaries")
    ssh = _exact(sec["ssh"], ("config", "known_hosts", "alias"), "ssh")
    if not isinstance(ssh["alias"], str) or not _ALIAS.fullmatch(ssh["alias"]):
        raise SecretSpecError("secrets.ssh.alias must be an ssh host alias")
    via_sudo = sec.get("docker_via_sudo", False)
    if not isinstance(via_sudo, bool):
        raise SecretSpecError("secrets.docker_via_sudo must be true or false")
    if via_sudo and "sudo" not in tools:
        raise SecretSpecError("secrets.docker_via_sudo needs tools.sudo")
    op = sec["operator_uid"]
    if isinstance(op, bool) or not isinstance(op, int) or op <= 0:
        raise SecretSpecError("secrets.operator_uid must be the operator's (non-root) uid")
    return SecretSpec(
        volume=sec["volume"], label=sec["label"], uid=owner.uid, gid=owner.gids[0],
        file=sec["file"], container_dir=_abs(sec["container_dir"], "container_dir"),
        image=sec["image"], writer_dir=_abs(w["dir"], "writer.dir"), writer_sha256=w["sha256"],
        writer_commit=w["commit"], anchor=_abs(sec["anchor"], "anchor"),
        state_file=_abs(sec["state_file"], "state_file"), clones=clones, tools=tools,
        uv={k: _abs(uv[k], f"uv.{k}") for k in ("binary", "cache_dir", "python_dir")},
        status_dir=_abs(sec["status_dir"], "status_dir"), run_dir=_abs(sec["run_dir"], "run_dir"),
        ssh={"config": _abs(ssh["config"], "ssh.config"),
             "known_hosts": _abs(ssh["known_hosts"], "ssh.known_hosts"), "alias": ssh["alias"]},
        operator_uid=op, docker_via_sudo=via_sudo,
        extra={k: sec[k] for k in ("caps_allow", "attestations") if k in sec})


# --- The plan -------------------------------------------------------------------


def docker(s: SecretSpec) -> List[str]:
    """The docker client, by its recorded path, through `sudo -n` where the
    operator's account reaches the engine only that way."""
    if s.docker_via_sudo:
        return [s.tools["sudo"], "-n", s.tools["docker"]]
    return [s.tools["docker"]]


def oneshot(s: SecretSpec, role: str, run_id: str, *, user: str, rw: bool, caps: Sequence[str] = (),
            stdin: bool = False) -> List[str]:
    """A one-shot container in the reviewed shape: the pinned image, no pull,
    no network, no log, a read-only root, no core, no new privileges, every
    capability dropped but `caps`, the volume (no copy from the image) and
    the writer directory read-only."""
    vol = f"type=volume,src={s.volume},dst={IN_VOLUME},volume-nocopy" + ("" if rw else ",readonly")
    argv = docker(s) + ["run", "--rm"] + (["-i"] if stdin else []) + [
        "--pull", "never", "--log-driver", "none", "--network", "none", "--read-only",
        "--ulimit", "core=0", "--security-opt", "no-new-privileges", "--user", user,
        "--cap-drop", "ALL"]
    for c in caps:
        argv += ["--cap-add", c]
    argv += ["--label", f"org.amap.oneshot={role}", "--label", f"org.amap.run={run_id}",
             "--mount", vol, "--mount", f"type=bind,src={s.writer_dir},dst={IN_WRITER},readonly",
             s.image, "python3", "-I", "-S", posixpath.join(IN_WRITER, WRITER)]
    return argv


def locked(s: SecretSpec, argv: List[str]) -> List[str]:
    """`argv` under the run directory's lock, through the pinned writer's own
    `lock`, run by the recorded python3."""
    return [s.tools["python3"], "-I", "-S", s.writer, "lock", s.run_dir, "--"] + argv


WRITER_CAPS = ("CHOWN", "FOWNER", "DAC_OVERRIDE")


def render(s: SecretSpec, q: Callable[[str], str]) -> List[str]:
    """The secret's root-run steps, as shell lines, in order. Printed, never run."""
    t = s.tools
    hash_tool = t.get("sha256sum") or t.get("shasum")
    hash_cmd = (q(hash_tool) + (" -a 256" if hash_tool == t.get("shasum") else "")) if hash_tool \
        else "<the recorded sha256 tool>"
    install = q(t["install"]) if "install" in t else "install"
    sudo = q(t["sudo"]) if "sudo" in t else "sudo"
    etc = posixpath.dirname(s.anchor)
    lines = [
        "# The runtime's secret file. The anchor is the operator's alone: the reviewed overlay's sha, "
        "copied from its approval record.",
        f"{sudo} {install} -d -o 0 -g 0 -m 0755 {q(etc)}",
        f"{sudo} {install} -o 0 -g 0 -m 0444 <a file holding the approved overlay sha> {q(s.anchor)}",
        f"# The writer, never by running the file being installed: its sha256 must be {s.writer_sha256}.",
        f"{hash_cmd} {q(posixpath.join(s.clones['deploy']['path'], WRITER))}",
        f"{sudo} {install} -d -o 0 -g 0 -m 0755 {q(s.writer_dir)}",
        f"{sudo} {install} -o 0 -g 0 -m 0444 {q(posixpath.join(s.clones['deploy']['path'], WRITER))} "
        f"{q(s.writer)}",
        f"{hash_cmd} {q(s.writer)}",
        "# The volume and its root, owned by the runtime's uid, 0700, made in a one-shot container.",
        " ".join(q(a) for a in docker(s)) + f" volume create --label {q(s.label)} {q(s.volume)}",
        " ".join(q(a) for a in oneshot(s, "root", "<run-id>", user="0:0", rw=True, caps=WRITER_CAPS))
        + f" root {IN_VOLUME} {s.uid} {s.gid} {ROOT_MODE:04o}",
        "# As the operator: the lock file the one-shots and verify share.",
        f"{install} -d -m 0700 {q(s.run_dir)}",
        f"{install} -m 0600 /dev/null {q(posixpath.join(s.run_dir, LOCK_FILE))}",
        f"# The state, until the secret is written: {STATES[0]}.",
        f"printf '{STATES[0]}\\n' | {sudo} {install} -o 0 -g 0 -m 0444 /dev/stdin {q(s.state_file)}",
    ]
    return lines


# --- Verify ---------------------------------------------------------------------


def _fact(name: str, value: Any, provenance: str) -> rh.Fact:
    return rh.Fact(name, value, provenance)


def _lst(path: str, lstat: Callable) -> Any:
    try:
        return lstat(path)
    except FileNotFoundError:
        return None
    except OSError as e:
        return rh.Unresolved(f"cannot inspect {path}: {e}")


def _ancestors(path: str) -> List[str]:
    out, p = [], posixpath.dirname(path)
    while True:
        out.append(p)
        if p == "/":
            return out
        p = posixpath.dirname(p)


def _no_write_by_others(st) -> bool:
    return not (stat.S_IMODE(st.st_mode) & 0o022)


def _owned_chain(claim: str, path: str, owners: Sequence[int], why: str, lstat: Callable) -> rh.Check:
    """Every ancestor of `path` is a real directory owned by one of `owners`
    and not writable by group or world."""
    want = _fact("ancestors", True, why)
    remedy = f"make every directory above {path} owned by {' or '.join(map(str, owners))} " \
             f"and not group- or world-writable"
    for d in _ancestors(path):
        st = _lst(d, lstat)
        if isinstance(st, rh.Unresolved):
            return rh.unknown(claim, want, st.reason, remedy)
        if st is None or not stat.S_ISDIR(st.st_mode) or st.st_uid not in owners \
                or not _no_write_by_others(st):
            return rh.check(claim, want, f"{d} is not", remedy,
                            do_not="never loosen this to let a tool run")
    return rh.check(claim, want, True, remedy)


def _pinned_file(claim: str, path: str, why: str, lstat: Callable) -> rh.Check:
    want = _fact("pinned file", (0, 0, PINNED_MODE, 1), why)
    remedy = f"install {path} as root:root 0444 (`install -o 0 -g 0 -m 0444`)"
    st = _lst(path, lstat)
    if isinstance(st, rh.Unresolved):
        return rh.unknown(claim, want, st.reason, remedy)
    if st is None or not stat.S_ISREG(st.st_mode):
        return rh.check(claim, want, "absent" if st is None else "not a regular file", remedy)
    return rh.check(claim, want, (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_nlink), remedy,
                    do_not="never make it writable to update it; install a new one")


def _read_small(path: str, read: Callable[[str], Any]) -> Any:
    try:
        return read(path)
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError) as e:
        return rh.Unresolved(f"cannot read {path}: {e}")


def _read_text(path: str) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        return f.read(65536).decode("utf-8")


def anchor_sha(s: SecretSpec, read: Callable[[str], Any] = _read_text) -> Any:
    """The anchored overlay sha, or None (absent), or an Unresolved."""
    text = _read_small(s.anchor, read)
    if text is None or isinstance(text, rh.Unresolved):
        return text
    sha = text.strip()
    return sha if _HEX40.fullmatch(sha) else rh.Unresolved(f"{s.anchor} does not hold a commit sha")


def state(s: SecretSpec, read: Callable[[str], Any] = _read_text) -> Any:
    """The recorded state, or an Unresolved: a missing, unreadable or unknown
    state is never guessed."""
    text = _read_small(s.state_file, read)
    if text is None:
        return rh.Unresolved(f"{s.state_file} is absent")
    if isinstance(text, rh.Unresolved):
        return text
    word = text.strip()
    return word if word in STATES else rh.Unresolved(f"{s.state_file} holds no known state")


def verify_pins(s: SecretSpec, lstat: Callable, digest: Callable[[str], Any],
                read: Callable[[str], Any]) -> List[rh.Check]:
    out = []
    why = "the writer runs as root inside the one-shot with the secret on stdin"
    out.append(_pinned_file(f"the writer {s.writer} is root:root 0444 with one link", s.writer, why, lstat))
    out.append(_owned_chain(f"every directory above {s.writer} is root-owned and not group- or "
                            f"world-writable", s.writer, (0,), why, lstat))
    got = digest(s.writer)
    want = _fact("writer sha256", s.writer_sha256, f"the reviewed commit {s.writer_commit}")
    claim = f"{s.writer} hashes to its pin"
    remedy = "install the reviewed host_steps.py again (`place SRC DEST --sha256 <pin>`)"
    out.append(rh.unknown(claim, want, got.reason, remedy) if isinstance(got, rh.Unresolved)
               else rh.check(claim, want, got, remedy, do_not="never change the pin to match the file"))
    for path, what in ((s.anchor, "the anchor"), (s.state_file, "the state file")):
        why = f"{what} decides what every other check trusts; only root may change it"
        out.append(_pinned_file(f"{what} {path} is root:root 0444 with one link", path, why, lstat))
        out.append(_owned_chain(f"every directory above {path} is root-owned and not group- or "
                                f"world-writable", path, (0,), why, lstat))
    a = anchor_sha(s, read)
    claim = f"{s.anchor} holds the reviewed overlay's commit sha"
    want = _fact("anchor", True, "written by the operator from the gate's approval record")
    remedy = f"write the approved sha to {s.anchor} (the operator's step alone)"
    out.append(rh.unknown(claim, want, a.reason, remedy) if isinstance(a, rh.Unresolved)
               else rh.check(claim, want, a is not None, remedy))
    st_ = state(s, read)
    claim = f"{s.state_file} holds one of {', '.join(STATES)}"
    want = _fact("state", True, "the runbook writes it at setup, after the secret is written, and at retire")
    remedy = f"write {STATES[0]}, {STATES[1]} or {STATES[2]} to {s.state_file} as the runbook does"
    out.append(rh.unknown(claim, want, st_.reason, remedy) if isinstance(st_, rh.Unresolved)
               else rh.check(claim, want, True, remedy))
    return out


def _git(s: SecretSpec, path: str, *args: str) -> Any:
    """git in `path` with system and user configuration ignored and no hook or
    fsmonitor able to run: stdout, or an Unresolved."""
    try:
        p = rh.run([s.tools["git"], "-C", path, "-c", "core.hooksPath=/dev/null",
                    "-c", "core.fsmonitor=false", *args],
                   extra_env={"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"})
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    if p.rc != 0:
        return rh.Unresolved(f"git {' '.join(args)} in {path} exited {p.rc}: {p.err.strip()[:200]}")
    return p.out


def verify_clones(s: SecretSpec, lstat: Callable, read: Callable[[str], Any],
                  listdir: Callable[[str], List[str]] = os.listdir) -> List[rh.Check]:
    out = []
    anchored = anchor_sha(s, read)
    for role in CLONE_ROLES:
        path = s.clones[role]["path"]
        why = f"the {role} clone: code or pins the operator runs with docker or root authority"
        st = _lst(path, lstat)
        claim = f"the {role} clone {path} is a directory owned by the operator, mode 0700"
        want = _fact("clone dir", (s.operator_uid, ROOT_MODE), why)
        remedy = f"make a fresh clone at {path} as the runbook does (hooks off, HEAD verified)"
        if isinstance(st, rh.Unresolved):
            out.append(rh.unknown(claim, want, st.reason, remedy))
            continue
        if st is None or not stat.S_ISDIR(st.st_mode):
            out.append(rh.check(claim, want, "absent" if st is None else "not a directory", remedy))
            continue
        out.append(rh.check(claim, want, (st.st_uid, stat.S_IMODE(st.st_mode)), remedy))
        sha = anchored if role == "overlay" else s.clones[role]["sha"]
        head = _git(s, path, "rev-parse", "HEAD")
        claim = f"the {role} clone's HEAD is its reviewed commit"
        prov = "the anchor" if role == "overlay" else "the anchored overlay"
        if isinstance(sha, rh.Unresolved) or sha is None:
            out.append(rh.unknown(claim, _fact("HEAD", None, prov),
                                  getattr(sha, "reason", f"{s.anchor} is absent"), remedy))
        elif isinstance(head, rh.Unresolved):
            out.append(rh.unknown(claim, _fact("HEAD", sha, prov), head.reason, remedy))
        else:
            out.append(rh.check(claim, _fact("HEAD", sha, prov), head.strip(), remedy,
                                do_not="never check out another commit in place; make a fresh clone"))
        dirty = _git(s, path, "status", "--porcelain", "--ignored")
        claim = f"the {role} clone has no change and no ignored file"
        want = _fact("clean", "", "a planted file (a .pyc, a hook) would run with the tooling")
        out.append(rh.unknown(claim, want, dirty.reason, remedy) if isinstance(dirty, rh.Unresolved)
                   else rh.check(claim, want, dirty.strip(), remedy))
        hooks = posixpath.join(path, ".git", "hooks")
        try:
            live = sorted(n for n in listdir(hooks) if not n.endswith(".sample"))
        except FileNotFoundError:
            live = []
        except OSError as e:
            live = rh.Unresolved(f"cannot list {hooks}: {e}")
        claim = f"the {role} clone holds no hook that could run"
        want = _fact("hooks", [], "every git call ignores hooks; none may be there to find")
        out.append(rh.unknown(claim, want, live.reason, remedy) if isinstance(live, rh.Unresolved)
                   else rh.check(claim, want, live, remedy))
    return out


def verify_tools(s: SecretSpec, lstat: Callable,
                 realpath: Callable[[str], str] = os.path.realpath) -> List[rh.Check]:
    out = []
    owners = (0, s.operator_uid)
    every = dict(s.tools)
    every.setdefault("uv", s.uv["binary"])
    for name, path in sorted(every.items()):
        why = f"{name} runs with docker or root authority in the runbook or verify"
        real = realpath(path)
        st = _lst(real, lstat)
        claim = f"the {name} tool {path} is a regular executable file owned by root or the operator"
        want = _fact("tool", True, why)
        remedy = f"record a {name} owned by root (a system one), or fix {real}'s owner and mode"
        if isinstance(st, rh.Unresolved):
            out.append(rh.unknown(claim, want, st.reason, remedy))
            continue
        ok = st is not None and stat.S_ISREG(st.st_mode) and bool(st.st_mode & 0o111) \
            and st.st_uid in owners and _no_write_by_others(st)
        out.append(rh.check(claim, want, ok, remedy, do_not="never record a tool that an agent could write"))
        out.append(_owned_chain(f"every directory above {real} is owned by root or the operator and "
                                f"not group- or world-writable", real, owners, why, lstat))
    return out


def _dir(claim: str, path: str, owner: Sequence[int], mode: Optional[int], why: str,
         lstat: Callable) -> rh.Check:
    want = _fact("directory", True, why)
    remedy = f"create {path} as the plan does"
    st = _lst(path, lstat)
    if isinstance(st, rh.Unresolved):
        return rh.unknown(claim, want, st.reason, remedy)
    ok = st is not None and stat.S_ISDIR(st.st_mode) and st.st_uid in owner \
        and (stat.S_IMODE(st.st_mode) == mode if mode is not None else _no_write_by_others(st))
    return rh.check(claim, want, ok, remedy)


def verify_dirs(s: SecretSpec, lstat: Callable) -> List[rh.Check]:
    op = (s.operator_uid,)
    out = [
        _dir(f"uv's cache {s.uv['cache_dir']} is the operator's, 0700", s.uv["cache_dir"], op, ROOT_MODE,
             "the producer's dependencies come from it", lstat),
        _dir(f"uv's interpreters {s.uv['python_dir']} are the operator's, 0700", s.uv["python_dir"], op,
             ROOT_MODE, "the producer's interpreter comes from it", lstat),
        _dir(f"the run directory {s.run_dir} is the operator's, 0700", s.run_dir, op, ROOT_MODE,
             "it holds the one-shots' lock", lstat),
        _dir(f"the status directory {s.status_dir} is root's and not group- or world-writable",
             s.status_dir, (0,), None, "the weekly probe's result is read from it", lstat),
    ]
    lock = posixpath.join(s.run_dir, LOCK_FILE)
    st = _lst(lock, lstat)
    claim = f"the lock file {lock} is a regular file owned by the operator, 0600"
    want = _fact("lock file", (s.operator_uid, LOCK_MODE), "made by the plan; `lock` never creates it")
    remedy = f"create {lock} as the plan does"
    if isinstance(st, rh.Unresolved):
        out.append(rh.unknown(claim, want, st.reason, remedy))
    elif st is None or not stat.S_ISREG(st.st_mode):
        out.append(rh.check(claim, want, "absent" if st is None else "not a regular file", remedy))
    else:
        out.append(rh.check(claim, want, (st.st_uid, stat.S_IMODE(st.st_mode)), remedy))
    return out


def verify_ssh(s: SecretSpec, lstat: Callable) -> List[rh.Check]:
    out = []
    kh, cfg, alias = s.ssh["known_hosts"], s.ssh["config"], s.ssh["alias"]
    st = _lst(kh, lstat)
    claim = f"the pinned known_hosts {kh} is the operator's, 0400"
    want = _fact("known_hosts", (s.operator_uid, KNOWN_HOSTS_MODE), "nothing may append a key to it")
    remedy = f"pre-populate {kh} with the hub's key under {alias}, then chmod 0400"
    if isinstance(st, rh.Unresolved):
        out.append(rh.unknown(claim, want, st.reason, remedy))
    elif st is None or not stat.S_ISREG(st.st_mode):
        out.append(rh.check(claim, want, "absent" if st is None else "not a regular file", remedy))
    else:
        out.append(rh.check(claim, want, (st.st_uid, stat.S_IMODE(st.st_mode)), remedy))
    claim = f"the hub's host key is pinned under {alias}"
    want = _fact("pinned key", True, "with it absent, a first connection would trust whatever answers")
    try:
        p = rh.run([s.tools["ssh-keygen"], "-F", alias, "-f", kh])
        found = p.rc == 0 and bool(p.out.strip())
        out.append(rh.check(claim, want, found, remedy))
    except rh.CannotRun as e:
        out.append(rh.unknown(claim, want, str(e), remedy))
    claim = "ssh's effective host-key checking is strict, in the producer's own option order"
    want = _fact("stricthostkeychecking", "true",
                 "ssh takes the first value; the producer appends accept-new after ours")
    remedy = "put -o StrictHostKeyChecking=yes FIRST in the producer's ssh command"
    try:
        p = rh.run([s.tools["ssh"], "-G", "-F", cfg, "-o", "StrictHostKeyChecking=yes",
                    "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", alias])
    except rh.CannotRun as e:
        out.append(rh.unknown(claim, want, str(e), remedy))
        return out
    if p.rc != 0:
        out.append(rh.unknown(claim, want, f"ssh -G exited {p.rc}", remedy))
        return out
    value = next((line.split(None, 1)[1].strip() for line in p.out.splitlines()
                  if line.lower().startswith("stricthostkeychecking ")), None)
    out.append(rh.check(claim, want, value, remedy))
    return out


def ask_volume(s: SecretSpec, run_id: str) -> Any:
    """The volume's metadata from a one-shot container under the lock, by
    lstat alone: a dict, or an Unresolved."""
    argv = locked(s, oneshot(s, "stat", run_id, user=f"{s.uid}:{s.gid}", rw=False)
                  + ["stat-secret", IN_VOLUME])
    try:
        p = rh.run(argv)
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    if p.rc != 0:
        return rh.Unresolved(f"the stat one-shot exited {p.rc}: {p.out.strip()[:120]}")
    try:
        doc = json.loads(p.out)
    except ValueError:
        return rh.Unresolved("the stat one-shot printed something other than one JSON line")
    return doc if isinstance(doc, dict) else rh.Unresolved("the stat one-shot's JSON is not an object")


def verify_volume(s: SecretSpec, st_: Any, seen: Any) -> List[rh.Check]:
    """The volume's entries against the recorded state."""
    claim = f"the volume {s.volume} holds what the state says"
    remedy_b5 = "write the secret through the runbook's pipeline"
    if isinstance(st_, rh.Unresolved):
        return [rh.unknown(claim, _fact("state", None, s.state_file), st_.reason,
                           f"record the state in {s.state_file}")]
    if isinstance(seen, rh.Unresolved):
        return [rh.unknown(claim, _fact("state", st_, s.state_file), seen.reason,
                           "start the engine and run verify again")]
    out = []
    root = (seen.get("uid"), seen.get("gid"), seen.get("mode"))
    want = _fact("volume root", (s.uid, s.gid, f"{ROOT_MODE:04o}"), "the plan's volume root step")
    out.append(rh.check(f"the volume {s.volume}'s root is owned by {s.uid}:{s.gid}, mode 0700",
                        want, root, "run the plan's volume root step"))
    entries = seen.get("entries") if isinstance(seen.get("entries"), list) else []
    names = [e.get("name") for e in entries if isinstance(e, dict)]
    if st_ == "active":
        want = _fact("entries", [s.file], f"{s.state_file} says active")
        out.append(rh.check(f"the volume holds exactly {s.file}", want, names,
                            remedy_b5 if not names else "remove the stray entry with `secret-remove`, "
                            "then write the secret again", do_not="never open a stray entry; never copy "
                            "the value from another host or a pane"))
        mine = next((e for e in entries if isinstance(e, dict) and e.get("name") == s.file), None)
        if mine is not None:
            got = (mine.get("regular"), mine.get("uid"), mine.get("gid"), mine.get("mode"),
                   mine.get("nlink"), mine.get("nonempty"))
            want = _fact("secret file", (True, s.uid, s.gid, f"{FILE_MODE:04o}", 1, True),
                         "the writer's step 7")
            out.append(rh.check(f"{s.file} is a regular file owned by {s.uid}:{s.gid}, 0400, one link, "
                                f"not empty", want, got, remedy_b5))
    else:
        want = _fact("entries", [], f"{s.state_file} says {st_}")
        remedy = remedy_b5 + ", then record active" if st_ == "pending_b5" else "remove it with `secret-remove`"
        out.append(rh.check(f"the volume holds nothing in the {st_} state", want, names, remedy,
                            do_not="never open an entry to see what it is"))
    return out


def verify_core(s: SecretSpec, platform: str, read: Callable[[str], Any]) -> List[rh.Check]:
    """No root service that relays the value may leave a persistent core."""
    out = []
    if platform.startswith("linux"):
        pattern = _read_small("/proc/sys/kernel/core_pattern", read)
        claim = "the kernel hands every core to systemd-coredump"
        want = _fact("core_pattern", True, "a pipe to systemd-coredump, whose storage is then set to none")
        remedy = "install systemd-coredump and remove apport, so core_pattern pipes to it"
        if isinstance(pattern, rh.Unresolved) or pattern is None:
            out.append(rh.unknown(claim, want, getattr(pattern, "reason", "core_pattern is absent"), remedy))
        else:
            p = pattern.strip()
            out.append(rh.check(claim, want, p.startswith("|") and "systemd-coredump" in p, remedy))
        claim = "systemd-coredump stores nothing"
        want = _fact("Storage", "none", "a crashing sshd, dockerd or shim holds the value in memory")
        remedy = "set Storage=none in a coredump.conf drop-in"
        tool = s.tools.get("systemd-analyze")
        if tool is None:
            out.append(rh.unknown(claim, want, "tools has no systemd-analyze to ask", remedy))
            return out
        try:
            p = rh.run([tool, "cat-config", "systemd/coredump.conf"])
        except rh.CannotRun as e:
            out.append(rh.unknown(claim, want, str(e), remedy))
            return out
        if p.rc != 0:
            out.append(rh.unknown(claim, want, f"systemd-analyze exited {p.rc}", remedy))
            return out
        value = None
        for line in p.out.splitlines():
            line = line.strip()
            if line.startswith("Storage="):
                value = line.split("=", 1)[1].strip()
        out.append(rh.check(claim, want, value, remedy))
        return out
    claim = "the kernel writes no core files (kern.coredump=0)"
    want = _fact("kern.coredump", "0", "a crashing root service holds the value in memory")
    remedy = "run `sudo sysctl kern.coredump=0` before each write or rotation"
    tool = s.tools.get("sysctl")
    if tool is None:
        return [rh.unknown(claim, want, "tools has no sysctl to ask", remedy)]
    try:
        p = rh.run([tool, "-n", "kern.coredump"])
    except rh.CannotRun as e:
        return [rh.unknown(claim, want, str(e), remedy)]
    if p.rc != 0:
        return [rh.unknown(claim, want, f"sysctl exited {p.rc}", remedy)]
    return [rh.check(claim, want, p.out.strip(), remedy)]


STATUS_FILE = "hub-probe.json"


def verify_status(s: SecretSpec, st_: Any, read: Callable[[str], Any], now: float) -> List[rh.Check]:
    """The weekly probe's last result, in the active state only: nothing is
    probed before the secret exists, and nothing after it is retired."""
    if st_ != "active":
        return []
    path = posixpath.join(s.status_dir, STATUS_FILE)
    claim = "the weekly probe has run within 8 days and its last result is not a problem"
    want = _fact("status", True, "the router-side probe is the only detector of an out-of-step pair")
    remedy = "run the weekly probe job; on auth_failed, the pair is out of step: write the secret again"
    text = _read_small(path, read)
    if text is None or isinstance(text, rh.Unresolved):
        return [rh.unknown(claim, want, getattr(text, "reason", f"{path} is absent"), remedy)]
    try:
        doc = json.loads(text)
        cls, at, run_id = doc["class"], doc["at"], doc["run_id"]
        last_ok, prev = doc["last_ok_at"], doc["previous_class"]
        if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
            raise ValueError("run_id")
    except (ValueError, KeyError, TypeError):
        return [rh.unknown(claim, want, f"{path} is not the probe job's status (class, smtp_code, at, "
                           f"run_id, previous_class, last_ok_at)", remedy)]
    out = [rh.check(claim, want, isinstance(at, int) and now - at <= STATUS_MAX_AGE_S
                    and cls in PROBE_CLASSES_NOT_FAILURES, remedy)]
    out.append(rh.check("the probe has passed within 15 days", _fact("last_ok_at", True,
                        "a pair that has not authenticated for two weeks is presumed broken"),
                        isinstance(last_ok, int) and now - last_ok <= LAST_OK_MAX_AGE_S, remedy))
    out.append(rh.check("the probe has not failed TLS twice in a row", _fact("tls", True,
                        "a certificate that keeps failing verification is an attack signal"),
                        not (cls == "tls_failed" and prev == "tls_failed"), remedy))
    return out


def checks(s: SecretSpec, *, lstat: Callable = os.lstat, digest: Optional[Callable[[str], Any]] = None,
           read: Callable[[str], Any] = _read_text, platform: str = sys.platform,
           volume: Optional[Callable[[SecretSpec, str], Any]] = None,
           listdir: Callable[[str], List[str]] = os.listdir,
           realpath: Callable[[str], str] = os.path.realpath,
           now: Optional[float] = None) -> List[rh.Check]:
    """Every check of the secret's layout on this host."""
    if digest is None:
        import host_setup
        digest = host_setup._sha256
    when = time.time() if now is None else now
    st_ = state(s, read)
    out = verify_pins(s, lstat, digest, read)
    out += verify_clones(s, lstat, read, listdir)
    out += verify_tools(s, lstat, realpath)
    out += verify_dirs(s, lstat)
    out += verify_ssh(s, lstat)
    out += verify_volume(s, st_, (volume or ask_volume)(s, f"verify-{int(when)}"))
    out += verify_core(s, platform, read)
    out += verify_status(s, st_, read, when)
    return out
