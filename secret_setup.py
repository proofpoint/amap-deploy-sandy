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
import shlex
import stat
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import root_trust as rt
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
#: install is the plan's root lines' own, and has no bare fallback (d3.3 §5(d)).
REQUIRED_TOOLS = ("git", "docker", "python3", "ssh", "ssh-keygen", "install")
#: The tools root executes: docker (the hub's supervisor, the weekly probe and
#: the one-shots), python3 (the pinned writer's steps), sudo (the operator's
#: door to root when docker_via_sudo) and install (the plan's root lines). Each
#: must be root's alone; every other tool may also be the operator's.
ROOT_EXEC_TOOLS = ("docker", "python3", "sudo", "install")
CLONE_ROLES = ("deploy", "overlay", "producer", "runtime")
OPTIONAL_CLONE_ROLE = "producer"
REQUIRED_CLONE_ROLES = set(CLONE_ROLES) - {OPTIONAL_CLONE_ROLE}
#: The weekly probe's status: older than this is a job that did not run, and
#: a last pass older than the second is a problem whatever the last class.
STATUS_MAX_AGE_S = 8 * 86400
LAST_OK_MAX_AGE_S = 15 * 86400
#: Every class host_steps' probe-weekly records: the probe's own and its two.
PROBE_CLASSES = ("ok", "secret_unavailable", "auth_failed", "hub_unreachable", "tls_failed",
                 "connect_failed", "protocol_error", "temporary", "engine_unavailable", "timeout")
_SMTP_CODE = re.compile(r"[0-9]{3}|-")   # ASCII only: \d also matches other scripts' digits
PROBE_CLASSES_NOT_FAILURES = ("ok", "engine_unavailable", "hub_unreachable", "tls_failed",
                              "connect_failed", "temporary")
_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
#: The runtime image, content-addressed: a name by its manifest digest, or a
#: locally built image by its Id as `docker image inspect` prints it, the
#: engine's content-addressed image Id: the config digest on the classic image
#: store, the manifest (list) digest on the containerd store. Either is passed
#: to docker verbatim, and hub_runtime.compare holds the container's
#: Config.Image to the same string.
_IMAGE = re.compile(r"[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}|sha256:[0-9a-f]{64}")
_LABEL = re.compile(r"[a-z0-9][a-z0-9._-]*=[A-Za-z0-9._-]+")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
#: The weekly job's run id, as host_steps' probe-weekly checks it.
_RUN_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")
#: Capabilities no allowlist can admit: each reaches another process's memory
#: or the host's files, and so the volume's backing store.
HARD_DENY = frozenset({"ALL", "SYS_ADMIN", "SYS_PTRACE", "DAC_READ_SEARCH", "SYS_MODULE",
                       "SYS_RAWIO", "BPF", "PERFMON", "SYS_BOOT", "MAC_ADMIN", "MAC_OVERRIDE"})
_LOCK_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\.lock")
#: The probe's own phase budgets, set so the whole probe fits well inside the
#: weekly job's timeout (connect, then each command, each at most this long).
PROBE_BUDGET_S = 30
PROBE_BUDGETS = ("RELAY_SMTP_CONNECT_TIMEOUT", "RELAY_SMTP_COMMAND_TIMEOUT", "RELAY_SMTP_DATA_TIMEOUT",
                 "RELAY_SMTP_DOT_TIMEOUT")
#: apport, Ubuntu's crash handler: its hook and the units that enable it.
APPORT_HOOK = "/usr/share/apport/apport"
APPORT_DEFAULT = "/etc/default/apport"
APPORT_UNITS = ("apport.service", "apport-forward.socket")


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
    principal: str = ""
    pipeline_locks: Tuple[str, ...] = ()    # further operator lock files in run_dir
    probe: Optional[Dict[str, Any]] = None  # network, smtp_host, smtp_port, username
    zsh: Optional[Dict[str, str]] = None    # version, module_path: the recorded zsh
    image_commit: Optional[str] = None      # the commit `image` was built from, when recorded

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
    sec = _exact(sec, keys, "(the section)", ("docker_via_sudo", "caps_allow", "attestations", "exposure",
                                                "pipeline_locks", "probe", "zsh", "image_commit"))
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
        raise SecretSpecError("secrets.image must be the runtime image by digest (name@sha256:<64 hex>) or, for a "
                              "locally built image, by its Id (sha256:<64 hex>)")
    image_commit = sec.get("image_commit")
    if image_commit is not None and (not isinstance(image_commit, str) or not _HEX40.fullmatch(image_commit)):
        raise SecretSpecError("secrets.image_commit must be a full commit sha")
    w = _exact(sec["writer"], ("dir", "sha256", "commit"), "writer")
    if not isinstance(w["sha256"], str) or not _HEX64.fullmatch(w["sha256"]):
        raise SecretSpecError("secrets.writer.sha256 must be 64 lower-case hex digits")
    if not isinstance(w["commit"], str) or not _HEX40.fullmatch(w["commit"]):
        raise SecretSpecError("secrets.writer.commit must be a full commit sha")
    clones = {}
    # The producer clone is needed only where the D7 source is read from it;
    # a host that pins the one file instead (hub.d7.source as {path, sha256})
    # holds no producer tree, whose commit carries secrets.
    if not isinstance(sec["clones"], dict) or set(sec["clones"]) not in (set(CLONE_ROLES), REQUIRED_CLONE_ROLES):
        raise SecretSpecError(f"secrets.clones must name exactly {', '.join(CLONE_ROLES)}, or all but "
                              f"{OPTIONAL_CLONE_ROLE}")
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
    caps = sec.get("caps_allow", {})
    if not isinstance(caps, dict) or any(not isinstance(k, str) or not re.fullmatch(r"[A-Z_]+", k)
                                         or not isinstance(v, str) or not v.strip() for k, v in caps.items()):
        raise SecretSpecError("secrets.caps_allow maps each allowed capability to the reason it is allowed")
    if set(caps) & HARD_DENY:
        raise SecretSpecError(f"secrets.caps_allow lists {', '.join(sorted(set(caps) & HARD_DENY))}, which no "
                              f"allowlist may admit")
    att = sec.get("attestations", {})
    if not isinstance(att, dict) or set(att) - {"native_agents", "other_runtimes"} \
            or any(not isinstance(v, list) for v in att.values()):
        raise SecretSpecError("secrets.attestations may hold native_agents and other_runtimes, each a list")
    exp = sec.get("exposure", {})
    exp_keys = ("secret_roots", "integrity_roots", "engine_sockets", "authorized_keys", "backup_excluded")
    if not isinstance(exp, dict) or set(exp) - set(exp_keys) \
            or any(not isinstance(v, list) for v in exp.values()):
        raise SecretSpecError(f"secrets.exposure may hold {', '.join(exp_keys)}, each a list of paths")
    exposure = {k: tuple(_abs(p, f"exposure.{k}[]") for p in exp.get(k, [])) for k in exp_keys}
    locks = sec.get("pipeline_locks", [])
    if not isinstance(locks, list) or any(not isinstance(n, str) or not _LOCK_NAME.fullmatch(n)
                                          or n == LOCK_FILE for n in locks):
        raise SecretSpecError("secrets.pipeline_locks must list plain <name>.lock file names")
    probe = sec.get("probe")
    if probe is not None:
        probe = _exact(probe, ("network", "smtp_host", "smtp_port", "username"), "probe")
        if not all(isinstance(probe[k], str) and _NAME.fullmatch(probe[k])
                   for k in ("network", "smtp_host")) or not isinstance(probe["username"], str) \
                or isinstance(probe["smtp_port"], bool) or not isinstance(probe["smtp_port"], int):
            raise SecretSpecError("secrets.probe: network and smtp_host are names, smtp_port a number, "
                                  "username a string")
    zsh = sec.get("zsh")
    if zsh is not None:
        zsh = _exact(zsh, ("version", "module_path"), "zsh")
        _abs(zsh["module_path"], "zsh.module_path")
        if "zsh" not in tools or not isinstance(zsh["version"], str):
            raise SecretSpecError("secrets.zsh needs tools.zsh and a version string")
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
        operator_uid=op, docker_via_sudo=via_sudo, principal=sec["principal"],
        pipeline_locks=tuple(locks), probe=probe, zsh=zsh, image_commit=image_commit,
        extra={"caps_allow": dict(caps), "attestations": dict(att), "exposure": exposure})


# --- The plan -------------------------------------------------------------------


def docker(s: SecretSpec) -> List[str]:
    """The docker client, by its recorded path, through `sudo -n` where the
    operator's account reaches the engine only that way."""
    if s.docker_via_sudo:
        return [s.tools["sudo"], "-n", s.tools["docker"]]
    return [s.tools["docker"]]


def oneshot(s: SecretSpec, role: str, run_id: str, *, user: str, rw: bool, caps: Sequence[str] = (),
            stdin: bool = False, client: Optional[List[str]] = None) -> List[str]:
    """A one-shot container in the reviewed shape: the pinned image, no pull,
    no network, no log, a read-only root, no core, no new privileges, every
    capability dropped but `caps`, the volume (no copy from the image) and
    the writer directory read-only. `client` is the docker to run it with: a
    live call's, from live_docker; the rendered plan's, docker(s), otherwise."""
    vol = f"type=volume,src={s.volume},dst={IN_VOLUME},volume-nocopy" + ("" if rw else ",readonly")
    argv = (docker(s) if client is None else list(client)) + ["run", "--rm"] + (["-i"] if stdin else []) + [
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


def probe(s: SecretSpec, run_id: str, root: bool = False) -> List[str]:
    """The one-shot login probe (the design's §6): the runtime's image, uid,
    read-only mount, network and SMTP settings, running only `probe-login`,
    with its phase budgets set so the whole probe fits inside the weekly
    job's timeout. `root`: the job root runs, which names docker directly
    (root's argv never holds sudo)."""
    if s.probe is None:
        raise SecretSpecError("secrets.probe is needed to render the probe")
    pr = s.probe
    argv = ([s.tools["docker"]] if root else docker(s)) + [
        "run", "--rm", "--pull", "never", "--log-driver", "none", "--read-only", "--ulimit", "core=0",
        "--security-opt", "no-new-privileges", "--cap-drop", "ALL", "--network", pr["network"],
        "--user", f"{s.uid}:{s.gid}", "--label", "org.amap.oneshot=probe", "--label", f"org.amap.run={run_id}",
        "--mount", f"type=volume,src={s.volume},dst={s.container_dir},readonly,volume-nocopy",
        "-e", f"SMTP_PASSWORD_FILE={posixpath.join(s.container_dir, s.file)}",
        "-e", f"SMTP_USERNAME={pr['username']}", "-e", f"SMTP_HOST={pr['smtp_host']}",
        "-e", f"SMTP_PORT={pr['smtp_port']}", "-e", "SMTP_AUTH_METHOD=password"]
    for budget in PROBE_BUDGETS:
        argv += ["-e", f"{budget}={PROBE_BUDGET_S}"]
    return argv + [s.image, "probe-login"]


def hash_command(s: SecretSpec, q: Callable[[str], str]) -> str:
    """The recorded sha256 tool, as the operator runs it."""
    t = s.tools
    tool = t.get("sha256sum") or t.get("shasum")
    if not tool:
        return "<the recorded sha256 tool>"
    return q(tool) + (" -a 256" if tool == t.get("shasum") else "")


#: What the plan prints in place of a root line when the document cannot bootstrap the barrier.
NO_BARRIER = "<a root line: it needs the secrets and supervision sections, the pinned writer and its barrier>"


def render(s: SecretSpec, q: Callable[[str], str], root: Optional[Callable[[List[str]], str]] = None) -> List[str]:
    """The secret's root-run steps, as shell lines, in order, after the
    bootstrap: each root line through the barrier (`root` renders it).
    Printed, never run."""
    root = root or (lambda argv: typed_root(s, argv, q))
    install = s.tools["install"]
    etc = posixpath.dirname(s.anchor)
    lines = [
        "# The runtime's secret file. The anchor is the operator's alone: the reviewed overlay's sha, "
        "copied from its approval record.",
        root([install, "-d", "-o", "0", "-g", "0", "-m", "0755", etc]),
        root([install, "-o", "0", "-g", "0", "-m", "0444", "<a file holding the approved overlay sha>", s.anchor]),
        "# As the operator, before any one-shot: the run directory and the lock files the one-shots, "
        "verify and the runbook share.",
        f"{q(install)} -d -m 0700 {q(s.run_dir)}",
    ]
    for name in (LOCK_FILE,) + s.pipeline_locks:
        lines.append(f"{q(install)} -m 0600 /dev/null {q(posixpath.join(s.run_dir, name))}")
    state_tmp = posixpath.join(s.run_dir, "state.tmp")
    lines += [
        "# The runtime's network is rendered with the runtime itself, not here.",
        "# The volume and its root, owned by the runtime's uid, 0700, made in a one-shot container under "
        "the lock, the root locked as the writer locks it.",
        " ".join(q(a) for a in docker(s)) + f" volume create --label {q(s.label)} {q(s.volume)}",
        " ".join(q(a) for a in locked(s, oneshot(s, "root", "<run-id>", user="0:0", rw=True, caps=WRITER_CAPS)))
        + f" root {IN_VOLUME} {s.uid} {s.gid} {ROOT_MODE:04o} --exclusive",
        f"# The state, until the secret is written: {STATES[0]}. Written to a file first: BSD install "
        f"refuses a pipe as its source.",
        f"printf '{STATES[0]}\\n' > {q(state_tmp)}",
        root([install, "-o", "0", "-g", "0", "-m", "0444", state_tmp, s.state_file]),
        f"rm {q(state_tmp)}",
    ]
    return lines


def _ancestry(path: str) -> List[str]:
    """`/`, each ancestor of `path`, then `path`, outermost first."""
    out = [path]
    while out[0] != "/":
        out.insert(0, posixpath.dirname(out[0]))
    return out


def bootstrap(spec: Any, q: Callable[[str], str], document: Optional[Tuple[str, str]] = None) -> List[str]:
    """Steps 0-3 of the bootstrap (d3.3 §5(d) §3.1): the operator's staging,
    the advisory hash of the writer's source, the one TXN line (GATE0, U0
    and B1-B3 in one operator shell, sudo only inside it), then G. Every
    root line after these runs through the barrier they place."""
    import hub_supervise as hv  # it imports this module
    s, sup = spec.secrets, spec.supervision
    clone = s.clones["deploy"]["path"]
    source = posixpath.join(clone, WRITER)
    rt_path = hv.rt_path(spec)
    rt_sha = hv.rt_sha256(spec)
    hashword = rt.HASHWORD[sup.kind]
    docsource, docpath = document or ("<the document's source: spec or overlay>", "<the document>")
    if sup.kind == "systemd":
        names = [posixpath.basename(sup.hub["unit"]), posixpath.basename(sup.weekly["service"]),
                 posixpath.basename(sup.weekly["timer"])]
        plists: List[str] = []
    else:
        names = [sup.hub["label"], sup.weekly["label"]]
        plists = [posixpath.join(s.run_dir, hv.staged(sup.weekly["plist"])), sup.weekly["plist"]]
    operands = [s.writer_dir, s.writer, rt_path, posixpath.join(s.writer_dir, rt.CONTEXT_NAME), s.writer_sha256,
                rt_sha, hashword, source, posixpath.join(s.run_dir, hv.staged(rt_path)), sup.kind] + names + \
        [s.tools["python3"], posixpath.join(clone, "amap-sandy.py"), docsource, docpath] + plists
    txn = rt.OPERATOR_ENV + [rt.render_txn(sup.kind, s.tools.get("systemctl", "/usr/bin/systemctl")), "sh"] + operands
    gate = rt.OPERATOR_ENV + [rt.render_gate(sup.kind), "sh", hashword, s.writer_sha256, rt_sha, s.writer, rt_path] + \
        _ancestry(s.writer_dir)
    stage = "amap-sandy.py " + (f"--overlay {q(docpath)} hub-supervise --apply" if docsource == "overlay"
                                else f"hub-supervise --apply --spec {q(docpath)}")
    return [
        f"# 0. As the operator: `{stage}` stages every supervision file in {s.run_dir}, root-trust.sh among "
        "them, and the deployed context. Placing them enables nothing.",
        f"# 1. As the operator, advisory (G binds the bytes): it must print {s.writer_sha256}.",
        f"{hash_command(s, q)} {q(source)}",
        "# 2. As the operator, one transaction: GATE0 decides from the state before any byte is replaced, "
        "U0 guards a running job, and only then root makes the writer's directory and copies what is new. "
        "Go on only when it ends with TXN-OK.",
        " ".join(q(a) for a in txn),
        "# 3. As the operator, G: the placed route and bytes, before anything sources root-trust.sh. Go on "
        "only when it prints exactly G-ROUTE-OK, G-BYTES-OK and BOOTSTRAP-OK.",
        " ".join(q(a) for a in gate),
    ]


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


def _writer_rows(s: SecretSpec, lstat: Callable, digest: Callable[[str], Any]) -> List[rh.Check]:
    """The writer root's alone and its bytes the pinned ones: verify's rows,
    and a prerequisite of every live engine call (d3.3 §5(c))."""
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
    return out


def verify_pins(s: SecretSpec, lstat: Callable, digest: Callable[[str], Any],
                read: Callable[[str], Any]) -> List[rh.Check]:
    out = _writer_rows(s, lstat, digest)
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


def git_env(path: str) -> Dict[str, str]:
    """The environment every git call gets: no system or user configuration,
    and the repository named outright, so no inherited GIT_DIR, GIT_WORK_TREE
    or GIT_COMMON_DIR can point it elsewhere and no GIT_CONFIG_COUNT or
    GIT_CONFIG_PARAMETERS can inject configuration."""
    git_dir = posixpath.join(path, ".git")
    return {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_DIR": git_dir,
            "GIT_WORK_TREE": path, "GIT_COMMON_DIR": git_dir, "GIT_CONFIG_COUNT": "0",
            "GIT_CONFIG_PARAMETERS": ""}


def _git(s: SecretSpec, path: str, *args: str) -> Any:
    """git in `path` with system and user configuration ignored and no hook or
    fsmonitor able to run: stdout, or an Unresolved."""
    try:
        p = rh.run([s.tools["git"], "-C", path, "-c", "core.hooksPath=/dev/null",
                    "-c", "core.fsmonitor=false", *args],
                   extra_env=git_env(path))
    except rh.CannotRun as e:
        return rh.Unresolved(str(e))
    if p.rc != 0:
        return rh.Unresolved(f"git {' '.join(args)} in {path} exited {p.rc}: {p.err.strip()[:200]}")
    return p.out


def verify_clones(s: SecretSpec, lstat: Callable, read: Callable[[str], Any],
                  listdir: Callable[[str], List[str]] = os.listdir) -> List[rh.Check]:
    out = []
    anchored = anchor_sha(s, read)
    for role in (r for r in CLONE_ROLES if r in s.clones):
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


def identity_chain(path: str, stat_: Callable, realpath: Callable[[str], str]) -> Any:
    """(st_dev, st_ino) of `path` resolved, then of every ancestor of the
    resolved path: a list, None when some component is absent, or an
    Unresolved when one cannot be asked."""
    out, p = [], realpath(path)
    while True:
        try:
            st = stat_(p)
        except FileNotFoundError:
            return None
        except OSError as e:
            return rh.Unresolved(f"cannot stat {p}: {e}")
        out.append((st.st_dev, st.st_ino))
        if p == "/":
            return out
        p = posixpath.dirname(p)


def verify_overlay_source(s: SecretSpec, overlay: Optional[str], stat_: Callable,
                          realpath: Callable[[str], str]) -> List[rh.Check]:
    """The document just read, which supplies every other pin, is a tracked
    file inside the anchored overlay clone: the overlay never vouches for its
    own sha, the anchor does, and only for that clone."""
    clone = s.clones["overlay"]["path"]
    claim = f"the host-setup document was read from the anchored overlay clone {clone}"
    want = _fact("overlay source", True, "every pin is trusted only as the anchored clone holds it")
    remedy = f"run verify with the overlay file inside {clone}, never a copy or a working checkout"
    if overlay is None:
        return [rh.check(claim, want, "read from --spec, not the overlay", remedy)]
    mine, top = identity_chain(overlay, stat_, realpath), identity_chain(clone, stat_, realpath)
    for c in (mine, top):
        if isinstance(c, rh.Unresolved):
            return [rh.unknown(claim, want, c.reason, remedy)]
    if mine is None or top is None or top[0] not in mine[1:]:
        return [rh.check(claim, want, f"{overlay} is not inside {clone}", remedy)]
    rel = posixpath.relpath(realpath(overlay), realpath(clone))
    claim2 = f"{rel} is a tracked file of the anchored overlay clone"
    try:
        p = rh.run([s.tools["git"], "-C", clone, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                    "ls-files", "--error-unmatch", "--", rel], extra_env=git_env(clone))
    except rh.CannotRun as e:
        return [rh.check(claim, want, True, remedy), rh.unknown(claim2, want, str(e), remedy)]
    # --error-unmatch exits 1 for a path git does not track; anything else is git not answering.
    second = (rh.check(claim2, want, p.rc == 0, remedy) if p.rc in (0, 1)
              else rh.unknown(claim2, want, f"git ls-files exited {p.rc}", remedy))
    return [rh.check(claim, want, True, remedy), second]


def verify_tools(s: SecretSpec, lstat: Callable,
                 realpath: Callable[[str], str] = os.path.realpath) -> List[rh.Check]:
    """Each tool's real path a regular executable no one else can write, under
    directories no one else can write. A tool root executes (ROOT_EXEC_TOOLS)
    must be root's: its real path and every directory above it, and above the
    recorded path too, so no one else can repoint a link. Any other tool may
    also be the operator's."""
    out = []
    every = dict(s.tools)
    every.setdefault("uv", s.uv["binary"])
    for name, path in sorted(every.items()):
        out += _tool_rows(s, name, path, lstat, realpath)
    return out


def _tool_rows(s: SecretSpec, name: str, path: str, lstat: Callable,
               realpath: Callable[[str], str]) -> List[rh.Check]:
    """verify_tools' rows for one tool."""
    if name in ROOT_EXEC_TOOLS:
        owners, whose, why = (0,), "root", f"root executes {name}"
    else:
        owners, whose = (0, s.operator_uid), "root or the operator"
        why = f"{name} runs with docker or root authority in the runbook or verify"
    real = realpath(path)
    st = _lst(real, lstat)
    claim = f"the {name} tool {path} is a regular executable file owned by {whose}"
    want = _fact("tool", True, why)
    remedy = f"record a {name} owned by root (a system one), or fix {real}'s owner and mode"
    if isinstance(st, rh.Unresolved):
        return [rh.unknown(claim, want, st.reason, remedy)]
    ok = st is not None and stat.S_ISREG(st.st_mode) and bool(st.st_mode & 0o111) \
        and st.st_uid in owners and _no_write_by_others(st)
    out = [rh.check(claim, want, ok, remedy, do_not="never record a tool that an agent could write"),
           _owned_chain(f"every directory above {real} is owned by {whose} and "
                        f"not group- or world-writable", real, owners, why, lstat)]
    if name in ROOT_EXEC_TOOLS and real != path:
        out.append(_owned_chain(f"every directory above the recorded {path} is owned by root and not group- "
                                f"or world-writable, so no one else can point it elsewhere", path, owners, why,
                                lstat))
    return out


# --- The live engine route ---------------------------------------------------------
#
# Every live docker call (a one-shot, an inspect, an exec, the exposure sweep)
# goes through live_docker(s), never through docker(s), which only renders.
# A live call is refused, before anything executes, unless every prerequisite
# of d3.3 §5(c) PASSes: the interpreter, docker and sudo by verify_tools' own
# rows, the writer by its pin, and the startup closure computed as the
# operator. On the sudo route the call is then the §3 grammar under sudo, so
# root runs docker only through root_exec and trusted-exec. The refusal is
# rh.CannotRun, which every caller already reports as UNKNOWN. Each check reads the filesystem
# through `lstat`: trust_gate holds an answer computed with the caller's own,
# so a verify run and its rows judge the same files; outside a gate, live_docker
# judges the real ones.


def _operator_closure(s: SecretSpec) -> Optional[str]:
    """None when the interpreter's and docker's startup closure, computed as
    the operator (no escalation), is root's alone; otherwise why not. Where
    the writer's module is not importable (a bundle without it), it refuses."""
    try:
        import host_steps
    except ImportError:
        return "the closure check (host_steps) is not importable here"
    try:
        host_steps._verified_tools(s.tools["python3"], s.tools["docker"])
    except host_steps.Tooling as e:
        return str(e)
    return None


def live_refusal(s: SecretSpec, lstat: Callable = os.lstat,
                 realpath: Callable[[str], str] = os.path.realpath, *,
                 digest: Optional[Callable[[str], Any]] = None,
                 closure: Optional[Callable[[SecretSpec], Optional[str]]] = None) -> Optional[str]:
    """None when every prerequisite of a live engine call PASSes (d3.3
    §5(c)), on the held and the lock-wrapped route alike: the interpreter,
    docker and sudo (where used) by verify_tools' rows; the writer by its pin;
    docker's startup closure, computed as the operator. Otherwise why not."""
    names = ["python3", "docker"] + (["sudo"] if s.docker_via_sudo else [])
    bad = [n for n in names
           if any(c.result != rh.PASS for c in _tool_rows(s, n, s.tools[n], lstat, realpath))]
    if bad:
        return f"not run: {' and '.join(bad)} not root's alone"
    if digest is None:
        import host_setup
        digest = host_setup._sha256
    if any(c.result != rh.PASS for c in _writer_rows(s, lstat, digest)):
        return f"not run: the writer {s.writer} is not the pinned one, root's alone"
    why = (closure or _operator_closure)(s)
    return f"not run: the startup closure is not root's alone: {why}" if why else None


@dataclass(frozen=True)
class Gate:
    """One run's judgement of the live engine route, and the engine its root
    lines name (DOCKER_HOST)."""
    refusal: Optional[str]
    engine: Optional[str] = None


_GATE: List[Gate] = []


class trust_gate:
    """While held, live_docker answers from this judgement, made once with
    `lstat`, `realpath`, `digest` and `closure`."""

    def __init__(self, s: SecretSpec, lstat: Callable = os.lstat, realpath: Callable[[str], str] = os.path.realpath,
                 *, engine: Optional[str] = None, digest: Optional[Callable[[str], Any]] = None,
                 closure: Optional[Callable[[SecretSpec], Optional[str]]] = None):
        inherited = _GATE[-1].engine if _GATE else None    # an inner gate keeps the outer one's engine
        self.answer = Gate(live_refusal(s, lstat, realpath, digest=digest, closure=closure), engine or inherited)

    def __enter__(self) -> "trust_gate":
        _GATE.append(self.answer)
        return self

    def __exit__(self, *exc: Any) -> None:
        _GATE.pop()


def live_docker(s: SecretSpec, *, engine: Optional[str] = None) -> List[str]:
    """The docker client for a call that runs now: rh.CannotRun, before
    anything executes, unless every prerequisite PASSes. On the sudo route it
    is `sudo -n` and then the §3 grammar (d3.3 §5(c)): the anchor with the
    engine as DOCKER_HOST, root-trust.sh's root_exec with the writer's pin,
    trusted-exec with the document's tools, and docker; the caller appends
    docker's arguments. The direct route is the operator's own docker."""
    gate = _GATE[-1] if _GATE else Gate(live_refusal(s), engine)
    if gate.refusal:
        raise rh.CannotRun(gate.refusal)
    if not s.docker_via_sudo:
        return [s.tools["docker"]]
    return sudo_route(s, engine or gate.engine)


#: The setting the coredump check's remedy writes, through the barrier.
COREDUMP_OFF = "kern.coredump=0"


def typed_root(s: SecretSpec, argv: Sequence[str], q: Callable[[str], str], python3: Optional[str] = None,
               also: Sequence[str] = (), tools: Optional[Sequence[str]] = None) -> str:
    """One operator-typed root line (d3.3 §5(d)) through the placed writer,
    with its section's recorded tools (the secrets section's unless `tools`
    names another's) and each `also` trusted-exec judges beside argv[0].
    `python3` is the barrier's interpreter when argv runs another than the
    secrets section's (the partition job's)."""
    return " ".join(q(a) for a in rt.typed_argv(posixpath.join(s.writer_dir, rt.NAME), s.writer_sha256,
                                                python3 or s.tools["python3"], s.writer,
                                                list(s.tools.values() if tools is None else tools),
                                                list(argv), also=also))


def sudo_route(s: SecretSpec, engine: Optional[str]) -> List[str]:
    """`sudo -n` and the §3 grammar up to `-- <docker>`, the one prefix of
    every live call on the sudo route. No sudoers rule can admit it safely
    (SUDO_ROUTE_NOTICE)."""
    tools = [x for t in sorted(set(s.tools.values())) if posixpath.basename(t) != "sudo" for x in ("--tool", t)]
    return [s.tools["sudo"], "-n"] + rt.root_argv_positional(
        posixpath.join(s.writer_dir, rt.NAME), s.writer_sha256, s.tools["python3"], s.writer,
        ["trusted-exec"] + tools + ["--", s.tools["docker"]], engine=engine)


#: What the plan says about sudo on the sudo route (Codex P1 at 0aa3e39e): there is no
#: safe rule to print. sudoers compares the space-joined arguments, so a rule for
#: /usr/bin/env cannot keep env's assignments apart from the command: the arguments
#: `-i` and one `PATH=<the rest>` followed by any program join to the same string, and
#: env runs that program as root without /bin/sh, root_exec or trusted-exec.
SUDO_ROUTE_NOTICE = [
    "# The sudo route (docker_via_sudo): NO sudoers rule is safe for it yet. Do NOT install a NOPASSWD rule "
    "for /usr/bin/env, however narrow it looks: sudoers matches the arguments as one joined string, so it cannot "
    "keep env's assignments apart from the command, and any such rule runs a program of the caller's choosing as "
    "root, skipping the barrier.",
    "# Until a separately reviewed, fixed-purpose, root-owned entry point enforces that boundary, the sudo route "
    "is unavailable: live engine calls on it are refused by sudo, so none of them can read the engine.",
]


def sudo_route_notice(s: SecretSpec) -> List[str]:
    """The plan's lines for the sudo route: that it has no safe sudoers rule
    yet, and so must not be granted one. Empty on the direct route."""
    return list(SUDO_ROUTE_NOTICE) if s.docker_via_sudo else []



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
    for name in (LOCK_FILE,) + s.pipeline_locks:
        lock = posixpath.join(s.run_dir, name)
        out.append(_operator_file(f"the lock file {lock} is a regular file owned by the operator, 0600",
                                  lock, LOCK_MODE, s, "made by the plan; nothing creates it later", lstat))
    return out


def _operator_file(claim: str, path: str, mode: int, s: SecretSpec, why: str, lstat: Callable) -> rh.Check:
    st = _lst(path, lstat)
    want = _fact("file", (s.operator_uid, mode), why)
    remedy = f"create {path} as the plan does, operator-owned {mode:04o}"
    if isinstance(st, rh.Unresolved):
        return rh.unknown(claim, want, st.reason, remedy)
    if st is None or not stat.S_ISREG(st.st_mode):
        return rh.check(claim, want, "absent" if st is None else "not a regular file", remedy)
    return rh.check(claim, want, (st.st_uid, stat.S_IMODE(st.st_mode)), remedy)


def verify_ssh(s: SecretSpec, lstat: Callable) -> List[rh.Check]:
    out = []
    kh, cfg, alias = s.ssh["known_hosts"], s.ssh["config"], s.ssh["alias"]
    out.append(_operator_file(f"the hub ssh config {cfg} is the operator's, 0600", cfg, LOCK_MODE, s,
                              "it replaces every other ssh config for the producer's ssh", lstat))
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


LOCK_WAIT_S = 60
LOCK_POLL_S = 0.25


class Lock:
    """The one-shots' lock, taken in-process by verify around every secret
    check and the exposure sweep, so no one-shot can start between them.
    Entering gives None, or an Unresolved naming why it was not taken."""

    def __init__(self, s: SecretSpec, wait_s: float = LOCK_WAIT_S):
        self.path, self.wait_s, self.fd = posixpath.join(s.run_dir, LOCK_FILE), wait_s, None

    def __enter__(self) -> Any:
        import fcntl
        try:
            self.fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        except OSError as e:
            return rh.Unresolved(f"cannot open the lock {self.path}: {e}")
        deadline = time.monotonic() + self.wait_s
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return None
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    return rh.Unresolved(f"{self.path} stayed held for {self.wait_s:.0f}s")
                time.sleep(LOCK_POLL_S)

    def __exit__(self, *exc: Any) -> None:
        if self.fd is not None:
            os.close(self.fd)


def ask_volume(s: SecretSpec, run_id: str, held: bool = False) -> Any:
    """The volume's metadata from a one-shot container, by lstat alone: a
    dict, or an Unresolved. Under the lock: verify's own (`held`), or the
    `lock` wrapper's."""
    try:
        argv = oneshot(s, "stat", run_id, user=f"{s.uid}:{s.gid}", rw=False, client=live_docker(s)) + [
            "stat-secret", IN_VOLUME]
        if not held:
            argv = locked(s, argv)
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
        tmp = f".{s.file}.tmp"
        stray = [n for n in names if n != s.file]
        remedy = (remedy_b5 if not names else
                  "remove the crash temp with `secret-remove`, then write the secret again"
                  if stray == [tmp] else
                  "do not open it; record it and escalate: `secret-remove` refuses any name but the file "
                  "and its crash temp")
        out.append(rh.check(f"the volume holds exactly {s.file}", want, names, remedy,
                            do_not="never open a stray entry; never copy the value from another host or a "
                            "pane"))
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
        remedy = ("record active after the probe passes, or `secret-remove`" if st_ == "pending_b5"
                  else "remove it with `secret-remove` (any other name: do not open it; escalate)")
        out.append(rh.check(f"the volume holds nothing in the {st_} state", want, names, remedy,
                            do_not="never open an entry to see what it is"))
    return out


def verify_core(s: SecretSpec, platform: str, read: Callable[[str], Any],
                exists: Callable[[str], bool] = os.path.lexists) -> List[rh.Check]:
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
        out.append(verify_apport(s, read, exists))
        return out
    claim = "the kernel writes no core files (kern.coredump=0)"
    want = _fact("kern.coredump", "0", "a crashing root service holds the value in memory")
    tool = s.tools.get("sysctl")
    remedy = (f"run `{typed_root(s, [tool, COREDUMP_OFF], shlex.quote)}` before each write or rotation" if tool
              else "record tools.sysctl, then run the root line this check prints for it before each write or "
                   "rotation")
    if tool is None:
        return [rh.unknown(claim, want, "tools has no sysctl to ask", remedy)]
    try:
        p = rh.run([tool, "-n", "kern.coredump"])
    except rh.CannotRun as e:
        return [rh.unknown(claim, want, str(e), remedy)]
    if p.rc != 0:
        return [rh.unknown(claim, want, f"sysctl exited {p.rc}", remedy)]
    return [rh.check(claim, want, p.out.strip(), remedy)]


def verify_apport(s: SecretSpec, read: Callable[[str], Any],
                  exists: Callable[[str], bool] = os.path.lexists) -> rh.Check:
    """apport is absent, or disabled both in its defaults and in systemd: with
    it, a packaged daemon's core goes to /var/crash whatever core_pattern
    says."""
    claim = "apport is absent or disabled"
    want = _fact("apport", True, "with apport on, a crashing sshd or dockerd leaves its memory in /var/crash")
    remedy = "remove apport, or set enabled=0 in /etc/default/apport and disable its units"
    if not exists(APPORT_HOOK):
        return rh.check(claim, want, True, remedy)
    text = _read_small(APPORT_DEFAULT, read)
    if isinstance(text, rh.Unresolved):
        return rh.unknown(claim, want, text.reason, remedy)
    enabled = None
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("enabled="):
            enabled = line.split("=", 1)[1].strip()
    if enabled != "0":
        return rh.check(claim, want, f"{APPORT_DEFAULT}: enabled={enabled}", remedy)
    tool = s.tools.get("systemctl")
    if tool is None:
        return rh.unknown(claim, want, "tools has no systemctl to ask about apport's units", remedy)
    for unit in APPORT_UNITS:
        try:
            p = rh.run([tool, "is-enabled", unit])
        except rh.CannotRun as e:
            return rh.unknown(claim, want, str(e), remedy)
        state_ = p.out.strip()
        if p.rc == 0 or state_ in ("enabled", "enabled-runtime", "static", "indirect", "alias"):
            return rh.check(claim, want, f"{unit} is {state_ or 'enabled'}", remedy)
        if state_ not in ("disabled", "masked", "not-found", "masked-runtime", ""):
            return rh.unknown(claim, want, f"systemctl says {unit} is {state_!r}", remedy)
    return rh.check(claim, want, True, remedy)


def verify_zsh(s: SecretSpec, lstat: Callable) -> List[rh.Check]:
    """The recorded zsh, run clean, is the version and module directory the
    section records, and that directory is not writable by anyone but root."""
    if s.zsh is None:
        return []
    claim = "the recorded zsh is its recorded version, with its recorded module directory"
    want = _fact("zsh", (s.zsh["version"], s.zsh["module_path"]), "amap_b5 refuses any other shell")
    remedy = "record the zsh this host actually runs, or run amap_b5 in it"
    try:
        p = rh.run([s.tools["zsh"], "-f", "-c", "print -r -- $ZSH_VERSION; print -r -- $module_path"])
    except rh.CannotRun as e:
        return [rh.unknown(claim, want, str(e), remedy)]
    lines = p.out.splitlines()
    got = (lines[0], lines[1]) if p.rc == 0 and len(lines) >= 2 else f"zsh exited {p.rc}"
    out = [rh.check(claim, want, got, remedy)]
    out.append(_owned_chain(f"the zsh module directory {s.zsh['module_path']} and every directory above it "
                            f"are root's and not group- or world-writable",
                            posixpath.join(s.zsh["module_path"], "zsh"), (0,),
                            "zmodload zsh/system loads code from it", lstat))
    return out


STATUS_FILE = "hub-probe.json"


def verify_status(s: SecretSpec, st_: Any, read: Callable[[str], Any], now: float,
                  lstat: Callable = os.lstat) -> List[rh.Check]:
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
        cls, code, at, run_id = doc["class"], doc["smtp_code"], doc["at"], doc["run_id"]
        last_ok, prev = doc["last_ok_at"], doc["previous_class"]
        if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
            raise ValueError("run_id")
        if cls not in PROBE_CLASSES or not (prev is None or prev in PROBE_CLASSES):
            raise ValueError("class")
        if not isinstance(code, str) or not _SMTP_CODE.fullmatch(code):
            raise ValueError("smtp_code")
        if isinstance(at, bool) or not isinstance(at, int) \
                or not (last_ok is None or (isinstance(last_ok, int) and not isinstance(last_ok, bool))):
            raise ValueError("time")
    except (ValueError, KeyError, TypeError):
        return [rh.unknown(claim, want, f"{path} is not the probe job's status (class, smtp_code, at, "
                           f"run_id, previous_class, last_ok_at)", remedy)]
    out = [rh.check(claim, want, isinstance(at, int) and now - at <= STATUS_MAX_AGE_S
                    and cls in PROBE_CLASSES_NOT_FAILURES, remedy)]
    st = _lst(path, lstat)
    meta = "the weekly probe's status file is root's, 0644, with one link"
    mwant = _fact("status file", (0, 0o644, 1), "only the root job writes it")
    if isinstance(st, rh.Unresolved):
        out.append(rh.unknown(meta, mwant, st.reason, remedy))
    elif st is None or not stat.S_ISREG(st.st_mode):
        out.append(rh.check(meta, mwant, "absent" if st is None else "not a regular file", remedy))
    else:
        out.append(rh.check(meta, mwant, (st.st_uid, stat.S_IMODE(st.st_mode), st.st_nlink), remedy))
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
           now: Optional[float] = None, overlay: Optional[str] = None,
           stat_: Callable = os.stat, held: bool = False,
           exists: Callable[[str], bool] = os.path.lexists) -> List[rh.Check]:
    """Every check of the secret's layout on this host. `overlay` is the file
    the document was read from (None for --spec); `held` says the caller
    holds the one-shots' lock, as verify does."""
    if digest is None:
        import host_setup
        digest = host_setup._sha256
    when = time.time() if now is None else now
    st_ = state(s, read)
    out = verify_overlay_source(s, overlay, stat_, realpath)
    out += verify_pins(s, lstat, digest, read)
    out += verify_clones(s, lstat, read, listdir)
    out += verify_tools(s, lstat, realpath)
    out += verify_dirs(s, lstat)
    out += verify_ssh(s, lstat)
    out += verify_zsh(s, lstat)
    run_id = f"verify-{int(when)}"
    with trust_gate(s, lstat, realpath, digest=digest):
        seen = volume(s, run_id) if volume is not None else ask_volume(s, run_id, held=held)
    out += verify_volume(s, st_, seen)
    out += verify_core(s, platform, read, exists)
    out += verify_status(s, st_, read, when, lstat)
    return out
