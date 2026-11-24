"""S8's two checks that need no running component: the clock skew between the run's VMs, and that no agent
sandbox mount covers a trust directory. Both read measured inputs and decide; neither touches a VM.

The clock skew (decision ALPHA2-L3-ID-REMINT, condition 3): each VM's clock is read once, bracketed by the runner's
own clock. Its offset is taken at the bracket's midpoint, with an error of half the bracket. The skew bound is the
difference of the two offsets plus both errors, so a slow read can only make the check refuse, never pass.

The trust directories (RE's condition on agent-account ownership, ruling RE-TRUSTDIR-MOUNT-CHECK-OWNER): a bind
mount covers a trust path when its source is that path, is inside it, or is a directory above it. The mount table
is the running container's own (the mount, never the host directory); its bind sources are resolved on the VM by
the caller before this check, so a symlink cannot hide a trust path.
"""

import posixpath
import re

import a2_s6_env as e6
from a2_causes import Refusal

STAGE = "START"
#: The largest skew S8 accepts between the run's VMs, in seconds (condition 3).
MAX_SKEW_S = 2.0
#: `date +%s.%N` as GNU date prints it: whole seconds, a dot, nine digits of nanoseconds.
_DATE = re.compile(rb"([0-9]{1,12})\.([0-9]{9})\n")
#: The mount types a sandbox may show. A bind has a host source; a volume or a tmpfs has none under a home.
BIND = "bind"
SOURCELESS = ("volume", "tmpfs")


def vm_time(stdout):
    """A VM's clock from `date +%s.%N` output, in seconds; anything else refuses (the clock could not be read)."""
    m = _DATE.fullmatch(stdout) if isinstance(stdout, bytes) else None
    if m is None:
        raise Refusal(STAGE + ".CLOCK_SKEW", "clock not readable")
    return int(m.group(1)) + int(m.group(2)) / 1e9


def skew_bound(readings):
    """`readings`: [(before, vm_clock, after)], one per VM, `before` and `after` on the runner's one clock. Returns
    the bound in seconds: |offset_a - offset_b| + err_a + err_b."""
    if len(readings) != 2:
        raise Refusal(STAGE + ".CLOCK_SKEW", "exactly two VMs")
    offs = []
    for before, clock, after in readings:
        if not after >= before:
            raise Refusal(STAGE + ".CLOCK_SKEW", "runner clock went back")
        offs.append((clock - (before + after) / 2, (after - before) / 2))
    (o1, e1), (o2, e2) = offs
    return abs(o1 - o2) + e1 + e2


def check_skew(readings):
    """Refuses START.CLOCK_SKEW when the bound exceeds MAX_SKEW_S; returns the bound in whole milliseconds."""
    bound = skew_bound(readings)
    if bound > MAX_SKEW_S:
        raise Refusal(STAGE + ".CLOCK_SKEW", "skew over the bound")
    return int(bound * 1000 + 0.999999)


def _abs_norm(p):
    return isinstance(p, str) and p.startswith("/") and (p == "/" or (posixpath.normpath(p) == p and "//" not in p))


_MOUNT_PATH = re.compile(r"(/[A-Za-z0-9._-]+)+")


def mount_path(p):
    """Whether p may be spliced into `--mount type=bind,src=<p>,dst=<p>`: S6's own path rule (a2_s6_env), each
    segment of [A-Za-z0-9._-] and none "." or "..", so docker's comma-separated parse sees one field."""
    return (isinstance(p, str) and _MOUNT_PATH.fullmatch(p) is not None and posixpath.normpath(p) == p
            and not any(s in (".", "..") for s in p.split("/")))


def mounts_of(inspect_doc):
    """[(type, source)] from `docker inspect <container>` output (a list of exactly one container). An unreadable
    or malformed table refuses START.TRUSTDIR_UNREAD: absent is never read as empty. A type other than bind,
    volume or tmpfs is unread too; a bind's source must be an absolute normalised path."""
    if not (isinstance(inspect_doc, list) and len(inspect_doc) == 1 and isinstance(inspect_doc[0], dict)
            and isinstance(inspect_doc[0].get("Mounts"), list)):
        raise Refusal(STAGE + ".TRUSTDIR_UNREAD", "mount table not readable")
    out = []
    for m in inspect_doc[0]["Mounts"]:
        typ = m.get("Type") if isinstance(m, dict) else None
        if typ == BIND:
            if not _abs_norm(m.get("Source")):
                raise Refusal(STAGE + ".TRUSTDIR_UNREAD", "bind source not absolute")
            out.append((typ, m["Source"]))
        elif typ in SOURCELESS:
            out.append((typ, None))
        else:
            raise Refusal(STAGE + ".TRUSTDIR_UNREAD", "mount type not known")
    return out


def covers(source, path):
    """Whether a bind of `source` makes `path` visible: the same path, a path inside it, or a directory above it."""
    return source == path or path.startswith(source.rstrip("/") + "/") or source.startswith(path + "/")


def check_trust(mounts, trust_paths):
    """Refuses START.TRUSTDIR_MOUNTED when a bind source (resolved on the VM) covers a trust path. `trust_paths`
    must be absolute normalised paths, at least one."""
    if not trust_paths or not all(_abs_norm(p) and p != "/" for p in trust_paths):
        raise Refusal(STAGE + ".TRUSTDIR_UNREAD", "trust paths not absolute")
    for typ, source in mounts:
        if typ != BIND:
            continue
        if not _abs_norm(source):
            raise Refusal(STAGE + ".TRUSTDIR_UNREAD", "bind source not absolute")
        for p in trust_paths:
            if covers(source, p):
                raise Refusal(STAGE + ".TRUSTDIR_MOUNTED", "a sandbox mount covers a trust path")
    return "CLEAR"


#: The docker daemon's sockets: a bind of either, or of a directory above one, hands a container the daemon.
DOCKER_SOCKETS = ("/run/docker.sock", "/var/run/docker.sock")
_GROUP_LINE = re.compile(rb"docker:[^:\n]*:([0-9]{1,10}):[^\n]*\n")


def docker_gid(rc, out):
    """The docker group's gid from `getent group docker` (rc 0 and one group line), None when getent reports no such
    group (rc 2); anything else refuses TRUSTDIR_UNREAD, since the daemon check could not be made."""
    if rc == 2 and out == b"":
        return None
    m = _GROUP_LINE.fullmatch(out) if rc == 0 else None
    if m is None:
        raise Refusal(STAGE + ".TRUSTDIR_UNREAD", "docker group not readable")
    return int(m.group(1))


def check_daemon(inspect_doc, gid):
    """Section 3(c) (RE's answer 738bb7fa, condition A): a container S8 started or checks must not reach the docker
    daemon. A bind of a docker socket or a directory above one, a GroupAdd naming the docker group or its gid, or a
    privileged container refuses TRUSTDIR_MOUNTED; a HostConfig that cannot be read refuses TRUSTDIR_UNREAD."""
    mounts = mounts_of(inspect_doc)
    hc = inspect_doc[0].get("HostConfig")
    groups = hc.get("GroupAdd") if isinstance(hc, dict) else None
    if (not isinstance(hc, dict) or type(hc.get("Privileged")) is not bool
            or not (groups is None or (isinstance(groups, list) and all(isinstance(g, str) for g in groups)))):
        raise Refusal(STAGE + ".TRUSTDIR_UNREAD", "host config not readable")
    for typ, source in mounts:
        if typ == BIND and any(covers(source, sock) for sock in DOCKER_SOCKETS):
            raise Refusal(STAGE + ".TRUSTDIR_MOUNTED", "a mount reaches the docker daemon")
    if hc["Privileged"] or any(g == "docker" or (gid is not None and g == str(gid)) for g in groups or ()):
        raise Refusal(STAGE + ".TRUSTDIR_MOUNTED", "a container reaches the docker daemon")
    return "CLEAR"


def relay_trust_paths(env, agent_home):
    """The trust paths RL's container must not bind (RE's answer d1c8069c, ask 1): the relay account's paths, the
    env-file's directory and the relay config directory. RL's own paths are binds run.sh makes by design."""
    relay, _agent = trust_paths(env, agent_home)
    extra = {posixpath.join(agent_home, ".amap-relay-env"), posixpath.dirname(env["HUB_D7_CONFIG"]),
             posixpath.dirname(env["HUB_PREFIX_TEMPLATE"])}
    return sorted(set(relay) | extra)


#: The env-file knobs whose value is a trust path, from S6's render (a2_s6_env.KEYS), and those whose DIRECTORY is
#: one too. The relay account owns the first group's values; the agent account owns or can read the rest.
RELAY_KNOBS = ("SMTP_PASSWORD_FILE", "MAILBOX_ROOT_DIR", "RELAY_LEDGER_DIR", "HUB_INBOUND_STATE_DIR")
RELAY_DIR_KNOBS = ("RELAY_LOG",)
AGENT_KNOBS = ("HOP_ROOT", "HOP_REGISTRY_DIR", "HUB_D7_CONFIG", "HUB_PREFIX_TEMPLATE", "TRANSPORT_PLUGIN_PATH")
AGENT_DIR_KNOBS = ("TRANSPORT_PLUGIN_PATH",)
#: Trust directories under the agent account's home that no env-file knob names (S6's layout, RL's paths).
AGENT_HOME_TRUST = (".amap-relay-env", ".amap-router", ".amap-delegation", ".amap-router-code", ".amap-registry",
                    ".amap-registry-batch")
_ENV_LINE = re.compile(rb"([A-Z][A-Z0-9_]*)=([^\n\r\0]+)")
#: `realpath -e --` with one path per argument; GNU realpath prints one resolved path per line, in argument order.
REALPATH_ARGV = ["/usr/bin/realpath", "-e", "--"]


def parse_env(data):
    """{KEY: value} from the env-file's bytes (S6's text: KEY=value lines, each once). Anything else refuses."""
    if not isinstance(data, bytes) or not data.endswith(b"\n"):
        raise Refusal(STAGE + ".TRUSTDIR_UNREAD", "env-file not readable")
    env = {}
    for line in data[:-1].split(b"\n"):
        m = _ENV_LINE.fullmatch(line)
        if m is None or m.group(1).decode() in env:
            raise Refusal(STAGE + ".TRUSTDIR_UNREAD", "env-file line")
        env[m.group(1).decode()] = m.group(2).decode("utf-8", "replace")
    # Gate A's W13 r4 note N1: a key RE must not be given (S6's own ABSENT rule) refuses here, in step 2, before any
    # write; RE's start argv keeps its own check.
    if any(k in e6.ABSENT or k.startswith(e6.ABSENT_PREFIXES) for k in env):
        raise Refusal(STAGE + ".TRUSTDIR_UNREAD", "env-file forbidden key")
    return env


def trust_paths(env, agent_home):
    """(relay_paths, agent_paths): the derived trust paths, each sorted and unique, split by the account that can
    resolve them (ruling W13-S8-C7-OWNING-ACCOUNT). Every knob must be present and keep S6's path rule (mount_path)."""
    if not _abs_norm(agent_home) or agent_home == "/":
        raise Refusal(STAGE + ".TRUSTDIR_UNREAD", "agent home")

    def knob(k):
        v = env.get(k)
        if not mount_path(v):
            raise Refusal(STAGE + ".TRUSTDIR_UNREAD", "env-file knob " + k)
        return v
    relay = {knob(k) for k in RELAY_KNOBS} | {posixpath.dirname(knob(k)) for k in RELAY_DIR_KNOBS}
    agent = {knob(k) for k in AGENT_KNOBS} | {posixpath.dirname(knob(k)) for k in AGENT_DIR_KNOBS}
    agent |= {posixpath.join(agent_home, n) for n in AGENT_HOME_TRUST}
    if "/" in relay | agent:
        raise Refusal(STAGE + ".TRUSTDIR_UNREAD", "a trust path is /")
    return sorted(relay), sorted(agent)


def check_realpaths(paths, rc, out):
    """Both realpath forms' one rule (ruling W13-S8-TRUSTPATHS-DERIVED): `realpath -e -- <paths>` exited 0 and
    printed exactly each path, in order. A path that does not resolve, or resolves elsewhere (a symlink anywhere in
    it), refuses TRUSTDIR_UNREAD."""
    want = "".join(p + "\n" for p in paths).encode()
    if rc != 0 or out != want:
        raise Refusal(STAGE + ".TRUSTDIR_UNREAD", "a path is not its own realpath")
    return "RESOLVED"
