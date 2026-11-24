"""S8 START's read-only steps on one VM (design W13 d3): step 2, S6's files still in place, and step 4, nothing of
S8's already started. Neither writes. Their refusals exit 2 while the stage has written nothing, and 3 once it has
(3.4, 4.2): on the second VM, steps 2 and 4 run after the first VM's start.

Step 2 reads, as the agent account, the five files S6 placed and hashed into its receipt (router.json, the feature
manifest, RE's env-file, d7.json, prefix.json), hashes the plugin, stats the plugin and its directory, stats the
env-file and its directory (the agent's own, 0600 and 0700: the docker CLI reads it as the agent account, and no
sandbox may reach it, section 3), and requires router.json's
hop root and registry directory to be the env-file's HOP_ROOT and HOP_REGISTRY_DIR (RL's note C). Any difference is
START.CONFIG_CHANGED.

Step 4 asks docker whether a container named amap-rl or amap-re exists, running or stopped; stats the relay ledger
directory as the relay account, which must find it as S6's bootstrap made it (the relay account's, 0700, a
directory); then runs RE's own `relay.py --verify` in a one-shot container of S4's RE image, as the relay uid and gid,
for the ledger's state (RE's correction C1, ruling W13-S8-RE-C1-C7). It decides from the report's "ledger" member,
never from the rc. Every docker CLI call runs as the agent account; the relay account is never given the daemon.
"""

import functools
import hashlib
import json
import posixpath
import re

import a2_s6
import a2_s6_render as r6
import a2_s8_checks as checks
from a2_causes import Refusal

STAGE = "START"
CAT = "/usr/bin/cat"
SHA256SUM = "/usr/bin/sha256sum"
STAT = "/usr/bin/stat"
DOCKER = "/usr/bin/docker"
#: The plugin's directory, which the bootstrap allowlist and RL's loader both require root-owned (check 7).
PLUGIN_DIR = posixpath.dirname(r6.PLUGIN_PATH)
#: `stat -c` format: uid, gid, octal mode, file type.
STAT_FORMAT = "%u %g %a %F"
RL_NAME = "amap-rl"
RE_NAME = "amap-re"
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_CONTAINER_ID = re.compile(rb"[0-9a-f]{12,64}")
_SHA_LINE = re.compile(rb"([0-9a-f]{64})  (.+)\n")
#: S6's receipt fact for each file step 2 re-reads, with the file's path under the agent account's home.
PLACED = (("ROUTER_JSON_SHA", posixpath.join(a2_s6.ROUTER_DIR, "router.json")),
          ("FEATURE_JSON_SHA", posixpath.join(a2_s6.FEATURE_ROOT, "feature.json")),
          ("RE_ENV_SHA", posixpath.join(a2_s6.RE_ENV, a2_s6.RE_ENV_NAME)),
          ("D7_SHA", posixpath.join(a2_s6.RELAY_CONFIG, "d7.json")),
          ("PREFIX_JSON_SHA", posixpath.join(a2_s6.RELAY_CONFIG, "prefix.json")))


def _after_write(step):
    """A step's refusal exits 3 when the stage has already written through this layer (an earlier VM's start), and
    keeps its cause: exit 2 always means the stage wrote nothing."""
    @functools.wraps(step)
    def run(layer, *a, **kw):
        try:
            return step(layer, *a, **kw)
        except Refusal as r:
            if r.rc == 2 and layer.wrote(STAGE):
                raise Refusal(r.cause, r.detail, rc=3) from None
            raise
    return run


def _changed(what):
    return Refusal(STAGE + ".CONFIG_CHANGED", what)


@_after_write
def measure(layer, vm, v):
    """S6's own step-1 measurement (homes, uids, the hop gid), read only. Its refusals keep their name in START."""
    try:
        return a2_s6.measure(layer, vm, v)
    except Refusal as r:
        raise Refusal(STAGE + "." + r.cause.partition(".")[2], vm)


def _read(layer, vm, v, path):
    rc, out, _err = layer.exec(vm, [CAT, "--", path], account=v["agent_account"], stage=STAGE, writes=False)
    if rc != 0:
        raise _changed(path)
    return out


@_after_write
def config_in_place(layer, vm, v, s6, home):
    """Step 2 on one VM. `s6` is that VM's S6 receipt facts, `home` the agent account's home. Returns
    {"env": the env-file's {KEY: value}, "router": router.json's document}."""
    files = {}
    for fact, rel in PLACED:
        data = _read(layer, vm, v, posixpath.join(home, rel))
        if hashlib.sha256(data).hexdigest() != s6.get(fact):
            raise _changed(rel)
        files[fact] = data
    rc, out, _err = layer.exec(vm, [SHA256SUM, "--", r6.PLUGIN_PATH], account=v["agent_account"], stage=STAGE,
                               writes=False)
    m = _SHA_LINE.fullmatch(out) if rc == 0 else None
    if m is None or m.group(2).decode("utf-8", "replace") != r6.PLUGIN_PATH or m.group(1).decode() != s6.get(
            "PLUGIN_SHA"):
        raise _changed("plugin")
    rc, out, _err = layer.exec(vm, [STAT, "-c", STAT_FORMAT, "--", r6.PLUGIN_PATH, PLUGIN_DIR],
                               account=v["agent_account"], stage=STAGE, writes=False)
    lines = out.split(b"\n") if rc == 0 else []
    if len(lines) != 3 or lines[2] != b"" or lines[0] != b"0 0 444 regular file":
        raise _changed("plugin owner or mode")
    d = re.fullmatch(rb"0 0 ([0-7]{3,4}) directory", lines[1])
    if d is None or int(d.group(1), 8) & 0o022:
        raise _changed("plugin directory owner or mode")
    env_dir = posixpath.join(home, a2_s6.RE_ENV)
    rc, out, _err = layer.exec(vm, [STAT, "-c", STAT_FORMAT, "--", posixpath.join(env_dir, a2_s6.RE_ENV_NAME), env_dir],
                               account=v["agent_account"], stage=STAGE, writes=False)
    uid = re.escape(str(s6.get("AGENT_UID")).encode())
    if rc != 0 or not re.fullmatch(rb"%s [0-9]+ 600 regular file\n%s [0-9]+ 700 directory\n" % (uid, uid), out):
        raise _changed("env-file owner or mode")
    env = checks.parse_env(files["RE_ENV_SHA"])
    try:
        router = json.loads(files["ROUTER_JSON_SHA"])
        hop_root, registry_dir = router["hop"]["root"], router["registry_dir"]
    except (ValueError, KeyError, TypeError, RecursionError):
        raise _changed("router.json")
    if hop_root != env.get("HOP_ROOT") or registry_dir != env.get("HOP_REGISTRY_DIR"):
        raise _changed("router.json and the env-file name different hop or registry paths")
    plugin = router.get("transport_plugin")
    if (env.get("TRANSPORT_PLUGIN_PATH") != r6.PLUGIN_PATH or not isinstance(plugin, dict)
            or plugin.get("path") != r6.PLUGIN_PATH):
        raise _changed("router.json or the env-file names another plugin path")
    return {"env": env, "router": router}


def container_exists(layer, vm, v, name):
    """Whether docker has a container named exactly `name`, running or stopped."""
    rc, out, _err = layer.exec(vm, [DOCKER, "ps", "-a", "--filter", "name=^" + name + "$", "--format", "{{.ID}}"],
                               account=v["agent_account"], stage=STAGE, writes=False)
    if rc != 0:
        raise Refusal(STAGE + ".UNCLASSIFIED", "docker ps")
    if out == b"":
        return False
    if all(_CONTAINER_ID.fullmatch(line) for line in out.split(b"\n")[:-1]) and out.endswith(b"\n"):
        return True
    raise Refusal(STAGE + ".UNCLASSIFIED", "docker ps output")


def verify_argv(ledger_dir, image_id, relay_uid, relay_gid):
    """RE's read-only ledger check (RE's C1): its own --verify, without RELAY_LINK_ROLE, no env-file, no network. The
    ledger keeps S6's path rule (checks.mount_path) here too, before it is spliced into --mount."""
    if not checks.mount_path(ledger_dir):
        raise _changed("RELAY_LEDGER_DIR")
    return [DOCKER, "run", "--rm", "--pull", "never", "--network", "none", "--user", "%d:%d" % (relay_uid, relay_gid),
            "--entrypoint", "python3", "--mount", "type=bind,src=%s,dst=%s" % (ledger_dir, ledger_dir),
            "-e", "RELAY_LEDGER_DIR=" + ledger_dir, image_id, "/app/host/relay.py", "--verify"]


def ledger_report(out):
    """The `ledger` member of --verify's stdout, or None when there is no report that parses."""
    try:
        return json.loads(out)["ledger"]
    except (ValueError, KeyError, TypeError, RecursionError):
        return None


def ledger_state(out):
    """The step-4 decision from --verify's stdout: "no_init" proceeds; anything else refuses (ruling
    W13-S8-RE-C1-C7): available true is RUNNING; any other, or no report that parses, is LEDGER_UNUSABLE (nothing is
    started yet, so there is no relay container to read). A ledger directory that is gone never reaches RE: the stat
    before it refuses CONFIG_CHANGED, and docker's --mount refuses a missing source with no report (RE's C5)."""
    try:
        doc = json.loads(out)
        led = doc["ledger"]
    except (ValueError, KeyError, TypeError, RecursionError):
        raise Refusal(STAGE + ".LEDGER_UNUSABLE", "ledger check output")
    if led == {"available": False, "reason": "no_init"}:
        return "no_init"
    if led == {"available": True}:
        raise Refusal(STAGE + ".RUNNING", "the ledger is initialised")
    raise Refusal(STAGE + ".LEDGER_UNUSABLE", "ledger")


def ledger_in_place(layer, vm, v, ledger, relay_uid, relay_gid):
    """The relay ledger directory as S6's bootstrap made it (vm_dirs.RELAY_DIRS), stat'ed as the relay account, which
    owns it: no answer is CONFIG_CHANGED (gone), another owner, mode or type (a symlink included) LEDGER_UNUSABLE."""
    rc, out, _err = layer.exec(vm, [STAT, "-c", STAT_FORMAT, "--", ledger], account=v["relay_account"], stage=STAGE,
                               writes=False)
    if rc != 0:
        raise _changed("the ledger directory")
    if out != ("%d %d 700 directory\n" % (relay_uid, relay_gid)).encode():
        raise Refusal(STAGE + ".LEDGER_UNUSABLE", "ledger owner or mode")


@_after_write
def not_started(layer, vm, v, env, image_id, relay_uid, relay_gid):
    """Step 4 on one VM: no amap-rl or amap-re container, running or stopped, the ledger directory in place, and an
    uninitialised ledger."""
    for name in (RL_NAME, RE_NAME):
        if container_exists(layer, vm, v, name):
            raise Refusal(STAGE + ".RUNNING", name)
    if not isinstance(image_id, str) or not _IMAGE_ID.fullmatch(image_id):
        raise Refusal(STAGE + ".UNCLASSIFIED", "RE image id")
    ledger = env.get("RELAY_LEDGER_DIR")
    if not checks.mount_path(ledger):
        raise _changed("RELAY_LEDGER_DIR")
    if any(type(n) is not int or n <= 0 for n in (relay_uid, relay_gid)):
        raise Refusal(STAGE + ".UNCLASSIFIED", "relay uid or gid")
    ledger_in_place(layer, vm, v, ledger, relay_uid, relay_gid)
    _rc, out, _err = layer.exec(vm, verify_argv(ledger, image_id, relay_uid, relay_gid),
                                account=v["agent_account"], stage=STAGE, writes=False)
    return ledger_state(out)


def _under(base, path):
    return path.startswith(base + "/")


@_after_write
def trust_resolved(layer, vm, v, env, home, relay_home):
    """Section 3 form (a): every derived trust path is its own realpath, each resolved by the account that owns it
    (ruling W13-S8-C7-OWNING-ACCOUNT): the relay home's paths as the relay account, the rest as the agent account.
    Each group must lie under its account's home (the agent's may also be the plugin's directory), and the agent's
    includes the five files step 2 re-hashes, so a placed file swapped for a symlink to the same bytes refuses.
    Both homes must be absolute, normalised and not "/", so an empty one cannot make every path count as under it,
    and disjoint (as S6's measure requires), so neither root can widen to hold the other account's paths.
    Returns every trust path, sorted, for check_trust."""
    if not (checks._abs_norm(home) and checks._abs_norm(relay_home)) or "/" in (home, relay_home):
        raise Refusal(STAGE + ".TRUSTDIR_UNREAD", "an account home is malformed")
    if relay_home == home or _under(home, relay_home) or _under(relay_home, home):
        raise Refusal(STAGE + ".TRUSTDIR_UNREAD", "the account homes overlap")
    relay, agent = checks.trust_paths(env, home)
    agent = sorted(set(agent) | {posixpath.join(home, rel) for _fact, rel in PLACED})
    if not (all(_under(relay_home, p) for p in relay)
            and all(_under(home, p) or p == PLUGIN_DIR or _under(PLUGIN_DIR, p) for p in agent)):
        raise Refusal(STAGE + ".TRUSTDIR_UNREAD", "a trust path outside its account's home")
    for paths, account in ((relay, v["relay_account"]), (agent, v["agent_account"])):
        rc, out, _err = layer.exec(vm, checks.REALPATH_ARGV + paths, account=account, stage=STAGE, writes=False)
        checks.check_realpaths(paths, rc, out)
    return sorted(relay + agent)


@_after_write
def sources_resolved(layer, vm, v, mounts):
    """Section 3 form (b): every bind source of a container's mount table (a sandbox's, or RL's) is its own realpath,
    resolved as the agent account, so a symlinked source cannot hide a trust path from check_trust or a docker socket
    from check_daemon."""
    sources = sorted({src for typ, src in mounts if typ == checks.BIND})
    if not sources:
        return "RESOLVED"
    rc, out, _err = layer.exec(vm, checks.REALPATH_ARGV + sources, account=v["agent_account"], stage=STAGE,
                               writes=False)
    return checks.check_realpaths(sources, rc, out)
