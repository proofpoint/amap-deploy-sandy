"""Activation: the local router's run spec as it WILL run once `delegation`
is rendered, and the checks that hold the running router to it. NOTHING HERE
STARTS, STOPS OR WRITES INTO A RUNTIME.

The local router runs from its hop checkout's docker/run.sh with `--detach`.
run.sh resolves `--config`, binds exactly that path read-only at itself, sets
`ROUTER_CONFIG` to it, and mounts what docker/derive-mounts.py derives from
the config's bytes; derive-mounts also uses the config's PATH to refuse an
overlap. So the config's path is part of the run spec, and two inputs are
kept apart:
- the staged, token-less BYTES (the activation rendering, in the run
  directory), from which every derived mount comes, the key directory's
  bind included;
- the FINAL path (the router config install renders), which gives the
  config mount, `ROUTER_CONFIG`, and derive-mounts' overlap context.
The prospective spec is built from both, the way run.sh builds its argv and
environment, by running the hop checkout's own derive-mounts.py with the
final path as its argument and the staged bytes as what that path reads.
The real router is never started on the staged file.
"""

import json
import os
import subprocess
import sys
from collections import Counter
from typing import Any, Callable, Dict, List, Optional, Sequence

import router_health as rh

#: run.sh's default poll interval, which it passes as ROUTER_INTERVAL.
DEFAULT_INTERVAL = "5"
#: Runs the hop checkout's derive-mounts.py unchanged, with the one file it
#: reads, the config, answered from stdin: the bytes are the staged ones and
#: the path is the final one.
_DERIVE = (
    "import builtins, io, runpy, sys\n"
    "script, final = sys.argv[1], sys.argv[2]\n"
    "data = sys.stdin.read()\n"
    "real = builtins.open\n"
    "def opened(p, *a, **k):\n"
    "    return io.StringIO(data) if p == final else real(p, *a, **k)\n"
    "builtins.open = opened\n"
    "sys.argv = [script, final]\n"
    "runpy.run_path(script, run_name='__main__')\n")


class ActivationError(ValueError):
    """The activation spec cannot be built."""


def derived_mounts(checkout: str, final_path: str, staged: bytes) -> List[Dict[str, Any]]:
    """The mounts derive-mounts.py emits for `staged` read at `final_path`,
    in its order, as identity binds."""
    script = os.path.join(checkout, "docker", "derive-mounts.py")
    try:
        p = subprocess.run([sys.executable, "-I", "-c", _DERIVE, script, final_path], input=staged.decode("utf-8"),
                           capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ActivationError(f"derive-mounts could not run: {e}") from None
    if p.returncode != 0:
        lines = [l.strip() for l in (p.stderr or p.stdout).strip().splitlines() if l.strip()]
        raise ActivationError(f"derive-mounts refuses: {' '.join(lines[:2]) if lines else f'exit {p.returncode}'}")
    out = []
    for line in p.stdout.splitlines():
        path, _, mode = line.partition("\t")
        if not path.startswith("/") or mode not in ("rw", "ro"):
            raise ActivationError(f"derive-mounts printed {line!r}")
        out.append({"type": "bind", "source": path, "target": path, "readonly": mode == "ro"})
    return out


def prospective_spec(*, checkout: str, final_path: str, staged: bytes, image: str, container: str, uid: int,
                     gid: int, interval: str = DEFAULT_INTERVAL) -> Dict[str, Any]:
    """The local router's run spec as run.sh --detach builds it, for the
    staged bytes at the final path."""
    if not os.path.isabs(final_path) or os.path.normpath(final_path) != final_path:
        raise ActivationError("the final config path must be absolute and normalised")
    mounts = derived_mounts(checkout, final_path, staged)
    mounts.append({"type": "bind", "source": final_path, "target": final_path, "readonly": True})
    return {"name": container, "image": image, "user": f"{uid}:{gid}", "network": "none",
            "restart": "unless-stopped", "env": {"ROUTER_CONFIG": final_path, "ROUTER_INTERVAL": interval},
            "mounts": mounts}


def router_argv(spec: Dict[str, Any]) -> List[str]:
    """`docker run`'s arguments for a local-router spec, as run.sh builds them,
    ending with the image."""
    out = ["--name", spec["name"], "--network", spec["network"], "--user", spec["user"]]
    if spec.get("restart") and spec["restart"] != "no":
        out += ["--restart", spec["restart"]]
    for k, v in sorted(spec["env"].items()):
        out += ["-e", f"{k}={v}"]
    for m in spec["mounts"]:
        out += ["-v", f"{m['source']}:{m['target']}:{'ro' if m['readonly'] else 'rw'}"]
    return out + [spec["image"]]


#: The namespace modes run.sh leaves at the engine's default; anything else
#: (the host's, or another container's) is named. CgroupnsMode admits "host"
#: because that IS the engine's default on a cgroup v1 host ("private" on
#: v2), and run.sh sets no cgroup namespace either way.
DEFAULT_NAMESPACES = {"PidMode": ("",), "IpcMode": ("", "private", "shareable"), "UTSMode": ("",),
                      "UsernsMode": ("",), "CgroupnsMode": ("", "private", "host")}


def is_running(live: Any) -> Optional[bool]:
    """True only when `docker inspect` affirms it: running, not paused, not
    restarting. False when it affirms otherwise; None when it cannot tell."""
    state = live.get("State") if isinstance(live, dict) else None
    if not isinstance(state, dict) or not isinstance(state.get("Running"), bool):
        return None
    return state["Running"] and not state.get("Paused") and not state.get("Restarting")


def running_differences(live: Dict[str, Any], spec: Dict[str, Any], image: Dict[str, Any]) -> List[str]:
    """The running local router (`docker inspect`) against its spec, field by
    field: image, user, network, restart policy, the whole environment (the
    image's entries the spec does not set, then the spec's), the program (the
    image's own entrypoint and command, which run.sh never overrides), every
    mount of any type with its mode, every privilege run.sh never grants, and
    every namespace run.sh leaves at its default. `image` is the image's
    inspected config: {Env, Entrypoint, Cmd}. Nothing is masked."""
    image_env = list(image.get("Env") or [])
    bad = []
    cfg, host = live.get("Config") or {}, live.get("HostConfig") or {}
    if live.get("Image") != spec["image"]:
        bad.append(f"it runs image {live.get('Image')}, not {spec['image']}")
    if cfg.get("User") != spec["user"]:
        bad.append(f"it runs as {cfg.get('User')!r}, not {spec['user']!r}")
    if host.get("NetworkMode") != spec["network"]:
        bad.append(f"its network is {host.get('NetworkMode')!r}, not {spec['network']!r}")
    if (host.get("RestartPolicy") or {}).get("Name") != spec["restart"]:
        bad.append(f"its restart policy is not {spec['restart']}")
    want_env = [e for e in image_env if e.partition("=")[0] not in spec["env"]] + [
        f"{k}={v}" for k, v in sorted(spec["env"].items())]
    got_env = Counter(str(e) for e in cfg.get("Env") or [])
    for e in sorted((got_env - Counter(want_env)) + (Counter(want_env) - got_env)):
        k = e.partition("=")[0]
        if f"its environment differs at {k}" not in bad:
            bad.append(f"its environment differs at {k}")
    for key in ("CapAdd", "CapDrop", "SecurityOpt", "GroupAdd", "Devices"):
        if host.get(key):
            bad.append(f"it has {key} {host[key]!r}, which run.sh never sets")
    for key in ("Privileged", "ReadonlyRootfs"):
        if host.get(key):
            bad.append(f"it runs with {key}, which run.sh never sets")
    for key in ("Entrypoint", "Cmd"):
        if (cfg.get(key) or None) != (image.get(key) or None):
            bad.append(f"its {key} is {cfg.get(key)!r}, not the image's {image.get(key)!r}")
    for key, allowed in sorted(DEFAULT_NAMESPACES.items()):
        if (host.get(key) or "") not in allowed:
            bad.append(f"its {key} is {host.get(key)!r}, which run.sh never sets")
    got = sorted((str(m.get("Type")), m.get("Source"), m.get("Destination"), bool(m.get("RW")))
                 for m in live.get("Mounts") or [])
    want = sorted(("bind", m["source"], m["target"], not m["readonly"]) for m in spec["mounts"])
    if got != want:
        extra, missing = sorted(set(got) - set(want)), sorted(set(want) - set(got))
        bad.append("its mounts differ from the spec: " + "; ".join(
            [f"+{t}:{s}:{d}:{'rw' if w else 'ro'}" for t, s, d, w in extra] +
            [f"-{t}:{s}:{d}:{'rw' if w else 'ro'}" for t, s, d, w in missing]))
    return bad


def activation_binding(spec: Dict[str, Any], staged: bytes) -> str:
    """The binding the evidence carries for the local router: its activation
    config (canonical, without `partition_verified`) and its prospective
    spec, never its container id."""
    import partition_evidence as pe
    return pe.sha_json({"config": pe.config_binding(json.loads(staged)), "spec": spec})


#: What A1's loader check puts where A3 will put the token: the loader
#: refuses `delegation` without a non-empty `partition_verified`. It is never
#: written anywhere.
LOADER_PLACEHOLDER = "a1-loader-check:" + "0" * 64


def staged_bytes(doc: Dict[str, Any], delegation: Any, validate: Callable[[Dict[str, Any]], Optional[str]]) -> bytes:
    """A1: install's rendering of the local router's config (`doc`) with the
    `delegation` block the delegation rendering supplies, which carries no
    `partition_verified`, in install's own serialisation. It is held to the
    hop pin's loader (`validate`: None when it accepts) as A3 will write it,
    with LOADER_PLACEHOLDER as the token; the placeholder is never in the
    bytes returned."""
    if not isinstance(delegation, dict) or not isinstance(delegation.get("signing_key"), dict):
        raise ActivationError("the delegation block needs a signing_key")
    if "partition_verified" in delegation:
        raise ActivationError("the delegation block must not carry partition_verified: A3 adds the token")
    if "delegation" in doc:
        raise ActivationError("the rendering already carries a delegation block")
    staged = (json.dumps(dict(doc, delegation=delegation), indent=2) + "\n").encode("utf-8")
    refused = validate(json.loads(final_bytes(staged, LOADER_PLACEHOLDER)))
    if refused:
        raise ActivationError(f"the hop router's loader refuses the activation rendering: {refused}")
    return staged


def final_bytes(staged: bytes, token: str) -> bytes:
    """A3: the staged bytes with exactly `delegation.partition_verified` set to
    `token`, and nothing else changed."""
    doc = json.loads(staged)
    if not isinstance(doc.get("delegation"), dict):
        raise ActivationError("the activation config has no delegation block to carry the token")
    if "partition_verified" in doc["delegation"]:
        raise ActivationError("the staged config already carries a token")
    doc["delegation"]["partition_verified"] = token
    # install's own serialisation (amap_sandy.sibling_text): insertion order,
    # so the token is the delegation block's last member, as the renderer
    # places it.
    return (json.dumps(doc, indent=2) + "\n").encode("utf-8")


#: Where a supervisor would live that could restart the local router: every
#: directory systemd loads system units from, and launchd's system-wide
#: daemons and agents.
SUPERVISOR_DIRS = ("/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system",
                   "/usr/lib/systemd/system", "/lib/systemd/system", "/Library/LaunchDaemons", "/Library/LaunchAgents")


def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def supervisor_problems(container: str, *, dirs: Sequence[str] = SUPERVISOR_DIRS,
                        listdir=os.listdir, read=None) -> Any:
    """Every unit or LaunchDaemon file that names the local router's
    container: one would start it again after a fail-stop stop. The local
    router runs `--detach` under `unless-stopped` and nothing else restarts
    it. An Unresolved when a file that exists cannot be read."""
    read = read or _read_bytes
    needle = container.encode("utf-8")
    bad = []
    for d in dirs:
        try:
            names = sorted(listdir(d))
        except FileNotFoundError:
            continue
        except OSError as e:
            return rh.Unresolved(f"cannot list {d}: {e}")
        for n in names:
            p = os.path.join(d, n)
            try:
                data = read(p)
            except IsADirectoryError:
                continue
            except OSError as e:
                return rh.Unresolved(f"cannot read {p}: {e}")
            if needle in data:
                bad.append(p)
    return bad


#: The way back to a router that does not sign, for any A5 failure (§3.2).
A5_REMEDY = ("render the local router's config without delegation (install --apply) and restart it; then a "
             "fresh partition-probe --apply and the activation again")


def verify_activation(*, live: Any, image: Any, spec: Dict[str, Any], staged: bytes, final_raw: Any,
                      token: Optional[str]) -> List[rh.Check]:
    """A5: the running local router is exactly A1's activation spec, its live
    config is A1's staged bytes plus the token and nothing else, and that
    token is the current passing evidence's (`token`: None when there is no
    current passing document). `live`, `image` (the image's inspected
    config) and `final_raw` are Unresolved when they could not be read. A
    router not affirmed running is never judged its spec."""
    import partition_evidence as pe
    out = []
    claim = "the running local router is exactly its activation spec"
    want = rh.Fact("activation spec", True, "A1's prospective spec for the final config path, as run.sh builds it")
    blocked = next((v for v in (live, image) if isinstance(v, rh.Unresolved)), None)
    running = None if blocked is not None or live is None else is_running(live)
    if blocked is not None:
        out.append(rh.unknown(claim, want, blocked.reason, "start the local router, or make the engine answer"))
    elif running is not True:
        out.append(rh.unknown(claim, want, "the local router is not running" if running is False or live is None
                              else "the engine does not say whether the local router runs",
                              "start the local router, or make the engine answer"))
    else:
        bad = running_differences(live, spec, image)
        out.append(rh.check(claim, want, "; ".join(bad) if bad else True, A5_REMEDY,
                            do_not="never edit the spec to match what is running"))

    claim = "the local router's live config is the activation rendering plus the token, and nothing else"
    if token is None:
        out.append(rh.unknown(claim, rh.Fact("config", rh.Unresolved("no token"), "A1's bytes plus the token"),
                              "there is no current passing evidence, so no token to expect", A5_REMEDY))
    else:
        try:
            expected = pe.sha_bytes(final_bytes(staged, token))
        except ActivationError as e:
            expected = rh.Unresolved(str(e))
        want = rh.Fact("config", expected, "A1's staged bytes with the current passing evidence's token added")
        if isinstance(expected, rh.Unresolved):
            out.append(rh.unknown(claim, want, f"the expected bytes cannot be built: {expected.reason}", A5_REMEDY))
        elif isinstance(final_raw, rh.Unresolved):
            out.append(rh.unknown(claim, want, final_raw.reason, "make the final config path readable"))
        else:
            out.append(rh.check(claim, want, pe.sha_bytes(final_raw), A5_REMEDY,
                                do_not="never rewrite the live config by hand"))
    return out
