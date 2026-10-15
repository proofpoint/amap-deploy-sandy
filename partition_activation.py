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
from typing import Any, Dict, List, Optional, Sequence

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


def running_differences(live: Dict[str, Any], spec: Dict[str, Any]) -> List[str]:
    """The running local router (`docker inspect`) against its spec, field by
    field: image, user, network, restart policy, the two environment
    variables, and the exact set of binds with their modes. Nothing is masked."""
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
    env = dict(e.partition("=")[::2] for e in cfg.get("Env") or [])
    for k, v in sorted(spec["env"].items()):
        if env.get(k) != v:
            bad.append(f"its {k} is {env.get(k)!r}, not {v!r}")
    got = sorted((m.get("Source"), m.get("Destination"), bool(m.get("RW"))) for m in live.get("Mounts") or []
                 if m.get("Type") == "bind")
    want = sorted((m["source"], m["target"], not m["readonly"]) for m in spec["mounts"])
    if got != want:
        extra, missing = sorted(set(got) - set(want)), sorted(set(want) - set(got))
        bad.append("its binds differ from the spec: " + "; ".join(
            [f"+{s}:{d}:{'rw' if w else 'ro'}" for s, d, w in extra] +
            [f"-{s}:{d}:{'rw' if w else 'ro'}" for s, d, w in missing]))
    return bad


def activation_binding(spec: Dict[str, Any], staged: bytes) -> str:
    """The binding the evidence carries for the local router: its activation
    config (canonical, without `partition_verified`) and its prospective
    spec, never its container id."""
    import partition_evidence as pe
    return pe.sha_json({"config": pe.config_binding(json.loads(staged)), "spec": spec})


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
