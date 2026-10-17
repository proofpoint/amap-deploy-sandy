"""The local router's upgrade base: a stop-gating precondition for the
activation's outage window. NOTHING HERE STOPS, STARTS OR CHANGES A ROUTER.

`amap-sandy.py router-fingerprint` captures what the running local router
([1]) is: the source it runs, the process that runs it, the config it
loaded and its state directory. It then decides whether the upgrade to the
hop pin was measured from that base (`router-upgrade-bases.json`, which the
router's maintainers review).

- Capture: `--step 0|2` reads the running container through one `docker
  exec` of PROGRAM, as the container's own user; `--image REF` runs PROGRAM
  in a throwaway container of the image's immutable Id. Each writes one
  canonical JSON file into the run directory, and only with `--apply`.
- The stop gate: `precheck`, `read_history` and `match`. The history enters
  as data: `read_history` builds it from object bytes it re-hashes itself,
  so neither replace refs, grafts, a commit-graph nor a forged loose object
  can move what the gate compares.
- `verify_image` answers whether an image capture is exactly one commit's
  router package: the clean-build check before A1.

The outcomes are MEASURED (exit 0), UNMEASURED (1), UNKNOWN (2) and MIGRATE
(3) for the match, and EXACT (0), DIFFERS (1) and UNKNOWN (2) for the image
check. MIGRATE means every check passed and the router's state is keyed by
instance name (`migration_required`), or its base predates `registry_dir`
(`pre_registry_base`): the upgrade is supported only by the router's own
migration, the runbook's R2, which no activation window runs. Every refusal
has a stable reason id, so another program compares ids, not prose.

The clock premises the match relies on (step 7):
- C1: the host wall clock is not stepped between the previous router
  process's last status write and this capture, nor while the live config
  could have been edited;
- C2: the config's ctime is stamped by the same clock as the router's
  timestamps, which holds on a filesystem local to the kernel that runs the
  container. A network or VM-shared filesystem stamps ctime with another
  clock, and the offset between the two is not bounded here.
Outside them a MEASURED answer is not a proof. The checks refuse what can
be detected of a violation.
"""

from __future__ import annotations

import calendar
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from fractions import Fraction
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import hygiene_gate as hg

SCHEMA = "amap-deploy.router-fingerprint/2"
BASES_NAME = "router-upgrade-bases.json"
BASES_SCHEMA = 3
BASES_PATH = Path(__file__).resolve().parent / BASES_NAME

MEASURED, UNMEASURED, UNKNOWN = "MEASURED", "UNMEASURED", "UNKNOWN"
#: Every stop-gate check passed, and the upgrade is supported only through the
#: router's own migration: continue, and only through the runbook's migration branch.
MIGRATE = "MIGRATE"
EXACT, DIFFERS = "EXACT", "DIFFERS"
EXIT = {MEASURED: 0, UNMEASURED: 1, UNKNOWN: 2, MIGRATE: 3, EXACT: 0, DIFFERS: 1}

_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_UMASK = re.compile(r"[0-7]{4}")
#: The time grammars match ASCII digits only: `\d` in a str pattern also matches other scripts' digits.
_AT = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{6})Z")
_WHOLE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z")
_DOCKER_TS = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z")
_PY_ENV_NAME = re.compile(r"PYTHON[A-Z]")
#: Docker's container-name grammar, so a --container value never reaches docker as an option.
CONTAINER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")

#: The pinned router's own vocabulary for its state_dir's top level
#: (router/config.py, router/registry.py and router/generations.py at the pin;
#: a test holds these equal to the hop checkout's): the names of the entries it
#: keeps there itself (RESERVED_STATE_NAMES, compared casefolded), an
#: instance name's grammar, a logical_id's shape, and the file that makes a
#: logical_id directory generation-keyed.
RESERVED_STATE_NAMES = frozenset({"registry", "status.json", "aliases", "peer-decision.key", "peer-replay",
                                  "peer-vacant", "peer-clock.json", "_runtime"})
INSTANCE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
#: A logical_id is lowercase, as the pinned registry mints it; 32 hex digits
#: in any other case are neither a logical_id nor a name the router keys by.
LOGICAL_ID = re.compile(r"[0-9a-f]{32}")
HEX32 = re.compile(r"[0-9a-fA-F]{32}")
GEN_FILE = "generations.json"
LAYOUT_KINDS = ("dir", "file", "link", "other")
#: A pre-registry router's entrypoint sets no umask (amap-router-local's
#: docker/entrypoint.sh gains `umask 0027` at 08aeed47, 31 first-parent
#: commits below the pin and 17 after a84e0d98); its PID 1, measured live,
#: must still mask group and other write. The umask reaches only directories
#: there: its state files are created 0600 explicitly, as the router's
#: maintainers measured over every rehearsal under 0022.
PRE_REGISTRY_UMASK_BITS = 0o022

ENTRY_TYPES = ("file", "dir", "link", "other")
OBJECT_TYPES = ("commit", "tree", "blob", "tag")
#: The raw tree modes, compared as the exact strings a tree object holds.
#: Every other string, `040000` and `160000` included, is `other`.
TREE_MODES = {b"100644": "file", b"100755": "file", b"120000": "link", b"40000": "dir"}

#: The only `^PYTHON[A-Z]` names the running router may carry. 3.11 reads no
#: `PYTHON_`-underscore name, which is why the interpreter must be 3.11.
PYTHON_ENV_ALLOWED = frozenset({"PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE"})
#: The run form: `python3 -m router --config <path> run --interval <n>`.
RUN_FORM_HEAD = ["python3", "-m", "router"]
RUN_FORM_ARGC = 8
ROUTER_CWD = "/app"
ROUTER_UMASK = "0027"
INTERPRETER = ("cpython", 3, 11)
APP_LAYOUT = {"router": "dir", "docker": "dir"}
DOCKER_LAYOUT = {"entrypoint.sh": "file"}
#: The one router subdirectory a clean image carries; the runtime never imports it.
TESTS_DIR = "tests"
PYCACHE = "__pycache__"
NATIVE_SUFFIXES = (".so", ".pyc", ".pth")

NS = 1_000_000_000
#: |at - the router's clock| may be at most this (step 7, `clock_skew`).
CLOCK_SKEW_NS = NS
#: The status must be stamped at least this long after StartedAt's second.
STALE_AFTER_S = 2
#: T may precede StartedAt's second by at most this (a late stamp).
STARTED_SLACK_S = 1
#: A status stamped after the capture's second by more than this is from the future.
FUTURE_SLACK_S = 1
#: The window for T minus PID 1's estimated start, for a µs T and a whole-second T.
PID1_AGE_US = (Fraction(-5, 100) * NS, 5 * NS)
PID1_AGE_WHOLE = (Fraction(-105, 100) * NS, 5 * NS)

STATUS_MEMBERS = ("started_ts", "process_started_ts", "last_poll_ts", "classification", "transport_plugin")
RELOAD_FLAG = "config_reload_failed"

#: The program the capture runs inside the router's container (`python3 -I -S
#: -c PROGRAM running`) or inside a throwaway container of an image
#: (`... image`). It never writes. Its functions are the test seam: tests
#: `exec` it under another `__name__` and call them on fixture paths.
PROGRAM = r'''
import hashlib, json, os, stat, sys, time

ERRORS = []
STATUS_MEMBERS = ("started_ts", "process_started_ts", "last_poll_ts", "classification", "transport_plugin")


def err(what, why=None):
    ERRORS.append(what if why is None else "%s: %s" % (what, why))


def kind(mode):
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISLNK(mode):
        return "link"
    return "other"


def entries(path):
    out = {}
    try:
        names = os.listdir(path)
    except OSError as e:
        err("cannot list " + path, e.strerror)
        return None
    for name in names:
        try:
            out[name] = kind(os.lstat(os.path.join(path, name)).st_mode)
        except OSError as e:
            err("cannot lstat " + os.path.join(path, name), e.strerror)
    return out


def read_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(0, "not a regular file")
        chunks = []
        while True:
            b = os.read(fd, 65536)
            if not b:
                return b"".join(chunks)
            chunks.append(b)
    finally:
        os.close(fd)


def blob(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def read_app(app):
    """/app, /app/docker and /app/router as {name: type}; every top-level
    regular *.py's blob id; docker/entrypoint.sh's blob id, or None."""
    out = {"app": entries(app), "docker": entries(os.path.join(app, "docker")),
           "entries": entries(os.path.join(app, "router")), "py": None, "entrypoint": None}
    if out["entries"] is not None:
        py = {}
        for name in sorted(out["entries"]):
            if out["entries"][name] == "file" and name.endswith(".py"):
                try:
                    py[name] = blob(read_file(os.path.join(app, "router", name)))
                except OSError as e:
                    err("cannot read " + os.path.join(app, "router", name), e.strerror)
        out["py"] = py
    if (out["docker"] or {}).get("entrypoint.sh") == "file":
        try:
            out["entrypoint"] = blob(read_file(os.path.join(app, "docker", "entrypoint.sh")))
        except OSError as e:
            err("cannot read " + os.path.join(app, "docker", "entrypoint.sh"), e.strerror)
    return out


def parse_environ(raw, where):
    """An environ block as {name: value}. A name set twice is an error: the
    interpreter reads the first, so the block is not one answer."""
    env = {}
    for item in raw.split(b"\0"):
        if b"=" in item:
            k, _, v = item.partition(b"=")
            name = os.fsdecode(k)
            if name in env:
                err(where + "/environ names " + name + " more than once")
            env[name] = os.fsdecode(v)
    return env


def read_process(pid):
    """PID `pid`'s argv, cwd, ROUTER_CONFIG, PYTHON* entries, LD_* names and
    umask; and its whole environment, for the user-site lookup."""
    proc = "/proc/%d" % pid
    with open(proc + "/cmdline", "rb") as f:
        raw = f.read().split(b"\0")
    if raw and raw[-1] == b"":
        raw.pop()
    with open(proc + "/environ", "rb") as f:
        env = parse_environ(f.read(), proc)
    umask = None
    with open(proc + "/status") as f:
        for line in f:
            if line.startswith("Umask:"):
                umask = line.split()[1]
    if umask is None:
        err("no Umask line in " + proc + "/status")
    doc = {"argv": [os.fsdecode(a) for a in raw], "cwd": os.readlink(proc + "/cwd"),
           "router_config": env.get("ROUTER_CONFIG"),
           "python_env": {k: v for k, v in env.items() if k.startswith("PYTHON")},
           "ld_env": sorted(k for k in env if k.startswith("LD_")), "umask": umask}
    return doc, env


def user_site(env):
    """Whether the user site directory PID 1 would load from exists: the
    lookup made under PID 1's HOME and PYTHONUSERBASE."""
    import site
    keys = ("HOME", "PYTHONUSERBASE")
    saved = {k: os.environ.get(k) for k in keys}
    try:
        for k in keys:
            if k in env:
                os.environ[k] = env[k]
            else:
                os.environ.pop(k, None)
        site.USER_BASE = None
        site.USER_SITE = None
        return os.path.exists(site.getusersitepackages())
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def read_interpreter(pid, env):
    impl = sys.implementation
    return {"name": impl.name, "major": sys.version_info[0], "minor": sys.version_info[1],
            "exec_exe": os.path.realpath(sys.executable),
            "pid1_exe": None if pid is None else os.path.realpath("/proc/%d/exe" % pid),
            "user_site": None if env is None else user_site(env)}


def read_config(path):
    """The live config, bound to ONE opened object: realpath before the open
    and after the read; one O_RDONLY|O_NOFOLLOW|O_NONBLOCK open; the first
    fstat, before any read, supplies the identity; a second fstat after the
    read, and a stat of the path, decide `stable`."""
    out = {"path": path, "realpath_ok": None, "regular": None, "stable": None, "dev": None, "ino": None,
           "ctime_ns": None, "state_dir": None, "transport_plugin": None, "registry_dir": None}
    before = os.path.realpath(path) == path
    out["realpath_ok"] = before
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as e:
        err("cannot open the live config " + path, e.strerror)
        return out
    try:
        st1 = os.fstat(fd)
        if not stat.S_ISREG(st1.st_mode):
            out["regular"] = False
            err("the live config is not a regular file")
            return out
        out.update(regular=True, dev=st1.st_dev, ino=st1.st_ino, ctime_ns=st1.st_ctime_ns)
        hook = globals().get("HOOK")
        if hook is not None:
            hook()
        chunks = []
        try:
            while True:
                b = os.read(fd, 65536)
                if not b:
                    break
                chunks.append(b)
        except OSError as e:
            err("cannot read the live config", e.strerror)
            return out
        data = b"".join(chunks)
        st2 = os.fstat(fd)
    finally:
        os.close(fd)
    if len(data) != st1.st_size:
        err("the live config's size changed during the read")
    ident = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    try:
        ps = os.stat(path)
        same_path = (ps.st_dev, ps.st_ino) == (st1.st_dev, st1.st_ino)
    except OSError as e:
        err("cannot stat the live config after the read", e.strerror)
        same_path = False
    out["realpath_ok"] = before and os.path.realpath(path) == path
    out["stable"] = ident(st1) == ident(st2) and same_path
    try:
        doc = json.loads(data)
    except ValueError as e:
        err("the live config is not JSON", str(e))
        return out
    if not isinstance(doc, dict) or not isinstance(doc.get("state_dir"), str):
        err("the live config names no state_dir")
    else:
        out["state_dir"] = doc["state_dir"]
    tp = doc.get("transport_plugin") if isinstance(doc, dict) else None
    present = isinstance(doc, dict) and "transport_plugin" in doc
    sha = tp.get("sha256") if isinstance(tp, dict) else None
    if present and not isinstance(sha, str):
        err("the live config's transport_plugin has no sha256")
    out["transport_plugin"] = {"present": present, "sha256": sha if present else None}
    rd_present = isinstance(doc, dict) and "registry_dir" in doc
    rd = doc.get("registry_dir") if rd_present else None
    if rd_present and not isinstance(rd, str):
        err("the live config's registry_dir is not a string")
        rd = None
    out["registry_dir"] = {"present": rd_present, "value": rd}
    return out


def read_layout(state_dir):
    """state_dir's top level, never followed: each entry's name and kind, and
    for a directory whether it holds a regular generations.json (null when
    that cannot be read)."""
    with os.scandir(state_dir) as it:
        found = list(it)
    out = []
    for e in found:
        if e.is_symlink():
            kind = "link"
        elif e.is_dir(follow_symlinks=False):
            kind = "dir"
        elif e.is_file(follow_symlinks=False):
            kind = "file"
        else:
            kind = "other"
        gen = None
        if kind == "dir":
            try:
                st = os.lstat(os.path.join(state_dir, e.name, "generations.json"))
                gen = True if stat.S_ISREG(st.st_mode) else None
                if gen is None:
                    err("a generations.json under the state directory is not a regular file")
            except FileNotFoundError:
                gen = False
            except OSError as x:
                err("cannot read a generations.json under the state directory", x.strerror)
        out.append([e.name, kind, gen])
    return {"state_dir": state_dir, "entries": sorted(out)}


def read_status(state_dir):
    try:
        doc = json.loads(read_file(os.path.join(state_dir, "status.json")))
    except OSError as e:
        err("cannot read " + os.path.join(state_dir, "status.json"), e.strerror)
        return None
    except ValueError as e:
        err("status.json is not JSON", str(e))
        return None
    if not isinstance(doc, dict):
        err("status.json is not an object")
        return None
    return {m: {"present": m in doc, "value": doc.get(m)} for m in STATUS_MEMBERS}


def walk_peer(state_dir):
    """Whether any entry under state_dir, at any depth, is named peer-*. A
    walk error is recorded, and with one the answer is never false."""
    found = False
    failed = []
    for _, dirs, files in os.walk(state_dir, onerror=failed.append, followlinks=False):
        if any(n.startswith("peer-") for n in dirs + files):
            found = True
    for e in failed:
        err("cannot walk " + str(e.filename), e.strerror)
    return {"state_dir": state_dir, "peer_entries": True if found else (None if failed else False)}


def read_clock(pid):
    """The wall clock, the uptime and PID `pid`'s start tick, read in that
    order with nothing between them, and the tick length."""
    now_ns = time.time_ns()
    with open("/proc/uptime") as f:
        up = f.read()
    with open("/proc/%d/stat" % pid) as f:
        st = f.read()
    fields = st[st.rindex(")") + 2:].split()
    return {"now_ns": now_ns, "uptime_s": float(up.split()[0]), "pid1_starttime_ticks": int(fields[19]),
            "clk_tck": os.sysconf("SC_CLK_TCK")}


def guarded(what, fn, *args):
    try:
        return fn(*args)
    except Exception as e:
        err("cannot read " + what, "%s: %s" % (type(e).__name__, e))
        return None


def collect(mode, app="/app", pid=1):
    result = dict(guarded("/app", read_app, app) or {"app": None, "docker": None, "entries": None,
                                                         "py": None, "entrypoint": None})
    process = config = status = peer = clock = env = layout = None
    if mode == "running":
        got = guarded("PID 1", read_process, pid)
        if got is not None:
            process, env = got
        result["interpreter"] = guarded("the interpreter", read_interpreter, pid, env)
        path = (process or {}).get("router_config")
        if process is not None and path is None:
            err("PID 1 has no ROUTER_CONFIG")
        if path is not None:
            config = guarded("the live config", read_config, path)
        state_dir = (config or {}).get("state_dir")
        if state_dir is not None:
            status = guarded("status.json", read_status, state_dir)
            peer = guarded("the state directory", walk_peer, state_dir)
            layout = guarded("the state directory's top level", read_layout, state_dir)
        clock = guarded("the clock", read_clock, pid)
    else:
        result["interpreter"] = guarded("the interpreter", read_interpreter, None, None)
    result.update(process=process, config=config, status=status, peer_lane=peer, clock=clock,
                  state_layout=layout)
    result["errors"] = list(ERRORS)
    return result


def main(mode):
    if mode not in ("running", "image"):
        raise SystemExit("usage: PROGRAM running|image")
    sys.stdout.write(json.dumps(collect(mode), sort_keys=True))


if __name__ == "__main__":
    main(sys.argv[1])
'''
PROGRAM_SHA256 = hashlib.sha256(PROGRAM.encode("utf-8")).hexdigest()


class HistoryReadError(Exception):
    """The hop checkout's history could not be read, or failed verification.
    The one exception `read_history` raises; a caller maps it to UNKNOWN
    `history_read`."""


# --- Canonical JSON and times -----------------------------------------------------


def canonical(doc: Any) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def utc_at(t_ns: int) -> str:
    """The host's UTC time in the capture's exact form, `%Y-%m-%dT%H:%M:%S.%fZ`."""
    s, ns = divmod(t_ns, NS)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(s)) + ".%06dZ" % (ns // 1000)


def _epoch(m: "re.Match[str]") -> int:
    y, mo, d, h, mi, s = (int(x) for x in m.groups()[:6])
    datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc)   # range-checks every field
    return calendar.timegm((y, mo, d, h, mi, s))


def parse_at(v: Any) -> int:
    """`at_before`/`at` and µs `process_started_ts`: nanoseconds."""
    m = _AT.fullmatch(v) if isinstance(v, str) else None
    if m is None:
        raise ValueError(f"{v!r} is not %Y-%m-%dT%H:%M:%S.%fZ")
    return _epoch(m) * NS + int(m.group(7)) * 1000


def parse_whole(v: Any) -> int:
    """`started_ts` and `last_poll_ts`: whole seconds."""
    m = _WHOLE.fullmatch(v) if isinstance(v, str) else None
    if m is None:
        raise ValueError(f"{v!r} is not %Y-%m-%dT%H:%M:%SZ")
    return _epoch(m)


def parse_started_at(v: Any) -> int:
    """Docker's StartedAt, RFC 3339 UTC with up to nanoseconds, floored to seconds."""
    m = _DOCKER_TS.fullmatch(v) if isinstance(v, str) else None
    if m is None:
        raise ValueError(f"{v!r} is not Docker's RFC 3339 UTC")
    return _epoch(m)


# --- The capture's structure ------------------------------------------------------


class _Bad(Exception):
    pass


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _str_map(v: Any, value_ok: Callable[[Any], bool]) -> bool:
    return isinstance(v, dict) and all(isinstance(k, str) and value_ok(x) for k, x in v.items())


def _members(v: Any, keys: Sequence[str], what: str) -> Dict[str, Any]:
    if not isinstance(v, dict) or set(v) != set(keys):
        raise _Bad(f"{what} does not have exactly the members {sorted(keys)}")
    return v


def _want(ok: bool, what: str) -> None:
    if not ok:
        raise _Bad(what)


TOP = ("schema", "source", "step", "at_before", "at", "container", "image", "image_python_env",
       "program_sha256", "result")
RESULT = ("app", "docker", "entries", "py", "entrypoint", "process", "clock", "interpreter", "config",
          "status", "peer_lane", "state_layout", "errors")
PROCESS = ("argv", "cwd", "router_config", "python_env", "ld_env", "umask")
CLOCK = ("now_ns", "uptime_s", "pid1_starttime_ticks", "clk_tck")
INTERP = ("name", "major", "minor", "exec_exe", "pid1_exe", "user_site")
CONFIG = ("path", "realpath_ok", "regular", "stable", "dev", "ino", "ctime_ns", "state_dir", "transport_plugin",
          "registry_dir")
PEER = ("state_dir", "peer_entries")


def _structure(doc: Any) -> None:
    """Raises _Bad unless `doc` has every member set exactly, for its source.
    A `result` member that could not be read may be null only when `errors`
    is non-empty."""
    _members(doc, TOP, "the capture")
    _want(doc["schema"] == SCHEMA, f"schema is not {SCHEMA}")
    src = doc["source"]
    _want(src in ("running", "image"), "source is neither running nor image")
    running = src == "running"
    _want(isinstance(doc["at_before"], str) and isinstance(doc["at"], str), "at_before and at are strings")
    _want(_str_map(doc["image_python_env"], lambda x: isinstance(x, str)), "image_python_env is {name: value}")
    _want(isinstance(doc["program_sha256"], str) and _HEX64.fullmatch(doc["program_sha256"]) is not None,
          "program_sha256 is 64 hex")
    if running:
        _want(_is_int(doc["step"]) and doc["step"] in (0, 2), "step is 0 or 2")
        c = _members(doc["container"], ("id", "name", "image", "started_at"), "container")
        _want(isinstance(c["id"], str) and _HEX64.fullmatch(c["id"]) is not None, "container.id is 64 hex")
        _want(isinstance(c["name"], str), "container.name is a string")
        _want(isinstance(c["image"], str) and _IMAGE_ID.fullmatch(c["image"]) is not None,
              "container.image is sha256:<64 hex>")
        _want(isinstance(c["started_at"], str), "container.started_at is a string")
        _want(doc["image"] is None, "image is null for a running capture")
    else:
        _want(doc["step"] is None and doc["container"] is None, "step and container are null for an image")
        i = _members(doc["image"], ("ref", "id"), "image")
        _want(isinstance(i["ref"], str) and isinstance(i["id"], str) and _IMAGE_ID.fullmatch(i["id"]) is not None,
              "image is {ref, id: sha256:<64 hex>}")
    r = _members(doc["result"], RESULT, "result")
    _want(isinstance(r["errors"], list) and all(isinstance(e, str) for e in r["errors"]), "errors is a list of strings")
    loose = bool(r["errors"])

    def opt(v: Any, ok: bool, what: str) -> None:
        _want(ok or (loose and v is None), what)

    for k in ("app", "docker", "entries"):
        opt(r[k], _str_map(r[k], lambda x: x in ENTRY_TYPES), f"{k} is {{name: type}}")
    opt(r["py"], _str_map(r["py"], lambda x: isinstance(x, str) and _HEX40.fullmatch(x) is not None),
        "py is {name: 40-hex}")
    _want(r["entrypoint"] is None or (isinstance(r["entrypoint"], str) and _HEX40.fullmatch(r["entrypoint"])),
          "entrypoint is 40-hex or null")
    it = r["interpreter"]
    if it is not None:
        _members(it, INTERP, "interpreter")
        _want(isinstance(it["name"], str) and _is_int(it["major"]) and _is_int(it["minor"])
              and isinstance(it["exec_exe"], str), "interpreter's name, version and exec_exe")
        if running:
            opt(it["pid1_exe"], isinstance(it["pid1_exe"], str), "interpreter.pid1_exe is a string")
            opt(it["user_site"], isinstance(it["user_site"], bool), "interpreter.user_site is a bool")
        else:
            _want(it["pid1_exe"] is None and it["user_site"] is None, "an image has no PID 1")
    else:
        _want(loose, "interpreter is present")
    if not running:
        for k in ("process", "clock", "config", "status", "peer_lane", "state_layout"):
            _want(r[k] is None, f"{k} is null for an image")
        return
    p = r["process"]
    if p is not None:
        _members(p, PROCESS, "process")
        _want(isinstance(p["argv"], list) and all(isinstance(a, str) for a in p["argv"]), "argv is a list of strings")
        _want(isinstance(p["cwd"], str), "cwd is a string")
        _want(p["router_config"] is None or isinstance(p["router_config"], str), "router_config is a string or null")
        _want(_str_map(p["python_env"], lambda x: isinstance(x, str)), "python_env is {name: value}")
        _want(isinstance(p["ld_env"], list) and all(isinstance(a, str) for a in p["ld_env"]), "ld_env is names")
        opt(p["umask"], isinstance(p["umask"], str) and _UMASK.fullmatch(p["umask"]) is not None,
            "umask is four octal digits")
    else:
        _want(loose, "process is present")
    k = r["clock"]
    if k is not None:
        _members(k, CLOCK, "clock")
        _want(_is_int(k["now_ns"]) and _is_int(k["pid1_starttime_ticks"]) and _is_int(k["clk_tck"])
              and k["clk_tck"] > 0, "clock's integers")
        _want(isinstance(k["uptime_s"], (int, float)) and not isinstance(k["uptime_s"], bool), "uptime_s is a number")
    else:
        _want(loose, "clock is present")
    c = r["config"]
    if c is not None:
        _members(c, CONFIG, "config")
        _want(isinstance(c["path"], str), "config.path is a string")
        opt(c["realpath_ok"], isinstance(c["realpath_ok"], bool), "config.realpath_ok is a bool")
        opt(c["regular"], isinstance(c["regular"], bool), "config.regular is a bool")
        opt(c["stable"], isinstance(c["stable"], bool), "config.stable is a bool")
        for f in ("dev", "ino", "ctime_ns"):
            opt(c[f], _is_int(c[f]), f"config.{f} is an integer")
        opt(c["state_dir"], isinstance(c["state_dir"], str), "config.state_dir is a string")
        tp = c["transport_plugin"]
        if tp is None:
            _want(loose, "config.transport_plugin is present")
        else:
            _members(tp, ("present", "sha256"), "config.transport_plugin")
            _want(isinstance(tp["present"], bool), "config.transport_plugin.present is a bool")
            _want(tp["sha256"] is None if not tp["present"] else (isinstance(tp["sha256"], str) or loose),
                  "config.transport_plugin.sha256")
        rd = c["registry_dir"]
        if rd is None:
            _want(loose, "config.registry_dir is present")
        else:
            _members(rd, ("present", "value"), "config.registry_dir")
            _want(isinstance(rd["present"], bool) and (rd["value"] is None if not rd["present"]
                                                       else (isinstance(rd["value"], str) or loose)),
                  "config.registry_dir is {present, value}")
    else:
        _want(loose, "config is present")
    s = r["status"]
    if s is not None:
        _members(s, STATUS_MEMBERS, "status")
        for m in STATUS_MEMBERS:
            e = _members(s[m], ("present", "value"), f"status.{m}")
            _want(isinstance(e["present"], bool) and (e["present"] or e["value"] is None),
                  f"status.{m} is {{present, value}}")
    else:
        _want(loose, "status is present")
    pl = r["peer_lane"]
    if pl is not None:
        _members(pl, PEER, "peer_lane")
        _want(isinstance(pl["state_dir"], str) and (pl["peer_entries"] is None or isinstance(pl["peer_entries"], bool)),
              "peer_lane is {state_dir, peer_entries}")
    else:
        _want(loose, "peer_lane is present")
    sl = r["state_layout"]
    if sl is not None:
        _members(sl, ("state_dir", "entries"), "state_layout")
        _want(isinstance(sl["state_dir"], str) and isinstance(sl["entries"], list),
              "state_layout is {state_dir, entries}")
        for e in sl["entries"]:
            _want(isinstance(e, list) and len(e) == 3 and isinstance(e[0], str) and e[1] in LAYOUT_KINDS
                  and (e[2] is None or e[2] is True or e[2] is False)
                  and (e[1] == "dir" or e[2] is None), "state_layout.entries are [name, kind, generations]")
    else:
        _want(loose, "state_layout is present")


def _times(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Parses every time and checks every raw status value's shape. Raises
    ValueError (`time_format`). A malformed value never falls through."""
    t: Dict[str, Any] = {"at_before": parse_at(doc["at_before"]), "at": parse_at(doc["at"])}
    if t["at_before"] > t["at"]:
        raise ValueError("the host clock moved backward during the capture; fingerprint again")
    if doc["source"] != "running":
        return t
    t["started_at"] = parse_started_at(doc["container"]["started_at"])
    s = doc["result"]["status"] or {}
    for m, parse in (("started_ts", parse_whole), ("last_poll_ts", parse_whole), ("process_started_ts", parse_at)):
        e = s.get(m)
        t[m] = parse(e["value"]) if e and e["present"] else None
    tp = s.get("transport_plugin")
    if tp and tp["present"]:
        v = tp["value"]
        if not (isinstance(v, dict) and set(v) == {"path", "sha256"} and isinstance(v["path"], str)
                and isinstance(v["sha256"], str) and _HEX64.fullmatch(v["sha256"])):
            raise ValueError("status.transport_plugin is not {path, sha256}")
    return t


def history_schema_ok(h: Any) -> bool:
    """The history's exact STRUCTURE (members, types, 40-hex ids, `trees`
    keys equal to set(first_parent)). Its `types` key set and the root
    binding are step 3's, not this one's."""
    hex40 = lambda v: isinstance(v, str) and _HEX40.fullmatch(v) is not None
    if not isinstance(h, dict) or set(h) != {"shallow", "promisor", "types", "first_parent", "trees"}:
        return False
    if not isinstance(h["shallow"], bool) or not isinstance(h["promisor"], bool):
        return False
    if not isinstance(h["types"], dict) or not all(hex40(k) and (v is None or v in OBJECT_TYPES)
                                                    for k, v in h["types"].items()):
        return False
    fp = h["first_parent"]
    if not isinstance(fp, list) or not all(hex40(c) for c in fp):
        return False
    trees = h["trees"]
    if not isinstance(trees, dict) or set(trees) != set(fp):
        return False
    for c, t in trees.items():
        if not isinstance(t, dict) or set(t) != {"router", "entrypoint"}:
            return False
        if not (t["entrypoint"] is None or hex40(t["entrypoint"])):
            return False
        r = t["router"]
        if not isinstance(r, dict):
            return False
        for name, v in r.items():
            if not (isinstance(name, str) and isinstance(v, list) and len(v) == 2 and v[0] in ENTRY_TYPES
                    and hex40(v[1])):
                return False
    return True


def source_eligible(source: Any) -> bool:
    """The stop gate reads a running capture only."""
    return source == "running"


def container_name_ok(inspect_name: Any, expected: str) -> bool:
    """Docker's inspect `.Name` carries a leading "/": the capture records it
    verbatim, and it must name exactly the router container."""
    return inspect_name == "/" + expected


def py_map(router: Dict[str, List[str]]) -> Dict[str, str]:
    """A commit's router/*.py {name: blob}: its top-level `.py` files."""
    return {n: v[1] for n, v in router.items() if v[0] == "file" and n.endswith(".py")}


def py_map_matches(py: Dict[str, str], router: Dict[str, List[str]]) -> bool:
    return py_map(router) == py


def entries_match(entries: Dict[str, str], router: Dict[str, List[str]]) -> bool:
    """Every captured entry but a `__pycache__` dir is in the commit with the
    same type; no dir but `tests`, apart from `__pycache__`; no native file."""
    for name, t in entries.items():
        if name == PYCACHE and t == "dir":
            continue
        if t == "dir" and name != TESTS_DIR:
            return False
        if name.endswith(NATIVE_SUFFIXES):
            return False
        got = router.get(name)
        if got is None or got[0] != t:
            return False
    return True


def commit_matches(result: Dict[str, Any], tree: Dict[str, Any]) -> bool:
    return (py_map_matches(result["py"], tree["router"]) and entries_match(result["entries"], tree["router"])
            and result["entrypoint"] == tree["entrypoint"])


# --- The stop gate ------------------------------------------------------------------


def _out(outcome: str, reason: str, text: str) -> Tuple[str, int, str, str]:
    return outcome, EXIT[outcome], reason, text


def _unknown(reason: str, text: str) -> Tuple[str, int, str, str]:
    return _out(UNKNOWN, reason, text)


def _load_capture(capture_bytes: bytes) -> Tuple[Optional[Dict[str, Any]], Optional[Tuple[str, int, str, str]]]:
    try:
        doc = json.loads(capture_bytes)
    except ValueError:
        return None, _unknown("schema", "the capture is not JSON")
    if canonical(doc) != capture_bytes:
        return None, _unknown("schema", "the capture is not canonical JSON")
    try:
        _structure(doc)
    except _Bad as e:
        return None, _unknown("schema", f"the capture's structure: {e}")
    return doc, None


def _capture_common(doc: Dict[str, Any]) -> Optional[Tuple[str, int, str, str]]:
    """Step 1 after the schema and the source: errors, py, program."""
    r = doc["result"]
    if r["errors"]:
        return _unknown("errors", "the capture could not read everything: " + "; ".join(r["errors"]))
    if not r["py"]:
        return _unknown("py_empty", "the capture found no router/*.py")
    if doc["program_sha256"] != PROGRAM_SHA256:
        return _unknown("program", "the capture was made by another version of this program; capture again")
    return None


def _bases(bases_bytes: bytes, pin: str) -> Tuple[Optional[Dict[str, Any]], Optional[Tuple[str, int, str, str]]]:
    try:
        b = json.loads(bases_bytes)
    except ValueError:
        return None, _unknown("bases_schema", f"{BASES_NAME} is not JSON")
    keys = {"schema", "target", "measured_from", "property", "peer_lane", "premises", "measured_by", "pre_registry"}
    if not isinstance(b, dict) or set(b) != keys:
        return None, _unknown("bases_schema", f"{BASES_NAME} does not have exactly the members {sorted(keys)}")
    if not _is_int(b["schema"]) or b["schema"] != BASES_SCHEMA:
        return None, _unknown("bases_schema", f"{BASES_NAME}'s schema is not {BASES_SCHEMA}")
    pre = b["pre_registry"]
    if (not isinstance(pre, dict) or set(pre) != {"before", "from", "statement"}
            or not all(isinstance(pre[k], str) and _HEX40.fullmatch(pre[k]) for k in ("before", "from"))
            or not isinstance(pre["statement"], str)):
        return None, _unknown("bases_schema", f"{BASES_NAME}'s pre_registry is not "
                              "{before: 40-hex, from: 40-hex, statement}")
    if not all(isinstance(b[k], str) and _HEX40.fullmatch(b[k]) for k in ("target", "measured_from")):
        return None, _unknown("bases_schema", f"{BASES_NAME}'s target and measured_from are not 40-hex")
    if not all(isinstance(b[k], str) for k in ("property", "peer_lane", "premises", "measured_by")):
        return None, _unknown("bases_schema", f"{BASES_NAME}'s text members are not strings")
    if b["target"] != pin:
        return None, _unknown("pin", f"{BASES_NAME} measures {b['target']}, not the hop pin {pin}")
    return b, None


def precheck(capture_bytes: bytes, bases_bytes: bytes, pin: str) -> Optional[Tuple[str, int, str, str]]:
    """Steps 1 and 2 without the history: the CLI runs it before any git
    command, and reports a refusal with match's own reason id."""
    doc, bad = _load_capture(capture_bytes)
    if bad:
        return bad
    if not source_eligible(doc["source"]):
        return _unknown("not_running", "the capture is of an image, not of the running router")
    bad = _capture_common(doc)
    if bad:
        return bad
    try:
        _times(doc)
    except ValueError as e:
        return _unknown("time_format", str(e))
    return _bases(bases_bytes, pin)[1]


def match(capture_bytes: bytes, bases_bytes: bytes, history: Any, pin: str,
          plugin_sha256: str) -> Tuple[str, int, str, str]:
    """The stop gate: MEASURED (0), UNMEASURED (1), UNKNOWN (2) or MIGRATE (3), with a
    stable reason id. Reads nothing but its arguments."""
    try:
        return _match(capture_bytes, bases_bytes, history, pin, plugin_sha256)
    except Exception as e:     # noqa: BLE001 — every failure is an answer, never a traceback
        return _unknown("internal", f"the match failed: {type(e).__name__}: {e}")


def _match(capture_bytes: bytes, bases_bytes: bytes, history: Any, pin: str,
           plugin_sha256: str) -> Tuple[str, int, str, str]:
    # 1. The capture.
    doc, bad = _load_capture(capture_bytes)
    if bad:
        return bad
    if not source_eligible(doc["source"]):
        return _unknown("not_running", "the capture is of an image, not of the running router")
    bad = _capture_common(doc)
    if bad:
        return bad
    if not history_schema_ok(history):
        return _unknown("history_schema", "the history is not the exact structure the gate reads")
    try:
        t = _times(doc)
    except ValueError as e:
        return _unknown("time_format", str(e))
    # 2. The bases file.
    bases, bad = _bases(bases_bytes, pin)
    if bad:
        return bad
    target, mfrom = bases["target"], bases["measured_from"]
    # 3. The history.
    if history["shallow"]:
        return _unknown("shallow", "the hop checkout is shallow; its history cannot be walked")
    if history["promisor"]:
        return _unknown("promisor", "the hop checkout has a promisor remote or partial clone configured")
    if set(history["types"]) != {target, mfrom}:
        return _unknown("history_keys", "the history's looked-up ids are not exactly target and measured_from")
    if history["types"][target] != "commit" or history["types"][mfrom] != "commit":
        return _unknown("not_commit", "target or measured_from is not a commit in the hop checkout")
    fp = history["first_parent"]
    if not fp or fp[0] != target:
        return _unknown("history_root", "the history's first-parent chain does not start at target")
    if mfrom not in fp:
        return _unknown("off_chain", "measured_from is not on target's first-parent chain")
    before = bases["pre_registry"]["before"]
    if before not in fp:
        return _unknown("pre_registry_off_chain", "the bases file's pre_registry.before is not on target's "
                        "first-parent chain")
    if fp.index(before) <= fp.index(mfrom):
        return _unknown("pre_registry_order", "the bases file's pre_registry.before is not older than "
                        "measured_from")
    oldest = bases["pre_registry"]["from"]
    if oldest not in fp:
        return _unknown("pre_registry_off_chain", "the bases file's pre_registry.from is not on target's "
                        "first-parent chain")
    if fp.index(oldest) < fp.index(before):
        return _unknown("pre_registry_order", "the bases file's pre_registry.from is newer than "
                        "pre_registry.before")
    # 4. The domains: measured is [measured_from, target]; the pre-registry
    # class is (before, from], older than before and no older than from.
    measured = set(fp[:fp.index(mfrom) + 1])
    pre_class = set(fp[fp.index(before) + 1:fp.index(oldest) + 1])
    # 5. The match classifies the base. Nothing returns on it yet but a refusal:
    # every later check applies to a pre-registry base too.
    r = doc["result"]
    m = [c for c in fp if commit_matches(r, history["trees"][c])]
    if not m:
        return _unknown("no_match", "the running router's source is no commit on the pin's first-parent chain")
    if set(m) <= measured:
        base = "measured"
    elif set(m) & measured:
        return _unknown("mixed", "the running router's source matches commits both inside and outside the "
                        "measured range: " + ", ".join(m))
    elif set(m) <= pre_class:
        base = "pre_registry"
    elif all(fp.index(c) > fp.index(before) for c in m):
        return _out(UNMEASURED, "pre_registry_unchecked", "the running router predates registry_dir and is older "
                    "than the pre-registry range the router's maintainers checked (pre_registry.from): "
                    + ", ".join(m))
    else:
        return _out(UNMEASURED, "unmeasured", "the running router is older than the measured range: "
                    + ", ".join(m))
    # 6. The layout, process and environment.
    if PYCACHE in r["entries"]:
        return _unknown("pycache", "/app/router holds a __pycache__; a cached .pyc may run in place of the source")
    if r["app"] != APP_LAYOUT or r["docker"] != DOCKER_LAYOUT:
        return _unknown("layout", "/app or /app/docker holds more than the router's own layout")
    p, c = r["process"], r["config"]
    argv = p["argv"]
    if (len(argv) != RUN_FORM_ARGC or argv[0:3] != RUN_FORM_HEAD or argv[3] != "--config"
            or argv[5:7] != ["run", "--interval"] or not (argv[4] == p["router_config"] == c["path"])):
        return _unknown("run_form", "PID 1 is not `python3 -m router --config <the live config> run --interval <n>`")
    if p["cwd"] != ROUTER_CWD:
        return _unknown("cwd", f"PID 1's working directory is not {ROUTER_CWD}")
    img_env = doc["image_python_env"]
    if any(img_env.get(k) != v for k, v in p["python_env"].items()):
        return _unknown("env_subset", "PID 1 carries a PYTHON* entry its image does not")
    names = [k for k in p["python_env"] if _PY_ENV_NAME.match(k)]
    if (any(k not in PYTHON_ENV_ALLOWED for k in names)
            or not p["python_env"].get("PYTHONDONTWRITEBYTECODE")):
        return _unknown("env_allow", "PID 1's PYTHON* environment is outside "
                        + ", ".join(sorted(PYTHON_ENV_ALLOWED)) + ", or PYTHONDONTWRITEBYTECODE is not set")
    if p["ld_env"]:
        return _unknown("ld_env", "PID 1 has LD_* variables: " + ", ".join(p["ld_env"]))
    if base == "measured" and p["umask"] != ROUTER_UMASK:
        return _unknown("umask", f"PID 1's umask is not {ROUTER_UMASK}")
    if base == "pre_registry" and int(p["umask"], 8) & PRE_REGISTRY_UMASK_BITS != PRE_REGISTRY_UMASK_BITS:
        return _unknown("umask", "PID 1's umask lets the pre-registry router create group- or world-writable files")
    it = r["interpreter"]
    if it["user_site"]:
        return _unknown("user_site", "the user site directory PID 1 would load from exists")
    if (it["name"], it["major"], it["minor"]) != INTERPRETER or it["pid1_exe"] != it["exec_exe"]:
        return _unknown("interpreter", "PID 1 is not CPython 3.11, or not the interpreter the capture ran")
    # 7. This process, and the config it runs.
    k = r["clock"]
    if abs(t["at"] - k["now_ns"]) > CLOCK_SKEW_NS:
        return _unknown("clock_skew", "the host and the router disagree on the time; wait until they agree and "
                        "fingerprint again")
    if not (c["realpath_ok"] and c["regular"] and c["stable"]):
        return _unknown("config_identity", "the live config is not one stable regular file at its own path; "
                        "relaunch the router with the config bound at its own real path")
    sa = t["started_at"]
    lp = t["last_poll_ts"]
    if lp is None or lp < sa + STALE_AFTER_S or lp > k["now_ns"] // NS + FUTURE_SLACK_S:
        return _unknown("stale_status", "the status is not yet this process's; wait for a poll at least 3 s "
                        "after the router started, then fingerprint again")
    us = t["process_started_ts"] is not None
    t_ns = t["process_started_ts"] if us else (None if t["started_ts"] is None else t["started_ts"] * NS)
    if t_ns is None or t_ns < (sa - STARTED_SLACK_S) * NS:
        return _unknown("stale_status", "the status's start time is not this process's; wait for a poll at "
                        "least 3 s after the router started, then fingerprint again")
    est = k["now_ns"] - (Fraction(repr(k["uptime_s"])) - Fraction(k["pid1_starttime_ticks"], k["clk_tck"])) * NS
    lo, hi = PID1_AGE_US if us else PID1_AGE_WHOLE
    if not lo <= t_ns - est <= hi:
        return _unknown("pid1_age", "the router's start and the clock disagree; let the host clock settle, "
                        "restart the router, wait for a poll and fingerprint again")
    if c["ctime_ns"] > t_ns:
        return _unknown("config_changed", "the live config changed after the router started; restart the router "
                        "and fingerprint again")
    cls = r["status"]["classification"]
    if cls["present"] and cls["value"] is not None:
        v = cls["value"]
        if not isinstance(v, dict) or RELOAD_FLAG in v:
            return _unknown("reload_flag", "the router reports a refused config reload")
    # 8. The peer lane.
    if r["peer_lane"]["peer_entries"] is None:
        return _unknown("peer_unknown", "whether the state directory holds peer-lane state is unknown")
    if r["peer_lane"]["peer_entries"]:
        return _out(UNMEASURED, "peer_lane", "the state directory holds peer-lane state, which was not measured")
    # 9. The plugin.
    stp = r["status"]["transport_plugin"]
    if stp["present"]:
        if stp["value"]["sha256"] != plugin_sha256:
            return _out(UNMEASURED, "plugin", "the running transport plugin is not the pinned plugin")
    elif c["transport_plugin"]["present"] and c["transport_plugin"]["sha256"] != plugin_sha256:
        return _out(UNMEASURED, "plugin", "the configured transport plugin is not the pinned plugin")
    # 10. The state layout: a migration is required by state keyed by name, or
    # by a logical_id directory with no generations file, whatever the commit.
    layout = _layout(r)
    if layout[0] == UNKNOWN:
        return layout
    needs = layout[1]
    if base == "pre_registry":
        if r["config"]["registry_dir"]["present"]:
            return _unknown("state_layout", "a pre-registry router's live config sets registry_dir, which its "
                            "loader cannot read")
        return _out(MIGRATE, "pre_registry_base", "every check passed; the running router predates registry_dir "
                    "and its upgrade is supported only by the router's own migration. Take the runbook's "
                    "migration branch: " + ", ".join(m) + _named(" state to migrate: ", needs))
    if needs:
        return _out(MIGRATE, "migration_required", "every check passed and the base was measured, but its state "
                    "is keyed by instance name or is pre-generation. Take the runbook's migration branch: "
                    + ", ".join(m) + _named(" state to migrate: ", needs))
    return _out(MEASURED, "measured", f"the running router's base was measured (capture step {doc['step']} at "
                f"{doc['at']}): " + ", ".join(m))


def _named(prefix: str, names: Sequence[str]) -> str:
    return (prefix + ", ".join(names)) if names else ""


def _layout(r: Dict[str, Any]) -> Tuple[Any, ...]:
    """The state directory's top level, in the pinned router's vocabulary:
    (UNKNOWN, reason, text) when it cannot be read, or holds what the
    router would not guess about; otherwise ("ok", the entries a migration
    must move or adopt, the generation-keyed entries)."""
    sl, c = r["state_layout"], r["config"]
    if sl is None or sl["state_dir"] != c["state_dir"]:
        return _unknown("state_layout", "the state directory's top level was not read for the live config's "
                        "state_dir")
    needs, generations = [], []
    for name, kind, gen in sl["entries"]:
        if name.casefold() in RESERVED_STATE_NAMES:
            continue
        if kind == "file":
            # The router holds an instance whose name has an entry of any type
            # (state_not_migrated); a file is never its state, so refuse it.
            if HEX32.fullmatch(name) or INSTANCE_NAME.fullmatch(name):
                return _unknown("state_layout", f"the state directory holds a file named {name!r}, like an "
                                "instance's state; if it is a temporary of the router's own, fingerprint again")
            continue
        if kind != "dir":
            return _unknown("state_layout", f"the state directory holds {name!r}, a {kind}, which is not one of "
                            "the router's own entries")
        if LOGICAL_ID.fullmatch(name) is None:
            if HEX32.fullmatch(name) or INSTANCE_NAME.fullmatch(name) is None:
                return _unknown("state_layout", f"the state directory holds {name!r}, which is neither the "
                                "router's own entry nor an instance's")
            needs.append(name)
        elif gen is None:
            return _unknown("state_layout", f"whether {name!r} holds a generations file is unknown")
        elif gen:
            generations.append(name)
        else:
            needs.append(name)
    rd = c["registry_dir"]
    if not rd["present"] and (generations or any(LOGICAL_ID.fullmatch(n) for n in needs)):
        return _unknown("state_layout", "the live config sets no registry_dir, yet the state directory holds "
                        "state keyed by logical_id")
    return "ok", needs, generations


def verify_image(capture_bytes: bytes, history: Any, commit: str) -> Tuple[str, int, str, str]:
    """EXACT (0) when an image capture is exactly `commit`'s router package;
    DIFFERS (1) when it is well formed and differs; UNKNOWN (2) otherwise."""
    try:
        return _verify_image(capture_bytes, history, commit)
    except Exception as e:     # noqa: BLE001
        return _unknown("internal", f"the check failed: {type(e).__name__}: {e}")


def _verify_image(capture_bytes: bytes, history: Any, commit: str) -> Tuple[str, int, str, str]:
    doc, bad = _load_capture(capture_bytes)
    if bad:
        return bad
    if doc["source"] != "image":
        return _unknown("not_image", "the capture is of a running router, not of an image")
    bad = _capture_common(doc)
    if bad:
        return bad
    if not history_schema_ok(history):
        return _unknown("history_schema", "the history is not the exact structure the check reads")
    try:
        _times(doc)
    except ValueError as e:
        return _unknown("time_format", str(e))
    if history["shallow"]:
        return _unknown("shallow", "the hop checkout is shallow")
    if history["promisor"]:
        return _unknown("promisor", "the hop checkout has a promisor remote or partial clone configured")
    if set(history["types"]) != {commit}:
        return _unknown("history_keys", "the history's looked-up ids are not exactly the commit")
    if history["types"][commit] != "commit":
        return _unknown("commit_absent", f"{commit} is not a commit in the hop checkout")
    fp = history["first_parent"]
    if not fp or fp[0] != commit:
        return _unknown("history_root", "the history does not start at the commit")
    r = doc["result"]
    if (commit_matches(r, history["trees"][commit]) and PYCACHE not in r["entries"]
            and r["app"] == APP_LAYOUT and r["docker"] == DOCKER_LAYOUT):
        return _out(EXACT, "exact", f"the image's router package is exactly {commit}'s")
    return _out(DIFFERS, "differs", f"the image's router package is not exactly {commit}'s")


# --- The history ------------------------------------------------------------------


#: A header line whose key is `tree` or `parent`, however it continues: a bare
#: key, a tab, or a space. Only the exact `parent <40-hex>` form is a parent.
_STRUCTURAL = re.compile(rb"(?:tree|parent)(?:[ \t]|$)")


def _parse_commit(body: bytes) -> Tuple[str, Optional[str]]:
    """The root tree and the first parent, from a verified commit's header."""
    end = body.find(b"\n\n")
    if end < 0:
        raise HistoryReadError("a commit has no empty line ending its header")
    lines = body[:end].split(b"\n")
    m = re.fullmatch(rb"tree ([0-9a-f]{40})", lines[0])
    if m is None:
        raise HistoryReadError("a commit's first header line is not `tree <40-hex>`")
    tree = m.group(1).decode("ascii")
    parents = []
    i = 1
    while i < len(lines) and _STRUCTURAL.match(lines[i]) and lines[i].startswith(b"parent"):
        p = re.fullmatch(rb"parent ([0-9a-f]{40})", lines[i])
        if p is None:
            raise HistoryReadError("a commit has a malformed parent line")
        parents.append(p.group(1).decode("ascii"))
        i += 1
    for line in lines[i:]:
        if line.startswith(b" "):
            continue    # a continuation (gpgsig, mergetag), never a parent
        if _STRUCTURAL.match(line):
            raise HistoryReadError("a commit has a tree or parent header after its parent block, or a "
                                   "malformed one")
    return tree, (parents[0] if parents else None)


def _parse_tree(body: bytes) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    pos = 0
    while pos < len(body):
        sp = body.find(b" ", pos)
        nul = body.find(b"\0", pos)
        if sp < 0 or nul < 0 or sp > nul:
            raise HistoryReadError("a tree entry has no mode, space and NUL")
        mode, raw = body[pos:sp], body[sp + 1:nul]
        oid = body[nul + 1:nul + 21]
        if len(oid) != 20:
            raise HistoryReadError("a tree entry's id is truncated")
        if not raw or b"/" in raw:
            raise HistoryReadError("a tree entry's name is empty or holds /")
        try:
            name = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise HistoryReadError("a tree entry's name is not UTF-8") from None
        if name in out:
            raise HistoryReadError(f"a tree holds {name!r} twice")
        out[name] = [TREE_MODES.get(mode, "other"), oid.hex()]
        pos = nul + 21
    return out


def read_history(hop_repo: str, target: str, measured_from: str, *, git: str) -> Dict[str, Any]:
    """The hop checkout's first-parent chain from `target`, and each commit's
    top-level router/ entries and docker/entrypoint.sh blob, built from
    commit and tree bytes this function re-hashes. Raises HistoryReadError,
    and nothing else, on any failure."""
    for v in (target, measured_from):
        if not isinstance(v, str) or _HEX40.fullmatch(v) is None:
            raise HistoryReadError(f"{v!r} is not a full lowercase 40-hex commit id")
    try:
        return _read_history(hop_repo, target, measured_from, git)
    except HistoryReadError:
        raise
    except Exception as e:     # noqa: BLE001 — the one exception class is the contract
        raise HistoryReadError(f"{type(e).__name__}: {e}") from None


def _read_history(hop_repo: str, target: str, measured_from: str, git: str) -> Dict[str, Any]:
    env = hg.git_env()
    env["GIT_NO_LAZY_FETCH"] = "1"
    opts = [*hg.GIT_OPTS, "-c", "core.commitGraph=false", "-c", "advice.graftFileDeprecated=false"]

    def run(args: Sequence[str], data: Optional[bytes] = None, ok: Sequence[int] = (0,)) -> subprocess.CompletedProcess:
        try:
            p = subprocess.run([git, "-C", hop_repo, *opts, *args], input=data, capture_output=True, env=env,
                               timeout=120)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise HistoryReadError(f"git cannot run: {e}") from None
        if p.returncode not in ok:
            raise HistoryReadError(f"git {args[0]} exited {p.returncode}")
        return p

    if run(["rev-parse", "--show-object-format"]).stdout != b"sha1\n":
        raise HistoryReadError("the hop checkout's object format is not sha1")
    flag = run(["rev-parse", "--is-shallow-repository"]).stdout
    if flag not in (b"true\n", b"false\n"):
        raise HistoryReadError("git did not say whether the hop checkout is shallow")
    shallow = flag == b"true\n"
    promisor = run(["config", "--get-regexp", r"^remote\..*\.promisor$|^extensions\.partialclone$"],
                   ok=(0, 1)).returncode == 0
    ids = list(dict.fromkeys((target, measured_from)))
    out = run(["cat-file", "--batch-check"], data="".join(i + "\n" for i in ids).encode("ascii")).stdout
    lines = out.split(b"\n")
    if lines[-1] != b"" or len(lines) - 1 != len(ids):
        raise HistoryReadError("cat-file --batch-check did not answer one line per id")
    types: Dict[str, Optional[str]] = {}
    for want, line in zip(ids, lines):
        parts = line.decode("ascii", "replace").split(" ")
        if parts[0] != want:
            raise HistoryReadError("cat-file --batch-check answered for another id")
        if parts[1:] == ["missing"]:
            types[want] = None
        elif len(parts) == 3 and parts[1] in OBJECT_TYPES and parts[2].isdigit():
            types[want] = parts[1]
        else:
            raise HistoryReadError("cat-file --batch-check gave an unreadable line")
    hist: Dict[str, Any] = {"shallow": shallow, "promisor": promisor, "types": types, "first_parent": [], "trees": {}}
    if shallow or types[target] != "commit":
        return hist

    def obj(oid: str, kind: str) -> bytes:
        body = run(["cat-file", kind, "--end-of-options", oid]).stdout
        if hashlib.sha1(b"%s %d\0" % (kind.encode("ascii"), len(body)) + body).hexdigest() != oid:
            raise HistoryReadError(f"{oid}'s bytes do not hash to its id as a {kind}")
        return body

    c: Optional[str] = target
    while c is not None:
        if c in hist["trees"]:
            raise HistoryReadError("the first-parent chain returns to a commit")
        root, parent = _parse_commit(obj(c, "commit"))
        top = _parse_tree(obj(root, "tree"))
        router: Dict[str, List[str]] = {}
        if top.get("router", ["", ""])[0] == "dir":
            router = _parse_tree(obj(top["router"][1], "tree"))
        entrypoint = None
        if top.get("docker", ["", ""])[0] == "dir":
            e = _parse_tree(obj(top["docker"][1], "tree")).get("entrypoint.sh")
            if e is not None and e[0] == "file":
                entrypoint = e[1]
        hist["first_parent"].append(c)
        hist["trees"][c] = {"router": router, "entrypoint": entrypoint}
        c = parent
    return hist


# --- The capture ------------------------------------------------------------------


class CaptureError(Exception):
    pass


Runner = Callable[..., subprocess.CompletedProcess]


def _engine(run: Runner, argv: List[str]) -> bytes:
    try:
        p = run(argv, capture_output=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise CaptureError(f"{argv[-1]}: the engine cannot be reached: {e}") from None
    if p.returncode != 0:
        raise CaptureError(f"`{' '.join(argv[len(argv) - 2:])}` exited {p.returncode}: "
                           f"{p.stderr.decode('utf-8', 'replace').strip()[:200]}")
    return p.stdout


def _inspect_one(raw: bytes, what: str) -> Dict[str, Any]:
    try:
        doc = json.loads(raw)
    except ValueError:
        raise CaptureError(f"{what}'s inspect is not JSON") from None
    if not isinstance(doc, list) or len(doc) != 1 or not isinstance(doc[0], dict):
        raise CaptureError(f"{what}'s inspect is not one object")
    return doc[0]


def _python_env(image: Dict[str, Any]) -> Dict[str, str]:
    env = (image.get("Config") or {}).get("Env")
    if not isinstance(env, list):
        raise CaptureError("the image's Config.Env is missing")
    out = {}
    for item in env:
        k, eq, v = str(item).partition("=")
        if eq and k.startswith("PYTHON"):
            out[k] = v
    return out


def _program_result(raw: bytes) -> Dict[str, Any]:
    try:
        doc = json.loads(raw)
    except ValueError:
        raise CaptureError("the capture program's output is not JSON") from None
    if not isinstance(doc, dict):
        raise CaptureError("the capture program's output is not an object")
    return doc


def capture_running(docker: List[str], container: str, step: int, *, run: Runner = subprocess.run,
                    clock: Callable[[], int] = time.time_ns) -> Dict[str, Any]:
    """Inspect, image inspect, one exec by Id, inspect again. Raises
    CaptureError on every failure; nothing is written here."""
    c1 = _inspect_one(_engine(run, docker + ["inspect", container]), container)
    state = c1.get("State") or {}
    if state.get("Running") is not True:
        raise CaptureError(f"{container} is not running")
    if state.get("Paused"):
        raise CaptureError(f"{container} is paused")
    cid, image, started = c1.get("Id"), c1.get("Image"), state.get("StartedAt")
    py_env = _python_env(_inspect_one(_engine(run, docker + ["image", "inspect", str(image)]), "the image"))
    at_before = clock()
    raw = _engine(run, docker + ["exec", str(cid), "python3", "-I", "-S", "-c", PROGRAM, "running"])
    at = clock()
    result = _program_result(raw)
    c2 = _inspect_one(_engine(run, docker + ["inspect", str(cid)]), container)
    if (c2.get("Id"), c2.get("Image"), (c2.get("State") or {}).get("StartedAt")) != (cid, image, started):
        raise CaptureError(f"{container} changed during the capture (Id, Image or StartedAt); capture again")
    return {"schema": SCHEMA, "source": "running", "step": step, "at_before": utc_at(at_before), "at": utc_at(at),
            "container": {"id": cid, "name": c1.get("Name"), "image": image, "started_at": started},
            "image": None, "image_python_env": py_env, "program_sha256": PROGRAM_SHA256, "result": result}


def capture_image(docker: List[str], ref: str, *, run: Runner = subprocess.run,
                  clock: Callable[[], int] = time.time_ns) -> Dict[str, Any]:
    """Image inspect, then one run of the inspected immutable Id. Raises
    CaptureError on every failure."""
    img = _inspect_one(_engine(run, docker + ["image", "inspect", ref]), ref)
    iid = img.get("Id")
    if not isinstance(iid, str) or _IMAGE_ID.fullmatch(iid) is None:
        raise CaptureError(f"{ref}'s Id is not sha256:<64 hex>")
    py_env = _python_env(img)
    at_before = clock()
    raw = _engine(run, docker + ["run", "--rm", "--network", "none", "--entrypoint", "python3", iid,
                                 "-I", "-S", "-c", PROGRAM, "image"])
    at = clock()
    return {"schema": SCHEMA, "source": "image", "step": None, "at_before": utc_at(at_before), "at": utc_at(at),
            "container": None, "image": {"ref": ref, "id": iid}, "image_python_env": py_env,
            "program_sha256": PROGRAM_SHA256, "result": _program_result(raw)}


def write_capture(run_dir: str, label: str, doc: Dict[str, Any]) -> str:
    stamp = doc["at"].replace("-", "").replace(":", "").replace(".", "")
    path = os.path.join(run_dir, f"router-fingerprint-{label}-{stamp}.json")
    with open(path, "xb") as f:
        f.write(canonical(doc))
    return path


# --- The verb ---------------------------------------------------------------------


#: The one mode the bases file may have, at HEAD and in the index: a regular, non-executable file.
BASES_MODE = "100644"


def _records(raw: bytes) -> List[Tuple[List[str], str]]:
    """`git ls-tree -z` / `ls-files --stage -z` output: each record's fields and its path."""
    out = []
    for rec in raw.decode("utf-8", "replace").split("\0"):
        if rec:
            meta, _, name = rec.partition("\t")
            out.append((meta.split(), name))
    return out


def bases_dirty(path: Path = BASES_PATH, data: Optional[bytes] = None) -> Optional[str]:
    """None when `data` (the bytes the matcher is given; by default the
    file's) equals the bases file's committed bytes at HEAD, where it is ONE
    regular file of mode 100644, and the index holds exactly one stage-0
    entry for it with that same mode and blob; otherwise why not. It reads
    only: `git status` is never consulted, because skip-worktree and
    assume-unchanged hide an edit from it, and an ignored or untracked file
    is not in it at all. A blob's type cannot tell a file from a symlink, so
    the modes are compared, and an unmerged path is refused."""
    repo = str(path.parent)
    try:
        data = path.read_bytes() if data is None else data
        head = _records(hg.git(repo, "ls-tree", "-z", "HEAD", "--", path.name))
        staged = _records(hg.git(repo, "ls-files", "--stage", "-z", "--", path.name))
    except (OSError, hg.CannotRun) as e:
        return f"the deploy checkout cannot be read: {e}"
    if len(head) != 1 or head[0][1] != path.name or len(head[0][0]) != 3 or head[0][0][1] != "blob":
        return f"{path.name} is not committed in the deploy checkout as one file"
    mode, _, blob = head[0][0]
    if mode != BASES_MODE:
        return f"{path.name} is committed with mode {mode}, not {BASES_MODE}"
    try:
        committed = hg.git(repo, "cat-file", "blob", "--end-of-options", blob)
    except hg.CannotRun as e:
        return f"the deploy checkout cannot be read: {e}"
    if data != committed:
        return f"{path.name} differs from its committed bytes in the deploy checkout"
    if len(staged) != 1 or staged[0][1] != path.name or staged[0][0] != [mode, blob, "0"]:
        return (f"{path.name}'s index entry is not exactly its committed one (mode {mode}, its blob, stage 0): "
                "a staged change, a mode or type change, an unmerged path, or no entry")
    return None


def _show(outcome: Tuple[str, int, str, str], out: Callable[[str], None]) -> int:
    o, code, reason, text = outcome
    out(f"{o} {reason}: {text}")
    return code


def run(args: Any, *, out: Callable[[str], None] = print, git: Optional[str] = None,
        runner: Runner = subprocess.run) -> int:
    """`router-fingerprint`: one of --step, --image, --match or --verify-image.
    An unexpected failure is UNKNOWN (exit 2), never a traceback's exit 1,
    which is UNMEASURED's and DIFFERS'."""
    try:
        return _run(args, out=out, git=git, runner=runner)
    except Exception as e:     # noqa: BLE001
        out(f"router-fingerprint: UNKNOWN internal: {type(e).__name__}: {e}")
        return EXIT[UNKNOWN]


def _run(args: Any, *, out: Callable[[str], None], git: Optional[str], runner: Runner) -> int:
    import hop_router as hp
    git = git or shutil.which("git") or "git"
    container = getattr(args, "container", None)
    if container is not None:
        if args.verify_image is not None or args.image is not None:
            out("router-fingerprint: --container applies only to --step and --match")
            return EXIT[UNKNOWN]
        if CONTAINER_NAME.fullmatch(container) is None:
            out("router-fingerprint: --container is not a container name ([A-Za-z0-9][A-Za-z0-9_.-]*)")
            return EXIT[UNKNOWN]
    if args.verify_image is not None:
        commit = args.commit
        if not isinstance(commit, str) or _HEX40.fullmatch(commit) is None:
            return _show(_unknown("commit_format", "--commit is not a full lowercase 40-hex commit id"), out)
        pin = hp.hop_pin()
        if commit != pin:
            out(f"warning: --commit {commit} is not the hop pin ({pin})")
        try:
            capture = Path(args.verify_image).read_bytes()
        except OSError as e:
            return _show(_unknown("schema", f"cannot read {args.verify_image}: {e.strerror}"), out)
        try:
            history = read_history(hp.hop_checkout(), commit, commit, git=git)
        except HistoryReadError as e:
            return _show(_unknown("history_read", str(e)), out)
        return _show(verify_image(capture, history, commit), out)
    spec = _load_spec(args, out, secrets=args.match is None)
    if spec is None:
        return EXIT[UNKNOWN]
    if args.match is not None:
        return _run_match(args, spec, out, git, hp)
    docker = ss_docker(spec)
    if args.image is not None:
        if not args.apply:
            out(f"would run: {' '.join(docker)} image inspect {args.image}, then {' '.join(docker)} run --rm "
                f"--network none --entrypoint python3 <its Id> -I -S -c PROGRAM image, and write "
                f"router-fingerprint-image-<at>.json into {spec.secrets.run_dir} (dry run; --apply to capture)")
            return 0
        try:
            doc = capture_image(ss_live_docker(spec), args.image, run=runner)
        except CaptureError as e:
            out(f"router-fingerprint: {e}")
            return EXIT[UNKNOWN]
        out(write_capture(spec.secrets.run_dir, "image", doc))
        return 0
    if spec.router is None:
        out("router-fingerprint: the host-setup document has no router section")
        return EXIT[UNKNOWN]
    name = getattr(args, "container", None) or spec.router.container
    if not args.apply:
        out(f"would run: {' '.join(docker)} inspect {name}; image inspect <its Image>; exec "
            f"<its Id> python3 -I -S -c PROGRAM running; inspect again; and write "
            f"router-fingerprint-{args.step}-<at>.json into {spec.secrets.run_dir} (dry run; --apply to capture)")
        return 0
    try:
        doc = capture_running(ss_live_docker(spec), name, args.step, run=runner)
    except CaptureError as e:
        out(f"router-fingerprint: {e}")
        return EXIT[UNKNOWN]
    out(write_capture(spec.secrets.run_dir, str(args.step), doc))
    return 0


def ss_docker(spec: Any) -> List[str]:
    """docker as a dry run shows it."""
    import secret_setup as ss
    return ss.docker(spec.secrets)


def ss_live_docker(spec: Any) -> List[str]:
    """docker for a call that runs now: through secret_setup's gate and, on
    the sudo route, the barrier (d3.3 §5(c)). The local router is on the
    default engine, so no DOCKER_HOST is named. A refusal is a CaptureError,
    reported as UNKNOWN before anything runs."""
    import router_health as rh
    import secret_setup as ss
    try:
        return ss.live_docker(spec.secrets)
    except rh.CannotRun as e:
        raise CaptureError(f"could not run: {e}") from None


def _load_spec(args: Any, out: Callable[[str], None], *, secrets: bool) -> Any:
    import host_adapter as ha
    import host_setup as hsu
    try:
        spec = hsu.load_spec(hsu.read_spec(args.spec, ha.overlay_path(getattr(args, "overlay", None))))
    except ValueError as e:
        out(f"router-fingerprint: {e}")
        return None
    if secrets and spec.secrets is None:
        out("router-fingerprint: the host-setup document has no secrets section (its docker and run_dir)")
        return None
    return spec


def _run_match(args: Any, spec: Any, out: Callable[[str], None], git: str, hp: Any) -> int:
    pin = hp.hop_pin()
    if not isinstance(pin, str):
        return _show(_unknown("pin", f"the hop pin cannot be read: {getattr(pin, 'reason', pin)}"), out)
    try:
        capture = Path(args.match).read_bytes()
        bases = BASES_PATH.read_bytes()
    except OSError as e:
        return _show(_unknown("schema", f"cannot read {e.filename}: {e.strerror}"), out)
    bad = precheck(capture, bases, pin)
    if bad:
        return _show(bad, out)
    dirty = bases_dirty(BASES_PATH, bases)
    if dirty:
        return _show(_unknown("bases_dirty", dirty), out)
    name = json.loads(capture)["container"]["name"]
    expected = getattr(args, "container", None) or (spec.router.container if spec.router is not None else None)
    if expected is None or not container_name_ok(name, expected):
        return _show(_unknown("container_name", f"the capture is of {name!r}, not of the router container"), out)
    b = json.loads(bases)
    try:
        history = read_history(hp.hop_checkout(), b["target"], b["measured_from"], git=git)
    except HistoryReadError as e:
        return _show(_unknown("history_read", str(e)), out)
    return _show(match(capture, bases, history, pin, hp.PLUGIN_SHA256), out)
