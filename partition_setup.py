"""The host-setup document's `partition` and `delegation_gate` sections: where
the partition evidence lives, where the controls may make throwaway paths,
when the weekly probe runs, and the conformance harness's passing record
that, with current evidence, lets `delegation` be rendered at all.

`partition` {evidence_dir, scratch_dir, exec_root, tools{python3, docker,
git, git-remote-https}, tool_sha256?, weekly{weekday, hour}} is authored
with the rest of the overlay. `delegation_gate` {harness_sha, record_sha256,
record_path} is the operator's alone: install and verify READ it and the
record, and nothing here writes either. Both have closed member sets, and a
`delegation_gate` with no `partition` refuses the document.

- `evidence_dir`: root-owned 0755 under root-owned parents, listed in the
  secrets section's integrity roots, so no container can bind it read-write
  or bind any directory above it (a read-only bind cannot alter what the
  gate accepts). The partition products the host-side writer places there
  are named by `EVIDENCE_NAME`; the gate record is not among them.
- `scratch_dir`: root-owned 0700, outside every root the document declares;
  the control pass's throwaway paths live under `<scratch_dir>/<run_id>/`.
- `exec_root`: root-owned 0700, outside every root the document declares and
  apart from `scratch_dir`: the weekly job's provisioned bundle, its lock,
  each run's work directory and the recovery description.
- `tools`: the interpreter and the docker CLI the weekly job runs as root,
  absolute paths, separate from the secrets section's own tools.
- `tool_sha256` (optional; required for docker on a launchd host): a pinned
  sha256 per tool name (d3.3 §4 C3), the same for a path the secrets
  section also records.
- `weekly`: the probe job's day and hour only.
- `record_path`: exactly `<evidence_dir>/gate-record.json`, a regular file,
  root:root 0444, one link, checked and read through ONE descriptor.
- `harness_sha`: the harness commit the gate RAN at, copied from the record's
  own member, which it must equal.
"""

import calendar
import hashlib
import json
import os
import posixpath
import re
import stat
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

import harness_gate as hg
import root_trust as rt
import router_health as rh

SECTION = "partition"
GATE_SECTION = "delegation_gate"
GATE_RECORD = "gate-record.json"
EVIDENCE_MODE = 0o755
SCRATCH_MODE = 0o700
EXEC_MODE = 0o700
#: The tools the weekly job runs as root, and the two its bundle is fetched with.
WEEKLY_TOOLS = ("docker", "python3", "git", "git-remote-https")
#: On darwin, git and its https helper are the Command Line Tools' own:
#: /usr/bin/git is the xcrun shim, which execs another git by absolute path.
CLT_GIT = "/Library/Developer/CommandLineTools/usr/bin/git"
CLT_GIT_REMOTE_HTTPS = "/Library/Developer/CommandLineTools/usr/libexec/git-core/git-remote-https"
RECORD_MODE = 0o444
_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_RUN = r"[A-Za-z0-9._-]{1,64}"
#: Every name the host-side evidence writer may place under evidence_dir.
#: The gate record is not one of them: only the operator places it.
EVIDENCE_NAME = re.compile(rf"partition-{_RUN}\.json|partition-control-{_RUN}\.json|partition-risk\.json"
                           rf"|incident-{_RUN}/(detected\.json|events\.jsonl)")


class PartitionSpecError(ValueError):
    """A partition or delegation_gate section is unusable."""


@dataclass(frozen=True)
class PartitionSpec:
    evidence_dir: str
    scratch_dir: str
    weekday: int
    hour: int
    exec_root: str
    tools: Dict[str, str]
    tool_sha256: Dict[str, str] = field(default_factory=dict)  # tool name -> pinned sha256 (C3)

    @property
    def pins(self) -> Dict[str, str]:
        """The pinned tools by recorded path (root_trust.tool_pins)."""
        return rt.tool_pins(self.tools, self.tool_sha256, SECTION)


@dataclass(frozen=True)
class GateSpec:
    harness_sha: str
    record_sha256: str
    record_path: str


def _abs(p: Any, what: str) -> str:
    if not isinstance(p, str) or not p.startswith("/") or posixpath.normpath(p) != p or p.startswith("//"):
        raise PartitionSpecError(f"{what} must be an absolute, normalised path")
    return p


def _related(a: str, b: str) -> bool:
    return a == b or a.startswith(b.rstrip("/") + "/") or b.startswith(a.rstrip("/") + "/")


def _int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def load(sec: Any, spec: Any) -> PartitionSpec:
    required = {"evidence_dir", "scratch_dir", "exec_root", "tools", "weekly"}
    if not isinstance(sec, dict) or not required <= set(sec) or set(sec) - required - {rt.TOOL_SHA256}:
        raise PartitionSpecError("partition must have exactly evidence_dir, scratch_dir, exec_root, tools and weekly, "
                                 f"and optionally {rt.TOOL_SHA256}")
    ev, scratch = _abs(sec["evidence_dir"], "partition.evidence_dir"), _abs(sec["scratch_dir"], "partition.scratch_dir")
    ex = _abs(sec["exec_root"], "partition.exec_root")
    t = sec["tools"]
    if not isinstance(t, dict) or set(t) != set(WEEKLY_TOOLS):
        raise PartitionSpecError(f"partition.tools must be exactly {', '.join(WEEKLY_TOOLS)}")
    tools = {k: _abs(t[k], f"partition.tools.{k}") for k in WEEKLY_TOOLS}
    if getattr(getattr(spec, "supervision", None), "kind", None) == "launchd" and \
            (tools["git"], tools["git-remote-https"]) != (CLT_GIT, CLT_GIT_REMOTE_HTTPS):
        raise PartitionSpecError(f"on a launchd host, partition.tools.git must be {CLT_GIT} and git-remote-https "
                                 f"{CLT_GIT_REMOTE_HTTPS}: /usr/bin/git is the xcrun shim")
    try:
        rt.tool_pins(tools, sec.get(rt.TOOL_SHA256), SECTION)
    except ValueError as e:
        raise PartitionSpecError(str(e)) from None
    w = sec["weekly"]
    if not isinstance(w, dict) or set(w) != {"weekday", "hour"} or not _int(w["weekday"]) or not _int(w["hour"]) \
            or not 0 <= w["weekday"] <= 6 or not 0 <= w["hour"] <= 23:
        raise PartitionSpecError("partition.weekly must be exactly {weekday 0-6, hour 0-23}")
    if spec.secrets is None or ev not in spec.secrets.extra["exposure"]["integrity_roots"]:
        raise PartitionSpecError("partition.evidence_dir must be listed in secrets.exposure.integrity_roots, so no "
                                 "container can bind it read-write or bind anything above it")
    others = [r.path for r in spec.roots] + list(spec.agent_paths) + [ev]
    if spec.hub is not None:
        others += [spec.hub.hop_root, spec.hub.registry_dir, spec.hub.d7_dir]
    if spec.keys is not None:
        others += [spec.keys.dir, spec.keys.evidence_dir]
    for o in others:
        if _related(scratch, o):
            raise PartitionSpecError(f"partition.scratch_dir {scratch} overlaps {o}; the controls' throwaway paths "
                                     "stay outside every live path")
    for o in others + [scratch]:
        if _related(ex, o):
            raise PartitionSpecError(f"partition.exec_root {ex} overlaps {o}; the weekly job's bundle and runs "
                                     "stay apart from every live path and from the controls' scratch")
    return PartitionSpec(evidence_dir=ev, scratch_dir=scratch, weekday=w["weekday"], hour=w["hour"], exec_root=ex,
                         tools=tools, tool_sha256=dict(sec.get(rt.TOOL_SHA256) or {}))


def load_gate(sec: Any, partition: Optional[PartitionSpec]) -> GateSpec:
    if partition is None:
        raise PartitionSpecError("delegation_gate needs the partition section: the record lives in its evidence_dir")
    if not isinstance(sec, dict) or set(sec) != {"harness_sha", "record_sha256", "record_path"}:
        raise PartitionSpecError("delegation_gate must have exactly harness_sha, record_sha256 and record_path")
    if not isinstance(sec["harness_sha"], str) or not _HEX40.fullmatch(sec["harness_sha"]):
        raise PartitionSpecError("delegation_gate.harness_sha must be 40 lower-case hex")
    if not isinstance(sec["record_sha256"], str) or not _HEX64.fullmatch(sec["record_sha256"]):
        raise PartitionSpecError("delegation_gate.record_sha256 must be 64 lower-case hex")
    want = posixpath.join(partition.evidence_dir, GATE_RECORD)
    if sec["record_path"] != want:
        raise PartitionSpecError(f"delegation_gate.record_path must be exactly {want}")
    return GateSpec(harness_sha=sec["harness_sha"], record_sha256=sec["record_sha256"], record_path=want)


def evidence_name_ok(name: str) -> bool:
    """Whether the host-side evidence writer may place `name` (relative to
    evidence_dir): only its own products, never the gate record."""
    return EVIDENCE_NAME.fullmatch(name) is not None


def read_record(path: str) -> bytes:
    """The gate record's bytes through ONE descriptor: opened without following
    a link, checked as opened (a regular file, root:root 0444, one link), then
    read bounded from that same descriptor."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_nlink) \
                != (0, 0, RECORD_MODE, 1):
            raise OSError(f"{path} as opened is not a root:root 0444 file with one link")
        chunks, total = [], 0
        while total <= hg.MAX_BYTES:
            chunk = os.read(fd, hg.MAX_BYTES + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def gate_problems(gs: Optional[GateSpec], *, rl_sha: Any, hop_sha: Any, plugin_sha256: str,
                  read: Callable[[str], bytes] = read_record) -> List[str]:
    """Why the delegation gate does not hold; empty when it does. No section,
    no placed record, an unreadable pin, or any failing check keeps it shut."""
    if gs is None:
        return ["the document has no delegation_gate section"]
    for what, v in (("the local router's commit", rl_sha), ("the hop plugin's commit", hop_sha)):
        if isinstance(v, rh.Unresolved) or not isinstance(v, str):
            return [f"{what} cannot be read: {getattr(v, 'reason', 'absent')}"]
    try:
        raw = read(gs.record_path)
    except FileNotFoundError:
        return [f"{gs.record_path} is absent"]
    except OSError as e:
        return [f"cannot read {gs.record_path}: {e}"]
    bad = [f"{g}: {why}" for g, why in hg.problems(raw, record_sha256=gs.record_sha256, rl_sha=rl_sha,
                                                    hop_sha=hop_sha, plugin_sha256=plugin_sha256)]
    if not bad and hg.parse(raw)["harness_sha"] != gs.harness_sha:
        bad.append("delegation_gate.harness_sha is not the record's own harness_sha (copy it from the record)")
    return bad


def verify(ps: Optional[PartitionSpec], gs: Optional[GateSpec], *, delegation_enabled: bool, lstat: Callable,
           owned_chain: Callable, rl_sha: Any, hop_sha: Any, plugin_sha256: str,
           read: Callable[[str], bytes] = read_record,
           realpath: Callable[[str], str] = os.path.realpath,
           pin_read: Optional[Callable[[str], Any]] = None) -> List[rh.Check]:
    """The two sections against the host. Absent sections are a NOTE (PASS
    with the reason in the claim) where nothing enables delegation, and a
    FAIL where something does."""
    out: List[rh.Check] = []
    need = rh.Fact("section", True, "delegation is rendered only with current evidence and a passing gate record")
    if ps is None:
        claim = ("the document has a partition section" if delegation_enabled else
                 "no partition section, and nothing on this host enables delegation")
        out.append(rh.check(claim, need, not delegation_enabled or None, "add the partition section to the overlay",
                            ok=lambda e, a: a is True))
    else:
        for path, mode, what in ((ps.evidence_dir, EVIDENCE_MODE, "evidence"), (ps.scratch_dir, SCRATCH_MODE, "scratch"),
                                 (ps.exec_root, EXEC_MODE, "weekly job's")):
            claim = f"the partition {what} directory {path} is root:root {oct(mode)[2:]}"
            want = rh.Fact(f"{what} dir", (0, 0, mode), "only root places or removes what is there")
            remedy = f"create it: install -d -o 0 -g 0 -m {oct(mode)[2:]} {path}"
            try:
                st = lstat(path)
                got: Any = (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) if stat.S_ISDIR(st.st_mode) else "not a directory"
            except FileNotFoundError:
                got = "absent"
            except OSError as e:
                got = rh.Unresolved(f"cannot inspect {path}: {e}")
            out.append(rh.unknown(claim, want, got.reason, remedy) if isinstance(got, rh.Unresolved)
                       else rh.check(claim, want, got, remedy))
            out.append(owned_chain(f"every directory above {path} is root-owned and not group- or world-writable",
                                   path, (0,), "the partition products are trusted only as root placed them", lstat))
        out += verify_tools(ps, lstat, owned_chain, realpath, pin_read)
    if delegation_enabled or gs is not None:
        bad = gate_problems(gs, rl_sha=rl_sha, hop_sha=hop_sha, plugin_sha256=plugin_sha256, read=read)
        claim = "the conformance harness's gate record holds for this deployment"
        want = rh.Fact("gate", [], "the harness's passing record, at this router commit, hop pin and plugin")
        out.append(rh.check(claim, want, bad, "the operator places the harness's record and writes delegation_gate "
                            "(the design's §11.2 steps); until then delegation stays off",
                            do_not="never edit the record or the section to make it hold"))
    return out


#: The stop target's verify copy and A1's approved record, under evidence_dir;
#: the pinned writer and the operator place them, never the library's store.
STOP_TARGET, ACTIVATION = "stop-target.json", "activation.json"
TARGET_SCHEMA = "amap-deploy.partition-recovery/1"
TARGET_MEMBERS = {"schema": str, "host": str, "run_id": str, "at": str, "evidence_dir": str, "live_config_path": str,
                  "engine": str, "docker": str, "router_container_id": str, "config_sha256": str,
                  "evidence_run_id": str, "evidence_sha256": str, "inspect_digest": str, "activation_sha256": str}
TARGET_CLAIM = "the weekly job has a stop target: the recorded id is the running local router"
TARGET_REMEDY = ("run the weekly job once now, in the foreground, with its unit's exact argv (A5's last step; after "
                 "any change of the local router's spec or image, A1 through A5 again)")


#: The most a protected record may hold; anything longer is refused, never cut.
PLACED_MAX = 1 << 20
_HEX64_RE = re.compile(r"[0-9a-f]{64}")
_AT_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
#: docker's Created: RFC 3339 in UTC, with up to nanoseconds.
_CREATED_RE = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(\.[0-9]{1,9})?Z")


def read_placed(path: str, lstat: Callable = os.lstat, fstat: Callable = os.fstat) -> bytes:
    """A file only root placed, read whole: a regular file, never a link,
    root:root 0444 with one link, as lstat sees it AND as the descriptor
    read from is (the same file), opened without blocking on a special
    file, and read to its end within PLACED_MAX, an oversized file refused."""
    want = (0, 0, RECORD_MODE, 1)

    def placed(st: Any) -> bool:
        return stat.S_ISREG(st.st_mode) and (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_nlink) == want
    st = lstat(path)
    if not placed(st):
        raise OSError(f"{path} is not a root:root 0444 regular file with one link")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    try:
        fst = fstat(fd)
        if (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino) or not placed(fst):
            raise OSError(f"{path} as opened is not the root:root 0444 regular file with one link it was")
        chunks, total = [], 0
        while total <= PLACED_MAX:
            chunk = os.read(fd, PLACED_MAX + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > PLACED_MAX:
            raise OSError(f"{path} is larger than {PLACED_MAX} bytes")
        return b"".join(chunks)
    finally:
        os.close(fd)


def created_seconds(created: Any) -> Optional[int]:
    """docker's Created, to the second, or None unless it is exactly the
    engine's form (RFC 3339 in UTC, up to nanoseconds)."""
    m = _CREATED_RE.fullmatch(created) if isinstance(created, str) else None
    if m is None:
        return None
    try:
        return calendar.timegm(time.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S"))
    except ValueError:
        return None


def _strict(raw: bytes) -> Any:
    import partition_evidence as pe
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pe._no_duplicates, parse_constant=pe._no_constant)


def parse_target(raw: bytes) -> Dict[str, Any]:
    """The writer's stop-target record, or ValueError: canonical bytes,
    exactly its members and types, run ids, full 64-hex ids and digests,
    and a real UTC time."""
    import partition_evidence as pe
    doc = _strict(raw)
    if not isinstance(doc, dict) or set(doc) != set(TARGET_MEMBERS) or doc.get("schema") != TARGET_SCHEMA:
        raise ValueError("not exactly the writer's members and schema")
    if not all(isinstance(doc[k], t) and not isinstance(doc[k], bool) for k, t in TARGET_MEMBERS.items()):
        raise ValueError("a member of the wrong type")
    if pe.canonical(doc) != raw:
        raise ValueError("not in canonical form")
    for k in ("router_container_id", "config_sha256", "evidence_sha256", "inspect_digest", "activation_sha256"):
        if not _HEX64_RE.fullmatch(doc[k]):
            raise ValueError(f"its {k} is not 64 lower-case hex")
    for k in ("run_id", "evidence_run_id", "host"):
        if not re.fullmatch(_RUN, doc[k]):
            raise ValueError(f"its {k} is malformed")
    if not _AT_RE.fullmatch(doc["at"]):
        raise ValueError("its time is malformed")
    calendar.timegm(time.strptime(doc["at"], "%Y-%m-%dT%H:%M:%SZ"))
    return doc


def _answer(doc: Any, cid: str) -> Optional[str]:
    """Why an inspect answer does not affirm container `cid` running, or None."""
    if not isinstance(doc, dict):
        return "the engine's answer is not a container"
    if doc.get("Id") != cid:
        return f"the engine answered for {doc.get('Id')!r}, not {cid}"
    state = doc.get("State")
    if not isinstance(state, dict) or not isinstance(state.get("Running"), bool):
        return "the engine's answer states no running state"
    return None if state["Running"] else f"{cid} is not running"


def verify_target(ps: Optional[PartitionSpec], gs: Optional[GateSpec], *, live_config: str, engine: str,
                  docker: str, router_name: str, inspect: Callable[[str], Any],
                  read: Callable[[str], bytes] = read_placed,
                  read_live: Callable[[str], bytes] = read_record) -> List[rh.Check]:
    """The stop target, judged from the verify copy the weekly job published,
    by its strict grammar: every approved field equal; A1's approved record
    and the cited evidence parsed by their own grammars, their hosts the
    record's and the evidence its cited run's; the live config's token the
    cited evidence's; the recorded id affirmed running by id AND by the
    local router's name (inspected only to compare); and the record no older
    than that container's creation, to the second. A NOTE only when the live
    config, a strict object, carries no delegation AND the gate is not set;
    UNKNOWN when either cannot be told or the engine cannot answer.
    `inspect(ref)`: the container's document, None when the engine affirms
    there is none, or an Unresolved. Never raises on what it reads."""
    import partition_activation as pa
    import partition_evidence as pe
    if ps is None:
        return []
    want = rh.Fact("stop target", True, "the weekly job's own verified record of the running local router")
    try:
        live_raw = read_live(live_config)
        live = _strict(live_raw)
        if not isinstance(live, dict):
            raise ValueError("it is not a JSON object")
    except (OSError, ValueError, UnicodeDecodeError) as e:
        return [rh.unknown(TARGET_CLAIM, want, f"whether delegation is rendered cannot be told: {e}",
                           "make the local router's live config readable, one JSON object")]
    if "delegation" not in live and gs is None:
        return [rh.check(f"{TARGET_CLAIM} (not required: delegation is not rendered and the gate is not set)",
                         want, True, TARGET_REMEDY, ok=lambda e, a: a is True)]

    def fail(why: str) -> List[rh.Check]:
        return [rh.check(TARGET_CLAIM, want, f"no stop target: {why}", TARGET_REMEDY, ok=lambda e, a: a is True,
                         do_not="never write the record by hand, and never copy an id from a name lookup")]

    def unknown(why: str) -> List[rh.Check]:
        return [rh.unknown(TARGET_CLAIM, want, why, "make the engine answer for the local router")]
    try:
        raw = read(posixpath.join(ps.evidence_dir, STOP_TARGET))
    except FileNotFoundError:
        return fail("the weekly job has not recorded one")
    except OSError as e:
        return fail(f"its record is not usable: {e}")
    try:
        doc = parse_target(raw)
    except (ValueError, UnicodeDecodeError) as e:
        return fail(f"its record is not the writer's grammar: {e}")
    for k, v in (("evidence_dir", ps.evidence_dir), ("live_config_path", live_config), ("engine", engine),
                 ("docker", docker)):
        if doc[k] != v:
            return fail(f"its {k} is not the approved document's")
    try:
        activation = read(posixpath.join(ps.evidence_dir, ACTIVATION))
        evidence = read(posixpath.join(ps.evidence_dir, f"partition-{doc['evidence_run_id']}.json"))
    except OSError as e:
        return fail(f"what it was recorded against cannot be read: {e}")
    if hashlib.sha256(activation).hexdigest() != doc["activation_sha256"]:
        return fail("it was recorded against another A1 activation than the approved one")
    if hashlib.sha256(evidence).hexdigest() != doc["evidence_sha256"]:
        return fail("its token's evidence has changed since it was recorded")
    if hashlib.sha256(live_raw).hexdigest() != doc["config_sha256"]:
        return fail("the live config has changed since it was recorded")
    try:
        approved = pa.parse_activation(activation)
        cited = pe.parse(evidence, host=doc["host"])
    except ValueError as e:
        return fail(f"what it was recorded against is not by its grammar, or is another host's: {e}")
    if approved["host"] != doc["host"] or approved["final_config_path"] != live_config:
        return fail("the approved activation is another host's or another config path's")
    if cited["run_id"] != doc["evidence_run_id"]:
        return fail("the cited evidence is another run's")
    delegation = live.get("delegation")
    if not isinstance(delegation, dict) or delegation.get("partition_verified") != pe.token_of(cited):
        return fail("the live config's token is not the cited evidence's")
    cid = doc["router_container_id"]
    try:
        by_id, by_name = inspect(cid), inspect(router_name)
    except Exception as e:  # an answer that cannot be had is not a verdict
        return unknown(f"the engine could not be asked: {e}")
    for what, got in (("by its id", by_id), ("by the local router's name", by_name)):
        if isinstance(got, rh.Unresolved):
            return unknown(f"the engine cannot say {what}: {got.reason}")
        if got is None:
            return fail(f"the engine has no such container {what}: the record is stale (the router was recreated)")
        why = _answer(got, cid)
        if why is None:
            continue
        if isinstance(got, dict) and isinstance(got.get("Id"), str) and got["Id"] != cid:
            return fail(f"{why} ({what}): the record is stale (the router was recreated)")
        if why.endswith("is not running"):
            return fail(f"{why} ({what})")
        return unknown(f"{why} ({what})")
    created = created_seconds(by_name.get("Created"))
    if created is None or created_seconds(by_id.get("Created")) != created:
        return unknown("the engine gives no creation time for the local router in its own form")
    if calendar.timegm(time.strptime(doc["at"], "%Y-%m-%dT%H:%M:%SZ")) < created:
        return fail("it was recorded before the running local router was created")
    return [rh.check(TARGET_CLAIM, want, True, TARGET_REMEDY, ok=lambda e, a: a is True)]


def verify_tools(ps: PartitionSpec, lstat: Callable, owned_chain: Callable,
                 realpath: Callable[[str], str] = os.path.realpath,
                 pin_read: Optional[Callable[[str], Any]] = None) -> List[rh.Check]:
    """The weekly job's tools as root will run them: each one's realpath a
    regular executable, root-owned and not group- or world-writable, under
    root-owned directories that are not either, and a pinned one the client
    its pin names (secret_setup.tool_pin_row). The tripwire half of the
    design's tool rule; the startup closure is validated at install time,
    with the operating system's own tools."""
    out: List[rh.Check] = []
    why = "the weekly job runs it as root"
    for name in WEEKLY_TOOLS:
        path = ps.tools[name]
        claim = f"the weekly job's {name} {path} resolves to a root-owned executable no one else can write"
        want = rh.Fact("tool", True, why)
        remedy = f"record a {name} the operating system or its vendor installed, root-owned, as partition.tools.{name}"
        if name in ps.tool_sha256:
            import secret_setup
            out.append(secret_setup.tool_pin_row(SECTION, name, path, ps.tool_sha256[name], lstat, pin_read))
        try:
            real = realpath(path)
            st = lstat(real)
        except OSError as e:
            out.append(rh.unknown(claim, want, f"cannot inspect {path}: {e}", remedy))
            continue
        ok = stat.S_ISREG(st.st_mode) and bool(st.st_mode & 0o111) and st.st_uid == 0 and not st.st_mode & 0o022
        out.append(rh.check(claim, want, ok or f"{real}: owner {st.st_uid}, mode {oct(stat.S_IMODE(st.st_mode))}",
                            remedy, ok=lambda e, a: a is True,
                            do_not="never record a tool the operator's account can replace"))
        out.append(owned_chain(f"every directory above {real} is root-owned and not group- or world-writable",
                               real, (0,), why, lstat))
        if real != path:
            out.append(owned_chain(f"every directory above the configured {path} is root-owned and not group- or "
                                   "world-writable, so no one else can point it elsewhere", path, (0,), why, lstat))
    return out


#: What the plan prints in place of a root line when there is no pinned writer to run it through.
NO_WRITER = "<the secrets section's pinned writer: every root line runs through it>"


def plan(p: PartitionSpec, gs: Optional[GateSpec], q: Callable[[str], str], *, anchor: Optional[str],
         install: Optional[Callable[[List[str]], str]] = None,
         read: Callable[[str], bytes] = read_record) -> List[str]:
    """The operator's steps for the two sections: the directories, and, for the
    gate, the design's six steps with this host's paths. When a record is
    already placed, its own harness_sha is printed for the overlay change.
    `install` renders one root `install` line through the barrier (d3.3
    §5(d)) from install's arguments; without one, each root line names the
    writer it needs instead."""
    root = install or (lambda args: NO_WRITER)
    record = posixpath.join(p.evidence_dir, GATE_RECORD)
    lines = [
        "# The partition evidence: root-owned, under root-owned directories; the controls' scratch space:",
        root(["-d", "-o", "0", "-g", "0", "-m", "0755", p.evidence_dir]),
        root(["-d", "-o", "0", "-g", "0", "-m", "0700", p.scratch_dir]),
        "# The weekly job's root: its provisioned bundle, lock, run directories and recovery description:",
        root(["-d", "-o", "0", "-g", "0", "-m", "0700", p.exec_root]),
        "# The delegation gate, the operator's alone, when the conformance harness reports its full run passed,",
        "# given the relayed record and its sha256:",
        "#   1. shasum -a 256 <the relayed file>   (or sha256sum): it must print the relayed sha256",
        "#   2. " + root(["-o", "0", "-g", "0", "-m", "0444", "<the relayed file>", record]),
        "#   3. in the private overlay, a PR setting delegation_gate: harness_sha COPIED from the record's own",
        "#      harness_sha member (the commit the gate ran at, reachable from the harness PR's head ref; squash",
        f"#      merges leave it off main), record_sha256 the relayed sha256, record_path {record}",
    ]
    try:
        own = hg.parse(read(record))["harness_sha"]
        lines.append(f"#      the placed record's harness_sha is {own}: confirm it is reachable from the harness PR's "
                     f"head ref in the harness repository")
    except (OSError, hg.RecordError) as e:
        lines.append(f"#      (no placed record to read the harness_sha from: {e})")
    lines += [
        "#   4. after the PR merges, write its commit to the anchor: "
        + root(["-o", "0", "-g", "0", "-m", "0444", "<a file holding the merged commit sha>",
                anchor if anchor else "<secrets.anchor>"]),
        "#   5. make the fresh overlay clone at that commit, as the runbook does for an overlay change",
        "#   6. amap-sandy.py install (a dry run first), then the activation sequence; it refuses unless the gate "
        "holds",
    ]
    if gs is not None:
        lines.append(f"# delegation_gate is set: harness_sha {gs.harness_sha}, record_sha256 {gs.record_sha256}")
    return lines
