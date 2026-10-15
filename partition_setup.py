"""The host-setup document's `partition` and `delegation_gate` sections: where
the partition evidence lives, where the controls may make throwaway paths,
when the weekly probe runs, and the conformance harness's passing record
that, with current evidence, lets `delegation` be rendered at all.

`partition` {evidence_dir, scratch_dir, weekly{weekday, hour}} is authored
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
- `weekly`: the probe job's day and hour only.
- `record_path`: exactly `<evidence_dir>/gate-record.json`, a regular file,
  root:root 0444, one link, checked and read through ONE descriptor.
- `harness_sha`: the harness commit the gate RAN at, copied from the record's
  own member, which it must equal.
"""

import os
import posixpath
import re
import stat
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence

import harness_gate as hg
import router_health as rh

SECTION = "partition"
GATE_SECTION = "delegation_gate"
GATE_RECORD = "gate-record.json"
EVIDENCE_MODE = 0o755
SCRATCH_MODE = 0o700
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
    if not isinstance(sec, dict) or set(sec) != {"evidence_dir", "scratch_dir", "weekly"}:
        raise PartitionSpecError("partition must have exactly evidence_dir, scratch_dir and weekly")
    ev, scratch = _abs(sec["evidence_dir"], "partition.evidence_dir"), _abs(sec["scratch_dir"], "partition.scratch_dir")
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
    return PartitionSpec(evidence_dir=ev, scratch_dir=scratch, weekday=w["weekday"], hour=w["hour"])


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
           read: Callable[[str], bytes] = read_record) -> List[rh.Check]:
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
        for path, mode, what in ((ps.evidence_dir, EVIDENCE_MODE, "evidence"), (ps.scratch_dir, SCRATCH_MODE, "scratch")):
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
    if delegation_enabled or gs is not None:
        bad = gate_problems(gs, rl_sha=rl_sha, hop_sha=hop_sha, plugin_sha256=plugin_sha256, read=read)
        claim = "the conformance harness's gate record holds for this deployment"
        want = rh.Fact("gate", [], "the harness's passing record, at this router commit, hop pin and plugin")
        out.append(rh.check(claim, want, bad, "the operator places the harness's record and writes delegation_gate "
                            "(the design's §11.2 steps); until then delegation stays off",
                            do_not="never edit the record or the section to make it hold"))
    return out
