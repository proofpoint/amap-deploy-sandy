"""The conformance harness's full-run gate record: one of the two conditions
under which the local router's `delegation` may be rendered at all (the
other is current partition evidence, partition_evidence). NOTHING HERE
FETCHES OR WRITES A RECORD: the operator places the record, and names its
sha256 and the harness commit it ran at, in the anchored overlay; this module
judges the bytes it is handed.

The record is canonical JSON with exactly RECORD_MEMBERS. The checks, G1 to
G7, are over that shape only; "no blocking case", "no surviving mutant" and
"the synthetic checks pass" are summaries DERIVED from its members, never
members of their own:
- G1: the bytes hash to the sha256 the overlay names and are exactly their
  canonical form;
- G2: `exit_status` is 0 and `verdict` is "PASS";
- G3: `rl_sha`, `hop_sha` and `hop_artifact_sha256` are the local router's
  commit, the hop pin and the plugin this deployment renders, compared whole;
- G4: inbound comes through the `delegation.inbound` opt-in, with no override
  of the build constant that makes it available;
- G5: the expected cases are the PINNED set (checked first), the cases seen
  are exactly the expected ones, every outcome kind is in the vocabulary, the
  kinds sum to the count, and every blocking kind is 0;
- G6: the expected mutants are the PINNED list (checked first; there is none
  until the harness's design freezes it, and until then G6 refuses), the
  mutants judged are exactly those ids, once each, and every one was killed;
- G7: the synthetic checks are exactly S1, S2 and S3, each passing with its
  sender never installed.

The expected sets are constants of this module and move only by a reviewed
change to it: a record that wrote its expected sets from what it ran would
otherwise be checked only against itself. The record's `schema` and `unit`
values, and the mutant list, are pinned by their sha256 alone.
"""

import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple

#: sha256 of the record's `schema` value and of its `unit` value.
SCHEMA_SHA256 = "c898385441775a67c15497eb7dcc2e9735bdb0697108dc5b41ff3c838376acae"
UNIT_SHA256 = "6310dd4912a80935203600f1d24922f49744b9324b494c6310b12479608995d5"
#: The expected case set: its count, and the sha256 of the sorted lower-case
#: case sha256s joined by "\n" (no trailing newline), each the sha256 of the
#: case document's raw blob in the pinned specification bundle.
CASE_COUNT = 112
CASES_SET_SHA256 = "10e1401b725739d050686d92bb6e642cb4d85dc0e61c898e451e6fe565576f43"
#: The expected mutant ids, as the sha256 of the sorted ids joined by "\n"
#: (no trailing newline), and their count. None until the harness's design
#: freezes the list: G6 refuses while it is None.
MUTANT_IDS_SHA256: Optional[str] = None
MUTANT_COUNT: Optional[int] = None
#: Every case outcome kind the record may report, and the ones that block:
#: the harness gate's own kinds, exactly, with no renames.
BLOCKING_KINDS = ("pending", "overlay_pending", "fail", "fail_stale_label", "known_erratum_unratified")
OUTCOME_KINDS = frozenset({"pass", "overlay_mapped", "declared_difference", "known_erratum", "spec_question"}
                          | set(BLOCKING_KINDS))
MUTANT_OUTCOMES = frozenset({"killed", "survived", "not_run"})
SYNTHETIC = ("S1", "S2", "S3")
INBOUND_MODE = "delegation.inbound"
#: The build constant whose override the record must not carry.
INBOUND_OVERRIDE = "INBOUND_AVAILABLE"
RECORD_MEMBERS = frozenset({
    "schema", "unit", "harness_sha", "rl_sha", "hop_sha", "hop_plugin_api", "hop_artifact_sha256",
    "rl_registry_fixture_sha256", "s5r4", "exit_status", "verdict", "cases_expected", "cases_seen",
    "case_outcomes", "mutants_expected", "mutants", "synthetic_expected", "synthetic", "o1", "o2",
    "o3_placed", "inbound_mode", "profiles", "overrides", "results_sha256"})
MAX_BYTES = 1 << 20
_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")


class RecordError(ValueError):
    """The record is not the gate record's one shape."""


def canonical(doc: Any) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def set_sha256(items: List[str]) -> str:
    return _sha("\n".join(sorted(items)).encode("utf-8"))


def _no_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise RecordError(f"the key {k!r} appears twice")
        out[k] = v
    return out


def _no_constant(name: str) -> Any:
    raise RecordError(f"{name} is not JSON")


def _int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _type_problems(r: Dict[str, Any]) -> List[str]:
    bad = []
    for k in ("schema", "unit", "verdict", "o1", "inbound_mode"):
        if not isinstance(r[k], str):
            bad.append(f"{k} is not a string")
    for k in ("harness_sha", "rl_sha", "hop_sha"):
        if not isinstance(r[k], str) or not _HEX40.fullmatch(r[k]):
            bad.append(f"{k} is not 40 lower-case hex")
    for k in ("hop_artifact_sha256", "rl_registry_fixture_sha256", "results_sha256"):
        if not isinstance(r[k], str) or not _HEX64.fullmatch(r[k]):
            bad.append(f"{k} is not 64 lower-case hex")
    api = r["hop_plugin_api"]
    if not isinstance(api, list) or len(api) != 2 or not all(_int(x) for x in api):
        bad.append("hop_plugin_api is not two integers")
    s = r["s5r4"]
    if not isinstance(s, dict) or set(s) != {"commit", "profile_sha256"} \
            or not isinstance(s.get("commit"), str) or not _HEX40.fullmatch(s["commit"]) \
            or not isinstance(s.get("profile_sha256"), str) or not _HEX64.fullmatch(s["profile_sha256"]):
        bad.append("s5r4 is not {commit, profile_sha256}")
    if not _int(r["exit_status"]):
        bad.append("exit_status is not an integer")
    for k in ("cases_expected", "cases_seen"):
        c = r[k]
        if not isinstance(c, dict) or set(c) != {"count", "set_sha256"} or not _int(c.get("count")) \
                or not isinstance(c.get("set_sha256"), str) or not _HEX64.fullmatch(c["set_sha256"]):
            bad.append(f"{k} is not {{count, set_sha256}}")
    co = r["case_outcomes"]
    if not isinstance(co, dict) or not all(isinstance(k, str) and _int(v) and v >= 0 for k, v in co.items()):
        bad.append("case_outcomes is not {kind: count}")
    me = r["mutants_expected"]
    if not isinstance(me, dict) or set(me) != {"count", "ids"} or not _int(me.get("count")) \
            or not isinstance(me.get("ids"), list) or not all(isinstance(i, str) and i for i in me["ids"]):
        bad.append("mutants_expected is not {count, ids}")
    ms = r["mutants"]
    if not isinstance(ms, list) or not all(isinstance(m, dict) and set(m) == {"id", "outcome", "by"}
                                           and all(isinstance(m[x], str) for x in m) for m in ms):
        bad.append("mutants is not a list of {id, outcome, by}")
    if not isinstance(r["synthetic_expected"], list) or not all(isinstance(x, str) for x in r["synthetic_expected"]):
        bad.append("synthetic_expected is not a list of names")
    sy = r["synthetic"]
    if not isinstance(sy, dict) or not all(isinstance(v, dict) and set(v) == {"verdict", "sender_never_installed"}
                                           and isinstance(v["verdict"], str)
                                           and isinstance(v["sender_never_installed"], bool) for v in sy.values()):
        bad.append("synthetic is not {name: {verdict, sender_never_installed}}")
    o2 = r["o2"]
    if not isinstance(o2, dict) or set(o2) != {"total", "hold", "accepted"} or not all(_int(v) for v in o2.values()):
        bad.append("o2 is not {total, hold, accepted}")
    if not _int(r["o3_placed"]):
        bad.append("o3_placed is not an integer")
    if not isinstance(r["profiles"], dict) or not all(isinstance(v, str) for v in r["profiles"].values()):
        bad.append("profiles is not {name: profile}")
    if not isinstance(r["overrides"], list) or not all(isinstance(x, str) for x in r["overrides"]):
        bad.append("overrides is not a list of names")
    return bad


def parse(raw: bytes) -> Dict[str, Any]:
    """`raw` as the gate record's one shape, or RecordError naming what is wrong."""
    if len(raw) > MAX_BYTES:
        raise RecordError(f"larger than {MAX_BYTES} bytes")
    try:
        r = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise RecordError(f"not JSON: {e}") from None
    if not isinstance(r, dict) or set(r) != RECORD_MEMBERS:
        raise RecordError("not exactly the record's members")
    if _sha(r["schema"].encode("utf-8") if isinstance(r["schema"], str) else b"") != SCHEMA_SHA256:
        raise RecordError("schema is not the pinned one")
    if _sha(r["unit"].encode("utf-8") if isinstance(r["unit"], str) else b"") != UNIT_SHA256:
        raise RecordError("unit is not the pinned one")
    bad = _type_problems(r)
    if bad:
        raise RecordError("; ".join(bad))
    return r


def problems(raw: bytes, *, record_sha256: str, rl_sha: str, hop_sha: str,
             plugin_sha256: str) -> List[Tuple[str, str]]:
    """Every (gate, reason) the record at `raw` fails; empty when the guard's
    condition holds. `record_sha256` is the overlay's; the other three are what
    this deployment renders."""
    out: List[Tuple[str, str]] = []
    if _sha(raw) != record_sha256:
        return [("G1", "the record's bytes do not hash to the sha256 the overlay names")]
    try:
        r = parse(raw)
    except RecordError as e:
        return [("G1", f"not the record's one shape: {e}")]
    if canonical(r) != raw:
        out.append(("G1", "the record is not exactly its canonical form"))
    if r["exit_status"] != 0 or r["verdict"] != "PASS":
        out.append(("G2", f"exit_status {r['exit_status']}, verdict {r['verdict']!r}"))
    for k, want in (("rl_sha", rl_sha), ("hop_sha", hop_sha), ("hop_artifact_sha256", plugin_sha256)):
        if r[k] != want:
            out.append(("G3", f"{k} is {r[k]}, not {want}, which this deployment renders"))
    if r["inbound_mode"] != INBOUND_MODE:
        out.append(("G4", f"inbound_mode is {r['inbound_mode']!r}, not {INBOUND_MODE!r}"))
    if any(INBOUND_OVERRIDE in o for o in r["overrides"]):
        out.append(("G4", f"an override names {INBOUND_OVERRIDE}"))
    out += [("G5", w) for w in _case_problems(r)]
    out += [("G6", w) for w in _mutant_problems(r)]
    out += [("G7", w) for w in _synthetic_problems(r)]
    return out


def _case_problems(r: Dict[str, Any]) -> List[str]:
    expected, seen, co = r["cases_expected"], r["cases_seen"], r["case_outcomes"]
    if expected != {"count": CASE_COUNT, "set_sha256": CASES_SET_SHA256}:
        return ["the expected cases are not the pinned set"]
    bad = []
    if seen != expected:
        bad.append("the cases seen are not exactly the expected ones")
    unknown = sorted(set(co) - OUTCOME_KINDS)
    if unknown:
        bad.append(f"outcome kinds outside the vocabulary: {', '.join(unknown)}")
    if sum(co.values()) != seen["count"]:
        bad.append(f"the outcomes sum to {sum(co.values())}, not {seen['count']}")
    blocking = {k: co[k] for k in BLOCKING_KINDS if co.get(k, 0)}
    if blocking:
        bad.append("blocking outcomes: " + ", ".join(f"{k} {n}" for k, n in sorted(blocking.items())))
    return bad


def _mutant_problems(r: Dict[str, Any]) -> List[str]:
    if MUTANT_IDS_SHA256 is None or MUTANT_COUNT is None or MUTANT_COUNT <= 0:
        return ["no mutant list is pinned yet: the harness's design has not frozen it"]
    expected = r["mutants_expected"]
    if expected["count"] != MUTANT_COUNT or len(expected["ids"]) != MUTANT_COUNT \
            or len(set(expected["ids"])) != MUTANT_COUNT or set_sha256(expected["ids"]) != MUTANT_IDS_SHA256:
        return ["the expected mutants are not the pinned list"]
    ids = [m["id"] for m in r["mutants"]]
    bad = []
    if len(ids) != len(set(ids)):
        bad.append("a mutant id appears more than once")
    if set(ids) != set(expected["ids"]):
        bad.append("the mutants judged are not exactly the expected ids")
    for m in r["mutants"]:
        if m["outcome"] not in MUTANT_OUTCOMES:
            bad.append(f"mutant {m['id']}'s outcome {m['outcome']!r} is outside the vocabulary")
        elif m["outcome"] != "killed":
            bad.append(f"mutant {m['id']} was {m['outcome']}, not killed")
    return bad


def _synthetic_problems(r: Dict[str, Any]) -> List[str]:
    bad = []
    if r["synthetic_expected"] != list(SYNTHETIC):
        bad.append(f"synthetic_expected is not {list(SYNTHETIC)}")
    if sorted(r["synthetic"]) != list(SYNTHETIC):
        bad.append(f"the synthetic checks are not exactly {', '.join(SYNTHETIC)}")
    for name, v in sorted(r["synthetic"].items()):
        if v["verdict"] != "pass" or v["sender_never_installed"] is not True:
            bad.append(f"{name}: verdict {v['verdict']!r}, sender_never_installed {v['sender_never_installed']}")
    return bad
