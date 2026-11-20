"""S10 SUMMARY (section 5.5) and the eligibility rule (section 5.4).

S10 writes its receipt, then the final manifest, then `summary.txt`, each
listed in SUMS in that order, and prints the SUMS sha to the terminal only
after SUMS is final: no file inside the chain carries the chain's own hash.

The eligibility verifier reads the run directory and the `alpha2.hosts`
bytes whose sha256 equals the manifest's `hosts_sha256`, and nothing else.
"""

import hashlib
import json
import os
import secrets

import a2_locks
import a2_private
import a2_record
from a2_causes import Refusal

#: Which stages have one receipt per VM of the run, and which one receipt
#: with host "-". Section 5.4 says "every host it applies to in
#: alpha2.hosts"; this table is this package's reading of section 2's
#: "Writes to" column, submitted to the reviewers (INFERRED).
PER_VM = ("S2", "S4", "S5", "S6", "S6b", "S7", "S8")
SINGLE = ("S0", "S1", "S3", "S9", "S10")
ORDER = ("S0", "S1", "S2", "S3", "S4", "S5", "S6", "S6b", "S7", "S8", "S9", "S10")
RUN_ELIGIBLE_LOOPS = (None, "L3")


def expected_receipts(hosts_doc, account):
    """(stage, host) pairs a full install of the run's scope must have."""
    vms = [v["name"] for v in hosts_doc["vms"] if v["scope"] == account]
    out = []
    for sid in ORDER:
        if sid in PER_VM:
            out.extend((sid, vm) for vm in vms)
        else:
            out.append((sid, None))
    return out


def _read(dir_fd, name, limit=1 << 24):
    return a2_record._read_at(dir_fd, name, limit)


MANIFEST_KEYS = ("schema", "state", "run_id", "command", "loop", "source_run", "installer_sha256",
                 "lock_sha256", "hosts_sha256", "started", "ended", "env_names", "stages")
STAGE_KEYS = ("stage", "host", "receipt", "sha256", "rc")
COMMANDS = ("install", "dry-run", "verify", "canary", "add-agent", "rotate-key", "check-roundtrip",
            "destroy")
LOOPS = ("L1", "L2", "L2-leak", "L3", None)


def check_manifest(man):
    """The closed 6.3 schema. Returns None, or the first rule broken."""
    if not isinstance(man, dict) or set(man) - set(MANIFEST_KEYS):
        return "the manifest has a key 6.3 does not name"
    if man.get("schema") != "alpha2.run/1":
        return "the manifest's schema token"
    if man.get("state") not in ("active", "final"):
        return "the manifest's state"
    if not a2_private.matches("run_id", man.get("run_id")):
        return "the manifest's run_id"
    if man.get("command") not in COMMANDS:
        return "the manifest's command"
    if "loop" not in man or man["loop"] not in LOOPS:
        return "the manifest's loop"
    sr = man.get("source_run", "missing")
    if not (sr is None or (isinstance(sr, dict) and set(sr) == {"run_id", "sums_sha256"}
                           and a2_private.matches("run_id", sr["run_id"])
                           and a2_private.matches("sha256", sr["sums_sha256"]))):
        return "the manifest's source_run"
    for k in ("installer_sha256", "lock_sha256", "hosts_sha256"):
        if not a2_private.matches("sha256", man.get(k)):
            return "the manifest's " + k
    if not a2_private.matches("utc", man.get("started")):
        return "the manifest's started"
    if man["state"] == "final":
        if not a2_private.matches("utc", man.get("ended")):
            return "the manifest's ended"
    elif "ended" in man:
        return "an active manifest has ended"
    if man.get("env_names") != ["HOME", "PATH", "SSH_AUTH_SOCK", "TERM"]:
        return "the manifest's env_names"
    stages = man.get("stages")
    if not isinstance(stages, list):
        return "the manifest's stages"
    seen = set()
    for st in stages:
        if not isinstance(st, dict) or set(st) != set(STAGE_KEYS):
            return "a manifest stage row's keys"
        if st["stage"] not in a2_record.STAGE_NAME:
            return "a manifest stage row's stage"
        host = st["host"]
        if not (host == "-" or a2_private.matches("name", host)):
            return "a manifest stage row's host"
        if st["receipt"] != "receipts/" + a2_record.receipt_name(st["stage"], None if host == "-" else host):
            return "a manifest stage row's receipt path"
        if not a2_private.matches("sha256", st["sha256"]):
            return "a manifest stage row's sha256"
        if type(st["rc"]) is not int or st["rc"] not in (0, 2, 3, 4):
            return "a manifest stage row's rc"
        if (st["stage"], host) in seen:
            return "a stage and host appear twice"
        seen.add((st["stage"], host))
    return None


def eligibility(run_fd, hosts_raw, before_summary=False):
    """5.4: (True, "") or (False, reason), reading only the run directory and
    the hosts bytes. Every malformed shape is NOT ELIGIBLE, never an
    exception. With before_summary (S10 itself), the chain is verified as it
    stands, ending with the final manifest."""
    try:
        return _eligibility(run_fd, hosts_raw, before_summary)
    except Exception:
        return False, "the run record is malformed"


def _eligibility(run_fd, hosts_raw, before_summary):
    try:
        a2_record.verify_sums(run_fd)
    except Refusal:
        return False, "SUMS does not verify"
    man_raw = _read(run_fd, a2_record.MANIFEST)
    man = json.loads(man_raw)
    bad = check_manifest(man)
    if bad:
        return False, bad
    sums = _read(run_fd, a2_record.SUMS).decode("ascii")
    if hashlib.sha256(hosts_raw).hexdigest() != man["hosts_sha256"]:
        return False, "the hosts file is not the one this run read"
    try:
        hosts = a2_private.parse(hosts_raw, "alpha2.hosts/1")
        a2_private.check_hosts(hosts)
    except a2_private.Invalid:
        return False, "the hosts file does not pass its schema"
    lines = [ln.split(" ") for ln in sums.splitlines()]
    paths = [f[3] for f in lines]
    tail = [a2_record.MANIFEST] if before_summary else [a2_record.MANIFEST, a2_record.SUMMARY]
    if paths[-len(tail):] != tail:
        return False, "SUMS does not end with the manifest and the summary"
    stages = man["stages"]
    if paths[:-len(tail)] != [st["receipt"] for st in stages]:
        return False, "the receipt lines are not the manifest's stages"
    digests = {f[3]: f[1] for f in lines}
    if any(digests[st["receipt"]] != st["sha256"] for st in stages):
        return False, "a receipt digest differs from the manifest"
    if man["command"] != "install" or man["loop"] not in RUN_ELIGIBLE_LOOPS:
        return False, "only an install whose loop is null or L3 is eligible"
    if man["source_run"] is not None:
        return False, "the run took predecessors from another run"
    if man["state"] != "final":
        return False, "the manifest is not final"
    # An eligible install (loop null or L3) runs as the L3 account (5.3b), so
    # its VMs are the l3 scope; the record names no other account.
    expected = expected_receipts(hosts, "l3")
    have = {(st["stage"], None if st["host"] == "-" else st["host"]): st for st in stages}
    if set(have) - set(expected):
        return False, "a stage row the run does not have"
    for sid, host in expected:
        st = have.get((sid, host))
        if st is None:
            return False, "a stage has no receipt: " + sid + (" " + host if host else "")
        if st["rc"] != 0:
            return False, "a stage did not pass: " + sid
    loop_token = "-" if man["loop"] is None else man["loop"]
    rfd = os.open(a2_record.RECEIPTS, a2_record.DIR_FLAGS, dir_fd=run_fd)
    try:
        for st in stages:
            name = st["receipt"].split("/", 1)[1]
            host = None if st["host"] == "-" else st["host"]
            data = _read(rfd, name)
            try:
                facts, rc = a2_record.check_receipt(data, st["stage"], host, name)
            except ValueError:
                return False, "a receipt breaks a 3.3 rule: " + st["stage"]
            if rc != st["rc"]:
                return False, "a receipt's rc differs from the manifest"
            if (facts["RUN_ID"] != man["run_id"] or facts["COMMAND"] != man["command"]
                    or facts["LOOP"] != loop_token):
                return False, "a receipt is not bound to this run"
            if facts["RESULT"] not in ("CHANGED", "ALREADY", "PASS"):
                return False, "a receipt's result is not CHANGED, ALREADY or PASS"
            if any(v == "UNOBSERVED" for v in facts.values()):
                return False, "a receipt carries an UNOBSERVED fact"
            if facts["INSTALLER_SHA"] != man["installer_sha256"]:
                return False, "a receipt's installer sha differs from the manifest"
            if facts["LOCK_SHA"] != man["lock_sha256"]:
                return False, "a receipt's lock sha differs from the manifest"
            if facts["HOSTS_SHA"] != man["hosts_sha256"]:
                return False, "a receipt's hosts sha differs from the manifest"
            if st["stage"] == "S9" and facts.get("PROCESSING_PROOF") != "pass":
                return False, "S9 has no processing proof"
    finally:
        os.close(rfd)
    return True, ""


OPERATOR_STEPS = 3


def summary_text(c, run, eligible, reason, first_causes, operator_steps, nonce):
    """The summary's lines (5.5). Every line is a fact a receipt may carry,
    or is marked INFERRED or UNMEASURED. RESULT comes from the stages' rcs
    alone; eligibility is its own last line. The agents and VMs listed are
    the run's (its scope, or destroy's set)."""
    if operator_steps is not None and (
            not isinstance(operator_steps, (list, tuple)) or len(operator_steps) != OPERATOR_STEPS
            or not all(isinstance(t, str) and t and t.isascii() and t.isprintable() for t in operator_steps)):
        raise ValueError("operator steps must be exactly three printable lines")
    failed = [s for s in run.stages if s["rc"] != 0]
    lines = ["RESULT " + ("FAIL" if failed else "PASS")]
    for s in run.stages:
        cause = first_causes.get((s["stage"], s["host"]))
        lines.append("stage %s host %s rc %d%s" % (s["stage"], s["host"], s["rc"],
                                                     " cause " + cause if cause else ""))
    lines.append("run directory runs/" + run.run_id)
    lines.append("lock sha " + run.lock_sha)
    vms = a2_locks.run_vms(c.hosts, c.inv, c.account)
    names = {v["name"] for v in vms}
    for a in c.hosts["agents"]:
        if a["vm"] not in names:
            continue
        vm = next(v for v in vms if v["name"] == a["vm"])
        lines.append("agent %s address %s@%s INFERRED" % (a["id"], a["id"], vm["fleet_domain"]))
    for v in vms:
        lines.append("vm %s access: ssh %s INFERRED" % (v["name"], v["ssh_alias"]))
    if operator_steps is not None:
        for i, step in enumerate(operator_steps, 1):
            lines.append("operator step %d: %s" % (i, step))
    else:
        lines.append("operator steps UNMEASURED: not supplied to this package")
    lines.append("round trip: alpha2_install.py --check-roundtrip " + nonce)
    if c.inv.loop in ("L2", "L3"):
        lines.append("RL reply-depth check UNMEASURED")
    lines.append("ELIGIBLE" if eligible else "NOT ELIGIBLE: " + reason)
    return "".join(ln + "\n" for ln in lines)


def run_s10(c, site, run, guard, custody_facts, custody_cause, custody_rc=2):
    """S10: its receipt (with the custody read-back before it), the final
    manifest, then the chain verified as it stands, then eligibility, the
    summary, the completed chain verified again, and the SUMS sha on the
    terminal. A custody mismatch fails S10's receipt; the summary is still
    written, NOT ELIGIBLE. custody_rc is the FAIL receipt's rc: 2 for a
    mismatch, 3 for a read-back the runner could not make. Returns
    (eligible, SUMS sha)."""
    started = run.started
    facts = [(k, custody_facts[k]) for k in ("CUSTODY_LOCKS", "CUSTODY_PLACEMENT", "CUSTODY_STOP")]
    if custody_cause:
        run.write_receipt("S10", None, started, "FAIL", facts, rc=custody_rc, cause=custody_cause)
    else:
        run.write_receipt("S10", None, started, "PASS", facts)
    first_causes = dict(run.causes)
    run.write_manifest(final=True)
    a2_record.verify_sums(c.run_fd)
    eligible, reason = eligibility(c.run_fd, c.hosts_raw, before_summary=True)
    nonce = secrets.token_hex(8)
    text = summary_text(c, run, eligible, reason, first_causes, site.operator_steps, nonce)
    data = text.encode("ascii")
    guard.check(data)
    a2_record._write_atomic(c.run_fd, a2_record.SUMMARY, data)
    run._append_sums(a2_record.SUMMARY, data)
    sums_sha = a2_record.verify_sums(c.run_fd)
    for ln in text.splitlines():
        guard.emit(site.out, ln)
    guard.emit(site.out, "SUMS sha256 " + sums_sha)
    return eligible, sums_sha
