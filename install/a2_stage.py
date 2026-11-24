"""The per-VM stage loop shared by S5 and S6 (and later per-VM stages): one receipt per VM of the run's scope.

Each VM's step returns (facts, result). The receipt is written with that result; a refusal writes that VM's FAIL
receipt, with the refusal's cause and exit code, and stops the stage there: later VMs get no receipt, which S10
reports as missing. A dry-run writes each VM's PLANNED receipt from the plan's facts and touches no VM (5.1:
`--dry-run` runs every stage's plan and writes only the run directory).
"""

import a2_record
from a2_causes import Refusal

PER_VM_SCOPE = {"L1": "loop", "L2": "loop", "L2-leak": "loop"}


def scope_of(loop):
    """`loop` for the loop's runs, `l3` for every other."""
    return PER_VM_SCOPE.get(loop, "l3")


def per_vm(rec, site, stage_id, names, step, plan=None, dry_run=False):
    """Run `step(name)` for each VM name in order, writing each VM's receipt. `plan(name)` gives a dry-run's facts."""
    for name in names:
        started = a2_record.utc_now(site.now)
        if dry_run:
            rec.write_receipt(stage_id, name, started, "PLANNED", plan(name) if plan else [])
            continue
        try:
            facts, result = step(name)
        except Refusal as r:
            # A stage may attach the state its refusal left (3.4: an rc-3 receipt says what state was left).
            rec.write_receipt(stage_id, name, started, "FAIL", getattr(r, "facts", []), rc=r.rc, cause=r.cause)
            raise
        rec.write_receipt(stage_id, name, started, result, facts)


def refuse_before_vms(rec, site, stage_id, names, refusal):
    """A refusal the stage meets before its first VM step (a scope or a predecessor): written in the first VM's
    receipt, then raised."""
    rec.write_receipt(stage_id, names[0] if names else None, a2_record.utc_now(site.now), "FAIL", [],
                      rc=refusal.rc, cause=refusal.cause)
    raise refusal
