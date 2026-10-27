"""The connector's committed unified adoption, judged by one rule in the sandbox and on the host.

Standard library only, importable on Python 3.9, with no connector Config: each caller passes
the values it trusts, and every adoption column must equal all of them.
"""
from contextlib import closing
from pathlib import Path
import re
import sqlite3

DIGEST = "[a-f0-9]{64}"
PENDING = ("; pending explicit revalidation: with the sandbox running, its relay held and no Codex service, "
           "run transition confirm, then confirm --apply")


def evidence(journal, instance_id):
    """`(binding, adoption)` rows from ONE read snapshot of the journal, opened read-only.

    It never creates, migrates or writes the journal. A missing table, a lock or a read error is
    a ValueError that names the evidence."""
    journal = Path(journal)
    if journal.is_symlink() or not journal.is_file():
        raise ValueError("journal is unavailable or a symlink")
    try:
        with closing(sqlite3.connect(journal.as_uri() + "?mode=ro", uri=True)) as db:
            db.row_factory = sqlite3.Row
            # A SELECT outside a transaction is its own snapshot; BEGIN holds one across both reads.
            db.execute("BEGIN")
            try:
                binding = db.execute("SELECT i.fingerprint,b.thread_id,b.policy_hash,b.effective_model "
                                     "FROM instance i JOIN unified_binding b USING(instance_id) "
                                     "WHERE i.instance_id=?", (instance_id,)).fetchone()
                adoption = db.execute("SELECT state,thread_id,fingerprint,previous_fingerprint,policy_hash,"
                                      "history_sha256 FROM unified_adoptions WHERE singleton=1").fetchone()
            finally:
                db.rollback()
    except sqlite3.Error as exc:
        raise ValueError("unified binding or native adoption record is unavailable: " + str(exc)) from exc
    return binding, adoption


def well_formed(value, digest):
    return isinstance(value, str) and bool(value) and (not digest or re.fullmatch(DIGEST, value) is not None)


def problems(adoption, *, thread, fingerprint, previous_fingerprint, policy_hash):
    """Named disagreements. Each keyword is a tuple of the trusted values that column must equal;
    an empty tuple, or a malformed trusted value, binds nothing and is itself a problem."""
    if adoption is None:
        return ["native adoption record is unavailable"]
    found = []
    if adoption["state"] != "confirmed":
        found.append("native adoption is not confirmed")
    for column, label, trusted in (("thread_id", "thread", thread), ("fingerprint", "fingerprint", fingerprint),
                                   ("previous_fingerprint", "previous_fingerprint", previous_fingerprint),
                                   ("policy_hash", "policy_hash", policy_hash)):
        digest = column != "thread_id"
        if not trusted or not all(well_formed(value, digest) for value in trusted):
            found.append("native adoption " + label + " has no valid expected value"
                         + (PENDING if column == "previous_fingerprint" else ""))
        elif not well_formed(adoption[column], digest) or any(adoption[column] != value for value in trusted):
            found.append("native adoption " + label + " is malformed or differs from its confirmed bindings")
    if not well_formed(adoption["history_sha256"], True):
        found.append("native adoption history digest is malformed")
    return found
