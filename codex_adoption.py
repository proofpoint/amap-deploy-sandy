"""The connector's committed unified adoption, judged by one rule in the sandbox and on the host.

Standard library only, importable on Python 3.9, with no connector Config: each caller passes
the values it trusts, and every adoption column must equal all of them.
"""
from contextlib import closing
from pathlib import Path
import re
import sqlite3

import codex_assets as assets

DIGEST = "[a-f0-9]{64}"
PENDING = ("; pending explicit revalidation: with the sandbox running, its relay held and no Codex service, "
           "run transition confirm, then confirm --apply")
BUILD = r"codex-cli ([0-9]+)\.([0-9]+)\.([0-9]+)(?:[-+][0-9A-Za-z.-]+)?"
BUILD_LINE = re.compile(rb'(?m)^[ \t]*(?:"codex_version"|codex_version)[ \t]*=[ \t]*"([^"\r\n]+)"[ \t]*(?:#[^\r\n]*)?$')


def build_number(value):
    match = re.fullmatch(BUILD, value) if isinstance(value, str) else None
    if match is None:
        raise ValueError("native Codex build is unavailable or malformed")
    return tuple(int(part) for part in match.groups())


def with_build(raw, version):
    """Replace only the one top-level build string; retain every other byte."""
    build_number(version)
    matches = list(BUILD_LINE.finditer(raw))
    if len(matches) != 1:
        raise ValueError("controller has no unique native build assignment")
    match = matches[0]
    if re.search(rb'(?m)^[ \t]*\[', raw[:match.start()]):
        raise ValueError("controller native build assignment is not top-level")
    build_number(match[1].decode())
    return raw[:match.start(1)] + version.encode() + raw[match.end(1):]


def runtime_record(state, record):
    """Read current build evidence without rewriting the original adoption receipt.

    A changed controller is accepted only when restoring the recorded build
    reproduces its exact confirmed bytes. All other edits still refuse.
    """
    raw = assets.regular(Path(state) / "controller.toml")
    digest = assets.digest(raw)
    if digest == record["target_sha256"]:
        return record
    matches = list(BUILD_LINE.finditer(raw))
    if len(matches) != 1:
        raise ValueError("current controller differs from the confirmed target")
    version = matches[0][1].decode()
    if (build_number(version) < build_number(record.get("codex_version"))
            or assets.digest(with_build(raw, record["codex_version"])) != record["target_sha256"]):
        raise ValueError("current controller differs from the confirmed target beyond an advancing Codex build")
    return {**record, "codex_version": version, "target_sha256": digest}


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
