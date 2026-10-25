#!/usr/bin/env python3
"""Prepare a stopped instance's explicit unified transition; never start it."""
import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import re
import sys

import codex_assets as assets

RECORD = "adapter-transition.json"
PREVIOUS = "adapter-previous.toml"
PAUSE = "adapter-pause.json"


def toml_bytes(doc):
    lines = []

    def table(value, prefix=()):
        if prefix:
            lines.append("[" + ".".join(json.dumps(k) for k in prefix) + "]")
        for key, item in value.items():
            if not isinstance(item, dict):
                lines.append(json.dumps(key) + " = " + json.dumps(item, allow_nan=False))
        for key, item in value.items():
            if isinstance(item, dict):
                table(item, prefix + (key,))

    table(doc)
    return ("\n".join(lines) + "\n").encode()


def read_record(state):
    value = json.loads(assets.regular(state / RECORD))
    if (not isinstance(value, dict) or type(value.get("schema")) is not int or value.get("schema") != 1
            or value.get("state") not in {"prepared", "confirmed"}
            or not isinstance(value.get("thread"), str)
            or not re.fullmatch(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}", value["thread"])):
        raise ValueError("invalid adapter transition record; retain it for inspection")
    for name in ("previous_sha256", "target_sha256", "fingerprint"):
        if not isinstance(value.get(name), str) or not re.fullmatch("[a-f0-9]{64}", value[name]):
            raise ValueError("invalid adapter transition " + name)
    return value


def config_at(state):
    from amap_codex.config import Config
    config = Config.load(state / "controller.toml", create_state=False)
    if config.state_dir != state:
        raise ValueError("configuration does not name this exact state directory")
    return config


def matching_status(config, *, fingerprint, thread=None):
    from amap_codex.cli import read_status
    status = read_status(config)
    if status.get("instance_id") != config.instance_id or status.get("fingerprint") != fingerprint:
        raise ValueError("retained journal does not match the selected configuration")
    if thread is not None and status.get("thread_id") != thread:
        raise ValueError("retained journal does not bind the selected canonical thread")
    return status


def confirmed_adoption(config, record):
    """Require the connector's committed adoption and matching policy binding."""
    import sqlite3
    from amap_codex.config import Config
    previous = Config.load(config.state_dir / PREVIOUS, create_state=False)
    path = config.state_dir / "journal.sqlite3"
    # Config/CLI enforce the same journal leaf rule. URI mode prevents creation.
    if path.is_symlink() or not path.is_file():
        raise ValueError("adoption journal must be an existing regular file")
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
        db.row_factory = sqlite3.Row
        try:
            adoption = db.execute("SELECT * FROM unified_adoptions WHERE singleton=1").fetchone()
            binding = db.execute("SELECT * FROM unified_binding WHERE instance_id=?", (config.instance_id,)).fetchone()
        except sqlite3.Error as exc:
            raise ValueError("confirmed native adoption evidence is unavailable") from exc
    if (adoption is None or binding is None or adoption["state"] != "confirmed"
            or adoption["thread_id"] != record["thread"] or binding["thread_id"] != record["thread"]
            or adoption["fingerprint"] != config.fingerprint()
            or adoption["previous_fingerprint"] != previous.fingerprint()
            or adoption["policy_hash"] != binding["policy_hash"]
            or not re.fullmatch("[a-f0-9]{64}", adoption["policy_hash"])
            or not re.fullmatch("[a-f0-9]{64}", adoption["history_sha256"])
            or (config.codex_model is not None and binding["effective_model"] != config.codex_model)):
        raise ValueError("native adoption, history or protected policy binding is not confirmed")
    return adoption["policy_hash"]


def prepare(state, payload, thread, *, apply=False):
    import tomllib
    from dataclasses import replace
    from amap_codex.config import Config
    from amap_codex.supervisor import Ownership
    if "conversation_mode" not in Config.__dataclass_fields__:
        raise ValueError("installed connector lacks unified configuration and explicit adoption support")
    try:
        from amap_codex.unified_maintenance import adopt  # capability gate; never invoked here
    except ImportError as exc:
        raise ValueError("installed connector lacks explicit native adoption support") from exc
    if not re.fullmatch(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}", thread):
        raise ValueError("select an explicit saved thread UUID; --last is not supported")
    assets.directory(state)
    assets.directory(payload)
    if len(os.fsencode(str(state / ("u-" + "0" * 32) / "b"))) > 100:
        raise ValueError("unified state directory exceeds the native Unix endpoint path bound")
    path = state / "controller.toml"
    current = assets.regular(path)
    if os.path.lexists(state / RECORD):
        record = read_record(state)
        if record["thread"] != thread or record["state"] != "prepared":
            raise ValueError("another or completed transition exists; retain it for inspection")
        previous = assets.regular(state / PREVIOUS)
        if assets.digest(previous) != record.get("previous_sha256"):
            raise ValueError("previous configuration snapshot differs")
    else:
        previous = current
        record = None
    doc = tomllib.loads(previous.decode())
    if doc.get("conversation_mode", "separate") != "separate" or doc.get("launcher_control_argv"):
        raise ValueError("transition requires the existing in-environment separate instance")
    selected = json.loads(assets.regular(payload / assets.SELECTED_RECORD))
    if not isinstance(selected, dict):
        raise ValueError("invalid installed protected asset selection")
    version = selected.get("version")
    if not isinstance(version, str) or not re.fullmatch("[a-f0-9]{64}", version):
        raise ValueError("invalid installed protected asset version")
    protected = payload / "protected" / version
    assets.directory(protected)
    if selected.get("schema") != 1 or set(selected.get("sha256", {})) != set(assets.ASSETS):
        raise ValueError("invalid installed protected asset hashes")
    for name in assets.ASSETS:
        if assets.digest(assets.regular(protected / name)) != selected["sha256"][name]:
            raise ValueError("installed protected asset differs: " + name)
    doc.update(conversation_mode="unified", unified_argv=["codex"], operator_kickoff_enabled=False,
               operator_instructions=str(protected / assets.ASSETS[0]),
               trusted_config_file=str(protected / assets.ASSETS[1]))
    target = toml_bytes(doc)
    config = (Config.load(state / PREVIOUS, create_state=False) if record is not None else config_at(state))
    candidate = replace(config, conversation_mode="unified", unified_argv=["codex"],
                        operator_kickoff_enabled=False, operator_instructions=protected / assets.ASSETS[0],
                        trusted_config_file=protected / assets.ASSETS[1])
    candidate.validate(create_state=False)
    planned = {"schema": 1, "state": "prepared", "thread": thread,
               "previous_sha256": assets.digest(previous), "target_sha256": assets.digest(target),
               "fingerprint": candidate.fingerprint(), "instance_id": candidate.instance_id,
               "codex_model": candidate.codex_model, "codex_version": candidate.codex_version,
               "sandbox": candidate.sandbox, "approval_policy": candidate.approval_policy,
               "state_dir": str(candidate.state_dir), "poll_interval_ms": candidate.poll_interval_ms}
    if record is not None and planned != record:
        raise ValueError("unfinished transition differs from the installed target assets")
    if current not in {previous, target}:
        raise ValueError("controller differs from both retained previous and planned target")
    if not apply:
        return {**planned, "apply": False, "next": "stop all native clients and service before --apply"}
    # Load the previous configuration at its preserved path. Only Config's
    # path-independent fingerprint is used; adoption uses the final path below.
    # The snapshot is immutable and durable before the gate or target changes.
    # Its original protected-file references remain unchanged.
    if config.state_dir != state:
        raise ValueError("previous configuration names a different state directory")
    with Ownership(config):
        if assets.regular(path) != current:
            raise ValueError("configuration changed while acquiring controller ownership")
        matching_status(config, fingerprint=config.fingerprint())
        assets.place(state / PREVIOUS, previous)
        assets.place(state / RECORD, assets.encoded(planned))
        if current != target:
            assets.place(path, target, replace=True)
    return {**planned, "apply": True, "next": "doctor, unified-adopt at controller.toml, then confirm"}


def confirm(state, *, apply=False):
    from amap_codex.supervisor import Ownership
    record = read_record(state)
    config = config_at(state)
    if (config.conversation_mode != "unified"
            or assets.digest(assets.regular(state / "controller.toml")) != record.get("target_sha256")
            or assets.digest(assets.regular(state / PREVIOUS)) != record.get("previous_sha256")):
        raise ValueError("transition target or retained previous configuration differs")
    if not apply:
        matching_status(config, fingerprint=config.fingerprint(), thread=record["thread"])
        confirmed_adoption(config, record)
        return {**record, "apply": False}
    with Ownership(config):
        matching_status(config, fingerprint=config.fingerprint(), thread=record["thread"])
        record["policy_hash"] = confirmed_adoption(config, record)
        record["state"] = "confirmed"
        raw = assets.encoded(record)
        if assets.regular(state / RECORD) != raw:
            assets.place(state / RECORD, raw, replace=True)
    return {**record, "apply": True}


def entry_mode(state, *, selected_model=None, observed_version=None):
    """Read-only gate, used before relay rendering and terminal attachment."""
    if not os.path.lexists(state / RECORD):
        path = state / "controller.toml"
        if os.path.lexists(path):
            import tomllib
            try:
                doc = tomllib.loads(assets.regular(path).decode())
            except (OSError, ValueError) as exc:
                raise ValueError("the supervisor has not written a regular controller configuration: " + str(exc)) from exc
            if doc.get("conversation_mode", "separate") != "separate":
                raise ValueError("unified configuration lacks explicit adapter transition confirmation")
        return "separate"
    record = read_record(state)
    if record["state"] != "confirmed":
        raise ValueError("explicit unified adoption is pending; retain controller and previous configuration")
    config = config_at(state)
    if (config.conversation_mode != "unified"
            or assets.digest(assets.regular(state / "controller.toml")) != record.get("target_sha256")):
        raise ValueError("confirmed target configuration differs; no automatic re-render")
    if selected_model is not None and config.codex_model != (selected_model or None):
        raise ValueError("native configuration model changed; explicit shared-settings transition required")
    if observed_version is not None and config.codex_version != observed_version:
        raise ValueError("native build changed; explicit configuration update required")
    matching_status(config, fingerprint=config.fingerprint(), thread=record["thread"])
    return "unified"


def pause(state, note, *, apply=False):
    if not note.strip() or len(note) > 500:
        raise ValueError("operator pause requires a note of 1 to 500 characters")
    config_at(state)
    record = {"schema": 1, "state": "paused", "note": note}
    if apply:
        assets.place(state / PAUSE, assets.encoded(record))
    return {**record, "apply": apply, "next": "operator stops service and native clients; pause itself stops nothing"}


def unpause(state, *, apply=False):
    from amap_codex.supervisor import Ownership
    mode = entry_mode(state)
    record = json.loads(assets.regular(state / PAUSE))
    if record.get("schema") != 1 or record.get("state") != "paused":
        raise ValueError("invalid operator pause record; retain for inspection")
    if apply:
        with Ownership(config_at(state)):
            entry_mode(state)
            os.unlink(state / PAUSE)
            assets.sync_directory(state)
    return {"apply": apply, "mode": mode, "next": "relay may resume after its pause check"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=Path("/opt/sandy/feature-state/amap/codex"))
    parser.add_argument("--payload", type=Path, default=Path(__file__).resolve().parent)
    commands = parser.add_subparsers(dest="command", required=True)
    preparation = commands.add_parser("prepare")
    preparation.add_argument("--thread", required=True)
    preparation.add_argument("--apply", action="store_true")
    confirmation = commands.add_parser("confirm")
    confirmation.add_argument("--apply", action="store_true")
    pausing = commands.add_parser("pause")
    pausing.add_argument("--note", required=True)
    pausing.add_argument("--apply", action="store_true")
    resuming = commands.add_parser("unpause")
    resuming.add_argument("--apply", action="store_true")
    entry = commands.add_parser("entry-mode")
    entry.add_argument("--model")
    entry.add_argument("--version")
    args = parser.parse_args(argv)
    sys.path.insert(0, str(args.payload / "src"))
    try:
        if args.command == "prepare":
            result = prepare(args.state, args.payload, args.thread, apply=args.apply)
        elif args.command == "confirm":
            result = confirm(args.state, apply=args.apply)
        elif args.command == "pause":
            result = pause(args.state, args.note, apply=args.apply)
        elif args.command == "unpause":
            result = unpause(args.state, apply=args.apply)
        else:
            print(entry_mode(args.state, selected_model=args.model, observed_version=args.version))
            return 0
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print("codex transition: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
