#!/usr/bin/env python3
"""Prepare a stopped instance's explicit unified transition; never start it."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import time
import subprocess

import codex_adoption as adoptions
import codex_assets as assets
import codex_fleet as fleet
import codex_settings as settings

RECORD = "adapter-transition.json"
PREVIOUS = "adapter-previous.toml"
PAUSE = "adapter-pause.json"


def require_native_runtime():
    if sys.version_info < (3, 11):
        raise ValueError("unified transition operations require Python 3.11 or newer; retain the hold")


def configuration_mode(raw):
    """Project mode on the host; native Python validates the complete TOML."""
    if sys.version_info >= (3, 11):
        import tomllib
        return tomllib.loads(raw.decode()).get("conversation_mode", "separate")
    # The separate renderer emits one JSON-compatible value per bare key and
    # bare lane headers. Other TOML syntax needs the native runtime; it never
    # defaults an uninspectable document to separate mode.
    mode, section, seen = "separate", "", set()
    decoder = json.JSONDecoder()
    text = raw.decode().replace("\r\n", "\n")
    if any(ord(char) < 32 and char not in "\t\n" or char == "\x7f" for char in text):
        raise ValueError("noncanonical controller inspection requires Python 3.11 or newer")
    for line in text.split("\n"):
        line = line.strip(" \t")
        if not line or line.startswith("#"):
            continue
        if re.fullmatch(r"\[lanes\.[A-Za-z0-9_-]+\]", line):
            section = line
            continue
        assignment = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(.+)", line)
        if assignment is None:
            raise ValueError("noncanonical controller inspection requires Python 3.11 or newer")
        key, encoded = assignment.groups()
        identity = (section, key)
        if identity in seen:
            raise ValueError("duplicate controller key; retain the hold")
        seen.add(identity)
        value, end = decoder.raw_decode(encoded)
        if not (type(value) in {str, bool, int}
                or isinstance(value, list) and all(isinstance(item, str) for item in value)):
            raise ValueError("noncanonical controller inspection requires Python 3.11 or newer")
        tail = encoded[end:].strip(" \t")
        if tail and not tail.startswith("#"):
            raise ValueError("noncanonical controller inspection requires Python 3.11 or newer")
        if not section and key == "conversation_mode":
            mode = value
    return mode


def snapshot_current(state):
    """Retain exact controller bytes before a separate-mode entry re-renders."""
    path = state / "controller.toml"
    if not os.path.lexists(path):
        return None
    assets.directory(state)
    raw = assets.regular(path)
    snapshot = state / "controller-history" / (assets.digest(raw) + ".toml")
    assets.place(snapshot, raw, mode=0o600)
    return snapshot


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


def read_record(state, *, legacy=False):
    """The transition record. Only confirm's enrichment (`legacy=True`) accepts a record
    from before the expected previous fingerprint was recorded."""
    value = json.loads(assets.regular(state / RECORD))
    if (not isinstance(value, dict) or type(value.get("schema")) is not int or value.get("schema") != 1
            or value.get("state") not in {"prepared", "confirmed"}
            or not isinstance(value.get("thread"), str)
            or not re.fullmatch(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}", value["thread"])):
        raise ValueError("invalid adapter transition record; retain it for inspection")
    for name in ("previous_sha256", "target_sha256", "fingerprint"):
        if not isinstance(value.get(name), str) or not re.fullmatch("[a-f0-9]{64}", value[name]):
            raise ValueError("invalid adapter transition " + name)
    if "previous_fingerprint" not in value:
        if legacy:
            return value
        if value["state"] == "prepared":
            raise ValueError("prepared adapter transition records no expected previous fingerprint; it "
                             "needs operator inspection: transition confirm --apply completes it only if "
                             "its native adoption committed")
        raise ValueError("adapter transition records no expected previous fingerprint; pending explicit "
                         "revalidation: with the sandbox running, its relay held and no Codex service, "
                         "run transition confirm, then confirm --apply")
    if not isinstance(value["previous_fingerprint"], str) or not re.fullmatch("[a-f0-9]{64}", value["previous_fingerprint"]):
        raise ValueError("invalid adapter transition previous_fingerprint")
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
    """Require the connector's committed adoption and matching policy binding (codex_adoption,
    the rule host verify applies), plus the model this configuration selects."""
    from amap_codex.config import Config
    previous = Config.load(config.state_dir / PREVIOUS, create_state=False)
    binding, adoption = adoptions.evidence(config.state_dir / "journal.sqlite3", config.instance_id)
    found = ["durable unified binding is unavailable"] if binding is None else adoptions.problems(
        adoption, thread=(record["thread"], binding["thread_id"]),
        fingerprint=(config.fingerprint(), record["fingerprint"], binding["fingerprint"]),
        previous_fingerprint=(previous.fingerprint(), record.get("previous_fingerprint")),
        policy_hash=(binding["policy_hash"],))
    if not found and config.codex_model is not None and binding["effective_model"] != config.codex_model:
        found.append("durable binding names another model")
    if found:
        raise ValueError("native adoption, history or protected policy binding is not confirmed: " + "; ".join(found))
    return adoption["policy_hash"]


def prepare(state, payload, thread, *, apply=False, use_installed_codex_version=False):
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
    if os.path.lexists(state / "bootstrap-inputs.json"):
        from codex_bootstrap_pause import verify
        verify(state, previous)
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
    config = (Config.load(state / PREVIOUS, create_state=False) if record is not None else config_at(state))
    selection = settings.resolve(os.environ)
    settings.require_unified_permissions(selection, config)
    target_version = config.codex_version
    if use_installed_codex_version:
        # Only the target changes; the retained controller and journal still
        # identify the original configuration until native adoption commits.
        measured = subprocess.run(["codex", "--version"], check=True,
                                  capture_output=True, text=True, timeout=10)
        target_version = measured.stdout.strip()
        if not re.fullmatch(r"codex-cli [0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", target_version):
            raise ValueError("installed Codex version is unavailable or malformed; retain the pause")
        doc["codex_version"] = target_version
    if selection["selected_model"] is None:
        doc.pop("codex_model", None)
    else:
        doc["codex_model"] = selection["selected_model"]
    target = toml_bytes(doc)
    candidate = replace(config, conversation_mode="unified", unified_argv=["codex"],
                        codex_model=selection["selected_model"],
                        codex_version=target_version,
                        operator_kickoff_enabled=False, operator_instructions=protected / assets.ASSETS[0],
                        trusted_config_file=protected / assets.ASSETS[1])
    candidate.validate(create_state=False)
    planned = {"schema": 1, "state": "prepared", "thread": thread,
               "previous_sha256": assets.digest(previous), "target_sha256": assets.digest(target),
               "previous_fingerprint": config.fingerprint(),
               "fingerprint": candidate.fingerprint(), "instance_id": candidate.instance_id,
               "codex_model": candidate.codex_model, "codex_version": candidate.codex_version,
               "model_source": selection["model_source"],
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
        assets.place(state / PREVIOUS, previous, mode=0o600)
        # The expectation comes from the exact retained bytes, before the record names it.
        if (assets.regular(state / PREVIOUS) != previous
                or Config.load(state / PREVIOUS, create_state=False).fingerprint() != planned["previous_fingerprint"]):
            raise ValueError("retained previous configuration does not yield the recorded previous fingerprint")
        assets.place(state / RECORD, assets.encoded(planned), mode=0o600)
        if current != target:
            assets.place(path, target, replace=True, mode=0o600)
    return {**planned, "apply": True, "next": "doctor, unified-adopt at controller.toml, then confirm"}


# The record's settings fields, which prepare wrote from the target configuration.
SETTINGS = ("instance_id", "codex_model", "codex_version", "sandbox", "approval_policy", "poll_interval_ms")


def confirm(state, *, apply=False):
    """Confirm a prepared transition, or enrich a record from before the expected previous
    fingerprint was recorded.

    For a record already confirmed, --apply adds only previous_fingerprint; its state and policy
    hash must already agree. For a prepared record, --apply also sets state "confirmed" and writes
    the policy hash, as confirmation always has. Controller bytes and journal rows are unchanged,
    and nothing is started or adopted. Ownership refuses while a service holds the controller; it
    does not stop one, so an --apply repeated after the relay has started the service refuses."""
    from amap_codex.config import Config
    from amap_codex.supervisor import Ownership
    original = assets.regular(state / RECORD)
    record = read_record(state, legacy=True)
    config = config_at(state)

    def checked():
        if (config.conversation_mode != "unified"
                or config.fingerprint() != record["fingerprint"]
                or assets.digest(assets.regular(state / "controller.toml")) != record.get("target_sha256")
                or assets.digest(assets.regular(state / PREVIOUS)) != record.get("previous_sha256")):
            raise ValueError("transition target or retained previous configuration differs")
        if (any(record.get(name) != getattr(config, name) for name in SETTINGS)
                or record.get("state_dir") != str(config.state_dir)):
            raise ValueError("transition settings differ from the target configuration")
        derived = Config.load(state / PREVIOUS, create_state=False).fingerprint()
        if record.get("previous_fingerprint", derived) != derived:
            raise ValueError("recorded previous fingerprint differs from the retained previous configuration")
        candidate = {**record, "previous_fingerprint": derived}
        matching_status(config, fingerprint=record["fingerprint"], thread=record["thread"])
        policy_hash = confirmed_adoption(config, candidate)
        if record["state"] == "confirmed" and policy_hash != record.get("policy_hash"):
            raise ValueError("confirmed adoption policy binding differs; retain the transition for inspection")
        candidate.update(policy_hash=policy_hash, state="confirmed")
        return candidate

    if not apply:
        return {**checked(), "apply": False}
    with Ownership(config):
        if assets.regular(state / RECORD) != original:
            raise ValueError("adapter transition changed while acquiring controller ownership")
        candidate = checked()
        raw = assets.encoded(candidate)
        if assets.regular(state / RECORD) != original:
            raise ValueError("adapter transition changed during confirmation")
        if raw != original:
            assets.place(state / RECORD, raw, replace=True, mode=0o600)
    return {**candidate, "apply": True}


def entry_mode(state, *, selected_model=None, observed_version=None, check_pane_settings=False):
    """Read-only gate, used before relay rendering and terminal attachment."""
    if any(os.path.lexists(path) for path in fleet.fresh_markers(state, os.environ.get("AMAP_OUTBOX_DIR"))):
        raise ValueError("fresh unified state cannot enter the separate/adoption path; use the protected fresh launcher")
    if not os.path.lexists(state / RECORD):
        path = state / "controller.toml"
        if os.path.lexists(path):
            try:
                mode = configuration_mode(assets.regular(path))
            except (OSError, ValueError) as exc:
                raise ValueError("the supervisor has not written a regular controller configuration: " + str(exc)) from exc
            if mode != "separate":
                raise ValueError("unified configuration lacks explicit adapter transition confirmation")
        return "separate"
    require_native_runtime()
    record = read_record(state)
    if record["state"] != "confirmed":
        raise ValueError("explicit unified adoption is pending; retain controller and previous configuration")
    config = config_at(state)
    if (config.conversation_mode != "unified"
            or config.fingerprint() != record["fingerprint"]
            or assets.digest(assets.regular(state / "controller.toml")) != record.get("target_sha256")):
        raise ValueError("confirmed target configuration differs; no automatic re-render")
    if selected_model is not None and config.codex_model != (selected_model or None):
        raise ValueError("native configuration model changed; explicit shared-settings transition required")
    if observed_version is not None and config.codex_version != observed_version:
        raise ValueError("native build changed; explicit configuration update required")
    if check_pane_settings:
        selection = settings.resolve(os.environ)
        settings.require_unified_permissions(selection, config)
        if selection["selected_model"] != config.codex_model:
            raise ValueError("pane CODEX_MODEL/native model differs from the canonical configuration")
    matching_status(config, fingerprint=record["fingerprint"], thread=record["thread"])
    return "unified"


def startup_route(state, session_path):
    """Select an existing confirmed adoption without initializing or adopting it."""
    if not os.path.lexists(state / RECORD):
        return "fresh"
    if entry_mode(state, check_pane_settings=True) != "unified":
        raise ValueError("existing adapter transition is not confirmed unified state")
    session = json.loads(assets.regular(session_path))
    config = config_at(state)
    record = read_record(state)
    if confirmed_adoption(config, record) != record.get("policy_hash"):
        raise ValueError("confirmed adoption policy binding differs")
    if (not isinstance(session, dict) or not isinstance(session.get("workspace"), str)
            or not Path(session["workspace"]).is_absolute()
            or session.get("sandbox_name") != config.instance_id
            or Path(session["workspace"]).resolve() != Path(config.cwd).resolve()):
        raise ValueError("confirmed adoption belongs to another Sandy instance or workspace")
    for lane in config.lanes:
        export = {"mail": "AMAP_INBOX_DIR", "peer": "AMAP_PEER_DIR"}.get(lane.name)
        root = os.environ.get(export) if export else None
        if (not isinstance(root, str) or not Path(root).is_absolute()
                or lane.notice_dir != Path(root) / "notices"
                or lane.message_dir != Path(root) / "messages"):
            raise ValueError("confirmed adoption delivery lanes differ from Sandy's mounts")
    return "adopted"


def pause(state, note, *, apply=False):
    if not note.strip() or len(note) > 500:
        raise ValueError("operator pause requires a note of 1 to 500 characters")
    config_at(state)
    record = {"schema": 1, "state": "paused", "note": note}
    if apply:
        assets.place(state / PAUSE, assets.encoded(record), mode=0o600)
    return {**record, "apply": apply, "next": "operator stops service and native clients; pause itself stops nothing"}


def unpause(state, *, apply=False):
    if os.path.lexists(state / "fresh-birth.json"):
        import codex_fresh
        return codex_fresh.unpause(state, apply=apply)
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


def startup_gate(state, generation, *, apply=False):
    entry_mode(state, check_pane_settings=True)
    if generation != settings.environment_generation():
        raise ValueError("execution-environment generation differs; fresh native selection required")
    config = config_at(state)
    record = read_record(state)
    request = settings.startup_request(state, config, record["thread"], generation)
    if apply:
        assets.place(state / settings.STARTUP, assets.encoded(request), replace=True, mode=0o600)
    try:
        saved = json.loads(assets.regular(state / settings.STARTUP))
        receipt = json.loads(assets.regular(state / settings.PANE_SELECTION))
        entry = json.loads(assets.regular(state / settings.RECEIPT))
    except (OSError, ValueError) as exc:
        raise ValueError("full native argv selection is pending; incoming service remains stopped") from exc
    problems = settings.startup_problems(saved, receipt, record, entry)
    problems += settings.evidence_problems(entry, record)
    if saved != request or problems:
        raise ValueError("; ".join(problems) or "native selection request differs")
    return {"selected": True, "entry_generation": generation}


def select_pane(state, argv, *, apply=False):
    if os.path.lexists(state / PAUSE):
        raise ValueError("operator maintenance pause; native selection refused")
    entry_mode(state, check_pane_settings=True)
    config = config_at(state)
    record = read_record(state)
    request = json.loads(assets.regular(state / settings.STARTUP))
    entry = json.loads(assets.regular(state / settings.RECEIPT))
    if settings.evidence_problems(entry, record):
        raise ValueError("entry selection evidence differs from the canonical configuration")
    if not isinstance(request, dict) or request != settings.startup_request(state, config, record["thread"], entry.get("entry_generation")):
        raise ValueError("native selection challenge differs from the canonical configuration")
    if request["entry_generation"] != settings.environment_generation():
        raise ValueError("native selection challenge belongs to another execution environment")
    receipt = {**request, "argv_sha256": settings.validate_native_argv(config, record["thread"], argv),
               "validated_at": time.time()}
    if apply:
        if os.path.lexists(state / PAUSE):
            raise ValueError("operator maintenance pause; native selection refused")
        assets.place(state / settings.PANE_SELECTION, assets.encoded(receipt), replace=True, mode=0o600)
    return receipt


def launch_pane(state, argv):
    select_pane(state, argv, apply=True)
    result = subprocess.run(["python3", "-m", "amap_codex.cli", "--config", str(state / "controller.toml"),
                             "interactive-args", "--", *argv], capture_output=True, text=True, timeout=35)
    if result.returncode:
        raise ValueError(result.stderr.strip() or "connector attachment preparation failed")
    selected = json.loads(result.stdout)
    if (not isinstance(selected, list) or not selected or not all(isinstance(a, str) and "\x00" not in a for a in selected)
            or selected[0] != config_at(state).unified_argv[0]):
        raise ValueError("connector returned no valid native argument vector")
    entry_mode(state, check_pane_settings=True)
    if os.path.lexists(state / PAUSE):
        raise ValueError("operator maintenance pause after attachment wait; not starting Codex")
    os.execvp(selected[0], selected)


def selection_ready(state):
    entry_mode(state, check_pane_settings=True)
    config = config_at(state)
    record = read_record(state)
    request = json.loads(assets.regular(state / settings.STARTUP))
    expected = settings.startup_request(state, config, record["thread"], settings.environment_generation())
    if request != expected or os.path.lexists(state / PAUSE):
        raise ValueError("native selection request is not current or the operator pause remains")
    return {"selection_ready": True, "scope": "startup selection, not backend readiness"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=Path("/opt/sandy/feature-state/amap/codex"))
    parser.add_argument("--payload", type=Path, default=Path(__file__).resolve().parent)
    commands = parser.add_subparsers(dest="command", required=True)
    preparation = commands.add_parser("prepare")
    preparation.add_argument("--thread", required=True)
    preparation.add_argument("--use-installed-codex-version", action="store_true",
                             help="explicitly select the measured installed Codex build for the adoption target")
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
    entry.add_argument("--check-pane-settings", action="store_true")
    route = commands.add_parser("startup-route")
    route.add_argument("--session", type=Path, required=True)
    startup = commands.add_parser("startup-gate")
    startup.add_argument("--generation", required=True)
    startup.add_argument("--apply", action="store_true")
    pane = commands.add_parser("select-pane")
    pane.add_argument("--apply", action="store_true")
    pane.add_argument("native_argv", nargs=argparse.REMAINDER)
    launch = commands.add_parser("launch-pane")
    launch.add_argument("native_argv", nargs=argparse.REMAINDER)
    commands.add_parser("selection-ready")
    args = parser.parse_args(argv)
    sys.path.insert(0, str(args.payload / "src"))
    try:
        if args.command != "entry-mode":
            require_native_runtime()
        if args.command == "prepare":
            result = prepare(args.state, args.payload, args.thread, apply=args.apply,
                             use_installed_codex_version=args.use_installed_codex_version)
        elif args.command == "confirm":
            result = confirm(args.state, apply=args.apply)
        elif args.command == "pause":
            result = pause(args.state, args.note, apply=args.apply)
        elif args.command == "unpause":
            result = unpause(args.state, apply=args.apply)
        elif args.command == "startup-route":
            print(startup_route(args.state, args.session))
            return 0
        elif args.command == "startup-gate":
            result = startup_gate(args.state, args.generation, apply=args.apply)
        elif args.command == "selection-ready":
            result = selection_ready(args.state)
        elif args.command in {"select-pane", "launch-pane"}:
            if len(args.native_argv) < 2 or args.native_argv[0] != "--":
                raise ValueError("native argv must follow -- and include the executable")
            if args.command == "launch-pane":
                launch_pane(args.state, args.native_argv[1:])
                return 0
            result = select_pane(args.state, args.native_argv[1:], apply=args.apply)
        else:
            print(entry_mode(args.state, selected_model=args.model, observed_version=args.version,
                             check_pane_settings=args.check_pane_settings))
            return 0
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print("codex transition: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
