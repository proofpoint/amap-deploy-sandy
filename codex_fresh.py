#!/usr/bin/env python3
"""Fresh fleet-unified birth, protected argv selection and owned service startup.

Fresh initialization is not adoption. Only the connector writes its real journal
and canonical binding; interrupted uncertain births hold without erasing history.
"""
import argparse
import asyncio
from contextlib import closing, contextmanager
import fcntl
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import time
import uuid

import codex_assets as assets
import codex_fleet as fleet
import codex_settings as settings

BIRTH = "fresh-birth.json"
PLAN = "fresh-plan.json"
INITIALIZATION = "fresh-initialization.json"
REQUEST = "fresh-startup.json"
SELECTION = "fresh-selection.json"
RECREATE = "HOLD: existing or uncertain Codex state requires operator recreation; retain it, do not erase or adopt automatically"


def native_runtime():
    if sys.version_info < (3, 11):
        raise ValueError("fresh unified execution requires Python 3.11 or newer")


def read_json(path):
    value = json.loads(assets.regular(path))
    if not isinstance(value, dict):
        raise ValueError("fresh evidence root is not an object")
    return value


def unpaused(state):
    if os.path.lexists(state / "adapter-pause.json"):
        raise ValueError("operator maintenance pause; fresh unified work remains held")


def publish(state, path, raw, **kwargs):
    unpaused(state)
    assets.place(path, raw, **kwargs)


def private_state(state):
    assets.directory(state)
    info = state.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("fresh state is not private and owned by the current user")


def identity(session, env):
    name, workspace = session.get("sandbox_name"), session.get("workspace")
    if (not isinstance(name, str) or not name or not isinstance(workspace, str)
            or not Path(workspace).is_absolute()):
        raise ValueError("fresh birth requires Sandy's instance and absolute workspace")
    if fleet.environment(env) != "unified":
        raise ValueError("fresh birth requires the explicit unified fleet choice")
    lanes = {}
    for key in ("AMAP_INBOX_DIR", "AMAP_OUTBOX_DIR", "AMAP_PEER_DIR"):
        value = env.get(key)
        if not isinstance(value, str) or not Path(value).is_absolute():
            raise ValueError("fresh birth requires explicit absolute lane mounts")
        lanes[key] = value
    return {"instance_id": name, "workspace": str(Path(workspace).resolve()),
            "fleet_mode": "unified", "lanes": lanes}


def birth(state, session, env):
    """An exclusive new directory is the fence; an unexplained directory holds."""
    native_runtime()
    state = Path(state)
    if not state.is_absolute():
        raise ValueError("fresh state must be an explicit absolute path")
    expected = identity(session, env)
    assets.directory(state.parent)
    unpaused(state)
    try:
        state.mkdir(mode=0o700)
    except FileExistsError:
        private_state(state)
        try:
            record = read_json(state / BIRTH)
        except (OSError, ValueError) as exc:
            raise ValueError(RECREATE) from exc
        if (record.get("schema") != 1 or type(record.get("schema")) is not int
                or record.get("kind") != "fresh_unified_birth" or record.get("identity") != expected
                or not isinstance(record.get("birth_id"), str)
                or not re.fullmatch("[a-f0-9]{32}", record["birth_id"])):
            raise ValueError(RECREATE + "; birth identity differs")
        return record
    assets.sync_directory(state.parent)
    record = {"schema": 1, "kind": "fresh_unified_birth", "birth_id": uuid.uuid4().hex,
              "identity": expected}
    publish(state, state / BIRTH, assets.encoded(record), mode=0o600)
    return record


@contextmanager
def locked(state, name):
    private_state(state)
    fd = os.open(state / name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077:
            raise ValueError("fresh lock is not a private regular file")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError("another fresh initialization or service owns this state") from exc
        yield
    finally:
        os.close(fd)


def native_config_digest(env):
    home = Path(env.get("CODEX_HOME") or str(Path(env["HOME"]) / ".codex"))
    path = home / "config.toml"
    try:
        return assets.digest(assets.regular(path))
    except FileNotFoundError:
        return None


def validator_digest():
    return assets.digest(assets.encoded({"settings": settings.validator_digest(),
                                       "fresh": assets.digest(Path(__file__).read_bytes())}))


def selected_assets(payload):
    selected = read_json(payload / assets.SELECTED_RECORD)
    version = selected.get("version")
    if not isinstance(version, str) or not re.fullmatch("[a-f0-9]{64}", version):
        raise ValueError("selected protected version is unknown")
    directory = payload / "protected" / version
    problems = assets.findings(payload, directory / assets.ASSETS[0], directory / assets.ASSETS[1])
    if problems:
        raise ValueError("; ".join(problems))
    return selected, directory


def controller_document(state, payload, context, selection):
    selected, protected = selected_assets(payload)
    doc = {"instance_id": context["instance_id"], "launch_argv": ["codex", "app-server", "--listen", "stdio://"],
           "state_dir": str(state), "codex_version": context["codex_version"], "cwd": context["workspace"],
           "sandbox": "danger-full-access", "approval_policy": "never", "conversation_mode": "unified",
           "unified_argv": ["codex"], "operator_kickoff_enabled": False,
           "operator_instructions": str(protected / assets.ASSETS[0]),
           "trusted_config_file": str(protected / assets.ASSETS[1]),
           "outcome_dir": str(Path(context["lanes"]["AMAP_OUTBOX_DIR"]) / "ext/codex/outcomes"), "lanes": {}}
    if context["self_address"]:
        doc["self_address"] = context["self_address"]
    if selection["selected_model"] is not None:
        doc["codex_model"] = selection["selected_model"]
    for lane, key in (("mail", "AMAP_INBOX_DIR"), ("peer", "AMAP_PEER_DIR")):
        if lane == "peer" and not context["self_address"]:
            continue
        root = Path(context["lanes"][key])
        doc["lanes"][lane] = {"notice_dir": str(root / "notices"), "message_dir": str(root / "messages"),
                              "claim_path": str(state / "claims" / (lane + ".amap-consumer.json"))}
    return doc, selected


def load_plan(state):
    private_state(state)
    unpaused(state)
    plan = read_json(state / PLAN)
    born = read_json(state / BIRTH)
    if (plan.get("schema") != 1 or type(plan.get("schema")) is not int
            or plan.get("kind") != "fresh_unified_plan" or plan.get("birth_id") != born.get("birth_id")
            or plan.get("identity") != born.get("identity") or born.get("kind") != "fresh_unified_birth"
            or type(born.get("schema")) is not int or born.get("schema") != 1
            or not isinstance(born.get("birth_id"), str) or not re.fullmatch("[a-f0-9]{32}", born["birth_id"])):
        raise ValueError("fresh plan does not belong to this birth")
    if assets.digest(assets.regular(state / "controller.toml")) != plan.get("controller_sha256"):
        raise ValueError("fresh controller changed; no automatic re-render")
    if os.path.lexists(state / "adapter-transition.json"):
        raise ValueError("fresh birth and adoption evidence cannot be combined")
    if plan.get("validator_sha256") != validator_digest():
        raise ValueError("protected fresh validator changed; retain the hold")
    if (not isinstance(plan.get("runtime_state_dir"), str)
            or not Path(plan["runtime_state_dir"]).is_absolute()):
        raise ValueError("fresh runtime state path is unknown")
    return plan


def config_at(state):
    from amap_codex.config import Config
    return Config.load(state / "controller.toml", create_state=False)


def initialization(state, plan):
    value = read_json(state / INITIALIZATION)
    if (value.get("schema") != 1 or type(value.get("schema")) is not int
            or value.get("kind") != "fresh_unified_initialization" or value.get("birth_id") != plan["birth_id"]
            or value.get("plan_sha256") != assets.digest(assets.encoded(plan))
            or value.get("phase") not in {"prepared", "start_attempted", "initialized"}
            or not isinstance(value.get("fingerprint"), str) or not re.fullmatch("[a-f0-9]{64}", value["fingerprint"])
            or type(value.get("poll_interval_ms")) is not int or value["poll_interval_ms"] <= 0):
        raise ValueError("fresh initialization evidence is unknown or foreign")
    return value


def prepare(state, payload, context, env):
    """Only equal known partial preparation resumes; no previous state is adopted."""
    native_runtime()
    state, payload = Path(state), Path(payload)
    unpaused(state)
    born = read_json(state / BIRTH)
    if born.get("identity") != {k: context[k] for k in ("instance_id", "workspace", "fleet_mode", "lanes")}:
        raise ValueError("fresh context differs from its exclusive birth")
    selection = settings.resolve(env)
    if selection["skip_permissions"] != "true":
        raise ValueError("fresh unified requires explicit SANDY_SKIP_PERMISSIONS=true")
    if len(os.fsencode(state / ("u-" + "0" * 32) / "b")) > 100:
        raise ValueError("private runtime path exceeds portable Unix socket length; use a shorter state directory")
    from codex_transition import toml_bytes
    doc, selected = controller_document(state, payload, context, selection)
    raw = toml_bytes(doc)
    plan = {"schema": 1, "kind": "fresh_unified_plan", "birth_id": born["birth_id"],
            "identity": born["identity"], "context": context, "selection": selection,
            "runtime_state_dir": doc["state_dir"],
            "controller_sha256": assets.digest(raw), "protected_assets": selected,
            "native_config_sha256": native_config_digest(env), "validator_sha256": validator_digest()}
    with locked(state, "fresh-init.lock"):
        if not os.path.lexists(state / PLAN):
            allowed = {BIRTH, "fresh-init.lock", "hold.json"}
            if set(p.name for p in state.iterdir()) - allowed:
                raise ValueError(RECREATE + "; unexplained files precede fresh preparation")
        elif read_json(state / PLAN) != plan:
            raise ValueError("fresh policy, settings, workspace or protected inputs changed; retain the hold")
        publish(state, state / PLAN, assets.encoded(plan), mode=0o600)
        (state / "claims").mkdir(mode=0o700, exist_ok=True)
        assets.directory(state / "claims")
        publish(state, state / "controller.toml", raw, mode=0o600)
        Path(doc["outcome_dir"]).parent.mkdir(parents=True, exist_ok=True)
        config = config_at(state)
        if not os.path.lexists(state / INITIALIZATION):
            allowed = {BIRTH, PLAN, "fresh-init.lock", "hold.json", "claims", "controller.toml"}
            if set(p.name for p in state.iterdir()) - allowed:
                raise ValueError(RECREATE + "; initialization receipt is missing beside runtime state")
            initial = {"schema": 1, "kind": "fresh_unified_initialization", "birth_id": born["birth_id"],
                       "plan_sha256": assets.digest(assets.encoded(plan)), "phase": "prepared",
                       "fingerprint": config.fingerprint(), "poll_interval_ms": config.poll_interval_ms}
            publish(state, state / INITIALIZATION, assets.encoded(initial), mode=0o600)
        initialization(state, plan)
    return plan


def request_for(plan, generation):
    if not isinstance(generation, str) or not re.fullmatch("[a-f0-9]{32}", generation):
        raise ValueError("fresh execution environment generation is unknown")
    return {"schema": 1, "scope": "fresh_canonical_argv_preselection", "birth_id": plan["birth_id"],
            "plan_sha256": assets.digest(assets.encoded(plan)), "controller_sha256": plan["controller_sha256"],
            "validator_sha256": plan["validator_sha256"], "entry_generation": generation,
            "selector": "owned_canonical_only"}


def current_guard(state, env):
    plan = load_plan(state)
    if fleet.environment(env) != "unified" or settings.resolve(env) != plan["selection"]:
        raise ValueError("fresh fleet model or permissions drifted")
    if native_config_digest(env) != plan["native_config_sha256"]:
        raise ValueError("fresh native configuration changed")
    selected, _ = selected_assets(Path(plan["context"]["payload"]))
    if selected != plan["protected_assets"]:
        raise ValueError("fresh protected version changed")
    config = config_at(state)
    if str(config.state_dir) != plan["runtime_state_dir"]:
        raise ValueError("fresh runtime state path differs from its controller")
    if initialization(state, plan).get("fingerprint") != config.fingerprint():
        raise ValueError("fresh protected configuration fingerprint changed")
    return plan, config


def binding(state, plan, config):
    path = state / "journal.sqlite3"
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077:
            raise ValueError("fresh journal is not a private regular file with one link")
    finally:
        os.close(fd)
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute("SELECT i.instance_id,i.thread_id,i.fingerprint,i.codex_version,b.policy_hash,b.effective_model "
                          "FROM instance i JOIN unified_binding b ON i.instance_id=b.instance_id AND i.thread_id=b.thread_id").fetchall()
    if len(rows) != 1:
        raise ValueError("real fresh canonical binding is unavailable")
    value = dict(rows[0])
    if (value["instance_id"] != config.instance_id or value["fingerprint"] != config.fingerprint()
            or value["codex_version"] != config.codex_version or not isinstance(value["thread_id"], str)
            or not isinstance(value["policy_hash"], str) or not re.fullmatch("[a-f0-9]{64}", value["policy_hash"])
            or not isinstance(value["effective_model"], str) or not value["effective_model"]
            or (config.codex_model is not None and value["effective_model"] != config.codex_model)):
        raise ValueError("real fresh canonical binding differs from the protected configuration")
    if str(uuid.UUID(value["thread_id"])) != value["thread_id"]:
        raise ValueError("fresh canonical is not an explicit native UUID")
    record = initialization(state, plan)
    if record["phase"] == "prepared":
        raise ValueError(RECREATE + "; journal exists before a recorded service attempt")
    if record["phase"] == "initialized" and record.get("binding") != value:
        raise ValueError("fresh initialized binding changed")
    return value


def selection_guard(state, env):
    plan, config = current_guard(state, env)
    expected = request_for(plan, settings.environment_generation())
    request = read_json(state / REQUEST)
    receipt = read_json(state / SELECTION)
    if request != expected or any(receipt.get(k) != v for k, v in expected.items()):
        raise ValueError("full native argv preselection is unknown or belongs to another environment")
    if (type(receipt.get("validated_at")) not in {int, float} or not math.isfinite(receipt["validated_at"])
            or receipt["validated_at"] <= 0 or not isinstance(receipt.get("argv"), list)
            or not receipt["argv"] or not all(isinstance(v, str) and "\x00" not in v for v in receipt["argv"])):
        raise ValueError("fresh native argv receipt is malformed")
    thread = selection_thread(state, plan, config)
    if settings.validate_native_argv(config, thread, receipt["argv"]) != receipt.get("argv_sha256"):
        raise ValueError("fresh native argv preselection digest differs")
    unpaused(state)
    return plan, config


def selection_thread(state, plan, config):
    """A committed core binding can authorize selection before adapter finalization."""
    record = initialization(state, plan)
    if (record["phase"] == "initialized"
            or record["phase"] == "start_attempted" and os.path.lexists(state / "journal.sqlite3")):
        return binding(state, plan, config)["thread_id"]
    if os.path.lexists(state / "journal.sqlite3"):
        raise ValueError(RECREATE + "; unexplained journal before first service start")
    return None


def publish_request(state, env):
    plan, _ = current_guard(state, env)
    request = request_for(plan, settings.environment_generation())
    with locked(state, "fresh-init.lock"):
        unpaused(state)
        publish(state, state / REQUEST, assets.encoded(request), replace=True, mode=0o600)
    return request


def select_pane(state, argv, env):
    plan, config = current_guard(state, env)
    expected = request_for(plan, settings.environment_generation())
    if read_json(state / REQUEST) != expected:
        raise ValueError("fresh native selection request is unavailable or foreign")
    thread = selection_thread(state, plan, config)
    receipt = {**expected, "argv": list(argv), "argv_sha256": settings.validate_native_argv(config, thread, argv),
               "validated_at": time.time()}
    with locked(state, "fresh-init.lock"):
        unpaused(state)
        publish(state, state / SELECTION, assets.encoded(receipt), replace=True, mode=0o600)
    return receipt


def finalize(state, plan, config):
    value = binding(state, plan, config)
    with locked(state, "fresh-init.lock"):
        unpaused(state)
        record = initialization(state, plan)
        record.update(phase="initialized", binding=value)
        publish(state, state / INITIALIZATION, assets.encoded(record), replace=True, mode=0o600)
    return value


def require_initialized(state, env):
    plan, config = selection_guard(state, env)
    if initialization(state, plan)["phase"] != "initialized":
        raise ValueError("fresh canonical initialization is pending; argv selection is not readiness")
    return plan, config, binding(state, plan, config)


def service_class():
    from amap_codex.unified import UnifiedService

    class FreshService(UnifiedService):
        async def start(self):
            plan, _ = selection_guard(self.config.state_dir, os.environ)
            state = self.config.state_dir
            with locked(state, "fresh-init.lock"):
                record = initialization(state, plan)
                if record["phase"] == "prepared":
                    if os.path.lexists(state / "journal.sqlite3"):
                        raise ValueError(RECREATE + "; unexplained journal before first service start")
                    record["phase"] = "start_attempted"
                    publish(state, state / INITIALIZATION, assets.encoded(record), replace=True, mode=0o600)
                elif record["phase"] == "start_attempted":
                    binding(state, plan, self.config)
            selection_guard(state, os.environ)
            await super().start()
            finalize(state, plan, self.config)
            selection_guard(state, os.environ)

        async def tick(self):
            try:
                require_initialized(self.config.state_dir, os.environ)
            except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
                self.gate.accepting = False
                try:
                    self.journal.operational_error("fresh startup evidence is held: " + str(exc))
                    self.write_status(False, None, None)
                except (OSError, ValueError, sqlite3.Error):
                    # Missing durable evidence leaves new attachment/dispatch held.
                    # Existing authorized native work still belongs to this backend.
                    pass
                return
            await super().tick()

    return FreshService


def evidence_problems(state, status, *, now=None):
    """Host-compatible read-only fresh proof; no connector import or invented adoption."""
    from codex_unified_status import evidence_problems as coherent_status
    state = Path(state)
    try:
        plan = load_plan(state)
        record = initialization(state, plan)
        if record["phase"] != "initialized":
            raise ValueError("fresh initialization is pending; preselection is not native readiness")
        bound = record.get("binding")
        if not isinstance(bound, dict):
            raise ValueError("fresh initialization carries no canonical binding")
        path = state / "journal.sqlite3"
        if path.is_symlink() or not path.is_file():
            raise ValueError("fresh journal is unavailable or a symlink")
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
            db.row_factory = sqlite3.Row
            row = db.execute("SELECT i.instance_id,i.thread_id,i.fingerprint,i.codex_version,b.policy_hash,b.effective_model "
                             "FROM instance i JOIN unified_binding b ON i.instance_id=b.instance_id AND i.thread_id=b.thread_id").fetchall()
        if len(row) != 1 or dict(row[0]) != bound or bound["fingerprint"] != record["fingerprint"]:
            raise ValueError("real canonical binding differs from fresh initialization")
        context = plan["context"]
        request = read_json(state / REQUEST)
        receipt = read_json(state / SELECTION)
        generation = request.get("entry_generation")
        if request != request_for(plan, generation) or any(receipt.get(k) != v for k, v in request.items()):
            raise ValueError("fresh full argv preselection is unknown or foreign")
        if (not isinstance(receipt.get("argv"), list) or not receipt["argv"]
                or not all(isinstance(v, str) for v in receipt["argv"])
                or receipt.get("argv_sha256") != assets.digest(assets.encoded(receipt["argv"]))
                or type(receipt.get("validated_at")) not in {int, float}
                or not math.isfinite(receipt["validated_at"]) or receipt["validated_at"] <= 0):
            raise ValueError("fresh full argv validation evidence is malformed")
        view = {"state_dir": plan["runtime_state_dir"], "instance_id": context["instance_id"], "thread": bound["thread_id"],
                "fingerprint": record["fingerprint"], "policy_hash": bound["policy_hash"],
                "poll_interval_ms": record["poll_interval_ms"], "codex_version": context["codex_version"],
                "codex_model": plan["selection"]["selected_model"], "sandbox": "danger-full-access",
                "approval_policy": "never"}
        descriptor = read_json(state / "unified.json")
        return coherent_status(status, descriptor, view, bound, now=time.time() if now is None else now)
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
        return ["fresh unified evidence unavailable: " + str(exc)]


def launch_pane(state, argv, env, *, wait=60):
    """Preselect once the entry is prepared; attach only after real readiness."""
    deadline = time.monotonic() + wait
    selected = False
    last = "fresh entry has not prepared the protected startup request"
    while time.monotonic() < deadline:
        unpaused(state)
        if os.path.lexists(state / PLAN) and os.path.lexists(state / REQUEST):
            if not selected:
                select_pane(state, argv, env)
                selected = True
            try:
                require_initialized(state, env)
                status = read_json(state / "status.json")
                problems = evidence_problems(state, status)
                if not problems:
                    break
                last = "; ".join(problems)
            except (OSError, ValueError, sqlite3.Error) as exc:
                last = str(exc)
        elif state.exists() and not os.path.lexists(state / BIRTH):
            raise ValueError(RECREATE)
        time.sleep(min(.1, max(0, deadline - time.monotonic())))
    else:
        raise ValueError("fresh canonical attachment remains held: " + last)
    result = subprocess.run(["python3", "-m", "amap_codex.cli", "--config", str(state / "controller.toml"),
                             "interactive-args", "--", *argv], capture_output=True, text=True,
                            timeout=max(1, deadline - time.monotonic()))
    if result.returncode:
        raise ValueError(result.stderr.strip() or "owned canonical attachment preparation failed")
    native = json.loads(result.stdout)
    _, config, _ = require_initialized(state, env)
    if (not isinstance(native, list) or not native or native[0] != config.unified_argv[0]
            or not all(isinstance(v, str) and "\x00" not in v for v in native)):
        raise ValueError("connector returned no valid canonical native argv")
    status = read_json(state / "status.json")
    problems = evidence_problems(state, status)
    if problems:
        raise ValueError("; ".join(problems))
    unpaused(state)
    os.execvp(native[0], native)


def hold(state, reason):
    print("codex fresh: holding: " + reason, file=sys.stderr, flush=True)
    if state.exists() and os.path.lexists(state / BIRTH):
        private_state(state)
        assets.place(state / "hold.json", assets.encoded({"reason": reason, "since": time.time()}),
                     replace=True, mode=0o600)


def relay(state, payload, context, env):
    while True:
        try:
            prepare(state, payload, context, env)
            publish_request(state, env)
            selection_guard(state, env)
            outcome = Path(context["lanes"]["AMAP_OUTBOX_DIR"]) / "ext/codex"
            outcome.mkdir(parents=True, exist_ok=True)
            if os.path.lexists(state / "hold.json"):
                (state / "hold.json").unlink()
            with locked(state, "fresh-service.lock"):
                _, config = selection_guard(state, env)
                asyncio.run(service_class()(config, state / "controller.toml").run())
                return
        except Exception as exc:
            hold(state, str(exc))
        time.sleep(1)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--payload", type=Path, default=Path(__file__).resolve().parent)
    commands = parser.add_subparsers(dest="command", required=True)
    born = commands.add_parser("birth")
    born.add_argument("--session", type=Path, required=True)
    entry = commands.add_parser("relay")
    entry.add_argument("--instance", required=True)
    entry.add_argument("--workspace", required=True)
    entry.add_argument("--address", default="")
    entry.add_argument("--version", required=True)
    pane = commands.add_parser("launch-pane")
    pane.add_argument("native_argv", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    try:
        native_runtime()
        if args.command == "birth":
            session = read_json(args.session)
            birth(args.state, session, os.environ)
        elif args.command == "relay":
            born = read_json(args.state / BIRTH)
            context = {**born["identity"], "self_address": args.address, "codex_version": args.version,
                       "payload": str(args.payload)}
            if (args.instance != context["instance_id"] or str(Path(args.workspace).resolve()) != context["workspace"]):
                raise ValueError("entry identity differs from the fresh birth")
            relay(args.state, args.payload, context, os.environ)
        else:
            native = args.native_argv[1:] if args.native_argv[:1] == ["--"] else args.native_argv
            raw_wait = os.environ.get("AMAP_CODEX_LAUNCH_WAIT_SECONDS", "60")
            wait = float(raw_wait)
            if not math.isfinite(wait) or not 0 < wait <= 3600:
                raise ValueError("fresh attachment wait must be finite, positive and at most 3600 seconds")
            launch_pane(args.state, native, os.environ, wait=wait)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, sqlite3.Error, subprocess.SubprocessError) as exc:
        print("codex fresh: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
