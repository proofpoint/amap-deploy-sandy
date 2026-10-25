"""Shared pane model selection and bounded entry-environment evidence.

Sandy forwards nonempty CODEX_MODEL to the container and its native Codex
command. Entry receipts describe that environment, not arbitrary later argv.
"""
import argparse
import json
import math
import os
from pathlib import Path
import sys
import time

import codex_assets as assets

RECEIPT = "entry-settings.json"
STARTUP = "pane-startup.json"
PANE_SELECTION = "pane-selection.json"


def environment_generation(proc=Path("/proc")):
    """Sandy's Linux execution lifetime, stable across entry-process retries."""
    import uuid
    try:
        boot = str(uuid.UUID((proc / "sys/kernel/random/boot_id").read_text().strip()))
        raw = (proc / "1/stat").read_text()
        start = raw[raw.rindex(")") + 2:].split()[19]
        namespace = (proc / "self/ns/pid").stat()
        if not start.isdigit():
            raise ValueError("missing PID1 start identity")
    except (OSError, ValueError, IndexError) as exc:
        raise ValueError("execution-environment identity unavailable; unified startup remains held") from exc
    return assets.digest(assets.encoded([boot, namespace.st_dev, namespace.st_ino, start]))[:32]


def validator_digest():
    return assets.digest(Path(__file__).read_bytes())


def resolve(env):
    explicit = env.get("CODEX_MODEL")
    if explicit:
        model, source = explicit, "CODEX_MODEL"
    else:
        import tomllib
        native_home = env.get("CODEX_HOME") or str(Path(env["HOME"]) / ".codex")
        path = Path(native_home) / "config.toml"
        try:
            with path.open("rb") as stream:
                raw = stream.read(assets.LIMIT + 1)
            if len(raw) > assets.LIMIT:
                raise ValueError("native model configuration exceeds read bound")
            doc = tomllib.loads(raw.decode())
        except FileNotFoundError:
            doc = {}
        except (OSError, ValueError) as exc:
            raise ValueError("native model configuration is unreadable or invalid") from exc
        model = doc.get("model")
        if model is not None and (not isinstance(model, str) or not model):
            raise ValueError("native model configuration does not name a nonempty model")
        source = "native_config" if model is not None else "native_default"
    if model is not None and any(char in model for char in "\r\n\x00"):
        raise ValueError("model selection must be single-line text")
    return {"selected_model": model, "model_source": source,
            "skip_permissions": env.get("SANDY_SKIP_PERMISSIONS")}


def require_unified_permissions(selection, config):
    if (selection["skip_permissions"] != "true"
            or (config.sandbox, config.approval_policy) != ("danger-full-access", "never")):
        raise ValueError("unified pane permissions are unknown or conflicting; require explicit "
                         "SANDY_SKIP_PERMISSIONS=true and the retained full-access/never profile")


def capture(state, instance_id, selection, *, generation=None):
    path = state / "controller.toml"
    fingerprint = assets.digest(assets.regular(path)) if os.path.lexists(path) else None
    receipt = {"schema": 1, "scope": "entry_environment", "instance_id": instance_id,
               "controller_sha256": fingerprint, "entry_generation": generation,
               "recorded_at": time.time(), **selection}
    assets.place(state / RECEIPT, assets.encoded(receipt), replace=True, mode=0o600)
    return receipt


def evidence_problems(receipt, record):
    if (not isinstance(receipt, dict) or type(receipt.get("schema")) is not int
            or receipt.get("schema") != 1 or receipt.get("scope") != "entry_environment"
            or receipt.get("instance_id") != record["instance_id"]
            or receipt.get("controller_sha256") != record["target_sha256"]
            or type(receipt.get("recorded_at")) not in {int, float}
            or not math.isfinite(receipt["recorded_at"]) or receipt["recorded_at"] <= 0):
        return ["entry model/permission evidence is unknown or for another controller"]
    problems = []
    if receipt.get("selected_model") != record["codex_model"]:
        problems.append("entry CODEX_MODEL/native model differs from the canonical configuration")
    if receipt.get("model_source") not in {"CODEX_MODEL", "native_config", "native_default"}:
        problems.append("entry model source is unknown")
    if receipt.get("skip_permissions") != "true":
        problems.append("entry SANDY_SKIP_PERMISSIONS is unknown or conflicts with the unified profile")
    return problems


def startup_request(state, config, thread, generation):
    import re
    if not isinstance(generation, str) or not re.fullmatch("[a-f0-9]{32}", generation):
        raise ValueError("entry generation is unknown")
    return {"schema": 1, "scope": "protected_wrapper_argv", "entry_generation": generation,
            "validator_sha256": validator_digest(),
            "instance_id": config.instance_id, "controller_sha256": assets.digest(assets.regular(state / "controller.toml")),
            "selected_model": config.codex_model, "sandbox": config.sandbox,
            "approval_policy": config.approval_policy, "thread": thread}


def startup_problems(request, receipt, record, entry):
    import re
    expected = {"schema": 1, "scope": "protected_wrapper_argv", "instance_id": record["instance_id"],
                "validator_sha256": validator_digest(),
                "controller_sha256": record["target_sha256"], "selected_model": record["codex_model"],
                "sandbox": record["sandbox"], "approval_policy": record["approval_policy"],
                "thread": record["thread"], "entry_generation": entry.get("entry_generation")}
    generation = expected["entry_generation"]
    if (not isinstance(generation, str) or not re.fullmatch("[a-f0-9]{32}", generation)
            or not isinstance(request, dict) or type(request.get("schema")) is not int
            or request != expected):
        return ["full native argv selection request is unknown or for another entry"]
    if (not isinstance(receipt, dict) or type(receipt.get("schema")) is not int
            or any(receipt.get(k) != v for k, v in expected.items())
            or not isinstance(receipt.get("argv_sha256"), str)
            or not re.fullmatch("[a-f0-9]{64}", receipt["argv_sha256"])
            or type(receipt.get("validated_at")) not in {int, float}
            or not math.isfinite(receipt["validated_at"]) or receipt["validated_at"] <= 0):
        return ["full native argv selection is unconfirmed or belongs to another entry"]
    return []


def validate_native_argv(config, thread, argv):
    """Validate an intentionally narrow startup subset without opening a backend."""
    from amap_codex.interactive import native_interactive_args
    executable, options, prompt, preflight, cwd, resume = native_interactive_args(argv, config.cwd)
    if executable != config.unified_argv[0] or preflight:
        raise ValueError("startup native executable/profile/configuration must match the protected backend")
    if Path(cwd).resolve() != Path(config.cwd).resolve():
        raise ValueError("startup native workspace differs")
    if resume and resume[0] != "--last" and resume[0].lower() != thread.lower():
        raise ValueError("startup resume selects another history")
    index, seen = 0, set()
    while index < len(options):
        token = options[index]
        if token in {"resume", "--no-daemon", "--no-alt-screen"} or (resume and index == resume[1]):
            index += 1
            continue
        if token == "--dangerously-bypass-approvals-and-sandbox":
            if (config.sandbox, config.approval_policy) != ("danger-full-access", "never"):
                raise ValueError("startup native full-access policy differs")
            seen.update({"sandbox", "approval"})
            index += 1
            continue
        name, equals, value = token.partition("=")
        if not token.startswith("--") and len(token) > 2 and token[:2] in {"-m", "-s", "-a", "-C", "-i"}:
            name, equals, value = token[:2], "=", token[2:].removeprefix("=")
        category = {"-m": "model", "--model": "model", "-s": "sandbox", "--sandbox": "sandbox",
                    "-a": "approval", "--ask-for-approval": "approval", "-C": "cwd", "--cd": "cwd",
                    "-i": "image", "--image": "image"}.get(name)
        if category is None:
            raise ValueError("unsupported native startup control")
        if not equals:
            index += 1
            value = options[index]
        if category in {"model", "sandbox", "approval"}:
            expected = {"model": config.codex_model, "sandbox": config.sandbox,
                        "approval": config.approval_policy}[category]
            if category in seen or expected is None or value != expected:
                raise ValueError("startup native model or permissions differ or repeat")
            seen.add(category)
        index += 1
    if not {"sandbox", "approval"} <= seen:
        raise ValueError("startup native argv must explicitly select sandbox and approval")
    if resolve(os.environ)["model_source"] == "CODEX_MODEL" and "model" not in seen:
        raise ValueError("startup native argv must carry the forwarded CODEX_MODEL")
    return assets.digest(assets.encoded(list(argv)))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path)
    parser.add_argument("--instance")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--generation")
    parser.add_argument("--environment-generation", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.environment_generation:
            print(environment_generation())
            return 0
        selection = resolve(os.environ)
        if args.apply:
            if args.state is None or not args.state.is_dir() or not args.instance:
                raise ValueError("entry capture requires an existing state directory and instance")
            assets.directory(args.state)
            capture(args.state, args.instance, selection, generation=args.generation)
        print(selection["selected_model"] or "")
        return 0
    except (OSError, ValueError, KeyError) as exc:
        print("codex settings: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
