"""Read-only unified evidence checks, usable on the host without Codex imports."""
import json
from contextlib import closing
import math
from pathlib import Path
import re
import sqlite3
import time

import codex_assets as assets
import codex_fleet as fleet
import codex_settings as settings

REQUIRED = {"backend_live", "canonical_binding", "configuration_matches", "protected_tools",
            "native_reconciled", "publication_resolved"}
SANDBOX_TYPES = {"read-only": "readOnly", "workspace-write": "workspaceWrite",
                 "danger-full-access": "dangerFullAccess"}


def selection_note(state):
    try:
        if (Path(state) / "fresh-birth.json").exists():
            plan = json.loads(assets.regular(Path(state) / "fresh-plan.json"))
            source = {"CODEX_MODEL": "CODEX_MODEL", "native_config": "native config.toml",
                      "native_default": "native Codex default"}[plan["selection"]["model_source"]]
            return "recorded fresh entry model source is " + source + " (entry environment scope)"
        record = json.loads(assets.regular(Path(state) / "adapter-transition.json"))
        receipt = json.loads(assets.regular(Path(state) / settings.RECEIPT))
        if settings.evidence_problems(receipt, record):
            return None
        source = {"CODEX_MODEL": "CODEX_MODEL", "native_config": "native config.toml",
                  "native_default": "native Codex default"}[receipt["model_source"]]
        return "recorded entry model source is " + source + " (entry environment scope)"
    except (OSError, ValueError, KeyError, TypeError):
        return None


def number(value):
    return type(value) in {int, float} and math.isfinite(value)


def evidence_problems(status, descriptor, record, binding, *, now):
    """Unknown, stale and contradictory evidence always yields a named problem."""
    problems = []
    expected_bound = max(10, record["poll_interval_ms"] / 1000 * 3)
    for label, value in (("status", status), ("descriptor", descriptor)):
        if not isinstance(value, dict):
            problems.append(label + " is unavailable")
            continue
        if type(value.get("schema_version")) is not int or value.get("schema_version") != 1:
            problems.append(label + " schema_version is unknown")
        if (value.get("mode") != "unified" or value.get("instance_id") != record["instance_id"]
                or value.get("fingerprint") != record["fingerprint"]
                or value.get("codex_version") != record["codex_version"]):
            problems.append(label + " configuration or instance does not match")
        stamp = value.get("updated_at")
        if (not number(stamp) or not 0 <= now - stamp <= expected_bound
                or value.get("heartbeat_max_age_seconds") != expected_bound):
            problems.append(label + " fresh_heartbeat is unknown or stale")
        generation = value.get("backend_generation")
        if not isinstance(generation, str) or not re.fullmatch("[a-f0-9]{32}", generation):
            problems.append(label + " backend_generation is unknown")
        if (value.get("canonical_thread_id") != record["thread"]
                or value.get("thread_id") != record["thread"]):
            problems.append(label + " canonical_binding does not match")
        readiness = value.get("readiness")
        checks = readiness.get("checks") if isinstance(readiness, dict) else None
        if not isinstance(readiness, dict) or readiness.get("state") != "ready":
            problems.append(label + " readiness is holding or unknown")
        if not isinstance(checks, dict):
            problems.append(label + " readiness checks are unavailable")
        else:
            for name in sorted(REQUIRED | set(checks)):
                if checks.get(name) != "pass":
                    problems.append(label + " " + name + "=" + str(checks.get(name, "unknown")))
        effective = value.get("effective_settings")
        if not isinstance(effective, dict):
            problems.append(label + " effective_settings is unknown")
        elif (not isinstance(effective.get("model"), str) or not effective["model"]
                or (record["codex_model"] is not None and effective["model"] != record["codex_model"])
                or effective["model"] != binding["effective_model"]
                or effective.get("approval_policy") != record["approval_policy"]
                or not isinstance(effective.get("sandbox"), dict)
                or effective["sandbox"].get("type") != SANDBOX_TYPES.get(record["sandbox"])):
            problems.append(label + " effective model or permissions differ")
        if isinstance(effective, dict) and any(not isinstance(effective.get(k), str) or not effective[k]
                                               for k in ("model_source", "permission_source")):
            problems.append(label + " effective settings sources are unknown")
        validation = value.get("protected_tools_validation")
        if (not isinstance(validation, dict) or validation.get("scope") != "startup"
                or validation.get("backend_generation") != generation
                or not number(validation.get("validated_at")) or not number(stamp)
                or not 0 < validation["validated_at"] <= stamp):
            problems.append(label + " protected_tools startup validation is unknown or foreign")
        if value.get("scheduler_state") not in {"idle", "active"}:
            problems.append(label + " native scheduler is holding or unknown")
        if type(value.get("attached_client_count")) is not int or value["attached_client_count"] not in {0, 1}:
            problems.append(label + " attached_client_count is unknown")
        sources = value.get("queue_sources")
        depth = value.get("queue_depth")
        if (type(depth) is not int or depth < 0 or not isinstance(sources, dict)
                or set(sources) != {"operator", "mail", "peer"}
                or any(type(n) is not int or n < 0 for n in sources.values())
                or sum(sources.values()) != depth):
            problems.append(label + " queue facts are unknown or inconsistent")
        expected_endpoint = "unix://" + record["state_dir"] + "/u-" + str(generation) + "/t"
        if value.get("endpoint") != expected_endpoint:
            problems.append(label + " endpoint differs from the canonical generation")
    if isinstance(status, dict) and isinstance(descriptor, dict):
        for key in ("backend_generation", "canonical_thread_id", "fingerprint", "endpoint"):
            if status.get(key) != descriptor.get(key):
                problems.append("status and descriptor disagree on " + key)
    if (binding["thread_id"] != record["thread"] or binding["fingerprint"] != record["fingerprint"]
            or binding["policy_hash"] != record.get("policy_hash")):
        problems.append("durable canonical or protected policy binding differs")
    return problems


def problems(state, status, *, now=None):
    state = Path(state)
    if any(path.exists() or path.is_symlink() for path in fleet.fresh_markers(state)):
        import codex_fresh
        return codex_fresh.evidence_problems(state, status, now=now)
    try:
        assets.directory(state)
        if state.stat().st_mode & 0o077:
            raise ValueError("state directory is not private")
        record = json.loads(assets.regular(state / "adapter-transition.json"))
        if (not isinstance(record, dict) or type(record.get("schema")) is not int
                or record.get("schema") != 1 or record.get("state") != "confirmed"):
            raise ValueError("explicit adapter transition is not confirmed")
        if type(record.get("poll_interval_ms")) is not int or record["poll_interval_ms"] <= 0:
            raise ValueError("configured polling interval is unknown")
        if assets.digest(assets.regular(state / "controller.toml")) != record["target_sha256"]:
            raise ValueError("current controller differs from the confirmed target")
        if assets.digest(assets.regular(state / "adapter-previous.toml")) != record["previous_sha256"]:
            raise ValueError("retained previous controller differs")
        descriptor = json.loads(assets.regular(state / "unified.json"))
        entry_selection = json.loads(assets.regular(state / settings.RECEIPT))
        startup = json.loads(assets.regular(state / settings.STARTUP))
        pane_selection = json.loads(assets.regular(state / settings.PANE_SELECTION))
        journal = state / "journal.sqlite3"
        if journal.is_symlink() or not journal.is_file():
            raise ValueError("journal is unavailable or a symlink")
        with closing(sqlite3.connect(journal.as_uri() + "?mode=ro", uri=True)) as db:
            db.row_factory = sqlite3.Row
            row = db.execute("SELECT i.fingerprint,b.thread_id,b.policy_hash,b.effective_model "
                             "FROM instance i JOIN unified_binding b USING(instance_id) "
                             "WHERE i.instance_id=?", (record["instance_id"],)).fetchone()
        if row is None:
            raise ValueError("durable unified binding is unavailable")
        return (settings.evidence_problems(entry_selection, record)
                + settings.startup_problems(startup, pane_selection, record, entry_selection)
                + evidence_problems(status, descriptor, record, dict(row), now=time.time() if now is None else now))
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
        return ["unified evidence unavailable: " + str(exc)]
