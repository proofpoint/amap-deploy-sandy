"""The sandy adapter's client for the host registry's registration interface.

The host registry is the host's single registry writer, a separate program
this repository neither ships nor names. Its identifiers (the interface
token, the CLI module, the operator-verb module, the name.json schema id)
are not written here: they come from the deployment overlay, a private JSON
file the operator names (`load_identifiers`). This module never imports the
registry: it runs `python -m <module> --registry DIR` from the registry's
checkout, writes one JSON request to its stdin, and reads one JSON line from
its stdout. The interface token is checked by membership, never parsed.

Every answer is classified into exactly one outcome:

- REGISTERED: the binding exists and name.json was delivered.
- UNDELIVERED: the binding IS committed, but name.json was not delivered
  (`committed: true`, for example `instances_dir_absent`). Registering again
  is idempotent and redelivers, so the next install completes it.
- UNKNOWN: nobody can say whether the binding was committed. That covers
  the registry's `internal` (exit 3, `committed: "unknown"`), output that is not
  exactly one JSON object, and a process that could not be run. It is
  retried, because `register` is idempotent, and it is never reported as a
  failure to register.
- REFUSED: the registry refused, and nothing was written. `bad_request` here
  is this module's defect, not the operator's.

Absences keep their own codes (`config_absent`, `registry_absent`,
`instances_dir_absent`), so a caller can tell "not registered yet" from a
misconfiguration.
"""

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

ADAPTER = "sandy"

OP_VERSION = "version"
OP_REGISTER = "register"
OP_SHOW = "show"
OP_LIST = "list"

# The registry's exit statuses.
EXIT_OK, EXIT_REFUSED, EXIT_BAD_REQUEST, EXIT_INTERNAL = 0, 1, 2, 3

# The registry's codes this client branches on. Every other code is carried
# through verbatim as a refusal.
CODE_INTERNAL = "internal"
CODE_BAD_REQUEST = "bad_request"
CODE_INTERFACE = "interface"
CODE_NOT_FOUND = "not_found"
CODE_REGISTRY_ABSENT = "registry_absent"
CODE_CONFIG_ABSENT = "config_absent"
CODE_INSTANCES_DIR_ABSENT = "instances_dir_absent"
COMMITTED_UNKNOWN = "unknown"

# name.json delivery states that `show` reports.
NAME_JSON_CURRENT = "current"
NAME_JSON_STATES = ("current", "stale", "absent", "unreadable")

REGISTERED = "registered"
UNDELIVERED = "undelivered"
UNKNOWN = "unknown"
REFUSED = "refused"

# This client's own codes, for answers that are not the registry's.
CODE_NO_ANSWER = "no_answer"           # not exactly one JSON object on stdout
CODE_NOT_RUN = "not_run"               # the process could not be started, or timed out

RETRIES = 3                            # attempts at an UNKNOWN register, in all
RETRY_DELAY_S = 1.0
TIMEOUT_S = 60.0


# The deployment overlay: where it is, and its registry section.
OVERLAY_ENV = "AMAP_DEPLOY_OVERLAY"
OVERLAY_SECTION = "registry"
CHECKOUT_ENV = "AMAP_REGISTRY_REPO"


class OverlayError(Exception):
    """The overlay is absent, unreadable, or lacks a registry identifier."""


@dataclass(frozen=True)
class Identifiers:
    """The registry's names, from the overlay. Opaque: compared, never parsed."""
    interface: str          # the adapter interface token
    module: str             # the CLI, run as `python -m <module>`
    operator_module: str    # the operator verbs, run the same way
    name_schema: str        # name.json's `schema`
    checkout: Optional[str] = None   # the registry checkout, when the overlay names one
    directory: Optional[str] = None  # the registry's directory, when the overlay names one


IDENTIFIER_KEYS = ("interface", "module", "operator_module", "name_schema")


def overlay_path(override: Optional[Path] = None) -> Optional[Path]:
    if override is not None:
        return Path(override)
    env = os.environ.get(OVERLAY_ENV)
    return Path(env) if env else None


def load_identifiers(path: Optional[Path]) -> Identifiers:
    """The registry section of the overlay at `path`. Every identifier must
    be a non-empty string without whitespace; anything else refuses, by
    name, rather than letting a registry verb run under a guessed name."""
    if path is None:
        raise OverlayError(f"no deployment overlay: pass --overlay, or set ${OVERLAY_ENV}")
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise OverlayError(f"deployment overlay {path} is unreadable: {e}") from None
    sec = doc.get(OVERLAY_SECTION) if isinstance(doc, dict) else None
    if not isinstance(sec, dict):
        raise OverlayError(f"deployment overlay {path} has no {OVERLAY_SECTION!r} object")
    vals = {}
    for k in IDENTIFIER_KEYS:
        v = sec.get(k)
        if not isinstance(v, str) or not v or any(c.isspace() for c in v):
            raise OverlayError(f"deployment overlay {path}: {OVERLAY_SECTION}.{k} is not a "
                               f"non-empty token")
        vals[k] = v
    paths = {}
    for k in ("checkout", "directory"):
        v = sec.get(k)
        if v is not None and (not isinstance(v, str) or not os.path.isabs(v)):
            raise OverlayError(f"deployment overlay {path}: {OVERLAY_SECTION}.{k} is not an "
                               f"absolute path")
        paths[k] = v
    return Identifiers(**paths, **vals)


@dataclass(frozen=True)
class Answer:
    """One CLI exchange: the exit status and the parsed response, or the
    reason there is none."""
    rc: Optional[int]
    doc: Optional[Dict[str, Any]]
    why: str = ""


@dataclass(frozen=True)
class Result:
    outcome: str
    code: Optional[str] = None
    detail: str = ""
    binding: Optional[Dict[str, Any]] = None
    attempts: int = 1
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def created(self) -> Optional[bool]:
        return None if self.binding is None else self.binding.get("created")


Runner = Callable[[Sequence[str], str, Dict[str, str], str, float],
                  Tuple[Optional[int], str, str]]


def _subprocess_runner(argv: Sequence[str], stdin: str, env: Dict[str, str], cwd: str,
                       timeout: float) -> Tuple[Optional[int], str, str]:
    p = subprocess.run(list(argv), input=stdin, capture_output=True, text=True,
                       env=env, cwd=cwd, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def registry_checkout(ids: Identifiers, override: Optional[Path] = None) -> Optional[Path]:
    """The registry checkout: `override`, else `$AMAP_REGISTRY_REPO`, else
    the overlay's `checkout`. None when none of them holds the CLI module."""
    env = os.environ.get(CHECKOUT_ENV)
    for c in (override, Path(env) if env else None,
              Path(ids.checkout) if ids.checkout else None):
        if c is not None and (Path(c).absolute() / ids.module / "cli.py").is_file():
            return Path(c).absolute()
    return None


class Client:
    """One registry, one checkout. `runner` is injected by tests; production
    uses subprocess."""

    def __init__(self, registry_dir: Path, host_repo: Path, ids: Identifiers, *,
                 python: str = sys.executable, runner: Optional[Runner] = None,
                 sleep: Callable[[float], None] = time.sleep,
                 timeout: float = TIMEOUT_S):
        self.registry_dir = Path(registry_dir)
        self.host_repo = Path(host_repo)
        self.ids = ids
        self.python = python
        self.runner = runner or _subprocess_runner
        self.sleep = sleep
        self.timeout = timeout

    # The exchange --------------------------------------------------------

    def call(self, request: Dict[str, Any]) -> Answer:
        argv = [self.python, "-m", self.ids.module, "--registry", str(self.registry_dir.absolute())]
        # `-m` puts the working directory first on sys.path, so the child runs
        # FROM the pinned checkout: the package is found there and nowhere
        # else. No inherited PYTHONPATH, and no user site.
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONNOUSERSITE": "1"}
        try:
            rc, out, err = self.runner(argv, json.dumps(request), env, str(self.host_repo),
                                       self.timeout)
        except (OSError, subprocess.SubprocessError) as e:
            return Answer(None, None, f"{CODE_NOT_RUN}: {type(e).__name__}: {e}")
        lines = [ln for ln in out.splitlines() if ln.strip()]
        if len(lines) != 1:
            tail = (err or "").strip().splitlines()[-1:] or [""]
            return Answer(rc, None, f"{CODE_NO_ANSWER}: {len(lines)} line(s) on stdout; "
                                    f"stderr: {tail[0][:200]}")
        try:
            doc = json.loads(lines[0])
        except ValueError as e:
            return Answer(rc, None, f"{CODE_NO_ANSWER}: stdout is not JSON: {e}")
        if not isinstance(doc, dict) or not isinstance(doc.get("ok"), bool):
            return Answer(rc, None, f"{CODE_NO_ANSWER}: the response has no boolean ok")
        return Answer(rc, doc)

    # Ops -----------------------------------------------------------------

    def supports_interface(self) -> Tuple[Optional[bool], str]:
        """Whether this registry speaks the overlay's interface, by membership in what
        `version` lists. None, with the reason, when it could not be asked."""
        a = self.call({"op": OP_VERSION})
        toks = a.doc.get("interfaces") if a.doc is not None else None
        if a.doc is None or not a.doc["ok"] or not isinstance(toks, list):
            return None, a.why or "version answered without an interface list"
        return self.ids.interface in toks, ", ".join(str(t) for t in toks)

    def register(self, workspace: str) -> Result:
        """Register a sandy workspace, by its host path as sandy reports it.
        The registry normalises the key. Retries an UNKNOWN outcome, since
        registration is idempotent."""
        req = {"interface": self.ids.interface, "op": OP_REGISTER, "adapter": ADAPTER, "key": workspace}
        result = Result(UNKNOWN, CODE_NO_ANSWER, "not attempted", attempts=0)
        for attempt in range(1, RETRIES + 1):
            result = _classify_register(self.call(req), attempt)
            if result.outcome != UNKNOWN:
                return result
            if attempt < RETRIES:
                self.sleep(RETRY_DELAY_S * attempt)
        return result

    def show(self, workspace: str) -> Result:
        """One binding by workspace path, with its name.json status. Read-only."""
        a = self.call({"interface": self.ids.interface, "op": OP_SHOW, "adapter": ADAPTER, "key": workspace})
        if a.doc is None:
            return Result(UNKNOWN, CODE_NO_ANSWER, a.why)
        if a.doc["ok"] and isinstance(a.doc.get("binding"), dict):
            return Result(REGISTERED, binding=a.doc["binding"])
        return _refusal(a)

    def list(self) -> Result:
        """Every binding. Before the first registration this is a REFUSED
        `registry_absent`, never an empty list."""
        a = self.call({"interface": self.ids.interface, "op": OP_LIST})
        if a.doc is None:
            return Result(UNKNOWN, CODE_NO_ANSWER, a.why)
        if a.doc["ok"] and isinstance(a.doc.get("bindings"), list):
            return Result(REGISTERED, extra={"bindings": a.doc["bindings"]})
        return _refusal(a)


def _error(doc: Dict[str, Any]) -> Tuple[Optional[str], str]:
    err = doc.get("error")
    if isinstance(err, dict):
        return err.get("code"), str(err.get("detail", ""))
    return None, ""


def _refusal(a: Answer) -> Result:
    code, detail = _error(a.doc or {})
    if code == CODE_INTERNAL or a.rc == EXIT_INTERNAL:
        return Result(UNKNOWN, code or CODE_INTERNAL, detail)
    return Result(REFUSED, code, detail)


def _classify_register(a: Answer, attempt: int) -> Result:
    if a.doc is None:
        return Result(UNKNOWN, CODE_NO_ANSWER, a.why, attempts=attempt)
    doc = a.doc
    binding = doc.get("binding") if isinstance(doc.get("binding"), dict) else None
    if doc["ok"]:
        if binding is None or a.rc != EXIT_OK:
            return Result(UNKNOWN, CODE_NO_ANSWER, "ok without a binding, or with a non-zero exit",
                          attempts=attempt)
        return Result(REGISTERED, binding=binding, attempts=attempt)
    code, detail = _error(doc)
    committed = doc.get("committed")
    if committed is True and binding is not None:
        return Result(UNDELIVERED, code, detail, binding=binding, attempts=attempt)
    if committed == COMMITTED_UNKNOWN or code == CODE_INTERNAL or a.rc == EXIT_INTERNAL:
        return Result(UNKNOWN, code or CODE_INTERNAL, detail, attempts=attempt)
    return Result(REFUSED, code, detail, attempts=attempt)


def address_domain(binding: Dict[str, Any]) -> Optional[str]:
    """The domain part of a binding's address, or None."""
    addr = binding.get("address")
    if not isinstance(addr, str) or addr.count("@") != 1:
        return None
    return addr.rpartition("@")[2] or None


def domain_mismatch(binding: Dict[str, Any], fleet_domain: Optional[str]) -> Optional[str]:
    """A sentence when the registry addresses this binding under a domain
    other than the fleet policy's, else None. The policy is the source; the
    registry's host.json is its copy of it."""
    have = address_domain(binding)
    if fleet_domain is None or have == fleet_domain:
        return None
    return (f"the registry addresses {binding.get('name')!r} at {have!r}, but the fleet "
            f"policy's domain is {fleet_domain!r}")


# The migration: today's slugs imported as already-bound names. The import is
# a registry OPERATOR verb, so this module only prepares it: it writes the
# batch and prints the commands, and the operator runs them.
OPERATOR_PLACEHOLDER = "<you>"
CONFIRM_PLACEHOLDER = "<confirm code from plan>"


def import_items(members: Dict[str, Path]) -> List[Dict[str, str]]:
    """The import batch for `{slug: workspace path}`: one sandy item per
    slug, the workspace as sandy reports it (the registry normalises it, exactly
    as `register` does), sorted by slug so a re-run writes the same bytes."""
    return [{"adapter": ADAPTER, "key": str(members[slug]), "slug": slug}
            for slug in sorted(members)]


def import_batch_text(members: Dict[str, Path]) -> str:
    return json.dumps(import_items(members), indent=2) + "\n"


def import_commands(host_repo: Path, registry_dir: Path, batch: Path, ids: Identifiers,
                    python: str = "python3") -> Tuple[str, str]:
    """The two commands the operator runs, from the registry checkout:
    `plan` prints the change and a confirmation code; `apply` takes that code
    and the operator's name and reason, which the journal records."""
    import shlex
    q = shlex.quote
    base = (f"cd {q(str(host_repo))} && {python} -m {ids.operator_module} "
            f"--registry {q(str(Path(registry_dir).absolute()))}")
    plan = f"{base} plan import --batch {q(str(Path(batch).absolute()))}"
    apply_ = (f"{base} apply import --batch {q(str(Path(batch).absolute()))} "
              f"--confirm '{CONFIRM_PLACEHOLDER}' --operator '{OPERATOR_PLACEHOLDER}' "
              f"--reason 'import existing sandy slugs as their names'")
    return plan, apply_
