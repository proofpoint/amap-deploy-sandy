"""router_health.py — the ROUTER PROCESS, read and asserted, for `verify`.

Two sections: `router-container` (docker: running, no network, restart
policy, the exact mount set, the router's own view of the fleet) and
`router-health` (`status`: polls, freshness, the discovered instance set,
every instance first-seen, the discovery report, no errors). `amap-sandy.py
verify` runs both after its per-sandbox checks, and `verify --host-facts
PATH` writes them as the schema-2 document amap-router-local's operator
console keys on by those two ids.

Nothing here plans, prompts or acts; every function READS. What makes its
assertions worth trusting is a discipline, because a read-only check has
every way there is to lie:

THREE OUTCOMES, NEVER TWO. `PASS` / `FAIL` / `UNKNOWN`, and `Unresolved` is
the value of a Fact that could not be computed — not `None`, not an empty
collection, equal to nothing including itself. Comparing anything to it
yields UNKNOWN, never PASS. `verify` reports every UNKNOWN by name with its
reason and exits 1 for it, because "could not tell" is not a clean bill.

EVERY EXPECTED VALUE IS A FACT WITH A PROVENANCE. `Check.expected` is typed
as a `Fact`, `ctx.fact()` over `FACT_SOURCES` is the only constructor, and
`tests/test_no_hardcoded_expectations.py` walks the AST of every assertion
site: no int literal but 0/1/2, no string literal that is not a `WIRE_NAMES`
key (a name another program chose), a `FACT_SOURCES` key (a handle), argv or
prose. A typed expectation — `17 mount(s)`, `since=1.7.0` — goes stale
within days, and then fails for a reason that has nothing to do with the
router.

ONE MISSING CONTAINER IS ONE FAILURE. Every property of a container that is
not there is UNKNOWN, not FALSE, and absence is decided by a `docker ps`
that SUCCEEDS and lists nothing — never by matching a daemon's error prose.

A NON-PASSING CHECK OWES THE OPERATOR A REMEDY, and `do_not` is where the
tempting wrong fix is named. `Check.__post_init__` refuses one without.

Nothing here imports the router. The router is run as a subprocess (its own
`docker/run.sh` one-shots, its own `docker/derive-mounts.py` emitter) and its
files are read; the container it is asked about is the operator's detached
one, which this module never starts, stops or restarts.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple

HERE = Path(__file__).resolve().parent

# The exit codes `verify` reports, as words, for a consumer that should never
# have to know our integers. `cannot_run` is the one that matters: it is NOT
# a failure and NOT success — "this read produced no verdict" — and a console
# that renders it green is the false-green this module exists to refuse.
EXIT_OK, EXIT_FAILED, EXIT_CANNOT_RUN = 0, 1, 2
EXIT_WORDS = {EXIT_OK: "ok", EXIT_FAILED: "failed", EXIT_CANNOT_RUN: "cannot_run"}

# Every subprocess gets this timeout unless it asks for another: a probe
# without one is how a check hangs forever.
DEFAULT_TIMEOUT = 300
# The router's one-shots (`status`, `status --json`) run inside a fresh
# container; image pull and start on a cold host take real time.
ONESHOT_TIMEOUT = 900

# status.py bakes in NO staleness heuristic, because the interval is
# unknowable from the file alone — so the caller supplies it. Three intervals
# is late enough not to flap and early enough to notice a dead poll loop.
FRESHNESS_MULTIPLE = 3

# The names the operator's detached router runs under, as the router's own
# docker/run.sh reads them from the environment. `verify --container` and
# `--image` override; the defaults are run.sh's.
DEFAULT_CONTAINER = os.environ.get("CONTAINER", "amap-router-local")
DEFAULT_IMAGE = os.environ.get("IMAGE", "amap-router-local")

# The one-shot container name: run.sh defaults CONTAINER=amap-router-local
# for BOTH the detached and the foreground path, so a foreground `-- status`
# with no name of its own collides with the running detached router and
# `docker run` fails with a name conflict that has nothing to do with the
# router. Generated in one place so the collision cannot be reintroduced.
ONESHOT_PREFIX = "amap-sandy-verify"

HOST_FACTS_SCHEMA = 2
SECTION_CONTAINER = "router-container"
SECTION_HEALTH = "router-health"


# ----------------------------------------------------------------- wire names
#
# Every string another program emits or reads, which we do not get to choose,
# with the reason it is a wire name. The literal budget admits exactly these
# inside an assertion site. A COUNT never belongs here; a test forbids a
# numeric key.
WIRE_NAMES: Dict[str, str] = {
    # the router's config (the generated sibling of the manifest)
    "instances_dir": "router.json top-level key — the tree the router DISCOVERS instances "
                     "under, one directory per slug",
    "selected_json": "router.json top-level key — sandy's verdict file the router ADMITS a "
                     "discovered directory by",
    "state_dir": "router.json top-level key",
    "intake_dir": "router.json top-level key — an optional fourth root run.sh mounts rw",
    "fleet_domain": "router.json top-level key; its presence IS the peer lane",
    # sandy's verdict file, as the router reads it
    "selected": "selected.json list key: the slugs sandy selected (schema 1)",
    "slug": "selected.json entry key: the sandbox's slug, which IS the instance name",
    # docker's own vocabulary
    "true": "docker inspect's spelling of a true boolean in {{.State.Running}}",
    "none": "docker's network mode for --network none, as run.sh sets it",
    "unless-stopped": "docker's restart policy name for --restart unless-stopped, as run.sh "
                      "sets it",
    "Source": "docker inspect .Mounts row key: the host path",
    "Destination": "docker inspect .Mounts row key: the container path",
    "RW": "docker inspect .Mounts row key: writable",
    "rw": "derive-mounts.py's spelling of a writable mount",
    "ro": "derive-mounts.py's spelling of a read-only mount",
    # the router's own files and output
    "first-seen.json": "the router's first-sight marker filename under state_dir/<name>/ "
                       "(router/firstsight.py)",
    "instance": "first-seen.json field: the instance the marker is for",
    "first_seen_ts": "first-seen.json field: when the router first polled this root",
    "outbox_snapshot": "first-seen.json field: what first sight quarantined, by filename",
    "filename": "an outbox_snapshot entry's field",
    "polls": "status.json field",
    "last_poll_ts": "status.json field",
    "instances": "status.json field: the per-instance map, monotonic for the process lifetime",
    "totals": "status.json field: the per-process-lifetime counters",
    "admitted": "status.json field: the set the loader accepted at the END "
                "of the most recent poll, replaced wholesale — written together with "
                "last_poll_ts; OMITTED before the first poll, never []. The capability IS "
                "the field: a list is read, and absence is UNKNOWN",
    "interval_s": "status.json field: the float the poll loop sleeps; "
                  "OMITTED on a tracker that is not a run loop, never defaulted",
    "outbound_errored": "status.json totals field",
    "instance_errored": "status.json totals field",
    "discovery:": "the router's plain `status` heading for its discovery report",
    "** ": "the router's marker wrapping a discovery line that needs a human",
    # the router's docker tooling, by path under its checkout
    "docker": "the router's docker/ directory, and the docker CLI itself",
    "run.sh": "the router's container launcher, docker/run.sh",
    "derive-mounts.py": "the router's mount emitter, docker/derive-mounts.py",
    "status": "the router subcommand that prints its status document",
    "--json": "the router's flag making `status` print JSON on stdout",
    "--config": "run.sh's flag naming the router config",
    "--name": "run.sh's flag naming the container",
    "--": "run.sh's separator before the router subcommand",
    "IMAGE": "the environment variable run.sh reads the image name from",
}


# ------------------------------------------------------------- the verdicts


class Verdict:
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


PASS, FAIL, UNKNOWN = Verdict.PASS, Verdict.FAIL, Verdict.UNKNOWN


class Unresolved:
    """The value of a Fact that could not be computed.

    NOT None and NOT an empty collection. Comparing anything to this yields
    UNKNOWN, never PASS and never FAIL; it is equal to nothing, including
    itself, and cannot be hashed into a set where it might count as one
    known thing."""
    __slots__ = ("reason",)

    def __init__(self, reason: str):
        self.reason = reason

    def __repr__(self) -> str:
        return f"UNRESOLVED({self.reason})"

    def __eq__(self, other):   # never equal to anything, including itself
        return False

    __hash__ = None


def _unresolved(reason: str) -> Unresolved:
    return Unresolved(reason)


class CannotRun(Exception):
    """A tool this module needs is absent or did not finish: docker not on
    PATH, a one-shot that never returned. Reported as UNKNOWN by the check
    that hit it; never a traceback."""


@dataclass(frozen=True)
class Fact:
    """A derived value, and the derivation that produced it.

    `provenance` is printed beside every non-passing check, so the operator
    is told WHY the program expected that value. A value with no provenance
    is a value somebody typed, and the history of this repo's checks is a
    list of those going stale."""
    name: str
    value: Any
    provenance: str

    @property
    def known(self) -> bool:
        return not isinstance(self.value, Unresolved)


@dataclass(frozen=True)
class Check:
    """One assertion, its expected value's derivation, and the fix.

    `expected` is typed as a Fact ON PURPOSE: `expected=15` cannot be
    written without first writing a derivation for 15, and `Ctx.fact()` is
    the only constructor. That is the type-level half of "no literal
    counts"; the AST test is the mechanical half."""
    claim: str
    expected: Fact
    actual: Any
    result: str
    remedy: str
    do_not: str = ""        # the TEMPTING WRONG FIX, where there is one

    def __post_init__(self):
        if self.result is not PASS and not self.remedy.strip():
            raise ValueError(
                f"a non-passing check owes the operator a remedy; {self.claim!r} "
                f"reports {self.result} with none. The report has nowhere to put "
                "'and here is what to do about it', which is the only reason an "
                "operator is reading it.")
        if not isinstance(self.expected, Fact):
            raise TypeError(
                "Check.expected must be a Fact, so the report can say where the "
                f"expected value came from; got {type(self.expected).__name__}. "
                "Use ctx.fact(NAME) — see FACT_SOURCES.")

    @property
    def reason(self) -> str:
        """Why an UNKNOWN is unknown — the Unresolved's own sentence."""
        if isinstance(self.actual, Unresolved):
            return self.actual.reason
        if not self.expected.known:
            return self.expected.value.reason
        return ""


# ------------------------------------------------------------ shared probes
#
# One `run()`, because the hazards are shared, and every rule below exists
# because a prose form of the same command got it wrong somewhere.


@dataclass(frozen=True)
class Proc:
    argv: Tuple[str, ...]
    rc: int
    out: str
    err: str


def run(argv: Sequence[str], *, cwd: Optional[Path] = None,
        timeout: int = DEFAULT_TIMEOUT, extra_env: Optional[Dict[str, str]] = None) -> Proc:
    """The ONLY way this module starts a child process.

    * never `shell=True`, and never a pipe: `a | grep X` reports GREP's exit
      status. A test asserts `shell=True` appears nowhere in this file.
    * always `PYTHONDONTWRITEBYTECODE=1`, so a mutate/test/restore cycle
      never runs MUTATED bytecode against RESTORED source.
    * always the CHILD's own returncode, captured here and nowhere else.
    * always a timeout. `docker logs -f` blocks forever.
    * FileNotFoundError is a NAMED failure, not a traceback: a missing
      docker CLI raises rather than exiting non-zero.
    """
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if extra_env:
        env.update(extra_env)
    try:
        r = subprocess.run(list(argv), capture_output=True, text=True,
                           cwd=str(cwd) if cwd else None, timeout=timeout, env=env)
    except FileNotFoundError:
        raise CannotRun(f"{argv[0]} not found on PATH")
    except subprocess.TimeoutExpired:
        raise CannotRun(f"{argv[0]} did not finish within {timeout}s: {' '.join(argv)}")
    return Proc(tuple(argv), r.returncode, r.stdout or "", r.stderr or "")


def oneshot_name(section: str) -> str:
    """Every one-shot container gets its own name, from here and nowhere else."""
    safe = re.sub(r"[^a-z0-9-]+", "-", section.lower()).strip("-")
    return f"{ONESHOT_PREFIX}-{safe}"


def _inspect(container: str, fmt: str) -> Proc:
    return run(["docker", "inspect", "-f", fmt, container], timeout=120)


def runsh_argv(ctx: "Ctx", section: str, *mode: str) -> Tuple[str, ...]:
    """The router's docker/run.sh, always with a --name of our own."""
    repo = ctx.value("router_repo")
    if isinstance(repo, Unresolved):
        return ()
    return (str(Path(repo) / "docker" / "run.sh"),
            "--config", str(ctx.value("router_config")),
            "--name", oneshot_name(section), "--") + mode


_PROV = None


def provisioner():
    """The adapter module (`amap_sandy`), imported lazily and once, so this
    module can be imported by it without a cycle at import time. Every value
    here that concerns the feature root, the router's sibling config or
    sandy's verdict is read from it rather than restated."""
    global _PROV
    if _PROV is None:
        if str(HERE) not in sys.path:
            sys.path.insert(0, str(HERE))
        import amap_sandy as mod
        _PROV = mod
    return _PROV


def fleet_policy_mod():
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    import fleet_policy
    return fleet_policy


# ----------------------------------------------------------------- facts
#
# Every derivation is a FUNCTION, never a value. A source that cannot answer
# returns Unresolved(reason) — it does not guess, and it does not return an
# empty collection that reads as "none".


def _f_sandy_bin(ctx) -> Tuple[Any, str]:
    return ctx.args.sandy, "--sandy"


def _f_sandy_home(ctx):
    return ctx.home, "--sandy-home (default: amap_sandy.sandy_home())"


def _f_sandboxes(ctx):
    p = provisioner()
    try:
        boxes = p.discover_sandboxes(ctx.value("sandy_bin"))
    except Exception as e:
        return _unresolved(f"sandy could not be asked: {e}"), "discover_sandboxes(sandy)"
    return boxes, "discover_sandboxes(sandy --print-state)"


def _f_selection_states(ctx):
    """`{slug: (state, detail)}` for every sandbox sandy reports —
    `selected` (when), `not selected` (sandy's reason) or `unknown` (not
    launched since the manifest was written: neither answer).

    Unresolved until sandy has written a verdict at all. A fleet with no
    `selected.json` has decided nothing, and an exclusion list read off it
    would be an empty one — a clean bill of health nobody issued."""
    p = provisioner()
    home = ctx.value("sandy_home")
    boxes = ctx.value("sandboxes")
    if isinstance(boxes, Unresolved):
        return boxes, ctx.fact("sandboxes").provenance
    try:
        p.load_selected(home)
    except p.ProvisionError as e:
        return _unresolved(str(e)), str(p.feature_selected_path(home))
    return (p.selection_states(home, boxes),
            f"selection_states({p.feature_selected_path(home)} ∪ sandy --print-state)")


def _f_not_enrolled(ctx):
    """The sandboxes sandy did NOT select for this feature, in sandy's own
    verdict — the policy's rule excluded them. Named `not_enrolled` on the
    wire because the console that consumes --host-facts reads it under that
    key; the sense is unchanged — the slugs the router will never see.

    DATA, not a verdict: a console asking "is any agent excluded" cannot get
    NAMES out of claim/result/remedy without parsing prose.

    A sandbox with NO verdict yet (not launched since the manifest was
    written) is in neither list — pending, not excluded. `[]` MEANS GENUINELY
    NONE, and Unresolved means could not tell; the document omits the field
    entirely in the second case, because a consumer renders absence as
    unanswered and would render `[]` as "none excluded". Those are different
    answers and this is the boundary where they must not be confused."""
    p = provisioner()
    states = ctx.value("selection_states")
    if isinstance(states, Unresolved):
        return states, ctx.fact("selection_states").provenance
    out = sorted(slug for slug, (state, _why) in states.items()
                 if state == p.STATE_NOT_SELECTED)
    return out, "selection_states over sandy's reported fleet — sandy's own not_selected verdicts"


def _f_router_repo(ctx):
    repo = provisioner().resolve_router_repo()
    if repo is None:
        return (_unresolved(fleet_policy_mod().router_not_found_message("router/reset.py")),
                "resolve_router_repo()")
    return repo, "resolve_router_repo() — the checkout whose router/reset.py exists"


def _f_router_config(ctx):
    """The router's config: the GENERATED SIBLING of the manifest under the
    feature root, which `install --apply` writes and the router reads by
    `--config` (one file, no search path)."""
    home = ctx.value("sandy_home")
    return (provisioner().router_sibling_path(Path(home)),
            "the sibling of the manifest under $SANDY_HOME/features/amap")


def _f_router_doc(ctx):
    path = ctx.value("router_config")
    try:
        return json.loads(Path(path).read_text()), f"the router's config at {path}"
    except Exception as e:
        return _unresolved(f"not rendered yet or unreadable: {e}"), str(path)


def _f_config_instances(ctx):
    """The instances the router will drain. Under discovery the config NAMES
    none: the router lists the directories under `instances_dir` and admits
    each by `selected_json`. Computed here the same way, from the
    config's own two roots — never from the policy, never from the manifest,
    and never rounded: a root that cannot be read is Unresolved."""
    doc = ctx.value("router_doc")
    if isinstance(doc, Unresolved):
        return doc, ctx.fact("router_doc").provenance
    idir, sel = doc.get("instances_dir"), doc.get("selected_json")
    where = f"instances_dir ∩ selected_json of {ctx.value('router_config')}"
    if not idir or not sel:
        return _unresolved("the config names no instances_dir / selected_json — not a "
                           "discovery config; re-run install --apply"), where
    try:
        verdict = json.loads(Path(sel).read_text())
    except (OSError, ValueError) as e:
        return _unresolved(f"selected_json unreadable: {e} — a launch rewrites it"), where
    selected = {e.get("slug") for e in (verdict.get("selected") or []) if isinstance(e, dict)}
    try:
        dirs = {d.name for d in Path(idir).iterdir() if d.is_dir()}
    except OSError as e:
        return _unresolved(f"instances_dir unreadable: {e}"), where
    return sorted(dirs & selected), (f"directories under {idir} that {sel} names selected — "
                                     f"the router's own discovery rule")


def _f_state_dir(ctx):
    if ctx.args.state_dir:
        return Path(ctx.args.state_dir), "--state-dir"
    doc = ctx.value("router_doc")
    if isinstance(doc, Unresolved):
        return doc, ctx.fact("router_doc").provenance
    # From the CONFIG, never a conventional default: a config whose state_dir
    # differs makes every first-sight marker silently invisible.
    return Path(doc["state_dir"]), "the config's own state_dir"


def _f_selected_json(ctx):
    """The verdict file the router admits by — from the config, never from
    the manifest's side of the tree, so the mount check asks about the file
    the router was actually pointed at."""
    doc = ctx.value("router_doc")
    if isinstance(doc, Unresolved):
        return doc, ctx.fact("router_doc").provenance
    sel = doc.get("selected_json")
    if not sel:
        return (_unresolved("the config names no selected_json — not a discovery config"),
                f"selected_json of {ctx.value('router_config')}")
    return Path(sel), f"selected_json of {ctx.value('router_config')}"


def _f_container(ctx):
    return ctx.args.container, "--container (default: $CONTAINER, as run.sh reads it)"


def _f_image(ctx):
    return ctx.args.image, "--image (default: $IMAGE, as run.sh reads it)"


def _f_status_doc(ctx):
    """`status --json` through the router's own run.sh one-shot, parsed:
    the document, or Unresolved with the router's own words. Fetched ONCE
    per run and shared by both sections. The noise warning is issued here,
    once, for the same reason."""
    argv = runsh_argv(ctx, SECTION_HEALTH, "status", "--json")
    where = "the router's `status --json`, through docker/run.sh"
    if not argv:
        return _unresolved("no router checkout"), where
    try:
        p = run(argv, timeout=ONESHOT_TIMEOUT, extra_env={"IMAGE": str(ctx.value("image"))})
    except CannotRun as e:
        return _unresolved(str(e)), where
    doc, noise = _status_doc(p.out)
    if noise:
        ctx.warn(f"the router printed {noise} log line(s) on STDOUT ahead of the status "
                 f"document, so this read started at the first `{{`. A --json command's stdout "
                 f"is the document or nothing — the router's own rule for `peers --json`; "
                 f"its discovery report goes to the log, at WARNING, which is "
                 f"stderr's job")
    if doc is None:
        # `status` with no status.json exits 1: only the poll loop writes it,
        # so before the router has ever run this is expected, not a fault.
        # read() also returns None for a CORRUPT file exactly as for a
        # missing one; the reason names which.
        return (_unresolved((p.err.strip() or p.out.strip())[:200] or "no status document"),
                where)
    return doc, where


def _f_announced_interval(ctx):
    """The poll interval the router REALLY got: `status.json`'s `interval_s`,
    the float the poll loop sleeps. OMITTED, never defaulted, on a tracker
    that is not a run loop, and then this is UNKNOWN. Never from an option:
    the program that started the router is not this one, so what it was
    asked for is not a fact this module holds."""
    doc = ctx.value("status_doc")
    if isinstance(doc, Unresolved):
        return doc, ctx.fact("status_doc").provenance
    value = doc.get("interval_s")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value), "status.json interval_s — the float the poll loop sleeps"
    return (_unresolved("status.json carries no interval_s — the router writes it from "
                        "its poll loop, so none means no loop is running"),
            "status.json interval_s")


def _f_admitted(ctx):
    """The router's own view of the fleet: `status.json`'s `admitted`, the
    set the loader accepted at the end of its most recent poll (replaced
    wholesale each poll, written together with `last_poll_ts` — a stale
    document makes both stale in step, and the freshness check covers the
    pair; OMITTED before the first poll, never [], and then this is
    UNKNOWN). NEVER `status.json`'s `instances` map: that one is monotonic
    for the process lifetime (no removal path), so a de-enrolled instance
    stays in it forever and a check reading it would never see the fleet
    shrink."""
    doc = ctx.value("status_doc")
    if isinstance(doc, Unresolved):
        return doc, ctx.fact("status_doc").provenance
    admitted = doc.get("admitted")
    if isinstance(admitted, list):
        return (sorted(str(x) for x in admitted),
                f"status.json admitted, as of its last_poll_ts {doc.get('last_poll_ts')!r}")
    return (_unresolved("status.json carries no admitted list — the router writes it "
                        "at the end of each poll, so none means it has not polled yet"),
            "status.json admitted")


def _f_max_poll_age(ctx):
    interval = ctx.value("announced_interval")
    if isinstance(interval, Unresolved):
        return interval, ctx.fact("announced_interval").provenance
    return (interval * FRESHNESS_MULTIPLE,
            f"{FRESHNESS_MULTIPLE} × the interval the router announced in status.json "
            f"({ctx.fact('announced_interval').provenance})")


def _f_true(ctx):
    return True, "the property this check exists to establish"


def _f_zero(ctx):
    return 0, "nothing of this kind may exist for the check to pass"


def _f_empty(ctx):
    return [], "the empty set — nothing of this kind may be reported"


FACT_SOURCES: Dict[str, Callable[["Ctx"], Tuple[Any, str]]] = {
    "sandy_bin": _f_sandy_bin,
    "sandy_home": _f_sandy_home,
    "sandboxes": _f_sandboxes,
    "selection_states": _f_selection_states,
    "not_enrolled": _f_not_enrolled,
    "router_repo": _f_router_repo,
    "router_config": _f_router_config,
    "router_doc": _f_router_doc,
    "config_instances": _f_config_instances,
    "state_dir": _f_state_dir,
    "selected_json": _f_selected_json,
    "container": _f_container,
    "image": _f_image,
    "status_doc": _f_status_doc,
    "announced_interval": _f_announced_interval,
    "admitted": _f_admitted,
    "max_poll_age": _f_max_poll_age,
    "true": _f_true,
    "zero": _f_zero,
    "empty": _f_empty,
}


class Ctx:
    """Run-scoped state: the options, the host, and the fact cache.

    Facts are computed once and memoized, so the value a report prints is
    the value the assertion used, and its provenance is printed beside it."""

    def __init__(self, args: argparse.Namespace, home: Path):
        self.args = args
        self.home = Path(home)
        self._facts: Dict[str, Fact] = {}
        self.warnings: List[str] = []

    def fact(self, name: str) -> Fact:
        if name not in FACT_SOURCES:
            raise KeyError(f"no derivation registered for fact {name!r}; "
                           f"add one to FACT_SOURCES rather than typing a value")
        if name not in self._facts:
            try:
                value, prov = FACT_SOURCES[name](self)
            except Exception as e:
                value, prov = _unresolved(f"{type(e).__name__}: {e}"), f"{name} (derivation failed)"
            self._facts[name] = Fact(name, value, prov)
        return self._facts[name]

    def value(self, name: str) -> Any:
        return self.fact(name).value

    def warn(self, text: str) -> None:
        self.warnings.append(text)


# ---------------------------------------------------------- check helpers
#
# Three outcomes, never two. UNKNOWN is first class and never rounds to
# PASS: if either side of a comparison is Unresolved, the answer is UNKNOWN.


def _cmp(expected: Fact, actual: Any, ok: Optional[Callable[[Any, Any], bool]]) -> str:
    if isinstance(actual, Unresolved) or not expected.known:
        return UNKNOWN
    try:
        return PASS if (ok(expected.value, actual) if ok else expected.value == actual) else FAIL
    except Exception:
        return FAIL


def check(claim: str, expected: Fact, actual: Any, remedy: str, *,
          do_not: str = "", ok: Optional[Callable[[Any, Any], bool]] = None) -> Check:
    return Check(claim=claim, expected=expected, actual=actual,
                 result=_cmp(expected, actual, ok), remedy=remedy, do_not=do_not)


def unknown(claim: str, expected: Fact, reason: str, remedy: str, *, do_not: str = "") -> Check:
    return Check(claim=claim, expected=expected, actual=_unresolved(reason),
                 result=UNKNOWN, remedy=remedy, do_not=do_not)


def same_set(expected_seq, actual_seq) -> bool:
    return set(expected_seq) == set(actual_seq)


# ====================================================== the router CONTAINER


def _container_presence(name: str) -> Any:
    """True (present), False (absent), or Unresolved (cannot tell), decided ONCE.

    Every other assertion about the container reads a PROPERTY of it. `docker
    inspect` on a container that does not exist exits non-zero with empty
    stdout, and `"".split()` is `[]`, so each property would compare an empty
    list against its expectation and report a FAILURE — one missing container
    coming out as four, each with a remedy about the thing it was measuring.

    Absence is decided by a query that SUCCEEDS and returns nothing, never by
    matching docker's error prose: which wording a given daemon uses is not a
    thing this module gets to depend on. `--all` on purpose: a container that
    exists but is stopped is present-and-not-running, which must fail the
    first check rather than make every property below unanswerable."""
    try:
        p = run(["docker", "ps", "--all", "--filter", f"name=^{name}$",
                 "--format", "{{.Names}}"], timeout=120)
    except CannotRun as e:
        return _unresolved(str(e))
    if p.rc != 0:
        # A daemon that will not answer is not evidence the container is gone;
        # saying "absent" here would send the operator to start a second copy.
        return _unresolved(f"`docker ps` failed, so whether {name} exists is unknown: "
                           f"{(p.err or p.out).strip()[:120]}")
    return name in p.out.split()


# The claim strings the container section yields, in order. Named ONCE
# because there are three paths through it — container present, container
# absent, docker unreachable — and a claim that only one path knows about is
# a claim the other two silently drop. A test drives all three and compares.
CONTAINER_RUNNING = "the router container is running"
CONTAINER_POSTURE = "it runs with no network and restarts unless stopped"
CONTAINER_MOUNTS = ("the router mounts exactly its derived set — state_dir rw, the verdict's "
                    "DIRECTORY ro, the instance tree rw as one mount, intake_dir rw when "
                    "configured, the config ro — and nothing else")
CONTAINER_VERDICT_DIR = "the verdict is mounted by its directory, never as a file"
CONTAINER_NO_SHADOW = "no read-only parent is mounted after its read-write child"
CONTAINER_VIEW = "the router's own view of the fleet is the config's"
CONTAINER_DOC_CLAIMS = (CONTAINER_MOUNTS, CONTAINER_VERDICT_DIR, CONTAINER_NO_SHADOW,
                        CONTAINER_VIEW)


def _container_unanswerable(ctx, *, reason: str, remedy: str, first=None):
    """Every container claim as an UNKNOWN, gated exactly as the live path
    gates them. `first` lets the caller substitute a real verdict for the
    leading claim: a container that is ABSENT makes "is it running"
    answerable (no) while leaving every property OF it unanswerable."""
    yield first if first is not None else unknown(
        claim=CONTAINER_RUNNING, expected=ctx.fact("true"), reason=reason, remedy=remedy)
    yield unknown(claim=CONTAINER_POSTURE, expected=ctx.fact("true"), reason=reason,
                  remedy=remedy)
    if isinstance(ctx.value("router_doc"), Unresolved):
        return          # the live path stops here too — same gate, one source
    for claim in CONTAINER_DOC_CLAIMS:
        yield unknown(claim=claim, expected=ctx.fact("true"), reason=reason, remedy=remedy)


def verify_container(ctx: Ctx) -> Iterator[Check]:
    name = str(ctx.value("container"))
    here = _container_presence(name)

    if isinstance(here, Unresolved):
        # Nothing below can be answered, and none of it is a failure.
        yield from _container_unanswerable(
            ctx, reason=here.reason,
            remedy="fix the docker connection first — `docker context show`, then "
                   "`docker version`")
        return

    if here is False:
        # ONE failure, not four. The rest are properties OF a container, and
        # with none to inspect they are unknown rather than false.
        yield from _container_unanswerable(
            ctx, reason=f"no container named {name} to inspect",
            remedy="start the container first; nothing here can be read until the "
                   "first check passes",
            first=check(claim=CONTAINER_RUNNING, expected=ctx.fact("true"), actual=False,
                        remedy=f"start it from the router checkout: docker/run.sh --config "
                               f"{ctx.value('router_config')} --name {name} --detach. "
                               f"There is no container named {name}"))
        return

    running = _inspect(name, "{{.State.Running}}")
    yield check(claim=CONTAINER_RUNNING,
                expected=ctx.fact("true"),
                actual=running.rc == 0 and running.out.strip().lower() == "true",
                remedy=f"the container exists but is stopped, and still holds its name, "
                       f"so docker/run.sh would fail on the name: docker start {name}. "
                       f"Read `docker logs --tail 200 {name}` for why it stopped",
                do_not="do not docker rm it to make room for run.sh: start it; its "
                       "state is on the host, but removing it discards the container's "
                       "own log")
    net = _inspect(name, "{{.HostConfig.NetworkMode}} {{.HostConfig.RestartPolicy.Name}}")
    yield check(claim=CONTAINER_POSTURE,
                expected=Fact("posture", ["none", "unless-stopped"],
                              "--network none and --restart unless-stopped, as run.sh sets "
                              "them; the network posture is a design statement, not a "
                              "convenience"),
                actual=net.out.split(),
                remedy="if a change ever makes the router want a network, that is an "
                       "argument to have, not a flag to add")
    doc = ctx.value("router_doc")
    if isinstance(doc, Unresolved):
        return
    got = _mount_sources(_inspect(name, "{{json .Mounts}}"))
    # Keyed by DESTINATION, realpath'd on both sides (docker reports the host
    # path it resolved; the emitter prints the config's spelling): a mapping,
    # so a difference names the row — an added mount, a mode flipped — where
    # a set of tuples says only "not equal".
    actual_map = {os.path.realpath(str(m.get("Destination") or "")):
                  (os.path.realpath(str(m.get("Source") or "")), bool(m.get("RW"))) for m in got}
    derived = _derived_mounts(ctx)
    # The emitter prints the ROOTS it derives from the config and NOT the
    # config itself: `run.sh` appends that identity mount on its own. So the
    # expected set is the emitter's rows PLUS that one — a check that
    # compared docker's set against the emitter's alone could never pass; it
    # failed on the first real router, and passed its own tests only because
    # the fixture made the emitter print a line it never prints.
    expected_rows = derived
    if not isinstance(derived, Unresolved):
        cfg = os.path.realpath(str(ctx.value("router_config")))
        if all(src != cfg for src, _rw in derived):
            expected_rows = list(derived) + [(cfg, False)]
    yield check(claim=CONTAINER_MOUNTS,
                expected=Fact("derived_mounts", _mount_map(expected_rows),
                              "docker/derive-mounts.py run against the config — the router's "
                              "own emitter, whose order run.sh follows — plus the config's own "
                              "identity mount, which run.sh adds and the emitter does not print"),
                actual=actual_map,
                remedy="the set is fixed at `docker run`: stop the container and re-run "
                       "docker/run.sh on the sibling. The router re-reads the sibling "
                       "every poll — a graph edit and a new sandbox are both picked "
                       "up without a restart — but a reload that would change state_dir is "
                       "REFUSED and ignored, so a state_dir change is a restart by design, "
                       "never a re-render",
                do_not="do not add a mount by hand: the set is derive-mounts.py's, and "
                       "this module derives the same one from the same roots")
    rows = [(src, rw) for src, rw in actual_map.values()]
    verdict = ctx.value("selected_json")
    as_file = (verdict if isinstance(verdict, Unresolved)
               else [src for src, _rw in rows if src == os.path.realpath(str(verdict))])
    yield check(claim=CONTAINER_VERDICT_DIR, expected=ctx.fact("empty"), actual=as_file,
                remedy="mount its DIRECTORY (as derive-mounts.py does): a file "
                       "bind-mount binds the inode found at `docker run`, and the verdict is "
                       "published by temp-file + rename, so after the first rename the "
                       "container reads the ORIGINAL file forever — a stale verdict that "
                       "parses, admits the membership of an hour ago, and looks healthy",
                do_not="do not 'fix' the publish path to write in place: a torn verdict that "
                       "parses is the other half of the same bug")
    yield check(claim=CONTAINER_NO_SHADOW, expected=ctx.fact("empty"),
                actual=derived if isinstance(derived, Unresolved) else _shadowed(derived),
                remedy="the router emits parents before children (sorted by component "
                       "count) because docker applies -v in order and a parent mounted after "
                       "its child SHADOWS it: the rw instance tree vanishes behind the ro "
                       "mount of its own parent and every delivery fails on a read-only "
                       "filesystem. Rebuild the container from run.sh; nothing else orders "
                       "the mounts")
    yield check(claim=CONTAINER_VIEW,
                expected=ctx.fact("config_instances"),
                actual=ctx.value("admitted"),
                ok=same_set,
                remedy="the router's admitted set is read from status.json (`admitted`, the "
                       "loader's set at the end of the last poll). A difference is a "
                       "sandbox whose lane tree or verdict the router does not see as this "
                       "program does — read the discovery report; no `admitted` at all is a "
                       "router that has not polled yet, and reads UNKNOWN",
                do_not="do not restart the router to 'refresh' it: the sibling is re-read "
                       "every poll, and a restart would only reload the same set")
    # No "container NEWER than its config" check: the router does not read
    # its config once at start — the sibling is re-read every poll,
    # so a container older than its config is the normal state of a fleet
    # whose graph was edited. The one change a reload refuses, state_dir, is
    # caught by the mount-set check above (the old state_dir is what is
    # mounted), with the restart as its remedy.


def _derived_mounts(ctx) -> Any:
    """The router's own mount emitter, `docker/derive-mounts.py <config>`,
    run rather than restated: one `<abspath>\\t<rw|ro>` line per mount IN
    EMISSION ORDER — run.sh appends `-v` in exactly that sequence, so this
    output is the only place the order is stated (docker's own `.Mounts`
    order is not vouched for by anyone). Returns `[(realpath, rw), ...]` in
    order, or Unresolved."""
    repo = ctx.value("router_repo")
    if isinstance(repo, Unresolved):
        return repo
    config = ctx.value("router_config")
    tool = Path(repo) / "docker" / "derive-mounts.py"
    if not tool.is_file():
        return _unresolved(f"{tool} is not there — a router checkout without "
                           f"the sibling-aware mount emitter")
    try:
        p = run([sys.executable, str(tool), str(config)], cwd=Path(repo))
    except CannotRun as e:
        return _unresolved(str(e))
    if p.rc != 0:
        return _unresolved(f"derive-mounts.py exited {p.rc}: {(p.err or p.out).strip()[:200]}")
    rows = []
    for line in p.out.splitlines():
        if not line.strip():
            continue
        parts = line.rstrip("\n").split("\t")
        if len(parts) != 2 or parts[1] not in ("rw", "ro"):
            return _unresolved(f"derive-mounts.py printed a line this program does not read: "
                               f"{line!r}")
        rows.append((os.path.realpath(parts[0]), parts[1] == "rw"))
    if not rows:
        return _unresolved("derive-mounts.py printed no mounts")
    return rows


def _mount_map(rows) -> Any:
    """`{destination: (source, rw)}` over `(path, rw)` rows — the router's
    mounts are identity mounts, so destination and source are one path;
    keyed so that a difference NAMES the row."""
    if isinstance(rows, Unresolved):
        return rows
    return {path: (path, rw) for path, rw in rows}


def _shadowed(rows) -> List[str]:
    """Read-only mounts that come AFTER a read-write mount nested under
    them, in EMISSION order — each one shadows that child."""
    out = []
    for i, (parent, rw) in enumerate(rows):
        if rw:
            continue
        for j, (child, child_rw) in enumerate(rows):
            if child_rw and j < i and child.startswith(parent.rstrip(os.sep) + os.sep):
                out.append(f"{parent} (ro) is mounted after {child} (rw) and shadows it")
    return out


def _mount_sources(p: Proc) -> Any:
    """`docker inspect -f '{{json .Mounts}}'`, parsed. A LIST or nothing:
    `json.loads` succeeds on plenty of documents that are not a mount table,
    and a verify that raises reports nothing about the checks that would
    have answered."""
    try:
        doc = json.loads(p.out or "[]")
    except Exception:
        return []
    return doc if isinstance(doc, list) else []


# ========================================================= the router's HEALTH


def _status_doc(out: str) -> Tuple[Any, int]:
    """`(document, lines of noise before it)` from `status --json`'s stdout.

    The contract is that stdout IS the document. The router logs its
    discovery report at WARNING through the same stream, so on a fleet with
    anything to report the document can arrive after a block of log lines.
    Reading from the first
    line that opens an object recovers it, and the COUNT is returned so the
    caller can say so out loud rather than tolerate it: a reader that
    silently eats a producer's noise is how the noise becomes the contract.
    `(None, n)` when there is no document to find, which stays UNKNOWN."""
    try:
        return json.loads(out), 0
    except Exception:
        pass
    lines = out.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if line.startswith("{"):
            try:
                return json.loads("".join(lines[i:])), i
            except Exception:
                return None, i
    return None, 0


HEALTH_STATUS = "the router reports itself healthy"
HEALTH_POLLED = "the poll loop has run at least once"
HEALTH_FRESH = "the last poll is recent relative to the interval the router announced"
HEALTH_INSTANCES = "the router's instance set is the config's"
HEALTH_FIRST_SEEN = "every configured instance has been first-seen: its marker exists"
HEALTH_MARKERS = ("each marker names its instance and carries a first_seen_ts (its "
                  "declared_root is provenance, never compared)")
HEALTH_DISCOVERY = "the router's discovery report flags nothing for a human"
HEALTH_ERRORS = "nothing errored in this process lifetime"


def verify_health(ctx: Ctx) -> Iterator[Check]:
    doc = ctx.value("status_doc")
    if isinstance(doc, Unresolved):
        # The reason is the router's (or docker's) own words; the remedy is
        # chosen by a STRUCTURAL fact — no checkout — never by matching the
        # reason's prose, which is the mistake `_container_presence` names.
        if isinstance(ctx.value("router_repo"), Unresolved):
            yield unknown(claim=HEALTH_STATUS, expected=ctx.fact("true"), reason=doc.reason,
                          remedy=fleet_policy_mod().router_not_found_message("router/reset.py"))
        else:
            yield unknown(claim=HEALTH_STATUS, expected=ctx.fact("true"), reason=doc.reason,
                          remedy="if docker could not be asked, fix the docker connection first "
                                 "(`docker context show`, then `docker version`); otherwise "
                                 "start the router first: docker/run.sh --detach from the "
                                 "router checkout")
        return
    yield check(claim=HEALTH_POLLED,
                expected=ctx.fact("true"), actual=int(doc.get("polls") or 0) > 0,
                remedy="the container is up but has not polled — read its logs")
    # Existence alone is worthless: status.json PERSISTS after the container
    # dies, so a stale document from a dead router is indistinguishable from
    # a healthy one except by AGE.
    age = _age_seconds(doc.get("last_poll_ts"))
    yield check(claim=HEALTH_FRESH,
                expected=ctx.fact("max_poll_age"),
                actual=age, ok=lambda e, a: a <= e,
                remedy="the router is not polling; check it is still running — and if the "
                       "bound itself is UNKNOWN, status.json carries no interval_s, which is "
                       "where the interval is read from")
    yield check(claim=HEALTH_INSTANCES,
                expected=ctx.fact("config_instances"),
                actual=sorted(doc.get("instances") or {}), ok=same_set,
                remedy="an instance that has never been polled simply does not appear — "
                       "absence is `never seen`, not `zero traffic`")
    yield from _first_sight_checks(ctx)
    yield from _discovery_checks(ctx)
    totals = doc.get("totals") or {}
    yield check(claim=HEALTH_ERRORS,
                expected=ctx.fact("zero"),
                actual=int(totals.get("outbound_errored") or 0)
                + int(totals.get("instance_errored") or 0),
                remedy="read state_dir/<name>/results — status.json is a convenience view, "
                       "not a ledger",
                do_not="do not assert absolute counter values: totals are PER-PROCESS-"
                       "LIFETIME and reset to zero on every container restart")


def _marker_paths(ctx) -> Any:
    """`{instance: state_dir/<instance>/first-seen.json}` for the config's
    instances. Composed here from the wire name rather than imported from
    `router.firstsight` on purpose: this module runs the router as a
    subprocess and reads its files, and does not import it."""
    sd = ctx.value("state_dir")
    names = ctx.value("config_instances")
    if isinstance(sd, Unresolved) or isinstance(names, Unresolved):
        return sd if isinstance(sd, Unresolved) else names
    return {n: Path(sd) / n / "first-seen.json" for n in names}


def _first_sight_checks(ctx):
    """The first-sight markers, checked once the router has polled. The
    router writes the marker itself, on its first poll of each root
    (`router/firstsight.py`). Everything here reads; nothing writes a
    marker, ever."""
    marks = _marker_paths(ctx)
    names = ctx.value("config_instances")
    if isinstance(marks, Unresolved) or isinstance(names, Unresolved):
        yield unknown(claim=HEALTH_FIRST_SEEN,
                      expected=ctx.fact("config_instances"),
                      reason=(marks if isinstance(marks, Unresolved) else names).reason,
                      remedy="render the config (install --apply) and start the router")
        return
    instances = set(names)
    seen = sorted(n for n, p in marks.items() if p.is_file())
    yield check(claim=HEALTH_FIRST_SEEN,
                expected=ctx.fact("config_instances"), actual=seen, ok=same_set,
                remedy="an instance with no marker has never been polled by this router — "
                       "check the drainer is running against THIS config, and that state_dir "
                       "is the persistent directory it was started with",
                do_not="do not write a marker; a snapshot taken by the wrong program at the "
                       "wrong moment is not a first sight")
    agree, lost = [], {}
    for n in seen:
        try:
            m = json.loads(marks[n].read_text())
        except (OSError, ValueError):
            continue
        if not isinstance(m, dict) or m.get("instance") != n or not m.get("first_seen_ts"):
            continue
        # `declared_root` is PROVENANCE — where the snapshot was taken — and
        # is never compared: first sight is keyed by name with no root
        # component. Rewriting it would lie about
        # provenance; comparing it would fail a correct fleet.
        agree.append(n)
        if m.get("outbox_snapshot"):
            lost[n] = [e.get("filename") if isinstance(e, dict) else e
                       for e in m["outbox_snapshot"]]
    yield check(claim=HEALTH_MARKERS,
                expected=Fact("seen_now", seen, "the markers present under state_dir"),
                actual=sorted(agree), ok=same_set,
                remedy="a marker that names another instance or no time was not written by "
                       "this router: router `reset` for that instance, then let it be polled "
                       "again — and expect that poll to quarantine whatever is staged")
    # An ORPHAN marker — a name with a marker but no instance in the config —
    # is what retiring a sandbox leaves behind, not a defect: nothing sweeps
    # state_dir/<name>/, and the router's `reset` rightly refuses a name the
    # config does not know. A WARNING naming the directory, never a FAIL.
    sd = Path(ctx.value("state_dir"))
    orphans = sorted(d.name for d in sd.iterdir()
                     if d.is_dir() and (d / "first-seen.json").is_file()
                     and d.name not in instances) if sd.is_dir() else []
    if orphans:
        ctx.warn(f"first-sight markers with no configured instance (a retired sandbox's "
                 f"state, kept on purpose — router `reset` refuses a name the config no "
                 f"longer knows, so reset BEFORE retiring next time): {orphans}")
    if lost:
        ctx.warn(f"permanently quarantined at first sight (never delivered, and not reported "
                 f"to the sender beyond the quarantine record): {lost}")


def _discovery_lines(text: str) -> List[str]:
    """The router's discovery report: the indented lines under its plain
    `status` heading `discovery:`. The heading
    is ABSENT on a clean fleet — never an empty section — so no heading is
    an empty report, not an unknown one."""
    lines = text.splitlines()
    out: List[str] = []
    for i, line in enumerate(lines):
        if line.strip() == "discovery:":
            for follower in lines[i + 1:]:
                if follower.strip() and not follower.startswith((" ", "\t")):
                    break
                if follower.strip():
                    out.append(follower)
            break
    return out


def _discovery_checks(ctx):
    """What the router SKIPPED, could not admit, or found broken while
    discovering — read from plain `status`, where the router prints it (not
    in status.json, deliberately). Every line the router wraps in `** ` is
    one that needs a human; a plain line is reported, never failed."""
    argv = runsh_argv(ctx, SECTION_HEALTH, "status")
    if not argv:
        return
    try:
        p = run(argv, timeout=ONESHOT_TIMEOUT, extra_env={"IMAGE": str(ctx.value("image"))})
    except CannotRun as e:
        yield unknown(claim=HEALTH_DISCOVERY, expected=ctx.fact("empty"), reason=str(e),
                      remedy="fix the docker connection first")
        return
    if p.rc != 0:
        yield unknown(claim=HEALTH_DISCOVERY,
                      expected=ctx.fact("empty"),
                      reason=(p.err.strip() or p.out.strip())[:200] or "status printed nothing",
                      remedy="start the router first: docker/run.sh --detach from the router "
                             "checkout")
        return
    report = _discovery_lines(p.out + p.err)
    flagged = [line.strip() for line in report if line.strip().startswith("** ")]
    plain = [line.strip() for line in report if not line.strip().startswith("** ")]
    yield check(claim=HEALTH_DISCOVERY,
                expected=ctx.fact("empty"), actual=flagged, ok=same_set,
                remedy="each line names its slug and its reason. VERDICT UNAVAILABLE: sandy's "
                       "selected.json is missing or unreadable — launch one sandbox so sandy "
                       "rewrites it. NO DIRECTORY: sandy selected a slug whose tree does not "
                       "exist; a verdict follows a launch and a launch creates the tree, so "
                       "this is broken state — relaunch it. INERT EDGE with no verdict: the "
                       "policy's graph names a sandbox that has never existed — a probable "
                       "typo in the manifest's `feature` section",
                do_not="do not silence a line by removing the slug from the policy without "
                       "reading why the router printed it")
    if plain:
        ctx.warn(f"the router's discovery report: {'; '.join(_condensed(plain))} — not "
                 f"drained, not deleted, not an error; a NO VERDICT directory is what every "
                 f"workspace rename leaves behind, and a pending INERT EDGE resolves at that "
                 f"sandbox's launch")


# The router's discovery line shape: `TAG  slug: reason` (two spaces after
# the tag). Lines sharing a tag and a reason are ONE fact about many slugs
# — dozens of NO VERDICT lines each repeating the same sentence — so they
# are reported once, with the slugs listed.
_DISCOVERY_LINE_RE = re.compile(r"^(?P<tag>[A-Z][A-Z ]*?)  (?P<slug>\S+): (?P<why>.*)$")


def _condensed(lines: List[str]) -> List[str]:
    """One entry per (tag, reason), naming every slug; a line that is not
    in the router's shape is kept verbatim. Order is first appearance."""
    slugs: Dict[Tuple[str, str], List[str]] = {}
    order: List[Any] = []
    for line in lines:
        m = _DISCOVERY_LINE_RE.match(line)
        if not m:
            order.append(line)
            continue
        key = (m.group("tag"), m.group("why"))
        if key not in slugs:
            slugs[key] = []
            order.append(key)
        slugs[key].append(m.group("slug"))
    return [item if isinstance(item, str)
            else f"{item[0]} ×{len(slugs[item])} ({', '.join(slugs[item])}): {item[1]}"
            for item in order]


def _age_seconds(ts) -> Any:
    if not ts:
        return _unresolved("status.json carries no last_poll_ts")
    try:
        t = datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        now = datetime.datetime.now(t.tzinfo) if t.tzinfo else datetime.datetime.now()
        return (now - t).total_seconds()
    except Exception:
        return _unresolved(f"cannot parse last_poll_ts {ts!r}")


# ================================================================ the sections
#
# Two records, in the order they run. Not a driver: `verify` calls each
# section's function and folds its checks into its own problem list; the
# record exists so the host-facts document and the tests name the sections
# from one place.


@dataclass(frozen=True)
class Section:
    id: str
    title: str
    verify: Callable[[Ctx], Iterator[Check]]


SECTIONS: Tuple[Section, ...] = (
    Section(SECTION_CONTAINER, "the router's container", verify_container),
    Section(SECTION_HEALTH, "the router's health", verify_health),
)


@dataclass
class Outcome:
    section: Section
    checks: List[Check]


def run_sections(ctx: Ctx) -> List[Outcome]:
    """Every section, every check, in order; nothing stops early. An
    operator fixing a router wants the whole list."""
    return [Outcome(s, list(s.verify(ctx))) for s in SECTIONS]


def problem_lines(outcomes: Sequence[Outcome]) -> List[str]:
    """Every non-passing check as one line for `verify`'s problem list. A
    FAIL leads with the claim's negation; an UNKNOWN says it could not tell
    and why, because an UNKNOWN printed as a bare claim reads as a fact."""
    out: List[str] = []
    for o in outcomes:
        for c in o.checks:
            if c.result is PASS:
                continue
            if c.result is FAIL:
                line = f"router: NOT {c.claim} — {c.remedy}"
            else:
                line = f"router: UNKNOWN whether {c.claim}: {c.reason} — {c.remedy}"
            if c.do_not:
                line += f" ({c.do_not})"
            out.append(line)
    return out


# ============================================================== --host-facts


def host_facts_doc(outcomes: Sequence[Outcome], rc: int,
                   ctx: Optional[Ctx] = None) -> Dict[str, Any]:
    """The host-level facts only this side can see, as a document for
    amap-router-local's operator console (schema 2: section ids
    `router-container` / `router-health`, from `amap-sandy.py verify`).

    WHY IT CARRIES ITS OWN TIMESTAMP: the lesson the health section encodes
    about `status.json`. That file outlives the container, so freshness is
    what is checked; this file outlives the run that produced it the same
    way, and a consumer reading an hour-old document would render docker as
    green now. `generated_ts` lets the reader apply our own rule back to us.

    WHAT IT DELIBERATELY OMITS: every `expected`/`actual` VALUE. The claims
    and remedies are operator-facing prose; the values are mount tables and
    absolute host paths, and this document's destination is a web page.

    `reason` IS THE EXCEPTION, AND IT STAYS ONE. It carries the producer's
    own words — docker's error, the router's stderr — so it is the one field
    here that can hold an arbitrary host path, and on a real capture it did
    (`Cannot connect to the Docker daemon` preceded by run.sh's own
    `N mount(s) derived from <absolute host path>`). Sanitising a daemon's
    error would be worse than carrying it: a console that paraphrases what a
    tool said is a console that lies about what a tool said, and the whole
    value of an UNKNOWN is the producer's sentence about why. So the
    omission above is NOT a guarantee that this document is path-free, and a
    reader should not take it that way: the console's page is not safe to
    paste into a ticket by construction. It is also free text and may be
    MULTI-LINE — a renderer that drops it into an HTML container without
    `pre-wrap` joins two producers' sentences into one run-on statement.

    `not_enrolled` is OMITTED when it cannot be answered, never emitted as
    `[]`: a consumer renders absence as unanswered and `[]` as "none
    excluded", and confusing them would manufacture a clean bill of health
    out of a failed lookup."""
    doc: Dict[str, Any] = {
        "schema": HOST_FACTS_SCHEMA,
        "generated_ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "generated_by": "amap-sandy.py verify",
        "exit_status": rc,
        "exit_meaning": EXIT_WORDS.get(rc, "unknown"),
        "phases": [
            {
                "id": o.section.id,
                "title": o.section.title,
                "checks": [
                    {"claim": c.claim, "result": c.result, "remedy": c.remedy,
                     **({"reason": c.reason} if c.result is UNKNOWN else {})}
                    for c in o.checks
                ],
            }
            for o in outcomes
        ],
    }
    if ctx is not None:
        excluded = ctx.value("not_enrolled")
        if not isinstance(excluded, Unresolved):
            doc["not_enrolled"] = list(excluded)
    return doc


def write_host_facts(path: Path, outcomes: Sequence[Outcome], rc: int,
                     ctx: Optional[Ctx] = None) -> None:
    """Atomically, because the consumer polls it: `os.replace` over a temp
    file in the same directory, so a reader never sees a truncated
    document."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}")
    tmp.write_text(json.dumps(host_facts_doc(outcomes, rc, ctx), indent=2) + "\n")
    os.replace(tmp, path)
