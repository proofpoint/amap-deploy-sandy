"""Make `tests/` importable as a plain directory (no package), so
`import _workspace` resolves from the test modules themselves.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "tests"))


# ---------------------------------------------------------------------------
# The sibling checkouts are READ, never written. The router checkout beside
# this repo may be a live working tree someone else is committing to, and a
# test that stages a stand-in at the resolved checkout's path overwrites the
# router's committed `docker/derive-mounts.py` with it. This guard
# fingerprints that checkout's working tree before the session and asserts
# it unchanged after, so such a test fails by name here instead of being
# found later by whoever owns the checkout. A --check that writes into a running
# agent's outbox is not a check; a suite that writes into a sibling checkout
# is the same sentence one level up. The fingerprint is the WORKING TREE's
# state (status + diff), not HEAD: a commit made in that checkout by its
# own session during the run leaves a clean tree clean; an edit made there
# during the run shows up here and is attributed to the suite — the
# message prints both fingerprints so a reader can tell which it was.
import pytest  # noqa: E402


def _router_root():
    try:
        import _workspace
        return _workspace.ROUTER_ROOT
    except Exception:  # no sibling resolvable — nothing to guard
        return None


@pytest.fixture(scope="session", autouse=True)
def _sibling_checkouts_are_not_written():
    import _workspace
    root = _router_root()
    before = _workspace.checkout_fingerprint(root) if root else None
    yield
    if before is None:
        return
    after = _workspace.checkout_fingerprint(root)
    if after != before:
        raise AssertionError(
            f"the test session CHANGED the router checkout at {root} — a test wrote "
            f"into a sibling working tree. Before/after `git status --porcelain` + "
            f"`git diff`:\n--- before ---\n{before}\n--- after ---\n{after}")


# ---------------------------------------------------------------------------
# DOCKER AND THE ROUTER ARE NEVER RUN BY THE SUITE. `verify` reads the
# router process through `router_health.run` — `docker ps`, `docker
# inspect`, and the router's own run.sh one-shots — and a test that reached
# it unpatched would read the OPERATOR'S live router (or, through run.sh,
# START one against a fixture config). So for the whole session `run`
# refuses with a named CannotRun, which every caller reports as UNKNOWN: a
# verify that reaches the router sections from a test sees "could not
# tell", never the host. The router_health tests patch below this with what
# the producers really print.
@pytest.fixture(scope="session", autouse=True)
def _docker_and_the_router_are_never_run_by_the_suite():
    import router_health as rh

    def refuse(argv, *a, **k):
        raise rh.CannotRun(f"the test suite never runs docker or the router; patch "
                           f"router_health.run for {argv[0]!r}")

    real_run = rh.run
    refuse.__wrapped__ = real_run          # the one test that wants the real one
    rh.run = refuse
    yield
    rh.run = real_run
