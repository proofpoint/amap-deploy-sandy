"""Locate the router this deployment is checked against.

The router owns the namespace skeleton; this side owns the sandbox wiring, and
the two must agree — which is what `test_layout_agreement.py` pins. The router
is a separate repository, found by walking up until a directory contains it
rather than by counting parent levels, so this holds at any nesting depth.
`$AMAP_ROUTER_REPO` overrides; `$AMAP_WORKSPACE` names the directory to look in.

The directory name is duplicated from `fleet_policy.ROUTER_REPO_NAME` rather
than imported: this helper is imported by every suite, including ones that run
before the repository root is on `sys.path`, and a test helper that can fail to
import takes the whole run with it. Keep the two in step.
"""

import os
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve()

# Keep in step with `fleet_policy.ROUTER_REPO_NAME`.
_ROUTER_REPO_NAME = "amap-router-local"


def router_root() -> Path:
    env = os.environ.get("AMAP_ROUTER_REPO")
    if env:
        return Path(env).resolve()
    ws = os.environ.get("AMAP_WORKSPACE")
    roots = [Path(ws).resolve()] if ws else list(_HERE.parents)
    for cand in roots:
        if (cand / _ROUTER_REPO_NAME).is_dir():
            return cand / _ROUTER_REPO_NAME
    base = roots[-1] if roots else _HERE.parent
    return base / _ROUTER_REPO_NAME


ROUTER_ROOT = router_root()


def skip_if_incomplete() -> None:
    """A missing router is an unsatisfied precondition, not a defect here."""
    if not ROUTER_ROOT.is_dir():
        raise unittest.SkipTest(
            f"router checkout not found at {ROUTER_ROOT} — set $AMAP_ROUTER_REPO "
            f"or check out {_ROUTER_REPO_NAME} beside this repository")


def checkout_fingerprint(root):
    """`git status --porcelain` plus `git diff` of the checkout at `root`, as
    one string — the working tree's state against its index and HEAD, which
    is what a test that writes into a sibling checkout changes. `None` when
    `root` is not a git checkout (nothing to guard, never a silent match)."""
    import subprocess
    try:
        status = subprocess.run(["git", "-C", str(root), "status", "--porcelain"],
                                capture_output=True, text=True, check=True).stdout
        diff = subprocess.run(["git", "-C", str(root), "diff"],
                              capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return status + "\n" + diff


# The Codex connector, found the same way. Keep in step with
# `amap_sandy.CODEX_CONNECTOR_REPO_NAME`.
_CODEX_CONNECTOR_REPO_NAME = "amap-connector-codex"


def codex_connector_root() -> Path:
    env = os.environ.get("AMAP_CODEX_CONNECTOR_REPO")
    if env:
        return Path(env).absolute()
    for cand in _HERE.parents:
        if (cand / _CODEX_CONNECTOR_REPO_NAME / "src" / "amap_codex").is_dir():
            return cand / _CODEX_CONNECTOR_REPO_NAME
    return _HERE.parents[2] / _CODEX_CONNECTOR_REPO_NAME


CODEX_CONNECTOR_ROOT = codex_connector_root()
