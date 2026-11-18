"""Run id and run directory (section 5.2).

The work directory `<HOME>/alpha2-work` and its `runs` directory must
already exist, each a real directory (not a symlink) owned by the run's
account with mode 0700. They are opened as directory descriptors without
following symlinks and checked with fstat; the run directory and its
`receipts` are created relative to those pinned descriptors, and the run
directory is handed on as a descriptor, never as a path to re-resolve.
"""

import os
import stat
import time

from a2_causes import Refusal
from a2_private import matches

#: The work directory's name inside `HOME`. Section 5.2 places it in
#: `HOME`; this name is submitted to the S0 review with the D3 paths.
WORK_NAME = "alpha2-work"
RUNS_NAME = "runs"
RECEIPTS_NAME = "receipts"
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def mint_run_id(now=None, rand=os.urandom):
    """`YYYYMMDDTHHMMSSZ-<8 hex>`, for a command that writes no target
    (5.1a step 3). A target-writing run's id is the broker's (5.3c)."""
    t = time.gmtime(time.time() if now is None else now)
    rid = time.strftime("%Y%m%dT%H%M%SZ", t) + "-" + rand(4).hex()
    assert matches("run_id", rid)
    return rid


def _check_dir_fd(fd, uid):
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != uid or stat.S_IMODE(st.st_mode) != 0o700:
        raise Refusal("RUNNER.RUN_DIR")


def _open_dir_at(name, dir_fd):
    try:
        return os.open(name, DIR_FLAGS, dir_fd=dir_fd)
    except OSError:
        raise Refusal("RUNNER.RUN_DIR")


def open_runs(home, uid):
    """The pinned `runs` directory descriptor. HOME is the account
    database's home (checked against the environment by RUNNER.ENV);
    below it, nothing is followed and nothing is created."""
    try:
        home_fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError:
        raise Refusal("RUNNER.RUN_DIR")
    try:
        work_fd = _open_dir_at(WORK_NAME, home_fd)
    finally:
        os.close(home_fd)
    try:
        _check_dir_fd(work_fd, uid)
        runs_fd = _open_dir_at(RUNS_NAME, work_fd)
    finally:
        os.close(work_fd)
    try:
        _check_dir_fd(runs_fd, uid)
    except Refusal:
        os.close(runs_fd)
        raise
    return runs_fd


def create_in(runs_fd, run_id, uid):
    """A new `<run_id>/` with `receipts/` inside, relative to the pinned
    `runs` descriptor. An existing entry of that name refuses. Returns the
    run directory's descriptor."""
    if not matches("run_id", run_id):
        raise Refusal("RUNNER.RUN_DIR")
    try:
        os.mkdir(run_id, 0o700, dir_fd=runs_fd)
    except OSError:
        raise Refusal("RUNNER.RUN_DIR")
    run_fd = _open_dir_at(run_id, runs_fd)
    try:
        _check_dir_fd(run_fd, uid)
        try:
            os.mkdir(RECEIPTS_NAME, 0o700, dir_fd=run_fd)
        except OSError:
            raise Refusal("RUNNER.RUN_DIR")
    except Refusal:
        os.close(run_fd)
        raise
    return run_fd


def create_run_dir(home, run_id, uid):
    """Both steps; returns the run directory's descriptor."""
    if not matches("run_id", run_id):
        raise Refusal("RUNNER.RUN_DIR")
    runs_fd = open_runs(home, uid)
    try:
        return create_in(runs_fd, run_id, uid)
    finally:
        os.close(runs_fd)
