"""Dispatch: the launcher, or the runner the launcher execs (5.1a step 5).

The runner is this same entry started as
  ... alpha2_install.py --runner --run-id <run_id> [the operator's flags]
That form is not a supported invocation: started any other way than by an
admitting process, it still meets S0's admission and refuses there.
"""

import signal
import threading

import a2_admit
import a2_causes
import a2_git
import a2_guard
import a2_record
import a2_s0
import a2_s1
import a2_s10
from a2_causes import Refusal
from a2_site import Site

#: The point where package 2a ends: S0 has passed and its receipt is
#: written; S1 to S10 follow it (package 2b).
NOT_BUILT = "RUNNER.UNCLASSIFIED"


def main(argv, installer_sha, entry, site=None):
    site = site if site is not None else Site()
    site.installer_sha = installer_sha
    site.entry = entry
    # The one writer (3.3): every line the run prints, refusals included.
    if site.guard is None:
        site.guard = a2_guard.OutputGuard()
    try:
        if argv[:2] == ["--runner", "--run-id"] and len(argv) >= 3:
            stops = _Stops()
            try:
                return run(argv[2], argv[3:], site, stops)
            except KeyboardInterrupt:
                # A SIGINT after the hand-back is this process's own: the
                # run has ended its closeout, so the process ends as an
                # interrupt does, with nothing more printed.
                if stops.closed:
                    return SIGINT_EXIT
                raise
        a2_admit.launch(argv, site)
        raise Refusal("RUNNER.UNCLASSIFIED")
    except Refusal as r:
        return a2_causes.report(r, site.out, site.guard)
    except (Exception, KeyboardInterrupt):
        # Before a run directory exists nothing has been written by the run:
        # rc 2 (3.4). After it, run() has already recorded the failure.
        return a2_causes.report(Refusal("RUNNER.UNCLASSIFIED"), site.out, site.guard)


#: The exit code of a process an interrupt ends (128 + SIGINT).
SIGINT_EXIT = 128 + signal.SIGINT


class RunStopped(KeyboardInterrupt):
    """A stop signal (INT, TERM, HUP or QUIT) received by the runner outside
    S1's prompt. An interrupt like Ctrl-C, so every path that finishes the
    record for an interrupt finishes it for these too."""


class _Stops:
    """For the whole run, in the main thread only: the first stop signal
    raises RunStopped. From that moment, and from the start of the
    record's closeout (`holding`), a further stop is recorded in `pending`
    and not raised, so nothing cuts the closeout short. S1's prompt puts
    in its own handlers and gives these back when it ends.

    The run hands stop ownership back to the caller at one point: the
    successful block of the stop signals in `__exit__`. A stop raised
    before it is the run's, and is held. A stop raised from it on is the
    caller's: it stays pending until all four of the caller's handlers and
    the caller's mask are back, and is then delivered to the caller's
    handler once, still inside `__exit__`. `closed` is set once the run
    has ended its closeout and raises its own cause."""

    def __init__(self):
        self.holding = False
        self.pending = None
        self.closed = False
        self.saved = {}

    def _handler(self, signum, frame):
        if self.holding:
            self.pending = signum
            return
        self.holding = True
        raise RunStopped()

    def __enter__(self):
        if threading.current_thread() is threading.main_thread():
            for sig in a2_s1.STOP_SIGNALS:
                self.saved[sig] = signal.signal(sig, self._handler)
        return self

    def __exit__(self, *exc):
        self.holding = True
        if not self.saved:
            return False
        # The hand-back. The caller's mask is read first. The successful
        # block is the boundary: a stop raised before it ran this object's
        # handler (Python runs pending handlers inside pthread_sigmask). The
        # four handlers go back while the stops are blocked, so no stop sees
        # a mix of ours and the caller's. Putting the caller's mask back
        # delivers a stop raised since the block to the caller's handler. A
        # stop the caller itself blocks stays pending. If a restore fails,
        # the caller's mask is still put back and the failure is raised.
        old = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        try:
            signal.pthread_sigmask(signal.SIG_BLOCK, a2_s1.MASKED)
            for sig, handler in self.saved.items():
                signal.signal(sig, handler)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, old)
        return False


CUSTODY_KEYS = ("CUSTODY_LOCKS", "CUSTODY_PLACEMENT", "CUSTODY_STOP")
UNOBSERVED_CUSTODY = [(k, "UNOBSERVED") for k in CUSTODY_KEYS]
#: S10's cause when its custody read-back raises.
UNREAD_AT_S10 = a2_record.STAGE_NAME["S10"] + ".UNCLASSIFIED"


def _custody_cause(facts, wrote_target):
    """5.3b at a boundary after S0: a set stop or any other mismatch is
    RUNNER.CUSTODY (rc 3 once a target was written, else 2)."""
    ok = (facts["CUSTODY_LOCKS"] == "held" and facts["CUSTODY_PLACEMENT"] == "match"
          and facts["CUSTODY_STOP"] in ("unset", "-"))
    return None if ok else "RUNNER.CUSTODY"


def run(run_id, argv, site, stops=None):
    """The runner: S0's admission, then S0, S1 and, whatever happened, S10.

    Once the run directory exists, every way out leaves a finished record:
    a named cause has its FAIL receipt (S0's named causes rc 2, contract 3.4
    as e4 states it); any other failure is UNCLASSIFIED with rc 3, recorded
    in a FAIL receipt for the stage that was running when none was written.
    S10 then writes its receipt, the final manifest and the summary, so
    SUMS verifies, even when its custody read-back cannot be made. S2 to
    S9 are not built in this package: a run that reaches them stops with
    RUNNER.UNCLASSIFIED, rc 3.

    A stop signal outside the prompt is an interrupt like any other (the
    running stage's UNCLASSIFIED, then S10). A stop that arrives once the
    closeout has begun is held and changes nothing: the record is
    finished, and the run ends with its own cause and rc. Stop ownership
    goes back to the caller at the hand-back's block (`_Stops`); `stops`
    is the caller's view of it."""
    if stops is None:
        stops = _Stops()
    with stops:
        _run(run_id, argv, site, stops)


def _run(run_id, argv, site, stops):
    c = a2_admit.admit(run_id, argv, site)
    guard = site.guard if site.guard is not None else a2_guard.OutputGuard()
    rec = None
    held = None
    stop = None
    active = "S0"
    s1_custody = None
    try:
        if site.git is None:
            site.git = a2_git.Git(a2_git.env_for(c.home, site.environ.get("SSH_AUTH_SOCK", "")))
        rec = a2_record.Run(c.run_fd, guard, run_id, c.inv.command, c.inv.loop, site.installer_sha,
                            c.lock_sha, c.hosts_sha, now=site.now)
        rec.write_manifest(final=False)
        a2_s0.run_s0(c, site, rec)
        active = "S1"
        facts = a2_s0.custody(c, site)
        s1_custody = [(k, facts[k]) for k in CUSTODY_KEYS]
        cause = _custody_cause(facts, guard.wrote_target)
        if cause:
            rec.write_receipt("S1", None, rec.started, "FAIL", s1_custody, rc=2, cause=cause)
            raise Refusal(cause)
        held = a2_s1.run_s1(c, site, rec, guard, s1_custody)
        stop = Refusal(NOT_BUILT, rc=3)
    except Refusal as r:
        stops.holding = True
        stop = r
    except BaseException:
        stops.holding = True
        # A failure the running stage does not name (3.4), an interrupt
        # included: that stage's UNCLASSIFIED, rc 3, recorded in its own
        # receipt if it has none. S1's carries the custody read-back taken
        # before it (5.3b), UNOBSERVED if that read did not complete.
        cause = a2_record.STAGE_NAME[active] + ".UNCLASSIFIED"
        if rec is not None and not any(s["stage"] == active for s in rec.stages):
            facts = []
            if active == "S1":
                facts = s1_custody if s1_custody is not None else UNOBSERVED_CUSTODY
            try:
                rec.write_receipt(active, None, rec.started, "FAIL", facts, rc=3, cause=cause)
            except Exception:
                pass
        stop = Refusal(cause, rc=3)
    finally:
        stops.holding = True
        if held is not None:
            held.clear()
        guard.release_all()
    if rec is not None and not rec.final:
        try:
            try:
                facts = a2_s0.custody(c, site)
                cause, rc = _custody_cause(facts, guard.wrote_target), 2
            except (Exception, KeyboardInterrupt):
                # 3.4: a read-back S10 cannot make, an interrupt included,
                # is its own UNCLASSIFIED, rc 3, with every custody fact
                # UNOBSERVED; the receipt, the final manifest and the
                # summary are still written.
                facts = dict.fromkeys(CUSTODY_KEYS, "UNOBSERVED")
                cause, rc = UNREAD_AT_S10, 3
            a2_s10.run_s10(c, site, rec, guard, facts, cause, rc)
            if rc == 3 and (stop is None or stop.rc < 3):
                stop = Refusal(UNREAD_AT_S10, rc=3)
        except BaseException:
            _finish(rec)
            if stop is None or stop.rc < 3:
                stop = Refusal("SUMMARY.UNCLASSIFIED", rc=3)
    stops.closed = True
    raise stop


def _finish(rec):
    """Make the manifest final, once, if the record exists."""
    if rec is None or rec.final:
        return
    try:
        rec.write_manifest(final=True)
    except Exception:
        pass
