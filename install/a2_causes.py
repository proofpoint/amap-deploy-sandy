"""Cause names, exit codes and fixed sentences (stage contract, sections 4.3,
4.4 and 4.7).

A refusal prints exactly one cause line and one sentence. The sentence is
the contract's fixed text with `<STAGE>` replaced by the stage NAME and
nothing else substituted: it never carries a value. A cause not in this
table cannot be raised.
"""

import sys

RUNNER_SENTENCES = {
    'RUNNER.ENV': 'Look at the launch line: the environment holds a variable it does not allow.',
    'RUNNER.ARGS': "Look at the command's arguments: one does not match its pattern.",
    'RUNNER.HOSTS_TARGETS': 'Look at alpha2.hosts: two targets share a name.',
    'RUNNER.LOCK_ROOT': 'Look at the runner entry in alpha2.hosts and the lock root: this host or its lock root is not the one named there, or the lock root or a lock file is missing or not owned and moded as required.',
    'RUNNER.TARGET_LOCKED': 'Look at the target named in the message: another run holds its lock.',
    'RUNNER.CUSTODY': 'Look at the custody facts in the receipt: lock, placement or the stop file changed at a stage boundary.',
    'RUNNER.RUN_DIR': 'Look at the work directory: the run directory exists or cannot be created.',
    'RUNNER.SUMS': 'Look at SUMS in the run directory: the chain does not verify.',
    'RUNNER.OUTPUT_GUARD': 'Look at the stage that was writing: it tried to print a held value.',
    'RUNNER.ADMISSION': 'Look at how the run was started: without the held locks of this run or, for a command that can write to a target, its broker record, or with ones that do not bind it.',
    'RUNNER.ACCOUNT': 'Look at the account the run was started as: it is not the runner account this command needs.',
    'RUNNER.DESTROY_DENY': 'Look at alpha2.hosts: destroy needs its destroy_deny list.',
    'RUNNER.NOT_STARTED': "Look at budget.d and the launcher's exec of the runner: no runner started, and a start record written for it stays counted.",
    'PREFLIGHT.MAC_TOOLS': "Look at the runner host's tools: one is missing or not at its recorded version.",
    'PREFLIGHT.INTERPRETER': 'Look at the interpreter and the installer files: a hash differs from alpha2.lock.',
    'PREFLIGHT.NET_RUNTIME': "Look at NET's runtime on the runner host: it is missing or cannot run offline.",
    'PREFLIGHT.LEAK_LOCK': 'Look at alpha2.lock: it fails the leak check named in the receipt.',
    'PREFLIGHT.LEAK_HOSTS': 'Look at alpha2.hosts: it fails the leak check named in the receipt.',
    'PREFLIGHT.PRIVATE_SOURCE': "Look at the private overlay checkout: a file is not from it, it is not clean at a commit, a file's bytes differ from its blob at HEAD, or it does not meet the lock's overlay pin and tag.",
    'PREFLIGHT.REPO_ACCESS': 'Look at access to the repository named in the receipt.',
    'PREFLIGHT.FETCH': 'Look at the work directory: a pinned commit was not fetched, or its pinned tag is not that commit.',
    'PREFLIGHT.TARGET_ACCESS': 'Look at access to the target named in the receipt.',
    'PREFLIGHT.HUB_READ': "Look at the hub's read-only checks in the receipt.",
    'PREFLIGHT.OPERATOR_ROUTE': "Look at the operator's ssh route from the runner host to the target named in the receipt.",
    'PREFLIGHT.LIVE_DEPLOY': "Look at the work directory: it is the runner host's live deploy.",
    'PREFLIGHT.KEEP_AWAKE': "Look at the runner host's sleep settings: sleep is not shown disabled.",
    'PREFLIGHT.SURVEY': 'Look at the survey in the receipt: an l3 target differs from the bare start state.',
    'PREFLIGHT.HANDOFF': "Look at the stop file, the hypervisor's loop tasks and, for an L3 or bare install or a destroy, the hypervisor's L3 arm gate: one does not allow this run.",
    'PREFLIGHT.BUDGET': "Look at the loop's budget: the day's runs are used up, its account usage is not shown below the limit, the broker refused the start record, or budget.d could not be read.",
}

CREDENTIALS_SENTENCES = {
    'CREDENTIALS.CORE_LIMIT': 'Look at the core-dump limit: it could not be set to zero.',
    'CREDENTIALS.NO_ECHO': 'Look at the terminal: the prompt could not read without echo.',
    'CREDENTIALS.FORM': 'Look at the value named by its form rule in the receipt: it is not well formed.',
    'CREDENTIALS.KEY_NOT_LIVE': 'Look at the API key: the live check did not accept it.',
    'CREDENTIALS.LEAK_LOCK': 'Look at alpha2.lock: it contains a value entered at the prompt.',
    'CREDENTIALS.LEAK_HOSTS': 'Look at alpha2.hosts: it contains a value entered at the prompt.',
}

STAGE_SENTENCES = {
    'LOCK': 'Look at alpha2.lock: it is unreadable, fails its schema, or changed since S0 read it.',
    'HOSTS': 'Look at alpha2.hosts: it is unreadable, fails its schema, or changed since S0 read it.',
    'PREDECESSOR_MISSING': 'Look at the run directory: a predecessor stage has no receipt.',
    'PREDECESSOR_INCOMPLETE': 'Look at the predecessor receipt: it is unfinished, malformed, or not bound to this run.',
    'PREDECESSOR_FAILED': 'Look at the predecessor receipt: its stage did not pass.',
    'PREDECESSOR_INSTALLER': 'Look at the predecessor receipt: a different installer wrote it.',
    'PIN': 'Look at the pin in alpha2.lock and the file, image or commit it names: they differ.',
    'NOT_RESTORED': "Look at the receipt's final observed state: a write failed and the restore did not complete.",
    'UNCLASSIFIED': "Look at the receipt's final observed state: this stage failed in a way it does not name.",
}

#: Exit code of each runner-level cause. RUNNER.CUSTODY and
#: RUNNER.OUTPUT_GUARD are 3 once the run has written to a target; the
#: launcher and S0 admission write nothing, so 2 is right for them here.
EXIT = {
    "RUNNER.SUMS": 4,
}
DEFAULT_EXIT = 2


class Refusal(Exception):
    """A refusal with a contract cause. `detail` is a fixed, value-free
    pointer (a check number and JSON path, or a target name the contract
    allows the message to name); it is never formatted from an input."""

    def __init__(self, cause, detail=None, rc=None):
        if sentence(cause) is None:
            raise ValueError("cause not in the contract table")
        if rc is not None and not (rc == 3 and _two_or_three(cause)):
            raise ValueError("exit code not allowed for this cause")
        super().__init__(cause)
        self.cause = cause
        self.detail = detail
        self._rc = rc

    @property
    def rc(self):
        if self._rc is not None:
            return self._rc
        return EXIT.get(self.cause, DEFAULT_EXIT)


def _two_or_three(cause):
    """Causes whose exit is 2 or 3 by whether a write happened (4.2, 4.3)."""
    return cause in ("RUNNER.CUSTODY", "RUNNER.OUTPUT_GUARD") or cause.endswith(".UNCLASSIFIED")


def sentence(cause):
    if cause in RUNNER_SENTENCES:
        return RUNNER_SENTENCES[cause]
    if cause in CREDENTIALS_SENTENCES:
        return CREDENTIALS_SENTENCES[cause]
    stage, _, name = cause.partition(".")
    text = STAGE_SENTENCES.get(name)
    if text is None or not stage:
        return None
    return text


def report(refusal, stream=None, guard=None):
    """Print the one cause line, the sentence, and the detail if any, every
    line through the run's output guard (3.3). A line the guard refuses is
    not written; the report then becomes RUNNER.OUTPUT_GUARD, whose fixed
    lines pass the same guard or are not written either. Returns the exit
    code."""
    out = stream if stream is not None else sys.stderr
    lines = ["CAUSE=" + refusal.cause, sentence(refusal.cause)]
    if refusal.detail:
        lines.append(refusal.detail)
    rc = refusal.rc
    if guard is not None:
        try:
            for ln in lines:
                guard.check(ln)
        except Refusal as g:
            rc = g.rc
            lines = ["CAUSE=" + g.cause, sentence(g.cause)]
            try:
                for ln in lines:
                    guard.check(ln)
            except Refusal:
                lines = []
    for ln in lines:
        out.write(ln + "\n")
    out.flush()
    return rc
