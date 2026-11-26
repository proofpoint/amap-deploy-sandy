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
    'RUNNER.STAGE_SET': "Look at the command's arguments: an L1 that runs S6 or a later stage must also run S3.",
    # PROPOSED for DS (W8 r4.1; Dan ALPHA2-W8-ROTATE-FALLBACK): the parser's refusal.
    'RUNNER.ROTATE_UNSUPPORTED': 'Look at the command: --rotate-key is disabled in this release.',
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
    'PREFLIGHT.PRIVATE_SOURCE': "Look at the private overlay checkout: a file is not from it, its working tree is not exactly the tagged commit's tree, a file's bytes differ from that tree, or the tagged commit does not meet the lock's overlay pin.",
    'PREFLIGHT.REPO_ACCESS': 'Look at access to the repository named in the receipt.',
    'PREFLIGHT.FETCH': 'Look at the work directory: a pinned commit was not fetched, or its pinned tag is not that commit.',
    'PREFLIGHT.TARGET_ACCESS': 'Look at access to the target named in the receipt.',
    'PREFLIGHT.HUB_READ': "Look at the hub's read-only checks in the receipt.",
    'PREFLIGHT.OPERATOR_ROUTE': "Look at the operator's ssh route from the runner host to the target named in the receipt.",
    'PREFLIGHT.LIVE_DEPLOY': "Look at the work directory: it is the runner host's live deploy.",
    'PREFLIGHT.KEEP_AWAKE': "Look at the runner host's sleep settings: sleep is not shown disabled.",
    'PREFLIGHT.SURVEY': 'Look at the survey in the receipt: an l3 target differs from the bare start state, or a loop target is not at its pinned snapshot.',
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

#: S7's own names (W8, PROPOSED for contract 4.6 and 4.7; DS folds them).
AGENTS_SENTENCES = {
    'AGENTS.NO_START_PATH': "Look at the agent's start path named in the receipt: sandy's approvals, the credential or the sandbox image would not let it start.",
    'AGENTS.ADD_AGENT_AMBIGUOUS': 'Look at alpha2.hosts: the agents named for this host do not pick exactly one agent to add.',
    'AGENTS.CONFIG_NOT_PLACED': "Look at S6's receipt for this VM and the VM's amap feature files: they are not placed, or differ from what S6 recorded.",
    'AGENTS.VM_ACCESS': 'Look at access to the VM named in the receipt.',
    'AGENTS.WRITER': "Look at the credential writer on the VM: it refused or failed.",
    'AGENTS.IMAGE_BUILD': "Look at sandy's sandbox image build on the VM: it did not finish.",
    'AGENTS.SLUG_UNOBSERVED': "Look at sandy's state for the workspace: the sandbox name could not be read.",
    'AGENTS.SLUG_TOO_LONG': "Look at alpha2.hosts: an agent's id makes a sandbox name longer than the agent registry accepts.",
    'AGENTS.REGISTRY': "Look at the agent's registry entry on the VM named in the receipt: the registry program refused its import, or its read-back does not match.",
    'AGENTS.ROTATE_LEFTOVER': "Look at the VM's sandy secrets directory: a previous credential file is left from a rotation.",
    'AGENTS.SECRETS_TEMP_LEFTOVER': "Look at the VM's sandy secrets directory: a temporary credential file is left from an interrupted write.",
    'AGENTS.ROTATE_UNDONE': 'Look at the rotation in the receipt: the new credential did not take, and the old one is back in force.',
    # PROPOSED for DS (Dan ALPHA2-W8-ROTATE-FALLBACK): --rotate-key is not in ALPHA-2.
    'AGENTS.ROTATE_UNSUPPORTED': 'Look at the ALPHA-2 scope: key rotation is not supported in this release; rotate by hand.',
}

STAGE_SENTENCES = {
    'LOCK': 'Look at alpha2.lock: it is unreadable, fails its schema, or changed since S0 read it.',
    'HOSTS': 'Look at alpha2.hosts: it is unreadable, fails its schema, or changed since S0 read it.',
    'PREDECESSOR_MISSING': 'Look at the run directory: a predecessor stage has no receipt.',
    'PREDECESSOR_INCOMPLETE': 'Look at the predecessor receipt: it is unfinished, malformed, or not bound to this run.',
    'PREDECESSOR_FAILED': 'Look at the predecessor receipt: its stage did not pass.',
    'PREDECESSOR_INSTALLER': 'Look at the predecessor receipt: a different installer wrote it.',
    'PIN': 'Look at the pin in alpha2.lock and the file, image or commit it names: they differ.',
    'TARGET_ACCESS': 'Look at the VM named in the receipt: the route to it failed, timed out, or is not configured.',
    'EXISTS_DIFFERENT': 'Look at the router key on the VM named in the receipt: a key is already there, and the router.json there names another.',
    'INTERPRETER': 'Look at the VM named in the receipt: its python3 is older than the release the stage requires.',
    'CLOCK': "Look at the run scope's hub clock: it differs from this machine's by more than the allowed skew, or could not be read.",
    'HUB_NAME': "Look at alpha2.hosts: the run's hub name is not a host key of the pinned inventory.",
    'HUB_HOSTNAME': "Look at this run's S3 receipt: its HUB_HOSTNAME fact, the hub's mail server hostname, is missing or malformed.",
    'ROUTER_REFUSED': "Look at router.json on the VM named in the receipt: the router's own check of it failed.",
    'PEER_STORE': "Look at the router's peer store on the VM named in the receipt: it is not ready with admission open, or its initialisation failed; it is never retried or repaired.",
    'REGISTRY': "Look at the router's registry entry on the VM named in the receipt: the registry program refused it, or its read-back does not match.",
    'CLOCK_SKEW': "Look at the clocks of the run's two VMs: they differ by more than 2 s, or one could not be read; nothing was started.",
    'TRUSTDIR_MOUNTED': "Look at the containers' mounts on the VM named in the receipt: a mount makes a router or relay trust directory, or the plugin's root path, visible inside a sandbox or the router's container, or a container S8 started or checks can reach the docker daemon (its socket, the docker group, or privileged).",
    'TRUSTDIR_UNREAD': "Look at the VM named in the receipt: a router or relay trust path S8 derives from S6's env-file and the agent home (the files S6 placed included) lies outside its allowed root (the relay home for the relay's paths, the agent home or the plugin's directory for the rest); or such a path, or a bind source of an agent sandbox or of the router's container, is missing, malformed or not its own path (a symlink in it) when its owning account resolves it; or S6's env-file could not be read or names a key the relay must not be given, or the docker group could not be read, or a container's mount table or host config could not be read or holds a mount the check cannot judge; the trust directories could not be shown clear.",
    'CONFIG_CHANGED': "Look at what S6 placed on the VM named in the receipt: a file no longer matches S6's receipt, the plugin's or the env-file's owner or mode moved, router.json and the env-file name different paths or another plugin path, or the relay ledger directory is gone or not reachable as the relay account; nothing was started on that VM.",
    'RUNNING': "Look at the VM named in the receipt: a router or relay container of this installer already exists there, or the relay ledger is already initialised; restore the VM, never re-run onto it.",
    'RL_REFUSED': "Look at the router on the VM named in the receipt: its start script refused, its container could not be inspected, or it exited, restarted or never polled, and the script's error or the container's logs name the reason; a started container was stopped, not removed.",
    'NOT_ADMITTING': "Look at the router's status on the VM named in the receipt: its first poll broke one of the six admission conditions; it was stopped, not removed.",
    'LEDGER_UNUSABLE': "Look at the relay ledger directory on the VM named in the receipt: it is not the relay account's own 0700 directory (its owner, mode or type), or RE's own read-only check reports it unusable or gave no report S8 could read; nothing was started on that VM.",
    'RE_REFUSED': "Look at the relay on the VM named in the receipt: its one-shot ledger init failed (a failed init leaves no container and no logs), or its container refused or never became healthy, and that container's logs name the reason; a started container was stopped, not removed.",
    'FINGERPRINT': "Look at the router image on the VM named in the receipt: its router package is not exactly the pinned router's.",
    'REVISION': 'Look at the image on the VM named in the receipt: its revision label is not the commit alpha2.lock pins for it.',
    'READBACK': 'Look at the image on the VM named in the receipt: a file under its working directory has another owner or mode, or the user it runs as cannot read a file it needs.',
    'OPENSSL': 'Look at the image on the VM named in the receipt: it has no openssl command, or one older than 3.0.',
    'RE_FIX': "Look at the relay's commit in alpha2.lock: it does not include the relay's fix for the hop wedge; nothing was written.",
    'DOCKER': 'Look at docker on the VM named in the receipt: it is not installed, or the agent account cannot reach the daemon.',
    'LOAD': "Look at the image archive and the VM named in the receipt: docker load of the archive failed; an image that loaded in part is never run, and the VM's recovery is a restore.",
    'ID_MISMATCH': "Look at the image archive and alpha2.lock: the archive loaded on the VM named in the receipt, but the image Id alpha2.lock pins is not there; the VM's recovery is a restore.",
    'PLACED_DIFFERENT': "Look at the directory on the VM named in the receipt: a file the stage places is there and differs, or the directory holds a name the stage does not place; nothing is ever replaced.",
    'OWNER': 'Look at the path on the VM named in the receipt: it, or a directory above it, has another owner, group or mode than the stage requires; it is never repaired.',
    'NOT_RESTORED': "Look at the receipt's final observed state: a write failed and the restore did not complete.",
    'UNCLASSIFIED': "Look at the receipt's final observed state: this stage failed in a way it does not name.",
}

#: Exit code of each runner-level cause. RUNNER.CUSTODY and
#: RUNNER.OUTPUT_GUARD are 3 once the run has written to a target; the
#: launcher and S0 admission write nothing, so 2 is right for them here.
EXIT = {
    "RUNNER.SUMS": 4,
    "AGENTS.ROTATE_UNDONE": 3,
}
DEFAULT_EXIT = 2
#: Stage causes that arise only after the stage's first write: they exit 3, never 2, and 4.2's Exit cell says "3".
#: The constructor refuses them without rc=3, so the code cannot give the exit the contract rules out.
AFTER_WRITE_ONLY = frozenset({"NOT_RESTORED", "RE_REFUSED", "RL_REFUSED", "NOT_ADMITTING", "LOAD", "ID_MISMATCH"})
#: Stage causes that arise only before the stage's first write: they exit 2, never 3, and 4.2's Exit cell says "2".
#: The constructor refuses them at rc=3.
BEFORE_WRITE_ONLY = frozenset({"CLOCK", "CLOCK_SKEW", "RE_FIX", "HUB_HOSTNAME", "HUB_NAME", "PREDECESSOR_FAILED",
                               "PREDECESSOR_INCOMPLETE", "PREDECESSOR_INSTALLER", "PREDECESSOR_MISSING"})


class Refusal(Exception):
    """A refusal with a contract cause. `detail` is a fixed, value-free
    pointer (a check number and JSON path, or a target name the contract
    allows the message to name); it is never formatted from an input."""

    def __init__(self, cause, detail=None, rc=None):
        if sentence(cause) is None:
            raise ValueError("cause not in the contract table")
        if rc is not None and not (rc == 3 and _two_or_three(cause)):
            raise ValueError("exit code not allowed for this cause")
        if cause.partition(".")[2] in AFTER_WRITE_ONLY and rc != 3:
            raise ValueError("this cause arises only after a write: rc=3")
        if cause.partition(".")[2] in BEFORE_WRITE_ONLY and rc == 3:
            raise ValueError("this cause arises only before a write: never rc=3")
        super().__init__(cause)
        self.cause = cause
        self.detail = detail
        self._rc = rc

    @property
    def rc(self):
        if self._rc is not None:
            return self._rc
        if self.cause.endswith(".NOT_RESTORED"):
            return 3  # 4.2: NOT_RESTORED exits 3
        return EXIT.get(self.cause, DEFAULT_EXIT)


#: The prefixes whose causes come before any write to a target: the runner and launcher, S0 and S1.
NOT_WRITING_PREFIXES = ("RUNNER", "PREFLIGHT", "CREDENTIALS")


def _two_or_three(cause):
    """Causes whose exit is 2 or 3 by whether a write happened (3.4, 4.2, 4.3): RUNNER.CUSTODY and
    RUNNER.OUTPUT_GUARD, every UNCLASSIFIED, and every cause of a stage that writes. A stage's cause exits 2 before
    the stage's first write and 3 after it, keeping its name: exit 2 always means the stage wrote nothing."""
    if cause in ("RUNNER.CUSTODY", "RUNNER.OUTPUT_GUARD") or cause.endswith(".UNCLASSIFIED"):
        return True
    stage, _, name = cause.partition(".")
    return stage not in NOT_WRITING_PREFIXES and (name in STAGE_SENTENCES or cause in AGENTS_SENTENCES)


def sentence(cause):
    if cause in RUNNER_SENTENCES:
        return RUNNER_SENTENCES[cause]
    if cause in CREDENTIALS_SENTENCES:
        return CREDENTIALS_SENTENCES[cause]
    if cause in AGENTS_SENTENCES:
        return AGENTS_SENTENCES[cause]
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
