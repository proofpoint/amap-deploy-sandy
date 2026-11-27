"""What the launcher and S0 read from the runner host, in one place.

Each input that the contract leaves to a later review is a named slot here
and FAILS CLOSED until that review fills it: a probe that is not supplied
answers UNOBSERVED, and an unset path refuses. Nothing here guesses.
"""

import hashlib
import os
import pwd
import re
import sys

import a2_git

UNOBSERVED = "UNOBSERVED"

#: The private overlay checkout S0 reads `alpha2.lock` and `alpha2.hosts`
#: from (5.3b), as the S0 review fixed it: the one path a run reads, kept a
#: clean checkout of the pinned overlay commit by a reviewed root sequence,
#: owned by the L3 runner account, readable by the loop runner account's
#: group, and nothing for others.
PRIVATE_DIR = "/srv/a2-private"

#: S1's mailbox form rule (ruling S1-MAILBOX-FORM-RULE): the hub's set-login
#: verb's own rule, so a value it accepts is the only kind S1 accepts. RE and
#: S6b's writer accept a superset (printable ASCII, no space).
MAILBOX_MIN = 24
MAILBOX_MAX = 128


def mailbox_form(v):
    """True only for a bytearray of MAILBOX_MIN to MAILBOX_MAX bytes, each
    0x21 to 0x7E. Reads the bytes in place: never a copy, never a str."""
    if not isinstance(v, bytearray) or not MAILBOX_MIN <= len(v) <= MAILBOX_MAX:
        return False
    for b in v:
        if not 0x21 <= b <= 0x7E:
            return False
    return True

#: The runner host's machine identity source (6.2 `runner.host_id`).
MACHINE_ID_PATH = "/etc/machine-id"
MACHINE_ID_READ = 128
_MACHINE_ID = re.compile(rb"([0-9a-f]{32})\n?")


def host_identity(path=MACHINE_ID_PATH):
    """`runner.host_id` as the S0 review fixed it: "a2-" and the first 16
    hex of the sha256 of the machine id's 32 hex characters (no newline).
    The file must read as exactly 32 lower-case hex characters and at most
    one newline. Anything else, or a read that fails, is None, which
    refuses RUNNER.LOCK_ROOT. The raw id is never returned."""
    try:
        with open(path, "rb") as f:
            raw = f.read(MACHINE_ID_READ)
    except OSError:
        return None
    m = _MACHINE_ID.fullmatch(raw)
    if m is None:
        return None
    return "a2-" + hashlib.sha256(m.group(1)).hexdigest()[:16]


#: A stage slot's default when the runner has the stage itself (a2_main.BUILT_IN_STAGES).
BUILT_IN = "built-in"


def _unobserved(*_args):
    return UNOBSERVED


def _refusing(suffix, site=None):
    """A slot that refuses `<STAGE>.<suffix>` until the runner or a later review fills it. It never returns. Its exit
    follows the write rule (3.4, 4.2): 3 once the stage has written through the bound VM layer, 2 before."""
    def slot(*_args, stage, **_kw):
        from a2_causes import Refusal
        layer = getattr(site, "vm_layer", None)
        raise Refusal(stage + "." + suffix, "slot not filled",
                      rc=3 if layer is not None and layer.wrote(stage) else None)
    return slot


class Site:
    def __init__(self):
        #: The private overlay checkout holding `alpha2.lock` and
        #: `alpha2.hosts` (5.3b). None refuses `PREFLIGHT.PRIVATE_SOURCE`.
        self.private_dir = PRIVATE_DIR
        #: Owner of every lock-root and `budget.d` object.
        self.root_uid = 0
        #: None: read the received environment (a2_host.received_environ).
        self.environ = None
        self.getuid = os.getuid
        self.geteuid = os.geteuid
        self.getpwuid = pwd.getpwuid
        #: The runner host's identity; None refuses RUNNER.LOCK_ROOT.
        self.host_identity = host_identity
        #: [OPEN: S2 review]: the hypervisor's read-only probe. Each takes
        #: the hosts document. `arm_gate` answers ("open", remaining
        #: seconds), "closed" or UNOBSERVED; `loop_tasks` answers "none",
        #: "present" or UNOBSERVED.
        self.arm_gate = _unobserved
        self.loop_tasks = _unobserved
        #: [OPEN: S2 review]: the remaining arm-gate time a full run needs.
        self.full_run_bound_s = None
        #: [OPEN: usage read-back measured]: "a" or "b". Unset refuses
        #: every run that can write to a target (`PREFLIGHT.BUDGET`).
        self.usage_path = None
        #: Path (a) usage reader: an integer percent, or None.
        self.usage_read = _unobserved
        #: S0 (a2_s0): the launch interpreter and the fixed tool that
        #: resolves it outside the interpreter under test (6.1).
        self.launch_interpreter = "/usr/bin/python3"
        self.realpath_tool = "/usr/bin/realpath"
        self.version_info = sys.version_info
        #: Git, built by the runner with an explicit environment (a2_git).
        self.git = None
        #: Section 8 L7: the committed deny list of sandbox mount roots, a
        #: slot of the S0 review. None refuses.
        self.sandbox_mount_roots = None
        #: 5.2: the runner host's live deploy paths, a slot of the S0
        #: review. None refuses PREFLIGHT.LIVE_DEPLOY.
        self.live_deploy_paths = None
        #: Test seam only: a map from a pinned repo URL to a local path.
        #: Empty in every runner-built site.
        self.repo_url_map = {}
        #: Probes owned elsewhere (4.4, 5.3a, 5.3b): each takes the hosts
        #: document and the run's scope ("loop" or "l3"; a hub or target probe
        #: reads a2_private.hub_for_scope(hosts, scope)) and answers "ok" or
        #: anything else. UNOBSERVED refuses.
        self.probe_tools = _unobserved          # D2 profile
        self.probe_net_runtime = _unobserved    # NET
        self.probe_keep_awake = _unobserved     # [OPEN: sleep probe measured]
        self.probe_target_access = _unobserved  # [OPEN: S2 review]
        self.probe_hub_read = _unobserved       # NET, S3
        self.probe_operator_route = _unobserved # E20, NET
        self.probe_survey = _unobserved         # [OPEN: S2 review]
        #: NET's read-only `snapshots` verb on the loop PVE program: takes the hosts document and the names of
        #: loop_restore_set, answers {name: {"snaptime": int, "current_parent": bool, "only": bool}} or UNOBSERVED.
        self.probe_loop_snapshots = _unobserved
        #: S0's read of ssh's effective overlay configuration (a2_git.ssh_effective): (home, host, port) ->
        #: {option: [values]}. The runner's own reader; a test stands one in.
        self.overlay_ssh_config = a2_git.ssh_effective
        #: 5.3b custody step 2: "match", "differs" or UNOBSERVED.
        self.probe_placement = _unobserved      # [OPEN: S2 review]
        self.fs_type_of = None
        self.account_ids = None
        self.fd_dir = "/proc/self/fd"
        self.interpreter = "/usr/bin/python3"
        self.entry = None
        self.installer_sha = None
        self.now = None
        self.execve = os.execve
        #: The run's output guard (3.3), created by a2_main.main.
        self.guard = None
        #: S1 (3.7): the core limit calls, the controlling terminal and
        #: stdin; the form rules, a dict {"api_key": f, "mailbox": f} of
        #: predicates over a bytearray, a missing one refusing: "mailbox" is
        #: mailbox_form, "api_key" is [OPEN: the shapes] (the S1 review); the
        #: live check ([OPEN: endpoint]), None refuses.
        import resource
        self.setrlimit = resource.setrlimit
        self.getrlimit = resource.getrlimit
        self.tty_path = "/dev/tty"
        self.stdin_fd = 0
        self.form_rules = {"mailbox": mailbox_form}
        self.live_check = None
        #: S10 (5.5): the three operator steps' text, from the runbook;
        #: None prints them as UNMEASURED.
        self.operator_steps = None
        #: The VM layer (a2_vm), bound by the runner after S2 (a2_vm.bind). Until then each refuses: the calls
        #: `<STAGE>.TARGET_ACCESS`, component_file `<STAGE>.PIN`.
        #: The VM layer once bound (a2_vm.bind): the slots below read its write state.
        self.vm_layer = None
        self.vm_exec = _refusing("TARGET_ACCESS", self)
        self.vm_install_file = _refusing("TARGET_ACCESS", self)
        self.vm_write_secret = _refusing("TARGET_ACCESS", self)
        self.component_file = _refusing("PIN", self)
        #: The agents' registry entries on a VM, filled by a2_vm.bind (a2_agent_registry). `registry_import(vm, slug,
        #: stable_key, stage=)` returns nothing; the logical id comes only from `registry_read(vm, slug, stage=)`,
        #: through a2_vm.logical_id, which accepts 32 lower-case hex and nothing else.
        self.registry_import = _refusing("TARGET_ACCESS", self)
        self.registry_read = _refusing("TARGET_ACCESS", self)
        #: [OPEN: e5, the hosts key]: the agent account on a VM, `vm_agent_account(vm, stage=)`.
        self.vm_agent_account = _refusing("HOSTS", self)
        #: The stages after S1, each `run_sN(c, site, rec)` writing its own receipts (ruling W7-STAGE-DISPATCH-OWNER,
        #: a2_main.DISPATCH). None is not built: the run stops there, RUNNER.UNCLASSIFIED rc 3. S2 and S3 are NET's
        #: to fill; S4 is its own package's. BUILT_IN is the runner's own stage, which a2_main resolves, so the
        #: launcher never imports a stage module.
        self.run_s2 = None
        self.run_s3 = None
        self.run_s4 = None
        self.run_s5 = BUILT_IN
        self.run_s6 = BUILT_IN
        self.out = sys.stderr
