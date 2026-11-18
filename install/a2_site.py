"""What the launcher and S0 read from the runner host, in one place.

Each input that the contract leaves to a later review is a named slot here
and FAILS CLOSED until that review fills it: a probe that is not supplied
answers UNOBSERVED, and an unset path refuses. Nothing here guesses.
"""

import os
import pwd
import sys

UNOBSERVED = "UNOBSERVED"


def _machine_id():
    """Candidate identity source for `runner.host_id`, submitted to the
    S0 review ([OPEN: S0 review: the identity source])."""
    try:
        with open("/etc/machine-id", "rb") as f:
            v = f.read(128).decode("ascii", "strict").strip()
    except (OSError, UnicodeDecodeError):
        return None
    return v or None


def _unobserved(*_args):
    return UNOBSERVED


class Site:
    def __init__(self):
        #: The private overlay checkout holding `alpha2.lock` and
        #: `alpha2.hosts`, fixed at the S0 review (5.3b). Unset refuses
        #: `PREFLIGHT.PRIVATE_SOURCE`.
        self.private_dir = None
        #: Owner of every lock-root and `budget.d` object.
        self.root_uid = 0
        #: None: read the received environment (a2_host.received_environ).
        self.environ = None
        self.getuid = os.getuid
        self.geteuid = os.geteuid
        self.getpwuid = pwd.getpwuid
        #: Unset until the S0 identity review records its source; the
        #: candidate is `_machine_id`. None refuses RUNNER.LOCK_ROOT.
        self.host_identity = lambda: None
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
        #: document and answers "ok" or anything else. UNOBSERVED refuses.
        self.probe_tools = _unobserved          # D2 profile
        self.probe_net_runtime = _unobserved    # NET
        self.probe_keep_awake = _unobserved     # [OPEN: sleep probe measured]
        self.probe_target_access = _unobserved  # [OPEN: S2 review]
        self.probe_hub_read = _unobserved       # NET, S3
        self.probe_operator_route = _unobserved # E20, NET
        self.probe_survey = _unobserved         # [OPEN: S2 review]
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
        #: stdin; the form rules ([OPEN: the shapes], the S1 review), a dict
        #: {"api_key": f, "mailbox": f} of predicates over a bytearray, None
        #: refuses; the live check ([OPEN: endpoint]), None refuses.
        import resource
        self.setrlimit = resource.setrlimit
        self.getrlimit = resource.getrlimit
        self.tty_path = "/dev/tty"
        self.stdin_fd = 0
        self.form_rules = None
        self.live_check = None
        #: S10 (5.5): the three operator steps' text, from the runbook;
        #: None prints them as UNMEASURED.
        self.operator_steps = None
        self.out = sys.stderr
