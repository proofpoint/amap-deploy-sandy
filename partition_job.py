"""The weekly partition job's installation: its unit (a systemd service and
timer, or a LaunchDaemon) and the operator's root steps that come before it:
provisioning the bundle, and validating the tools root will run. NOTHING HERE
RUNS, PLACES OR ENABLES ANYTHING: it renders bytes and prints commands.

The unit's argv is the job's trusted input, so it carries everything the job
may not take from the operator's own files: the exec root, the host name, and
the host-setup document's path with the sha256 of its exact approved bytes.
The job reads that document only when its bytes still hash to that value, so
a document changed after the unit was rendered is a handoff, never authority:
the unit is rendered again after every overlay change.

The job also starts once after boot (the timer's OnBootSec, launchd's
RunAtLoad), so a run whose writer and child both died is decided at the next
boot, not a week later: the job decides every abandoned run before its own.
"""

import hashlib
import plistlib
import posixpath
import shlex
from typing import Any, Callable, List, Optional, Tuple

import partition_setup as ps
import root_trust as rt

#: The job's unit names: systemd's, and launchd's label.
UNIT = "amap-partition-weekly"
LABEL = "org.amap.partition-weekly"
SYSTEMD_DIR = "/etc/systemd/system"
LAUNCHD_DIR = "/Library/LaunchDaemons"
DAYS = ("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat")
#: How long after boot the job first runs: the engine has started by then.
BOOT_DELAY_S = 300
#: The public repository the bundle is provisioned from, over https only.
PUBLIC_REPO = "https://github.com/proofpoint/amap-deploy-sandy"
HEADER = "# Rendered by amap-deploy-sandy from the anchored overlay. Place it; never edit it.\n"


#: A1's approved record's one place, under the evidence directory.
ACTIVATION = "activation.json"


def activation_path(p: ps.PartitionSpec) -> str:
    return posixpath.join(p.evidence_dir, ACTIVATION)


def job_argv(p: ps.PartitionSpec, *, writer: str, writer_sha256: str, host: str, document: str,
             document_bytes: bytes, activation_bytes: bytes) -> List[str]:
    """The job's command, through the one barrier (ROOT-BOOTSTRAP d3.2):
    root-trust.sh (beside the writer) judges the OS interpreter and the pinned
    writer, the writer's trusted-exec judges docker and what everything loads,
    then the writer runs partition-weekly with the document's and A1's
    approved record's sha256s computed from their exact bytes. The unit is
    rendered again after every overlay change and after every A1."""
    py = p.tools["python3"]
    step = [py, "-I", "-S", "-B", writer, "partition-weekly", "--exec-root", p.exec_root, "--host", host,
            "--document", document, "--document-sha256", hashlib.sha256(document_bytes).hexdigest(),
            "--activation", activation_path(p), "--activation-sha256", hashlib.sha256(activation_bytes).hexdigest()]
    tools = [x for t in sorted(set(p.tools.values())) if posixpath.basename(t) != "sudo" for x in ("--tool", t)]
    return rt.root_argv(posixpath.join(posixpath.dirname(writer), rt.NAME), writer_sha256, py, writer,
                        ["trusted-exec"] + tools + ["--also", p.tools["docker"], "--"] + step)


def activation_steps(p: ps.PartitionSpec, *, writer: str, writer_sha256: str, tools: List[str], source: str,
                     activation_bytes: bytes, q: Callable[[str], str] = shlex.quote) -> List[str]:
    """The operator's root step after A1: place A1's record, checked against
    the sha256 of the bytes A1 wrote, at its one place (root:root 0444), by
    the pinned writer through the barrier (d3.3 §5(d)), as job_argv runs it.
    The unit carrying the same sha256 is then rendered and placed again."""
    py = p.tools["python3"]
    return ["# A1's approved record, where the weekly job and verify read it (after every A1):",
            " ".join(q(a) for a in rt.typed_argv(
                posixpath.join(posixpath.dirname(writer), rt.NAME), writer_sha256, py, writer, tools,
                [py, "-I", "-S", "-B", writer, "place", source, activation_path(p),
                 "--sha256", hashlib.sha256(activation_bytes).hexdigest()]))]


def _sd(arg: str) -> str:
    a = arg.replace("%", "%%").replace("$", "$$")
    return a if a and all(c.isalnum() or c in "_@+=:,./-" for c in a) else \
        '"' + a.replace("\\", "\\\\").replace('"', '\\"') + '"'


def systemd_units(p: ps.PartitionSpec, argv: List[str]) -> List[Tuple[str, bytes]]:
    service = (HEADER + "[Unit]\nDescription=amap partition probes, weekly\n\n"
               "[Service]\nType=oneshot\n"
               f"ExecStart={' '.join(_sd(a) for a in argv)}\n").encode("utf-8")
    timer = (HEADER + "[Unit]\nDescription=amap partition probes, weekly and after boot\n\n"
             f"[Timer]\nOnCalendar={DAYS[p.weekday]} *-*-* {p.hour:02d}:00:00\nOnBootSec={BOOT_DELAY_S}\n"
             f"Persistent=true\nUnit={UNIT}.service\n\n"
             "[Install]\nWantedBy=timers.target\n").encode("utf-8")
    return [(posixpath.join(SYSTEMD_DIR, UNIT + ".service"), service),
            (posixpath.join(SYSTEMD_DIR, UNIT + ".timer"), timer)]


def launchd_plist(p: ps.PartitionSpec, argv: List[str]) -> List[Tuple[str, bytes]]:
    return [(posixpath.join(LAUNCHD_DIR, LABEL + ".plist"), plistlib.dumps({
        "Label": LABEL, "ProgramArguments": argv,
        "StartCalendarInterval": {"Weekday": p.weekday, "Hour": p.hour, "Minute": 0},
        "RunAtLoad": True}, sort_keys=True))]


def rendered(kind: str, p: ps.PartitionSpec, argv: List[str]) -> List[Tuple[str, bytes]]:
    """`(placed path, bytes)` for the job's unit files, for `kind` systemd or
    launchd."""
    if kind == "systemd":
        return systemd_units(p, argv)
    if kind == "launchd":
        return launchd_plist(p, argv)
    raise ValueError(f"no unit kind {kind!r}")


def provision_steps(p: ps.PartitionSpec, pin: str, writer: str, q: Callable[[str], str] = shlex.quote) -> List[str]:
    """The operator's root steps that provision the bundle at the deploy pin,
    from a fresh root-owned https clone of the public repository, never the
    operator's clone, and swap it in under the job's lock."""
    ex, src, new = p.exec_root, posixpath.join(p.exec_root, "src.new"), posixpath.join(p.exec_root, "bundle.new")
    empty = posixpath.join(p.exec_root, "empty-home")
    env = f"GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null HOME={q(empty)}"
    git = f"sudo env {env} git -c core.hooksPath=/dev/null -c protocol.allow=never -c protocol.https.allow=always"
    return [
        "# The weekly job's bundle, at the deploy pin, as root (at install and after every pin move):",
        f"sudo install -d -o 0 -g 0 -m 0700 {q(empty)}",
        f"{git} clone --no-checkout {PUBLIC_REPO} {q(src)}",
        f"{git} -C {q(src)} cat-file -e {pin}^{{commit}}",
        f"sudo install -d -o 0 -g 0 -m 0755 {q(new)}",
        f"{git} -C {q(src)} archive --format=tar {pin} -- partition_weekly.closure "
        f"$({git} -C {q(src)} show {pin}:partition_weekly.closure) | sudo tar -x --no-same-owner -C {q(new)}",
        f"echo {pin} | sudo tee {q(posixpath.join(new, 'PIN'))} >/dev/null",
        f"sudo chmod 0444 {q(new)}/* && sudo chmod 0555 {q(new)}",
        f"sudo {q(p.tools['python3'])} -I -S -B {q(writer)} partition-provision {q(ex)}",
        f"sudo rm -rf {q(src)}",
    ]


#: The line partition-judge prints last, and only when its judging found
#: nothing (host_steps.JUDGE_SENTINEL; a test holds the two equal).
SENTINEL = "END-OF-BLOCK"


def validation_steps(p: ps.PartitionSpec, *, writer: str, writer_sha256: str, tools: List[str],
                     q: Callable[[str], str] = shlex.quote) -> List[str]:
    """The operator's install-time check of what root will run (d3.3 §5(d)
    §2): the writer's partition-judge, through the barrier, judges the
    weekly job's interpreter and docker exactly as trusted-exec judges them
    on every run. root-trust.sh has judged that interpreter before it
    starts, so nothing runs as another identity and no script is written."""
    py = p.tools["python3"]
    line = rt.typed_argv(posixpath.join(posixpath.dirname(writer), rt.NAME), writer_sha256, py, writer, tools,
                         [py, "-I", "-S", "-B", writer, "partition-judge", "--python3", py,
                          "--docker", p.tools["docker"]])
    return [
        "# The tools the weekly job runs as root, and everything they load: run this at install AND again after",
        "# any operating-system, interpreter or docker update, before the next weekly run. root-trust.sh judges",
        "# the interpreter before it starts; the writer's partition-judge then judges it and docker as",
        "# trusted-exec does on every run, and writes nothing.",
        " ".join(q(a) for a in line),
        f"# Go on only when that printed exactly {SENTINEL} as its last line and exited 0. The plan prints this",
        "# check first among the root lines, so every later step that runs an interpreter as root comes after it.",
    ]
