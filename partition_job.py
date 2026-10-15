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
from typing import Any, Callable, List, Tuple

import partition_setup as ps

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


def job_argv(p: ps.PartitionSpec, *, writer: str, host: str, document: str, document_bytes: bytes) -> List[str]:
    """The job's command: the pinned writer, under the root-trusted
    interpreter, with the document's sha256 computed from its exact bytes."""
    return [p.tools["python3"], "-I", "-S", "-B", writer, "partition-weekly", "--exec-root", p.exec_root,
            "--host", host, "--document", document, "--document-sha256", hashlib.sha256(document_bytes).hexdigest()]


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


def validation_steps(p: ps.PartitionSpec, q: Callable[[str], str] = shlex.quote) -> List[str]:
    """The operator's install-time check of what root will run, with the
    operating system's own tools only, never the interpreter under test (its
    paths are only discovered with it, under an empty environment): the
    tools, the interpreter's library, its extension modules and any zip on
    its path, the libraries the tools and every extension module link, the
    developer directory on macOS, and every directory above each of them.
    Every path printed must be root-owned and writable by no one else. The
    pinned writer applies the same rule before every run."""
    py, docker = q(p.tools["python3"]), q(p.tools["docker"])
    bad = "\\( ! -user root -o -perm -g+w -o -perm -o+w \\) -print"
    paths = (f"$(env -i {py} -I -S -B -c 'import os,sys,sysconfig; g=sysconfig.get_paths(); "
             "print(g[\"stdlib\"], g[\"platstdlib\"], sysconfig.get_config_var(\"DESTSHARED\") or "
             "os.path.join(g[\"platstdlib\"], \"lib-dynload\"), *[x for x in sys.path if x.endswith(\".zip\")])')")
    dynload = (f"$(env -i {py} -I -S -B -c 'import os,sysconfig; print(sysconfig.get_config_var(\"DESTSHARED\") or "
               "os.path.join(sysconfig.get_paths()[\"platstdlib\"], \"lib-dynload\"))')")
    tools = f"$(realpath {py}) $(realpath {docker}) {dynload}/*.so"
    return [
        "# The tools the weekly job runs as root: each must be the operating system's or its vendor's,",
        "# and nothing in their startup closure may be writable by anyone but root (each command prints nothing):",
        f"find {py} {docker} $(realpath {py} {docker}) {bad}",
        f"find {paths} {bad}",
        f"ldd {tools} 2>/dev/null | awk '/=>/ {{print $3}}' | sort -u | xargs -r find {bad}   # Linux",
        f"otool -L {tools} | awk '/^\\t/ {{print $1}}' | sort -u | xargs find {bad} 2>/dev/null   # macOS",
        f"find \"$(xcode-select -p)\" {bad}   # macOS: the developer directory /usr/bin/python3 runs",
        "# Every directory above each of those paths (each prints nothing):",
        f"for p in $(realpath {py} {docker}) {paths} \"$(xcode-select -p 2>/dev/null)\"; do "
        f"while [ -n \"$p\" ] && [ \"$p\" != / ]; do p=$(dirname \"$p\"); find \"$p\" -maxdepth 0 {bad}; done; done",
    ]
