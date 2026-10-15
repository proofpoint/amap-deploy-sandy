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


#: A1's approved record's one place, under the evidence directory.
ACTIVATION = "activation.json"


def activation_path(p: ps.PartitionSpec) -> str:
    return posixpath.join(p.evidence_dir, ACTIVATION)


def job_argv(p: ps.PartitionSpec, *, writer: str, host: str, document: str, document_bytes: bytes,
             activation_bytes: bytes) -> List[str]:
    """The job's command: the pinned writer, under the root-trusted
    interpreter, with the document's and A1's approved record's sha256s
    computed from their exact bytes. The unit is rendered again after every
    overlay change and after every A1."""
    return [p.tools["python3"], "-I", "-S", "-B", writer, "partition-weekly", "--exec-root", p.exec_root,
            "--host", host, "--document", document, "--document-sha256", hashlib.sha256(document_bytes).hexdigest(),
            "--activation", activation_path(p), "--activation-sha256", hashlib.sha256(activation_bytes).hexdigest()]


def activation_steps(p: ps.PartitionSpec, *, writer: str, source: str, activation_bytes: bytes,
                     q: Callable[[str], str] = shlex.quote) -> List[str]:
    """The operator's root step after A1: place A1's record, checked against
    the sha256 of the bytes A1 wrote, at its one place (root:root 0444). The
    unit carrying the same sha256 is then rendered and placed again."""
    return ["# A1's approved record, where the weekly job and verify read it (after every A1):",
            f"sudo {q(p.tools['python3'])} -I -S -B {q(writer)} place {q(source)} {q(activation_path(p))} "
            f"--sha256 {hashlib.sha256(activation_bytes).hexdigest()}"]


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
    paths are only discovered with it, under an empty environment). The
    lines are one shell block, run in order: they name the closure (P, the
    library and the extension modules; Z, each zip on the interpreter's
    path; T, the binaries and modules whose links are listed; L, those
    links and the loader, by ldd on Linux and otool on macOS, never both),
    then print every path, link target and directory above each that is not
    root-owned or is writable by others, and each file whose listing failed
    or that is required and absent. A zip that is absent has its would-be
    place's directories checked instead. Every line prints nothing on a host
    that passes. The pinned writer applies the same rule before every run."""
    py, docker = q(p.tools["python3"]), q(p.tools["docker"])
    bad = "\\( ! -user root -o -perm -g+w -o -perm -o+w \\) -print"
    # Without -L, find judges a link itself: only its owner (its mode is always 0777); -L judges its target.
    own = ("\\( -type l ! -user root -o ! -type l \\( ! -user root -o -perm -g+w -o -perm -o+w \\) \\) "
           "-print")
    query = "env -i " + py + " -I -S -B -c 'import os,sys,sysconfig; g=sysconfig.get_paths(); "
    return [
        "# The tools the weekly job runs as root, and their startup closure. Paste these lines as one block into",
        "# one shell (bash or dash; the functions below are defined on earlier lines and used on later ones).",
        "# Each prints nothing on a host whose closure is root's alone. A path holding whitespace is named, never",
        "# split, since the lists below are split on it. It needs realpath(1): on macOS, 13 or later.",
        f"P=$({query}print(g[\"stdlib\"], g[\"platstdlib\"], sysconfig.get_config_var(\"DESTSHARED\") or "
        "os.path.join(g[\"platstdlib\"], \"lib-dynload\"))')",
        f"Z=$({query}print(*[x for x in sys.path if x.endswith(\".zip\")])')",
        f"T=\"$(realpath {py}) $(realpath {docker}) $(for d in $P; do ls \"$d\"/*.so 2>/dev/null; done)\"",
        "if [ \"$(uname)\" = Darwin ]; then "
        "for f in $T; do otool -L \"$f\" >/dev/null 2>&1 || echo \"discovery failed: $f\"; done; "
        "otool -L $T | awk '/^\\t/ { sub(/^\\t/, \"\"); sub(/ \\(compatibility.*$/, \"\"); "
        "if ($0 ~ /[[:space:]]/) print \"discovery failed: whitespace in \" $0 }'; "
        "L=$(otool -L $T | awk '/^\\t/ {print $1}' | sort -u); "
        "else "
        "for f in $T; do ldd \"$f\" >/dev/null 2>&1 || { file \"$f\" | grep -q 'statically linked' "
        "|| echo \"discovery failed: $f\"; }; done; "
        "ldd $T 2>/dev/null | awk '/=>/ { sub(/^.*=> /, \"\"); sub(/ \\(0x[0-9a-f]+\\)$/, \"\"); "
        "if ($0 ~ /[[:space:]]/) print \"discovery failed: whitespace in \" $0 }'; "
        "L=$(ldd $T 2>/dev/null | awk '/=>/ {print $3} /^[[:space:]]+\\// {print $1}' | sort -u); fi",
        f"for x in {py} {docker} $(realpath {py} {docker}) $P; do [ -e \"$x\" ] || echo \"absent: $x\"; done"
        "   # required: never excused",
        "for x in $L; do [ -e \"$x\" ] || { [ \"$(uname)\" = Darwin ] && case \"$x\" in /usr/lib/*|/System/Library/*) "
        "true;; *) false;; esac; } || echo \"absent: $x\"; done   # a library otool named may be in macOS's shared cache",
        f"find {py} {docker} $(realpath {py} {docker}) $P $L {own} 2>/dev/null",
        f"find -L {py} {docker} $(realpath {py} {docker}) $P $L {bad} 2>/dev/null   # every link's target",
        f"for z in $Z; do [ -e \"$z\" ] && {{ find \"$z\" {own}; find -L \"$z\" {bad}; }}; done   # a zip present",
        "[ \"$(uname)\" = Darwin ] && { D=$(xcode-select -p); find \"$D\" " + own + "; find -L \"$D\" " + bad + "; }",
        # Every link met in the closure, followed one hop at a time, as the writer's own check does: a
        # link inside the closure has its target, everything under a target directory and every
        # directory above it judged (a tree visit); a link among those directories has only its target
        # and the directories above it judged (a chain visit). Every path a hop reaches has the
        # directories above it judged first, whatever was visited before. A visit is then known by the
        # directory entry its target names (its parent's realpath and its own name): each link along a
        # chain is visited once, and every cycle ends, relative or not. A chain visit never stands in
        # for a later tree visit of the same entry. A directory is known by its spelling and what it
        # is, so no link among them goes unjudged.
        f"chk() {{ find \"$1\" -maxdepth 0 {own}; }}",
        "norm() { local c o IFS=/; o=; set -f; for c in $1; do case $c in ''|.) ;; ..) o=${o%/*};; "
        "*) o=\"$o/$c\";; esac; done; set +f; echo \"${o:-/}\"; }",
        "ent() { local p; p=$(realpath \"$(dirname \"$1\")\" 2>/dev/null) && echo \"$p/$(basename \"$1\")\" "
        "|| echo \"?$(norm \"$1\")\"; }",
        "up() { local x=$1 k; while [ \"$x\" != / ] && [ \"$x\" != . ]; do x=$(dirname \"$x\"); "
        "k=\"$(norm \"$x\")|$(realpath \"$x\" 2>/dev/null)\"; case \" $ups \" in *\" $k \"*) return;; esac; "
        "ups=\"$ups $k\"; chk \"$x\"; [ -L \"$x\" ] && hop \"$x\" chain; done; }",
        "hop() { local r t l k; r=$(readlink \"$1\"); case \"$r\" in /*) t=$r;; *) t=\"$(dirname \"$1\")/$r\";; esac; "
        "case \"$t\" in *[[:space:]]*) echo \"discovery failed: whitespace in $t\"; return;; esac; "
        "up \"$t\"; k=$(ent \"$t\"); "
        "if [ \"$2\" = tree ]; then case \" $trees \" in *\" $k \"*) return;; esac; trees=\"$trees $k\"; "
        f"find \"$t\" {own} 2>/dev/null; "
        "find \"$t\" -name '*[[:space:]]*' -print 2>/dev/null | sed 's/^/discovery failed: whitespace in /'; "
        "for l in $(find \"$t\" -type l 2>/dev/null); do hop \"$l\" tree; done; "
        "else case \" $trees $chains \" in *\" $k \"*) return;; esac; chains=\"$chains $k\"; "
        "chk \"$t\"; [ -L \"$t\" ] && hop \"$t\" chain; fi; }",
        f"find {py} {docker} $(realpath {py} {docker}) $P $L $(for z in $Z; do [ -e \"$z\" ] && echo \"$z\"; done) "
        "$( [ \"$(uname)\" = Darwin ] && xcode-select -p) -name '*[[:space:]]*' -print 2>/dev/null "
        "| sed 's/^/discovery failed: whitespace in /'   # a path the lists would split",
        f"trees=; chains=; ups=; for l in $(find {py} {docker} $P $L $(for z in $Z; do [ -e \"$z\" ] && echo \"$z\"; done) "
        "$( [ \"$(uname)\" = Darwin ] && xcode-select -p) -type l 2>/dev/null); do hop \"$l\" tree; done"
        "   # every link's target, its tree and its directories",
        f"for p in {py} {docker} $P $Z $L \"$( [ \"$(uname)\" = Darwin ] && xcode-select -p)\"; do for x in \"$p\" "
        "\"$(realpath \"$p\" 2>/dev/null)\"; do while [ -n \"$x\" ] && [ \"$x\" != / ]; do x=$(dirname \"$x\"); "
        f"find \"$x\" -maxdepth 0 {own}; done; done; done   # every directory above each, and above its realpath",
    ]
