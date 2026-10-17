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


#: The judging step's cap on what discovery may write, and the size judge.sh
#: accepts: one byte over the cap is refused, so a stream is never cut into
#: something that parses.
CLOSURE_MAX = 1 << 20
#: The line judge.sh prints last, and only when its judging ran to the end.
SENTINEL = "END-OF-BLOCK"
#: Who discovery runs as: an unprivileged identity, with no sudo rule and no
#: terminal, inside root's own invocation.
DISCOVERY_USER = "nobody"
#: The OS tools discovery may find on its PATH, under an empty environment.
DISCOVERY_PATH = "/usr/bin:/bin"
#: Each operating system's identity drop and detachment, and its digest check.
DROP = {"systemd": ("setsid -w", f"runuser -u {DISCOVERY_USER} --", "env", "HOME=/", "sh"),
        "launchd": ('/usr/bin/perl -MPOSIX -e "POSIX::setsid() >= 0 or exit 1; exec @ARGV"',
                    f"/usr/bin/sudo -u {DISCOVERY_USER} -g {DISCOVERY_USER}", "/usr/bin/env", "HOME=/var/empty",
                    "/bin/sh")}
DIGEST = {"systemd": "sha256sum --status -c", "launchd": "shasum -a 256 --status -c"}
#: What step 3 prints when a script is not the bytes the plan rendered.
MISMATCH = "discovery failed: the judging scripts do not match their digests; nothing is run"
#: The six lists discovery writes, in order, one line each.
LISTS = ("P", "Z", "T", "L", "Lw", "X")
#: The characters an entry of a list may hold: never a quote, "$", a glob,
#: whitespace or a backslash, and every entry begins with "/", so none can be
#: an option to find.
ENTRY_CHARS = "A-Za-z0-9._+,@%=:~/-"
#: Where macOS keeps system libraries that may be only in the dyld shared
#: cache: one the tool names that is absent from disk is excused there (the
#: writer's SEALED_PREFIXES; a test holds the two equal).
CACHE_PREFIXES = ("/usr/lib/", "/System/Library/")
CACHE = "|".join(f"{c}*" for c in CACHE_PREFIXES)


def discover_script(p: ps.PartitionSpec, darwin: bool, q: Callable[[str], str] = shlex.quote) -> str:
    """Half A: the lines that EXECUTE what is being vetted (the interpreter,
    ldd, which may run a binary's program interpreter, otool, xcode-select),
    run as an unprivileged identity under an empty environment, never as
    root. It prints only the six lists and its own "discovery failed:"
    lines; root captures them as data. Each list is written sorted and
    without repeats, so T holds the tools' spellings and realpaths among the
    extension modules, in that order; judge.sh checks it by containment. A
    path holding whitespace is named and left out of the lists."""
    py, docker = q(p.tools["python3"]), q(p.tools["docker"])
    query = py + " -I -S -B -c 'import os,sys,sysconfig; g=sysconfig.get_paths(); "
    lines = [
        "# Half A, discovery: run by root as " + DISCOVERY_USER + ", never as root; prints the six lists as data.",
        "fail() { echo \"discovery failed: $*\"; }",
        "bad() { for x in $1; do case $x in *[!" + ENTRY_CHARS + "]*|[!/]*) fail \"cannot be listed: $x\";; esac; "
        "done; }",
        "good() { for x in $1; do case $x in *[!" + ENTRY_CHARS + "]*|[!/]*) ;; *) echo \"$x\";; esac; done "
        "| sort -u | tr '\\n' ' ' | sed 's/ $//'; }",
        f"P=$({query}print(g[\"stdlib\"], g[\"platstdlib\"], sysconfig.get_config_var(\"DESTSHARED\") or "
        "os.path.join(g[\"platstdlib\"], \"lib-dynload\"))') || fail \"the interpreter cannot name its library\"",
        f"Z=$({query}print(*[x for x in sys.path if x.endswith(\".zip\")])') || fail \"the interpreter cannot name its "
        "path\"",
        f"T=\"{py} $(realpath {py}) {docker} $(realpath {docker}) $(for d in $P; do ls \"$d\"/*.so 2>/dev/null; done)\"",
    ]
    if darwin:
        lines += [
            "for f in $T; do otool -L \"$f\" >/dev/null 2>&1 || fail \"$f\"; done",
            "otool -L $T 2>/dev/null | awk '/^\\t/ { sub(/^\\t/, \"\"); sub(/ \\(compatibility.*$/, \"\"); "
            "if ($0 ~ /[[:space:]]/) print \"discovery failed: whitespace in \" $0 }'",
            "L=$(otool -L $T 2>/dev/null | awk '/^\\t/ {print $1}' | sort -u)",
            "Lw=$(for x in $L; do [ -e \"$x\" ] || case $x in " + CACHE + ") continue;; esac; echo \"$x\"; done)"
            "   # a library otool named may be only in macOS's shared cache",
            "X=$(xcode-select -p 2>/dev/null) || fail \"xcode-select cannot say which developer directory is chosen\"",
        ]
    else:
        lines += [
            "for f in $T; do ldd \"$f\" >/dev/null 2>&1 || { file \"$f\" | grep -q 'statically linked' "
            "|| fail \"$f\"; }; done",
            "ldd $T 2>/dev/null | awk '/=> not found/ { print \"discovery failed: \" $1 \" not found\"; next } "
            "/=>/ { sub(/^.*=> /, \"\"); sub(/ \\(0x[0-9a-f]+\\)$/, \"\"); "
            "if ($0 ~ /[[:space:]]/) print \"discovery failed: whitespace in \" $0 }'",
            "L=$(ldd $T 2>/dev/null | awk '/=> not found/ {next} /=>/ {print $3} /^[[:space:]]+\\// {print $1}' "
            "| sort -u)",
            "Lw=$L",
            "X=",
        ]
    lines += ["set -f   # the lists hold no glob, and are never expanded as one"]
    lines += [f"bad \"${n}\"; echo \"{n}=$(good \"${n}\")\"" for n in LISTS]
    return "\n".join(lines) + "\n"


def judge_script(p: ps.PartitionSpec, darwin: bool, owner: str = "root", q: Callable[[str], str] = shlex.quote) -> str:
    """Half B: run by root over discovery's output, closure.env, read as DATA
    under a strict grammar (never sourced). It executes nothing it judges:
    only the operating system's find, readlink, realpath, dirname, basename,
    sed, grep and sh. The tools as the approved document spells them are
    rendered into it, and judged first, from its own list, whatever
    closure.env says; it then checks that closure.env names them, that P is
    not empty and (on Linux) that L holds the loader the interpreter names.
    It prints every path, link target and directory above each that is not
    `owner`'s or is writable by others, each failed discovery and each
    required path that is absent, then the sentinel; it exits 0 only when
    it printed nothing else. A judging that stops early never prints the
    sentinel."""
    py, docker = q(p.tools["python3"]), q(p.tools["docker"])
    bad = f"\\( ! -user {owner} -o -perm -g+w -o -perm -o+w \\) -print"
    # Without -L, find judges a link itself: only its owner (its mode is always 0777); -L judges its target.
    own = (f"\\( -type l ! -user {owner} -o ! -type l \\( ! -user {owner} -o -perm -g+w -o -perm -o+w \\) \\) "
           "-print")

    def named(paths: str) -> str:
        """A tree find whose errors are named, its findings kept, in order."""
        return f"{{ find {paths} {own} 2>&1 1>&3 | sed 's/^/discovery failed: /'; }} 3>&1"
    # The links are found with the lists split on spaces, then split on newlines themselves.
    links = ("found=$(find {} -type l 2>/dev/null); IFS=$NL; for l in $found; do IFS=' '; hop \"$l\" tree; done; "
             "IFS=' '")
    above = ("for p in {}; do for x in \"$p\" \"$(realpath \"$p\" 2>/dev/null)\"; do while [ -n \"$x\" ] && "
             "[ \"$x\" != / ]; do x=$(dirname \"$x\"); chk \"$x\"; done; done; done")
    order = " ".join(LISTS)
    return "\n".join([
        "# Half B, judging: run as root, over closure.env as data. It executes only the operating system's find,",
        "# readlink, realpath, dirname, basename, sed, grep and sh; never the interpreter, ldd, otool or xcode-select.",
        f"PY={py}",
        f"DOCKER={docker}",
        f"DARWIN={1 if darwin else 0}",
        "NL='",
        "'",
        "set -f",
        "IFS=' '",
        "refuse() { echo \"discovery failed: closure.env is not the discovery's output: $1\"; }",
        "omits() { echo \"discovery failed: closure.env omits $1\"; }",
        f"chk() {{ find \"$1\" -maxdepth 0 {own} 2>/dev/null; }}",
        # Every link met in the closure, followed one hop at a time, as the writer's own check does: a
        # link inside the closure has its target, everything under a target directory and every
        # directory above it judged (a tree visit); a link among those directories has only its target
        # and the directories above it judged (a chain visit). Every path a hop reaches has the
        # directories above it judged first, whatever was visited before. A visit is then known by the
        # directory entry its target names (its parent's realpath and its own name): each link along a
        # chain is visited once, and every cycle ends, relative or not. A chain visit never stands in
        # for a later tree visit of the same entry. A directory is known by its spelling and what it
        # is, so no link among them goes unjudged.
        "norm() { local c o f IFS=/; case $- in *f*) f=1;; *) f=;; esac; o=; set -f; for c in $1; do case $c in "
        "''|.) ;; ..) o=${o%/*};; *) o=\"$o/$c\";; esac; done; [ -n \"$f\" ] || set +f; echo \"${o:-/}\"; }",
        "ent() { local p; p=$(realpath \"$(dirname \"$1\")\" 2>/dev/null) && echo \"$p/$(basename \"$1\")\" "
        "|| echo \"?$(norm \"$1\")\"; }",
        "up() { local x=$1 k; while [ \"$x\" != / ] && [ \"$x\" != . ]; do x=$(dirname \"$x\"); "
        "k=\"$(norm \"$x\")|$(realpath \"$x\" 2>/dev/null)\"; case \" $ups \" in *\" $k \"*) return;; esac; "
        "ups=\"$ups $k\"; chk \"$x\"; [ -L \"$x\" ] && hop \"$x\" chain; done; }",
        "hop() { local r t l k found; r=$(readlink \"$1\"); case \"$r\" in /*) t=$r;; *) t=\"$(dirname \"$1\")/$r\";; esac; "
        "case \"$t\" in *[[:space:]]*) echo \"discovery failed: whitespace in $t\"; return;; esac; "
        "up \"$t\"; k=$(ent \"$t\"); "
        "if [ \"$2\" = tree ]; then case \" $trees \" in *\" $k \"*) return;; esac; trees=\"$trees $k\"; "
        + named("\"$t\"") + "; "
        "find \"$t\" -name '*[[:space:]]*' -print 2>/dev/null | sed 's/^/discovery failed: whitespace in /'; "
        + links.format("\"$t\"") + "; "
        "else case \" $trees $chains \" in *\" $k \"*) return;; esac; chains=\"$chains $k\"; "
        "chk \"$t\"; [ -L \"$t\" ] && hop \"$t\" chain; fi; }",
        # The tools, from this script's own list: their spellings, realpaths, routes and ancestors.
        "fixed() { local found; trees=; chains=; ups=; "
        "for x in \"$PY\" \"$DOCKER\"; do [ -e \"$x\" ] || echo \"absent: $x\"; done; "
        "[ -n \"$PYR\" ] || echo \"discovery failed: cannot resolve $PY\"; "
        "[ -n \"$DR\" ] || echo \"discovery failed: cannot resolve $DOCKER\"; "
        + named("\"$PY\" \"$DOCKER\" $PYR $DR") + "; "
        f"find -L \"$PY\" \"$DOCKER\" $PYR $DR {bad} 2>/dev/null; "
        + links.format("\"$PY\" \"$DOCKER\"") + "; "
        + above.format("\"$PY\" \"$DOCKER\"") + "; }",
        # closure.env, by its grammar: the six lists in order, each name once, every entry absolute and of
        # the allowed characters, single spaces between; any number of discovery's own failure lines.
        "parse() { local line n v e rest; "
        "[ -f \"$1\" ] && [ ! -h \"$1\" ] || { refuse \"not a regular file\"; return 1; }; "
        f"[ -z \"$(find \"$1\" -size +{CLOSURE_MAX}c -print)\" ] || {{ refuse \"larger than {CLOSURE_MAX} bytes\"; "
        "return 1; }; "
        "! LC_ALL=C grep -q '[^ -~]' \"$1\" || { refuse \"a character that is not printable\"; return 1; }; "
        f"rest=\"{order}\"; line=; "
        "while IFS= read -r line; do "
        "case $line in \"discovery failed: \"*) echo \"$line\"; continue;; *=*) ;; *) refuse \"a line that is "
        "not a list\"; return 1;; esac; "
        "n=${line%%=*}; v=${line#*=}; "
        "[ -n \"$rest\" ] && [ \"$n\" = \"${rest%% *}\" ] || { refuse \"a list out of order: $n\"; return 1; }; "
        "case $rest in *\" \"*) rest=${rest#* };; *) rest=;; esac; "
        f"case $v in *[!\\ {ENTRY_CHARS}]*) refuse \"a character outside the grammar in $n\"; return 1;; "
        "\" \"*|*\" \"|*\"  \"*) refuse \"spacing in $n\"; return 1;; esac; "
        "for e in $v; do case $e in /*) ;; *) refuse \"an entry of $n that is not absolute\"; return 1;; esac; "
        "done; "
        "case $n in P) P=$v;; Z) Z=$v;; T) T=$v;; L) L=$v;; Lw) Lw=$v;; X) X=$v;; esac; line=; "
        "done < \"$1\"; "
        "[ -z \"$line\" ] || { refuse \"its last line does not end\"; return 1; }; "
        "[ -z \"$rest\" ] || { refuse \"missing ${rest%% *}\"; return 1; }; }",
        "selfcheck() { local x ld ldr; [ -n \"$P\" ] || omits P; "
        "for x in \"$PY\" \"$PYR\" \"$DOCKER\" \"$DR\"; do case \" $T \" in *\" $x \"*) ;; *) omits \"$x\";; esac; "
        "done; "
        "[ \"$DARWIN\" = 1 ] && return; "
        "if [ -z \"$fixedout\" ] && [ -f \"$PYR\" ] && [ ! -h \"$PYR\" ]; then "
        "ld=$(LC_ALL=C grep -a -o '/[A-Za-z0-9._/-]*/ld-[A-Za-z0-9._-]*\\.so[.0-9]*' \"$PYR\" | sed -n 1p); "
        "[ -z \"$ld\" ] && return; ldr=$(realpath \"$ld\" 2>/dev/null); "
        "case \" $L \" in *\" $ld \"*|*\" ${ldr:-//} \"*) ;; *) omits \"the loader $ld\";; esac; "
        "else echo \"discovery failed: the interpreter's loader cannot be checked\"; fi; }",
        "lists() { local x z found ZP=; for z in $Z; do [ -e \"$z\" ] && ZP=\"$ZP $z\"; done; "
        "for x in $P; do [ -e \"$x\" ] || echo \"absent: $x\"; done   # required: never excused\n"
        "for x in $L; do [ -e \"$x\" ] || { [ \"$DARWIN\" = 1 ] && case $x in " + CACHE + ") true;; "
        "*) false;; esac; } || echo \"absent: $x\"; done   # a system library may be only in macOS's shared cache\n"
        "if [ -n \"$P$Lw\" ]; then " + named("$P $Lw") + f"; find -L $P $Lw {bad} 2>/dev/null; fi\n"
        "for z in $ZP; do " + named("\"$z\"") + f"; find -L \"$z\" {bad} 2>/dev/null; done   # a zip present\n"
        "if [ -n \"$X\" ]; then " + named("\"$X\"") + f"; find -L \"$X\" {bad} 2>/dev/null; fi\n"
        "if [ -n \"$P$Lw$ZP$X\" ]; then find $P $Lw $ZP $X -name '*[[:space:]]*' -print 2>/dev/null "
        "| sed 's/^/discovery failed: whitespace in /'; " + links.format("$P $Lw $ZP $X") + "; fi\n"
        + above.format("$P $Z $L $X") + "; }   # every directory above each, and above its realpath",
        "body() { PYR=$(realpath \"$PY\" 2>/dev/null); DR=$(realpath \"$DOCKER\" 2>/dev/null); "
        "fixedout=$(fixed); [ -z \"$fixedout\" ] || printf '%s\\n' \"$fixedout\"; "
        "if parse \"$1\"; then selfcheck; trees=; chains=; ups=; lists; fi; echo BODY-COMPLETE; }",
        "body \"$1\" | { n=0; fin=; while IFS= read -r l; do if [ \"$l\" = BODY-COMPLETE ]; then fin=1; continue; "
        "fi; fin=; printf '%s\\n' \"$l\"; n=1; done; if [ -n \"$fin\" ]; then echo " + SENTINEL + "; exit $n; fi; "
        "echo \"discovery failed: the judging did not run to its end\"; exit 1; }",
    ]) + "\n"


def step3(kind: str, *, identity: Optional[str] = None, path: str = DISCOVERY_PATH) -> str:
    """The one root invocation, `sudo sh -c '<this>' sh "$R"`: the digests
    checked quietly, discovery run as the unprivileged identity with no
    terminal and an empty environment, its output captured by root under a
    cap, then judge.sh over it. Every file by its absolute path; the cd is
    the subshell's alone. `identity` replaces the identity drop (a test
    keeps its own uid); `path` is discovery's PATH."""
    detach, drop, env, home, sh = DROP[kind]
    drop = drop if identity is None else identity
    text = (f"{DIGEST[kind]} \"$1/judge.sha256\" || {{ echo \"{MISMATCH}\"; exit 1; }}; "
            f"( cd / && {detach} {drop} {env} -i PATH={path} {home} LC_ALL=C {sh} -c \"$(cat \"$1/discover.sh\")\" "
            f"</dev/null 2>/dev/null ) | head -c {CLOSURE_MAX + 1} > \"$1/closure.env\"; "
            "chmod 0400 \"$1/closure.env\" && sh \"$1/judge.sh\" \"$1/closure.env\"")
    if "'" in text:
        raise ValueError("step 3 is printed inside single quotes and may hold none")
    return text


def validation_steps(p: ps.PartitionSpec, kind: str, q: Callable[[str], str] = shlex.quote, *,
                     template: str = "/tmp/amap-judge.XXXXXXXX", owner: str = "root", identity: Optional[str] = None,
                     path: str = DISCOVERY_PATH) -> List[str]:
    """The operator's install-time check of what root will run (d2.16
    §12.1b), for a `kind` (systemd or launchd) host. Root makes a root-only
    directory, writes the two scripts into it from this text BEFORE anything
    vetted runs, and checks their digests in the same invocation that runs
    discovery (as an unprivileged identity) and then judging (as root). Only
    when that prints exactly the sentinel and exits 0 may anything run the
    vetted interpreter as root. `owner`, `identity` and `path` are for a
    test, which cannot be root."""
    darwin = kind == "launchd"
    judge, discover = judge_script(p, darwin, owner, q=q), discover_script(p, darwin, q=q)
    dj, dd = hashlib.sha256(judge.encode()).hexdigest(), hashlib.sha256(discover.encode()).hexdigest()
    return [
        "# The tools the weekly job runs as root, and their startup closure: run these steps at install AND again",
        "# after any operating-system, interpreter or docker update, before the next weekly run. Those updates",
        "# change the startup closure the per-run tripwire holds to the install-time state.",
        f"# Discovery runs as {DISCOVERY_USER} (it must hold no sudoers rule and own nothing in the closure), with no",
        "# terminal and an empty environment; judging runs as root and executes only the operating system's own",
        "# tools. sudo's default closefrom must hold (no closefrom_override or preserve_fds for these steps).",
        "# Trusted as given: the completeness of P, Z, L and Lw beyond the tools and the self-checks, and only as far",
        f"# as no hostile process runs as {DISCOVERY_USER}; P and Z come from the interpreter's own sysconfig, so whoever",
        "# can already write its standard library can make it misreport them. A process discovery leaves behind",
        "# that holds the pipe makes step 3 hang visibly: interrupt it, and run nothing after it.",
        f"# judge.sh sha256 {dj}",
        f"# discover.sh sha256 {dd}",
        f"R=$(sudo mktemp -d {template})",
        "sudo sh -c 'umask 077; cat > \"$1\"' sh \"$R/judge.sh\" <<'END-OF-JUDGE'",
        *judge.rstrip("\n").split("\n"),
        "END-OF-JUDGE",
        "sudo sh -c 'umask 077; cat > \"$1\"' sh \"$R/discover.sh\" <<'END-OF-DISCOVER'",
        *discover.rstrip("\n").split("\n"),
        "END-OF-DISCOVER",
        "sudo chmod 0400 \"$R/judge.sh\" \"$R/discover.sh\"",
        f"printf '%s  %s\\n' {dj} \"$R/judge.sh\" {dd} \"$R/discover.sh\" "
        "| sudo sh -c 'umask 077; cat > \"$1\"' sh \"$R/judge.sha256\"",
        f"sudo sh -c '{step3(kind, identity=identity, path=path)}' sh \"$R\"",
        f"# Go on only when that printed exactly {SENTINEL} and exited 0. The plan prints this check first, so every",
        "# later step that runs an interpreter as root comes after it.",
    ]
