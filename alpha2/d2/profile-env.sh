#!/bin/sh
# D2 profile capture, part A: the runner host's fixed facts (alpha2/d2/PROFILE-CAPTURE.md).
#
# Target-read-only. Run by alpha2/d2/capture.sh, in an empty environment:
#   /usr/bin/env -i PATH=/usr/bin:/bin /bin/sh <checkout>/alpha2/d2/profile-env.sh [ACCOUNT ...]
# It prints `key=value` lines on stdout and nothing else there. It never prints
# an environment value, a key or a file's content: only paths, sha256s, versions,
# ids and fixed words. It runs each tool it reports (`--version`), so a replaced tool
# runs too; that is inherent in reading a version.
# Exit 0 and a last line `profile.end=complete` only when every fact was read. Any
# line reading ABSENT or UNOBSERVED, an empty value, or a sha that is not 64 hex
# digits gives exit 1 and a last line `profile.end=incomplete` (every line is still
# printed). A capture without a `profile.end=` last line is incomplete.

PATH=/usr/bin:/bin
export PATH
LC_ALL=C
export LC_ALL
umask 077

rc=0
say() { printf '%s=%s\n' "$1" "$2"; }
miss() { say "$1" "$2"; rc=1; }

# sha FILE: sha256sum's hex digest, or nothing when sha256sum fails (its rc is checked).
sha() {
    s=$(/usr/bin/sha256sum < "$1" 2>/dev/null) || return 0
    printf '%s' "${s%% *}"
}
# say_sha KEY FILE: the file's sha256, or UNOBSERVED (an unreadable file, for example an
# execute-only binary, hashes to nothing).
say_sha() {
    h=$(sha "$2")
    case $h in
        [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*)
            if [ ${#h} -eq 64 ]; then say "$1" "$h"; return; fi ;;
    esac
    miss "$1" UNOBSERVED
}
# say_val KEY VALUE: VALUE, or UNOBSERVED when it is empty.
say_val() { if [ -n "$2" ]; then say "$1" "$2"; else miss "$1" UNOBSERVED; fi; }

say profile.schema d2-profile-env/2
say captured_at "$(/usr/bin/date -u +%Y-%m-%dT%H:%M:%SZ)"
say host.kernel "$(/usr/bin/uname -sr)"
say host.arch "$(/usr/bin/uname -m)"

# 6.1 `interpreter`, in the lock's own five fields, found the way S0 finds them:
# the launch path and the binary it resolves to, each hashed; the resolved path
# found by a fixed tool outside the interpreter under test (b.4: the version is
# part of this capture).
py=/usr/bin/python3
if [ -x "$py" ] && res=$(/usr/bin/realpath -e -- "$py" 2>/dev/null); then
    say interpreter.path "$py"
    say_sha interpreter.sha256 "$py"
    say_val interpreter.resolved_path "$res"
    say_sha interpreter.resolved_sha256 "$res"
    say_val interpreter.version "$("$py" -I -S -B -c 'import sys; print("%d.%d.%d" % tuple(sys.version_info[:3]))' 2>/dev/null)"
else
    miss interpreter.path ABSENT
fi

# The fixed tools the launch line and the installer call by absolute path, plus
# the two this capture uses. TOOLS is pinned by alpha2/d2/tests/test_d2_texts.py
# to every absolute tool path in install/*.py.
TOOLS="/usr/bin/env /usr/bin/git /usr/bin/realpath /usr/bin/ssh /usr/bin/sha256sum /bin/sh"
for t in $TOOLS; do
    n=$(/usr/bin/basename "$t")
    if [ ! -x "$t" ]; then
        miss "tool.$n.path" ABSENT
        continue
    fi
    say "tool.$n.path" "$t"
    r=$(/usr/bin/realpath -e -- "$t" 2>/dev/null)
    say_val "tool.$n.resolved_path" "$r"
    if [ -f "$r" ]; then say_sha "tool.$n.sha256" "$r"; else miss "tool.$n.sha256" UNOBSERVED; fi
    case $n in
        ssh) v=$("$t" -V 2>&1 </dev/null) ;;
        sh) v=UNVERSIONED ;;
        *) v=$("$t" --version 2>/dev/null </dev/null) ;;
    esac
    v=$(printf '%s\n' "$v" | /usr/bin/head -n 1)
    say_val "tool.$n.version" "$v"
done

# Sleep (A2-16, 5.3a). An observation for the S0 review's [OPEN: sleep probe
# measured], not that probe: systemd's own word for each sleep target.
if [ -x /usr/bin/systemctl ]; then
    for u in sleep.target suspend.target hibernate.target hybrid-sleep.target; do
        w=$(/usr/bin/systemctl is-enabled "$u" 2>/dev/null </dev/null)
        say_val "sleep.$u" "$w"
    done
else
    miss sleep.systemctl ABSENT
fi

# The runner accounts named on the command line (5.3b): uid and primary gid.
for a in "$@"; do
    case $a in
        *[!A-Za-z0-9._-]*|'') miss account.invalid_name REFUSED; continue ;;
    esac
    if u=$(/usr/bin/id -u -- "$a" 2>/dev/null) && g=$(/usr/bin/id -g -- "$a" 2>/dev/null); then
        say "account.$a.uid" "$u"
        say "account.$a.gid" "$g"
    else
        miss "account.$a" ABSENT
    fi
done

if [ "$rc" -eq 0 ]; then say profile.end complete; else say profile.end incomplete; fi
exit $rc
